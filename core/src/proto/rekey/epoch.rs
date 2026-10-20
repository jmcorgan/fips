//! Epochs: a set of transport keys with the state derived from them.
//!
//! An epoch owns its session behind a `Box`, so moving it between the
//! current, pending and previous slots copies a pointer and its key bytes
//! are erased in place when it is retired. Everything derived from the keys
//! belongs to the epoch that holds them: the replay window (inside the
//! session), the key-epoch bit, the timestamp base, the per-epoch MMP state
//! and whether a decrypt worker holds its receive half. A frame that
//! authenticates under one epoch updates only that epoch.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::Wire;
use super::ladder::Ladder;
use super::lease::{EpochTag, IndexLease};
use super::profile::{FrameHint, Profile, SessionKeys};
use super::proof::Bonded;
use crate::time::Instant;

/// Which held epoch something refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// The epoch this node seals under.
    Current,
    /// The completed epoch waiting to become current.
    Pending,
    /// The epoch being drained after a cutover.
    Previous,
}

/// Which side of the handshake that made an epoch this node was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// This node started the handshake.
    Initiator,
    /// This node answered it.
    Responder,
}

/// Where an epoch's receive half lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecvHome {
    /// The machine opens the epoch's frames.
    Here,
    /// A decrypt worker accepted the receive half and opens them.
    Delegated,
}

/// What a binding of an index is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// The index of an own attempt, awaiting its reply.
    Attempt,
    /// The index of a pending epoch.
    Pending,
    /// The index of the current epoch.
    Current,
    /// The index of the epoch being drained.
    Previous,
}

/// The session indices of an epoch or attempt: this node's (as a lease),
/// the peer's, and the transport the binding was made on.
///
/// An unindexed profile (FSP) holds neither index.
#[derive(Debug)]
pub struct Ids<T> {
    pub(super) lease: Option<IndexLease>,
    pub(super) theirs: Option<u32>,
    pub(super) transport: T,
}

impl<T: Copy> Ids<T> {
    /// The indices of a link's first epoch: this node's `lease`, the peer's
    /// `theirs`, bound on `transport`.
    pub fn new(lease: IndexLease, theirs: u32, transport: T) -> Self {
        Self {
            lease: Some(lease),
            theirs: Some(theirs),
            transport,
        }
    }

    /// No indices, for a profile that has none.
    pub fn unindexed(transport: T) -> Self {
        Self {
            lease: None,
            theirs: None,
            transport,
        }
    }

    /// This node's index and the transport it is bound on, if it has one.
    pub(super) fn binding(&self) -> Option<(T, u32)> {
        self.lease.as_ref().map(|l| (self.transport, l.index()))
    }

    /// This node's index, if it has one.
    pub(super) fn ours(&self) -> Option<u32> {
        self.lease.as_ref().map(IndexLease::index)
    }
}

/// A retained final message and its resend ladder.
#[derive(Debug)]
pub(super) struct Final<I> {
    pub(super) msg: Wire,
    pub(super) ladder: Ladder<I>,
}

/// One set of transport keys and what is derived from them.
#[derive(Debug)]
pub(super) struct Epoch<P: Profile, I> {
    pub(super) tag: EpochTag,
    pub(super) session: Box<P::Session>,
    pub(super) ids: Ids<P::Transport>,
    /// The key-epoch bit, fixed when the epoch is made (or, for a
    /// responder pending, by the frame that adopts it).
    pub(super) k: bool,
    pub(super) role: Role,
    /// The inner-header timestamp base; `None` until fixed, and no seal
    /// reaches an epoch without one.
    pub(super) base: Option<I>,
    /// The rekey-age anchor: the cutover or install instant.
    pub(super) started: I,
    /// The coordinates the peer's handshake message carried.
    pub(super) route: Option<P::Route>,
    pub(super) ext: P::Ext,
    pub(super) recv: RecvHome,
    /// The highest counter a lost decrypt worker reported.
    pub(super) floor: Option<u64>,
    /// The first authenticated frame from the peer under this epoch.
    pub(super) heard: Option<I>,
    /// The first frame showing the peer seals under this epoch.
    pub(super) moved: Option<I>,
    /// Installed at a confirmation deadline without evidence.
    pub(super) assumed: bool,
    /// A retained final message resent until the peer is heard.
    pub(super) fin: Option<Final<I>>,
    /// Prompt repeats after the cutover, until the peer is seen to move.
    pub(super) elicit: Option<Ladder<I>>,
    /// When the last prompt was sealed under this epoch.
    pub(super) prompted: Option<I>,
}

/// The outcome of trying one epoch's key on a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Trial {
    /// The key authenticated the frame; the plaintext is `len` bytes in the
    /// scratch buffer.
    Opened(usize),
    /// The epoch's window refused the counter.
    Refused,
    /// The key did not authenticate the frame.
    Failed,
}

impl<P: Profile, I: Instant> Epoch<P, I> {
    /// An epoch made from a bonded completion.
    pub(super) fn new(
        tag: EpochTag,
        done: Bonded<P>,
        ids: Ids<P::Transport>,
        k: bool,
        role: Role,
        started: I,
    ) -> Self {
        Self {
            tag,
            session: done.into_inner().session,
            ids,
            k,
            role,
            base: fault!(BaseAtCreation).then_some(started),
            started,
            route: None,
            ext: P::Ext::default(),
            recv: RecvHome::Here,
            floor: None,
            heard: None,
            moved: None,
            assumed: false,
            fin: None,
            elicit: None,
            prompted: None,
        }
    }

    /// Try this epoch's key on `frame`, writing the plaintext to `scratch`
    /// on success. The frame and the epoch are unchanged either way.
    pub(super) fn trial(&self, hint: &FrameHint, frame: &[u8], scratch: &mut Vec<u8>) -> Trial {
        let below_floor = self.floor.is_some_and(|f| hint.counter <= f);
        if below_floor || !self.session.fresh(hint.counter) {
            return Trial::Refused;
        }
        scratch.clear();
        if self.session.open(hint, frame, scratch) {
            Trial::Opened(scratch.len())
        } else {
            Trial::Failed
        }
    }

    /// Whether this epoch is an XK responder's, at which a probe does not
    /// show that the initiator moved.
    pub(super) fn probe_blind(&self, at_proof: bool) -> bool {
        at_proof && self.role == Role::Responder
    }
}

/// The previous epoch, kept after a cutover until evidence the peer moved,
/// never past an absolute ceiling.
#[derive(Debug)]
pub(super) struct Drain<P: Profile, I> {
    pub(super) ep: Epoch<P, I>,
    pub(super) deadline: I,
    /// The deadline is the short one, after evidence the peer moved.
    pub(super) evidenced: bool,
}
