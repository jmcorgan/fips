//! The rotation cycle: at most one own attempt or one pending epoch.
//!
//! A pending epoch exists only inside `PendI` or `PendR`, the two pending
//! variants of one enum, so its role cannot disagree with it and the
//! machine holds at most one at rest. Retransmission state belongs to the
//! attempt that produced it: the retained first message lives in the
//! attempt, the retained msg3 in the `PendI` (or, after a restart or a
//! delayed cutover, in the current epoch), and each dies with its owner.
//! A second pending epoch has nowhere to go: no variant has a field for it.

use alloc::boxed::Box;

use super::Wire;
use super::epoch::{Epoch, Final};
use super::ladder::Ladder;
use super::lease::IndexLease;
use super::profile::Profile;
use super::record::{HeldAnswer, Record};
use crate::time::Instant;

/// What a completed own attempt waits for before it becomes current.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// Nothing: the completion proves the peer holds the keys (IK); the
    /// next poll cuts over.
    Held,
    /// A frame from the peer under the new epoch, or the confirmation
    /// deadline (XK).
    Evidence,
    /// A fixed delay (next's XX only).
    Delay,
}

/// The rotation cycle.
///
/// The variants differ in size by their epoch and ladders. One machine
/// holds one cycle and moves between variants at every rotation, so boxing
/// the large ones would trade a few hundred bytes per peer for an
/// allocation per transition.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(super) enum Cycle<P: Profile, I> {
    /// No attempt in progress.
    Idle,
    /// An own attempt sent, its reply not yet authenticated.
    Init(Attempt<P, I>),
    /// An own attempt completed; the new epoch is held.
    PendI(PendI<P, I>),
    /// A peer attempt completed; the new epoch is held until a frame from
    /// the peer authenticates under it.
    PendR(PendR<P, I>),
}

/// An own attempt in flight.
#[derive(Debug)]
pub(super) struct Attempt<P: Profile, I> {
    pub(super) hs: Box<P::Hs>,
    /// The first message, resent byte for byte.
    pub(super) out: Wire,
    pub(super) lease: Option<IndexLease>,
    /// The transport the attempt's index was bound on.
    pub(super) transport: P::Transport,
    pub(super) first: I,
    pub(super) ladder: Ladder<I>,
    pub(super) deadline: I,
    /// A resend of the first message has been sent, so a reply no longer
    /// measures the round trip.
    pub(super) resent: bool,
}

/// An own attempt that completed.
#[derive(Debug)]
pub(super) struct PendI<P: Profile, I> {
    pub(super) ep: Epoch<P, I>,
    pub(super) wait: Wait,
    pub(super) deadline: I,
    /// The completion revealed the peer restarted.
    pub(super) restart: bool,
    /// The retained msg3.
    pub(super) fin: Option<Final<I>>,
    /// Probe and keepalive rungs while waiting for evidence.
    pub(super) probes: Option<Ladder<I>>,
    pub(super) probed: Option<I>,
    /// The peer was heard on an epoch it stays on if it did not move.
    pub(super) stayed: bool,
    /// The epoch came back here from an assumed cutover.
    pub(super) reverted: bool,
}

/// A peer attempt that completed, held until the peer's first frame under
/// it.
#[derive(Debug)]
pub(super) struct PendR<P: Profile, I> {
    pub(super) ep: Epoch<P, I>,
    pub(super) deadline: I,
    pub(super) restart: bool,
    pub(super) answer: Option<HeldAnswer>,
}

impl<P: Profile, I: Instant> PendR<P, I> {
    /// End the pending: its arming msg1's ephemeral enters the record, then
    /// the epoch is handed back to be retired or installed. Every exit of a
    /// responder pending goes through here, so no exit leaves the msg1 that
    /// armed it replayable.
    pub(super) fn end(self, record: &mut Record) -> (Epoch<P, I>, bool) {
        if let Some(answer) = self.answer {
            record.push(answer.ephemeral);
        }
        (self.ep, self.restart)
    }
}

/// A pending epoch taken out of its cycle for a cutover.
#[derive(Debug)]
pub(super) struct Pend<P: Profile, I> {
    pub(super) ep: Epoch<P, I>,
    pub(super) restart: bool,
    pub(super) fin: Option<Final<I>>,
}
