//! Values that carry authority, and the only code that makes them.
//!
//! Unauthenticated input changes nothing, by type. `step` judges an input
//! with a shared borrow and then applies a commit, and every commit caused
//! by a network input, except a bounded candidate, carries one of these:
//!
//! - [`Bonded`]: a completed handshake whose remote static is the peer's.
//!   Only [`Bond::check`] makes one, and an epoch is made only from one.
//! - [`ReplyProof`], [`FinalProof`], [`FrameProof`]: a reply, msg3 or frame
//!   that authenticated in `judge`. Their constructors are visible only
//!   inside this module tree; the root crate can hold none of them.
//! - [`Authentic`]: a message read elsewhere in `fips-core` (an IK msg1 at
//!   node level, a leg-table completion on next), marked [`Fresh`] or
//!   [`Replayable`]. Its constructor is `pub(crate)`, so the root crate can
//!   pass one on but never make one.
//! - [`Evidence`]: why a pending epoch may become current.

use core::fmt;
use core::marker::PhantomData;

use super::Wire;
use super::epoch::Slot;
use super::lease::EpochTag;
use super::profile::{Completed, Profile};
use crate::identity::NodeAddr;

/// A peer's static key, compared on its X coordinate only.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerKey([u8; 32]);

impl PeerKey {
    /// The key whose X coordinate is `x`.
    pub fn new(x: [u8; 32]) -> Self {
        Self(x)
    }

    /// The key of an x-only public key.
    pub fn from_xonly(key: &secp256k1::XOnlyPublicKey) -> Self {
        Self(key.serialize())
    }

    /// The X coordinate.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The node address derived from the key: the first 16 bytes of the
    /// SHA-256 of its X coordinate, as `NodeAddr::from_pubkey` derives it.
    pub fn addr(&self) -> NodeAddr {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(self.0);
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash[..16]);
        NodeAddr::from_bytes(bytes)
    }
}

impl fmt::Debug for PeerKey {
    /// The first four bytes, which is enough to tell test keys apart.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PeerKey({:02x}{:02x}{:02x}{:02x})",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

/// What a completed handshake must match to become an epoch of this
/// machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bond {
    /// The peer's static key.
    Key(PeerKey),
    /// The address an inbound first setup claimed, until the session is
    /// wanted by key or a completion proves the key.
    Claimed(NodeAddr),
}

impl Bond {
    /// Accept `done` only if it authenticated the bonded peer: the same X
    /// coordinate, or for a claimed address the same derived address.
    pub fn check<P: Profile>(&self, done: Completed<P>) -> Result<Bonded<P>, Completed<P>> {
        let matches = match self {
            Self::Key(key) => done.remote == *key,
            Self::Claimed(addr) => done.remote.addr() == *addr,
        };
        if matches || fault!(BondAlways) {
            Ok(Bonded { done })
        } else {
            Err(done)
        }
    }

    /// The peer's node address.
    pub fn addr(&self) -> NodeAddr {
        match self {
            Self::Key(key) => key.addr(),
            Self::Claimed(addr) => *addr,
        }
    }
}

/// A completed handshake that passed [`Bond::check`].
#[derive(Debug)]
pub struct Bonded<P: Profile> {
    done: Completed<P>,
}

impl<P: Profile> Bonded<P> {
    /// The peer's startup epoch.
    pub fn epoch(&self) -> [u8; 8] {
        self.done.epoch
    }

    /// The static key the completion authenticated.
    pub fn remote(&self) -> PeerKey {
        self.done.remote
    }

    /// The peer's session index, for an index-bearing profile.
    pub fn theirs(&self) -> Option<u32> {
        self.done.theirs
    }

    /// Give up the proof for the completion inside it.
    pub(super) fn into_inner(self) -> Completed<P> {
        self.done
    }
}

/// The freshness of an [`Authentic`] value whose authentication cannot be
/// replayed.
#[derive(Debug)]
pub struct Fresh;

/// The freshness of an [`Authentic`] value that authenticates the peer but
/// carries nothing fresh, so a captured copy reads as the peer again.
#[derive(Debug)]
pub struct Replayable;

/// A message `fips-core` read and authenticated as the peer, with how fresh
/// that authentication is.
pub struct Authentic<T, F> {
    inner: T,
    freshness: PhantomData<F>,
}

impl<T, F> Authentic<T, F> {
    /// Mark `inner` as read and authenticated. Only `fips-core` code that
    /// performed the read calls this.
    pub(crate) fn new(inner: T) -> Self {
        Self {
            inner,
            freshness: PhantomData,
        }
    }

    /// The authenticated message.
    pub fn get(&self) -> &T {
        &self.inner
    }

    /// Give up the mark for the message.
    pub(super) fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: fmt::Debug, F> fmt::Debug for Authentic<T, F> {
    /// The message, marked.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Authentic").field(&self.inner).finish()
    }
}

/// A reply that read on the attempt's fork and passed [`Bond::check`].
#[derive(Debug)]
pub(super) struct ReplyProof<P: Profile> {
    pub(super) done: Bonded<P>,
    pub(super) fin: Option<Wire>,
}

impl<P: Profile> ReplyProof<P> {
    /// The proof of a reply that `judge` read and bonded.
    pub(super) fn new(done: Bonded<P>, fin: Option<Wire>) -> Self {
        Self { done, fin }
    }
}

/// A msg3 that read on a candidate's fork and passed [`Bond::check`].
#[derive(Debug)]
pub(super) struct FinalProof<P: Profile> {
    pub(super) done: Bonded<P>,
    /// The candidate it completes.
    pub(super) seq: u64,
}

impl<P: Profile> FinalProof<P> {
    /// The proof of a msg3 that `judge` read on candidate `seq` and bonded.
    pub(super) fn new(done: Bonded<P>, seq: u64) -> Self {
        Self { done, seq }
    }
}

/// A frame that authenticated under one held epoch and passed its window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FrameProof {
    pub(super) tag: EpochTag,
    pub(super) slot: Slot,
    pub(super) counter: u64,
    pub(super) k: bool,
    /// The plaintext's length; the plaintext is in the scratch buffer.
    pub(super) len: usize,
    pub(super) probe: bool,
}

impl FrameProof {
    /// The proof of a frame `judge` opened under the epoch `tag` in `slot`.
    pub(super) fn new(
        tag: EpochTag,
        slot: Slot,
        counter: u64,
        k: bool,
        len: usize,
        probe: bool,
    ) -> Self {
        Self {
            tag,
            slot,
            counter,
            k,
            len,
            probe,
        }
    }
}

/// How an epoch came to be installed as current.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceKind {
    /// The completion proves the peer holds the keys (IK msg2, XK msg3).
    Proof,
    /// A frame from the peer authenticated under the epoch.
    Frame,
    /// The completion revealed a restart; the old epoch is unreadable to
    /// the peer.
    Restart,
    /// The confirmation deadline passed with nothing heard (counted).
    Assumed,
    /// A delayed cutover's deadline passed (next only).
    Delay,
    /// The first handshake of a session.
    First,
}

/// Why a pending epoch may become current.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Evidence {
    pub(super) kind: EvidenceKind,
    /// The adopting frame's key-epoch bit, for frame evidence.
    pub(super) k: Option<bool>,
}

impl Evidence {
    /// A completion that proves the peer holds the keys.
    pub(super) fn proof() -> Self {
        Self {
            kind: EvidenceKind::Proof,
            k: None,
        }
    }

    /// A frame under the pending epoch. A previous-epoch frame is not
    /// evidence of anything about a newer epoch.
    pub(super) fn frame(proof: &FrameProof) -> Option<Self> {
        match proof.slot {
            Slot::Pending => Some(Self {
                kind: EvidenceKind::Frame,
                k: Some(proof.k),
            }),
            Slot::Previous if fault!(EvidencePrevious) => Some(Self {
                kind: EvidenceKind::Frame,
                k: Some(proof.k),
            }),
            Slot::Current | Slot::Previous => None,
        }
    }

    /// A completion that revealed the peer restarted.
    pub(super) fn restart() -> Self {
        Self {
            kind: EvidenceKind::Restart,
            k: None,
        }
    }

    /// The confirmation deadline passed with nothing heard.
    pub(super) fn assumed() -> Self {
        Self {
            kind: EvidenceKind::Assumed,
            k: None,
        }
    }

    /// A delayed cutover's deadline passed.
    pub(super) fn delay() -> Self {
        Self {
            kind: EvidenceKind::Delay,
            k: None,
        }
    }

    /// Whether the evidence is a frame from the peer.
    pub(super) fn is_frame(&self) -> bool {
        self.kind == EvidenceKind::Frame
    }
}
