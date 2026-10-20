//! The profile: what distinguishes one layer's and one pattern's rekey from
//! another's.
//!
//! The machine implements the transitions once. A profile chooses the
//! constants that select rows (how many messages, where the responder
//! commits, who cuts over when), supplies the crypto (start, answer and read
//! a handshake, open and seal frames) and the prompt plaintext, and adds no
//! transition of its own. Layer differences that are not handshake
//! properties (selection by index or by trial, who can inject a setup, what
//! a prompt is) are constants or functions here, never a branch on the layer
//! inside the machine.
//!
//! An input a profile never receives is excluded by type: the variant
//! carries a field of an associated type that such a profile binds to
//! `core::convert::Infallible`, so the variant cannot be built for it.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::convert::Infallible;
use core::fmt::Debug;

use super::Wire;
use super::lease::{IndexLease, IndexSource};
use super::proof::PeerKey;
use super::record::Digest;
use super::resolve::Commit;
use crate::noise::Fork;
use crate::time::Duration;

/// Which layer a machine serves; carried in `Output::PeerRestarted`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    /// The link layer.
    Fmp,
    /// The end-to-end session layer.
    Fsp,
}

/// When the side that completes first cuts over as initiator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitiatorCutover {
    /// At the next poll after the reply, which proves the responder holds
    /// the keys (IK).
    OnProof,
    /// On a frame from the peer under the new epoch, with probes meanwhile
    /// and a confirmation deadline (XK).
    OnEvidence,
    /// After a fixed delay, retaining msg3 until the peer is heard (next's
    /// XX only).
    AfterDelay,
}

/// When the responder cuts over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponderCutover {
    /// On the first frame from the initiator under the pending epoch.
    OnFrame,
    /// At the authenticated msg3, which proves the initiator holds the keys.
    AtProof,
}

/// When answering or completing a peer's rekey opens dampening.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DampenAt {
    /// When this node answers the peer's msg1.
    Answer,
    /// When the peer's attempt completes at msg3.
    Completion,
}

/// How a frame's epoch is found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Select {
    /// By the receiver index in the frame header.
    ByIndex,
    /// By trying each held key in turn.
    Trial,
}

/// A handshake step failed: the message did not read, or could not be
/// written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HsError;

/// What the shell parsed from an established frame's header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHint {
    /// The frame's counter.
    pub counter: u64,
    /// The frame's key-epoch bit.
    pub k: bool,
    /// The receiver index the frame names (FMP; 0 for FSP).
    pub index: u32,
    /// Where the ciphertext starts in the frame.
    pub body: usize,
}

/// A handshake that has completed: its transport session, the remote static
/// it authenticated, the remote startup epoch and, for an index-bearing
/// profile, the index the peer chose.
///
/// Carries no authority by itself. The machine makes an epoch only from a
/// [`super::proof::Bonded`], which only `Bond::check` makes from this.
#[derive(Debug)]
pub struct Completed<P: Profile> {
    /// The transport session.
    pub session: Box<P::Session>,
    /// The static key the handshake authenticated.
    pub remote: PeerKey,
    /// The peer's startup epoch.
    pub epoch: [u8; 8],
    /// The peer's session index, for an index-bearing profile.
    pub theirs: Option<u32>,
}

/// What reading a reply produced: the completion and, for a three-message
/// pattern, the msg3 written on the same fork.
#[derive(Debug)]
pub struct Read<P: Profile> {
    /// The completed handshake.
    pub done: Completed<P>,
    /// The msg3 to send, for a three-message pattern.
    pub fin: Option<Wire>,
}

/// A peer attempt a node-level leg table completed (next's FMP XX), with
/// the index lease the leg held.
#[derive(Debug)]
pub struct Leg<P: Profile> {
    /// The completed handshake.
    pub done: Completed<P>,
    /// The leg's index, which the machine takes over.
    pub lease: Option<IndexLease>,
}

/// A transport session as the machine uses it.
///
/// The replay window is checked and marked separately from the decrypt, so
/// a frame is checked before it is opened, opened in `judge` without
/// changing anything, and marked in `apply`.
pub trait SessionKeys {
    /// The receive half handed to a decrypt worker.
    type RecvCopy: Debug;
    /// What a sender needs to seal one frame outside the machine: a cipher
    /// clone, for the pipelined send paths.
    type SendCopy: Debug;

    /// Authenticate `frame` under this session's receive key and write its
    /// plaintext to `out`, without touching the replay window or `frame`.
    fn open(&self, hint: &FrameHint, frame: &[u8], out: &mut Vec<u8>) -> bool;

    /// Whether the replay window would accept `counter`.
    fn fresh(&self, counter: u64) -> bool;

    /// Record `counter` as received.
    fn mark(&mut self, counter: u64);

    /// How many counters this session has sealed with.
    fn sent(&self) -> u64;

    /// Reserve the next send counter, with a copy of the send key.
    fn reserve(&mut self) -> (u64, Self::SendCopy);

    /// A copy of the receive half, its window as it stands, refusing every
    /// counter at or below `floor`.
    fn copy(&self, floor: Option<u64>) -> Self::RecvCopy;
}

/// An IK msg1 read at node level as the peer (master's link profile).
pub trait Msg1Read<P: Profile>: Debug {
    /// The startup epoch the msg1 carries.
    fn epoch(&self) -> [u8; 8];
    /// The digest of the whole msg1 as it arrived.
    fn digest(&self) -> Digest;
    /// The digest of the ephemeral the msg1 carries.
    fn ephemeral(&self) -> Digest;
    /// The static key the msg1 authenticated.
    fn remote(&self) -> PeerKey;
    /// Write msg2 with this node's epoch and index `ours`, completing the
    /// handshake.
    fn answer(
        &self,
        local: &P::LocalKeys,
        ours: Option<u32>,
    ) -> Result<(Completed<P>, Wire), HsError>;
}

/// The completion a leg table hands over (next only; `fmp::rekey::read_final`).
pub trait DoneRead<P: Profile>: Debug {
    /// The startup epoch the completion carries.
    fn epoch(&self) -> [u8; 8];
    /// Take the completion and the leg's lease.
    fn take(self) -> Leg<P>;
}

impl<P: Profile> Msg1Read<P> for Infallible {
    fn epoch(&self) -> [u8; 8] {
        match *self {}
    }

    fn digest(&self) -> Digest {
        match *self {}
    }

    fn ephemeral(&self) -> Digest {
        match *self {}
    }

    fn remote(&self) -> PeerKey {
        match *self {}
    }

    fn answer(&self, _: &P::LocalKeys, _: Option<u32>) -> Result<(Completed<P>, Wire), HsError> {
        match *self {}
    }
}

impl<P: Profile> DoneRead<P> for Infallible {
    fn epoch(&self) -> [u8; 8] {
        match *self {}
    }

    fn take(self) -> Leg<P> {
        match self {}
    }
}

/// A layer and handshake pattern, as the machine needs to know it.
pub trait Profile: Sized + Debug + 'static {
    /// The handshake state; read functions run on a fork of it.
    type Hs: Fork + Debug;
    /// The transport session of an epoch.
    type Session: SessionKeys + Debug;
    /// The allocator capability (FMP) or `()`.
    type Indices: IndexSource;
    /// The transport an index is bound on (FMP) or `()`.
    type Transport: Copy + Eq + Debug;
    /// The authenticated link peer a setup arrived over (FSP) or `()`.
    type Carrier: Copy + Eq + Debug;
    /// The coordinates the peer's handshake message carried (FSP) or `()`.
    type Route: Clone + Debug;
    /// Per-epoch state the shell reads through `view` (MMP receiver, spin).
    type Ext: Default + Debug;
    /// The local static key and startup epoch.
    type LocalKeys;
    /// `()` for profiles that receive the FSP-only inputs, else `Infallible`.
    type Fsp: Copy + Debug;
    /// `()` for profiles that receive the FMP-only inputs, else `Infallible`.
    type Fmp: Copy + Debug;
    /// The IK msg1 token, or `Infallible`.
    type Msg1: Msg1Read<Self>;
    /// The leg-table completion token, or `Infallible`.
    type Done: DoneRead<Self>;

    /// The layer, reported with a restart.
    const LAYER: Layer;
    /// Messages in the handshake: 2 (IK) or 3 (XK, XX).
    const MESSAGES: u8;
    /// Where the responder commits.
    const COMMIT: Commit;
    /// When the initiator cuts over.
    const INITIATOR_CUTOVER: InitiatorCutover;
    /// When the responder cuts over.
    const RESPONDER_CUTOVER: ResponderCutover;
    /// Candidates a machine holds at most (0: the pattern has none).
    const CANDIDATES: usize;
    /// Candidates one carrier may hold at most.
    const PER_CARRIER: usize;
    /// When dampening opens.
    const DAMPEN_AT: DampenAt;
    /// How a frame's epoch is found.
    const SELECT: Select;
    /// Whether the authenticated-silence trigger runs.
    const SILENCE: bool;
    /// Whether the rekey setup's first rung scales with the round trip.
    const SETUP_RTT: bool;
    /// Whether epochs and attempts hold session indices.
    const INDEXED: bool;
    /// The shortest plaintext the layer delivers.
    const FLOOR: usize;

    /// Start an initiator handshake toward `peer` and write its first
    /// message, carrying `ours` when the profile is index-bearing.
    fn initiate(
        local: &Self::LocalKeys,
        peer: &PeerKey,
        ours: Option<u32>,
    ) -> Result<(Self::Hs, Wire), HsError>;

    /// Whether a setup's msg1 passes validation (length, point).
    fn valid(msg1: &[u8]) -> bool;

    /// Read a setup's msg1 on a fresh responder handshake and write the
    /// reply.
    fn answer(local: &Self::LocalKeys, msg1: &[u8]) -> Result<(Self::Hs, Wire), HsError>;

    /// The receiver index a reply names, for an index-bearing profile.
    fn index(reply: &[u8]) -> Option<u32>;

    /// Read a reply on a fork of the initiator handshake `hs`.
    fn reply(hs: &Self::Hs, local: &Self::LocalKeys, bytes: &[u8]) -> Result<Read<Self>, HsError>;

    /// Read a final message on a fork of the responder handshake `hs`.
    fn complete(hs: &Self::Hs, bytes: &[u8]) -> Result<Completed<Self>, HsError>;

    /// Write the fixed prompt plaintext (FMP Heartbeat, FSP CoordsWarmup),
    /// its inner-header timestamp `elapsed` since the epoch's timestamp base.
    fn prompt(elapsed: Duration, out: &mut Vec<u8>);

    /// Whether `plaintext` is a probe (an FSP CoordsWarmup); always false
    /// for FMP.
    fn is_probe(plaintext: &[u8]) -> bool;
}
