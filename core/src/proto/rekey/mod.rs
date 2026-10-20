//! Rekey as one sans-IO state machine per keyed relationship.
//!
//! [`Rekey`] holds every piece of one relationship's key rotation: the
//! current epoch, an optional previous epoch being drained, one cycle slot
//! (idle, an own attempt, an own completed attempt, a peer's completed
//! attempt), a bounded list of peer-started attempts (candidates), the
//! replay record, and every deadline as an instant of the host's clock. One
//! machine serves a link peer (FMP) or an end-to-end session (FSP); a
//! [`Profile`] selects which, and the transitions are written once for
//! both.
//!
//! The machine is synchronous, `no_std` with `alloc`, and sans-IO. It never
//! reads a clock, sends, dials, closes or logs. Each call takes the current
//! instant and returns an ordered list of [`Output`]s that the shell
//! executes front to back. It owns the keys: its attempts' and candidates'
//! handshake states and every epoch's transport session, each behind a
//! `Box`, so no move leaves key bytes behind.
//!
//! [`Rekey::step`] runs in two phases. `judge` takes a shared borrow and
//! either rejects the input or produces a commit, doing every read and
//! check of the input's row on the way; `apply` is the only code that
//! changes the machine, and builds no output until the row's checks have
//! all passed. Every commit a network input causes, except a bounded
//! candidate, carries a proof only this module tree can make, so input that
//! has not authenticated changes nothing but the candidate list.
//!
//! The module is hidden from the crate's documentation: nothing outside
//! `fips-core` calls it yet. The transition tables it implements are in
//! this directory's README.

#![deny(clippy::wildcard_enum_match_arm)]

use alloc::vec::Vec;
use core::ops::Range;

/// Whether the test-only switch `$f` is on (see `faults.rs`). Outside test
/// builds it is the literal `false`, so production code has no switch to
/// turn and the branch it guards compiles away.
#[cfg(test)]
macro_rules! fault {
    ($f:ident) => {
        $crate::proto::rekey::faults::on($crate::proto::rekey::faults::Fault::$f)
    };
}

/// Outside test builds no guard can be switched off.
#[cfg(not(test))]
macro_rules! fault {
    ($f:ident) => {
        false
    };
}

mod candidates;
mod cycle;
mod epoch;
#[cfg(test)]
mod faults;
pub(crate) mod keys;
mod ladder;
mod lease;
mod machine;
mod params;
mod profile;
mod proof;
mod reason;
mod record;
mod resolve;

pub use cycle::Wait;
pub use epoch::{Ids, Purpose, RecvHome, Role, Slot};
pub use keys::{NodeKeys, NoiseKeys, RecvCopy, SendCopy};
pub use lease::{EpochTag, IndexLease, IndexSource, TagSource, allocate, leaked};
pub use machine::Rekey;
pub use params::{Config, Inert, MAX_AFTER, Params, ParamsError};
pub use profile::{
    Completed, DampenAt, DoneRead, FrameHint, HsError, InitiatorCutover, Layer, Leg, Msg1Read,
    Profile, Read, ResponderCutover, Select, SessionKeys,
};
pub use proof::{Authentic, Bond, Bonded, EvidenceKind, Fresh, PeerKey, Replayable};
pub use reason::{Abandon, Attribution, Close, Reason, Teardown};
pub use record::{Digest, RECORD_BOUND, Record};
pub use resolve::{Commit, Own, Verdict, resolve};

use crate::identity::NodeAddr;
use crate::time::Duration;

/// Bytes of one handshake message, built by the profile's codec.
pub type Wire = Vec<u8>;

/// The outputs of one call, executed by the shell front to back.
pub type Outputs<P> = Vec<Output<P>>;

/// The two facts FMP's eligibility rule needs about where a msg1 arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arrival {
    /// The msg1 arrived on the peer's established link.
    pub on_link: bool,
    /// The established link is reachable.
    pub reachable: bool,
}

/// What a leg table decided a completed handshake is (next only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intent {
    /// A rekey of this machine's session.
    Rekey,
    /// A fresh dial, for link setup.
    Fresh,
    /// A declared rekey of a session the leg table does not match.
    Mismatch,
}

/// One input to [`Rekey::step`].
#[derive(Debug)]
pub enum Input<'a, P: Profile> {
    /// A reply to the own attempt: an IK msg2 routed by its receiver index,
    /// or an XK ack. `route` is the coordinates it carried.
    Reply {
        /// The message.
        bytes: &'a [u8],
        /// The coordinates the message carried.
        route: P::Route,
    },
    /// An XK msg3.
    Final {
        /// The message.
        bytes: &'a [u8],
        /// Present only for profiles that receive it.
        only: P::Fsp,
    },
    /// An XK msg1 (a setup), admitted by the shell's caps.
    Setup {
        /// The Noise msg1.
        msg1: &'a [u8],
        /// The authenticated link peer it arrived over.
        carrier: P::Carrier,
        /// The coordinates it carried.
        route: P::Route,
        /// Present only for profiles that receive it.
        only: P::Fsp,
    },
    /// An IK msg1 read at node level as this machine's peer.
    PeerMsg1 {
        /// The authenticated, replayable msg1.
        tok: Authentic<P::Msg1, Replayable>,
        /// Where it arrived.
        arrival: Arrival,
    },
    /// A peer attempt a leg table completed (next only).
    PeerDone {
        /// The authenticated completion.
        tok: Authentic<P::Done, Fresh>,
        /// What the leg table decided it is.
        intent: Intent,
    },
    /// An established frame on the slow path, lent so its plaintext can be
    /// delivered in place.
    Frame {
        /// The whole frame.
        buf: &'a mut [u8],
        /// What the shell parsed from its header.
        hint: FrameHint,
    },
    /// A decrypt worker authenticated a frame under `tag`.
    WorkerFrame {
        /// The epoch.
        tag: EpochTag,
        /// The frame's key-epoch bit.
        k: bool,
        /// The frame's counter.
        counter: u64,
        /// Present only for profiles that receive it.
        only: P::Fmp,
    },
    /// The worker accepted the receive copy of `tag`.
    Delegated {
        /// The epoch.
        tag: EpochTag,
        /// Present only for profiles that receive it.
        only: P::Fmp,
    },
    /// The worker holding `tag` is gone.
    Undelegated {
        /// The epoch.
        tag: EpochTag,
        /// Present only for profiles that receive it.
        only: P::Fmp,
    },
    /// This node wants the session, with `peer` as its key.
    Open {
        /// The peer's static key.
        peer: PeerKey,
        /// Present only for profiles that receive it.
        only: P::Fsp,
    },
    /// An application Data message was sealed.
    DataSent {
        /// Present only for profiles that receive it.
        only: P::Fsp,
    },
    /// Whether a next hop exists, and the session's smoothed round trip.
    PathFacts {
        /// A next hop exists.
        reachable: bool,
        /// The session MMP's smoothed round trip, when measured.
        srtt: Option<Duration>,
        /// Present only for profiles that receive it.
        only: P::Fsp,
    },
    /// Process deadlines and start conditions at `now`.
    Poll,
}

/// Which handshake message a `Send` carries, for the shell's framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgKind {
    /// An IK msg1.
    Msg1,
    /// An IK msg2.
    Msg2,
    /// An XK msg1, wrapped by the shell with current coordinates.
    Setup,
    /// An XK msg2.
    Ack,
    /// An XK msg3.
    Msg3,
}

/// Where a reply goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// The peer's established path, resolved when the send executes.
    Established {
        /// For a connection-oriented binding whose connection has gone,
        /// send on the connection the message being answered arrived on.
        fallback: bool,
    },
    /// The path the msg1 being answered arrived on (multipath replies).
    Arrival,
}

/// One thing the shell must do.
#[derive(Debug)]
pub enum Output<P: Profile> {
    /// Send a handshake message.
    Send {
        /// The message.
        msg: Wire,
        /// Which message it is.
        kind: MsgKind,
        /// Where it goes.
        route: Route,
    },
    /// Call [`Rekey::seal_prompt`] with `tag` now and send the result.
    Prompt {
        /// The epoch to seal under.
        tag: EpochTag,
    },
    /// Deliver the plaintext at `range` of the frame's buffer.
    Deliver {
        /// The slot the frame authenticated under.
        slot: Slot,
        /// The epoch.
        tag: EpochTag,
        /// Where the plaintext is.
        range: Range<usize>,
    },
    /// Route frames for `index` on `transport` to this machine.
    Bind {
        /// The transport the binding is made on.
        transport: P::Transport,
        /// This node's index.
        index: u32,
        /// The epoch the index belongs to; `None` for an own attempt.
        tag: Option<EpochTag>,
        /// What the index is for.
        purpose: Purpose,
    },
    /// Remove the binding of `index` on `transport`.
    Unbind {
        /// The transport recorded when the binding was made.
        transport: P::Transport,
        /// The index.
        index: u32,
    },
    /// Offer the receive half of `tag` to a decrypt worker, and report
    /// `Delegated` if the worker accepts it.
    Delegate {
        /// The epoch.
        tag: EpochTag,
        /// The transport its index is bound on.
        transport: P::Transport,
        /// Its index.
        index: u32,
        /// The receive half.
        recv: <P::Session as SessionKeys>::RecvCopy,
    },
    /// Withdraw the worker's copy of `tag`.
    Revoke {
        /// The epoch.
        tag: EpochTag,
        /// The transport its index was bound on.
        transport: P::Transport,
        /// Its index.
        index: u32,
    },
    /// Return the lease's index to the allocator.
    Release(IndexLease),
    /// An epoch became current.
    Installed {
        /// The epoch.
        tag: EpochTag,
        /// Which side of its handshake this node was.
        role: Role,
        /// What justified the install.
        evidence: EvidenceKind,
    },
    /// An epoch's keys were discarded.
    Retired {
        /// The epoch.
        tag: EpochTag,
    },
    /// An assumed epoch went back to pending.
    Reverted {
        /// The epoch.
        tag: EpochTag,
    },
    /// The peer restarted with a new startup epoch; reset the layer's
    /// per-peer state under the epoch just installed.
    PeerRestarted {
        /// The layer that saw it.
        layer: Layer,
        /// The peer's new startup epoch.
        epoch: [u8; 8],
    },
    /// A cutover happened; carried protocols may resend their state.
    Rekeyed {
        /// Which side of the handshake this node was.
        role: Role,
    },
    /// A fresh msg1 from a link too young to rekey: apply the restart gates
    /// and, if they pass, close this machine and set the peer up afresh.
    ReplaceRequested {
        /// The msg1.
        tok: Authentic<P::Msg1, Replayable>,
    },
    /// An input changed nothing (or only what its row names).
    Reject(Reason),
    /// An attempt or held epoch was given up.
    Abandoned(Abandon),
    /// Close this machine.
    Teardown(Teardown),
}

/// A source of whole-second jitter, seeded in tests.
pub trait JitterSource {
    /// A value drawn uniformly from `[0, bound]`.
    fn draw(&mut self, bound: u16) -> u16;
}

/// The capabilities and facts a call needs from the shell.
pub struct Env<'e, P: Profile> {
    /// The index allocator (FMP) or `()`.
    pub indices: &'e mut P::Indices,
    /// The transport the link uses now (FMP) or `()`.
    pub transport: P::Transport,
    /// The node-wide epoch tags.
    pub tags: &'e mut TagSource,
    /// A decrypt-worker pool exists now.
    pub workers: bool,
    /// The jitter source.
    pub jitter: &'e mut dyn JitterSource,
    /// The local static key and startup epoch.
    pub local: &'e P::LocalKeys,
    /// A buffer reused across calls for trial opens.
    pub scratch: &'e mut Vec<u8>,
}

/// What a machine built by [`Rekey::established`] cannot derive itself.
#[derive(Debug)]
pub struct SetupFacts<I> {
    /// The peer's startup epoch, read in link setup.
    pub peer_epoch: [u8; 8],
    /// The first epoch's key-epoch bit.
    pub k: bool,
    /// When the link was promoted.
    pub link_since: I,
    /// When the session started.
    pub started: I,
    /// The key-epoch bit last seen on the peer's frames, if any.
    pub peer_k: Option<bool>,
    /// The replay record.
    pub record: Record,
}

/// What [`Rekey::close`] hands back for the node's replay store and a
/// cross-connection move.
#[derive(Debug)]
pub struct Carry<I> {
    /// The peer's startup epoch.
    pub peer_epoch: [u8; 8],
    /// The current epoch's key-epoch bit.
    pub k: bool,
    /// When the current epoch started.
    pub started: I,
    /// When the link was promoted.
    pub link_since: I,
    /// The key-epoch bit last seen on the peer's frames, if any.
    pub peer_k: Option<bool>,
    /// The replay record.
    pub record: Record,
}

/// Who the machine's peer is known to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Identity {
    /// A completion authenticated this static key.
    Proven(PeerKey),
    /// An inbound first setup claimed this address; nothing has proven it.
    Claimed(NodeAddr),
}

/// What the cycle holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CycleView {
    /// No attempt.
    Idle,
    /// An own attempt in flight.
    Init,
    /// An own completed attempt, waiting as described.
    PendI(Wait),
    /// A peer's completed attempt, waiting for its first frame.
    PendR,
}

/// One held epoch, read-only.
#[derive(Debug)]
pub struct EpochView<'a, P: Profile, I> {
    /// The epoch's tag.
    pub tag: EpochTag,
    /// Its key-epoch bit.
    pub k: bool,
    /// Which side of its handshake this node was.
    pub role: Role,
    /// When it became current (or was made, for a pending epoch).
    pub started: I,
    /// Where its receive half lives.
    pub recv: RecvHome,
    /// Its per-epoch state.
    pub ext: &'a P::Ext,
}

/// The machine, read-only.
#[derive(Debug)]
pub struct View<'a, P: Profile, I> {
    /// Who the peer is known to be.
    pub identity: Identity,
    /// The peer's startup epoch.
    pub peer_epoch: Option<[u8; 8]>,
    /// The last authenticated frame from the peer under any epoch.
    pub last_rx: Option<I>,
    /// When the link was promoted (FMP).
    pub link_since: I,
    /// The current epoch; `None` while opening.
    pub current: Option<EpochView<'a, P, I>>,
    /// The epoch being drained.
    pub previous: Option<EpochView<'a, P, I>>,
    /// The pending epoch.
    pub pending: Option<EpochView<'a, P, I>>,
    /// What the cycle holds.
    pub cycle: CycleView,
    /// How many candidates are held.
    pub candidates: usize,
}

/// One index binding the machine holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding<T> {
    /// The transport recorded when it was made.
    pub transport: T,
    /// This node's index.
    pub index: u32,
    /// What it is for.
    pub purpose: Purpose,
}

/// Why a seal was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealRefusal {
    /// The session has no current epoch yet.
    NotEstablished,
    /// The epoch's send counter has reached its hard limit.
    Exhausted,
    /// The tag names no epoch a prompt may be sealed under.
    NotSealable,
}

/// What a sender needs to seal one frame: a reserved counter and a copy of
/// the send key, with the header fields the epoch fixes.
#[derive(Debug)]
pub struct Sealed<S> {
    /// The epoch sealed under.
    pub tag: EpochTag,
    /// Its key-epoch bit.
    pub k: bool,
    /// The reserved counter.
    pub counter: u64,
    /// Time since the epoch's timestamp base, for the inner header.
    pub elapsed: Duration,
    /// The peer's index, for an index-bearing profile.
    pub theirs: Option<u32>,
    /// The send key.
    pub key: S,
}

/// A prompt to seal: the counter and key, the fixed plaintext the core
/// built, and the coordinates the peer's handshake message carried, for the
/// shell to use when it has none cached.
#[derive(Debug)]
pub struct SealedPrompt<P: Profile> {
    /// The counter, key and header fields.
    pub sealed: Sealed<<P::Session as SessionKeys>::SendCopy>,
    /// The prompt plaintext.
    pub plaintext: Wire,
    /// The peer's handshake coordinates, if any.
    pub route: Option<P::Route>,
}

#[cfg(test)]
mod tests;
