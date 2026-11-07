//! What the settlement core asks of the shell, run front to back.
//!
//! An [`Output::Install`] names the link the peer holds, where the peer is
//! now, how the peer's rekey machine is built and the lease the new
//! session's index is held by; [`Output::Reset`] names the transition the
//! per-peer data takes. A teardown is an [`Output::Remove`] with its
//! reason, a link the core no longer keeps is an [`Output::Retire`] with
//! the connections the close rule closes, and every lease the core does not
//! keep comes back in an [`Output::Free`].

use alloc::vec::Vec;

use super::gates::{Refusal, Source};
use super::links::{LinkNo, Pair};
use crate::identity::NodeAddr;
use crate::proto::rekey::{Arrival, IndexLease};

/// How the peer's rekey machine is built at an install.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Build {
    /// From the handshake that completed.
    Fresh,
    /// From what the closed machine carried: a move keeps the link's age,
    /// the session's start and the replay record.
    FromCarry,
}

/// The ways a peer's link, session or existence changes that the core
/// decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition {
    /// A peer installed for an identity not held.
    Promote,
    /// The held peer torn down and a new one installed.
    Replace,
    /// The peer moved onto this node's own completed dial.
    Move,
    /// The larger node of a crossing kept its inbound handshake.
    Keep,
    /// A restart revealed at a rekey; the link is kept.
    Restarted,
    /// An authenticated frame moved the peer's address.
    Roam,
}

/// Why a peer was removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// A msg1 at a new epoch replaced it (rule 2).
    Restart,
    /// A same-epoch msg1 replaced it (rule 3.3).
    Replacement,
    /// This node's own dial found it restarted.
    OwnRestart,
    /// Its rekey machine tore it down.
    Ended,
    /// Its path bundle has no path left.
    Orphaned,
    /// It sent a `Disconnect`.
    Disconnect,
    /// Its link was declared dead.
    Dead,
    /// The operator disconnected it.
    Admin,
    /// The core was closed.
    Closed,
}

/// Why a msg1 or msg2 was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denial {
    /// A restart gate refused it.
    Gate(Refusal),
    /// The admission cap on answers in flight is reached.
    Full,
}

/// A peer installed.
#[derive(Debug, PartialEq, Eq)]
pub struct Install {
    /// The peer.
    pub peer: NodeAddr,
    /// The link it holds.
    pub link: LinkNo,
    /// Where it is now.
    pub pair: Pair,
    /// How its rekey machine is built.
    pub rekey: Build,
    /// This node started the handshake that completed.
    pub initiator: bool,
    /// The lease the new session's index is held by.
    pub lease: IndexLease,
}

/// One output.
#[derive(Debug, PartialEq, Eq)]
pub enum Output {
    /// A dial's link, for the shell to name it by.
    Opened {
        /// The link.
        link: LinkNo,
    },
    /// Send this msg2 on `link`. `stored` says it is the one already
    /// built for that msg1, sent again.
    Answer {
        /// The link it answers on.
        link: LinkNo,
        /// The msg2.
        msg2: Vec<u8>,
        /// It was stored.
        stored: bool,
    },
    /// Send this dial's msg1 again, byte for byte.
    Resend {
        /// The dial's link.
        link: LinkNo,
        /// The msg1.
        bytes: Vec<u8>,
    },
    /// Hand the msg1 to the peer's rekey machine, with where it arrived.
    Rekey {
        /// The peer.
        peer: NodeAddr,
        /// Whether it is on the established link, and that link's reach.
        arrival: Arrival,
    },
    /// Install the peer.
    Install(Install),
    /// The per-peer data takes this transition.
    Reset {
        /// The peer.
        peer: NodeAddr,
        /// The transition.
        transition: Transition,
    },
    /// Tear the peer down.
    Remove {
        /// The peer.
        peer: NodeAddr,
        /// Why.
        why: Why,
    },
    /// The core no longer keeps `link`; close these connections.
    Retire {
        /// The link.
        link: LinkNo,
        /// The connections to close.
        closes: Vec<Pair>,
    },
    /// A path of `link` was released; close these connections.
    Release {
        /// The link.
        link: LinkNo,
        /// The connections to close.
        closes: Vec<Pair>,
    },
    /// Close these connections; no link uses them any more.
    Close {
        /// The connections to close.
        closes: Vec<Pair>,
    },
    /// Give this lease back to the allocator.
    Free {
        /// The lease.
        lease: IndexLease,
    },
    /// Schedule a reconnect to the peer.
    Retry {
        /// The peer.
        peer: NodeAddr,
    },
    /// The msg1 or msg2 is refused.
    Reject {
        /// The identity, when the input proved one.
        peer: Option<NodeAddr>,
        /// What asked the gate, for a gate's refusal.
        source: Option<Source>,
        /// Why.
        why: Denial,
    },
    /// Test-only, for a candidate rule: keep the session of `link`, the
    /// one the peer held until now, decryptable beside the one it holds
    /// next, until an [`Output::Settle`] ends it.
    #[cfg(test)]
    Hold {
        /// The peer.
        peer: NodeAddr,
        /// The link whose session is kept.
        link: LinkNo,
    },
    /// Test-only, for a candidate rule: the session kept for `link` is
    /// held no longer. With `back` the peer is on that session again and
    /// the one it held is dropped; otherwise the kept one is dropped.
    #[cfg(test)]
    Settle {
        /// The peer.
        peer: NodeAddr,
        /// The link whose session was kept.
        link: LinkNo,
        /// The peer is back on the kept session.
        back: bool,
    },
}
