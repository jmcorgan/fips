//! What the settlement core asks of the shell, run front to back.
//!
//! An [`Output::Ask`] asks the shell for an admitted msg1's answer, which
//! [`Output::Answer`] then sends. An [`Output::Install`] names the link the
//! peer holds, where the peer is
//! now, how the peer's rekey machine is built and the lease the new
//! session's index is held by; [`Output::Reset`] names the transition the
//! per-peer data takes. A teardown is an [`Output::Remove`] with its
//! reason, a link the core no longer keeps is an [`Output::Retire`] with
//! the connections the close rule closes, and every lease the core does not
//! keep comes back in an [`Output::Free`].

use alloc::vec::Vec;
use core::convert::Infallible;

use super::gates::{Refusal, Source};
use super::links::{Dir, LinkNo, Pair};
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
    /// A redial from another address replaced its link: a fresh same-epoch
    /// msg1 off the established link, answered into a pending redial and
    /// proven by the peer's first frame under it. The peer's identity-level
    /// state (its tree declaration and filter) is kept.
    Redial,
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

/// Why a msg1 or msg2 was refused. `X` is the refusal a handshake flow
/// adds ([`Flow::Deny`](super::flow::Flow::Deny)), which the IK flow, the
/// default, has none of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denial<X = Infallible> {
    /// A restart gate refused it.
    Gate(Refusal),
    /// The admission cap on answers in flight is reached.
    Full,
    /// Another redial of the identity is pending and younger than the
    /// unheard floor.
    Held,
    /// The max-peers cap is reached, and the msg1 or the completed dial
    /// is from an identity not held.
    Cap,
    /// A refusal of the table's handshake flow.
    Flow(X),
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

/// One output. `X` is the output a handshake flow adds
/// ([`Flow::Out`](super::flow::Flow::Out)) and `D` its refusal
/// ([`Flow::Deny`](super::flow::Flow::Deny)), which the IK flow, the
/// default, has none of.
#[derive(Debug, PartialEq, Eq)]
pub enum Output<X = Infallible, D = Infallible> {
    /// A dial's link, for the shell to name it by.
    Opened {
        /// The link.
        link: LinkNo,
    },
    /// The msg1 that opened `link` is admitted: authorize it, build its
    /// msg2 and draw its session index, and answer with
    /// [`Input::Hello`](super::input::Input::Hello), or refuse it with
    /// [`Input::Abandon`](super::input::Input::Abandon). Any teardown the
    /// msg1 causes comes before it.
    Ask {
        /// The link the msg1 opened.
        link: LinkNo,
        /// The identity the msg1 proves.
        peer: NodeAddr,
        /// The answer opens a leg beside the held peering, which the peer's
        /// first frame under it replaces (a redial or a restart), rather
        /// than installing at its send.
        leg: bool,
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
    /// The held peer moved onto this node's own completed dial (beside
    /// its [`Transition::Move`] reset): `own` says the link it left was one
    /// this node dialed, and `unpin` whether the move ends an operator's
    /// pin of the peer's path, which it does when the link it left was this
    /// node's own dial or the dial was made while the peer was held on the
    /// link it left.
    Swapped {
        /// The peer.
        peer: NodeAddr,
        /// The link it left was one this node dialed.
        own: bool,
        /// The move ends an operator's pin of the peer's path.
        unpin: bool,
    },
    /// The link record of `link` now says `dir` set it up; the shell's
    /// record of the link takes the same direction.
    Turned {
        /// The link.
        link: LinkNo,
        /// The end that set it up, as the record says now.
        dir: Dir,
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
        why: Denial<D>,
    },
    /// An output of the table's handshake flow.
    Flow(X),
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
