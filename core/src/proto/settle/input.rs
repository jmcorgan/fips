//! What the shell tells the settlement core, each built after any Noise
//! read.
//!
//! A msg1 arrives in two steps, as the current node takes it. The shell
//! hands over what it read (the identity, source, exact bytes, ephemeral
//! and epoch), and the core classifies it and runs any teardown first. Only
//! an admitted msg1 draws an
//! [`Output::Ask`](super::output::Output::Ask), and only then does the
//! shell authorize it, draw a session index and build the msg2, which it
//! returns as [`Input::Hello`], or refuse it with [`Input::Abandon`]. So a
//! refused or rekey msg1 costs no msg2 and draws no index. A lease the core
//! does not keep comes back in
//! [`Output::Free`](super::output::Output::Free).
//!
//! A same-epoch msg1 from a held identity goes to that peer's rekey
//! machine, which keeps FRC-1201 Section 5.7 rules 3.1, 3.2 and 4.1 to
//! 4.5. The machine's replacement request, redial request, restart report
//! and teardown come back as [`Input::Replace`], [`Input::Redial`],
//! [`Input::Restarted`] and [`Input::Ended`]. A frame that authenticates
//! under a redial's answer, which no peer holds yet, comes back as
//! [`Input::LegHeard`]. The path inputs mirror the path bundle's outputs with
//! plain pairs, and its finding that the peer is capable.

use alloc::vec::Vec;
use core::convert::Infallible;

use super::gates::Epoch;
use super::links::{LinkNo, Pair, Proven};
use crate::identity::NodeAddr;
use crate::proto::fmp::EphemeralDigest;
use crate::proto::rekey::IndexLease;

/// This node's own initial dial.
#[derive(Debug, PartialEq, Eq)]
pub struct Dial {
    /// The identity dialed.
    pub peer: NodeAddr,
    /// The address dialed.
    pub to: Pair,
    /// The msg1 sent, byte for byte.
    pub msg1: Vec<u8>,
    /// The session index the msg1 names.
    pub lease: IndexLease,
    /// A cap on this dial's resends below the configured count, or `None`
    /// for the configured count (see `legs::Start::resends`).
    pub resends: Option<u32>,
    /// The link an [`Input::Connecting`] opened for this dial, or `None`
    /// for a dial with no connection to open first, whose link opens here.
    /// A dial on a link a `Connecting` opened takes that input's peer and
    /// resend cap, not the ones here.
    pub link: Option<LinkNo>,
}

/// A msg1 the shell has read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Read {
    /// The identity the msg1 proves.
    pub peer: NodeAddr,
    /// Its source.
    pub from: Pair,
    /// Its exact bytes.
    pub bytes: Vec<u8>,
    /// Its ephemeral.
    pub ephemeral: EphemeralDigest,
    /// The epoch it carries.
    pub epoch: Epoch,
}

/// The answer the shell built for an
/// [`Output::Ask`](super::output::Output::Ask).
#[derive(Debug, PartialEq, Eq)]
pub struct Hello {
    /// The link the ask named.
    pub link: LinkNo,
    /// The msg2 that answers the msg1.
    pub msg2: Vec<u8>,
    /// The session index that msg2 names.
    pub lease: IndexLease,
}

/// One input. `X` is the input a handshake flow adds
/// ([`Flow::In`](super::flow::Flow::In)), which the IK flow, the default,
/// has none of.
#[derive(Debug, PartialEq, Eq)]
pub enum Input<X = Infallible> {
    /// This node dials, with its msg1 built.
    Dial(Dial),
    /// This node dials on a connection it must open first, and builds its
    /// msg1 only once the connection is up: the link opens now, with no
    /// leg, so the index names its address and the close rule counts it in
    /// use, as the node's link and index entry exist from the dial. The
    /// [`Input::Dial`] that follows names the link; an
    /// [`Input::ConnectFailed`] retires it.
    Connecting {
        /// The identity dialed.
        peer: NodeAddr,
        /// The address dialed.
        to: Pair,
        /// A cap on the dial's resends below the configured count, or
        /// `None` for the configured count.
        resends: Option<u32>,
    },
    /// A hole punch opened a path to the peer, and this node dials on it.
    Punched(Dial),
    /// The connection a dial waited on could not be opened, or the dial
    /// was abandoned.
    ConnectFailed {
        /// The dial's link.
        link: LinkNo,
    },
    /// A msg1 arrived, before any Diffie-Hellman: a resend of a stored
    /// answer's msg1 is answered from here, and a msg1 past the admission
    /// cap is refused.
    Arrived {
        /// Its source.
        from: Pair,
        /// Its exact bytes.
        bytes: Vec<u8>,
    },
    /// A msg1, read.
    Msg1 {
        /// The msg1.
        read: Read,
        /// Whether the held peer's link is reachable: connectionless, or
        /// its connection still open. The shell knows its connections.
        reachable: bool,
    },
    /// The rekey machine asked for this same-epoch msg1 to replace the
    /// peering (rule 3.3).
    Replace(Read),
    /// The rekey machine asked for this fresh same-epoch msg1, which arrived
    /// off the held peer's established link, to be answered into a redial
    /// (operator decision, 2026-11-17). The held peer is left as it is. An
    /// admitted redial is asked for its answer as any msg1 is; when the
    /// [`Input::Hello`] that follows draws a fresh
    /// [`Output::Answer`](super::output::Output::Answer), the shell records
    /// the msg1's ephemeral in the held link's machine
    /// (`Rekey::note_redial`), so a copy of it is a copy from then on; the
    /// shell records it there too when the ACL passed the redial and no
    /// session index could be drawn for its answer
    /// ([`Input::Abandon`]'s `authorized`).
    Redial(Read),
    /// A frame authenticated under the answer on `link`, a redial's leg
    /// that no peer holds, from `from`: the peer holds the redial's keys.
    /// The trial open leaves the replay window as it was; the shell hands
    /// the frame to the peer installed here afterwards.
    LegHeard {
        /// The leg's link.
        link: LinkNo,
        /// The frame's source.
        from: Pair,
    },
    /// The answer to an admitted msg1, which opens its responder leg.
    Hello(Hello),
    /// The shell refused an admitted msg1 after the core asked for its
    /// answer: the link the msg1 opened is retired, and no leg or lease
    /// was ever taken for it.
    Abandon {
        /// The link the ask named.
        link: LinkNo,
        /// The ACL passed the msg1 and the refusal came after it, at the
        /// session index's draw: a redial's ephemeral goes into the redial
        /// memory as an answered redial's does, as the node notes it once
        /// the ACL has passed it.
        authorized: bool,
    },
    /// The msg2 of this node's own dial, authenticated.
    Msg2 {
        /// The dial's link.
        link: LinkNo,
        /// The epoch it carries.
        epoch: Epoch,
        /// Its source.
        from: Pair,
    },
    /// The rekey machine found the peer restarted to `epoch` at its own
    /// rekey's msg2; the link is kept.
    Restarted {
        /// The peer.
        peer: NodeAddr,
        /// Its new epoch.
        epoch: Epoch,
    },
    /// The peer's link rekey took `epoch` as the peer's, at the rekey whose
    /// msg2 revealed the peer's restart, before the cutover reports the
    /// restart ([`Input::Restarted`]): the peer is held at that epoch from
    /// here, as its rekey judges what the peer sends.
    PeerEpoch {
        /// The peer.
        peer: NodeAddr,
        /// The epoch its rekey took.
        epoch: Epoch,
    },
    /// The rekey machine tore the peering down.
    Ended {
        /// The peer.
        peer: NodeAddr,
    },
    /// The path bundle has no path left.
    Orphaned {
        /// The peer.
        peer: NodeAddr,
    },
    /// A frame from the peer authenticated, from `from`.
    Heard {
        /// The peer.
        peer: NodeAddr,
        /// Its source.
        from: Pair,
        /// Its link message type, which says whether the frame shows the
        /// path the peer sends on.
        kind: u8,
    },
    /// The peer sent a `Disconnect`.
    Disconnect {
        /// The peer.
        peer: NodeAddr,
    },
    /// The peer's link was declared dead.
    Dead {
        /// The peer.
        peer: NodeAddr,
    },
    /// The operator disconnected the peer.
    Admin {
        /// The peer.
        peer: NodeAddr,
    },
    /// A frame of the held peer authenticated under the session its rekey
    /// machine answered a msg1 into, where that answer went out on the
    /// connection the msg1 arrived on because the link's own connection
    /// had gone (FRC-1201 Section 5.7): the peer opened that connection,
    /// and the link now runs on it.
    Adopted {
        /// The peer.
        peer: NodeAddr,
    },
    /// The msg2 an [`Output::Answer`](super::output::Output::Answer), or the
    /// msg1 an [`Output::Resend`](super::output::Output::Resend), asked for
    /// was sent.
    Sent {
        /// The answer's link.
        link: LinkNo,
    },
    /// That send failed. An answer is kept for the msg1's resend; a dial's
    /// msg1 resend is tried again at the next poll.
    SendFailed {
        /// The answer's or the dial's link.
        link: LinkNo,
    },
    /// The msg2 an [`Output::Answer`](super::output::Output::Answer) asked
    /// for could not be sent, for a cause no resend outlasts: the answer is
    /// given up, its lease returned and its link retired, and no connection
    /// is closed.
    Unsendable {
        /// The answer's link.
        link: LinkNo,
    },
    /// A path of `link` moved from one pair to another.
    Moved {
        /// The link.
        link: LinkNo,
        /// The pair it left.
        from: Pair,
        /// The pair it is at now.
        to: Pair,
        /// The move is a roam of the link's one path, which FMP v1's
        /// address rule makes at an authentic frame and the shell reports
        /// itself; otherwise the bundle moved the path at a path message
        /// attributed to it, as it does once the link holds more than its
        /// original path.
        roam: bool,
    },
    /// The bundle switched its active path to `to`.
    Switched {
        /// The link.
        link: LinkNo,
        /// The pair it switched to.
        to: Pair,
        /// That path's state as the bundle holds it after the switch: an
        /// acknowledged path the bundle hands over to need not be Live.
        proven: Proven,
    },
    /// The bundle released its path at `pair`; `keep` says the peer may
    /// still send there.
    Released {
        /// The link.
        link: LinkNo,
        /// The released pair.
        pair: Pair,
        /// Whether to keep its connection open.
        keep: bool,
    },
    /// The bundle found the peer capable of multipath (draft Section 5.2).
    /// It stays capable for the life of the link: a new link's bundle,
    /// and a bundle renewed at a move, start not capable.
    Capable {
        /// The link.
        link: LinkNo,
    },
    /// A path's proven state changed.
    State {
        /// The link.
        link: LinkNo,
        /// The path's pair.
        pair: Pair,
        /// Its state now.
        proven: Proven,
    },
    /// An input of the table's handshake flow, which the flow classifies
    /// ([`Flow::step`](super::flow::Flow::step)).
    Flow(X),
    /// Test-only, for a candidate rule: a frame of `peer` authenticated
    /// under the session an [`Output::Hold`](super::output::Output::Hold)
    /// kept.
    #[cfg(test)]
    HeldFrame {
        /// The peer.
        peer: NodeAddr,
        /// Its source.
        from: Pair,
    },
    /// Test-only, for a candidate rule: the connection of the link whose
    /// session is kept for `peer` is gone.
    #[cfg(test)]
    HoldLost {
        /// The peer.
        peer: NodeAddr,
    },
}
