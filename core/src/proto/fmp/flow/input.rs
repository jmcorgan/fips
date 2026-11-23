//! What the shell tells the XX flow, each fed after any Noise read, as the
//! table's own inputs are.
//!
//! An XX msg1 proves no identity and carries no epoch, so it opens an
//! anonymous answer ([`In::Anon`]) that no gate or cap judges. The
//! identity and epoch arrive at msg2 for this node's own dial
//! ([`In::Msg2`]) and at msg3 for an answer ([`In::Msg3`]). A dial may
//! name no one ([`In::AnonDial`]), as next's shared-media discovery dials.
//! The msg2 decision waits for the outcome of the msg3 send
//! ([`In::FinalSent`], [`In::FinalFailed`]), which the shell feeds within
//! the same handler call. A refusal the shell makes itself, by the ACL, the
//! self check, a failed msg3 read or a session index it could not draw,
//! ends the leg at once ([`In::Refused`]); a failure at msg2 marks it for
//! the next sweep ([`In::Failed`], [`In::Sweep`]).

use alloc::vec::Vec;

use crate::identity::NodeAddr;
use crate::proto::fmp::{EphemeralDigest, RekeyClaim};
use crate::proto::rekey::IndexLease;
use crate::proto::settle::gates::Epoch;
use crate::proto::settle::links::{LinkNo, Pair};

/// An XX msg1, read: its ephemeral and nothing that names its sender.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anon {
    /// Its source.
    pub from: Pair,
    /// Its exact bytes.
    pub bytes: Vec<u8>,
    /// Its ephemeral.
    pub ephemeral: EphemeralDigest,
    /// The link of an established peer at its source (next's `rekey_of`).
    /// The shell computes it and keeps its own map of it for the moved-msg3
    /// lookup (`src/node/handlers/handshake.rs`, `src/node/settle/maps.rs`);
    /// the flow reads it only in `AnonLegNamed`'s defect shape.
    pub rekey_of: Option<LinkNo>,
}

/// This node's dial that names no peer: its msg2 supplies the identity.
#[derive(Debug, PartialEq, Eq)]
pub struct AnonDial {
    /// The address dialed.
    pub to: Pair,
    /// The msg1 sent, byte for byte.
    pub msg1: Vec<u8>,
    /// The session index the msg1 names.
    pub lease: IndexLease,
    /// A cap on this dial's resends below the configured count, or `None`
    /// for the configured count.
    pub resends: Option<u32>,
    /// The link an [`In::AnonConnecting`] opened for this dial, or `None`
    /// for a dial with no connection to open first.
    pub link: Option<LinkNo>,
}

/// One input of the XX flow.
#[derive(Debug, PartialEq, Eq)]
pub enum In {
    /// An XX msg1, read: its link opens inbound, and the shell is asked to
    /// draw a session index and build the msg2
    /// ([`Out::Ask`](super::output::Out::Ask)).
    Anon(Anon),
    /// The answer the shell built for an anonymous msg1: its leg opens,
    /// naming no peer, and the msg2 goes out.
    Hello {
        /// The link the ask named.
        link: LinkNo,
        /// The msg2 that answers the msg1.
        msg2: Vec<u8>,
        /// The session index that msg2 names.
        lease: IndexLease,
    },
    /// This node dials and names no one.
    AnonDial(AnonDial),
    /// This node dials and names no one, on a connection it must open
    /// first: the link opens now, with no leg until the
    /// [`In::AnonDial`] that names it.
    AnonConnecting {
        /// The address dialed.
        to: Pair,
        /// A cap on the dial's resends below the configured count.
        resends: Option<u32>,
    },
    /// The connection an anonymous dial waited on could not be opened.
    AnonConnectFailed {
        /// The dial's link.
        link: LinkNo,
    },
    /// The msg2 of this node's own dial, authenticated, and the identity it
    /// taught, which the shell has checked against the identity the dial
    /// named, if it named one.
    Msg2 {
        /// The dial's link.
        link: LinkNo,
        /// The epoch it carries.
        epoch: Epoch,
        /// Its source.
        from: Pair,
        /// The identity the msg2 taught.
        peer: NodeAddr,
    },
    /// The msg3 an [`Out::Final`](super::output::Out::Final) asked for was
    /// sent, or its transport was gone, which next promotes on too.
    FinalSent {
        /// The dial's link.
        link: LinkNo,
    },
    /// That send failed: nothing is installed, and the leg fails.
    FinalFailed {
        /// The dial's link.
        link: LinkNo,
    },
    /// Completing the msg2, or its negotiation, failed: the leg is reaped
    /// at the next [`In::Sweep`], which asks for a retry of the identity
    /// next's stale sweep reads, the one the leg expects by then.
    Failed {
        /// The dial's link.
        link: LinkNo,
        /// The identity the leg's completion learned from the msg2 before
        /// the failure, which next's leg then expects in place of the one
        /// dialed, or `None` when it learned none.
        learned: Option<NodeAddr>,
    },
    /// The shell refused the handshake on `link`: the leg and its link go
    /// at once, with no close in the retire, since the node closes the
    /// connection by its own rule, and `retry` is asked for when it names
    /// someone.
    Refused {
        /// The leg's link.
        link: LinkNo,
        /// The identity to reconnect to, if any.
        retry: Option<NodeAddr>,
    },
    /// An anonymous answer's msg3, read, negotiated and past the ACL.
    Msg3 {
        /// The answer's link.
        link: LinkNo,
        /// The identity it proves.
        peer: NodeAddr,
        /// The epoch it carries.
        epoch: Epoch,
        /// The session its negotiation says it replaces, as the shell
        /// resolved it against the session held.
        claim: RekeyClaim,
        /// Its source.
        from: Pair,
    },
    /// The shell's sweep: every failed leg is reaped.
    Sweep,
    /// The node's timers run, before the table's poll at the same instant:
    /// each dial past its deadline asks for a retry of the identity it
    /// expects, as next's handshake timeout does; the poll then reaps it.
    Due,
    /// The node's timer reaps its dial on `link`, past its deadline or
    /// failed: the dial asks for a retry of the identity it expects by
    /// then, as [`In::Due`] has each dial past its deadline ask, for a
    /// shell whose timers reap one dial at a time, as next's do.
    Timed {
        /// The dial's link.
        link: LinkNo,
    },
    /// The connection a dial waited on could not be opened, and the shell
    /// names the identity the dial named, if it named one: the link goes,
    /// closing nothing, and an identified dial asks for its retry, as next
    /// does at a failed connect.
    Unconnected {
        /// The dial's link.
        link: LinkNo,
        /// The identity the dial named, if any.
        retry: Option<NodeAddr>,
    },
    /// The shell stops the msg1 resends of its dial on `link`, which is
    /// left to its deadline: the msg2 completed, the peer is held through
    /// another link, or the dial's own state rules out a resend, as next's
    /// timer driver decides.
    Quiet {
        /// The dial's link.
        link: LinkNo,
    },
}
