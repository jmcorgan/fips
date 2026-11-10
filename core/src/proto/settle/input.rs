//! What the shell tells the settlement core, each built after any Noise
//! read.
//!
//! The handshake inputs carry what the shell read and what it built: a
//! msg1's identity, source, exact bytes, ephemeral and epoch, with the
//! msg2 answering it and the session index lease that msg2 names. The core
//! decides whether that answer is sent and that lease kept; a lease it does
//! not keep comes back in [`Output::Free`](super::output::Output::Free).
//!
//! A same-epoch msg1 from a held identity goes to that peer's rekey
//! machine, which keeps FRC-1201 Section 5.7 rules 3.1, 3.2 and 4.1 to
//! 4.5. The machine's replacement request, restart report and teardown
//! come back as [`Input::Replace`], [`Input::Restarted`] and
//! [`Input::Ended`]. The path inputs mirror the path bundle's outputs with
//! plain pairs.

use alloc::vec::Vec;

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
}

/// A msg1 the shell has read, and the answer it built.
#[derive(Debug, PartialEq, Eq)]
pub struct Hello {
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
    /// The msg2 that answers it.
    pub msg2: Vec<u8>,
    /// The session index that msg2 names.
    pub lease: IndexLease,
}

/// One input.
#[derive(Debug, PartialEq, Eq)]
pub enum Input {
    /// This node dials.
    Dial(Dial),
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
        /// The msg1 and its answer.
        hello: Hello,
        /// Whether the held peer's link is reachable: connectionless, or
        /// its connection still open. The shell knows its connections.
        reachable: bool,
    },
    /// The rekey machine asked for this same-epoch msg1 to replace the
    /// peering (rule 3.3), with a fresh answer.
    Replace(Hello),
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
    /// The msg2 an [`Output::Answer`](super::output::Output::Answer), or the
    /// msg1 an [`Output::Resend`](super::output::Output::Resend), asked for
    /// was sent.
    Sent {
        /// The answer's link.
        link: LinkNo,
    },
    /// That send failed; the answer is kept for the msg1's resend.
    SendFailed {
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
    },
    /// The bundle switched its active path to `to`.
    Switched {
        /// The link.
        link: LinkNo,
        /// The pair it switched to.
        to: Pair,
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
    /// A path's proven state changed.
    State {
        /// The link.
        link: LinkNo,
        /// The path's pair.
        pair: Pair,
        /// Its state now.
        proven: Proven,
    },
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
