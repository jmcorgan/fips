//! What the XX flow asks of the shell beside the table's own outputs, and
//! the refusal it adds to the table's.

use crate::identity::NodeAddr;
use crate::proto::rekey::IndexLease;
use crate::proto::settle::links::{LinkNo, Pair};

/// One output of the XX flow.
#[derive(Debug, PartialEq, Eq)]
pub enum Out {
    /// The anonymous msg1 that opened `link` needs its answer: draw a
    /// session index and build its msg2, and answer with
    /// [`In::Hello`](super::input::In::Hello), or refuse it with
    /// [`In::Refused`](super::input::In::Refused).
    Ask {
        /// The link the msg1 opened.
        link: LinkNo,
    },
    /// Send the msg3 of the dial on `link`, and feed the outcome.
    Final {
        /// The dial's link.
        link: LinkNo,
    },
    /// Send the held peer's stored setup msg2 on the connection the msg3 on
    /// `link` came over.
    Repeat {
        /// The held peer.
        peer: NodeAddr,
        /// The answer's link.
        link: LinkNo,
    },
    /// Hand the msg3 on `link`, which declares a rekey of the session held,
    /// to the peer's rekey machine with the leg's lease.
    Rekey {
        /// The peer.
        peer: NodeAddr,
        /// The answer's link.
        link: LinkNo,
        /// The lease on the leg's session index.
        lease: IndexLease,
    },
    /// Offer `pair`, where a msg2 kept beside this node's own dial
    /// authenticated the peer, to the peer's link as a heard path.
    Offer {
        /// The peer.
        peer: NodeAddr,
        /// The pair.
        pair: Pair,
    },
}

/// A refusal of the XX flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deny {
    /// A leaf node holds one peer at most, and this identity is not it.
    Leaf,
}
