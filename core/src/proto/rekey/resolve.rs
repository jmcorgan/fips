//! The tie-break: one function decides every competing attempt.
//!
//! Both ends of a crossing evaluate this with the same inputs, which they
//! both observe (the commit point of the pattern, the state of their own
//! attempt, the two node addresses and whether the peer restarted), so they
//! name the same survivor. It runs only at authenticated events: an IK msg1
//! that read as the peer, a bonded XK msg3, or a completion handed over by a
//! leg table. A setup, forged or genuine, never reaches it.

use crate::identity::NodeAddr;

/// The state of this node's own attempt when a competing one arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Own {
    /// No own attempt.
    None,
    /// An own attempt whose reply has not authenticated (`Init`).
    Unanswered,
    /// An own attempt that completed (`PendI`, or the current epoch while
    /// its final message is still resent).
    Completed,
}

/// Where the peer's attempt commits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Commit {
    /// The responder commits when it answers msg1 (IK).
    AtAnswer,
    /// The responder commits at msg3 (XK and XX).
    AtFinal,
}

/// What this node does with its own attempt and the competing one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// No own attempt: take the competing one.
    Accept,
    /// Drop the own attempt and take the competing one.
    YieldOwn,
    /// Keep the own attempt and refuse the competing one.
    KeepOwn,
    /// Keep the own completed attempt; the competing msg1 is discarded and
    /// the peer's attempt expires.
    DiscardCompeting,
}

/// Decide between this node's attempt and the peer's.
///
/// A restarted peer always wins, because it no longer holds any epoch of
/// this node's. Otherwise a responder that commits at the answer keeps the
/// smaller node's unanswered attempt, and keeps any completed own attempt.
/// In a three-message pattern a node whose attempt is unanswered always
/// yields, since the peer cannot hold its epoch before the msg3 it has not
/// sent, and two completed attempts resolve to the smaller node's.
pub fn resolve(
    commit: Commit,
    own: Own,
    me: &NodeAddr,
    peer: &NodeAddr,
    peer_restarted: bool,
) -> Verdict {
    match (commit, own) {
        (Commit::AtAnswer | Commit::AtFinal, Own::None) => Verdict::Accept,
        (Commit::AtAnswer | Commit::AtFinal, Own::Unanswered | Own::Completed)
            if peer_restarted =>
        {
            Verdict::YieldOwn
        }
        (Commit::AtAnswer, Own::Unanswered) => smaller_keeps(me, peer),
        (Commit::AtAnswer, Own::Completed) => Verdict::DiscardCompeting,
        (Commit::AtFinal, Own::Unanswered) => Verdict::YieldOwn,
        (Commit::AtFinal, Own::Completed) if fault!(ResolveSwapped) => smaller_keeps(peer, me),
        (Commit::AtFinal, Own::Completed) => smaller_keeps(me, peer),
    }
}

/// The address order: the smaller node keeps its own attempt.
fn smaller_keeps(me: &NodeAddr, peer: &NodeAddr) -> Verdict {
    if me < peer {
        Verdict::KeepOwn
    } else {
        Verdict::YieldOwn
    }
}

#[cfg(test)]
#[path = "tests/resolve.rs"]
mod tests;
