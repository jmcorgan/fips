//! Why an input was refused, an attempt or epoch given up, or a machine
//! ended.
//!
//! Every discarded input emits `Output::Reject` with a reason of its own, so
//! a counter per reason tells the causes apart. Each reason says who it is
//! attributed to, so a fault of this node is never counted against the peer,
//! and whether input that has not authenticated can cause it, so the shell
//! can log those at a bounded rate while counting every one.

/// Who an outcome is attributed to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attribution {
    /// The authenticated peer did it.
    Peer,
    /// Anyone could have sent it: the input did not authenticate, or it is
    /// a copy of a message that did, delivered again.
    Network,
    /// This node: its own resources, configuration or bookkeeping.
    Local,
}

/// Why an input changed nothing (or, where its row says so, only the
/// candidate list or the replay record).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// An IK msg1 carried a startup epoch other than the peer's.
    EpochChanged,
    /// A copy of a msg1 the replay record holds.
    AnsweredBefore,
    /// An eligible msg1 arrived off the established link while the link
    /// was reachable.
    OffLink,
    /// A msg1 met a pending epoch in either role.
    PendingHeld,
    /// A fresh msg1 lost the crossing to this node's unanswered attempt.
    DualInitWon,
    /// No session index was free.
    IndexExhausted,
    /// A handshake message could not be written locally.
    HandshakeWrite,
    /// A reply failed its read on the attempt's fork, or read as another
    /// static.
    ReplyUnauthenticated,
    /// A reply for an attempt that has already completed.
    LateReply,
    /// A reply with no attempt to answer.
    UnknownAttempt,
    /// A reply naming an index this machine does not hold.
    UnknownIndex,
    /// A setup that failed validation.
    SetupMalformed,
    /// The tie-break kept this node's own attempt.
    TieBreakKept,
    /// A setup found the candidate list full.
    CandidatesFull,
    /// A msg3 with no candidate to complete.
    FinalNoAttempt,
    /// A msg3 that no candidate's fork could read.
    FinalUnauthenticated,
    /// A completed handshake or a wanted key named another static.
    KeyMismatch,
    /// A msg3 from the peer's incarnation before a restart this node
    /// recorded.
    StaleIncarnation,
    /// A frame whose counter the epoch's replay window refused.
    Replay,
    /// A frame no held key authenticated.
    FrameUnauthenticated,
    /// A frame whose plaintext is shorter than the layer's floor.
    ShortPlaintext,
    /// A frame for an epoch a decrypt worker holds.
    DelegatedEpoch,
    /// A frame or completion before the session is established.
    NotEstablished,
    /// A report names an epoch this machine no longer holds.
    StaleTag,
    /// A report names an epoch that is not delegated.
    NotDelegated,
    /// A worker accepted an epoch that was already delegated.
    AlreadyDelegated,
    /// A worker accepted the pending epoch, which is never offered.
    NotOffered,
    /// `Open` while the own first attempt is in flight.
    AttemptInFlight,
    /// `Open` on an established session.
    AlreadyEstablished,
    /// A candidate reached its deadline.
    CandidateExpired,
    /// A completion handed over with an intent other than a rekey.
    NotRekey,
}

impl Reason {
    /// Who the outcome is attributed to.
    pub fn attribution(self) -> Attribution {
        match self {
            Self::IndexExhausted
            | Self::HandshakeWrite
            | Self::StaleTag
            | Self::NotDelegated
            | Self::AlreadyDelegated
            | Self::NotOffered
            | Self::AttemptInFlight
            | Self::AlreadyEstablished
            | Self::NotRekey
            | Self::DelegatedEpoch => Attribution::Local,
            Self::EpochChanged
            | Self::PendingHeld
            | Self::DualInitWon
            | Self::TieBreakKept
            | Self::StaleIncarnation
            | Self::ShortPlaintext => Attribution::Peer,
            // A replayed msg1 arrives off the link as readily as a genuine
            // one, and any third party can complete a candidate with its
            // own static, so neither says anything about the peer.
            Self::OffLink
            | Self::KeyMismatch
            | Self::AnsweredBefore
            | Self::ReplyUnauthenticated
            | Self::LateReply
            | Self::UnknownAttempt
            | Self::UnknownIndex
            | Self::SetupMalformed
            | Self::CandidatesFull
            | Self::FinalNoAttempt
            | Self::FinalUnauthenticated
            | Self::Replay
            | Self::FrameUnauthenticated
            | Self::NotEstablished
            | Self::CandidateExpired => Attribution::Network,
        }
    }

    /// Whether input that has not authenticated can cause this outcome, so
    /// the shell logs it at a bounded rate while it counts every one.
    pub fn unauthenticated_reachable(self) -> bool {
        match self.attribution() {
            Attribution::Network => true,
            Attribution::Peer | Attribution::Local => matches!(self, Self::TieBreakKept),
        }
    }
}

/// Why an own attempt or a held epoch was given up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Abandon {
    /// A drain reached its ceiling with no frame showing the peer moved.
    AdoptionNotSeen,
    /// A responder pending reached its hold with no frame adopting it.
    Unadopted,
    /// At the confirmation deadline the peer was heard staying on its old
    /// epoch.
    PeerStayedOnOld,
    /// A reverted epoch reached the end of its window unconfirmed.
    RevertUnconfirmed,
    /// The own attempt reached its deadline unanswered.
    Unanswered,
    /// The tie-break gave the peer's attempt precedence.
    Yielded,
    /// A previous-epoch frame reverted an assumed cutover while a repair was
    /// unanswered.
    Reverted,
    /// A responder pending was replaced by a newer completion of the peer.
    Superseded,
    /// The machine was closed.
    Closed(Close),
}

/// Why the shell must close the machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Teardown {
    /// A first handshake with no attempt and no candidate left.
    OpeningIdle,
    /// A first handshake whose own attempt failed with no candidate left.
    OpeningFailed,
    /// The current epoch's send counter reached its hard limit.
    CounterExhausted,
}

/// Why the shell closed a machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Close {
    /// The peer restarted, seen at node level.
    Restart,
    /// The peer sent a Disconnect.
    Disconnect,
    /// The link was declared dead.
    LinkDead,
    /// The session was idle too long.
    IdlePurge,
    /// An operator removed the peer.
    Admin,
    /// The peer moved to the winning session of a cross-connection.
    CrossConnectionMove,
    /// The machine asked to be torn down while opening.
    OpeningTeardown,
    /// The node is shutting down.
    Shutdown,
}

#[cfg(test)]
#[path = "tests/reason.rs"]
mod tests;
