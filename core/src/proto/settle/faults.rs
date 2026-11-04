//! Test-only switches, each of which turns one guard off.
//!
//! Every guard of the settlement core, and of its tests in the world, its
//! parties or its oracles, sits behind one condition, and each has a switch here that
//! removes it in a shape a real defect would take. A test that a switch
//! names must fail with the switch on and pass with none, so a guard whose
//! removal turns nothing red is itself a failure.
//!
//! The set is read once per process from the `FIPS_SETTLE_FAULTS`
//! environment variable, a comma-separated list of variant names, as the
//! rekey machine's switches are. Outside test builds the `fault!` macro is
//! the literal `false` and this module is not compiled.

use std::sync::OnceLock;
use std::vec::Vec;

/// The environment variable that names the switches a test process runs
/// with.
pub(crate) const VAR: &str = "FIPS_SETTLE_FAULTS";

/// One guard switched off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    /// Retiring a link leaves its index entries.
    IndexStale,
    /// The close rule asks only about links that peers hold, as the
    /// predicate over peers' addresses did.
    CloseByPeerAddress,
    /// The close rule asks only about other links' setup addresses.
    CloseBySetupAddress,
    /// A probing path counts as in use.
    ProbingCounts,
    /// A path released with keep is closed anyway.
    KeepIgnored,
    /// The unheard floor refuses at exactly its age as well.
    UnheardInclusive,
    /// The heard floor counts from the peering's installation only.
    HeardFromInstall,
    /// A heard peering with no frame yet has no floor.
    HeardNeedsFrame,
    /// A refusal stamps the dampener too, so its ceiling counts from the
    /// last refusal.
    DampenerFromRefusal,
    /// A restart found at this node's own msg2 goes through the floors and
    /// the dampener.
    OutboundGated,
    /// A restart found at a msg2 stamps the dampener.
    DampenerAtMsg2,
    /// The replay memory has no bound.
    ReplayUnbounded,
    /// A msg1 whose ephemeral already promoted an unheard peering is not
    /// refused for it.
    ReplaySeenIgnored,
    /// A frame forgets neither the replay memory nor the silent sessions.
    HeardKeepsMemory,
    /// The silent-session refusal starts one session early.
    SilentEarly,
    /// The silent-session refusal does not double.
    SilentFlat,
    /// The default restart interval is 10 s.
    IntervalTen,
    /// No handshake leg is reaped at its deadline.
    LegNeverReaped,
    /// A msg1 resend carries other bytes than the msg1 sent.
    ResendFresh,
    /// A responder leg does not answer a resend with its stored msg2.
    AnswerFresh,
    /// A poll acts on a timer one millisecond before it is due.
    PollAhead,
    /// A deadline is an unchecked add.
    DeadlineWraps,
    /// Closing the legs keeps one leg's lease.
    LeaseKept,
    /// A move keeps the peer's address where it was.
    MoveKeepsOldPair,
    /// A move retires nothing, so the link it leaves stays.
    MoveKeepsInboundLink,
    /// A move hands the per-peer data no reset.
    MoveNoReset,
    /// A move sets the peering heard, as the model does.
    MoveSetsHeard,
    /// An own dial completing on a held link this node dialed is judged by
    /// the tie-break alone.
    IgnoreOwnDial,
    /// At a late second dial the core keeps the link moved off, as the
    /// model keeps its fallback.
    ModelFallbackInCore,
    /// A replacement the rekey machine asks for skips the gate.
    ReplacementUngated,
    /// A msg1 counts as on the link only from the link's setup address.
    AttributeBySetupOnly,
    /// A path's move leaves its pair where it was.
    PathMoveIgnored,
    /// A switch to a new path adds nothing.
    SwitchIgnored,
    /// A released path's pair stays in the link's record.
    ReleaseKeepsPair,
    /// A path's state change is ignored.
    StateIgnored,
    /// A punched path's dial is dropped.
    PunchedDropped,
    /// A failed msg2 send reclaims its leg.
    SendFailedDropsLeg,
    /// An orphaned bundle removes nothing.
    OrphanedIgnored,
    /// The admission cap is lifted.
    CapLifted,
    /// Every start's state cap is set one depth below what it explores.
    ReachOneMore,
    /// The world keeps its flight in hash-map order.
    FlightByHash,
    /// The stub crypto opens a frame under any session.
    FrameOpensAny,
    /// A party sends no heartbeat.
    NoHeartbeat,
    /// A reply to an accepted connection opens a new connection.
    ReplyNewConn,
    /// A close sends no end-of-stream to the far end.
    EofDropped,
    /// A second dial between one BLE pair opens a second connection.
    BleSecondConn,
    /// A packet sent inside the connect window goes out at once.
    SendAtDial,
    /// What is in flight survives an advance of the clock.
    DelayUnbounded,
    /// A restart closes a connection inside its connect window and its
    /// dialer is never told.
    ConnectRefusedSilent,
    /// A party never closes an inbound connection its msg1 left unused.
    RefusedConnKept,
    /// A replacement over another connection leaves the replaced link's
    /// connection open.
    ReplacedConnKept,
    /// The world records no known shape.
    ShapeBlind,
    /// The world records a known shape at any frame or msg1 that moves or
    /// installs its receiver, stale, old or not.
    ShapeLoose,
    /// The right-link oracle checks nothing.
    RightLinkOff,
    /// The right-link oracle compares only the link's address with the
    /// peer's.
    RightLinkPairOnly,
    /// The right-link oracle has no direction clause.
    RightLinkNoDirection,
    /// The one-session oracle does not compare the two ends' sessions.
    OneSessionNoSplit,
    /// The one-session oracle does not look for an unadoptable pending.
    OneSessionNoPending,
    /// The one-session oracle does not ask whether a fresh frame opens.
    OneSessionNoFresh,
    /// The classification oracle compares the class and not the refusal.
    ClassifiedNoRefusal,
    /// The rekey side answers any msg1 while a pending is held.
    PendingAnswers,
    /// The close computed at a late second dial's resync is always empty.
    ResyncKeepsAll,
    /// The model party keeps nothing of the session a late dial moved off.
    ModelDropsFallback,
    /// An answer not yet sent is drawn only by its own msg1, byte for byte.
    StoredByBytes,
}

impl Fault {
    /// Every switch, for the name lookup and the meta-test.
    pub(crate) const ALL: &'static [Fault] = &[
        Self::IndexStale,
        Self::CloseByPeerAddress,
        Self::CloseBySetupAddress,
        Self::ProbingCounts,
        Self::KeepIgnored,
        Self::UnheardInclusive,
        Self::HeardFromInstall,
        Self::HeardNeedsFrame,
        Self::DampenerFromRefusal,
        Self::OutboundGated,
        Self::DampenerAtMsg2,
        Self::ReplayUnbounded,
        Self::ReplaySeenIgnored,
        Self::HeardKeepsMemory,
        Self::SilentEarly,
        Self::SilentFlat,
        Self::IntervalTen,
        Self::LegNeverReaped,
        Self::ResendFresh,
        Self::AnswerFresh,
        Self::PollAhead,
        Self::DeadlineWraps,
        Self::LeaseKept,
        Self::MoveKeepsOldPair,
        Self::MoveKeepsInboundLink,
        Self::MoveNoReset,
        Self::MoveSetsHeard,
        Self::IgnoreOwnDial,
        Self::ModelFallbackInCore,
        Self::ReplacementUngated,
        Self::AttributeBySetupOnly,
        Self::PathMoveIgnored,
        Self::SwitchIgnored,
        Self::ReleaseKeepsPair,
        Self::StateIgnored,
        Self::PunchedDropped,
        Self::SendFailedDropsLeg,
        Self::OrphanedIgnored,
        Self::CapLifted,
        Self::ReachOneMore,
        Self::FlightByHash,
        Self::FrameOpensAny,
        Self::NoHeartbeat,
        Self::ReplyNewConn,
        Self::EofDropped,
        Self::BleSecondConn,
        Self::SendAtDial,
        Self::DelayUnbounded,
        Self::ConnectRefusedSilent,
        Self::RefusedConnKept,
        Self::ReplacedConnKept,
        Self::ShapeBlind,
        Self::ShapeLoose,
        Self::RightLinkOff,
        Self::RightLinkPairOnly,
        Self::RightLinkNoDirection,
        Self::OneSessionNoSplit,
        Self::OneSessionNoPending,
        Self::OneSessionNoFresh,
        Self::ClassifiedNoRefusal,
        Self::PendingAnswers,
        Self::ResyncKeepsAll,
        Self::ModelDropsFallback,
        Self::StoredByBytes,
    ];

    /// The switch whose variant name is `name`.
    pub(crate) fn named(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|f| std::format!("{f:?}") == name)
    }
}

/// The switches this process runs with.
fn set() -> &'static [Fault] {
    static SET: OnceLock<Vec<Fault>> = OnceLock::new();
    SET.get_or_init(|| {
        let names = std::env::var(VAR).unwrap_or_default();
        names
            .split(',')
            .filter(|n| !n.is_empty())
            .map(|n| Fault::named(n).unwrap_or_else(|| panic!("{VAR} names no switch {n:?}")))
            .collect()
    })
}

/// Whether `fault` is on in this process.
pub(crate) fn on(fault: Fault) -> bool {
    set().contains(&fault)
}
