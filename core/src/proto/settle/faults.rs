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
//!
//! The candidate rules for the two settlement cases left for later
//! ([`Candidate`]) are chosen here too: by `FIPS_SETTLE_CANDIDATE` for a
//! whole process, or by a test for the stub nodes one thread builds. The
//! core runs one only when its table is built under it, and only in a
//! test build.

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
    /// The core's stub shell hands the core a packet's wall stamp as its
    /// instant.
    PacketStamp,
    /// An answer not yet sent is drawn only by its own msg1, byte for byte.
    StoredByBytes,
    /// The comparison keeps the larger node's own rekey after it yielded
    /// it at a simultaneous rekey.
    YieldKept,
    /// The comparison keeps this node's own rekey after the peering it
    /// rekeyed was removed or replaced.
    RekeyOutlivesPeer,
    /// The comparison does not count a frame under a drained session as
    /// heard.
    PreviousUnheard,
    /// The core's stub shell takes a connection the far end closed as
    /// unreachable before its end-of-stream arrives.
    ReachablePeeks,
    /// A failing seeded run is reported with its whole schedule, unshrunk.
    NoShrink,
    /// The comparison takes a silent msg1 that the rekey side named a copy
    /// or recorded, where the model names it otherwise, for a difference.
    RecordedCompared,
    /// The comparison does not cut the shadow over at the peer's frame
    /// after the rekey side cut its own rekey over there.
    FrameCutoverMissed,
    /// The core's stub shell drops a candidate rule's held session, so
    /// frames under it no longer open.
    CandidateHoldsNothing,
    /// Under the aged-link candidate, an own dial completing on an aged
    /// inbound link is judged by the tie-break alone.
    AgedTieBreak,
    /// The world's digest prints a packet's wire index in place of its
    /// bytes.
    WireByNumber,
    /// A joint node's machine after a cross-connection move is built as a
    /// new link's, keeping neither the link's age nor the replay record.
    MoveBuildsFresh,
    /// A joint node does not start the bundle again at a cross-connection
    /// move.
    RenewSkipped,
    /// A joint node's bundle is built enabled whatever its multipath
    /// setting.
    ModeIgnored,
    /// A joint node drops its rekey machine's request that a fresh msg1
    /// replace the peering, so the msg1 never reaches the restart gates.
    ReplaceDropped,
    /// A joint node does not tell the core of its bundle's one-path roam.
    PathsUnmirrored,
    /// A joint node does not tell the core of a restart its rekey machine
    /// found at its own rekey's msg2.
    RestartDropped,
    /// A joint node sends to the peer, and counts its link's use, at the
    /// core's record of where the peer is, in place of the bundle's active
    /// path.
    SendsByHeld,
    /// A joint node's state key holds what its machines show (`view` and
    /// `bindings`) in place of every field that can change.
    KeyFromView,
    /// A joint node's state key leaves out the path bundle.
    KeyOmitsBundle,
    /// A joint node does not report an authentic frame from a pair its
    /// link holds no path at to its bundle as a candidate.
    HeardFeedDropped,
    /// A joint node with multipath on sends a rekey answer on the
    /// established link, never on the msg1's arrival path.
    ArrivalIgnored,
    /// The comparison takes a msg1 on a pair the bundle holds proven,
    /// which the model reads as off the link, for a difference.
    ProvenCompared,
    /// A joint node keeps its rekey machine as it was at a
    /// cross-connection move, so the machine runs the session of the
    /// handshake moved off in place of the one moved onto.
    MoveBuildsStale,
    /// A joint node keeps the replaced peering's rekey machine at a
    /// replacement or a restart, in place of building one on the new
    /// handshake.
    ReplaceKeepsMachine,
    /// A joint node loses a lease the core hands back, without returning
    /// its index to the pool.
    LeaseForgotten,
    /// A joint node leaves a removed peer's machines in place, unclosed.
    CloseSkipped,
    /// A joint node does not tell the core that a peer's bundle was
    /// orphaned, so the core keeps a peer the node would remove.
    OrphanKept,
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
        Self::PacketStamp,
        Self::StoredByBytes,
        Self::YieldKept,
        Self::RekeyOutlivesPeer,
        Self::PreviousUnheard,
        Self::ReachablePeeks,
        Self::NoShrink,
        Self::RecordedCompared,
        Self::FrameCutoverMissed,
        Self::CandidateHoldsNothing,
        Self::AgedTieBreak,
        Self::WireByNumber,
        Self::MoveBuildsFresh,
        Self::RenewSkipped,
        Self::ModeIgnored,
        Self::ReplaceDropped,
        Self::PathsUnmirrored,
        Self::RestartDropped,
        Self::SendsByHeld,
        Self::KeyFromView,
        Self::KeyOmitsBundle,
        Self::HeardFeedDropped,
        Self::ArrivalIgnored,
        Self::ProvenCompared,
        Self::MoveBuildsStale,
        Self::ReplaceKeepsMachine,
        Self::LeaseForgotten,
        Self::CloseSkipped,
        Self::OrphanKept,
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

/// The environment variable that names the candidate rule the core's
/// stub nodes of a test process run, when a test does not choose one.
pub(crate) const CANDIDATE: &str = "FIPS_SETTLE_CANDIDATE";

/// A candidate rule for a settlement case left for later, built into the
/// core behind this test-only selection so that the explorer can compare
/// it with the core's own rule. No candidate reaches a non-test build.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Candidate {
    /// The late second dial: the dialer keeps the session it moved off
    /// decryptable, and the peer's first frame under either session
    /// settles which one it keeps.
    DialerSettle,
    /// The late second dial: a responder that replaced an unheard
    /// peering keeps the replaced session for a while, and the dialer's
    /// first frame under either settles which one it keeps; the dialer
    /// keeps the session it moved off receive-only until it hears the
    /// peer on the one it kept.
    ResponderHold,
    /// The dial on the peer's aged link: an own dial completing for a
    /// peer held through a link old enough to rekey moves onto that dial,
    /// whatever the held link's direction.
    AgedMove,
}

impl Candidate {
    /// Every candidate.
    pub(crate) const ALL: &'static [Candidate] =
        &[Self::DialerSettle, Self::ResponderHold, Self::AgedMove];

    /// The candidate whose variant name is `name`.
    pub(crate) fn named(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|c| std::format!("{c:?}") == name)
    }
}

std::thread_local! {
    /// The candidate a test chose for the stub nodes this thread builds,
    /// over the process's (see [`under_candidate`]).
    static CHOSEN: core::cell::Cell<Option<Option<Candidate>>> =
        const { core::cell::Cell::new(None) };
}

/// Run `f` with the stub nodes this thread builds running `cand` (or the
/// core's own rules, with none), whatever the process names.
#[cfg(feature = "slow-tests")]
pub(crate) fn under_candidate<T>(cand: Option<Candidate>, f: impl FnOnce() -> T) -> T {
    struct Reset(Option<Option<Candidate>>);
    impl Drop for Reset {
        fn drop(&mut self) {
            CHOSEN.with(|c| c.set(self.0));
        }
    }
    let _reset = Reset(CHOSEN.with(|c| c.replace(Some(cand))));
    f()
}

/// The candidate the stub nodes this thread builds run: the one a test
/// chose, or else the one the process names in [`CANDIDATE`]; none when
/// neither names one.
pub(crate) fn candidate() -> Option<Candidate> {
    if let Some(chosen) = CHOSEN.with(core::cell::Cell::get) {
        return chosen;
    }
    static SET: OnceLock<Option<Candidate>> = OnceLock::new();
    *SET.get_or_init(|| {
        let name = std::env::var(CANDIDATE).unwrap_or_default();
        (!name.is_empty()).then(|| {
            Candidate::named(&name)
                .unwrap_or_else(|| panic!("{CANDIDATE} names no candidate {name:?}"))
        })
    })
}
