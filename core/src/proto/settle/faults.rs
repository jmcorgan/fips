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
    /// A setup address whose path the bundle released stays in the index.
    ReleasedSetupIndexed,
    /// A msg1 from a capable peer's setup pair, at which the bundle holds
    /// no path, counts as on the link.
    CapableIgnored,
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
    /// A frame on a peering heard already, by this node's own dial or a
    /// move, forgets the replay memory an earlier unheard peering left.
    FrameForgetsReplays,
    /// A removed session counts as silent only when its peering was
    /// unheard, so an own dial's session with no frame is not counted.
    SilentReadsHeard,
    /// A standby path's roam is marked a roam, so the core resets the peer.
    StandbyRoamResets,
    /// The gates keep a memory entry for every identity they were asked
    /// about, and never drop one whose state has lapsed.
    MemoryNeverDropped,
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
    /// A dial resend whose send failed stays due at the instant it was
    /// missed, so the next wake stays in the past.
    UnsentStaysDue,
    /// A dial resend whose send failed is due only at the wake it reports,
    /// one tick on, not at the next poll.
    UnsentDueAtWake,
    /// A dial whose last resend was sent takes a failed send reported
    /// after it as one more resend to try again.
    UnsentPastCap,
    /// A move keeps the peer's address where it was.
    MoveKeepsOldPair,
    /// A move retires nothing, so the link it leaves stays.
    MoveKeepsInboundLink,
    /// A move retires the link it leaves before the moved-onto link's
    /// record holds the msg2's pair, so it closes the connection the
    /// peering moved onto.
    MoveClosesNewPair,
    /// A move onto a pair other than the dial's own leaves the connection
    /// the dial was set up at open with no link using it.
    MoveLeavesDialOpen,
    /// A rekey answer adopted on its msg1's connection, the link's own
    /// connection having gone, leaves the link's record as this node's
    /// dial.
    AdoptedKeepsDir,
    /// A move hands the per-peer data no reset.
    MoveNoReset,
    /// A move leaves the peering unheard until the peer's first frame.
    MoveLeavesUnheard,
    /// A move that makes a peering heard keeps the replay memory of the
    /// msg1s that promoted it unheard.
    MoveKeepsReplayMemory,
    /// An own dial completing on a held link this node dialed is judged by
    /// the tie-break alone.
    IgnoreOwnDial,
    /// A crossing the tie-break alone decides keeps the peer on its inbound
    /// session at the smaller node, as at the larger.
    CrossedRunsKeep,
    /// A frame marks the peering heard without moving the instant of its
    /// last frame.
    TouchKeepsHeardInstant,
    /// A moved path's old pair stays in the link's record beside the pair
    /// it moved to.
    MovedLeavesEntry,
    /// A restarted peer's epoch, which its rekey took at the msg2 that
    /// revealed the restart, is taken only at the cutover that reports it.
    EpochAtCutover,
    /// At a late second dial the core keeps the link moved off, as the
    /// model keeps its fallback.
    ModelFallbackInCore,
    /// A replacement the rekey machine asks for skips the gate.
    ReplacementUngated,
    /// A redial's answer, once sent while the peer is held, replaces the
    /// peering at once, with no frame from the peer.
    RedialInstallsAtSent,
    /// A frame under a redial's leg is not heard: the leg replaces nothing
    /// and is reaped at its deadline.
    LegHeardIgnored,
    /// A redial skips its memory and the dampener, and records no ephemeral.
    RedialUngated,
    /// A redial is held by the heard floor, as a replacement is.
    RedialHeardFloored,
    /// A second redial replaces a pending one however young that one is.
    RedialSlotIgnored,
    /// A redial's mark outlives its leg: reaped, or installed at its send
    /// once its peer is gone.
    RedialLegKept,
    /// A redial's mark outlives its leg's install at its send once its
    /// peer is gone.
    RedialEntryKeptAtPromote,
    /// A redial's ephemeral is neither asked of the redial memory nor
    /// noted in it.
    RedialMemoryIgnored,
    /// The restart dampener does not hold a redial back.
    RedialSkipsDampener,
    /// A redial passes no slot, memory or dampener, and its answer
    /// replaces the held peer at once.
    RedialTearsDownAtMsg1,
    /// A redial's leg is never reaped.
    RedialNeverExpires,
    /// A redial the ACL passed and no session index could be drawn for
    /// leaves no mark in the redial memory.
    AuthorizedRedialUnnoted,
    /// The redial memory keeps no identity of its own: a frame of the held
    /// peering, or the lapse of the identity's other memory, drops the
    /// ephemerals that armed a redial of it.
    RedialMemoryLapses,
    /// A redial's swap installs the peer heard, forgetting its replay
    /// memory and silent sessions at the swap, rather than unheard until
    /// the frame's own `Heard`.
    RedialSwapHeard,
    /// An operator disconnect of a held peer leaves its pending redial.
    RedialKeptAtDisconnect,
    /// A redial proven by a frame from another transport than the
    /// redial's, at a pair of the held link, replaces the peering as any
    /// proof does, rather than moving the held link onto the redial's
    /// session.
    RedialProofLeavesHeldLink,
    /// A redial proven at a pair of the held link moves the held link onto
    /// the redial's session whatever transport the proof arrived on, so a
    /// peer that moved to the redial and sends from a path the held link
    /// holds on the redial's transport is kept on the link it left.
    RedialProofAnyTransport,
    /// A redial's answer given up as unsendable leaves the redial's mark.
    UnsendableKeepsRedial,
    /// A msg1 counts as on the link only from the link's setup address.
    AttributeBySetupOnly,
    /// A msg1 from the pair the core's record of the peer is at counts as
    /// on the link, and one from the setup pair whatever its path's state.
    AttributeByCurrent,
    /// A path's move leaves its pair where it was.
    PathMoveIgnored,
    /// A switch to a new path adds nothing.
    SwitchIgnored,
    /// A switch leaves the core's record of where the peer is at the path
    /// switched away from.
    SwitchLeavesPeer,
    /// A frame moves the core's record of where the peer is to its
    /// source, wherever it came from, and a path's move leaves that record
    /// where it was.
    HeardMovesPeer,
    /// A path the bundle moved at a path message, where the peer is held,
    /// resets the peer's data as a one-path roam does.
    FollowResets,
    /// A switch records the path switched to Live, whatever state the
    /// bundle holds it in.
    SwitchWritesLive,
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
    /// An orphaned bundle's peer is removed with no reconnect.
    OrphanedNoRetry,
    /// A peer removed for a restart, a replacement or an own-dial restart
    /// is removed with no reconnect.
    RestartNoRetry,
    /// A peer a redial's swap replaces is removed with no reconnect.
    RedialNoRetry,
    /// An orphaned or disconnected peer's removal closes every pair of its
    /// link no other link uses, and a disconnect guards the peer's pair.
    RemovalClosesEveryPair,
    /// The admission cap is lifted.
    CapLifted,
    /// A msg1's answer is asked for before the msg1 is classified, so a
    /// refused or rekey msg1 costs an answer too.
    AnswerBeforeAdmit,
    /// The max-peers cap counts no peer, so a new identity is admitted
    /// and installed past it.
    CapNotCounted,
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
    /// A known shape exempts any breach of convergence on its path, as the
    /// shape exemption once did, not only the split or pending it left.
    ExemptByPath,
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
    /// The close computed at a late second dial's resync is always empty.
    ResyncKeepsAll,
    /// The core's stub shell hands the core a packet's wall stamp as its
    /// instant.
    PacketStamp,
    /// An answer not yet sent is drawn only by its own msg1, byte for byte.
    StoredByBytes,
    /// An answer once sent is drawn by any msg1 from its address, not only
    /// by the msg1 it was written for.
    StoredAnswersAny,
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
    /// The join function builds the rekey machine after a
    /// cross-connection move as a new link's, keeping neither the link's
    /// age nor the replay record.
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
    /// The comparison takes a deployed release's refusal or replacement of
    /// a msg1 the model answers into a redial for a difference.
    RedialCompared,
    /// A joint node, the driver and the model of `master` do not record an
    /// armed redial's msg1 in the held link's machine, so a copy of it is
    /// judged afresh.
    RedialUnnoted,
    /// The comparison holds an address closed for good, so a redial over a
    /// connection opened to it again is a difference.
    ReopenedCompared,
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
    /// A dial's resend waits double from the first interval, whatever
    /// multiplier the node is configured with.
    BackoffDoubles,
    /// A dial's first resend comes one configured resend interval after
    /// its msg1, not the node's fixed second.
    FirstResendAtInterval,
    /// A dial's own resend cap is ignored, so a dial an mDNS advert directs
    /// at a node not configured to dial resends the configured count.
    OriginIgnored,
    /// A dial on a connection still to be opened has no link record until
    /// its msg1, so its address is in no index and in use by nothing.
    ConnectingUnlinked,
    /// A dial given up while still connecting closes the pair it dialed.
    ConnectingCloses,
    /// An answer whose msg2 could not be sent at all closes the msg1's
    /// pair when it is given up.
    UnsendableCloses,
    /// A teardown closes its link's paths by the link's records alone,
    /// not by its bundle's keep: a removal other than an orphaned bundle's,
    /// an operator disconnect's and the core's close closes none, and those
    /// and a move close every path.
    TeardownIgnoresKeep,
    /// A move onto this node's own dial ends an operator's pin of the
    /// peer's path only when the link it left was this node's dial, not
    /// when the dial was made while the peer was held on that link.
    UnpinOwnOnly,
    /// A joint node's liveness timer never fires: its party reports no
    /// link-dead deadline, so a peer silent past the link-dead timeout is
    /// kept, and a split neither end hears across is never ended.
    TimerNever,
}

impl Fault {
    /// Every switch, for the name lookup and the meta-test.
    pub(crate) const ALL: &'static [Fault] = &[
        Self::IndexStale,
        Self::CloseByPeerAddress,
        Self::CloseBySetupAddress,
        Self::ProbingCounts,
        Self::KeepIgnored,
        Self::ReleasedSetupIndexed,
        Self::CapableIgnored,
        Self::UnheardInclusive,
        Self::HeardFromInstall,
        Self::HeardNeedsFrame,
        Self::DampenerFromRefusal,
        Self::OutboundGated,
        Self::DampenerAtMsg2,
        Self::ReplayUnbounded,
        Self::ReplaySeenIgnored,
        Self::HeardKeepsMemory,
        Self::FrameForgetsReplays,
        Self::SilentReadsHeard,
        Self::StandbyRoamResets,
        Self::MemoryNeverDropped,
        Self::SilentEarly,
        Self::SilentFlat,
        Self::IntervalTen,
        Self::LegNeverReaped,
        Self::ResendFresh,
        Self::AnswerFresh,
        Self::PollAhead,
        Self::DeadlineWraps,
        Self::LeaseKept,
        Self::UnsentStaysDue,
        Self::UnsentDueAtWake,
        Self::UnsentPastCap,
        Self::MoveKeepsOldPair,
        Self::MoveKeepsInboundLink,
        Self::MoveClosesNewPair,
        Self::MoveLeavesDialOpen,
        Self::AdoptedKeepsDir,
        Self::MoveNoReset,
        Self::MoveLeavesUnheard,
        Self::MoveKeepsReplayMemory,
        Self::IgnoreOwnDial,
        Self::CrossedRunsKeep,
        Self::TouchKeepsHeardInstant,
        Self::MovedLeavesEntry,
        Self::EpochAtCutover,
        Self::ModelFallbackInCore,
        Self::ReplacementUngated,
        Self::RedialInstallsAtSent,
        Self::LegHeardIgnored,
        Self::RedialUngated,
        Self::RedialHeardFloored,
        Self::RedialSlotIgnored,
        Self::RedialLegKept,
        Self::RedialEntryKeptAtPromote,
        Self::RedialMemoryIgnored,
        Self::RedialSkipsDampener,
        Self::RedialTearsDownAtMsg1,
        Self::RedialNeverExpires,
        Self::AuthorizedRedialUnnoted,
        Self::RedialMemoryLapses,
        Self::RedialSwapHeard,
        Self::RedialKeptAtDisconnect,
        Self::RedialProofLeavesHeldLink,
        Self::RedialProofAnyTransport,
        Self::UnsendableKeepsRedial,
        Self::AttributeBySetupOnly,
        Self::AttributeByCurrent,
        Self::PathMoveIgnored,
        Self::SwitchIgnored,
        Self::SwitchLeavesPeer,
        Self::HeardMovesPeer,
        Self::FollowResets,
        Self::SwitchWritesLive,
        Self::ReleaseKeepsPair,
        Self::StateIgnored,
        Self::PunchedDropped,
        Self::SendFailedDropsLeg,
        Self::OrphanedIgnored,
        Self::OrphanedNoRetry,
        Self::RestartNoRetry,
        Self::RedialNoRetry,
        Self::RemovalClosesEveryPair,
        Self::CapLifted,
        Self::AnswerBeforeAdmit,
        Self::CapNotCounted,
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
        Self::ExemptByPath,
        Self::RightLinkOff,
        Self::RightLinkPairOnly,
        Self::RightLinkNoDirection,
        Self::OneSessionNoSplit,
        Self::OneSessionNoPending,
        Self::OneSessionNoFresh,
        Self::ClassifiedNoRefusal,
        Self::ResyncKeepsAll,
        Self::PacketStamp,
        Self::StoredByBytes,
        Self::StoredAnswersAny,
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
        Self::KeyFromView,
        Self::KeyOmitsBundle,
        Self::HeardFeedDropped,
        Self::ArrivalIgnored,
        Self::ProvenCompared,
        Self::RedialCompared,
        Self::RedialUnnoted,
        Self::ReopenedCompared,
        Self::MoveBuildsStale,
        Self::ReplaceKeepsMachine,
        Self::LeaseForgotten,
        Self::CloseSkipped,
        Self::OrphanKept,
        Self::BackoffDoubles,
        Self::FirstResendAtInterval,
        Self::OriginIgnored,
        Self::ConnectingUnlinked,
        Self::ConnectingCloses,
        Self::UnsendableCloses,
        Self::TeardownIgnoresKeep,
        Self::UnpinOwnOnly,
        Self::TimerNever,
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
/// core behind this test-only selection, which the candidates' scripted
/// tests make; comparing it with the core's own rule across the starts is
/// left to a later decision. No candidate reaches a non-test build.
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
