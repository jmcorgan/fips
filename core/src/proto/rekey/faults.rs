//! Test-only switches, each of which turns one guard of the machine off.
//!
//! Every enforcement the machine makes sits behind one function or one
//! condition, and each has a switch here that removes it in a shape a real
//! defect would take. The meta-test in `tests/faults.rs` runs every test a
//! switch names in a child process of the test binary with that switch on,
//! and requires each to fail, so a guard whose removal turns nothing red is
//! itself a failure; it also runs the same tests with no switch and
//! requires each to pass.
//!
//! The set is read once per process from the `FIPS_REKEY_FAULTS`
//! environment variable, a comma-separated list of variant names. It lives
//! here rather than in `Params` because several guards (the bond check,
//! the tie-break, the evidence constructors, the record's bound, the
//! candidate eviction and `Params::new` itself) run where no `Params` is in
//! reach, and because the meta-test switches a guard inside tests that build
//! their own parameters. Outside test builds the `fault!` macro is the
//! literal `false` and this module is not compiled.

use std::sync::OnceLock;
use std::vec::Vec;

/// The environment variable that names the switches a test process runs
/// with.
pub(crate) const VAR: &str = "FIPS_REKEY_FAULTS";

/// One guard switched off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    /// A frame no key opens adopts the pending epoch anyway.
    GarbageAdopts,
    /// `Bond::check` accepts every remote static.
    BondAlways,
    /// A reply's epoch is compared before its static is bonded.
    BondAfterEpoch,
    /// A previous-epoch frame counts as evidence for the pending epoch.
    EvidencePrevious,
    /// `saw_old` is set by previous-epoch frames instead of current ones.
    StayedFromPrevious,
    /// `seal` hands out the pending epoch's key.
    SealPending,
    /// A probe counts as the XK initiator having moved.
    ProbeMoves,
    /// No prompt answers a probe.
    NoProbeAnswer,
    /// A revert retires the assumed epoch instead of returning it to
    /// pending.
    RevertRetires,
    /// An empty first handshake is not torn down.
    NoOpeningTeardown,
    /// A refused IK msg1 is not recorded.
    RefusalUnrecorded,
    /// The larger node keeps its attempt against a fresh eligible msg1.
    LargerKeepsOwn,
    /// A cutover on evidence keeps every candidate.
    KeepCandidatesAtCutover,
    /// `accept` drops every other candidate, newer ones included.
    AcceptDropsNewer,
    /// The larger node drops its candidates at an assumed cutover.
    LargerDropsAtAssumed,
    /// An own rekey starts while a final message is retained.
    StartWhileFin,
    /// A revert over an unanswered repair drops it without abandoning it.
    RevertWithoutAbandon,
    /// A drained-epoch frame beside a newer completed attempt reverts the
    /// assumed epoch.
    F6bPendIReverts,
    /// A drained-epoch frame beside a newer completed attempt does not
    /// mark the peer as staying.
    F6bPendINotStaying,
    /// Answering a peer's msg1 retires an open drain.
    RespondRetiresDrain,
    /// `close` drops a responder pending without recording its msg1.
    CloseSkipsRecord,
    /// Confirming a first-handshake epoch keeps every candidate.
    F4KeepsCandidates,
    /// Confirming a first-handshake epoch drops every candidate at both
    /// addresses.
    F4DropsAll,
    /// Confirming a first-handshake epoch keeps the candidates born after
    /// the install at both addresses.
    F4KeepsAtBoth,
    /// The smaller node acknowledges a new setup while it retains its
    /// final message.
    S10Fin,
    /// The smaller node acknowledges a new setup while its own attempt has
    /// completed.
    S10PendI,
    /// A restart cutover drops every candidate.
    RestartDropsCandidates,
    /// A msg3 from the peer's incarnation before a recorded restart
    /// completes its candidate.
    SkipStaleIncarnation,
    /// A reply to a resent message samples the handshake round trip.
    KarnOff,
    /// The probe grace has no cap.
    NoGraceCap,
    /// A reply to a resent setup leaves no backed-off first rung.
    NoKeptBackoff,
    /// A late pass sends a probe the confirmation deadline cannot judge.
    LateProbe,
    /// A drain shortened by evidence stays counted as unevidenced.
    ShortenedUnevidenced,
    /// A cutover on a frame keeps the retained msg3 of a delayed cutover.
    FinOutlivesLadder,
    /// No keepalive is sealed under the current epoch beside the probe.
    NoKeepalive,
    /// Keepalive-only rungs are added only late in the probe ladder.
    KeepaliveLate,
    /// The larger node sends its early first-handshake resends while it
    /// holds a candidate.
    NoHoldBack,
    /// A window refusal under one key ends the trial of the others.
    RefusalEndsTrial,
    /// The confirmation window leaves out the check interval.
    ConfirmWithoutCheck,
    /// Every epoch's timestamp base is fixed when the epoch is made.
    BaseAtCreation,
    /// `Params::new` accepts a time trigger below the jitter plus the
    /// link-age floor.
    NoLinkFloorCheck,
    /// An established session evicts a candidate for a new setup.
    EvictEstablished,
    /// A held candidate vetoes the own trigger.
    CandidateVeto,
    /// The tie-break between two completed attempts favours the larger
    /// node at one end.
    ResolveSwapped,
    /// Retiring a delegated epoch does not revoke the worker's copy.
    RetireSkipsRevoke,
    /// An epoch counts as delegated when it is offered.
    DelegatedAtOffer,
    /// A receive copy offered again after a worker loss has no floor.
    ReofferNoFloor,
    /// Previous-epoch frames extend the drain.
    DrainExtends,
    /// A cutover over an open drain drops it without retiring it.
    CutoverKeepsDrain,
    /// A restart is reported at the completion instead of the cutover.
    RestartAtCompletion,
    /// The XK initiator cuts over without waiting for evidence.
    CutoverAtProof,
    /// An initiator epoch's key-epoch bit is the inverse of its own.
    KFromOwn,
    /// Each resend extends the attempt's deadline.
    DeadlinePerRung,
    /// `Params::new` accepts a message trigger of zero.
    NoZeroMessagesCheck,
    /// A poll processes its due deadlines by kind, not instant.
    DueByKind,
    /// The confirmation deadline measures what it creates from its own
    /// instant rather than the poll's.
    AnchorAtDeadline,
    /// A revert moves the assumed epoch's session to a new allocation.
    Rebox,
    /// Every cutover resets the link-age anchor.
    LinkAgeReset,
    /// A responder pending past its hold is installed instead of retired.
    ResponderTimerCutover,
    /// A byte-identical setup is answered with a freshly written ack.
    FreshAck,
    /// An unbind names the transport of now instead of the one recorded at
    /// the binding.
    UnbindTransportNow,
    /// A frame no key opens tears the machine down.
    ForgedTeardown,
    /// A replay-window refusal is reported as an unauthenticated frame.
    ReplayAsUnauthenticated,
    /// A responder's msg2 goes on the arrival path with arrival replies
    /// off.
    ReplyOnArrival,
    /// Answering a msg1 refreshes liveness.
    RespondRefreshes,
    /// A msg3 from another static also retires the own completed epoch.
    FailedFinalRetires,
    /// Abandoning an unanswered attempt clears the trigger.
    AbandonClearsTrigger,
    /// An unevidenced drain ends at the short drain window.
    DrainReapedAtWindow,
    /// The replay record never evicts.
    RecordUnbounded,
    /// The jitter comes from a process-wide counter instead of `Env`.
    GlobalJitter,
}

impl Fault {
    /// Every switch.
    pub(crate) const ALL: &'static [Fault] = &[
        Self::GarbageAdopts,
        Self::BondAlways,
        Self::BondAfterEpoch,
        Self::EvidencePrevious,
        Self::StayedFromPrevious,
        Self::SealPending,
        Self::ProbeMoves,
        Self::NoProbeAnswer,
        Self::RevertRetires,
        Self::NoOpeningTeardown,
        Self::RefusalUnrecorded,
        Self::LargerKeepsOwn,
        Self::KeepCandidatesAtCutover,
        Self::AcceptDropsNewer,
        Self::LargerDropsAtAssumed,
        Self::StartWhileFin,
        Self::RevertWithoutAbandon,
        Self::F6bPendIReverts,
        Self::F6bPendINotStaying,
        Self::RespondRetiresDrain,
        Self::CloseSkipsRecord,
        Self::F4KeepsCandidates,
        Self::F4DropsAll,
        Self::F4KeepsAtBoth,
        Self::S10Fin,
        Self::S10PendI,
        Self::RestartDropsCandidates,
        Self::SkipStaleIncarnation,
        Self::KarnOff,
        Self::NoGraceCap,
        Self::NoKeptBackoff,
        Self::LateProbe,
        Self::ShortenedUnevidenced,
        Self::FinOutlivesLadder,
        Self::NoKeepalive,
        Self::KeepaliveLate,
        Self::NoHoldBack,
        Self::RefusalEndsTrial,
        Self::ConfirmWithoutCheck,
        Self::BaseAtCreation,
        Self::NoLinkFloorCheck,
        Self::EvictEstablished,
        Self::CandidateVeto,
        Self::ResolveSwapped,
        Self::RetireSkipsRevoke,
        Self::DelegatedAtOffer,
        Self::ReofferNoFloor,
        Self::DrainExtends,
        Self::CutoverKeepsDrain,
        Self::RestartAtCompletion,
        Self::CutoverAtProof,
        Self::KFromOwn,
        Self::DeadlinePerRung,
        Self::NoZeroMessagesCheck,
        Self::DueByKind,
        Self::AnchorAtDeadline,
        Self::Rebox,
        Self::LinkAgeReset,
        Self::ResponderTimerCutover,
        Self::FreshAck,
        Self::UnbindTransportNow,
        Self::ForgedTeardown,
        Self::ReplayAsUnauthenticated,
        Self::ReplyOnArrival,
        Self::RespondRefreshes,
        Self::FailedFinalRetires,
        Self::AbandonClearsTrigger,
        Self::DrainReapedAtWindow,
        Self::RecordUnbounded,
        Self::GlobalJitter,
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

/// A jitter draw from a process-wide counter, for the switch that breaks
/// the machine's determinism.
pub(crate) fn global_jitter(bound: u16) -> u16 {
    use core::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let n = NEXT.fetch_add(7, Ordering::Relaxed);
    n % bound.saturating_add(1)
}
