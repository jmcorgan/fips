//! Sans-IO probe stage machine.
//!
//! Pure, runtime-agnostic decisions for the `probe` diagnostic: which stage is
//! current, whether its budget has expired, whether the probe owns the session
//! it is about to tear down, and what the overall verdict is. The async driver
//! in `node::handlers::probe` builds a plain-data [`Observation`] (every clock
//! read pre-resolved into `u64`, every map read into `bool`/`Option`), calls
//! [`Probe::step`], and performs the returned [`ProbeAction`]s. No I/O, no
//! clock, no logging here.
//!
//! Time enters in three ways and is never read inside the core: `now_ms` on
//! every observation, the budgets computed once by the shell from config, and
//! the four MMP report counters — which are *counters* rather than timestamps
//! precisely so the core need not reason about when a report arrived.

use super::limits::{
    BLOOM_MIN_TICKS, RESOLVE_SLACK_TICKS, RTT_FLOOR_MS, RTT_MIN_TICKS, SESSION_FLOOR_MS,
    SESSION_MIN_TICKS, TEARDOWN_GRACE_TICKS, WARMUP_RETRY_MS,
};
use super::state::{
    FailKind, LeftIntact, LookupOutcomeKind, NextHopFacts, NoHopReason, Overall, PathFacts,
    Preflight, ProbeSnapshot, ResolveSource, RttCounters, Stage, StageRecord, StageVerdict,
};
use crate::proto::stp::TreeCoordinate;

/// Per-stage budgets, all monotonic milliseconds and all tick-quantized by the
/// shell before they get here.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Budgets {
    pub(crate) bloom_ms: u64,
    pub(crate) discovery_ms: u64,
    pub(crate) session_ms: u64,
    pub(crate) rtt_ms: u64,
    pub(crate) tick_ms: u64,
}

impl Budgets {
    /// Derive the stage budgets from the rx-loop tick period and the lookup
    /// attempt ladder. Each stage is `max(floor, N * tick_ms)` so a node with a
    /// long tick does not expire a stage between two observations.
    pub(crate) fn derive(tick_ms: u64, attempt_timeouts_secs: &[u64]) -> Self {
        let ladder_ms: u64 = attempt_timeouts_secs.iter().sum::<u64>() * 1000;
        Self {
            bloom_ms: BLOOM_MIN_TICKS * tick_ms,
            discovery_ms: ladder_ms + RESOLVE_SLACK_TICKS * tick_ms,
            session_ms: SESSION_FLOOR_MS.max(SESSION_MIN_TICKS * tick_ms),
            rtt_ms: RTT_FLOOR_MS.max(RTT_MIN_TICKS * tick_ms),
            tick_ms,
        }
    }

    /// Total worst-case budget, which is what the client sizes its own ceiling
    /// from.
    pub(crate) fn total_ms(&self) -> u64 {
        self.bloom_ms + self.discovery_ms + self.session_ms + self.rtt_ms
    }
}

/// Live state as of one tick, with every clock read already resolved.
#[derive(Clone, Debug)]
pub(crate) struct Observation {
    /// Monotonic. All budget arithmetic uses this.
    ///
    /// Deliberately the monotonic clock and not the wall clock: an NTP step or
    /// a resume from suspend must not invent a handshake timeout against a
    /// healthy peer. Wall time is read shell-side only, where the surrounding
    /// API requires it (the coord cache's TTLs are keyed to it).
    pub(crate) now_ms: u64,
    pub(crate) coords_cached: bool,
    pub(crate) lookup_pending: bool,
    pub(crate) lookup_outcome: Option<LookupOutcomeKind>,
    pub(crate) lookup_fanout: Option<usize>,
    pub(crate) path: Option<PathFacts>,
    pub(crate) next_hop: Option<NextHopFacts>,
    pub(crate) no_hop_reason: Option<NoHopReason>,
    pub(crate) session_present: bool,
    pub(crate) session_established: bool,
    /// The identity check passed at drive time: the live entry is the one this
    /// probe created and still exclusively owns.
    pub(crate) session_is_ours: bool,
    pub(crate) session_error: Option<String>,
    pub(crate) target_is_direct_peer: bool,
    pub(crate) counters: RttCounters,
    pub(crate) last_rtt_ms: Option<u32>,
    pub(crate) srtt_ms: Option<f64>,
    pub(crate) path_mtu: Option<u32>,
}

/// An effect the async driver performs on the core's behalf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProbeAction {
    /// Call the gated lookup entry point for the target.
    InitiateLookup,
    /// Open an FSP session, after re-checking that no entry exists.
    OpenSession,
    /// Send one standalone `CoordsWarmup` on the session.
    SendWarmup,
    /// Remove the probe-created session, after the identity and adoption
    /// checks pass.
    TeardownSession,
    /// Mark the job terminal and release its target claim.
    Finish,
}

/// The probe stage machine.
pub(crate) struct Probe {
    started_ms: u64,
    ended_ms: Option<u64>,
    deadline_ms: u64,
    budgets: Budgets,
    preflight: Preflight,

    stage: Stage,
    stage_started_ms: u64,
    bloom: StageRecord,
    discovery: StageRecord,
    path: StageRecord,
    session: StageRecord,
    rtt: StageRecord,
    overall: Overall,

    // --- ownership ---
    owns_session: bool,
    open_requested: bool,
    teardown_emitted: bool,
    teardown_at_ms: Option<u64>,
    left_intact: Option<LeftIntact>,

    // --- latched observations ---
    resolve_source: Option<ResolveSource>,
    lookup_issued: bool,
    lookup_fanout: Option<usize>,
    lookup_was_pending: bool,
    lookup_outcome: Option<LookupOutcomeKind>,
    path_facts: Option<PathFacts>,
    next_hop: Option<NextHopFacts>,
    no_hop_reason: Option<NoHopReason>,
    session_preexisting: bool,
    session_established: bool,
    path_mtu: Option<u32>,
    rtt_ms: Option<u32>,
    srtt_ms: Option<f64>,
    baseline: RttCounters,
    counters: RttCounters,
    warmups_sent: u8,
    last_warmup_ms: Option<u64>,
    finished: bool,
}

impl Probe {
    /// Start a probe. Records the deadline; it does **not** decide ownership,
    /// which is latched at action time (see [`Probe::step`]).
    pub(crate) fn new(now_ms: u64, budgets: Budgets, preflight: Preflight) -> Self {
        Self {
            started_ms: now_ms,
            ended_ms: None,
            deadline_ms: now_ms + budgets.total_ms(),
            budgets,
            preflight,
            stage: Stage::Bloom,
            stage_started_ms: now_ms,
            bloom: StageRecord::pending(),
            discovery: StageRecord::pending(),
            path: StageRecord::pending(),
            session: StageRecord::pending(),
            rtt: StageRecord::pending(),
            overall: Overall::Running,
            owns_session: false,
            open_requested: false,
            teardown_emitted: false,
            teardown_at_ms: None,
            left_intact: None,
            resolve_source: None,
            lookup_issued: false,
            lookup_fanout: None,
            lookup_was_pending: false,
            lookup_outcome: None,
            path_facts: None,
            next_hop: None,
            no_hop_reason: None,
            session_preexisting: preflight.session_present,
            session_established: false,
            path_mtu: None,
            rtt_ms: None,
            srtt_ms: None,
            baseline: RttCounters::default(),
            counters: RttCounters::default(),
            warmups_sent: 0,
            last_warmup_ms: None,
            finished: false,
        }
    }

    /// Whether the probe currently holds exclusive ownership of the session.
    #[cfg(test)]
    pub(crate) fn owns_session(&self) -> bool {
        self.owns_session
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.finished
    }

    /// Advance the machine by one observation.
    pub(crate) fn step(&mut self, obs: &Observation) -> Vec<ProbeAction> {
        let mut actions = Vec::new();
        if self.finished {
            return actions;
        }

        self.absorb(obs);

        // Ownership can be lost but never regained. A live entry that is no
        // longer byte-for-byte the one we created is not ours to remove.
        //
        // The discriminator is `open_requested`, not `confirmed_ours`: under
        // simultaneous initiation the peer's inbound handshake can replace our
        // entry before the first observation that would have confirmed it, and
        // an entry the probe asked for and obtained was still replaced rather
        // than pre-existing.
        if self.owns_session && !obs.session_is_ours {
            self.owns_session = false;
            self.left_intact = Some(if self.open_requested {
                LeftIntact::Replaced
            } else {
                LeftIntact::Preexisting
            });
        }

        if self.stage == Stage::Terminal {
            return self.drive_terminal(obs, actions);
        }

        // Total-deadline backstop, independent of the per-stage budgets.
        if obs.now_ms >= self.deadline_ms {
            self.expire_running_stage();
            self.enter_terminal(obs);
            return self.drive_terminal(obs, actions);
        }

        // Run the stage machine until it blocks. A stage that completes
        // without needing I/O — the path stage always, and a skipped resolve —
        // hands straight on to the next one inside the same tick, so a probe
        // against a cached peer does not spend three ticks doing arithmetic.
        loop {
            let before = self.stage;
            match self.stage {
                Stage::Bloom => self.step_bloom(obs, &mut actions),
                Stage::Discovery => self.step_discovery(obs),
                Stage::Path => self.step_path(obs),
                Stage::Session => self.step_session(obs, &mut actions),
                Stage::Rtt => self.step_rtt(obs, &mut actions),
                Stage::Terminal => {}
            }
            if self.stage == before || self.stage == Stage::Terminal {
                break;
            }
        }

        if self.stage == Stage::Terminal {
            return self.drive_terminal(obs, actions);
        }
        actions
    }

    /// Cancel the probe: mark it cancelled and emit the terminal actions
    /// without waiting out the teardown grace, since the caller wants the job
    /// gone now.
    pub(crate) fn cancel(&mut self, now_ms: u64) -> Vec<ProbeAction> {
        let mut actions = Vec::new();
        if self.finished {
            return actions;
        }
        self.expire_running_stage();
        self.overall = Overall::Cancelled;
        self.stage = Stage::Terminal;
        self.ended_ms = Some(now_ms);
        if self.owns_session && !self.teardown_emitted {
            self.teardown_emitted = true;
            actions.push(ProbeAction::TeardownSession);
        }
        self.finished = true;
        actions.push(ProbeAction::Finish);
        actions
    }

    /// Project the report the control socket publishes.
    pub(crate) fn snapshot(&self) -> ProbeSnapshot {
        ProbeSnapshot {
            overall: self.overall,
            tick_ms: self.budgets.tick_ms,
            bloom: self.bloom.clone(),
            discovery: self.discovery.clone(),
            path: self.path.clone(),
            session: self.session.clone(),
            rtt: self.rtt.clone(),
            resolve_source: self.resolve_source,
            lookup_fanout: self.lookup_fanout,
            path_facts: self.path_facts.clone(),
            next_hop: self.next_hop.clone(),
            no_hop_reason: self.no_hop_reason,
            session_preexisting: self.session_preexisting,
            session_established: self.session_established,
            path_mtu: self.path_mtu,
            rtt_ms: self.rtt_ms,
            srtt_ms: self.srtt_ms,
            counters: self.counters,
            torn_down: self.teardown_emitted,
            left_intact: self.left_intact,
            lookup_issued: self.lookup_issued,
            coords_were_cached: self.preflight.coords_cached,
            identity_was_cached: self.preflight.identity_cached,
            warmups_sent: self.warmups_sent,
        }
    }

    /// Elapsed wall of the job so far, for a poll that arrives mid-run.
    pub(crate) fn elapsed_ms(&self, now_ms: u64) -> u64 {
        self.ended_ms
            .unwrap_or(now_ms)
            .saturating_sub(self.started_ms)
    }

    // ---- stages ----------------------------------------------------------

    /// Is the target claimed by anyone, and did a request therefore go out?
    ///
    /// The gate is evaluated shell-side inside the action this stage emits, so
    /// its answer arrives on the following observation rather than this one.
    /// Every outcome that means *no request was sent* ends the probe here,
    /// which is the whole reason this is its own stage: "nobody claims this
    /// address" and "nobody answered for it" are different findings and used
    /// to share one verdict.
    fn step_bloom(&mut self, obs: &Observation, actions: &mut Vec<ProbeAction>) {
        if !self.lookup_issued {
            if obs.coords_cached {
                self.finish_stage(FailKind::Cached.into_skip(), obs);
                self.resolve_source = Some(ResolveSource::Cache);
                self.advance(obs);
                return;
            }
            if obs.target_is_direct_peer {
                // Routing short-circuits on a send-ready direct peer before it
                // reads the coord cache, so a neighbour needs no lookup at all.
                self.finish_stage(FailKind::DirectPeer.into_skip(), obs);
                self.resolve_source = Some(ResolveSource::DirectPeer);
                self.advance(obs);
                return;
            }
            self.bloom.verdict = StageVerdict::Running;
            self.lookup_issued = true;
            actions.push(ProbeAction::InitiateLookup);
            return;
        }

        match self.lookup_outcome {
            Some(LookupOutcomeKind::BloomMiss) => self.fail_stage(FailKind::BloomMiss, obs),
            Some(LookupOutcomeKind::Suppressed) => {
                self.fail_stage(FailKind::BackoffSuppressed, obs)
            }
            Some(LookupOutcomeKind::ZeroFanout) => self.fail_stage(FailKind::NoTreePeers, obs),
            // A request is on the wire, or this probe joined one already in
            // flight. Either way the filters claimed the target.
            Some(LookupOutcomeKind::Sent) | Some(LookupOutcomeKind::Deduplicated) => {
                self.finish_stage(ok_record(), obs);
                self.advance(obs);
            }
            // Can only be reached if the action never ran. The total deadline
            // backstops it; this bounds the wait to something legible.
            None => {
                if obs.now_ms.saturating_sub(self.stage_started_ms) >= self.budgets.bloom_ms {
                    self.fail_stage(FailKind::NoResponse, obs);
                }
            }
        }
    }

    /// Wait for a LookupResponse to put coordinates in the cache.
    fn step_discovery(&mut self, obs: &Observation) {
        // Nothing was asked, so there is nothing to wait for: the bloom stage
        // already settled the cases that need no lookup, and this stage
        // records the same reason rather than inventing a second one.
        if !self.lookup_issued {
            let kind = match self.resolve_source {
                Some(ResolveSource::DirectPeer) => FailKind::DirectPeer,
                _ => FailKind::Cached,
            };
            self.finish_stage(kind.into_skip(), obs);
            self.advance(obs);
            return;
        }

        if obs.coords_cached {
            self.finish_stage(ok_record(), obs);
            self.resolve_source = Some(ResolveSource::Lookup);
            self.advance(obs);
            return;
        }

        // The request is out and the answer has not arrived. Say so: a stage
        // left `Pending` while it is in fact waiting reads to a poller as one
        // that has not started, and this one waits the longest of any.
        self.discovery.verdict = StageVerdict::Running;

        // The ladder gave up: the pending entry existed and is now gone with
        // no coordinates. The answer is already known, so do not hold the
        // caller for the rest of the budget.
        let gave_up = self.lookup_was_pending && !obs.lookup_pending;
        if gave_up || obs.now_ms.saturating_sub(self.stage_started_ms) >= self.budgets.discovery_ms
        {
            let reason = if self.lookup_outcome == Some(LookupOutcomeKind::Deduplicated) {
                FailKind::AlreadyPending
            } else {
                FailKind::NoResponse
            };
            self.fail_stage(reason, obs);
        }
    }

    fn step_path(&mut self, obs: &Observation) {
        // Path is pure computation over what resolve established; it never
        // halts the probe, because `initiate_session`'s own routing may
        // succeed where this non-touching preview did not.
        let record = match &self.path_facts {
            None => {
                // A send-ready direct peer already latched a next hop from the
                // routing short-circuit, which reads no coordinates at all. Only
                // claim "no coords" when there is genuinely no hop to name.
                if self.next_hop.is_none() {
                    self.no_hop_reason = Some(NoHopReason::NoCoords);
                }
                if obs.target_is_direct_peer {
                    FailKind::DirectPeer.into_skip()
                } else {
                    FailKind::NoNextHop.into_fail()
                }
            }
            Some(facts) if !facts.same_root => FailKind::DisjointTrees.into_fail(),
            Some(_) if self.next_hop.is_none() => FailKind::NoNextHop.into_fail(),
            Some(_) => ok_record(),
        };
        self.finish_stage(record, obs);
        self.advance(obs);
    }

    fn step_session(&mut self, obs: &Observation, actions: &mut Vec<ProbeAction>) {
        if obs.session_established && self.owns_session {
            self.session_established = true;
            self.finish_stage(ok_record(), obs);
            self.advance(obs);
            return;
        }

        if let Some(err) = &obs.session_error {
            // `initiate_session` inserts its entry only after the send
            // succeeds, so an error means nothing was created.
            self.owns_session = false;
            let mut record = FailKind::SendError.into_fail();
            record.detail = Some(err.clone());
            self.finish_stage(record, obs);
            self.skip_rest(FailKind::NotReached);
            self.enter_terminal(obs);
            return;
        }

        if obs.session_present {
            // Only an entry the probe never asked for is pre-existing. The
            // ticks between our own `OpenSession` and establishment also see
            // `session_present`, and reporting those as pre-existing would
            // contradict the teardown the same report carries.
            if !self.open_requested {
                self.session_preexisting = true;
            }
            if !self.owns_session {
                if obs.session_established {
                    self.session_established = true;
                    self.finish_stage(FailKind::Preexisting.into_skip(), obs);
                    self.left_intact = Some(self.left_intact.unwrap_or(LeftIntact::Preexisting));
                    self.advance(obs);
                    return;
                }
                // Someone else's handshake is in flight. Wait it out, but do
                // not touch it.
                if obs.now_ms.saturating_sub(self.stage_started_ms) >= self.budgets.session_ms {
                    self.finish_stage(FailKind::Preexisting.into_skip(), obs);
                    self.left_intact = Some(self.left_intact.unwrap_or(LeftIntact::Preexisting));
                    self.skip_rest(FailKind::NotReached);
                    self.enter_terminal(obs);
                }
                return;
            }
        } else if !self.open_requested && !self.preflight.target_claimed {
            // The one place ownership is taken, and only on a step where no
            // entry exists at all — broader than production's
            // established-or-initiating predicate, so an inbound handshake
            // awaiting msg3 also counts as "not mine".
            self.session.verdict = StageVerdict::Running;
            self.open_requested = true;
            self.owns_session = true;
            actions.push(ProbeAction::OpenSession);
            return;
        }

        if obs.now_ms.saturating_sub(self.stage_started_ms) >= self.budgets.session_ms {
            let record = if self.owns_session {
                FailKind::HandshakeTimeout.into_fail()
            } else {
                FailKind::Preexisting.into_skip()
            };
            self.finish_stage(record, obs);
            self.skip_rest(FailKind::NotReached);
            self.enter_terminal(obs);
        }
    }

    fn step_rtt(&mut self, obs: &Observation, actions: &mut Vec<ProbeAction>) {
        if self.warmups_sent == 0 {
            self.rtt.verdict = StageVerdict::Running;
            self.baseline = obs.counters;
            self.warmups_sent = 1;
            self.last_warmup_ms = Some(obs.now_ms);
            actions.push(ProbeAction::SendWarmup);
            return;
        }

        let delta = obs.counters.delta(self.baseline);
        self.counters = delta;

        // A pre-existing session may already carry an SRTT, and SRTT survives
        // rekey, so `srtt_ms.is_some()` proves nothing about this probe. A new
        // accepted sample is the only attributable signal.
        if delta.samples > 0 {
            self.rtt_ms = obs.last_rtt_ms;
            self.finish_stage(ok_record(), obs);
            self.enter_terminal(obs);
            return;
        }

        let retry_after = WARMUP_RETRY_MS.max(self.budgets.tick_ms);
        if self.warmups_sent == 1
            && delta.reports_seen == 0
            && obs.now_ms.saturating_sub(self.last_warmup_ms.unwrap_or(0)) >= retry_after
        {
            self.warmups_sent = 2;
            self.last_warmup_ms = Some(obs.now_ms);
            actions.push(ProbeAction::SendWarmup);
        }

        if obs.now_ms.saturating_sub(self.stage_started_ms) >= self.budgets.rtt_ms {
            self.finish_stage(classify_rtt_failure(delta).into_fail(), obs);
            self.enter_terminal(obs);
        }
    }

    // ---- helpers ---------------------------------------------------------

    /// Latch the report-only facts every stage publishes.
    fn absorb(&mut self, obs: &Observation) {
        if let Some(kind) = obs.lookup_outcome {
            self.lookup_outcome = Some(kind);
        }
        if obs.lookup_fanout.is_some() {
            self.lookup_fanout = obs.lookup_fanout;
        }
        if obs.lookup_pending {
            self.lookup_was_pending = true;
        }
        if obs.path.is_some() {
            self.path_facts = obs.path.clone();
        }
        if obs.next_hop.is_some() {
            self.next_hop = obs.next_hop.clone();
        }
        if obs.no_hop_reason.is_some() {
            self.no_hop_reason = obs.no_hop_reason;
        }
        if obs.path_mtu.is_some() {
            self.path_mtu = obs.path_mtu;
        }
        if obs.srtt_ms.is_some() {
            self.srtt_ms = obs.srtt_ms;
        }
        if obs.session_established {
            self.session_established = true;
        }
    }

    /// End the probe on the current stage's failure: record it, mark
    /// everything behind it not reached, and go terminal.
    fn fail_stage(&mut self, kind: FailKind, obs: &Observation) {
        self.finish_stage(kind.into_fail(), obs);
        self.skip_rest(FailKind::NotReached);
        self.enter_terminal(obs);
    }

    fn finish_stage(&mut self, mut record: StageRecord, obs: &Observation) {
        record.elapsed_ms = Some(obs.now_ms.saturating_sub(self.stage_started_ms));
        *self.current_record_mut() = record;
    }

    fn current_record_mut(&mut self) -> &mut StageRecord {
        match self.stage {
            Stage::Bloom => &mut self.bloom,
            Stage::Discovery => &mut self.discovery,
            Stage::Path => &mut self.path,
            Stage::Session => &mut self.session,
            Stage::Rtt | Stage::Terminal => &mut self.rtt,
        }
    }

    fn advance(&mut self, obs: &Observation) {
        self.stage = match self.stage {
            Stage::Bloom => Stage::Discovery,
            Stage::Discovery => Stage::Path,
            Stage::Path => Stage::Session,
            Stage::Session => Stage::Rtt,
            Stage::Rtt | Stage::Terminal => Stage::Terminal,
        };
        self.stage_started_ms = obs.now_ms;
    }

    /// Mark every stage after the current one as not reached.
    fn skip_rest(&mut self, kind: FailKind) {
        let record = kind.into_skip();
        let current = self.stage;
        let mut mark = false;
        for (stage, slot) in [
            (Stage::Bloom, &mut self.bloom),
            (Stage::Discovery, &mut self.discovery),
            (Stage::Path, &mut self.path),
            (Stage::Session, &mut self.session),
            (Stage::Rtt, &mut self.rtt),
        ] {
            if mark {
                *slot = record.clone();
            }
            if stage == current {
                mark = true;
            }
        }
    }

    /// The deadline fired mid-stage: record the running stage as failed for
    /// the reason its own budget would have given.
    fn expire_running_stage(&mut self) {
        let kind = match self.stage {
            Stage::Bloom | Stage::Discovery => FailKind::NoResponse,
            Stage::Path => FailKind::NoNextHop,
            Stage::Session => {
                if self.owns_session {
                    FailKind::HandshakeTimeout
                } else {
                    FailKind::Preexisting
                }
            }
            Stage::Rtt => classify_rtt_failure(self.counters),
            Stage::Terminal => return,
        };
        let record = if self.stage == Stage::Session && !self.owns_session {
            kind.into_skip()
        } else {
            kind.into_fail()
        };
        if self.current_record_mut().verdict != StageVerdict::Ok {
            *self.current_record_mut() = record;
        }
        self.skip_rest(FailKind::NotReached);
    }

    fn enter_terminal(&mut self, obs: &Observation) {
        self.stage = Stage::Terminal;
        self.teardown_at_ms = Some(obs.now_ms + TEARDOWN_GRACE_TICKS * self.budgets.tick_ms.max(1));
        self.overall = self.compute_overall();
    }

    fn drive_terminal(
        &mut self,
        obs: &Observation,
        mut actions: Vec<ProbeAction>,
    ) -> Vec<ProbeAction> {
        if self.owns_session && !self.teardown_emitted {
            if obs.now_ms < self.teardown_at_ms.unwrap_or(obs.now_ms) {
                // Absorb the grace tick so a receiver report still in flight
                // lands on a session that exists.
                return actions;
            }
            self.teardown_emitted = true;
            actions.push(ProbeAction::TeardownSession);
        }
        self.finished = true;
        self.ended_ms = Some(obs.now_ms);
        self.overall = self.compute_overall();
        actions.push(ProbeAction::Finish);
        actions
    }

    fn compute_overall(&self) -> Overall {
        if self.overall == Overall::Cancelled {
            return Overall::Cancelled;
        }
        if self.bloom.is_failed() || self.discovery.is_failed() || self.session.is_failed() {
            return Overall::Failed;
        }
        if self.rtt.verdict == StageVerdict::Ok {
            return Overall::Ok;
        }
        Overall::Partial
    }
}

impl FailKind {
    fn into_skip(self) -> StageRecord {
        StageRecord {
            verdict: StageVerdict::Skipped,
            reason: Some(self),
            detail: None,
            elapsed_ms: None,
        }
    }

    fn into_fail(self) -> StageRecord {
        StageRecord {
            verdict: StageVerdict::Failed,
            reason: Some(self),
            detail: None,
            elapsed_ms: None,
        }
    }
}

fn ok_record() -> StageRecord {
    StageRecord {
        verdict: StageVerdict::Ok,
        reason: None,
        detail: None,
        elapsed_ms: None,
    }
}

/// Discriminate the four rtt failure modes, which mean opposite things: only
/// `NoReport` leaves reachability genuinely in doubt, and only
/// `BadTimestampEcho` is an anomaly rather than an artifact.
fn classify_rtt_failure(delta: RttCounters) -> FailKind {
    if delta.arith_fail > 0 {
        FailKind::BadTimestampEcho
    } else if delta.zero > 0 {
        FailKind::SubMillisecond
    } else if delta.reports_seen > 0 {
        FailKind::NoEcho
    } else {
        FailKind::NoReport
    }
}

/// Pure LCA arithmetic over two coordinates.
///
/// `TreeCoordinate::lca` is the primary discriminator because it returns
/// `None` for different roots. `lca_depth` alone returns `0` there via its
/// `saturating_sub(1)`, indistinguishable from "the LCA is the root", so the
/// core never keys off it directly.
pub(crate) fn describe_path(my: &TreeCoordinate, their: &TreeCoordinate) -> PathFacts {
    let our_depth = my.depth();
    let their_depth = their.depth();
    let lca = my.lca(their).copied();
    let same_root = lca.is_some();
    let lca_depth = if same_root {
        Some(my.lca_depth(their))
    } else {
        None
    };
    let up = lca_depth.map(|d| our_depth.saturating_sub(d));
    let down = lca_depth.map(|d| their_depth.saturating_sub(d));
    PathFacts {
        our_coords: my.node_addrs().copied().collect(),
        their_coords: their.node_addrs().copied().collect(),
        our_depth,
        their_depth,
        same_root,
        lca,
        lca_depth,
        tree_hops_up: up,
        tree_hops_down: down,
        tree_distance: up.zip(down).map(|(u, d)| u + d),
    }
}
