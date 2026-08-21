//! Async driver for the `probe` diagnostic.
//!
//! The probe needs a mesh lookup, a Noise XK handshake and at least one remote
//! MMP tick, so it cannot be one control round-trip: `IO_TIMEOUT` is 5s and the
//! command dispatcher is awaited inline inside the rx-loop `select!`. It is
//! therefore a daemon-side job driven on the tick, with a start/poll/cancel
//! control triplet. Every round-trip returns immediately; `fipsctl` hides the
//! polling.
//!
//! Because the job carries its own deadline it self-cleans when the client
//! goes away, which is what makes running a probe against a production node
//! safe. All protocol and stage decisions live in the sans-IO
//! [`crate::proto::probe`] core; this file performs I/O, reads the clocks, and
//! executes the returned actions.

use std::collections::{BTreeMap, HashSet};

use secp256k1::PublicKey;
use tracing::{debug, info};

use crate::node::Node;
use crate::node::session::SessionEntry;
use crate::proto::probe::{
    Budgets, LeftIntact, LookupOutcomeKind, MAX_CONCURRENT_PROBES, NextHopFacts, NoHopReason,
    Observation, Preflight, Probe, ProbeAction, REAP_MS, RttCounters, describe_path,
};
use crate::proto::routing::{self, RouteClass};
use crate::{NodeAddr, PeerIdentity};

/// Why a live session entry is not the probe's to remove.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Disowned {
    /// The probe never created one.
    NeverOwned,
    /// A different entry took its place, or the peer became the initiator.
    Replaced,
    /// Real application traffic moved on the session during the probe.
    Adopted,
    /// The entry is no longer there at all.
    Gone,
}

/// One in-flight probe plus the shell-side facts the core cannot read.
pub(crate) struct ProbeJob {
    id: u64,
    target: NodeAddr,
    pubkey: PublicKey,
    npub: String,
    probe: Probe,
    /// Set only while this job holds the registry's target claim.
    holds_claim: bool,
    /// `created_at` of the entry `initiate_session` inserted for us. The
    /// teardown identity check is an equality against this, not an inequality
    /// against the start time — a `>=` still admits a replacement entry.
    owned_created_at: Option<u64>,
    activity_at_establish: Option<u64>,
    traffic_at_establish: Option<(u64, u64, u64, u64)>,
    lookup_outcome: Option<LookupOutcomeKind>,
    lookup_fanout: Option<usize>,
    lookup_attempts: Option<u8>,
    session_error: Option<String>,
    /// Set when the drive-time guard refused a teardown the core had already
    /// decided on, so the report says the session was left in place.
    teardown_refused: Option<LeftIntact>,
    reap_at_ms: Option<u64>,
}

impl ProbeJob {
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn target(&self) -> &NodeAddr {
        &self.target
    }

    pub(crate) fn npub(&self) -> &str {
        &self.npub
    }

    pub(crate) fn probe(&self) -> &Probe {
        &self.probe
    }

    pub(crate) fn lookup_attempts(&self) -> Option<u8> {
        self.lookup_attempts
    }

    pub(crate) fn teardown_refused(&self) -> Option<LeftIntact> {
        self.teardown_refused
    }
}

/// Probe jobs in flight, with a per-target ownership claim.
///
/// The claim is what stops two probes started between ticks from both taking
/// ownership of one target's session: the first job to reach `OpenSession`
/// holds it, and the second behaves exactly as it would for a pre-existing
/// session.
pub(in crate::node) struct ProbeRegistry {
    jobs: BTreeMap<u64, ProbeJob>,
    claims: HashSet<NodeAddr>,
    next_id: u64,
}

impl ProbeRegistry {
    pub(in crate::node) fn new() -> Self {
        Self {
            jobs: BTreeMap::new(),
            claims: HashSet::new(),
            next_id: 1,
        }
    }
}

impl Node {
    // === Control API methods ===

    /// Start a probe toward `npub` and return immediately.
    pub(crate) async fn api_probe_start(
        &mut self,
        npub: &str,
    ) -> Result<serde_json::Value, String> {
        let identity =
            PeerIdentity::from_npub(npub).map_err(|e| format!("invalid peer npub: {e}"))?;
        let target = *identity.node_addr();
        if target == *self.node_addr() {
            return Err("cannot probe this node".to_string());
        }
        // Only unfinished jobs count against the cap. A terminal job is
        // retained for `REAP_MS` so a late poll still gets its report, and
        // counting those would lock a caller that never polls out of new
        // probes for 30s with an error that says the opposite of what is true.
        let in_flight = self
            .probes
            .jobs
            .values()
            .filter(|j| !j.probe.is_finished())
            .count();
        if in_flight >= MAX_CONCURRENT_PROBES {
            return Err("too many probes in flight".to_string());
        }

        // Seeding the identity cache is mandatory, not a convenience: the
        // originator path aborts a LookupResponse it cannot verify. `connect`
        // seeds identically for the same reason.
        self.peer_aliases.insert(target, identity.short_npub());
        self.register_identity(target, identity.pubkey_full());

        let wall_ms = Self::now_ms();
        let now_ms = crate::time::mono_ms();
        let tick_ms = self.config().node.tick_interval_secs * 1000;
        let ladder = self.config().node.lookup.attempt_timeouts_secs.clone();
        let budgets = Budgets::derive(tick_ms, &ladder);
        let budget_ms = budgets.total_ms();

        let claimed = !self.probes.claims.insert(target);
        let preflight = Preflight {
            session_present: self.sessions.contains_key(&target),
            coords_cached: self.coord_cache.get(&target, wall_ms).is_some(),
            identity_cached: self.has_cached_identity(&target),
            target_claimed: claimed,
        };

        let id = self.probes.next_id;
        self.probes.next_id += 1;
        let mut job = ProbeJob {
            id,
            target,
            pubkey: identity.pubkey_full(),
            npub: npub.to_string(),
            probe: Probe::new(now_ms, budgets, preflight),
            holds_claim: !claimed,
            owned_created_at: None,
            activity_at_establish: None,
            traffic_at_establish: None,
            lookup_outcome: None,
            lookup_fanout: None,
            lookup_attempts: None,
            session_error: None,
            teardown_refused: None,
            reap_at_ms: None,
        };
        let data = serde_json::json!({
            "probe_id": id,
            "npub": npub,
            "node_addr": target.to_string(),
            "display_name": self.peer_display_name(&target),
            "budget_ms": budget_ms,
        });

        // Step it here rather than leaving it for the tick. Admission runs on
        // the rx loop already, so this is the same context the tick driver
        // uses, and without it the first stage does not begin until the next
        // tick fires -- a whole tick of a probe's budget spent before anything
        // is sent, and a client watching four pending stages for as long.
        self.drive_probe(&mut job, now_ms, wall_ms).await;
        self.probes.jobs.insert(id, job);

        info!(npub = %npub, probe_id = id, budget_ms, "Probe started");
        Ok(data)
    }

    /// Report a probe's progress. A terminal job is removed on the poll that
    /// observes it, so the report is delivered exactly once.
    pub(crate) fn api_probe_poll(&mut self, probe_id: u64) -> Result<serde_json::Value, String> {
        let now_ms = crate::time::mono_ms();
        let Some(job) = self.probes.jobs.get(&probe_id) else {
            return Err(format!("unknown probe id: {probe_id}"));
        };
        let done = job.probe.is_finished();
        let report = crate::control::probe::ProbeReport::build(self, job, now_ms);
        let data = serde_json::json!({
            "state": if done { "done" } else { "running" },
            "report": report,
        });
        if done {
            self.probes.jobs.remove(&probe_id);
        }
        Ok(data)
    }

    /// Read a job without consuming it, for tests that assert on a probe's
    /// progress without the poll API's remove-on-done behaviour.
    #[cfg(test)]
    pub(crate) fn probe_job(&self, probe_id: u64) -> Option<&ProbeJob> {
        self.probes.jobs.get(&probe_id)
    }

    /// Cancel a probe: run its terminal actions now, without the grace tick.
    pub(crate) async fn api_probe_cancel(
        &mut self,
        probe_id: u64,
    ) -> Result<serde_json::Value, String> {
        let now_ms = crate::time::mono_ms();
        let Some(mut job) = self.probes.jobs.remove(&probe_id) else {
            return Err(format!("unknown probe id: {probe_id}"));
        };
        for action in job.probe.cancel(now_ms) {
            self.drive_probe_action(&mut job, action, now_ms).await;
        }
        self.probes.jobs.insert(probe_id, job);
        Ok(serde_json::json!({ "probe_id": probe_id, "cancelled": true }))
    }

    // === Tick driver ===

    /// Advance every in-flight probe by one observation, then reap the
    /// terminal jobs whose retention window has passed.
    pub(in crate::node) async fn poll_probes(&mut self) {
        if self.probes.jobs.is_empty() {
            return;
        }
        let now_ms = crate::time::mono_ms();
        let wall_ms = Self::now_ms();
        let ids: Vec<u64> = self.probes.jobs.keys().copied().collect();

        for id in ids {
            // Take the job out of the registry so the drive path can hold
            // `&mut self` without an outstanding borrow of the map.
            let Some(mut job) = self.probes.jobs.remove(&id) else {
                continue;
            };
            if job.probe.is_finished() {
                if job.reap_at_ms.is_some_and(|t| now_ms >= t) {
                    self.release_probe_claim(&mut job);
                    continue;
                }
                self.probes.jobs.insert(id, job);
                continue;
            }

            self.drive_probe(&mut job, now_ms, wall_ms).await;
            self.probes.jobs.insert(id, job);
        }
    }

    /// Step one job and perform whatever it emits.
    ///
    /// The caller owns the job for the duration, because driving an action
    /// needs `&mut self` and the job cannot stay borrowed out of the registry
    /// at the same time.
    async fn drive_probe(&mut self, job: &mut ProbeJob, now_ms: u64, wall_ms: u64) {
        let obs = self.observe_probe(job, now_ms, wall_ms);
        for action in job.probe.step(&obs) {
            self.drive_probe_action(job, action, now_ms).await;
        }
    }

    /// Build one observation. Every read here is deliberately non-mutating:
    /// `coord_cache.get` rather than `get_and_touch`, `has_cached_identity`
    /// rather than `lookup_by_fips_prefix`.
    fn observe_probe(&self, job: &mut ProbeJob, now_ms: u64, wall_ms: u64) -> Observation {
        let target = job.target;
        let entry = self.sessions.get(&target);
        let session_present = entry.is_some();
        let session_established = entry.is_some_and(SessionEntry::is_established);
        let is_ours = self.probe_session_is_ours(job);

        // Baseline for the adoption check: real user traffic arriving after
        // this point means the session is no longer the probe's to remove.
        if is_ours
            && session_established
            && job.activity_at_establish.is_none()
            && let Some(entry) = entry
        {
            job.activity_at_establish = Some(entry.last_activity());
            job.traffic_at_establish = Some(entry.traffic_counters());
        }

        let mmp = entry.and_then(SessionEntry::mmp);
        let counters = mmp.map_or(RttCounters::default(), |m| RttCounters {
            reports_seen: m.metrics.reports_seen(),
            samples: m.metrics.rtt_samples(),
            zero: m.metrics.rtt_zero(),
            arith_fail: m.metrics.rtt_arith_fail(),
        });
        let path_mtu = mmp
            .map(|m| m.path_mtu.last_observed_mtu())
            .filter(|mtu| *mtu != u16::MAX)
            .map(u32::from);

        let mut lookup_pending = false;
        for (addr, pending) in self.pending_lookups_iter() {
            if *addr == target {
                lookup_pending = true;
                job.lookup_attempts = Some(pending.attempt);
            }
        }

        let coords = self.coord_cache.get(&target, wall_ms).cloned();
        let path = coords
            .as_ref()
            .map(|c| describe_path(self.tree_state().my_coords(), c));
        let (next_hop, mut no_hop_reason) = self.preview_next_hop(&target, wall_ms);
        if path.as_ref().is_some_and(|p| !p.same_root) {
            no_hop_reason = Some(NoHopReason::DisjointTrees);
        }

        Observation {
            now_ms,
            coords_cached: coords.is_some(),
            lookup_pending,
            lookup_outcome: job.lookup_outcome.take(),
            lookup_fanout: job.lookup_fanout.take(),
            path,
            next_hop,
            no_hop_reason,
            session_present,
            session_established,
            session_is_ours: is_ours,
            session_error: job.session_error.take(),
            target_is_direct_peer: self.peers.get(&target).is_some_and(|p| p.can_send()),
            counters,
            last_rtt_ms: mmp.and_then(|m| m.metrics.last_rtt_ms()),
            srtt_ms: mmp.and_then(|m| m.metrics.srtt_ms()),
            path_mtu,
        }
    }

    async fn drive_probe_action(&mut self, job: &mut ProbeJob, action: ProbeAction, now_ms: u64) {
        match action {
            ProbeAction::InitiateLookup => {
                let outcome = self.maybe_initiate_lookup(&job.target).await;
                job.lookup_outcome = Some(outcome.kind());
                job.lookup_fanout = outcome.fanout();
                // Count the first attempt here rather than waiting to see it
                // in the pending table. A lookup answered inside one tick
                // never appears there, so the observation path alone reports
                // no attempts at all for the fastest case there is.
                if outcome.fanout().is_some_and(|f| f > 0) {
                    job.lookup_attempts = Some(1);
                }
            }
            ProbeAction::OpenSession => {
                // Re-check at the moment of action: `api_probe_start` runs on
                // the control arm and can interleave with ticks, and an
                // inbound handshake can land between the observation and here.
                if self.sessions.contains_key(&job.target) {
                    debug!(
                        probe_id = job.id,
                        "Probe declined to open an existing session"
                    );
                    return;
                }
                match self.initiate_session(job.target, job.pubkey).await {
                    Ok(()) => {
                        job.owned_created_at =
                            self.sessions.get(&job.target).map(SessionEntry::created_at);
                    }
                    Err(e) => job.session_error = Some(e.to_string()),
                }
            }
            ProbeAction::SendWarmup => {
                if let Err(e) = self.send_coords_warmup(&job.target).await {
                    debug!(probe_id = job.id, error = %e, "Probe warmup send failed");
                }
            }
            ProbeAction::TeardownSession => self.probe_teardown(job),
            ProbeAction::Finish => {
                job.reap_at_ms = Some(now_ms + REAP_MS);
                self.release_probe_claim(job);
                debug!(probe_id = job.id, "Probe finished");
            }
        }
    }

    /// The entry is ours only if it is byte-for-byte the one `initiate_session`
    /// inserted, we are still the initiator, and no application traffic has
    /// adopted it.
    fn probe_session_is_ours(&self, job: &ProbeJob) -> bool {
        self.probe_session_disowned(job).is_none()
    }

    /// Why the live entry is not the probe's to remove, or `None` when it is.
    ///
    /// The three causes are distinct and an operator debugging a surviving
    /// session needs to be told which one applied: a replacement entry, a
    /// peer-driven takeover and a session adopted by real traffic call for
    /// different next steps.
    fn probe_session_disowned(&self, job: &ProbeJob) -> Option<Disowned> {
        let Some(created) = job.owned_created_at else {
            return Some(Disowned::NeverOwned);
        };
        let Some(entry) = self.sessions.get(&job.target) else {
            return Some(Disowned::Gone);
        };
        if entry.created_at() != created || !entry.is_initiator() {
            return Some(Disowned::Replaced);
        }
        match (job.activity_at_establish, job.traffic_at_establish) {
            (Some(activity), Some(traffic))
                if entry.last_activity() != activity || entry.traffic_counters() != traffic =>
            {
                Some(Disowned::Adopted)
            }
            _ => None,
        }
    }

    /// Remove a probe-created session, or decline and say why.
    ///
    /// `pending_tun_packets` is deliberately untouched: the idle-purge path
    /// removes it because it runs after the idle timeout, but here the map can
    /// only hold real user packets queued while the session was `Initiating`.
    /// The probe queues none, so it has none to remove.
    fn probe_teardown(&mut self, job: &mut ProbeJob) {
        if let Some(cause) = self.probe_session_disowned(job) {
            // `Gone` leaves the refusal unset: there is no session left in
            // place, so reporting one would be its own falsehood.
            job.teardown_refused = match cause {
                Disowned::NeverOwned => Some(LeftIntact::Preexisting),
                Disowned::Replaced => Some(LeftIntact::Replaced),
                Disowned::Adopted => Some(LeftIntact::AdoptedByTraffic),
                Disowned::Gone => None,
            };
            return;
        }
        let name = self.peer_display_name(&job.target);
        if let Some(entry) = self.sessions.get(&job.target)
            && let Some(mmp) = entry.mmp()
        {
            Self::log_session_mmp_teardown(&name, mmp);
        }
        self.sessions.remove(&job.target);
        debug!(probe_id = job.id, dest = %name, "Probe tore down the session it opened");
    }

    fn release_probe_claim(&mut self, job: &mut ProbeJob) {
        if job.holds_claim {
            self.probes.claims.remove(&job.target);
            job.holds_claim = false;
        }
    }

    /// Non-touching mirror of [`Node::find_next_hop`]: the same five steps in
    /// the same order, but reading the coord cache without the LRU touch and
    /// taking `wall_ms` as a parameter instead of reading the clock inline.
    /// A diagnostic must not perturb the state it reports on.
    pub(in crate::node) fn preview_next_hop(
        &self,
        dest: &NodeAddr,
        wall_ms: u64,
    ) -> (Option<NextHopFacts>, Option<NoHopReason>) {
        if dest == self.node_addr() {
            return (None, Some(NoHopReason::Local));
        }
        if let Some(peer) = self.peers.get(dest)
            && peer.can_send()
        {
            return (
                Some(NextHopFacts {
                    node_addr: *dest,
                    class: RouteClass::DirectPeer,
                    direct_peer: true,
                    leaves_tree_walk: false,
                }),
                None,
            );
        }
        let Some(dest_coords) = self.coord_cache.get(dest, wall_ms).cloned() else {
            return (None, Some(NoHopReason::NoCoords));
        };

        let selected = {
            let view = crate::node::NodeRoutingView {
                coord_cache: &self.coord_cache,
                peers: &self.peers,
                tree_state: &self.tree_state,
                congested: false,
            };
            routing::select_best_candidate(&view, dest, &dest_coords, self.tree_state.my_coords())
        }
        .or_else(|| {
            self.tree_state
                .find_next_hop(&dest_coords, &std::collections::BTreeSet::new())
        });

        let Some(hop) = selected else {
            return (None, Some(NoHopReason::NoCloserPeer));
        };
        if !self.peers.get(&hop).is_some_and(|p| p.can_send()) {
            return (None, Some(NoHopReason::HopNotSendReady));
        }
        let class = self.classify_forward(dest, &hop);
        (
            Some(NextHopFacts {
                node_addr: hop,
                class,
                direct_peer: hop == *dest,
                leaves_tree_walk: matches!(
                    class,
                    RouteClass::TreeDownCross
                        | RouteClass::CrosslinkDescend
                        | RouteClass::CrosslinkAscend
                ),
            }),
            None,
        )
    }
}
