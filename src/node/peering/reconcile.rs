//! Peering homeostatic reconciler — sans-IO core (Milestone-1 Step 1b).
//!
//! A synchronous `reconcile(inputs) -> Vec<PeeringAction>` decision core over
//! the node's peer set. It owns the *decision* of which peers to dial and how
//! the cross-attempt retry schedule escalates; the async driver in
//! [`crate::node::lifecycle`] performs the actual dial / advert-refetch I/O each
//! [`PeeringAction`] names and reports results back as reflex events
//! ([`PeeringReconciler::on_handshake_timeout`] /
//! [`PeeringReconciler::on_link_dead`]). The core reads no clock, performs no
//! I/O, and holds no runtime handles — time enters only as the `now` input, and
//! the live dataplane maps enter only as an immutable [`Observed`] snapshot — so
//! it is unit-testable with synthetic inputs and survives a later
//! thread-boundary move (design doc §6 Core 2, §8 "cores are sans-IO"). It
//! mirrors the [`crate::node::lifecycle::supervisor`] template.
//!
//! ## Scope: the four reconcile layers (behavior-neutral rewrite)
//!
//! [`PeeringReconciler::reconcile`] runs four layers in priority order, each
//! subsuming today's imperative `Node` methods verbatim:
//!
//! 1. **Mandatory floor** — the auto-connect config peers (subsumes
//!    `initiate_peer_connections`) plus the **retry-dial phase** (subsumes
//!    `process_pending_retries`). The floor is not budget-gated at startup;
//!    the retry-dial phase is gated only by [`Budget::admission_ok`], matching
//!    today.
//! 2. **Overlay pool** — Nostr open-discovery, **ceiling-only** enqueue with no
//!    set-point floor (design doc §9.2 option b; subsumes
//!    `run_open_discovery_sweep`). Enqueues into the durable retry schedule; the
//!    dial happens on a later retry-slot invocation (the two-phase timing,
//!    below).
//! 3. **Opportunistic growth** — transport-neighbor beacons (subsumes
//!    `poll_transport_discovery`, budget + per-peer cap) and LAN mDNS peers
//!    (subsumes `poll_lan_rendezvous`, connected/connecting skip only).
//! 4. **Ceiling** — not a separate pass; the `node.limits` triple plus the
//!    per-tick and per-peer caps are enforced inline in every layer through the
//!    [`Budget`] the driver builds. "Any limb binds → stop growing" (design
//!    §6:673). Ceiling-only posture: never emits [`PeeringAction::Disconnect`].
//!
//! ### Two-phase overlay timing (design §2.5)
//!
//! The durable `retry_pending` schedule survives between the reconcile
//! invocations at the two relevant cadence slots. The overlay layer at the
//! nostr-poll slot *enqueues* entries at `retry_after_ms = now`; the retry-dial
//! phase at the retry slot *dials* those now-due entries. Layer order within a
//! single call runs the retry-dial phase **before** the overlay enqueue, so an
//! overlay enqueue never dials in its own call — reproducing today's
//! insert-then-later-dial exactly.
//!
//! ### Cadence contract (driver responsibility)
//!
//! Behavior-neutrality across the tick depends on the driver populating only the
//! input relevant to each cadence slot (design §2 intro): the config-peer floor
//! runs only when `policy.auto_connect_peers` is non-empty (the startup
//! peer-connect seam, design §3 D4); the overlay/opportunistic layers run only
//! when their pools are populated. The driver also excludes the node's own
//! identity and the driver-only "candidate fresh enough to skip" /
//! "already connecting on this exact path" predicates when building the pools —
//! those read the live freshness cache / connection table at path granularity,
//! which the pure core does not observe (see the deviation notes in the C2
//! disposition).
//!
//! ## Scope: the drain gate (consumed by the C3 cutover)
//!
//! The `Gate` derived from the published `NodeState` gates the whole core: a
//! `Suspended` (draining) gate clears the retry schedule and returns no actions,
//! and the reflexes self-suppress, so the drain does not reconnect the peers it
//! just closed (design §8 correctness trap). `NotRunning` is the inert startup
//! gate. This core is **unwired** in this commit — nothing calls it on the hot
//! path yet; the driver cutover lands in the following commits.

use std::collections::{HashMap, HashSet};

use crate::PeerIdentity;
use crate::config::{ConnectPolicy, PeerAddress, PeerConfig};
use crate::identity::NodeAddr;
use crate::node::NodeState;
use crate::nostr::{OverlayEndpointAdvert, RendezvousDriver};
use crate::proto::fmp::backoff_ms;
use crate::transport::{TransportAddr, TransportId};

use super::retry::RetryState;

/// Drain/run gate derived from the supervisor's published [`NodeState`]
/// (design §6). Not a bare bool: it must also express "not yet running" (the
/// startup gate) distinctly from "draining" (the suspend gate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Gate {
    /// Pre-`Running` (or post-drain terminal): the core is inert.
    NotRunning,
    /// `Running`/`Degraded`: the core actively reconciles.
    Reconciling,
    /// `Draining`: the drain gate — clear the schedule, suppress reflexes,
    /// desired set is empty.
    Suspended,
}

impl Gate {
    /// Map the published [`NodeState`] to the gate (design §6:636):
    /// `Running`/`Degraded` → `Reconciling`; `Draining` → `Suspended`;
    /// everything else (`Created`/`Starting`/`Stopping`/`Stopped`/`Failed`) →
    /// `NotRunning`.
    pub(crate) fn from_state(state: NodeState) -> Self {
        match state {
            NodeState::Running | NodeState::Degraded => Gate::Reconciling,
            NodeState::Draining => Gate::Suspended,
            NodeState::Created
            | NodeState::Starting
            | NodeState::Stopping
            | NodeState::Stopped
            | NodeState::Failed => Gate::NotRunning,
        }
    }
}

/// Admission observations the ceiling needs (design §6:654), built by the driver
/// from the live maps at each cadence point. This is the only place the deleted
/// `available_outbound_slots` / `outbound_handshake_slots` / `outbound_link_slots`
/// arithmetic survives.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Budget {
    /// `outbound_handshake_slots()`: `max_connections == 0 ? MAX
    /// : max_connections - (connections + pending_connects)`.
    pub handshake_slots: usize,
    /// `outbound_link_slots()`: `max_links == 0 ? MAX : max_links - links`.
    pub link_slots: usize,
    /// `available_outbound_slots()` peer limb: `max_peers == 0 ? MAX
    /// : max_peers - peers`.
    pub peer_slots: usize,
    /// `outbound_admission_check()`: `max_peers == 0 || peers < max_peers`.
    pub admission_ok: bool,
    /// `MAX_DISCOVERY_CONNECTS_PER_TICK` (16).
    pub discovery_per_tick: usize,
    /// `MAX_RETRY_CONNECTIONS_PER_TICK` (16).
    pub retry_per_tick: usize,
    /// `MAX_PARALLEL_PATH_CANDIDATES_PER_PEER` (4).
    pub per_peer_cap: usize,
}

/// What the reconciler observes of today's dataplane maps (it never owns them).
/// Peer/leg identity is anonymous-capable so re-applying over
/// refactor-node-next's XX first-contact path stays neutral (design §7:1181).
#[derive(Clone, Debug, Default)]
pub(crate) struct Observed {
    /// `self.peers.len()`.
    // The scalar counts are carried for the ceiling's future set-point use and
    // driver observability; the C3b core reads admission via `Budget`, so they
    // are not yet read by any layer.
    #[allow(dead_code)] // populated for observability; read by later cutovers
    pub peers: usize,
    /// `self.connections.len()`.
    #[allow(dead_code)] // populated for observability; read by later cutovers
    pub connections: usize,
    /// `self.links.len()`.
    #[allow(dead_code)] // populated for observability; read by later cutovers
    pub links: usize,
    /// `self.pending_connects.len()`.
    #[allow(dead_code)] // populated for observability; read by later cutovers
    pub pending_connects: usize,
    /// The `peers` map keys (fully authenticated peers).
    pub connected: HashSet<NodeAddr>,
    /// Peers with an in-flight outbound connection (`is_connecting_to_peer`).
    pub connecting: HashSet<NodeAddr>,
    /// In-flight legs per peer = connections(expected == addr) +
    /// pending_connects(addr), used by the per-peer parallel cap. Anonymous
    /// None-identity legs never key this map.
    pub in_flight_by_peer: HashMap<NodeAddr, usize>,
}

/// A dialable candidate. Mirrors next's discovery tuple exactly
/// (`(TransportId, TransportAddr, Option<PeerIdentity>, bool)`), identity
/// anonymous-capable.
#[derive(Clone, Debug)]
pub(crate) struct Candidate {
    // transport_id / remote_addr are read by the opportunistic-growth driver
    // cutover (C5); the mandatory-floor + retry cutover (C3b) dials by identity.
    /// The transport to dial over.
    #[allow(dead_code)] // wired by the opportunistic cutover (C5)
    pub transport_id: TransportId,
    /// The remote address to dial.
    #[allow(dead_code)] // wired by the opportunistic cutover (C5)
    pub remote_addr: TransportAddr,
    /// The peer identity; `None` is an anonymous first-contact leg (design §7).
    pub identity: Option<PeerIdentity>,
    /// The trailing bool in next's tuple: whether this is an active-refresh dial
    /// against an already-connected peer.
    pub active_refresh: bool,
}

impl Candidate {
    /// Construct a peer-level dial candidate for the mandatory floor / retry
    /// layers.
    ///
    /// Config-peer dials are peer-level: the driver's `initiate_peer_connection`
    /// expands `peer_config.addresses` and selects transports as I/O, so the
    /// `transport_id` / `remote_addr` carried here are driver-reexpanded
    /// placeholders — only `identity` is authoritative for these layers. The
    /// placeholder `remote_addr` mirrors the peer's first configured address for
    /// observability; `transport_id` is a sentinel the driver ignores.
    fn for_peer_dial(identity: PeerIdentity, peer_config: &PeerConfig) -> Self {
        let remote_addr = peer_config
            .addresses
            .first()
            .map(|addr| TransportAddr::from_string(&addr.addr))
            .unwrap_or_else(|| TransportAddr::from_string(""));
        Self {
            transport_id: TransportId::new(0),
            remote_addr,
            identity: Some(identity),
            active_refresh: true,
        }
    }
}

/// Read-only candidate pools the driver drained this tick (design §6:650). Plain
/// data, no runtime handles.
#[derive(Clone, Debug, Default)]
pub(crate) struct DiscoveryPools {
    /// `bootstrap.cached_open_discovery_candidates(64)`:
    /// `(npub, endpoints, created_at_secs)`.
    pub overlay: Vec<(String, Vec<OverlayEndpointAdvert>, u64)>,
    /// `transport.discover()` beacons (auto-connect transports), pre-resolved.
    pub transport_neighbors: Vec<Candidate>,
    /// mDNS `LanEvent::Discovered` peers, pre-resolved.
    pub lan: Vec<Candidate>,
    /// `config.peers()` npub set (the overlay configured-vs-open filter).
    pub configured_npubs: HashSet<String>,
    /// npubs with `bootstrap.cooldown_until(npub, now).is_some()`.
    pub overlay_cooldown: HashSet<String>,
    /// `Some` on the one-shot startup sweep: the advert-age filter in seconds.
    pub startup_sweep_max_age_secs: Option<u64>,
}

/// The desired-state policy (design §5 knobs). Built once per invocation from
/// config.
#[derive(Clone, Debug)]
pub(crate) struct Policy {
    /// `config.peers()` filtered by `is_auto_connect()`.
    pub auto_connect_peers: Vec<PeerConfig>,
    // The limit triple is enforced through `Budget` (the admission arithmetic the
    // driver pre-computes), so the core does not read these directly; they are
    // carried on the policy for completeness and future set-point use.
    /// `node.limits.max_peers`.
    #[allow(dead_code)] // ceiling is enforced via Budget; carried for completeness
    pub max_peers: usize,
    /// `node.limits.max_connections`.
    #[allow(dead_code)] // ceiling is enforced via Budget; carried for completeness
    pub max_connections: usize,
    /// `node.limits.max_links`.
    #[allow(dead_code)] // ceiling is enforced via Budget; carried for completeness
    pub max_links: usize,
    /// `node.retry.base_interval_secs * 1000`.
    pub retry_base_interval_ms: u64,
    /// `node.retry.max_backoff_secs * 1000`.
    pub retry_max_backoff_ms: u64,
    /// `node.retry.max_retries`.
    pub retry_max_retries: u32,
    /// `node.rate_limit.handshake_timeout_secs * 1000`.
    pub handshake_timeout_ms: u64,
    /// `nostr.enabled && policy == Open`.
    pub open_discovery_enabled: bool,
    /// `nostr.open_discovery_max_pending`.
    pub open_discovery_max_pending: usize,
    /// `advert_ttl_secs * 1000 * OPEN_DISCOVERY_RETRY_LIFETIME_MULTIPLIER`.
    // NOTE: there is deliberately NO set-point N knob. The overlay pool is
    // CEILING-ONLY (design §9.2 option b).
    pub open_discovery_expires_ms: u64,
}

/// The action vocabulary (design §6:643). `Connect` carries the
/// anonymous-capable [`Candidate`]; `ScheduleRetry` reports the retry-schedule
/// delta the reconciler owns (for driver observability; the durable mutation is
/// internal).
#[derive(Clone, Debug)]
pub(crate) enum PeeringAction {
    /// Dial this candidate (driver performs the connect / handshake I/O).
    Connect(Candidate),
    /// Shed this peer. Reserved and unused at the ceiling-only posture of Step
    /// 1b (design §9.3 refuse-to-grow, no shed).
    #[allow(dead_code)] // Step 2: shedding/eviction emits this
    Disconnect(NodeAddr),
    /// A retry was (re)scheduled for `peer` at `backoff_ms` delay. Observability
    /// only; the durable mutation is on the reconciler's `retry_pending`.
    ScheduleRetry {
        /// The peer whose retry was scheduled.
        #[allow(dead_code)] // observability payload; the durable mutation is internal
        peer: NodeAddr,
        /// The backoff delay applied.
        #[allow(dead_code)] // observability payload; the durable mutation is internal
        backoff_ms: u64,
    },
}

/// The sans-IO decision core (mirror of `SupervisorFsm`). Holds the durable
/// cross-attempt retry schedule; time and I/O enter only as inputs.
#[derive(Default)]
pub(crate) struct PeeringReconciler {
    /// Cross-attempt retry schedule (moved off `Node.retry_pending`). The
    /// `retry_count` lives here, not per-connection, so escalating backoff
    /// survives a fresh connection per re-dial (design §6:704 / §7:1150). Keyed
    /// by [`NodeAddr`].
    pub(in crate::node) retry_pending: HashMap<NodeAddr, RetryState>,
}

impl PeeringReconciler {
    /// Reconcile the observed peer set toward the desired-state policy, returning
    /// the actions the driver must perform. See the module docs for the four
    /// layers, the two-phase overlay timing, and the cadence contract.
    pub(crate) fn reconcile(
        &mut self,
        policy: &Policy,
        observed: &Observed,
        budget: &Budget,
        pools: &DiscoveryPools,
        now: u64,
        gate: Gate,
    ) -> Vec<PeeringAction> {
        // Gate prologue (design §2.0).
        match gate {
            // Startup gate: inert before the substrate is ready (design §2.3).
            Gate::NotRunning => return Vec::new(),
            // Drain gate: clear the schedule and desire nothing (design §2.3).
            Gate::Suspended => {
                self.retry_pending.clear();
                return Vec::new();
            }
            Gate::Reconciling => {}
        }

        let mut actions = Vec::new();
        // Layer 1: mandatory floor. The config floor precedes the retry-dial
        // phase; the retry-dial phase precedes the overlay enqueue so a
        // same-call overlay insert never dials in its own call (two-phase, §2.5).
        self.layer_config_floor(policy, observed, &mut actions);
        self.layer_retry_dial(policy, observed, budget, now, &mut actions);
        // Layer 2: overlay pool (ceiling-only enqueue).
        self.layer_overlay_enqueue(policy, observed, budget, pools, now, &mut actions);
        // Layer 3: opportunistic growth.
        self.layer_opportunistic(observed, budget, pools, &mut actions);
        actions
    }

    /// Per-layer wrapper: run **only** the overlay-enqueue layer (design §10).
    ///
    /// The monolithic [`reconcile`] runs the always-on retry-dial phase on every
    /// call, so the driver must NOT call it at the overlay (nostr-poll) cadence
    /// slot — that would re-fire the retry-dial there, dialing the due entries a
    /// second time in the tick and applying the per-tick 16-cap more than once
    /// (today the cap applies exactly once, at the retry slot). This wrapper is
    /// gate-checked and then calls [`Self::layer_overlay_enqueue`] only.
    ///
    /// On `NotRunning` / `Suspended` it returns no actions. It does **not**
    /// clear `retry_pending` on `Suspended` — that clear is owned by the drain
    /// gate (`enter_drain`) and the retry-slot [`reconcile`], not the overlay
    /// slot (design §10). The returned [`PeeringAction::ScheduleRetry`] items are
    /// observability only; the durable mutation is the insert the layer performed
    /// into `retry_pending`, dialed at the later retry slot (two-phase, §2.5).
    pub(in crate::node) fn reconcile_overlay(
        &mut self,
        policy: &Policy,
        observed: &Observed,
        budget: &Budget,
        pools: &DiscoveryPools,
        now: u64,
        gate: Gate,
    ) -> Vec<PeeringAction> {
        match gate {
            Gate::NotRunning | Gate::Suspended => return Vec::new(),
            Gate::Reconciling => {}
        }
        let mut actions = Vec::new();
        self.layer_overlay_enqueue(policy, observed, budget, pools, now, &mut actions);
        actions
    }

    /// Layer 1a — config bring-up floor (subsumes `initiate_peer_connections`).
    ///
    /// Emits a `Connect` for every auto-connect peer not already connected or
    /// connecting. Not budget-gated (the startup floor is mandatory); the driver
    /// populates `policy.auto_connect_peers` only at the startup peer-connect
    /// seam so this does not re-fire every tick (design §3 D4).
    fn layer_config_floor(
        &self,
        policy: &Policy,
        observed: &Observed,
        actions: &mut Vec<PeeringAction>,
    ) {
        for peer_config in &policy.auto_connect_peers {
            let Ok(identity) = PeerIdentity::from_npub(&peer_config.npub) else {
                continue;
            };
            let addr = *identity.node_addr();
            if observed.connected.contains(&addr) || observed.connecting.contains(&addr) {
                continue;
            }
            actions.push(PeeringAction::Connect(Candidate::for_peer_dial(
                identity,
                peer_config,
            )));
        }
    }

    /// Layer 1b — retry-dial phase (subsumes `process_pending_retries`).
    ///
    /// Drops expired entries, refuses to grow when admission binds, then dials
    /// the first `retry_per_tick` due entries. Gated only by
    /// [`Budget::admission_ok`], matching today's `process_pending_retries`
    /// (which checks neither handshake nor link slots here).
    fn layer_retry_dial(
        &mut self,
        policy: &Policy,
        observed: &Observed,
        budget: &Budget,
        now: u64,
        actions: &mut Vec<PeeringAction>,
    ) {
        if self.retry_pending.is_empty() {
            return;
        }

        // Drop expired entries (retry.rs:204–220).
        let expired: Vec<NodeAddr> = self
            .retry_pending
            .iter()
            .filter_map(|(addr, state)| {
                state
                    .expires_at_ms
                    .filter(|expires_at_ms| now >= *expires_at_ms)
                    .map(|_| *addr)
            })
            .collect();
        for addr in expired {
            self.retry_pending.remove(&addr);
        }
        if self.retry_pending.is_empty() {
            return;
        }

        // At capacity → no growth (retry.rs:225).
        if !budget.admission_ok {
            return;
        }

        // Due entries, in HashMap iteration order (do not sort — preserves
        // today's order), capped at retry_per_tick (retry.rs:236–252).
        let due: Vec<NodeAddr> = self
            .retry_pending
            .iter()
            .filter(|(_, state)| now >= state.retry_after_ms)
            .map(|(addr, _)| *addr)
            .collect();

        for addr in due.into_iter().take(budget.retry_per_tick) {
            // Peer may have connected inbound while we waited (retry.rs:254).
            if observed.connected.contains(&addr) {
                self.retry_pending.remove(&addr);
                continue;
            }
            let Some(state) = self.retry_pending.get(&addr) else {
                continue;
            };
            let Ok(identity) = PeerIdentity::from_npub(&state.peer_config.npub) else {
                continue;
            };
            let candidate = Candidate::for_peer_dial(identity, &state.peer_config);
            actions.push(PeeringAction::Connect(candidate));
            // Suppress re-fire until the handshake window closes (retry.rs:298).
            if let Some(state) = self.retry_pending.get_mut(&addr) {
                state.retry_after_ms = now + policy.handshake_timeout_ms;
            }
        }
    }

    /// Layer 2 — overlay pool enqueue (subsumes `run_open_discovery_sweep`).
    ///
    /// Ceiling-only: the sole bound is the enqueue budget (pending cap ∧
    /// available outbound slots). No `>= N` set-point floor (design §9.2 option
    /// b). Enqueues due-now retry entries; the dial happens on a later
    /// retry-slot invocation (two-phase, §2.5).
    fn layer_overlay_enqueue(
        &mut self,
        policy: &Policy,
        observed: &Observed,
        budget: &Budget,
        pools: &DiscoveryPools,
        now: u64,
        actions: &mut Vec<PeeringAction>,
    ) {
        if !policy.open_discovery_enabled {
            return;
        }
        let now_secs = now / 1000;

        // open_discovery_enqueue_budget: cap_remaining ∧ available_outbound_slots
        // (== handshake_slots ∧ peer_slots). Note this is min(cap, handshake,
        // peer) — the real helper uses available_outbound_slots, NOT peer_slots
        // alone (see deviation note).
        let current_open_discovery_pending = self
            .retry_pending
            .values()
            .filter(|state| !pools.configured_npubs.contains(&state.peer_config.npub))
            .count();
        let cap_remaining = policy
            .open_discovery_max_pending
            .saturating_sub(current_open_discovery_pending);
        let available_outbound = budget.handshake_slots.min(budget.peer_slots);
        let mut enqueue_budget = cap_remaining.min(available_outbound);
        if enqueue_budget == 0 {
            return;
        }

        for (npub, endpoints, created_at_secs) in &pools.overlay {
            if enqueue_budget == 0 {
                break;
            }

            // Startup-sweep age filter (lifecycle:2155).
            if let Some(max_age) = pools.startup_sweep_max_age_secs
                && now_secs.saturating_sub(*created_at_secs) > max_age
            {
                continue;
            }

            // Configured peer: expedite an existing pending retry, then skip
            // (lifecycle:2162–2180).
            if pools.configured_npubs.contains(npub) {
                if let Ok(peer_identity) = PeerIdentity::from_npub(npub) {
                    let addr = *peer_identity.node_addr();
                    if !observed.connected.contains(&addr)
                        && !observed.connecting.contains(&addr)
                        && let Some(state) = self.retry_pending.get_mut(&addr)
                        && state.retry_after_ms > now
                    {
                        state.retry_after_ms = now;
                    }
                }
                continue;
            }

            let Ok(peer_identity) = PeerIdentity::from_npub(npub) else {
                continue; // skipped_invalid_npub (lifecycle:2182)
            };
            let addr = *peer_identity.node_addr();
            // Self is excluded by the driver when building the pool (the core has
            // no self identity input).
            if observed.connected.contains(&addr) {
                continue; // skipped_connected (lifecycle:2194)
            }
            if self.retry_pending.contains_key(&addr) {
                continue; // skipped_retry_pending (lifecycle:2198)
            }
            if pools.overlay_cooldown.contains(npub) {
                continue; // skipped_cooldown (lifecycle:2202)
            }
            if observed.connecting.contains(&addr) {
                continue; // skipped_connecting (lifecycle:2206)
            }

            // Build the address list from the advert endpoints (lifecycle:2216).
            let mut addresses = Vec::new();
            let mut priority = 120u8;
            for endpoint in endpoints {
                let Some(candidate) =
                    RendezvousDriver::overlay_endpoint_to_peer_address(endpoint, priority, now)
                else {
                    continue;
                };
                if addresses.iter().any(|existing: &PeerAddress| {
                    existing.transport == candidate.transport && existing.addr == candidate.addr
                }) {
                    continue;
                }
                addresses.push(candidate);
                priority = priority.saturating_add(1);
            }
            if addresses.is_empty() {
                continue; // skipped_no_endpoints (lifecycle:2235)
            }

            // Enqueue, immediately due (lifecycle:2245–2256).
            let mut state = RetryState::new(PeerConfig {
                npub: npub.clone(),
                alias: None,
                addresses,
                connect_policy: ConnectPolicy::AutoConnect,
                auto_reconnect: true,
                via_nostr: false,
            });
            state.reconnect = false;
            state.retry_after_ms = now;
            state.expires_at_ms = Some(now.saturating_add(policy.open_discovery_expires_ms));
            self.retry_pending.insert(addr, state);
            actions.push(PeeringAction::ScheduleRetry {
                peer: addr,
                backoff_ms: 0,
            });
            enqueue_budget = enqueue_budget.saturating_sub(1);
        }
    }

    /// Layer 3 — opportunistic growth (transport neighbors + LAN).
    ///
    /// Transport-neighbor growth (subsumes `poll_transport_discovery`) uses the
    /// discovery connect budget and the per-peer parallel cap; LAN growth
    /// (subsumes `poll_lan_rendezvous`) is simpler — connected/connecting skip
    /// only, no budget. The driver pre-filters self, "fresh enough to skip", and
    /// "already connecting on this exact path" when building the pools.
    fn layer_opportunistic(
        &self,
        observed: &Observed,
        budget: &Budget,
        pools: &DiscoveryPools,
        actions: &mut Vec<PeeringAction>,
    ) {
        // Transport neighbors: discovery_connect_budget ∧ per-peer cap.
        let mut connect_budget = budget
            .handshake_slots
            .min(budget.link_slots)
            .min(budget.discovery_per_tick);
        let mut queued_per_peer: HashMap<NodeAddr, usize> = HashMap::new();

        for cand in &pools.transport_neighbors {
            let Some(identity) = cand.identity else {
                continue; // anonymous leg cannot key the per-peer cap
            };
            let addr = *identity.node_addr();
            let queued = queued_per_peer.get(&addr).copied().unwrap_or(0);
            let per_peer = self
                .path_candidate_budget(&addr, observed, budget)
                .saturating_sub(queued);
            if connect_budget == 0 || per_peer == 0 {
                continue;
            }
            let connected = observed.connected.contains(&addr);
            let mut emit = cand.clone();
            emit.active_refresh = connected;
            actions.push(PeeringAction::Connect(emit));
            *queued_per_peer.entry(addr).or_default() += 1;
            connect_budget = connect_budget.saturating_sub(1);
        }

        // LAN: skip if connected or connecting, else dial (lifecycle:936). No
        // budget or per-peer cap in today's poll_lan_rendezvous.
        for cand in &pools.lan {
            let Some(identity) = cand.identity else {
                continue;
            };
            let addr = *identity.node_addr();
            if observed.connected.contains(&addr) || observed.connecting.contains(&addr) {
                continue;
            }
            actions.push(PeeringAction::Connect(cand.clone()));
        }
    }

    /// The per-peer parallel-attempt budget (subsumes
    /// `path_candidate_attempt_budget`): zero when the peer is new and admission
    /// binds, else `min(handshake_slots, link_slots, per_peer_cap - in_flight)`.
    fn path_candidate_budget(
        &self,
        addr: &NodeAddr,
        observed: &Observed,
        budget: &Budget,
    ) -> usize {
        if !observed.connected.contains(addr) && !budget.admission_ok {
            return 0;
        }
        let in_flight = observed.in_flight_by_peer.get(addr).copied().unwrap_or(0);
        budget
            .handshake_slots
            .min(budget.link_slots)
            .min(budget.per_peer_cap.saturating_sub(in_flight))
    }

    /// Reflex: an outbound handshake timed out (== `Node::schedule_retry`,
    /// retry.rs:58). Byte-identical retry_count/backoff math. No-op when the gate
    /// is `Suspended` (drain trap, §2.3, review decision D1).
    ///
    /// NOTE: today's `schedule_retry` also returns early if the peer is already
    /// connected (`self.peers.contains_key`). The reflex takes no [`Observed`]
    /// (D1 keeps the signature `(addr, now, policy, gate)`), so that
    /// connected-guard is the driver's responsibility at the call site.
    pub(crate) fn on_handshake_timeout(
        &mut self,
        addr: NodeAddr,
        now: u64,
        policy: &Policy,
        gate: Gate,
    ) -> Vec<PeeringAction> {
        if gate == Gate::Suspended {
            return Vec::new();
        }
        let max_retries = policy.retry_max_retries;
        if max_retries == 0 {
            return Vec::new();
        }
        let base = policy.retry_base_interval_ms;
        let cap = policy.retry_max_backoff_ms;

        if let Some(state) = self.retry_pending.get_mut(&addr) {
            state.retry_count += 1;
            if !state.reconnect && state.retry_count > max_retries {
                self.retry_pending.remove(&addr);
                return Vec::new();
            }
            let delay = backoff_ms(state.retry_count, base, cap);
            state.retry_after_ms = now + delay;
            return vec![PeeringAction::ScheduleRetry {
                peer: addr,
                backoff_ms: delay,
            }];
        }

        // First failure — find the matching config peer.
        let Some(peer_config) = policy
            .auto_connect_peers
            .iter()
            .find(|pc| {
                PeerIdentity::from_npub(&pc.npub)
                    .map(|id| *id.node_addr() == addr)
                    .unwrap_or(false)
            })
            .cloned()
        else {
            return Vec::new();
        };
        let mut state = RetryState::new(peer_config);
        state.retry_count = 1;
        state.reconnect = true;
        let delay = backoff_ms(state.retry_count, base, cap);
        state.retry_after_ms = now + delay;
        self.retry_pending.insert(addr, state);
        vec![PeeringAction::ScheduleRetry {
            peer: addr,
            backoff_ms: delay,
        }]
    }

    /// Reflex: a link went dead (== `Node::schedule_reconnect`, retry.rs:134).
    /// Byte-identical retry_count/backoff math, including preserving accumulated
    /// backoff across repeated link-dead events. No-op when the gate is
    /// `Suspended` (drain trap, §2.3, review decision D1).
    pub(crate) fn on_link_dead(
        &mut self,
        addr: NodeAddr,
        now: u64,
        policy: &Policy,
        gate: Gate,
    ) -> Vec<PeeringAction> {
        if gate == Gate::Suspended {
            return Vec::new();
        }
        let Some(peer_config) = policy
            .auto_connect_peers
            .iter()
            .find(|pc| {
                PeerIdentity::from_npub(&pc.npub)
                    .map(|id| *id.node_addr() == addr)
                    .unwrap_or(false)
            })
            .cloned()
        else {
            return Vec::new();
        };
        if !peer_config.auto_reconnect {
            return Vec::new();
        }
        let base = policy.retry_base_interval_ms;
        let cap = policy.retry_max_backoff_ms;

        if let Some(state) = self.retry_pending.get_mut(&addr) {
            state.reconnect = true;
            state.retry_count += 1;
            let delay = backoff_ms(state.retry_count, base, cap);
            state.retry_after_ms = now + delay;
            return vec![PeeringAction::ScheduleRetry {
                peer: addr,
                backoff_ms: delay,
            }];
        }

        let mut state = RetryState::new(peer_config);
        state.reconnect = true;
        let delay = backoff_ms(state.retry_count, base, cap);
        state.retry_after_ms = now + delay;
        self.retry_pending.insert(addr, state);
        vec![PeeringAction::ScheduleRetry {
            peer: addr,
            backoff_ms: delay,
        }]
    }

    /// Number of scheduled retries (for the driver's bookkeeping and tests).
    #[cfg(test)]
    pub(crate) fn retry_pending_len(&self) -> usize {
        self.retry_pending.len()
    }

    /// Whether a retry is scheduled for `addr` (tests).
    #[cfg(test)]
    pub(crate) fn retry_state(&self, addr: &NodeAddr) -> Option<&RetryState> {
        self.retry_pending.get(addr)
    }
}

/// Owner of the peering-homeostasis state that left `Node`, plus the sans-IO
/// reconciler (mirror of `Supervisor`). Pure relocation: the driver reaches each
/// field via `self.peering.*`.
pub(crate) struct Peering {
    /// Sans-IO decision core (owns the retry schedule).
    pub(in crate::node) reconciler: PeeringReconciler,
    /// Links awaiting transport-level connect before handshake (moved off
    /// `Node.pending_connects`). This is driver I/O-completion state, not a
    /// decision, so it lives on the owner, not the pure core.
    pub(in crate::node) pending_connects: Vec<crate::node::PendingConnect>,
}

impl Peering {
    /// A fresh owner with an empty reconciler and no pending connects.
    pub(crate) fn new() -> Self {
        Self {
            reconciler: PeeringReconciler::default(),
            pending_connects: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    const BASE_MS: u64 = 1_000;
    const CAP_MS: u64 = 60_000;
    const HS_TIMEOUT_MS: u64 = 5_000;

    /// A distinct random peer: its resolved identity, node address, and npub.
    fn mk_peer() -> (PeerIdentity, NodeAddr, String) {
        let identity = Identity::generate();
        let peer = PeerIdentity::from_pubkey(identity.pubkey());
        let addr = *peer.node_addr();
        let npub = peer.npub();
        (peer, addr, npub)
    }

    fn auto_peer(npub: &str) -> PeerConfig {
        PeerConfig {
            npub: npub.to_string(),
            alias: None,
            addresses: vec![PeerAddress::new("udp", "203.0.113.1:2121")],
            connect_policy: ConnectPolicy::AutoConnect,
            auto_reconnect: true,
            via_nostr: false,
        }
    }

    fn base_policy() -> Policy {
        Policy {
            auto_connect_peers: Vec::new(),
            max_peers: 0,
            max_connections: 0,
            max_links: 0,
            retry_base_interval_ms: BASE_MS,
            retry_max_backoff_ms: CAP_MS,
            retry_max_retries: 5,
            handshake_timeout_ms: HS_TIMEOUT_MS,
            open_discovery_enabled: false,
            open_discovery_max_pending: 32,
            open_discovery_expires_ms: 600_000,
        }
    }

    fn ample_budget() -> Budget {
        Budget {
            handshake_slots: 1_000,
            link_slots: 1_000,
            peer_slots: 1_000,
            admission_ok: true,
            discovery_per_tick: 16,
            retry_per_tick: 16,
            per_peer_cap: 4,
        }
    }

    fn count_connects(actions: &[PeeringAction]) -> usize {
        actions
            .iter()
            .filter(|a| matches!(a, PeeringAction::Connect(_)))
            .count()
    }

    // ---- Canonical test 1 --------------------------------------------------

    #[test]
    fn observed_3_desired_5_emits_two_connects() {
        let peers: Vec<_> = (0..5).map(|_| mk_peer()).collect();
        let mut policy = base_policy();
        policy.auto_connect_peers = peers.iter().map(|(_, _, npub)| auto_peer(npub)).collect();

        let mut observed = Observed::default();
        // First three are already connected.
        for (_, addr, _) in &peers[..3] {
            observed.connected.insert(*addr);
        }

        let mut r = PeeringReconciler::default();
        let actions = r.reconcile(
            &policy,
            &observed,
            &ample_budget(),
            &DiscoveryPools::default(),
            10_000,
            Gate::Reconciling,
        );

        assert_eq!(count_connects(&actions), 2);
        // The two Connects are exactly the two unconnected peers.
        let connected_addrs: HashSet<NodeAddr> = actions
            .iter()
            .filter_map(|a| match a {
                PeeringAction::Connect(c) => Some(*c.identity.unwrap().node_addr()),
                _ => None,
            })
            .collect();
        let expected: HashSet<NodeAddr> = peers[3..].iter().map(|(_, addr, _)| *addr).collect();
        assert_eq!(connected_addrs, expected);
    }

    // ---- Canonical test 2 --------------------------------------------------

    #[test]
    fn at_cap_any_limit_binds_no_growth() {
        // Each limb is tested against the layers it actually gates in today's
        // code: admission gates retry + overlay + opportunistic; handshake gates
        // overlay + opportunistic; link gates opportunistic.
        let (_, retry_addr, retry_npub) = mk_peer();
        let (_, overlay_addr, overlay_npub) = mk_peer();
        let (_, neigh_id, _neigh_addr, _) = {
            let (id, addr, npub) = mk_peer();
            (id, id, addr, npub)
        };
        let _ = overlay_addr;

        // auto_connect_peers stays empty: these reconcile calls model non-startup
        // cadence slots, where the config floor does not run (design §3 D4).
        let mut policy = base_policy();
        policy.open_discovery_enabled = true;

        // Seed a due retry, an overlay candidate, and a transport neighbor.
        let seed = |r: &mut PeeringReconciler| {
            let mut st = RetryState::new(auto_peer(&retry_npub));
            st.retry_after_ms = 0;
            r.insert_retry_for_test(retry_addr, st);
        };
        let pools = || DiscoveryPools {
            overlay: vec![(
                overlay_npub.clone(),
                vec![OverlayEndpointAdvert {
                    transport: crate::nostr::OverlayTransportKind::Udp,
                    addr: "203.0.113.9:2121".to_string(),
                }],
                0,
            )],
            transport_neighbors: vec![Candidate {
                transport_id: TransportId::new(1),
                remote_addr: TransportAddr::from_string("203.0.113.5:2121"),
                identity: Some(neigh_id),
                active_refresh: false,
            }],
            ..DiscoveryPools::default()
        };

        // (a) admission binds (peer_slots == 0, admission_ok == false).
        {
            let mut r = PeeringReconciler::default();
            seed(&mut r);
            let mut b = ample_budget();
            b.peer_slots = 0;
            b.admission_ok = false;
            let actions = r.reconcile(
                &policy,
                &Observed::default(),
                &b,
                &pools(),
                10_000,
                Gate::Reconciling,
            );
            assert_eq!(
                count_connects(&actions),
                0,
                "admission bind must refuse all growth"
            );
            assert!(
                !actions
                    .iter()
                    .any(|a| matches!(a, PeeringAction::ScheduleRetry { .. })),
                "admission bind must not enqueue overlay"
            );
        }

        // (b) handshake_slots == 0 → overlay + opportunistic refuse.
        {
            let mut r = PeeringReconciler::default();
            let mut b = ample_budget();
            b.handshake_slots = 0;
            let actions = r.reconcile(
                &policy,
                &Observed::default(),
                &b,
                &pools(),
                10_000,
                Gate::Reconciling,
            );
            assert!(
                !actions
                    .iter()
                    .any(|a| matches!(a, PeeringAction::ScheduleRetry { .. })),
                "handshake bind must not enqueue overlay"
            );
            assert_eq!(
                count_connects(&actions),
                0,
                "handshake bind must refuse opportunistic"
            );
        }

        // (c) link_slots == 0 → opportunistic refuses.
        {
            let mut r = PeeringReconciler::default();
            let mut b = ample_budget();
            b.link_slots = 0;
            let neigh_only = DiscoveryPools {
                transport_neighbors: pools().transport_neighbors,
                ..DiscoveryPools::default()
            };
            let actions = r.reconcile(
                &policy,
                &Observed::default(),
                &b,
                &neigh_only,
                10_000,
                Gate::Reconciling,
            );
            assert_eq!(
                count_connects(&actions),
                0,
                "link bind must refuse opportunistic"
            );
        }
    }

    // ---- Canonical test 3 --------------------------------------------------

    #[test]
    fn auto_connect_down_schedules_reconnect() {
        let (_, addr, npub) = mk_peer();
        let mut policy = base_policy();
        policy.auto_connect_peers = vec![auto_peer(&npub)];

        let mut r = PeeringReconciler::default();
        // First link-dead: fresh entry, retry_count stays 0, delay = backoff(0).
        let out = r.on_link_dead(addr, 1_000, &policy, Gate::Reconciling);
        assert!(matches!(
            out.as_slice(),
            [PeeringAction::ScheduleRetry { .. }]
        ));
        let st = r.retry_state(&addr).expect("entry scheduled");
        assert_eq!(st.retry_count, 0);
        assert_eq!(st.retry_after_ms, 1_000 + backoff_ms(0, BASE_MS, CAP_MS));

        // A later retry-slot reconcile (now past retry_after) dials once. The
        // retry-slot policy has an empty config floor (cadence contract, §3 D4),
        // so the single Connect comes only from the retry-dial phase.
        let now = 1_000 + backoff_ms(0, BASE_MS, CAP_MS);
        let tick_policy = base_policy();
        let actions = r.reconcile(
            &tick_policy,
            &Observed::default(),
            &ample_budget(),
            &DiscoveryPools::default(),
            now,
            Gate::Reconciling,
        );
        assert_eq!(count_connects(&actions), 1);

        // Escalation: a second link-dead bumps retry_count (does NOT reset to
        // base) and lengthens the backoff.
        r.on_link_dead(addr, now, &policy, Gate::Reconciling);
        let st = r.retry_state(&addr).expect("entry still scheduled");
        assert_eq!(st.retry_count, 1, "retry_count escalates, not reset");
        assert_eq!(st.retry_after_ms, now + backoff_ms(1, BASE_MS, CAP_MS));
        assert!(backoff_ms(1, BASE_MS, CAP_MS) > backoff_ms(0, BASE_MS, CAP_MS));
    }

    // ---- Canonical test 4 --------------------------------------------------

    #[test]
    fn draining_gate_empties_and_suppresses() {
        let (_, addr, npub) = mk_peer();
        let mut policy = base_policy();
        policy.auto_connect_peers = vec![auto_peer(&npub)];

        let mut r = PeeringReconciler::default();
        // Seed a retry entry.
        r.on_link_dead(addr, 1_000, &policy, Gate::Reconciling);
        assert_eq!(r.retry_pending_len(), 1);

        // Draining reconcile returns nothing AND clears the schedule.
        let actions = r.reconcile(
            &policy,
            &Observed::default(),
            &ample_budget(),
            &DiscoveryPools::default(),
            2_000,
            Gate::Suspended,
        );
        assert!(actions.is_empty());
        assert_eq!(r.retry_pending_len(), 0, "drain clears the schedule");

        // Reflex is suppressed while draining.
        let out = r.on_link_dead(addr, 3_000, &policy, Gate::Suspended);
        assert!(out.is_empty());
        assert_eq!(r.retry_pending_len(), 0, "drain suppresses the reflex");
        let out2 = r.on_handshake_timeout(addr, 3_000, &policy, Gate::Suspended);
        assert!(out2.is_empty());
        assert_eq!(r.retry_pending_len(), 0);
    }

    // ---- Canonical test 5 --------------------------------------------------

    #[test]
    fn startup_gate_no_connect_before_running() {
        let peers: Vec<_> = (0..3).map(|_| mk_peer()).collect();
        let mut policy = base_policy();
        policy.auto_connect_peers = peers.iter().map(|(_, _, npub)| auto_peer(npub)).collect();

        let mut r = PeeringReconciler::default();
        let actions = r.reconcile(
            &policy,
            &Observed::default(),
            &ample_budget(),
            &DiscoveryPools::default(),
            10_000,
            Gate::NotRunning,
        );
        assert!(actions.is_empty(), "no dial before Running");
    }

    // ---- Parity: two-phase overlay enqueue → later dial --------------------

    #[test]
    fn overlay_two_phase_enqueue_then_dial() {
        let (_, addr, npub) = mk_peer();
        let mut policy = base_policy();
        policy.open_discovery_enabled = true;

        let pools = DiscoveryPools {
            overlay: vec![(
                npub.clone(),
                vec![OverlayEndpointAdvert {
                    transport: crate::nostr::OverlayTransportKind::Udp,
                    addr: "203.0.113.7:2121".to_string(),
                }],
                0,
            )],
            ..DiscoveryPools::default()
        };

        let mut r = PeeringReconciler::default();
        // Phase 1 (nostr slot): overlay populated → enqueue only, no dial.
        let phase1 = r.reconcile(
            &policy,
            &Observed::default(),
            &ample_budget(),
            &pools,
            10_000,
            Gate::Reconciling,
        );
        assert_eq!(
            count_connects(&phase1),
            0,
            "phase 1 enqueues, does not dial"
        );
        assert!(
            phase1
                .iter()
                .any(|a| matches!(a, PeeringAction::ScheduleRetry { peer, backoff_ms: 0 } if *peer == addr)),
            "phase 1 enqueues the overlay peer at 0 backoff"
        );
        assert!(r.retry_state(&addr).is_some());
        assert_eq!(r.retry_state(&addr).unwrap().retry_after_ms, 10_000);

        // Phase 2 (retry slot): overlay empty → the now-due entry dials.
        let phase2 = r.reconcile(
            &policy,
            &Observed::default(),
            &ample_budget(),
            &DiscoveryPools::default(),
            10_000,
            Gate::Reconciling,
        );
        assert_eq!(
            count_connects(&phase2),
            1,
            "phase 2 dials the enqueued entry"
        );
    }

    // ---- Parity: per-peer parallel cap (4 legs max) ------------------------

    #[test]
    fn per_peer_parallel_cap_limits_legs() {
        let (id, _addr, _npub) = mk_peer();
        // Five distinct paths to the SAME peer.
        let neighbors: Vec<Candidate> = (0..5)
            .map(|i| Candidate {
                transport_id: TransportId::new(1),
                remote_addr: TransportAddr::from_string(&format!("203.0.113.{i}:2121")),
                identity: Some(id),
                active_refresh: false,
            })
            .collect();
        let pools = DiscoveryPools {
            transport_neighbors: neighbors,
            ..DiscoveryPools::default()
        };

        let mut r = PeeringReconciler::default();
        let actions = r.reconcile(
            &base_policy(),
            &Observed::default(),
            &ample_budget(),
            &pools,
            10_000,
            Gate::Reconciling,
        );
        // per_peer_cap == 4, in_flight == 0 → at most 4 legs to one peer.
        assert_eq!(count_connects(&actions), 4);
    }

    // ---- Parity: per-tick retry cap (17 due → 16 dial + 1 deferred) --------

    #[test]
    fn per_tick_retry_cap_defers_seventeenth() {
        let peers: Vec<_> = (0..17).map(|_| mk_peer()).collect();
        // Empty config floor: the retry-dial phase alone drives this slot.
        let policy = base_policy();

        let mut r = PeeringReconciler::default();
        for (_, addr, npub) in &peers {
            let mut st = RetryState::new(auto_peer(npub));
            st.retry_after_ms = 0; // due
            r.insert_retry_for_test(*addr, st);
        }

        let actions = r.reconcile(
            &policy,
            &Observed::default(),
            &ample_budget(),
            &DiscoveryPools::default(),
            10_000,
            Gate::Reconciling,
        );
        // retry_per_tick == 16 → exactly 16 dialed, the 17th deferred.
        assert_eq!(count_connects(&actions), 16);
        // All 17 entries survive (dialed ones just get retry_after_ms bumped).
        assert_eq!(r.retry_pending_len(), 17);
    }

    // ---- Parity: expires_at_ms drop ----------------------------------------

    #[test]
    fn expired_retry_entry_is_dropped_before_dial() {
        let (_, addr, npub) = mk_peer();
        // Empty config floor: the retry-dial phase alone drives this slot.
        let policy = base_policy();

        let mut r = PeeringReconciler::default();
        let mut st = RetryState::new(auto_peer(&npub));
        st.retry_after_ms = 0; // would be due
        st.expires_at_ms = Some(5_000); // but expires before now
        r.insert_retry_for_test(addr, st);

        let actions = r.reconcile(
            &policy,
            &Observed::default(),
            &ample_budget(),
            &DiscoveryPools::default(),
            10_000, // now >= expires_at_ms
            Gate::Reconciling,
        );
        assert_eq!(count_connects(&actions), 0, "expired entry does not dial");
        assert_eq!(r.retry_pending_len(), 0, "expired entry is dropped");
    }

    // ---- Reflex: max-retries exhaustion (schedule_retry parity) ------------

    #[test]
    fn handshake_timeout_gives_up_after_max_retries() {
        let (_, addr, npub) = mk_peer();
        let mut policy = base_policy();
        policy.retry_max_retries = 3;
        // A one-shot (non-reconnect) peer: schedule_retry seeds reconnect=true on
        // first entry, so use on_handshake_timeout repeatedly on a non-reconnect
        // seed to exercise the give-up path.
        policy.auto_connect_peers = vec![auto_peer(&npub)];

        let mut r = PeeringReconciler::default();
        // Seed a non-reconnect entry so the max-retries give-up path applies.
        let mut st = RetryState::new(auto_peer(&npub));
        st.reconnect = false;
        st.retry_count = 3; // at the limit
        r.insert_retry_for_test(addr, st);

        // Next timeout bumps to 4 > max(3) with reconnect=false → give up.
        let out = r.on_handshake_timeout(addr, 1_000, &policy, Gate::Reconciling);
        assert!(out.is_empty());
        assert_eq!(r.retry_pending_len(), 0, "exhausted retry is removed");
    }

    #[test]
    fn gate_from_state_maps_all_variants() {
        assert_eq!(Gate::from_state(NodeState::Running), Gate::Reconciling);
        assert_eq!(Gate::from_state(NodeState::Degraded), Gate::Reconciling);
        assert_eq!(Gate::from_state(NodeState::Draining), Gate::Suspended);
        for s in [
            NodeState::Created,
            NodeState::Starting,
            NodeState::Stopping,
            NodeState::Stopped,
            NodeState::Failed,
        ] {
            assert_eq!(Gate::from_state(s), Gate::NotRunning);
        }
    }

    impl PeeringReconciler {
        /// Seed a retry entry directly (tests only).
        fn insert_retry_for_test(&mut self, addr: NodeAddr, state: RetryState) {
            self.retry_pending.insert(addr, state);
        }
    }
}
