//! Sans-IO discovery decision core.
//!
//! Pure, runtime-agnostic decision logic for the discovery protocol. The
//! async I/O adapter in `node::handlers::discovery` decodes wire bytes,
//! calls into this core, and drives the returned actions (the actual
//! encrypted sends). No I/O, no clock, no metrics, no logging here.

use alloc::sync::Arc;

use super::state::{Discovery, PendingLookup, RecentRequest};
use super::wire::LookupRequest;
use crate::NodeAddr;

/// Read-only view of routing state the discovery core needs.
///
/// The core defines this interface; the async shell (`node`) implements it
/// over the live peer/tree tables. Keeping it a trait keeps `proto` free of
/// any dependency on `node` and lets the core be unit-tested with a mock.
pub(crate) trait RoutingView {
    /// Is `addr` a spanning-tree peer (parent or child)?
    fn is_tree_peer(&self, addr: &NodeAddr) -> bool;
    /// Peers whose bloom filter may reach `target` (i.e. `may_reach(target)`).
    fn peers_reaching(&self, target: &NodeAddr) -> Vec<NodeAddr>;
}

/// An I/O action the async shell performs on the core's behalf.
pub(crate) enum DiscoveryAction {
    /// Send an encoded discovery PDU to a peer as an encrypted link message.
    /// `bytes` is `Arc`-shared so a fan-out encodes once.
    SendLink { peer: NodeAddr, bytes: Arc<[u8]> },
    /// Cache the verified destination coordinates + path MTU (coord_cache).
    CacheCoords {
        target: NodeAddr,
        coords: crate::TreeCoordinate,
        now_ms: u64,
        path_mtu: u16,
    },
    /// Mirror path_mtu into the FipsAddress-keyed TUN-shared lookup map.
    WritePathMtu { target: NodeAddr, path_mtu: u16 },
    /// Reset the coords-warmup counter if an established session exists.
    ResetWarmupIfEstablished { target: NodeAddr },
    /// Retry queued TUN packets for the target if any are pending.
    RetryQueuedPackets { target: NodeAddr },
}

/// Outcome of planning a LookupRequest forward.
pub(crate) enum ForwardOutcome {
    /// TTL was exhausted — nothing to do.
    TtlExhausted,
    /// No eligible peer had the target in its bloom filter.
    NoPeers,
    /// Forward: one SendLink per selected peer. `used_fallback` is true when
    /// the non-tree bloom-match fallback set was used (no tree peer matched).
    Forward {
        actions: Vec<DiscoveryAction>,
        used_fallback: bool,
    },
}

/// Plan the transit forward of an inbound LookupRequest.
///
/// Decrements TTL; selects tree peers whose bloom matches the target, else a
/// non-tree bloom-match fallback; encodes the (decremented) request once and
/// emits one SendLink per selected peer. Pure — no I/O, metrics, or logs.
pub(crate) fn plan_forward(request: &mut LookupRequest, rv: &impl RoutingView) -> ForwardOutcome {
    if !request.forward() {
        return ForwardOutcome::TtlExhausted;
    }
    let target = request.target;
    let reaching = rv.peers_reaching(&target);
    let tree: Vec<NodeAddr> = reaching
        .iter()
        .copied()
        .filter(|a| rv.is_tree_peer(a))
        .collect();
    let (targets, used_fallback) = if tree.is_empty() {
        let fallback: Vec<NodeAddr> = reaching
            .into_iter()
            .filter(|a| !rv.is_tree_peer(a))
            .collect();
        if fallback.is_empty() {
            return ForwardOutcome::NoPeers;
        }
        (fallback, true)
    } else {
        (tree, false)
    };
    let bytes: Arc<[u8]> = Arc::from(request.encode());
    let actions = targets
        .into_iter()
        .map(|peer| DiscoveryAction::SendLink {
            peer,
            bytes: bytes.clone(),
        })
        .collect();
    ForwardOutcome::Forward {
        actions,
        used_fallback,
    }
}

/// Plan the origination of a freshly-generated LookupRequest.
///
/// Selects tree peers whose bloom matches the target and emits one SendLink per
/// selected peer, encoding the request once (Arc-shared). Returns an empty Vec
/// when no tree peer matches; the shell treats that as an immediate failure.
/// Pure — no I/O, metrics, or logs; the shell generates and signs the request.
///
/// NOTE: unlike [`plan_forward`], this does NOT fall back to non-tree
/// (cross-link) bloom-matching peers. That asymmetry is preserved verbatim from
/// the pre-sans-IO `initiate_lookup` to keep this extraction behavior-neutral;
/// it is a known origination gap (ISSUE-2026-0059) whose fix adds the fallback
/// branch as a separate, behavior-changing change.
pub(crate) fn plan_initiate(
    request: &LookupRequest,
    rv: &impl RoutingView,
) -> Vec<DiscoveryAction> {
    let targets: Vec<NodeAddr> = rv
        .peers_reaching(&request.target)
        .into_iter()
        .filter(|addr| rv.is_tree_peer(addr))
        .collect();
    if targets.is_empty() {
        return Vec::new();
    }
    let bytes: Arc<[u8]> = Arc::from(request.encode());
    targets
        .into_iter()
        .map(|peer| DiscoveryAction::SendLink {
            peer,
            bytes: bytes.clone(),
        })
        .collect()
}

/// Classification of an inbound LookupRequest, decided from Discovery state.
pub(crate) enum RequestOutcome {
    /// request_id already in the dedup cache — drop.
    Duplicate,
    /// dedup cache at capacity — drop. `len` is the current cache size (for the log).
    DedupCacheFull { len: usize },
    /// We are the lookup target — the shell generates + sends the response.
    RespondAsTarget,
    /// Forward the request onward (the shell calls the forward planner).
    Forward,
    /// Transit forward suppressed by the per-target forward rate limiter.
    ForwardRateLimited,
    /// TTL exhausted, not the target — drop.
    TtlExhausted,
}

/// Classify an inbound LookupRequest against the recent-request dedup cache and
/// the transit forward rate limiter. Purges expired dedup entries, records the
/// request for reverse-path forwarding on the non-drop paths, and decides the
/// route. Pure over Discovery state + node addr + injected clock; no I/O, no view.
pub(crate) fn classify_request(
    disc: &mut Discovery,
    request: &LookupRequest,
    from: &NodeAddr,
    my_addr: &NodeAddr,
    now_ms: u64,
    recent_expiry_ms: u64,
    max_recent: usize,
) -> RequestOutcome {
    // Purge expired dedup entries (was purge_expired_requests).
    disc.recent_requests
        .retain(|_, entry| !entry.is_expired(now_ms, recent_expiry_ms));

    if disc.recent_requests.contains_key(&request.request_id) {
        return RequestOutcome::Duplicate;
    }
    if disc.recent_requests.len() >= max_recent {
        return RequestOutcome::DedupCacheFull {
            len: disc.recent_requests.len(),
        };
    }
    disc.recent_requests
        .insert(request.request_id, RecentRequest::new(*from, now_ms));

    if request.target == *my_addr {
        return RequestOutcome::RespondAsTarget;
    }
    if request.can_forward() {
        if disc.forward_limiter.should_forward(&request.target, now_ms) {
            RequestOutcome::Forward
        } else {
            RequestOutcome::ForwardRateLimited
        }
    } else {
        RequestOutcome::TtlExhausted
    }
}

/// How an inbound LookupResponse should be routed, decided from the
/// recent-request dedup state.
pub(crate) enum ResponseRoute {
    /// A response for a request we forwarded, but we already reverse-forwarded
    /// one for this request_id — drop to prevent response routing loops.
    AlreadyForwarded,
    /// Transit node: reverse-path forward toward `from_peer`.
    Transit { from_peer: NodeAddr },
    /// We originated this request — the shell verifies the proof and caches.
    Originator,
}

/// Classify an inbound LookupResponse against the recent-request dedup cache.
///
/// Pure decision over `Discovery` state: sets `response_forwarded` when this is
/// the first response we transit for the request. No I/O, no view, no metrics.
pub(crate) fn classify_response(disc: &mut Discovery, request_id: u64) -> ResponseRoute {
    match disc.recent_requests.get_mut(&request_id) {
        Some(recent) => {
            if recent.response_forwarded {
                ResponseRoute::AlreadyForwarded
            } else {
                recent.response_forwarded = true;
                ResponseRoute::Transit {
                    from_peer: recent.from_peer,
                }
            }
        }
        None => ResponseRoute::Originator,
    }
}

/// Where a LookupResponse we originate as the target should be sent first.
pub(crate) enum ResponseRouteDecision {
    /// Send toward the peer the matching request arrived from — the reverse path
    /// recorded in `recent_requests` by [`classify_request`].
    ReversePath(NodeAddr),
    /// No recorded reverse path: the shell must route greedily toward the origin.
    NeedsTreeRoute,
}

/// Decide the first hop for a LookupResponse we originate as the target, from
/// the recent-request reverse-path record. Pure over `Discovery` state.
///
/// Only the reverse-path decision is pure. The `NeedsTreeRoute` fallback (greedy
/// tree routing toward the origin) is a `&mut Node` coord-cache operation with a
/// TTL-touch side effect, so it stays in the shell rather than moving here.
pub(crate) fn plan_response_route(disc: &Discovery, request_id: u64) -> ResponseRouteDecision {
    match disc.recent_requests.get(&request_id) {
        Some(recent) => ResponseRouteDecision::ReversePath(recent.from_peer),
        None => ResponseRouteDecision::NeedsTreeRoute,
    }
}

/// Apply the accept-side effects of a verified LookupResponse we originated.
///
/// Mutates the Discovery success state (clears backoff, drops the pending
/// lookup) and returns the cross-subsystem effects for the shell to drive.
/// Verification is the shell's job — this runs only after the proof checked out.
pub(crate) fn on_response_accepted(
    disc: &mut Discovery,
    target: &NodeAddr,
    coords: crate::TreeCoordinate,
    now_ms: u64,
    path_mtu: u16,
) -> Vec<DiscoveryAction> {
    disc.backoff.record_success(target);
    disc.pending_lookups.remove(target);
    vec![
        DiscoveryAction::CacheCoords {
            target: *target,
            coords,
            now_ms,
            path_mtu,
        },
        DiscoveryAction::WritePathMtu {
            target: *target,
            path_mtu,
        },
        DiscoveryAction::ResetWarmupIfEstablished { target: *target },
        DiscoveryAction::RetryQueuedPackets { target: *target },
    ]
}

/// Result of polling the pending-lookup retry ladder at `now_ms`.
///
/// The core has already applied the state mutations: retried entries have had
/// their attempt bumped and last_sent updated; timed-out entries have been
/// removed and a backoff failure recorded. The shell drives the effects.
pub(crate) struct PollOutcome {
    /// (target, new attempt number) — shell re-sends via initiate_lookup.
    pub retries: Vec<(NodeAddr, u8)>,
    /// (target, failure_count after recording) — shell emits unreachable.
    pub timeouts: Vec<(NodeAddr, u32)>,
}

/// Advance the pending-lookup retry ladder. Pure over `Discovery` state +
/// injected clock: partitions due entries into retries (attempt bumped) and
/// final timeouts (removed + backoff failure recorded). No I/O, no view.
pub(crate) fn poll_pending(
    disc: &mut Discovery,
    now_ms: u64,
    attempt_timeouts_secs: &[u64],
) -> PollOutcome {
    let max_attempts = attempt_timeouts_secs.len() as u8;

    // Collect targets needing action (can't mutate while iterating).
    let mut retry_targets: Vec<NodeAddr> = Vec::new();
    let mut timeout_targets: Vec<NodeAddr> = Vec::new();

    for (&target, entry) in &disc.pending_lookups {
        let idx = (entry.attempt as usize).saturating_sub(1);
        let to_ms = attempt_timeouts_secs.get(idx).copied().unwrap_or(0) * 1000;
        if now_ms.saturating_sub(entry.last_sent_ms) >= to_ms {
            if entry.attempt >= max_attempts {
                timeout_targets.push(target);
            } else {
                retry_targets.push(target);
            }
        }
    }

    let mut retries: Vec<(NodeAddr, u8)> = Vec::new();
    for target in retry_targets {
        if let Some(entry) = disc.pending_lookups.get_mut(&target) {
            entry.attempt += 1;
            entry.last_sent_ms = now_ms;
            retries.push((target, entry.attempt));
        }
    }

    let mut timeouts: Vec<(NodeAddr, u32)> = Vec::new();
    for target in timeout_targets {
        disc.pending_lookups.remove(&target);
        disc.backoff.record_failure(&target, now_ms);
        let failures = disc.backoff.failure_count(&target);
        timeouts.push((target, failures));
    }

    PollOutcome { retries, timeouts }
}

/// Decision for whether/how to initiate a discovery lookup for a target.
pub(crate) enum InitiateDecision {
    /// A lookup is already pending for this target — skip.
    Deduplicated,
    /// Suppressed by post-failure backoff. `failures` is the current count (for the log).
    Suppressed { failures: u32 },
    /// No peer's bloom filter reaches the target — skip (a failure was recorded).
    BloomMiss,
    /// Proceed: a PendingLookup was inserted; the shell sends the first attempt.
    Proceed,
}

/// Gate a discovery-lookup initiation against pending-dedup, backoff
/// suppression, and bloom reachability (passed in — the shell reads the peer
/// filters). On BloomMiss records a failure; on Proceed inserts the pending
/// lookup. Pure over Discovery state + injected clock; no I/O, no view.
pub(crate) fn initiate_gate(
    disc: &mut Discovery,
    dest: &NodeAddr,
    now_ms: u64,
    reachable: bool,
) -> InitiateDecision {
    if disc.pending_lookups.contains_key(dest) {
        return InitiateDecision::Deduplicated;
    }
    if disc.backoff.is_suppressed(dest, now_ms) {
        return InitiateDecision::Suppressed {
            failures: disc.backoff.failure_count(dest),
        };
    }
    if !reachable {
        disc.backoff.record_failure(dest, now_ms);
        return InitiateDecision::BloomMiss;
    }
    disc.pending_lookups
        .insert(*dest, PendingLookup::new(now_ms));
    InitiateDecision::Proceed
}

/// Roll back a lookup whose first attempt reached no tree peers (sent == 0):
/// drop the pending entry and record a backoff failure.
pub(crate) fn initiate_failed(disc: &mut Discovery, dest: &NodeAddr, now_ms: u64) {
    disc.pending_lookups.remove(dest);
    disc.backoff.record_failure(dest, now_ms);
}
