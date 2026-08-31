//! Sans-IO mesh lookup decision core.
//!
//! Pure, runtime-agnostic decision logic for the mesh lookup protocol. The
//! async I/O adapter in `node::handlers::lookup` decodes wire bytes,
//! calls into this core, and drives the returned actions (the actual
//! encrypted sends). No I/O, no clock, no metrics, no logging here.

use alloc::sync::Arc;

use super::state::{Lookup, PendingLookup};
use super::wire::LookupRequest;
use crate::NodeAddr;

/// Read-only view of routing state the lookup core needs.
///
/// The core defines this interface; the async shell (`node`) implements it
/// over the live peer/tree tables. Keeping it a trait keeps `proto` free of
/// any dependency on `node` and lets the core be unit-tested with a mock.
pub(crate) trait RoutingView {
    /// Is `addr` a spanning-tree peer (parent or child)?
    fn is_tree_peer(&self, addr: &NodeAddr) -> bool;
    /// Peers whose bloom filter may reach `target` (i.e. `may_reach(target)`).
    fn peers_reaching(&self, target: &NodeAddr) -> Vec<NodeAddr>;
    /// Is this node a Leaf? Leaves do not transit-forward lookup requests.
    fn node_is_leaf(&self) -> bool;
    /// Does `addr` advertise the Full profile? Only Full peers are forwarded to.
    fn peer_is_full(&self, addr: &NodeAddr) -> bool;
    /// Does `addr`'s outgoing link MTU satisfy `min_mtu`? (`min_mtu == 0` means
    /// no requirement; a peer with no known transport MTU is not pruned.)
    fn peer_meets_mtu(&self, addr: &NodeAddr, min_mtu: u16) -> bool;
}

/// An I/O action the async shell performs on the core's behalf.
pub(crate) enum LookupAction {
    /// Send an encoded lookup PDU to a peer as an encrypted link message.
    /// `bytes` is `Arc`-shared so a fan-out encodes once.
    SendLink { peer: NodeAddr, bytes: Arc<[u8]> },
    /// Cache the verified destination coordinates + path MTU (coord_cache).
    ///
    /// `request_id` is the correlator of the response this write came from. The
    /// shell logs a warning here when `path_mtu` is below the actionable floor,
    /// and that line is only correlatable with the rest of the exchange if the
    /// action carries the id — by then the response itself is out of scope.
    CacheCoords {
        request_id: u64,
        target: NodeAddr,
        coords: crate::TreeCoordinate,
        now_ms: u64,
        path_mtu: u16,
    },
    /// Mirror path_mtu into the FipsAddress-keyed TUN-shared lookup map.
    ///
    /// `now_ms` stamps the entry's expiry deadline. It is the same instant
    /// [`Self::CacheCoords`] carries, because the clamp this write feeds must
    /// not outlive the route it was learned with.
    WritePathMtu {
        target: NodeAddr,
        now_ms: u64,
        path_mtu: u16,
    },
    /// Reset the coords-warmup counter if an established session exists.
    ResetWarmupIfEstablished { target: NodeAddr },
    /// Retry queued TUN packets for the target if any are pending.
    RetryQueuedPackets { target: NodeAddr },
}

/// Outcome of planning a LookupRequest forward.
pub(crate) enum ForwardOutcome {
    /// TTL was exhausted — nothing to do.
    TtlExhausted,
    /// This node is a Leaf; leaves do not transit-forward. Silent no-op.
    LeafNoForward,
    /// No eligible peer had the target in its bloom filter.
    NoPeers,
    /// Forward: one SendLink per selected peer. `used_fallback` is true when
    /// the non-tree bloom-match fallback set was used (no tree peer matched).
    Forward {
        actions: Vec<LookupAction>,
        used_fallback: bool,
    },
}

/// Plan the transit forward of an inbound LookupRequest.
///
/// Decrements TTL; suppresses forwarding on a Leaf node; restricts candidates to
/// Full peers whose link satisfies the request's `min_mtu`; selects tree peers
/// whose bloom matches the target, else a non-tree bloom-match fallback; encodes
/// the (decremented) request once and emits one SendLink per selected peer. Pure
/// — no I/O, metrics, or logs.
pub(crate) fn plan_forward(request: &mut LookupRequest, rv: &impl RoutingView) -> ForwardOutcome {
    if !request.forward() {
        return ForwardOutcome::TtlExhausted;
    }
    // Leaf nodes do not transit-forward lookup requests.
    if rv.node_is_leaf() {
        return ForwardOutcome::LeafNoForward;
    }
    let target = request.target;
    let min_mtu = request.min_mtu;
    // Only Full peers whose outgoing link satisfies min_mtu are eligible.
    let eligible: Vec<NodeAddr> = rv
        .peers_reaching(&target)
        .into_iter()
        .filter(|a| rv.peer_is_full(a) && rv.peer_meets_mtu(a, min_mtu))
        .collect();
    let tree: Vec<NodeAddr> = eligible
        .iter()
        .copied()
        .filter(|a| rv.is_tree_peer(a))
        .collect();
    let (targets, used_fallback) = if tree.is_empty() {
        let fallback: Vec<NodeAddr> = eligible
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
        .map(|peer| LookupAction::SendLink {
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
/// it is a known origination gap whose fix adds the fallback branch as a
/// separate, behavior-changing change.
pub(crate) fn plan_initiate(request: &LookupRequest, rv: &impl RoutingView) -> Vec<LookupAction> {
    let min_mtu = request.min_mtu;
    let targets: Vec<NodeAddr> = rv
        .peers_reaching(&request.target)
        .into_iter()
        .filter(|addr| {
            rv.is_tree_peer(addr) && rv.peer_is_full(addr) && rv.peer_meets_mtu(addr, min_mtu)
        })
        .collect();
    if targets.is_empty() {
        return Vec::new();
    }
    let bytes: Arc<[u8]> = Arc::from(request.encode());
    targets
        .into_iter()
        .map(|peer| LookupAction::SendLink {
            peer,
            bytes: bytes.clone(),
        })
        .collect()
}

/// Classification of an inbound LookupRequest, decided from Lookup state.
pub(crate) enum RequestOutcome {
    /// request_id already in the dedup cache — drop.
    Duplicate,
    /// A request this node originated, looped back to it — drop without
    /// recording. Kept separate from `Duplicate`, which means another node
    /// resent a request, so the two do not share a rejection counter: this
    /// one has a nonzero floor in healthy operation and says nothing about
    /// the peer that delivered it.
    OwnRequestLooped,
    /// We are the lookup target — the shell generates + sends the response.
    RespondAsTarget,
    /// Forward the request onward (the shell calls the forward planner).
    Forward,
    /// Transit forward suppressed by the per-target forward rate limiter.
    ForwardRateLimited,
    /// TTL exhausted, not the target — drop.
    TtlExhausted,
}

/// One dedup-cache entry dropped to make room for an arriving request.
///
/// Returned to the shell so it can count and log the eviction; the core does
/// no metrics and no logging itself.
pub(crate) struct Eviction {
    /// The `request_id` that was dropped. Its reverse path is gone: a
    /// response still in flight for it will be treated as unsolicited.
    pub request_id: u64,
    /// The link peer charged for the eviction — the one whose oldest entry
    /// this was, which is not necessarily the peer being admitted.
    pub peer: NodeAddr,
    /// The per-peer share in force at the time, for the log line.
    pub share: usize,
}

/// The result of classifying an inbound LookupRequest: the route decision,
/// plus any entry that was evicted to make room for it.
pub(crate) struct Classification {
    /// What the shell should do with the request.
    pub outcome: RequestOutcome,
    /// The entry dropped to admit this request, if one was.
    pub evicted: Option<Eviction>,
}

/// Evict from the dedup cache if admitting one more request would put this
/// peer over its share, or the cache over its capacity.
///
/// Who pays is the whole point. Over its own share a peer pays for itself,
/// and at global capacity the peer holding the most entries pays, so a light
/// peer's reverse path is never taken to admit a heavy one and extra
/// identities buy a flooder proportionally less. Nothing is evicted while
/// the peer is under its share and the cache is under capacity.
fn make_room(
    lookup: &mut Lookup,
    from: &NodeAddr,
    max_recent: usize,
    peer_count: usize,
) -> Option<Eviction> {
    let share = Lookup::peer_share(max_recent, peer_count);
    let victim = if lookup.peer_entries(from) >= share {
        *from
    } else if lookup.recent_requests.len() >= max_recent {
        // Never charge the arriving peer when it is under its share: charge
        // whoever is holding the most.
        lookup.heaviest_peer()?
    } else {
        return None;
    };
    let request_id = lookup.evict_oldest_from(&victim)?;
    Some(Eviction {
        request_id,
        peer: victim,
        share,
    })
}

/// Classify an inbound LookupRequest against the recent-request dedup cache and
/// the transit forward rate limiter. Purges expired dedup entries, records the
/// request for reverse-path forwarding on the non-drop paths, and decides the
/// route. Pure over Lookup state + node addr + injected clock; no I/O, no view.
///
/// A full cache evicts rather than refuses. Refusing put the capacity check
/// ahead of the check for whether the request names this node, so one link
/// peer emitting fresh `request_id`s could stop the node answering lookups
/// for itself and stop it carrying anyone else's for as long as it kept the
/// cache full — a denial of exactly the service the cache exists to protect.
/// [`make_room`] charges the eviction to the peer that filled the cache.
///
/// The loosening this accepts: an evicted `request_id` arriving again inside
/// the dedup window is forwarded a second time rather than recognised as a
/// duplicate, and a response still in flight for it has lost its reverse
/// path. The per-target forward limiter and the request TTL already bound
/// what that second forward can cost, and the alternative — refusing the
/// arrival — is the availability defect above.
///
/// `peer_count` is the current link-peer count, supplied by the caller: the
/// core is sans-IO and clockless and has no view of the live peer table.
#[allow(clippy::too_many_arguments)]
pub(crate) fn classify_request(
    lookup: &mut Lookup,
    request: &LookupRequest,
    from: &NodeAddr,
    my_addr: &NodeAddr,
    now_ms: u64,
    recent_expiry_ms: u64,
    max_recent: usize,
    peer_count: usize,
) -> Classification {
    // Purge expired dedup entries (was purge_expired_requests). Cache and
    // per-peer index are purged together, or the eviction policy below reads
    // a stale index and charges the wrong peer.
    lookup.purge_recent(now_ms, recent_expiry_ms);

    if lookup.recent_requests.contains_key(&request.request_id) {
        return Classification {
            outcome: RequestOutcome::Duplicate,
            evicted: None,
        };
    }

    // A request this node originated, flooded to every bloom-matching tree
    // peer and circulated back to us by one of them. The only identity test
    // below is `request.target == *my_addr`, and for a lookup we originated
    // the target is someone else, so without this the copy is filed as an
    // ordinary transit entry keyed on our own `request_id` — and the answer,
    // when it comes, is reverse-path forwarded to the peer that looped the
    // request instead of being accepted here. Dropping it as the duplicate it
    // is also stops the copy being forwarded a second time: our flood already
    // reached the peers that could carry it.
    //
    // `request.origin` looks like the cheaper identity test and cannot be
    // used. It is unsigned and set by whoever sends the frame, so a peer
    // could put this node's address on any request and make it refuse to
    // transit that request. An id has to have been issued here to match,
    // which is what makes this test safe to drop on.
    //
    // The test reaches only as far as `PendingLookup::ids`, which keeps the
    // last `MAX_RECORDED_IDS` that a target's ladder issued. A ladder
    // configured with more rungs than that loses its earliest ids, and a
    // returning copy of one of those attempts is recorded as transit again.
    // The bound is inherited from the originator test in `classify_response`
    // rather than introduced here, and a reply to such an attempt was already
    // being dropped as unsolicited.
    if lookup
        .pending_lookups
        .get(&request.target)
        .is_some_and(|pending| pending.matches(request.request_id))
    {
        return Classification {
            outcome: RequestOutcome::OwnRequestLooped,
            evicted: None,
        };
    }

    let evicted = make_room(lookup, from, max_recent, peer_count);
    lookup.record_recent(request.request_id, *from, now_ms);

    let outcome = if request.target == *my_addr {
        RequestOutcome::RespondAsTarget
    } else if request.can_forward() {
        if lookup
            .forward_limiter
            .should_forward(&request.target, now_ms)
        {
            RequestOutcome::Forward
        } else {
            RequestOutcome::ForwardRateLimited
        }
    } else {
        RequestOutcome::TtlExhausted
    };
    Classification { outcome, evicted }
}

/// How an inbound LookupResponse should be routed, decided from the pending
/// lookups this node has outstanding and, failing that, the recent-request
/// dedup state.
pub(crate) enum ResponseRoute {
    /// A response for a request we forwarded, but we already reverse-forwarded
    /// one for this request_id — drop to prevent response routing loops.
    AlreadyForwarded,
    /// Transit node: reverse-path forward toward `from_peer`.
    Transit { from_peer: NodeAddr },
    /// We originated this request — the shell verifies the proof and caches.
    Originator,
    /// Nobody asked for this: it is neither a request we transited nor an
    /// answer to a lookup we have outstanding for its target. Dropped before
    /// the identity resolve and the signature verify, so it costs nothing.
    Unsolicited,
}

/// Classify an inbound LookupResponse against the pending lookups and the
/// recent-request dedup cache, in that order.
///
/// Pure decision over `Lookup` state: sets `response_forwarded` when this is
/// the first response we transit for the request. No I/O, no view, no metrics.
pub(crate) fn classify_response(
    lookup: &mut Lookup,
    request_id: u64,
    target: &NodeAddr,
) -> ResponseRoute {
    // Originator-ness is decided first, ahead of the transit dedup record.
    // The response names a target this node has a lookup outstanding for and
    // carries an id that lookup issued, so it answers us whatever else the
    // dedup cache happens to hold for that id. Testing `recent_requests`
    // first instead made this arm unreachable whenever a copy of our own
    // flooded request found its way back to us and was filed as transit: the
    // reply was relayed away rather than accepted, the pending lookup was
    // never satisfied, and discovery failed while the answers were arriving.
    //
    // The id is fresh 64-bit randomness drawn per attempt and the target
    // signs over it, so a harvested response is bound to the request it
    // answered and cannot be redirected or replayed: an id we never issued
    // still cannot match, and preferring this arm takes nothing away from
    // what the `Unsolicited` arm protects. Replies to earlier attempts of a
    // still-outstanding lookup match too, which is the common case on a link
    // whose round trip exceeds the first rung of the retry ladder.
    if lookup
        .pending_lookups
        .get(target)
        .is_some_and(|pending| pending.matches(request_id))
    {
        return ResponseRoute::Originator;
    }

    match lookup.recent_requests.get_mut(&request_id) {
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
        // Neither a request we transited nor an answer to a lookup we have
        // outstanding for its target. Nobody asked for it.
        None => ResponseRoute::Unsolicited,
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
/// the recent-request reverse-path record. Pure over `Lookup` state.
///
/// Only the reverse-path decision is pure. The `NeedsTreeRoute` fallback (greedy
/// tree routing toward the origin) is a `&mut Node` coord-cache operation with a
/// TTL-touch side effect, so it stays in the shell rather than moving here.
pub(crate) fn plan_response_route(lookup: &Lookup, request_id: u64) -> ResponseRouteDecision {
    match lookup.recent_requests.get(&request_id) {
        Some(recent) => ResponseRouteDecision::ReversePath(recent.from_peer),
        None => ResponseRouteDecision::NeedsTreeRoute,
    }
}

/// Apply the accept-side effects of a verified LookupResponse we originated.
///
/// Mutates the Lookup success state (clears backoff, drops the pending
/// lookup) and returns the cross-subsystem effects for the shell to drive.
/// Verification is the shell's job — this runs only after the proof checked out.
pub(crate) fn on_response_accepted(
    lookup: &mut Lookup,
    request_id: u64,
    target: &NodeAddr,
    coords: crate::TreeCoordinate,
    now_ms: u64,
    path_mtu: u16,
) -> Vec<LookupAction> {
    lookup.backoff.record_success(target);
    lookup.pending_lookups.remove(target);
    vec![
        LookupAction::CacheCoords {
            request_id,
            target: *target,
            coords,
            now_ms,
            path_mtu,
        },
        LookupAction::WritePathMtu {
            target: *target,
            now_ms,
            path_mtu,
        },
        LookupAction::ResetWarmupIfEstablished { target: *target },
        LookupAction::RetryQueuedPackets { target: *target },
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

/// Advance the pending-lookup retry ladder. Pure over `Lookup` state +
/// injected clock: partitions due entries into retries (attempt bumped) and
/// final timeouts (removed + backoff failure recorded). No I/O, no view.
pub(crate) fn poll_pending(
    lookup: &mut Lookup,
    now_ms: u64,
    attempt_timeouts_secs: &[u64],
) -> PollOutcome {
    let max_attempts = attempt_timeouts_secs.len() as u8;

    // Collect targets needing action (can't mutate while iterating).
    let mut retry_targets: Vec<NodeAddr> = Vec::new();
    let mut timeout_targets: Vec<NodeAddr> = Vec::new();

    for (&target, entry) in &lookup.pending_lookups {
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
        if let Some(entry) = lookup.pending_lookups.get_mut(&target) {
            entry.attempt += 1;
            entry.last_sent_ms = now_ms;
            retries.push((target, entry.attempt));
        }
    }

    let mut timeouts: Vec<(NodeAddr, u32)> = Vec::new();
    for target in timeout_targets {
        lookup.pending_lookups.remove(&target);
        lookup.backoff.record_failure(&target, now_ms);
        let failures = lookup.backoff.failure_count(&target);
        timeouts.push((target, failures));
    }

    PollOutcome { retries, timeouts }
}

/// Decision for whether/how to initiate a lookup for a target.
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

/// Gate a lookup initiation against pending-dedup, backoff
/// suppression, and bloom reachability (passed in — the shell reads the peer
/// filters). On BloomMiss records a failure; on Proceed inserts the pending
/// lookup. Pure over Lookup state + injected clock; no I/O, no view.
pub(crate) fn initiate_gate(
    lookup: &mut Lookup,
    dest: &NodeAddr,
    now_ms: u64,
    reachable: bool,
) -> InitiateDecision {
    if lookup.pending_lookups.contains_key(dest) {
        return InitiateDecision::Deduplicated;
    }
    if lookup.backoff.is_suppressed(dest, now_ms) {
        return InitiateDecision::Suppressed {
            failures: lookup.backoff.failure_count(dest),
        };
    }
    if !reachable {
        lookup.backoff.record_failure(dest, now_ms);
        return InitiateDecision::BloomMiss;
    }
    lookup
        .pending_lookups
        .insert(*dest, PendingLookup::new(now_ms));
    InitiateDecision::Proceed
}

/// Roll back a lookup whose first attempt reached no tree peers (sent == 0):
/// drop the pending entry and record a backoff failure.
pub(crate) fn initiate_failed(lookup: &mut Lookup, dest: &NodeAddr, now_ms: u64) {
    lookup.pending_lookups.remove(dest);
    lookup.backoff.record_failure(dest, now_ms);
}

#[cfg(test)]
mod dedup_eviction_tests {
    //! Capacity policy for the dedup cache.
    //!
    //! These live beside the policy rather than in `lookup/tests/core.rs`
    //! because they are the regression tests for a security finding and read
    //! directly against `make_room`'s two branches.

    use super::super::limits::{LookupBackoff, LookupForwardRateLimiter};
    use super::super::state::MIN_RECENT_PER_PEER;
    use super::*;
    use crate::testutil::make_node_addr;

    /// The cache bound used by the behavioural tests. Smaller than the
    /// production 4096 so a saturation test stays cheap; the policy is a
    /// function of the bound, not of its value.
    const CACHE: usize = 128;

    fn empty() -> Lookup {
        Lookup::new(
            LookupBackoff::default(),
            LookupForwardRateLimiter::default(),
        )
    }

    fn request(request_id: u64, target: NodeAddr) -> LookupRequest {
        let origin = make_node_addr(0xCC);
        // `next`'s LookupRequest carries no coordinates.
        LookupRequest::new(request_id, target, origin, 5, 0)
    }

    /// Deliver one transit request from `from`, discarding the route
    /// decision: these tests are about which entries survive, and the
    /// forward limiter's verdict does not affect what is cached.
    fn deliver(
        lookup: &mut Lookup,
        request_id: u64,
        from: &NodeAddr,
        my_addr: &NodeAddr,
        peer_count: usize,
    ) -> Classification {
        let target = make_node_addr(0xBB);
        classify_request(
            lookup,
            &request(request_id, target),
            from,
            my_addr,
            1_000,
            60_000,
            CACHE,
            peer_count,
        )
    }

    #[test]
    fn a_peer_over_its_share_evicts_its_own_oldest_and_not_a_light_peers() {
        let mut lookup = empty();
        let heavy = make_node_addr(0x01);
        let light = make_node_addr(0x02);
        let me = make_node_addr(0x99);
        // 64 peers over a 128-entry cache: 128/64 = 2, floored to 64.
        let peer_count = 64;
        let share = Lookup::peer_share(CACHE, peer_count);

        deliver(&mut lookup, 7, &light, &me, peer_count);

        // One request past the share, so the heavy peer pays for its own
        // admission rather than the cache paying for it.
        for i in 0..=share as u64 {
            deliver(&mut lookup, 1_000 + i, &heavy, &me, peer_count);
        }

        assert!(
            lookup.recent_requests.contains_key(&7),
            "a light peer's reverse-path entry must survive a neighbour's flood"
        );
        assert!(
            !lookup.recent_requests.contains_key(&1_000),
            "the flooder's own oldest entry is what pays for its newest"
        );
        assert!(
            lookup.recent_requests.contains_key(&(1_000 + share as u64)),
            "and its newest is admitted rather than dropped"
        );
        assert_eq!(
            lookup.peer_entries(&heavy),
            share,
            "the flooder is held at its share"
        );
    }

    #[test]
    fn the_per_peer_share_never_falls_below_the_floor_however_many_peers() {
        // A node with as many peers as cache entries would otherwise give
        // each peer a share of one, which no genuine transit burst survives.
        assert_eq!(Lookup::peer_share(CACHE, CACHE), MIN_RECENT_PER_PEER);
        assert_eq!(Lookup::peer_share(CACHE, usize::MAX), MIN_RECENT_PER_PEER);
        // Above the floor the share still tracks the peer count.
        assert_eq!(Lookup::peer_share(4096, 8), 512);
        // And a zero peer count (no links up yet) must not divide by zero.
        assert_eq!(Lookup::peer_share(CACHE, 0), CACHE);

        // Behaviourally: at the floor, entry number 64 costs the peer
        // nothing and entry number 65 costs it its oldest.
        let mut lookup = empty();
        let peer = make_node_addr(0x01);
        let me = make_node_addr(0x99);
        let peer_count = usize::MAX;
        for i in 0..MIN_RECENT_PER_PEER as u64 {
            let evicted = deliver(&mut lookup, i, &peer, &me, peer_count).evicted;
            assert!(evicted.is_none(), "nothing is evicted below the floor");
        }
        let evicted = deliver(&mut lookup, 999, &peer, &me, peer_count)
            .evicted
            .expect("the entry past the floor must evict");
        assert_eq!(evicted.request_id, 0, "the peer's oldest entry pays");
        assert_eq!(evicted.peer, peer);
        assert_eq!(evicted.share, MIN_RECENT_PER_PEER);
    }

    #[test]
    fn a_node_whose_dedup_cache_is_saturated_still_answers_a_lookup_for_itself() {
        // The availability claim, and the actual finding: the capacity check
        // used to sit ahead of the check for whether the request names us,
        // so a peer holding the cache full made this node unresolvable.
        let mut lookup = empty();
        let flooder = make_node_addr(0x01);
        let other = make_node_addr(0x02);
        let me = make_node_addr(0x99);
        // A single link peer, so its share is the whole cache and it can
        // saturate without evicting itself.
        let peer_count = 1;

        for i in 0..CACHE as u64 {
            deliver(&mut lookup, i, &flooder, &me, peer_count);
        }
        assert_eq!(
            lookup.recent_requests.len(),
            CACHE,
            "precondition: the cache is full, or the rest observes nothing"
        );

        let classification = classify_request(
            &mut lookup,
            &request(u64::MAX, me),
            &other,
            &me,
            1_000,
            60_000,
            CACHE,
            peer_count,
        );

        assert!(
            matches!(classification.outcome, RequestOutcome::RespondAsTarget),
            "a saturated cache must not stop the node answering lookups for itself"
        );
        let evicted = classification
            .evicted
            .expect("room must have been made at capacity");
        assert_eq!(
            evicted.peer, flooder,
            "the peer holding the most entries pays, not the arriving one"
        );
        assert_eq!(evicted.request_id, 0, "and it pays with its oldest");
        assert!(
            lookup.recent_requests.contains_key(&u64::MAX),
            "the arriving request is recorded, so its response can be routed back"
        );
        assert_eq!(
            lookup.recent_requests.len(),
            CACHE,
            "the cache stays at its bound"
        );
    }

    #[test]
    fn a_duplicate_is_not_indexed_twice_and_evicts_nothing() {
        // The index is a second container over the same entries, so the
        // maintenance risk is drift: everything the policy decides reads it.
        let mut lookup = empty();
        let peer = make_node_addr(0x01);
        let me = make_node_addr(0x99);

        deliver(&mut lookup, 42, &peer, &me, 1);
        let repeat = deliver(&mut lookup, 42, &peer, &me, 1);

        assert!(matches!(repeat.outcome, RequestOutcome::Duplicate));
        assert!(repeat.evicted.is_none(), "a duplicate makes no room");
        assert_eq!(lookup.peer_entries(&peer), 1);
        assert_eq!(lookup.recent_requests.len(), 1);
    }

    #[test]
    fn purging_expired_entries_leaves_the_index_level_with_the_cache() {
        let mut lookup = empty();
        let a = make_node_addr(0x01);
        let b = make_node_addr(0x02);
        let me = make_node_addr(0x99);

        for i in 0..5u64 {
            deliver(&mut lookup, i, &a, &me, 2);
        }
        for i in 100..103u64 {
            deliver(&mut lookup, i, &b, &me, 2);
        }
        let indexed: usize = lookup.recent_by_peer.values().map(|ids| ids.len()).sum();
        assert_eq!(
            indexed,
            lookup.recent_requests.len(),
            "every cached request is indexed exactly once"
        );

        // Entries were stamped at 1_000 with a 60s window; age them out.
        lookup.purge_recent(1_000 + 60_000 + 1, 60_000);
        assert!(lookup.recent_requests.is_empty());
        assert!(
            lookup.recent_by_peer.is_empty(),
            "the index must not keep entries the cache no longer holds"
        );
    }
}
