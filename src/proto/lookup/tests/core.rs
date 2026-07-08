//! Tests for the sans-IO lookup decision core.

use super::util::{
    MockRoutingView, action_peers, empty_lookup, make_request, make_request_id, suppressing_lookup,
};
use crate::TreeCoordinate;
use crate::proto::lookup::*;
use crate::testutil::make_node_addr;

#[test]
fn picks_only_tree_peers_when_a_tree_peer_matches() {
    let tree_peer = make_node_addr(1);
    let non_tree_peer = make_node_addr(2);
    let rv = MockRoutingView {
        peers: vec![(tree_peer, true, true), (non_tree_peer, false, true)],
        ..Default::default()
    };
    let mut request = make_request(3);
    match plan_forward(&mut request, &rv) {
        ForwardOutcome::Forward {
            actions,
            used_fallback,
        } => {
            assert!(!used_fallback, "tree match must not use fallback");
            assert_eq!(action_peers(&actions), vec![tree_peer]);
        }
        _ => panic!("expected Forward"),
    }
}

#[test]
fn falls_back_to_non_tree_peers_when_no_tree_peer_matches() {
    let non_tree_a = make_node_addr(3);
    let non_tree_b = make_node_addr(4);
    // A tree peer exists but does not reach the target.
    let tree_no_reach = make_node_addr(5);
    let rv = MockRoutingView {
        peers: vec![
            (tree_no_reach, true, false),
            (non_tree_a, false, true),
            (non_tree_b, false, true),
        ],
        ..Default::default()
    };
    let mut request = make_request(3);
    match plan_forward(&mut request, &rv) {
        ForwardOutcome::Forward {
            actions,
            used_fallback,
        } => {
            assert!(used_fallback, "no tree match must use fallback");
            assert_eq!(action_peers(&actions), vec![non_tree_a, non_tree_b]);
        }
        _ => panic!("expected Forward via fallback"),
    }
}

#[test]
fn returns_no_peers_when_nothing_reaches_target() {
    let tree_peer = make_node_addr(6);
    let non_tree_peer = make_node_addr(7);
    let rv = MockRoutingView {
        peers: vec![(tree_peer, true, false), (non_tree_peer, false, false)],
        ..Default::default()
    };
    let mut request = make_request(3);
    assert!(matches!(
        plan_forward(&mut request, &rv),
        ForwardOutcome::NoPeers
    ));
}

#[test]
fn returns_ttl_exhausted_when_ttl_is_zero() {
    let tree_peer = make_node_addr(8);
    let rv = MockRoutingView {
        peers: vec![(tree_peer, true, true)],
        ..Default::default()
    };
    let mut request = make_request(0);
    assert!(matches!(
        plan_forward(&mut request, &rv),
        ForwardOutcome::TtlExhausted
    ));
}

#[test]
fn initiate_picks_only_tree_peers_and_never_falls_back() {
    let tree_peer = make_node_addr(1);
    let non_tree_peer = make_node_addr(2);
    let rv = MockRoutingView {
        peers: vec![(tree_peer, true, true), (non_tree_peer, false, true)],
        ..Default::default()
    };
    let request = make_request(3);
    let actions = plan_initiate(&request, &rv);
    assert_eq!(action_peers(&actions), vec![tree_peer]);
}

#[test]
fn initiate_returns_empty_when_only_non_tree_peers_reach() {
    // A tree peer exists but cannot reach the target; only cross-links reach.
    // plan_forward would fall back to the cross-links here; plan_initiate does
    // NOT — the tree-only origination gap preserved for behavior-neutrality.
    let tree_no_reach = make_node_addr(5);
    let non_tree_a = make_node_addr(3);
    let non_tree_b = make_node_addr(4);
    let rv = MockRoutingView {
        peers: vec![
            (tree_no_reach, true, false),
            (non_tree_a, false, true),
            (non_tree_b, false, true),
        ],
        ..Default::default()
    };
    let request = make_request(3);
    assert!(plan_initiate(&request, &rv).is_empty());
}

#[test]
fn initiate_returns_empty_when_nothing_reaches_target() {
    let tree_peer = make_node_addr(6);
    let non_tree_peer = make_node_addr(7);
    let rv = MockRoutingView {
        peers: vec![(tree_peer, true, false), (non_tree_peer, false, false)],
        ..Default::default()
    };
    let request = make_request(3);
    assert!(plan_initiate(&request, &rv).is_empty());
}

#[test]
fn leaf_node_does_not_forward() {
    let tree_peer = make_node_addr(1);
    let rv = MockRoutingView {
        peers: vec![(tree_peer, true, true)],
        leaf: true,
        ..Default::default()
    };
    let mut request = make_request(3);
    assert!(matches!(
        plan_forward(&mut request, &rv),
        ForwardOutcome::LeafNoForward
    ));
}

#[test]
fn forward_excludes_non_full_peers() {
    let full_tree = make_node_addr(1);
    let lite_tree = make_node_addr(2);
    let rv = MockRoutingView {
        peers: vec![(full_tree, true, true), (lite_tree, true, true)],
        not_full: vec![lite_tree],
        ..Default::default()
    };
    let mut request = make_request(3);
    match plan_forward(&mut request, &rv) {
        ForwardOutcome::Forward {
            actions,
            used_fallback,
        } => {
            assert!(!used_fallback);
            assert_eq!(action_peers(&actions), vec![full_tree]);
        }
        _ => panic!("expected Forward to the Full tree peer only"),
    }
}

#[test]
fn forward_excludes_peers_below_min_mtu() {
    let ok_tree = make_node_addr(1);
    let small_tree = make_node_addr(2);
    let rv = MockRoutingView {
        peers: vec![(ok_tree, true, true), (small_tree, true, true)],
        mtu_fail: vec![small_tree],
        ..Default::default()
    };
    let mut request = make_request(3);
    match plan_forward(&mut request, &rv) {
        ForwardOutcome::Forward {
            actions,
            used_fallback,
        } => {
            assert!(!used_fallback);
            assert_eq!(action_peers(&actions), vec![ok_tree]);
        }
        _ => panic!("expected Forward to the MTU-satisfying tree peer only"),
    }
}

#[test]
fn initiate_excludes_non_full_and_mtu_fail_peers() {
    let good = make_node_addr(1);
    let lite = make_node_addr(2);
    let small = make_node_addr(3);
    let rv = MockRoutingView {
        peers: vec![(good, true, true), (lite, true, true), (small, true, true)],
        not_full: vec![lite],
        mtu_fail: vec![small],
        ..Default::default()
    };
    let request = make_request(3);
    let actions = plan_initiate(&request, &rv);
    assert_eq!(action_peers(&actions), vec![good]);
}

#[test]
fn response_route_uses_recorded_reverse_path() {
    let mut lookup = empty_lookup();
    let from = make_node_addr(9);
    lookup
        .recent_requests
        .insert(42, RecentRequest::new(from, 0));
    match plan_response_route(&lookup, 42) {
        ResponseRouteDecision::ReversePath(peer) => assert_eq!(peer, from),
        ResponseRouteDecision::NeedsTreeRoute => panic!("expected ReversePath"),
    }
}

#[test]
fn response_route_needs_tree_route_when_no_record() {
    let lookup = empty_lookup();
    assert!(matches!(
        plan_response_route(&lookup, 42),
        ResponseRouteDecision::NeedsTreeRoute
    ));
}

#[test]
fn classify_response_transit_on_fresh_forwarded_request() {
    let from_peer = make_node_addr(0x11);
    let mut lookup = empty_lookup();
    lookup
        .recent_requests
        .insert(42, RecentRequest::new(from_peer, 1000));

    match classify_response(&mut lookup, 42) {
        ResponseRoute::Transit { from_peer: peer } => assert_eq!(peer, from_peer),
        _ => panic!("expected Transit"),
    }
    // The dedup flag must flip after the first transit.
    assert!(lookup.recent_requests.get(&42).unwrap().response_forwarded);
}

#[test]
fn classify_response_already_forwarded_on_second_call() {
    let from_peer = make_node_addr(0x22);
    let mut lookup = empty_lookup();
    lookup
        .recent_requests
        .insert(7, RecentRequest::new(from_peer, 1000));

    assert!(matches!(
        classify_response(&mut lookup, 7),
        ResponseRoute::Transit { .. }
    ));
    assert!(matches!(
        classify_response(&mut lookup, 7),
        ResponseRoute::AlreadyForwarded
    ));
}

#[test]
fn classify_response_originator_when_request_absent() {
    let mut lookup = empty_lookup();
    assert!(matches!(
        classify_response(&mut lookup, 999),
        ResponseRoute::Originator
    ));
}

#[test]
fn on_response_accepted_clears_state_and_emits_effects() {
    let target = make_node_addr(0x5A);
    let mut lookup = empty_lookup();

    // Seed a backoff entry and a pending lookup for the target.
    lookup.backoff.record_failure(&target, 1000);
    assert!(!lookup.backoff.is_empty(), "precondition: backoff seeded");
    lookup
        .pending_lookups
        .insert(target, PendingLookup::new(1000));
    assert!(lookup.pending_lookups.contains_key(&target));

    let coords = TreeCoordinate::root(target);
    let now_ms = 12_345u64;
    let path_mtu = 1400u16;
    let actions = on_response_accepted(&mut lookup, &target, coords, now_ms, path_mtu);

    // Success state must be cleared.
    assert!(
        lookup.backoff.is_empty(),
        "backoff entry must clear on success"
    );
    assert!(
        !lookup.pending_lookups.contains_key(&target),
        "pending lookup must be dropped"
    );

    // Exactly the four effect actions, in order.
    assert_eq!(actions.len(), 4, "expected four effect actions");
    match &actions[0] {
        LookupAction::CacheCoords {
            target: t,
            now_ms: n,
            path_mtu: p,
            ..
        } => {
            assert_eq!(*t, target);
            assert_eq!(*n, now_ms);
            assert_eq!(*p, path_mtu);
        }
        _ => panic!("action[0] must be CacheCoords"),
    }
    match &actions[1] {
        LookupAction::WritePathMtu {
            target: t,
            path_mtu: p,
        } => {
            assert_eq!(*t, target);
            assert_eq!(*p, path_mtu);
        }
        _ => panic!("action[1] must be WritePathMtu"),
    }
    match &actions[2] {
        LookupAction::ResetWarmupIfEstablished { target: t } => assert_eq!(*t, target),
        _ => panic!("action[2] must be ResetWarmupIfEstablished"),
    }
    match &actions[3] {
        LookupAction::RetryQueuedPackets { target: t } => assert_eq!(*t, target),
        _ => panic!("action[3] must be RetryQueuedPackets"),
    }
}

#[test]
fn poll_pending_no_action_before_first_deadline() {
    let target = make_node_addr(0x30);
    let mut lookup = empty_lookup();
    let t0 = 10_000u64;
    lookup
        .pending_lookups
        .insert(target, PendingLookup::new(t0));

    // Just before the attempt-1 deadline (1s): nothing fires.
    let outcome = poll_pending(&mut lookup, t0 + 999, &[1, 2, 4, 8]);
    assert!(outcome.retries.is_empty(), "no retry before deadline");
    assert!(outcome.timeouts.is_empty(), "no timeout before deadline");

    // Entry unchanged.
    let entry = lookup.pending_lookups.get(&target).unwrap();
    assert_eq!(entry.attempt, 1);
    assert_eq!(entry.last_sent_ms, t0);
}

#[test]
fn poll_pending_retries_at_first_deadline() {
    let target = make_node_addr(0x31);
    let mut lookup = empty_lookup();
    let t0 = 10_000u64;
    lookup
        .pending_lookups
        .insert(target, PendingLookup::new(t0));

    // At the attempt-1 deadline (t0 + 1000): one retry to attempt 2.
    let outcome = poll_pending(&mut lookup, t0 + 1000, &[1, 2, 4, 8]);
    assert_eq!(outcome.retries, vec![(target, 2)]);
    assert!(outcome.timeouts.is_empty());

    // Entry mutated: attempt bumped, last_sent refreshed.
    let entry = lookup.pending_lookups.get(&target).unwrap();
    assert_eq!(entry.attempt, 2);
    assert_eq!(entry.last_sent_ms, t0 + 1000);
}

#[test]
fn poll_pending_final_timeout_at_max_attempt() {
    let target = make_node_addr(0x32);
    let mut lookup = empty_lookup();

    // Drive the entry to attempt == max (4) with a known last_sent.
    let tn = 50_000u64;
    let mut entry = PendingLookup::new(tn);
    entry.attempt = 4;
    entry.last_sent_ms = tn;
    lookup.pending_lookups.insert(target, entry);

    // attempt_timeouts_secs[3] == 8 → deadline at tn + 8000.
    let outcome = poll_pending(&mut lookup, tn + 8000, &[1, 2, 4, 8]);
    assert!(outcome.retries.is_empty(), "max attempt cannot retry");
    assert_eq!(
        outcome.timeouts,
        vec![(target, 1)],
        "one timeout, failure #1"
    );

    // Entry removed and a backoff failure recorded.
    assert!(
        !lookup.pending_lookups.contains_key(&target),
        "timed-out entry must be removed"
    );
    assert_eq!(lookup.backoff.failure_count(&target), 1);
}

// --- classify_request tests ---

#[test]
fn classify_request_forwards_fresh_and_records_it() {
    let mut lookup = empty_lookup();
    let from = make_node_addr(0x01);
    let my_addr = make_node_addr(0x99);
    let target = make_node_addr(0xAA);
    let request = make_request_id(1, target, 3);

    let outcome = classify_request(&mut lookup, &request, &from, &my_addr, 1000, 5000, 4096);
    assert!(matches!(outcome, RequestOutcome::Forward));
    // Recorded for reverse-path forwarding.
    assert!(lookup.recent_requests.contains_key(&1));
    assert_eq!(lookup.recent_requests.get(&1).unwrap().from_peer, from);
}

#[test]
fn classify_request_duplicate_on_second_call() {
    let mut lookup = empty_lookup();
    let from = make_node_addr(0x01);
    let my_addr = make_node_addr(0x99);
    let target = make_node_addr(0xAA);
    let request = make_request_id(1, target, 3);

    assert!(matches!(
        classify_request(&mut lookup, &request, &from, &my_addr, 1000, 5000, 4096),
        RequestOutcome::Forward
    ));
    assert!(matches!(
        classify_request(&mut lookup, &request, &from, &my_addr, 1000, 5000, 4096),
        RequestOutcome::Duplicate
    ));
}

#[test]
fn classify_request_dedup_cache_full() {
    let mut lookup = empty_lookup();
    let from = make_node_addr(0x01);
    let my_addr = make_node_addr(0x99);
    let target = make_node_addr(0xAA);
    // Fill the cache to max_recent with distinct request_ids.
    let max_recent = 3usize;
    for id in 100..(100 + max_recent as u64) {
        lookup
            .recent_requests
            .insert(id, RecentRequest::new(from, 1000));
    }
    assert_eq!(lookup.recent_requests.len(), max_recent);

    let request = make_request_id(1, target, 3);
    match classify_request(
        &mut lookup,
        &request,
        &from,
        &my_addr,
        1000,
        5000,
        max_recent,
    ) {
        RequestOutcome::DedupCacheFull { len } => assert_eq!(len, max_recent),
        _ => panic!("expected DedupCacheFull"),
    }
    // The new request must not have been recorded on the drop path.
    assert!(!lookup.recent_requests.contains_key(&1));
}

#[test]
fn classify_request_respond_as_target() {
    let mut lookup = empty_lookup();
    let from = make_node_addr(0x01);
    let my_addr = make_node_addr(0xAA);
    // target == my_addr
    let request = make_request_id(1, my_addr, 3);

    assert!(matches!(
        classify_request(&mut lookup, &request, &from, &my_addr, 1000, 5000, 4096),
        RequestOutcome::RespondAsTarget
    ));
    // Recorded before the target decision.
    assert!(lookup.recent_requests.contains_key(&1));
}

#[test]
fn classify_request_ttl_exhausted_for_non_target() {
    let mut lookup = empty_lookup();
    let from = make_node_addr(0x01);
    let my_addr = make_node_addr(0x99);
    let target = make_node_addr(0xAA);
    // ttl 0 → not forwardable, and not the target.
    let request = make_request_id(1, target, 0);

    assert!(matches!(
        classify_request(&mut lookup, &request, &from, &my_addr, 1000, 5000, 4096),
        RequestOutcome::TtlExhausted
    ));
}

#[test]
fn classify_request_forward_rate_limited() {
    let mut lookup = empty_lookup();
    let from = make_node_addr(0x01);
    let my_addr = make_node_addr(0x99);
    let target = make_node_addr(0xAA);
    // Pre-seed the forward limiter so should_forward(target) returns false
    // on the next call within the (default 2s) min interval.
    assert!(lookup.forward_limiter.should_forward(&target, 1000));

    let request = make_request_id(1, target, 3);
    assert!(matches!(
        classify_request(&mut lookup, &request, &from, &my_addr, 1000, 5000, 4096),
        RequestOutcome::ForwardRateLimited
    ));
}

#[test]
fn classify_request_purges_expired_entries() {
    let mut lookup = empty_lookup();
    let from = make_node_addr(0x01);
    let my_addr = make_node_addr(0x99);
    let target = make_node_addr(0xAA);
    // Seed an entry that is expired at now_ms with the given expiry window.
    // is_expired: now - timestamp > expiry_ms → expired.
    lookup
        .recent_requests
        .insert(55, RecentRequest::new(from, 1000));
    // now_ms = 10_000, expiry_ms = 5000 → 9000 > 5000 → expired.
    let request = make_request_id(1, target, 3);
    let outcome = classify_request(&mut lookup, &request, &from, &my_addr, 10_000, 5000, 4096);
    assert!(matches!(outcome, RequestOutcome::Forward));
    // The expired entry (55) must have been purged.
    assert!(!lookup.recent_requests.contains_key(&55));
    // The fresh request is recorded.
    assert!(lookup.recent_requests.contains_key(&1));
}

#[test]
fn poll_pending_full_ladder_end_to_end() {
    let target = make_node_addr(0x33);
    let mut lookup = empty_lookup();
    let t0 = 0u64;
    lookup
        .pending_lookups
        .insert(target, PendingLookup::new(t0));
    let ladder = [1u64, 2, 4, 8];

    // attempt 1 → 2 at deadline 1s
    let o = poll_pending(&mut lookup, t0 + 1000, &ladder);
    assert_eq!(o.retries, vec![(target, 2)]);
    // attempt 2 → 3 at deadline 2s after last send
    let o = poll_pending(&mut lookup, t0 + 1000 + 2000, &ladder);
    assert_eq!(o.retries, vec![(target, 3)]);
    // attempt 3 → 4 at deadline 4s after last send
    let o = poll_pending(&mut lookup, t0 + 1000 + 2000 + 4000, &ladder);
    assert_eq!(o.retries, vec![(target, 4)]);
    // attempt 4 is max → final timeout at deadline 8s after last send
    let last = t0 + 1000 + 2000 + 4000;
    let o = poll_pending(&mut lookup, last + 8000, &ladder);
    assert!(o.retries.is_empty());
    assert_eq!(o.timeouts, vec![(target, 1)]);
    assert!(!lookup.pending_lookups.contains_key(&target));
}

// --- initiate_gate / initiate_failed tests ---

#[test]
fn initiate_gate_deduplicated_when_pending() {
    let dest = make_node_addr(0x40);
    let mut lookup = empty_lookup();
    lookup.pending_lookups.insert(dest, PendingLookup::new(500));

    // reachable=true would otherwise Proceed, but the pending entry wins.
    assert!(matches!(
        initiate_gate(&mut lookup, &dest, 1000, true),
        InitiateDecision::Deduplicated
    ));
}

#[test]
fn initiate_gate_suppressed_by_backoff() {
    let dest = make_node_addr(0x41);
    let mut lookup = suppressing_lookup();
    // One failure arms suppression under with_params(30, 300).
    lookup.backoff.record_failure(&dest, 1000);
    assert!(
        lookup.backoff.is_suppressed(&dest, 1000),
        "precondition: suppressed"
    );

    match initiate_gate(&mut lookup, &dest, 1000, true) {
        InitiateDecision::Suppressed { failures } => assert_eq!(failures, 1),
        _ => panic!("expected Suppressed"),
    }
    // No pending entry was inserted on the suppress path.
    assert!(!lookup.pending_lookups.contains_key(&dest));
}

#[test]
fn initiate_gate_bloom_miss_records_failure() {
    let dest = make_node_addr(0x42);
    let mut lookup = empty_lookup();

    assert!(matches!(
        initiate_gate(&mut lookup, &dest, 1000, false),
        InitiateDecision::BloomMiss
    ));
    // A backoff failure was recorded, and no pending entry created.
    assert_eq!(lookup.backoff.failure_count(&dest), 1);
    assert!(!lookup.pending_lookups.contains_key(&dest));
}

#[test]
fn initiate_gate_proceed_inserts_pending() {
    let dest = make_node_addr(0x43);
    let mut lookup = empty_lookup();
    let now_ms = 7_777u64;

    assert!(matches!(
        initiate_gate(&mut lookup, &dest, now_ms, true),
        InitiateDecision::Proceed
    ));
    // The pending entry now exists, stamped with now_ms.
    let entry = lookup
        .pending_lookups
        .get(&dest)
        .expect("Proceed must insert a pending lookup");
    assert_eq!(entry.last_sent_ms, now_ms);
    assert_eq!(entry.attempt, 1);
}

#[test]
fn initiate_failed_drops_pending_and_records_failure() {
    let dest = make_node_addr(0x44);
    let mut lookup = empty_lookup();
    lookup
        .pending_lookups
        .insert(dest, PendingLookup::new(1000));

    initiate_failed(&mut lookup, &dest, 1000);
    assert!(
        !lookup.pending_lookups.contains_key(&dest),
        "pending entry must be dropped"
    );
    assert_eq!(lookup.backoff.failure_count(&dest), 1);
}
