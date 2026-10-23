//! Tests for the sans-IO lookup decision core.

use super::util::{
    MockRoutingView, action_peers, distinct_addr, empty_lookup, make_request, make_request_id,
    suppressing_lookup,
};
use crate::identity::NodeAddr;
use crate::proto::coord::TreeCoordinate;
use crate::proto::lookup::*;
use crate::testutil::make_node_addr;
use alloc::vec;
use alloc::vec::Vec;

/// The proof digest a response under test carries, where the test is not
/// about telling responses apart.
const DIGEST: [u8; 8] = [0x5A; 8];

/// The link peer a response under test arrives from, where the test is not
/// about which peer that is.
fn responder() -> NodeAddr {
    make_node_addr(0xE0)
}

/// A recent-request entry for a request from `from_peer` naming `target`,
/// forwarded to [`responder`].
fn transited(from_peer: NodeAddr, target: NodeAddr) -> RecentRequest {
    let mut recent = RecentRequest::new(from_peer, target, 1000);
    recent.forwarded_to.push(responder());
    recent
}

#[test]
fn picks_only_tree_peers_when_a_tree_peer_matches() {
    let tree_peer = make_node_addr(1);
    let non_tree_peer = make_node_addr(2);
    let rv = MockRoutingView {
        peers: vec![(tree_peer, true, true), (non_tree_peer, false, true)],
        ..Default::default()
    };
    let mut request = make_request(3);
    match plan_forward(&mut request, &make_node_addr(0xCC), &rv) {
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
    match plan_forward(&mut request, &make_node_addr(0xCC), &rv) {
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
        plan_forward(&mut request, &make_node_addr(0xCC), &rv),
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
        plan_forward(&mut request, &make_node_addr(0xCC), &rv),
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
        plan_forward(&mut request, &make_node_addr(0xCC), &rv),
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
    match plan_forward(&mut request, &make_node_addr(0xCC), &rv) {
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
    match plan_forward(&mut request, &make_node_addr(0xCC), &rv) {
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
        .insert(42, RecentRequest::new(from, make_node_addr(0xF0), 0));
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
    let target = make_node_addr(0xF1);
    lookup
        .recent_requests
        .insert(42, transited(from_peer, target));

    // With no lookup of ours outstanding for the target, transit is decided by
    // the dedup record — pass a target no pending lookup mentions.
    match classify_response(&mut lookup, 42, &target, &responder(), DIGEST) {
        ResponseRoute::Transit { from_peer: peer } => assert_eq!(peer, from_peer),
        _ => panic!("expected Transit"),
    }
    // The relayed response is remembered after the first transit.
    assert_eq!(lookup.recent_requests.get(&42).unwrap().relayed, [DIGEST]);
}

#[test]
fn classify_response_already_forwarded_on_second_call() {
    let from_peer = make_node_addr(0x22);
    let mut lookup = empty_lookup();
    let target = make_node_addr(0xF2);
    lookup
        .recent_requests
        .insert(7, transited(from_peer, target));

    assert!(matches!(
        classify_response(&mut lookup, 7, &target, &responder(), DIGEST),
        ResponseRoute::Transit { .. }
    ));
    assert!(matches!(
        classify_response(&mut lookup, 7, &target, &responder(), DIGEST),
        ResponseRoute::AlreadyForwarded
    ));
}

#[test]
fn classify_response_originator_wins_over_a_transit_dedup_record() {
    // Regression. A copy of a request we originated can be flooded back to us
    // and filed in `recent_requests` as ordinary transit, keyed on our own
    // request_id. Consulting the dedup record first then classified the answer
    // as Transit and relayed it to the peer that looped the request, so the
    // pending lookup was never satisfied and discovery failed with "no reply"
    // while the responses were in fact arriving. Originator-ness wins.
    let target = make_node_addr(0x61);
    let looping_peer = make_node_addr(0x62);
    let mut lookup = empty_lookup();
    lookup
        .recent_requests
        .insert(4242, transited(looping_peer, target));
    let mut pending = PendingLookup::new(1000);
    pending.record(4242);
    lookup.pending_lookups.insert(target, pending);

    assert!(matches!(
        classify_response(&mut lookup, 4242, &target, &responder(), DIGEST),
        ResponseRoute::Originator
    ));
    // And nothing was reverse-path forwarded on our behalf.
    assert!(
        lookup
            .recent_requests
            .get(&4242)
            .unwrap()
            .relayed
            .is_empty()
    );
}

#[test]
fn classify_response_originator_when_a_pending_lookup_issued_the_id() {
    // No dedup record, so this is not a response we transit. It counts as ours
    // only because the target has a lookup outstanding and that lookup issued
    // the very request_id the response carries.
    let target = make_node_addr(0x51);
    let mut lookup = empty_lookup();
    let mut pending = PendingLookup::new(1000);
    pending.record(999);
    lookup.pending_lookups.insert(target, pending);

    assert!(matches!(
        classify_response(&mut lookup, 999, &target, &responder(), DIGEST),
        ResponseRoute::Originator
    ));
}

#[test]
fn classify_response_unsolicited_when_nothing_correlates_the_id() {
    // The three ways a response can fail to correlate, each of which must be
    // dropped before the identity resolve and the signature verify rather than
    // being treated as an answer to something we asked for.
    let target = make_node_addr(0x52);
    let other = make_node_addr(0x53);
    let mut lookup = empty_lookup();

    // 1. Nothing outstanding at all.
    assert!(matches!(
        classify_response(&mut lookup, 999, &target, &responder(), DIGEST),
        ResponseRoute::Unsolicited
    ));

    // 2. A lookup is outstanding for the target, but it never issued this id:
    //    a harvested response cannot be replayed against a live lookup.
    let mut pending = PendingLookup::new(1000);
    pending.record(1);
    lookup.pending_lookups.insert(target, pending);
    assert!(matches!(
        classify_response(&mut lookup, 999, &target, &responder(), DIGEST),
        ResponseRoute::Unsolicited
    ));

    // 3. The id was issued, but for a different target: the id is bound to the
    //    exchange it was drawn for and cannot be redirected onto another name.
    assert!(matches!(
        classify_response(&mut lookup, 1, &other, &responder(), DIGEST),
        ResponseRoute::Unsolicited
    ));

    // The matching pair still classifies as ours, so the checks above are
    // discriminating rather than rejecting everything.
    assert!(matches!(
        classify_response(&mut lookup, 1, &target, &responder(), DIGEST),
        ResponseRoute::Originator
    ));
}

#[test]
fn on_response_accepted_clears_state_and_emits_effects() {
    let target = make_node_addr(0x5A);
    // Backoff enabled, so the seeded failure below is recorded.
    let mut lookup = suppressing_lookup();

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
    let actions = on_response_accepted(&mut lookup, 7, &target, coords, now_ms, path_mtu);

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
            now_ms: n,
            path_mtu: p,
        } => {
            assert_eq!(*t, target);
            assert_eq!(
                *n, now_ms,
                "the path-MTU entry must be stamped with the same instant the \
                 coordinates are cached at, or the clamp outlives its route"
            );
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
fn cache_coords_action_carries_the_request_id_the_response_arrived_with() {
    let target = make_node_addr(0x5A);
    let mut lookup = empty_lookup();

    // Distinct from now_ms and path_mtu below, so substituting either for the
    // correlator fails rather than coincidentally matching.
    let request_id = 0xDEAD_BEEF_0000_0001u64;
    let now_ms = 12_345u64;
    let path_mtu = 1400u16;
    let actions = on_response_accepted(
        &mut lookup,
        request_id,
        &target,
        TreeCoordinate::root(target),
        now_ms,
        path_mtu,
    );

    match &actions[0] {
        LookupAction::CacheCoords { request_id: id, .. } => assert_eq!(
            *id, request_id,
            "the cache-coords action must carry the correlator of the response it \
             was planned from, or the shell's sub-floor path-MTU warning cannot \
             name the exchange its sibling warnings do"
        ),
        _ => panic!("action[0] must be CacheCoords"),
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
        vec![(target, None)],
        "one timeout, no failure count while backoff is disabled"
    );

    // Entry removed and, with the default disabled backoff, nothing recorded.
    assert!(
        !lookup.pending_lookups.contains_key(&target),
        "timed-out entry must be removed"
    );
    assert_eq!(lookup.backoff.entry_count(), 0);
}

#[test]
fn poll_pending_final_timeout_at_max_attempt_records_a_failure_with_backoff_enabled() {
    let target = make_node_addr(0x32);
    let mut lookup = suppressing_lookup();

    let tn = 50_000u64;
    let mut entry = PendingLookup::new(tn);
    entry.attempt = 4;
    entry.last_sent_ms = tn;
    lookup.pending_lookups.insert(target, entry);

    let outcome = poll_pending(&mut lookup, tn + 8000, &[1, 2, 4, 8]);
    assert_eq!(
        outcome.timeouts,
        vec![(target, Some(1))],
        "one timeout, failure #1"
    );
    assert!(!lookup.pending_lookups.contains_key(&target));
    assert_eq!(lookup.backoff.failure_count(&target), 1);
}

#[test]
fn with_backoff_enabled_an_entry_is_forgotten_once_its_window_and_one_cap_interval_have_passed_on_the_lookup_tick()
 {
    let target = make_node_addr(0x34);
    // 30 s base, 300 s cap.
    let mut lookup = suppressing_lookup();
    let t = 1_000u64;
    assert!(matches!(
        initiate_gate(&mut lookup, &target, t, false),
        InitiateDecision::BloomMiss
    ));
    assert_eq!(lookup.backoff.entry_count(), 1, "precondition: recorded");

    let forget_at = t + 30_000 + 300_000;
    poll_pending(&mut lookup, forget_at - 1, &[1, 2, 4, 8]);
    assert_eq!(
        lookup.backoff.entry_count(),
        1,
        "one millisecond before the forget time the entry must be kept"
    );

    poll_pending(&mut lookup, forget_at, &[1, 2, 4, 8]);
    assert_eq!(
        lookup.backoff.entry_count(),
        0,
        "the lookup tick must forget an entry once its window and one cap interval have passed"
    );
}

#[test]
fn a_bloom_miss_under_the_default_disabled_backoff_records_nothing_so_ten_thousand_distinct_misses_leave_the_failure_table_empty()
 {
    let mut lookup = empty_lookup();
    let mut misses = 0u32;
    for i in 0..10_000u32 {
        if matches!(
            initiate_gate(&mut lookup, &distinct_addr(i), 1_000 + u64::from(i), false),
            InitiateDecision::BloomMiss
        ) {
            misses += 1;
        }
    }
    // Control: every call took the bloom-miss path, so an empty table below
    // is not a path that never ran.
    assert_eq!(misses, 10_000);
    assert_eq!(
        lookup.backoff.entry_count(),
        0,
        "disabled backoff must record no failure, but the table holds {} entries",
        lookup.backoff.entry_count()
    );
    assert!(lookup.pending_lookups.is_empty());
}

#[test]
fn with_backoff_enabled_a_failed_target_is_suppressed_inside_its_window_allowed_after_it_and_escalates_on_the_next_failure()
 {
    let target = make_node_addr(0x35);
    let mut lookup = suppressing_lookup();
    let t = 1_000u64;
    assert!(matches!(
        initiate_gate(&mut lookup, &target, t, false),
        InitiateDecision::BloomMiss
    ));

    match initiate_gate(&mut lookup, &target, t + 29_999, true) {
        InitiateDecision::Suppressed { failures } => assert_eq!(failures, 1),
        _ => panic!("expected Suppressed inside the 30 s window"),
    }

    // The lookup tick at the window's end must keep the count.
    poll_pending(&mut lookup, t + 30_000, &[1, 2, 4, 8]);
    assert_eq!(lookup.backoff.failure_count(&target), 1);

    assert!(matches!(
        initiate_gate(&mut lookup, &target, t + 30_000, false),
        InitiateDecision::BloomMiss
    ));
    assert_eq!(lookup.backoff.failure_count(&target), 2, "escalates");
    assert!(lookup.backoff.is_suppressed(&target, t + 30_000 + 59_999));
    assert!(
        !lookup.backoff.is_suppressed(&target, t + 30_000 + 60_000),
        "the second window is 60 s"
    );
}

// --- classify_request tests ---

#[test]
fn classify_request_forwards_fresh_and_records_it() {
    let mut lookup = empty_lookup();
    let from = make_node_addr(0x01);
    let my_addr = make_node_addr(0x99);
    let target = make_node_addr(0xAA);
    let request = make_request_id(1, target, 3);

    let outcome =
        classify_request(&mut lookup, &request, &from, &my_addr, 1000, 5000, 4096, 1).outcome;
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
        classify_request(&mut lookup, &request, &from, &my_addr, 1000, 5000, 4096, 1).outcome,
        RequestOutcome::Forward
    ));
    assert!(matches!(
        classify_request(&mut lookup, &request, &from, &my_addr, 1000, 5000, 4096, 1).outcome,
        RequestOutcome::Duplicate
    ));
}

#[test]
fn classify_request_drops_our_own_request_looped_back_to_us() {
    // Regression, request side of the same defect. Our flood reaches a peer
    // that circulates it back; the only identity test is `target == my_addr`,
    // which a lookup we originated never satisfies. Recording it would file
    // our own request_id as a transit entry and forward the copy again, so
    // it is dropped as the duplicate it is. The answer is accepted by the
    // originator-first check either way; keeping the id out of the transit
    // record also leaves a response after completion with nothing to relay.
    let mut lookup = empty_lookup();
    let looping_peer = make_node_addr(0x01);
    let my_addr = make_node_addr(0x99);
    let target = make_node_addr(0xAA);
    let mut pending = PendingLookup::new(1000);
    pending.record(77);
    lookup.pending_lookups.insert(target, pending);

    // Built here rather than through `make_request_id`, whose origin is a
    // third party: the defect is our *own* request returning, so the request
    // under test has to carry our address as its origin. The guard keys on
    // the id and ignores the origin, so this asserts the same behaviour the
    // helper would; it asserts it on the shape the defect actually has.
    let request = LookupRequest::new(77, target, my_addr, 3, 0);
    let classification = classify_request(
        &mut lookup,
        &request,
        &looping_peer,
        &my_addr,
        1000,
        5000,
        4096,
        1,
    );
    assert!(matches!(
        classification.outcome,
        RequestOutcome::OwnRequestLooped
    ));
    assert!(classification.evicted.is_none());
    // Crucially, our own id must not enter the transit dedup cache.
    assert!(!lookup.recent_requests.contains_key(&77));
    assert!(lookup.recent_by_peer.is_empty());
    // A response for it is then ours to accept.
    assert!(matches!(
        classify_response(&mut lookup, 77, &target, &responder(), DIGEST),
        ResponseRoute::Originator
    ));
    // Once the lookup completes, a later response for the same id finds no
    // pending lookup and no transit record, so nothing relays it anywhere.
    on_response_accepted(
        &mut lookup,
        77,
        &target,
        TreeCoordinate::root(target),
        2000,
        1280,
    );
    assert!(matches!(
        classify_response(&mut lookup, 77, &target, &responder(), DIGEST),
        ResponseRoute::Unsolicited
    ));
}

#[test]
fn classify_request_records_our_own_id_as_transit_once_its_lookup_has_timed_out() {
    // The own-request guard reaches only as far as the pending lookup. Once
    // the ladder times out and the entry is dropped, a late copy of our own
    // request is indistinguishable from transit: it is recorded and forwarded,
    // and a later copy of it is a duplicate.
    let mut lookup = empty_lookup();
    let looping_peer = make_node_addr(0x01);
    let my_addr = make_node_addr(0x99);
    let target = make_node_addr(0xAA);
    let t0 = 1000u64;
    let mut pending = PendingLookup::new(t0);
    pending.record(77);
    lookup.pending_lookups.insert(target, pending);

    // A one-rung ladder of 1s: the entry times out at t0 + 1000.
    let now = t0 + 1000;
    let outcome = poll_pending(&mut lookup, now, &[1]);
    assert_eq!(outcome.timeouts.len(), 1, "the lookup must time out");

    let request = make_request_id(77, target, 3);
    let first = classify_request(
        &mut lookup,
        &request,
        &looping_peer,
        &my_addr,
        now,
        5000,
        4096,
        1,
    );
    assert!(matches!(first.outcome, RequestOutcome::Forward));
    assert!(lookup.recent_requests.contains_key(&77));

    let second = classify_request(
        &mut lookup,
        &request,
        &looping_peer,
        &my_addr,
        now,
        5000,
        4096,
        1,
    );
    assert!(matches!(second.outcome, RequestOutcome::Duplicate));
}

#[test]
fn classify_request_records_an_own_id_older_than_the_recorded_window_as_transit() {
    // A pending lookup keeps only the last MAX_RECORDED_IDS (eight) ids its
    // ladder issued. A returning copy of an earlier attempt is outside the
    // guard's reach and goes through as transit; a recent one is still caught.
    let mut lookup = empty_lookup();
    let looping_peer = make_node_addr(0x01);
    let my_addr = make_node_addr(0x99);
    let target = make_node_addr(0xAA);
    let mut pending = PendingLookup::new(1000);
    for id in 1..=9 {
        pending.record(id);
    }
    lookup.pending_lookups.insert(target, pending);

    let oldest = classify_request(
        &mut lookup,
        &make_request_id(1, target, 3),
        &looping_peer,
        &my_addr,
        1000,
        5000,
        4096,
        1,
    );
    assert!(matches!(oldest.outcome, RequestOutcome::Forward));
    assert!(lookup.recent_requests.contains_key(&1));

    let newest = classify_request(
        &mut lookup,
        &make_request_id(9, target, 3),
        &looping_peer,
        &my_addr,
        1000,
        5000,
        4096,
        1,
    );
    assert!(matches!(newest.outcome, RequestOutcome::OwnRequestLooped));
    assert!(!lookup.recent_requests.contains_key(&9));
}

#[test]
fn classify_request_still_transits_a_foreign_id_for_a_target_we_are_looking_up() {
    // The guard keys on the id, not the target: another node's lookup for the
    // same target must still be transited normally while ours is outstanding.
    let mut lookup = empty_lookup();
    let from = make_node_addr(0x01);
    let my_addr = make_node_addr(0x99);
    let target = make_node_addr(0xAA);
    let mut pending = PendingLookup::new(1000);
    pending.record(77);
    lookup.pending_lookups.insert(target, pending);

    let request = make_request_id(88, target, 3);
    let outcome =
        classify_request(&mut lookup, &request, &from, &my_addr, 1000, 5000, 4096, 1).outcome;
    assert!(matches!(outcome, RequestOutcome::Forward));
    assert_eq!(lookup.recent_requests.get(&88).unwrap().from_peer, from);
}

#[test]
fn classify_request_evicts_rather_than_refusing_a_full_dedup_cache() {
    // Regression. The cache-full path used to drop the arriving request, so
    // one peer emitting fresh request_ids
    // could stop this node forwarding anyone's lookups and answering
    // lookups for itself. A full cache now evicts instead, charged to the
    // peer holding the most entries.
    let mut lookup = empty_lookup();
    let from = make_node_addr(0x01);
    let my_addr = make_node_addr(0x99);
    let target = make_node_addr(0xAA);
    // Fill the cache to max_recent with distinct request_ids, through
    // `record_recent` so the per-peer index stays level with the cache. A
    // direct `recent_requests.insert` would leave the index short and turn
    // the eviction policy into a no-op, so the test would pass without
    // exercising it.
    let max_recent = 3usize;
    for id in 100..(100 + max_recent as u64) {
        lookup.record_recent(id, from, make_node_addr(0xF0), 1000);
    }
    assert_eq!(lookup.recent_requests.len(), max_recent);

    let request = make_request_id(1, target, 3);
    let classification = classify_request(
        &mut lookup,
        &request,
        &from,
        &my_addr,
        1000,
        5000,
        max_recent,
        1,
    );
    assert!(
        matches!(classification.outcome, RequestOutcome::Forward),
        "a full cache must not stop the node forwarding"
    );
    let evicted = classification
        .evicted
        .expect("admitting into a full cache must evict something");
    assert_eq!(evicted.request_id, 100, "the oldest entry is what pays");
    assert_eq!(
        evicted.peer, from,
        "and the peer that filled the cache is what pays"
    );
    // The arriving request is admitted, the evicted one is gone, and the
    // cache has not grown past its bound.
    assert!(lookup.recent_requests.contains_key(&1));
    assert!(!lookup.recent_requests.contains_key(&100));
    assert_eq!(lookup.recent_requests.len(), max_recent);
}

#[test]
fn classify_request_respond_as_target() {
    let mut lookup = empty_lookup();
    let from = make_node_addr(0x01);
    let my_addr = make_node_addr(0xAA);
    // target == my_addr
    let request = make_request_id(1, my_addr, 3);

    assert!(matches!(
        classify_request(&mut lookup, &request, &from, &my_addr, 1000, 5000, 4096, 1).outcome,
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
        classify_request(&mut lookup, &request, &from, &my_addr, 1000, 5000, 4096, 1).outcome,
        RequestOutcome::TtlExhausted
    ));
}

#[test]
fn plan_transit_forward_rate_limited() {
    let mut lookup = empty_lookup();
    let from = make_node_addr(0x01);
    let my_addr = make_node_addr(0x99);
    let target = make_node_addr(0xAA);
    // Pre-seed the forward limiter so should_forward(from, target) returns
    // false on the next call within the (default 2s) min interval.
    assert!(lookup.forward_limiter.should_forward(&from, &target, 1000));

    let mut request = make_request_id(1, target, 3);
    assert!(matches!(
        classify_request(&mut lookup, &request, &from, &my_addr, 1000, 5000, 4096, 1).outcome,
        RequestOutcome::Forward
    ));
    let rv = MockRoutingView {
        peers: vec![(make_node_addr(0x02), true, true)],
        ..Default::default()
    };
    assert!(matches!(
        plan_transit_forward(&mut lookup, &mut request, &from, &rv, 1000),
        ForwardOutcome::RateLimited
    ));
    assert!(
        lookup.recent_requests[&1].forwarded_to.is_empty(),
        "a rate-limited request records no peer it was sent to"
    );
}

#[test]
fn classify_request_purges_expired_entries() {
    let mut lookup = empty_lookup();
    let from = make_node_addr(0x01);
    let my_addr = make_node_addr(0x99);
    let target = make_node_addr(0xAA);
    // Seed an entry that is expired at now_ms with the given expiry window.
    // is_expired: now - timestamp > expiry_ms → expired.
    lookup.record_recent(55, from, target, 1000);
    // now_ms = 10_000, expiry_ms = 5000 → 9000 > 5000 → expired.
    let request = make_request_id(1, target, 3);
    let outcome = classify_request(
        &mut lookup,
        &request,
        &from,
        &my_addr,
        10_000,
        5000,
        4096,
        1,
    )
    .outcome;
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
    assert_eq!(o.timeouts, vec![(target, None)]);
    assert!(!lookup.pending_lookups.contains_key(&target));
    assert_eq!(lookup.backoff.entry_count(), 0);
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

    // Default (disabled) backoff: nothing recorded.
    let mut lookup = empty_lookup();
    assert!(matches!(
        initiate_gate(&mut lookup, &dest, 1000, false),
        InitiateDecision::BloomMiss
    ));
    assert_eq!(lookup.backoff.entry_count(), 0);
    assert!(!lookup.pending_lookups.contains_key(&dest));

    // Enabled backoff: a failure was recorded, and no pending entry created.
    let mut lookup = suppressing_lookup();
    assert!(matches!(
        initiate_gate(&mut lookup, &dest, 1000, false),
        InitiateDecision::BloomMiss
    ));
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

    // Default (disabled) backoff: the entry is dropped and nothing recorded.
    let mut lookup = empty_lookup();
    lookup
        .pending_lookups
        .insert(dest, PendingLookup::new(1000));
    initiate_failed(&mut lookup, &dest, 1000);
    assert!(
        !lookup.pending_lookups.contains_key(&dest),
        "pending entry must be dropped"
    );
    assert_eq!(lookup.backoff.entry_count(), 0);

    // Enabled backoff: the failure is recorded.
    let mut lookup = suppressing_lookup();
    lookup
        .pending_lookups
        .insert(dest, PendingLookup::new(1000));
    initiate_failed(&mut lookup, &dest, 1000);
    assert!(!lookup.pending_lookups.contains_key(&dest));
    assert_eq!(lookup.backoff.failure_count(&dest), 1);
}

// --- Reverse-path relay: who may answer a request, and how often ---

/// A proof digest distinct per `n`.
fn digest(n: u8) -> [u8; 8] {
    [n; 8]
}

/// Record request `request_id` for `target` arriving from `upstream`, and
/// forward it through `plan_transit_forward` to `downstream`. The upstream
/// peer's filter also reaches the target, so the record shows the planner
/// leaving it out rather than the view never offering it.
fn forwarded(
    lookup: &mut Lookup,
    request_id: u64,
    target: NodeAddr,
    upstream: NodeAddr,
    downstream: &[NodeAddr],
) {
    let me = make_node_addr(0x99);
    let mut request = make_request_id(request_id, target, 5);
    let classification = classify_request(lookup, &request, &upstream, &me, 1000, 60_000, 4096, 4);
    assert!(
        matches!(classification.outcome, RequestOutcome::Forward),
        "precondition: the request is to be forwarded"
    );
    let mut peers: Vec<(NodeAddr, bool, bool)> =
        downstream.iter().map(|peer| (*peer, true, true)).collect();
    peers.push((upstream, true, true));
    let rv = MockRoutingView {
        peers,
        ..Default::default()
    };
    match plan_transit_forward(lookup, &mut request, &upstream, &rv, 1000) {
        ForwardOutcome::Forward { actions, .. } => {
            assert_eq!(action_peers(&actions), downstream, "precondition: sent on")
        }
        _ => panic!("precondition: the request is forwarded"),
    }
}

#[test]
fn a_response_from_the_requests_upstream_peer_is_ineligible() {
    let mut lookup = empty_lookup();
    let upstream = make_node_addr(0x01);
    let target = make_node_addr(0xAA);
    forwarded(&mut lookup, 7, target, upstream, &[responder()]);

    assert!(matches!(
        classify_response(&mut lookup, 7, &target, &upstream, digest(1)),
        ResponseRoute::Ineligible(Ineligibility::NotSentTo)
    ));
    assert!(
        lookup.recent_requests[&7].relayed.is_empty(),
        "an ineligible response must not take a place in the relay memory"
    );
}

#[test]
fn a_response_for_another_target_is_ineligible() {
    let mut lookup = empty_lookup();
    let target = make_node_addr(0xAA);
    let other = make_node_addr(0xAB);
    forwarded(&mut lookup, 7, target, make_node_addr(0x01), &[responder()]);

    assert!(matches!(
        classify_response(&mut lookup, 7, &other, &responder(), digest(1)),
        ResponseRoute::Ineligible(Ineligibility::OtherTarget)
    ));
    // The same peer naming the request's own target is relayed, so the
    // refusal above is the target check and not a refusal of the peer.
    assert!(matches!(
        classify_response(&mut lookup, 7, &target, &responder(), digest(1)),
        ResponseRoute::Transit { .. }
    ));
}

#[test]
fn a_response_from_a_peer_the_request_was_not_forwarded_to_is_ineligible() {
    let mut lookup = empty_lookup();
    let target = make_node_addr(0xAA);
    let stranger = make_node_addr(0x0F);
    forwarded(&mut lookup, 7, target, make_node_addr(0x01), &[responder()]);

    assert!(matches!(
        classify_response(&mut lookup, 7, &target, &stranger, digest(1)),
        ResponseRoute::Ineligible(Ineligibility::NotSentTo)
    ));
    assert!(matches!(
        classify_response(&mut lookup, 7, &target, &responder(), digest(2)),
        ResponseRoute::Transit { .. }
    ));
}

#[test]
fn a_response_to_a_request_this_node_did_not_forward_is_ineligible() {
    let mut lookup = empty_lookup();
    let upstream = make_node_addr(0x01);
    let target = make_node_addr(0xAA);
    let me = make_node_addr(0x99);
    let mut request = make_request_id(7, target, 5);
    classify_request(&mut lookup, &request, &upstream, &me, 1000, 60_000, 4096, 4);
    let rv = MockRoutingView {
        peers: vec![(responder(), true, false)],
        ..Default::default()
    };
    assert!(
        matches!(
            plan_transit_forward(&mut lookup, &mut request, &upstream, &rv, 1000),
            ForwardOutcome::NoPeers
        ),
        "precondition: no peer reaches the target"
    );

    assert!(lookup.recent_requests[&7].forwarded_to.is_empty());
    assert!(matches!(
        classify_response(&mut lookup, 7, &target, &responder(), digest(1)),
        ResponseRoute::Ineligible(Ineligibility::NotSentTo)
    ));
}

#[test]
fn a_response_from_each_peer_the_request_was_forwarded_to_is_eligible() {
    let mut lookup = empty_lookup();
    let target = make_node_addr(0xAA);
    let upstream = make_node_addr(0x01);
    let downstream = [
        make_node_addr(0x02),
        make_node_addr(0x03),
        make_node_addr(0x04),
    ];
    forwarded(&mut lookup, 7, target, upstream, &downstream);

    for (n, peer) in downstream.iter().enumerate() {
        match classify_response(&mut lookup, 7, &target, peer, digest(n as u8)) {
            ResponseRoute::Transit { from_peer } => assert_eq!(from_peer, upstream),
            _ => panic!("a response from a peer the request went to must be relayed"),
        }
    }
}

#[test]
fn an_identical_response_is_relayed_once() {
    let mut lookup = empty_lookup();
    let target = make_node_addr(0xAA);
    forwarded(&mut lookup, 7, target, make_node_addr(0x01), &[responder()]);

    assert!(matches!(
        classify_response(&mut lookup, 7, &target, &responder(), digest(1)),
        ResponseRoute::Transit { .. }
    ));
    assert!(matches!(
        classify_response(&mut lookup, 7, &target, &responder(), digest(1)),
        ResponseRoute::AlreadyForwarded
    ));
}

#[test]
fn a_reverse_path_cycle_stops_after_one_circuit() {
    // Three transits whose reverse paths form a ring: A has the request from
    // C and sent it to B, B from A and sent it to C, C from B and sent it to
    // A. Each hop is eligible, so only the relay memory ends the circuit.
    let target = make_node_addr(0xAA);
    let addrs = [
        make_node_addr(0x0A),
        make_node_addr(0x0B),
        make_node_addr(0x0C),
    ];
    let mut nodes: Vec<Lookup> = (0..3).map(|_| empty_lookup()).collect();
    for (i, node) in nodes.iter_mut().enumerate() {
        let upstream = addrs[(i + 2) % 3];
        let downstream = addrs[(i + 1) % 3];
        forwarded(node, 7, target, upstream, &[downstream]);
    }

    // B answers A, and the response follows the reverse path from there.
    let (mut at, mut sender) = (0usize, addrs[1]);
    let mut relays = 0;
    for _ in 0..30 {
        match classify_response(&mut nodes[at], 7, &target, &sender, digest(1)) {
            ResponseRoute::Transit { from_peer } => {
                relays += 1;
                sender = addrs[at];
                at = addrs
                    .iter()
                    .position(|addr| *addr == from_peer)
                    .expect("the reverse path stays on the ring");
            }
            ResponseRoute::AlreadyForwarded => break,
            _ => panic!("every hop on the ring is eligible"),
        }
    }
    assert_eq!(
        relays, 3,
        "the response must go round the ring once and then stop"
    );
}

#[test]
fn the_duplicate_memory_holds_at_most_eight_digests() {
    let mut lookup = empty_lookup();
    let target = make_node_addr(0xAA);
    forwarded(&mut lookup, 7, target, make_node_addr(0x01), &[responder()]);

    for n in 0..20u8 {
        classify_response(&mut lookup, 7, &target, &responder(), digest(n));
        assert!(lookup.recent_requests[&7].relayed.len() <= MAX_RELAYED_DIGESTS);
    }
    assert_eq!(MAX_RELAYED_DIGESTS, 8);
    let relayed: Vec<[u8; 8]> = lookup.recent_requests[&7].relayed.iter().copied().collect();
    assert_eq!(
        relayed,
        (12..20u8).map(digest).collect::<Vec<_>>(),
        "the memory keeps the newest eight, oldest dropped first"
    );
    // The oldest has gone, so a late copy of it is relayed once more.
    assert!(matches!(
        classify_response(&mut lookup, 7, &target, &responder(), digest(0)),
        ResponseRoute::Transit { .. }
    ));
}

#[test]
fn a_ninth_distinct_response_is_still_relayed() {
    // A duplicate filter, not a ceiling: a forger that answers first any
    // number of times must not stop the genuine answer.
    let mut lookup = empty_lookup();
    let target = make_node_addr(0xAA);
    forwarded(&mut lookup, 7, target, make_node_addr(0x01), &[responder()]);

    for n in 0..MAX_RELAYED_DIGESTS as u8 {
        assert!(matches!(
            classify_response(&mut lookup, 7, &target, &responder(), digest(n)),
            ResponseRoute::Transit { .. }
        ));
    }
    assert!(matches!(
        classify_response(&mut lookup, 7, &target, &responder(), digest(0xFF)),
        ResponseRoute::Transit { .. }
    ));
}

// --- Transit forward limiter: who shares a slot, and what fills it ---

/// Deliver one transit request through `classify_request` and
/// `plan_transit_forward`, as the shell does, with a dedup cache large enough
/// that its own eviction policy never interferes and one tree peer that
/// reaches every target.
fn transit_request(
    lookup: &mut Lookup,
    request_id: u64,
    target: NodeAddr,
    from: &NodeAddr,
    now_ms: u64,
) -> ForwardOutcome {
    let my_addr = make_node_addr(0x99);
    let mut request = make_request_id(request_id, target, 5);
    let classification =
        classify_request(lookup, &request, from, &my_addr, now_ms, 60_000, 1 << 20, 2);
    assert!(
        matches!(classification.outcome, RequestOutcome::Forward),
        "precondition: a fresh transit request is to be forwarded"
    );
    let rv = MockRoutingView {
        peers: vec![(make_node_addr(0x77), true, true)],
        ..Default::default()
    };
    plan_transit_forward(lookup, &mut request, from, &rv, now_ms)
}

#[test]
fn one_peer_refreshing_a_target_does_not_suppress_another_peers_request_for_it() {
    let mut lookup = empty_lookup();
    let attacker = make_node_addr(0x01);
    let honest = make_node_addr(0x02);
    let target = make_node_addr(0xAA);

    assert!(matches!(
        transit_request(&mut lookup, 1, target, &attacker, 1_000),
        ForwardOutcome::Forward { .. }
    ));
    assert!(
        matches!(
            transit_request(&mut lookup, 2, target, &honest, 1_500),
            ForwardOutcome::Forward { .. }
        ),
        "another link peer's request for the same target was suppressed by the first \
         peer's entry"
    );
}

#[test]
fn a_peer_repeating_a_target_within_the_interval_is_still_suppressed() {
    let mut lookup = empty_lookup();
    let peer = make_node_addr(0x01);
    let target = make_node_addr(0xAA);

    assert!(matches!(
        transit_request(&mut lookup, 1, target, &peer, 1_000),
        ForwardOutcome::Forward { .. }
    ));
    assert!(matches!(
        transit_request(&mut lookup, 2, target, &peer, 1_500),
        ForwardOutcome::RateLimited
    ));
}

#[test]
fn a_target_no_peer_reaches_takes_no_limiter_entry() {
    let mut lookup = empty_lookup();
    let from = make_node_addr(0x01);
    let my_addr = make_node_addr(0x99);
    let unreachable = make_node_addr(0xAB);
    let mut request = make_request_id(1, unreachable, 5);
    classify_request(
        &mut lookup,
        &request,
        &from,
        &my_addr,
        1_000,
        60_000,
        4096,
        2,
    );
    // A peer exists, but no peer's filter reaches the target.
    let rv = MockRoutingView {
        peers: vec![(make_node_addr(0x05), true, false)],
        ..Default::default()
    };

    assert!(
        matches!(
            plan_transit_forward(&mut lookup, &mut request, &from, &rv, 1_000),
            ForwardOutcome::NoPeers
        ),
        "precondition: no peer can carry the request"
    );
    assert_eq!(
        lookup.forward_limiter.len(),
        0,
        "a request no peer can carry took a forward limiter entry"
    );

    // The same peer and target once a peer reaches it: the limiter records
    // it and suppresses the repeat, so the zero above is the planner leaving
    // the limiter alone and not a limiter that records nothing.
    let rv = MockRoutingView {
        peers: vec![(make_node_addr(0x05), true, true)],
        ..Default::default()
    };
    let mut request = make_request_id(2, unreachable, 5);
    classify_request(
        &mut lookup,
        &request,
        &from,
        &my_addr,
        1_100,
        60_000,
        4096,
        2,
    );
    assert!(matches!(
        plan_transit_forward(&mut lookup, &mut request, &from, &rv, 1_100),
        ForwardOutcome::Forward { .. }
    ));
    assert_eq!(lookup.forward_limiter.len(), 1);
    let mut request = make_request_id(3, unreachable, 5);
    classify_request(
        &mut lookup,
        &request,
        &from,
        &my_addr,
        1_200,
        60_000,
        4096,
        2,
    );
    assert!(matches!(
        plan_transit_forward(&mut lookup, &mut request, &from, &rv, 1_200),
        ForwardOutcome::RateLimited
    ));
}

#[test]
fn a_full_limiter_still_records_the_newcomer() {
    // MAX_FORWARD_ENTRIES (4096) is the production bound on the limiter.
    let mut lookup = empty_lookup();
    let flooder = make_node_addr(0x01);
    let honest = make_node_addr(0x02);
    let now = 1_000;
    for i in 0..MAX_FORWARD_ENTRIES as u32 {
        transit_request(
            &mut lookup,
            10_000 + u64::from(i),
            distinct_addr(i + 1),
            &flooder,
            now,
        );
    }
    assert_eq!(
        lookup.forward_limiter.len(),
        MAX_FORWARD_ENTRIES,
        "precondition: the flooder's made-up targets fill the limiter"
    );

    let target = make_node_addr(0xAA);
    assert!(matches!(
        transit_request(&mut lookup, 1, target, &honest, now),
        ForwardOutcome::Forward { .. }
    ));
    assert!(
        matches!(
            transit_request(&mut lookup, 2, target, &honest, now + 100),
            ForwardOutcome::RateLimited
        ),
        "with the limiter full, a repeat for the same target inside the interval was \
         forwarded: the newcomer was admitted without being recorded"
    );
}
