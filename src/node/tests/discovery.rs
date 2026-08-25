//! Discovery protocol tests: LookupRequest and LookupResponse.
//!
//! Unit tests for handler logic (dedup, TTL, response caching) and
//! integration tests for multi-node forwarding and reverse-path
//! response routing.

use super::*;
use crate::proto::lookup::{LookupRequest, LookupResponse, RecentRequest};
use crate::proto::stp::TreeCoordinate;
use spanning_tree::{
    cleanup_nodes, generate_random_edges, lock_large_network_test, process_available_packets,
    run_tree_test, run_tree_test_with_mtus, verify_tree_convergence,
};

// ============================================================================
// Unit Tests — LookupRequest Handler
// ============================================================================

#[tokio::test]
async fn test_request_decode_error() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    // Too-short payload: should log error and return without panic
    node.handle_lookup_request(&from, &[0x00; 5]).await;
    assert!(node.lookup.recent_requests.is_empty());
}

#[tokio::test]
async fn test_request_dedup() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let target = make_node_addr(0xBB);
    let origin = make_node_addr(0xCC);

    let request = LookupRequest::new(999, target, origin, 5, 0);
    let payload = &request.encode()[1..]; // skip msg_type byte

    // First request: accepted
    node.handle_lookup_request(&from, payload).await;
    assert_eq!(node.lookup.recent_requests.len(), 1);

    // Duplicate request: dropped
    node.handle_lookup_request(&from, payload).await;
    assert_eq!(node.lookup.recent_requests.len(), 1);
}

#[tokio::test]
async fn test_request_target_is_self() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let origin = make_node_addr(0xCC);
    let my_addr = *node.node_addr();

    // Request targeting us
    let request = LookupRequest::new(777, my_addr, origin, 5, 0);
    let payload = &request.encode()[1..];

    // Should succeed without panic (response send will fail silently
    // since we have no peers to route toward origin)
    node.handle_lookup_request(&from, payload).await;
    assert!(node.lookup.recent_requests.contains_key(&777));
}

#[tokio::test]
async fn test_request_ttl_zero_not_forwarded() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let target = make_node_addr(0xBB);
    let origin = make_node_addr(0xCC);

    let request = LookupRequest::new(666, target, origin, 0, 0);
    let payload = &request.encode()[1..];

    node.handle_lookup_request(&from, payload).await;
    // Request recorded, but not forwarded (TTL=0, and no peers anyway)
    assert!(node.lookup.recent_requests.contains_key(&666));
}

// ============================================================================
// Unit Tests — LookupResponse Handler
// ============================================================================

/// Record `request_id` as outstanding for `target`, exactly as
/// `initiate_lookup` does when it puts a request on the wire. The response
/// handler correlates against this, so a unit test that hands the handler a
/// response without it is testing the correlation gate rather than whatever
/// it names.
fn seed_pending_lookup(node: &mut Node, target: crate::NodeAddr, request_id: u64) {
    node.lookup
        .pending_lookups
        .entry(target)
        .or_insert_with(|| crate::proto::lookup::PendingLookup::new(Node::now_ms()))
        .record(request_id);
}

#[tokio::test]
async fn test_response_decode_error() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    node.handle_lookup_response(&from, &[0x00; 10]).await;
    // No panic, no route cached
    assert!(node.coord_cache().is_empty());
}

#[tokio::test]
async fn test_response_originator_caches_route() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    // Use the target identity's actual node_addr for consistency
    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let root = make_node_addr(0xF0);
    let coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();

    // Register target identity in cache so verification can find it
    node.register_identity(target, target_identity.pubkey_full());

    seed_pending_lookup(&mut node, target, 555);

    // Create a valid response with a real proof signature (includes coords)
    let proof_data = LookupResponse::proof_bytes(555, &target, &coords);
    let proof = target_identity.sign(&proof_data);

    let response = LookupResponse::new(555, target, coords.clone(), proof);
    let payload = &response.encode()[1..]; // skip msg_type

    // No entry in recent_requests for 555 → we're the originator
    assert!(!node.lookup.recent_requests.contains_key(&555));

    node.handle_lookup_response(&from, payload).await;

    // Route should be cached in coord_cache
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    assert!(node.coord_cache().contains(&target, now_ms));
    assert_eq!(node.coord_cache().get(&target, now_ms).unwrap(), &coords);
}

#[tokio::test]
async fn test_response_transit_needs_recent_request() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let target = make_node_addr(0xBB);
    let root = make_node_addr(0xF0);
    let coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();

    // Transit nodes don't verify proofs, so any valid signature suffices
    let proof_data = LookupResponse::proof_bytes(444, &target, &coords);
    let target_identity = Identity::generate();
    let proof = target_identity.sign(&proof_data);

    let response = LookupResponse::new(444, target, coords, proof);
    let payload = &response.encode()[1..];

    // Simulate being a transit node: record a recent_request for this ID
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    node.lookup
        .recent_requests
        .insert(444, RecentRequest::new(make_node_addr(0xDD), now_ms));

    // Handle response — should try to reverse-path forward to 0xDD
    // (will fail silently since 0xDD is not an actual peer)
    node.handle_lookup_response(&from, payload).await;

    // Should NOT cache in coord_cache (we're transit, not originator)
    let now_ms2 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    assert!(!node.coord_cache().contains(&target, now_ms2));
}

// ============================================================================
// Unit Tests — LookupResponse Proof Verification
// ============================================================================

#[tokio::test]
async fn test_response_proof_verification_success() {
    // Verify that a properly signed response is accepted and cached
    // when the origin has the target's pubkey in identity_cache.
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let root = make_node_addr(0xF0);
    let coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();

    // Register target in identity_cache
    node.register_identity(target, target_identity.pubkey_full());

    seed_pending_lookup(&mut node, target, 700);

    // Sign with correct proof_bytes (including coords)
    let proof_data = LookupResponse::proof_bytes(700, &target, &coords);
    let proof = target_identity.sign(&proof_data);

    let response = LookupResponse::new(700, target, coords.clone(), proof);
    let payload = &response.encode()[1..];

    node.handle_lookup_response(&from, payload).await;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    assert!(
        node.coord_cache().contains(&target, now_ms),
        "Valid proof should result in cached coords"
    );
    assert_eq!(node.coord_cache().get(&target, now_ms).unwrap(), &coords);
}

#[tokio::test]
async fn test_response_proof_verification_failure() {
    // Verify that a response with a bad signature is discarded.
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let root = make_node_addr(0xF0);
    let coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();

    // Register target in identity_cache
    node.register_identity(target, target_identity.pubkey_full());

    // Sign with a DIFFERENT identity (wrong key)
    seed_pending_lookup(&mut node, target, 701);

    let wrong_identity = Identity::generate();
    let proof_data = LookupResponse::proof_bytes(701, &target, &coords);
    let proof = wrong_identity.sign(&proof_data);

    let response = LookupResponse::new(701, target, coords, proof);
    let payload = &response.encode()[1..];

    node.handle_lookup_response(&from, payload).await;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    assert!(
        !node.coord_cache().contains(&target, now_ms),
        "Bad signature should NOT result in cached coords"
    );
}

#[tokio::test]
async fn test_response_identity_cache_miss() {
    // Verify that a response is discarded when the origin lacks the
    // target's pubkey in identity_cache (e.g., XX responder before msg3).
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let root = make_node_addr(0xF0);
    let coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();

    // Do NOT register target in identity_cache

    seed_pending_lookup(&mut node, target, 702);

    let proof_data = LookupResponse::proof_bytes(702, &target, &coords);
    let proof = target_identity.sign(&proof_data);

    let response = LookupResponse::new(702, target, coords, proof);
    let payload = &response.encode()[1..];

    node.handle_lookup_response(&from, payload).await;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    assert!(
        !node.coord_cache().contains(&target, now_ms),
        "identity_cache miss should discard the response"
    );
}

#[tokio::test]
async fn test_response_coord_substitution_detected() {
    // Verify that if the proof was signed with correct coords but
    // different coords are placed in the response, verification fails.
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let root = make_node_addr(0xF0);
    let real_coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();
    let fake_coords = TreeCoordinate::from_addrs(vec![target, make_node_addr(0xEE), root]).unwrap();

    // Register target in identity_cache
    node.register_identity(target, target_identity.pubkey_full());

    seed_pending_lookup(&mut node, target, 703);

    // Sign proof with real coords
    let proof_data = LookupResponse::proof_bytes(703, &target, &real_coords);
    let proof = target_identity.sign(&proof_data);

    // But construct the response with FAKE coords
    let response = LookupResponse::new(703, target, fake_coords, proof);
    let payload = &response.encode()[1..];

    node.handle_lookup_response(&from, payload).await;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    assert!(
        !node.coord_cache().contains(&target, now_ms),
        "Substituted coords should be detected and response discarded"
    );
}

/// Build a signed LookupResponse body for `target_identity` over
/// `request_id`, ready to hand to `handle_lookup_response`.
fn signed_response_body(
    target_identity: &Identity,
    request_id: u64,
    coords: &TreeCoordinate,
) -> Vec<u8> {
    let target = *target_identity.node_addr();
    let proof_data = LookupResponse::proof_bytes(request_id, &target, coords);
    let proof = target_identity.sign(&proof_data);
    LookupResponse::new(request_id, target, coords.clone(), proof).encode()[1..].to_vec()
}

/// Register `target_identity` and return its address and a plausible
/// coordinate for it, the shared preamble of the correlation tests.
fn register_lookup_target(node: &mut Node, target_identity: &Identity) -> TreeCoordinate {
    let target = *target_identity.node_addr();
    node.register_identity(target, target_identity.pubkey_full());
    TreeCoordinate::from_addrs(vec![target, make_node_addr(0xF0)]).unwrap()
}

fn wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[tokio::test]
async fn test_unsolicited_lookup_response_is_dropped_before_proof_verification() {
    // Any admitted peer can hand us a correctly signed response for a target
    // we never asked about. Accepting it lets that peer clear our pending
    // state, refresh a cache entry's TTL and flush our queued packets at a
    // moment it picks, so the response must not be acted on at all.
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let coords = register_lookup_target(&mut node, &target_identity);
    let body = signed_response_body(&target_identity, 900, &coords);

    assert!(
        node.lookup.pending_lookups.is_empty(),
        "precondition: this node has no lookup outstanding for anything"
    );

    node.handle_lookup_response(&from, &body).await;

    assert!(
        !node.coord_cache().contains(&target, wall_clock_ms()),
        "a response answering no request of ours must not reach the coordinate cache"
    );
    assert_eq!(
        node.metrics().lookup.resp_accepted.get(),
        0,
        "an unsolicited response must not count as accepted"
    );
    assert_eq!(
        node.metrics().lookup.resp_unsolicited.get(),
        1,
        "the drop must be visible on a counter, not only in a log"
    );
    assert_eq!(
        node.metrics().lookup.resp_proof_failed.get(),
        0,
        "the drop must happen before the signature verify, so the verify is not a cost gate"
    );
}

#[tokio::test]
async fn test_lookup_response_with_a_request_id_we_never_issued_is_dropped() {
    // Correlating on the target alone would leave the attack open: there is
    // no inbound limiter on responses, so a peer can spray a harvested one
    // and land inside any window in which we happen to be looking that
    // target up. The id must match too.
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let coords = register_lookup_target(&mut node, &target_identity);

    node.initiate_lookup(&target, 5).await;
    let issued = node
        .lookup
        .pending_lookups
        .get(&target)
        .unwrap()
        .ids
        .clone();
    assert_eq!(issued.len(), 1, "precondition: one attempt went out");

    let body = signed_response_body(&target_identity, issued[0] ^ 1, &coords);
    node.handle_lookup_response(&from, &body).await;

    assert!(
        !node.coord_cache().contains(&target, wall_clock_ms()),
        "a response bearing an id we never issued must not reach the coordinate cache"
    );
    assert!(
        node.lookup.pending_lookups.contains_key(&target),
        "it must not cancel the lookup that is genuinely outstanding"
    );
    assert_eq!(node.metrics().lookup.resp_unsolicited.get(), 1);
}

#[tokio::test]
async fn test_a_response_matching_a_pending_attempt_is_accepted_and_clears_the_pending_lookup() {
    // The healthy path. A fix that reds a legitimate lookup is no use, and
    // this is the test that catches it.
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let coords = register_lookup_target(&mut node, &target_identity);

    node.initiate_lookup(&target, 5).await;
    let issued = node.lookup.pending_lookups.get(&target).unwrap().ids[0];

    let body = signed_response_body(&target_identity, issued, &coords);
    node.handle_lookup_response(&from, &body).await;

    assert_eq!(
        node.coord_cache().get(&target, wall_clock_ms()),
        Some(&coords),
        "a response to our own outstanding request must be cached"
    );
    assert!(
        !node.lookup.pending_lookups.contains_key(&target),
        "accepting it must clear the pending lookup"
    );
    assert_eq!(node.metrics().lookup.resp_accepted.get(), 1);
    assert_eq!(node.metrics().lookup.resp_unsolicited.get(), 0);
}

#[tokio::test]
async fn test_a_late_response_for_an_earlier_retry_attempt_is_still_accepted() {
    // Each retry draws a fresh id, and on any link with more than a second
    // of round trip the reply to an earlier attempt is the common case. A
    // correlator that remembered only the newest id would drop it.
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let coords = register_lookup_target(&mut node, &target_identity);

    node.initiate_lookup(&target, 5).await;
    node.initiate_lookup(&target, 5).await;
    let issued = node
        .lookup
        .pending_lookups
        .get(&target)
        .unwrap()
        .ids
        .clone();
    assert_eq!(issued.len(), 2, "precondition: two attempts, two ids");

    let body = signed_response_body(&target_identity, issued[0], &coords);
    node.handle_lookup_response(&from, &body).await;

    assert_eq!(
        node.coord_cache().get(&target, wall_clock_ms()),
        Some(&coords),
        "the first attempt's id is still ours and its answer must be accepted"
    );
}

#[tokio::test]
async fn test_a_second_genuine_response_after_the_first_is_accepted_is_dropped() {
    // The request is flooded to every qualifying tree peer, so duplicate
    // replies are routine. They are dropped at the correlation gate, which
    // gives the unsolicited counter a nonzero floor in healthy operation:
    // it is not by itself a sign of attack traffic.
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let coords = register_lookup_target(&mut node, &target_identity);

    node.initiate_lookup(&target, 5).await;
    let issued = node.lookup.pending_lookups.get(&target).unwrap().ids[0];
    let body = signed_response_body(&target_identity, issued, &coords);

    node.handle_lookup_response(&from, &body).await;
    node.handle_lookup_response(&from, &body).await;

    assert_eq!(
        node.coord_cache().get(&target, wall_clock_ms()),
        Some(&coords),
        "the value written by the first response must still be there"
    );
    assert_eq!(
        node.metrics().lookup.resp_accepted.get(),
        1,
        "only the first of the two answers our request"
    );
    assert_eq!(
        node.metrics().lookup.resp_unsolicited.get(),
        1,
        "the duplicate is counted, which is why the counter has a healthy floor"
    );
}

#[tokio::test]
async fn test_a_validly_signed_response_for_a_retired_lookup_is_dropped() {
    // The pending entry's lifetime is what bounds how stale an accepted
    // coordinate can be. Once the retry ladder is exhausted and the entry
    // goes, a transit node holding the genuine reply can no longer deliver
    // it late.
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let coords = register_lookup_target(&mut node, &target_identity);

    node.initiate_lookup(&target, 5).await;
    let issued = node.lookup.pending_lookups.get(&target).unwrap().ids[0];

    // Drive the whole ladder: three retries, then the final timeout.
    let mut now_ms = Node::now_ms();
    for _ in 0..4 {
        now_ms += 100_000;
        node.check_pending_lookups(now_ms).await;
    }
    assert!(
        !node.lookup.pending_lookups.contains_key(&target),
        "precondition: the ladder retired the lookup"
    );

    let body = signed_response_body(&target_identity, issued, &coords);
    node.handle_lookup_response(&from, &body).await;

    assert!(
        !node.coord_cache().contains(&target, wall_clock_ms()),
        "a reply to a retired lookup must not install a coordinate"
    );
    assert_eq!(node.metrics().lookup.resp_unsolicited.get(), 1);
}

#[test]
fn pending_lookup_id_set_evicts_the_oldest_id_rather_than_refusing_the_newest() {
    // The retry ladder is operator configuration and can be longer than the
    // recorded-id cap. Refusing the newest id would discard the attempt most
    // likely to be answered and fail a healthy lookup.
    let mut pending = crate::proto::lookup::PendingLookup::new(0);
    for id in 0..12u64 {
        pending.record(id);
    }
    assert!(
        pending.matches(11),
        "the newest attempt's id must always be remembered"
    );
    assert!(!pending.matches(0), "the oldest id is the one evicted");
    assert_eq!(pending.ids.len(), 8, "the set stays bounded");
}

// ============================================================================
// Unit Tests — RecentRequest Expiry
// ============================================================================

#[tokio::test]
async fn test_recent_request_expiry() {
    let mut node = make_node();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Insert an old request (11 seconds ago)
    node.lookup
        .recent_requests
        .insert(123, RecentRequest::new(make_node_addr(1), now_ms - 11_000));

    // Insert a recent request
    node.lookup
        .recent_requests
        .insert(456, RecentRequest::new(make_node_addr(2), now_ms));

    assert_eq!(node.lookup.recent_requests.len(), 2);

    // Trigger purge via a new lookup request
    let target = make_node_addr(0xBB);
    let origin = make_node_addr(0xCC);
    let request = LookupRequest::new(789, target, origin, 3, 0);
    let payload = &request.encode()[1..];
    node.handle_lookup_request(&make_node_addr(0xAA), payload)
        .await;

    // Old entry (123) should be purged, recent entry (456) and new entry (789) kept
    assert!(!node.lookup.recent_requests.contains_key(&123));
    assert!(node.lookup.recent_requests.contains_key(&456));
    assert!(node.lookup.recent_requests.contains_key(&789));
}

// ============================================================================
// Unit Tests — dedup cache capacity policy
// ============================================================================

use crate::proto::lookup::{MAX_RECENT_LOOKUP_REQUESTS, MIN_RECENT_PER_PEER};

/// Encode a LookupRequest for `target` carrying `request_id`, ready for
/// `handle_lookup_request` (which is handed the payload without the
/// msg_type byte).
fn lookup_request_payload(request_id: u64, target: &crate::NodeAddr) -> Vec<u8> {
    let origin = make_node_addr(0xCC);
    // `next`'s LookupRequest carries no coordinates.
    LookupRequest::new(request_id, *target, origin, 5, 0).encode()[1..].to_vec()
}

/// Deliver `count` distinct requests from `from`, ids starting at `first_id`.
async fn flood_requests(node: &mut Node, from: &crate::NodeAddr, first_id: u64, count: u64) {
    let target = make_node_addr(0xBB);
    for i in 0..count {
        let payload = lookup_request_payload(first_id + i, &target);
        node.handle_lookup_request(from, &payload).await;
    }
}

/// Register `count` peers so the per-peer share of the dedup cache is the
/// floor rather than the whole cache, and return their addresses.
fn register_peers(node: &mut Node, count: usize) -> Vec<crate::NodeAddr> {
    (0..count)
        .map(|i| {
            let identity = Identity::generate();
            let addr = *identity.node_addr();
            let peer_identity = crate::PeerIdentity::from_pubkey(identity.pubkey());
            node.peers.insert(
                addr,
                ActivePeer::new(peer_identity, LinkId::new(i as u64), 0),
            );
            addr
        })
        .collect()
}

#[tokio::test]
async fn test_a_full_dedup_cache_admits_the_new_request_by_evicting_the_oldest() {
    // A full cache used to drop the arriving request, which let one peer
    // spend 4096 fresh request_ids and stop the node forwarding anyone
    // else's lookups until the entries aged out.
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    flood_requests(&mut node, &from, 1, MAX_RECENT_LOOKUP_REQUESTS as u64).await;
    assert_eq!(
        node.lookup.recent_requests.len(),
        MAX_RECENT_LOOKUP_REQUESTS,
        "precondition: the cache is full, or the rest observes nothing"
    );

    let payload = lookup_request_payload(u64::MAX, &make_node_addr(0xBB));
    node.handle_lookup_request(&from, &payload).await;

    assert!(
        node.lookup.recent_requests.contains_key(&u64::MAX),
        "the arriving request must be recorded, so its response can be routed back"
    );
    assert!(
        !node.lookup.recent_requests.contains_key(&1),
        "room is made by dropping the oldest entry"
    );
    assert_eq!(
        node.lookup.recent_requests.len(),
        MAX_RECENT_LOOKUP_REQUESTS,
        "the cache stays at its bound"
    );
    assert_eq!(node.metrics().lookup.req_dedup_evicted.get(), 1);
    assert_eq!(
        node.metrics().lookup.req_dedup_cache_full.get(),
        0,
        "the cache-full drop is gone, and its counter stays frozen at zero"
    );
}

#[tokio::test]
async fn test_a_flooding_peer_evicts_only_its_own_dedup_entries() {
    // The whole point of partitioning the cache by link peer: one peer
    // filling its share must not cost another peer the reverse path its own
    // lookup depends on.
    let mut node = make_node();
    let peers = register_peers(&mut node, 64);
    let flooder = peers[0];
    let light = peers[1];

    let payload = lookup_request_payload(7, &make_node_addr(0xBB));
    node.handle_lookup_request(&light, &payload).await;

    // One over the share, so the flooder pays for its own admission.
    flood_requests(&mut node, &flooder, 1000, MIN_RECENT_PER_PEER as u64 + 1).await;

    assert!(
        node.lookup.recent_requests.contains_key(&7),
        "a light peer's reverse-path entry must survive a neighbour's flood"
    );
    assert!(
        !node.lookup.recent_requests.contains_key(&1000),
        "the flooder's own oldest entry is what pays for its newest"
    );
    assert!(
        node.lookup
            .recent_requests
            .contains_key(&(1000 + MIN_RECENT_PER_PEER as u64)),
        "and its newest is admitted rather than dropped"
    );
}

#[tokio::test]
async fn test_a_node_whose_dedup_cache_is_flooded_still_answers_a_lookup_for_itself() {
    // The availability claim. Filling the cache used to make the node
    // unresolvable, because the cache-full drop sat ahead of the check for
    // whether the request names us.
    let mut node = make_node();
    let flooder = make_node_addr(0xAA);
    let other = make_node_addr(0xAB);

    flood_requests(&mut node, &flooder, 1, MAX_RECENT_LOOKUP_REQUESTS as u64).await;

    let my_addr = *node.node_addr();
    let payload = lookup_request_payload(u64::MAX, &my_addr);
    node.handle_lookup_request(&other, &payload).await;

    assert_eq!(
        node.metrics().lookup.req_target_is_us.get(),
        1,
        "a flooded cache must not stop the node answering lookups for itself"
    );
}

#[tokio::test]
async fn test_the_dedup_index_stays_level_with_the_cache_across_insert_duplicate_and_purge() {
    // Two containers where there was one, so the desync is the maintenance
    // risk. Everything the eviction policy decides reads the index, so an
    // index that has drifted evicts the wrong entry or none at all.
    let mut node = make_node();
    let peers = register_peers(&mut node, 64);

    flood_requests(&mut node, &peers[0], 1, 70).await;
    flood_requests(&mut node, &peers[1], 500, 5).await;
    // Duplicates, which must not be indexed twice.
    flood_requests(&mut node, &peers[1], 500, 5).await;

    let indexed: usize = node
        .lookup
        .recent_by_peer
        .values()
        .map(|ids| ids.len())
        .sum();
    assert_eq!(
        indexed,
        node.lookup.recent_requests.len(),
        "every cached request is indexed exactly once"
    );

    // Age everything out and purge through the ordinary request path.
    let expiry_ms = node.config().node.lookup.recent_expiry_secs * 1000;
    let future = Node::now_ms() + expiry_ms + 1;
    node.purge_expired_requests(future);

    assert!(
        node.lookup.recent_requests.is_empty(),
        "precondition: the purge removed everything"
    );
    assert!(
        node.lookup.recent_by_peer.is_empty(),
        "the index must not keep entries the cache no longer holds"
    );
}

#[tokio::test]
async fn test_answering_lookups_for_ourselves_stops_at_the_per_peer_signing_budget() {
    // Each answer costs a fresh Schnorr signature, because the proof is
    // bound to the requester's request_id and cannot be reused. Without a
    // budget, one neighbour sets this node's signing rate.
    let mut node = make_node();
    node.set_discovery_sign_budget(3.0, 0.0);
    let from = make_node_addr(0xAA);
    let other = make_node_addr(0xAB);
    let my_addr = *node.node_addr();

    for id in 0..4u64 {
        let payload = lookup_request_payload(id, &my_addr);
        node.handle_lookup_request(&from, &payload).await;
    }

    assert_eq!(
        node.metrics().lookup.req_target_is_us.get(),
        3,
        "the burst is answered and the fourth request is not"
    );
    assert_eq!(node.metrics().lookup.req_sign_rate_limited.get(), 1);

    let payload = lookup_request_payload(100, &my_addr);
    node.handle_lookup_request(&other, &payload).await;
    assert_eq!(
        node.metrics().lookup.req_target_is_us.get(),
        4,
        "one peer spending its budget must not make the node unresolvable through another"
    );
}

// ============================================================================
// Integration Tests — Multi-Node Forwarding
// ============================================================================

#[tokio::test]
async fn test_request_forwarding_two_node() {
    // Set up a two-node topology: node0 — node1
    // Send a LookupRequest from node0 targeting node1's address.
    // Node1 should receive the forwarded request.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;

    let node0_addr = *nodes[0].node.node_addr();
    let target = *nodes[1].node.node_addr(); // target node1 (in bloom filters)

    let request = LookupRequest::new(42, target, node0_addr, 5, 0);
    let payload = &request.encode()[1..];

    // Handle on node0 as if we received it from outside
    nodes[0]
        .node
        .handle_lookup_request(&node0_addr, payload)
        .await;

    // Process packets — node1 should receive the forwarded request
    tokio::time::sleep(Duration::from_millis(50)).await;
    let count = process_available_packets(&mut nodes).await;
    assert!(
        count > 0,
        "Expected forwarded LookupRequest to arrive at node 1"
    );

    // Node1 should have recorded the request
    assert!(
        nodes[1].node.lookup.recent_requests.contains_key(&42),
        "Node 1 should have recorded the forwarded request"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_request_target_found_generates_response() {
    // Set up a two-node topology: node0 — node1
    // Node0 initiates a lookup targeting node1.
    // Node1 receives, detects it's the target, generates a LookupResponse.
    // Response routes back to node0 which caches the coordinates.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;

    let node1_addr = *nodes[1].node.node_addr();

    // Node0 initiates lookup (doesn't record in recent_requests)
    nodes[0].node.initiate_lookup(&node1_addr, 5).await;

    // Process packets in rounds to allow request + response
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    // Node0 should have cached node1's route (it originated the request)
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    assert!(
        nodes[0].node.coord_cache().contains(&node1_addr, now_ms),
        "Node 0 should have cached node 1's route from LookupResponse"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_request_three_node_chain() {
    // Topology: node0 — node1 — node2
    // Node0 initiates a lookup targeting node2.
    // Request should propagate: node0 → node1 → node2.
    // Node2 generates response, reverse-path: node2 → node1 → node0.
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;

    let node2_addr = *nodes[2].node.node_addr();
    let node2_pubkey = nodes[2].node.identity().pubkey_full();

    // Pre-populate node0's identity_cache with node2's identity
    // (in production, DNS resolution or prior handshake would do this)
    nodes[0].node.register_identity(node2_addr, node2_pubkey);

    // Node0 initiates lookup (doesn't record in recent_requests)
    nodes[0].node.initiate_lookup(&node2_addr, 8).await;

    // Process packets in rounds to allow multi-hop propagation + response
    // Chain: node0→node1→node2 (request), node2→node1→node0 (response)
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        process_available_packets(&mut nodes).await;
    }

    // Node1 should have been a transit node (has the request_id in recent_requests)
    assert!(
        !nodes[1].node.lookup.recent_requests.is_empty(),
        "Node 1 should have recorded the forwarded request"
    );

    // Node2 should have received the request (it's the target)
    assert!(
        !nodes[2].node.lookup.recent_requests.is_empty(),
        "Node 2 should have received the request"
    );

    // Node0 should have cached node2's route
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    assert!(
        nodes[0].node.coord_cache().contains(&node2_addr, now_ms),
        "Node 0 should have cached node 2's route through 3-node chain"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_request_dedup_convergent_paths() {
    // Topology: triangle (node0 — node1, node0 — node2, node1 — node2)
    // A request from node0 targeting node2 may reach it via two paths
    // depending on bloom filter state. If both paths deliver the request,
    // the second arrival at node2 should be deduped.
    let edges = vec![(0, 1), (0, 2), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;

    let node0_addr = *nodes[0].node.node_addr();
    let target = *nodes[2].node.node_addr(); // target node2 (in bloom filters)

    let request = LookupRequest::new(300, target, node0_addr, 5, 0);
    let payload = &request.encode()[1..];

    // Node0 handles the request (forwards to peers whose bloom filter
    // contains node2 — bloom-guided, not flooding)
    nodes[0]
        .node
        .handle_lookup_request(&node0_addr, payload)
        .await;

    // Process several rounds
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    // Node2 (the target) must have received the request
    assert!(
        nodes[2].node.lookup.recent_requests.contains_key(&300),
        "Node 2 (target) should have received the request"
    );

    // If node1 also received and forwarded it, node2 would have seen a
    // duplicate — verify dedup counter reflects convergent arrivals.
    // With bloom-guided routing, node1 may or may not receive the request
    // depending on filter state, so we only assert the target received it.

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Integration Tests — 100-Node Discovery
// ============================================================================

#[tokio::test]
#[ignore] // Long-running (~2 min): run explicitly with --ignored
async fn test_discovery_100_nodes() {
    let _guard = lock_large_network_test().await;

    // Set up a 100-node random topology (same seed as other 100-node tests).
    // Each node initiates lookups to a sample of other nodes in batches,
    // processing packets between batches to avoid flooding the network.
    const NUM_NODES: usize = 100;
    const TARGET_EDGES: usize = 250;
    const SEED: u64 = 42;
    const TTL: u8 = 20; // must exceed tree diameter (can reach 17+ hops)
    let edges = generate_random_edges(NUM_NODES, TARGET_EDGES, SEED);
    let mut nodes = run_tree_test(NUM_NODES, &edges, false).await;
    verify_tree_convergence(&nodes);

    // Disable forward rate limiting: in this test all 100 nodes look up
    // the same 10 targets in <1s wall time. The 2s per-target rate limit
    // would suppress nearly all transit forwarding.
    for tn in nodes.iter_mut() {
        tn.node.disable_discovery_forward_rate_limit();
    }

    // Collect all node addresses and public keys for lookup targets
    let all_addrs: Vec<NodeAddr> = nodes.iter().map(|tn| *tn.node.node_addr()).collect();
    let all_pubkeys: Vec<secp256k1::PublicKey> = nodes
        .iter()
        .map(|tn| tn.node.identity().pubkey_full())
        .collect();

    // Pre-populate identity caches: each source needs the target's pubkey
    // for proof verification. In production, DNS resolution populates this
    // before lookups are initiated.
    for (src, node) in nodes.iter_mut().enumerate() {
        for dst in (0..NUM_NODES).step_by(10) {
            if src == dst {
                continue;
            }
            node.node
                .register_identity(all_addrs[dst], all_pubkeys[dst]);
        }
    }

    // Each node looks up every 10th other node (~10 targets per node).
    // Build the full list of (src, dst) pairs.
    let mut lookup_pairs: Vec<(usize, usize)> = Vec::new();
    for src in 0..NUM_NODES {
        for dst in (0..NUM_NODES).step_by(10) {
            if src == dst {
                continue;
            }
            lookup_pairs.push((src, dst));
        }
    }
    let total_lookups = lookup_pairs.len();

    // Process one source node at a time. Each node initiates ~10 lookups,
    // which route through the tree via bloom filters. We drain until
    // quiescent before moving to the next node.
    for src in 0..NUM_NODES {
        // Initiate all lookups for this source node
        let mut initiated = false;
        for &(s, dst) in &lookup_pairs {
            if s == src {
                nodes[src].node.initiate_lookup(&all_addrs[dst], TTL).await;
                initiated = true;
            }
        }
        if !initiated {
            continue;
        }

        // Drain packets until quiescent. With single-path tree routing,
        // a packet forwarded by node X may land in node Y's queue where
        // Y < X in iteration order, causing a zero-count round even though
        // packets are in flight. Use a higher idle threshold to handle this.
        let mut idle_rounds = 0;
        for _ in 0..80 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            let count = process_available_packets(&mut nodes).await;
            if count == 0 {
                idle_rounds += 1;
                if idle_rounds >= 5 {
                    break;
                }
            } else {
                idle_rounds = 0;
            }
        }
    }

    // Verify: each originator should have the target's coords in coord_cache
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut resolved = 0usize;
    let mut failed = 0usize;
    let mut failed_pairs: Vec<(usize, usize)> = Vec::new();

    for &(src, dst) in &lookup_pairs {
        if nodes[src]
            .node
            .coord_cache()
            .contains(&all_addrs[dst], now_ms)
        {
            resolved += 1;
        } else {
            failed += 1;
            if failed_pairs.len() < 20 {
                failed_pairs.push((src, dst));
            }
        }
    }

    eprintln!("\n  === Discovery 100-Node Test ===",);
    eprintln!(
        "  Lookups: {} | Resolved: {} | Failed: {} | Success rate: {:.1}%",
        total_lookups,
        resolved,
        failed,
        resolved as f64 / total_lookups as f64 * 100.0
    );

    // Report coord_cache stats across all nodes
    let total_cached: usize = nodes.iter().map(|tn| tn.node.coord_cache().len()).sum();
    let min_cached = nodes
        .iter()
        .map(|tn| tn.node.coord_cache().len())
        .min()
        .unwrap();
    let max_cached = nodes
        .iter()
        .map(|tn| tn.node.coord_cache().len())
        .max()
        .unwrap();
    eprintln!(
        "  Coord cache entries: total={} min={} max={} avg={:.1}",
        total_cached,
        min_cached,
        max_cached,
        total_cached as f64 / NUM_NODES as f64
    );

    // Detailed diagnostics for failures (to aid future debugging)
    if !failed_pairs.is_empty() {
        eprintln!(
            "  --- Failure Diagnostics ({} failures) ---",
            failed_pairs.len()
        );
        for &(src, dst) in &failed_pairs {
            let src_coords = nodes[src].node.tree_state().my_coords().clone();
            let dst_coords = nodes[dst].node.tree_state().my_coords().clone();
            let tree_dist = src_coords.distance_to(&dst_coords);
            let reverse_cached = nodes[dst]
                .node
                .coord_cache()
                .contains(&all_addrs[src], now_ms);
            let src_peers = nodes[src].node.peers.len();
            let dst_peers = nodes[dst].node.peers.len();

            eprintln!(
                "    node {} -> node {}: tree_dist={} src_depth={} dst_depth={} \
                 src_peers={} dst_peers={} reverse_cached={}",
                src,
                dst,
                tree_dist,
                src_coords.depth(),
                dst_coords.depth(),
                src_peers,
                dst_peers,
                reverse_cached
            );
        }
    }

    assert_eq!(
        failed, 0,
        "All {} lookups should resolve, but {} failed",
        total_lookups, failed
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Integration Tests — MTU Propagation
// ============================================================================

#[tokio::test]
async fn test_response_path_mtu_two_node() {
    // Two-node topology: node0 — node1
    // Node0 initiates lookup for node1. node1 is the target and generates
    // the response: send_lookup_response folds in node1's own outgoing-link
    // MTU before sending, so path_mtu reflects the target-edge link
    // constraint (the test transport MTU, 1280) even with no transit hops.
    // Without that target-edge fold, a 2-node lookup would leave path_mtu
    // at u16::MAX since no transit min-fold runs — that's the gap closed
    // alongside the configured-peer seed in the B3 follow-up.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;

    let node1_addr = *nodes[1].node.node_addr();

    nodes[0].node.initiate_lookup(&node1_addr, 5).await;

    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    assert!(
        nodes[0].node.coord_cache().contains(&node1_addr, now_ms),
        "Node 0 should have cached node 1's route"
    );

    let entry = nodes[0].node.coord_cache().get_entry(&node1_addr).unwrap();
    let path_mtu = entry
        .path_mtu()
        .expect("path_mtu should be set from discovery");
    assert_eq!(
        path_mtu, 1280,
        "Two-node path_mtu should be the target-edge link MTU (1280 in tests)"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_apply_outgoing_link_mtu_to_response_unknown_peer_noop() {
    // When next_hop is not a directly-connected peer (no entry in
    // self.peers), apply_outgoing_link_mtu_to_response is a no-op and the
    // response's path_mtu is left unchanged. Pins the early-return path.
    let node = make_node();
    let unknown = make_node_addr(0x99);

    let coords = TreeCoordinate::from_addrs(vec![unknown, make_node_addr(0)]).unwrap();
    let identity = Identity::generate();
    let proof_data = LookupResponse::proof_bytes(1, &unknown, &coords);
    let proof = identity.sign(&proof_data);
    let mut response = LookupResponse::new(1, unknown, coords, proof);
    response.path_mtu = 1500;

    node.apply_outgoing_link_mtu_to_response(&mut response, &unknown);
    assert_eq!(
        response.path_mtu, 1500,
        "Unknown next_hop must leave path_mtu untouched"
    );
}

#[tokio::test]
async fn test_response_path_mtu_three_node_chain() {
    // Topology: node0 — node1 — node2
    // Node0 initiates lookup for node2. The response travels node2→node1→node0.
    // Node1 is a transit node and applies path_mtu = min(u16::MAX, link_mtu).
    // With test transport MTU of 1280, the final path_mtu at node0 should be 1280.
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;

    let node2_addr = *nodes[2].node.node_addr();
    let node2_pubkey = nodes[2].node.identity().pubkey_full();

    nodes[0].node.register_identity(node2_addr, node2_pubkey);

    nodes[0].node.initiate_lookup(&node2_addr, 8).await;

    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        process_available_packets(&mut nodes).await;
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    assert!(
        nodes[0].node.coord_cache().contains(&node2_addr, now_ms),
        "Node 0 should have cached node 2's route"
    );

    // Node1 is transit and applies min(u16::MAX, 1280) = 1280
    let entry = nodes[0].node.coord_cache().get_entry(&node2_addr).unwrap();
    let path_mtu = entry
        .path_mtu()
        .expect("path_mtu should be set from discovery");
    assert_eq!(
        path_mtu, 1280,
        "Three-node chain path_mtu should reflect transit node's transport MTU (1280)"
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Unit Tests — Cache Entry path_mtu
// ============================================================================

#[tokio::test]
async fn test_cache_entry_path_mtu_stored() {
    // Verify that insert_verified_with_path_mtu stores the path_mtu in the cache entry
    let mut node = make_node();
    let target = make_node_addr(0xBB);

    let coords = TreeCoordinate::from_addrs(vec![target, make_node_addr(0)]).unwrap();

    let now_ms = 1000u64;
    node.coord_cache_mut()
        .insert_verified_with_path_mtu(target, coords, now_ms, 1280);

    let entry = node.coord_cache().get_entry(&target).unwrap();
    assert_eq!(entry.path_mtu(), Some(1280));
}

#[tokio::test]
async fn test_cache_entry_no_path_mtu_from_regular_insert() {
    // Verify that regular insert() does not set path_mtu
    let mut node = make_node();
    let target = make_node_addr(0xBB);

    let coords = TreeCoordinate::from_addrs(vec![target, make_node_addr(0)]).unwrap();

    let now_ms = 1000u64;
    let _ = node.coord_cache_mut().insert(target, coords, now_ms);

    let entry = node.coord_cache().get_entry(&target).unwrap();
    assert_eq!(entry.path_mtu(), None);
}

// ============================================================================
// Unit Tests — LookupRequest min_mtu field
// ============================================================================

#[tokio::test]
async fn test_request_min_mtu_preserved_through_encode_decode() {
    // Verify min_mtu survives encode/decode in the handler test context
    let target = make_node_addr(0xBB);
    let origin = make_node_addr(0xCC);

    let request = LookupRequest::new(100, target, origin, 5, 1386);
    let encoded = request.encode();
    let decoded = LookupRequest::decode(&encoded[1..]).unwrap();
    assert_eq!(decoded.min_mtu, 1386);
}

// ============================================================================
// Unit Tests — LookupResponse path_mtu in originator handling
// ============================================================================

#[tokio::test]
async fn test_originator_stores_path_mtu_in_cache() {
    // Verify that the originator stores path_mtu from the response in coord_cache
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let root = make_node_addr(0xF0);
    let coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();

    node.register_identity(target, target_identity.pubkey_full());

    seed_pending_lookup(&mut node, target, 800);

    let proof_data = LookupResponse::proof_bytes(800, &target, &coords);
    let proof = target_identity.sign(&proof_data);

    let mut response = LookupResponse::new(800, target, coords.clone(), proof);
    // Simulate transit having reduced path_mtu
    response.path_mtu = 1280;

    let payload = &response.encode()[1..];

    node.handle_lookup_response(&from, payload).await;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    assert!(node.coord_cache().contains(&target, now_ms));

    let entry = node.coord_cache().get_entry(&target).unwrap();
    assert_eq!(
        entry.path_mtu(),
        Some(1280),
        "Originator should store path_mtu from LookupResponse in cache"
    );
}

#[tokio::test]
async fn test_originator_ignores_sub_floor_path_mtu_but_still_caches_coords() {
    // The path_mtu annotation accumulates hop by hop outside the signed proof,
    // so any forwarder on the reverse path can lower it. A value below the
    // actionable floor must be treated as absent rather than stored — but the
    // coordinates it travelled with are proof-covered and must still land,
    // otherwise a value-poisoning vector becomes a discovery-denial one.
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let target_fips = crate::FipsAddress::from_node_addr(&target);
    let root = make_node_addr(0xF0);
    let coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();

    node.register_identity(target, target_identity.pubkey_full());

    seed_pending_lookup(&mut node, target, 801);

    let proof_data = LookupResponse::proof_bytes(801, &target, &coords);
    let proof = target_identity.sign(&proof_data);

    let mut response = LookupResponse::new(801, target, coords.clone(), proof);
    response.path_mtu = 64;

    let payload = &response.encode()[1..];
    let (logs, guard) = crate::testutil::capture_logs_scoped();
    node.handle_lookup_response(&from, payload).await;
    drop(guard);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    assert!(
        node.coord_cache().contains(&target, now_ms),
        "coordinates must still be cached; the proof covers them"
    );
    assert_eq!(
        node.coord_cache().get_entry(&target).unwrap().path_mtu(),
        None,
        "a sub-floor annotation must not reach the coordinate cache"
    );
    assert_eq!(
        node.path_mtu_lookup_get(&target_fips),
        None,
        "a sub-floor annotation must not reach the MSS clamp lookup"
    );
    assert_eq!(
        node.metrics().errors.lookup_resp_mtu_below_floor.get(),
        1,
        "refusing the annotation must be visible on a counter, not only in a log"
    );

    // The counter says a refusal happened; only the correlator says which
    // exchange it happened in. The warning is the sole place that pairing
    // exists, so the field an operator greps on is asserted here rather than
    // left to survive on the strength of compiling.
    let floor_warning = logs
        .warnings()
        .into_iter()
        .find(|line| line.contains("below the actionable floor"))
        .expect("the sub-floor refusal must be logged at WARN");
    assert!(
        floor_warning.contains("request_id=801"),
        "the sub-floor warning must carry the correlator of the response it \
         refused, got: {floor_warning}"
    );
}

#[tokio::test]
async fn test_actionable_lookup_response_path_mtu_does_not_bump_below_floor_counter() {
    // Discriminating half of the sub-floor counter check: the refusal counter
    // is only useful if an ordinary verified response leaves it alone.
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let target_fips = crate::FipsAddress::from_node_addr(&target);
    let root = make_node_addr(0xF0);
    let coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();

    node.register_identity(target, target_identity.pubkey_full());

    seed_pending_lookup(&mut node, target, 802);

    let proof_data = LookupResponse::proof_bytes(802, &target, &coords);
    let proof = target_identity.sign(&proof_data);

    let mut response = LookupResponse::new(802, target, coords.clone(), proof);
    response.path_mtu = 1280;

    let payload = &response.encode()[1..];
    node.handle_lookup_response(&from, payload).await;

    assert_eq!(
        node.path_mtu_lookup_get(&target_fips),
        Some(1280),
        "an actionable annotation must reach the MSS clamp lookup"
    );
    assert_eq!(
        node.coord_cache().get_entry(&target).unwrap().path_mtu(),
        Some(1280),
        "an actionable annotation must reach the coordinate cache"
    );
    assert_eq!(
        node.metrics().errors.lookup_resp_mtu_below_floor.get(),
        0,
        "an actionable annotation must not bump the below-floor counter"
    );
}

#[tokio::test]
async fn test_originator_lookup_response_keeps_tighter_path_mtu_lookup() {
    // Regression: a LookupResponse carrying a looser (larger) path_mtu must
    // NOT clobber a tighter (smaller) value already in path_mtu_lookup that a
    // reactive MtuExceeded or PathMtuNotification learned. Cross-carrier
    // keep-tighter: the clamp must never loosen.
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let root = make_node_addr(0xF0);
    let coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();

    node.register_identity(target, target_identity.pubkey_full());

    // Pre-seed a tighter value, as if a reactive signal already narrowed it.
    let target_fips = crate::FipsAddress::from_node_addr(&target);
    node.path_mtu_lookup_insert(target_fips, 1280);

    seed_pending_lookup(&mut node, target, 800);

    let proof_data = LookupResponse::proof_bytes(800, &target, &coords);
    let proof = target_identity.sign(&proof_data);

    let mut response = LookupResponse::new(800, target, coords.clone(), proof);
    // Looser discovery estimate that must be rejected in favor of the tighter
    // existing entry.
    response.path_mtu = 1500;

    let payload = &response.encode()[1..];

    node.handle_lookup_response(&from, payload).await;

    assert_eq!(
        node.path_mtu_lookup_get(&target_fips),
        Some(1280),
        "LookupResponse must not loosen a tighter existing path_mtu_lookup value"
    );
}

/// Build a verified LookupResponse for a fresh target and hand it to the
/// handler, returning the target and its FipsAddress. The identity is
/// registered so the proof verifies and the originator branch is taken.
fn make_verified_lookup_response(
    node: &mut Node,
    request_id: u64,
    path_mtu: u16,
) -> (crate::NodeAddr, crate::FipsAddress, Vec<u8>) {
    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let target_fips = crate::FipsAddress::from_node_addr(&target);
    let root = make_node_addr(0xF0);
    let coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();

    node.register_identity(target, target_identity.pubkey_full());
    seed_pending_lookup(node, target, request_id);

    let proof_data = LookupResponse::proof_bytes(request_id, &target, &coords);
    let proof = target_identity.sign(&proof_data);
    let mut response = LookupResponse::new(request_id, target, coords, proof);
    response.path_mtu = path_mtu;

    (target, target_fips, response.encode()[1..].to_vec())
}

#[tokio::test]
async fn test_lookup_response_path_mtu_expires_without_a_session() {
    // The discovery carrier writes an entry for a destination this node may
    // never open a session with, and all three release callers fire on
    // session state. Without a deadline, one response carrying 256 pins that
    // destination's SYN-time MSS clamp at 119 bytes until the process
    // restarts.
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let (_target, target_fips, body) = make_verified_lookup_response(&mut node, 803, 256);
    node.handle_lookup_response(&from, &body).await;

    let entry = node
        .path_mtu_lookup_entry(&target_fips)
        .expect("precondition: the response wrote an entry, or the rest observes nothing");
    assert_eq!(entry.mtu, 256, "precondition: the annotation was stored");
    let learned_ms = entry
        .learned_ms
        .expect("the discovery carrier has no release path, so its entry must carry a learn time");
    assert_eq!(
        node.session_count(),
        0,
        "precondition: no session exists, so nothing but the deadline would ever release this"
    );

    let ttl_ms = node.config().node.cache.coord_ttl_secs * 1000;
    assert!(ttl_ms > 0, "precondition: the expiry pass is not disabled");

    // The healthy half: an entry inside its lifetime must survive an
    // ordinary tick, or the clamp loses a value it is entitled to.
    node.purge_expired_path_mtu(learned_ms + ttl_ms - 1);
    assert_eq!(
        node.path_mtu_lookup_get(&target_fips),
        Some(256),
        "an entry inside its lifetime must survive the expiry pass"
    );

    node.purge_expired_path_mtu(learned_ms + ttl_ms + 1);
    assert_eq!(
        node.path_mtu_lookup_get(&target_fips),
        None,
        "past its deadline the entry must go, since nothing else will ever release it"
    );
}

#[tokio::test]
async fn test_replayed_lookup_response_does_not_extend_the_path_mtu_deadline() {
    // The response carries no replay dedupe, so a captured one can be
    // re-injected indefinitely. What bounds the damage is that a replay of a
    // value already stored takes the keep-tighter arm, which does not touch
    // the learn time: each injection buys one TTL, not one per packet.
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let (_target, target_fips, body) = make_verified_lookup_response(&mut node, 804, 256);
    node.handle_lookup_response(&from, &body).await;

    let first = node
        .path_mtu_lookup_entry(&target_fips)
        .expect("precondition: the first response wrote an entry");
    let learned_ms = first
        .learned_ms
        .expect("precondition: the entry carries a learn time");

    // Real elapsed wall-clock between replays. The handler stamps its own
    // `Self::now_ms()`, so a version that refreshed the deadline would be
    // indistinguishable from one that did not if all three landed in the
    // same millisecond.
    for _ in 0..2 {
        std::thread::sleep(std::time::Duration::from_millis(5));
        node.handle_lookup_response(&from, &body).await;
    }

    assert_eq!(
        node.path_mtu_lookup_entry(&target_fips),
        Some(first),
        "a replay must leave the entry exactly as it was, deadline included"
    );

    let ttl_ms = node.config().node.cache.coord_ttl_secs * 1000;
    node.purge_expired_path_mtu(learned_ms + ttl_ms + 1);
    assert_eq!(
        node.path_mtu_lookup_get(&target_fips),
        None,
        "replaying the same value must not push the deadline out"
    );
}

// ============================================================================
// Integration Tests — min_mtu transit pruning
// ============================================================================

#[tokio::test]
async fn test_transit_prunes_lookup_by_min_mtu() {
    // Topology: node0(1280) — node1(800) — node2(1280)
    // Node0 initiates lookup for node2 with min_mtu=1280 (default TUN MTU).
    // Node1's transport MTU is 800 < 1280, so node1 should NOT forward
    // the request to node2. The lookup should fail (no cache entry).
    let mtus = [1280, 800, 1280];
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test_with_mtus(&mtus, &edges).await;

    let node2_addr = *nodes[2].node.node_addr();
    let node2_pubkey = nodes[2].node.identity().pubkey_full();
    nodes[0].node.register_identity(node2_addr, node2_pubkey);

    nodes[0].node.initiate_lookup(&node2_addr, 8).await;

    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        process_available_packets(&mut nodes).await;
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    assert!(
        !nodes[0].node.coord_cache().contains(&node2_addr, now_ms),
        "Node0 should NOT have cached node2 route (transit pruned by min_mtu)"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_transit_forwards_when_mtu_sufficient() {
    // Topology: node0(1280) — node1(1400) — node2(1280)
    // Node0 initiates lookup for node2 with min_mtu=1280 (default TUN MTU).
    // Node1's transport MTU is 1400 >= 1280, so the request passes through.
    // Bottleneck min-fold accumulates contributions from BOTH the target's
    // own outgoing-link MTU (the target-edge fold added with the
    // direct-link/target-edge gap fix) and each transit node's outgoing-
    // link MTU. With node2 (target) at 1280 and node1 (transit) at 1400,
    // the bottleneck is min(1280, 1400) = 1280.
    let mtus = [1280, 1400, 1280];
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test_with_mtus(&mtus, &edges).await;

    let node2_addr = *nodes[2].node.node_addr();
    let node2_pubkey = nodes[2].node.identity().pubkey_full();
    nodes[0].node.register_identity(node2_addr, node2_pubkey);

    nodes[0].node.initiate_lookup(&node2_addr, 8).await;

    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        process_available_packets(&mut nodes).await;
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    assert!(
        nodes[0].node.coord_cache().contains(&node2_addr, now_ms),
        "Node0 should have cached node2 route (MTU sufficient)"
    );

    let entry = nodes[0].node.coord_cache().get_entry(&node2_addr).unwrap();
    let path_mtu = entry.path_mtu().expect("path_mtu should be set");
    assert_eq!(
        path_mtu, 1280,
        "path_mtu should be min(target-edge 1280, transit 1400) = 1280"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_response_path_mtu_four_node_chain() {
    // Topology: node0(1280) — node1(1500) — node2(1350) — node3(1280)
    // Node0 initiates lookup for node3. Response travels node3→node2→node1→node0.
    // The bottleneck min-fold now accumulates contributions from the target's
    // own outgoing link MTU (target-edge fold added with the direct-link gap
    // fix) AND each transit node's outgoing link MTU on the reverse path.
    // node3 (target, 1280) → 1280; node2 (transit, 1350) → min(1280, 1350) =
    // 1280; node1 (transit, 1500) → min(1280, 1500) = 1280. Result: 1280.
    //
    // Note: min_mtu=1280 from TUN config. All transit MTUs ≥ 1280 so the
    // forward request is not pruned; the test exercises the response-side
    // min-fold accumulation explicitly.
    let mtus = [1280, 1500, 1350, 1280];
    let edges = vec![(0, 1), (1, 2), (2, 3)];
    let mut nodes = run_tree_test_with_mtus(&mtus, &edges).await;

    let node3_addr = *nodes[3].node.node_addr();
    let node3_pubkey = nodes[3].node.identity().pubkey_full();
    nodes[0].node.register_identity(node3_addr, node3_pubkey);

    nodes[0].node.initiate_lookup(&node3_addr, 8).await;

    for _ in 0..15 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        process_available_packets(&mut nodes).await;
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    assert!(
        nodes[0].node.coord_cache().contains(&node3_addr, now_ms),
        "Node0 should have cached node3 route"
    );

    let entry = nodes[0].node.coord_cache().get_entry(&node3_addr).unwrap();
    let path_mtu = entry.path_mtu().expect("path_mtu should be set");
    assert_eq!(
        path_mtu, 1280,
        "Four-node chain path_mtu = min(target-edge 1280, transits 1350+1500) = 1280"
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Open-Discovery Sweep — cache-injection unit test
// ============================================================================

/// Pin the iterate-filter-queue contract of `run_open_discovery_sweep`.
///
/// Builds a `Node` with `nostr.policy = Open` and an empty peer list,
/// then injects three cached adverts into a test `NostrRendezvous` and
/// asserts the sweep:
///   - queues a retry for an eligible (unknown, not-self) advert,
///   - skips the advert whose author is our own node identity, and
///   - skips the advert whose author is an already-connected peer.
///
/// Uses `NostrRendezvous::new_for_test()` and `insert_advert_for_test()`
/// (both `#[cfg(test)]`-gated test escape hatches in
/// `src/discovery/nostr/runtime.rs`) to populate the cache without
/// requiring live relay subscriptions.
#[tokio::test]
async fn test_open_discovery_sweep_queues_eligible_skips_filtered() {
    use crate::config::NostrRendezvousPolicy;
    use crate::nostr::{NostrRendezvous, OverlayEndpointAdvert, OverlayTransportKind};
    use crate::peer::ActivePeer;
    use crate::transport::LinkId;
    use std::sync::Arc;

    // Build node with open-discovery enabled.
    let mut config = crate::Config::new();
    config.node.rendezvous.nostr.enabled = true;
    config.node.rendezvous.nostr.policy = NostrRendezvousPolicy::Open;
    let mut node = crate::Node::new(config).unwrap();

    // Identity of an already-connected peer; insert into node.peers
    // so the sweep's `self.peers.contains_key(&node_addr)` filter fires.
    let connected_identity = crate::Identity::generate();
    let connected_npub = crate::encode_npub(&connected_identity.pubkey());
    let connected_node_addr = *connected_identity.node_addr();
    let connected_peer_identity = crate::PeerIdentity::from_pubkey(connected_identity.pubkey());
    node.peers.insert(
        connected_node_addr,
        ActivePeer::new(connected_peer_identity, LinkId::new(1), 1_000),
    );

    // Eligible peer: fresh identity not in node.peers / retry_pending.
    let eligible_identity = crate::Identity::generate();
    let eligible_npub = crate::encode_npub(&eligible_identity.pubkey());
    let eligible_node_addr = *eligible_identity.node_addr();

    // Self filter: advert authored by node's own identity.
    let self_npub = crate::encode_npub(&node.identity().pubkey());
    let self_node_addr = *node.identity().node_addr();

    // Build a NostrRendezvous test instance and inject the three adverts.
    let bootstrap = Arc::new(NostrRendezvous::new_for_test());
    let endpoint = OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: "203.0.113.7:2121".to_string(),
    };
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for npub in [&eligible_npub, &connected_npub, &self_npub] {
        let advert =
            NostrRendezvous::cached_advert_for_test(npub.clone(), endpoint.clone(), now_secs);
        bootstrap.insert_advert_for_test(npub.clone(), advert).await;
    }

    // The sweep now runs through the gate-checked reconciler overlay layer,
    // which is inert unless the node is Running/Degraded. In production the
    // sweep fires only from the rx_loop tick (which spins after `start()`
    // returns Running), so drive the node into `Running` to reflect that.
    node.supervisor.state = crate::node::NodeState::Running;

    // Run the sweep.
    node.run_open_discovery_sweep(&bootstrap, Some(3_600)).await;

    // Eligible peer was queued.
    assert!(
        node.peering
            .reconciler
            .retry_pending
            .contains_key(&eligible_node_addr),
        "eligible advert should be queued for retry"
    );
    let queued = node
        .peering
        .reconciler
        .retry_pending
        .get(&eligible_node_addr)
        .unwrap();
    assert_eq!(queued.peer_config.npub, eligible_npub);

    // Connected-peer skip filter held.
    assert!(
        !node
            .peering
            .reconciler
            .retry_pending
            .contains_key(&connected_node_addr),
        "advert for already-connected peer must not be queued"
    );

    // Self skip filter held.
    assert!(
        !node
            .peering
            .reconciler
            .retry_pending
            .contains_key(&self_node_addr),
        "advert authored by own node must not be queued"
    );

    // Exactly one queued entry from the three injected adverts.
    assert_eq!(node.peering.reconciler.retry_pending.len(), 1);
}

// ============================================================================
// Per-Attempt Timeout State Machine — IF-3-A
// ============================================================================

/// Pin the per-attempt timeout sequence in `check_pending_lookups`.
///
/// Drives the state machine deterministically through the default
/// `node.lookup.attempt_timeouts_secs = [1, 2, 4, 8]` sequence.
/// Asserts:
///   1. **Sequence timing** — retries fire at the cumulative deadlines
///      (t=1100ms, 3100ms, 7100ms) and unreachable at t=15100ms.
///   2. **Fresh `initiate_lookup` per attempt** — `req_initiated` counter
///      increments by exactly one on each retry. The actual `request_id`
///      is drawn via `rand::rng().random()` at the shell inside
///      `initiate_lookup` and passed to `LookupRequest::new(...)`; it is
///      not stored on the originator side, so per-attempt freshness is
///      verified indirectly: each `req_initiated` increment corresponds
///      to one fresh `initiate_lookup` call.
///   3. **Final-timeout state transitions** — `pending_lookups` entry is
///      removed, `lookup.resp_timed_out` counter ticks, queued packet
///      is drained, and an ICMPv6 Destination Unreachable frame is
///      emitted via the TUN sender.
///
/// Skipped: direct request_id capture (originator does not record its
/// own request_ids; would require production instrumentation). The
/// `req_initiated` counter is the strongest cleanly-observable signal
/// that `initiate_lookup` ran fresh on each attempt.
#[tokio::test]
async fn test_check_pending_lookups_default_sequence_unreachable() {
    use crate::peer::ActivePeer;
    use crate::proto::bloom::BloomFilter;
    use crate::proto::lookup::PendingLookup;
    use crate::transport::LinkId;
    use std::sync::mpsc;

    let mut node = make_node();

    // Default attempt_timeouts_secs is [1, 2, 4, 8]. Confirm so the test
    // cannot silently drift if the default changes.
    assert_eq!(
        node.config().node.lookup.attempt_timeouts_secs,
        vec![1, 2, 4, 8],
        "test pins the [1,2,4,8] default; update the test if the default changes"
    );

    // Inject a TUN sender so `send_icmpv6_dest_unreachable` is observable.
    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>();
    node.supervisor.tun_tx = Some(tun_tx);

    // Build a target identity (the unreachable destination).
    let target_identity = Identity::generate();
    let target_addr = *target_identity.node_addr();

    // Build a tree-peer that:
    //   - has the target in its inbound bloom filter (so `may_reach` is true),
    //   - declares us as its parent (so `is_tree_peer` returns true).
    // The peer has no Noise session, so `send_encrypted_link_message` will
    // fail at the wire-send step — but `initiate_lookup` already incremented
    // `req_initiated` and the failure is logged at `debug!`. The state-
    // machine bookkeeping we want to test runs to completion either way.
    let peer_identity_full = Identity::generate();
    let peer_addr = *peer_identity_full.node_addr();
    let peer_identity = crate::PeerIdentity::from_pubkey(peer_identity_full.pubkey());
    let mut peer = ActivePeer::new(peer_identity, LinkId::new(1), 0);
    let mut bloom = BloomFilter::new();
    bloom.insert(&target_addr);
    peer.update_filter(bloom, 1, 0);
    node.peers.insert(peer_addr, peer);

    // Make the peer a tree-peer: install a peer declaration that names us
    // as its parent. `is_tree_peer` checks both directions — the child
    // direction (peer.parent_id == self.node_addr) is what we exercise.
    let our_addr = *node.node_addr();
    let peer_decl = crate::proto::stp::ParentDeclaration::new(peer_addr, our_addr, 1, 0);
    let peer_coords = TreeCoordinate::from_addrs(vec![peer_addr, our_addr]).unwrap();
    node.tree_state_mut().update_peer(peer_decl, peer_coords);
    assert!(node.is_tree_peer(&peer_addr), "peer must be a tree peer");

    // Queue an IPv6 packet for the target so the final-timeout drop +
    // ICMPv6 emission can be observed. Build a minimal valid IPv6 header
    // with a non-multicast, non-unspecified source so
    // `should_send_icmp_error` returns true.
    let mut ipv6_pkt = vec![0u8; 40];
    ipv6_pkt[0] = 0x60; // version 6
    ipv6_pkt[6] = 17; // next_header = UDP (not ICMPv6)
    ipv6_pkt[7] = 64; // hop limit
    // src = fd00::1 (non-multicast, non-unspecified)
    ipv6_pkt[8] = 0xfd;
    ipv6_pkt[23] = 0x01;
    // dst = target's IPv6 representation (not strictly required, just non-multicast)
    let target_ipv6 = crate::FipsAddress::from_node_addr(&target_addr).to_ipv6();
    ipv6_pkt[24..40].copy_from_slice(&target_ipv6.octets());
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(ipv6_pkt);
    node.pending_tun_packets.insert(target_addr, queue);

    // Inject a PendingLookup directly: attempt=1, last_sent_ms=0. This
    // mirrors the post-condition of a successful `maybe_initiate_lookup`
    // at t=0 without depending on wall-clock-derived `Self::now_ms()`.
    node.lookup
        .pending_lookups
        .insert(target_addr, PendingLookup::new(0));

    let baseline_initiated = node.metrics().lookup.req_initiated.get();
    let baseline_timed_out = node.metrics().lookup.resp_timed_out.get();

    // --- t = 1100ms: first retry deadline (1*1000) ---
    node.check_pending_lookups(1100).await;
    {
        let entry = node
            .lookup
            .pending_lookups
            .get(&target_addr)
            .expect("still pending");
        assert_eq!(entry.attempt, 2, "after retry #1, attempt should be 2");
        assert_eq!(entry.last_sent_ms, 1100);
    }
    assert_eq!(
        node.metrics().lookup.req_initiated.get(),
        baseline_initiated + 1,
        "retry #1 must invoke initiate_lookup exactly once"
    );

    // --- t = 3100ms: second retry deadline (cumulative 1+2 = 3s) ---
    node.check_pending_lookups(3100).await;
    {
        let entry = node
            .lookup
            .pending_lookups
            .get(&target_addr)
            .expect("still pending");
        assert_eq!(entry.attempt, 3, "after retry #2, attempt should be 3");
        assert_eq!(entry.last_sent_ms, 3100);
    }
    assert_eq!(
        node.metrics().lookup.req_initiated.get(),
        baseline_initiated + 2,
        "retry #2 must invoke initiate_lookup exactly once more"
    );

    // --- t = 7100ms: third retry deadline (cumulative 1+2+4 = 7s) ---
    node.check_pending_lookups(7100).await;
    {
        let entry = node
            .lookup
            .pending_lookups
            .get(&target_addr)
            .expect("still pending");
        assert_eq!(entry.attempt, 4, "after retry #3, attempt should be 4");
        assert_eq!(entry.last_sent_ms, 7100);
    }
    assert_eq!(
        node.metrics().lookup.req_initiated.get(),
        baseline_initiated + 3,
        "retry #3 must invoke initiate_lookup exactly once more"
    );

    // --- Just-before-final: at t=15099ms the 8s window is not yet reached ---
    node.check_pending_lookups(15_099).await;
    assert!(
        node.lookup.pending_lookups.contains_key(&target_addr),
        "8s window not yet expired: pending_lookup must persist"
    );
    assert_eq!(
        node.metrics().lookup.req_initiated.get(),
        baseline_initiated + 3,
        "no new attempt before final deadline"
    );
    assert_eq!(
        node.metrics().lookup.resp_timed_out.get(),
        baseline_timed_out,
        "no timeout before final deadline"
    );

    // --- t = 15100ms: final deadline (cumulative 1+2+4+8 = 15s) ---
    // Drain any TUN frames that may have leaked from earlier steps so the
    // post-final-timeout drain observes only the unreachable-emission output.
    while tun_rx.try_recv().is_ok() {}

    node.check_pending_lookups(15_100).await;

    // Pending lookup is dropped.
    assert!(
        !node.lookup.pending_lookups.contains_key(&target_addr),
        "final timeout must remove the pending_lookups entry"
    );
    // resp_timed_out counter ticked.
    assert_eq!(
        node.metrics().lookup.resp_timed_out.get(),
        baseline_timed_out + 1,
        "final timeout must increment lookup.resp_timed_out"
    );
    // No additional initiate_lookup on the timeout step.
    assert_eq!(
        node.metrics().lookup.req_initiated.get(),
        baseline_initiated + 3,
        "the final-timeout step must NOT call initiate_lookup"
    );
    // Queued packet was drained from pending_tun_packets.
    assert!(
        !node.pending_tun_packets.contains_key(&target_addr),
        "queued packets for the unreachable target must be drained"
    );

    // ICMPv6 Destination Unreachable was emitted to the TUN sender.
    let icmp_frame = tun_rx
        .try_recv()
        .expect("ICMPv6 Destination Unreachable must be emitted on final timeout");
    assert!(
        icmp_frame.len() >= 48,
        "ICMPv6 frame must be at least IPv6 header (40) + ICMPv6 header (8)"
    );
    assert_eq!(icmp_frame[0] >> 4, 6, "must be IPv6");
    assert_eq!(icmp_frame[6], 58, "next_header must be IPPROTO_ICMPV6 (58)");
    assert_eq!(icmp_frame[40], 1, "ICMPv6 type 1 = Destination Unreachable");
}
