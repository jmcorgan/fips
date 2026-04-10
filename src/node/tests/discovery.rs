//! Discovery protocol tests: LookupRequest and LookupResponse.
//!
//! Unit tests for handler logic (dedup, TTL, response caching) and
//! integration tests for multi-node forwarding and reverse-path
//! response routing.

use super::*;
use crate::node::RecentRequest;
use crate::protocol::{LookupRequest, LookupResponse};
use crate::tree::TreeCoordinate;
use spanning_tree::{
    cleanup_nodes, generate_random_edges, process_available_packets, run_tree_test,
    verify_tree_convergence,
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
    assert!(node.recent_requests.is_empty());
}

#[tokio::test]
async fn test_request_dedup() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let target = make_node_addr(0xBB);
    let origin = make_node_addr(0xCC);
    let coords = TreeCoordinate::from_addrs(vec![origin, make_node_addr(0)]).unwrap();

    let request = LookupRequest::new(999, target, origin, coords, 5, 0);
    let payload = &request.encode()[1..]; // skip msg_type byte

    // First request: accepted
    node.handle_lookup_request(&from, payload).await;
    assert_eq!(node.recent_requests.len(), 1);

    // Duplicate request: dropped
    node.handle_lookup_request(&from, payload).await;
    assert_eq!(node.recent_requests.len(), 1);
}

#[tokio::test]
async fn test_request_target_is_self() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let origin = make_node_addr(0xCC);
    let my_addr = *node.node_addr();
    let coords = TreeCoordinate::from_addrs(vec![origin, make_node_addr(0)]).unwrap();

    // Request targeting us
    let request = LookupRequest::new(777, my_addr, origin, coords, 5, 0);
    let payload = &request.encode()[1..];

    // Should succeed without panic (response send will fail silently
    // since we have no peers to route toward origin)
    node.handle_lookup_request(&from, payload).await;
    assert!(node.recent_requests.contains_key(&777));
}

#[tokio::test]
async fn test_request_ttl_zero_not_forwarded() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let target = make_node_addr(0xBB);
    let origin = make_node_addr(0xCC);
    let coords = TreeCoordinate::from_addrs(vec![origin, make_node_addr(0)]).unwrap();

    let request = LookupRequest::new(666, target, origin, coords, 0, 0);
    let payload = &request.encode()[1..];

    node.handle_lookup_request(&from, payload).await;
    // Request recorded, but not forwarded (TTL=0, and no peers anyway)
    assert!(node.recent_requests.contains_key(&666));
}

// ============================================================================
// Unit Tests — LookupResponse Handler
// ============================================================================

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

    // Create a valid response with a real proof signature (includes coords)
    let proof_data = LookupResponse::proof_bytes(555, &target, &coords);
    let proof = target_identity.sign(&proof_data);

    let response = LookupResponse::new(555, target, coords.clone(), proof);
    let payload = &response.encode()[1..]; // skip msg_type

    // No entry in recent_requests for 555 → we're the originator
    assert!(!node.recent_requests.contains_key(&555));

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
    node.recent_requests
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
    // target's pubkey in identity_cache (e.g., XK responder before msg3).
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let root = make_node_addr(0xF0);
    let coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();

    // Do NOT register target in identity_cache

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
    node.recent_requests
        .insert(123, RecentRequest::new(make_node_addr(1), now_ms - 11_000));

    // Insert a recent request
    node.recent_requests
        .insert(456, RecentRequest::new(make_node_addr(2), now_ms));

    assert_eq!(node.recent_requests.len(), 2);

    // Trigger purge via a new lookup request
    let target = make_node_addr(0xBB);
    let origin = make_node_addr(0xCC);
    let coords = TreeCoordinate::from_addrs(vec![origin, make_node_addr(0)]).unwrap();
    let request = LookupRequest::new(789, target, origin, coords, 3, 0);
    let payload = &request.encode()[1..];
    node.handle_lookup_request(&make_node_addr(0xAA), payload)
        .await;

    // Old entry (123) should be purged, recent entry (456) and new entry (789) kept
    assert!(!node.recent_requests.contains_key(&123));
    assert!(node.recent_requests.contains_key(&456));
    assert!(node.recent_requests.contains_key(&789));
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
    let root = make_node_addr(0);

    let coords = TreeCoordinate::from_addrs(vec![node0_addr, root]).unwrap();
    let request = LookupRequest::new(42, target, node0_addr, coords, 5, 0);
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
        nodes[1].node.recent_requests.contains_key(&42),
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
        !nodes[1].node.recent_requests.is_empty(),
        "Node 1 should have recorded the forwarded request"
    );

    // Node2 should have received the request (it's the target)
    assert!(
        !nodes[2].node.recent_requests.is_empty(),
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
    let root = make_node_addr(0);

    let coords = TreeCoordinate::from_addrs(vec![node0_addr, root]).unwrap();
    let request = LookupRequest::new(300, target, node0_addr, coords, 5, 0);
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
        nodes[2].node.recent_requests.contains_key(&300),
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
    // Node0 initiates lookup for node1. The response should carry path_mtu
    // reflecting the transport MTU (1280 in tests) clamped by transit.
    // In a two-node setup: node1 (target) initializes path_mtu=u16::MAX,
    // then the response is sent directly to node0. Since node1 is the
    // target and sends directly, the transit logic does not apply for the
    // first hop (the target sends directly). But node0 is the originator
    // and doesn't apply transit MTU. So path_mtu should be u16::MAX in
    // this simple case (no transit nodes to clamp it).
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

    // Check that path_mtu was stored in the cache entry
    let entry = nodes[0].node.coord_cache().get_entry(&node1_addr).unwrap();
    let path_mtu = entry
        .path_mtu()
        .expect("path_mtu should be set from discovery");
    // In a 2-node setup, no transit node applies the min() so path_mtu stays u16::MAX
    assert_eq!(
        path_mtu,
        u16::MAX,
        "Two-node path_mtu should be u16::MAX (no transit nodes to clamp)"
    );

    cleanup_nodes(&mut nodes).await;
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
    // Verify that insert_with_path_mtu stores the path_mtu in the cache entry
    let mut node = make_node();
    let target = make_node_addr(0xBB);

    let coords = TreeCoordinate::from_addrs(vec![target, make_node_addr(0)]).unwrap();

    let now_ms = 1000u64;
    node.coord_cache_mut()
        .insert_with_path_mtu(target, coords, now_ms, 1280);

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
    node.coord_cache_mut().insert(target, coords, now_ms);

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
    let coords = TreeCoordinate::from_addrs(vec![origin, make_node_addr(0)]).unwrap();

    let request = LookupRequest::new(100, target, origin, coords, 5, 1386);
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
