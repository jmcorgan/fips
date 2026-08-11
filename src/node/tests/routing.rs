//! Routing integration tests.
//!
//! Tests the full Node::find_next_hop() routing logic including bloom
//! filter priority, greedy tree routing, and tie-breaking.

use super::*;
use crate::proto::bloom::BloomFilter;
use crate::proto::stp::{ParentDeclaration, TreeCoordinate};
use spanning_tree::{
    TestNode, cleanup_nodes, drain_all_packets, generate_random_edges, initiate_handshake,
    lock_large_network_test, make_test_node, run_tree_test, verify_tree_convergence,
};
use std::collections::HashSet;

// === Local delivery ===

#[test]
fn test_routing_local_delivery() {
    let mut node = make_node();
    let my_addr = *node.node_addr();
    assert!(node.find_next_hop(&my_addr).is_none());
}

// === Direct peer ===

#[test]
fn test_routing_direct_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    let identity = seed_completed_connection(&mut node, link_id, transport_id, 1000);
    let peer_addr = *identity.node_addr();
    node.promote_connection(link_id, identity, 2000).unwrap();

    let result = node.find_next_hop(&peer_addr);
    assert!(result.is_some());
    assert_eq!(result.unwrap().node_addr(), &peer_addr);
}

// === No route ===

#[test]
fn test_routing_unknown_destination() {
    let mut node = make_node();
    let unknown = make_node_addr(99);
    assert!(node.find_next_hop(&unknown).is_none());
}

// === Bloom filter priority ===

/// Scope note: this covers the bloom *ordering* path, not the bloom predicate.
/// The chosen peer here is also the greedy tree winner, so the assertion holds
/// whichever branch produced it. See the `Seam: NodeRoutingView adapter`
/// section at the end of this file for the discriminating tests.
#[test]
fn test_routing_bloom_filter_hit() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let my_addr = *node.node_addr();

    // Create two peers
    let link_id1 = LinkId::new(1);
    let id1 = seed_completed_connection(&mut node, link_id1, transport_id, 1000);
    let peer1_addr = *id1.node_addr();
    node.promote_connection(link_id1, id1, 2000).unwrap();

    let link_id2 = LinkId::new(2);
    let id2 = seed_completed_connection(&mut node, link_id2, transport_id, 1000);
    let peer2_addr = *id2.node_addr();
    node.promote_connection(link_id2, id2, 2000).unwrap();

    // Set up tree: we are root, both peers are our children
    let peer1_coords = TreeCoordinate::from_addrs(vec![peer1_addr, my_addr]).unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(peer1_addr, my_addr, 1, 1000),
        peer1_coords,
    );
    let peer2_coords = TreeCoordinate::from_addrs(vec![peer2_addr, my_addr]).unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(peer2_addr, my_addr, 1, 1000),
        peer2_coords,
    );

    // Destination not directly connected — placed under peer1 in the tree
    let dest = make_node_addr(99);
    let dest_coords = TreeCoordinate::from_addrs(vec![dest, peer1_addr, my_addr]).unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    node.coord_cache_mut().insert(dest, dest_coords, now_ms);

    // Add dest to peer1's bloom filter only
    let peer1 = node.get_peer_mut(&peer1_addr).unwrap();
    let mut filter = BloomFilter::new();
    filter.insert(&dest);
    peer1.update_filter(filter, 1, 3000);

    // Should route through peer1 (bloom filter hit, closer to dest)
    let result = node.find_next_hop(&dest);
    assert!(result.is_some());
    assert_eq!(result.unwrap().node_addr(), &peer1_addr);

    // Peer2 should NOT be selected (no filter hit)
    assert_ne!(result.unwrap().node_addr(), &peer2_addr);
}

/// Scope note: as above, this pins the tie-break ordering rather than the bloom
/// predicate — the inline comment below already notes that the self-distance
/// check is what does the filtering here.
#[test]
fn test_routing_bloom_filter_multiple_hits_tiebreak() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let my_addr = *node.node_addr();

    // Create three peers
    let mut peer_addrs = Vec::new();
    for i in 1..=3 {
        let link_id = LinkId::new(i);
        let id = seed_completed_connection(&mut node, link_id, transport_id, 1000);
        let addr = *id.node_addr();
        peer_addrs.push(addr);
        node.promote_connection(link_id, id, 2000).unwrap();
    }

    // Set up tree: we are root, all peers are our children (equidistant)
    for &addr in &peer_addrs {
        let coords = TreeCoordinate::from_addrs(vec![addr, my_addr]).unwrap();
        node.tree_state_mut()
            .update_peer(ParentDeclaration::new(addr, my_addr, 1, 1000), coords);
    }

    // Destination placed under the first peer (arbitrary — all peers are
    // equidistant from dest since dest is 2 hops from root via any child)
    let dest = make_node_addr(99);
    let dest_coords = TreeCoordinate::from_addrs(vec![dest, peer_addrs[0], my_addr]).unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    node.coord_cache_mut().insert(dest, dest_coords, now_ms);

    // Add dest to ALL peers' bloom filters
    for &addr in &peer_addrs {
        let peer = node.get_peer_mut(&addr).unwrap();
        let mut filter = BloomFilter::new();
        filter.insert(&dest);
        peer.update_filter(filter, 1, 3000);
    }

    // All peers have equal link_cost (1.0). peer_addrs[0] is closest to dest
    // (distance 1 vs distance 3 for the others). Self-distance check filters
    // peers that aren't strictly closer than us (our distance = 2).
    // peer_addrs[0] has distance 1 (passes), others have distance 3 (filtered).
    let result = node.find_next_hop(&dest);
    assert!(result.is_some());
    assert_eq!(result.unwrap().node_addr(), &peer_addrs[0]);
}

// === Greedy tree routing ===

#[test]
fn test_routing_tree_fallback() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let my_addr = *node.node_addr();

    // Create a peer
    let link_id = LinkId::new(1);
    let id = seed_completed_connection(&mut node, link_id, transport_id, 1000);
    let peer_addr = *id.node_addr();
    node.promote_connection(link_id, id, 2000).unwrap();

    // Set up tree state through the public API.
    // We're root, peer is our child. The peer has a subtree below it.
    // TreeState::new() already makes us the root with coords [my_addr].
    // Add peer as child of us.
    let peer_coords = TreeCoordinate::from_addrs(vec![peer_addr, my_addr]).unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(peer_addr, my_addr, 1, 1000),
        peer_coords,
    );

    // Destination: a node under our peer in the tree
    let dest = make_node_addr(99);
    let dest_coords = TreeCoordinate::from_addrs(vec![dest, peer_addr, my_addr]).unwrap();

    // Put dest coords in the cache
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    node.coord_cache_mut().insert(dest, dest_coords, now_ms);

    // No bloom filter hit — should fall back to tree routing.
    // Our distance to dest: 2 (root → peer → dest)
    // Peer's distance to dest: 1 (peer → dest)
    // Peer is closer, so it's the next hop.
    let result = node.find_next_hop(&dest);
    assert!(result.is_some());
    assert_eq!(result.unwrap().node_addr(), &peer_addr);
}

/// Regression: bloom hit on a peer that is NOT strictly closer to dest
/// than we are must fall through to greedy tree routing rather than
/// returning None. Pinned by commit a859da7.
///
/// Pre-fix behavior: bloom candidates exist but `select_best_candidate`
/// rejects them all under the self-distance check (peer dist >= my dist),
/// and `find_next_hop` returned None — a NoRoute failure even though the
/// tree had a valid greedy next hop.
///
/// Post-fix behavior: same scenario falls through to greedy tree routing
/// and returns the tree-routing-selected next hop.
///
/// Scope note: despite the name, this does **not** discriminate the bloom
/// predicate. Under a `NodeRoutingView::peer_may_reach` that returns `true`
/// unconditionally the healthy and broken runs return the same peer by
/// different branches, and `find_next_hop` exposes no branch information, so
/// no assertion here can tell them apart. The test that does discriminate it
/// is `test_seam_bloom_hit_overrides_tree_tiebreak`.
#[test]
fn test_routing_bloom_hit_not_closer_falls_through_to_tree() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let my_addr = *node.node_addr();

    // tree_peer: child of self, on the path to dest (greedy tree pick).
    let tree_link = LinkId::new(1);
    let tree_id = seed_completed_connection(&mut node, tree_link, transport_id, 1000);
    let tree_peer_addr = *tree_id.node_addr();
    node.promote_connection(tree_link, tree_id, 2000).unwrap();

    // bloom_peer: also a child of self, but with a stale/false-positive
    // bloom hit for dest. Its tree distance to dest is NOT closer than
    // ours, so the self-distance check in select_best_candidate excludes
    // it — leaving zero viable bloom candidates.
    let bloom_link = LinkId::new(2);
    let bloom_id = seed_completed_connection(&mut node, bloom_link, transport_id, 1000);
    let bloom_peer_addr = *bloom_id.node_addr();
    node.promote_connection(bloom_link, bloom_id, 2000).unwrap();

    // Tree topology (we are root):
    //   self ── tree_peer ── dest
    //     └──── bloom_peer
    //
    // Distances to dest:
    //   self        : 2 (root → tree_peer → dest)
    //   tree_peer   : 1 (tree_peer → dest)            ← greedy winner
    //   bloom_peer  : 3 (bloom_peer → root → tree_peer → dest)  ← NOT closer than self
    let tree_peer_coords = TreeCoordinate::from_addrs(vec![tree_peer_addr, my_addr]).unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(tree_peer_addr, my_addr, 1, 1000),
        tree_peer_coords,
    );
    let bloom_peer_coords = TreeCoordinate::from_addrs(vec![bloom_peer_addr, my_addr]).unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(bloom_peer_addr, my_addr, 1, 1000),
        bloom_peer_coords,
    );

    // Destination is a child of tree_peer in the tree.
    let dest = make_node_addr(99);
    let dest_coords = TreeCoordinate::from_addrs(vec![dest, tree_peer_addr, my_addr]).unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    node.coord_cache_mut().insert(dest, dest_coords, now_ms);

    // dest is in bloom_peer's filter only (the "bloom hit" candidate),
    // but bloom_peer's tree distance (3) is NOT strictly less than our
    // distance (2), so select_best_candidate yields no winner.
    // tree_peer has NO bloom entry for dest.
    let bloom_peer = node.get_peer_mut(&bloom_peer_addr).unwrap();
    let mut filter = BloomFilter::new();
    filter.insert(&dest);
    bloom_peer.update_filter(filter, 1, 3000);

    // Pre-fix this returned None. Post-fix it falls through to greedy
    // tree routing and picks tree_peer (distance 1 < self distance 2).
    let result = node.find_next_hop(&dest);
    assert!(
        result.is_some(),
        "find_next_hop must fall through to tree routing when bloom \
         candidates exist but none are strictly closer than self"
    );
    let next_hop = result.unwrap().node_addr();
    assert_eq!(
        next_hop, &tree_peer_addr,
        "tree-routing winner expected (tree_peer), got {:?}",
        next_hop,
    );
    assert_ne!(
        next_hop, &bloom_peer_addr,
        "bloom_peer must be excluded by the self-distance check",
    );
}

#[test]
fn test_routing_tree_no_coords_in_cache() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // Create a peer
    let link_id = LinkId::new(1);
    let id = seed_completed_connection(&mut node, link_id, transport_id, 1000);
    node.promote_connection(link_id, id, 2000).unwrap();

    // Destination not in bloom filters and not in coord cache
    let dest = make_node_addr(99);
    assert!(node.find_next_hop(&dest).is_none());
}

// === Active routing refreshes coord_cache TTL ===

#[test]
fn test_routing_refreshes_coord_cache_ttl() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let my_addr = *node.node_addr();

    // Create a peer
    let link_id = LinkId::new(1);
    let id = seed_completed_connection(&mut node, link_id, transport_id, 1000);
    let peer_addr = *id.node_addr();
    node.promote_connection(link_id, id, 2000).unwrap();

    // Set up tree coordinates
    let dest = make_node_addr(99);
    let dest_coords = TreeCoordinate::from_addrs(vec![dest, peer_addr, my_addr]).unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(peer_addr, my_addr, 1, 1000),
        TreeCoordinate::from_addrs(vec![peer_addr, my_addr]).unwrap(),
    );

    // Insert with a short TTL (10s) — enough to survive until find_next_hop runs
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let short_ttl = 10_000; // 10 seconds
    node.coord_cache_mut()
        .insert_with_ttl(dest, dest_coords, now_ms, short_ttl);
    let original_expiry = node.coord_cache().get_entry(&dest).unwrap().expires_at();

    // find_next_hop should succeed and refresh TTL to now + default_ttl (300s)
    assert!(node.find_next_hop(&dest).is_some());

    // The refresh should have extended expires_at beyond the original
    let new_expiry = node.coord_cache().get_entry(&dest).unwrap().expires_at();
    assert!(
        new_expiry > original_expiry,
        "find_next_hop should refresh the coord_cache TTL: original={}, new={}",
        original_expiry,
        new_expiry,
    );
}

// === Bloom filter without coords → no route (loop prevention) ===

#[test]
fn test_routing_bloom_hit_without_coords_returns_none() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // Create two peers
    let link_id1 = LinkId::new(1);
    let id1 = seed_completed_connection(&mut node, link_id1, transport_id, 1000);
    let peer1_addr = *id1.node_addr();
    node.promote_connection(link_id1, id1, 2000).unwrap();

    let link_id2 = LinkId::new(2);
    let id2 = seed_completed_connection(&mut node, link_id2, transport_id, 1000);
    let peer2_addr = *id2.node_addr();
    node.promote_connection(link_id2, id2, 2000).unwrap();

    let dest = make_node_addr(99);

    // Add dest to BOTH peers' bloom filters
    for &addr in &[peer1_addr, peer2_addr] {
        let peer = node.get_peer_mut(&addr).unwrap();
        let mut filter = BloomFilter::new();
        filter.insert(&dest);
        peer.update_filter(filter, 1, 3000);
    }

    // Bloom filter candidates exist, but dest coords are NOT cached.
    // find_next_hop must return None to prevent routing loops.
    // The caller should signal CoordsRequired back to the source.
    assert!(node.find_next_hop(&dest).is_none());
}

// === Discovery-populated coord_cache ===

#[test]
fn test_routing_discovery_coord_cache() {
    // Verify that find_next_hop() uses coord_cache entries populated by
    // discovery. initiate_lookup() populates coord_cache, and
    // find_next_hop() consults it.
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let my_addr = *node.node_addr();

    // Create a peer
    let link_id = LinkId::new(1);
    let id = seed_completed_connection(&mut node, link_id, transport_id, 1000);
    let peer_addr = *id.node_addr();
    node.promote_connection(link_id, id, 2000).unwrap();

    // Set up tree: we are root, peer is our child
    let peer_coords = TreeCoordinate::from_addrs(vec![peer_addr, my_addr]).unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(peer_addr, my_addr, 1, 1000),
        peer_coords,
    );

    // Create a destination "behind" the peer in the tree
    let dest = make_node_addr(99);
    let dest_coords = TreeCoordinate::from_addrs(vec![dest, peer_addr, my_addr]).unwrap();

    // Put dest in peer's bloom filter so there's a candidate
    let peer = node.get_peer_mut(&peer_addr).unwrap();
    let mut filter = BloomFilter::new();
    filter.insert(&dest);
    peer.update_filter(filter, 1, 3000);

    // Verify: coord_cache has nothing for dest
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    assert!(node.coord_cache().get(&dest, now_ms).is_none());

    // Without coord_cache entry, should return None
    assert!(node.find_next_hop(&dest).is_none());

    // Now populate coord_cache (as discovery would do)
    node.coord_cache_mut().insert(dest, dest_coords, now_ms);

    // find_next_hop should succeed via coord_cache
    let result = node.find_next_hop(&dest);
    assert!(result.is_some(), "Should route via coord_cache");
    assert_eq!(
        result.unwrap().node_addr(),
        &peer_addr,
        "Should pick peer with bloom filter hit"
    );
}

// === Integration: converged network ===

#[tokio::test]
async fn test_routing_chain_topology() {
    // Build a 4-node chain: 0 -- 1 -- 2 -- 3
    let mut nodes = vec![
        make_test_node().await,
        make_test_node().await,
        make_test_node().await,
        make_test_node().await,
    ];

    // Connect the chain
    initiate_handshake(&mut nodes, 0, 1).await;
    initiate_handshake(&mut nodes, 1, 2).await;
    initiate_handshake(&mut nodes, 2, 3).await;

    // Converge tree and bloom filters
    drain_all_packets(&mut nodes, false).await;

    // Verify tree convergence
    let root = nodes.iter().map(|n| *n.node.node_addr()).min().unwrap();
    for tn in &nodes {
        assert_eq!(*tn.node.tree_state().root(), root, "Tree not converged");
    }

    // Populate coord caches: each node caches the far-end node's coords
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let node3_addr = *nodes[3].node.node_addr();
    let node3_coords = nodes[3].node.tree_state().my_coords().clone();
    nodes[0]
        .node
        .coord_cache_mut()
        .insert(node3_addr, node3_coords, now_ms);

    let node0_addr = *nodes[0].node.node_addr();
    let node0_coords = nodes[0].node.tree_state().my_coords().clone();
    nodes[3]
        .node
        .coord_cache_mut()
        .insert(node0_addr, node0_coords, now_ms);

    // Node 0 should be able to route toward node 3.
    // The next hop should be node 1 (only peer of node 0).
    let node1_addr = *nodes[1].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    let hop = nodes[0].node.find_next_hop(&node3_addr);
    assert!(hop.is_some(), "Node 0 should find route to node 3");
    assert_eq!(
        hop.unwrap().node_addr(),
        &node1_addr,
        "Node 0's next hop to node 3 should be node 1"
    );

    // Node 3 should route toward node 0 via node 2.
    let hop = nodes[3].node.find_next_hop(&node0_addr);
    assert!(hop.is_some(), "Node 3 should find route to node 0");
    assert_eq!(
        hop.unwrap().node_addr(),
        &node2_addr,
        "Node 3's next hop to node 0 should be node 2"
    );
}

#[tokio::test]
async fn test_routing_bloom_preferred_over_tree() {
    // Build a 3-node triangle: 0 -- 1, 0 -- 2, 1 -- 2
    let mut nodes = vec![
        make_test_node().await,
        make_test_node().await,
        make_test_node().await,
    ];

    initiate_handshake(&mut nodes, 0, 1).await;
    initiate_handshake(&mut nodes, 0, 2).await;
    initiate_handshake(&mut nodes, 1, 2).await;

    drain_all_packets(&mut nodes, false).await;

    // Create a destination beyond the network and cache its coords.
    // Place dest as a child of peer2 in the converged tree so bloom
    // filter routing selects peer2 (strictly closer to dest than us).
    let dest = make_node_addr(99);
    let peer2_addr = *nodes[2].node.node_addr();
    let mut dest_path: Vec<NodeAddr> = nodes[2]
        .node
        .tree_state()
        .my_coords()
        .node_addrs()
        .copied()
        .collect();
    dest_path.insert(0, dest);
    let dest_coords = TreeCoordinate::from_addrs(dest_path).unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    nodes[0]
        .node
        .coord_cache_mut()
        .insert(dest, dest_coords, now_ms);

    // Add dest to peer 2's bloom filter (from node 0's perspective)
    let peer2 = nodes[0].node.get_peer_mut(&peer2_addr).unwrap();
    let mut filter = BloomFilter::new();
    filter.insert(&dest);
    peer2.update_filter(filter, 100, 50000);

    // Bloom filter hit with cached coords should route via peer 2.
    let hop = nodes[0].node.find_next_hop(&dest);
    assert!(hop.is_some(), "Should route via bloom filter");
    assert_eq!(
        hop.unwrap().node_addr(),
        &peer2_addr,
        "Should pick peer with bloom filter hit"
    );
}

// === Multi-hop forwarding simulation ===

/// Result of simulating multi-hop packet forwarding.
#[derive(Debug)]
enum ForwardResult {
    /// Packet reached the destination in the given number of hops.
    Delivered(usize),
    /// Routing returned None at the given node index (no route).
    NoRoute { at_node: usize, hops: usize },
    /// Routing loop detected (visited the same node twice).
    Loop { at_node: usize, hops: usize },
}

/// Build a NodeAddr → node index lookup table.
fn build_addr_index(nodes: &[TestNode]) -> std::collections::HashMap<NodeAddr, usize> {
    nodes
        .iter()
        .enumerate()
        .map(|(i, tn)| (*tn.node.node_addr(), i))
        .collect()
}

/// Simulate multi-hop forwarding from source to destination.
///
/// At each hop, calls `find_next_hop` on the current node and follows
/// the result to the next node. Terminates on delivery, routing failure,
/// or loop detection.
fn simulate_forwarding(
    nodes: &mut [TestNode],
    addr_index: &std::collections::HashMap<NodeAddr, usize>,
    src: usize,
    dst: usize,
) -> ForwardResult {
    let dest_addr = *nodes[dst].node.node_addr();
    let max_hops = nodes.len(); // can't take more hops than nodes

    let mut current = src;
    let mut visited = HashSet::new();
    visited.insert(current);

    for hop in 0..max_hops {
        let next = nodes[current].node.find_next_hop(&dest_addr);

        match next {
            None => {
                // find_next_hop returns None for local delivery (dest == self)
                if *nodes[current].node.node_addr() == dest_addr {
                    return ForwardResult::Delivered(hop);
                }
                return ForwardResult::NoRoute {
                    at_node: current,
                    hops: hop,
                };
            }
            Some(peer) => {
                let next_addr = *peer.node_addr();

                // Is next hop the destination?
                if next_addr == dest_addr {
                    return ForwardResult::Delivered(hop + 1);
                }

                // Find the node index for the next hop
                let next_idx = match addr_index.get(&next_addr) {
                    Some(&idx) => idx,
                    None => {
                        return ForwardResult::NoRoute {
                            at_node: current,
                            hops: hop,
                        };
                    }
                };

                // Loop detection
                if visited.contains(&next_idx) {
                    return ForwardResult::Loop {
                        at_node: next_idx,
                        hops: hop + 1,
                    };
                }

                visited.insert(next_idx);
                current = next_idx;
            }
        }
    }

    ForwardResult::NoRoute {
        at_node: current,
        hops: max_hops,
    }
}

/// 100-node random graph: verify all-pairs routing reachability.
///
/// After tree and bloom filter convergence, simulates multi-hop packet
/// forwarding between every pair of nodes. Every packet must be delivered
/// without loops.
#[tokio::test]
async fn test_routing_reachability_100_nodes() {
    let _guard = lock_large_network_test().await;

    const NUM_NODES: usize = 100;
    const TARGET_EDGES: usize = 250;
    const SEED: u64 = 42;

    let edges = generate_random_edges(NUM_NODES, TARGET_EDGES, SEED);
    let mut nodes = run_tree_test(NUM_NODES, &edges, false).await;
    verify_tree_convergence(&nodes);

    // Populate coord caches: every node learns every other node's coordinates.
    // In production this happens via SessionSetup/LookupResponse; here we
    // inject them directly. Bloom filter routing requires cached dest_coords
    // for loop-free forwarding — without coords, find_next_hop returns None.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // Collect all (addr, coords) pairs first to avoid borrow issues
    let all_coords: Vec<(NodeAddr, TreeCoordinate)> = nodes
        .iter()
        .map(|tn| {
            (
                *tn.node.node_addr(),
                tn.node.tree_state().my_coords().clone(),
            )
        })
        .collect();

    for node in &mut nodes {
        for (addr, coords) in &all_coords {
            if addr != node.node.node_addr() {
                node.node
                    .coord_cache_mut()
                    .insert(*addr, coords.clone(), now_ms);
            }
        }
    }

    let addr_index = build_addr_index(&nodes);

    let mut total_pairs = 0;
    let mut total_hops = 0usize;
    let mut max_hops = 0usize;
    let mut failures = Vec::new();
    let mut loops = Vec::new();

    // Test all pairs
    for src in 0..NUM_NODES {
        for dst in 0..NUM_NODES {
            if src == dst {
                continue;
            }

            total_pairs += 1;

            match simulate_forwarding(&mut nodes, &addr_index, src, dst) {
                ForwardResult::Delivered(hops) => {
                    total_hops += hops;
                    if hops > max_hops {
                        max_hops = hops;
                    }
                }
                ForwardResult::NoRoute { at_node, hops } => {
                    failures.push((src, dst, at_node, hops));
                }
                ForwardResult::Loop { at_node, hops } => {
                    loops.push((src, dst, at_node, hops));
                }
            }
        }
    }

    let delivered = total_pairs - failures.len() - loops.len();
    let avg_hops = if delivered > 0 {
        total_hops as f64 / delivered as f64
    } else {
        0.0
    };

    eprintln!("\n  === Routing Reachability ({} nodes) ===", NUM_NODES);
    eprintln!(
        "  Pairs tested: {} | Delivered: {} | Failed: {} | Loops: {}",
        total_pairs,
        delivered,
        failures.len(),
        loops.len()
    );
    eprintln!("  Hops: avg={:.1} max={}", avg_hops, max_hops);

    if !failures.is_empty() {
        let show = failures.len().min(10);
        eprintln!("  First {} failures:", show);
        for &(src, dst, at_node, hops) in &failures[..show] {
            eprintln!(
                "    {} -> {}: stuck at node {} after {} hops",
                src, dst, at_node, hops
            );
        }
    }

    if !loops.is_empty() {
        let show = loops.len().min(10);
        eprintln!("  First {} loops:", show);
        for &(src, dst, at_node, hops) in &loops[..show] {
            eprintln!(
                "    {} -> {}: loop at node {} after {} hops",
                src, dst, at_node, hops
            );
        }
    }

    assert!(
        loops.is_empty(),
        "Detected {} routing loops out of {} pairs",
        loops.len(),
        total_pairs
    );
    assert!(
        failures.is_empty(),
        "Detected {} routing failures out of {} pairs",
        failures.len(),
        total_pairs
    );

    cleanup_nodes(&mut nodes).await;
}

// === Peer removal stops routing through removed peer ===

/// After removing a peer from a converged chain, routing to destinations
/// previously reachable through that peer should fail.
///
/// Chain: 0 -- 1 -- 2 -- 3. Remove node 2 from node 1's perspective.
/// Node 0 should no longer be able to route to node 3.
#[tokio::test]
async fn test_routing_stops_after_peer_removal() {
    use crate::proto::fmp::{Disconnect, DisconnectReason};

    let edges = vec![(0, 1), (1, 2), (2, 3)];
    let mut nodes = run_tree_test(4, &edges, false).await;
    verify_tree_convergence(&nodes);

    let _node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    let node3_addr = *nodes[3].node.node_addr();

    // Inject coordinates so routing works before removal
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let all_coords: Vec<(NodeAddr, crate::proto::stp::TreeCoordinate)> = nodes
        .iter()
        .map(|tn| {
            (
                *tn.node.node_addr(),
                tn.node.tree_state().my_coords().clone(),
            )
        })
        .collect();

    for node in &mut nodes {
        for (addr, coords) in &all_coords {
            if addr != node.node.node_addr() {
                node.node
                    .coord_cache_mut()
                    .insert(*addr, coords.clone(), now_ms);
            }
        }
    }

    // Verify routing works before removal: node 0 → node 3
    let addr_index = build_addr_index(&nodes);
    match simulate_forwarding(&mut nodes, &addr_index, 0, 3) {
        ForwardResult::Delivered(_) => {}
        other => panic!("Expected delivery before removal, got {:?}", other),
    }

    // Node 2 sends Disconnect to node 1
    let disconnect = Disconnect::new(DisconnectReason::Shutdown);
    let plaintext = disconnect.encode();
    nodes[2]
        .node
        .send_encrypted_link_message(&node1_addr, &plaintext)
        .await
        .expect("Failed to send disconnect");

    // Process disconnect and let bloom filters reconverge
    drain_all_packets(&mut nodes, false).await;

    // Verify node 1 removed node 2
    assert!(
        nodes[1].node.get_peer(&node2_addr).is_none(),
        "Node 1 should have removed node 2"
    );

    // Bloom filter check: node 0's peer (node 1) should no longer
    // advertise node 3 as reachable
    let node0_reaches_node3 = nodes[0]
        .node
        .peers()
        .any(|peer| peer.may_reach(&node3_addr));
    assert!(
        !node0_reaches_node3,
        "Node 0 should not see node 3 as reachable after partition"
    );

    // Routing from node 0 to node 3 should now fail: no bloom filter hit.
    // Greedy tree routing may still have stale coords cached, but without
    // bloom filter hits, routing should stop at node 1 (which lost its
    // peer to the other side). If stale coords exist, greedy routing could
    // still attempt forwarding — but the self-distance check prevents loops.
    // Either NoRoute or Loop-with-stale-coords is acceptable here; what
    // matters is that delivery does NOT succeed.
    match simulate_forwarding(&mut nodes, &addr_index, 0, 3) {
        ForwardResult::NoRoute { .. } => {} // Expected: can't reach node 3
        ForwardResult::Loop { .. } => {}    // Also acceptable: stale coords cause loop detection
        ForwardResult::Delivered(hops) => {
            panic!(
                "Should NOT deliver after partition, but got delivery in {} hops",
                hops
            );
        }
    }

    // But routing within the same component still works: node 2 → node 3
    match simulate_forwarding(&mut nodes, &addr_index, 2, 3) {
        ForwardResult::Delivered(_) => {}
        other => panic!("Expected delivery within component, got {:?}", other),
    }

    cleanup_nodes(&mut nodes).await;
}

// === Bloom-filter-only transit routing (no globally injected coords) ===

/// Verify that transit routers can forward using bloom filters alone.
///
/// In a converged network, only the SOURCE has the destination's coords
/// in its cache (simulating a real first-contact scenario where only the
/// source ran discovery). Transit routers have no cached coords for the
/// destination. Routing should still work because transit routers use
/// bloom filter hits to select next hops.
///
/// Chain: 0 -- 1 -- 2 -- 3. Only node 0 has node 3's coords cached.
/// Nodes 1 and 2 route using bloom filters only.
///
/// Scope note: despite the name, what this actually pins is that transit
/// requires cached coordinates at each hop and that the last hop short-circuits
/// on direct peering. It does not discriminate the bloom predicate: the node-1
/// and node-2 assertions return from `find_next_hop` before the routing view is
/// ever constructed, and node 0 has exactly one peer, so its assertion cannot
/// separate any two candidates. See the `Seam: NodeRoutingView adapter` section
/// at the end of this file for the tests that do.
#[tokio::test]
async fn test_routing_bloom_only_transit() {
    let edges = vec![(0, 1), (1, 2), (2, 3)];
    let mut nodes = run_tree_test(4, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node3_addr = *nodes[3].node.node_addr();
    let node3_coords = nodes[3].node.tree_state().my_coords().clone();

    // Only inject node 3's coords at node 0 (the source).
    // Transit nodes (1, 2) have NO coords for node 3 in their caches.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    nodes[0]
        .node
        .coord_cache_mut()
        .insert(node3_addr, node3_coords, now_ms);

    // Node 0 should find a next hop (bloom filter hit at peer node 1,
    // with coords available for tie-breaking at the source)
    let hop = nodes[0].node.find_next_hop(&node3_addr);
    assert!(hop.is_some(), "Node 0 should route to node 3 (has coords)");

    // Node 1 should also find a next hop using bloom filter alone.
    // But wait — find_next_hop requires dest_coords to be cached when
    // bloom filter hits exist (loop prevention). Node 1 has no coords
    // for node 3, so it should return None.
    let hop_at_1 = nodes[1].node.find_next_hop(&node3_addr);

    // This is the key insight: bloom-filter-only transit routing does NOT
    // work in the current implementation because find_next_hop gates bloom
    // filter candidate selection on having cached dest_coords. Transit
    // routers without coords return None, which is the correct behavior
    // (prevents loops) but means the SessionSetup must carry coords to
    // warm transit router caches before data packets can flow.
    assert!(
        hop_at_1.is_none(),
        "Node 1 should NOT route without cached coords (loop prevention)"
    );

    // However, node 1 IS a direct peer of node 2, and node 2 IS a direct
    // peer of node 3. The "direct peer" priority (step 2 in find_next_hop)
    // would handle adjacency. Let's verify node 2 can route to its direct
    // peer node 3.
    let hop_at_2 = nodes[2].node.find_next_hop(&node3_addr);
    assert!(
        hop_at_2.is_some(),
        "Node 2 should route to node 3 (direct peer)"
    );
    assert_eq!(
        hop_at_2.unwrap().node_addr(),
        &node3_addr,
        "Node 2's next hop to node 3 should be node 3 itself"
    );

    cleanup_nodes(&mut nodes).await;
}

/// 100-node routing: verify that with coords cached ONLY at the source,
/// multi-hop forwarding still works because each transit node either has
/// the destination as a direct peer OR needs coords to break bloom filter
/// ties.
///
/// This test reveals the boundary: in a converged network, bloom filter
/// routing needs dest_coords at each hop for loop-free forwarding through
/// non-adjacent nodes. Direct peer adjacency handles the last hop.
#[tokio::test]
async fn test_routing_source_only_coords_100_nodes() {
    let _guard = lock_large_network_test().await;

    const NUM_NODES: usize = 100;
    const TARGET_EDGES: usize = 250;
    const SEED: u64 = 42;

    let edges = generate_random_edges(NUM_NODES, TARGET_EDGES, SEED);
    let mut nodes = run_tree_test(NUM_NODES, &edges, false).await;
    verify_tree_convergence(&nodes);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // Collect all coords for injection
    let all_coords: Vec<(NodeAddr, crate::proto::stp::TreeCoordinate)> = nodes
        .iter()
        .map(|tn| {
            (
                *tn.node.node_addr(),
                tn.node.tree_state().my_coords().clone(),
            )
        })
        .collect();

    let addr_index = build_addr_index(&nodes);

    // Test: for each pair, inject dest coords ONLY at the source.
    // Count how many pairs can be delivered vs fail.
    let mut source_only_delivered = 0usize;
    let mut source_only_failed = 0usize;
    let mut total_pairs = 0usize;

    // Test a sample of pairs (all pairs would be expensive)
    let sample_pairs: Vec<(usize, usize)> = (0..NUM_NODES)
        .step_by(10)
        .flat_map(|s| {
            (0..NUM_NODES)
                .step_by(10)
                .filter(move |&d| d != s)
                .map(move |d| (s, d))
        })
        .collect();

    for &(src, dst) in &sample_pairs {
        total_pairs += 1;

        // Clear ALL coord caches
        for node in &mut nodes {
            node.node.coord_cache_mut().clear();
        }

        // Inject dest coords ONLY at the source
        let (dest_addr, dest_coords) = &all_coords[dst];
        nodes[src]
            .node
            .coord_cache_mut()
            .insert(*dest_addr, dest_coords.clone(), now_ms);

        match simulate_forwarding(&mut nodes, &addr_index, src, dst) {
            ForwardResult::Delivered(_) => source_only_delivered += 1,
            ForwardResult::NoRoute { .. } => source_only_failed += 1,
            ForwardResult::Loop { .. } => {
                panic!(
                    "Routing loop detected with source-only coords: {} -> {}",
                    src, dst
                );
            }
        }
    }

    eprintln!(
        "\n  === Source-Only Coords Routing ({} nodes) ===",
        NUM_NODES
    );
    eprintln!(
        "  Pairs: {} | Delivered: {} | Failed: {} | Delivery rate: {:.1}%",
        total_pairs,
        source_only_delivered,
        source_only_failed,
        source_only_delivered as f64 / total_pairs as f64 * 100.0
    );

    // With source-only coords, only single-hop (direct peer) destinations
    // are guaranteed to be delivered. Multi-hop destinations fail at the
    // first transit node that doesn't have dest_coords cached. This
    // confirms the protocol's design: SessionSetup MUST carry coords
    // to warm transit router caches for multi-hop delivery.
    assert!(
        source_only_delivered > 0,
        "At least some direct-peer pairs should be delivered"
    );

    // Now compare: inject coords at ALL nodes (full cache) and verify 100%
    for node in &mut nodes {
        for (addr, coords) in &all_coords {
            if addr != node.node.node_addr() {
                node.node
                    .coord_cache_mut()
                    .insert(*addr, coords.clone(), now_ms);
            }
        }
    }

    let mut full_cache_failures = 0usize;
    for &(src, dst) in &sample_pairs {
        match simulate_forwarding(&mut nodes, &addr_index, src, dst) {
            ForwardResult::Delivered(_) => {}
            _ => full_cache_failures += 1,
        }
    }
    assert_eq!(
        full_cache_failures, 0,
        "With full coord caches, all pairs should be delivered"
    );

    cleanup_nodes(&mut nodes).await;
}

// === Route-class classification (transit-forward partition) ===

use crate::node::metrics::{ForwardingMetrics, RouteClass};

/// Current epoch millis, matching the cache-insert idiom used above.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[test]
fn test_classify_forward_tree_up() {
    // my_coords = [me, parent, root]; the chosen peer is our parent (an
    // ancestor in our path) → tree-up.
    let mut node = make_node();
    let me = *node.node_addr();
    let parent = make_node_addr(10);
    let root = make_node_addr(1);
    node.tree_state_mut()
        .set_my_coords_for_test(TreeCoordinate::from_addrs(vec![me, parent, root]).unwrap());

    // Destination somewhere above us; routed via the parent.
    let dest = make_node_addr(50);
    node.coord_cache_mut().insert(
        dest,
        TreeCoordinate::from_addrs(vec![dest, root]).unwrap(),
        now_ms(),
    );

    assert_eq!(
        node.classify_forward(&dest, &parent),
        RouteClass::TreeUp,
        "chosen peer is our ancestor"
    );
}

#[test]
fn test_classify_forward_tree_down() {
    // Chosen peer is our descendant: its coords name us as an ancestor.
    let mut node = make_node();
    let me = *node.node_addr();
    let root = make_node_addr(1);
    node.tree_state_mut()
        .set_my_coords_for_test(TreeCoordinate::from_addrs(vec![me, root]).unwrap());

    let child = make_node_addr(20);
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(child, me, 1, 1000),
        TreeCoordinate::from_addrs(vec![child, me, root]).unwrap(),
    );

    // Destination below the child; routed down to it.
    let dest = make_node_addr(60);
    node.coord_cache_mut().insert(
        dest,
        TreeCoordinate::from_addrs(vec![dest, child, me, root]).unwrap(),
        now_ms(),
    );

    assert_eq!(
        node.classify_forward(&dest, &child),
        RouteClass::TreeDown,
        "chosen peer is our descendant, dest in its subtree"
    );
}

#[test]
fn test_classify_forward_tree_down_cross() {
    // Chosen peer is our descendant (a tree child), but the destination is NOT
    // in that child's subtree: we are diving down to the child only because it
    // advertised cross-link reach upward, beyond its own subtree. This is the
    // dive-to-tree-child cut-through.
    let mut node = make_node();
    let me = *node.node_addr();
    let root = make_node_addr(1);
    node.tree_state_mut()
        .set_my_coords_for_test(TreeCoordinate::from_addrs(vec![me, root]).unwrap());

    let child = make_node_addr(20);
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(child, me, 1, 1000),
        TreeCoordinate::from_addrs(vec![child, me, root]).unwrap(),
    );

    // Destination lives elsewhere (directly under root), NOT under the child;
    // reachable from the child only via a cross-link.
    let dest = make_node_addr(60);
    node.coord_cache_mut().insert(
        dest,
        TreeCoordinate::from_addrs(vec![dest, root]).unwrap(),
        now_ms(),
    );

    assert_eq!(
        node.classify_forward(&dest, &child),
        RouteClass::TreeDownCross,
        "descendant peer, dest not in its subtree (dive-to-tree-child cut-through)"
    );
}

#[test]
fn test_classify_forward_crosslink_descend() {
    // Chosen peer is lateral (not in our path, we are not in its path) and the
    // destination is inside the peer's subtree → cross-link descend.
    let mut node = make_node();
    let me = *node.node_addr();
    let root = make_node_addr(1);
    let sibling_parent = make_node_addr(2);
    node.tree_state_mut()
        .set_my_coords_for_test(TreeCoordinate::from_addrs(vec![me, root]).unwrap());

    let peer = make_node_addr(30);
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(peer, sibling_parent, 1, 1000),
        TreeCoordinate::from_addrs(vec![peer, sibling_parent, root]).unwrap(),
    );

    // Destination is under the cross-link peer.
    let dest = make_node_addr(70);
    node.coord_cache_mut().insert(
        dest,
        TreeCoordinate::from_addrs(vec![dest, peer, sibling_parent, root]).unwrap(),
        now_ms(),
    );

    assert_eq!(
        node.classify_forward(&dest, &peer),
        RouteClass::CrosslinkDescend,
        "lateral peer, dest in its subtree"
    );
}

#[test]
fn test_classify_forward_crosslink_ascend() {
    // Chosen peer is lateral and the destination is NOT in its subtree → the
    // up-and-over case (the Bloom v2 behavior delta).
    let mut node = make_node();
    let me = *node.node_addr();
    let root = make_node_addr(1);
    let sibling_parent = make_node_addr(2);
    node.tree_state_mut()
        .set_my_coords_for_test(TreeCoordinate::from_addrs(vec![me, root]).unwrap());

    let peer = make_node_addr(40);
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(peer, sibling_parent, 1, 1000),
        TreeCoordinate::from_addrs(vec![peer, sibling_parent, root]).unwrap(),
    );

    // Destination lives elsewhere (under root directly), NOT under the peer.
    let dest = make_node_addr(80);
    node.coord_cache_mut().insert(
        dest,
        TreeCoordinate::from_addrs(vec![dest, root]).unwrap(),
        now_ms(),
    );

    assert_eq!(
        node.classify_forward(&dest, &peer),
        RouteClass::CrosslinkAscend,
        "lateral peer, dest not in its subtree"
    );
}

#[test]
fn test_classify_forward_direct_peer() {
    // Degenerate case: the next hop is the destination itself.
    let mut node = make_node();
    let me = *node.node_addr();
    let root = make_node_addr(1);
    node.tree_state_mut()
        .set_my_coords_for_test(TreeCoordinate::from_addrs(vec![me, root]).unwrap());

    let dest = make_node_addr(90);
    assert_eq!(
        node.classify_forward(&dest, &dest),
        RouteClass::DirectPeer,
        "next hop is the destination"
    );
}

#[test]
fn test_route_class_partition_sums_to_forwarded() {
    // The six route classes partition forwarded_packets: bumping
    // record_forwarded once per record_route_class keeps the sum of the class
    // counters equal to forwarded_packets.
    let m = ForwardingMetrics::default();
    let classes = [
        RouteClass::TreeUp,
        RouteClass::TreeUp,
        RouteClass::TreeDown,
        RouteClass::TreeDownCross,
        RouteClass::TreeDownCross,
        RouteClass::CrosslinkDescend,
        RouteClass::CrosslinkAscend,
        RouteClass::CrosslinkAscend,
        RouteClass::CrosslinkAscend,
        RouteClass::DirectPeer,
    ];
    for &c in &classes {
        m.record_forwarded(100);
        m.record_route_class(c);
    }

    let snap = m.snapshot();
    let class_sum = snap.route_tree_up
        + snap.route_tree_down
        + snap.route_tree_down_cross
        + snap.route_crosslink_descend
        + snap.route_crosslink_ascend
        + snap.route_direct_peer;
    assert_eq!(
        class_sum, snap.forwarded_packets,
        "route classes must partition forwarded_packets"
    );
    assert_eq!(snap.route_tree_up, 2);
    assert_eq!(snap.route_tree_down_cross, 2);
    assert_eq!(snap.route_crosslink_ascend, 3);
    assert_eq!(snap.route_direct_peer, 1);
}

// === Coord-cache invalidation on parent loss ===
//
// Parent-lost-via-peer-removal is a genuine position change and must
// surgically invalidate the coordinate cache like every other such path
// (reparent → invalidate_via_node; self-root → invalidate_other_roots).
// `make_node_addr(0)` is the network minimum, so the node's random identity
// addr is always greater than it — the reparent/child geometry is deterministic.

#[test]
fn test_parent_loss_reparent_invalidates_coord_cache() {
    let mut node = make_node();
    let my_addr = *node.node_addr();

    let root = make_node_addr(0);
    let parent = make_node_addr(1);
    let alt = make_node_addr(2);

    // Current parent and an alternative, both rooted at `root`.
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(parent, root, 1, 1000),
        TreeCoordinate::from_addrs(vec![parent, root]).unwrap(),
    );
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(alt, root, 1, 1000),
        TreeCoordinate::from_addrs(vec![alt, root]).unwrap(),
    );
    // Adopt `parent`; our coords become [my_addr, parent, root], root = `root`.
    node.tree_state_mut().set_parent(parent, 1, 1000, 1000);
    node.tree_state_mut().recompute_coords();
    assert!(!node.tree_state().is_root());
    assert_eq!(node.tree_state().root(), &root);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // via-node class: a downstream destination that routes through us.
    let downstream = make_node_addr(10);
    node.coord_cache_mut().insert(
        downstream,
        TreeCoordinate::from_addrs(vec![downstream, my_addr, root]).unwrap(),
        now_ms,
    );
    // survivor: same root, does not route through us.
    let sibling_dest = make_node_addr(11);
    node.coord_cache_mut().insert(
        sibling_dest,
        TreeCoordinate::from_addrs(vec![sibling_dest, alt, root]).unwrap(),
        now_ms,
    );

    // Parent link drops; node reparents onto `alt` (still rooted at `root`).
    let changed = node.handle_peer_removal_tree_cleanup(&parent);
    assert!(changed);
    assert_eq!(node.tree_state().my_declaration().parent_id(), &alt);
    assert_eq!(node.tree_state().root(), &root);

    assert!(
        !node.coord_cache().contains(&downstream, now_ms),
        "entry routing through us must be invalidated after reparent"
    );
    assert!(
        node.coord_cache().contains(&sibling_dest, now_ms),
        "same-root entry not routing through us must survive (surgical, not a flush)"
    );
}

#[test]
fn test_parent_loss_selfroot_invalidates_coord_cache() {
    let mut node = make_node();
    let my_addr = *node.node_addr();

    let old_root = make_node_addr(0);
    let parent = make_node_addr(1);

    // Adopt `parent` (rooted at `old_root`); no alternative peers exist, so a
    // parent loss self-roots the node.
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(parent, old_root, 1, 1000),
        TreeCoordinate::from_addrs(vec![parent, old_root]).unwrap(),
    );
    node.tree_state_mut().set_parent(parent, 1, 1000, 1000);
    node.tree_state_mut().recompute_coords();
    assert!(!node.tree_state().is_root());

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // via-node class: routes through us.
    let downstream = make_node_addr(10);
    node.coord_cache_mut().insert(
        downstream,
        TreeCoordinate::from_addrs(vec![downstream, my_addr, old_root]).unwrap(),
        now_ms,
    );
    // other-roots class: on the old root, does not route through us.
    let foreign = make_node_addr(11);
    node.coord_cache_mut().insert(
        foreign,
        TreeCoordinate::from_addrs(vec![foreign, parent, old_root]).unwrap(),
        now_ms,
    );

    // Parent link drops; no alternative parent → node self-roots.
    let changed = node.handle_peer_removal_tree_cleanup(&parent);
    assert!(changed);
    assert!(node.tree_state().is_root());
    assert_eq!(node.tree_state().root(), &my_addr);

    assert!(
        !node.coord_cache().contains(&downstream, now_ms),
        "via-node entry must be invalidated after self-root"
    );
    assert!(
        !node.coord_cache().contains(&foreign, now_ms),
        "stale old-root entry must be invalidated after self-root"
    );
}

// === Seam: NodeRoutingView adapter ===
//
// The tests above exercise the routing *decision*; the ones below exercise the
// *adapter* that feeds it. `NodeRoutingView` (src/node/mod.rs) is the only
// thing connecting the node's live peer map to the sans-IO routing core, and
// the core's own tests in src/proto/routing/tests/ drive a mock view, so
// nothing else in the suite observes the real adapter.
//
// Why no pre-existing test discriminates it: in every other fixture in this
// file the bloom winner and the greedy-tree winner are the same peer, which
// makes branch 3 and branch 4 of `find_next_hop` indistinguishable — the route
// is unchanged whichever branch produced it. The fixtures below break that
// collinearity deliberately, so the answer each one asserts is a peer the tree
// fallback would *not* have chosen. A broken adapter changes the answer rather
// than merely changing the path to it.
//
// Every assertion pins a peer identity rather than `is_some()`, and every route
// goes through the real `Node::find_next_hop`, which constructs the real
// `NodeRoutingView` internally and cannot be handed a mock.

fn seam_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn seam_add_peer(node: &mut Node, link_num: u64, transport_id: TransportId) -> NodeAddr {
    let link_id = LinkId::new(link_num);
    let identity = seed_completed_connection(node, link_id, transport_id, 1000);
    let addr = *identity.node_addr();
    node.promote_connection(link_id, identity, 2000).unwrap();
    addr
}

/// Put `dest` into `peer`'s inbound bloom filter.
fn seam_set_filter(node: &mut Node, peer: &NodeAddr, dest: &NodeAddr) {
    let mut filter = BloomFilter::new();
    filter.insert(dest);
    node.get_peer_mut(peer)
        .unwrap()
        .update_filter(filter, 1, 3000);
}

/// Set a peer's link cost inputs directly. `etx * (1.0 + srtt_ms / 100.0)`.
fn seam_set_cost(node: &mut Node, peer: &NodeAddr, etx: f64, rtt_us: i64) {
    let mmp = node.get_peer_mut(peer).unwrap().mmp_mut().unwrap();
    mmp.metrics.etx = etx;
    mmp.metrics.srtt.update(rtt_us);
}

/// Two peers *equidistant* from `dest`, both strictly closer than we are.
///
/// Tree (we are root):  my ── near ── dest ── far
///
/// `far` is also a direct peer of ours: a mesh link that is not a tree edge.
/// Distances to dest are my = 2, near = 1, far = 1, so both peers clear the
/// self-distance check at the same distance and the same link cost. The only
/// thing separating them is the address tie-break, which is what lets a test
/// make one of the adapter's predicates pick the peer the tree would have
/// rejected — and then the two branches finally disagree.
///
/// Peer addresses come from `Identity::generate()` and are random, so callers
/// assign roles at runtime with `near.min(far)` / `near.max(far)` rather than
/// assuming which topological role drew the smaller key.
///
/// Returns `(near, far, dest)`.
fn seam_two_equidistant_peers(node: &mut Node) -> (NodeAddr, NodeAddr, NodeAddr) {
    let transport_id = TransportId::new(1);
    let my_addr = *node.node_addr();

    let near = seam_add_peer(node, 1, transport_id);
    let far = seam_add_peer(node, 2, transport_id);
    let dest = make_node_addr(99);

    let near_coords = TreeCoordinate::from_addrs(vec![near, my_addr]).unwrap();
    node.tree_state_mut()
        .update_peer(ParentDeclaration::new(near, my_addr, 1, 1000), near_coords);

    let far_coords = TreeCoordinate::from_addrs(vec![far, dest, near, my_addr]).unwrap();
    node.tree_state_mut()
        .update_peer(ParentDeclaration::new(far, dest, 3, 1000), far_coords);

    let dest_coords = TreeCoordinate::from_addrs(vec![dest, near, my_addr]).unwrap();
    node.coord_cache_mut()
        .insert(dest, dest_coords, seam_now_ms());

    (near, far, dest)
}

/// Three peers at *distinct* distances from `dest`, strung along one tree path.
///
/// Tree (we are root):  my ── rung3 ── rung2 ── rung1 ── dest
///
/// All three rungs are also direct peers of ours. Distances to dest are
/// my = 4, rung1 = 1, rung2 = 2, rung3 = 3. Putting the bloom hits on
/// `{rung2, rung3}` makes the winner depend on the coordinate *values* the
/// adapter hands back rather than merely on whether it hands back any: rung2
/// wins on distance from inside the bloom set, while the tree fallback would
/// have answered rung1. Link costs are all 1.0 and the three distances differ,
/// so the address tie-break never engages and the answer does not depend on
/// which peer drew the smaller random key.
///
/// Returns `(rung1, rung2, rung3, dest)`.
fn seam_distance_ladder(node: &mut Node) -> (NodeAddr, NodeAddr, NodeAddr, NodeAddr) {
    let transport_id = TransportId::new(1);
    let my_addr = *node.node_addr();

    let rung1 = seam_add_peer(node, 1, transport_id);
    let rung2 = seam_add_peer(node, 2, transport_id);
    let rung3 = seam_add_peer(node, 3, transport_id);
    let dest = make_node_addr(99);

    let rung3_coords = TreeCoordinate::from_addrs(vec![rung3, my_addr]).unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(rung3, my_addr, 1, 1000),
        rung3_coords,
    );

    let rung2_coords = TreeCoordinate::from_addrs(vec![rung2, rung3, my_addr]).unwrap();
    node.tree_state_mut()
        .update_peer(ParentDeclaration::new(rung2, rung3, 2, 1000), rung2_coords);

    let rung1_coords = TreeCoordinate::from_addrs(vec![rung1, rung2, rung3, my_addr]).unwrap();
    node.tree_state_mut()
        .update_peer(ParentDeclaration::new(rung1, rung2, 3, 1000), rung1_coords);

    let dest_coords = TreeCoordinate::from_addrs(vec![dest, rung1, rung2, rung3, my_addr]).unwrap();
    node.coord_cache_mut()
        .insert(dest, dest_coords, seam_now_ms());

    (rung1, rung2, rung3, dest)
}

/// Guard on the two seam fixtures rather than on the seam itself.
///
/// Every seam test below asserts an answer that only holds while the fixture's
/// distances are what its comment claims. If tree-coordinate or distance
/// semantics ever change so that the fixtures stop discriminating, those tests
/// would go on passing while observing nothing — the exact blindness they exist
/// to remove. This one fails first and says which fixture collapsed.
#[test]
fn test_seam_fixture_distances_are_as_documented() {
    let mut node = make_node();
    let my_addr = *node.node_addr();
    let (near, far, dest) = seam_two_equidistant_peers(&mut node);

    let dest_coords = TreeCoordinate::from_addrs(vec![dest, near, my_addr]).unwrap();
    let ts = node.tree_state();
    assert_eq!(ts.my_coords().distance_to(&dest_coords), 2, "my distance");
    assert_eq!(
        ts.peer_coords(&near).unwrap().distance_to(&dest_coords),
        1,
        "near distance"
    );
    assert_eq!(
        ts.peer_coords(&far).unwrap().distance_to(&dest_coords),
        1,
        "far distance"
    );

    // Both peers equidistant and equally cheap, so greedy tree routing resolves
    // the tie on address. The equidistant-fixture tests below each assert the
    // *other* peer; this is the answer they are contradicting.
    let tree_pick = ts.find_next_hop(&dest_coords, &BTreeSet::new()).unwrap();
    assert_eq!(
        tree_pick,
        near.min(far),
        "greedy tree tie-break is min addr"
    );

    let mut node = make_node();
    let my_addr = *node.node_addr();
    let (rung1, rung2, rung3, dest) = seam_distance_ladder(&mut node);
    let dest_coords = TreeCoordinate::from_addrs(vec![dest, rung1, rung2, rung3, my_addr]).unwrap();
    let ts = node.tree_state();
    assert_eq!(ts.my_coords().distance_to(&dest_coords), 4, "my distance");
    assert_eq!(
        ts.peer_coords(&rung1).unwrap().distance_to(&dest_coords),
        1,
        "rung1 distance"
    );
    assert_eq!(
        ts.peer_coords(&rung2).unwrap().distance_to(&dest_coords),
        2,
        "rung2 distance"
    );
    assert_eq!(
        ts.peer_coords(&rung3).unwrap().distance_to(&dest_coords),
        3,
        "rung3 distance"
    );
    let tree_pick = ts.find_next_hop(&dest_coords, &BTreeSet::new()).unwrap();
    assert_eq!(tree_pick, rung1, "greedy tree picks the nearest rung");
}

/// `NodeRoutingView::peer_may_reach` decides the bloom candidate set.
///
/// The bloom hit is placed on the peer the greedy tree tie-break would have
/// *rejected*, so the only path to the asserted answer is branch 3 of
/// `find_next_hop` selecting it on that hit. Widening `peer_may_reach` to
/// `true` — bloom filtering off, the break that motivated this whole section —
/// or inverting it collapses the answer back to the tree pick.
#[test]
fn test_seam_bloom_hit_overrides_tree_tiebreak() {
    let mut node = make_node();
    let (near, far, dest) = seam_two_equidistant_peers(&mut node);
    let tree_pick = near.min(far);
    let bloom_pick = near.max(far);

    // Fixture preconditions, so a red below reads as a seam regression rather
    // than as the fixture having collapsed.
    assert_eq!(node.peers.len(), 2, "fixture: two peers");
    assert!(node.tree_state().peer_coords(&near).is_some());
    assert!(node.tree_state().peer_coords(&far).is_some());

    seam_set_filter(&mut node, &bloom_pick, &dest);
    assert!(!node.get_peer(&tree_pick).unwrap().may_reach(&dest));

    let hop = node.find_next_hop(&dest).expect("route exists");
    assert_eq!(
        hop.node_addr(),
        &bloom_pick,
        "the bloom candidate must beat the greedy tree tie-break winner {tree_pick:?}"
    );
}

/// `NodeRoutingView::peer_can_send` keeps a down link out of the candidate set.
///
/// Both peers hold a bloom hit, so the address tie-break would hand the route
/// to the low-address peer; that peer is the one marked reconnecting. Widening
/// `peer_can_send` to `true` lets it back in and hands a down link to the
/// forwarder.
#[test]
fn test_seam_unsendable_bloom_candidate_is_skipped() {
    let mut node = make_node();
    let (near, far, dest) = seam_two_equidistant_peers(&mut node);
    let low = near.min(far);
    let high = near.max(far);

    seam_set_filter(&mut node, &low, &dest);
    seam_set_filter(&mut node, &high, &dest);
    node.get_peer_mut(&low).unwrap().mark_reconnecting();

    assert_eq!(node.peers.len(), 2, "fixture: two peers");
    assert!(
        !node.get_peer(&low).unwrap().can_send(),
        "fixture: low is down"
    );
    assert!(
        node.get_peer(&high).unwrap().can_send(),
        "fixture: high is up"
    );

    let hop = node.find_next_hop(&dest).expect("route exists");
    assert!(hop.can_send(), "a down link must never be returned");
    assert_eq!(
        hop.node_addr(),
        &high,
        "the sendable peer must win despite losing the address tie-break"
    );
}

/// `NodeRoutingView::peer_link_cost` must carry the ETX factor.
///
/// SRTT is equal on both peers, so ETX is the only thing that can order them,
/// and the cheap peer is the one that loses the address tie-break. This reds
/// for a flattened cost, a negated cost, and — the shape a rewrite of the
/// adapter actually produces — a cost that reads only the latency half of
/// `etx * (1.0 + srtt_ms / 100.0)`.
#[test]
fn test_seam_link_cost_etx_orders_bloom_candidates() {
    let mut node = make_node();
    let (near, far, dest) = seam_two_equidistant_peers(&mut node);
    let low = near.min(far);
    let high = near.max(far);

    seam_set_filter(&mut node, &low, &dest);
    seam_set_filter(&mut node, &high, &dest);
    seam_set_cost(&mut node, &low, 3.0, 1_000);
    seam_set_cost(&mut node, &high, 1.0, 1_000);

    let cost_low = node.get_peer(&low).unwrap().link_cost();
    let cost_high = node.get_peer(&high).unwrap().link_cost();
    assert!(
        cost_high < cost_low,
        "fixture: ETX alone must make high cheaper ({cost_high} vs {cost_low})"
    );

    let hop = node.find_next_hop(&dest).expect("route exists");
    assert_eq!(
        hop.node_addr(),
        &high,
        "the lower-ETX link must win despite losing the address tie-break"
    );
}

/// `NodeRoutingView::peer_link_cost` must carry the SRTT factor.
///
/// The mirror of the ETX test: ETX is equal on both peers, so latency is the
/// only thing that can order them. This reds for a flattened cost, a negated
/// cost, and a cost that reads only the ETX half.
#[test]
fn test_seam_link_cost_srtt_orders_bloom_candidates() {
    let mut node = make_node();
    let (near, far, dest) = seam_two_equidistant_peers(&mut node);
    let low = near.min(far);
    let high = near.max(far);

    seam_set_filter(&mut node, &low, &dest);
    seam_set_filter(&mut node, &high, &dest);
    seam_set_cost(&mut node, &low, 1.0, 50_000); // 50 ms -> cost 1.5
    seam_set_cost(&mut node, &high, 1.0, 1_000); // 1 ms -> cost 1.01

    let cost_low = node.get_peer(&low).unwrap().link_cost();
    let cost_high = node.get_peer(&high).unwrap().link_cost();
    assert!(
        cost_high < cost_low,
        "fixture: SRTT alone must make high cheaper ({cost_high} vs {cost_low})"
    );

    let hop = node.find_next_hop(&dest).expect("route exists");
    assert_eq!(
        hop.node_addr(),
        &high,
        "the lower-latency link must win despite losing the address tie-break"
    );
}

/// `NodeRoutingView::peer_coords` must return each peer's *own* coordinates.
///
/// The ladder puts the two bloom candidates at *different* distances, so the
/// winner is decided by the coordinate values the adapter returns and not
/// merely by whether it returns any: rung2 (distance 2) beats rung3
/// (distance 3) from inside the bloom set, while the tree fallback would have
/// answered rung1 (distance 1). Dropping the lookup to `None`, or sourcing it
/// from the wrong object (our own coordinates rather than the peer's), moves
/// the answer to rung1.
#[test]
fn test_seam_peer_coords_distance_orders_bloom_candidates() {
    let mut node = make_node();
    let (rung1, rung2, rung3, dest) = seam_distance_ladder(&mut node);

    // rung1 is the greedy tree winner and deliberately carries no bloom hit.
    seam_set_filter(&mut node, &rung2, &dest);
    seam_set_filter(&mut node, &rung3, &dest);

    assert_eq!(node.peers.len(), 3, "fixture: three peers");
    assert!(
        !node.get_peer(&rung1).unwrap().may_reach(&dest),
        "fixture: the tree winner is not a bloom candidate"
    );

    let hop = node.find_next_hop(&dest).expect("route exists");
    assert_eq!(
        hop.node_addr(),
        &rung2,
        "the nearer bloom candidate must win: rung1 {rung1:?} is the tree \
         answer, rung3 {rung3:?} is the farther candidate"
    );
}

/// A peer with no tree coordinates is infinitely far and can never be chosen.
///
/// A peer that has completed a handshake but whose tree declaration has not yet
/// arrived is an ordinary runtime state, and it is the state the core maps to
/// `usize::MAX` in its self-distance check. This exercises the adapter's `None`
/// arm and reds if the adapter ever fabricates coordinates for a peer the tree
/// does not know — a fallback to some other peer's coordinates would make this
/// peer the sole viable bloom candidate and hand it the route.
#[test]
fn test_seam_peer_without_tree_coords_is_never_selected() {
    let mut node = make_node();
    let (near, far, dest) = seam_two_equidistant_peers(&mut node);
    let tree_pick = near.min(far);

    // A third peer: in the peer map, sendable, holding a bloom hit for dest,
    // and absent from tree state.
    let ghost = seam_add_peer(&mut node, 3, TransportId::new(1));
    seam_set_filter(&mut node, &ghost, &dest);

    assert!(node.get_peer(&ghost).unwrap().can_send());
    assert!(node.get_peer(&ghost).unwrap().may_reach(&dest));
    assert!(
        node.tree_state().peer_coords(&ghost).is_none(),
        "fixture: ghost has no tree coordinates"
    );

    let hop = node.find_next_hop(&dest).expect("route exists");
    assert_ne!(
        hop.node_addr(),
        &ghost,
        "a peer with no tree coordinates must never be selected"
    );
    assert_eq!(
        hop.node_addr(),
        &tree_pick,
        "with no viable bloom candidate the tree fallback answers"
    );
}

/// Every `NodeRoutingView` read must report the live node state it adapts.
///
/// The tests above cover the reads that change a routing decision. This one
/// covers the residue: reads whose corruption has no behavioural consequence
/// through `find_next_hop` (a peer enumerated twice cannot displace itself,
/// since the core's dominance test is a strict-improvement check) and reads
/// `find_next_hop` never performs at all (`is_congested` and `cached_coords`,
/// which are reached from the datagram forwarding path).
///
/// Assertions are against values this test *set*, not against a second call to
/// the same production getter the adapter itself calls: a mirror comparison of
/// the form `view.x(p) == peer.x()` reduces to `f(x) == f(x)` and is blind to
/// anything the two sides share. The parity loop at the end is the secondary
/// check, not the primary one.
#[test]
fn test_seam_routing_view_reads_match_live_peer_state() {
    use crate::proto::routing::RoutingView;

    let mut node = make_node();
    let my_addr = *node.node_addr();
    let (near, far, dest) = seam_two_equidistant_peers(&mut node);

    // Make the two peers differ on every predicate, in opposite directions, so
    // no constant in either direction can satisfy the assertions below.
    seam_set_filter(&mut node, &near, &dest);
    node.get_peer_mut(&far).unwrap().mark_reconnecting();
    // Both cost factors off the multiplicative identity: with etx pinned at 1.0
    // a cost that reads only the latency half is indistinguishable from the
    // real one, and this assertion would be blind to it.
    seam_set_cost(&mut node, &near, 2.0, 50_000); // 2.0 * (1.0 + 0.5) -> 3.0

    // A short-TTL entry, so the expiry arm of `cached_coords` is exercised and
    // not only the present/absent arms.
    let stale = make_node_addr(201);
    let stale_coords = TreeCoordinate::from_addrs(vec![stale, near, my_addr]).unwrap();
    node.coord_cache_mut()
        .insert_with_ttl(stale, stale_coords, 1_000_000, 10);

    let unknown = make_node_addr(202);
    let near_coords = TreeCoordinate::from_addrs(vec![near, my_addr]).unwrap();
    let far_coords = TreeCoordinate::from_addrs(vec![far, dest, near, my_addr]).unwrap();

    let view = NodeRoutingView {
        coord_cache: node.coord_cache(),
        peers: &node.peers,
        tree_state: node.tree_state(),
        congested: true,
    };

    // Enumeration: every peer exactly once, and no peer the map does not hold.
    // A visitor that skips *some* peers is order-nondeterministic through
    // `find_next_hop`; one that repeats a peer is invisible there entirely.
    let mut handles = Vec::new();
    view.for_each_peer(|peer| handles.push(peer));
    assert_eq!(handles.len(), 2, "each peer visited exactly once");
    let visited: HashSet<NodeAddr> = handles.iter().map(|p| view.peer_addr(*p)).collect();
    assert_eq!(
        visited,
        node.peers.keys().copied().collect::<HashSet<_>>(),
        "enumeration must cover exactly the live peer map"
    );

    let near_h = *handles
        .iter()
        .find(|p| view.peer_addr(**p) == near)
        .unwrap();
    let far_h = *handles.iter().find(|p| view.peer_addr(**p) == far).unwrap();

    // peer_may_reach: near holds a filter containing dest; far holds none.
    assert!(view.peer_may_reach(near_h, &dest));
    assert!(!view.peer_may_reach(far_h, &dest));
    assert!(
        !view.peer_may_reach(near_h, &unknown),
        "the filter is per-destination"
    );

    // peer_can_send: far was marked reconnecting.
    assert!(view.peer_can_send(near_h));
    assert!(!view.peer_can_send(far_h));

    // peer_link_cost: etx 2.0 * (1.0 + 50ms/100) for near; far has no RTT
    // sample, so it takes the optimistic 1.0 default. Neither factor is at the
    // identity, so a cost reading only one half of the product is caught.
    assert_eq!(view.peer_link_cost(near_h), 3.0);
    assert_eq!(view.peer_link_cost(far_h), 1.0);

    // peer_coords: each peer's own coordinates, as the fixture installed them.
    assert_eq!(view.peer_coords(near_h), Some(&near_coords));
    assert_eq!(view.peer_coords(far_h), Some(&far_coords));

    // is_congested, both directions: a constant in either direction is wrong,
    // and the false-negative direction silently drops the ECN CE mark.
    assert!(view.is_congested(&near));
    let calm = NodeRoutingView {
        coord_cache: node.coord_cache(),
        peers: &node.peers,
        tree_state: node.tree_state(),
        congested: false,
    };
    assert!(!calm.is_congested(&near));

    // cached_coords: present, absent, and expired. The expiry arm is what
    // decides PathBroken-vs-CoordsRequired for a route that has gone away.
    let now_ms = seam_now_ms();
    assert_eq!(
        view.cached_coords(&dest, now_ms).as_ref(),
        node.coord_cache().get(&dest, now_ms)
    );
    assert!(view.cached_coords(&unknown, now_ms).is_none());
    assert!(
        view.cached_coords(&stale, 1_000_005).is_some(),
        "within TTL"
    );
    assert!(view.cached_coords(&stale, 1_000_100).is_none(), "past TTL");

    // Secondary parity sweep over the live peer map.
    for peer in &handles {
        let addr = view.peer_addr(*peer);
        let live = node.peers.get(&addr).unwrap();
        assert_eq!(view.peer_may_reach(*peer, &dest), live.may_reach(&dest));
        assert_eq!(view.peer_can_send(*peer), live.can_send());
        assert_eq!(view.peer_link_cost(*peer), live.link_cost());
        assert_eq!(
            view.peer_coords(*peer),
            node.tree_state().peer_coords(&addr)
        );
    }
}
