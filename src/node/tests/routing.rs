//! Routing integration tests.
//!
//! Tests the full Node::find_next_hop() routing logic including bloom
//! filter priority, greedy tree routing, and tie-breaking.

use super::*;
use crate::bloom::BloomFilter;
use crate::tree::{ParentDeclaration, TreeCoordinate};
use spanning_tree::{
    cleanup_nodes, drain_all_packets, generate_random_edges, initiate_handshake, make_test_node,
    run_tree_test, verify_tree_convergence, TestNode,
};
use std::collections::HashSet;

// === Local delivery ===

#[test]
fn test_routing_local_delivery() {
    let node = make_node();
    let my_addr = *node.node_addr();
    assert!(node.find_next_hop(&my_addr).is_none());
}

// === Direct peer ===

#[test]
fn test_routing_direct_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let peer_addr = *identity.node_addr();
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();

    let result = node.find_next_hop(&peer_addr);
    assert!(result.is_some());
    assert_eq!(result.unwrap().node_addr(), &peer_addr);
}

// === No route ===

#[test]
fn test_routing_unknown_destination() {
    let node = make_node();
    let unknown = make_node_addr(99);
    assert!(node.find_next_hop(&unknown).is_none());
}

// === Bloom filter priority ===

#[test]
fn test_routing_bloom_filter_hit() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // Create two peers
    let link_id1 = LinkId::new(1);
    let (conn1, id1) = make_completed_connection(&mut node, link_id1, transport_id, 1000);
    let peer1_addr = *id1.node_addr();
    node.add_connection(conn1).unwrap();
    node.promote_connection(link_id1, id1, 2000).unwrap();

    let link_id2 = LinkId::new(2);
    let (conn2, id2) = make_completed_connection(&mut node, link_id2, transport_id, 1000);
    let peer2_addr = *id2.node_addr();
    node.add_connection(conn2).unwrap();
    node.promote_connection(link_id2, id2, 2000).unwrap();

    // Destination not directly connected
    let dest = make_node_addr(99);

    // Add dest to peer1's bloom filter only
    let peer1 = node.get_peer_mut(&peer1_addr).unwrap();
    let mut filter = BloomFilter::new();
    filter.insert(&dest);
    peer1.update_filter(filter, 1, 3000);

    // Should route through peer1 (bloom filter hit)
    let result = node.find_next_hop(&dest);
    assert!(result.is_some());
    assert_eq!(result.unwrap().node_addr(), &peer1_addr);

    // Peer2 should NOT be selected (no filter hit)
    assert_ne!(result.unwrap().node_addr(), &peer2_addr);
}

#[test]
fn test_routing_bloom_filter_multiple_hits_tiebreak() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // Create three peers
    let mut peer_addrs = Vec::new();
    for i in 1..=3 {
        let link_id = LinkId::new(i);
        let (conn, id) = make_completed_connection(&mut node, link_id, transport_id, 1000);
        let addr = *id.node_addr();
        peer_addrs.push(addr);
        node.add_connection(conn).unwrap();
        node.promote_connection(link_id, id, 2000).unwrap();
    }

    let dest = make_node_addr(99);

    // Add dest to ALL peers' bloom filters
    for &addr in &peer_addrs {
        let peer = node.get_peer_mut(&addr).unwrap();
        let mut filter = BloomFilter::new();
        filter.insert(&dest);
        peer.update_filter(filter, 1, 3000);
    }

    // All peers have equal link_cost (1.0) and no tree coords set,
    // so tree distance is usize::MAX for all. Tie-break by smallest node_addr.
    let result = node.find_next_hop(&dest);
    assert!(result.is_some());

    let smallest_addr = peer_addrs.iter().min().unwrap();
    assert_eq!(result.unwrap().node_addr(), smallest_addr);
}

// === Greedy tree routing ===

#[test]
fn test_routing_tree_fallback() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let my_addr = *node.node_addr();

    // Create a peer
    let link_id = LinkId::new(1);
    let (conn, id) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let peer_addr = *id.node_addr();
    node.add_connection(conn).unwrap();
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
    let dest_coords =
        TreeCoordinate::from_addrs(vec![dest, peer_addr, my_addr]).unwrap();

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

#[test]
fn test_routing_tree_no_coords_in_cache() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // Create a peer
    let link_id = LinkId::new(1);
    let (conn, id) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, id, 2000).unwrap();

    // Destination not in bloom filters and not in coord cache
    let dest = make_node_addr(99);
    assert!(node.find_next_hop(&dest).is_none());
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
        assert_eq!(
            *tn.node.tree_state().root(),
            root,
            "Tree not converged"
        );
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
    let hop = nodes[0].node.find_next_hop(&node3_addr);
    assert!(hop.is_some(), "Node 0 should find route to node 3");
    let node1_addr = *nodes[1].node.node_addr();
    assert_eq!(
        hop.unwrap().node_addr(),
        &node1_addr,
        "Node 0's next hop to node 3 should be node 1"
    );

    // Node 3 should route toward node 0 via node 2.
    let hop = nodes[3].node.find_next_hop(&node0_addr);
    assert!(hop.is_some(), "Node 3 should find route to node 0");
    let node2_addr = *nodes[2].node.node_addr();
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

    // Create a destination beyond the network
    let dest = make_node_addr(99);

    // Add dest to peer 2's bloom filter (from node 0's perspective)
    let peer2_addr = *nodes[2].node.node_addr();
    let peer2 = nodes[0].node.get_peer_mut(&peer2_addr).unwrap();
    let mut filter = BloomFilter::new();
    filter.insert(&dest);
    peer2.update_filter(filter, 100, 50000);

    // Even though we could use tree routing (if coords were cached),
    // the bloom filter hit should be preferred.
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
    nodes: &[TestNode],
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
    const NUM_NODES: usize = 100;
    const TARGET_EDGES: usize = 250;
    const SEED: u64 = 42;

    let edges = generate_random_edges(NUM_NODES, TARGET_EDGES, SEED);
    let mut nodes = run_tree_test(NUM_NODES, &edges, false).await;
    verify_tree_convergence(&nodes);

    // Populate coord caches: every node learns every other node's coordinates.
    // In production this happens via SessionSetup/LookupResponse; here we
    // inject them directly so routing can make progress-based decisions.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // Collect all (addr, coords) pairs first to avoid borrow issues
    let all_coords: Vec<(NodeAddr, TreeCoordinate)> = nodes
        .iter()
        .map(|tn| (*tn.node.node_addr(), tn.node.tree_state().my_coords().clone()))
        .collect();

    for node in &mut nodes {
        for &(ref addr, ref coords) in &all_coords {
            if addr != node.node.node_addr() {
                node.node.coord_cache_mut().insert(*addr, coords.clone(), now_ms);
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

            match simulate_forwarding(&nodes, &addr_index, src, dst) {
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

    eprintln!(
        "\n  === Routing Reachability ({} nodes) ===",
        NUM_NODES
    );
    eprintln!(
        "  Pairs tested: {} | Delivered: {} | Failed: {} | Loops: {}",
        total_pairs,
        delivered,
        failures.len(),
        loops.len()
    );
    eprintln!(
        "  Hops: avg={:.1} max={}",
        avg_hops, max_hops
    );

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

