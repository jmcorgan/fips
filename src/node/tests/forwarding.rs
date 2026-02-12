//! SessionDatagram forwarding tests.
//!
//! Tests for the handle_session_datagram handler including decode errors,
//! hop limit enforcement, local delivery, coordinate cache warming, and
//! multi-hop forwarding through live node topologies.

use super::*;
use crate::protocol::{DataPacket, SessionAck, SessionDatagram, SessionSetup};
use crate::tree::TreeCoordinate;
use spanning_tree::{
    cleanup_nodes, process_available_packets, run_tree_test, verify_tree_convergence,
    TestNode,
};

// ============================================================================
// Unit Tests
// ============================================================================

// --- Decode errors ---

#[tokio::test]
async fn test_forwarding_decode_error() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    // Too-short payload: should log error and return without panic
    node.handle_session_datagram(&from, &[0x00; 5]).await;
}

// --- Hop limit ---

#[tokio::test]
async fn test_forwarding_hop_limit_exhausted() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let src = make_node_addr(0x01);
    let dest = make_node_addr(0x02);
    let dg = SessionDatagram::new(src, dest, vec![0x10, 0x00, 0x00, 0x00])
        .with_hop_limit(0);
    let encoded = dg.encode();
    // Dispatch with payload after msg_type byte
    node.handle_session_datagram(&from, &encoded[1..]).await;
    // No panic, no send (node has no peers)
}

#[tokio::test]
async fn test_forwarding_hop_limit_one_drops_at_transit() {
    // hop_limit=1 means after decrement it becomes 0 — the datagram can
    // still be delivered this hop but would be dropped at the next.
    // decrement_hop_limit returns true (1 > 0), so the handler proceeds.
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let my_addr = *node.node_addr();
    let src = make_node_addr(0x01);
    let dg = SessionDatagram::new(src, my_addr, vec![0x10, 0x00, 0x00, 0x00])
        .with_hop_limit(1);
    let encoded = dg.encode();
    // Should succeed — hop_limit=1 decrements to 0 but packet is still processed
    node.handle_session_datagram(&from, &encoded[1..]).await;
}

// --- Local delivery ---

#[tokio::test]
async fn test_forwarding_local_delivery() {
    let mut node = make_node();
    let my_addr = *node.node_addr();
    let from = make_node_addr(0xAA);
    let dg = SessionDatagram::new(from, my_addr, vec![0x10, 0x00, 0x00, 0x00]);
    let encoded = dg.encode();
    // Should detect local delivery and return without forwarding
    node.handle_session_datagram(&from, &encoded[1..]).await;
}

// --- Direct peer forwarding ---

#[tokio::test]
async fn test_forwarding_direct_peer() {
    // Set up a node with one peer. Send a datagram destined for that peer.
    // The handler should forward it directly.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    // Build a datagram from some external source destined for node 1
    let external_src = make_node_addr(0xEE);
    let dg = SessionDatagram::new(external_src, node1_addr, vec![0x10, 0x00, 0x00, 0x00]);
    let encoded = dg.encode();

    // Handle on node 0: should forward to node 1 (direct peer)
    nodes[0]
        .node
        .handle_session_datagram(&node0_addr, &encoded[1..])
        .await;

    // Process packets — node 1 should receive the forwarded datagram
    tokio::time::sleep(Duration::from_millis(50)).await;
    let count = process_available_packets(&mut nodes).await;
    assert!(count > 0, "Expected forwarded packet to arrive at node 1");

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Coordinate Cache Warming Tests
// ============================================================================

#[tokio::test]
async fn test_coord_cache_warming_session_setup() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let src_addr = make_node_addr(0x01);
    let dest_addr = make_node_addr(0x02);
    let root_addr = make_node_addr(0xF0);

    let src_coords = TreeCoordinate::from_addrs(vec![src_addr, root_addr]).unwrap();
    let dest_coords = TreeCoordinate::from_addrs(vec![dest_addr, root_addr]).unwrap();

    let setup = SessionSetup::new(src_coords.clone(), dest_coords.clone());
    let setup_payload = setup.encode();

    let dg = SessionDatagram::new(src_addr, dest_addr, setup_payload);
    let encoded = dg.encode();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Before: cache is empty
    assert!(node.coord_cache().get(&src_addr, now_ms).is_none());
    assert!(node.coord_cache().get(&dest_addr, now_ms).is_none());

    // Handle the datagram (will be local delivery or no-route, but cache warming
    // happens before routing decision)
    node.handle_session_datagram(&from, &encoded[1..]).await;

    // After: both src and dest coords should be cached
    let cached_src = node.coord_cache().get(&src_addr, now_ms);
    let cached_dest = node.coord_cache().get(&dest_addr, now_ms);
    assert!(cached_src.is_some(), "src_addr coords not cached");
    assert!(cached_dest.is_some(), "dest_addr coords not cached");

    // Verify the cached coords have the right root
    let cached_src = cached_src.unwrap();
    let cached_dest = cached_dest.unwrap();
    assert_eq!(cached_src.root_id(), &root_addr);
    assert_eq!(cached_dest.root_id(), &root_addr);
}

#[tokio::test]
async fn test_coord_cache_warming_session_ack() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let src_addr = make_node_addr(0x01);
    let dest_addr = make_node_addr(0x02);
    let root_addr = make_node_addr(0xF0);

    let src_coords = TreeCoordinate::from_addrs(vec![src_addr, root_addr]).unwrap();

    let ack = SessionAck::new(src_coords.clone());
    let ack_payload = ack.encode();

    let dg = SessionDatagram::new(src_addr, dest_addr, ack_payload);
    let encoded = dg.encode();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    assert!(node.coord_cache().get(&src_addr, now_ms).is_none());

    node.handle_session_datagram(&from, &encoded[1..]).await;

    // SessionAck only caches src_coords (the acknowledger's coords)
    let cached_src = node.coord_cache().get(&src_addr, now_ms);
    assert!(cached_src.is_some(), "src_addr coords not cached from SessionAck");
    assert_eq!(cached_src.unwrap().root_id(), &root_addr);

    // dest_addr should NOT be cached (SessionAck doesn't carry dest coords)
    assert!(node.coord_cache().get(&dest_addr, now_ms).is_none());
}

#[tokio::test]
async fn test_coord_cache_warming_data_packet_with_coords() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let src_addr = make_node_addr(0x01);
    let dest_addr = make_node_addr(0x02);
    let root_addr = make_node_addr(0xF0);

    let src_coords = TreeCoordinate::from_addrs(vec![src_addr, root_addr]).unwrap();
    let dest_coords = TreeCoordinate::from_addrs(vec![dest_addr, root_addr]).unwrap();

    let data = DataPacket::new(vec![1, 2, 3, 4])
        .with_coords(src_coords.clone(), dest_coords.clone());
    let data_payload = data.encode();

    let dg = SessionDatagram::new(src_addr, dest_addr, data_payload);
    let encoded = dg.encode();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    assert!(node.coord_cache().get(&src_addr, now_ms).is_none());
    assert!(node.coord_cache().get(&dest_addr, now_ms).is_none());

    node.handle_session_datagram(&from, &encoded[1..]).await;

    assert!(
        node.coord_cache().get(&src_addr, now_ms).is_some(),
        "src coords not cached from DataPacket"
    );
    assert!(
        node.coord_cache().get(&dest_addr, now_ms).is_some(),
        "dest coords not cached from DataPacket"
    );
}

#[tokio::test]
async fn test_coord_cache_warming_opaque_data_packet() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let src_addr = make_node_addr(0x01);
    let dest_addr = make_node_addr(0x02);

    // DataPacket without COORDS_PRESENT — no coords to cache
    let data = DataPacket::new(vec![1, 2, 3, 4]);
    let data_payload = data.encode();

    let dg = SessionDatagram::new(src_addr, dest_addr, data_payload);
    let encoded = dg.encode();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    node.handle_session_datagram(&from, &encoded[1..]).await;

    assert!(
        node.coord_cache().get(&src_addr, now_ms).is_none(),
        "Should not cache coords from opaque DataPacket"
    );
    assert!(
        node.coord_cache().get(&dest_addr, now_ms).is_none(),
        "Should not cache coords from opaque DataPacket"
    );
}

// ============================================================================
// Integration Tests
// ============================================================================

/// Helper: populate all coordinate caches across a set of test nodes.
fn populate_all_coord_caches(nodes: &mut [TestNode]) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Collect all coords first to avoid borrow conflicts
    let all_coords: Vec<(NodeAddr, TreeCoordinate)> = nodes
        .iter()
        .map(|tn| {
            (
                *tn.node.node_addr(),
                tn.node.tree_state().my_coords().clone(),
            )
        })
        .collect();

    for tn in nodes.iter_mut() {
        for (addr, coords) in &all_coords {
            if addr != tn.node.node_addr() {
                tn.node
                    .coord_cache_mut()
                    .insert(*addr, coords.clone(), now_ms);
            }
        }
    }
}

#[tokio::test]
async fn test_forwarding_single_hop() {
    // 3-node chain: 0 -- 1 -- 2
    // Send datagram from node 0 destined for node 2.
    // Node 1 should forward it.
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();

    // Build a SessionDatagram from node 0 to node 2
    let dg = SessionDatagram::new(
        node0_addr,
        node2_addr,
        vec![0x10, 0x00, 0x04, 0x00, 1, 2, 3, 4],
    );
    let encoded = dg.encode();

    // Send from node 0 to node 1 (the first hop)
    nodes[0]
        .node
        .send_encrypted_link_message(&node1_addr, &encoded)
        .await
        .unwrap();

    // Process: node 1 receives, decrypts, dispatches to handler, forwards to node 2
    tokio::time::sleep(Duration::from_millis(50)).await;
    process_available_packets(&mut nodes).await;

    // Give time for the forwarded packet to arrive at node 2
    tokio::time::sleep(Duration::from_millis(50)).await;
    let count = process_available_packets(&mut nodes).await;

    // Node 2 should have received the forwarded datagram
    // (it sees dest_addr == self, treats as local delivery)
    // We verify the chain completed by checking packets were processed.
    assert!(count > 0, "Expected forwarded packet at node 2");

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_forwarding_multi_hop() {
    // 5-node chain: 0 -- 1 -- 2 -- 3 -- 4
    // Send datagram from node 0 destined for node 4.
    let edges = vec![(0, 1), (1, 2), (2, 3), (3, 4)];
    let mut nodes = run_tree_test(5, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node4_addr = *nodes[4].node.node_addr();

    // Build a SessionDatagram with enough hop_limit for 4 hops
    let dg = SessionDatagram::new(
        node0_addr,
        node4_addr,
        vec![0x10, 0x00, 0x04, 0x00, 1, 2, 3, 4],
    );
    let encoded = dg.encode();

    // Inject at node 0 → node 1
    nodes[0]
        .node
        .send_encrypted_link_message(&node1_addr, &encoded)
        .await
        .unwrap();

    // Process multiple rounds to let the datagram traverse the chain
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    // Verify no crashes — the datagram should have traversed 1→2→3→4
    // and been delivered locally at node 4.
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_forwarding_hop_limit_prevents_infinite_loops() {
    // 3-node chain: 0 -- 1 -- 2
    // Send a datagram with hop_limit=1. It should be forwarded by node 1
    // (decrement to 0) and delivered at node 2 (local delivery). If node 2
    // tried to forward further, the 0 hop_limit would prevent it.
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();

    let dg = SessionDatagram::new(
        node0_addr,
        node2_addr,
        vec![0x10, 0x00, 0x04, 0x00, 1, 2, 3, 4],
    )
    .with_hop_limit(2); // Enough for 0→1 (decrement to 1) and 1→2 (decrement to 0, local delivery)

    let encoded = dg.encode();

    nodes[0]
        .node
        .send_encrypted_link_message(&node1_addr, &encoded)
        .await
        .unwrap();

    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    // No panic, no infinite loop
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_forwarding_no_route_generates_error() {
    // 2-node network: 0 -- 1
    // Node 0 receives a datagram from node 1 destined for unknown node.
    // Node 0 should generate CoordsRequired back to node 1.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let unknown_dest = make_node_addr(0xFF);

    // Node 1 sends a datagram to unknown dest via node 0
    let dg = SessionDatagram::new(node1_addr, unknown_dest, vec![0x10, 0x00, 0x00, 0x00]);
    let encoded = dg.encode();

    // Inject at node 1 → node 0
    nodes[1]
        .node
        .send_encrypted_link_message(&node0_addr, &encoded)
        .await
        .unwrap();

    // Process: node 0 receives, can't route to unknown_dest, sends error back to node 1
    tokio::time::sleep(Duration::from_millis(50)).await;
    process_available_packets(&mut nodes).await;

    // Process the error signal arriving at node 1
    tokio::time::sleep(Duration::from_millis(50)).await;
    let count = process_available_packets(&mut nodes).await;
    assert!(count > 0, "Expected error signal to arrive at node 1");

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_forwarding_with_cache_warming_enables_routing() {
    // 4-node chain: 0 -- 1 -- 2 -- 3
    // Initially, only populate coord caches at node 0.
    // Send a SessionSetup from node 0 to node 3.
    // As it traverses 1 and 2, those nodes should cache coordinates from the
    // SessionSetup. Then verify the caches were warmed.
    let edges = vec![(0, 1), (1, 2), (2, 3)];
    let mut nodes = run_tree_test(4, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let _node2_addr = *nodes[2].node.node_addr();
    let node3_addr = *nodes[3].node.node_addr();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Only populate node 0's cache with all coords (the source knows where to send)
    let all_coords: Vec<(NodeAddr, TreeCoordinate)> = nodes
        .iter()
        .map(|tn| {
            (
                *tn.node.node_addr(),
                tn.node.tree_state().my_coords().clone(),
            )
        })
        .collect();

    // Node 0 gets full cache
    for (addr, coords) in &all_coords {
        if addr != nodes[0].node.node_addr() {
            nodes[0]
                .node
                .coord_cache_mut()
                .insert(*addr, coords.clone(), now_ms);
        }
    }

    // Nodes 1 and 2 only get their direct peers' coords (from tree state)
    // but NOT node 0 or node 3's coords (the endpoints)
    // Actually, they need bloom filter hits to route, so let's also ensure
    // bloom filters are converged (which they should be from run_tree_test).

    // But nodes 1 and 2 need cached coords to make loop-free forwarding
    // decisions. Without coords, find_next_hop returns None.
    // This is exactly what the SessionSetup cache warming solves!
    // Populate enough so nodes can route to their adjacent peers,
    // but NOT the distant endpoint coords.
    for i in 0..4 {
        for j in 0..4 {
            if i != j {
                // Give each node coords for its direct peers only
                let j_addr = *nodes[j].node.node_addr();
                if nodes[i].node.get_peer(&j_addr).is_some() {
                    let coords = all_coords.iter().find(|(a, _)| a == &j_addr).unwrap().1.clone();
                    nodes[i].node.coord_cache_mut().insert(j_addr, coords, now_ms);
                }
            }
        }
    }

    // Build SessionSetup with real coordinates
    let src_coords = nodes[0].node.tree_state().my_coords().clone();
    let dest_coords = nodes[3].node.tree_state().my_coords().clone();
    let setup = SessionSetup::new(src_coords, dest_coords);
    let setup_payload = setup.encode();

    let dg = SessionDatagram::new(node0_addr, node3_addr, setup_payload);
    let encoded = dg.encode();

    // Inject: node 0 → node 1
    nodes[0]
        .node
        .send_encrypted_link_message(&node1_addr, &encoded)
        .await
        .unwrap();

    // Process multiple rounds for the datagram to traverse 1→2→3
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    // Verify cache warming: nodes 1 and 2 should now have cached coords
    // for both node 0 and node 3 (from the SessionSetup)
    let cached_0_at_1 = nodes[1].node.coord_cache().get(&node0_addr, now_ms);
    let cached_3_at_1 = nodes[1].node.coord_cache().get(&node3_addr, now_ms);
    assert!(
        cached_0_at_1.is_some(),
        "Node 1 should have cached node 0's coords from SessionSetup"
    );
    assert!(
        cached_3_at_1.is_some(),
        "Node 1 should have cached node 3's coords from SessionSetup"
    );

    let cached_0_at_2 = nodes[2].node.coord_cache().get(&node0_addr, now_ms);
    let cached_3_at_2 = nodes[2].node.coord_cache().get(&node3_addr, now_ms);
    assert!(
        cached_0_at_2.is_some(),
        "Node 2 should have cached node 0's coords from SessionSetup"
    );
    assert!(
        cached_3_at_2.is_some(),
        "Node 2 should have cached node 3's coords from SessionSetup"
    );

    cleanup_nodes(&mut nodes).await;
}
