//! SessionDatagram forwarding tests.
//!
//! Tests for the handle_session_datagram handler including decode errors,
//! TTL enforcement, local delivery, coordinate cache warming, and
//! multi-hop forwarding through live node topologies.

use super::*;
use crate::node::session_wire::{FSP_FLAG_CP, build_fsp_header};
use crate::protocol::{SessionAck, SessionDatagram, SessionSetup, encode_coords};
use crate::tree::TreeCoordinate;
use spanning_tree::{
    TestNode, cleanup_nodes, process_available_packets, run_tree_test, verify_tree_convergence,
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
    node.handle_session_datagram(&from, &[0x00; 5], false).await;
}

// --- TTL ---

#[tokio::test]
async fn test_forwarding_hop_limit_exhausted() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let src = make_node_addr(0x01);
    let dest = make_node_addr(0x02);
    let dg = SessionDatagram::new(src, dest, vec![0x10, 0x00, 0x00, 0x00]).with_ttl(0);
    let encoded = dg.encode();
    // Dispatch with payload after msg_type byte
    node.handle_session_datagram(&from, &encoded[1..], false)
        .await;
    // No panic, no send (node has no peers)
}

#[tokio::test]
async fn test_forwarding_hop_limit_one_drops_at_transit() {
    // ttl=1 means after decrement it becomes 0 — the datagram can
    // still be delivered this hop but would be dropped at the next.
    // decrement_ttl returns true (1 > 0), so the handler proceeds.
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let my_addr = *node.node_addr();
    let src = make_node_addr(0x01);
    let dg = SessionDatagram::new(src, my_addr, vec![0x10, 0x00, 0x00, 0x00]).with_ttl(1);
    let encoded = dg.encode();
    // Should succeed — ttl=1 decrements to 0 but packet is still processed
    node.handle_session_datagram(&from, &encoded[1..], false)
        .await;
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
    node.handle_session_datagram(&from, &encoded[1..], false)
        .await;
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
        .handle_session_datagram(&node0_addr, &encoded[1..], false)
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
    node.handle_session_datagram(&from, &encoded[1..], false)
        .await;

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
    let dest_coords = TreeCoordinate::from_addrs(vec![dest_addr, root_addr]).unwrap();

    let ack = SessionAck::new(src_coords.clone(), dest_coords.clone());
    let ack_payload = ack.encode();

    let dg = SessionDatagram::new(src_addr, dest_addr, ack_payload);
    let encoded = dg.encode();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    assert!(node.coord_cache().get(&src_addr, now_ms).is_none());
    assert!(node.coord_cache().get(&dest_addr, now_ms).is_none());

    node.handle_session_datagram(&from, &encoded[1..], false)
        .await;

    // SessionAck caches both src_coords and dest_coords
    let cached_src = node.coord_cache().get(&src_addr, now_ms);
    assert!(
        cached_src.is_some(),
        "src_addr coords not cached from SessionAck"
    );
    assert_eq!(cached_src.unwrap().root_id(), &root_addr);

    let cached_dest = node.coord_cache().get(&dest_addr, now_ms);
    assert!(
        cached_dest.is_some(),
        "dest_addr coords not cached from SessionAck"
    );
    assert_eq!(cached_dest.unwrap().root_id(), &root_addr);
}

#[tokio::test]
async fn test_coord_cache_warming_encrypted_msg_with_coords() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let src_addr = make_node_addr(0x01);
    let dest_addr = make_node_addr(0x02);
    let root_addr = make_node_addr(0xF0);

    let src_coords = TreeCoordinate::from_addrs(vec![src_addr, root_addr]).unwrap();
    let dest_coords = TreeCoordinate::from_addrs(vec![dest_addr, root_addr]).unwrap();

    // Build FSP encrypted message with CP flag: header(12) + coords + fake_ciphertext
    let header = build_fsp_header(0, FSP_FLAG_CP, 20);
    let mut data_payload = Vec::new();
    data_payload.extend_from_slice(&header);
    encode_coords(&src_coords, &mut data_payload);
    encode_coords(&dest_coords, &mut data_payload);
    data_payload.extend_from_slice(&[0xCC; 36]); // fake ciphertext (20 payload + 16 tag)

    let dg = SessionDatagram::new(src_addr, dest_addr, data_payload);
    let encoded = dg.encode();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    assert!(node.coord_cache().get(&src_addr, now_ms).is_none());
    assert!(node.coord_cache().get(&dest_addr, now_ms).is_none());

    node.handle_session_datagram(&from, &encoded[1..], false)
        .await;

    assert!(
        node.coord_cache().get(&src_addr, now_ms).is_some(),
        "src coords not cached from encrypted message"
    );
    assert!(
        node.coord_cache().get(&dest_addr, now_ms).is_some(),
        "dest coords not cached from encrypted message"
    );
}

#[tokio::test]
async fn test_coord_cache_warming_encrypted_msg_no_coords() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let src_addr = make_node_addr(0x01);
    let dest_addr = make_node_addr(0x02);

    // Build FSP encrypted message without CP flag: header(12) + fake_ciphertext
    let header = build_fsp_header(0, 0, 20);
    let mut data_payload = Vec::new();
    data_payload.extend_from_slice(&header);
    data_payload.extend_from_slice(&[0xCC; 36]); // fake ciphertext (20 payload + 16 tag)

    let dg = SessionDatagram::new(src_addr, dest_addr, data_payload);
    let encoded = dg.encode();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    node.handle_session_datagram(&from, &encoded[1..], false)
        .await;

    assert!(
        node.coord_cache().get(&src_addr, now_ms).is_none(),
        "Should not cache coords from message without CP flag"
    );
    assert!(
        node.coord_cache().get(&dest_addr, now_ms).is_none(),
        "Should not cache coords from message without CP flag"
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

    // Build a SessionDatagram with enough TTL for 4 hops
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
    // Send a datagram with ttl=1. It should be forwarded by node 1
    // (decrement to 0) and delivered at node 2 (local delivery). If node 2
    // tried to forward further, the 0 ttl would prevent it.
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
    .with_ttl(2); // Enough for 0->1 (decrement to 1) and 1->2 (decrement to 0, local delivery)

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
                    let coords = all_coords
                        .iter()
                        .find(|(a, _)| a == &j_addr)
                        .unwrap()
                        .1
                        .clone();
                    nodes[i]
                        .node
                        .coord_cache_mut()
                        .insert(j_addr, coords, now_ms);
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

// ============================================================================
// ECN Tests
// ============================================================================

use crate::node::TransportDropState;
use crate::node::handlers::session::mark_ipv6_ecn_ce;
use crate::transport::TransportId;

/// Build a minimal IPv6 header (40 bytes) with specified ECN bits.
fn make_ipv6_packet_with_ecn(ecn: u8) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    let tc = ecn; // DSCP=0, ECN=ecn
    pkt[0] = 0x60 | (tc >> 4);
    pkt[1] = tc << 4;
    pkt
}

/// Extract ECN bits from an IPv6 packet.
fn read_ecn(pkt: &[u8]) -> u8 {
    let tc = ((pkt[0] & 0x0F) << 4) | (pkt[1] >> 4);
    tc & 0x03
}

#[test]
fn test_mark_ecn_ce_on_ect0() {
    let mut pkt = make_ipv6_packet_with_ecn(0b10);
    assert_eq!(read_ecn(&pkt), 0b10);
    mark_ipv6_ecn_ce(&mut pkt);
    assert_eq!(read_ecn(&pkt), 0b11);
}

#[test]
fn test_mark_ecn_ce_on_ect1() {
    let mut pkt = make_ipv6_packet_with_ecn(0b01);
    assert_eq!(read_ecn(&pkt), 0b01);
    mark_ipv6_ecn_ce(&mut pkt);
    assert_eq!(read_ecn(&pkt), 0b11);
}

#[test]
fn test_mark_ecn_ce_on_not_ect() {
    let mut pkt = make_ipv6_packet_with_ecn(0b00);
    mark_ipv6_ecn_ce(&mut pkt);
    assert_eq!(read_ecn(&pkt), 0b00);
}

#[test]
fn test_mark_ecn_ce_already_ce() {
    let mut pkt = make_ipv6_packet_with_ecn(0b11);
    mark_ipv6_ecn_ce(&mut pkt);
    assert_eq!(read_ecn(&pkt), 0b11);
}

#[test]
fn test_mark_ecn_ce_preserves_dscp_and_flow_label() {
    let mut pkt = vec![0u8; 40];
    // DSCP=0b101100 (46=EF), ECN=ECT(0)=0b10 → TC=0xB2
    let tc: u8 = 0xB2;
    pkt[0] = 0x60 | (tc >> 4); // 0x6B
    pkt[1] = (tc << 4) | 0x0A; // 0x2A (flow label high nibble = 0xA)
    pkt[2] = 0xBC;
    pkt[3] = 0xDE;

    mark_ipv6_ecn_ce(&mut pkt);

    let new_tc = ((pkt[0] & 0x0F) << 4) | (pkt[1] >> 4);
    assert_eq!(new_tc, 0xB3, "TC should be 0xB3 (DSCP preserved, ECN=CE)");
    assert_eq!(pkt[0] >> 4, 6, "Version nibble preserved");
    assert_eq!(pkt[1] & 0x0F, 0x0A, "Flow label high nibble preserved");
    assert_eq!(pkt[2], 0xBC, "Flow label byte 2 preserved");
    assert_eq!(pkt[3], 0xDE, "Flow label byte 3 preserved");
}

#[test]
fn test_mark_ecn_ce_short_packet() {
    let mut pkt = vec![0x60];
    mark_ipv6_ecn_ce(&mut pkt);
    assert_eq!(pkt, vec![0x60]);

    let mut empty: Vec<u8> = vec![];
    mark_ipv6_ecn_ce(&mut empty);
    assert!(empty.is_empty());
}

#[tokio::test]
async fn test_ce_relay_through_forwarding() {
    // 3-node chain: 0 -- 1 -- 2
    // Send a datagram with CE set from node 0 to node 1.
    // Node 1 should relay CE to node 2.
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();

    // Record ecn_ce_count at node 2 before
    let ce_before = nodes[2]
        .node
        .get_peer(&node1_addr)
        .and_then(|p| p.mmp())
        .map(|m| m.receiver.ecn_ce_count())
        .unwrap_or(0);

    // Build a SessionDatagram from node 0 to node 2
    let dg = SessionDatagram::new(
        node0_addr,
        node2_addr,
        vec![0x10, 0x00, 0x04, 0x00, 1, 2, 3, 4],
    );
    let encoded = dg.encode();

    // Send from node 0 to node 1 with CE flag set
    nodes[0]
        .node
        .send_encrypted_link_message_with_ce(&node1_addr, &encoded, true)
        .await
        .unwrap();

    // Process: node 1 receives (CE set), forwards to node 2 (CE relayed)
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    // Node 2's link-layer MMP should have received a CE-flagged frame from node 1
    let ce_after = nodes[2]
        .node
        .get_peer(&node1_addr)
        .and_then(|p| p.mmp())
        .map(|m| m.receiver.ecn_ce_count())
        .unwrap_or(0);

    assert!(
        ce_after > ce_before,
        "Node 2 should see CE flag relayed from node 1 (before={ce_before}, after={ce_after})"
    );

    cleanup_nodes(&mut nodes).await;
}

#[test]
fn test_detect_congestion_with_transport_drops() {
    let mut node = make_node();

    // No drops — detect_congestion should return false for any address
    let fake_addr = NodeAddr::from_bytes([1; 16]);
    assert!(!node.detect_congestion(&fake_addr));

    // Simulate transport kernel drops
    let tid = TransportId::new(1);
    node.transport_drops.insert(
        tid,
        TransportDropState {
            prev_drops: 100,
            dropping: true,
        },
    );

    // Now detect_congestion should return true (local transport congestion)
    assert!(node.detect_congestion(&fake_addr));

    // Clear the dropping flag — should return false again
    node.transport_drops.get_mut(&tid).unwrap().dropping = false;
    assert!(!node.detect_congestion(&fake_addr));
}

#[test]
fn test_detect_congestion_disabled_ecn() {
    let mut node = make_node();
    node.config.node.ecn.enabled = false;

    // Even with transport drops, disabled ECN should return false
    let tid = TransportId::new(1);
    node.transport_drops.insert(
        tid,
        TransportDropState {
            prev_drops: 50,
            dropping: true,
        },
    );

    let fake_addr = NodeAddr::from_bytes([1; 16]);
    assert!(!node.detect_congestion(&fake_addr));
}

#[test]
fn test_sample_transport_congestion() {
    let mut node = make_node();

    // Insert a transport drop state with a baseline
    let tid = TransportId::new(1);
    node.transport_drops.insert(
        tid,
        TransportDropState {
            prev_drops: 0,
            dropping: false,
        },
    );

    // No transports registered — sample_transport_congestion is a no-op
    // (transport_drops entry stays unchanged)
    node.sample_transport_congestion();
    assert!(!node.transport_drops[&tid].dropping);
}
