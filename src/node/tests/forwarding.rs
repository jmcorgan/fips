//! SessionDatagram forwarding tests.
//!
//! Tests for the handle_session_datagram handler including decode errors,
//! TTL enforcement, local delivery, coordinate cache warming, and
//! multi-hop forwarding through live node topologies.

use super::*;
use crate::node::peer_error_budget::PEER_ERROR_BURST;
use crate::proto::fsp::wire::{FSP_FLAG_CP, build_fsp_header};
use crate::proto::fsp::{SessionAck, SessionSetup};
use crate::proto::link::SessionDatagram;
use crate::proto::stp::TreeCoordinate;
use crate::proto::stp::encode_coords;

use spanning_tree::{
    TestNode, cleanup_nodes, populate_all_coord_caches, process_available_packets, run_tree_test,
    verify_tree_convergence,
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
    let fwd = &node.metrics().forwarding;
    assert_eq!(
        fwd.ttl_exhausted_packets.get(),
        1,
        "transit ttl=0 should be charged to TtlExhausted"
    );
    assert_eq!(
        fwd.drop_no_route_packets.get(),
        0,
        "transit ttl=0 should never reach the routing step"
    );
}

#[tokio::test]
async fn test_forwarding_ttl_one_local_delivery_is_not_gated() {
    // dest == self, so this is local delivery, not transit: the TTL gate
    // does not apply and the datagram is handed to the session layer.
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let my_addr = *node.node_addr();
    let src = make_node_addr(0x01);
    let dg = SessionDatagram::new(src, my_addr, vec![0x10, 0x00, 0x00, 0x00]).with_ttl(1);
    let encoded = dg.encode();
    node.handle_session_datagram(&from, &encoded[1..], false)
        .await;
    let fwd = &node.metrics().forwarding;
    assert_eq!(fwd.delivered_packets.get(), 1, "ttl=1 should be delivered");
    assert_eq!(fwd.ttl_exhausted_packets.get(), 0);
}

/// The shell's half of the acceptance: a datagram addressed to this node with
/// ttl=0 reaches the session layer and is charged to `delivered`, not to the
/// `TtlExhausted` reject. The shell has its own TTL-shaped gates ahead of the
/// core, so the core-level test alone would not pin this.
#[tokio::test]
async fn test_forwarding_ttl_zero_local_delivery_is_not_gated() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let my_addr = *node.node_addr();
    let src = make_node_addr(0x01);
    let dg = SessionDatagram::new(src, my_addr, vec![0x10, 0x00, 0x00, 0x00]).with_ttl(0);
    let encoded = dg.encode();
    node.handle_session_datagram(&from, &encoded[1..], false)
        .await;
    let fwd = &node.metrics().forwarding;
    assert_eq!(
        fwd.delivered_packets.get(),
        1,
        "ttl=0 addressed to this node must still be delivered locally"
    );
    assert_eq!(
        fwd.ttl_exhausted_packets.get(),
        0,
        "local delivery must not be charged to the TtlExhausted reject"
    );
    assert_eq!(fwd.drop_no_route_packets.get(), 0);
}

/// The shell's half of the transit boundary: ttl=1 is charged to
/// `TtlExhausted` and never reaches the routing step, and ttl=2 clears the
/// gate — visible here as the no-route charge this peerless node produces
/// once the datagram gets that far.
#[tokio::test]
async fn test_forwarding_ttl_one_transit_dropped_before_routing() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let src = make_node_addr(0x01);
    let dest = make_node_addr(0x02);
    let dg = SessionDatagram::new(src, dest, vec![0x10, 0x00, 0x00, 0x00]).with_ttl(1);
    let encoded = dg.encode();
    node.handle_session_datagram(&from, &encoded[1..], false)
        .await;
    let fwd = &node.metrics().forwarding;
    assert_eq!(
        fwd.ttl_exhausted_packets.get(),
        1,
        "transit ttl=1 must be dropped as TTL-exhausted, not forwarded"
    );
    assert_eq!(
        fwd.drop_no_route_packets.get(),
        0,
        "transit ttl=1 must not reach the routing step"
    );
    assert_eq!(fwd.forwarded_packets.get(), 0);
    assert_eq!(fwd.delivered_packets.get(), 0);
}

#[tokio::test]
async fn test_forwarding_ttl_two_transit_clears_the_gate() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let src = make_node_addr(0x01);
    let dest = make_node_addr(0x02);
    let dg = SessionDatagram::new(src, dest, vec![0x10, 0x00, 0x00, 0x00]).with_ttl(2);
    let encoded = dg.encode();
    node.handle_session_datagram(&from, &encoded[1..], false)
        .await;
    let fwd = &node.metrics().forwarding;
    assert_eq!(
        fwd.ttl_exhausted_packets.get(),
        0,
        "transit ttl=2 must clear the TTL gate"
    );
    assert_eq!(
        fwd.drop_no_route_packets.get(),
        1,
        "transit ttl=2 should have reached the routing step and found no route"
    );
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
async fn a_forged_warm_cannot_displace_a_coordinate_established_by_a_verified_lookup() {
    let mut node = make_node();
    let attacker_link = make_node_addr(0xAA);
    let victim_dest = make_node_addr(0x02);
    let root_addr = *node.tree_state.my_coords().root_id();

    // The state a completed lookup leaves behind.
    let real_coords = TreeCoordinate::from_addrs(vec![victim_dest, root_addr]).unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    node.coord_cache_mut()
        .insert_verified(victim_dest, real_coords.clone(), now_ms);

    // One packet, claiming to be from the destination, carrying a different
    // position for it under the same root. This is the whole attack.
    let forged =
        TreeCoordinate::from_addrs(vec![victim_dest, make_node_addr(0x77), root_addr]).unwrap();
    let src_coords = TreeCoordinate::from_addrs(vec![victim_dest, root_addr]).unwrap();
    let payload = SessionSetup::new(src_coords, forged.clone()).encode();
    let encoded = SessionDatagram::new(victim_dest, victim_dest, payload).encode();

    let rejected_before = node.metrics().forwarding.coord_hint_rejected.get();
    node.handle_session_datagram(&attacker_link, &encoded[1..], false)
        .await;

    assert_eq!(
        node.coord_cache().get(&victim_dest, now_ms),
        Some(&real_coords),
        "a forged warm displaced a verified coordinate"
    );
    assert!(
        node.metrics().forwarding.coord_hint_rejected.get() > rejected_before,
        "the refusal should be counted"
    );
}

#[tokio::test]
async fn warming_refuses_a_coordinate_rooted_in_a_tree_this_node_is_not_in() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let src_addr = make_node_addr(0x01);
    let dest_addr = make_node_addr(0x02);
    // Deliberately NOT this node's root. Such an entry can never route: both
    // selectors reject a foreign root, so caching it only occupies a slot and
    // flips the error-PDU choice in `synth_routing_error` from CoordsRequired
    // to PathBroken, which is the primitive this guard removes.
    let foreign_root = make_node_addr(0xF0);
    assert_ne!(
        &foreign_root,
        node.tree_state.my_coords().root_id(),
        "fixture must not accidentally share the node's root"
    );

    let src_coords = TreeCoordinate::from_addrs(vec![src_addr, foreign_root]).unwrap();
    let dest_coords = TreeCoordinate::from_addrs(vec![dest_addr, foreign_root]).unwrap();
    let setup_payload = SessionSetup::new(src_coords, dest_coords).encode();
    let encoded = SessionDatagram::new(src_addr, dest_addr, setup_payload).encode();

    let before = node.metrics().forwarding.coord_warm_foreign_root.get();
    node.handle_session_datagram(&from, &encoded[1..], false)
        .await;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    assert!(
        node.coord_cache().get(&src_addr, now_ms).is_none(),
        "a foreign-root src coordinate was cached"
    );
    assert!(
        node.coord_cache().get(&dest_addr, now_ms).is_none(),
        "a foreign-root dest coordinate was cached"
    );
    assert_eq!(
        node.metrics().forwarding.coord_warm_foreign_root.get(),
        before + 2,
        "both refusals should be counted"
    );
}

#[tokio::test]
async fn warming_counts_but_still_caches_a_coordinate_that_does_not_name_its_own_key() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let src_addr = make_node_addr(0x01);
    let dest_addr = make_node_addr(0x02);
    let root_addr = *node.tree_state.my_coords().root_id();
    let someone_else = make_node_addr(0x09);

    // dest_coords names 0x09, not the 0x02 it will be filed under. This is the
    // shape an honest sender produces when its own cache missed and
    // `get_dest_coords` fell back to the sender's own coordinates, so it is
    // counted and NOT refused.
    let src_coords = TreeCoordinate::from_addrs(vec![src_addr, root_addr]).unwrap();
    let dest_coords = TreeCoordinate::from_addrs(vec![someone_else, root_addr]).unwrap();
    let setup_payload = SessionSetup::new(src_coords, dest_coords).encode();
    let encoded = SessionDatagram::new(src_addr, dest_addr, setup_payload).encode();

    let before = node.metrics().forwarding.coord_warm_key_mismatch.get();
    node.handle_session_datagram(&from, &encoded[1..], false)
        .await;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    assert!(
        node.coord_cache().get(&dest_addr, now_ms).is_some(),
        "the mismatching entry should still be cached; this check counts only"
    );
    assert_eq!(
        node.metrics().forwarding.coord_warm_key_mismatch.get(),
        before + 1,
        "the mismatch should be counted exactly once"
    );
    assert_eq!(
        node.metrics().forwarding.coord_warm_key_mismatch.get() - before,
        1,
        "the well-formed src coordinate must not be counted as a mismatch"
    );
}

#[tokio::test]
async fn test_coord_cache_warming_session_setup() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let src_addr = make_node_addr(0x01);
    let dest_addr = make_node_addr(0x02);
    // The warming path refuses a coordinate under a root other than this
    // node's, so a fixture that wants the write to land has to share the
    // node's root. A fresh node is its own root.
    let root_addr = *node.tree_state.my_coords().root_id();

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
    // The warming path refuses a coordinate under a root other than this
    // node's, so a fixture that wants the write to land has to share the
    // node's root. A fresh node is its own root.
    let root_addr = *node.tree_state.my_coords().root_id();

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
    // The warming path refuses a coordinate under a root other than this
    // node's, so a fixture that wants the write to land has to share the
    // node's root. A fresh node is its own root.
    let root_addr = *node.tree_state.my_coords().root_id();

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
    // Changing what the malformed counter charges is close enough to changing
    // when it fires that the well-formed case is pinned in the same place.
    assert_eq!(
        node.metrics().forwarding.warm_malformed_packets.get(),
        0,
        "a well-formed CP datagram must not be counted as an abandoned warm attempt"
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

/// Cache warming is not gated on the TTL, case 1 of 2: a datagram addressed
/// to this node that arrives already exhausted is delivered, and its
/// plaintext coordinates still reach the cache.
///
/// The warming call sits ahead of the routing decision precisely so that it
/// is unconditional. The other warming tests all run at the default TTL of 64
/// and so cannot see a TTL-shaped gate around it; this one runs at zero.
/// `SessionSetup` is used rather than a CP-flagged encrypted message because
/// the local-delivery path caches coords from the latter itself, which would
/// mask a suppressed warming call.
#[tokio::test]
async fn test_coord_cache_warming_ttl_zero_local_delivery() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let my_addr = *node.node_addr();
    let src_addr = make_node_addr(0x01);
    // The warming path refuses a coordinate under a root other than this
    // node's, so a fixture that wants the write to land has to share the
    // node's root. A fresh node is its own root.
    let root_addr = *node.tree_state.my_coords().root_id();

    let src_coords = TreeCoordinate::from_addrs(vec![src_addr, root_addr]).unwrap();
    let dest_coords = TreeCoordinate::from_addrs(vec![my_addr, root_addr]).unwrap();
    let setup = SessionSetup::new(src_coords, dest_coords);

    let dg = SessionDatagram::new(src_addr, my_addr, setup.encode()).with_ttl(0);
    let encoded = dg.encode();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    assert!(node.coord_cache().get(&src_addr, now_ms).is_none());

    node.handle_session_datagram(&from, &encoded[1..], false)
        .await;

    assert_eq!(
        node.metrics().forwarding.delivered_packets.get(),
        1,
        "ttl=0 addressed to this node must be delivered, not dropped"
    );
    let cached = node.coord_cache().get(&src_addr, now_ms);
    assert!(
        cached.is_some(),
        "warming must not be gated on the TTL: a delivered ttl=0 datagram \
         still carries usable coords"
    );
    assert_eq!(cached.unwrap().root_id(), &root_addr);
}

/// Cache warming is not gated on the TTL, case 2 of 2: a transit datagram
/// that is dropped for hop limit still contributes its plaintext coordinates.
///
/// This is the case the gate suppressed most visibly — the datagram never
/// reaches any other code that could cache coords, so the assertion below is
/// only satisfiable by the unconditional warming call. The `TtlExhausted`
/// charge is asserted alongside it to show the drop did happen, so the test
/// cannot be satisfied by the datagram merely surviving the TTL gate.
#[tokio::test]
async fn test_coord_cache_warming_ttl_zero_transit_drop() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let src_addr = make_node_addr(0x01);
    let dest_addr = make_node_addr(0x02);
    // The warming path refuses a coordinate under a root other than this
    // node's, so a fixture that wants the write to land has to share the
    // node's root. A fresh node is its own root.
    let root_addr = *node.tree_state.my_coords().root_id();

    let src_coords = TreeCoordinate::from_addrs(vec![src_addr, root_addr]).unwrap();
    let dest_coords = TreeCoordinate::from_addrs(vec![dest_addr, root_addr]).unwrap();
    let setup = SessionSetup::new(src_coords, dest_coords);

    let dg = SessionDatagram::new(src_addr, dest_addr, setup.encode()).with_ttl(0);
    let encoded = dg.encode();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    assert!(node.coord_cache().get(&src_addr, now_ms).is_none());
    assert!(node.coord_cache().get(&dest_addr, now_ms).is_none());

    node.handle_session_datagram(&from, &encoded[1..], false)
        .await;

    assert_eq!(
        node.metrics().forwarding.ttl_exhausted_packets.get(),
        1,
        "the transit datagram should have been dropped for hop limit"
    );
    assert!(
        node.coord_cache().get(&src_addr, now_ms).is_some(),
        "a transit datagram dropped for hop limit must still warm the cache \
         with its source coords"
    );
    assert!(
        node.coord_cache().get(&dest_addr, now_ms).is_some(),
        "a transit datagram dropped for hop limit must still warm the cache \
         with its destination coords"
    );
}

// ============================================================================
// Integration Tests
// ============================================================================

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
    // Send a datagram with ttl=2. Node 1 forwards it as transit (2 -> 1) and
    // node 2 delivers it locally, which is not TTL-gated. Had node 2 been
    // transit instead, the arriving ttl=1 would have stopped it there.
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
    .with_ttl(2); // Node 1 forwards with ttl=1; node 2 is the destination

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

    // The datagram must actually have traversed the chain rather than dying
    // somewhere en route: node 1 forwarded it and node 2 delivered it. These
    // hold on both sides of the hop-limit change — the per-hop decrement is
    // pinned by `test_forwarding_ttl_decrement_is_one_per_hop` below — but
    // without them the test asserts nothing and would pass on a chain that
    // dropped the datagram at the first hop.
    assert_eq!(
        nodes[1].node.metrics().forwarding.forwarded_packets.get(),
        1,
        "node 1 should have forwarded the transit datagram"
    );
    assert_eq!(
        nodes[2].node.metrics().forwarding.delivered_packets.get(),
        1,
        "node 2 should have delivered the datagram addressed to it"
    );
    assert_eq!(
        nodes[2]
            .node
            .metrics()
            .forwarding
            .ttl_exhausted_packets
            .get(),
        0,
        "the destination must not charge a TTL drop for a datagram it delivers"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Acceptance for the hop limit as the *composed* system sees it: the shell's
/// TTL-shaped predicates in `node::dataplane::forwarding` driving the
/// authoritative rule in `Router::route`, across real links.
///
/// The decision is split across those two files on this branch, and the
/// core-level tests exercise only one side of that seam. This is the coverage
/// that runs both together over a hop.
///
/// The TTL a node puts on the wire is not directly observable, so it is
/// bracketed from both sides by where the datagram comes to rest on a live
/// 3-node chain (0 -- 1 -- 2). Both injections are handed to node 0 as
/// transit — an external source, addressed to node 2 — so nodes 0 and 1 are
/// both forwarders and only node 2 is the addressed destination.
///
/// - ttl=2 must reach node 1 as ttl=1 and stop there, because forwarding it
///   again would put it on the wire at zero. Emitting ttl=2 unchanged would
///   instead show up as a delivery at node 2.
/// - ttl=3 must survive both forwarders and be delivered at node 2, which
///   receives it at ttl=1 — delivery is not TTL-gated. Decrementing by more
///   than one per hop would have stopped it at node 1.
#[tokio::test]
async fn test_forwarding_ttl_decrement_is_one_per_hop() {
    /// `(forwarded, ttl_exhausted, delivered)` for one node.
    fn counts(node: &TestNode) -> (u64, u64, u64) {
        let fwd = &node.node.metrics().forwarding;
        (
            fwd.forwarded_packets.get(),
            fwd.ttl_exhausted_packets.get(),
            fwd.delivered_packets.get(),
        )
    }

    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    let external_src = make_node_addr(0xEE);

    /// Hand a transit datagram to node 0 and let the chain settle.
    async fn inject(nodes: &mut [TestNode], from: &NodeAddr, dg: SessionDatagram) {
        let encoded = dg.encode();
        nodes[0]
            .node
            .handle_session_datagram(from, &encoded[1..], false)
            .await;
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            process_available_packets(nodes).await;
        }
    }

    let transit = |ttl: u8| {
        SessionDatagram::new(external_src, node2_addr, vec![0x10, 0x00, 0x00, 0x00]).with_ttl(ttl)
    };

    // ttl=2 in: node 0 emits 1, node 1 has nothing left to emit.
    inject(&mut nodes, &node0_addr, transit(2)).await;
    assert_eq!(
        counts(&nodes[0]),
        (1, 0, 0),
        "node 0 should have forwarded the ttl=2 datagram at ttl=1"
    );
    assert_eq!(
        counts(&nodes[1]),
        (0, 1, 0),
        "node 1 should have received ttl=1 and dropped it rather than sending at ttl=0"
    );
    assert_eq!(
        counts(&nodes[2]),
        (0, 0, 0),
        "node 2 must never see a datagram that started two hops away at ttl=2"
    );

    // ttl=3 in: node 0 emits 2, node 1 emits 1, node 2 delivers at ttl=1.
    inject(&mut nodes, &node0_addr, transit(3)).await;
    assert_eq!(
        counts(&nodes[0]),
        (2, 0, 0),
        "node 0 should have forwarded the ttl=3 datagram too"
    );
    assert_eq!(
        counts(&nodes[1]),
        (1, 1, 0),
        "node 1 should have forwarded the ttl=2 it received, and dropped nothing new"
    );
    assert_eq!(
        counts(&nodes[2]),
        (0, 0, 1),
        "node 2 should have delivered the datagram that arrived at ttl=1"
    );

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
            let _ = nodes[0]
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
                    let _ = nodes[i]
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
use crate::proto::fsp::mark_ipv6_ecn_ce;
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
    let mut config = Config::new();
    config.node.ecn.enabled = false;
    let mut node = Node::new(config).unwrap();

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

/// Acceptance: an inner FSP payload of 4 to 11 bytes with phase 0x0 and the
/// CP flag set is dropped rather than panicking the forwarding path. That
/// window sits between the common prefix parser's 4-byte floor and the
/// 12-byte header slice the warm path takes, so before the fix the first
/// iteration panicked with a range start index out of range.
#[tokio::test]
async fn test_coord_cache_warming_short_inner_payload_is_dropped_not_panic() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let src_addr = make_node_addr(0x01);
    let dest_addr = make_node_addr(0x02);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    for extra in 0..=7 {
        let mut data_payload = vec![0x00, FSP_FLAG_CP, 0x00, 0x00];
        data_payload.resize(4 + extra, 0x00);

        let dg = SessionDatagram::new(src_addr, dest_addr, data_payload).with_ttl(1);
        let encoded = dg.encode();
        node.handle_session_datagram(&from, &encoded[1..], false)
            .await;
    }

    assert!(
        node.coord_cache().get(&src_addr, now_ms).is_none(),
        "Short inner payload must not warm src coords"
    );
    assert!(
        node.coord_cache().get(&dest_addr, now_ms).is_none(),
        "Short inner payload must not warm dest coords"
    );
    // Anti-vacuity: only a datagram that ran past the warm call reaches the
    // TTL gate. `received_packets` is charged before decode and so would
    // count a datagram rejected earlier.
    assert_eq!(
        node.metrics().forwarding.ttl_exhausted_packets.get(),
        8,
        "each short-inner-payload datagram must run past the warm call to the TTL gate"
    );
    // Discriminating: separates "the guard fired" from "coords parsed and
    // yielded nothing", which the cache assertions above cannot tell apart.
    assert_eq!(
        node.metrics().forwarding.warm_malformed_packets.get(),
        8,
        "each short-inner-payload datagram must be counted as an abandoned warm attempt"
    );

    // Inner lengths 12 to 27 document the new 28-byte floor: they do not
    // panic today either, so this half is not discriminating.
    for len in 12..=27 {
        let mut data_payload = vec![0x00, FSP_FLAG_CP, 0x00, 0x00];
        data_payload.resize(len, 0x00);

        let dg = SessionDatagram::new(src_addr, dest_addr, data_payload).with_ttl(1);
        let encoded = dg.encode();
        node.handle_session_datagram(&from, &encoded[1..], false)
            .await;
    }

    assert!(
        node.coord_cache().get(&src_addr, now_ms).is_none(),
        "Payload below the encrypted minimum must not warm src coords"
    );
    assert!(
        node.coord_cache().get(&dest_addr, now_ms).is_none(),
        "Payload below the encrypted minimum must not warm dest coords"
    );
    assert_eq!(
        node.metrics().forwarding.ttl_exhausted_packets.get(),
        24,
        "every datagram in both loops must reach the TTL gate"
    );
    assert_eq!(
        node.metrics().forwarding.warm_malformed_packets.get(),
        24,
        "every datagram in both loops must be counted as an abandoned warm attempt"
    );
    // The byte counter shares a fipstop row with `received_bytes` and
    // `decode_error_bytes`, so it has to measure the same population: the
    // outer SessionDatagram payload, not the inner FSP one. Two assertions
    // produced two different ways, because a single one cannot tell "the
    // basis matches" from "two counters are wrong in the same direction".
    //
    // Self-derived: every one of the 24 datagrams reaches the warm guard, as
    // the two packet counts above already pin, and `record_received` charges
    // the identical outer slice.
    assert_eq!(
        node.metrics().forwarding.warm_malformed_bytes.get(),
        node.metrics().forwarding.received_bytes.get(),
        "the byte counter must be charged the same outer payload as its \
         siblings on the same row"
    );
    // Literal cross-check. The first loop sends inner lengths 4..=11, so
    // outer 39..=46, summing to 340; the second sends inner 12..=27, so
    // outer 47..=62, summing to 872. Charging the inner payload instead
    // reads 60 + 312 = 372, about 15% of the wire volume that arrived.
    assert_eq!(
        node.metrics().forwarding.warm_malformed_bytes.get(),
        1212,
        "24 frames of 39..=46 and 47..=62 outer bytes sum to 1212"
    );
}

// --- Emission bounds on induced routing errors ---

/// A distinct destination per index, standing for the fresh `dest_addr` a
/// flooding sender puts on every datagram to escape the per-destination gate.
fn minted_dest(val: u32) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[..4].copy_from_slice(&val.to_le_bytes());
    bytes[15] = 0xfe;
    NodeAddr::from_bytes(bytes)
}

/// Feed one transit datagram whose destination this node cannot route.
async fn inject_unroutable(node: &mut Node, from: &NodeAddr, src: NodeAddr, dest: NodeAddr) {
    let dg = SessionDatagram::new(src, dest, vec![0x10, 0x00, 0x00, 0x00]).with_ttl(8);
    let encoded = dg.encode();
    node.handle_session_datagram(from, &encoded[1..], false)
        .await;
}

#[tokio::test]
async fn one_link_peer_cannot_induce_unbounded_errors_by_varying_the_destination() {
    let mut node = make_node();
    let attacker = make_node_addr(0xAA);
    let overshoot = 10u32;

    for i in 0..PEER_ERROR_BURST + overshoot {
        // Fresh destination and fresh spoofed source per packet: neither
        // address-keyed gate sees a repeat.
        inject_unroutable(
            &mut node,
            &attacker,
            minted_dest(i + 1_000_000),
            minted_dest(i),
        )
        .await;
    }

    let errors = &node.metrics().errors;
    assert_eq!(
        errors.emit_over_dest_interval.get(),
        0,
        "the per-destination gate cannot bound a sender that varies the destination"
    );
    assert_eq!(
        errors.emit_over_peer_budget.get(),
        u64::from(overshoot),
        "everything past the link peer's burst must be refused"
    );
}

#[tokio::test]
async fn a_destination_suppressed_error_does_not_spend_the_link_peer_budget() {
    let mut node = make_node();
    let peer = make_node_addr(0xAA);
    let src = make_node_addr(0x01);
    let dest = make_node_addr(0x02);
    let injected = PEER_ERROR_BURST * 4;

    for _ in 0..injected {
        inject_unroutable(&mut node, &peer, src, dest).await;
    }

    let errors = &node.metrics().errors;
    assert_eq!(
        errors.emit_over_peer_budget.get(),
        0,
        "an outage on one destination must not spend the peer's budget for the others"
    );
    assert_eq!(
        errors.emit_over_dest_interval.get(),
        u64::from(injected - 1),
        "only the first error for a destination goes out within the interval"
    );
}

#[tokio::test]
async fn a_single_unroutable_datagram_still_produces_its_error() {
    let mut node = make_node();
    let peer = make_node_addr(0xAA);

    inject_unroutable(&mut node, &peer, make_node_addr(0x01), make_node_addr(0x02)).await;

    let errors = &node.metrics().errors;
    assert_eq!(errors.emit_over_peer_budget.get(), 0);
    assert_eq!(errors.emit_over_dest_interval.get(), 0);
}
