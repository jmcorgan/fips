//! SessionDatagram forwarding tests.
//!
//! Tests for the handle_session_datagram handler including decode errors,
//! TTL enforcement, local delivery, coordinate cache warming, and
//! multi-hop forwarding through live node topologies.

use super::*;
use crate::cache::Funding;
use crate::node::peer_budget::{PEER_ERROR_BURST, PeerBudget};
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

/// The next hop is resolved only for a datagram the core can forward, and that
/// resolution refreshes the destination's cached coordinates. A last-hop
/// transit datagram (ttl=1) is dropped by the core, so it must not refresh
/// them; a ttl=2 datagram reaches the resolution and does.
#[tokio::test]
async fn test_forwarding_last_hop_transit_does_not_refresh_destination_coords() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let src = make_node_addr(0x01);
    let dest = make_node_addr(0x02);
    let root = make_node_addr(0xF0);
    let coords = TreeCoordinate::from_addrs(vec![dest, root]).unwrap();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let stamped_ms = now_ms - node.coord_cache().default_ttl_ms() / 2;
    node.coord_cache_mut()
        .insert_verified(dest, coords, stamped_ms);
    let last_used = |node: &Node| node.coord_cache().get_entry(&dest).unwrap().last_used();
    assert_eq!(
        last_used(&node),
        stamped_ms,
        "precondition: the entry carries the past stamp"
    );

    for ttl in [1u8, 2] {
        let dg = SessionDatagram::new(src, dest, vec![0x10, 0x00, 0x00, 0x00]).with_ttl(ttl);
        let encoded = dg.encode();
        node.handle_session_datagram(&from, &encoded[1..], false)
            .await;
        if ttl == 1 {
            assert_eq!(
                last_used(&node),
                stamped_ms,
                "a transit ttl=1 datagram is dropped, so it must not refresh the destination's coords"
            );
        } else {
            assert!(
                last_used(&node) > stamped_ms,
                "a transit ttl=2 datagram reaches next-hop resolution, which refreshes the coords"
            );
        }
    }
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

/// A `SessionSetup` or `SessionAck` addressed to this node: its destination
/// coordinates are this node's, and no node files a coordinate under its own
/// address. The source is still warmed.
#[tokio::test]
async fn a_session_setup_or_ack_addressed_to_this_node_writes_nothing_under_its_own_address() {
    for ack in [false, true] {
        let mut node = make_node();
        let from = make_node_addr(0xAA);
        let my_addr = *node.node_addr();
        let src_addr = make_node_addr(0x01);
        // A fresh node is its own root.
        let root_addr = *node.tree_state.my_coords().root_id();
        let src_coords = TreeCoordinate::from_addrs(vec![src_addr, root_addr]).unwrap();
        let dest_coords = node.tree_state.my_coords().clone();
        let payload = if ack {
            SessionAck::new(src_coords, dest_coords).encode()
        } else {
            SessionSetup::new(src_coords, dest_coords).encode()
        };
        let encoded = SessionDatagram::new(src_addr, my_addr, payload).encode();

        node.handle_session_datagram(&from, &encoded[1..], false)
            .await;

        let kind = if ack { "SessionAck" } else { "SessionSetup" };
        assert!(
            node.coord_cache().get(&src_addr, wall_ms()).is_some(),
            "{kind}: the source coordinates must still be warmed"
        );
        assert!(
            node.coord_cache().get_entry(&my_addr).is_none(),
            "{kind}: a node must not file a coordinate under its own address"
        );
    }
}

/// A coordinate filed under this node's own address that names another
/// node is counted as it was before, and not written; one under a foreign
/// root is counted as a foreign-root refusal, not a key mismatch.
#[tokio::test]
async fn a_misfiled_coordinate_addressed_to_this_node_is_counted_and_not_written() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let my_addr = *node.node_addr();
    let src_addr = make_node_addr(0x01);
    let root_addr = *node.tree_state.my_coords().root_id();
    let foreign_root = make_node_addr(0xF0);
    assert_ne!(foreign_root, root_addr, "fixture: the root must be foreign");
    let src_coords = TreeCoordinate::from_addrs(vec![src_addr, root_addr]).unwrap();

    for (dest_root, mismatches, foreign) in [(root_addr, 1, 0), (foreign_root, 0, 1)] {
        let dest_coords =
            TreeCoordinate::from_addrs(vec![make_node_addr(0x09), dest_root]).unwrap();
        let payload = SessionSetup::new(src_coords.clone(), dest_coords).encode();
        let encoded = SessionDatagram::new(src_addr, my_addr, payload).encode();
        let fwd = &node.metrics().forwarding;
        let before = (
            fwd.coord_warm_key_mismatch.get(),
            fwd.coord_warm_foreign_root.get(),
        );

        node.handle_session_datagram(&from, &encoded[1..], false)
            .await;

        let fwd = &node.metrics().forwarding;
        assert_eq!(
            (
                fwd.coord_warm_key_mismatch.get() - before.0,
                fwd.coord_warm_foreign_root.get() - before.1,
            ),
            (mismatches, foreign),
            "a misfiled coordinate under root {dest_root} must be counted once, \
             as (key mismatch, foreign root)"
        );
        assert!(
            node.coord_cache().get_entry(&my_addr).is_none(),
            "a misfiled coordinate under root {dest_root} must not be written under this node's address"
        );
    }
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

    // But nodes 1 and 2 need cached coords for the self-distance check
    // (strict progress by each node's view). Without coords, find_next_hop
    // returns None.
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

use crate::ipv6tun::inbound::mark_ce as mark_ipv6_ecn_ce;
use crate::node::TransportDropState;
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

// --- Coordinate cache bounds under transit warming ---

/// Wall-clock milliseconds, the clock the warm path stamps entries with.
fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Coordinates for `addr` carrying `len` addresses in all: `addr`, then
/// `len - 2` minted ancestors, then `root`.
fn coords_of_len(addr: NodeAddr, root: NodeAddr, len: usize) -> TreeCoordinate {
    let mut path = Vec::with_capacity(len);
    path.push(addr);
    path.extend((0..len as u32 - 2).map(|i| {
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&i.to_le_bytes());
        bytes[15] = 0xd0;
        NodeAddr::from_bytes(bytes)
    }));
    path.push(root);
    TreeCoordinate::from_addrs(path).unwrap()
}

/// One encoded SessionSetup from `src` to `dest`, without the msg_type byte.
fn setup_frame(
    src: NodeAddr,
    src_coords: TreeCoordinate,
    dest: NodeAddr,
    dest_coords: TreeCoordinate,
    ttl: u8,
) -> Vec<u8> {
    let payload = SessionSetup::new(src_coords, dest_coords).encode();
    let encoded = SessionDatagram::new(src, dest, payload)
        .with_ttl(ttl)
        .encode();
    encoded[1..].to_vec()
}

/// New destinations one link peer may place per second once its budget is
/// spent, and the entries the probation segment holds whatever their depth, at the
/// default cache size.
const HINT_KEYS_PER_SEC: u64 = crate::node::peer_budget::COORD_HINT_WEIGHT_PER_SEC as u64
    / crate::cache::ADDRS_PER_ENTRY as u64;
const UNPAID_HINT_ENTRIES: u64 =
    (crate::cache::DEFAULT_COORD_CACHE_SIZE / crate::cache::PROBATION_SHARE_DIVISOR) as u64;

#[tokio::test]
async fn one_link_peer_cannot_put_more_new_destinations_in_the_cache_than_its_budget_and_probation_allow()
 {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let root = *node.tree_state.my_coords().root_id();
    let dest = make_node_addr(0x02);
    let dest_coords = coords_of_len(dest, root, 2);
    let _ = node
        .coord_cache_mut()
        .insert(dest, dest_coords.clone(), wall_ms());

    let sent = 5_000u32;
    let started = std::time::Instant::now();
    for i in 0..sent {
        let src = minted_dest(i);
        let frame = setup_frame(
            src,
            coords_of_len(src, root, 2),
            dest,
            dest_coords.clone(),
            8,
        );
        node.handle_session_datagram(&from, &frame, false).await;
    }
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let allowed = (elapsed_ms * HINT_KEYS_PER_SEC).div_ceil(1000) + UNPAID_HINT_ENTRIES;
    assert!(
        allowed < u64::from(sent),
        "the run took {elapsed_ms} ms, too long for the bound to discriminate"
    );

    let now = wall_ms();
    let present = (0..sent)
        .filter(|&i| node.coord_cache().get(&minted_dest(i), now).is_some())
        .count() as u64;
    assert!(
        node.coord_cache().get(&dest, now).is_some(),
        "the fixed destination must stay cached"
    );
    assert!(
        present <= allowed,
        "one link peer placed {present} of {sent} new destinations in the \
         cache in {elapsed_ms} ms, against an allowance of {allowed}"
    );
}

#[tokio::test]
async fn a_drained_link_peer_still_forwards_an_honest_setup_for_a_new_destination() {
    // 3-node chain: 0 -- 1 -- 2. Node 1 is the transit under test.
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node0 = *nodes[0].node.node_addr();
    let node2_coords = nodes[2].node.tree_state().my_coords().clone();
    let root = *nodes[1].node.tree_state().my_coords().root_id();

    // Drain: far more fresh source keys from node 0 than any budget pays for.
    // TTL 1 keeps them off the wire; warming runs before the TTL decision.
    let sink = make_node_addr(0x02);
    for i in 0..2_000u32 {
        let src = minted_dest(i);
        let frame = setup_frame(
            src,
            coords_of_len(src, root, 2),
            sink,
            coords_of_len(sink, root, 2),
            1,
        );
        nodes[1]
            .node
            .handle_session_datagram(&node0, &frame, false)
            .await;
    }

    // An honest setup for a destination behind node 2 that node 1 has never
    // cached: the setup's own coordinates are the only route to it.
    let fresh_dest = make_node_addr(0x77);
    let mut path = vec![fresh_dest];
    path.extend(node2_coords.node_addrs().copied());
    let fresh_coords = TreeCoordinate::from_addrs(path).unwrap();
    let honest_src = make_node_addr(0x66);
    let frame = setup_frame(
        honest_src,
        coords_of_len(honest_src, root, 2),
        fresh_dest,
        fresh_coords,
        64,
    );

    let fwd = &nodes[1].node.metrics().forwarding;
    let (forwarded, no_route) = (fwd.forwarded_packets.get(), fwd.drop_no_route_packets.get());
    nodes[1]
        .node
        .handle_session_datagram(&node0, &frame, false)
        .await;
    let fwd = &nodes[1].node.metrics().forwarding;
    assert_eq!(
        fwd.drop_no_route_packets.get(),
        no_route,
        "the honest setup was dropped for want of a route"
    );
    assert_eq!(
        fwd.forwarded_packets.get(),
        forwarded + 1,
        "the honest setup must be forwarded"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_session_setup_at_a_full_cache_examines_a_bounded_number_of_entries() {
    let mut node = make_node();
    // A link peer that pays for every write, so each source goes to main and
    // main's eviction runs.
    node.coord_hint_budget = PeerBudget::with_rate(0, u32::MAX);
    let from = make_node_addr(0xAA);
    let root = *node.tree_state.my_coords().root_id();
    let capacity = node.coord_cache().max_entries() as u32;
    let start = wall_ms();
    let dest = make_node_addr(0x02);
    let dest_coords = coords_of_len(dest, root, 2);
    let _ = node
        .coord_cache_mut()
        .insert(dest, dest_coords.clone(), start);
    for i in 1..capacity {
        let addr = minted_dest(1_000_000 + i);
        let _ = node
            .coord_cache_mut()
            .insert(addr, coords_of_len(addr, root, 2), start);
    }
    assert_eq!(node.coord_cache().len(), capacity as usize);

    let frames = 100u32;
    let before = node.coord_cache().eviction_examined();
    for i in 0..frames {
        let src = minted_dest(i);
        let frame = setup_frame(
            src,
            coords_of_len(src, root, 2),
            dest,
            dest_coords.clone(),
            8,
        );
        node.handle_session_datagram(&from, &frame, false).await;
    }
    assert!(
        node.coord_cache()
            .get(&minted_dest(frames - 1), wall_ms())
            .is_some(),
        "the last frame's source must have been cached"
    );
    let examined = node.coord_cache().eviction_examined() - before;
    assert!(
        examined >= u64::from(frames),
        "main eviction must run once per frame, examined {examined}"
    );
    let mean = examined / u64::from(frames);
    assert!(
        mean <= 8,
        "each SessionSetup at a full cache examined {mean} entries on average, \
         against a bound of 8"
    );

    // Sources the link peer cannot pay for go to probation, so fill that too
    // and check its eviction is as cheap.
    node.coord_hint_budget = PeerBudget::coord_hints();
    let now = wall_ms();
    // Each unpaid new key below the segment's bound adds one probation entry,
    // so the bound is reached in at most UNPAID_HINT_ENTRIES writes. A cache
    // that refuses unpaid new keys must fail here, not loop forever.
    let mut writes = 0u32;
    while writes < UNPAID_HINT_ENTRIES as u32
        && node.coord_cache().probation_len() < UNPAID_HINT_ENTRIES as usize
    {
        let addr = minted_dest(2_000_000 + writes);
        let _ = node.coord_cache_mut().insert_funded(
            addr,
            coords_of_len(addr, root, 2),
            now,
            Funding::Upto(0),
        );
        writes += 1;
    }
    assert_eq!(
        node.coord_cache().probation_len(),
        UNPAID_HINT_ENTRIES as usize,
        "unpaid new keys were not placed in probation: the segment holds {} after \
         {writes} unpaid writes, against a bound of {UNPAID_HINT_ENTRIES}",
        node.coord_cache().probation_len(),
    );
    let before = node.coord_cache().eviction_examined();
    for i in 0..frames {
        let src = minted_dest(3_000_000 + i);
        let frame = setup_frame(
            src,
            coords_of_len(src, root, 2),
            dest,
            dest_coords.clone(),
            8,
        );
        node.handle_session_datagram(&from, &frame, false).await;
    }
    let examined = node.coord_cache().eviction_examined() - before;
    assert!(
        examined >= u64::from(frames) / 2,
        "probation eviction must have run"
    );
    let mean = examined / u64::from(frames);
    assert!(
        mean <= 8,
        "each SessionSetup at a full probation segment examined {mean} entries \
         on average, against a bound of 8"
    );
}

#[tokio::test]
async fn a_link_peer_cannot_fill_the_cache_with_deep_coordinates_past_the_address_budget() {
    let mut node = make_node();
    // A link peer that can pay for every write, so each deep key is placed in
    // main and only the address bound limits what the cache stores.
    node.coord_hint_budget = PeerBudget::with_rate(0, u32::MAX);
    let from = make_node_addr(0xAA);
    let root = *node.tree_state.my_coords().root_id();
    let capacity = node.coord_cache().max_entries();
    let dest = make_node_addr(0x02);
    let dest_coords = coords_of_len(dest, root, 2);
    let _ = node
        .coord_cache_mut()
        .insert(dest, dest_coords.clone(), wall_ms());

    // The deepest source coordinate a SessionSetup carries on a 1280-byte link.
    let depth_len = 71;
    let probe = setup_frame(
        minted_dest(0),
        coords_of_len(minted_dest(0), root, depth_len),
        dest,
        dest_coords.clone(),
        8,
    );
    let link_overhead =
        1 + crate::proto::fmp::wire::ESTABLISHED_HEADER_SIZE + 4 + crate::noise::TAG_SIZE;
    assert!(
        probe.len() + link_overhead <= 1280,
        "a {}-byte frame does not fit a 1280-byte link",
        probe.len() + link_overhead
    );

    for i in 0..(capacity as u32 - 1) {
        let src = minted_dest(i);
        let frame = setup_frame(
            src,
            coords_of_len(src, root, depth_len),
            dest,
            dest_coords.clone(),
            8,
        );
        node.handle_session_datagram(&from, &frame, false).await;
    }
    assert!(
        node.coord_cache()
            .get(&minted_dest(capacity as u32 - 2), wall_ms())
            .is_some(),
        "the last deep source must have been cached"
    );

    assert_eq!(
        node.coord_cache().probation_len(),
        0,
        "every write was paid"
    );
    let budget = capacity * 16;
    assert!(
        node.coord_cache().stored_addrs() <= budget,
        "one link peer made the cache store {} coordinate addresses in {} \
         entries, against a budget of {budget}",
        node.coord_cache().stored_addrs(),
        node.coord_cache().len()
    );
}

// --- Foreign-root refusal at every hint write ---

#[tokio::test]
async fn an_established_frame_with_foreign_root_source_coords_caches_nothing() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let my_addr = *node.node_addr();
    let my_coords = node.tree_state.my_coords().clone();
    let src_addr = make_node_addr(0x01);
    let foreign_root = make_node_addr(0xF0);
    assert_ne!(&foreign_root, my_coords.root_id());

    let src_coords = TreeCoordinate::from_addrs(vec![src_addr, foreign_root]).unwrap();
    let header = build_fsp_header(0, FSP_FLAG_CP, 20);
    let mut data_payload = header.to_vec();
    encode_coords(&src_coords, &mut data_payload);
    encode_coords(&my_coords, &mut data_payload);
    data_payload.extend_from_slice(&[0xCC; 36]);
    let encoded = SessionDatagram::new(src_addr, my_addr, data_payload).encode();

    let fwd = &node.metrics().forwarding;
    let (refused, delivered) = (
        fwd.coord_warm_foreign_root.get(),
        fwd.delivered_packets.get(),
    );
    node.handle_session_datagram(&from, &encoded[1..], false)
        .await;
    let fwd = &node.metrics().forwarding;
    assert_eq!(
        fwd.delivered_packets.get(),
        delivered + 1,
        "must reach local delivery"
    );
    // The destination reads an established message's coordinates only once
    // the message authenticates, and this one cannot: there is no session.
    assert_eq!(
        fwd.coord_warm_foreign_root.get(),
        refused,
        "the destination must not read the coordinates before authentication"
    );

    assert!(
        node.coord_cache().get(&src_addr, wall_ms()).is_none(),
        "a CP frame to this node cached a source coordinate under a foreign root"
    );
}

/// An established message addressed to this node writes nothing before it
/// authenticates: the destination writes the source coordinates only after
/// a key of the session has opened the message, and never the destination
/// coordinates, which are its own.
#[tokio::test]
async fn an_established_message_addressed_to_this_node_writes_no_coordinates_before_it_authenticates()
 {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let my_addr = *node.node_addr();
    let my_coords = node.tree_state.my_coords().clone();
    let src_addr = make_node_addr(0x01);
    let src_coords = TreeCoordinate::from_addrs(vec![src_addr, *my_coords.root_id()]).unwrap();

    let header = build_fsp_header(0, FSP_FLAG_CP, 20);
    let mut data_payload = header.to_vec();
    encode_coords(&src_coords, &mut data_payload);
    encode_coords(&my_coords, &mut data_payload);
    data_payload.extend_from_slice(&[0xCC; 36]);
    let encoded = SessionDatagram::new(src_addr, my_addr, data_payload).encode();

    node.handle_session_datagram(&from, &encoded[1..], false)
        .await;
    assert!(
        node.coord_cache().get_entry(&src_addr).is_none(),
        "a CP frame to this node with no session must not write its source coordinates"
    );
    assert!(
        node.coord_cache().get_entry(&my_addr).is_none(),
        "nor its destination coordinates, under this node's own address"
    );
    assert_eq!(
        node.metrics().forwarding.warm_malformed_packets.get(),
        0,
        "a well-formed CP frame must not be counted as malformed"
    );
}

#[tokio::test]
async fn a_hint_write_under_a_foreign_root_is_refused_at_insert_coord_hint() {
    let mut node = make_node();
    let addr = make_node_addr(0x01);
    let foreign_root = make_node_addr(0xF0);
    assert_ne!(&foreign_root, node.tree_state.my_coords().root_id());
    let coords = TreeCoordinate::from_addrs(vec![addr, foreign_root]).unwrap();

    let now = wall_ms();
    let _ = node.insert_coord_hint(addr, coords, now, Funding::Uncharged);
    assert!(
        node.coord_cache().get(&addr, now).is_none(),
        "a hint under a foreign root was cached through insert_coord_hint"
    );

    // Control: the same write under this node's root lands.
    let root = *node.tree_state.my_coords().root_id();
    let ours = TreeCoordinate::from_addrs(vec![addr, root]).unwrap();
    let _ = node.insert_coord_hint(addr, ours.clone(), now, Funding::Uncharged);
    assert_eq!(node.coord_cache().get(&addr, now), Some(&ours));
}

// --- Per-link-peer hint budget ---

/// Stored placements of `count` minted sources from `first`: (main, probation).
fn placements(node: &Node, first: u32, count: u32) -> (u64, u64) {
    let (mut main, mut probation) = (0, 0);
    for i in first..first + count {
        match node.coord_cache().segment_of(&minted_dest(i)) {
            Some(crate::cache::Segment::Main) => main += 1,
            Some(crate::cache::Segment::Probation) => probation += 1,
            None => {}
        }
    }
    (main, probation)
}

/// Send `count` SessionSetups over `from`, each with a fresh source of
/// `len` addresses from `first`, to one fixed cached destination.
async fn send_fresh_sources(node: &mut Node, from: &NodeAddr, first: u32, count: u32, len: usize) {
    let root = *node.tree_state.my_coords().root_id();
    let dest = make_node_addr(0x02);
    let dest_coords = coords_of_len(dest, root, 2);
    for i in first..first + count {
        let src = minted_dest(i);
        let frame = setup_frame(
            src,
            coords_of_len(src, root, len),
            dest,
            dest_coords.clone(),
            8,
        );
        node.handle_session_datagram(from, &frame, false).await;
    }
}

/// A node with the fixed destination of `send_fresh_sources` cached.
fn node_with_cached_dest() -> Node {
    let mut node = make_node();
    let root = *node.tree_state.my_coords().root_id();
    let dest = make_node_addr(0x02);
    let _ = node
        .coord_cache_mut()
        .insert(dest, coords_of_len(dest, root, 2), wall_ms());
    node
}

#[tokio::test]
async fn main_placements_match_the_budget_and_the_rest_are_counted_unfunded() {
    let mut node = node_with_cached_dest();
    let from = make_node_addr(0xAA);
    let sent = 3_000u32;
    let unfunded = node.metrics().forwarding.coord_hint_unfunded.get();

    let started = std::time::Instant::now();
    send_fresh_sources(&mut node, &from, 0, sent, 2).await;
    let elapsed_ms = started.elapsed().as_millis() as u64;

    let (main, probation) = placements(&node, 0, sent);
    let counted = node.metrics().forwarding.coord_hint_unfunded.get() - unfunded;
    let allowed = (elapsed_ms * HINT_KEYS_PER_SEC).div_ceil(1000);
    assert!(
        main <= allowed,
        "one link peer placed {main} new destinations in main in {elapsed_ms} ms, \
         against an allowance of {allowed}"
    );
    assert_eq!(
        main + counted,
        u64::from(sent),
        "every source not paid into main must be counted unfunded"
    );
    assert_eq!(probation, counted.min(UNPAID_HINT_ENTRIES));
}

#[tokio::test]
async fn twenty_fresh_link_peers_place_no_more_in_main_than_twenty_initial_fills_and_their_refill()
{
    let mut node = node_with_cached_dest();
    let (peers, each) = (20u32, 200u32);
    let started = std::time::Instant::now();
    for p in 0..peers {
        let from = make_node_addr(0x40 + p as u8);
        send_fresh_sources(&mut node, &from, p * each, each, 2).await;
    }
    let elapsed_ms = started.elapsed().as_millis() as u64;

    // Each peer starts with no weight and earns at most its rate for the run.
    // The initial fill of zero is what this test pins, so it is not read from
    // the constant.
    let allowed = u64::from(peers) * (elapsed_ms * HINT_KEYS_PER_SEC).div_ceil(1000);
    let (main, _) = placements(&node, 0, peers * each);
    assert!(
        allowed < u64::from(peers * each),
        "the run took {elapsed_ms} ms, too long for the bound to discriminate"
    );
    assert!(
        main <= allowed,
        "{peers} fresh link peers placed {main} new destinations in main in \
         {elapsed_ms} ms, against an allowance of {allowed}"
    );
}

#[tokio::test]
async fn a_peer_holding_fifteen_units_places_a_depth_sixteen_key_in_probation() {
    // A budget that never refills, so the peer holds exactly what it starts with.
    let mut node = node_with_cached_dest();
    node.coord_hint_budget = PeerBudget::with_initial(0, 4_096, 15);
    let from = make_node_addr(0xAA);
    send_fresh_sources(&mut node, &from, 0, 1, 16).await;
    assert_eq!(
        node.coord_cache().segment_of(&minted_dest(0)),
        Some(crate::cache::Segment::Probation),
        "fifteen units do not pay for a key of weight sixteen"
    );

    // Control: sixteen units do.
    let mut node = node_with_cached_dest();
    node.coord_hint_budget = PeerBudget::with_initial(0, 4_096, 16);
    send_fresh_sources(&mut node, &from, 0, 1, 16).await;
    assert_eq!(
        node.coord_cache().segment_of(&minted_dest(0)),
        Some(crate::cache::Segment::Main)
    );
    assert_eq!(
        node.coord_hint_budget
            .available(&from, std::time::Instant::now()),
        0
    );
}

#[tokio::test]
async fn a_second_link_peer_is_still_paid_for() {
    let mut node = node_with_cached_dest();
    node.coord_hint_budget = PeerBudget::with_initial(0, 4_096, 64);
    let (noisy, quiet) = (make_node_addr(0xAA), make_node_addr(0xBB));
    send_fresh_sources(&mut node, &noisy, 0, 10, 2).await;
    assert_eq!(
        placements(&node, 0, 10),
        (4, 6),
        "64 units pay for four keys"
    );

    send_fresh_sources(&mut node, &quiet, 100, 1, 2).await;
    assert_eq!(
        node.coord_cache().segment_of(&minted_dest(100)),
        Some(crate::cache::Segment::Main),
        "another link peer's budget is its own"
    );
}

#[tokio::test]
async fn a_hint_refused_for_a_verified_entry_costs_its_link_peer_nothing() {
    let mut node = node_with_cached_dest();
    node.coord_hint_budget = PeerBudget::with_initial(0, 4_096, 100);
    let root = *node.tree_state.my_coords().root_id();
    let from = make_node_addr(0xAA);
    let src = minted_dest(0);
    node.coord_cache_mut()
        .insert_verified(src, coords_of_len(src, root, 2), wall_ms());

    // A deeper rewrite of the verified source would cost 24 if it were made.
    let refused = node.metrics().forwarding.coord_hint_rejected.get();
    send_fresh_sources(&mut node, &from, 0, 1, 40).await;
    assert_eq!(
        node.metrics().forwarding.coord_hint_rejected.get(),
        refused + 1,
        "the write must have been refused for the verified entry"
    );
    assert_eq!(
        node.coord_hint_budget
            .available(&from, std::time::Instant::now()),
        100,
        "a refused write must not be charged"
    );
}

/// Run a session from node 0 to node 3 over the chain 0 - 1 - 2 - 3, with
/// node 1's cache emptied so both its link peers' hints are unpaid, and
/// `flood` unpaid depth-70 keys from node 0 arriving at node 1 between the
/// ack and the msg3. With `touch`, one frame from node 0 to node 3 that
/// carries no coordinates is routed by node 1 halfway through the flood, using
/// node 3's entry. Returns the nodes, with node 1's no-route drops during the
/// msg3's arrival.
async fn session_through_drained_transit(flood: u32, touch: bool) -> (Vec<TestNode>, u64) {
    let edges = vec![(0, 1), (1, 2), (2, 3)];
    let mut nodes = run_tree_test(4, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    nodes[1].node.coord_cache_mut().clear();

    let node0 = *nodes[0].node.node_addr();
    let node3 = *nodes[3].node.node_addr();
    let node3_pubkey = nodes[3].node.identity().pubkey_full();
    nodes[0]
        .node
        .initiate_session(node3, node3_pubkey)
        .await
        .expect("initiate_session failed");

    // Setup 0 -> 1 -> 2 -> 3, then ack 3 -> 2 -> 1 -> 0: six hops.
    for _ in 0..6 {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }
    assert!(
        nodes[0]
            .node
            .get_session(&node3)
            .is_some_and(|e| e.is_established()),
        "the initiator is established once its msg3 leaves"
    );
    assert_eq!(
        nodes[1].node.coord_cache().segment_of(&node3),
        Some(crate::cache::Segment::Probation),
        "the responder's entry at the transit must be unpaid"
    );

    let root = *nodes[1].node.tree_state.my_coords().root_id();
    let sink = make_node_addr(0x02);
    for i in 0..flood {
        if touch && i == flood / 2 {
            // Too short for an FSP prefix, so it warms nothing, and node 3
            // drops it.
            let frame = SessionDatagram::new(make_node_addr(0x55), node3, vec![0u8; 2])
                .with_ttl(64)
                .encode()[1..]
                .to_vec();
            nodes[1]
                .node
                .handle_session_datagram(&node0, &frame, false)
                .await;
        }
        let src = minted_dest(i);
        let frame = setup_frame(
            src,
            coords_of_len(src, root, 71),
            sink,
            coords_of_len(sink, root, 2),
            1,
        );
        nodes[1]
            .node
            .handle_session_datagram(&node0, &frame, false)
            .await;
    }

    // The msg3, 0 -> 1, then on to 2 and 3 if node 1 can route it.
    let no_route = nodes[1]
        .node
        .metrics()
        .forwarding
        .drop_no_route_packets
        .get();
    for _ in 0..3 {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }
    let dropped = nodes[1]
        .node
        .metrics()
        .forwarding
        .drop_no_route_packets
        .get()
        - no_route;
    (nodes, dropped)
}

#[tokio::test]
async fn a_session_completes_through_a_transit_with_both_sides_drained_under_a_deep_flood_below_the_probation_size()
 {
    // Below the probation size: the msg3 is forwarded and the session completes.
    let (mut nodes, dropped) = session_through_drained_transit(1_000, false).await;
    let node0 = *nodes[0].node.node_addr();
    assert_eq!(dropped, 0, "the msg3 must not meet a missing route");
    assert!(
        nodes[3]
            .node
            .get_session(&node0)
            .is_some_and(|e| e.is_established()),
        "the responder must complete the session"
    );
    cleanup_nodes(&mut nodes).await;

    // The accepted residual: past the probation size the msg3 meets no route,
    // and the session completes once the flood stops, through the warmup the
    // routing error draws and the msg3 resend.
    let (mut nodes, dropped) = session_through_drained_transit(2_000, false).await;
    let node0 = *nodes[0].node.node_addr();
    assert_eq!(
        dropped, 1,
        "past the probation size the msg3 meets no route"
    );
    assert!(
        !nodes[3]
            .node
            .get_session(&node0)
            .is_some_and(|e| e.is_established())
    );
    // The initiator's session machine resends its retained msg3 at its
    // first rung, 1 s after the session was set up.
    nodes[0]
        .node
        .poll_session_rekeys(crate::node::session::session_after(
            Node::session_now(),
            1_001,
        ))
        .await;
    for _ in 0..6 {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }
    assert!(
        nodes[3]
            .node
            .get_session(&node0)
            .is_some_and(|e| e.is_established()),
        "the responder must complete the session once the msg3 is resent"
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_session_completes_through_a_drained_transit_past_the_probation_size_when_a_frame_used_the_responders_entry()
 {
    // The flood that makes the msg3 meet no route above, but a frame of the
    // flow has used node 3's entry since it was written, so it is restamped
    // rather than evicted.
    let (mut nodes, dropped) = session_through_drained_transit(2_000, true).await;
    let node0 = *nodes[0].node.node_addr();
    assert_eq!(dropped, 0, "the used entry must survive the flood");
    assert!(
        nodes[3]
            .node
            .get_session(&node0)
            .is_some_and(|e| e.is_established()),
        "the responder must complete the session"
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn an_honest_rewrite_corrects_a_shallow_forgery_of_a_deep_destination() {
    let mut node = make_node();
    let (honest, attacker) = (make_node_addr(0xAA), make_node_addr(0xBB));
    let root = *node.tree_state.my_coords().root_id();

    // A destination nineteen hops deep, cached from earlier honest traffic,
    // and a key the hub's own traffic deepens by one address at a time.
    let d = make_node_addr(0x42);
    let real = coords_of_len(d, root, 20);
    let _ = node.coord_cache_mut().insert(d, real.clone(), wall_ms());
    let sink = make_node_addr(0x02);
    let sink_coords = coords_of_len(sink, root, 2);
    let _ = node
        .coord_cache_mut()
        .insert(sink, sink_coords.clone(), wall_ms());
    let k = make_node_addr(0x43);
    let _ = node
        .coord_cache_mut()
        .insert(k, coords_of_len(k, root, 16), wall_ms());

    // The forgery: shallow coordinates for d from another link peer, unpaid.
    let forged = coords_of_len(d, root, 3);
    let frame = setup_frame(d, forged.clone(), sink, sink_coords.clone(), 1);
    node.handle_session_datagram(&attacker, &frame, false).await;
    assert_eq!(node.coord_cache().get(&d, wall_ms()), Some(&forged));

    // Traffic through the honest hub spends its budget.
    for i in 0..64u32 {
        let s = minted_dest(i);
        let frame = setup_frame(s, coords_of_len(s, root, 2), sink, sink_coords.clone(), 1);
        node.handle_session_datagram(&honest, &frame, false).await;
    }
    for _ in 0..32 {
        for len in [17, 16] {
            let frame = setup_frame(k, coords_of_len(k, root, len), sink, sink_coords.clone(), 1);
            node.handle_session_datagram(&honest, &frame, false).await;
        }
    }

    // d's own traffic carries its real coordinates through the hub.
    let frame = setup_frame(d, real.clone(), sink, sink_coords.clone(), 1);
    node.handle_session_datagram(&honest, &frame, false).await;
    assert_eq!(
        node.coord_cache().get(&d, wall_ms()),
        Some(&real),
        "the honest rewrite did not replace the forged shallow coordinates"
    );
}

#[tokio::test]
async fn a_paid_shallow_write_cannot_promote_a_deep_destination_past_its_honest_correction() {
    let mut node = make_node();
    // Every link peer starts with 16 units and never refills, so the test
    // does not depend on the wall clock.
    node.coord_hint_budget = PeerBudget::with_initial(0, 4_096, 16);
    let (honest, attacker) = (make_node_addr(0xAA), make_node_addr(0xBB));
    let root = *node.tree_state.my_coords().root_id();
    let sink = make_node_addr(0x02);
    let sink_coords = coords_of_len(sink, root, 2);
    let _ = node
        .coord_cache_mut()
        .insert(sink, sink_coords.clone(), wall_ms());

    // The honest hub spends its 16 units on one ordinary new destination.
    let x = minted_dest(1);
    let frame = setup_frame(x, coords_of_len(x, root, 2), sink, sink_coords.clone(), 1);
    node.handle_session_datagram(&honest, &frame, false).await;
    assert_eq!(
        node.coord_cache().segment_of(&x),
        Some(crate::cache::Segment::Main)
    );

    // d, twenty addresses deep, first appears through the drained hub, so it
    // goes to probation.
    let d = make_node_addr(0x42);
    let real = coords_of_len(d, root, 20);
    let frame = setup_frame(d, real.clone(), sink, sink_coords.clone(), 1);
    node.handle_session_datagram(&honest, &frame, false).await;
    assert_eq!(
        node.coord_cache().segment_of(&d),
        Some(crate::cache::Segment::Probation)
    );

    // Another link peer, holding 16 units, names d with shallow coordinates.
    let forged = coords_of_len(d, root, 3);
    let frame = setup_frame(d, forged.clone(), sink, sink_coords.clone(), 1);
    node.handle_session_datagram(&attacker, &frame, false).await;

    // d's own traffic carries its real coordinates through the hub again.
    let frame = setup_frame(d, real.clone(), sink, sink_coords.clone(), 1);
    node.handle_session_datagram(&honest, &frame, false).await;
    assert_eq!(
        node.coord_cache().get(&d, wall_ms()),
        Some(&real),
        "the honest rewrite did not replace the forged coordinates"
    );
}

/// Node 1 holds an expired entry for a destination behind node 2, more than
/// sixteen addresses deep. A SessionSetup for it arrives over node 0, whose
/// coordinate budget is empty, carrying coordinates one level deeper when
/// `deepen` is set, or at the same depth. The setup carries the only route to
/// the destination, so node 1 must forward it either way. Returns the frames
/// forwarded and the frames dropped for want of a route.
async fn setup_for_an_expired_destination(deepen: bool) -> (u64, u64) {
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node0 = *nodes[0].node.node_addr();
    let node2_coords = nodes[2].node.tree_state().my_coords().clone();
    let root = *nodes[1].node.tree_state().my_coords().root_id();
    nodes[1].node.coord_hint_budget = PeerBudget::with_initial(0, 0, 0);

    let dest = make_node_addr(0x77);
    let deep = |fillers: u32| {
        let mut path = vec![dest];
        path.extend((0..fillers).map(|i| {
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&i.to_le_bytes());
            bytes[15] = 0xe0;
            NodeAddr::from_bytes(bytes)
        }));
        path.extend(node2_coords.node_addrs().copied());
        TreeCoordinate::from_addrs(path).unwrap()
    };
    let old = deep(15);
    let new = if deepen { deep(16) } else { deep(15) };
    assert!(
        old.entries().len() > 16,
        "old depth {}",
        old.entries().len()
    );
    assert!(!deepen || new.entries().len() == old.entries().len() + 1);

    // Cached long enough ago that its TTL has lapsed, and never used since.
    let long_ago = wall_ms() - 2 * crate::cache::DEFAULT_COORD_CACHE_TTL_MS;
    let _ = nodes[1].node.coord_cache_mut().insert(dest, old, long_ago);

    let src = make_node_addr(0x66);
    let frame = setup_frame(src, coords_of_len(src, root, 2), dest, new, 64);
    let fwd = &nodes[1].node.metrics().forwarding;
    let (forwarded, no_route) = (fwd.forwarded_packets.get(), fwd.drop_no_route_packets.get());
    nodes[1]
        .node
        .handle_session_datagram(&node0, &frame, false)
        .await;
    let fwd = &nodes[1].node.metrics().forwarding;
    let result = (
        fwd.forwarded_packets.get() - forwarded,
        fwd.drop_no_route_packets.get() - no_route,
    );
    cleanup_nodes(&mut nodes).await;
    result
}

#[tokio::test]
async fn a_drained_peers_setup_for_an_expired_destination_at_the_same_depth_is_forwarded() {
    assert_eq!(setup_for_an_expired_destination(false).await, (1, 0));
}

#[tokio::test]
async fn a_drained_peers_setup_for_an_expired_destination_one_level_deeper_is_forwarded() {
    assert_eq!(
        setup_for_an_expired_destination(true).await,
        (1, 0),
        "the setup was dropped for want of a route"
    );
}

/// Node 1's main segment holds only live-verified entries (its own lookups),
/// so a hint cannot make room there. An honest SessionSetup for a destination
/// behind node 2 that node 1 has never cached arrives over node 0, whose
/// coordinate budget can pay for it when `paid` is set and is empty otherwise.
/// The budget decides where the hint is placed, never whether the frame
/// routes. Returns the frames forwarded and the frames dropped for want of a
/// route.
async fn setup_through_a_transit_full_of_verified_entries(paid: bool) -> (u64, u64) {
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node0 = *nodes[0].node.node_addr();
    let node2_coords = nodes[2].node.tree_state().my_coords().clone();
    let root = *nodes[1].node.tree_state().my_coords().root_id();

    *nodes[1].node.coord_cache_mut() = crate::cache::CoordCache::new(4, 300_000);
    for i in 0..4u32 {
        let a = minted_dest(900_000 + i);
        nodes[1]
            .node
            .coord_cache_mut()
            .insert_verified(a, coords_of_len(a, root, 2), wall_ms());
    }
    nodes[1].node.coord_hint_budget = if paid {
        PeerBudget::with_initial(0, 4_096, 4_096)
    } else {
        PeerBudget::with_initial(0, 0, 0)
    };

    let dest = make_node_addr(0x77);
    let mut path = vec![dest];
    path.extend(node2_coords.node_addrs().copied());
    let dest_coords = TreeCoordinate::from_addrs(path).unwrap();
    let src = make_node_addr(0x66);
    let frame = setup_frame(src, coords_of_len(src, root, 2), dest, dest_coords, 64);

    let fwd = &nodes[1].node.metrics().forwarding;
    let (forwarded, no_route) = (fwd.forwarded_packets.get(), fwd.drop_no_route_packets.get());
    nodes[1]
        .node
        .handle_session_datagram(&node0, &frame, false)
        .await;
    let fwd = &nodes[1].node.metrics().forwarding;
    let result = (
        fwd.forwarded_packets.get() - forwarded,
        fwd.drop_no_route_packets.get() - no_route,
    );
    cleanup_nodes(&mut nodes).await;
    result
}

#[tokio::test]
async fn a_drained_peers_setup_routes_through_a_transit_full_of_verified_entries() {
    assert_eq!(
        setup_through_a_transit_full_of_verified_entries(false).await,
        (1, 0)
    );
}

#[tokio::test]
async fn a_paying_peers_setup_routes_through_a_transit_full_of_verified_entries() {
    assert_eq!(
        setup_through_a_transit_full_of_verified_entries(true).await,
        (1, 0),
        "the paid setup was dropped for want of a route while an unpaid one routes"
    );
}

#[tokio::test]
async fn a_foreign_root_write_is_not_counted_as_a_key_mismatch() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let root = *node.tree_state.my_coords().root_id();
    let foreign_root = make_node_addr(0xF0);
    assert_ne!(foreign_root, root);
    // A foreign-root coordinate that also names another key first.
    let src = make_node_addr(0x01);
    let src_coords = TreeCoordinate::from_addrs(vec![make_node_addr(0x03), foreign_root]).unwrap();
    let dest = make_node_addr(0x02);
    let frame = setup_frame(src, src_coords, dest, coords_of_len(dest, root, 2), 8);
    let fwd = &node.metrics().forwarding;
    let (foreign, mismatch) = (
        fwd.coord_warm_foreign_root.get(),
        fwd.coord_warm_key_mismatch.get(),
    );
    node.handle_session_datagram(&from, &frame, false).await;
    let fwd = &node.metrics().forwarding;
    assert_eq!(fwd.coord_warm_foreign_root.get(), foreign + 1);
    assert_eq!(
        fwd.coord_warm_key_mismatch.get(),
        mismatch,
        "a write refused for a foreign root was also counted as a key mismatch"
    );
}
