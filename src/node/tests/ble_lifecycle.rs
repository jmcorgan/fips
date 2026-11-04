//! The BLE connection lifecycle at node level: a deliberate close still
//! sends what was queued, and a channel that never carries a handshake is
//! closed once the handshake timeout has passed (FRC-1301 Section 6.5.4).
//!
//! Two `MockBleIo` nodes, through the helpers `ble.rs` exports. The ageing
//! tests advance every clock the node and the BLE pool read together:
//! tokio's (the pool's admission stamps), the wall clock and the monotonic
//! host clock (`check_timeouts`, peer timers), and run the node's tick after
//! each second as the receive loop does: `check_timeouts()`, then
//! `drive_peer_timers(Node::interval_ms())`, as `settle::clock` does, then
//! the retry, connect and discovery polls.

use super::ble::{
    base_config, ble_addr, inject_claim, larger_second, link_genuinely, make_test_node_ble_with,
    pooled_at, until,
};
use super::spanning_tree::{self, TestNode, cleanup_nodes, drain_all_packets, initiate_handshake};
use super::*;
use crate::config::BleConfig;
use crate::transport::ConnectionState;

/// Advance every clock by one second `secs` times, running the node's
/// timer-driven tick steps after each second, as the rx loop's tick does.
async fn age(node: &mut TestNode, secs: u64) {
    age_with(node, secs, true).await;
}

/// As [`age`], polling transport discovery each second only when `discover`
/// is set, so a claim waiting in the neighbour buffer is not dialled.
async fn age_with(node: &mut TestNode, secs: u64, discover: bool) {
    for _ in 0..secs {
        tokio::time::advance(Duration::from_secs(1)).await;
        crate::time::step_wall(1_000);
        crate::time::advance(Duration::from_secs(1));
        node.node.check_timeouts().await;
        node.node.drive_peer_timers(Node::interval_ms()).await;
        node.node.process_pending_retries(Node::peering_now()).await;
        node.node.poll_pending_connects().await;
        if discover {
            node.node.poll_transport_discovery().await;
        }
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }
}

/// Two BLE nodes under `config`, node 1 the larger so it admits inbound
/// channels claiming node 0's key; node 1 is running.
async fn pair(config: BleConfig) -> Vec<TestNode> {
    let mut nodes = vec![
        make_test_node_ble_with(1, config.clone()).await,
        make_test_node_ble_with(2, config).await,
    ];
    larger_second(&mut nodes);
    nodes[1].node.supervisor.state = NodeState::Running;
    nodes
}

/// The handshake timeout of node 1, in seconds.
fn timeout_secs(nodes: &[TestNode]) -> u64 {
    nodes[1]
        .node
        .config()
        .node
        .rate_limit
        .handshake_timeout_secs
}

// ============================================================================
// A deliberate close sends what was queued
// ============================================================================

/// The Disconnect `api_disconnect` sends must reach the BLE peer before the
/// connection closes, so the peer forgets this node at once rather than at
/// link-dead detection (30 s by default, far past the two-second wait). The
/// BLE twin of `tcp::api_disconnect_delivers_the_disconnect_before_closing`.
#[tokio::test]
async fn api_disconnect_over_ble_delivers_the_disconnect_before_closing() {
    let mut nodes = vec![
        make_test_node_ble_with(1, base_config()).await,
        make_test_node_ble_with(2, base_config()).await,
    ];
    larger_second(&mut nodes);
    nodes[1].node.supervisor.state = NodeState::Running;
    let _bank = link_genuinely(&nodes).await;
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;

    let addr_0 = *nodes[0].node.node_addr();
    let addr_1 = *nodes[1].node.node_addr();
    let node1_npub = nodes[1].node.npub();
    assert!(
        nodes[0].node.get_peer(&addr_1).is_some(),
        "precondition: node 0 peers with node 1"
    );
    assert!(
        nodes[1].node.get_peer(&addr_0).is_some(),
        "precondition: node 1 peers with node 0"
    );
    let peer = nodes[0].node.get_peer(&addr_1).unwrap();
    let tid = peer
        .transport_id()
        .expect("precondition: the peer has a transport");
    let at = peer
        .current_addr()
        .expect("precondition: the peer has an address")
        .clone();
    assert_eq!(
        nodes[0]
            .node
            .transports
            .get(&tid)
            .unwrap()
            .connection_state(&at),
        ConnectionState::Connected,
        "precondition: node 0 pools the BLE link"
    );

    nodes[0]
        .node
        .api_disconnect(&node1_npub)
        .await
        .expect("precondition: api_disconnect succeeds");
    assert!(
        nodes[0].node.get_peer(&addr_1).is_none(),
        "precondition: node 0 removed node 1"
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while nodes[1].node.get_peer(&addr_0).is_some() && std::time::Instant::now() < deadline {
        spanning_tree::process_available_packets(&mut nodes).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let held = nodes[1].node.get_peer(&addr_0).is_some();
    cleanup_nodes(&mut nodes).await;
    assert!(
        !held,
        "defect: node 1 never received the Disconnect node 0 sent over BLE before the close"
    );
}

// ============================================================================
// A channel with no handshake is closed after the handshake timeout
// ============================================================================

/// Default BLE configuration (`auto_connect` off): a channel whose key
/// exchange completes and that never carries a msg1 must be closed once the
/// handshake timeout has passed since it was admitted.
#[tokio::test(start_paused = true)]
async fn an_unverified_ble_channel_with_no_msg1_is_closed_after_the_handshake_timeout() {
    let mut nodes = pair(base_config()).await;
    let key_0 = nodes[0].node.identity().pubkey().serialize();
    let at = ble_addr(9).to_transport_addr();
    let _remote = inject_claim(&nodes, 1, &ble_addr(9), key_0).await;
    assert!(
        until(|| pooled_at(&nodes[1], &at)).await,
        "precondition: the key exchange is done and the channel pooled"
    );
    assert_eq!(
        nodes[1].node.connection_count(),
        0,
        "precondition: no msg1, so no handshake leg"
    );

    let deadline = timeout_secs(&nodes);
    age(&mut nodes[1], 4 * deadline).await;
    let held = pooled_at(&nodes[1], &at);
    cleanup_nodes(&mut nodes).await;
    assert!(
        !held,
        "defect: an unverified channel with no msg1 was still pooled {}s after its key \
         exchange (handshake timeout {deadline}s)",
        4 * deadline
    );
}

/// Control: with `auto_connect` on and no peer yet, the node dials the claim,
/// so a msg1 goes out; the handshake reaper then closes the channel with the
/// leg it reaps.
#[tokio::test(start_paused = true)]
async fn a_dialled_claim_that_never_answers_is_closed_by_the_handshake_reaper() {
    let auto = BleConfig {
        auto_connect: Some(true),
        ..base_config()
    };
    let mut nodes = pair(auto).await;
    let key_0 = nodes[0].node.identity().pubkey().serialize();
    let n0 = *nodes[0].node.node_addr();
    let at = ble_addr(9).to_transport_addr();
    let _remote = inject_claim(&nodes, 1, &ble_addr(9), key_0).await;
    assert!(
        until(|| pooled_at(&nodes[1], &at)).await,
        "precondition: the claim is pooled"
    );
    nodes[1].node.poll_transport_discovery().await;
    for _ in 0..50 {
        nodes[1].node.poll_pending_connects().await;
        if nodes[1].node.peering.pending_connects.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        nodes[1]
            .node
            .is_connecting_to_peer_on_path(&n0, nodes[1].transport_id, &at),
        "precondition: node 1 dials the claim, so a msg1 went out on it"
    );

    let deadline = timeout_secs(&nodes);
    age(&mut nodes[1], 4 * deadline).await;
    let held = pooled_at(&nodes[1], &at);
    cleanup_nodes(&mut nodes).await;
    assert!(
        !held,
        "defect: a dialled claim was still pooled {}s after its msg1",
        4 * deadline
    );
}

/// A claim the node dials late, 25 s after its key exchange, is kept a full
/// handshake timeout after the dial's msg1, as FRC-1301 Section 6.5.4 asks,
/// and is closed with the leg's reap.
#[tokio::test(start_paused = true)]
async fn a_channel_whose_first_msg1_comes_late_is_kept_a_full_timeout_after_it() {
    let auto = BleConfig {
        auto_connect: Some(true),
        ..base_config()
    };
    let mut nodes = pair(auto).await;
    let key_0 = nodes[0].node.identity().pubkey().serialize();
    let n0 = *nodes[0].node.node_addr();
    let at = ble_addr(9).to_transport_addr();
    let _remote = inject_claim(&nodes, 1, &ble_addr(9), key_0).await;
    assert!(
        until(|| pooled_at(&nodes[1], &at)).await,
        "precondition: the claim is pooled"
    );
    let deadline = timeout_secs(&nodes);
    assert_eq!(deadline, 30, "precondition: the default handshake timeout");

    age_with(&mut nodes[1], 25, false).await;
    assert!(
        pooled_at(&nodes[1], &at),
        "precondition: the claim is still pooled before its timeout"
    );
    nodes[1].node.poll_transport_discovery().await;
    for _ in 0..50 {
        nodes[1].node.poll_pending_connects().await;
        if nodes[1].node.peering.pending_connects.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        nodes[1]
            .node
            .is_connecting_to_peer_on_path(&n0, nodes[1].transport_id, &at),
        "precondition: node 1 dials the claim 25 s after its key exchange"
    );

    age(&mut nodes[1], 15).await;
    let kept = pooled_at(&nodes[1], &at);
    age(&mut nodes[1], 20).await;
    let held_after_reap = pooled_at(&nodes[1], &at);
    cleanup_nodes(&mut nodes).await;
    assert!(
        kept,
        "defect: a channel was closed 15 s after its first msg1, less than the handshake timeout"
    );
    assert!(
        !held_after_reap,
        "defect: a channel was still pooled 35 s after its first msg1, after the leg's reap"
    );
}

/// Healthy path: a verified link carrying an established peer survives the
/// same ageing.
#[tokio::test(start_paused = true)]
async fn a_verified_ble_link_survives_the_same_ageing() {
    let mut nodes = pair(base_config()).await;
    let _bank = link_genuinely(&nodes).await;
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let n0 = *nodes[0].node.node_addr();
    assert!(
        nodes[1].node.get_peer(&n0).is_some(),
        "precondition: node 1 peers with node 0"
    );
    let genuine = nodes[1].addr.clone();
    assert!(
        pooled_at(&nodes[1], &genuine),
        "precondition: the genuine link is pooled"
    );

    let deadline = timeout_secs(&nodes);
    age(&mut nodes[1], 4 * deadline).await;
    let held = pooled_at(&nodes[1], &genuine);
    cleanup_nodes(&mut nodes).await;
    assert!(held, "defect: the verified link was closed");
}
