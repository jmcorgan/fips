//! A BLE channel on which no handshake has completed is closed once the
//! handshake timeout has passed since its key exchange, or since the node
//! last held a handshake or link on it (FRC-1301 Section 6.5.4).
//!
//! Two `MockBleIo` nodes, through the helpers `ble.rs` exports. The ageing
//! tests advance tokio's clock, which the pool's admission stamps and the
//! node's channel sweep read, and run the node's tick steps after each
//! second as the receive loop does. The wall clock the handshake leg reaper
//! reads is not advanced, so no test here depends on a leg being reaped.

use super::ble::{
    base_config, ble_addr, inject_claim, larger_second, link_genuinely, make_test_node_ble_with,
    pooled_at, until,
};
use super::spanning_tree::{TestNode, cleanup_nodes, drain_all_packets, initiate_handshake};
use super::*;
use crate::config::BleConfig;

/// Advance tokio's clock by one second `secs` times, running the node's
/// timer-driven tick steps after each second, as the rx loop's tick does.
async fn age(node: &mut TestNode, secs: u64) {
    age_with(node, secs, true).await;
}

/// As [`age`], polling transport discovery each second only when `discover`
/// is set, so a claim waiting in the neighbour buffer is not dialled.
async fn age_with(node: &mut TestNode, secs: u64, discover: bool) {
    for _ in 0..secs {
        // Only tokio's clock moves: the tests have no wall clock to step.
        tokio::time::advance(Duration::from_secs(1)).await;
        node.node.check_timeouts().await;
        node.node.drive_peer_timers(Node::now_ms()).await;
        node.node.process_pending_retries(Node::now_ms()).await;
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

/// Default BLE configuration (`auto_connect` off): a channel whose key
/// exchange completes and that never carries a msg1 is kept until the
/// handshake timeout and closed once it has passed.
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
    age(&mut nodes[1], deadline - 2).await;
    let early = pooled_at(&nodes[1], &at);
    age(&mut nodes[1], 4).await;
    let late = pooled_at(&nodes[1], &at);
    cleanup_nodes(&mut nodes).await;
    assert!(
        early,
        "a channel was closed {}s after its key exchange, before the handshake timeout \
         ({deadline}s)",
        deadline - 2
    );
    assert!(
        !late,
        "an unverified channel with no msg1 was still pooled {}s after its key exchange \
         (handshake timeout {deadline}s)",
        deadline + 2
    );
}

/// A claim the node dials late, 25 s after its key exchange, is still kept
/// 15 s after the dial's msg1, 40 s after its admission: the node holds a
/// handshake on it, so its clock starts again.
#[tokio::test(start_paused = true)]
async fn a_channel_whose_first_msg1_comes_late_is_kept_a_timeout_after_it() {
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
    cleanup_nodes(&mut nodes).await;
    assert!(
        kept,
        "a channel was closed 15 s after its first msg1, less than the handshake timeout"
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
    assert!(held, "the verified link was closed");
}
