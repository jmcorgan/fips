//! Link-dead heartbeat rekey-awareness integration tests.
//!
//! `check_link_heartbeats()` reaps a peer after the link-dead timeout,
//! but suppresses teardown while an FMP rekey is genuinely in flight with
//! its msg1 retransmission budget unexhausted. These tests drive a real
//! two-node UDP peering, inject rekey state on the peer, and verify the
//! suppress / resume / regression behaviors. `link_dead_timeout_secs` is
//! set to 0 so the elapsed-time predicate is always satisfied and the only
//! variable is the rekey-active guard.

use super::spanning_tree::*;
use super::*;
use crate::Identity;
use crate::noise::HandshakeState;
use crate::utils::index::SessionIndex;

/// Arm a real (initiator) FMP rekey on the peer the given node holds for
/// `peer_addr`, so the msg1 resend budget can be exercised.
fn arm_rekey(node: &mut crate::node::Node, peer_addr: &NodeAddr) {
    let remote = Identity::generate();
    let local = Identity::generate();
    let hs = HandshakeState::new_initiator(local.keypair(), remote.pubkey_full());
    let peer = node.get_peer_mut(peer_addr).expect("peer present");
    peer.set_rekey_state(hs, SessionIndex::new(7), vec![0xAB; 64], 0);
}

/// A peer past the link-dead timeout is NOT reaped while an FMP rekey is in
/// progress with its msg1 budget unexhausted.
#[tokio::test]
async fn heartbeat_suppressed_during_rekey() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    assert!(nodes[0].node.get_peer(&addr_1).is_some());

    // Force every link to read as dead on elapsed time alone.
    nodes[0].node.config.node.link_dead_timeout_secs = 0;

    // Arm a rekey with budget left (count 0 < max_resends default 5).
    arm_rekey(&mut nodes[0].node, &addr_1);
    assert!(nodes[0].node.get_peer(&addr_1).unwrap().rekey_in_progress());

    nodes[0].node.check_link_heartbeats().await;

    assert!(
        nodes[0].node.get_peer(&addr_1).is_some(),
        "peer reaped despite an in-flight rekey with budget remaining"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Once the msg1 budget is exhausted the rekey-active guard no longer
/// holds, so a peer past the link-dead timeout IS reaped.
#[tokio::test]
async fn heartbeat_resumes_after_budget_exhausted() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    assert!(nodes[0].node.get_peer(&addr_1).is_some());

    nodes[0].node.config.node.link_dead_timeout_secs = 0;
    let max_resends = nodes[0].node.config.node.rate_limit.handshake_max_resends;

    arm_rekey(&mut nodes[0].node, &addr_1);

    // Exhaust the budget: count reaches max_resends, guard goes false.
    let peer = nodes[0].node.get_peer_mut(&addr_1).unwrap();
    for i in 0..max_resends {
        peer.record_rekey_msg1_resend(1000 + i as u64 * 100);
    }
    assert_eq!(
        nodes[0]
            .node
            .get_peer(&addr_1)
            .unwrap()
            .rekey_msg1_resend_count(),
        max_resends
    );

    nodes[0].node.check_link_heartbeats().await;

    assert!(
        nodes[0].node.get_peer(&addr_1).is_none(),
        "peer not reaped after its rekey budget was exhausted"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Regression guard: with no rekey in flight, a peer past the link-dead
/// timeout is reaped exactly as before.
#[tokio::test]
async fn heartbeat_unaffected_without_rekey() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    assert!(nodes[0].node.get_peer(&addr_1).is_some());
    assert!(!nodes[0].node.get_peer(&addr_1).unwrap().rekey_in_progress());

    nodes[0].node.config.node.link_dead_timeout_secs = 0;

    nodes[0].node.check_link_heartbeats().await;

    assert!(
        nodes[0].node.get_peer(&addr_1).is_none(),
        "dead peer with no rekey in flight should be reaped"
    );

    cleanup_nodes(&mut nodes).await;
}
