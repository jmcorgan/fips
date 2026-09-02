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

/// Set `link_dead_timeout_secs` on an already-constructed node via the
/// sole-store copy-on-write context swap (immutable state is no longer a
/// directly-pokeable field; `config()` is a read-only accessor).
fn set_link_dead_timeout(node: &mut crate::node::Node, secs: u64) {
    node.replace_context(|ctx| {
        let mut cfg = (*ctx.config).clone();
        cfg.node.link_dead_timeout_secs = secs;
        ctx.config = std::sync::Arc::new(cfg);
    });
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
    set_link_dead_timeout(&mut nodes[0].node, 0);

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

    set_link_dead_timeout(&mut nodes[0].node, 0);
    let max_resends = nodes[0].node.config().node.rate_limit.handshake_max_resends;

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

    set_link_dead_timeout(&mut nodes[0].node, 0);

    nodes[0].node.check_link_heartbeats().await;

    assert!(
        nodes[0].node.get_peer(&addr_1).is_none(),
        "dead peer with no rekey in flight should be reaped"
    );

    cleanup_nodes(&mut nodes).await;
}

// ---------------------------------------------------------------------------
// Reaping peers when their interface goes away
//
// The detach edge is both earlier and more certain than inactivity, so it is
// the better trigger for withdrawing what the interface carried. These drive
// the same real two-node peering the liveness tests use, because a peer only
// reaches the established context the reap acts on by actually peering.
// ---------------------------------------------------------------------------

/// A peer reachable only through an interface that has gone is withdrawn on
/// the detach edge, without waiting out `link_dead_timeout_secs`.
///
/// Note what is *not* set here: the link-dead timeout keeps its default, and
/// no time is advanced. The peer is live by every liveness measure and is
/// still withdrawn, because the transport under it is gone — which is the
/// whole distinction this adds.
#[tokio::test]
async fn a_detached_transport_withdraws_the_peers_that_needed_it() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    let transport_id = nodes[0]
        .node
        .get_peer(&addr_1)
        .expect("peer present")
        .transport_id()
        .expect("an established peer names its transport");

    let reaped = nodes[0].node.reap_peers_on_transport(transport_id).await;

    assert_eq!(reaped, 1);
    assert!(
        nodes[0].node.get_peer(&addr_1).is_none(),
        "a peer must not outlive the interface it was reachable through"
    );

    cleanup_nodes(&mut nodes).await;
}

/// The reap is scoped to the transport that detached.
///
/// The failure this guards is the one that would make the feature worse than
/// the defect: an interface going away must not withdraw the peers that were
/// never reachable through it, which on a mesh router is most of them.
#[tokio::test]
async fn a_detached_transport_leaves_other_transports_peers_alone() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    let peer_transport = nodes[0]
        .node
        .get_peer(&addr_1)
        .expect("peer present")
        .transport_id()
        .expect("an established peer names its transport");

    // A transport this peer was never reachable through.
    let unrelated = TransportId::new(peer_transport.as_u32() + 100);
    let reaped = nodes[0].node.reap_peers_on_transport(unrelated).await;

    assert_eq!(reaped, 0, "an unrelated transport withdraws nothing");
    assert!(
        nodes[0].node.get_peer(&addr_1).is_some(),
        "a peer on a healthy transport must survive another one detaching"
    );

    cleanup_nodes(&mut nodes).await;
}
