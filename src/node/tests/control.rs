//! Control API (`connect` / `disconnect`) behaviour tests.
//!
//! These drive `Node::api_connect` and `Node::api_disconnect` directly —
//! the same entry points the control socket's mutating commands dispatch to
//! (`src/control/commands.rs`) — so the assertions are about node state, not
//! socket framing.

use super::*;
use spanning_tree::{
    TestNode, add_loopback_alias, cleanup_nodes, drain_all_packets, make_test_node,
    process_available_packets, run_tree_test,
};

/// Count the in-flight handshake legs a node is running toward `peer`.
fn outbound_leg_count(node: &Node, peer: &NodeAddr) -> usize {
    node.peer_machines
        .values()
        .filter(|machine| {
            machine.leg().is_some()
                && machine
                    .conn_expected_identity()
                    .map(|id| id.node_addr() == peer)
                    .unwrap_or(false)
        })
        .count()
}

/// The loopback address string the control API would be handed for a node.
fn loopback_address(node: &TestNode) -> String {
    node.addr.to_string()
}

/// `connect` for a peer the node does not know dials it and the handshake
/// completes: the baseline the other tests are contrasted against.
#[tokio::test]
async fn test_api_connect_dials_an_unknown_peer() {
    let mut nodes = vec![make_test_node().await, make_test_node().await];

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_npub = nodes[1].node.npub();
    let node1_address = loopback_address(&nodes[1]);

    let data = nodes[0]
        .node
        .api_connect(&node1_npub, &node1_address, "loopback")
        .await
        .expect("api_connect should dial an unknown peer");
    assert_eq!(
        data["refreshed"], false,
        "a first dial is not an alternate-path refresh"
    );

    let total = drain_all_packets(&mut nodes, false).await;
    assert!(total > 0, "the dial should have produced packets");

    assert!(
        nodes[0].node.get_peer(&node1_addr).is_some(),
        "node 0 should have node 1 as a peer after api_connect"
    );
    assert!(
        nodes[1].node.get_peer(&node0_addr).is_some(),
        "node 1 should have node 0 as a peer after api_connect"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A second `connect` while the first handshake is still in flight must not
/// start a second leg — the `is_connecting_to_peer` guard.
#[tokio::test]
async fn test_api_connect_duplicate_while_connecting_starts_one_leg() {
    let mut nodes = vec![make_test_node().await, make_test_node().await];

    let node1_addr = *nodes[1].node.node_addr();
    let node1_npub = nodes[1].node.npub();
    let node1_address = loopback_address(&nodes[1]);

    nodes[0]
        .node
        .api_connect(&node1_npub, &node1_address, "loopback")
        .await
        .expect("first api_connect should succeed");
    assert_eq!(
        outbound_leg_count(&nodes[0].node, &node1_addr),
        1,
        "the first connect should start exactly one handshake leg"
    );

    // Deliberately do not pump packets: the peer is still mid-handshake.
    nodes[0]
        .node
        .api_connect(&node1_npub, &node1_address, "loopback")
        .await
        .expect("second api_connect should succeed");

    assert_eq!(
        outbound_leg_count(&nodes[0].node, &node1_addr),
        1,
        "a duplicate connect must not start a second handshake leg"
    );

    cleanup_nodes(&mut nodes).await;
}

/// `connect` naming the path an active peer is already on, while that path is
/// fresh, is a successful no-op — and says so.
///
/// This is the regression guard for the alternate-path fix: a caller that
/// re-announces the same peer at the same address every discovery cycle must
/// not churn a healthy link.
#[tokio::test]
async fn test_api_connect_on_current_fresh_path_is_a_no_op() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;

    let node1_addr = *nodes[1].node.node_addr();
    let node1_npub = nodes[1].node.npub();
    let node1_address = loopback_address(&nodes[1]);

    let link_before = nodes[0]
        .node
        .get_peer(&node1_addr)
        .expect("node 0 should have node 1")
        .link_id();
    let legs_before = outbound_leg_count(&nodes[0].node, &node1_addr);

    let data = nodes[0]
        .node
        .api_connect(&node1_npub, &node1_address, "loopback")
        .await
        .expect("api_connect on the current path should succeed");

    assert_eq!(
        data["refreshed"], false,
        "re-announcing the current fresh path is a no-op"
    );
    assert_eq!(
        outbound_leg_count(&nodes[0].node, &node1_addr),
        legs_before,
        "no new handshake leg for the path the peer is already on"
    );
    let peer = nodes[0]
        .node
        .get_peer(&node1_addr)
        .expect("the live peer must survive a no-op connect");
    assert_eq!(peer.link_id(), link_before, "the live link must not change");

    cleanup_nodes(&mut nodes).await;
}

/// `connect` naming a *different* address for a peer the node is already
/// connected to starts an alternate-path handshake instead of silently doing
/// nothing — the fix.
///
/// The existing peer stays put while that handshake runs: promotion is the
/// handshake's job, not the command's.
#[tokio::test]
async fn test_api_connect_starts_alternate_path_for_active_peer() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;

    let node1_addr = *nodes[1].node.node_addr();
    let node1_npub = nodes[1].node.npub();
    let transport_id = nodes[0].transport_id;

    // A second address that reaches node 1, standing in for a second path
    // coming up.
    let alternate = add_loopback_alias(&nodes[1].addr);
    assert_ne!(alternate, nodes[1].addr);

    let link_before = nodes[0]
        .node
        .get_peer(&node1_addr)
        .expect("node 0 should have node 1")
        .link_id();

    let data = nodes[0]
        .node
        .api_connect(&node1_npub, &alternate.to_string(), "loopback")
        .await
        .expect("api_connect on an alternate path should succeed");

    assert_eq!(
        data["refreshed"], true,
        "a new path for an active peer must start a refresh"
    );
    assert!(
        nodes[0]
            .node
            .is_connecting_to_peer_on_path(&node1_addr, transport_id, &alternate),
        "an outbound leg should exist on the alternate path"
    );
    let peer = nodes[0]
        .node
        .get_peer(&node1_addr)
        .expect("the existing peer must survive the parallel handshake");
    assert_eq!(
        peer.link_id(),
        link_before,
        "the alternate handshake must not tear the live link down before it authenticates"
    );

    // Let the alternate handshake run to completion; the peer must still be
    // there afterwards.
    for _ in 0..20 {
        if process_available_packets(&mut nodes).await == 0 {
            break;
        }
    }
    assert!(
        nodes[0].node.get_peer(&node1_addr).is_some(),
        "node 1 should still be a peer after the alternate path resolves"
    );

    cleanup_nodes(&mut nodes).await;
}

/// An unparseable npub is rejected and changes nothing.
#[tokio::test]
async fn test_api_connect_rejects_invalid_npub() {
    let mut node = make_node();

    let err = node
        .api_connect("notanpub", "loopback:0", "loopback")
        .await
        .expect_err("an invalid npub must be rejected");
    assert!(
        err.contains("notanpub"),
        "the error should name the bad npub, got: {err}"
    );
    assert_eq!(node.peer_count(), 0);
    assert!(node.peer_machines.is_empty());
}

/// `connect` naming a transport the node does not have fails cleanly rather
/// than half-registering a peer. This is also the pre-start case: a node with
/// no transports yet cannot dial anything.
#[tokio::test]
async fn test_api_connect_without_a_matching_transport_fails_cleanly() {
    let mut node = make_node();
    let peer = make_node();
    let peer_npub = peer.npub();
    let peer_addr = *peer.node_addr();

    let err = node
        .api_connect(&peer_npub, "127.0.0.1:1", "tor")
        .await
        .expect_err("no tor transport is configured");
    assert!(
        err.contains("no operational transport"),
        "unexpected error: {err}"
    );

    assert_eq!(node.peer_count(), 0, "no peer may be registered");
    assert!(
        node.peer_machines.is_empty(),
        "no handshake leg may be left behind"
    );
    assert_eq!(outbound_leg_count(&node, &peer_addr), 0);
}

/// `disconnect` on a connectionless transport removes the peer and the
/// transport close degrades to the no-op trait default — no error, no panic.
///
/// Disconnecting again reports `peer not found`, which is also the
/// double-close path: the first call already closed the connection.
#[tokio::test]
async fn test_api_disconnect_on_a_connectionless_transport() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;

    let node1_addr = *nodes[1].node.node_addr();
    let node1_npub = nodes[1].node.npub();

    nodes[0]
        .node
        .api_disconnect(&node1_npub)
        .await
        .expect("api_disconnect should succeed");
    assert!(
        nodes[0].node.get_peer(&node1_addr).is_none(),
        "the peer must be gone"
    );

    let err = nodes[0]
        .node
        .api_disconnect(&node1_npub)
        .await
        .expect_err("a second disconnect has no peer to remove");
    assert!(err.contains("peer not found"), "unexpected error: {err}");

    cleanup_nodes(&mut nodes).await;
}

/// `disconnect` for a peer the node does not hold is rejected without any
/// partial teardown.
#[tokio::test]
async fn test_api_disconnect_unknown_peer_changes_nothing() {
    let mut node = make_node();
    let stranger = make_node();

    let peers_before = node.peer_count();
    let machines_before = node.peer_machines.len();
    let links_before = node.links.len();

    let err = node
        .api_disconnect(&stranger.npub())
        .await
        .expect_err("an unknown peer cannot be disconnected");
    assert!(err.contains("peer not found"), "unexpected error: {err}");

    assert_eq!(node.peer_count(), peers_before);
    assert_eq!(node.peer_machines.len(), machines_before);
    assert_eq!(node.links.len(), links_before);
}
