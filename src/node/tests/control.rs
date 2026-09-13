//! Control API (`connect` / `disconnect`) behaviour tests.
//!
//! These drive `Node::api_connect` and `Node::api_disconnect` directly —
//! the same entry points the control socket's mutating commands dispatch to
//! (`src/control/commands.rs`) — so the assertions are about node state, not
//! socket framing.

use super::*;
use heartbeat::set_heartbeat_interval;
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
/// connected to takes it as a path under the session it has — never a
/// second handshake, which the far side would read as a rekey. The peer and
/// its link stay put; the heartbeat tick probes the path from here.
#[tokio::test]
async fn test_api_connect_takes_an_alternate_address_as_a_path() {
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
        "a new address for an active peer is taken as a path"
    );
    assert!(
        !nodes[0]
            .node
            .is_connecting_to_peer_on_path(&node1_addr, transport_id, &alternate),
        "no handshake: a peer with a session is probed, not dialled"
    );
    assert_eq!(nodes[0].node.connection_count(), 0);
    let peer = nodes[0]
        .node
        .get_peer(&node1_addr)
        .expect("the existing peer is untouched");
    assert_eq!(peer.link_id(), link_before, "the live link must not change");
    assert!(
        peer.path_on(transport_id).is_some(),
        "the transport still has its one path"
    );

    for _ in 0..20 {
        if process_available_packets(&mut nodes).await == 0 {
            break;
        }
    }
    assert!(
        nodes[0].node.get_peer(&node1_addr).is_some(),
        "node 1 is still a peer"
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

/// The `show_links` row whose `link_id` is `link_id`.
fn link_row(links: &serde_json::Value, link_id: LinkId) -> &serde_json::Value {
    links["links"]
        .as_array()
        .expect("show_links returns a links array")
        .iter()
        .find(|row| row["link_id"] == link_id.as_u64())
        .expect("show_links lists the link bound to the peer")
}

/// Check one node's `show_links` row for the link it shares with `peer_idx`
/// against the counters the data plane kept on that peer, and return the row.
fn assert_link_row_matches_peer(
    nodes: &[TestNode],
    node_idx: usize,
    peer_idx: usize,
) -> serde_json::Value {
    let peer_addr = *nodes[peer_idx].node.node_addr();
    let peer = nodes[node_idx]
        .node
        .get_peer(&peer_addr)
        .expect("the tree test establishes the peer");
    let link_id = peer.link_id();
    let expected = peer.link_stats().clone();

    // Without traffic every counter is zero on both copies and the comparison
    // below would pass whether or not show_links reads the right one.
    assert!(expected.packets_sent > 0, "node {node_idx} sent no frames");
    assert!(
        expected.packets_recv > 0,
        "node {node_idx} received no frames"
    );
    assert!(expected.bytes_sent > 0, "node {node_idx} sent no bytes");
    assert!(expected.bytes_recv > 0, "node {node_idx} received no bytes");
    assert!(
        expected.last_recv_ms > 0,
        "node {node_idx} stamped no receive time"
    );

    let links = crate::control::queries::show_links(&nodes[node_idx].node);
    let row = link_row(&links, link_id).clone();
    let stats = &row["stats"];
    assert_eq!(
        stats["packets_sent"], expected.packets_sent,
        "node {node_idx}"
    );
    assert_eq!(
        stats["packets_recv"], expected.packets_recv,
        "node {node_idx}"
    );
    assert_eq!(stats["bytes_sent"], expected.bytes_sent, "node {node_idx}");
    assert_eq!(stats["bytes_recv"], expected.bytes_recv, "node {node_idx}");
    assert_eq!(
        stats["last_recv_ms"], expected.last_recv_ms,
        "node {node_idx}"
    );
    row
}

/// `show_links` reports the traffic a link has carried, not zero: for a link
/// bound to an authenticated peer its counters are the ones the data plane
/// keeps on that peer, on both ends of the link, and the tick-published
/// snapshot render agrees with the on-loop render.
#[tokio::test]
async fn show_links_reports_the_traffic_counters_of_the_peer_bound_to_each_link() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;

    let row0 = assert_link_row_matches_peer(&nodes, 0, 1);

    // The off-loop render comes from the snapshot published on the tick.
    nodes[0].node.record_stats_history();
    let handle = nodes[0].node.control_read_handle();
    let on_loop = crate::control::queries::show_links(&nodes[0].node);
    let off_loop = crate::control::queries::show_links_from_handle(&handle);
    assert_eq!(
        off_loop, on_loop,
        "the snapshot render of show_links must match the on-loop render"
    );
    let link_id = nodes[0]
        .node
        .get_peer(nodes[1].node.node_addr())
        .expect("node 0 still has node 1")
        .link_id();
    let off_row = link_row(&off_loop, link_id);
    assert!(
        off_row["stats"]["packets_recv"].as_u64().unwrap_or(0) > 0,
        "the snapshot render must carry the link's receive count, got {off_row}"
    );

    let row1 = assert_link_row_matches_peer(&nodes, 1, 0);

    // A check that does not come from the same node's peer copy: every frame
    // node 1 counted as received from node 0 was counted as sent by node 0.
    // Loopback is lossless, but a frame sent before node 1 promoted node 0 is
    // counted by the sender only, so the bound is not an equality.
    let sent0 = row0["stats"]["packets_sent"]
        .as_u64()
        .expect("packets_sent is a number");
    let recv1 = row1["stats"]["packets_recv"]
        .as_u64()
        .expect("packets_recv is a number");
    assert!(recv1 > 0, "node 1's link row shows no frames received");
    assert!(
        recv1 <= sent0,
        "node 1's link row counts {recv1} frames received, more than the {sent0} node 0 sent"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Insert an authenticated peer last heard from at `last_seen_ms` and return
/// its address.
fn insert_peer_last_seen_at(node: &mut Node, link: u64, last_seen_ms: u64) -> NodeAddr {
    let identity = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    let addr = *identity.node_addr();
    node.peers.insert(
        addr,
        ActivePeer::new(identity, LinkId::new(link), last_seen_ms),
    );
    addr
}

/// The `connectivity` string a `show_peers` response gives the peer at `addr`.
fn connectivity_of(peers: &serde_json::Value, addr: &NodeAddr) -> String {
    let addr_hex = hex::encode(addr.as_bytes());
    peers["peers"]
        .as_array()
        .expect("show_peers returns a peers array")
        .iter()
        .find(|row| row["node_addr"] == addr_hex.as_str())
        .and_then(|row| row["connectivity"].as_str())
        .expect("show_peers lists the peer with a connectivity string")
        .to_string()
}

/// Render `show_peers` on the loop, then publish a tick and render it again
/// from the snapshot the control socket serves.
fn show_peers_both_renders(node: &mut Node) -> [(&'static str, serde_json::Value); 2] {
    let on_loop = crate::control::queries::show_peers(node);
    node.record_stats_history();
    let off_loop = crate::control::queries::show_peers_from_handle(&node.control_read_handle());
    [("on-loop", on_loop), ("snapshot", off_loop)]
}

/// `show_peers` reports a peer silent for longer than the heartbeat interval
/// as `stale`, and a peer heard from just now as `connected`, on both the
/// on-loop render and the tick-published snapshot render.
#[test]
fn show_peers_reports_a_peer_idle_past_the_heartbeat_interval_as_stale() {
    let mut node = make_node();
    let interval_ms = node.config().node.heartbeat_interval_secs * 1000;
    assert_eq!(interval_ms, 10_000, "the default heartbeat interval");
    let now = Node::now_ms();
    let fresh = insert_peer_last_seen_at(&mut node, 1, now);
    let idle = insert_peer_last_seen_at(&mut node, 2, now - interval_ms - 5_000);

    for (render, peers) in show_peers_both_renders(&mut node) {
        assert_eq!(
            connectivity_of(&peers, &idle),
            "stale",
            "{render} render, peer silent for 15 s"
        );
        assert_eq!(
            connectivity_of(&peers, &fresh),
            "connected",
            "{render} render, peer heard from just now"
        );
    }
}

/// The `stale` threshold is the configured heartbeat interval rather than a
/// fixed ten seconds: with a 30 s interval a peer silent for 15 s still reads
/// `connected`, and one silent for 35 s reads `stale`.
#[test]
fn show_peers_stale_threshold_follows_the_configured_heartbeat_interval() {
    let mut node = make_node();
    set_heartbeat_interval(&mut node, 30);
    let now = Node::now_ms();
    let quiet = insert_peer_last_seen_at(&mut node, 1, now - 15_000);
    let idle = insert_peer_last_seen_at(&mut node, 2, now - 35_000);

    for (render, peers) in show_peers_both_renders(&mut node) {
        assert_eq!(
            connectivity_of(&peers, &idle),
            "stale",
            "{render} render, peer silent for 35 s"
        );
        assert_eq!(
            connectivity_of(&peers, &quiet),
            "connected",
            "{render} render, peer silent for 15 s"
        );
    }
}

/// The derived connectivity changes at the heartbeat interval exactly: a peer
/// silent for the whole interval still reads `connected`, and one millisecond
/// more reads `stale`. A zero interval is floored at one second, the floor the
/// discovery re-dial gate applies.
#[test]
fn peer_connectivity_turns_stale_one_millisecond_past_the_heartbeat_interval() {
    let mut node = make_node();
    let seen = 1_000_000;
    let addr = insert_peer_last_seen_at(&mut node, 1, seen);
    let at = |node: &Node, now_ms: u64| {
        let peer = node.get_peer(&addr).expect("the peer was inserted");
        node.peer_connectivity(peer, now_ms)
    };

    assert_eq!(at(&node, seen + 10_000), ConnectivityState::Connected);
    assert_eq!(at(&node, seen + 10_001), ConnectivityState::Stale);

    set_heartbeat_interval(&mut node, 0);
    assert_eq!(at(&node, seen + 1_000), ConnectivityState::Connected);
    assert_eq!(at(&node, seen + 1_001), ConnectivityState::Stale);
}
