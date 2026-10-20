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
        data["detail"], "peer live, not dialled",
        "the response says the live peer was not dialled"
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

/// `connect` naming a *different* address for a peer the node holds but has
/// not heard from for longer than the heartbeat interval dials that address,
/// and the dial leaves the link where it was at both ends. This is the
/// failover path; a live peer is not dialled at all.
///
/// Both sessions are past the 30 s rekey floor, and the alternate address
/// reaches the peer from the dialer's usual source, so the peer answers the
/// msg1 as a rekey of the link it already has. What each end is left holding
/// depends on which is the smaller address and which end set the link up:
///
/// - dialer smaller, or dialer larger on a link it set up itself: it moves to
///   the session of the dial, its session index changes, and its first frame
///   promotes the peer's pending session;
/// - dialer larger on a link the peer set up: it keeps its own session, and
///   the peer is left holding a responder pending the dialer will never
///   adopt.
///
/// In no case does the link, its transport or its remote address change at
/// either end. The last case is recorded here as what the code does, not as
/// what it should do. Only the dialer's view of the peer is quiet; the peer
/// still hears the dialer.
#[tokio::test]
async fn test_api_connect_to_a_second_address_of_a_quiet_peer_dials_it_and_leaves_the_link_on_its_path()
 {
    for dialer_smaller in [true, false] {
        for dialer_set_up in [true, false] {
            alternate_path_for_quiet_peer(dialer_smaller, dialer_set_up).await;
        }
    }
}

/// Make `tn` see `peer` as quiet: last heard one second past the heartbeat
/// interval, so its link is no longer live.
pub(super) fn quieten(tn: &mut TestNode, peer: &NodeAddr) {
    let quiet_ms = (tn.node.config().node.heartbeat_interval_secs + 1) * 1000;
    tn.node
        .get_peer_mut(peer)
        .expect("the node holds the peer")
        .touch(Node::now_ms().saturating_sub(quiet_ms));
}

/// Where one end's link to the other sits, and which session it is on.
#[derive(Debug, Clone, PartialEq)]
struct LinkView {
    link_id: LinkId,
    transport_id: Option<TransportId>,
    current_addr: Option<TransportAddr>,
    our_index: Option<SessionIndex>,
}

/// Read `tn`'s view of its link to `peer`.
fn link_view(tn: &TestNode, peer: &NodeAddr) -> LinkView {
    let p = tn
        .node
        .get_peer(peer)
        .expect("the node still holds the peer");
    LinkView {
        link_id: p.link_id(),
        transport_id: p.transport_id(),
        current_addr: p.current_addr().cloned(),
        our_index: p.our_index(),
    }
}

/// One orientation of
/// [`test_api_connect_to_a_second_address_of_a_quiet_peer_dials_it_and_leaves_the_link_on_its_path`].
async fn alternate_path_for_quiet_peer(dialer_smaller: bool, dialer_set_up: bool) {
    use super::rekey_parity::{age_link, deliver, failures, heartbeat};
    use super::spanning_tree::initiate_handshake;
    use fips_core::proto::rekey::Role;

    let mut nodes = vec![make_test_node().await, make_test_node().await];
    let zero_smaller = nodes[0].node.node_addr() < nodes[1].node.node_addr();
    let (d, p) = if zero_smaller == dialer_smaller {
        (0, 1)
    } else {
        (1, 0)
    };
    let dialer_addr = *nodes[d].node.node_addr();
    let peer_addr = *nodes[p].node.node_addr();
    let (from, to) = if dialer_set_up { (d, p) } else { (p, d) };
    initiate_handshake(&mut nodes, from, to).await;
    drain_all_packets(&mut nodes, false).await;
    assert!(
        nodes[d].node.get_peer(&peer_addr).is_some()
            && nodes[p].node.get_peer(&dialer_addr).is_some(),
        "precondition: the two nodes are peered"
    );
    let swaps = dialer_smaller || dialer_set_up;
    let peer_npub = nodes[p].node.npub();
    let transport_id = nodes[d].transport_id;
    age_link(&mut nodes, d, p, Duration::from_secs(31));
    quieten(&mut nodes[d], &peer_addr);

    // A second address that reaches the peer, standing in for a second path
    // coming up.
    let alternate = add_loopback_alias(&nodes[p].addr);
    assert_ne!(alternate, nodes[p].addr);

    let dialer_before = link_view(&nodes[d], &peer_addr);
    let peer_before = link_view(&nodes[p], &dialer_addr);
    assert_eq!(
        dialer_before.current_addr.as_ref(),
        Some(&nodes[p].addr),
        "precondition: the dialer reaches the peer on its primary address"
    );

    let data = nodes[d]
        .node
        .api_connect(&peer_npub, &alternate.to_string(), "loopback")
        .await
        .expect("api_connect on an alternate path should succeed");

    assert_eq!(
        data["refreshed"], true,
        "a new path for an active peer must start a refresh"
    );
    assert!(
        nodes[d]
            .node
            .is_connecting_to_peer_on_path(&peer_addr, transport_id, &alternate),
        "an outbound leg should exist on the alternate path"
    );

    // Deliver the msg1 to the peer only: it answers as a rekey of the link it
    // already has, because the alternate address reaches it from the
    // dialer's usual source.
    assert_eq!(
        deliver(&mut nodes[p]).await,
        1,
        "only the dialer's msg1 is queued at the peer (dialer smaller: {dialer_smaller})"
    );
    let peer_pending = {
        let peer = nodes[p].node.get_peer(&dialer_addr).unwrap();
        assert_eq!(
            peer.pending_role(),
            Some(Role::Responder),
            "the peer holds a responder pending after the msg1 (dialer smaller: {dialer_smaller})"
        );
        peer.pending_our_index()
            .expect("the peer's responder pending has an index")
    };

    // Let the alternate handshake run to completion.
    for _ in 0..20 {
        if process_available_packets(&mut nodes).await == 0 {
            break;
        }
    }

    // The link stays on its path at both ends.
    let dialer_after = link_view(&nodes[d], &peer_addr);
    let peer_after = link_view(&nodes[p], &dialer_addr);
    assert_eq!(
        (
            dialer_after.link_id,
            dialer_after.transport_id,
            dialer_after.current_addr.as_ref()
        ),
        (
            dialer_before.link_id,
            dialer_before.transport_id,
            Some(&nodes[p].addr)
        ),
        "the dialer's link must stay on the peer's primary address (dialer smaller: {dialer_smaller})"
    );
    assert_eq!(
        (
            peer_after.link_id,
            peer_after.transport_id,
            peer_after.current_addr.as_ref()
        ),
        (
            peer_before.link_id,
            peer_before.transport_id,
            peer_before.current_addr.as_ref()
        ),
        "the peer's link must stay where it was (dialer smaller: {dialer_smaller})"
    );

    // The msg2 consumed the dialer's leg.
    assert_eq!(
        outbound_leg_count(&nodes[d].node, &peer_addr),
        0,
        "the dialer holds no leg toward the peer once the dial resolves (dialer smaller: {dialer_smaller})"
    );

    // Session: the smaller dialer, and a larger one that set the link up,
    // moved to the dial's; a larger one on the peer's link kept its own.
    if swaps {
        assert_ne!(
            dialer_after.our_index, dialer_before.our_index,
            "the dialer moves to the alternate-path session (dialer smaller: {dialer_smaller})"
        );
    } else {
        assert_eq!(
            dialer_after.our_index, dialer_before.our_index,
            "the larger dialer on the peer's link keeps its own session"
        );
    }
    // Each end's next frame must authenticate at the other.
    for (from, to, from_addr, to_addr) in [
        (d, p, dialer_addr, peer_addr),
        (p, d, peer_addr, dialer_addr),
    ] {
        let recv_before = nodes[to]
            .node
            .get_peer(&from_addr)
            .expect("the receiver still holds the sender as a peer")
            .link_stats()
            .packets_recv;
        heartbeat(&mut nodes[from], &to_addr).await;
        deliver(&mut nodes[to]).await;
        assert_eq!(
            failures(&nodes[to], &from_addr),
            0,
            "decrypt failures at node {to} after node {from}'s heartbeat (dialer smaller: {dialer_smaller})"
        );
        assert_eq!(
            nodes[to]
                .node
                .get_peer(&from_addr)
                .unwrap()
                .link_stats()
                .packets_recv,
            recv_before + 1,
            "node {from}'s heartbeat must authenticate at node {to} (dialer smaller: {dialer_smaller})"
        );
    }

    let peer = nodes[p].node.get_peer(&dialer_addr).unwrap();
    if swaps {
        assert!(
            peer.pending_role().is_none(),
            "the swapped dialer's first frame promotes the peer's pending (dialer smaller: {dialer_smaller})"
        );
        assert_eq!(
            peer.our_index(),
            Some(peer_pending),
            "the peer is on the former pending session"
        );
    } else {
        // The larger dialer never adopts the session the peer answered with,
        // so the peer keeps holding it; this pending also refuses the
        // dialer's own rekeys until it is retired.
        assert_eq!(
            peer.pending_role(),
            Some(Role::Responder),
            "the peer still holds the unadopted responder pending"
        );
        assert!(
            peer.rekey_answer().is_some(),
            "the peer still holds its answer to the dialer's msg1"
        );
        assert_eq!(
            peer.our_index(),
            peer_before.our_index,
            "the peer stays on its original session"
        );
    }

    cleanup_nodes(&mut nodes).await;
}

/// `connect` naming a different address for a peer whose link is live does
/// not dial it, says so, and leaves both ends exactly as they were.
///
/// Between two nodes on this code, a dial to a live peer did not move its
/// link; it either re-keyed the link or left the peer holding a responder
/// pending the dialer would not adopt. So a live link is kept, the same rule
/// discovery applies.
#[tokio::test]
async fn test_api_connect_to_a_live_peer_on_another_address_dials_nothing_and_changes_neither_end()
{
    for dialer_smaller in [true, false] {
        connect_to_live_peer_on_another_address(dialer_smaller).await;
    }
}

/// One orientation of
/// [`test_api_connect_to_a_live_peer_on_another_address_dials_nothing_and_changes_neither_end`].
async fn connect_to_live_peer_on_another_address(dialer_smaller: bool) {
    use super::rekey_parity::{age_link, deliver};

    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    let zero_smaller = nodes[0].node.node_addr() < nodes[1].node.node_addr();
    let (d, p) = if zero_smaller == dialer_smaller {
        (0, 1)
    } else {
        (1, 0)
    };
    let dialer_addr = *nodes[d].node.node_addr();
    let peer_addr = *nodes[p].node.node_addr();
    let peer_npub = nodes[p].node.npub();
    age_link(&mut nodes, d, p, Duration::from_secs(31));
    let alternate = add_loopback_alias(&nodes[p].addr);

    let dialer_before = link_view(&nodes[d], &peer_addr);
    let peer_before = link_view(&nodes[p], &dialer_addr);

    let data = nodes[d]
        .node
        .api_connect(&peer_npub, &alternate.to_string(), "loopback")
        .await
        .expect("api_connect to a live peer is not an error");

    assert_eq!(
        data["refreshed"], false,
        "a live peer is not dialled (dialer smaller: {dialer_smaller})"
    );
    assert_eq!(
        data["detail"], "peer live, not dialled",
        "the response says why nothing was dialled (dialer smaller: {dialer_smaller})"
    );
    assert_eq!(
        outbound_leg_count(&nodes[d].node, &peer_addr),
        0,
        "no handshake leg toward a live peer (dialer smaller: {dialer_smaller})"
    );
    assert_eq!(
        deliver(&mut nodes[p]).await,
        0,
        "nothing reaches the peer (dialer smaller: {dialer_smaller})"
    );
    assert_eq!(
        link_view(&nodes[d], &peer_addr),
        dialer_before,
        "the dialer's link and session are unchanged (dialer smaller: {dialer_smaller})"
    );
    assert_eq!(
        link_view(&nodes[p], &dialer_addr),
        peer_before,
        "the peer's link and session are unchanged (dialer smaller: {dialer_smaller})"
    );
    assert!(
        nodes[p]
            .node
            .get_peer(&dialer_addr)
            .unwrap()
            .pending_role()
            .is_none(),
        "the peer holds no pending session (dialer smaller: {dialer_smaller})"
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

/// `show_transports` served off the rx loop reports the transport counters
/// as they are now, not as the last tick published them: a counter that
/// moves after the publish shows up without another tick, in the same
/// fields and shape the on-loop render gives.
#[tokio::test]
async fn show_transports_off_loop_reports_counters_that_moved_since_the_last_tick() {
    use crate::config::{TcpConfig, UdpConfig};
    use crate::control::queries::{show_transports, show_transports_from_handle};
    use crate::transport::tcp::TcpTransport;
    use crate::transport::udp::UdpTransport;

    let mut node = make_node();
    let (tx, _rx) = packet_channel(16);
    let udp_cfg = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    };
    let mut udp = UdpTransport::new(TransportId::new(1), None, udp_cfg, tx.clone());
    udp.start_async().await.unwrap();
    let udp_stats = udp.stats().clone();
    let tcp_cfg = TcpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    };
    let mut tcp = TcpTransport::new(TransportId::new(2), None, tcp_cfg, tx);
    tcp.start_async().await.unwrap();
    let tcp_stats = tcp.stats().clone();
    node.transports
        .insert(TransportId::new(1), TransportHandle::Udp(udp));
    node.transports
        .insert(TransportId::new(2), TransportHandle::Tcp(tcp));

    // One tick publishes the transport rows.
    node.record_stats_history();
    let handle = node.control_read_handle();
    let published = std::sync::Arc::clone(&*handle.entities());
    let row = |v: &serde_json::Value, id: u32| {
        v["transports"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["transport_id"] == id)
            .unwrap_or_else(|| panic!("no row for transport {id}: {v}"))
            .clone()
    };
    let before = show_transports_from_handle(&handle);
    assert_eq!(row(&before, 1)["stats"]["packets_recv"], 0);
    assert_eq!(row(&before, 2)["stats"]["connect_timeouts"], 0);

    // The counters move; no tick runs.
    for _ in 0..3 {
        udp_stats.record_recv(100);
    }
    tcp_stats.record_connect_timeout();
    tcp_stats.record_connect_refused();

    let after = show_transports_from_handle(&handle);
    assert!(
        std::sync::Arc::ptr_eq(&published, &handle.entities()),
        "precondition: nothing republished the snapshot"
    );
    let udp_row = row(&after, 1);
    let tcp_row = row(&after, 2);
    assert_eq!(
        udp_row["stats"]["packets_recv"], 3,
        "off-loop show_transports did not see the UDP counter move"
    );
    assert_eq!(udp_row["stats"]["bytes_recv"], 300);
    assert_eq!(
        tcp_row["stats"]["connect_timeouts"], 1,
        "off-loop show_transports did not see the TCP counter move"
    );
    assert_eq!(tcp_row["stats"]["connect_refused"], 1);

    // Same fields and shape as before: each block is its stats snapshot
    // serialized whole, and the whole render matches the on-loop one.
    assert_eq!(
        udp_row["stats"],
        serde_json::to_value(udp_stats.snapshot()).unwrap()
    );
    assert_eq!(
        tcp_row["stats"],
        serde_json::to_value(tcp_stats.snapshot()).unwrap()
    );
    assert_eq!(after, show_transports(&node));
    let keys = |v: &serde_json::Value| {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(keys(&udp_row), keys(&row(&before, 1)));
    assert_eq!(keys(&tcp_row["stats"]), keys(&row(&before, 2)["stats"]));

    for (_, t) in node.transports.iter_mut() {
        t.stop().await.ok();
    }
}

/// Render `show_sessions` on the loop, then publish a tick and render it
/// again from the snapshot the control socket serves.
fn show_sessions_both_renders(node: &mut Node) -> [(&'static str, serde_json::Value); 2] {
    let on_loop = crate::control::queries::show_sessions(node);
    node.record_stats_history();
    let off_loop = crate::control::queries::show_sessions_from_handle(&node.control_read_handle());
    [("on-loop", on_loop), ("snapshot", off_loop)]
}

/// The `show_sessions` row of the session with `addr`.
fn session_row<'a>(sessions: &'a serde_json::Value, addr: &NodeAddr) -> &'a serde_json::Value {
    let addr_hex = hex::encode(addr.as_bytes());
    sessions["sessions"]
        .as_array()
        .expect("show_sessions returns a sessions array")
        .iter()
        .find(|row| row["remote_addr"] == addr_hex.as_str())
        .unwrap_or_else(|| panic!("show_sessions lists no session with {addr_hex}: {sessions}"))
}

/// A session whose peer no handshake has proven is reported with no `npub`
/// and with `identity: "unproven"`, on both renderings: one a setup claiming
/// an address opened, which used to report this node's own key, and one this
/// node opened, which used to report the key it dialed even though nothing
/// had answered for it. An established session reports its peer's key and
/// `identity: "proven"`.
#[test]
fn unproved_inbound_session_is_shown_without_npub_and_with_a_status() {
    use crate::node::session::{SessionEntry, session_at};

    let mut node = make_node();
    let keypair = node.identity().keypair();

    let claimed = *Identity::generate().node_addr();
    node.sessions.insert(
        claimed,
        SessionEntry::answering_for_test(claimed, keypair, session_at(1000)),
    );

    let dialed = Identity::generate();
    let dialed_addr = *dialed.node_addr();
    node.register_identity(dialed_addr, dialed.pubkey_full());
    node.sessions.insert(
        dialed_addr,
        SessionEntry::opened_for_test(&dialed.pubkey_full(), keypair, session_at(1000)),
    );

    let proven = Identity::generate();
    let proven_addr = *proven.node_addr();
    let session = super::session::make_noise_session(node.identity(), &proven);
    node.sessions.insert(
        proven_addr,
        SessionEntry::keyed(proven_addr, session, session_at(1000), true),
    );

    for (render, sessions) in show_sessions_both_renders(&mut node) {
        for (what, addr) in [("inbound", claimed), ("outbound", dialed_addr)] {
            let row = session_row(&sessions, &addr);
            assert_eq!(
                row.get("npub"),
                None,
                "{render} render, unproved {what} session must carry no npub"
            );
            assert_eq!(
                row["identity"], "unproven",
                "{render} render, unproved {what} session status"
            );
        }
        let row = session_row(&sessions, &proven_addr);
        assert_eq!(
            row["npub"],
            proven.npub().as_str(),
            "{render} render, established session reports its peer's key"
        );
        assert_eq!(
            row["identity"], "proven",
            "{render} render, established session status"
        );
    }
}
