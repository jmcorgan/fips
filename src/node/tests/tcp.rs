//! TCP transport integration tests.
//!
//! Tests that the TCP transport works end-to-end at the node level:
//! handshake, spanning tree convergence, mixed-transport routing,
//! MMP link-dead detection, reconnection after link death, a TCP
//! path joining a multipath link made on loopback, the close of a
//! connection whose msg1 is refused after the answer was asked for or whose
//! dial is refused at the peer cap, and a
//! pending redial's connection kept for the later redial that replaces it
//! there.
//! All tests use 127.0.0.1:0 (ephemeral ports) and need no privileges.

use super::heartbeat::set_link_dead_timeout;
use super::*;
use crate::config::{Config, TcpConfig};
use crate::transport::tcp::TcpTransport;
use crate::transport::{
    ConnectionState, TransportAddr, TransportHandle, TransportId, packet_channel,
};
use spanning_tree::{
    TestNode, cleanup_nodes, drain_all_packets, initiate_handshake, process_available_packets,
    verify_tree_convergence,
};
use std::time::Duration;

/// Create a test node with a live TCP transport on loopback.
///
/// Parallel to `make_test_node()` in spanning_tree.rs but uses
/// TcpTransport instead of UDP. Binds to 127.0.0.1:0 for an
/// ephemeral port.
async fn make_test_node_tcp() -> TestNode {
    make_test_node_tcp_with(Config::new()).await
}

/// Like `make_test_node_tcp` but builds the node from an explicit `Config`,
/// so immutable fields (e.g. heartbeat/link-dead timeouts) are set before the
/// `NodeContext` is built rather than poked afterward.
async fn make_test_node_tcp_with(config: Config) -> TestNode {
    make_test_node_tcp_idle(config, None).await
}

/// Like `make_test_node_tcp_with`, and also sets the transport's inbound
/// idle deadline when `idle` is given, as `create_transports` does for a
/// node built from config.
async fn make_test_node_tcp_idle(config: Config, idle: Option<Duration>) -> TestNode {
    let mut node = make_node_with(config);
    let transport_id = TransportId::new(1);

    let config = TcpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1400),
        ..Default::default()
    };

    let (packet_tx, packet_rx) = packet_channel(256);
    let mut transport = TcpTransport::new(transport_id, None, config, packet_tx);
    if let Some(d) = idle {
        transport.set_inbound_idle_timeout(d);
    }
    transport.start_async().await.unwrap();

    let local_addr = transport
        .local_addr()
        .expect("TCP transport should have local addr after start");
    let addr = TransportAddr::from_string(&local_addr.to_string());

    node.transports
        .insert(transport_id, TransportHandle::Tcp(transport));

    TestNode {
        node,
        transport_id,
        packet_rx: spanning_tree::bridge_to_unbounded(packet_rx),
        addr,
    }
}

/// Two TCP nodes complete a Noise handshake and establish bidirectional peering.
#[tokio::test]
async fn test_tcp_two_node_handshake() {
    let mut nodes = vec![make_test_node_tcp().await, make_test_node_tcp().await];

    // Initiate handshake from node 0 to node 1
    initiate_handshake(&mut nodes, 0, 1).await;

    // Drain all packets (handshake msg1/msg2 + TreeAnnounce exchange)
    let total = drain_all_packets(&mut nodes, false).await;
    assert!(total > 0, "should have processed packets");

    // Verify bidirectional peering
    let addr_0 = *nodes[0].node.node_addr();
    let addr_1 = *nodes[1].node.node_addr();
    assert!(
        nodes[0].node.get_peer(&addr_1).is_some(),
        "node 0 should have node 1 as peer"
    );
    assert!(
        nodes[1].node.get_peer(&addr_0).is_some(),
        "node 1 should have node 0 as peer"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Three TCP nodes in a chain converge to a consistent spanning tree.
///
/// Chain: 0 -- 1 -- 2. Verifies tree convergence, peer counts, and
/// bloom filter reachability across multiple hops.
#[tokio::test]
async fn test_tcp_three_node_chain() {
    let mut nodes = vec![
        make_test_node_tcp().await,
        make_test_node_tcp().await,
        make_test_node_tcp().await,
    ];

    // Chain: 0 -- 1 -- 2
    initiate_handshake(&mut nodes, 0, 1).await;
    initiate_handshake(&mut nodes, 1, 2).await;

    let total = drain_all_packets(&mut nodes, false).await;
    assert!(total > 0, "should have processed packets");

    // Verify spanning tree convergence
    verify_tree_convergence(&nodes);

    // Verify correct root (smallest NodeAddr)
    let expected_root = nodes.iter().map(|tn| *tn.node.node_addr()).min().unwrap();
    for tn in &nodes {
        assert_eq!(*tn.node.tree_state().root(), expected_root);
    }

    // Verify peer counts
    assert_eq!(nodes[0].node.peer_count(), 1, "endpoint should have 1 peer");
    assert_eq!(
        nodes[1].node.peer_count(),
        2,
        "middle node should have 2 peers"
    );
    assert_eq!(nodes[2].node.peer_count(), 1, "endpoint should have 1 peer");

    // Verify bloom filter reachability: node 0 can reach node 2 via node 1
    let addr_2 = *nodes[2].node.node_addr();
    let reaches = nodes[0].node.peers().any(|p| p.may_reach(&addr_2));
    assert!(
        reaches,
        "node 0 should see node 2 as reachable through bloom filters"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Mixed transport: UDP and TCP nodes coexist in the same test.
///
/// Two UDP nodes and two TCP nodes each form independent components.
/// Validates that `process_available_packets()` handles heterogeneous
/// transport types correctly.
#[tokio::test]
async fn test_tcp_mixed_transport_coexistence() {
    use spanning_tree::{make_test_node, verify_tree_convergence_components};

    // Create 2 UDP nodes and 2 TCP nodes
    let udp_0 = make_test_node().await;
    let udp_1 = make_test_node().await;
    let tcp_0 = make_test_node_tcp().await;
    let tcp_1 = make_test_node_tcp().await;

    let mut nodes = vec![udp_0, udp_1, tcp_0, tcp_1];

    // Handshake within each component
    initiate_handshake(&mut nodes, 0, 1).await; // UDP pair
    initiate_handshake(&mut nodes, 2, 3).await; // TCP pair

    let total = drain_all_packets(&mut nodes, false).await;
    assert!(total > 0);

    // Verify each component converges independently
    verify_tree_convergence_components(&nodes, &[vec![0, 1], vec![2, 3]]);

    // TCP component has its own root
    let tcp_root = std::cmp::min(*nodes[2].node.node_addr(), *nodes[3].node.node_addr());
    assert_eq!(*nodes[2].node.tree_state().root(), tcp_root);
    assert_eq!(*nodes[3].node.tree_state().root(), tcp_root);

    cleanup_nodes(&mut nodes).await;
}

/// A TCP link whose only traffic is heartbeats outlives two inbound idle
/// deadlines when the deadline is the one the node derives from its own
/// liveness timers.
///
/// This is the healthy-path check for the idle deadline: it uses the real
/// derivation (`inbound_idle_timeout`), not a hand-picked value, and
/// short timers so two deadlines fit in a test. Two, not one: a deadline
/// that each frame does not refresh, but one frame does, still lets the
/// connection outlive the first deadline, and only the second catches it.
/// Break-check: give the listening node's transport an idle deadline below
/// the heartbeat interval and its inbound connection is dropped, so the
/// inbound count falls to 0.
#[tokio::test]
async fn tcp_link_kept_alive_only_by_heartbeats_survives_two_idle_deadlines() {
    use crate::node::handlers::rekey::inbound_idle_timeout;

    let mut config = Config::new();
    config.node.heartbeat_interval_secs = 1;
    config.node.link_dead_timeout_secs = 3;
    config.node.rate_limit.handshake_max_resends = 1;
    let idle = inbound_idle_timeout(&config.node);
    // 1 s of msg1 ladder (one resend), three 1 s ticks, 3 s link-dead.
    assert_eq!(idle, Duration::from_millis(7000));
    let mut nodes = vec![
        make_test_node_tcp_idle(config.clone(), Some(idle)).await,
        make_test_node_tcp_idle(config, Some(idle)).await,
    ];
    // The nodes are built at the 30 s link-dead floor; run them with the
    // 3 s the deadline was derived from.
    for tn in nodes.iter_mut() {
        set_link_dead_timeout(&mut tn.node, 3);
    }

    // Node 0 dials node 1, so node 1 holds the inbound connection.
    initiate_handshake(&mut nodes, 0, 1).await;
    assert!(drain_all_packets(&mut nodes, false).await > 0);

    let addr_0 = *nodes[0].node.node_addr();
    let addr_1 = *nodes[1].node.node_addr();
    let inbound = |nodes: &[TestNode]| match nodes[1].node.transports.get(&nodes[1].transport_id) {
        Some(TransportHandle::Tcp(t)) => t.stats().pool_inbound_count(),
        _ => panic!("node 1 should have its TCP transport"),
    };
    assert_eq!(
        inbound(&nodes),
        1,
        "node 1 should hold one inbound connection"
    );

    // Heartbeats only, for two idle deadlines and a little more.
    let start = tokio::time::Instant::now();
    let mut processed = 0;
    let mut after_first = 0;
    while start.elapsed() < idle * 2 + Duration::from_millis(500) {
        nodes[0].node.check_link_heartbeats().await;
        nodes[1].node.check_link_heartbeats().await;
        let frames = process_available_packets(&mut nodes).await;
        processed += frames;
        if start.elapsed() > idle {
            after_first += frames;
        }
        assert_eq!(
            inbound(&nodes),
            1,
            "the inbound connection was dropped after {:?} of heartbeat-only traffic",
            start.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // Sibling control: heartbeats were actually exchanged, through the
    // second deadline as well as the first, so the kept connection is not
    // an artefact of nothing having run. One heartbeat a second each way
    // gives about 30 frames, 15 of them after the first deadline; the
    // floors are half that.
    assert!(
        processed >= 14,
        "expected about a heartbeat a second each way, processed {processed}"
    );
    assert!(
        after_first >= 7,
        "expected heartbeats past the first idle deadline, processed {after_first} there"
    );
    assert!(
        nodes[0].node.get_peer(&addr_1).is_some(),
        "node 0 lost node 1"
    );
    assert!(
        nodes[1].node.get_peer(&addr_0).is_some(),
        "node 1 lost node 0"
    );

    cleanup_nodes(&mut nodes).await;
}

/// TCP reconnection after link death: connect-on-send re-establishes the link.
///
/// After both peers detect a dead link and remove each other, a fresh
/// handshake triggers TCP connect-on-send to open a new connection.
/// Verifies that bidirectional peering is restored. Each end's
/// `check_link_heartbeats()` removes the peer once the link-dead timeout
/// passes, so this covers the detection of the dead link as well as the
/// reconnection.
///
/// The link-dead timeout passes on the node's monotonic clock, which the
/// check reads, by `crate::time::advance` rather than a real wait. What the
/// real wait also gave the far end, time for its receive loop to read the
/// close and drop its pooled connection, is waited for in real time and
/// asserted before the re-handshake, so the new connection never meets the
/// old one's pool entry.
#[tokio::test]
async fn test_tcp_reconnection_after_link_death() {
    // Short timeouts; the link-dead one is set on the built nodes, which
    // would otherwise run at the 30 s floor.
    let mut config = Config::new();
    config.node.heartbeat_interval_secs = 1;
    let mut nodes = vec![
        make_test_node_tcp_with(config.clone()).await,
        make_test_node_tcp_with(config).await,
    ];
    for tn in nodes.iter_mut() {
        set_link_dead_timeout(&mut tn.node, 3);
    }

    // Establish initial peering
    initiate_handshake(&mut nodes, 0, 1).await;
    let total = drain_all_packets(&mut nodes, false).await;
    assert!(total > 0);

    let addr_0 = *nodes[0].node.node_addr();
    let addr_1 = *nodes[1].node.node_addr();
    assert!(nodes[0].node.get_peer(&addr_1).is_some());
    assert!(
        nodes[1].node.get_peer(&addr_0).is_some(),
        "precondition: node 1 holds node 0 before the close"
    );
    let inbound = |nodes: &[TestNode]| match nodes[1].node.transports.get(&nodes[1].transport_id) {
        Some(TransportHandle::Tcp(t)) => t.stats().pool_inbound_count(),
        _ => panic!("node 1 should have its TCP transport"),
    };
    assert_eq!(
        inbound(&nodes),
        1,
        "precondition: node 1 holds the inbound connection before the close"
    );

    // Force-close the TCP connection on node 0's side
    let node1_listen_addr = nodes[1].addr.clone();
    let transport = nodes[0]
        .node
        .transports
        .get(&nodes[0].transport_id)
        .unwrap();
    transport.close_connection(&node1_listen_addr).await;

    // Node 1's receive loop reads the close and removes its inbound
    // connection, which takes real time, not node time.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while inbound(&nodes) > 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        inbound(&nodes),
        0,
        "node 1 should have dropped the closed connection before the re-handshake"
    );

    // Past the 3 s link-dead timeout on the node's clock
    crate::time::advance(Duration::from_secs(4));

    // Trigger dead peer removal on both sides
    nodes[0].node.check_link_heartbeats().await;
    nodes[1].node.check_link_heartbeats().await;

    // Both should have removed the peer
    assert!(
        nodes[0].node.get_peer(&addr_1).is_none(),
        "node 0 should have removed node 1"
    );
    assert!(
        nodes[1].node.get_peer(&addr_0).is_none(),
        "node 1 should have removed node 0"
    );

    // Re-initiate handshake — triggers TCP connect-on-send
    initiate_handshake(&mut nodes, 0, 1).await;

    // Drain to complete handshake + tree announce
    let total2 = drain_all_packets(&mut nodes, false).await;
    assert!(total2 > 0, "should have processed reconnection packets");

    // Verify re-established peering
    assert!(
        nodes[0].node.get_peer(&addr_1).is_some(),
        "node 0 should have re-established peer node 1"
    );
    assert!(
        nodes[1].node.get_peer(&addr_0).is_some(),
        "node 1 should have re-established peer node 0"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Connection-oriented outbound connect succeeds on loopback and reaches the
/// handshake.
///
/// `initiate_connection` opens a real non-blocking TCP connect to a live
/// listener (node 1's `TcpTransport`) and queues a `PendingConnect`;
/// `poll_pending_connects` promotes the resolved connection to `Connected` and
/// runs `start_handshake`. The observable is `pending_outbound`: `start_handshake`
/// → `prepare_outbound_msg1` tracks the dispatched msg1 there (keyed by the
/// allocated session index), which is empty until the connect resolves.
#[tokio::test]
async fn test_tcp_oriented_connect_success_reaches_handshake() {
    let mut nodes = vec![make_test_node_tcp().await, make_test_node_tcp().await];

    // Target: node 1's live TCP listener + its verified identity.
    let target_addr = nodes[1].addr.clone();
    let target_identity = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let transport_id = nodes[0].transport_id;

    // Kick off the non-blocking oriented connect.
    nodes[0]
        .node
        .initiate_connection(transport_id, target_addr, target_identity)
        .await
        .expect("initiate_connection should queue a pending connect");

    // One pending connect queued, no msg1 dispatched yet.
    assert_eq!(nodes[0].node.peering.pending_connects.len(), 1);
    assert!(nodes[0].node.pending_outbound().is_empty());

    // Drive the tick-side poll until the background connect resolves.
    for _ in 0..100 {
        nodes[0].node.poll_pending_connects().await;
        if nodes[0].node.peering.pending_connects.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert!(
        nodes[0].node.peering.pending_connects.is_empty(),
        "connect should have resolved"
    );
    // Reaching start_handshake -> prepare_outbound_msg1 tracks the outbound msg1
    // in pending_outbound: proof the connect-success path dispatched the handshake.
    assert_eq!(
        nodes[0].node.pending_outbound().len(),
        1,
        "connect-success path should have reached start_handshake and dispatched msg1"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Connection-oriented outbound connect to a closed port fails and tears down
/// the link.
///
/// The dial targets a guaranteed-closed loopback port (bind then drop the
/// listener). `initiate_connection` is non-blocking, so it still queues a
/// `PendingConnect` and a `Connecting` link; `poll_pending_connects` observes the
/// background task's `Failed` result and routes through the failure arm
/// (`remove_link` + `note_handshake_timeout`). The observable is the removed link
/// and the absent `pending_outbound` entry — the failure path never reaches
/// `start_handshake`.
#[tokio::test]
async fn test_tcp_oriented_connect_failure_tears_down_link() {
    let mut nodes = vec![make_test_node_tcp().await];

    // A guaranteed-closed loopback port: bind to grab a port, then drop it.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_addr = closed.local_addr().unwrap();
    drop(closed);
    let target_addr = TransportAddr::from_string(&closed_addr.to_string());
    let target_identity = make_peer_identity();
    let transport_id = nodes[0].transport_id;

    nodes[0]
        .node
        .initiate_connection(transport_id, target_addr, target_identity)
        .await
        .expect("initiate_connection is non-blocking; it queues a pending connect");

    // One pending connect + the in-flight dial's link.
    assert_eq!(nodes[0].node.peering.pending_connects.len(), 1);
    assert_eq!(nodes[0].node.links.len(), 1);

    for _ in 0..100 {
        nodes[0].node.poll_pending_connects().await;
        if nodes[0].node.peering.pending_connects.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert!(
        nodes[0].node.peering.pending_connects.is_empty(),
        "failed connect should have been drained"
    );
    // Failure path removes the link and never reaches start_handshake.
    assert!(
        nodes[0].node.links.is_empty(),
        "connect-failure path should have torn down the link"
    );
    assert!(
        nodes[0].node.pending_outbound().is_empty(),
        "connect-failure path must not dispatch msg1"
    );

    cleanup_nodes(&mut nodes).await;
}

/// `api_disconnect` closes the pooled TCP connection, not just the peer.
///
/// Regression test: node-side teardown used to leave the socket, its pool
/// entry and its inbound-slot accounting alive after the node had forgotten
/// the peer they belonged to.
#[tokio::test]
async fn test_api_disconnect_closes_the_tcp_connection() {
    let mut nodes = vec![make_test_node_tcp().await, make_test_node_tcp().await];

    initiate_handshake(&mut nodes, 0, 1).await;
    let total = drain_all_packets(&mut nodes, false).await;
    assert!(total > 0, "should have processed packets");

    let addr_1 = *nodes[1].node.node_addr();
    let node1_npub = nodes[1].node.npub();

    let peer = nodes[0]
        .node
        .get_peer(&addr_1)
        .expect("node 0 should have node 1 as peer");
    let peer_transport_id = peer.transport_id().expect("peer should have a transport");
    let peer_addr = peer
        .current_addr()
        .expect("peer should have a current address")
        .clone();

    assert_eq!(
        nodes[0]
            .node
            .transports
            .get(&peer_transport_id)
            .unwrap()
            .connection_state(&peer_addr),
        ConnectionState::Connected,
        "the TCP connection should be pooled while the peer is up"
    );

    nodes[0]
        .node
        .api_disconnect(&node1_npub)
        .await
        .expect("api_disconnect should succeed");

    assert!(
        nodes[0].node.get_peer(&addr_1).is_none(),
        "node 0 should have removed node 1"
    );
    assert_eq!(
        nodes[0]
            .node
            .transports
            .get(&peer_transport_id)
            .unwrap()
            .connection_state(&peer_addr),
        ConnectionState::None,
        "the pooled TCP connection must not outlive the peer"
    );

    cleanup_nodes(&mut nodes).await;
}

/// The Disconnect `api_disconnect` sends must reach the peer before the TCP
/// connection closes, so the peer forgets this node at once.
///
/// The send only queues the Disconnect for the connection's writer, and the
/// close follows in the same call. Nothing else removes the peer on node 1
/// within the wait: its TCP EOF removes only the pool entry, and link-dead
/// detection takes far longer.
#[tokio::test]
async fn api_disconnect_delivers_the_disconnect_before_closing() {
    let mut nodes = vec![make_test_node_tcp().await, make_test_node_tcp().await];

    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;

    let addr_0 = *nodes[0].node.node_addr();
    let node1_npub = nodes[1].node.npub();
    assert!(
        nodes[1].node.get_peer(&addr_0).is_some(),
        "node 1 should have node 0 as peer"
    );

    nodes[0]
        .node
        .api_disconnect(&node1_npub)
        .await
        .expect("api_disconnect should succeed");

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while nodes[1].node.get_peer(&addr_0).is_some() && std::time::Instant::now() < deadline {
        spanning_tree::process_available_packets(&mut nodes).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        nodes[1].node.get_peer(&addr_0).is_none(),
        "node 1 never received the Disconnect sent before the close"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A peer that redials over TCP after its connection closed, at the same
/// epoch, has its rekey answered on the new connection and completes it,
/// without waiting for the link-dead reaper to remove the stale peering.
///
/// node 0 dialed node 1. node 0's connection closes, and node 1 still holds
/// the peering at node 0's old source port, where nothing answers. node 0's
/// rekey finds no connection, starts a background connect, and sends its
/// msg1 on the new connection a tick later. node 1 answers on that
/// connection, node 0 completes the rekey and cuts over, and its first frame
/// on the new session moves node 1's link to the new connection.
#[tokio::test]
async fn same_epoch_tcp_redial_completes_its_rekey_without_waiting_for_the_reaper() {
    use crate::proto::link::LinkMessageType;
    use std::time::Instant;

    const REKEY_AFTER_SECS: u64 = 60;
    let age = Duration::from_secs(REKEY_AFTER_SECS + crate::node::REKEY_JITTER_SECS as u64 + 1);
    let mut cfg0 = Config::new();
    cfg0.node.rekey.after_secs = REKEY_AFTER_SECS;
    cfg0.node.rekey.after_messages = u64::MAX;
    let mut cfg1 = Config::new();
    cfg1.node.rekey.after_secs = u64::MAX;
    cfg1.node.rekey.after_messages = u64::MAX;
    let mut nodes = vec![
        make_test_node_tcp_with(cfg0).await,
        make_test_node_tcp_with(cfg1).await,
    ];
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let addr0 = *nodes[0].node.node_addr();
    let addr1 = *nodes[1].node.node_addr();
    assert!(nodes[0].node.get_peer(&addr1).is_some(), "node 0 peers");
    let old_addr = nodes[1]
        .node
        .get_peer(&addr0)
        .expect("node 1 peers")
        .current_addr()
        .cloned()
        .unwrap();
    nodes[0]
        .node
        .get_peer_mut(&addr1)
        .unwrap()
        .test_backdate_session_established(age);
    nodes[1]
        .node
        .get_peer_mut(&addr0)
        .unwrap()
        .test_backdate_session_established(age);

    // node 0's connection closes; node 1's receive task drops its end.
    let node1_listen = nodes[1].addr.clone();
    let t0 = nodes[0].transport_id;
    let t1 = nodes[1].transport_id;
    nodes[0]
        .node
        .transports
        .get(&t0)
        .unwrap()
        .close_connection(&node1_listen)
        .await;
    let start = Instant::now();
    while nodes[1]
        .node
        .transports
        .get(&t1)
        .unwrap()
        .connection_state(&old_addr)
        != ConnectionState::None
    {
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "node 1 never dropped the closed connection"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // node 0's rekey starts on its tick. The first copy of its msg1 is lost
    // with the closed connection, whose failed send starts a new one, and
    // the resend at 1 s goes over that.
    let start = Instant::now();
    nodes[0].node.poll_link_rekeys().await;
    assert!(
        nodes[0].node.get_peer(&addr1).unwrap().rekey_in_progress(),
        "node 0's rekey started"
    );

    // The msg1 reaches node 1 on the new connection, the msg2 node 0, with
    // node 0's tick running.
    for _ in 0..150 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        nodes[0].node.poll_link_rekeys().await;
        process_available_packets(&mut nodes).await;
        if nodes[0]
            .node
            .get_peer(&addr1)
            .unwrap()
            .pending_new_session()
            .is_some()
        {
            break;
        }
    }
    let pending_idx = nodes[1]
        .node
        .get_peer(&addr0)
        .unwrap()
        .pending_our_index()
        .expect("node 1 must answer the redialed rekey and hold its new session");
    assert!(
        nodes[0]
            .node
            .get_peer(&addr1)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "node 0 must complete its rekey on the answer"
    );

    // node 0 cuts over; its first frame on the new session promotes node 1's
    // pending and moves node 1's link to the new connection.
    nodes[0].node.poll_link_rekeys().await;
    nodes[0]
        .node
        .send_encrypted_link_message(&addr1, &[LinkMessageType::Heartbeat.to_byte()])
        .await
        .expect("node 0 sends on the new connection");
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
        if nodes[1].node.get_peer(&addr0).unwrap().our_index() == Some(pending_idx) {
            break;
        }
    }
    let peer = nodes[1].node.get_peer(&addr0).unwrap();
    assert_eq!(
        peer.our_index(),
        Some(pending_idx),
        "node 1 must promote the session it answered with"
    );
    assert_ne!(
        peer.current_addr(),
        Some(&old_addr),
        "node 1's link must move to the new connection"
    );
    let took = start.elapsed();
    println!("redial rekey completed {took:?} after node 0's first rekey tick");
    assert!(
        took < Duration::from_secs(5),
        "the rekey took {took:?}; the link-dead reaper is 30 s"
    );

    cleanup_nodes(&mut nodes).await;
}

/// How long a TCP hop of the path tests may take in real time before the
/// test fails: the connect and each frame cross the loopback interface,
/// which `crate::time::advance` does not move.
const HOP: Duration = Duration::from_secs(5);

/// Give `tn`, a loopback test node, a started TCP transport `t2()` listening
/// on an ephemeral port of 127.0.0.1, whose paths are of the Internet kind
/// as the loopback link's are, so a path on it may join that link. What it
/// receives is forwarded into the channel `tn`'s loopback address delivers
/// to, stamped with `t2()` as the transport stamps it, so the test takes
/// TCP and loopback frames from one queue. Returns its listen address.
async fn second_tcp(tn: &mut TestNode) -> TransportAddr {
    use super::paths::t2;
    let config = TcpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1400),
        kind: Some(crate::config::PathKind::Internet),
        ..Default::default()
    };
    let (packet_tx, mut packet_rx) = packet_channel(256);
    let mut transport = TcpTransport::new(t2(), None, config, packet_tx);
    transport.start_async().await.unwrap();
    let listen = TransportAddr::from_string(&transport.local_addr().unwrap().to_string());
    let (_, into_node) = spanning_tree::LOOPBACK_REGISTRY
        .lock()
        .unwrap()
        .get(&tn.addr)
        .expect("the node's loopback address is registered")
        .clone();
    tokio::spawn(async move {
        while let Some(packet) = packet_rx.recv().await {
            if into_node.send(packet).is_err() {
                break;
            }
        }
    });
    tn.node
        .transports
        .insert(t2(), TransportHandle::Tcp(transport));
    listen
}

/// The path `tn` holds to `peer` on `transport`, with its address and
/// state, if it holds one there.
fn path_on(
    tn: &TestNode,
    peer: &NodeAddr,
    transport: TransportId,
) -> Option<(TransportAddr, crate::peer::PathState)> {
    let bundle = tn.node.get_peer(peer)?.bundle()?;
    bundle
        .paths()
        .paths()
        .iter()
        .find(|p| p.transport_id() == transport)
        .map(|p| (p.addr().clone(), p.state()))
}

/// A path candidate on TCP, a connection-oriented transport, is connected
/// before it is probed, its probe goes over that connection as its first
/// frame, and the peer takes the probe on its inbound connection with no
/// handshake on it, by the session index alone, and answers on the pair it
/// arrived on (multipath draft, Section 5.1); when the path is
/// discarded, its connection is closed, since the peer does not send on it
/// (Section 5.8). Each hop crosses a real socket, so each is awaited with a
/// bound in real time around a polling loop that yields, never a sleep.
#[tokio::test]
async fn a_tcp_candidate_is_connected_probed_and_its_connection_closed_with_its_path() {
    use super::paths::{enabled, exchange, hand, phase, state_at, t2, take_packets};
    use crate::peer::PathState;
    use crate::proto::fmp::wire::PHASE_ESTABLISHED;

    let mut nodes = super::rekey_parity::linked_pair(enabled(), enabled()).await;
    let (a, b) = (*nodes[0].node.node_addr(), *nodes[1].node.node_addr());
    second_tcp(&mut nodes[0]).await;
    let b_tcp = second_tcp(&mut nodes[1]).await;
    let state = |nodes: &[TestNode]| {
        nodes[0]
            .node
            .transports
            .get(&t2())
            .unwrap()
            .connection_state(&b_tcp)
    };

    // The capability exchange on the loopback path makes B capable at A and
    // admits the candidate, which asks for its connection and is not probed.
    nodes[0].node.offer_path(&b, t2(), b_tcp.clone()).await;
    exchange(&mut nodes).await;
    let outstanding = {
        let paths = nodes[0]
            .node
            .get_peer(&b)
            .unwrap()
            .bundle()
            .unwrap()
            .paths();
        let q = paths
            .get(paths.find(t2(), &b_tcp).expect("q admitted"))
            .unwrap();
        q.live().outstanding()
    };
    assert_eq!(outstanding, 0, "no probe on q before its connection");
    assert!(
        matches!(
            state(&nodes),
            ConnectionState::Connecting | ConnectionState::Connected
        ),
        "A asked for q's connection: {:?}",
        state(&nodes)
    );

    // The path tick that finds the connection open probes q over it.
    let opened = tokio::time::timeout(HOP, async {
        loop {
            nodes[0].node.path_tick().await;
            let tcp = nodes[0].node.transports.get(&t2()).unwrap();
            if tcp.has_connection(&b_tcp).await {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(opened.is_ok(), "q's connection opened within {HOP:?}");
    let outstanding = {
        let paths = nodes[0]
            .node
            .get_peer(&b)
            .unwrap()
            .bundle()
            .unwrap()
            .paths();
        paths
            .get(paths.find(t2(), &b_tcp).unwrap())
            .unwrap()
            .live()
            .outstanding()
    };
    assert_eq!(outstanding, 1, "q probed once its connection opened");

    // B's first frame on TCP is that probe, with no handshake before it: B
    // takes it by its index alone and holds a path at its source.
    let first = tokio::time::timeout(HOP, async {
        loop {
            let mut queued = take_packets(&mut nodes[1]);
            if let Some(i) = queued.iter().position(|p| p.transport_id == t2()) {
                let packet = queued.remove(i);
                for other in queued {
                    hand(&mut nodes[1], other).await;
                }
                return packet;
            }
            for other in queued {
                hand(&mut nodes[1], other).await;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("A's probe reached B over TCP");
    assert_eq!(phase(&first), Some(PHASE_ESTABLISHED), "no handshake on it");
    let source = first.remote_addr.clone();
    hand(&mut nodes[1], first).await;
    assert_eq!(
        path_on(&nodes[1], &a, t2()).map(|(addr, _)| addr),
        Some(source),
        "B holds a path at the probe's source"
    );

    // B's answer, on that pair, makes q Live at A.
    let live = tokio::time::timeout(HOP, async {
        loop {
            for packet in take_packets(&mut nodes[0]) {
                hand(&mut nodes[0], packet).await;
            }
            if state_at(&nodes[0], &b, t2(), &b_tcp) == Some(PathState::Live) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        live.is_ok(),
        "q Live at A within {HOP:?}: {:?}",
        state_at(&nodes[0], &b, t2(), &b_tcp)
    );

    // q's interface goes: q is discarded and, B's active path being p, its
    // connection is closed.
    assert_eq!(state(&nodes), ConnectionState::Connected, "precondition");
    assert_eq!(
        nodes[0].node.path_presence(t2(), false).await,
        0,
        "A keeps B"
    );
    assert_eq!(state_at(&nodes[0], &b, t2(), &b_tcp), None, "q discarded");
    assert_ne!(
        state(&nodes),
        ConnectionState::Connected,
        "q's connection closed with it"
    );
    cleanup_nodes(&mut nodes).await;
}

/// Deny `peer` in `node`'s peer ACL, read from files in a directory of its
/// own, which the caller keeps until the node is done with them.
async fn deny(node: &mut Node, peer: &Node) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    node.isolate_peer_acl_for_test(
        dir.path().join("peers.allow"),
        dir.path().join("peers.deny"),
    );
    std::fs::write(dir.path().join("peers.deny"), format!("{}\n", peer.npub())).unwrap();
    node.reload_peer_acl().await;
    dir
}

/// A raw TCP connection to `responder`'s listener on which one genuine msg1
/// from `initiator`'s identity at `epoch` has been sent, and the packet the
/// responder received for it.
async fn raw_msg1(
    responder: &mut TestNode,
    initiator: &Node,
    epoch: [u8; 8],
) -> (tokio::net::TcpStream, ReceivedPacket) {
    use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG1, build_msg1};
    use crate::utils::index::SessionIndex;
    use tokio::io::AsyncWriteExt;

    let identity = PeerIdentity::from_pubkey_full(responder.node.identity().pubkey_full());
    let mut leg = outbound_leg(LinkId::new(1), identity, 1000);
    let noise = leg
        .start_handshake(initiator.identity().keypair(), epoch, LegStamp::at(1000))
        .unwrap();
    let wire = build_msg1(SessionIndex::new(7), &noise);
    let listen: std::net::SocketAddr = responder.addr.as_str().unwrap().parse().unwrap();
    let mut stream = tokio::net::TcpStream::connect(listen).await.unwrap();
    stream.write_all(&wire).await.unwrap();
    let from = TransportAddr::from_string(&stream.local_addr().unwrap().to_string());
    let packet = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let p = responder
                .packet_rx
                .recv()
                .await
                .expect("packet channel open");
            let msg1 = CommonPrefix::parse(&p.data).is_some_and(|c| c.phase == PHASE_MSG1);
            if msg1 && p.remote_addr == from {
                break p;
            }
        }
    })
    .await
    .expect("precondition: the msg1 reaches the responder");
    (stream, packet)
}

/// What `node`'s TCP transport holds of the connection from `from`, and how
/// many inbound connections its pool holds.
fn pooled(node: &TestNode, from: &TransportAddr) -> (ConnectionState, u64) {
    let handle = node.node.transports.get(&node.transport_id).unwrap();
    let inbound = match handle {
        TransportHandle::Tcp(t) => t.stats().pool_inbound_count(),
        _ => unreachable!("a TCP test node"),
    };
    (handle.connection_state(from), inbound)
}

/// How long after `since` the responder ended `stream`, read with nothing
/// more sent: `Ok` at its end of stream or a reset, `Err` with what was
/// read if it is still open at `bound`.
async fn ended(
    stream: &mut tokio::net::TcpStream,
    since: std::time::Instant,
    bound: Duration,
) -> Result<Duration, String> {
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 256];
    match tokio::time::timeout(bound, stream.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => Ok(since.elapsed()),
        Ok(Ok(n)) => Err(format!("{n} bytes read")),
        Err(_) => Err(format!(
            "still open {:?} after the refusal",
            since.elapsed()
        )),
    }
}

/// Make `node`'s peering with `peer` a minute past its promotion and its
/// last authenticated frame, so the liveness gate does not hold a restart
/// back.
fn quiet(node: &mut Node, peer: &NodeAddr) {
    let p = node
        .get_peer_mut(peer)
        .expect("precondition: the responder holds the initiator");
    p.test_backdate_promoted(Duration::from_secs(60));
    p.test_backdate_heard(Duration::from_secs(60));
}

/// Stop every transport of `node`.
async fn stop_tcp(node: &mut TestNode) {
    for (_, t) in node.node.transports.iter_mut() {
        t.stop().await.ok();
    }
}

/// A msg1 on a fresh inbound TCP connection from an identity the ACL denies
/// is refused at the late ACL, after the answer is asked for, and its
/// connection closes at once: the initiator reads the end of its stream
/// well inside a second, not at the transport's inbound idle deadline (64 s
/// at stock settings), and the responder's inbound pool is free of it as the
/// refusal returns.
#[tokio::test]
async fn a_late_acl_refusal_of_a_fresh_inbound_tcp_msg1_closes_its_connection_at_once() {
    let config = Config::new();
    let idle = super::super::handlers::rekey::inbound_idle_timeout(&config.node);
    let mut b = make_test_node_tcp_idle(config, Some(idle)).await;
    let a = make_node();
    let _acl = deny(&mut b.node, &a).await;
    let (mut stream, packet) = raw_msg1(&mut b, &a, a.startup_epoch()).await;
    let from = packet.remote_addr.clone();
    let open = pooled(&b, &from);

    let refused_at = std::time::Instant::now();
    b.node.handle_msg1(packet).await;
    let held = (b.node.peer_count(), b.node.link_count());
    let asked = b.node.seen("Abandon");
    let after = pooled(&b, &from);
    let end = ended(&mut stream, refused_at, Duration::from_secs(1)).await;
    stop_tcp(&mut b).await;

    assert_eq!(
        open,
        (ConnectionState::Connected, 1),
        "precondition: the msg1's connection is pooled inbound"
    );
    assert_eq!(held, (0, 0), "precondition: the msg1 is refused");
    assert_eq!(
        asked, 1,
        "precondition: the refusal is the late ACL's, after the answer was asked for"
    );
    assert_eq!(
        after,
        (ConnectionState::None, 0),
        "defect: the responder's pool still holds the refused msg1's connection"
    );
    assert!(
        end.is_ok(),
        "defect: the refused msg1's connection did not close within a second: {end:?}"
    );
}

/// A node at a peer cap of one dials two nodes over TCP and both answer:
/// the first answer read installs its peer, and the second, refused at the
/// cap, closes the dial's connection at once, since no other link uses it,
/// as a connection refused by the ACL is closed.
#[tokio::test]
async fn a_dial_refused_at_the_peer_cap_closes_its_tcp_connection_at_once() {
    let mut config = Config::new();
    config.node.limits.max_peers = 1;
    let mut nodes = vec![
        make_test_node_tcp_with(config).await,
        make_test_node_tcp().await,
        make_test_node_tcp().await,
    ];
    initiate_handshake(&mut nodes, 0, 1).await;
    initiate_handshake(&mut nodes, 0, 2).await;
    let dialled = [1, 2].map(|j| pooled(&nodes[0], &nodes[j].addr.clone()).0);
    // Each responder answers, and the dialer reads both answers.
    for _ in 0..200 {
        if nodes[0].node.legs().iter().next().is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        process_available_packets(&mut nodes).await;
    }
    let settled = nodes[0].node.legs().iter().next().is_none();
    let held = nodes[0].node.peer_count();
    let refused = [1, 2]
        .into_iter()
        .find(|&j| nodes[0].node.get_peer(nodes[j].node.node_addr()).is_none());
    let after = refused.map(|j| pooled(&nodes[0], &nodes[j].addr.clone()).0);
    cleanup_nodes(&mut nodes).await;

    assert_eq!(
        dialled,
        [ConnectionState::Connected, ConnectionState::Connected],
        "precondition: both dials hold a connection"
    );
    assert!(settled, "precondition: the dialer read both answers");
    assert_eq!(held, 1, "precondition: the cap holds one peer");
    assert!(refused.is_some(), "precondition: one dial was refused");
    assert_eq!(
        after,
        Some(ConnectionState::None),
        "defect: the dial refused at the peer cap left its connection open"
    );
}

/// A peer this node holds over TCP, quiet for a minute, restarts (a msg1 at
/// a new epoch, on a new connection) while the ACL denies it. The restart's teardown removes the
/// held peer before the late ACL, which refuses the msg1, and the msg1's
/// connection closes at once, as a fresh connection's does.
#[tokio::test]
async fn a_late_acl_refusal_of_a_restart_msg1_over_tcp_closes_its_connection_at_once() {
    let mut nodes = vec![make_test_node_tcp().await, make_test_node_tcp().await];
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let a = *nodes[0].node.node_addr();
    let was_held = nodes[1].node.get_peer(&a).is_some();
    let mut epoch = nodes[0].node.startup_epoch();
    epoch[0] ^= 0xff;
    let (initiator, mut b) = (nodes.remove(0), nodes.remove(0));
    quiet(&mut b.node, &a);
    let _acl = deny(&mut b.node, &initiator.node).await;
    let (mut stream, packet) = raw_msg1(&mut b, &initiator.node, epoch).await;
    let from = packet.remote_addr.clone();

    let refused_at = std::time::Instant::now();
    b.node.handle_msg1(packet).await;
    let held = b.node.get_peer(&a).is_some();
    let after = pooled(&b, &from).0;
    let end = ended(&mut stream, refused_at, Duration::from_secs(1)).await;
    let mut nodes = vec![initiator, b];
    cleanup_nodes(&mut nodes).await;

    assert!(was_held, "precondition: the responder holds the initiator");
    assert!(
        !held,
        "precondition: the restart's teardown removed the held peer before the ACL refused it"
    );
    assert_eq!(
        after,
        ConnectionState::None,
        "defect: the responder's pool still holds the refused restart's connection"
    );
    assert!(
        end.is_ok(),
        "defect: the refused restart's connection did not close within a second: {end:?}"
    );
}

/// A msg1 on a fresh inbound TCP connection that the ACL admits, refused
/// because no session index can be drawn for its answer, closes its
/// connection at once, as the late ACL's refusal does.
#[tokio::test]
async fn a_fresh_inbound_tcp_msg1_refused_for_want_of_a_session_index_closes_its_connection_at_once()
 {
    let mut b = make_test_node_tcp().await;
    let a = make_node();
    b.node.index_allocator = crate::utils::index::IndexAllocator::with_max_attempts(0);
    let (mut stream, packet) = raw_msg1(&mut b, &a, a.startup_epoch()).await;
    let from = packet.remote_addr.clone();

    let refused_at = std::time::Instant::now();
    b.node.handle_msg1(packet).await;
    let held = b.node.peer_count();
    let asked = b.node.seen("Abandon");
    let after = pooled(&b, &from).0;
    let end = ended(&mut stream, refused_at, Duration::from_secs(1)).await;
    stop_tcp(&mut b).await;

    assert_eq!(held, 0, "precondition: the msg1 is refused");
    assert_eq!(
        asked, 1,
        "precondition: the refusal follows the ask, at the index draw"
    );
    assert_eq!(
        after,
        ConnectionState::None,
        "defect: the responder's pool still holds the refused msg1's connection"
    );
    assert!(
        end.is_ok(),
        "defect: the refused msg1's connection did not close within a second: {end:?}"
    );
}

/// A held peer's restart over TCP, quiet for a minute, that the ACL admits,
/// refused because no session index can be drawn for its answer once the
/// teardown has run, closes the msg1's connection at once.
#[tokio::test]
async fn a_restart_msg1_over_tcp_refused_for_want_of_a_session_index_closes_its_connection_at_once()
{
    let mut nodes = vec![make_test_node_tcp().await, make_test_node_tcp().await];
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let a = *nodes[0].node.node_addr();
    let was_held = nodes[1].node.get_peer(&a).is_some();
    let mut epoch = nodes[0].node.startup_epoch();
    epoch[0] ^= 0xff;
    let (initiator, mut b) = (nodes.remove(0), nodes.remove(0));
    quiet(&mut b.node, &a);
    // An allocator that draws nothing, holding the indices already drawn.
    let mut none = crate::utils::index::IndexAllocator::with_max_attempts(0);
    for peer in b.node.peers.values() {
        for ((_, index), _) in peer.link_bindings() {
            none.reserve(crate::utils::index::SessionIndex::new(index))
                .expect("precondition: each bound index once");
        }
    }
    b.node.index_allocator = none;
    let (mut stream, packet) = raw_msg1(&mut b, &initiator.node, epoch).await;
    let from = packet.remote_addr.clone();

    let refused_at = std::time::Instant::now();
    b.node.handle_msg1(packet).await;
    let held = b.node.get_peer(&a).is_some();
    let after = pooled(&b, &from).0;
    let end = ended(&mut stream, refused_at, Duration::from_secs(1)).await;
    let mut nodes = vec![initiator, b];
    cleanup_nodes(&mut nodes).await;

    assert!(was_held, "precondition: the responder holds the initiator");
    assert!(
        !held,
        "precondition: the restart's teardown removed the held peer before the index draw failed"
    );
    assert_eq!(
        after,
        ConnectionState::None,
        "defect: the responder's pool still holds the refused restart's connection"
    );
    assert!(
        end.is_ok(),
        "defect: the refused restart's connection did not close within a second: {end:?}"
    );
}

/// A peer this node holds over TCP, heard from, redials it from a new
/// connection (a fresh msg1 at the same epoch, off the established link)
/// while the ACL denies it. The redial is refused at the ACL, before an
/// index is drawn for it, and the redial's connection closes at once, as a
/// fresh connection's does; the held peering stays.
#[tokio::test]
async fn a_redial_over_tcp_refused_by_the_acl_closes_its_connection_at_once() {
    let mut nodes = vec![make_test_node_tcp().await, make_test_node_tcp().await];
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let a = *nodes[0].node.node_addr();
    let heard = nodes[1].node.get_peer(&a).is_some_and(|p| p.is_heard());
    let held_link = nodes[1].node.get_peer(&a).map(|p| p.link_id());
    let epoch = nodes[0].node.startup_epoch();
    let (initiator, mut b) = (nodes.remove(0), nodes.remove(0));
    let _acl = deny(&mut b.node, &initiator.node).await;
    let was = b.node.stats().handshake.snapshot();
    let (mut stream, packet) = raw_msg1(&mut b, &initiator.node, epoch).await;
    let from = packet.remote_addr.clone();
    let open = pooled(&b, &from).0;

    let refused_at = std::time::Instant::now();
    b.node.handle_msg1(packet).await;
    let r = b.node.stats().handshake.snapshot();
    let armed = b.node.redials.of(&a).is_some();
    let still = b.node.get_peer(&a).map(|p| p.link_id());
    let after = pooled(&b, &from).0;
    let end = ended(&mut stream, refused_at, Duration::from_secs(1)).await;
    let mut nodes = vec![initiator, b];
    cleanup_nodes(&mut nodes).await;

    assert!(heard, "precondition: the responder has heard the initiator");
    assert_eq!(
        open,
        ConnectionState::Connected,
        "precondition: the redial's connection is pooled inbound"
    );
    assert!(
        r.redials == was.redials && r.bad_state > was.bad_state && !armed,
        "precondition: the redial is refused at the ACL: {was:?} -> {r:?}"
    );
    assert_eq!(still, held_link, "precondition: the held peering stays");
    assert_eq!(
        after,
        ConnectionState::None,
        "defect: the responder's pool still holds the refused redial's connection"
    );
    assert!(
        end.is_ok(),
        "defect: the refused redial's connection did not close within a second: {end:?}"
    );
}

/// A genuine msg1 from `initiator`'s identity at `epoch` to `responder`,
/// sender index `sidx`, written on `stream`, an open connection to the
/// responder's listener, and the packet the responder received for it.
async fn msg1_on(
    stream: &mut tokio::net::TcpStream,
    responder: &mut TestNode,
    initiator: &Node,
    epoch: [u8; 8],
    sidx: u32,
) -> ReceivedPacket {
    use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG1, build_msg1};
    use crate::utils::index::SessionIndex;
    use tokio::io::AsyncWriteExt;

    let identity = PeerIdentity::from_pubkey_full(responder.node.identity().pubkey_full());
    let mut leg = outbound_leg(LinkId::new(1), identity, 1000);
    let noise = leg
        .start_handshake(initiator.identity().keypair(), epoch, LegStamp::at(1000))
        .unwrap();
    let wire = build_msg1(SessionIndex::new(sidx), &noise);
    stream.write_all(&wire).await.unwrap();
    let from = TransportAddr::from_string(&stream.local_addr().unwrap().to_string());
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let p = responder
                .packet_rx
                .recv()
                .await
                .expect("packet channel open");
            let msg1 = CommonPrefix::parse(&p.data).is_some_and(|c| c.phase == PHASE_MSG1);
            if msg1 && p.remote_addr == from {
                break p;
            }
        }
    })
    .await
    .expect("precondition: the msg1 reaches the responder")
}

/// The receiver index of the next msg2 read off `stream` within a second,
/// or why none was read.
async fn msg2_on(stream: &mut tokio::net::TcpStream) -> Result<u32, String> {
    use crate::proto::fmp::wire::{MSG2_WIRE_SIZE, Msg2Header};
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; MSG2_WIRE_SIZE];
    match tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut buf)).await {
        Ok(Ok(_)) => Msg2Header::parse(&buf)
            .map(|h| h.receiver_idx.as_u32())
            .ok_or_else(|| "not a msg2".to_string()),
        Ok(Err(e)) => Err(format!("the stream ended: {e}")),
        Err(_) => Err("nothing read within a second".to_string()),
    }
}

/// A peer this node holds over TCP, heard from, redials it from a new
/// connection, and the redial is answered into a pending redial that no
/// frame proves. More than a second later a second fresh msg1 of the peer
/// arrives on the same connection: it replaces the pending redial, whose
/// leg is cleaned up, and is answered. The connection is the second
/// redial's own as much as the first's, so it stays open, and the second
/// redial's msg2 goes out on it.
#[tokio::test]
async fn a_second_redial_over_tcp_on_a_pending_redials_connection_keeps_the_connection_and_is_answered()
 {
    crate::time::freeze();
    let mut nodes = vec![make_test_node_tcp().await, make_test_node_tcp().await];
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let a = *nodes[0].node.node_addr();
    let heard = nodes[1].node.get_peer(&a).is_some_and(|p| p.is_heard());
    let held_link = nodes[1].node.get_peer(&a).map(|p| p.link_id());
    let epoch = nodes[0].node.startup_epoch();
    let (initiator, mut b) = (nodes.remove(0), nodes.remove(0));
    let was = b.node.stats().handshake.snapshot();
    let (mut stream, packet) = raw_msg1(&mut b, &initiator.node, epoch).await;
    let from = packet.remote_addr.clone();
    b.node.handle_msg1(packet).await;
    let first = b.node.redials.of(&a);
    let first_msg2 = msg2_on(&mut stream).await;

    crate::time::advance(Duration::from_millis(1500));
    let packet = msg1_on(&mut stream, &mut b, &initiator.node, epoch, 0x5EC0).await;
    b.node.handle_msg1(packet).await;
    let second = b.node.redials.of(&a);
    let r = b.node.stats().handshake.snapshot();
    let after = pooled(&b, &from).0;
    let second_msg2 = msg2_on(&mut stream).await;
    let still = b.node.get_peer(&a).map(|p| p.link_id());
    let mut nodes = vec![initiator, b];
    cleanup_nodes(&mut nodes).await;

    assert!(heard, "precondition: the responder has heard the initiator");
    assert_eq!(
        first_msg2,
        Ok(7),
        "precondition: the first redial is answered on the connection"
    );
    assert!(
        first.is_some() && r.redials == was.redials + 2,
        "precondition: both msg1s are answered as redials: {was:?} -> {r:?}"
    );
    assert_eq!(still, held_link, "precondition: the held peering stays");
    assert_eq!(
        after,
        ConnectionState::Connected,
        "defect: the cleanup of the first redial closed the second redial's connection"
    );
    assert!(
        second.is_some_and(|s| Some(s.link) != first.map(|f| f.link)),
        "defect: the second redial is not pending in place of the first: {first:?} -> {second:?}"
    );
    assert_eq!(
        second_msg2,
        Ok(0x5EC0),
        "defect: the second redial's msg2 did not reach its connection"
    );
}
