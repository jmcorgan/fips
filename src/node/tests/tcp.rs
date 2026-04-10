//! TCP transport integration tests.
//!
//! Tests that the TCP transport works end-to-end at the node level:
//! handshake, spanning tree convergence, mixed-transport routing,
//! MMP link-dead detection, and reconnection after link death.
//! All tests use 127.0.0.1:0 (ephemeral ports) and need no privileges.

use super::*;
use crate::config::TcpConfig;
use crate::transport::tcp::TcpTransport;
use crate::transport::{TransportAddr, TransportHandle, TransportId, packet_channel};
use spanning_tree::{
    TestNode, cleanup_nodes, drain_all_packets, initiate_handshake, verify_tree_convergence,
};
use std::time::Duration;

/// Create a test node with a live TCP transport on loopback.
///
/// Parallel to `make_test_node()` in spanning_tree.rs but uses
/// TcpTransport instead of UDP. Binds to 127.0.0.1:0 for an
/// ephemeral port.
async fn make_test_node_tcp() -> TestNode {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let config = TcpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1400),
        ..Default::default()
    };

    let (packet_tx, packet_rx) = packet_channel(256);
    let mut transport = TcpTransport::new(transport_id, None, config, packet_tx);
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
        packet_rx,
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

/// TCP connection drop is detected by MMP link-dead timeout.
///
/// Establishes peering, force-closes the TCP connection, then verifies
/// that `check_link_heartbeats()` detects the dead peer after the
/// link-dead timeout fires.
#[tokio::test]
async fn test_tcp_connection_loss_detection() {
    let mut nodes = vec![make_test_node_tcp().await, make_test_node_tcp().await];

    // Short heartbeat/link-dead timeouts for faster test execution
    for tn in nodes.iter_mut() {
        tn.node.config.node.heartbeat_interval_secs = 1;
        tn.node.config.node.link_dead_timeout_secs = 3;
    }

    // Establish peering
    initiate_handshake(&mut nodes, 0, 1).await;
    let total = drain_all_packets(&mut nodes, false).await;
    assert!(total > 0);

    let addr_0 = *nodes[0].node.node_addr();
    let addr_1 = *nodes[1].node.node_addr();
    assert!(nodes[0].node.get_peer(&addr_1).is_some());
    assert!(nodes[1].node.get_peer(&addr_0).is_some());

    // Force-close the TCP connection on node 0's side toward node 1
    let node1_listen_addr = nodes[1].addr.clone();
    let transport = nodes[0]
        .node
        .transports
        .get(&nodes[0].transport_id)
        .unwrap();
    transport.close_connection(&node1_listen_addr).await;

    // Wait for link-dead timeout to fire (3 seconds + margin)
    tokio::time::sleep(Duration::from_secs(4)).await;

    // Trigger heartbeat check (normally done by the tick handler)
    nodes[0].node.check_link_heartbeats().await;

    // Node 0 should have detected node 1 as dead and removed it
    assert!(
        nodes[0].node.get_peer(&addr_1).is_none(),
        "node 0 should have removed dead peer node 1"
    );

    cleanup_nodes(&mut nodes).await;
}

/// TCP reconnection after link death: connect-on-send re-establishes the link.
///
/// After both peers detect a dead link and remove each other, a fresh
/// handshake triggers TCP connect-on-send to open a new connection.
/// Verifies that bidirectional peering is restored.
#[tokio::test]
async fn test_tcp_reconnection_after_link_death() {
    let mut nodes = vec![make_test_node_tcp().await, make_test_node_tcp().await];

    // Short timeouts
    for tn in nodes.iter_mut() {
        tn.node.config.node.heartbeat_interval_secs = 1;
        tn.node.config.node.link_dead_timeout_secs = 3;
    }

    // Establish initial peering
    initiate_handshake(&mut nodes, 0, 1).await;
    let total = drain_all_packets(&mut nodes, false).await;
    assert!(total > 0);

    let addr_0 = *nodes[0].node.node_addr();
    let addr_1 = *nodes[1].node.node_addr();
    assert!(nodes[0].node.get_peer(&addr_1).is_some());

    // Force-close the TCP connection on node 0's side
    let node1_listen_addr = nodes[1].addr.clone();
    let transport = nodes[0]
        .node
        .transports
        .get(&nodes[0].transport_id)
        .unwrap();
    transport.close_connection(&node1_listen_addr).await;

    // Wait for link-dead timeout
    tokio::time::sleep(Duration::from_secs(4)).await;

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
