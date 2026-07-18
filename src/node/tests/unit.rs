use super::*;
use crate::nostr::{BootstrapEvent, NostrRendezvous};
use crate::proto::fmp::PromotionResult;
use crate::transport::udp::UdpTransport;
use crate::transport::{TransportHandle, packet_channel};
use std::sync::Arc;

#[test]
fn test_node_creation() {
    let node = make_node();

    assert_eq!(node.state(), NodeState::Created);
    assert_eq!(node.peer_count(), 0);
    assert_eq!(node.connection_count(), 0);
    assert_eq!(node.link_count(), 0);
    assert!(!node.is_leaf_only());
}

#[test]
fn test_node_with_identity() {
    let identity = Identity::generate();
    let expected_node_addr = *identity.node_addr();
    let config = Config::new();

    let node = Node::with_identity(identity, config).unwrap();

    assert_eq!(node.node_addr(), &expected_node_addr);
}

#[test]
fn test_node_with_identity_validates_config() {
    let identity = Identity::generate();
    let mut config = Config::new();
    config.node.rendezvous.nostr.enabled = false;
    config.peers = vec![crate::config::PeerConfig {
        npub: "npub1peer".to_string(),
        via_nostr: true,
        ..Default::default()
    }];

    let err = Node::with_identity(identity, config).expect_err("expected config validation error");
    assert!(matches!(err, NodeError::Config(_)));
}

#[test]
fn test_node_leaf_only() {
    let config = Config::new();
    let node = Node::leaf_only(config).unwrap();

    assert!(node.is_leaf_only());
    assert!(node.bloom_state().is_leaf_only());
}

#[tokio::test]
async fn test_nat_bootstrap_failure_falls_back_to_direct_udp_address() {
    let peer_identity = Identity::generate();
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "nat", 1),
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:9", 2),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        via_nostr: false,
    };
    let peer_identity = PeerIdentity::from_npub(&peer_config.npub).unwrap();

    node.try_peer_addresses(&peer_config, peer_identity, false)
        .await
        .unwrap();

    assert_eq!(node.connection_count(), 1);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_try_peer_addresses_races_all_concrete_udp_candidates() {
    let peer_identity = Identity::generate();
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:9", 1),
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:10", 2),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        via_nostr: false,
    };
    let peer_identity = PeerIdentity::from_npub(&peer_config.npub).unwrap();

    node.try_peer_addresses(&peer_config, peer_identity, false)
        .await
        .unwrap();

    let mut addrs = node
        .connections
        .values()
        .filter_map(|conn| conn.source_addr().and_then(|addr| addr.as_str()))
        .collect::<Vec<_>>();
    addrs.sort();
    assert_eq!(addrs, vec!["127.0.0.1:10", "127.0.0.1:9"]);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_node_state_transitions() {
    // A transport-less node now resolves to `Failed` on start, so exercise
    // state transitions with a genuinely healthy node.
    let mut node = make_healthy_node();

    assert!(!node.is_running());
    assert!(node.state().can_start());

    node.start().await.unwrap();
    assert!(node.is_running());
    assert_eq!(node.state(), NodeState::Running);
    assert!(!node.state().can_start());

    node.stop().await.unwrap();
    assert!(!node.is_running());
    assert_eq!(node.state(), NodeState::Stopped);
}

#[tokio::test]
async fn test_transportless_start_fails_and_publishes_failed() {
    // The intended behavioral change: a node with zero
    // transports up cannot serve, so `start()` returns `NoOperationalTransports`
    // and leaves the published state at `Failed` (not operational, not
    // restartable in-process).
    let mut node = make_node();
    assert!(node.state().can_start());

    let result = node.start().await;
    assert!(matches!(result, Err(NodeError::NoOperationalTransports)));
    assert_eq!(node.state(), NodeState::Failed);
    assert!(!node.is_running());
    assert!(!node.state().is_operational());
    assert!(!node.state().can_start());
}

#[tokio::test]
async fn test_drain_publishes_draining_state() {
    let mut node = make_healthy_node();
    node.start().await.unwrap();
    assert_eq!(node.state(), NodeState::Running);
    assert!(node.state().is_operational());

    // Enter the bounded drain in place: publishes the operator-visible
    // `Draining` state (not operational) without tearing down.
    node.enter_drain().await;
    assert_eq!(node.state(), NodeState::Draining);
    assert!(!node.state().is_operational());
    // `Draining` is neither startable nor externally stoppable; the daemon
    // drain finishes via the supervisor's `DrainDeadlineElapsed`, not `stop()`.
    assert!(!node.state().can_start());
    assert!(!node.state().can_stop());

    // Finishing shutdown from `Draining` tears down to `Stopped`.
    node.finish_shutdown().await;
    assert_eq!(node.state(), NodeState::Stopped);
}

#[tokio::test]
async fn test_immediate_stop_never_publishes_draining() {
    let mut node = make_healthy_node();
    node.start().await.unwrap();
    assert_eq!(node.state(), NodeState::Running);

    // The immediate stop() path (used by tests and the stop-now path)
    // transitions Running → Stopping → Stopped and never enters `Draining`.
    node.stop().await.unwrap();
    assert_eq!(node.state(), NodeState::Stopped);
    assert_ne!(node.state(), NodeState::Draining);
}

#[tokio::test]
async fn test_node_start_does_not_wait_for_nostr_relay_startup() {
    let mut config = Config::new();
    config.node.control.enabled = false;
    config.node.rendezvous.nostr.enabled = true;
    config.node.rendezvous.nostr.advertise = true;
    config.node.rendezvous.nostr.policy = crate::config::NostrRendezvousPolicy::Open;
    config.node.rendezvous.nostr.advert_relays = vec!["wss://127.0.0.1:9".to_string()];
    config.node.rendezvous.nostr.dm_relays = vec!["wss://127.0.0.1:9".to_string()];
    config.transports.udp = crate::config::TransportInstances::Single(crate::config::UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        advertise_on_nostr: Some(true),
        public: Some(false),
        accept_connections: Some(true),
        ..Default::default()
    });

    let mut node = Node::new(config).unwrap();
    tokio::time::timeout(std::time::Duration::from_millis(500), node.start())
        .await
        .expect("node start should not wait for relay I/O")
        .unwrap();

    assert!(node.is_running());
    assert!(node.nostr_rendezvous_handle().is_some());

    node.stop().await.unwrap();
}

#[tokio::test]
async fn test_node_double_start() {
    let mut node = make_healthy_node();
    node.start().await.unwrap();

    let result = node.start().await;
    assert!(matches!(result, Err(NodeError::AlreadyStarted)));

    // Clean up
    node.stop().await.unwrap();
}

#[tokio::test]
async fn test_node_stop_not_started() {
    let mut node = make_node();

    let result = node.stop().await;
    assert!(matches!(result, Err(NodeError::NotStarted)));
}

#[test]
fn test_node_link_management() {
    let mut node = make_node();

    let link_id = node.allocate_link_id();
    let link = Link::connectionless(
        link_id,
        TransportId::new(1),
        TransportAddr::from_string("test"),
        LinkDirection::Outbound,
        Duration::from_millis(50),
    );

    node.add_link(link).unwrap();
    assert_eq!(node.link_count(), 1);

    assert!(node.get_link(&link_id).is_some());

    // Test addr_to_link lookup
    assert_eq!(
        node.find_link_by_addr(TransportId::new(1), &TransportAddr::from_string("test")),
        Some(link_id)
    );

    node.remove_link(&link_id);
    assert_eq!(node.link_count(), 0);

    // Lookup should be gone
    assert!(
        node.find_link_by_addr(TransportId::new(1), &TransportAddr::from_string("test"))
            .is_none()
    );
}

#[test]
fn test_node_link_limit() {
    let mut node = make_node_with_max_links(2);

    for i in 0..2 {
        let link_id = node.allocate_link_id();
        let link = Link::connectionless(
            link_id,
            TransportId::new(1),
            TransportAddr::from_string(&format!("test{}", i)),
            LinkDirection::Outbound,
            Duration::from_millis(50),
        );
        node.add_link(link).unwrap();
    }

    let link_id = node.allocate_link_id();
    let link = Link::connectionless(
        link_id,
        TransportId::new(1),
        TransportAddr::from_string("test_extra"),
        LinkDirection::Outbound,
        Duration::from_millis(50),
    );

    let result = node.add_link(link);
    assert!(matches!(result, Err(NodeError::MaxLinksExceeded { .. })));
}

#[test]
fn test_node_connection_management() {
    let mut node = make_node();

    let identity = make_peer_identity();
    let link_id = LinkId::new(1);
    let conn = PeerConnection::outbound(link_id, identity, 1000);

    node.add_connection(conn).unwrap();
    assert_eq!(node.connection_count(), 1);

    assert!(node.get_connection(&link_id).is_some());

    node.remove_connection(&link_id);
    assert_eq!(node.connection_count(), 0);
}

#[test]
fn test_node_connection_duplicate() {
    let mut node = make_node();

    let identity = make_peer_identity();
    let link_id = LinkId::new(1);
    let conn1 = PeerConnection::outbound(link_id, identity, 1000);
    let conn2 = PeerConnection::outbound(link_id, identity, 2000);

    node.add_connection(conn1).unwrap();
    let result = node.add_connection(conn2);

    assert!(matches!(result, Err(NodeError::ConnectionAlreadyExists(_))));
}

#[test]
fn test_node_promote_connection() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn).unwrap();
    assert_eq!(node.connection_count(), 1);
    assert_eq!(node.peer_count(), 0);

    let result = node.promote_connection(link_id, identity, 2000).unwrap();

    assert!(matches!(result, PromotionResult::Promoted(_)));
    assert_eq!(node.connection_count(), 0);
    assert_eq!(node.peer_count(), 1);

    let peer = node.get_peer(&node_addr).unwrap();
    assert_eq!(peer.authenticated_at(), 2000);
    assert!(peer.has_session(), "Promoted peer should have NoiseSession");
    assert!(
        peer.our_index().is_some(),
        "Promoted peer should have our_index"
    );
    assert!(
        peer.their_index().is_some(),
        "Promoted peer should have their_index"
    );

    // Verify peers_by_index is populated
    let our_index = peer.our_index().unwrap();
    assert_eq!(
        node.peers_by_index.get(&(transport_id, our_index.as_u32())),
        Some(&node_addr)
    );
}

#[test]
fn test_node_cross_connection_resolution() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // First connection and promotion (becomes active peer)
    let link_id1 = LinkId::new(1);
    let (conn1, identity) = make_completed_connection(&mut node, link_id1, transport_id, 1000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn1).unwrap();
    node.promote_connection(link_id1, identity, 1500).unwrap();

    assert_eq!(node.peer_count(), 1);
    assert_eq!(node.get_peer(&node_addr).unwrap().link_id(), link_id1);

    // Cross-connection tie-breaker logic is tested in peer/mod.rs tests.
    // The integration test will cover the real cross-connection path with
    // two actual nodes. Here we verify promotion works correctly.

    // Verify first promotion populated peers_by_index
    let peer = node.get_peer(&node_addr).unwrap();
    let our_idx = peer.our_index().unwrap();
    assert_eq!(
        node.peers_by_index.get(&(transport_id, our_idx.as_u32())),
        Some(&node_addr)
    );

    // Still only one peer
    assert_eq!(node.peer_count(), 1);
}

#[test]
fn test_node_peer_limit() {
    let mut node = make_node_with_max_peers(2);
    let transport_id = TransportId::new(1);

    // Add two peers via promotion
    for i in 0..2 {
        let link_id = LinkId::new(i as u64 + 1);
        let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
        node.add_connection(conn).unwrap();
        node.promote_connection(link_id, identity, 2000).unwrap();
    }

    assert_eq!(node.peer_count(), 2);

    // Third should fail
    let link_id = LinkId::new(3);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 3000);
    node.add_connection(conn).unwrap();

    let result = node.promote_connection(link_id, identity, 4000);
    assert!(matches!(result, Err(NodeError::MaxPeersExceeded { .. })));
}

#[test]
fn test_node_link_id_allocation() {
    let mut node = make_node();

    let id1 = node.allocate_link_id();
    let id2 = node.allocate_link_id();
    let id3 = node.allocate_link_id();

    assert_ne!(id1, id2);
    assert_ne!(id2, id3);
    assert_eq!(id1.as_u64(), 1);
    assert_eq!(id2.as_u64(), 2);
    assert_eq!(id3.as_u64(), 3);
}

#[test]
fn test_node_transport_management() {
    let mut node = make_node();

    // Initially no transports (transports are created during start())
    assert_eq!(node.transport_count(), 0);

    // Allocating IDs still works
    let id1 = node.allocate_transport_id();
    let id2 = node.allocate_transport_id();
    assert_ne!(id1, id2);

    // get_transport returns None when transport doesn't exist
    assert!(node.get_transport(&id1).is_none());
    assert!(node.get_transport(&id2).is_none());

    // transport_ids() iterator is empty
    assert_eq!(node.transport_ids().count(), 0);
}

#[test]
fn test_node_sendable_peers() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // Add a healthy peer
    let link_id1 = LinkId::new(1);
    let (conn1, identity1) = make_completed_connection(&mut node, link_id1, transport_id, 1000);
    let node_addr1 = *identity1.node_addr();
    node.add_connection(conn1).unwrap();
    node.promote_connection(link_id1, identity1, 2000).unwrap();

    // Add another peer and mark it stale (still sendable)
    let link_id2 = LinkId::new(2);
    let (conn2, identity2) = make_completed_connection(&mut node, link_id2, transport_id, 1000);
    node.add_connection(conn2).unwrap();
    node.promote_connection(link_id2, identity2, 2000).unwrap();

    // Add a third peer and mark it disconnected (not sendable)
    let link_id3 = LinkId::new(3);
    let (conn3, identity3) = make_completed_connection(&mut node, link_id3, transport_id, 1000);
    let node_addr3 = *identity3.node_addr();
    node.add_connection(conn3).unwrap();
    node.promote_connection(link_id3, identity3, 2000).unwrap();
    node.get_peer_mut(&node_addr3).unwrap().mark_disconnected();

    assert_eq!(node.peer_count(), 3);
    assert_eq!(node.sendable_peer_count(), 2);

    let sendable: Vec<_> = node.sendable_peers().collect();
    assert_eq!(sendable.len(), 2);
    assert!(sendable.iter().any(|p| p.node_addr() == &node_addr1));
}

// === RX Loop Tests ===

#[test]
fn test_node_index_allocator_initialized() {
    let node = make_node();
    // Index allocator should be empty on creation
    assert_eq!(node.index_allocator.count(), 0);
}

#[test]
fn test_node_pending_outbound_tracking() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    // Allocate an index
    let index = node.index_allocator.allocate().unwrap();

    // Track in pending_outbound
    node.pending_outbound
        .insert((transport_id, index.as_u32()), link_id);

    // Verify we can look it up
    let found = node.pending_outbound.get(&(transport_id, index.as_u32()));
    assert_eq!(found, Some(&link_id));

    // Clean up
    node.pending_outbound
        .remove(&(transport_id, index.as_u32()));
    let _ = node.index_allocator.free(index);

    assert_eq!(node.index_allocator.count(), 0);
    assert!(node.pending_outbound.is_empty());
}

#[test]
fn test_node_peers_by_index_tracking() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let node_addr = make_node_addr(42);

    // Allocate an index
    let index = node.index_allocator.allocate().unwrap();

    // Track in peers_by_index
    node.peers_by_index
        .insert((transport_id, index.as_u32()), node_addr);

    // Verify lookup
    let found = node.peers_by_index.get(&(transport_id, index.as_u32()));
    assert_eq!(found, Some(&node_addr));

    // Clean up
    node.peers_by_index.remove(&(transport_id, index.as_u32()));
    let _ = node.index_allocator.free(index);

    assert!(node.peers_by_index.is_empty());
}

#[tokio::test]
async fn test_node_rx_loop_requires_start() {
    let mut node = make_node();

    // RX loop should fail if node not started (no packet_rx)
    let result = node.run_rx_loop().await;
    assert!(matches!(result, Err(NodeError::NotStarted)));
}

#[tokio::test]
async fn test_node_rx_loop_takes_channel() {
    let mut node = make_healthy_node();
    node.start().await.unwrap();

    // packet_rx should be available after start
    assert!(node.packet_rx.is_some());

    // After run_rx_loop takes ownership, it should be None
    // We can't actually run the loop (it blocks), but we can test the take
    let rx = node.packet_rx.take();
    assert!(rx.is_some());
    assert!(node.packet_rx.is_none());

    node.stop().await.unwrap();
}

#[test]
fn test_rate_limiter_initialized() {
    let mut node = make_node();

    // Rate limiter should allow handshakes initially
    assert!(node.msg1_rate_limiter.can_start_handshake());

    // Start a handshake
    assert!(node.msg1_rate_limiter.start_handshake());
    assert_eq!(node.msg1_rate_limiter.pending_count(), 1);

    // Complete it
    node.msg1_rate_limiter.complete_handshake();
    assert_eq!(node.msg1_rate_limiter.pending_count(), 0);
}

// === Promotion / Retry Tests ===

/// Test that promoting a connection cleans up a pending outbound to the same peer.
///
/// Simulates the scenario where node A has a pending outbound handshake to B
/// (unanswered because B wasn't running), then B starts and initiates to A.
/// When A promotes B's inbound connection, it should immediately clean up the
/// stale pending outbound rather than waiting for the 30s timeout.
#[test]
fn test_promote_cleans_up_pending_outbound_to_same_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // Generate peer B's identity (shared between the two connections)
    let peer_b_full = Identity::generate();
    let peer_b_identity = PeerIdentity::from_pubkey_full(peer_b_full.pubkey_full());
    let peer_b_node_addr = *peer_b_identity.node_addr();

    // --- Set up the pending outbound to B (link_id 1) ---
    // This simulates A having sent msg1 to B before B was running.
    let pending_link_id = LinkId::new(1);
    let pending_time_ms = 1000;
    let mut pending_conn =
        PeerConnection::outbound(pending_link_id, peer_b_identity, pending_time_ms);

    let our_keypair = node.identity().keypair();
    let _msg1 = pending_conn
        .start_handshake(our_keypair, node.startup_epoch(), pending_time_ms)
        .unwrap();

    let pending_index = node.index_allocator.allocate().unwrap();
    pending_conn.set_our_index(pending_index);
    pending_conn.set_transport_id(transport_id);
    let pending_addr = TransportAddr::from_string("10.0.0.2:2121");
    pending_conn.set_source_addr(pending_addr.clone());

    let pending_link = Link::connectionless(
        pending_link_id,
        transport_id,
        pending_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node.links.insert(pending_link_id, pending_link);
    node.addr_to_link
        .insert((transport_id, pending_addr.clone()), pending_link_id);
    node.connections.insert(pending_link_id, pending_conn);
    node.pending_outbound
        .insert((transport_id, pending_index.as_u32()), pending_link_id);

    // Verify pending state
    assert_eq!(node.connection_count(), 1);
    assert_eq!(node.link_count(), 1);
    assert_eq!(node.index_allocator.count(), 1);

    // --- Set up the completing inbound from B (link_id 2) ---
    // Simulate B's outbound arriving at A and completing the handshake.
    // We use make_completed_connection's pattern but with B's known identity.
    let completing_link_id = LinkId::new(2);
    let completing_time_ms = 2000;

    let mut completing_conn =
        PeerConnection::outbound(completing_link_id, peer_b_identity, completing_time_ms);

    let our_keypair = node.identity().keypair();
    let msg1 = completing_conn
        .start_handshake(our_keypair, node.startup_epoch(), completing_time_ms)
        .unwrap();

    // B responds
    let mut resp_conn = PeerConnection::inbound(LinkId::new(999), completing_time_ms);
    let peer_keypair = peer_b_full.keypair();
    let mut resp_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut resp_epoch);
    let msg2 = resp_conn
        .receive_handshake_init(peer_keypair, resp_epoch, &msg1, None, completing_time_ms)
        .unwrap();

    let (msg3, _neg) = completing_conn
        .complete_handshake(&msg2, None, completing_time_ms)
        .unwrap();
    resp_conn
        .complete_handshake_msg3(&msg3, completing_time_ms)
        .unwrap();

    let completing_index = node.index_allocator.allocate().unwrap();
    completing_conn.set_our_index(completing_index);
    completing_conn.set_their_index(SessionIndex::new(99));
    completing_conn.set_transport_id(transport_id);
    completing_conn.set_source_addr(TransportAddr::from_string("10.0.0.2:4001"));

    node.add_connection(completing_conn).unwrap();

    // Now 2 connections, 1 link (pending has link, completing doesn't yet need one for this test)
    assert_eq!(node.connection_count(), 2);
    assert_eq!(node.index_allocator.count(), 2);

    // --- Promote the completing connection ---
    let result = node
        .promote_connection(completing_link_id, peer_b_identity, completing_time_ms)
        .unwrap();

    assert!(matches!(result, PromotionResult::Promoted(_)));

    // The pending outbound should NOT be cleaned up during promotion —
    // it's deferred so handle_msg2 can learn the peer's inbound index.
    assert_eq!(
        node.connection_count(),
        1,
        "Pending outbound should be preserved (deferred cleanup)"
    );
    assert_eq!(node.peer_count(), 1, "Promoted peer should exist");
    assert!(
        node.pending_outbound
            .contains_key(&(transport_id, pending_index.as_u32())),
        "pending_outbound entry should still exist (awaiting msg2)"
    );
    assert_eq!(
        node.index_allocator.count(),
        2,
        "Both indices should remain until msg2 cleanup"
    );

    // Verify the promoted peer is correct
    let peer = node.get_peer(&peer_b_node_addr).unwrap();
    assert_eq!(peer.link_id(), completing_link_id);
}

/// Test that schedule_retry creates a retry entry for auto-connect peers.
#[test]
fn test_schedule_retry_creates_entry() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    assert!(node.peering.reconciler.retry_pending.is_empty());

    node.note_handshake_timeout(peer_node_addr, 1000);

    assert_eq!(node.peering.reconciler.retry_pending.len(), 1);
    let state = node
        .peering
        .reconciler
        .retry_pending
        .get(&peer_node_addr)
        .unwrap();
    assert_eq!(state.retry_count, 1);
    assert!(
        state.reconnect,
        "Auto-connect peers always get reconnect=true"
    );
    // Default base = 5s, 2^1 = 10s, but first retry is 2^0... let me check:
    // retry_count is set to 1, backoff_ms(5000) = 5000 * 2^1 = 10000
    assert_eq!(state.retry_after_ms, 1000 + 10_000);
}

/// Test that schedule_retry increments on subsequent calls.
#[test]
fn test_schedule_retry_increments() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    // First failure
    node.note_handshake_timeout(peer_node_addr, 1000);
    assert_eq!(
        node.peering
            .reconciler
            .retry_pending
            .get(&peer_node_addr)
            .unwrap()
            .retry_count,
        1
    );

    // Second failure
    node.note_handshake_timeout(peer_node_addr, 11_000);
    let state = node
        .peering
        .reconciler
        .retry_pending
        .get(&peer_node_addr)
        .unwrap();
    assert_eq!(state.retry_count, 2);
    // backoff_ms(5000) with retry_count=2 = 5000 * 4 = 20000
    assert_eq!(state.retry_after_ms, 11_000 + 20_000);
}

/// Retry processing is paced so a large due set cannot start every
/// handshake candidate in one maintenance tick.
#[tokio::test]
async fn test_process_pending_retries_is_budgeted_per_tick() {
    let mut node = make_node();
    let mut addrs = Vec::new();

    for _ in 0..20 {
        let identity = Identity::generate();
        let npub = identity.npub();
        let peer_identity = PeerIdentity::from_npub(&npub).unwrap();
        let node_addr = *peer_identity.node_addr();
        node.peering.reconciler.retry_pending.insert(
            node_addr,
            crate::node::peering::retry::RetryState {
                peer_config: crate::config::PeerConfig::new(npub, "udp", "10.0.0.2:2121"),
                retry_count: 0,
                retry_after_ms: 0,
                reconnect: true,
                expires_at_ms: None,
            },
        );
        addrs.push(node_addr);
    }

    // The retry-dial tick runs only under a `Reconciling` gate (it fires from the
    // rx loop, which spins only after start() reaches Running). Put the node in
    // Running so the retry-dial budget — the property under test — is exercised.
    node.supervisor.state = crate::node::NodeState::Running;
    node.process_pending_retries(1).await;

    let processed = addrs
        .iter()
        .filter(|addr| {
            node.peering
                .reconciler
                .retry_pending
                .get(addr)
                .is_some_and(|state| state.retry_count > 0)
        })
        .count();
    let deferred = addrs.len().saturating_sub(processed);

    assert_eq!(processed, 16);
    assert_eq!(deferred, 4);
    assert_eq!(node.peering.reconciler.retry_pending.len(), 20);
}

/// Test that auto-connect peers retry indefinitely (never exhaust).
#[test]
fn test_schedule_retry_auto_connect_never_exhausts() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.node.retry.max_retries = 2;
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    // All attempts should keep the entry alive despite max_retries=2
    node.note_handshake_timeout(peer_node_addr, 1000);
    assert!(
        node.peering
            .reconciler
            .retry_pending
            .contains_key(&peer_node_addr)
    );

    node.note_handshake_timeout(peer_node_addr, 2000);
    assert!(
        node.peering
            .reconciler
            .retry_pending
            .contains_key(&peer_node_addr)
    );

    // Attempt 3 would have exhausted before, but now retries indefinitely
    node.note_handshake_timeout(peer_node_addr, 3000);
    assert!(
        node.peering
            .reconciler
            .retry_pending
            .contains_key(&peer_node_addr),
        "Auto-connect peers should never exhaust retries"
    );
    assert_eq!(
        node.peering
            .reconciler
            .retry_pending
            .get(&peer_node_addr)
            .unwrap()
            .retry_count,
        3
    );
}

/// Test that schedule_retry does nothing when max_retries is 0.
#[test]
fn test_schedule_retry_disabled() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.node.retry.max_retries = 0;
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    node.note_handshake_timeout(peer_node_addr, 1000);
    assert!(
        node.peering.reconciler.retry_pending.is_empty(),
        "No retry should be scheduled when max_retries=0"
    );
}

/// Test that schedule_retry does nothing for non-auto-connect peers.
#[test]
fn test_schedule_retry_ignores_non_autoconnect() {
    let peer_identity = Identity::generate();
    let peer_node_addr = *peer_identity.node_addr();

    // No peers configured at all
    let mut node = make_node();

    node.note_handshake_timeout(peer_node_addr, 1000);
    assert!(
        node.peering.reconciler.retry_pending.is_empty(),
        "No retry for unconfigured peer"
    );
}

/// Test that schedule_retry does nothing if peer is already connected.
#[test]
fn test_schedule_retry_skips_connected_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // Promote a peer so it's in the peers map
    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();
    assert_eq!(node.peer_count(), 1);

    // Scheduling a retry for an already-connected peer should be a no-op
    node.note_handshake_timeout(node_addr, 3000);
    assert!(
        node.peering.reconciler.retry_pending.is_empty(),
        "No retry for already-connected peer"
    );
}

#[tokio::test]
async fn test_try_peer_addresses_skips_connected_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let (conn, peer_identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let peer_config = crate::config::PeerConfig::new(peer_identity.npub(), "udp", "127.0.0.1:9");

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, peer_identity, 2000)
        .unwrap();
    let link_count = node.link_count();
    let connection_count = node.connection_count();

    node.try_peer_addresses(&peer_config, peer_identity, true)
        .await
        .unwrap();

    assert_eq!(
        node.link_count(),
        link_count,
        "stale retry/traversal fallback must not create a duplicate link"
    );
    assert_eq!(
        node.connection_count(),
        connection_count,
        "stale retry/traversal fallback must not create a duplicate handshake"
    );
}

#[tokio::test]
async fn test_try_peer_addresses_skips_connecting_peer() {
    let mut node = make_node();
    let peer_identity = make_peer_identity();
    let peer_config = crate::config::PeerConfig::new(peer_identity.npub(), "udp", "127.0.0.1:9");
    let pending = PeerConnection::outbound(LinkId::new(1), peer_identity, 1000);
    node.add_connection(pending).unwrap();

    node.try_peer_addresses(&peer_config, peer_identity, true)
        .await
        .unwrap();

    assert_eq!(
        node.connection_count(),
        1,
        "stale retry/traversal fallback must not start a second handshake"
    );
    assert_eq!(
        node.link_count(),
        0,
        "stale retry/traversal fallback must not allocate a link while a handshake is pending"
    );
}

#[test]
fn active_peer_same_path_discovery_skips_fresh_peer() {
    let mut node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), Node::now_ms());
    active_peer.set_current_addr(transport_id, current_addr.clone());
    node.peers.insert(peer_node_addr, active_peer);
    let candidate = crate::config::PeerAddress::new("udp", "127.0.0.1:9");

    assert!(node.active_peer_candidate_is_fresh_enough_to_skip(
        &peer_node_addr,
        std::slice::from_ref(&candidate),
    ));
}

#[test]
fn active_peer_same_path_discovery_refreshes_stale_peer() {
    let mut node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let stale_at = Node::now_ms().saturating_sub(
        node.config()
            .node
            .heartbeat_interval_secs
            .saturating_add(1)
            .saturating_mul(1000),
    );
    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), stale_at);
    active_peer.set_current_addr(transport_id, current_addr.clone());
    node.peers.insert(peer_node_addr, active_peer);
    let candidate = crate::config::PeerAddress::new("udp", "127.0.0.1:9");

    assert!(!node.active_peer_candidate_is_fresh_enough_to_skip(
        &peer_node_addr,
        std::slice::from_ref(&candidate),
    ));
}

#[tokio::test]
async fn node_context_mirrors_config_and_immutable_facades() {
    let mut node = make_node();

    // The immutable facades read the shared NodeContext.
    let expected_addr = *node.identity().node_addr();
    assert_eq!(node.node_addr(), &expected_addr);
    assert!(!node.is_leaf_only());
    let _ = node.uptime();
    assert_eq!(node.config().peers().len(), 0);

    // update_peers must rebuild the context so config() — which now reads the
    // context — reflects the new peer list. Guards the copy-on-write sync.
    let peer = Identity::generate();
    let new_peer = crate::config::PeerConfig {
        npub: peer.npub(),
        alias: None,
        addresses: vec![],
        connect_policy: crate::config::ConnectPolicy::OnDemand,
        auto_reconnect: false,
        via_nostr: false,
    };
    node.update_peers(vec![new_peer]).await.unwrap();

    assert_eq!(
        node.config().peers().len(),
        1,
        "config() must reflect update_peers through the rebuilt context"
    );
    assert_eq!(node.config().peers()[0].npub, peer.npub());
}

#[tokio::test]
async fn update_peers_races_new_alternative_without_dropping_active_peer() {
    // The node's *current* (pre-update) peer set must contain `old_peer`, so it
    // is baked into the Config at construction (immutable context = sole store).
    let peer_full = Identity::generate();
    let old_peer = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::new("udp", "127.0.0.1:9")],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        via_nostr: false,
    };
    let mut config = Config::new();
    config.peers = vec![old_peer.clone()];
    let mut node = make_node_with(config);
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let new_addr = TransportAddr::from_string("127.0.0.1:10");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, Node::now_ms());
    active_peer.set_current_addr(transport_id, current_addr.clone());
    node.peers.insert(peer_node_addr, active_peer);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            transport_id,
            current_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );

    let new_peer = crate::config::PeerConfig {
        addresses: vec![
            crate::config::PeerAddress::new("udp", "127.0.0.1:9"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:10"),
        ],
        ..old_peer.clone()
    };

    let outcome = node.update_peers(vec![new_peer]).await.unwrap();

    assert_eq!(outcome.updated, 1);
    assert_eq!(node.peer_count(), 1, "existing link must stay live");
    assert_eq!(node.connection_count(), 1);
    assert_eq!(
        node.connections
            .values()
            .next()
            .and_then(|conn| conn.source_addr()),
        Some(&new_addr)
    );
    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.current_addr(), Some(&current_addr));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_nostr_traversal_failure_skips_connected_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let (conn, peer_identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, peer_identity, 2000)
        .unwrap();

    let bootstrap = Arc::new(NostrRendezvous::new_for_test());
    bootstrap.push_event_for_test(BootstrapEvent::Failed {
        peer_config: crate::config::PeerConfig::new(peer_identity.npub(), "udp", "127.0.0.1:9"),
        reason: "stale traversal failure".to_string(),
    });
    node.supervisor
        .nostr_rendezvous
        .set_engine(bootstrap.clone());

    node.poll_nostr_rendezvous().await;

    assert!(
        bootstrap.failure_state_snapshot().is_empty(),
        "stale failures for connected peers must not affect traversal cooldown"
    );
    assert!(
        node.peering.reconciler.retry_pending.is_empty(),
        "stale failures for connected peers must not enqueue reconnect attempts"
    );
}

#[tokio::test]
async fn test_nostr_traversal_established_skips_connected_peer() {
    use crate::nostr::EstablishedTraversal;
    use std::net::UdpSocket;

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let (conn, peer_identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, peer_identity, 2000)
        .unwrap();
    let link_count = node.link_count();
    let connection_count = node.connection_count();

    let bootstrap = Arc::new(NostrRendezvous::new_for_test());
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind local UDP socket");
    let remote_addr = "127.0.0.1:9999".parse().expect("parse remote addr");
    bootstrap.push_event_for_test(BootstrapEvent::Established {
        traversal: EstablishedTraversal::new(
            "test-session",
            peer_identity.npub(),
            remote_addr,
            socket,
        ),
    });
    node.supervisor
        .nostr_rendezvous
        .set_engine(bootstrap.clone());

    node.poll_nostr_rendezvous().await;

    assert_eq!(
        node.link_count(),
        link_count,
        "stale established handoff must not allocate a new link"
    );
    assert_eq!(
        node.connection_count(),
        connection_count,
        "stale established handoff must not start a new handshake"
    );
    assert!(
        node.peering.reconciler.retry_pending.is_empty(),
        "stale established handoff must not enqueue a reconnect"
    );
}

#[tokio::test]
async fn test_process_pending_retries_drops_expired_entries() {
    let mut node = make_node();
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut state = super::super::peering::retry::RetryState::new(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "127.0.0.1:9",
    ));
    state.retry_after_ms = 0;
    state.expires_at_ms = Some(1_000);
    state.reconnect = true;
    node.peering
        .reconciler
        .retry_pending
        .insert(peer_node_addr, state);

    // Retry-dial runs only under a `Reconciling` gate; put the node in Running so
    // the expired-entry drop (the property under test) is reached.
    node.supervisor.state = crate::node::NodeState::Running;
    node.process_pending_retries(1_000).await;

    assert!(
        !node
            .peering
            .reconciler
            .retry_pending
            .contains_key(&peer_node_addr),
        "expired retry entries should be dropped before retry processing"
    );
}

/// Test that schedule_reconnect preserves accumulated backoff across link-dead cycles.
///
/// Regression test for issue #5: previously `schedule_reconnect` always created a
/// fresh `RetryState` with `retry_count=0`, discarding any backoff accumulated by
/// prior failed handshake attempts. On repeated link-dead evictions the node would
/// restart exponential backoff from the base interval every time instead of
/// continuing to back off.
#[test]
fn test_schedule_reconnect_preserves_backoff() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    // Simulate two stale handshake timeouts incrementing the retry count.
    node.note_handshake_timeout(peer_node_addr, 1_000); // count=1, delay=10s
    node.note_handshake_timeout(peer_node_addr, 11_000); // count=2, delay=20s
    {
        let state = node
            .peering
            .reconciler
            .retry_pending
            .get(&peer_node_addr)
            .unwrap();
        assert_eq!(state.retry_count, 2, "Two failures should yield count=2");
    }

    // Now simulate a link-dead removal triggering schedule_reconnect.
    // The existing retry entry (count=2) should be preserved and bumped to 3,
    // NOT reset to 0 as it was before the fix.
    node.note_link_dead(peer_node_addr, 31_000);

    let state = node
        .peering
        .reconciler
        .retry_pending
        .get(&peer_node_addr)
        .unwrap();
    assert!(state.reconnect, "Entry should be marked as reconnect");
    assert_eq!(
        state.retry_count, 3,
        "schedule_reconnect should increment existing count (was 2), not reset to 0 (regression: issue #5)"
    );

    // With count=3, backoff should be 5s * 2^3 = 40s.
    let base_ms = node.config().node.retry.base_interval_secs * 1000;
    let max_ms = node.config().node.retry.max_backoff_secs * 1000;
    let expected_delay = crate::proto::fmp::backoff_ms(state.retry_count, base_ms, max_ms);
    assert_eq!(
        state.retry_after_ms,
        31_000 + expected_delay,
        "retry_after_ms should reflect count=3 backoff"
    );
}

/// Test that schedule_reconnect on a fresh peer (no prior retry entry) starts at count=0.
#[test]
fn test_schedule_reconnect_fresh_state() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    // No prior retry entry — first reconnect should use base delay.
    node.note_link_dead(peer_node_addr, 1_000);

    let state = node
        .peering
        .reconciler
        .retry_pending
        .get(&peer_node_addr)
        .unwrap();
    assert!(state.reconnect, "Entry should be marked as reconnect");
    assert_eq!(
        state.retry_count, 0,
        "Fresh reconnect should start at count=0"
    );
    // Base delay: 5s * 2^0 = 5s
    let base_ms = node.config().node.retry.base_interval_secs * 1000;
    let max_ms = node.config().node.retry.max_backoff_secs * 1000;
    let expected_delay = crate::proto::fmp::backoff_ms(state.retry_count, base_ms, max_ms);
    assert_eq!(state.retry_after_ms, 1_000 + expected_delay);
}

/// Test that a graceful Disconnect from an auto-connect peer schedules reconnect.
///
/// Regression test for issue #60: `handle_disconnect` previously called
/// `remove_active_peer` without `schedule_reconnect`, orphaning auto-connect
/// entries on a clean upstream shutdown. Other peer-removal paths (link-dead,
/// decrypt failure, peer restart) all schedule reconnect.
#[test]
fn test_disconnect_schedules_reconnect() {
    use crate::proto::fmp::{Disconnect, DisconnectReason};

    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    let payload = Disconnect::new(DisconnectReason::Shutdown).encode();
    node.handle_disconnect(&peer_node_addr, &payload);

    let state = node
        .peering
        .reconciler
        .retry_pending
        .get(&peer_node_addr)
        .expect("handle_disconnect should schedule reconnect for auto-connect peer");
    assert!(state.reconnect, "Entry should be marked as reconnect");
    assert_eq!(
        state.retry_count, 0,
        "Fresh reconnect after disconnect should start at count=0"
    );
}

/// Test that promote_connection clears retry_pending.
#[test]
fn test_promote_clears_retry_pending() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();

    // Simulate a retry entry existing for this peer
    node.peering.reconciler.retry_pending.insert(
        node_addr,
        super::super::peering::retry::RetryState::new(crate::config::PeerConfig::default()),
    );
    assert_eq!(node.peering.reconciler.retry_pending.len(), 1);

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();

    assert!(
        !node
            .peering
            .reconciler
            .retry_pending
            .contains_key(&node_addr),
        "retry_pending should be cleared on successful promotion"
    );
}

/// Initial peer-init failure at startup must enqueue a retry. Otherwise a peer
/// whose addresses cannot be dialed at boot (no operational transport for the
/// configured transport types, all addresses unreachable, NAT rebind, etc.)
/// stays dead forever — pings arrive but cannot be answered until the daemon
/// is manually restarted.
#[tokio::test]
async fn test_initiate_peer_connections_schedules_retry_on_no_transport() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    // udp address but no UDP transport registered on the node — every dial
    // attempt resolves to NodeError::NoTransportForType.
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();
    assert!(node.peering.reconciler.retry_pending.is_empty());

    node.initiate_peer_connections().await;

    assert!(
        node.peering
            .reconciler
            .retry_pending
            .contains_key(&peer_node_addr),
        "startup peer-init failure must enqueue a retry so the peer can recover \
         without a daemon restart"
    );
}

// ============================================================================
// transport_mtu() — ISSUE-2026-0011 regression coverage
// ============================================================================

/// Helper: spawn a UdpTransport with the given mtu, started and operational.
async fn make_udp_transport_with_mtu(id: u32, mtu: u16) -> TransportHandle {
    let (packet_tx, _packet_rx) = packet_channel(64);
    let transport_id = TransportId::new(id);
    let mut udp = UdpTransport::new(
        transport_id,
        Some(format!("udp{}", id)),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(mtu),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    TransportHandle::Udp(udp)
}

#[tokio::test]
async fn test_transport_mtu_returns_min_across_operational() {
    // Multiple operational transports with varied MTUs. The picker must
    // return the smallest, deterministically, regardless of HashMap
    // iteration order. This is the core ISSUE-2026-0011 regression test.
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp1 = make_udp_transport_with_mtu(1, 1497).await;
    let udp2 = make_udp_transport_with_mtu(2, 1280).await;
    let udp3 = make_udp_transport_with_mtu(3, 1400).await;

    node.transports.insert(TransportId::new(1), udp1);
    node.transports.insert(TransportId::new(2), udp2);
    node.transports.insert(TransportId::new(3), udp3);

    // Expect the smallest (UDP-1280), not whichever HashMap iterates first.
    assert_eq!(node.transport_mtu(), 1280);

    // effective_ipv6_mtu = 1280 - 77 = 1203, max_mss = 1203 - 60 = 1143
    // (verifies the downstream clamp value).
    assert_eq!(node.effective_ipv6_mtu(), 1203);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_transport_mtu_fallback_when_no_operational_transports() {
    // No transports configured at all → falls back to 1280 (IPv6 minimum).
    let node = make_node();
    assert_eq!(node.transport_mtu(), 1280);
}

#[tokio::test]
async fn test_transport_mtu_min_with_single_operational() {
    // Single transport: trivially returns its MTU. Pins the picker doesn't
    // accidentally drop down to a smaller fallback when one transport is
    // operational.
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp = make_udp_transport_with_mtu(1, 1452).await;
    node.transports.insert(TransportId::new(1), udp);

    assert_eq!(node.transport_mtu(), 1452);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

// path_mtu_lookup seeding for direct-link (configured) peers — closes the
// B3 coverage gap where configured/auto-connect peers never go through the
// discovery Lookup flow and so their FipsAddress was missing from
// path_mtu_lookup, causing the SYN-time TCP MSS clamp to fall back to the
// global ceiling.

#[tokio::test]
async fn test_seed_path_mtu_inserts_when_empty() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp = make_udp_transport_with_mtu(1, 1452).await;
    node.transports.insert(TransportId::new(1), udp);

    let peer_addr = make_node_addr(0xAA);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let transport_addr = TransportAddr::from_string("10.0.0.2:2121");

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &transport_addr);

    let stored = node
        .path_mtu_lookup
        .read()
        .unwrap()
        .get(&fips_addr)
        .copied();
    assert_eq!(
        stored,
        Some(1452),
        "Empty lookup should be seeded with the link MTU"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_seed_path_mtu_keeps_tighter_existing_value() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp = make_udp_transport_with_mtu(1, 1452).await;
    node.transports.insert(TransportId::new(1), udp);

    let peer_addr = make_node_addr(0xBB);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let transport_addr = TransportAddr::from_string("10.0.0.3:2121");

    // Pre-populate with a tighter value, e.g. learned from discovery's
    // reverse-path bottleneck.
    node.path_mtu_lookup
        .write()
        .unwrap()
        .insert(fips_addr, 1280);

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &transport_addr);

    let stored = node
        .path_mtu_lookup
        .read()
        .unwrap()
        .get(&fips_addr)
        .copied();
    assert_eq!(
        stored,
        Some(1280),
        "Existing tighter value (1280) must not be loosened by direct-link seed (1452)"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_seed_path_mtu_tightens_looser_existing_value() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp = make_udp_transport_with_mtu(1, 1280).await;
    node.transports.insert(TransportId::new(1), udp);

    let peer_addr = make_node_addr(0xCC);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let transport_addr = TransportAddr::from_string("10.0.0.4:2121");

    // Pre-populate with a looser stale value.
    node.path_mtu_lookup
        .write()
        .unwrap()
        .insert(fips_addr, 1452);

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &transport_addr);

    let stored = node
        .path_mtu_lookup
        .read()
        .unwrap()
        .get(&fips_addr)
        .copied();
    assert_eq!(
        stored,
        Some(1280),
        "Direct-link seed (1280) must overwrite looser existing value (1452)"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_seed_path_mtu_noop_for_unknown_transport() {
    let node = make_node();
    let peer_addr = make_node_addr(0xDD);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let transport_addr = TransportAddr::from_string("10.0.0.5:2121");

    // No transport registered — call must be a no-op, not panic.
    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(99), &transport_addr);

    let map = node.path_mtu_lookup.read().unwrap();
    assert!(
        map.get(&fips_addr).is_none(),
        "Seed must be a no-op when transport_id is not registered"
    );
}

// === Outbound admission gate tests ===

/// Inject `count` synthetic active peers into `node.peers` so peer_count()
/// reflects a desired saturation level for admission-gate tests.
fn inject_dummy_peers(node: &mut Node, count: usize) {
    use crate::peer::ActivePeer;
    for i in 0..count {
        let identity = make_peer_identity();
        let addr = *identity.node_addr();
        let peer = ActivePeer::new(identity, LinkId::new((i + 1) as u64), 0);
        node.peers.insert(addr, peer);
    }
}

#[test]
fn outbound_admission_check_direct() {
    // max_peers cap honored: above-cap returns false, below-cap returns true.
    let mut node = make_node_with_max_peers(3);

    assert!(node.outbound_admission_check(), "0/3 should be admissible");
    inject_dummy_peers(&mut node, 2);
    assert!(node.outbound_admission_check(), "2/3 should be admissible");
    inject_dummy_peers(&mut node, 1);
    assert!(
        !node.outbound_admission_check(),
        "3/3 (at cap) should suppress"
    );
    inject_dummy_peers(&mut node, 1);
    assert!(
        !node.outbound_admission_check(),
        "4/3 (above cap) should suppress"
    );

    // No-cap sentinel: max_peers == 0 admits unconditionally.
    let mut uncapped = make_node_with_max_peers(0);
    assert!(uncapped.outbound_admission_check());
    inject_dummy_peers(&mut uncapped, 50);
    assert!(
        uncapped.outbound_admission_check(),
        "max_peers=0 (no cap) must always admit"
    );
}

#[tokio::test]
async fn process_pending_retries_gated_at_capacity() {
    let mut node = make_node_with_max_peers(2);
    inject_dummy_peers(&mut node, 2);

    // Queue a retry that would otherwise be due.
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();
    let mut state = super::super::peering::retry::RetryState::new(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "127.0.0.1:9",
    ));
    state.retry_after_ms = 0;
    state.reconnect = true;
    node.peering
        .reconciler
        .retry_pending
        .insert(peer_node_addr, state);

    let before_peers = node.peer_count();
    let before_connections = node.connection_count();

    // Running gate so the admission short-circuit (not the startup gate) is what
    // suppresses the dial — the fingerprint this test asserts on.
    node.supervisor.state = crate::node::NodeState::Running;
    node.process_pending_retries(1_000).await;

    // At capacity: gate short-circuits before due-list collection. The
    // retry entry must still be present (untouched) and no connection
    // attempt may have been started. Without the gate, the due-list
    // collector would pick the entry up, fire `initiate_peer_connection`
    // (which fails without a registered transport), and the failure
    // handler would call `schedule_retry`, bumping `retry_count` to 1.
    let state = node
        .peering
        .reconciler
        .retry_pending
        .get(&peer_node_addr)
        .expect("retry entry must be preserved when suppressed at capacity");
    assert_eq!(
        state.retry_count, 0,
        "gate must short-circuit before initiate_peer_connection; \
         a bumped retry_count is the fingerprint of the ungated path"
    );
    assert_eq!(
        state.retry_after_ms, 0,
        "gate must short-circuit before initiate_peer_connection; \
         retry_after_ms still zero means no attempt fired"
    );
    assert_eq!(
        node.peer_count(),
        before_peers,
        "no peer adoption while suppressed"
    );
    assert_eq!(
        node.connection_count(),
        before_connections,
        "no connection initiated while suppressed"
    );
}

#[tokio::test]
async fn poll_nostr_rendezvous_established_gated_at_capacity() {
    use crate::nostr::EstablishedTraversal;
    use std::net::UdpSocket;

    let mut node = make_node_with_max_peers(2);
    inject_dummy_peers(&mut node, 2);

    let bootstrap = Arc::new(NostrRendezvous::new_for_test());
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind local UDP socket");
    let remote_addr = "127.0.0.1:9999".parse().expect("parse remote addr");
    let peer_identity = Identity::generate();
    bootstrap.push_event_for_test(BootstrapEvent::Established {
        traversal: EstablishedTraversal::new(
            "cap-test-session",
            peer_identity.npub(),
            remote_addr,
            socket,
        ),
    });
    node.supervisor
        .nostr_rendezvous
        .set_engine(bootstrap.clone());

    let before_peers = node.peer_count();
    let before_links = node.link_count();
    let before_connections = node.connection_count();

    node.poll_nostr_rendezvous().await;

    assert_eq!(
        node.peer_count(),
        before_peers,
        "Established event must not add a peer while at capacity"
    );
    assert_eq!(
        node.link_count(),
        before_links,
        "Established event must not allocate a link while at capacity"
    );
    assert_eq!(
        node.connection_count(),
        before_connections,
        "Established event must not start a handshake while at capacity"
    );
}

#[test]
fn nostr_rendezvous_outbound_admission_atomic_roundtrip() {
    // Verifies the runtime-side plumbing for the two NAT-traversal gate
    // points: the setter mutates the atomic and the (super-visible)
    // reader observes the value the Node-side wiring would publish.
    let bootstrap = NostrRendezvous::new_for_test();
    assert!(
        bootstrap.outbound_admission_allowed(),
        "default must allow (start unsaturated)"
    );
    bootstrap.set_outbound_admission(false);
    assert!(
        !bootstrap.outbound_admission_allowed(),
        "after suppression store: traversal initiator/responder must see false"
    );
    bootstrap.set_outbound_admission(true);
    assert!(
        bootstrap.outbound_admission_allowed(),
        "after recovery store: traversal initiator/responder must see true"
    );
}

/// Two-node UDP scaffold for driving a full Noise XX handshake
/// (Msg1 -> Msg2 -> Msg3) from `node_a` (initiator) into `node_b`
/// (responder, the unit under test). Mirrors `test_two_node_handshake_udp`
/// in `handshake.rs`, condensed for the cap-check tests.
///
/// `node_a` and `node_b` must already have a UDP transport under
/// `TransportId::new(1)`; the test passes in the bound local addrs and the
/// two receive channels. After this returns, `node_b` has processed the
/// initiator's Msg3 and the cap-enforcement decision has been made. Returns
/// the initiator's `NodeAddr`.
///
/// Critically for the silent-drop test: `node_a` is the only initiator —
/// `node_b` never dials `node_a`, so there is no pending-outbound connection
/// to bypass the cap. The inbound peer is therefore truly unsolicited.
async fn drive_xx_handshake(
    node_a: &mut Node,
    node_b: &mut Node,
    transport_id: TransportId,
    addr_b: std::net::SocketAddr,
    packet_rx_a: &mut crate::transport::PacketRx,
    packet_rx_b: &mut crate::transport::PacketRx,
) -> NodeAddr {
    use crate::proto::fmp::wire::build_msg1;
    use tokio::time::{Duration, timeout};

    let remote_addr_b = TransportAddr::from_string(&addr_b.to_string());

    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity().pubkey_full());

    // node_a initiates the outbound handshake.
    let link_id_a = node_a.allocate_link_id();
    let mut conn_a = PeerConnection::outbound(link_id_a, peer_b_identity, 1000);
    let our_index_a = node_a.index_allocator.allocate().unwrap();
    let our_keypair_a = node_a.identity().keypair();
    let noise_msg1 = conn_a
        .start_handshake(our_keypair_a, node_a.startup_epoch(), 1000)
        .unwrap();
    conn_a.set_our_index(our_index_a);
    conn_a.set_transport_id(transport_id);
    conn_a.set_source_addr(remote_addr_b.clone());
    let wire_msg1 = build_msg1(our_index_a, &noise_msg1);

    let link_a = Link::connectionless(
        link_id_a,
        transport_id,
        remote_addr_b.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node_a.links.insert(link_id_a, link_a);
    node_a.connections.insert(link_id_a, conn_a);
    node_a
        .pending_outbound
        .insert((transport_id, our_index_a.as_u32()), link_id_a);

    let transport = node_a.transports.get(&transport_id).unwrap();
    transport
        .send(&remote_addr_b, &wire_msg1)
        .await
        .expect("Failed to send msg1");

    // node_b receives Msg1, replies Msg2 (XX: no promotion yet).
    let packet_b = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await
        .expect("Timeout waiting for msg1")
        .expect("Channel closed");
    node_b.handle_msg1(packet_b).await;

    // node_a receives Msg2, sends Msg3, promotes locally.
    let packet_a = timeout(Duration::from_secs(1), packet_rx_a.recv())
        .await
        .expect("Timeout waiting for msg2")
        .expect("Channel closed");
    node_a.handle_msg2(packet_a).await;

    // node_b receives Msg3 — the cap-enforcement decision happens here.
    let packet_b_msg3 = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await
        .expect("Timeout waiting for msg3")
        .expect("Channel closed");
    node_b.handle_msg3(packet_b_msg3).await;

    *PeerIdentity::from_pubkey_full(node_a.identity().pubkey_full()).node_addr()
}

/// Register a UDP transport on `node` under `TransportId::new(1)`, returning
/// the bound local address and the packet receive channel.
async fn register_udp_transport(
    node: &mut Node,
) -> (std::net::SocketAddr, crate::transport::PacketRx) {
    use crate::config::UdpConfig;

    let transport_id = TransportId::new(1);
    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };
    let (packet_tx, packet_rx) = packet_channel(64);
    let mut transport = UdpTransport::new(transport_id, None, udp_config, packet_tx);
    transport.start_async().await.unwrap();
    let addr = transport.local_addr().unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(transport));
    (addr, packet_rx)
}

// The inbound max_peers cap on the XX FMP handshake is enforced solely by
// the late `promote_connection` check (the early `handle_msg3` gate was
// removed: on XX, identity isn't known until Msg3, by which point all three
// messages have crossed the wire, so an early gate saved no bytes and
// duplicated the late check's peer set). These two tests assert the
// path-agnostic invariant — no promotion over cap, peer count unchanged, no
// index-allocator/connection leak — driven through the full XX three-message
// pump. They do NOT assert the IK "no Msg2 on the wire" discriminator
// (false on XX: Msg2 is the responder ephemeral, sent before identity is
// known), nor the IK rate-limiter rebalance (the msg3 cap-reject path does
// not touch `msg1_rate_limiter`).
#[tokio::test]
async fn handle_msg3_silent_drops_at_cap_for_new_peer() {
    let transport_id = TransportId::new(1);

    // node_b is the cap'd unit under test: max_peers=1, already at cap.
    let mut node_b = make_node_with_max_peers(1);
    inject_dummy_peers(&mut node_b, 1);
    assert_eq!(node_b.peer_count(), 1, "precondition: node_b at cap");

    // node_a is a truly-unsolicited inbound initiator. node_b never dials
    // node_a, so `is_pending_outbound` is false and the cap (not the
    // cross-connection path) governs.
    let mut node_a = make_node();

    let (addr_b, mut packet_rx_b) = register_udp_transport(&mut node_b).await;
    let (_addr_a, mut packet_rx_a) = register_udp_transport(&mut node_a).await;

    // Snapshot node_b resource state before the over-cap handshake.
    let before_peers = node_b.peer_count();
    let before_connections = node_b.connection_count();
    let before_links = node_b.link_count();
    let before_index_count = node_b.index_allocator.count();

    let peer_a_node_addr = drive_xx_handshake(
        &mut node_a,
        &mut node_b,
        transport_id,
        addr_b,
        &mut packet_rx_a,
        &mut packet_rx_b,
    )
    .await;

    // Path-agnostic invariant: no promotion over cap.
    assert_eq!(
        node_b.peer_count(),
        before_peers,
        "cap'd node must not promote a net-new peer over max_peers"
    );
    assert!(
        !node_b.peers.contains_key(&peer_a_node_addr),
        "denied peer must not appear in node_b's peers map"
    );

    // Resource non-leak: the rejected handshake's connection, link, and
    // allocated index must all be released, returning node_b to its
    // pre-handshake bookkeeping baseline.
    assert_eq!(
        node_b.connection_count(),
        before_connections,
        "rejected handshake's pending connection must be cleaned up"
    );
    assert_eq!(
        node_b.link_count(),
        before_links,
        "rejected handshake's link must be removed"
    );
    assert_eq!(
        node_b.index_allocator.count(),
        before_index_count,
        "rejected handshake's allocated session index must be freed"
    );
}

/// Regression guard: a full XX handshake from a KNOWN-identity peer at cap
/// must be admitted (reconnect/cross-connection bypass), not evicted. The
/// existing peer's key must remain present and the peer count must hold.
#[tokio::test]
async fn handle_msg3_admits_existing_peer_at_cap() {
    let transport_id = TransportId::new(1);

    // node_a is the initiator whose identity we pre-insert as node_b's
    // existing peer, so node_b is at cap WITH the incoming peer already known.
    let mut node_a = make_node();
    let mut node_b = make_node_with_max_peers(1);

    let existing_pid = PeerIdentity::from_pubkey_full(node_a.identity().pubkey_full());
    let existing_node_addr = *existing_pid.node_addr();
    {
        use crate::peer::ActivePeer;
        let peer = ActivePeer::new(existing_pid, LinkId::new(7777), 0);
        node_b.peers.insert(existing_node_addr, peer);
    }
    assert_eq!(
        node_b.peer_count(),
        1,
        "precondition: node_b at cap with node_a already known"
    );

    let (addr_b, mut packet_rx_b) = register_udp_transport(&mut node_b).await;
    let (_addr_a, mut packet_rx_a) = register_udp_transport(&mut node_a).await;

    let peer_a_node_addr = drive_xx_handshake(
        &mut node_a,
        &mut node_b,
        transport_id,
        addr_b,
        &mut packet_rx_a,
        &mut packet_rx_b,
    )
    .await;
    assert_eq!(
        peer_a_node_addr, existing_node_addr,
        "sanity: initiator carries the existing peer's NodeAddr"
    );

    // The known peer is admitted (session replaced cleanly), not evicted,
    // and the cap is not breached.
    assert_eq!(
        node_b.peer_count(),
        1,
        "peer count must hold at cap (known peer admitted, not double-counted)"
    );
    assert!(
        node_b.peers.contains_key(&existing_node_addr),
        "existing peer must still be present after a known-peer reconnect"
    );
}

/// App-owned TUN seam: `enable_app_owned_tun` wires the embedder's packet
/// channels (an Android `VpnService` owns the fd) and marks the TUN active so
/// `start()` skips system-TUN creation.
#[test]
fn app_owned_tun_seam_wires_channels() {
    let mut config = crate::Config::new();
    config.tun.enabled = true;
    let mut node = make_node_with(config);

    let (outbound_tx, tun_rx) = node.enable_app_owned_tun();

    // TUN is active and the inbound (mesh→app) sender is installed, so `start()`
    // will skip `TunDevice::create` (it gates on `tun_tx.is_none()`).
    assert_eq!(node.tun_state(), crate::upper::tun::TunState::Active);
    assert!(node.tun_tx().is_some(), "inbound sender installed");

    // mesh → app: a packet the node delivers to its `tun_tx` reaches the app's rx.
    let pkt = vec![0x60u8, 0, 0, 0, 0, 0];
    node.tun_tx().unwrap().send(pkt.clone()).unwrap();
    assert_eq!(
        tun_rx
            .recv_timeout(std::time::Duration::from_millis(200))
            .unwrap(),
        pkt,
        "the app pulls the same bytes the node wrote",
    );

    // app → mesh: the returned sender is live (its matching rx is held by the node
    // and drained by `run_rx_loop` → `handle_tun_outbound`).
    assert!(outbound_tx.try_send(vec![0x60]).is_ok());
}

/// With an app-owned TUN configured, `start()` must NOT create a system TUN
/// device: it leaves `tun_name` unset (a real device records its interface name)
/// and keeps the TUN `Active` with the app-owned channels.
#[tokio::test]
async fn start_skips_system_tun_when_app_owned() {
    // Mirror `make_healthy_node` (one loopback UDP transport so bring-up
    // reaches `Full`), plus tun.enabled so the Tun child WOULD spawn if the
    // app-owned gate failed.
    let mut config = crate::Config::new();
    config.transports.udp = crate::config::TransportInstances::Single(crate::config::UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    });
    config.dns.enabled = false;
    config.tun.enabled = true;
    let mut node = make_node_with(config);

    let (_outbound_tx, _tun_rx) = node.enable_app_owned_tun();
    node.start().await.unwrap();

    // No system device was created (that path records the interface name); the
    // app-owned TUN stayed active.
    assert!(
        node.tun_name().is_none(),
        "app-owned TUN must not create a named system device",
    );
    assert_eq!(node.tun_state(), crate::upper::tun::TunState::Active);

    node.stop().await.unwrap();
}
