use super::*;
use crate::index::SessionIndex;
use crate::transport::{LinkDirection, TransportAddr};
use std::time::Duration;

fn make_node() -> Node {
    let config = Config::new();
    Node::new(config).unwrap()
}

#[allow(dead_code)]
fn make_node_addr(val: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = val;
    NodeAddr::from_bytes(bytes)
}

fn make_peer_identity() -> PeerIdentity {
    let identity = Identity::generate();
    PeerIdentity::from_pubkey(identity.pubkey())
}

/// Create a PeerConnection with a completed Noise IK handshake.
///
/// Returns (connection, peer_identity) where the connection is outbound,
/// in Complete state, with session, indices, and transport info set.
fn make_completed_connection(
    node: &mut Node,
    link_id: LinkId,
    transport_id: TransportId,
    current_time_ms: u64,
) -> (PeerConnection, PeerIdentity) {
    let peer_identity_full = Identity::generate();
    // Must use from_pubkey_full to preserve parity for ECDH
    let peer_identity = PeerIdentity::from_pubkey_full(peer_identity_full.pubkey_full());

    // Create outbound connection
    let mut conn = PeerConnection::outbound(link_id, peer_identity.clone(), current_time_ms);

    // Run initiator side of handshake
    let our_keypair = node.identity.keypair();
    let msg1 = conn.start_handshake(our_keypair, current_time_ms).unwrap();

    // Run responder side to generate msg2
    let mut resp_conn = PeerConnection::inbound(LinkId::new(999), current_time_ms);
    let peer_keypair = peer_identity_full.keypair();
    let msg2 = resp_conn
        .receive_handshake_init(peer_keypair, &msg1, current_time_ms)
        .unwrap();

    // Complete initiator handshake
    conn.complete_handshake(&msg2, current_time_ms).unwrap();

    // Set indices and transport info
    let our_index = node.index_allocator.allocate().unwrap();
    conn.set_our_index(our_index);
    conn.set_their_index(SessionIndex::new(42));
    conn.set_transport_id(transport_id);
    conn.set_source_addr(TransportAddr::from_string("127.0.0.1:5000"));

    (conn, peer_identity)
}

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

    let node = Node::with_identity(identity, config);

    assert_eq!(node.node_addr(), &expected_node_addr);
}

#[test]
fn test_node_leaf_only() {
    let config = Config::new();
    let node = Node::leaf_only(config).unwrap();

    assert!(node.is_leaf_only());
    assert!(node.bloom_state().is_leaf_only());
}

#[tokio::test]
async fn test_node_state_transitions() {
    let mut node = make_node();

    assert!(!node.is_running());
    assert!(node.state().can_start());

    node.start().await.unwrap();
    assert!(node.is_running());
    assert!(!node.state().can_start());

    node.stop().await.unwrap();
    assert!(!node.is_running());
    assert_eq!(node.state(), NodeState::Stopped);
}

#[tokio::test]
async fn test_node_double_start() {
    let mut node = make_node();
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
    assert!(node.find_link_by_addr(TransportId::new(1), &TransportAddr::from_string("test")).is_none());
}

#[test]
fn test_node_link_limit() {
    let mut node = make_node();
    node.set_max_links(2);

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
    let conn1 = PeerConnection::outbound(link_id, identity.clone(), 1000);
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
    assert!(peer.our_index().is_some(), "Promoted peer should have our_index");
    assert!(peer.their_index().is_some(), "Promoted peer should have their_index");

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
    let (conn1, identity) =
        make_completed_connection(&mut node, link_id1, transport_id, 1000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn1).unwrap();
    node.promote_connection(link_id1, identity.clone(), 1500).unwrap();

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
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    node.set_max_peers(2);

    // Add two peers via promotion
    for i in 0..2 {
        let link_id = LinkId::new(i as u64 + 1);
        let (conn, identity) =
            make_completed_connection(&mut node, link_id, transport_id, 1000);
        node.add_connection(conn).unwrap();
        node.promote_connection(link_id, identity, 2000).unwrap();
    }

    assert_eq!(node.peer_count(), 2);

    // Third should fail
    let link_id = LinkId::new(3);
    let (conn, identity) =
        make_completed_connection(&mut node, link_id, transport_id, 3000);
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
    let (conn1, identity1) =
        make_completed_connection(&mut node, link_id1, transport_id, 1000);
    let node_addr1 = *identity1.node_addr();
    node.add_connection(conn1).unwrap();
    node.promote_connection(link_id1, identity1, 2000).unwrap();

    // Add another peer and mark it stale (still sendable)
    let link_id2 = LinkId::new(2);
    let (conn2, identity2) =
        make_completed_connection(&mut node, link_id2, transport_id, 1000);
    node.add_connection(conn2).unwrap();
    node.promote_connection(link_id2, identity2, 2000).unwrap();

    // Add a third peer and mark it disconnected (not sendable)
    let link_id3 = LinkId::new(3);
    let (conn3, identity3) =
        make_completed_connection(&mut node, link_id3, transport_id, 1000);
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
    node.pending_outbound.insert((transport_id, index.as_u32()), link_id);

    // Verify we can look it up
    let found = node.pending_outbound.get(&(transport_id, index.as_u32()));
    assert_eq!(found, Some(&link_id));

    // Clean up
    node.pending_outbound.remove(&(transport_id, index.as_u32()));
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
    node.peers_by_index.insert((transport_id, index.as_u32()), node_addr);

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
    let mut node = make_node();
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

// === Integration Tests: End-to-End Handshake ===

#[tokio::test]
async fn test_two_node_handshake_udp() {
    use crate::config::UdpConfig;
    use crate::transport::udp::UdpTransport;
    use crate::wire::{build_encrypted, build_msg1};
    use tokio::time::{timeout, Duration};

    // === Setup: Two nodes with UDP transports on localhost ===

    let mut node_a = make_node();
    let mut node_b = make_node();

    let transport_id_a = TransportId::new(1);
    let transport_id_b = TransportId::new(1);

    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
    };

    let (packet_tx_a, mut packet_rx_a) = packet_channel(64);
    let (packet_tx_b, mut packet_rx_b) = packet_channel(64);

    let mut transport_a =
        UdpTransport::new(transport_id_a, None, udp_config.clone(), packet_tx_a);
    let mut transport_b =
        UdpTransport::new(transport_id_b, None, udp_config, packet_tx_b);

    transport_a.start_async().await.unwrap();
    transport_b.start_async().await.unwrap();

    let addr_a = transport_a.local_addr().unwrap();
    let addr_b = transport_b.local_addr().unwrap();
    let remote_addr_b = TransportAddr::from_string(&addr_b.to_string());
    let remote_addr_a = TransportAddr::from_string(&addr_a.to_string());

    node_a
        .transports
        .insert(transport_id_a, TransportHandle::Udp(transport_a));
    node_b
        .transports
        .insert(transport_id_b, TransportHandle::Udp(transport_b));

    // === Phase 1: Node A initiates handshake to Node B ===

    // Create peer identity for B (must use full key for ECDH parity)
    let peer_b_identity =
        PeerIdentity::from_pubkey_full(node_b.identity.pubkey_full());
    let peer_b_node_addr = *peer_b_identity.node_addr();

    let link_id_a = node_a.allocate_link_id();
    let mut conn_a = PeerConnection::outbound(
        link_id_a,
        peer_b_identity.clone(),
        1000,
    );

    // Allocate session index for A's outbound
    let our_index_a = node_a.index_allocator.allocate().unwrap();

    // Start handshake (generates Noise IK msg1)
    let our_keypair_a = node_a.identity.keypair();
    let noise_msg1 = conn_a.start_handshake(our_keypair_a, 1000).unwrap();
    conn_a.set_our_index(our_index_a);
    conn_a.set_transport_id(transport_id_a);
    conn_a.set_source_addr(remote_addr_b.clone());

    // Build wire msg1 and track in node state
    let wire_msg1 = build_msg1(our_index_a, &noise_msg1);

    let link_a = Link::connectionless(
        link_id_a,
        transport_id_a,
        remote_addr_b.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node_a.links.insert(link_id_a, link_a);
    node_a.connections.insert(link_id_a, conn_a);
    node_a.pending_outbound.insert(
        (transport_id_a, our_index_a.as_u32()),
        link_id_a,
    );

    // Send msg1 from A to B over UDP
    let transport = node_a.transports.get(&transport_id_a).unwrap();
    transport
        .send(&remote_addr_b, &wire_msg1)
        .await
        .expect("Failed to send msg1");

    // === Phase 2: Node B receives msg1, sends msg2, promotes ===

    let packet_b = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await
        .expect("Timeout waiting for msg1")
        .expect("Channel closed");

    node_b.handle_msg1(packet_b).await;

    // Verify B promoted the inbound connection
    let peer_a_node_addr = *PeerIdentity::from_pubkey_full(
        node_a.identity.pubkey_full(),
    )
    .node_addr();
    assert_eq!(node_b.peer_count(), 1, "Node B should have 1 peer after msg1");
    let peer_a_on_b = node_b
        .get_peer(&peer_a_node_addr)
        .expect("Node B should have peer A");
    assert!(
        peer_a_on_b.has_session(),
        "Peer A on B should have NoiseSession"
    );
    let our_index_b = peer_a_on_b.our_index().expect("B should have our_index");
    assert!(
        node_b
            .peers_by_index
            .contains_key(&(transport_id_b, our_index_b.as_u32())),
        "Node B peers_by_index should be populated"
    );

    // === Phase 3: Node A receives msg2, completes handshake, promotes ===

    let packet_a = timeout(Duration::from_secs(1), packet_rx_a.recv())
        .await
        .expect("Timeout waiting for msg2")
        .expect("Channel closed");

    node_a.handle_msg2(packet_a).await;

    // Verify A promoted the outbound connection
    assert_eq!(node_a.peer_count(), 1, "Node A should have 1 peer after msg2");
    let peer_b_on_a = node_a
        .get_peer(&peer_b_node_addr)
        .expect("Node A should have peer B");
    assert!(
        peer_b_on_a.has_session(),
        "Peer B on A should have NoiseSession"
    );
    assert_eq!(
        peer_b_on_a.our_index(),
        Some(our_index_a),
        "Peer B on A should have our_index matching what we allocated"
    );
    assert!(
        node_a
            .peers_by_index
            .contains_key(&(transport_id_a, our_index_a.as_u32())),
        "Node A peers_by_index should be populated"
    );

    // === Phase 4: Encrypted frame A → B ===

    // A encrypts a test message and sends to B
    let plaintext_a = b"hello from A";
    let peer_b = node_a.get_peer_mut(&peer_b_node_addr).unwrap();
    let their_index_b = peer_b.their_index().expect("A should know B's index");
    let session_a = peer_b.noise_session_mut().unwrap();
    let ciphertext_a = session_a.encrypt(plaintext_a).unwrap();

    let wire_encrypted = build_encrypted(their_index_b, 0, &ciphertext_a);
    let transport = node_a.transports.get(&transport_id_a).unwrap();
    transport
        .send(&remote_addr_b, &wire_encrypted)
        .await
        .expect("Failed to send encrypted frame");

    // B receives and decrypts
    let encrypted_packet_b = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await
        .expect("Timeout waiting for encrypted frame")
        .expect("Channel closed");

    node_b.handle_encrypted_frame(encrypted_packet_b).await;

    // Verify B's peer was touched (last_seen updated)
    let peer_a = node_b.get_peer(&peer_a_node_addr).unwrap();
    assert!(
        peer_a.is_healthy(),
        "Peer A on B should still be healthy after receiving encrypted frame"
    );

    // === Phase 5: Encrypted frame B → A ===

    let plaintext_b = b"hello from B";
    let peer_a = node_b.get_peer_mut(&peer_a_node_addr).unwrap();
    let their_index_a = peer_a.their_index().expect("B should know A's index");
    let session_b = peer_a.noise_session_mut().unwrap();
    let ciphertext_b = session_b.encrypt(plaintext_b).unwrap();

    let wire_encrypted_b = build_encrypted(their_index_a, 0, &ciphertext_b);
    let transport = node_b.transports.get(&transport_id_b).unwrap();
    transport
        .send(&remote_addr_a, &wire_encrypted_b)
        .await
        .expect("Failed to send encrypted frame B→A");

    // A receives and decrypts
    let encrypted_packet_a = timeout(Duration::from_secs(1), packet_rx_a.recv())
        .await
        .expect("Timeout waiting for encrypted frame B→A")
        .expect("Channel closed");

    node_a.handle_encrypted_frame(encrypted_packet_a).await;

    // Verify A's peer was touched
    let peer_b = node_a.get_peer(&peer_b_node_addr).unwrap();
    assert!(
        peer_b.is_healthy(),
        "Peer B on A should still be healthy after receiving encrypted frame"
    );

    // Clean up transports
    for (_, t) in node_a.transports.iter_mut() {
        t.stop().await.ok();
    }
    for (_, t) in node_b.transports.iter_mut() {
        t.stop().await.ok();
    }
}

/// Integration test: two nodes complete a handshake via run_rx_loop.
///
/// Unlike test_two_node_handshake_udp which calls handle_msg1/handle_msg2
/// directly, this test exercises the full rx loop dispatch path:
/// UDP socket → packet channel → run_rx_loop → process_packet →
/// discriminator dispatch → handler.
#[tokio::test]
async fn test_run_rx_loop_handshake() {
    use crate::config::UdpConfig;
    use crate::transport::udp::UdpTransport;
    use crate::wire::build_msg1;
    use tokio::time::Duration;

    // === Setup: Two nodes with UDP transports on localhost ===

    let mut node_a = make_node();
    let mut node_b = make_node();

    let transport_id_a = TransportId::new(1);
    let transport_id_b = TransportId::new(1);

    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
    };

    let (packet_tx_a, packet_rx_a) = packet_channel(64);
    let (packet_tx_b, packet_rx_b) = packet_channel(64);

    let mut transport_a =
        UdpTransport::new(transport_id_a, None, udp_config.clone(), packet_tx_a);
    let mut transport_b =
        UdpTransport::new(transport_id_b, None, udp_config, packet_tx_b);

    transport_a.start_async().await.unwrap();
    transport_b.start_async().await.unwrap();

    let addr_b = transport_b.local_addr().unwrap();
    let remote_addr_b = TransportAddr::from_string(&addr_b.to_string());

    node_a
        .transports
        .insert(transport_id_a, TransportHandle::Udp(transport_a));
    node_b
        .transports
        .insert(transport_id_b, TransportHandle::Udp(transport_b));

    // Store packet_rx on nodes for run_rx_loop
    node_a.packet_rx = Some(packet_rx_a);
    node_b.packet_rx = Some(packet_rx_b);

    // Set node state to Running (transports need to be operational)
    node_a.state = NodeState::Running;
    node_b.state = NodeState::Running;

    // === Phase 1: Node A initiates handshake to Node B ===

    let peer_b_identity =
        PeerIdentity::from_pubkey_full(node_b.identity.pubkey_full());
    let peer_b_node_addr = *peer_b_identity.node_addr();

    let link_id_a = node_a.allocate_link_id();
    let mut conn_a = PeerConnection::outbound(
        link_id_a,
        peer_b_identity.clone(),
        1000,
    );

    let our_index_a = node_a.index_allocator.allocate().unwrap();
    let our_keypair_a = node_a.identity.keypair();
    let noise_msg1 = conn_a.start_handshake(our_keypair_a, 1000).unwrap();
    conn_a.set_our_index(our_index_a);
    conn_a.set_transport_id(transport_id_a);
    conn_a.set_source_addr(remote_addr_b.clone());

    let wire_msg1 = build_msg1(our_index_a, &noise_msg1);

    let link_a = Link::connectionless(
        link_id_a,
        transport_id_a,
        remote_addr_b.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node_a.links.insert(link_id_a, link_a);
    node_a.connections.insert(link_id_a, conn_a);
    node_a.pending_outbound.insert(
        (transport_id_a, our_index_a.as_u32()),
        link_id_a,
    );

    // Send msg1 from A to B over real UDP
    let transport = node_a.transports.get(&transport_id_a).unwrap();
    transport
        .send(&remote_addr_b, &wire_msg1)
        .await
        .expect("Failed to send msg1");

    // Small delay to ensure msg1 is received by B's transport
    tokio::time::sleep(Duration::from_millis(50)).await;

    // === Phase 2: Run Node B's rx loop (processes msg1, sends msg2) ===
    //
    // This is the key difference from test_two_node_handshake_udp:
    // instead of calling handle_msg1() directly, we run the full rx loop
    // which dispatches based on the discriminator byte.

    tokio::select! {
        result = node_b.run_rx_loop() => {
            panic!("Node B rx loop exited unexpectedly: {:?}", result);
        }
        _ = tokio::time::sleep(Duration::from_millis(500)) => {
            // Timeout: rx loop processed available packets
        }
    }

    // Verify Node B promoted the inbound connection via rx loop dispatch
    let peer_a_node_addr = *PeerIdentity::from_pubkey_full(
        node_a.identity.pubkey_full(),
    )
    .node_addr();

    assert_eq!(node_b.peer_count(), 1, "Node B should have 1 peer after rx loop processed msg1");
    let peer_a_on_b = node_b
        .get_peer(&peer_a_node_addr)
        .expect("Node B should have peer A");
    assert!(
        peer_a_on_b.has_session(),
        "Peer A on B should have NoiseSession"
    );
    let our_index_b = peer_a_on_b.our_index().expect("B should have our_index");
    assert!(
        peer_a_on_b.their_index().is_some(),
        "B should have their_index"
    );
    assert!(
        node_b
            .peers_by_index
            .contains_key(&(transport_id_b, our_index_b.as_u32())),
        "Node B peers_by_index should be populated"
    );

    // === Phase 3: Run Node A's rx loop (processes msg2) ===
    //
    // msg2 was sent by Node B during its rx loop processing of msg1.
    // It arrived at A's UDP transport, which forwarded it to A's packet channel.

    tokio::select! {
        result = node_a.run_rx_loop() => {
            panic!("Node A rx loop exited unexpectedly: {:?}", result);
        }
        _ = tokio::time::sleep(Duration::from_millis(500)) => {
            // Timeout: rx loop processed msg2
        }
    }

    // Verify Node A promoted the outbound connection via rx loop dispatch
    assert_eq!(node_a.peer_count(), 1, "Node A should have 1 peer after rx loop processed msg2");
    let peer_b_on_a = node_a
        .get_peer(&peer_b_node_addr)
        .expect("Node A should have peer B");
    assert!(
        peer_b_on_a.has_session(),
        "Peer B on A should have NoiseSession"
    );
    assert_eq!(
        peer_b_on_a.our_index(),
        Some(our_index_a),
        "Peer B on A should have our_index matching what we allocated"
    );
    assert!(
        peer_b_on_a.their_index().is_some(),
        "A should know B's index"
    );
    assert!(
        node_a
            .peers_by_index
            .contains_key(&(transport_id_a, our_index_a.as_u32())),
        "Node A peers_by_index should be populated"
    );

    // Clean up transports
    for (_, t) in node_a.transports.iter_mut() {
        t.stop().await.ok();
    }
    for (_, t) in node_b.transports.iter_mut() {
        t.stop().await.ok();
    }
}

/// Integration test: simultaneous cross-connection (both nodes initiate).
///
/// Simulates the live scenario where both nodes have auto_connect to each other.
/// Both send msg1 simultaneously, creating a cross-connection that must be
/// resolved by the tie-breaker rule. Exercises the addr_to_link fix that allows
/// inbound msg1 when an outbound link to the same address already exists.
#[tokio::test]
async fn test_cross_connection_both_initiate() {
    use crate::config::UdpConfig;
    use crate::transport::udp::UdpTransport;
    use crate::wire::build_msg1;
    use tokio::time::{timeout, Duration};

    // === Setup: Two nodes with UDP transports on localhost ===

    let mut node_a = make_node();
    let mut node_b = make_node();

    let transport_id_a = TransportId::new(1);
    let transport_id_b = TransportId::new(1);

    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
    };

    let (packet_tx_a, mut packet_rx_a) = packet_channel(64);
    let (packet_tx_b, mut packet_rx_b) = packet_channel(64);

    let mut transport_a =
        UdpTransport::new(transport_id_a, None, udp_config.clone(), packet_tx_a);
    let mut transport_b =
        UdpTransport::new(transport_id_b, None, udp_config, packet_tx_b);

    transport_a.start_async().await.unwrap();
    transport_b.start_async().await.unwrap();

    let addr_a = transport_a.local_addr().unwrap();
    let addr_b = transport_b.local_addr().unwrap();
    let remote_addr_b = TransportAddr::from_string(&addr_b.to_string());
    let remote_addr_a = TransportAddr::from_string(&addr_a.to_string());

    node_a
        .transports
        .insert(transport_id_a, TransportHandle::Udp(transport_a));
    node_b
        .transports
        .insert(transport_id_b, TransportHandle::Udp(transport_b));

    // Peer identities (must use full key for ECDH parity)
    let peer_b_identity =
        PeerIdentity::from_pubkey_full(node_b.identity.pubkey_full());
    let peer_b_node_addr = *peer_b_identity.node_addr();
    let peer_a_identity =
        PeerIdentity::from_pubkey_full(node_a.identity.pubkey_full());
    let peer_a_node_addr = *peer_a_identity.node_addr();

    // === Phase 1: Both nodes initiate handshakes (simulate auto_connect) ===

    // Node A initiates to Node B
    let link_id_a_out = node_a.allocate_link_id();
    let mut conn_a = PeerConnection::outbound(link_id_a_out, peer_b_identity.clone(), 1000);
    let our_index_a = node_a.index_allocator.allocate().unwrap();
    let our_keypair_a = node_a.identity.keypair();
    let noise_msg1_a = conn_a.start_handshake(our_keypair_a, 1000).unwrap();
    conn_a.set_our_index(our_index_a);
    conn_a.set_transport_id(transport_id_a);
    conn_a.set_source_addr(remote_addr_b.clone());

    let wire_msg1_a = build_msg1(our_index_a, &noise_msg1_a);

    let link_a_out = Link::connectionless(
        link_id_a_out, transport_id_a, remote_addr_b.clone(),
        LinkDirection::Outbound, Duration::from_millis(100),
    );
    node_a.links.insert(link_id_a_out, link_a_out);
    node_a.addr_to_link.insert((transport_id_a, remote_addr_b.clone()), link_id_a_out);
    node_a.connections.insert(link_id_a_out, conn_a);
    node_a.pending_outbound.insert((transport_id_a, our_index_a.as_u32()), link_id_a_out);

    // Node B initiates to Node A
    let link_id_b_out = node_b.allocate_link_id();
    let mut conn_b = PeerConnection::outbound(link_id_b_out, peer_a_identity.clone(), 1000);
    let our_index_b = node_b.index_allocator.allocate().unwrap();
    let our_keypair_b = node_b.identity.keypair();
    let noise_msg1_b = conn_b.start_handshake(our_keypair_b, 1000).unwrap();
    conn_b.set_our_index(our_index_b);
    conn_b.set_transport_id(transport_id_b);
    conn_b.set_source_addr(remote_addr_a.clone());

    let wire_msg1_b = build_msg1(our_index_b, &noise_msg1_b);

    let link_b_out = Link::connectionless(
        link_id_b_out, transport_id_b, remote_addr_a.clone(),
        LinkDirection::Outbound, Duration::from_millis(100),
    );
    node_b.links.insert(link_id_b_out, link_b_out);
    node_b.addr_to_link.insert((transport_id_b, remote_addr_a.clone()), link_id_b_out);
    node_b.connections.insert(link_id_b_out, conn_b);
    node_b.pending_outbound.insert((transport_id_b, our_index_b.as_u32()), link_id_b_out);

    // Both send msg1 over UDP
    let transport = node_a.transports.get(&transport_id_a).unwrap();
    transport.send(&remote_addr_b, &wire_msg1_a).await.expect("A send msg1");

    let transport = node_b.transports.get(&transport_id_b).unwrap();
    transport.send(&remote_addr_a, &wire_msg1_b).await.expect("B send msg1");

    // === Phase 2: Both nodes receive the other's msg1 ===
    // Before the fix, addr_to_link would reject these because outbound links
    // already exist for these addresses.

    // B receives A's msg1
    let packet_at_b = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await.expect("Timeout").expect("Channel closed");
    node_b.handle_msg1(packet_at_b).await;

    // B should have promoted the inbound connection
    assert_eq!(node_b.peer_count(), 1, "Node B should have 1 peer after processing A's msg1");
    assert!(node_b.get_peer(&peer_a_node_addr).is_some(), "Node B should have peer A");

    // A receives B's msg1
    let packet_at_a = timeout(Duration::from_secs(1), packet_rx_a.recv())
        .await.expect("Timeout").expect("Channel closed");
    node_a.handle_msg1(packet_at_a).await;

    // A should have promoted the inbound connection
    assert_eq!(node_a.peer_count(), 1, "Node A should have 1 peer after processing B's msg1");
    assert!(node_a.get_peer(&peer_b_node_addr).is_some(), "Node A should have peer B");

    // === Phase 3: Both nodes receive msg2 responses ===
    // The msg2 was sent during handle_msg1 processing. When handle_msg2
    // processes it, it will detect the cross-connection and resolve.

    // A receives B's msg2 (response to A's original msg1)
    let msg2_at_a = timeout(Duration::from_secs(1), packet_rx_a.recv())
        .await.expect("Timeout waiting for msg2 at A").expect("Channel closed");
    node_a.handle_msg2(msg2_at_a).await;

    // B receives A's msg2 (response to B's original msg1)
    let msg2_at_b = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await.expect("Timeout waiting for msg2 at B").expect("Channel closed");
    node_b.handle_msg2(msg2_at_b).await;

    // === Verification ===
    // Both nodes should have exactly 1 peer each after cross-connection resolution
    assert_eq!(node_a.peer_count(), 1, "Node A should have exactly 1 peer after cross-connection");
    assert_eq!(node_b.peer_count(), 1, "Node B should have exactly 1 peer after cross-connection");

    let peer_b_on_a = node_a.get_peer(&peer_b_node_addr).expect("A should have peer B");
    let peer_a_on_b = node_b.get_peer(&peer_a_node_addr).expect("B should have peer A");

    assert!(peer_b_on_a.has_session(), "Peer B on A should have session");
    assert!(peer_a_on_b.has_session(), "Peer A on B should have session");
    assert!(peer_b_on_a.can_send(), "Peer B on A should be sendable");
    assert!(peer_a_on_b.can_send(), "Peer A on B should be sendable");

    // Clean up transports
    for (_, t) in node_a.transports.iter_mut() {
        t.stop().await.ok();
    }
    for (_, t) in node_b.transports.iter_mut() {
        t.stop().await.ok();
    }
}

/// Test that stale handshake connections are cleaned up by check_timeouts().
///
/// Simulates the scenario where a node initiates a handshake to a peer that
/// isn't running. The outbound connection should be cleaned up after the
/// handshake timeout expires.
#[tokio::test]
async fn test_stale_connection_cleanup() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let peer_identity = make_peer_identity();
    let remote_addr = TransportAddr::from_string("10.0.0.2:4000");

    // Create outbound connection with a timestamp far in the past
    let past_time_ms = 1000; // A very early timestamp
    let link_id = node.allocate_link_id();
    let mut conn = PeerConnection::outbound(link_id, peer_identity.clone(), past_time_ms);

    // Allocate session index and set transport info
    let our_index = node.index_allocator.allocate().unwrap();
    let our_keypair = node.identity.keypair();
    let _noise_msg1 = conn.start_handshake(our_keypair, past_time_ms).unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(transport_id);
    conn.set_source_addr(remote_addr.clone());

    // Set up all the state that initiate_peer_connection would create
    let link = Link::connectionless(
        link_id, transport_id, remote_addr.clone(),
        LinkDirection::Outbound, Duration::from_millis(100),
    );
    node.links.insert(link_id, link);
    node.addr_to_link.insert((transport_id, remote_addr.clone()), link_id);
    node.connections.insert(link_id, conn);
    node.pending_outbound.insert((transport_id, our_index.as_u32()), link_id);

    // Verify state before timeout check
    assert_eq!(node.connection_count(), 1);
    assert_eq!(node.link_count(), 1);
    assert!(node.pending_outbound.contains_key(&(transport_id, our_index.as_u32())));
    assert_eq!(node.index_allocator.count(), 1);

    // Connection was created at time 1000ms. check_timeouts uses SystemTime::now(),
    // which is far beyond the 30s timeout. The connection should be cleaned up.
    node.check_timeouts();

    // Verify everything was cleaned up
    assert_eq!(node.connection_count(), 0, "Stale connection should be removed");
    assert_eq!(node.link_count(), 0, "Stale link should be removed");
    assert!(!node.pending_outbound.contains_key(&(transport_id, our_index.as_u32())),
        "pending_outbound should be cleaned up");
    assert_eq!(node.index_allocator.count(), 0, "Session index should be freed");
    assert!(node.addr_to_link.get(&(transport_id, remote_addr)).is_none(),
        "addr_to_link should be cleaned up");
}

/// Test that failed connections are cleaned up by check_timeouts().
#[tokio::test]
async fn test_failed_connection_cleanup() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let peer_identity = make_peer_identity();
    let remote_addr = TransportAddr::from_string("10.0.0.2:4000");

    // Create a connection and mark it failed (simulating a send failure)
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let link_id = node.allocate_link_id();
    let mut conn = PeerConnection::outbound(link_id, peer_identity.clone(), now_ms);

    let our_index = node.index_allocator.allocate().unwrap();
    let our_keypair = node.identity.keypair();
    let _noise_msg1 = conn.start_handshake(our_keypair, now_ms).unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(transport_id);
    conn.set_source_addr(remote_addr.clone());
    conn.mark_failed(); // Simulate send failure

    let link = Link::connectionless(
        link_id, transport_id, remote_addr.clone(),
        LinkDirection::Outbound, Duration::from_millis(100),
    );
    node.links.insert(link_id, link);
    node.addr_to_link.insert((transport_id, remote_addr.clone()), link_id);
    node.connections.insert(link_id, conn);
    node.pending_outbound.insert((transport_id, our_index.as_u32()), link_id);

    assert_eq!(node.connection_count(), 1);

    // Failed connections should be cleaned up immediately regardless of age
    node.check_timeouts();

    assert_eq!(node.connection_count(), 0, "Failed connection should be removed");
    assert_eq!(node.link_count(), 0, "Failed link should be removed");
    assert_eq!(node.index_allocator.count(), 0, "Session index should be freed");
}

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
        PeerConnection::outbound(pending_link_id, peer_b_identity.clone(), pending_time_ms);

    let our_keypair = node.identity.keypair();
    let _msg1 = pending_conn.start_handshake(our_keypair, pending_time_ms).unwrap();

    let pending_index = node.index_allocator.allocate().unwrap();
    pending_conn.set_our_index(pending_index);
    pending_conn.set_transport_id(transport_id);
    let pending_addr = TransportAddr::from_string("10.0.0.2:4000");
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

    let mut completing_conn = PeerConnection::outbound(
        completing_link_id,
        peer_b_identity.clone(),
        completing_time_ms,
    );

    let our_keypair = node.identity.keypair();
    let msg1 = completing_conn
        .start_handshake(our_keypair, completing_time_ms)
        .unwrap();

    // B responds
    let mut resp_conn = PeerConnection::inbound(LinkId::new(999), completing_time_ms);
    let peer_keypair = peer_b_full.keypair();
    let msg2 = resp_conn
        .receive_handshake_init(peer_keypair, &msg1, completing_time_ms)
        .unwrap();

    completing_conn
        .complete_handshake(&msg2, completing_time_ms)
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
        .promote_connection(completing_link_id, peer_b_identity.clone(), completing_time_ms)
        .unwrap();

    assert!(matches!(result, PromotionResult::Promoted(_)));

    // The pending outbound should have been cleaned up
    assert_eq!(
        node.connection_count(),
        0,
        "Pending outbound should be cleaned up during promotion"
    );
    assert_eq!(node.peer_count(), 1, "Promoted peer should exist");
    assert!(
        !node
            .pending_outbound
            .contains_key(&(transport_id, pending_index.as_u32())),
        "pending_outbound entry for stale connection should be freed"
    );
    assert_eq!(
        node.index_allocator.count(),
        1,
        "Only the promoted peer's index should remain"
    );
    assert!(
        node.addr_to_link
            .get(&(transport_id, pending_addr))
            .is_none(),
        "addr_to_link for stale connection should be cleaned up"
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
        "10.0.0.2:4000",
    ));

    let mut node = Node::new(config).unwrap();

    assert!(node.retry_pending.is_empty());

    node.schedule_retry(peer_node_addr, 1000);

    assert_eq!(node.retry_pending.len(), 1);
    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert_eq!(state.retry_count, 1);
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
        "10.0.0.2:4000",
    ));

    let mut node = Node::new(config).unwrap();

    // First failure
    node.schedule_retry(peer_node_addr, 1000);
    assert_eq!(node.retry_pending.get(&peer_node_addr).unwrap().retry_count, 1);

    // Second failure
    node.schedule_retry(peer_node_addr, 11_000);
    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert_eq!(state.retry_count, 2);
    // backoff_ms(5000) with retry_count=2 = 5000 * 4 = 20000
    assert_eq!(state.retry_after_ms, 11_000 + 20_000);
}

/// Test that schedule_retry gives up after max_retries.
#[test]
fn test_schedule_retry_max_retries_exhausted() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.node.max_retries = 2;
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:4000",
    ));

    let mut node = Node::new(config).unwrap();

    // Attempts 1 and 2 should schedule retries
    node.schedule_retry(peer_node_addr, 1000);
    assert!(node.retry_pending.contains_key(&peer_node_addr));

    node.schedule_retry(peer_node_addr, 2000);
    assert!(node.retry_pending.contains_key(&peer_node_addr));

    // Attempt 3 exceeds max_retries=2, should remove entry
    node.schedule_retry(peer_node_addr, 3000);
    assert!(
        !node.retry_pending.contains_key(&peer_node_addr),
        "Should be removed after max retries exhausted"
    );
}

/// Test that schedule_retry does nothing when max_retries is 0.
#[test]
fn test_schedule_retry_disabled() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.node.max_retries = 0;
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:4000",
    ));

    let mut node = Node::new(config).unwrap();

    node.schedule_retry(peer_node_addr, 1000);
    assert!(
        node.retry_pending.is_empty(),
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

    node.schedule_retry(peer_node_addr, 1000);
    assert!(
        node.retry_pending.is_empty(),
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
    node.schedule_retry(node_addr, 3000);
    assert!(
        node.retry_pending.is_empty(),
        "No retry for already-connected peer"
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
    node.retry_pending.insert(
        node_addr,
        super::retry::RetryState::new(crate::config::PeerConfig::default()),
    );
    assert_eq!(node.retry_pending.len(), 1);

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();

    assert!(
        !node.retry_pending.contains_key(&node_addr),
        "retry_pending should be cleared on successful promotion"
    );
}

// ===== Spanning Tree Convergence Integration Tests =====

/// A test node bundling a Node with its transport and packet channel.
struct TestNode {
    node: Node,
    transport_id: TransportId,
    packet_rx: PacketRx,
    addr: TransportAddr,
}

/// Create a test node with a live UDP transport on localhost.
async fn make_test_node() -> TestNode {
    use crate::config::UdpConfig;
    use crate::transport::udp::UdpTransport;

    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
    };

    let (packet_tx, packet_rx) = packet_channel(256);
    let mut transport = UdpTransport::new(transport_id, None, udp_config, packet_tx);
    transport.start_async().await.unwrap();

    let addr = TransportAddr::from_string(&transport.local_addr().unwrap().to_string());
    node.transports
        .insert(transport_id, TransportHandle::Udp(transport));

    TestNode {
        node,
        transport_id,
        packet_rx,
        addr,
    }
}

/// Initiate a Noise handshake from nodes[i] to nodes[j].
///
/// Sends msg1 over UDP. The drain loop will handle msg1 processing,
/// msg2 response, and subsequent TreeAnnounce exchange.
async fn initiate_handshake(nodes: &mut [TestNode], i: usize, j: usize) {
    use crate::wire::build_msg1;

    // Extract responder info before mutably borrowing initiator
    let responder_addr = nodes[j].addr.clone();
    let responder_pubkey_full = nodes[j].node.identity().pubkey_full();
    let peer_identity = PeerIdentity::from_pubkey_full(responder_pubkey_full);

    let initiator = &mut nodes[i];
    let transport_id = initiator.transport_id;

    let link_id = initiator.node.allocate_link_id();
    let mut conn = PeerConnection::outbound(link_id, peer_identity, 1000);

    let our_index = initiator.node.index_allocator.allocate().unwrap();
    let our_keypair = initiator.node.identity().keypair();
    let noise_msg1 = conn.start_handshake(our_keypair, 1000).unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(transport_id);
    conn.set_source_addr(responder_addr.clone());

    let wire_msg1 = build_msg1(our_index, &noise_msg1);

    let link = Link::connectionless(
        link_id,
        transport_id,
        responder_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    initiator.node.links.insert(link_id, link);
    initiator
        .node
        .addr_to_link
        .insert((transport_id, responder_addr.clone()), link_id);
    initiator.node.connections.insert(link_id, conn);
    initiator
        .node
        .pending_outbound
        .insert((transport_id, our_index.as_u32()), link_id);

    let transport = initiator.node.transports.get(&transport_id).unwrap();
    transport
        .send(&responder_addr, &wire_msg1)
        .await
        .expect("Failed to send msg1");
}

/// Print a snapshot of each node's tree state.
///
/// For small networks (≤20 nodes) prints per-node detail.
/// For larger networks prints a compact summary with depth histogram.
fn print_tree_snapshot(label: &str, nodes: &[TestNode]) {
    eprintln!("\n  --- {} ---", label);

    // Find expected root for reference
    let expected_root = nodes.iter().map(|tn| *tn.node.node_addr()).min().unwrap();
    let expected_root_idx = nodes
        .iter()
        .position(|tn| *tn.node.node_addr() == expected_root)
        .unwrap();

    // Count how many nodes agree on the correct root
    let correct_root_count = nodes
        .iter()
        .filter(|tn| *tn.node.tree_state().root() == expected_root)
        .count();
    let total_pending: usize = nodes
        .iter()
        .map(|tn| {
            tn.node
                .peers
                .values()
                .filter(|p| p.has_pending_tree_announce())
                .count()
        })
        .sum();

    // Build depth histogram
    let mut depth_counts = std::collections::BTreeMap::new();
    for tn in nodes {
        *depth_counts
            .entry(tn.node.tree_state().my_coords().depth())
            .or_insert(0usize) += 1;
    }
    let depth_str: Vec<String> = depth_counts
        .iter()
        .map(|(d, c)| format!("d{}={}", d, c))
        .collect();

    // Count distinct roots
    let mut roots = std::collections::BTreeSet::new();
    for tn in nodes {
        roots.insert(*tn.node.tree_state().root());
    }

    eprintln!(
        "  converged={}/{} roots={} depths=[{}] pending={}",
        correct_root_count,
        nodes.len(),
        roots.len(),
        depth_str.join(" "),
        total_pending,
    );

    // Per-node detail for small networks
    if nodes.len() <= 20 {
        for (i, tn) in nodes.iter().enumerate() {
            let ts = tn.node.tree_state();
            let parent_idx = if ts.is_root() {
                "self".to_string()
            } else {
                nodes
                    .iter()
                    .position(|n| n.node.node_addr() == ts.my_declaration().parent_id())
                    .map(|p| format!("{}", p))
                    .unwrap_or_else(|| format!("?{}", ts.my_declaration().parent_id()))
            };
            let root_idx = nodes
                .iter()
                .position(|n| n.node.node_addr() == ts.root())
                .map(|r| format!("{}", r))
                .unwrap_or_else(|| format!("?{}", ts.root()));
            let pending = tn
                .node
                .peers
                .values()
                .filter(|p| p.has_pending_tree_announce())
                .count();
            eprintln!(
                "  node[{}] root=node[{}] depth={} parent=node[{}] peers={} pending={}",
                i, root_idx, ts.my_coords().depth(), parent_idx, tn.node.peer_count(), pending,
            );
        }
    } else if correct_root_count < nodes.len() {
        // For large networks that haven't converged, show which nodes are wrong
        let wrong: Vec<usize> = nodes
            .iter()
            .enumerate()
            .filter(|(_, tn)| *tn.node.tree_state().root() != expected_root)
            .map(|(i, _)| i)
            .collect();
        if wrong.len() <= 20 {
            eprintln!("  unconverged nodes: {:?}", wrong);
        } else {
            eprintln!("  unconverged nodes: {} remaining", wrong.len());
        }
    }

    let _ = expected_root_idx; // suppress unused
}

/// Process all currently available packets across all nodes.
///
/// Returns the number of packets processed.
async fn process_available_packets(nodes: &mut [TestNode]) -> usize {
    use crate::wire::{DISCRIMINATOR_ENCRYPTED, DISCRIMINATOR_MSG1, DISCRIMINATOR_MSG2};

    let mut count = 0;
    for i in 0..nodes.len() {
        while let Ok(packet) = nodes[i].packet_rx.try_recv() {
            if packet.data.is_empty() {
                continue;
            }
            match packet.data[0] {
                DISCRIMINATOR_MSG1 => nodes[i].node.handle_msg1(packet).await,
                DISCRIMINATOR_MSG2 => nodes[i].node.handle_msg2(packet).await,
                DISCRIMINATOR_ENCRYPTED => {
                    nodes[i].node.handle_encrypted_frame(packet).await
                }
                _ => {}
            }
            count += 1;
        }
    }
    count
}

/// Drain all packet channels across all nodes until quiescence.
///
/// Processes msg1, msg2, and encrypted frames (including TreeAnnounce)
/// through the appropriate handlers. Handles rate-limited TreeAnnounce
/// messages by waiting for the rate limit window to expire and then
/// flushing pending announces. Returns total packets processed.
///
/// If `verbose` is true, prints tree state snapshots after each phase.
async fn drain_all_packets(nodes: &mut [TestNode], verbose: bool) -> usize {
    let mut total = 0;

    // Phase 1: Fast drain — process packets as fast as they arrive.
    // This handles handshakes (msg1/msg2) and the first wave of TreeAnnounce.
    for _round in 0..200 {
        tokio::time::sleep(Duration::from_millis(10)).await;

        let count = process_available_packets(nodes).await;
        total += count;
        if count == 0 {
            break;
        }
    }

    if verbose {
        print_tree_snapshot(
            &format!("After handshakes + initial announces ({} packets)", total),
            nodes,
        );
    }

    // Phase 2: Rate-limit flush cycles. Each cycle waits for rate limits
    // to expire, flushes pending announces, processes resulting packets,
    // and repeats. Each cycle propagates the tree one hop further through
    // rate-limited paths. For a chain of depth D, we need D cycles.
    for flush in 0..20 {
        // Wait for rate limit window (500ms) to fully expire
        tokio::time::sleep(Duration::from_millis(550)).await;

        // Flush pending rate-limited tree announces on all nodes
        for tn in nodes.iter_mut() {
            tn.node.send_pending_tree_announces().await;
        }

        // Allow flushed packets to arrive
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Process the resulting packets. Processing may trigger new
        // parent switches → new announces, but those to the same peer
        // will be rate-limited again and caught by the next flush cycle.
        let mut flush_total = process_available_packets(nodes).await;

        // Do a few more quick rounds in case packet processing above
        // triggered non-rate-limited sends (to different peers)
        for _sub in 0..20 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let count = process_available_packets(nodes).await;
            flush_total += count;
            if count == 0 {
                break;
            }
        }

        total += flush_total;
        if flush_total == 0 {
            break;
        }

        if verbose {
            print_tree_snapshot(
                &format!("After flush cycle {} ({} packets)", flush + 1, flush_total),
                nodes,
            );
        }
    }

    total
}

/// Generate a connected random graph with deterministic topology.
///
/// First builds a random spanning tree to ensure connectivity,
/// then adds extra edges up to the target count.
fn generate_random_edges(n: usize, target_edges: usize, seed: u64) -> Vec<(usize, usize)> {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    let mut rng = StdRng::seed_from_u64(seed);
    let mut edges = Vec::new();
    let mut adj = vec![vec![false; n]; n];

    // Build a random spanning tree (ensures connectivity)
    let mut connected = vec![false; n];
    connected[0] = true;
    let mut connected_count = 1;

    while connected_count < n {
        let from = rng.gen_range(0..n);
        if !connected[from] {
            continue;
        }
        let to = rng.gen_range(0..n);
        if connected[to] || from == to {
            continue;
        }

        edges.push((from, to));
        adj[from][to] = true;
        adj[to][from] = true;
        connected[to] = true;
        connected_count += 1;
    }

    // Add random extra edges up to target
    let mut attempts = 0;
    while edges.len() < target_edges && attempts < target_edges * 10 {
        let a = rng.gen_range(0..n);
        let b = rng.gen_range(0..n);
        attempts += 1;
        if a == b || adj[a][b] {
            continue;
        }
        edges.push((a, b));
        adj[a][b] = true;
        adj[b][a] = true;
    }

    edges
}

/// Verify that all nodes in a connected component have converged to a
/// consistent spanning tree.
fn verify_tree_convergence(nodes: &[TestNode]) {
    let n = nodes.len();
    assert!(n > 0);

    // Find the expected root (smallest NodeAddr across all nodes)
    let expected_root = nodes
        .iter()
        .map(|tn| *tn.node.node_addr())
        .min()
        .unwrap();

    // All nodes should agree on the root
    for (i, tn) in nodes.iter().enumerate() {
        let ts = tn.node.tree_state();
        assert_eq!(
            *ts.root(),
            expected_root,
            "Node {} (addr={}) has root {} but expected {}",
            i,
            tn.node.node_addr(),
            ts.root(),
            expected_root
        );
    }

    // Root node should have is_root() == true and depth 0
    let root_node = nodes
        .iter()
        .find(|tn| *tn.node.node_addr() == expected_root)
        .unwrap();
    assert!(
        root_node.node.tree_state().is_root(),
        "Expected root node should have is_root = true"
    );
    assert_eq!(
        root_node.node.tree_state().my_coords().depth(),
        0,
        "Root node should have depth 0"
    );

    // Non-root nodes should have depth > 0
    for (i, tn) in nodes.iter().enumerate() {
        let ts = tn.node.tree_state();
        if *tn.node.node_addr() != expected_root {
            assert!(
                ts.my_coords().depth() > 0,
                "Non-root node {} should have depth > 0, got {}",
                i,
                ts.my_coords().depth()
            );
        }
    }

    // Each non-root node's parent should be one of its peers
    for (i, tn) in nodes.iter().enumerate() {
        let ts = tn.node.tree_state();
        if ts.is_root() {
            continue;
        }

        let parent_id = ts.my_declaration().parent_id();
        assert!(
            tn.node.get_peer(parent_id).is_some(),
            "Node {}'s parent {} should be in its peer list",
            i,
            parent_id
        );
    }

    // Each node's coordinate root should match expected root
    for (i, tn) in nodes.iter().enumerate() {
        let coords = tn.node.tree_state().my_coords();
        assert_eq!(
            *coords.root_id(),
            expected_root,
            "Node {}'s coordinate root {} should match expected root {}",
            i,
            coords.root_id(),
            expected_root
        );
    }

    // Depth consistency: child's depth = parent's depth + 1
    for (i, tn) in nodes.iter().enumerate() {
        let ts = tn.node.tree_state();
        if ts.is_root() {
            continue;
        }

        let my_depth = ts.my_coords().depth();
        let parent_id = ts.my_declaration().parent_id();

        // Find the parent node in our array
        if let Some(parent_node) = nodes.iter().find(|pn| pn.node.node_addr() == parent_id) {
            let parent_depth = parent_node.node.tree_state().my_coords().depth();
            assert_eq!(
                my_depth,
                parent_depth + 1,
                "Node {}'s depth ({}) should be parent's depth ({}) + 1",
                i,
                my_depth,
                parent_depth
            );
        }
    }
}

/// Verify tree convergence for disconnected components.
///
/// Each connected component should converge to its own root (smallest
/// NodeAddr in that component).
fn verify_tree_convergence_components(nodes: &[TestNode], components: &[Vec<usize>]) {
    for component in components {
        let component_nodes: Vec<&TestNode> = component.iter().map(|&i| &nodes[i]).collect();

        let expected_root = component_nodes
            .iter()
            .map(|tn| *tn.node.node_addr())
            .min()
            .unwrap();

        for &idx in component {
            let ts = nodes[idx].node.tree_state();
            assert_eq!(
                *ts.root(),
                expected_root,
                "Node {} in component should have root {}",
                idx,
                expected_root
            );
        }
    }
}

/// Run a spanning tree test for a given set of edges.
///
/// Creates nodes, initiates handshakes, drains packets, and verifies convergence.
/// If `verbose` is true, prints topology and convergence progress.
async fn run_tree_test(
    num_nodes: usize,
    edges: &[(usize, usize)],
    verbose: bool,
) -> Vec<TestNode> {
    // Create nodes
    let mut nodes = Vec::new();
    for _ in 0..num_nodes {
        nodes.push(make_test_node().await);
    }

    if verbose {
        eprintln!(
            "\n  === Spanning Tree Convergence ({} nodes, {} edges) ===",
            num_nodes,
            edges.len()
        );
        let expected_root = nodes.iter().map(|tn| *tn.node.node_addr()).min().unwrap();
        let root_idx = nodes
            .iter()
            .position(|tn| *tn.node.node_addr() == expected_root)
            .unwrap();
        eprintln!("  Expected root: node[{}] = {}", root_idx, expected_root);

        // Compute average degree
        let mut degree = vec![0usize; num_nodes];
        for &(i, j) in edges {
            degree[i] += 1;
            degree[j] += 1;
        }
        let avg_degree = degree.iter().sum::<usize>() as f64 / num_nodes as f64;
        let max_degree = degree.iter().max().copied().unwrap_or(0);
        let min_degree = degree.iter().min().copied().unwrap_or(0);
        eprintln!(
            "  Degree: min={} max={} avg={:.1}",
            min_degree, max_degree, avg_degree
        );

        // Per-node/edge detail only for small networks
        if num_nodes <= 20 {
            let mut sorted: Vec<(usize, NodeAddr)> = nodes
                .iter()
                .enumerate()
                .map(|(i, tn)| (i, *tn.node.node_addr()))
                .collect();
            sorted.sort_by_key(|(_, addr)| *addr);
            eprintln!("  Node addresses (sorted, smallest = expected root):");
            for (i, addr) in &sorted {
                let marker = if *i == sorted[0].0 { " <-- root" } else { "" };
                eprintln!("    node[{}] = {}{}", i, addr, marker);
            }
            eprintln!("  Edges:");
            for (idx, &(i, j)) in edges.iter().enumerate() {
                eprintln!("    edge[{}]: node[{}] -- node[{}]", idx, i, j);
            }
        }
    }

    // Initiate all handshakes
    for &(i, j) in edges {
        initiate_handshake(&mut nodes, i, j).await;
    }

    // Drain packets until convergence (handles rate-limited announces)
    let total = drain_all_packets(&mut nodes, verbose).await;
    assert!(total > 0, "Should have processed at least some packets");

    if verbose {
        eprintln!("\n  Total packets processed: {}", total);
    }

    // Verify all edges established bidirectional peers
    for &(i, j) in edges {
        let j_addr = *nodes[j].node.node_addr();
        let i_addr = *nodes[i].node.node_addr();

        assert!(
            nodes[i].node.get_peer(&j_addr).is_some(),
            "Node {} should have peer {} (node {})",
            i,
            j_addr,
            j
        );
        assert!(
            nodes[j].node.get_peer(&i_addr).is_some(),
            "Node {} should have peer {} (node {})",
            j,
            i_addr,
            i
        );
    }

    nodes
}

/// Clean up transports for all test nodes.
async fn cleanup_nodes(nodes: &mut [TestNode]) {
    for tn in nodes.iter_mut() {
        for (_, t) in tn.node.transports.iter_mut() {
            t.stop().await.ok();
        }
    }
}

// ===== Main Convergence Test =====

/// Integration test: 100 nodes with random connectivity converge to a
/// consistent spanning tree with the correct root.
#[tokio::test]
async fn test_spanning_tree_convergence_100_nodes() {
    const NUM_NODES: usize = 100;
    const TARGET_EDGES: usize = 250;
    const SEED: u64 = 42;

    let edges = generate_random_edges(NUM_NODES, TARGET_EDGES, SEED);
    let mut nodes = run_tree_test(NUM_NODES, &edges, true).await;
    verify_tree_convergence(&nodes);
    cleanup_nodes(&mut nodes).await;
}

// ===== Topology Variant Tests =====

/// Ring topology: 5 nodes in a cycle.
#[tokio::test]
async fn test_spanning_tree_ring() {
    let edges: Vec<(usize, usize)> = vec![(0, 1), (1, 2), (2, 3), (3, 4), (4, 0)];
    let mut nodes = run_tree_test(5, &edges, false).await;
    verify_tree_convergence(&nodes);
    cleanup_nodes(&mut nodes).await;
}

/// Star topology: node 0 connected to all others.
#[tokio::test]
async fn test_spanning_tree_star() {
    let edges: Vec<(usize, usize)> = vec![(0, 1), (0, 2), (0, 3), (0, 4)];
    let mut nodes = run_tree_test(5, &edges, false).await;
    verify_tree_convergence(&nodes);
    cleanup_nodes(&mut nodes).await;
}

/// Linear chain: 0-1-2-3-4.
#[tokio::test]
async fn test_spanning_tree_chain() {
    let edges: Vec<(usize, usize)> = vec![(0, 1), (1, 2), (2, 3), (3, 4)];
    let mut nodes = run_tree_test(5, &edges, false).await;
    verify_tree_convergence(&nodes);
    cleanup_nodes(&mut nodes).await;
}

/// Two disconnected components: nodes 0-2 and nodes 3-5.
#[tokio::test]
async fn test_spanning_tree_disconnected() {
    let edges: Vec<(usize, usize)> = vec![
        (0, 1),
        (1, 2), // component 1
        (3, 4),
        (4, 5), // component 2
    ];
    let mut nodes = run_tree_test(6, &edges, false).await;
    verify_tree_convergence_components(&nodes, &[vec![0, 1, 2], vec![3, 4, 5]]);
    cleanup_nodes(&mut nodes).await;
}
