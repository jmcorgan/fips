//! Integration tests for end-to-end Noise IK handshake scenarios.

use super::*;

#[tokio::test]
async fn test_two_node_handshake_udp() {
    use crate::config::UdpConfig;
    use crate::transport::udp::UdpTransport;
    use crate::node::wire::{build_encrypted, build_established_header, build_msg1, prepend_inner_header};
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
        peer_b_identity,
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
    // Prepend inner header (timestamp + msg_type) as the real send path does
    let msg_a = b"\x10test from A"; // msg_type 0x10 (TreeAnnounce) + dummy payload
    let inner_a = prepend_inner_header(0, msg_a);
    let peer_b = node_a.get_peer_mut(&peer_b_node_addr).unwrap();
    let their_index_b = peer_b.their_index().expect("A should know B's index");
    let session_a = peer_b.noise_session_mut().unwrap();
    let counter_a = session_a.current_send_counter();
    let header_a = build_established_header(their_index_b, counter_a, 0, inner_a.len() as u16);
    let ciphertext_a = session_a.encrypt_with_aad(&inner_a, &header_a).unwrap();

    let wire_encrypted = build_encrypted(&header_a, &ciphertext_a);
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

    // Prepend inner header (timestamp + msg_type) as the real send path does
    let msg_b = b"\x10test from B"; // msg_type 0x10 (TreeAnnounce) + dummy payload
    let inner_b = prepend_inner_header(0, msg_b);
    let peer_a = node_b.get_peer_mut(&peer_a_node_addr).unwrap();
    let their_index_a = peer_a.their_index().expect("B should know A's index");
    let session_b = peer_a.noise_session_mut().unwrap();
    let counter_b = session_b.current_send_counter();
    let header_b = build_established_header(their_index_a, counter_b, 0, inner_b.len() as u16);
    let ciphertext_b = session_b.encrypt_with_aad(&inner_b, &header_b).unwrap();

    let wire_encrypted_b = build_encrypted(&header_b, &ciphertext_b);
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
    use crate::node::wire::build_msg1;
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
        peer_b_identity,
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
    // which dispatches based on the common prefix phase field.

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
    use crate::node::wire::build_msg1;
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
    let mut conn_a = PeerConnection::outbound(link_id_a_out, peer_b_identity, 1000);
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
    let mut conn_b = PeerConnection::outbound(link_id_b_out, peer_a_identity, 1000);
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
    let mut conn = PeerConnection::outbound(link_id, peer_identity, past_time_ms);

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
    assert!(!node.addr_to_link.contains_key(&(transport_id, remote_addr)),
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
    let mut conn = PeerConnection::outbound(link_id, peer_identity, now_ms);

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
