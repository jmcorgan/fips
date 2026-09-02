//! Integration tests for end-to-end Noise IK handshake scenarios.

use super::*;

#[tokio::test]
async fn test_two_node_handshake_udp() {
    use crate::config::UdpConfig;
    use crate::proto::fmp::wire::{
        build_encrypted, build_established_header, build_msg1, prepend_inner_header,
    };
    use crate::transport::udp::UdpTransport;
    use tokio::time::{Duration, timeout};

    // === Setup: Two nodes with UDP transports on localhost ===

    let mut node_a = make_node();
    let mut node_b = make_node();

    let transport_id_a = TransportId::new(1);
    let transport_id_b = TransportId::new(1);

    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };

    let (packet_tx_a, mut packet_rx_a) = packet_channel(64);
    let (packet_tx_b, mut packet_rx_b) = packet_channel(64);

    let mut transport_a = UdpTransport::new(transport_id_a, None, udp_config.clone(), packet_tx_a);
    let mut transport_b = UdpTransport::new(transport_id_b, None, udp_config, packet_tx_b);

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
    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity().pubkey_full());
    let peer_b_node_addr = *peer_b_identity.node_addr();

    let link_id_a = node_a.allocate_link_id();

    // Allocate session index for A's outbound
    let our_index_a = node_a.index_allocator.allocate().unwrap();

    node_a
        .seed_handshake_machine(
            HandshakeSeed::outbound(link_id_a, peer_b_identity, 1000)
                .with_our_index(our_index_a)
                .with_transport_id(transport_id_a)
                .with_source_addr(remote_addr_b.clone()),
        )
        .unwrap();

    // Start handshake (generates Noise IK msg1)
    let our_keypair_a = node_a.identity().keypair();
    let startup_epoch_a = node_a.startup_epoch();
    let noise_msg1 = node_a
        .peer_machines
        .get_mut(&link_id_a)
        .unwrap()
        .start_handshake(our_keypair_a, startup_epoch_a, 1000)
        .unwrap();

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
    node_a
        .pending_outbound
        .insert((transport_id_a, our_index_a.as_u32()), link_id_a);

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
    let peer_a_node_addr =
        *PeerIdentity::from_pubkey_full(node_a.identity().pubkey_full()).node_addr();
    assert_eq!(
        node_b.peer_count(),
        1,
        "Node B should have 1 peer after msg1"
    );
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
    assert_eq!(
        node_a.peer_count(),
        1,
        "Node A should have 1 peer after msg2"
    );
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
    use crate::proto::fmp::wire::build_msg1;
    use crate::transport::udp::UdpTransport;
    use tokio::time::Duration;

    // === Setup: Two nodes with UDP transports on localhost ===

    let mut node_a = make_node();
    let mut node_b = make_node();

    let transport_id_a = TransportId::new(1);
    let transport_id_b = TransportId::new(1);

    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };

    let (packet_tx_a, packet_rx_a) = packet_channel(64);
    let (packet_tx_b, packet_rx_b) = packet_channel(64);

    let mut transport_a = UdpTransport::new(transport_id_a, None, udp_config.clone(), packet_tx_a);
    let mut transport_b = UdpTransport::new(transport_id_b, None, udp_config, packet_tx_b);

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
    node_a.supervisor.state = NodeState::Running;
    node_b.supervisor.state = NodeState::Running;

    // === Phase 1: Node A initiates handshake to Node B ===

    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity().pubkey_full());
    let peer_b_node_addr = *peer_b_identity.node_addr();

    let link_id_a = node_a.allocate_link_id();

    let our_index_a = node_a.index_allocator.allocate().unwrap();
    node_a
        .seed_handshake_machine(
            HandshakeSeed::outbound(link_id_a, peer_b_identity, 1000)
                .with_our_index(our_index_a)
                .with_transport_id(transport_id_a)
                .with_source_addr(remote_addr_b.clone()),
        )
        .unwrap();
    let our_keypair_a = node_a.identity().keypair();
    let startup_epoch_a = node_a.startup_epoch();
    let noise_msg1 = node_a
        .peer_machines
        .get_mut(&link_id_a)
        .unwrap()
        .start_handshake(our_keypair_a, startup_epoch_a, 1000)
        .unwrap();

    let wire_msg1 = build_msg1(our_index_a, &noise_msg1);

    let link_a = Link::connectionless(
        link_id_a,
        transport_id_a,
        remote_addr_b.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node_a.links.insert(link_id_a, link_a);
    node_a
        .pending_outbound
        .insert((transport_id_a, our_index_a.as_u32()), link_id_a);

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
    let peer_a_node_addr =
        *PeerIdentity::from_pubkey_full(node_a.identity().pubkey_full()).node_addr();

    assert_eq!(
        node_b.peer_count(),
        1,
        "Node B should have 1 peer after rx loop processed msg1"
    );
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
    assert_eq!(
        node_a.peer_count(),
        1,
        "Node A should have 1 peer after rx loop processed msg2"
    );
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
    use crate::proto::fmp::wire::build_msg1;
    use crate::transport::udp::UdpTransport;
    use tokio::time::{Duration, timeout};

    // === Setup: Two nodes with UDP transports on localhost ===

    let mut node_a = make_node();
    let mut node_b = make_node();

    let transport_id_a = TransportId::new(1);
    let transport_id_b = TransportId::new(1);

    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };

    let (packet_tx_a, mut packet_rx_a) = packet_channel(64);
    let (packet_tx_b, mut packet_rx_b) = packet_channel(64);

    let mut transport_a = UdpTransport::new(transport_id_a, None, udp_config.clone(), packet_tx_a);
    let mut transport_b = UdpTransport::new(transport_id_b, None, udp_config, packet_tx_b);

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
    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity().pubkey_full());
    let peer_b_node_addr = *peer_b_identity.node_addr();
    let peer_a_identity = PeerIdentity::from_pubkey_full(node_a.identity().pubkey_full());
    let peer_a_node_addr = *peer_a_identity.node_addr();

    // === Phase 1: Both nodes initiate handshakes (simulate auto_connect) ===

    // Node A initiates to Node B
    let link_id_a_out = node_a.allocate_link_id();
    let our_index_a = node_a.index_allocator.allocate().unwrap();
    node_a
        .seed_handshake_machine(
            HandshakeSeed::outbound(link_id_a_out, peer_b_identity, 1000)
                .with_our_index(our_index_a)
                .with_transport_id(transport_id_a)
                .with_source_addr(remote_addr_b.clone()),
        )
        .unwrap();
    let our_keypair_a = node_a.identity().keypair();
    let startup_epoch_a = node_a.startup_epoch();
    let noise_msg1_a = node_a
        .peer_machines
        .get_mut(&link_id_a_out)
        .unwrap()
        .start_handshake(our_keypair_a, startup_epoch_a, 1000)
        .unwrap();

    let wire_msg1_a = build_msg1(our_index_a, &noise_msg1_a);

    let link_a_out = Link::connectionless(
        link_id_a_out,
        transport_id_a,
        remote_addr_b.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node_a.links.insert(link_id_a_out, link_a_out);
    node_a
        .addr_to_link
        .insert((transport_id_a, remote_addr_b.clone()), link_id_a_out);
    node_a
        .pending_outbound
        .insert((transport_id_a, our_index_a.as_u32()), link_id_a_out);

    // Node B initiates to Node A
    let link_id_b_out = node_b.allocate_link_id();
    let our_index_b = node_b.index_allocator.allocate().unwrap();
    node_b
        .seed_handshake_machine(
            HandshakeSeed::outbound(link_id_b_out, peer_a_identity, 1000)
                .with_our_index(our_index_b)
                .with_transport_id(transport_id_b)
                .with_source_addr(remote_addr_a.clone()),
        )
        .unwrap();
    let our_keypair_b = node_b.identity().keypair();
    let startup_epoch_b = node_b.startup_epoch();
    let noise_msg1_b = node_b
        .peer_machines
        .get_mut(&link_id_b_out)
        .unwrap()
        .start_handshake(our_keypair_b, startup_epoch_b, 1000)
        .unwrap();

    let wire_msg1_b = build_msg1(our_index_b, &noise_msg1_b);

    let link_b_out = Link::connectionless(
        link_id_b_out,
        transport_id_b,
        remote_addr_a.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node_b.links.insert(link_id_b_out, link_b_out);
    node_b
        .addr_to_link
        .insert((transport_id_b, remote_addr_a.clone()), link_id_b_out);
    node_b
        .pending_outbound
        .insert((transport_id_b, our_index_b.as_u32()), link_id_b_out);

    // Both send msg1 over UDP
    let transport = node_a.transports.get(&transport_id_a).unwrap();
    transport
        .send(&remote_addr_b, &wire_msg1_a)
        .await
        .expect("A send msg1");

    let transport = node_b.transports.get(&transport_id_b).unwrap();
    transport
        .send(&remote_addr_a, &wire_msg1_b)
        .await
        .expect("B send msg1");

    // === Phase 2: Both nodes receive the other's msg1 ===
    // Before the fix, addr_to_link would reject these because outbound links
    // already exist for these addresses.

    // B receives A's msg1
    let packet_at_b = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await
        .expect("Timeout")
        .expect("Channel closed");
    node_b.handle_msg1(packet_at_b).await;

    // B should have promoted the inbound connection
    assert_eq!(
        node_b.peer_count(),
        1,
        "Node B should have 1 peer after processing A's msg1"
    );
    assert!(
        node_b.get_peer(&peer_a_node_addr).is_some(),
        "Node B should have peer A"
    );

    // A receives B's msg1
    let packet_at_a = timeout(Duration::from_secs(1), packet_rx_a.recv())
        .await
        .expect("Timeout")
        .expect("Channel closed");
    node_a.handle_msg1(packet_at_a).await;

    // A should have promoted the inbound connection
    assert_eq!(
        node_a.peer_count(),
        1,
        "Node A should have 1 peer after processing B's msg1"
    );
    assert!(
        node_a.get_peer(&peer_b_node_addr).is_some(),
        "Node A should have peer B"
    );

    // === Phase 3: Both nodes receive msg2 responses ===
    // The msg2 was sent during handle_msg1 processing. When handle_msg2
    // processes it, it will detect the cross-connection and resolve.

    // A receives B's msg2 (response to A's original msg1)
    let msg2_at_a = timeout(Duration::from_secs(1), packet_rx_a.recv())
        .await
        .expect("Timeout waiting for msg2 at A")
        .expect("Channel closed");
    node_a.handle_msg2(msg2_at_a).await;

    // B receives A's msg2 (response to B's original msg1)
    let msg2_at_b = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await
        .expect("Timeout waiting for msg2 at B")
        .expect("Channel closed");
    node_b.handle_msg2(msg2_at_b).await;

    // === Verification ===
    // Both nodes should have exactly 1 peer each after cross-connection resolution
    assert_eq!(
        node_a.peer_count(),
        1,
        "Node A should have exactly 1 peer after cross-connection"
    );
    assert_eq!(
        node_b.peer_count(),
        1,
        "Node B should have exactly 1 peer after cross-connection"
    );

    let peer_b_on_a = node_a
        .get_peer(&peer_b_node_addr)
        .expect("A should have peer B");
    let peer_a_on_b = node_b
        .get_peer(&peer_a_node_addr)
        .expect("B should have peer A");

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
    let remote_addr = TransportAddr::from_string("10.0.0.2:2121");

    // Create outbound connection with a timestamp far in the past
    let past_time_ms = 1000; // A very early timestamp
    let link_id = node.allocate_link_id();

    // Allocate session index and set transport info
    let our_index = node.index_allocator.allocate().unwrap();
    node.seed_handshake_machine(
        HandshakeSeed::outbound(link_id, peer_identity, past_time_ms)
            .with_our_index(our_index)
            .with_transport_id(transport_id)
            .with_source_addr(remote_addr.clone()),
    )
    .unwrap();
    let our_keypair = node.identity().keypair();
    let startup_epoch = node.startup_epoch();
    let _noise_msg1 = node
        .peer_machines
        .get_mut(&link_id)
        .unwrap()
        .start_handshake(our_keypair, startup_epoch, past_time_ms)
        .unwrap();

    // Set up all the state that initiate_peer_connection would create
    let link = Link::connectionless(
        link_id,
        transport_id,
        remote_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node.links.insert(link_id, link);
    node.addr_to_link
        .insert((transport_id, remote_addr.clone()), link_id);
    node.pending_outbound
        .insert((transport_id, our_index.as_u32()), link_id);

    // Verify state before timeout check
    assert_eq!(node.connection_count(), 1);
    assert_eq!(node.link_count(), 1);
    assert!(
        node.pending_outbound
            .contains_key(&(transport_id, our_index.as_u32()))
    );
    assert_eq!(node.index_allocator.count(), 1);

    // Connection was created at time 1000ms. check_timeouts uses SystemTime::now(),
    // which is far beyond the 30s timeout. The connection should be cleaned up.
    node.check_timeouts().await;

    // Verify everything was cleaned up
    assert_eq!(
        node.connection_count(),
        0,
        "Stale connection should be removed"
    );
    assert_eq!(node.link_count(), 0, "Stale link should be removed");
    assert!(
        !node
            .pending_outbound
            .contains_key(&(transport_id, our_index.as_u32())),
        "pending_outbound should be cleaned up"
    );
    assert_eq!(
        node.index_allocator.count(),
        0,
        "Session index should be freed"
    );
    assert!(
        !node.addr_to_link.contains_key(&(transport_id, remote_addr)),
        "addr_to_link should be cleaned up"
    );
}

/// Test that failed connections are cleaned up by check_timeouts().
#[tokio::test]
async fn test_failed_connection_cleanup() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let peer_identity = make_peer_identity();
    let remote_addr = TransportAddr::from_string("10.0.0.2:2121");

    // Create a connection and mark it failed (simulating a send failure)
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let link_id = node.allocate_link_id();

    let our_index = node.index_allocator.allocate().unwrap();
    node.seed_handshake_machine(
        HandshakeSeed::outbound(link_id, peer_identity, now_ms)
            .with_our_index(our_index)
            .with_transport_id(transport_id)
            .with_source_addr(remote_addr.clone()),
    )
    .unwrap();
    let our_keypair = node.identity().keypair();
    let startup_epoch = node.startup_epoch();
    let _noise_msg1 = node
        .peer_machines
        .get_mut(&link_id)
        .unwrap()
        .start_handshake(our_keypair, startup_epoch, now_ms)
        .unwrap();

    let link = Link::connectionless(
        link_id,
        transport_id,
        remote_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node.links.insert(link_id, link);
    node.addr_to_link
        .insert((transport_id, remote_addr.clone()), link_id);
    node.pending_outbound
        .insert((transport_id, our_index.as_u32()), link_id);

    // Simulate a stored-handshake send failure through the control machine —
    // the failure carrier the stale-connection sweep now reads (the leg no
    // longer carries a failed phase of its own).
    {
        let machine = node
            .peer_machines
            .get_mut(&link_id)
            .expect("machine seeded by the handshake seeder");
        let alloc = &mut node.index_allocator;
        let actions = machine.step(
            crate::peer::machine::PeerEvent::HandshakeSendFailed,
            now_ms,
            alloc,
        );
        assert!(actions.is_empty());
        assert!(machine.is_failed());
    }

    assert_eq!(node.connection_count(), 1);

    // Failed connections should be cleaned up immediately regardless of age
    node.check_timeouts().await;

    assert_eq!(
        node.connection_count(),
        0,
        "Failed connection should be removed"
    );
    assert_eq!(node.link_count(), 0, "Failed link should be removed");
    assert_eq!(
        node.index_allocator.count(),
        0,
        "Session index should be freed"
    );
}

/// Test that msg1 bytes are stored on connection for resend.
#[tokio::test]
async fn test_msg1_stored_for_resend() {
    use crate::proto::fmp::wire::build_msg1;

    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let peer_identity = make_peer_identity();
    let remote_addr = TransportAddr::from_string("10.0.0.2:2121");

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let link_id = node.allocate_link_id();
    let mut conn = outbound_leg(link_id, peer_identity, now_ms);

    let our_index = node.index_allocator.allocate().unwrap();
    let our_keypair = node.identity().keypair();
    let noise_msg1 = conn
        .start_handshake(our_keypair, node.startup_epoch(), now_ms)
        .unwrap();
    conn.set_conn_our_index(our_index);
    conn.set_conn_transport_id(transport_id);
    conn.set_conn_source_addr(remote_addr.clone());

    // Build wire msg1 and store it (as initiate_peer_connection does)
    let wire_msg1 = build_msg1(our_index, &noise_msg1);
    let resend_interval = node.config().node.rate_limit.handshake_resend_interval_ms;
    conn.set_conn_handshake_msg1(wire_msg1.clone(), now_ms + resend_interval);

    // Verify stored msg1 matches what was built
    assert_eq!(conn.conn_handshake_msg1().unwrap(), &wire_msg1);
}

/// Test that resend scheduling respects max_resends and backoff.
#[tokio::test]
async fn test_resend_scheduling() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let peer_identity = make_peer_identity();
    let remote_addr = TransportAddr::from_string("10.0.0.2:2121");

    let now_ms = 100_000u64; // Use a fixed time for predictable testing
    let link_id = node.allocate_link_id();
    let mut conn = outbound_leg(link_id, peer_identity, now_ms);

    let our_index = node.index_allocator.allocate().unwrap();
    let our_keypair = node.identity().keypair();
    let noise_msg1 = conn
        .start_handshake(our_keypair, node.startup_epoch(), now_ms)
        .unwrap();
    conn.set_conn_source_addr(remote_addr.clone());

    // Store msg1 with first resend at now + 1000ms
    let wire_msg1 = crate::proto::fmp::wire::build_msg1(our_index, &noise_msg1);

    let link = Link::connectionless(
        link_id,
        transport_id,
        remote_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node.links.insert(link_id, link);
    node.addr_to_link
        .insert((transport_id, remote_addr.clone()), link_id);
    node.pending_outbound
        .insert((transport_id, our_index.as_u32()), link_id);

    // The msg1-resend counter and its due timer live on the per-peer machine,
    // which also carries the pending connection. Dial it to `SentMsg1`
    // (connectionless: no connect step) and arm its retransmit timer at
    // now + 1000ms, mirroring what a real dial arms.
    let mut machine =
        crate::peer::machine::PeerMachine::new_outbound(link_id, peer_identity, now_ms);
    let _ = machine.step(
        crate::peer::machine::PeerEvent::Dial {
            transport_id,
            remote_addr: remote_addr.clone(),
            peer_identity,
            connection_oriented: false,
        },
        now_ms,
        &mut node.index_allocator,
    );
    // The msg1 wire lives on the machine's carrier (the retransmit driver's
    // resend source), mirroring `prepare_outbound_msg1`.
    machine.set_conn_handshake_msg1(wire_msg1, now_ms + 1000);
    machine.set_conn_our_index(our_index);
    machine.set_conn_transport_id(transport_id);
    machine.set_leg(conn.take_leg().unwrap());
    node.peer_machines.insert(link_id, machine);
    node.peer_timers.entry(link_id).or_default().insert(
        crate::peer::machine::TimerKind::HandshakeRetransmit,
        now_ms + 1000,
    );

    // Before the scheduled time the timer isn't due, so nothing fires.
    node.drive_peer_timers(now_ms + 500).await;
    assert_eq!(
        node.connection_resend_count(link_id),
        0,
        "No resend before scheduled time"
    );

    // At the scheduled time the timer is due, but no transport is registered so
    // the send fails. Record-on-success: the count does NOT advance (and the
    // connection is not marked failed) — a failed resend just retries next tick.
    node.drive_peer_timers(now_ms + 1000).await;
    assert_eq!(
        node.connection_resend_count(link_id),
        0,
        "Failed send records no resend"
    );
}

/// Test that the timer driver reaps an outbound leg whose machine
/// `HandshakeTimeout` timer has come due (the timeout fold). The reap re-checks
/// the shell `is_timed_out` predicate, then tears the connection down exactly as
/// the old `check_timeouts` Teardown path did.
#[tokio::test]
async fn test_handshake_timeout_drive() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let peer_identity = make_peer_identity();
    let remote_addr = TransportAddr::from_string("10.0.0.2:2121");

    let dial_ms = 1000u64;
    let link_id = node.allocate_link_id();
    let mut conn = outbound_leg(link_id, peer_identity, dial_ms);
    let our_index = node.index_allocator.allocate().unwrap();
    let our_keypair = node.identity().keypair();
    let _ = conn
        .start_handshake(our_keypair, node.startup_epoch(), dial_ms)
        .unwrap();
    conn.set_conn_source_addr(remote_addr.clone());

    let link = Link::connectionless(
        link_id,
        transport_id,
        remote_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node.links.insert(link_id, link);
    node.addr_to_link
        .insert((transport_id, remote_addr.clone()), link_id);
    node.pending_outbound
        .insert((transport_id, our_index.as_u32()), link_id);

    // Machine in SentMsg1, carrying the pending connection, with a
    // HandshakeTimeout timer armed at dial + 30s.
    let mut machine =
        crate::peer::machine::PeerMachine::new_outbound(link_id, peer_identity, dial_ms);
    let _ = machine.step(
        crate::peer::machine::PeerEvent::Dial {
            transport_id,
            remote_addr: remote_addr.clone(),
            peer_identity,
            connection_oriented: false,
        },
        dial_ms,
        &mut node.index_allocator,
    );
    machine.set_conn_our_index(our_index);
    machine.set_conn_transport_id(transport_id);
    machine.set_leg(conn.take_leg().unwrap());
    node.peer_machines.insert(link_id, machine);
    node.peer_timers.entry(link_id).or_default().insert(
        crate::peer::machine::TimerKind::HandshakeTimeout,
        dial_ms + 30_000,
    );

    assert_eq!(node.connection_count(), 1);

    // Well past dial + 30s: the timer is due and the leg is idle-timed-out.
    node.drive_peer_timers(dial_ms + 100_000).await;

    assert_eq!(
        node.connection_count(),
        0,
        "Timed-out leg reaped by the timer drive"
    );
    assert_eq!(node.index_allocator.count(), 0, "Session index freed");
    assert!(
        !node.peer_machines.contains_key(&link_id),
        "Control machine dropped with the reaped connection"
    );
    assert!(
        !node.peer_timers.contains_key(&link_id),
        "Timer store dropped with the reaped connection"
    );
}

/// Test that msg2 is stored on the control machine's carrier for responder resend.
#[test]
fn test_msg2_stored_on_connection() {
    let mut machine = crate::peer::machine::PeerMachine::new_inbound(LinkId::new(1), 1000);

    assert!(machine.conn_handshake_msg2().is_none());

    let msg2_bytes = vec![0x01, 0x02, 0x03, 0x04];
    machine.set_conn_handshake_msg2(msg2_bytes.clone());

    assert_eq!(machine.conn_handshake_msg2().unwrap(), &msg2_bytes);
}

/// Test that duplicate msg2 is silently dropped when pending_outbound is already cleared.
#[tokio::test]
async fn test_duplicate_msg2_dropped() {
    use crate::proto::fmp::wire::build_msg2;
    use crate::transport::ReceivedPacket;

    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // No pending_outbound entry — simulate post-promotion state
    let receiver_idx = SessionIndex::new(42);
    let sender_idx = SessionIndex::new(99);

    // Build a fake msg2 packet
    let fake_noise_msg2 = vec![0u8; 57]; // Noise IK msg2 is 57 bytes (33 ephem + 24 encrypted epoch)
    let wire_msg2 = build_msg2(sender_idx, receiver_idx, &fake_noise_msg2);

    let packet = ReceivedPacket {
        transport_id,
        remote_addr: TransportAddr::from_string("10.0.0.2:2121"),
        data: wire_msg2,
        timestamp_ms: 1000,
    };

    // Should silently drop — no pending_outbound for this index
    node.handle_msg2(packet).await;
    // No panic, no state change — that's the test
    assert_eq!(node.connection_count(), 0);
    assert_eq!(node.peer_count(), 0);
}

/// `should_admit_msg1` admits when no transport is registered for the id.
/// (No gate to apply — the caller's other checks decide the outcome.)
///
/// This node is also the discriminator for the extraction of
/// `is_established_link_msg1`: with no transport registered the
/// `accept_connections` fallback admits, so the two predicates disagree
/// here and nowhere else. An extraction that dragged the fallback into
/// `is_established_link_msg1` fails the second assertion.
#[test]
fn test_should_admit_msg1_no_transport() {
    let node = make_node();
    let addr = TransportAddr::from_string("10.0.0.2:2121");
    assert!(node.should_admit_msg1(TransportId::new(1), &addr));
    assert!(
        !node.is_established_link_msg1(TransportId::new(1), &addr),
        "the accept_connections fallback must not be part of the \
         established-link predicate"
    );
}

/// `should_admit_msg1` rejects a fresh msg1 (no addr_to_link entry) when
/// the transport has accept_connections=false. Behavior unchanged from
/// before the carve-out.
#[tokio::test]
async fn test_should_admit_msg1_rejects_fresh_when_accept_off() {
    use crate::config::TcpConfig;
    use crate::transport::tcp::TcpTransport;

    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // bind_addr=None → accept_connections() == false
    let cfg = TcpConfig {
        bind_addr: None,
        ..Default::default()
    };
    let (tx, _rx) = packet_channel(64);
    let tcp = TcpTransport::new(transport_id, None, cfg, tx);
    node.transports
        .insert(transport_id, TransportHandle::Tcp(tcp));

    let addr = TransportAddr::from_string("10.0.0.2:2121");
    assert!(!node.should_admit_msg1(transport_id, &addr));
}

/// Regression test: `should_admit_msg1` admits rekey/restart
/// msg1 from a peer with an existing link even when the transport has
/// accept_connections=false. Without this, the dual-init tie-breaker
/// deadlocks (the larger-NodeAddr side drops the winner's rekey msg1).
#[tokio::test]
async fn test_should_admit_msg1_admits_rekey_when_accept_off() {
    use crate::config::TcpConfig;
    use crate::transport::tcp::TcpTransport;

    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let cfg = TcpConfig {
        bind_addr: None,
        ..Default::default()
    };
    let (tx, _rx) = packet_channel(64);
    let tcp = TcpTransport::new(transport_id, None, cfg, tx);
    node.transports
        .insert(transport_id, TransportHandle::Tcp(tcp));

    let addr = TransportAddr::from_string("10.0.0.2:2121");

    // Pre-populate addr_to_link as if a session were established for this
    // peer on this transport (rekey msg1 will arrive against this entry).
    let link_id = node.allocate_link_id();
    node.addr_to_link
        .insert((transport_id, addr.clone()), link_id);

    assert!(node.should_admit_msg1(transport_id, &addr));
}

/// Same regression coverage as the TCP test above, but exercising the
/// UDP transport's new `accept_connections` config field (introduced
/// alongside the `outbound_only` mode). Proves the Node-level gate's
/// addr_to_link carve-out is transport-agnostic and that the new UDP
/// config knob is wired correctly through the Transport trait.
#[tokio::test]
async fn test_should_admit_msg1_admits_rekey_when_udp_accept_off() {
    use crate::config::UdpConfig;
    use crate::transport::udp::UdpTransport;

    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let cfg = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        accept_connections: Some(false),
        ..Default::default()
    };
    let (tx, _rx) = packet_channel(64);
    let udp = UdpTransport::new(transport_id, None, cfg, tx);
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let addr = TransportAddr::from_string("10.0.0.2:2121");

    // Fresh msg1 (no addr_to_link entry) is rejected by the gate when
    // the transport refuses inbound.
    assert!(!node.should_admit_msg1(transport_id, &addr));

    // Pre-populate addr_to_link as if a session were established. The
    // rekey carve-out admits the msg1 even though the transport still
    // says accept_connections() == false.
    let link_id = node.allocate_link_id();
    node.addr_to_link
        .insert((transport_id, addr.clone()), link_id);

    assert!(node.should_admit_msg1(transport_id, &addr));
}

/// Regression test for the udp.outbound_only rekey loop observed in
/// production 2026-04-30 (parallel to the rekey/restart admission case
/// above).
///
/// Production scenario: nomad runs `udp.outbound_only=true` with peer
/// core-vm configured by hostname (`core-vm.tail65015.ts.net:2121`).
/// `initiate_connection` populates `addr_to_link` with the literal
/// hostname-form `TransportAddr`. core-vm's later rekey msg1 arrives at
/// nomad with a numeric source addr (the kernel always reports
/// `SocketAddr` in numeric form via `recvfrom`), so the `addr_to_link`
/// lookup misses, the gate falls through to `accept_connections()`
/// (false in outbound_only mode), and rejects. Result: dual-init
/// tie-breaker stalls because the loser side never produces msg2.
///
/// The carve-out predicate must also consult peer state by source
/// address: `current_addr()` is updated from inbound encrypted-frame
/// source addrs (`dataplane/encrypted.rs`), so an established peer can
/// be matched even when the addr_to_link key is hostname-form and the
/// incoming addr is numeric.
#[tokio::test]
async fn test_should_admit_msg1_admits_rekey_when_addr_form_differs() {
    use crate::config::UdpConfig;
    use crate::peer::ActivePeer;
    use crate::transport::udp::UdpTransport;

    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // outbound_only mode forces accept_connections() to false.
    let cfg = UdpConfig {
        outbound_only: Some(true),
        ..Default::default()
    };
    let (tx, _rx) = packet_channel(64);
    let udp = UdpTransport::new(transport_id, None, cfg, tx);
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    // Simulate initiate_connection's effect when peer config carries a
    // hostname: addr_to_link is populated with hostname-form, not
    // numeric-form.
    let hostname_addr = TransportAddr::from_string("core-vm.example:2121");
    let link_id = node.allocate_link_id();
    node.addr_to_link
        .insert((transport_id, hostname_addr.clone()), link_id);

    // Promote a peer at the hostname's resolved numeric form
    // (current_addr is set from the SocketAddr in udp_receive_loop).
    let peer_full = crate::Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey(peer_full.pubkey());
    let peer_node_addr = *peer_identity.node_addr();
    let mut peer = ActivePeer::new(peer_identity, link_id, 1000);
    let numeric_addr = TransportAddr::from_string("100.64.0.5:2121");
    peer.set_current_addr(transport_id, numeric_addr.clone());
    node.peers.insert(peer_node_addr, peer);

    // Sanity: legacy carve-out still works for the hostname-form lookup.
    assert!(node.should_admit_msg1(transport_id, &hostname_addr));

    // The bug: incoming rekey msg1 arrives with numeric source addr.
    // Without the additional carve-out, this is rejected (addr_to_link
    // miss → accept_connections() false → drop).
    assert!(
        node.should_admit_msg1(transport_id, &numeric_addr),
        "rekey msg1 from established peer must be admitted even when \
         addr_to_link is keyed by a different addr-form (hostname vs \
         numeric); the carve-out must consult peer current_addr"
    );

    // Negative: a stranger at a different numeric addr is still rejected
    // (no peer there, no addr_to_link entry, falls to accept_connections).
    let stranger_addr = TransportAddr::from_string("198.51.100.1:2121");
    assert!(
        !node.should_admit_msg1(transport_id, &stranger_addr),
        "fresh msg1 from unknown source must still be rejected"
    );

    // The same two predicates read directly: both addr-forms of the
    // established peer are established links, the stranger is not.
    assert!(node.is_established_link_msg1(transport_id, &hostname_addr));
    assert!(node.is_established_link_msg1(transport_id, &numeric_addr));
    assert!(!node.is_established_link_msg1(transport_id, &stranger_addr));
}

// ============================================================================
// Frame-length validation at the dispatch point
// ============================================================================

/// Build a promoted peer and return the node, the peer's address, and the
/// session index inbound frames must name to reach it.
///
/// `handle_encrypted_frame` looks a frame up by `(transport_id, receiver_idx)`
/// in `peers_by_index`, so a frame carrying this index reaches the decrypt and
/// bumps the peer's failure counter. That counter is how the tests below tell
/// "the frame reached its handler" apart from "the frame was dropped before
/// the dispatch": an unknown session is dropped silently and counts nothing.
fn node_with_promoted_peer(transport_id: TransportId) -> (Node, NodeAddr, SessionIndex) {
    let mut node = make_node();
    let link_id = LinkId::new(1);
    let identity = seed_completed_connection(&mut node, link_id, transport_id, 1_000);
    let node_addr = *identity.node_addr();
    node.promote_connection(link_id, identity, 2_000).unwrap();
    let our_index = node
        .get_peer(&node_addr)
        .and_then(|p| p.our_index())
        .expect("promoted peer must have our_index");
    (node, node_addr, our_index)
}

/// A well-formed established frame carrying 40 bytes of inner plaintext.
///
/// 16-byte header + 40 + 16-byte tag = 72 bytes on the wire, declaring 40.
/// The ciphertext is filler: these tests are about the length check, and
/// every one of them stops before or at the AEAD.
fn established_frame_declaring_40(receiver_idx: SessionIndex) -> Vec<u8> {
    use crate::noise::TAG_SIZE;
    use crate::proto::fmp::wire::{build_encrypted, build_established_header};

    let header = build_established_header(receiver_idx, 0, 0, 40);
    build_encrypted(&header, &[0u8; 40 + TAG_SIZE])
}

#[tokio::test]
async fn an_established_frame_whose_declared_payload_len_disagrees_with_its_length_is_dropped() {
    let transport_id = TransportId::new(1);
    let (mut node, node_addr, our_index) = node_with_promoted_peer(transport_id);

    let mut frame = established_frame_declaring_40(our_index);
    // Bytes 2-3 are the little-endian payload_len. 68 is what a validator
    // written to the field's looser description would compute for this frame
    // (72 on the wire minus the 4-byte common prefix), so it is both a wrong
    // value and the specific wrong value worth naming.
    frame[2..4].copy_from_slice(&68u16.to_le_bytes());

    node.process_packet(ReceivedPacket::new(
        transport_id,
        TransportAddr::from_string("127.0.0.1:2121"),
        frame,
    ))
    .await;

    assert_eq!(
        node.stats().transport.payload_len_mismatch,
        1,
        "the frame must be counted as a framing drop"
    );
    assert_eq!(
        node.get_peer(&node_addr)
            .expect("peer must survive a dropped frame")
            .consecutive_decrypt_failures(),
        0,
        "the frame must be dropped before the phase dispatch, so the \
         encrypted-frame handler never sees it"
    );
}

#[tokio::test]
async fn an_established_frame_with_a_correct_payload_len_is_not_dropped() {
    let transport_id = TransportId::new(1);
    let (mut node, node_addr, our_index) = node_with_promoted_peer(transport_id);

    let frame = established_frame_declaring_40(our_index);

    node.process_packet(ReceivedPacket::new(
        transport_id,
        TransportAddr::from_string("127.0.0.1:2121"),
        frame,
    ))
    .await;

    assert_eq!(
        node.stats().transport.payload_len_mismatch,
        0,
        "a frame whose header agrees with its length must not be dropped"
    );
    assert_eq!(
        node.get_peer(&node_addr)
            .expect("peer must survive a failed decrypt below the threshold")
            .consecutive_decrypt_failures(),
        1,
        "the frame must reach the encrypted-frame handler, where the filler \
         ciphertext fails the AEAD tag"
    );
}

#[tokio::test]
async fn a_msg1_with_a_correct_payload_len_is_not_dropped() {
    use crate::proto::fmp::wire::build_msg1;

    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // A real-shaped msg1 with filler Noise bytes: `build_msg1` writes the
    // only payload_len the msg1 arm accepts, and the handshake fails one
    // step later at the DH, which is the observable that it got there.
    let frame = build_msg1(SessionIndex::new(1), &[0u8; 106]);

    node.process_packet(ReceivedPacket::new(
        transport_id,
        TransportAddr::from_string("127.0.0.1:2121"),
        frame,
    ))
    .await;

    assert_eq!(
        node.stats().transport.payload_len_mismatch,
        0,
        "a msg1 built by the encoder must not be dropped by the length check"
    );
    assert_eq!(
        node.stats().handshake.bad_state,
        1,
        "the msg1 must reach handle_msg1, which rejects the filler Noise \
         payload at the DH"
    );
}

// ============================================================================
// Identity confirmation after the DH (the address-keyed msg1 carve-out)
// ============================================================================

/// A node whose only transport refuses fresh inbound handshakes, paired with
/// a second started UDP socket standing in for the far end.
///
/// Returns the node, the far end's address, the far end's receive channel,
/// and the far end's transport, which the caller must keep alive for its
/// receive loop to go on running.
///
/// Both transports are started on purpose. A msg2 the node decides to send
/// then really leaves it and really arrives on the returned channel, which is
/// what makes "no msg2 was sent" an observation about the confirmation rather
/// than a property of the fixture: on an unstarted transport every send
/// fails, and the send-failure arm records the same reject the confirmation
/// records, so the two worlds would be indistinguishable.
async fn node_refusing_inbound(
    transport_id: TransportId,
) -> (
    Node,
    TransportAddr,
    crate::transport::PacketRx,
    crate::transport::udp::UdpTransport,
) {
    use crate::config::UdpConfig;
    use crate::transport::udp::UdpTransport;

    let mut node = make_node();

    let refusing = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        accept_connections: Some(false),
        ..Default::default()
    };
    let (tx, _rx) = packet_channel(64);
    let mut udp = UdpTransport::new(transport_id, None, refusing, tx);
    udp.start_async().await.expect("node transport must bind");
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let far_end_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    };
    let (far_tx, far_rx) = packet_channel(64);
    let mut far_end = UdpTransport::new(TransportId::new(200), None, far_end_config, far_tx);
    far_end.start_async().await.expect("far end must bind");
    let far_addr = TransportAddr::from_string(
        &far_end
            .local_addr()
            .expect("a started transport has a local address")
            .to_string(),
    );

    (node, far_addr, far_rx, far_end)
}

/// A real, cryptographically valid msg1 from `initiator` addressed to
/// `responder`'s static key.
///
/// It has to be valid under our static, or `receive_handshake_init` refuses
/// it for the wrong reason and the test passes without ever reaching the
/// confirmation.
fn genuine_msg1(initiator: &Node, responder: &Node) -> Vec<u8> {
    use crate::proto::fmp::wire::build_msg1;

    let responder_identity = PeerIdentity::from_pubkey_full(responder.identity().pubkey_full());
    let mut machine = outbound_leg(LinkId::new(9_999), responder_identity, 1_000);
    let noise_msg1 = machine
        .start_handshake(
            initiator.identity().keypair(),
            initiator.startup_epoch(),
            1_000,
        )
        .expect("the initiator side of a real msg1 must build");
    build_msg1(SessionIndex::new(7), &noise_msg1)
}

/// The node address a `Node`'s own identity presents to its peers.
fn node_addr_of(node: &Node) -> NodeAddr {
    *PeerIdentity::from_pubkey_full(node.identity().pubkey_full()).node_addr()
}

/// The FMP phase byte of a packet, for telling a msg1 from a msg2 on the wire.
fn wire_phase(data: &[u8]) -> Option<u8> {
    crate::proto::fmp::wire::CommonPrefix::parse(data).map(|p| p.phase)
}

/// Assert that nothing arrives on `rx` within a window long enough for a
/// localhost datagram to have been delivered had one been sent.
async fn assert_nothing_sent(rx: &mut crate::transport::PacketRx, why: &str) {
    let arrival = tokio::time::timeout(std::time::Duration::from_millis(250), rx.recv()).await;
    assert!(arrival.is_err(), "{}", why);
}

#[tokio::test]
async fn a_msg1_spoofed_from_an_established_peers_address_is_dropped_after_the_dh_reveals_a_different_identity()
 {
    use crate::peer::ActivePeer;

    let transport_id = TransportId::new(1);
    let (mut node, victim_addr, mut far_rx, _far_end) = node_refusing_inbound(transport_id).await;

    // The victim: a promoted peer at the address the spoofed msg1 will be
    // sourced from, so the carve-out admits the msg1 past the refusing gate.
    let victim = make_node();
    let victim_identity = PeerIdentity::from_pubkey_full(victim.identity().pubkey_full());
    let victim_node_addr = *victim_identity.node_addr();
    let victim_link = node.allocate_link_id();
    let mut victim_peer = ActivePeer::new(victim_identity, victim_link, 1_000);
    victim_peer.set_current_addr(transport_id, victim_addr.clone());
    node.peers.insert(victim_node_addr, victim_peer);
    node.addr_to_link
        .insert((transport_id, victim_addr.clone()), victim_link);

    // The off-path party: a genuine msg1 under our static, built with a
    // different identity's keypair, sourced from the victim's address.
    let attacker = make_node();
    let attacker_node_addr = node_addr_of(&attacker);
    let wire_msg1 = genuine_msg1(&attacker, &node);

    let bad_state_before = node.stats().handshake.bad_state;
    node.handle_msg1(ReceivedPacket::with_timestamp(
        transport_id,
        victim_addr.clone(),
        wire_msg1,
        2_000,
    ))
    .await;

    assert!(
        node.get_peer(&attacker_node_addr).is_none(),
        "the identity the DH revealed does not own the address the waiver \
         matched, so it must not become a peer"
    );
    assert_eq!(
        node.peer_count(),
        1,
        "only the victim may remain a peer after the spoofed msg1"
    );
    assert_eq!(
        node.connection_count(),
        0,
        "the rejected msg1 must leave no connection behind"
    );
    assert_eq!(
        node.link_count(),
        0,
        "the rejected msg1 must leave no link behind"
    );
    assert_eq!(
        node.stats().handshake.bad_state - bad_state_before,
        1,
        "the drop must be counted"
    );
    assert_nothing_sent(
        &mut far_rx,
        "no msg2 may reach the victim's address: the responder answers only \
         after the confirmation, and this msg1 must not get that far",
    )
    .await;
}

#[tokio::test]
async fn a_msg1_admitted_by_a_link_no_identity_owns_is_dropped_after_the_dh() {
    let transport_id = TransportId::new(1);
    let (mut node, source_addr, mut far_rx, _far_end) = node_refusing_inbound(transport_id).await;

    // The fixture `test_should_admit_msg1_admits_rekey_when_accept_off` uses:
    // a reverse-address entry with no peer and no connection behind it. It is
    // enough to waive the refusing gate, and it attributes the address to
    // nobody.
    let link_id = node.allocate_link_id();
    node.addr_to_link
        .insert((transport_id, source_addr.clone()), link_id);

    assert!(
        node.should_admit_msg1(transport_id, &source_addr),
        "the fixture must exercise the carve-out, not the gate"
    );

    let initiator = make_node();
    let initiator_node_addr = node_addr_of(&initiator);
    let wire_msg1 = genuine_msg1(&initiator, &node);

    let bad_state_before = node.stats().handshake.bad_state;
    node.handle_msg1(ReceivedPacket::with_timestamp(
        transport_id,
        source_addr.clone(),
        wire_msg1,
        2_000,
    ))
    .await;

    assert!(
        node.get_peer(&initiator_node_addr).is_none(),
        "a msg1 the waiver could attribute to no identity must not promote \
         the identity the DH revealed"
    );
    assert_eq!(node.peer_count(), 0, "no peer may be created");
    assert_eq!(
        node.connection_count(),
        0,
        "the rejected msg1 must leave no connection behind"
    );
    assert_eq!(
        node.link_count(),
        0,
        "the rejected msg1 must leave no link behind"
    );
    assert_eq!(
        node.stats().handshake.bad_state - bad_state_before,
        1,
        "the drop must be counted"
    );
    assert_nothing_sent(
        &mut far_rx,
        "no msg2 may leave the node for an address no identity owns",
    )
    .await;
}

#[tokio::test]
async fn a_msg1_from_a_link_whose_dial_expects_this_identity_is_admitted() {
    let transport_id = TransportId::new(1);
    let (mut node, peer_addr, mut far_rx, _far_end) = node_refusing_inbound(transport_id).await;

    // UDP is connectionless, so `initiate_connection` runs `start_handshake`
    // in the same synchronous stretch: the reverse-address entry and the
    // connection carrying the dialled identity land together, and the
    // classifier can attribute the address. Do not substitute a
    // connection-oriented transport here; that arm defers `start_handshake`
    // and is the window the next test is about.
    let peer = make_node();
    let peer_identity = PeerIdentity::from_pubkey_full(peer.identity().pubkey_full());
    node.initiate_connection(transport_id, peer_addr.clone(), peer_identity)
        .await
        .expect("the dial must register the link and the connection");

    // Our own dial's msg1 went out first; drain it so the assertion below is
    // about the answer to the crossing msg1.
    let ours = tokio::time::timeout(std::time::Duration::from_secs(1), far_rx.recv())
        .await
        .expect("our dial's msg1 must arrive")
        .expect("the far end's channel must be open");
    assert_eq!(
        wire_phase(&ours.data),
        Some(crate::proto::fmp::wire::PHASE_MSG1),
        "the dial's own packet is a msg1"
    );

    let bad_state_before = node.stats().handshake.bad_state;
    let wire_msg1 = genuine_msg1(&peer, &node);
    node.handle_msg1(ReceivedPacket::with_timestamp(
        transport_id,
        peer_addr.clone(),
        wire_msg1,
        2_000,
    ))
    .await;

    let answer = tokio::time::timeout(std::time::Duration::from_secs(1), far_rx.recv())
        .await
        .expect("the crossing msg1 must be answered")
        .expect("the far end's channel must be open");
    assert_eq!(
        wire_phase(&answer.data),
        Some(crate::proto::fmp::wire::PHASE_MSG2),
        "a simultaneous open with the peer we dialled must still be answered"
    );
    assert_eq!(
        node.stats().handshake.bad_state - bad_state_before,
        0,
        "a crossing msg1 from the identity the dial expects must not be \
         rejected"
    );
}

#[tokio::test]
async fn a_crossing_msg1_in_the_connection_oriented_dial_window_is_rejected() {
    use crate::config::TcpConfig;
    use crate::transport::tcp::TcpTransport;

    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // bind_addr=None makes accept_connections() false, the idiom
    // `test_should_admit_msg1_rejects_fresh_when_accept_off` uses.
    let cfg = TcpConfig {
        bind_addr: None,
        ..Default::default()
    };
    let (tx, _rx) = packet_channel(64);
    let tcp = TcpTransport::new(transport_id, None, cfg, tx);
    node.transports
        .insert(transport_id, TransportHandle::Tcp(tcp));

    let peer = make_node();
    let peer_identity = PeerIdentity::from_pubkey_full(peer.identity().pubkey_full());
    let addr = TransportAddr::from_string("10.0.0.2:2121");

    // The state `initiate_connection`'s connection-oriented arm leaves behind
    // while the transport connect is outstanding: a link, a reverse-address
    // entry, a pending connect, and no connection yet. Built directly rather
    // than by driving a connect, which would need a reachable peer.
    let link_id = node.allocate_link_id();
    let link = Link::new(
        link_id,
        transport_id,
        addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node.links.insert(link_id, link);
    node.addr_to_link
        .insert((transport_id, addr.clone()), link_id);
    node.peering.pending_connects.push(PendingConnect {
        link_id,
        transport_id,
        remote_addr: addr.clone(),
        peer_identity,
    });

    let bad_state_before = node.stats().handshake.bad_state;
    let wire_msg1 = genuine_msg1(&peer, &node);
    node.handle_msg1(ReceivedPacket::with_timestamp(
        transport_id,
        addr.clone(),
        wire_msg1,
        2_000,
    ))
    .await;

    // This is the assertion that separates the two worlds, and it is the one
    // to read first when the test reds. After the change the reject returns
    // above every registry mutation, so the dial's own entry is untouched.
    // Without it, `handle_msg1` allocates a fresh link id, writes it over
    // this entry, and then removes the entry outright when the msg2 send
    // fails on the unstarted transport.
    assert_eq!(
        node.addr_to_link.get(&(transport_id, addr.clone())),
        Some(&link_id),
        "the dial's reverse-address entry must still name the dial's own link"
    );
    // The remaining three state the shape of the outcome. They hold either
    // way for this fixture, whose unstarted TCP transport cannot send, so
    // they are not what makes this test able to fail.
    assert_eq!(node.peer_count(), 0, "no peer may be created");
    assert_eq!(node.connection_count(), 0, "no connection may be created");
    assert_eq!(
        node.stats().handshake.bad_state - bad_state_before,
        1,
        "the drop must be counted"
    );
}

#[tokio::test]
async fn msg1_waiver_classifies_all_three_outcomes() {
    use crate::config::UdpConfig;
    use crate::node::handlers::handshake::Msg1Waiver;
    use crate::peer::ActivePeer;
    use crate::transport::udp::UdpTransport;

    let mut node = make_node();

    // A registered accepting transport, not an unregistered id, so the
    // NotNeeded assertion exercises the `accept_connections()` limb of the
    // guard rather than its absent-transport fallback.
    let accepting_id = TransportId::new(1);
    let (accept_tx, _accept_rx) = packet_channel(64);
    let accepting = UdpTransport::new(
        accepting_id,
        None,
        UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            accept_connections: Some(true),
            ..Default::default()
        },
        accept_tx,
    );
    node.transports
        .insert(accepting_id, TransportHandle::Udp(accepting));

    let refusing_id = TransportId::new(2);
    let (refuse_tx, _refuse_rx) = packet_channel(64);
    let refusing = UdpTransport::new(
        refusing_id,
        None,
        UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            accept_connections: Some(false),
            ..Default::default()
        },
        refuse_tx,
    );
    node.transports
        .insert(refusing_id, TransportHandle::Udp(refusing));

    let classify = |node: &Node, transport_id: TransportId, addr: &TransportAddr| {
        node.msg1_waiver(
            node.is_established_link_msg1(transport_id, addr),
            transport_id,
            addr,
        )
    };

    // NotNeeded: the gate would have admitted this msg1 anyway, so nothing
    // was waived and there is nothing to confirm.
    let fresh = TransportAddr::from_string("10.0.0.2:2121");
    assert_eq!(
        classify(&node, accepting_id, &fresh),
        Msg1Waiver::NotNeeded,
        "an accepting transport waives nothing"
    );

    // Unattributed: the carve-out admits on a bare reverse-address entry
    // that names neither a promoted peer nor a carrier.
    let bare = TransportAddr::from_string("10.0.0.3:2121");
    let bare_link = node.allocate_link_id();
    node.addr_to_link
        .insert((refusing_id, bare.clone()), bare_link);
    assert_eq!(
        classify(&node, refusing_id, &bare),
        Msg1Waiver::Unattributed,
        "a link no identity owns must fail closed"
    );

    // Expect, by promoted peer. `ActivePeer::new` sets neither transport_id
    // nor current_addr, so this peer is reached through the reverse-address
    // entry that names its link.
    let promoted_addr = TransportAddr::from_string("10.0.0.4:2121");
    let promoted_link = node.allocate_link_id();
    let promoted = make_peer_identity();
    let promoted_node_addr = *promoted.node_addr();
    node.peers.insert(
        promoted_node_addr,
        ActivePeer::new(promoted, promoted_link, 1_000),
    );
    node.addr_to_link
        .insert((refusing_id, promoted_addr.clone()), promoted_link);
    assert_eq!(
        classify(&node, refusing_id, &promoted_addr),
        Msg1Waiver::Expect(promoted_node_addr),
        "an address whose link a promoted peer owns is attributed to that peer"
    );

    // Expect, by carrier: a link with no promoted peer yet, whose connection
    // carries the identity the dial expects.
    let carrier_addr = TransportAddr::from_string("10.0.0.5:2121");
    let carrier_link = node.allocate_link_id();
    let dialled = make_peer_identity();
    let dialled_node_addr = *dialled.node_addr();
    node.seed_handshake_machine(HandshakeSeed::outbound(carrier_link, dialled, 1_000))
        .unwrap();
    node.addr_to_link
        .insert((refusing_id, carrier_addr.clone()), carrier_link);
    assert_eq!(
        classify(&node, refusing_id, &carrier_addr),
        Msg1Waiver::Expect(dialled_node_addr),
        "an address whose link carries a dialled identity is attributed to it"
    );
}

#[tokio::test]
async fn a_stale_reverse_address_entry_does_not_hide_a_peer_reachable_by_address() {
    use crate::config::UdpConfig;
    use crate::node::handlers::handshake::Msg1Waiver;
    use crate::peer::ActivePeer;
    use crate::transport::udp::UdpTransport;

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let (tx, _rx) = packet_channel(64);
    let udp = UdpTransport::new(
        transport_id,
        None,
        UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            accept_connections: Some(false),
            ..Default::default()
        },
        tx,
    );
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    // A live peer whose current_addr is the numeric form inbound packets
    // carry, which is the second predicate's whole reason for existing.
    let numeric = TransportAddr::from_string("100.64.0.5:2121");
    let peer_link = node.allocate_link_id();
    let peer_identity = make_peer_identity();
    let peer_node_addr = *peer_identity.node_addr();
    let mut peer = ActivePeer::new(peer_identity, peer_link, 1_000);
    peer.set_current_addr(transport_id, numeric.clone());
    node.peers.insert(peer_node_addr, peer);

    // A reverse-address entry at that same numeric address naming a link
    // that no longer exists. `remove_link` clears the reverse lookup only
    // under the key it rebuilds from the removed link's own remote address,
    // so an entry inserted for that link under a second address form outlives
    // it, and link ids are never reused.
    let dead_link = node.allocate_link_id();
    assert_ne!(
        dead_link, peer_link,
        "the stale entry names a different link"
    );
    node.addr_to_link
        .insert((transport_id, numeric.clone()), dead_link);

    assert_eq!(
        node.msg1_waiver(
            node.is_established_link_msg1(transport_id, &numeric),
            transport_id,
            &numeric
        ),
        Msg1Waiver::Expect(peer_node_addr),
        "the stale entry must not hide the peer the address scan finds: \
         classifying this Unattributed would reject the peer's rekey msg1 \
         after the DH, and would go on rejecting it, because the reject \
         returns above the insert that would overwrite the stale entry"
    );
}

// ===== Epoch-restart dampening =====
//
// An epoch-mismatch msg1 is authentic, because the epoch travels inside the
// AEAD, but it is replayable: a captured one stays valid forever and
// accepting it destroys a working peering. Two receiver-local conditions
// gate the teardown, and each of the first two cases below breaks one of
// them.

/// Install a peering for `initiator` that carries an epoch its genuine msg1
/// does not, and that has gone `idle_secs` without authenticated inbound
/// traffic. Returns the link the peering is bound to.
fn install_peering_at_a_different_epoch(
    node: &mut Node,
    initiator: &Node,
    transport_id: TransportId,
    source_addr: &TransportAddr,
    idle_secs: u64,
) -> LinkId {
    use crate::peer::ActivePeer;

    let identity = PeerIdentity::from_pubkey_full(initiator.identity().pubkey_full());
    let node_addr = *identity.node_addr();
    let link_id = node.allocate_link_id();
    let authenticated_at = Node::now_ms().saturating_sub(idle_secs * 1000);
    let mut peer = ActivePeer::new(identity, link_id, authenticated_at);
    peer.set_current_addr(transport_id, source_addr.clone());
    // Anything but the epoch the initiator's msg1 carries, so the msg1 reads
    // as a restart.
    peer.set_remote_epoch(Some([0xAA; 8]));
    node.peers.insert(node_addr, peer);
    node.addr_to_link
        .insert((transport_id, source_addr.clone()), link_id);
    link_id
}

/// A peering long enough past its last authenticated inbound frame that the
/// liveness gate does not hold the restart back.
const IDLE_SECS: u64 = 60;

#[tokio::test]
async fn an_epoch_mismatch_msg1_against_a_live_peering_leaves_it_intact() {
    let transport_id = TransportId::new(1);
    let mut node = make_node();
    let initiator = make_node();
    let initiator_addr = node_addr_of(&initiator);
    let source_addr = TransportAddr::from_string("127.0.0.1:41001");

    // The peering is carrying authenticated traffic: it decrypted a frame a
    // moment ago. Under replay that is always the case, because the genuine
    // peer is heartbeating.
    let peer_link =
        install_peering_at_a_different_epoch(&mut node, &initiator, transport_id, &source_addr, 0);

    let bad_state_before = node.stats().handshake.bad_state;
    node.handle_msg1(ReceivedPacket::with_timestamp(
        transport_id,
        source_addr.clone(),
        genuine_msg1(&initiator, &node),
        Node::now_ms(),
    ))
    .await;

    let peer = node
        .get_peer(&initiator_addr)
        .expect("a live peering must survive an epoch-mismatch msg1");
    assert_eq!(
        peer.link_id(),
        peer_link,
        "the peering must be the one that was already established, not a \
         replacement promoted from the msg1"
    );
    assert_eq!(
        peer.remote_epoch(),
        Some([0xAA; 8]),
        "the stored epoch must not have moved to the one the msg1 carried"
    );
    assert_eq!(
        node.connection_count(),
        0,
        "the dropped msg1 must leave no connection behind"
    );
    assert_eq!(
        node.stats().handshake.bad_state - bad_state_before,
        1,
        "the drop must be counted"
    );
}

#[tokio::test]
async fn a_second_epoch_change_inside_the_dampening_interval_leaves_the_peering_intact() {
    let transport_id = TransportId::new(1);
    let mut node = make_node();
    let initiator = make_node();
    let initiator_addr = node_addr_of(&initiator);
    let source_addr = TransportAddr::from_string("127.0.0.1:41002");

    // First epoch change: the peering is genuinely idle, so it is accepted
    // and stamps the dampener.
    let first_link = install_peering_at_a_different_epoch(
        &mut node,
        &initiator,
        transport_id,
        &source_addr,
        IDLE_SECS,
    );
    node.handle_msg1(ReceivedPacket::with_timestamp(
        transport_id,
        source_addr.clone(),
        genuine_msg1(&initiator, &node),
        Node::now_ms(),
    ))
    .await;
    let promoted = node
        .get_peer(&initiator_addr)
        .expect("the first epoch change must be accepted");
    assert_ne!(
        promoted.link_id(),
        first_link,
        "the first epoch change must have replaced the peering"
    );

    // The peer moves epoch again straight away. Nothing about the second
    // msg1 is distinguishable from the first, which is why the interval,
    // not the message, has to be what refuses it.
    let second_link = install_peering_at_a_different_epoch(
        &mut node,
        &initiator,
        transport_id,
        &source_addr,
        IDLE_SECS,
    );

    let bad_state_before = node.stats().handshake.bad_state;
    node.handle_msg1(ReceivedPacket::with_timestamp(
        transport_id,
        source_addr.clone(),
        genuine_msg1(&initiator, &node),
        Node::now_ms(),
    ))
    .await;

    let peer = node
        .get_peer(&initiator_addr)
        .expect("a second epoch change inside the interval must not tear the peering down");
    assert_eq!(
        peer.link_id(),
        second_link,
        "the peering must be the one that was already established"
    );
    assert_eq!(
        peer.remote_epoch(),
        Some([0xAA; 8]),
        "the stored epoch must not have moved to the one the msg1 carried"
    );
    assert_eq!(
        node.connection_count(),
        0,
        "the dropped msg1 must leave no connection behind"
    );
    assert_eq!(
        node.stats().handshake.bad_state - bad_state_before,
        1,
        "the drop must be counted"
    );
}

/// A REFUSED epoch-mismatch msg1 must not slide the dampening window.
///
/// The stamp is written on acceptance only. If it were written on every
/// sighting, a sender replaying a captured msg1 faster than the interval would
/// hold the window open indefinitely and a genuinely restarting peer could
/// never re-peer — the refusal would become the denial of service it exists to
/// prevent. The 15s interval is far longer than a test can wait, so this pins
/// the ordering directly: after an accepted change stamps the dampener,
/// repeated refused msg1s must leave that stamp byte-identical.
///
/// Discriminator: moving the three stamp lines above the gate in
/// `InboundDecision::RestartThenPromote` reds this and nothing else in the
/// module.
#[tokio::test]
async fn a_refused_epoch_change_does_not_slide_the_dampening_window() {
    let transport_id = TransportId::new(1);
    let mut node = make_node();
    let initiator = make_node();
    let initiator_addr = node_addr_of(&initiator);
    let source_addr = TransportAddr::from_string("127.0.0.1:41009");

    // Accepted change: stamps the dampener.
    install_peering_at_a_different_epoch(
        &mut node,
        &initiator,
        transport_id,
        &source_addr,
        IDLE_SECS,
    );
    node.handle_msg1(ReceivedPacket::with_timestamp(
        transport_id,
        source_addr.clone(),
        genuine_msg1(&initiator, &node),
        Node::now_ms(),
    ))
    .await;
    let stamped = node
        .restart_dampener_stamp(&initiator_addr)
        .expect("an accepted epoch change must stamp the dampener");

    // Sustained replay: every one of these is refused by the dampener.
    for _ in 0..5 {
        install_peering_at_a_different_epoch(
            &mut node,
            &initiator,
            transport_id,
            &source_addr,
            IDLE_SECS,
        );
        node.handle_msg1(ReceivedPacket::with_timestamp(
            transport_id,
            source_addr.clone(),
            genuine_msg1(&initiator, &node),
            Node::now_ms(),
        ))
        .await;
    }

    assert_eq!(
        node.restart_dampener_stamp(&initiator_addr),
        Some(stamped),
        "a refused epoch change must not restamp the dampener; if it does, a \
         sustained replay holds the window open and starves a real restart"
    );
}

/// Healthy path, and NOT discriminating: this passes with or without the
/// gates. It is here so that tightening either one, or a bug that stamps the
/// dampener on a refusal, reds the suite instead of silently refusing every
/// genuine restart.
#[tokio::test]
async fn a_first_epoch_change_against_a_silent_peering_still_restarts_it() {
    let transport_id = TransportId::new(1);
    let mut node = make_node();
    let initiator = make_node();
    let initiator_addr = node_addr_of(&initiator);
    let source_addr = TransportAddr::from_string("127.0.0.1:41003");

    let stale_link = install_peering_at_a_different_epoch(
        &mut node,
        &initiator,
        transport_id,
        &source_addr,
        IDLE_SECS,
    );

    node.handle_msg1(ReceivedPacket::with_timestamp(
        transport_id,
        source_addr.clone(),
        genuine_msg1(&initiator, &node),
        Node::now_ms(),
    ))
    .await;

    let peer = node
        .get_peer(&initiator_addr)
        .expect("a restart with no prior epoch change must be promoted");
    assert_ne!(
        peer.link_id(),
        stale_link,
        "the stale peering must have been torn down and replaced"
    );
    assert_eq!(
        peer.remote_epoch(),
        Some(initiator.startup_epoch()),
        "the replacement must carry the epoch the msg1 announced"
    );
}

/// A transient send failure during msg2 leaves the half-built link alone.
///
/// The interface under the transport is absent or mid-rebind, and the binder
/// is already working to bring it back. Tearing the link down here meant the
/// initiator's msg1 resend had nothing to land on, and — worse — recorded
/// `HandshakeReject::BadState`, a counter whose whole meaning is "the remote
/// sent something invalid". A local interface flap is not the remote's fault,
/// and an operator reading that counter would conclude it was.
///
/// Nothing leaks by staying: an initiator that never resends leaves a stale
/// connection, which `check_timeouts` reaps at `handshake_timeout_secs` like
/// any other abandoned handshake.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn a_transient_msg2_failure_keeps_the_link_for_the_retry() {
    use crate::config::EthernetConfig;
    use crate::proto::fmp::wire::build_msg1;
    use crate::transport::TransportHandle;
    use crate::transport::ethernet::EthernetTransport;

    let mut node_b = make_node();
    let node_a = make_node();
    let transport_id = TransportId::new(1);
    node_b.supervisor.state = NodeState::Running;

    // An interface no host has, so every send off this transport reports
    // `InterfaceUnavailable` — the real error, from the real code path,
    // rather than a stub that merely returns something transient.
    let config = EthernetConfig {
        interface: "fips-absent-x0".to_string(),
        ethertype: None,
        mtu: None,
        recv_buf_size: None,
        send_buf_size: None,
        listen: Some(true),
        announce: Some(false),
        auto_connect: None,
        accept_connections: Some(true),
        beacon_interval_secs: None,
        optional: Some(true),
    };
    let (tx, _rx) = crate::transport::packet_channel(8);
    let mut eth = EthernetTransport::new(transport_id, Some("lab".into()), config, tx);
    eth.start_async()
        .await
        .expect("an absent interface is not a start failure");
    node_b
        .transports
        .insert(transport_id, TransportHandle::Ethernet(eth));

    let rejects_before = node_b.stats().handshake.snapshot().bad_state;

    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity().pubkey_full());
    let mut conn_a = outbound_leg(LinkId::new(1), peer_b_identity, 1000);
    let noise_msg1 = conn_a
        .start_handshake(node_a.identity().keypair(), node_a.startup_epoch(), 1000)
        .unwrap();
    let wire_msg1 = build_msg1(SessionIndex::new(7), &noise_msg1);
    let packet = ReceivedPacket::with_timestamp(
        transport_id,
        TransportAddr::from_string("aa:bb:cc:dd:ee:ff"),
        wire_msg1,
        1000,
    );

    node_b.handle_msg1(packet).await;

    assert_eq!(
        node_b.link_count(),
        1,
        "the link must survive a transport that is merely between interfaces"
    );
    assert_eq!(
        node_b.stats().handshake.snapshot().bad_state,
        rejects_before,
        "a local interface flap must not be recorded as the peer's misbehaviour"
    );
}
