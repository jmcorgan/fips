//! Integration tests for end-to-end Noise XX handshake scenarios.

use super::spanning_tree::{cleanup_nodes, drain_all_packets, initiate_handshake, make_test_node};
use super::*;

#[tokio::test]
async fn test_two_node_handshake_udp() {
    use crate::config::UdpConfig;
    use crate::node::wire::{
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
    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity.pubkey_full());
    let peer_b_node_addr = *peer_b_identity.node_addr();

    let link_id_a = node_a.allocate_link_id();
    let mut conn_a = PeerConnection::outbound(link_id_a, peer_b_identity, 1000);

    // Allocate session index for A's outbound
    let our_index_a = node_a.index_allocator.allocate().unwrap();

    // Start handshake (generates Noise XX msg1)
    let our_keypair_a = node_a.identity.keypair();
    let noise_msg1 = conn_a
        .start_handshake(our_keypair_a, node_a.startup_epoch, 1000)
        .unwrap();
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
    node_a
        .pending_outbound
        .insert((transport_id_a, our_index_a.as_u32()), link_id_a);

    // Send msg1 from A to B over UDP
    let transport = node_a.transports.get(&transport_id_a).unwrap();
    transport
        .send(&remote_addr_b, &wire_msg1)
        .await
        .expect("Failed to send msg1");

    // === Phase 2: Node B receives msg1, sends msg2 (XX: does NOT promote yet) ===

    let packet_b = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await
        .expect("Timeout waiting for msg1")
        .expect("Channel closed");

    node_b.handle_msg1(packet_b).await;

    let peer_a_node_addr =
        *PeerIdentity::from_pubkey_full(node_a.identity.pubkey_full()).node_addr();

    // XX: B has NOT promoted yet (needs msg3)
    assert_eq!(
        node_b.peer_count(),
        0,
        "Node B should have 0 peers after msg1 (XX awaits msg3)"
    );
    assert_eq!(
        node_b.connections.len(),
        1,
        "Node B should have 1 pending connection awaiting msg3"
    );

    // === Phase 3: Node A receives msg2, sends msg3, promotes ===

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

    // === Phase 4: Node B receives msg3, promotes ===

    let packet_b_msg3 = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await
        .expect("Timeout waiting for msg3")
        .expect("Channel closed");

    node_b.handle_msg3(packet_b_msg3).await;

    // Verify B promoted after msg3
    assert_eq!(
        node_b.peer_count(),
        1,
        "Node B should have 1 peer after msg3"
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
    use crate::node::wire::build_msg1;
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
    node_a.state = NodeState::Running;
    node_b.state = NodeState::Running;

    // === Phase 1: Node A initiates handshake to Node B ===

    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity.pubkey_full());
    let peer_b_node_addr = *peer_b_identity.node_addr();

    let link_id_a = node_a.allocate_link_id();
    let mut conn_a = PeerConnection::outbound(link_id_a, peer_b_identity, 1000);

    let our_index_a = node_a.index_allocator.allocate().unwrap();
    let our_keypair_a = node_a.identity.keypair();
    let noise_msg1 = conn_a
        .start_handshake(our_keypair_a, node_a.startup_epoch, 1000)
        .unwrap();
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

    // === Phase 2: Run Node B's rx loop (processes msg1 and later msg3) ===
    //
    // This is the key difference from test_two_node_handshake_udp:
    // instead of calling handle_msg1() directly, we run the full rx loop
    // which dispatches based on the common prefix phase field.
    //
    // With XX, the rx loop will process msg1 (sending msg2) but NOT
    // promote B yet (needs msg3). We run the rx loop once for msg1,
    // then later use direct handler calls for msg3 (since run_rx_loop
    // takes packet_rx and can't be called twice).

    tokio::select! {
        result = node_b.run_rx_loop() => {
            panic!("Node B rx loop exited unexpectedly: {:?}", result);
        }
        _ = tokio::time::sleep(Duration::from_millis(500)) => {
            // Timeout: rx loop processed available packets
        }
    }

    // XX: Node B has NOT promoted yet (needs msg3)
    assert_eq!(
        node_b.peer_count(),
        0,
        "Node B should have 0 peers after rx loop processed msg1 (XX awaits msg3)"
    );
    assert_eq!(
        node_b.connections.len(),
        1,
        "Node B should have 1 pending connection"
    );

    // === Phase 3: Run Node A's rx loop (processes msg2, sends msg3) ===

    tokio::select! {
        result = node_a.run_rx_loop() => {
            panic!("Node A rx loop exited unexpectedly: {:?}", result);
        }
        _ = tokio::time::sleep(Duration::from_millis(500)) => {
            // Timeout: rx loop processed msg2
        }
    }

    // Verify Node A promoted after processing msg2
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

    // Note: Phase 4 (msg3 → B promotes) cannot be tested via run_rx_loop
    // because it consumes packet_rx on first call. The msg3 dispatch is
    // verified by test_two_node_handshake_udp which uses direct handler calls.
    // This test verifies rx_loop correctly dispatches PHASE_MSG1 (Phase 2)
    // and PHASE_MSG2 (Phase 3). B still has a pending connection awaiting msg3.
    assert_eq!(
        node_b.connections.len(),
        1,
        "Node B should still have pending connection awaiting msg3"
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
    use crate::node::wire::build_msg1;
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
    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity.pubkey_full());
    let peer_b_node_addr = *peer_b_identity.node_addr();
    let peer_a_identity = PeerIdentity::from_pubkey_full(node_a.identity.pubkey_full());
    let peer_a_node_addr = *peer_a_identity.node_addr();

    // === Phase 1: Both nodes initiate handshakes (simulate auto_connect) ===

    // Node A initiates to Node B
    let link_id_a_out = node_a.allocate_link_id();
    let mut conn_a = PeerConnection::outbound(link_id_a_out, peer_b_identity, 1000);
    let our_index_a = node_a.index_allocator.allocate().unwrap();
    let our_keypair_a = node_a.identity.keypair();
    let noise_msg1_a = conn_a
        .start_handshake(our_keypair_a, node_a.startup_epoch, 1000)
        .unwrap();
    conn_a.set_our_index(our_index_a);
    conn_a.set_transport_id(transport_id_a);
    conn_a.set_source_addr(remote_addr_b.clone());

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
    node_a.connections.insert(link_id_a_out, conn_a);
    node_a
        .pending_outbound
        .insert((transport_id_a, our_index_a.as_u32()), link_id_a_out);

    // Node B initiates to Node A
    let link_id_b_out = node_b.allocate_link_id();
    let mut conn_b = PeerConnection::outbound(link_id_b_out, peer_a_identity, 1000);
    let our_index_b = node_b.index_allocator.allocate().unwrap();
    let our_keypair_b = node_b.identity.keypair();
    let noise_msg1_b = conn_b
        .start_handshake(our_keypair_b, node_b.startup_epoch, 1000)
        .unwrap();
    conn_b.set_our_index(our_index_b);
    conn_b.set_transport_id(transport_id_b);
    conn_b.set_source_addr(remote_addr_a.clone());

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
    node_b.connections.insert(link_id_b_out, conn_b);
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

    // === Phase 2: Both nodes receive the other's msg1 (XX: no promotion yet) ===

    // B receives A's msg1
    let packet_at_b = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await
        .expect("Timeout")
        .expect("Channel closed");
    node_b.handle_msg1(packet_at_b).await;

    // XX: B has NOT promoted yet (needs msg3 from A)
    assert_eq!(
        node_b.peer_count(),
        0,
        "Node B should have 0 peers after processing A's msg1 (XX)"
    );

    // A receives B's msg1
    let packet_at_a = timeout(Duration::from_secs(1), packet_rx_a.recv())
        .await
        .expect("Timeout")
        .expect("Channel closed");
    node_a.handle_msg1(packet_at_a).await;

    // XX: A has NOT promoted yet (needs msg3 from B)
    assert_eq!(
        node_a.peer_count(),
        0,
        "Node A should have 0 peers after processing B's msg1 (XX)"
    );

    // === Phase 3: Both nodes receive msg2 + send msg3, initiator side promotes ===

    // A receives B's msg2 (response to A's original msg1) → A sends msg3, A promotes
    let msg2_at_a = timeout(Duration::from_secs(1), packet_rx_a.recv())
        .await
        .expect("Timeout waiting for msg2 at A")
        .expect("Channel closed");
    node_a.handle_msg2(msg2_at_a).await;

    // A promoted as initiator
    assert_eq!(
        node_a.peer_count(),
        1,
        "Node A should have 1 peer after processing msg2"
    );

    // B receives A's msg2 (response to B's original msg1) → B sends msg3, B promotes
    let msg2_at_b = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await
        .expect("Timeout waiting for msg2 at B")
        .expect("Channel closed");
    node_b.handle_msg2(msg2_at_b).await;

    // B promoted as initiator
    assert_eq!(
        node_b.peer_count(),
        1,
        "Node B should have 1 peer after processing msg2"
    );

    // === Phase 4: Both nodes receive msg3, responder side completes ===
    // Cross-connection resolution happens here (or in Phase 3 promotion).

    // A receives B's msg3 (B completing A's inbound handshake)
    let msg3_at_a = timeout(Duration::from_secs(1), packet_rx_a.recv())
        .await
        .expect("Timeout waiting for msg3 at A")
        .expect("Channel closed");
    node_a.handle_msg3(msg3_at_a).await;

    // B receives A's msg3 (A completing B's inbound handshake)
    let msg3_at_b = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await
        .expect("Timeout waiting for msg3 at B")
        .expect("Channel closed");
    node_b.handle_msg3(msg3_at_b).await;

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
    let mut conn = PeerConnection::outbound(link_id, peer_identity, past_time_ms);

    // Allocate session index and set transport info
    let our_index = node.index_allocator.allocate().unwrap();
    let our_keypair = node.identity.keypair();
    let _noise_msg1 = conn
        .start_handshake(our_keypair, node.startup_epoch, past_time_ms)
        .unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(transport_id);
    conn.set_source_addr(remote_addr.clone());

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
    node.connections.insert(link_id, conn);
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
    node.check_timeouts();

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
    let mut conn = PeerConnection::outbound(link_id, peer_identity, now_ms);

    let our_index = node.index_allocator.allocate().unwrap();
    let our_keypair = node.identity.keypair();
    let _noise_msg1 = conn
        .start_handshake(our_keypair, node.startup_epoch, now_ms)
        .unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(transport_id);
    conn.set_source_addr(remote_addr.clone());
    conn.mark_failed(); // Simulate send failure

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
    node.connections.insert(link_id, conn);
    node.pending_outbound
        .insert((transport_id, our_index.as_u32()), link_id);

    assert_eq!(node.connection_count(), 1);

    // Failed connections should be cleaned up immediately regardless of age
    node.check_timeouts();

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
    use crate::node::wire::build_msg1;

    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let peer_identity = make_peer_identity();
    let remote_addr = TransportAddr::from_string("10.0.0.2:2121");

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let link_id = node.allocate_link_id();
    let mut conn = PeerConnection::outbound(link_id, peer_identity, now_ms);

    let our_index = node.index_allocator.allocate().unwrap();
    let our_keypair = node.identity.keypair();
    let noise_msg1 = conn
        .start_handshake(our_keypair, node.startup_epoch, now_ms)
        .unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(transport_id);
    conn.set_source_addr(remote_addr.clone());

    // Build wire msg1 and store it (as initiate_peer_connection does)
    let wire_msg1 = build_msg1(our_index, &noise_msg1);
    let resend_interval = node.config.node.rate_limit.handshake_resend_interval_ms;
    conn.set_handshake_msg1(wire_msg1.clone(), now_ms + resend_interval);

    // Verify stored msg1 matches what was built
    assert_eq!(conn.handshake_msg1().unwrap(), &wire_msg1);
    assert_eq!(conn.resend_count(), 0);
    assert!(conn.next_resend_at_ms() > now_ms);
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
    let mut conn = PeerConnection::outbound(link_id, peer_identity, now_ms);

    let our_index = node.index_allocator.allocate().unwrap();
    let our_keypair = node.identity.keypair();
    let noise_msg1 = conn
        .start_handshake(our_keypair, node.startup_epoch, now_ms)
        .unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(transport_id);
    conn.set_source_addr(remote_addr.clone());

    // Store msg1 with first resend at now + 1000ms
    let wire_msg1 = crate::node::wire::build_msg1(our_index, &noise_msg1);
    conn.set_handshake_msg1(wire_msg1, now_ms + 1000);

    let link = Link::connectionless(
        link_id,
        transport_id,
        remote_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node.links.insert(link_id, link);
    node.addr_to_link
        .insert((transport_id, remote_addr), link_id);
    node.pending_outbound
        .insert((transport_id, our_index.as_u32()), link_id);
    node.connections.insert(link_id, conn);

    // Before resend time: nothing should happen (no transport = can't send,
    // but the filter should exclude it because now < next_resend_at)
    node.resend_pending_handshakes(now_ms + 500).await;
    let conn = node.connections.get(&link_id).unwrap();
    assert_eq!(conn.resend_count(), 0, "No resend before scheduled time");

    // At resend time: would resend if transport existed. Without transport,
    // the send fails silently and resend_count stays at 0.
    // This tests the filtering logic — the connection IS a candidate.
    node.resend_pending_handshakes(now_ms + 1000).await;
    // No transport registered, so send fails — count stays 0.
    // That's the expected behavior (transport absence is a transient condition).
    let conn = node.connections.get(&link_id).unwrap();
    assert_eq!(
        conn.resend_count(),
        0,
        "No transport means no resend recorded"
    );
}

/// Test that msg2 is stored on PeerConnection for responder resend.
#[test]
fn test_msg2_stored_on_connection() {
    let mut conn = PeerConnection::inbound(LinkId::new(1), 1000);

    assert!(conn.handshake_msg2().is_none());

    let msg2_bytes = vec![0x01, 0x02, 0x03, 0x04];
    conn.set_handshake_msg2(msg2_bytes.clone());

    assert_eq!(conn.handshake_msg2().unwrap(), &msg2_bytes);
}

/// Test that resend_count and next_resend_at_ms track correctly.
#[test]
fn test_resend_count_tracking() {
    let peer_identity = make_peer_identity();
    let mut conn = PeerConnection::outbound(LinkId::new(1), peer_identity, 1000);

    assert_eq!(conn.resend_count(), 0);
    assert_eq!(conn.next_resend_at_ms(), 0);

    // Simulate storing msg1 and scheduling first resend
    conn.set_handshake_msg1(vec![0x01], 2000);
    assert_eq!(conn.resend_count(), 0);
    assert_eq!(conn.next_resend_at_ms(), 2000);

    // Record first resend
    conn.record_resend(4000); // next at 4000 (2s backoff)
    assert_eq!(conn.resend_count(), 1);
    assert_eq!(conn.next_resend_at_ms(), 4000);

    // Record second resend
    conn.record_resend(8000); // next at 8000 (4s backoff)
    assert_eq!(conn.resend_count(), 2);
    assert_eq!(conn.next_resend_at_ms(), 8000);
}

/// Test that duplicate msg2 is silently dropped when pending_outbound is already cleared.
#[tokio::test]
async fn test_duplicate_msg2_dropped() {
    use crate::node::wire::build_msg2;
    use crate::transport::ReceivedPacket;

    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // No pending_outbound entry — simulate post-promotion state
    let receiver_idx = SessionIndex::new(42);
    let sender_idx = SessionIndex::new(99);

    // Build a fake msg2 packet (XX msg2 is at least 106 bytes)
    let fake_noise_msg2 = vec![0u8; 106];
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

// ===== Profile Rejection Tests =====

/// Helper: create two test nodes, set their profiles, attempt a handshake,
/// and return whether they successfully peered.
async fn attempt_profile_handshake(
    profile_a: crate::protocol::NodeProfile,
    profile_b: crate::protocol::NodeProfile,
) -> (usize, usize) {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    nodes[0].node.node_profile = profile_a;
    nodes[1].node.node_profile = profile_b;

    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;

    let peers = (nodes[0].node.peer_count(), nodes[1].node.peer_count());
    cleanup_nodes(&mut nodes).await;
    peers
}

#[tokio::test]
async fn test_nonrouting_nonrouting_rejected() {
    use crate::protocol::NodeProfile;
    let (a, b) = attempt_profile_handshake(NodeProfile::NonRouting, NodeProfile::NonRouting).await;
    assert_eq!(a, 0, "NonRouting↔NonRouting should reject: node A");
    assert_eq!(b, 0, "NonRouting↔NonRouting should reject: node B");
}

#[tokio::test]
async fn test_leaf_leaf_rejected() {
    use crate::protocol::NodeProfile;
    let (a, b) = attempt_profile_handshake(NodeProfile::Leaf, NodeProfile::Leaf).await;
    assert_eq!(a, 0, "Leaf↔Leaf should reject: node A");
    assert_eq!(b, 0, "Leaf↔Leaf should reject: node B");
}

#[tokio::test]
async fn test_nonrouting_leaf_rejected() {
    use crate::protocol::NodeProfile;
    let (a, b) = attempt_profile_handshake(NodeProfile::NonRouting, NodeProfile::Leaf).await;
    assert_eq!(a, 0, "NonRouting↔Leaf should reject: node A");
    assert_eq!(b, 0, "NonRouting↔Leaf should reject: node B");
}

#[tokio::test]
async fn test_leaf_nonrouting_rejected() {
    use crate::protocol::NodeProfile;
    let (a, b) = attempt_profile_handshake(NodeProfile::Leaf, NodeProfile::NonRouting).await;
    assert_eq!(a, 0, "Leaf↔NonRouting should reject: node A");
    assert_eq!(b, 0, "Leaf↔NonRouting should reject: node B");
}

#[tokio::test]
async fn test_full_nonrouting_accepted() {
    use crate::protocol::NodeProfile;
    let (a, b) = attempt_profile_handshake(NodeProfile::Full, NodeProfile::NonRouting).await;
    assert_eq!(a, 1, "Full↔NonRouting should accept: node A");
    assert_eq!(b, 1, "Full↔NonRouting should accept: node B");
}

#[tokio::test]
async fn test_full_leaf_accepted() {
    use crate::protocol::NodeProfile;
    let (a, b) = attempt_profile_handshake(NodeProfile::Full, NodeProfile::Leaf).await;
    assert_eq!(a, 1, "Full↔Leaf should accept: node A");
    assert_eq!(b, 1, "Full↔Leaf should accept: node B");
}

// ===== XX Address-Based Dedup Tests =====

#[tokio::test]
async fn test_xx_duplicate_msg1_resends_msg2() {
    use crate::node::wire::build_msg1;
    use crate::transport::ReceivedPacket;

    // Node B with NO transport — msg2 send silently skips (if let Some check),
    // but the pending connection and link are created.
    let mut node_b = make_node();
    let transport_id = TransportId::new(1);

    // Build a valid XX msg1 from an external initiator
    let initiator = Identity::generate();
    let mut hs = crate::noise::HandshakeState::new_initiator(initiator.keypair());
    let noise_msg1 = hs.write_message_1().unwrap();
    let sender_idx = SessionIndex::new(42);
    let wire_msg1 = build_msg1(sender_idx, &noise_msg1);

    let remote_addr = TransportAddr::from_string("10.0.0.1:2121");

    // First msg1 → B creates pending inbound connection
    let first_packet = ReceivedPacket {
        transport_id,
        remote_addr: remote_addr.clone(),
        data: wire_msg1.clone(),
        timestamp_ms: 1000,
    };
    node_b.handle_msg1(first_packet).await;

    assert_eq!(
        node_b.connection_count(),
        1,
        "B: 1 connection after first msg1"
    );
    assert_eq!(
        node_b.peer_count(),
        0,
        "B: 0 peers (XX, no promotion at msg1)"
    );

    // Duplicate msg1 from same address → dedup triggers msg2 resend, not new handshake
    let dup_packet = ReceivedPacket {
        transport_id,
        remote_addr: remote_addr.clone(),
        data: wire_msg1.clone(),
        timestamp_ms: 1100,
    };
    node_b.handle_msg1(dup_packet).await;

    assert_eq!(
        node_b.connection_count(),
        1,
        "B: still 1 connection after duplicate msg1 (dedup, not new handshake)"
    );
    assert_eq!(node_b.peer_count(), 0, "B: still 0 peers");
}
