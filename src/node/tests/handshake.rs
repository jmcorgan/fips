//! Integration tests for end-to-end Noise XX handshake scenarios.

use super::spanning_tree::{
    cleanup_nodes, drain_all_packets, initiate_handshake, make_test_node_with_profile,
};
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

    // Start handshake (generates Noise XX msg1)
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

    // === Phase 2: Node B receives msg1, sends msg2 (XX: does NOT promote yet) ===

    let packet_b = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await
        .expect("Timeout waiting for msg1")
        .expect("Channel closed");

    node_b.handle_msg1(packet_b).await;

    let peer_a_node_addr =
        *PeerIdentity::from_pubkey_full(node_a.identity().pubkey_full()).node_addr();

    // XX: B has NOT promoted yet (needs msg3)
    assert_eq!(
        node_b.peer_count(),
        0,
        "Node B should have 0 peers after msg1 (XX awaits msg3)"
    );
    assert_eq!(
        node_b.connection_count(),
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
        node_b.connection_count(),
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
        node_b.connection_count(),
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
        crate::peer::machine::PeerMachine::new_outbound(link_id, Some(peer_identity), now_ms);
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
        crate::peer::machine::PeerMachine::new_outbound(link_id, Some(peer_identity), dial_ms);
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
    profile_a: crate::proto::fmp::NodeProfile,
    profile_b: crate::proto::fmp::NodeProfile,
) -> (usize, usize) {
    let mut nodes = vec![
        make_test_node_with_profile(profile_a).await,
        make_test_node_with_profile(profile_b).await,
    ];

    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;

    let peers = (nodes[0].node.peer_count(), nodes[1].node.peer_count());
    cleanup_nodes(&mut nodes).await;
    peers
}

#[tokio::test]
async fn test_nonrouting_nonrouting_rejected() {
    use crate::proto::fmp::NodeProfile;
    let (a, b) = attempt_profile_handshake(NodeProfile::NonRouting, NodeProfile::NonRouting).await;
    assert_eq!(a, 0, "NonRouting↔NonRouting should reject: node A");
    assert_eq!(b, 0, "NonRouting↔NonRouting should reject: node B");
}

#[tokio::test]
async fn test_leaf_leaf_rejected() {
    use crate::proto::fmp::NodeProfile;
    let (a, b) = attempt_profile_handshake(NodeProfile::Leaf, NodeProfile::Leaf).await;
    assert_eq!(a, 0, "Leaf↔Leaf should reject: node A");
    assert_eq!(b, 0, "Leaf↔Leaf should reject: node B");
}

#[tokio::test]
async fn test_nonrouting_leaf_rejected() {
    use crate::proto::fmp::NodeProfile;
    let (a, b) = attempt_profile_handshake(NodeProfile::NonRouting, NodeProfile::Leaf).await;
    assert_eq!(a, 0, "NonRouting↔Leaf should reject: node A");
    assert_eq!(b, 0, "NonRouting↔Leaf should reject: node B");
}

#[tokio::test]
async fn test_leaf_nonrouting_rejected() {
    use crate::proto::fmp::NodeProfile;
    let (a, b) = attempt_profile_handshake(NodeProfile::Leaf, NodeProfile::NonRouting).await;
    assert_eq!(a, 0, "Leaf↔NonRouting should reject: node A");
    assert_eq!(b, 0, "Leaf↔NonRouting should reject: node B");
}

#[tokio::test]
async fn test_full_nonrouting_accepted() {
    use crate::proto::fmp::NodeProfile;
    let (a, b) = attempt_profile_handshake(NodeProfile::Full, NodeProfile::NonRouting).await;
    assert_eq!(a, 1, "Full↔NonRouting should accept: node A");
    assert_eq!(b, 1, "Full↔NonRouting should accept: node B");
}

#[tokio::test]
async fn test_full_leaf_accepted() {
    use crate::proto::fmp::NodeProfile;
    let (a, b) = attempt_profile_handshake(NodeProfile::Full, NodeProfile::Leaf).await;
    assert_eq!(a, 1, "Full↔Leaf should accept: node A");
    assert_eq!(b, 1, "Full↔Leaf should accept: node B");
}

// ===== XX Address-Based Dedup Tests =====

#[tokio::test]
async fn test_xx_duplicate_msg1_resends_msg2() {
    use crate::proto::fmp::wire::build_msg1;
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

/// `should_admit_msg1` admits when no transport is registered for the id.
/// (No gate to apply — the caller's other checks decide the outcome.)
#[test]
fn test_should_admit_msg1_no_transport() {
    let node = make_node();
    let addr = TransportAddr::from_string("10.0.0.2:2121");
    assert!(node.should_admit_msg1(TransportId::new(1), &addr));
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
}

// ===========================================================================
// Regression: `handle_msg3` must return the msg1-allocated session index to
// the allocator on the two inbound-establish arms that abandon the pending
// inbound leg without promoting it — the `Reject{DualRekeyWon}` tie-break
// (dual-init rekey we win) and the `ResendMsg2` duplicate-handshake arm. Both
// tear the pending connection/link down; neither must orphan the index.
// ===========================================================================

/// A node bundled with its UDP transport, receive channel, and bound address,
/// used to drive real msg1/msg2/msg3 exchanges below.
struct HsNode {
    node: Node,
    transport_id: TransportId,
    packet_rx: crate::transport::PacketRx,
    addr: TransportAddr,
}

/// Build an `HsNode` on an ephemeral localhost UDP port from an explicit config.
async fn make_hs_node(config: Config) -> HsNode {
    use crate::config::UdpConfig;
    use crate::transport::udp::UdpTransport;

    let mut node = make_node_with(config);
    let transport_id = TransportId::new(1);
    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };
    let (packet_tx, packet_rx) = packet_channel(64);
    let mut transport = UdpTransport::new(transport_id, None, udp_config, packet_tx);
    transport.start_async().await.unwrap();
    let addr = TransportAddr::from_string(&transport.local_addr().unwrap().to_string());
    node.transports
        .insert(transport_id, TransportHandle::Udp(transport));

    HsNode {
        node,
        transport_id,
        packet_rx,
        addr,
    }
}

async fn stop_hs(n: &mut HsNode) {
    for (_, t) in n.node.transports.iter_mut() {
        t.stop().await.ok();
    }
}

/// Receive the next packet whose handshake phase matches `phase` (the low
/// nibble of the wire type byte: 1=msg1, 2=msg2, 3=msg3), skipping unrelated
/// traffic. Post-promotion tree/filter announces (phase 0, encrypted data)
/// share these channels, so a phase filter keeps the hand-driven exchange in
/// step.
async fn recv_phase(rx: &mut crate::transport::PacketRx, phase: u8, what: &str) -> ReceivedPacket {
    use std::time::Duration;
    use tokio::time::timeout;

    loop {
        let pkt = timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("timeout waiting for {}", what))
            .expect("channel closed");
        if pkt.data.first().is_some_and(|b| b & 0x0f == phase) {
            return pkt;
        }
    }
}

/// Drive one initiator -> responder XX exchange (msg1 then msg2) and return the
/// responder's inbound msg3 packet, left unhandled for the caller. The msg3 is
/// produced by the initiator's real `handle_msg2`, so it carries a valid Noise
/// payload.
async fn drive_to_msg3(
    initiator: &mut HsNode,
    responder: &mut HsNode,
    now_ms: u64,
) -> ReceivedPacket {
    use crate::proto::fmp::wire::build_msg1;
    use std::time::Duration;

    let peer_identity = PeerIdentity::from_pubkey_full(responder.node.identity().pubkey_full());

    let link_id = initiator.node.allocate_link_id();
    let our_index = initiator.node.index_allocator.allocate().unwrap();
    // Mirror the production dial path: the seam seeds the identified outbound
    // leg's control machine at dial, and the promote feedback later
    // crystallizes that same machine in place.
    initiator
        .node
        .seed_handshake_machine(
            HandshakeSeed::outbound(link_id, peer_identity, now_ms)
                .with_our_index(our_index)
                .with_transport_id(initiator.transport_id)
                .with_source_addr(responder.addr.clone()),
        )
        .unwrap();
    let our_keypair = initiator.node.identity().keypair();
    let startup_epoch = initiator.node.startup_epoch();
    let noise_msg1 = initiator
        .node
        .peer_machines
        .get_mut(&link_id)
        .unwrap()
        .start_handshake(our_keypair, startup_epoch, now_ms)
        .unwrap();

    let wire_msg1 = build_msg1(our_index, &noise_msg1);
    let link = Link::connectionless(
        link_id,
        initiator.transport_id,
        responder.addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    initiator.node.links.insert(link_id, link);
    initiator
        .node
        .addr_to_link
        .insert((initiator.transport_id, responder.addr.clone()), link_id);
    initiator
        .node
        .pending_outbound
        .insert((initiator.transport_id, our_index.as_u32()), link_id);

    initiator
        .node
        .transports
        .get(&initiator.transport_id)
        .unwrap()
        .send(&responder.addr, &wire_msg1)
        .await
        .expect("send msg1");

    // Responder processes msg1 and emits msg2 back to the initiator.
    let msg1_pkt = recv_phase(&mut responder.packet_rx, 1, "msg1").await;
    responder.node.handle_msg1(msg1_pkt).await;

    // Initiator processes msg2 and emits msg3 to the responder.
    let msg2_pkt = recv_phase(&mut initiator.packet_rx, 2, "msg2").await;
    initiator.node.handle_msg2(msg2_pkt).await;

    // Capture the responder's inbound msg3, left unhandled for the caller.
    recv_phase(&mut responder.packet_rx, 3, "msg3").await
}

#[tokio::test]
async fn test_msg3_dual_rekey_won_frees_index() {
    // Rekey enabled with a tiny interval so the rekey age floor collapses to
    // its 5s minimum; the peer session is then backdated past it.
    let make_config = || {
        let mut c = Config::new();
        c.node.rekey.enabled = true;
        c.node.rekey.after_secs = 1;
        c
    };

    let mut initiator = make_hs_node(Config::new()).await;
    // The DualRekeyWon tie-break is won by the numerically smaller node addr,
    // so the responder (whose handle_msg3 we exercise) must be the smaller.
    let mut responder = loop {
        let cand = make_hs_node(make_config()).await;
        if cand.node.node_addr() < initiator.node.node_addr() {
            break cand;
        }
    };

    // First handshake: the responder promotes the initiator to a healthy active
    // peer holding exactly one allocated session index.
    let msg3 = drive_to_msg3(&mut initiator, &mut responder, 1000).await;
    responder.node.handle_msg3(msg3).await;
    assert_eq!(responder.node.peer_count(), 1);
    let baseline = responder.node.index_allocator.count();
    assert_eq!(baseline, 1, "responder holds exactly the peer's index");

    // Age the session past the rekey floor and mark a rekey in progress so a
    // fresh inbound msg3 classifies as the dual-init rekey we win.
    let peer_addr =
        *PeerIdentity::from_pubkey_full(initiator.node.identity().pubkey_full()).node_addr();
    {
        let peer = responder.node.get_peer_mut(&peer_addr).unwrap();
        peer.test_backdate_session_established(std::time::Duration::from_secs(6));
        peer.set_rekey_in_progress();
    }

    // Second handshake: the new inbound msg1 allocates a fresh index, then the
    // msg3 lands on the DualRekeyWon reject arm.
    let msg3b = drive_to_msg3(&mut initiator, &mut responder, 2000).await;
    assert_eq!(
        responder.node.index_allocator.count(),
        baseline + 1,
        "second msg1 allocated a fresh index"
    );
    responder.node.handle_msg3(msg3b).await;

    // The rejected msg3 must return its index and leave the active peer intact.
    assert_eq!(
        responder.node.index_allocator.count(),
        baseline,
        "DualRekeyWon must free the msg1-allocated index"
    );
    assert_eq!(responder.node.peer_count(), 1, "active peer untouched");
    // The rejected leg's msg1-born machine goes with the leg; only the
    // established peer's machine remains.
    let peer_link = responder.node.get_peer(&peer_addr).unwrap().link_id();
    assert_eq!(responder.node.peer_machines.len(), 1);
    assert!(responder.node.peer_machines.contains_key(&peer_link));
    responder.node.debug_assert_peer_maps_coherent();
    assert!(
        responder
            .node
            .get_peer(&peer_addr)
            .unwrap()
            .pending_new_session()
            .is_none(),
        "reject arm must not store rekey-responder state"
    );

    stop_hs(&mut initiator).await;
    stop_hs(&mut responder).await;
}

#[tokio::test]
async fn test_msg3_resend_msg2_frees_index() {
    // Rekey disabled so an aged-session inbound msg3 classifies as a duplicate
    // handshake (ResendMsg2), not a rekey; the tiny interval keeps the
    // cross-connection age bound (the rekey floor) at its 5s minimum so the
    // aged session skips the cross-connection arm too.
    let mut config = Config::new();
    config.node.rekey.enabled = false;
    config.node.rekey.after_secs = 1;

    let mut initiator = make_hs_node(Config::new()).await;
    let mut responder = make_hs_node(config).await;

    // First handshake establishes the active peer.
    let msg3 = drive_to_msg3(&mut initiator, &mut responder, 1000).await;
    responder.node.handle_msg3(msg3).await;
    assert_eq!(responder.node.peer_count(), 1);
    let baseline = responder.node.index_allocator.count();
    assert_eq!(baseline, 1, "responder holds exactly the peer's index");

    // Age the session past the cross-connection bound so the duplicate inbound
    // msg3 resolves to ResendMsg2 rather than CrossConnect.
    let peer_addr =
        *PeerIdentity::from_pubkey_full(initiator.node.identity().pubkey_full()).node_addr();
    responder
        .node
        .get_peer_mut(&peer_addr)
        .unwrap()
        .test_backdate_session_established(std::time::Duration::from_secs(6));

    // Second (duplicate) handshake: fresh index allocated at msg1, then freed
    // on the ResendMsg2 arm.
    let msg3b = drive_to_msg3(&mut initiator, &mut responder, 2000).await;
    assert_eq!(
        responder.node.index_allocator.count(),
        baseline + 1,
        "second msg1 allocated a fresh index"
    );
    responder.node.handle_msg3(msg3b).await;

    assert_eq!(
        responder.node.index_allocator.count(),
        baseline,
        "ResendMsg2 must free the msg1-allocated index"
    );
    assert_eq!(responder.node.peer_count(), 1, "active peer untouched");
    // The duplicate leg's msg1-born machine goes with the leg; only the
    // established peer's machine remains.
    let peer_link = responder.node.get_peer(&peer_addr).unwrap().link_id();
    assert_eq!(responder.node.peer_machines.len(), 1);
    assert!(responder.node.peer_machines.contains_key(&peer_link));
    responder.node.debug_assert_peer_maps_coherent();
    assert!(
        responder
            .node
            .get_peer(&peer_addr)
            .unwrap()
            .pending_new_session()
            .is_none(),
        "duplicate-handshake arm must not store rekey-responder state"
    );

    stop_hs(&mut initiator).await;
    stop_hs(&mut responder).await;
}

// ===========================================================================
// Inbound machine lifecycle: every window leg carries a persistent machine
// from msg1 — parked `SentMsg2`, crystallized in place on promote, disposed
// with the leg on every terminating msg3 arm.
// ===========================================================================

#[tokio::test]
async fn test_inbound_machine_born_at_msg1_and_crystallized_at_promote() {
    use crate::peer::machine::{HandshakePhase, PeerState};

    let mut initiator = make_hs_node(Config::new()).await;
    let mut responder = make_hs_node(Config::new()).await;

    let msg3 = drive_to_msg3(&mut initiator, &mut responder, 1000).await;

    // After msg1 the responder's window leg carries a machine parked at
    // `SentMsg2`, seeded with the leg's msg1-allocated index.
    assert_eq!(responder.node.connection_count(), 1);
    let leg_link = responder.node.connections().next().unwrap().1.link_id();
    let leg_index = responder
        .node
        .peer_machines
        .get(&leg_link)
        .unwrap()
        .our_index();
    assert!(leg_index.is_some(), "msg1 allocated the leg index");
    {
        let machine = responder
            .node
            .peer_machines
            .get(&leg_link)
            .expect("window leg carries a machine from msg1");
        assert!(matches!(
            machine.state(),
            PeerState::Handshaking {
                phase: HandshakePhase::SentMsg2,
                ..
            }
        ));
        assert_eq!(machine.our_index(), leg_index);
    }
    responder.node.debug_assert_peer_maps_coherent();

    // msg3 promotes; the SAME machine survives and crystallizes in place.
    responder.node.handle_msg3(msg3).await;
    assert_eq!(responder.node.peer_count(), 1);
    let peer_addr =
        *PeerIdentity::from_pubkey_full(initiator.node.identity().pubkey_full()).node_addr();
    let peer = responder.node.get_peer(&peer_addr).unwrap();
    assert_eq!(peer.link_id(), leg_link, "promote keeps the leg's link");
    let peer_index = peer.our_index();
    assert_eq!(peer_index, leg_index, "promote keeps the msg1 index");
    let machine = responder
        .node
        .peer_machines
        .get(&leg_link)
        .expect("machine survives promotion");
    assert_eq!(machine.state(), PeerState::Established { addr: peer_addr });
    assert_eq!(machine.our_index(), peer_index);
    responder.node.debug_assert_peer_maps_coherent();

    // The initiator's dial-persisted machine crystallized in place too.
    let responder_addr =
        *PeerIdentity::from_pubkey_full(responder.node.identity().pubkey_full()).node_addr();
    let init_link = initiator.node.get_peer(&responder_addr).unwrap().link_id();
    let init_machine = initiator
        .node
        .peer_machines
        .get(&init_link)
        .expect("dial machine survives promotion");
    assert_eq!(
        init_machine.state(),
        PeerState::Established {
            addr: responder_addr
        }
    );
    initiator.node.debug_assert_peer_maps_coherent();

    stop_hs(&mut initiator).await;
    stop_hs(&mut responder).await;
}

#[tokio::test]
async fn test_msg3_crypto_fail_disposes_leg_machine() {
    let mut initiator = make_hs_node(Config::new()).await;
    let mut responder = make_hs_node(Config::new()).await;

    let mut msg3 = drive_to_msg3(&mut initiator, &mut responder, 1000).await;
    assert_eq!(responder.node.peer_machines.len(), 1, "msg1-born machine");
    assert_eq!(responder.node.index_allocator.count(), 1);

    // Corrupt the Noise payload so `complete_handshake_msg3` fails.
    let last = msg3.data.len() - 1;
    msg3.data[last] ^= 0xFF;
    responder.node.handle_msg3(msg3).await;

    assert_eq!(responder.node.peer_count(), 0, "no promotion");
    assert!(
        responder.node.connections().next().is_none(),
        "leg torn down"
    );
    assert!(
        responder.node.peer_machines.is_empty(),
        "crypto-fail teardown disposes the leg's machine"
    );
    assert_eq!(
        responder.node.index_allocator.count(),
        0,
        "msg1-allocated index returned"
    );
    responder.node.debug_assert_peer_maps_coherent();

    stop_hs(&mut initiator).await;
    stop_hs(&mut responder).await;
}

#[tokio::test]
async fn test_msg3_rekey_respond_disposes_leg_machine() {
    // Rekey enabled with a tiny interval so the rekey age floor collapses to
    // its 5s minimum; with the session backdated past it and NO rekey of our
    // own in flight, a fresh inbound msg3 classifies as rekey-responder.
    let mut config = Config::new();
    config.node.rekey.enabled = true;
    config.node.rekey.after_secs = 1;

    let mut initiator = make_hs_node(Config::new()).await;
    let mut responder = make_hs_node(config).await;

    // First handshake establishes the active peer (and its machine).
    let msg3 = drive_to_msg3(&mut initiator, &mut responder, 1000).await;
    responder.node.handle_msg3(msg3).await;
    assert_eq!(responder.node.peer_count(), 1);

    let peer_addr =
        *PeerIdentity::from_pubkey_full(initiator.node.identity().pubkey_full()).node_addr();
    responder
        .node
        .get_peer_mut(&peer_addr)
        .unwrap()
        .test_backdate_session_established(std::time::Duration::from_secs(6));

    // Second handshake lands on the rekey-responder arm: the pending session
    // moves onto the established peer; the window leg and its msg1-born
    // machine are consumed.
    let msg3b = drive_to_msg3(&mut initiator, &mut responder, 2000).await;
    responder.node.handle_msg3(msg3b).await;

    let peer = responder.node.get_peer(&peer_addr).unwrap();
    assert!(
        peer.pending_new_session().is_some(),
        "rekey-responder arm stores the pending session"
    );
    let peer_link = peer.link_id();
    assert_eq!(
        responder.node.peer_machines.len(),
        1,
        "the rekey window leg's machine is disposed with the leg"
    );
    assert!(responder.node.peer_machines.contains_key(&peer_link));
    responder.node.debug_assert_peer_maps_coherent();

    stop_hs(&mut initiator).await;
    stop_hs(&mut responder).await;
}

// ===========================================================================
// Anonymous-discovery outbound lifecycle: the leg's persistent machine is
// born identity-less at leg birth inside `start_handshake`, learns its
// identity from XX msg2 (crystallization), survives the promote, and is
// disposed with the leg when the dial turns out to target ourselves.
// ===========================================================================

#[tokio::test]
async fn test_anonymous_dial_births_identityless_machine_at_leg_birth() {
    use crate::peer::machine::PeerState;

    let mut initiator = make_hs_node(Config::new()).await;
    let responder = make_hs_node(Config::new()).await;

    // Anonymous dial (no peer identity): the connectionless path runs the
    // inline handshake, which creates the leg and its machine together.
    initiator
        .node
        .initiate_connection(initiator.transport_id, responder.addr.clone(), None)
        .await
        .expect("anonymous dial");

    assert_eq!(initiator.node.connection_count(), 1);
    let leg_link = initiator.node.connections().next().unwrap().1.link_id();
    let machine = initiator
        .node
        .peer_machines
        .get(&leg_link)
        .expect("anonymous leg carries a machine from leg birth");
    assert!(
        machine.identity().is_none(),
        "anonymous machine is born without an identity"
    );
    assert_eq!(
        machine.state(),
        PeerState::Discovered,
        "no event is dispatched on the inline dial path"
    );
    initiator.node.debug_assert_peer_maps_coherent();

    let mut initiator = initiator;
    let mut responder = responder;
    stop_hs(&mut initiator).await;
    stop_hs(&mut responder).await;
}

#[tokio::test]
async fn test_anonymous_msg2_crystallizes_identity_and_promotes() {
    use crate::peer::machine::PeerState;

    let mut initiator = make_hs_node(Config::new()).await;
    let mut responder = make_hs_node(Config::new()).await;

    initiator
        .node
        .initiate_connection(initiator.transport_id, responder.addr.clone(), None)
        .await
        .expect("anonymous dial");
    let leg_link = initiator.node.connections().next().unwrap().1.link_id();
    initiator.node.debug_assert_peer_maps_coherent();

    // Responder answers msg1 with msg2; the initiator's msg2 processing learns
    // who answered, crystallizes the identity onto the leg-born machine, and
    // promotes through it.
    let msg1_pkt = recv_phase(&mut responder.packet_rx, 1, "msg1").await;
    responder.node.handle_msg1(msg1_pkt).await;
    let msg2_pkt = recv_phase(&mut initiator.packet_rx, 2, "msg2").await;
    initiator.node.handle_msg2(msg2_pkt).await;

    let responder_identity =
        PeerIdentity::from_pubkey_full(responder.node.identity().pubkey_full());
    let responder_addr = *responder_identity.node_addr();
    assert_eq!(initiator.node.peer_count(), 1);
    let peer = initiator.node.get_peer(&responder_addr).expect("promoted");
    assert_eq!(peer.link_id(), leg_link, "promote keeps the leg's link");

    // The SAME machine survived the promote, with the learned identity and
    // the established state crystallized in place.
    let machine = initiator
        .node
        .peer_machines
        .get(&leg_link)
        .expect("machine survives the anonymous promote");
    assert_eq!(
        machine.identity().map(|id| *id.node_addr()),
        Some(responder_addr),
        "msg2 crystallized the learned identity onto the machine"
    );
    assert_eq!(
        machine.state(),
        PeerState::Established {
            addr: responder_addr
        }
    );
    initiator.node.debug_assert_peer_maps_coherent();

    // Complete the exchange so the responder promotes too, and both sides
    // stay coherent across the full anonymous establish path.
    let msg3_pkt = recv_phase(&mut responder.packet_rx, 3, "msg3").await;
    responder.node.handle_msg3(msg3_pkt).await;
    assert_eq!(responder.node.peer_count(), 1);
    responder.node.debug_assert_peer_maps_coherent();

    stop_hs(&mut initiator).await;
    stop_hs(&mut responder).await;
}

#[tokio::test]
async fn test_anonymous_self_connect_drop_disposes_machine() {
    let mut node = make_hs_node(Config::new()).await;
    let self_addr = node.addr.clone();

    // Anonymously dial our own bound address (a shared-media beacon can echo
    // ourselves back at us).
    node.node
        .initiate_connection(node.transport_id, self_addr, None)
        .await
        .expect("anonymous self dial");
    let leg_link = node.node.connections().next().unwrap().1.link_id();
    assert_eq!(node.node.peer_machines.len(), 1);

    // We answer our own msg1, then our msg2 processing discovers the learned
    // identity is our own and drops the leg — machine included.
    let msg1_pkt = recv_phase(&mut node.packet_rx, 1, "msg1").await;
    node.node.handle_msg1(msg1_pkt).await;
    let msg2_pkt = recv_phase(&mut node.packet_rx, 2, "msg2").await;
    node.node.handle_msg2(msg2_pkt).await;

    assert_eq!(node.node.peer_count(), 0, "no promotion");
    assert!(
        !node.node.has_pending_leg(&leg_link),
        "self-connect drop removes the outbound leg"
    );
    assert!(
        !node.node.peer_machines.contains_key(&leg_link),
        "self-connect drop disposes the outbound leg's machine"
    );
    node.node.debug_assert_peer_maps_coherent();

    stop_hs(&mut node).await;
}

// ===========================================================================
// Initiator rekey static-key continuity
//
// The rekey msg2 is dispatched to its peer by the session index the initiator
// itself allocated, and that index travels in the CLEARTEXT rekey msg1 header.
// Under XX the responder's static arrives in msg2 rather than being pinned at
// dial (as IK pinned it), so an on-path party that beats the real peer to the
// reply produces a perfectly valid handshake under its own static. The
// continuity gate is what stops that session from taking the peer's slot.
// ===========================================================================

/// Establish initiator↔responder, start a real rekey on the initiator, then
/// let a third node answer the rekey msg1 with a valid XX msg2 built from its
/// OWN static. The initiator must reject it and keep the established session
/// live and usable.
#[tokio::test]
async fn test_rekey_msg2_foreign_static_rejected() {
    let mut rekey_config = Config::new();
    rekey_config.node.rekey.enabled = true;
    rekey_config.node.rekey.after_secs = 1;

    let mut initiator = make_hs_node(rekey_config).await;
    let mut responder = make_hs_node(Config::new()).await;
    let mut attacker = make_hs_node(Config::new()).await;

    let responder_addr =
        *PeerIdentity::from_pubkey_full(responder.node.identity().pubkey_full()).node_addr();
    let initiator_addr =
        *PeerIdentity::from_pubkey_full(initiator.node.identity().pubkey_full()).node_addr();
    let attacker_addr =
        *PeerIdentity::from_pubkey_full(attacker.node.identity().pubkey_full()).node_addr();

    // Establish the link both ways.
    let msg3 = drive_to_msg3(&mut initiator, &mut responder, 1000).await;
    responder.node.handle_msg3(msg3).await;
    assert_eq!(initiator.node.peer_count(), 1);
    assert_eq!(responder.node.peer_count(), 1);

    // Record what the established session must still look like afterwards.
    let session_hash = *initiator
        .node
        .get_peer(&responder_addr)
        .unwrap()
        .noise_session()
        .unwrap()
        .handshake_hash();
    let peer_link = initiator.node.get_peer(&responder_addr).unwrap().link_id();

    // Age the session past the (jittered) rekey threshold and let the real
    // cadence fire, so the rekey msg1 and its index are produced exactly as in
    // production.
    initiator
        .node
        .get_peer_mut(&responder_addr)
        .unwrap()
        .test_backdate_session_established(std::time::Duration::from_secs(120));
    let baseline = initiator.node.index_allocator.count();
    initiator.node.check_rekey().await;
    let rekey_index = initiator
        .node
        .get_peer(&responder_addr)
        .unwrap()
        .rekey_our_index()
        .expect("cadence started a rekey");
    assert_eq!(
        initiator.node.index_allocator.count(),
        baseline + 1,
        "rekey allocated its own index"
    );

    // The attacker observes the cleartext rekey msg1 on path and answers it
    // first, under its own static. The real responder never sees it.
    let rekey_msg1 = recv_phase(&mut responder.packet_rx, 1, "rekey msg1").await;
    attacker.node.handle_msg1(rekey_msg1).await;
    let forged_msg2 = recv_phase(&mut initiator.packet_rx, 2, "forged rekey msg2").await;
    initiator.node.handle_msg2(forged_msg2).await;

    // The impostor never becomes (or displaces) a peer.
    assert_eq!(initiator.node.peer_count(), 1, "peer set unchanged");
    assert!(
        initiator.node.get_peer(&attacker_addr).is_none(),
        "impostor must not enter the peer set"
    );
    let peer = initiator.node.get_peer(&responder_addr).expect("kept");
    assert!(
        peer.pending_new_session().is_none(),
        "a foreign static must not be installed as the pending session"
    );
    assert!(
        !peer.rekey_in_progress(),
        "the rejected rekey cycle is abandoned"
    );
    assert_eq!(peer.link_id(), peer_link, "the peer keeps its link");

    // The established session is byte-for-byte the one we started with, still
    // bound to the real responder.
    assert_eq!(
        peer.noise_session().unwrap().handshake_hash(),
        &session_hash,
        "the established session was not replaced"
    );
    assert_eq!(
        peer.noise_session().unwrap().remote_static_xonly(),
        responder.node.identity().pubkey(),
        "the established session stays bound to the real peer"
    );

    // The rekey index is returned and its msg2 dispatch entry is gone, so a
    // late (or replayed) msg2 on that index cannot re-enter the dead cycle.
    assert_eq!(
        initiator.node.index_allocator.count(),
        baseline,
        "the rejected rekey must free its index"
    );
    assert!(
        !initiator
            .node
            .pending_outbound
            .contains_key(&(initiator.transport_id, rekey_index.as_u32())),
        "the rejected rekey's dispatch entry must not survive"
    );
    initiator.node.debug_assert_peer_maps_coherent();

    // ...and it is still usable: the initiator encrypts under the surviving
    // session and the real responder decrypts it.
    let probe = b"link still live after the rejected rekey";
    let counter = initiator
        .node
        .get_peer(&responder_addr)
        .unwrap()
        .noise_session()
        .unwrap()
        .current_send_counter();
    let ciphertext = initiator
        .node
        .get_peer_mut(&responder_addr)
        .unwrap()
        .noise_session_mut()
        .unwrap()
        .encrypt(probe)
        .expect("encrypt under the surviving session");
    let plaintext = responder
        .node
        .get_peer_mut(&initiator_addr)
        .unwrap()
        .noise_session_mut()
        .unwrap()
        .decrypt_with_replay_check(&ciphertext, counter)
        .expect("the peer still decrypts under the original session");
    assert_eq!(plaintext, probe);

    stop_hs(&mut initiator).await;
    stop_hs(&mut responder).await;
    stop_hs(&mut attacker).await;
}

/// The same cadence-driven rekey, answered by the REAL peer, still installs the
/// pending session — the gate must be invisible on the legitimate path.
#[tokio::test]
async fn test_rekey_msg2_matching_static_installs() {
    let mut rekey_config = Config::new();
    rekey_config.node.rekey.enabled = true;
    rekey_config.node.rekey.after_secs = 1;

    let mut initiator = make_hs_node(rekey_config).await;
    let mut responder = make_hs_node(Config::new()).await;

    let responder_addr =
        *PeerIdentity::from_pubkey_full(responder.node.identity().pubkey_full()).node_addr();

    let msg3 = drive_to_msg3(&mut initiator, &mut responder, 1000).await;
    responder.node.handle_msg3(msg3).await;
    assert_eq!(initiator.node.peer_count(), 1);

    initiator
        .node
        .get_peer_mut(&responder_addr)
        .unwrap()
        .test_backdate_session_established(std::time::Duration::from_secs(120));
    initiator.node.check_rekey().await;
    let rekey_index = initiator
        .node
        .get_peer(&responder_addr)
        .unwrap()
        .rekey_our_index()
        .expect("cadence started a rekey");

    // The real peer answers its own rekey msg1.
    let rekey_msg1 = recv_phase(&mut responder.packet_rx, 1, "rekey msg1").await;
    responder.node.handle_msg1(rekey_msg1).await;
    let rekey_msg2 = recv_phase(&mut initiator.packet_rx, 2, "rekey msg2").await;
    initiator.node.handle_msg2(rekey_msg2).await;

    let peer = initiator.node.get_peer(&responder_addr).expect("kept");
    assert!(
        peer.pending_new_session().is_some(),
        "a matching static installs the pending session"
    );
    assert_eq!(
        peer.pending_new_session().unwrap().remote_static_xonly(),
        responder.node.identity().pubkey(),
        "the pending session is bound to the real peer"
    );
    assert!(
        initiator
            .node
            .peers_by_index
            .contains_key(&(initiator.transport_id, rekey_index.as_u32())),
        "the rekey index maps to the peer, awaiting K-bit cutover"
    );
    initiator.node.debug_assert_peer_maps_coherent();

    stop_hs(&mut initiator).await;
    stop_hs(&mut responder).await;
}

// ===========================================================================
// Initiator dial-identity pinning (initial outbound handshake)
//
// The rekey gate above protects a link that is already established; this one
// protects the link being formed, and needs no rekey to reach. Under XX the
// responder's static arrives in msg2 rather than being pinned at dial (as IK
// pinned it), so an on-path party that observes our msg1 and answers it first
// produces a perfectly valid handshake under its own static. The dial-identity
// gate is what stops that leg from being promoted as the peer we dialed.
//
// The three cases below are the whole decision surface: a named dial answered
// by a stranger (reject), a named dial answered by its peer (promote), and an
// anonymous dial, which names nobody and so must still promote whoever answers
// - the carve-out that keeps shared-media discovery working.
// ===========================================================================

/// A named dial answered by a foreign static must not promote, and must leave
/// no residue behind: no machine, no leg, no link, no `pending_outbound`
/// dispatch entry, and no orphaned session index.
#[tokio::test]
async fn test_dial_msg2_foreign_static_rejected() {
    use std::time::Duration;
    use tokio::time::timeout;

    let mut initiator = make_hs_node(Config::new()).await;
    let mut intended = make_hs_node(Config::new()).await;
    let mut attacker = make_hs_node(Config::new()).await;

    let intended_identity = PeerIdentity::from_pubkey_full(intended.node.identity().pubkey_full());
    let intended_addr = *intended_identity.node_addr();
    let attacker_addr =
        *PeerIdentity::from_pubkey_full(attacker.node.identity().pubkey_full()).node_addr();
    assert_ne!(intended_addr, attacker_addr);

    let baseline = initiator.node.index_allocator.count();

    // A named dial whose msg1 reaches the attacker instead of the peer. From
    // the initiator's side this is indistinguishable from an on-path party
    // racing the real responder's msg2, and it is the same thing the code sees.
    initiator
        .node
        .initiate_connection(
            initiator.transport_id,
            attacker.addr.clone(),
            Some(intended_identity),
        )
        .await
        .expect("named dial");

    let leg_link = initiator.node.connections().next().unwrap().1.link_id();
    let leg_index = initiator
        .node
        .peer_machines
        .get(&leg_link)
        .unwrap()
        .our_index()
        .expect("msg1 preparation allocated our index");
    assert_eq!(
        initiator.node.index_allocator.count(),
        baseline + 1,
        "the dial allocated its own index"
    );

    // The attacker answers the dial with a valid XX msg2 under its own static.
    let msg1 = recv_phase(&mut attacker.packet_rx, 1, "msg1").await;
    attacker.node.handle_msg1(msg1).await;
    let forged_msg2 = recv_phase(&mut initiator.packet_rx, 2, "forged msg2").await;
    initiator.node.handle_msg2(forged_msg2).await;

    // Nothing is promoted - not the impostor, and not the peer we dialed
    // (whose identity never authenticated anything here).
    assert_eq!(initiator.node.peer_count(), 0, "no promotion");
    assert!(
        initiator.node.get_peer(&attacker_addr).is_none(),
        "the impostor must not enter the peer set"
    );
    assert!(
        initiator.node.get_peer(&intended_addr).is_none(),
        "the dialed peer must not be credited with a handshake it never ran"
    );

    // No registry residue: the leg, its machine, its link, its dispatch entry
    // and its index are all gone.
    assert!(
        !initiator.node.has_pending_leg(&leg_link),
        "the rejected leg is torn down"
    );
    assert!(
        !initiator.node.peer_machines.contains_key(&leg_link),
        "the rejected leg's machine is disposed"
    );
    assert!(
        !initiator.node.links.contains_key(&leg_link),
        "the rejected leg's link is removed"
    );
    assert!(
        !initiator
            .node
            .pending_outbound
            .contains_key(&(initiator.transport_id, leg_index.as_u32())),
        "the rejected leg's dispatch entry must not survive, or a replayed \
         msg2 could re-enter the dead leg"
    );
    assert_eq!(
        initiator.node.index_allocator.count(),
        baseline,
        "the rejected dial must free the index it allocated"
    );
    initiator.node.debug_assert_peer_maps_coherent();

    // The gate sits ahead of the msg3 send, so the impostor's handshake is
    // never completed: it is left waiting on a msg3 that never comes.
    assert!(
        timeout(Duration::from_millis(250), attacker.packet_rx.recv())
            .await
            .is_err(),
        "no msg3 may be sent to a responder that substituted its identity"
    );
    assert_eq!(
        attacker.node.peer_count(),
        0,
        "the impostor never completes its own side either"
    );

    stop_hs(&mut initiator).await;
    stop_hs(&mut intended).await;
    stop_hs(&mut attacker).await;
}

/// The rejected dial must stay on the dial schedule. Disposing the leg takes it
/// out of both reapers, so the handshake-timeout sweep that normally reschedules
/// a stuck outbound dial never sees it; the reject arm has to fire that reflex
/// itself. Without it a configured peer is dialed once at startup and, after one
/// substituted msg2, never again for the life of the process - a persistent
/// outbound blackhole costing the attacker a single packet. The retry must also
/// name the peer we dialed, not the static that answered.
#[tokio::test]
async fn test_dial_msg2_foreign_static_reschedules_dial() {
    let intended_local = Identity::generate();
    let intended_identity =
        PeerIdentity::from_npub(&intended_local.npub()).expect("generated npub parses");
    let intended_addr = *intended_identity.node_addr();

    let mut attacker = make_hs_node(Config::new()).await;
    let attacker_addr =
        *PeerIdentity::from_pubkey_full(attacker.node.identity().pubkey_full()).node_addr();
    assert_ne!(intended_addr, attacker_addr);

    // The dialed peer is a configured auto-connect peer: that is the only
    // shape the retry machinery will seed a schedule entry for, and it is the
    // shape the blackhole strands.
    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        intended_local.npub(),
        "udp",
        "10.0.0.2:2121",
    ));
    let mut initiator = make_hs_node(config).await;

    assert!(
        initiator.node.peering.reconciler.retry_pending.is_empty(),
        "nothing is scheduled before the dial"
    );

    initiator
        .node
        .initiate_connection(
            initiator.transport_id,
            attacker.addr.clone(),
            Some(intended_identity),
        )
        .await
        .expect("named dial");

    let msg1 = recv_phase(&mut attacker.packet_rx, 1, "msg1").await;
    attacker.node.handle_msg1(msg1).await;
    let forged_msg2 = recv_phase(&mut initiator.packet_rx, 2, "forged msg2").await;
    initiator.node.handle_msg2(forged_msg2).await;

    assert_eq!(initiator.node.peer_count(), 0, "no promotion");
    assert!(
        initiator
            .node
            .peering
            .reconciler
            .retry_pending
            .contains_key(&intended_addr),
        "the rejected dial must leave the peer we dialed scheduled for retry, \
         or the configured peer is never dialed again"
    );
    assert!(
        !initiator
            .node
            .peering
            .reconciler
            .retry_pending
            .contains_key(&attacker_addr),
        "the retry must name the peer we dialed, never the static that answered"
    );

    stop_hs(&mut initiator).await;
    stop_hs(&mut attacker).await;
}

/// The same named dial, answered by the peer it named, still promotes - the
/// gate must be invisible on the legitimate path.
#[tokio::test]
async fn test_dial_msg2_matching_static_promotes() {
    let mut initiator = make_hs_node(Config::new()).await;
    let mut responder = make_hs_node(Config::new()).await;

    let responder_identity =
        PeerIdentity::from_pubkey_full(responder.node.identity().pubkey_full());
    let responder_addr = *responder_identity.node_addr();

    initiator
        .node
        .initiate_connection(
            initiator.transport_id,
            responder.addr.clone(),
            Some(responder_identity),
        )
        .await
        .expect("named dial");
    let leg_link = initiator.node.connections().next().unwrap().1.link_id();

    let msg1 = recv_phase(&mut responder.packet_rx, 1, "msg1").await;
    responder.node.handle_msg1(msg1).await;
    let msg2 = recv_phase(&mut initiator.packet_rx, 2, "msg2").await;
    initiator.node.handle_msg2(msg2).await;

    assert_eq!(initiator.node.peer_count(), 1);
    let peer = initiator.node.get_peer(&responder_addr).expect("promoted");
    assert_eq!(peer.link_id(), leg_link, "promote keeps the leg's link");
    initiator.node.debug_assert_peer_maps_coherent();

    // The responder completes its own side from the msg3 the gate let through.
    let msg3 = recv_phase(&mut responder.packet_rx, 3, "msg3").await;
    responder.node.handle_msg3(msg3).await;
    assert_eq!(responder.node.peer_count(), 1);
    responder.node.debug_assert_peer_maps_coherent();

    stop_hs(&mut initiator).await;
    stop_hs(&mut responder).await;
}

/// The anonymous carve-out. A shared-media dial names nobody, so the msg2
/// static is the ONLY identity the leg will ever have and there is no intent
/// for it to contradict - it must promote exactly as before. A gate that
/// pinned the wrong thing (or pinned unconditionally) stops anonymous
/// discovery promoting anything at all, and this is where that shows up.
///
/// Whether a leg is anonymous is settled here, at construction, from what the
/// caller passed - never from anything on the wire - so no responder can steer
/// a named dial onto this path.
#[tokio::test]
async fn test_anonymous_dial_msg2_promotes_whoever_answers() {
    let mut initiator = make_hs_node(Config::new()).await;
    let mut responder = make_hs_node(Config::new()).await;

    let responder_addr =
        *PeerIdentity::from_pubkey_full(responder.node.identity().pubkey_full()).node_addr();

    initiator
        .node
        .initiate_connection(initiator.transport_id, responder.addr.clone(), None)
        .await
        .expect("anonymous dial");
    let leg_link = initiator.node.connections().next().unwrap().1.link_id();
    assert_eq!(
        initiator
            .node
            .peer_machines
            .get(&leg_link)
            .unwrap()
            .conn_dialed_identity(),
        None,
        "an anonymous dial records no dial intent, which is what selects the \
         no-comparison branch"
    );

    let msg1 = recv_phase(&mut responder.packet_rx, 1, "msg1").await;
    responder.node.handle_msg1(msg1).await;
    let msg2 = recv_phase(&mut initiator.packet_rx, 2, "msg2").await;
    initiator.node.handle_msg2(msg2).await;

    assert_eq!(
        initiator.node.peer_count(),
        1,
        "an anonymous dial promotes whoever answered it"
    );
    let peer = initiator.node.get_peer(&responder_addr).expect("promoted");
    assert_eq!(peer.link_id(), leg_link);
    initiator.node.debug_assert_peer_maps_coherent();

    let msg3 = recv_phase(&mut responder.packet_rx, 3, "msg3").await;
    responder.node.handle_msg3(msg3).await;
    assert_eq!(responder.node.peer_count(), 1);

    stop_hs(&mut initiator).await;
    stop_hs(&mut responder).await;
}
