//! Integration tests for bootstrap handoff into the FIPS node.

use super::*;
use crate::EstablishedTraversal;
use crate::config::UdpConfig;
use crate::node::wire::{PHASE_MSG1, PHASE_MSG2};
use crate::transport::udp::UdpTransport;
use crate::utils::index::IndexAllocator;
use tokio::time::{Duration, timeout, timeout_at};

#[ignore = "needs XX-handshake adaptation: peer promotion now happens at msg3, not msg1; test runs only two rx_loop iterations"]
#[tokio::test]
async fn test_adopted_udp_traversal_completes_handshake() {
    let mut node_a = make_node();
    let mut node_b = make_node();

    let transport_id_b = TransportId::new(1);
    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };

    let (packet_tx_a, packet_rx_a) = packet_channel(64);
    let (packet_tx_b, packet_rx_b) = packet_channel(64);

    node_a.packet_tx = Some(packet_tx_a.clone());
    node_a.packet_rx = Some(packet_rx_a);
    node_a.state = NodeState::Running;

    let mut transport_b = UdpTransport::new(transport_id_b, None, udp_config, packet_tx_b.clone());
    transport_b.start_async().await.unwrap();

    let addr_b = transport_b.local_addr().unwrap();
    node_b.packet_tx = Some(packet_tx_b.clone());
    node_b.packet_rx = Some(packet_rx_b);
    node_b.state = NodeState::Running;
    node_b
        .transports
        .insert(transport_id_b, TransportHandle::Udp(transport_b));

    let adopted_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let handoff = EstablishedTraversal::new("sess-1", node_b.npub(), addr_b, adopted_socket)
        .with_transport_name("nostr-punched");

    let result = node_a.adopt_established_traversal(handoff).await.unwrap();
    assert_eq!(result.remote_addr, addr_b);
    assert!(node_a.get_transport(&result.transport_id).is_some());

    tokio::select! {
        result = node_b.run_rx_loop() => {
            panic!("node_b rx loop exited unexpectedly: {:?}", result);
        }
        _ = tokio::time::sleep(Duration::from_millis(500)) => {}
    }

    tokio::select! {
        result = node_a.run_rx_loop() => {
            panic!("node_a rx loop exited unexpectedly: {:?}", result);
        }
        _ = tokio::time::sleep(Duration::from_millis(500)) => {}
    }

    let peer_a_node_addr =
        *PeerIdentity::from_pubkey_full(node_a.identity.pubkey_full()).node_addr();
    let peer_b_node_addr =
        *PeerIdentity::from_pubkey_full(node_b.identity.pubkey_full()).node_addr();

    assert_eq!(
        node_a.peer_count(),
        1,
        "node_a should promote node_b after handoff"
    );
    assert_eq!(
        node_b.peer_count(),
        1,
        "node_b should promote node_a after receiving msg1"
    );
    assert!(node_a.get_peer(&peer_b_node_addr).unwrap().has_session());
    assert!(node_b.get_peer(&peer_a_node_addr).unwrap().has_session());

    for (_, transport) in node_a.transports.iter_mut() {
        transport.stop().await.ok();
    }
    for (_, transport) in node_b.transports.iter_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_failed_adopted_traversal_cleans_up_transport() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);
    node.state = NodeState::Running;
    node.index_allocator = IndexAllocator::with_max_attempts(0);

    let peer = make_node();
    let adopted_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let handoff = EstablishedTraversal::new(
        "sess-fail",
        peer.npub(),
        "127.0.0.1:9".parse().unwrap(),
        adopted_socket,
    )
    .with_transport_name("nostr-punched");

    let result = node.adopt_established_traversal(handoff).await;
    assert!(
        result.is_err(),
        "handoff should fail when handshake setup cannot allocate a session index"
    );
    assert!(
        node.transports.is_empty(),
        "failed handoff should remove the adopted transport"
    );
}

#[ignore = "needs XX-handshake adaptation: peer promotion now happens at msg3, not msg1; test runs only two rx_loop iterations"]
#[tokio::test]
async fn test_third_peer_can_handshake_via_adopted_transport_socket() {
    let mut node_a = make_node(); // Existing traversal peer (Alice)
    let mut node_b = make_node(); // Node with adopted socket (Bob)
    let mut node_c = make_node(); // New peer onboarding via Bob socket (Colin)

    let transport_id_a = TransportId::new(1);
    let transport_id_c = TransportId::new(1);
    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };

    let (packet_tx_a, packet_rx_a) = packet_channel(64);
    let (packet_tx_b, packet_rx_b) = packet_channel(64);
    let (packet_tx_c, packet_rx_c) = packet_channel(64);

    node_a.packet_tx = Some(packet_tx_a.clone());
    node_a.packet_rx = Some(packet_rx_a);
    node_a.state = NodeState::Running;

    node_b.packet_tx = Some(packet_tx_b.clone());
    node_b.packet_rx = Some(packet_rx_b);
    node_b.state = NodeState::Running;

    node_c.packet_tx = Some(packet_tx_c.clone());
    node_c.packet_rx = Some(packet_rx_c);
    node_c.state = NodeState::Running;

    let mut transport_a = UdpTransport::new(transport_id_a, None, udp_config.clone(), packet_tx_a);
    transport_a.start_async().await.unwrap();
    let addr_a = transport_a.local_addr().unwrap();
    node_a
        .transports
        .insert(transport_id_a, TransportHandle::Udp(transport_a));

    // Bob adopts a traversal socket already "established" to Alice.
    let adopted_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let handoff = EstablishedTraversal::new("sess-existing", node_a.npub(), addr_a, adopted_socket)
        .with_transport_name("nostr-nat");
    let handoff_result = node_b.adopt_established_traversal(handoff).await.unwrap();

    // Drive Alice/Bob handshake manually (msg1 -> msg2).
    let mut rx_a = node_a.packet_rx.take().expect("node_a packet_rx");
    let mut rx_b = node_b.packet_rx.take().expect("node_b packet_rx");

    let pkt_at_a = timeout(Duration::from_secs(1), rx_a.recv())
        .await
        .expect("timeout waiting for Bob->Alice msg1")
        .expect("node_a channel closed");
    assert_eq!(pkt_at_a.data[0] & 0x0f, PHASE_MSG1);
    node_a.handle_msg1(pkt_at_a).await;

    let pkt_at_b = timeout(Duration::from_secs(1), rx_b.recv())
        .await
        .expect("timeout waiting for Alice->Bob msg2")
        .expect("node_b channel closed");
    assert_eq!(pkt_at_b.data[0] & 0x0f, PHASE_MSG2);
    node_b.handle_msg2(pkt_at_b).await;

    let node_a_addr = *PeerIdentity::from_pubkey_full(node_a.identity.pubkey_full()).node_addr();
    assert!(
        node_b.get_peer(&node_a_addr).is_some(),
        "node_b should first be connected to node_a via adopted transport"
    );

    // Start Colin UDP transport and connect to Bob's adopted socket address.
    let mut transport_c = UdpTransport::new(transport_id_c, None, udp_config, packet_tx_c);
    transport_c.start_async().await.unwrap();
    let addr_c = transport_c.local_addr().unwrap();
    node_c
        .transports
        .insert(transport_id_c, TransportHandle::Udp(transport_c));

    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity.pubkey_full());
    let adopted_addr = TransportAddr::from_string(&handoff_result.local_addr.to_string());
    node_c
        .initiate_connection(transport_id_c, adopted_addr, Some(peer_b_identity))
        .await
        .unwrap();

    // Drive Bob/Colin handshake manually (msg1 -> msg2).
    let mut rx_c = node_c.packet_rx.take().expect("node_c packet_rx");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let pkt_at_b = loop {
        let pkt = timeout_at(deadline, rx_b.recv())
            .await
            .expect("timeout waiting for Colin->Bob msg1")
            .expect("node_b channel closed");
        if pkt.remote_addr.as_str() == Some(&addr_c.to_string())
            && pkt.data.first().map(|b| b & 0x0f) == Some(PHASE_MSG1)
        {
            break pkt;
        }
    };
    node_b.handle_msg1(pkt_at_b).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let pkt_at_c = loop {
        let pkt = timeout_at(deadline, rx_c.recv())
            .await
            .expect("timeout waiting for Bob->Colin msg2")
            .expect("node_c channel closed");
        if pkt.data.first().map(|b| b & 0x0f) == Some(PHASE_MSG2) {
            break pkt;
        }
    };
    node_c.handle_msg2(pkt_at_c).await;

    let node_c_addr = *PeerIdentity::from_pubkey_full(node_c.identity.pubkey_full()).node_addr();
    assert!(
        node_b.get_peer(&node_c_addr).is_some(),
        "node_b should promote node_c when node_c handshakes via adopted socket"
    );

    for (_, transport) in node_a.transports.iter_mut() {
        transport.stop().await.ok();
    }
    for (_, transport) in node_b.transports.iter_mut() {
        transport.stop().await.ok();
    }
    for (_, transport) in node_c.transports.iter_mut() {
        transport.stop().await.ok();
    }
}
