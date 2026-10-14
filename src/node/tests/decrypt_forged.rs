//! Forged frames on a live peer's receiver index.
//!
//! An established frame is matched to its peer by transport and receiver
//! index alone, and the receiver index travels in clear. These tests send
//! frames that carry a live peer's index but do not authenticate, from an
//! address that is not the peer's, and assert the peer is kept on each path
//! a frame can take to the failure count: the inline decrypt, the decrypt
//! worker, and a second TCP connection to a node holding the peer over TCP.
//! A last test checks the forged frames do not keep a dead link alive.
//!
//! Every forged frame enters through `process_packet`, the real entry point,
//! and declares the payload length its size implies, so the framing check
//! passes it to the encrypted-frame handler. Each test asserts no frame was
//! dropped as a framing mismatch, so a framing drop cannot pass for a result.

use super::*;
use crate::node::tests::spanning_tree::{
    TestNode, cleanup_nodes, drain_all_packets, initiate_handshake, make_test_node_with_config,
};
use crate::noise::TAG_SIZE;
use crate::proto::fmp::wire::{build_encrypted, build_established_header};
use crate::proto::link::LinkMessageType;
use rand::Rng;

/// Threshold constant in node/dataplane/encrypted.rs (kept in sync with
/// production code; see DECRYPT_FAILURE_THRESHOLD).
const THRESHOLD: u32 = 20;

/// Forged frames each test sends, past the threshold with margin.
const FORGED: u32 = 25;

/// Inner plaintext length the forged frames declare.
const BODY: usize = 40;

/// A first counter above any the session under test has used.
const FIRST_COUNTER: u64 = 1_000_000;

/// A correctly framed established frame on `index` whose ciphertext is
/// random, so it fails the AEAD tag on every session.
fn forged_frame(index: SessionIndex, counter: u64) -> Vec<u8> {
    let mut body = vec![0u8; BODY + TAG_SIZE];
    rand::rng().fill_bytes(&mut body);
    build_encrypted(
        &build_established_header(index, counter, 0, BODY as u16),
        &body,
    )
}

/// An address on the loopback transport that no node holds.
fn foreign_addr() -> TransportAddr {
    TransportAddr::from_string("loopback:forger")
}

/// Two loopback nodes peered over FMP, node 0 dialling node 1. Node 1 is not
/// started, so it has no decrypt worker pool and decrypts inline.
async fn linked_pair(cfg1: crate::config::Config) -> Vec<TestNode> {
    let mut nodes = vec![
        make_test_node_with_config(crate::config::Config::new(), 1280).await,
        make_test_node_with_config(cfg1, 1280).await,
    ];
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let addr0 = *nodes[0].node.node_addr();
    let addr1 = *nodes[1].node.node_addr();
    assert!(
        nodes[0].node.get_peer(&addr1).is_some() && nodes[1].node.get_peer(&addr0).is_some(),
        "precondition: the pair is peered"
    );
    nodes
}

/// The receiver index node 1 holds for node 0, which node 0's frames carry.
fn index_at_1(nodes: &[TestNode]) -> SessionIndex {
    let addr0 = *nodes[0].node.node_addr();
    nodes[1]
        .node
        .get_peer(&addr0)
        .and_then(|p| p.our_index())
        .expect("node 1 holds an index for node 0")
}

/// Assert no frame `node` received was dropped as a framing mismatch.
fn assert_no_framing_drop(node: &Node) {
    assert_eq!(
        node.stats().transport.payload_len_mismatch,
        0,
        "a forged frame was dropped by the framing check, not the decrypt"
    );
}

/// Forged frames on a live peer's index, decrypted inline, leave the peer
/// established, and the link still authenticates afterwards.
#[tokio::test]
async fn twenty_five_forged_frames_on_a_live_peers_index_from_another_address_leave_the_peer_established()
 {
    let mut nodes = linked_pair(crate::config::Config::new()).await;
    let addr0 = *nodes[0].node.node_addr();
    let addr1 = *nodes[1].node.node_addr();
    let index = index_at_1(&nodes);
    let key = index.as_u32();
    // Windows has no decrypt worker pool, so it always decrypts inline.
    #[cfg(unix)]
    assert!(
        nodes[1].node.supervisor.decrypt_workers.is_none(),
        "precondition: node 1 decrypts inline"
    );
    assert_eq!(
        nodes[1]
            .node
            .get_peer(&addr0)
            .unwrap()
            .consecutive_decrypt_failures(),
        0,
        "precondition: no failures yet"
    );

    for n in 1..=FORGED {
        let frame = forged_frame(index, FIRST_COUNTER + u64::from(n));
        let packet = ReceivedPacket::new(nodes[1].transport_id, foreign_addr(), frame);
        nodes[1].node.process_packet(packet).await;

        let peer = nodes[1]
            .node
            .get_peer(&addr0)
            .unwrap_or_else(|| panic!("node 0 is still a peer after forged frame {n}"));
        assert_eq!(
            peer.consecutive_decrypt_failures(),
            n,
            "each forged frame counts one failure"
        );
        assert_eq!(
            nodes[1].node.peers_by_index.get(&key),
            Some(&addr0),
            "the index still maps to node 0 after forged frame {n}"
        );
    }
    assert_no_framing_drop(&nodes[1].node);

    // The real peer's next frame still authenticates and clears the count.
    nodes[0]
        .node
        .send_encrypted_link_message(&addr1, &[LinkMessageType::Heartbeat.to_byte()])
        .await
        .expect("heartbeat send");
    let mut delivered = 0;
    while let Ok(packet) = nodes[1].packet_rx.try_recv() {
        nodes[1].node.process_packet(packet).await;
        delivered += 1;
    }
    assert!(delivered >= 1, "the heartbeat reached node 1");
    let peer = nodes[1]
        .node
        .get_peer(&addr0)
        .expect("node 0 is still a peer after its heartbeat");
    assert_eq!(
        peer.consecutive_decrypt_failures(),
        0,
        "an authenticated frame resets the failure count"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Forged frames that fail in the decrypt worker, the path a deployed Unix
/// node takes, leave the peer established.
#[cfg(unix)]
#[tokio::test]
async fn twenty_five_forged_frames_failing_in_the_decrypt_worker_leave_the_peer_established() {
    use crate::node::decrypt_worker::{DecryptWorkerEvent, DecryptWorkerPool};

    let mut nodes = linked_pair(crate::config::Config::new()).await;
    let addr0 = *nodes[0].node.node_addr();
    let index = index_at_1(&nodes);

    nodes[1].node.supervisor.decrypt_workers = Some(DecryptWorkerPool::spawn(1));
    nodes[1].node.register_decrypt_worker_session(&addr0);
    assert!(
        nodes[1]
            .node
            .decrypt_registered_sessions
            .contains(&index.as_u32()),
        "precondition: node 0's session is registered with the worker"
    );
    let mut events = nodes[1]
        .node
        .decrypt_fallback_rx
        .take()
        .expect("node 1 holds its worker event receiver");

    // All frames are queued on the worker before any report is handled, so
    // every one reaches the worker whatever the reports do to the peer.
    for n in 1..=FORGED {
        let frame = forged_frame(index, FIRST_COUNTER + u64::from(n));
        let packet = ReceivedPacket::new(nodes[1].transport_id, foreign_addr(), frame);
        nodes[1].node.process_packet(packet).await;
    }
    assert_no_framing_drop(&nodes[1].node);

    let mut failures = 0;
    for n in 1..=FORGED {
        let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .unwrap_or_else(|_| panic!("worker event {n} never arrived"))
            .expect("worker event channel closed");
        if matches!(event, DecryptWorkerEvent::DecryptFailure(_)) {
            failures += 1;
        }
        nodes[1].node.process_decrypt_worker_event(event).await;
    }
    assert_eq!(
        failures, FORGED,
        "the worker reported every forged frame as a decrypt failure"
    );

    let peer = nodes[1]
        .node
        .get_peer(&addr0)
        .expect("node 0 is still a peer after the worker's failure reports");
    assert_eq!(peer.consecutive_decrypt_failures(), FORGED);

    cleanup_nodes(&mut nodes).await;
}

/// The TCP transport's id on the node built by `node_with_tcp`.
const TCP_ID: u32 = 2;

/// A node with one TCP transport listening on loopback and feeding the
/// node's packet channel, as a node built from config has.
async fn node_with_tcp() -> Node {
    use crate::config::TcpConfig;
    use crate::transport::TransportHandle;
    use crate::transport::tcp::TcpTransport;

    let mut node = make_node();
    let (tx, rx) = packet_channel(1024);
    let tcp_cfg = TcpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1400),
        ..Default::default()
    };
    let mut tcp = TcpTransport::new(TransportId::new(TCP_ID), None, tcp_cfg, tx);
    tcp.start_async().await.unwrap();
    node.transports
        .insert(TransportId::new(TCP_ID), TransportHandle::Tcp(tcp));
    node.packet_rx = Some(rx);
    node.supervisor.state = NodeState::Running;
    node
}

/// The next frame the node's TCP transport delivered.
async fn next_tcp_packet(node: &mut Node) -> ReceivedPacket {
    let rx = node.packet_rx.as_mut().expect("packet channel");
    let packet = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("frame never reached the packet channel")
        .expect("packet channel closed");
    assert_eq!(packet.transport_id, TransportId::new(TCP_ID));
    packet
}

/// Forged frames written on a second TCP connection to a node that holds the
/// peer over TCP leave the peer established at its own connection.
#[tokio::test]
async fn twenty_five_forged_frames_on_a_second_tcp_connection_leave_a_tcp_held_peer_established() {
    use crate::proto::fmp::wire::build_msg1;
    use tokio::io::AsyncWriteExt;

    let mut node = node_with_tcp().await;
    let listen = node
        .transports
        .get(&TransportId::new(TCP_ID))
        .and_then(|t| t.local_addr())
        .expect("TCP listener bound");

    // The peer dials in and sends a genuine msg1.
    let sender = Identity::generate();
    let peer_addr = *PeerIdentity::from_pubkey_full(sender.pubkey_full()).node_addr();
    let target = PeerIdentity::from_pubkey_full(node.identity().pubkey_full());
    let mut leg = outbound_leg(LinkId::new(0x5EED), target, 1000);
    let noise_msg1 = leg
        .start_handshake(sender.keypair(), [7u8; 8], 1000)
        .expect("start_handshake produces noise msg1");
    let mut peer_conn = tokio::net::TcpStream::connect(listen).await.unwrap();
    peer_conn
        .write_all(&build_msg1(SessionIndex::new(0x51), &noise_msg1))
        .await
        .unwrap();
    let msg1 = next_tcp_packet(&mut node).await;
    let peer_remote = msg1.remote_addr.clone();
    node.process_packet(msg1).await;

    let index = {
        let peer = node
            .get_peer(&peer_addr)
            .expect("precondition: the msg1 promoted the peer");
        assert_eq!(peer.current_addr(), Some(&peer_remote));
        peer.our_index().expect("the peer has a receiver index")
    };

    // A second connection, not the peer's, writes frames on its index.
    let mut forger = tokio::net::TcpStream::connect(listen).await.unwrap();
    for n in 1..=FORGED {
        forger
            .write_all(&forged_frame(index, FIRST_COUNTER + u64::from(n)))
            .await
            .unwrap();
        let packet = next_tcp_packet(&mut node).await;
        assert_ne!(
            packet.remote_addr, peer_remote,
            "the forged frame arrived on the second connection"
        );
        node.process_packet(packet).await;
    }
    assert_no_framing_drop(&node);

    let peer = node
        .get_peer(&peer_addr)
        .expect("the TCP-held peer is still a peer after the forged frames");
    assert_eq!(peer.current_addr(), Some(&peer_remote));
    assert_eq!(peer.consecutive_decrypt_failures(), FORGED);

    for (_, t) in node.transports.iter_mut() {
        t.stop().await.ok();
    }
    drop(peer_conn);
}

/// Forged frames on a silent link do not count as liveness: the link-dead
/// timeout still reaps the peer.
#[tokio::test]
async fn forged_frames_do_not_hold_a_dead_link_alive() {
    let mut nodes = linked_pair(crate::config::Config::new()).await;
    // Set after construction: a 1 s timeout fails config validation against
    // the default medium-change debounce.
    super::heartbeat::set_link_dead_timeout(&mut nodes[1].node, 1);
    let addr0 = *nodes[0].node.node_addr();
    let index = index_at_1(&nodes);

    tokio::time::sleep(Duration::from_millis(1_200)).await;

    // Below the threshold, so no build removes the peer for that reason.
    for n in 1..THRESHOLD {
        let frame = forged_frame(index, FIRST_COUNTER + u64::from(n));
        let packet = ReceivedPacket::new(nodes[1].transport_id, foreign_addr(), frame);
        nodes[1].node.process_packet(packet).await;
    }
    assert_no_framing_drop(&nodes[1].node);
    assert_eq!(
        nodes[1]
            .node
            .get_peer(&addr0)
            .expect("precondition: the forged frames alone do not remove the peer")
            .consecutive_decrypt_failures(),
        THRESHOLD - 1,
        "precondition: every forged frame reached the decrypt"
    );

    nodes[1].node.check_link_heartbeats().await;
    assert!(
        nodes[1].node.get_peer(&addr0).is_none(),
        "the link-dead timeout reaps a peer heard from only by forged frames"
    );

    cleanup_nodes(&mut nodes).await;
}
