//! Per-peer connected UDP sockets against the in-line decrypt path.
//!
//! A `connect(2)`-ed UDP socket is pinned to one 5-tuple. When the peer
//! moves, the address the socket was opened against is gone, but the
//! socket is still installed and the send path prefers it over the
//! wildcard listen socket. `ActivePeer::set_current_addr` returns
//! whether the address actually changed precisely so the caller can
//! drop the stale socket, and both post-decrypt paths have to act on
//! that return: the decrypt-worker completion path
//! (`process_authentic_fmp_plaintext`) and the in-line one
//! (`handle_encrypted_frame`). These tests cover the in-line path,
//! which is the one the worker path's own coverage does not reach.
//!
//! `bool` carries no `#[must_use]`, so discarding the return here is
//! silent under `-D warnings`; the assertions below are what makes the
//! difference between binding it and dropping it observable.
//!
//! The tests at the end check that datagrams the node receives through a
//! connected socket's drain, and sends through the encrypt workers on
//! either kind of socket, are counted once in the UDP transport's stats.

use super::*;
use crate::noise::NoiseSession;
use crate::proto::fmp::wire::{build_encrypted, build_established_header, prepend_inner_header};

/// The address `seed_completed_connection` promotes a peer on, and so
/// the peer's `current_addr` before anything rotates it.
pub(super) const PROMOTED_ADDR: &str = "127.0.0.1:5000";

/// The address the peer is made to move to.
const ROAMED_ADDR: &str = "127.0.0.1:5001";

/// Build a promoted peer and hand back the far side's Noise session.
///
/// [`seed_completed_connection`] runs both legs of the handshake and
/// then drops the responder, so nothing outside it can produce a frame
/// the node will actually authenticate. This is the same seeding with
/// the responder's session kept, which is what lets these tests reach
/// the post-decrypt side effects rather than stopping at the AEAD.
///
/// Returns the node, the peer's `NodeAddr`, the session index an
/// inbound frame must name to be routed to that peer, and the session
/// to encrypt those frames with.
pub(super) fn promoted_peer_with_the_far_side_session(
    transport_id: TransportId,
) -> (Node, NodeAddr, SessionIndex, NoiseSession) {
    let mut node = make_node();
    let link_id = LinkId::new(1);

    let peer_identity_full = Identity::generate();
    // from_pubkey_full, not from_pubkey: the ECDH needs the parity bit.
    let peer_identity = PeerIdentity::from_pubkey_full(peer_identity_full.pubkey_full());

    let our_index = node.index_allocator.allocate().unwrap();
    node.seed_handshake_machine(
        HandshakeSeed::outbound(link_id, peer_identity, 1_000)
            .with_our_index(our_index)
            .with_their_index(SessionIndex::new(42))
            .with_transport_id(transport_id)
            .with_source_addr(TransportAddr::from_string(PROMOTED_ADDR)),
    )
    .unwrap();

    let our_keypair = node.identity().keypair();
    let startup_epoch = node.startup_epoch();
    let msg1 = node
        .peer_machines
        .get_mut(&link_id)
        .unwrap()
        .start_handshake(our_keypair, startup_epoch, 1_000)
        .unwrap();

    let mut responder = inbound_leg(LinkId::new(999), 1_000);
    let mut responder_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut responder_epoch);
    let msg2 = responder
        .receive_handshake_init(peer_identity_full.keypair(), responder_epoch, &msg1, 1_000)
        .unwrap();

    node.peer_machines
        .get_mut(&link_id)
        .unwrap()
        .complete_handshake(&msg2, 1_000)
        .unwrap();

    let far_side_session = responder
        .take_session()
        .expect("the responder holds a session once it has written msg2");

    node.promote_connection(link_id, peer_identity, 2_000)
        .unwrap();
    let node_addr = *peer_identity.node_addr();
    let our_index = node
        .get_peer(&node_addr)
        .and_then(|p| p.our_index())
        .expect("a promoted peer carries the index it was allocated");

    (node, node_addr, our_index, far_side_session)
}

/// Encrypt one well-formed established frame from the far side.
///
/// The link message is a heartbeat (`0x51`), which the dispatcher
/// handles as a no-op — these tests are about the side effects that run
/// before the dispatch, so the message must not have any of its own.
pub(super) fn far_side_frame(session: &mut NoiseSession, receiver_idx: SessionIndex) -> Vec<u8> {
    let inner = prepend_inner_header(0, &[0x51]);
    let counter = session.current_send_counter();
    let header = build_established_header(receiver_idx, counter, 0, inner.len() as u16);
    let ciphertext = session.encrypt_with_aad(&inner, &header).unwrap();
    build_encrypted(&header, &ciphertext)
}

/// **The defect.**
///
/// The in-line decrypt path called `set_current_addr` as a bare
/// statement and dropped its return, so a peer could roam, have its
/// `current_addr` updated, and keep a connected socket pinned to the
/// 5-tuple it had just left. The send path prefers that socket while it
/// is installed, so every frame after the move goes out to an address
/// the peer is no longer at.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn a_peer_that_roams_loses_the_connected_socket_pinned_to_the_address_it_left() {
    let transport_id = TransportId::new(1);
    let (mut node, node_addr, our_index, mut far_side) =
        promoted_peer_with_the_far_side_session(transport_id);

    install_connected_udp(&mut node, &node_addr, transport_id);
    assert!(
        node.get_peer(&node_addr).unwrap().connected_udp().is_some(),
        "precondition: the peer holds a connected socket before it moves"
    );

    let frame = far_side_frame(&mut far_side, our_index);
    node.handle_encrypted_frame(ReceivedPacket::new(
        transport_id,
        TransportAddr::from_string(ROAMED_ADDR),
        frame,
    ))
    .await;

    let peer = node
        .get_peer(&node_addr)
        .expect("the peer survives an authentic frame");
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string(ROAMED_ADDR)),
        "precondition for the assertion below: the frame must have been \
         authenticated and the rotation recorded, or the test proves nothing"
    );
    assert!(
        peer.connected_udp().is_none(),
        "a socket pinned to the address the peer has left must not survive \
         the rotation"
    );
}

/// **The healthy path.**
///
/// A frame from the address the peer is already on changes nothing, so
/// the connected socket has to stay. A fix that cleared unconditionally
/// would tear down and reopen the socket on every single frame.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn a_frame_from_the_address_the_peer_is_already_on_keeps_the_connected_socket() {
    let transport_id = TransportId::new(1);
    let (mut node, node_addr, our_index, mut far_side) =
        promoted_peer_with_the_far_side_session(transport_id);

    install_connected_udp(&mut node, &node_addr, transport_id);

    let frame = far_side_frame(&mut far_side, our_index);
    node.handle_encrypted_frame(ReceivedPacket::new(
        transport_id,
        TransportAddr::from_string(PROMOTED_ADDR),
        frame,
    ))
    .await;

    let peer = node
        .get_peer(&node_addr)
        .expect("the peer survives an authentic frame");
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string(PROMOTED_ADDR)),
        "the peer has not moved"
    );
    assert!(
        peer.connected_udp().is_some(),
        "a frame from the address already in use must leave the socket alone"
    );
}

/// Datagrams a peer sends after its connected socket is installed reach
/// the node through that socket's drain thread, not the wildcard listen
/// socket, and must still be counted in the UDP transport's own stats:
/// `packets_recv` means datagrams received on this transport.
///
/// The runtime thread is blocked while the count is read, so the
/// wildcard socket's receive task (a task on this runtime) cannot be the
/// one counting; only the drain thread can.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn datagrams_on_a_peers_connected_socket_are_counted_in_the_udp_transport_stats() {
    use crate::config::UdpConfig;
    use crate::transport::udp::UdpTransport;

    const SENT: u64 = 5;
    let transport_id = TransportId::new(1);
    let (mut node, node_addr, _, _) = promoted_peer_with_the_far_side_session(transport_id);
    let (tx, mut rx) = packet_channel(64);
    let udp_cfg = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    };
    let mut udp = UdpTransport::new(transport_id, None, udp_cfg, tx);
    udp.start_async().await.unwrap();
    let local = udp.local_addr().unwrap();
    let stats = udp.stats().clone();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let remote = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    node.get_peer_mut(&node_addr).unwrap().set_current_addr(
        transport_id,
        TransportAddr::from_string(&remote.local_addr().unwrap().to_string()),
    );
    node.activate_connected_udp_sessions().await;
    assert!(
        node.get_peer(&node_addr).unwrap().connected_udp().is_some(),
        "precondition: the tick activation installed a connected socket"
    );

    for i in 0..SENT {
        remote.send_to(&[i as u8; 8], local).unwrap();
    }
    // Block the runtime thread: the wildcard receive task cannot run.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while stats.snapshot().packets_recv < SENT && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let counted = stats.snapshot();
    assert_eq!(
        counted.packets_recv, SENT,
        "datagrams read by the connected socket's drain were not counted"
    );
    assert_eq!(counted.bytes_recv, SENT * 8);

    for _ in 0..SENT {
        let packet = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("a counted datagram was not delivered")
            .expect("packet channel closed");
        assert_eq!(packet.transport_id, transport_id);
    }
    node.clear_connected_udp_for_peer(&node_addr);
    for (_, t) in node.transports.iter_mut() {
        t.stop().await.ok();
    }
}

/// A promoted peer reached over a real UDP transport on loopback, with an
/// encrypt worker pool, so the node's sends to it take the worker path
/// rather than `UdpTransport::send_async`. Returns the node, the peer's
/// address, the UDP transport's stats, and the plain socket standing in
/// for the peer.
#[cfg(unix)]
async fn peer_behind_the_encrypt_workers() -> (
    Node,
    NodeAddr,
    std::sync::Arc<crate::transport::udp::UdpStats>,
    std::net::UdpSocket,
) {
    use crate::config::UdpConfig;
    use crate::transport::udp::UdpTransport;

    let transport_id = TransportId::new(1);
    let (mut node, node_addr, _, _) = promoted_peer_with_the_far_side_session(transport_id);
    let (tx, _rx) = packet_channel(64);
    let udp_cfg = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    };
    let mut udp = UdpTransport::new(transport_id, None, udp_cfg, tx);
    udp.start_async().await.unwrap();
    let stats = udp.stats().clone();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));
    node.supervisor.encrypt_workers =
        Some(crate::node::encrypt_worker::EncryptWorkerPool::spawn(1));

    let remote = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    remote
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    node.get_peer_mut(&node_addr).unwrap().set_current_addr(
        transport_id,
        TransportAddr::from_string(&remote.local_addr().unwrap().to_string()),
    );
    (node, node_addr, stats, remote)
}

/// Wait for the encrypt worker to count `sent` datagrams, then a little
/// longer so a second count of any of them would show. The worker counts
/// after its send returns, so a datagram can reach the peer just before
/// its count lands.
#[cfg(unix)]
fn settle_sent(stats: &crate::transport::udp::UdpStats, sent: u64) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while stats.snapshot().packets_sent < sent && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(50));
}

/// A link message the encrypt worker sends counts once in the UDP
/// transport's own stats, whether it leaves on the wildcard socket or on
/// the peer's connected socket: `packets_sent` means datagrams sent on
/// this transport, and the worker's sends never pass through
/// `UdpTransport::send_async`, which counts the rest.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn a_link_message_the_encrypt_worker_sends_counts_once_in_the_udp_transport_stats() {
    let (mut node, node_addr, stats, remote) = peer_behind_the_encrypt_workers().await;
    let mut buf = [0u8; 2048];
    // One tick publishes the transport rows `show transports` serves off
    // the rx loop; no tick runs after this.
    node.record_stats_history();
    let handle = node.control_read_handle();

    node.send_encrypted_link_message(&node_addr, &[0x51])
        .await
        .expect("send on the wildcard socket");
    let (wildcard_len, _) = remote.recv_from(&mut buf).expect("the peer receives it");
    settle_sent(&stats, 1);
    let counted = stats.snapshot();
    assert_eq!(
        counted.packets_sent, 1,
        "a datagram the worker sent on the wildcard socket must count once"
    );
    assert_eq!(counted.bytes_sent, wildcard_len as u64);

    node.activate_connected_udp_sessions().await;
    assert!(
        node.get_peer(&node_addr).unwrap().connected_udp().is_some(),
        "precondition: the tick activation installed a connected socket"
    );
    node.send_encrypted_link_message(&node_addr, &[0x51])
        .await
        .expect("send on the connected socket");
    let (connected_len, _) = remote.recv_from(&mut buf).expect("the peer receives it");
    settle_sent(&stats, 2);
    let counted = stats.snapshot();
    assert_eq!(
        counted.packets_sent, 2,
        "a datagram the worker sent on the connected socket must count once"
    );
    assert_eq!(counted.bytes_sent, (wildcard_len + connected_len) as u64);
    assert_eq!(counted.send_errors, 0);

    // `show transports`, on the rx loop and off it, reports the same counts.
    let off_loop = crate::control::queries::show_transports_from_handle(&handle);
    assert_eq!(off_loop, crate::control::queries::show_transports(&node));
    let row = off_loop["transports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["transport_id"] == 1)
        .unwrap_or_else(|| panic!("no row for the UDP transport: {off_loop}"))
        .clone();
    assert_eq!(
        row["stats"]["packets_sent"], 2,
        "show transports must report the datagrams the worker sent"
    );
    assert_eq!(
        row["stats"]["bytes_sent"],
        (wildcard_len + connected_len) as u64
    );

    node.clear_connected_udp_for_peer(&node_addr);
    for (_, t) in node.transports.iter_mut() {
        t.stop().await.ok();
    }
}

/// Session data takes the pipelined path, where the worker seals both
/// layers and sends; its datagram counts once in the UDP transport's
/// stats, as a link message's does.
#[cfg(unix)]
#[tokio::test]
async fn session_data_the_encrypt_worker_sends_counts_once_in_the_udp_transport_stats() {
    use crate::node::session::{EndToEndState, SessionEntry};

    let (mut node, node_addr, stats, remote) = peer_behind_the_encrypt_workers().await;
    let far_side = Identity::generate();
    let session = super::session::make_noise_session(node.identity(), &far_side);
    node.sessions.insert(
        node_addr,
        SessionEntry::new(
            node_addr,
            far_side.pubkey_full(),
            EndToEndState::Established(session),
            1_000,
            true,
        ),
    );

    node.send_session_data(&node_addr, 0, 0, b"counted once")
        .await
        .expect("send session data");
    let mut buf = [0u8; 2048];
    let (len, _) = remote.recv_from(&mut buf).expect("the peer receives it");
    settle_sent(&stats, 1);
    let counted = stats.snapshot();
    assert_eq!(
        counted.packets_sent, 1,
        "a session datagram the worker sent must count once"
    );
    assert_eq!(counted.bytes_sent, len as u64);
    assert_eq!(counted.send_errors, 0);

    for (_, t) in node.transports.iter_mut() {
        t.stop().await.ok();
    }
}
