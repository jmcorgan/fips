//! Per-peer connected UDP sockets against the in-line decrypt path.
//!
//! A `connect(2)`-ed UDP socket is pinned to one 5-tuple. When the peer
//! moves, the address the socket was opened against is gone, but the
//! socket is still installed and the send path prefers it over the
//! wildcard listen socket. `ActivePeer::account` returns what the roam
//! did, and its `changed()` says whether the address actually
//! changed, precisely so the caller can drop the stale socket. Both
//! post-decrypt paths, the decrypt-worker completion path
//! (`process_authentic_fmp_plaintext`) and the in-line one
//! (`handle_encrypted_frame`), reach `account_authentic`, which acts on
//! that return. These tests drive it through the in-line entry, and the
//! test of both paths through both entries: one frame stream, with an
//! address change in it, leaves the same link counters, MMP receiver and
//! spin bit, decrypt-failure count and roam on a peer whichever path it
//! takes. A crossed dial's move to the pair its winning msg2 came from
//! drops the socket the same way; the two tests after the roaming ones
//! cover it, reusing `crossed_dial`'s driver.
//!
//! `Roam` carries no `#[must_use]`, so discarding the return here is
//! silent under `-D warnings`; the assertions below are what makes the
//! difference between binding it and dropping it observable.
//!
//! The tests at the end check that datagrams the node receives through a
//! connected socket's drain, and sends through the encrypt workers on
//! either kind of socket, are counted once in the UDP transport's stats,
//! and that the encrypt-worker path refuses a frame over the UDP MTU as the
//! inline path does. One checks that a connected socket's drain applies
//! the datagram classifier registered with its UDP transport. The last
//! checks that a won crossed handshake, which starts the link's path
//! machine again, keeps the active path's socket.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::crossed_dial::{Crossed, Dial, cross_dials, hand};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::spanning_tree::cleanup_nodes;
use super::*;
use crate::noise::NoiseSession;
#[cfg(unix)]
use crate::proto::fmp::wire::FRAME_OVERHEAD;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::proto::fmp::wire::{FLAG_CE, FLAG_SP};
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

    let our_index_lease = fips_core::proto::rekey::allocate(&mut node.index_allocator).unwrap();
    node.seed_handshake_machine(
        HandshakeSeed::outbound(link_id, peer_identity, 1_000)
            .with_our_index(our_index_lease)
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
        .start_handshake(our_keypair, startup_epoch, LegStamp::at(1_000))
        .unwrap();

    let mut responder = inbound_leg(LinkId::new(999), 1_000);
    let mut responder_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut responder_epoch);
    let msg2 = responder
        .receive_handshake_init(
            peer_identity_full.keypair(),
            responder_epoch,
            &msg1,
            LegStamp::at(1_000),
        )
        .unwrap();

    node.peer_machines
        .get_mut(&link_id)
        .unwrap()
        .complete_handshake(&msg2, LegStamp::at(1_000))
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
    // The peer is promoted with no link, which no production path does.
    node.plant();

    (node, node_addr, our_index, far_side_session)
}

/// Encrypt one well-formed established frame from the far side.
///
/// The link message is a heartbeat (`0x51`), which the dispatcher
/// handles as a no-op — these tests are about the side effects that run
/// before the dispatch, so the message must not have any of its own.
pub(super) fn far_side_frame(session: &mut NoiseSession, receiver_idx: SessionIndex) -> Vec<u8> {
    heartbeat_frame(session, receiver_idx, 0, 0)
}

/// [`far_side_frame`] with the inner timestamp `ts` and the header flags
/// `flags`.
fn heartbeat_frame(
    session: &mut NoiseSession,
    receiver_idx: SessionIndex,
    ts: u32,
    flags: u8,
) -> Vec<u8> {
    let inner = prepend_inner_header(ts, &[0x51]);
    let counter = session.current_send_counter();
    let header = build_established_header(receiver_idx, counter, flags, inner.len() as u16);
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

/// Cross two nodes' dials as `dial` says, install a connected socket on the
/// smaller node's peer while its link is on the pair the peer's msg1 came
/// from, hand it the msg2 that wins, and return whether the socket is still
/// installed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn connected_socket_after_the_move(dial: Dial) -> bool {
    let Crossed {
        mut nodes,
        s,
        l,
        outbound,
        msg2,
        ..
    } = cross_dials(dial).await;
    let peer = *nodes[l].node.node_addr();
    let transport = nodes[s].transport_id;
    install_connected_udp(&mut nodes[s].node, &peer, transport);
    assert!(
        nodes[s]
            .node
            .get_peer(&peer)
            .unwrap()
            .connected_udp()
            .is_some(),
        "precondition: the peer holds a connected socket before the msg2"
    );
    hand(&mut nodes[s].node, msg2).await;
    let peer = nodes[s].node.get_peer(&peer).expect("s keeps l");
    assert_eq!(
        peer.our_index(),
        Some(outbound),
        "precondition: s swapped to its outbound session"
    );
    let kept = peer.connected_udp().is_some();
    cleanup_nodes(&mut nodes).await;
    kept
}

/// A crossed dial whose winning msg2 comes from another address than the
/// one the link was on moves the peer there, so the socket pinned to the
/// old address must go, as it does on a roam.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn a_crossed_dial_moved_to_another_address_drops_the_connected_socket_pinned_to_the_old_one()
{
    assert!(
        !connected_socket_after_the_move(Dial::OtherAddress).await,
        "a socket pinned to the address the peer has left must not survive the move"
    );
}

/// **The healthy path.** A crossed dial whose winning msg2 comes from the
/// pair the link is already on leaves the peer where it is, so the socket
/// stays.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn a_crossed_dial_whose_msg2_comes_from_the_pair_the_link_is_on_keeps_the_connected_socket() {
    assert!(
        connected_socket_after_the_move(Dial::AnsweredFromFirst).await,
        "a move that leaves the peer's address alone must leave the socket alone"
    );
}

/// The frames both receive paths are fed, in order: each heartbeat's inner
/// timestamp, header flags and source address. The third moves the peer.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const STREAM: [(u32, u8, &str); 5] = [
    (100, 0, PROMOTED_ADDR),
    (120, FLAG_CE, PROMOTED_ADDR),
    (140, FLAG_SP, ROAMED_ADDR),
    (160, FLAG_CE | FLAG_SP, ROAMED_ADDR),
    (180, 0, ROAMED_ADDR),
];

/// What a frame stream leaves on a peer: its link counters, its MMP
/// receiver's counts and spin bit, where its roam left it, whether it is
/// heard, and whether its connected socket survived. The MMP receiver's
/// jitter and local receive times are left out: they read the host clock,
/// which two nodes never read at the same instant.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, PartialEq)]
struct Books {
    packets: u64,
    bytes: u64,
    last_recv: u64,
    mmp_packets: u64,
    mmp_bytes: u64,
    highest: u64,
    ce: u32,
    spin: bool,
    transport: Option<TransportId>,
    addr: Option<TransportAddr>,
    paths: usize,
    heard: bool,
    last_seen: u64,
    failures: u32,
    socket: bool,
}

/// The [`Books`] of `peer` on `node`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn books(node: &Node, peer: &NodeAddr) -> Books {
    let p = node.get_peer(peer).expect("the peer survives the stream");
    let stats = p.link_stats();
    let mmp = p.mmp().expect("a promoted peer measures its link");
    Books {
        packets: stats.packets_recv,
        bytes: stats.bytes_recv,
        last_recv: stats.last_recv_ms,
        mmp_packets: mmp.receiver.cumulative_packets_recv(),
        mmp_bytes: mmp.receiver.cumulative_bytes_recv(),
        highest: mmp.receiver.highest_counter(),
        ce: mmp.receiver.ecn_ce_count(),
        spin: mmp.spin_bit.tx_bit(),
        transport: p.transport_id(),
        addr: p.current_addr().cloned(),
        paths: p.paths().len(),
        heard: p.heard(),
        last_seen: p.last_seen(),
        failures: p.consecutive_decrypt_failures(),
        socket: p.connected_udp().is_some(),
    }
}

/// The in-line path and the decrypt-worker path keep the same books. One
/// stream of heartbeats, with CE and spin bits set on some and an address
/// change partway, goes through `handle_encrypted_frame` on one node and,
/// as the worker hands it back once it has checked the frame, through
/// `process_authentic_fmp_plaintext` on another node in the same state. Both
/// peers end with the same counters, MMP state, decrypt-failure count and
/// roam, and with the values the stream implies, so a step dropped from both
/// paths fails too.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn the_inline_and_worker_receive_paths_keep_the_same_books_across_a_roam() {
    let tid = TransportId::new(1);
    let (mut inline, inline_peer, index, mut far_side) =
        promoted_peer_with_the_far_side_session(tid);
    let (mut worker, worker_peer, _, _) = promoted_peer_with_the_far_side_session(tid);
    install_connected_udp(&mut inline, &inline_peer, tid);
    install_connected_udp(&mut worker, &worker_peer, tid);
    // Both peers start with no decrypt failures, so a path that skipped the
    // reset on an authentic frame would still end at zero. One failure each
    // makes the reset show in the books.
    let promoted = TransportAddr::from_string(PROMOTED_ADDR);
    for (node, peer) in [(&mut inline, &inline_peer), (&mut worker, &worker_peer)] {
        node.charge_failure(peer, tid, &promoted);
    }

    let mut bytes = 0;
    let mut last = 0;
    for (i, &(ts, flags, from)) in STREAM.iter().enumerate() {
        let counter = far_side.current_send_counter();
        let frame = heartbeat_frame(&mut far_side, index, ts, flags);
        let at = 1_700_000_000_000 + 10 * i as u64;
        let addr = TransportAddr::from_string(from);
        bytes += frame.len() as u64;
        last = counter;
        inline
            .handle_encrypted_frame(ReceivedPacket::with_timestamp(
                tid,
                addr.clone(),
                frame.clone(),
                at,
            ))
            .await;
        worker
            .process_authentic_fmp_plaintext(
                &worker_peer,
                crate::node::dataplane::LinkSlot::Current,
                tid,
                &addr,
                at,
                frame.len(),
                counter,
                flags & FLAG_CE != 0,
                flags & FLAG_SP != 0,
                &prepend_inner_header(ts, &[0x51]),
            )
            .await;
    }

    let seen = books(&inline, &inline_peer);
    assert_eq!(
        seen,
        books(&worker, &worker_peer),
        "the two receive paths must keep the same books"
    );
    let expected = Books {
        packets: 5,
        bytes,
        last_recv: 1_700_000_000_040,
        mmp_packets: 5,
        mmp_bytes: bytes,
        highest: last,
        ce: 2,
        // The node is the spin initiator: it flips on a frame that reflects
        // its own bit, frames 1, 3 and 5 of STREAM, and ends set.
        spin: true,
        transport: Some(tid),
        addr: Some(TransportAddr::from_string(ROAMED_ADDR)),
        paths: 1,
        heard: true,
        last_seen: 1_700_000_000_040,
        // Seeded at one above: the first authentic frame resets it.
        failures: 0,
        socket: false,
    };
    assert_eq!(seen, expected, "the books the stream implies");
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

/// A peer's connected socket applies the datagram classifier registered
/// with its UDP transport, as the transport's own listen socket does: a
/// datagram the classifier discards is counted as received on the
/// transport but never reaches the packet channel, and one it passes does.
///
/// The test classifier discards only datagrams starting `0xAA`, which the
/// default filter would pass, so a drain that fell back to the default
/// filter delivers it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn a_peers_connected_socket_applies_its_udp_transports_classifier() {
    use crate::config::UdpConfig;
    use crate::transport::udp::{DatagramClass, UdpTransport};

    fn discard_marked(data: &[u8]) -> DatagramClass {
        if data.first() == Some(&0xAA) {
            DatagramClass::Discard
        } else {
            DatagramClass::Fmp
        }
    }
    const MARKED: [u8; 8] = [0xAA; 8];
    const PASSED: [u8; 8] = [0x01; 8];

    let transport_id = TransportId::new(1);
    let (mut node, node_addr, _, _) = promoted_peer_with_the_far_side_session(transport_id);
    let (tx, mut rx) = packet_channel(64);
    let udp_cfg = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    };
    let mut udp = UdpTransport::new(transport_id, None, udp_cfg, tx);
    udp.set_classifier(discard_marked);
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

    remote.send_to(&MARKED, local).unwrap();
    remote.send_to(&PASSED, local).unwrap();
    // Block the runtime thread until both are counted: the wildcard
    // receive task cannot run, so the drain thread is what read them.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while stats.snapshot().packets_recv < 2 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        stats.snapshot().packets_recv,
        2,
        "precondition: the connected socket's drain read both datagrams"
    );

    let mut delivered = Vec::new();
    while let Ok(Some(packet)) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
        delivered.push(packet.data);
    }
    assert_eq!(
        delivered,
        vec![PASSED.to_vec()],
        "the connected socket's drain did not apply the transport's classifier"
    );

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
    use crate::node::session::SessionEntry;

    let (mut node, node_addr, stats, remote) = peer_behind_the_encrypt_workers().await;
    let far_side = Identity::generate();
    let session = super::session::make_noise_session(node.identity(), &far_side);
    node.sessions.insert(
        node_addr,
        SessionEntry::keyed(
            node_addr,
            session,
            crate::node::session::session_at(1_000),
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

/// A UDP transport bound to an interface (`udp.interface`) must bind the
/// connected socket the node opens for each of its peers to the same
/// interface, or that peer's traffic routes by the kernel's table and can
/// leave by another NIC. This drives the node's own tick activation, the
/// code that hands the transport's interface to `open_connected_fd`, and
/// reads the binding back from the kernel.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_node_connected_socket_on_an_interface_bound_udp_transport_reads_back_that_interface() {
    use crate::config::UdpConfig;
    use crate::transport::udp::UdpTransport;
    use std::os::unix::io::AsRawFd;

    let transport_id = TransportId::new(1);
    let (mut node, node_addr, _, _) = promoted_peer_with_the_far_side_session(transport_id);
    let (tx, _rx) = packet_channel(64);
    let udp_cfg = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        interface: Some("lo".to_string()),
        ..Default::default()
    };
    let mut udp = UdpTransport::new(transport_id, None, udp_cfg, tx);
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let remote = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    node.get_peer_mut(&node_addr).unwrap().set_current_addr(
        transport_id,
        TransportAddr::from_string(&remote.local_addr().unwrap().to_string()),
    );
    node.activate_connected_udp_sessions().await;
    let socket = node
        .get_peer(&node_addr)
        .unwrap()
        .connected_udp()
        .expect("precondition: the tick activation installed a connected socket");

    assert_eq!(
        crate::transport::udp::io::bound_interface(socket.as_raw_fd()).unwrap(),
        "lo"
    );
}

/// The UDP transport's MTU in the encrypt-worker fixture. Tests size their
/// frames from it rather than from the default, so they keep testing the
/// boundary if the default changes.
#[cfg(unix)]
fn udp_mtu(node: &Node) -> u16 {
    node.transports
        .get(&TransportId::new(1))
        .expect("the fixture's UDP transport")
        .mtu()
}

/// A link message whose frame exceeds the UDP transport's MTU is refused on
/// the encrypt-worker path with `MtuExceeded`, as `UdpTransport::send_async`
/// refuses it on the inline path, and nothing reaches the peer. A frame of
/// exactly the MTU is still sent.
#[cfg(unix)]
#[tokio::test]
async fn a_link_message_over_the_udp_mtu_is_refused_on_the_encrypt_worker_path() {
    let (mut node, node_addr, stats, remote) = peer_behind_the_encrypt_workers().await;
    let mtu = udp_mtu(&node);
    let mut buf = [0u8; 4096];

    let over = vec![0x51u8; mtu as usize + 1 - FRAME_OVERHEAD];
    let result = node.send_encrypted_link_message(&node_addr, &over).await;
    match result {
        Err(NodeError::MtuExceeded {
            packet_size,
            mtu: reported,
            ..
        }) => {
            assert_eq!(packet_size, mtu as usize + 1);
            assert_eq!(reported, mtu);
        }
        other => panic!("a frame of mtu + 1 bytes must be refused, got {other:?}"),
    }
    assert_eq!(stats.snapshot().mtu_exceeded, 1);
    remote
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    assert!(
        remote.recv_from(&mut buf).is_err(),
        "a refused frame must not reach the peer"
    );

    let at_mtu = vec![0x51u8; mtu as usize - FRAME_OVERHEAD];
    node.send_encrypted_link_message(&node_addr, &at_mtu)
        .await
        .expect("a frame of exactly the MTU is sent");
    remote
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (len, _) = remote.recv_from(&mut buf).expect("the peer receives it");
    assert_eq!(len, mtu as usize);
    assert_eq!(stats.snapshot().mtu_exceeded, 1);

    for (_, t) in node.transports.iter_mut() {
        t.stop().await.ok();
    }
}

/// A transit forward onto the encrypt-worker path whose frame exceeds the
/// UDP next hop's MTU is counted as an MTU reject, not as forwarded, and the
/// source is sent an MtuExceeded signal instead of the oversize frame. The
/// datagram names the peer as both source and destination so the signal has
/// a route back over the same link.
#[cfg(unix)]
#[tokio::test]
async fn a_transit_forward_onto_the_encrypt_worker_path_over_the_udp_mtu_signals_mtu_exceeded() {
    use crate::proto::link::{SESSION_DATAGRAM_HEADER_SIZE, SessionDatagram};

    let (mut node, node_addr, _stats, remote) = peer_behind_the_encrypt_workers().await;
    let mtu = udp_mtu(&node);
    let payload_len = mtu as usize + 1 - FRAME_OVERHEAD - SESSION_DATAGRAM_HEADER_SIZE;
    let encoded = SessionDatagram::new(node_addr, node_addr, vec![0u8; payload_len]).encode();
    assert_eq!(encoded.len() + FRAME_OVERHEAD, mtu as usize + 1);

    let before = node.metrics().forwarding.snapshot();
    node.handle_session_datagram(&node_addr, &encoded[1..], false)
        .await;
    let after = node.metrics().forwarding.snapshot();
    assert_eq!(
        after.drop_mtu_exceeded_packets,
        before.drop_mtu_exceeded_packets + 1,
        "the oversize forward must be counted as an MTU reject"
    );
    assert_eq!(
        after.forwarded_packets, before.forwarded_packets,
        "the oversize forward must not be counted as forwarded"
    );

    let mut buf = [0u8; 4096];
    remote
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (len, _) = remote
        .recv_from(&mut buf)
        .expect("the source receives the MtuExceeded signal");
    assert!(
        len < mtu as usize,
        "the peer must receive the small MtuExceeded signal, not the {len}-byte frame"
    );
    remote
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    assert!(
        remote.recv_from(&mut buf).is_err(),
        "nothing else may reach the peer"
    );

    for (_, t) in node.transports.iter_mut() {
        t.stop().await.ok();
    }
}

/// A won crossed handshake starts the link's path machine again on the
/// active path and keeps that path's connected socket: the socket installed
/// before the move is the one installed after.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn a_won_cross_connection_keeps_the_active_paths_connected_socket() {
    use super::paths::cross_move;
    use super::rekey_parity::linked_pair;
    use super::spanning_tree::cleanup_nodes;

    let mut nodes = linked_pair(Config::new(), Config::new()).await;
    let (s, l) = if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        (0, 1)
    } else {
        (1, 0)
    };
    let l_addr = *nodes[l].node.node_addr();
    let tid = nodes[s].transport_id;
    install_connected_udp(&mut nodes[s].node, &l_addr, tid);
    let peer = nodes[s].node.get_peer(&l_addr).unwrap();
    let before = peer
        .connected_udp()
        .expect("precondition: a socket installed");
    let (id, index) = (peer.active_path().unwrap().path_id(), peer.our_index());

    cross_move(&mut nodes, s, l).await;

    let peer = nodes[s].node.get_peer(&l_addr).unwrap();
    assert_ne!(peer.our_index(), index, "precondition: the link moved");
    assert_ne!(
        peer.active_path().unwrap().path_id(),
        id,
        "precondition: the path machine started again"
    );
    let after = peer.connected_udp().expect("the socket survives the move");
    assert!(
        std::sync::Arc::ptr_eq(&before, &after),
        "the active path keeps the socket installed before the move"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A sealed frame of the far side whose plaintext is `inner`, which may be
/// shorter than the inner header.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn sealed_frame(session: &mut NoiseSession, receiver_idx: SessionIndex, inner: &[u8]) -> Vec<u8> {
    let counter = session.current_send_counter();
    let header = build_established_header(receiver_idx, counter, 0, inner.len() as u16);
    let ciphertext = session.encrypt_with_aad(inner, &header).unwrap();
    build_encrypted(&header, &ciphertext)
}

/// Authentic frames of the link attributed to `peer`'s active path.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn active_frames(node: &Node, peer: &NodeAddr) -> u32 {
    let held = node.get_peer(peer).expect("the peer is kept");
    held.active_path()
        .expect("the peer holds a path")
        .live()
        .frames()
}

/// Section 5.3 of the multipath draft: the node resets a path's count when
/// an authentic frame of the link arrives on it, whatever its length. With
/// one failure charged on each of two peers, a frame whose plaintext is 3
/// bytes, shorter than the five-byte inner header, resets the count on both
/// the in-line path and the decrypt-worker path. A 4-byte plaintext, too
/// short for the inner header but long enough for its timestamp, resets the
/// count too, and neither path attributes it to the path as a frame.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn the_inline_and_worker_paths_both_reset_the_count_on_a_frame_too_short_for_the_inner_header()
 {
    let tid = TransportId::new(1);
    let (mut inline, inline_peer, index, mut far_side) =
        promoted_peer_with_the_far_side_session(tid);
    let (mut worker, worker_peer, _, _) = promoted_peer_with_the_far_side_session(tid);
    let promoted = TransportAddr::from_string(PROMOTED_ADDR);
    for len in [3usize, 4] {
        for (node, peer) in [(&mut inline, &inline_peer), (&mut worker, &worker_peer)] {
            node.charge_failure(peer, tid, &promoted);
            assert_eq!(
                node.get_peer(peer).unwrap().consecutive_decrypt_failures(),
                1,
                "precondition: one failure charged before the {len}-byte frame"
            );
        }
        let frames = (
            active_frames(&inline, &inline_peer),
            active_frames(&worker, &worker_peer),
        );
        let inner = vec![0u8; len];
        let frame = sealed_frame(&mut far_side, index, &inner);
        inline
            .handle_encrypted_frame(ReceivedPacket::new(tid, promoted.clone(), frame.clone()))
            .await;
        worker
            .process_authentic_fmp_plaintext(
                &worker_peer,
                crate::node::dataplane::LinkSlot::Current,
                tid,
                &promoted,
                1_700_000_000_000,
                frame.len(),
                0,
                false,
                false,
                &inner,
            )
            .await;
        assert_eq!(
            inline
                .get_peer(&inline_peer)
                .unwrap()
                .consecutive_decrypt_failures(),
            0,
            "the in-line path did not reset the count on a {len}-byte plaintext"
        );
        assert_eq!(
            worker
                .get_peer(&worker_peer)
                .unwrap()
                .consecutive_decrypt_failures(),
            0,
            "the worker path did not reset the count on a {len}-byte plaintext"
        );
        assert_eq!(
            (
                active_frames(&inline, &inline_peer),
                active_frames(&worker, &worker_peer),
            ),
            frames,
            "a {len}-byte plaintext was attributed to the path as a frame"
        );
    }
}
