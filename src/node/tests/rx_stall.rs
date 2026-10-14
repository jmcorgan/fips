//! A handshake send to a TCP connection that has gone away must not dial.
//!
//! When a msg1 arrives on an inbound TCP connection that has since closed,
//! the reply has nowhere to go. The handlers that answer it run inline on the
//! rx loop, so a reply that fell through to TCP connect-on-send held every
//! other frame the loop owns, including frames that arrived on UDP, for the
//! whole connect timeout. The tick's handshake sends (the rekey msg1 and its
//! resends, the msg1 resend on an outbound handshake), the executor's msg1
//! send and the encrypted link send are awaited by the same loop and had
//! the same exposure. These tests assert each send now fails at once
//! instead: no connect attempt is counted and the call returns well inside
//! a bound far below the timeout. Each one also runs a healthy control, so a
//! run that skips the send path entirely fails too.
//!
//! The tick and dial-path sends may start a background connect, but only to
//! an address this node dialed; the tests check that it starts there, that
//! it does not start toward an inbound peer's address, and that a later send
//! uses the connection once it is up.
//!
//! The unanswered SYN is constructed locally by `Blackhole`: a listener whose
//! accept queue is full, which Linux, macOS and Windows leave unanswered, or
//! on FreeBSD a bound port with no listener and the kernel's blackhole
//! settings on (see `Blackhole`). A connect to it times out rather than being
//! refused. `Blackhole` checks that before any test relies on it, which is
//! what lets a regression show up at its real size: one connect timeout per
//! reply, counted in `connect_timeouts`.
//!
//! The tests print their measurements; run with `--nocapture` to see them.

use super::*;
use crate::config::{TcpConfig, UdpConfig};
use crate::peer::machine::{PeerEvent, PeerMachine, TimerKind};
use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG1, PHASE_MSG2, build_msg1};
use crate::proto::link::LinkMessageType;
use crate::testutil::Blackhole;
use crate::transport::tcp::TcpTransport;
use crate::transport::tcp::stats::TcpStatsSnapshot;
use crate::transport::udp::UdpTransport;
use crate::transport::{ConnectionState, PacketTx, TransportHandle, TransportId};
use std::net::SocketAddr;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const UDP_ID: u32 = 1;
const TCP_ID: u32 = 2;
const EPOCH: [u8; 8] = [7u8; 8];

/// The connect timeout every dead-link test runs at: the shipped default, so
/// a send that dials shows up at the size it has in the field.
const CONNECT_TIMEOUT_MS: u64 = 5000;

/// How long a handler answering a dead link may take. Far below any connect
/// timeout, far above the microseconds a failed pool lookup costs.
const BOUND: Duration = Duration::from_millis(250);

/// A genuine wire msg1 from `sender` to `node`.
fn craft_msg1(node: &Node, sender: &Identity, sender_index: u32) -> Vec<u8> {
    let target = PeerIdentity::from_pubkey_full(node.identity().pubkey_full());
    let mut conn = outbound_leg(LinkId::new(0x5EED), target, 1000);
    let noise_msg1 = conn
        .start_handshake(sender.keypair(), EPOCH, 1000)
        .expect("start_handshake produces noise msg1");
    build_msg1(SessionIndex::new(sender_index), &noise_msg1)
}

/// A node with a UDP and a TCP transport feeding one packet channel, as a
/// node built from config has. Returns the node, a sender into that channel
/// (to inject frames as if a transport had delivered them), and the UDP
/// transport's local address.
async fn node_with_udp_and_tcp(connect_timeout_ms: u64) -> (Node, PacketTx, SocketAddr) {
    let mut node = make_node();
    let (tx, rx) = packet_channel(1024);

    let udp_cfg = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };
    let mut udp = UdpTransport::new(TransportId::new(UDP_ID), None, udp_cfg, tx.clone());
    udp.start_async().await.unwrap();
    let udp_addr = udp.local_addr().unwrap();

    let tcp_cfg = TcpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1400),
        connect_timeout_ms: Some(connect_timeout_ms),
        ..Default::default()
    };
    let mut tcp = TcpTransport::new(TransportId::new(TCP_ID), None, tcp_cfg, tx.clone());
    tcp.start_async().await.unwrap();

    node.transports
        .insert(TransportId::new(UDP_ID), TransportHandle::Udp(udp));
    node.transports
        .insert(TransportId::new(TCP_ID), TransportHandle::Tcp(tcp));
    node.packet_rx = Some(rx);
    node.supervisor.state = NodeState::Running;
    (node, tx, udp_addr)
}

/// The node's TCP transport.
fn tcp(node: &Node) -> &TransportHandle {
    node.transports
        .get(&TransportId::new(TCP_ID))
        .expect("no TCP transport")
}

/// The TCP transport's live counters.
fn tcp_stats(node: &Node) -> TcpStatsSnapshot {
    match tcp(node) {
        TransportHandle::Tcp(t) => t.stats().snapshot(),
        _ => panic!("transport {TCP_ID} is not TCP"),
    }
}

/// Stop every transport the node holds.
async fn stop_all(node: &mut Node) {
    for (_, t) in node.transports.iter_mut() {
        t.stop().await.ok();
    }
}

/// Wait until the TCP transport holds no connection to `addr`.
async fn wait_pool_gone(node: &Node, addr: &TransportAddr) {
    let start = Instant::now();
    while tcp(node).connection_state(addr) != ConnectionState::None {
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "pool entry for {addr} never dropped"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Open a connection from the node to `bh`'s free accept slot, the way a
/// node ends up holding a live connection to a peer's address, and return
/// the far end of it.
async fn prime_link(node: &Node, bh: &Blackhole) -> std::net::TcpStream {
    let addr = bh.transport_addr();
    tcp(node).connect(&addr).await.unwrap();
    let start = Instant::now();
    while tcp(node).connection_state(&addr) != ConnectionState::Connected {
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "connection to {addr} never came up"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (accepted, _) = bh.listener.accept().unwrap();
    std::net::TcpStream::from(accepted)
}

/// Close the node's connection to `bh` from the far end, after filling `bh`
/// so that any later dial to the address hangs.
async fn kill_link(node: &Node, bh: &mut Blackhole, accepted: std::net::TcpStream) {
    bh.fill();
    drop(accepted);
    wait_pool_gone(node, &bh.transport_addr()).await;
}

/// Read one FMP frame the node wrote to `far_end`, if one arrives within
/// `limit`.
///
/// The frame is read by its own length, with the transport's frame reader,
/// not by what one `read` returns: TCP may hand over two frames in one read or
/// one across two, and which it does differs by kernel (FreeBSD delivered the
/// announce that follows a msg2 in a read of its own, where Linux returned the
/// two together). A TCP send only queues the frame for the connection's
/// writer task, so the read must not block the test's runtime thread: it reads
/// a tokio stream on a duplicate of the socket, which lets the writer run.
async fn read_frame_within(far_end: &mut std::net::TcpStream, limit: Duration) -> Option<Vec<u8>> {
    let dup = far_end.try_clone().expect("try_clone");
    dup.set_nonblocking(true).expect("set_nonblocking");
    let mut stream = tokio::net::TcpStream::from_std(dup).expect("from_std");
    let frame = timeout(
        limit,
        crate::transport::framing::read_fmp_packet(&mut stream, u16::MAX),
    )
    .await;
    // The duplicate shares the socket's file status flags, so blocking reads
    // on `far_end` need the flag cleared again.
    far_end.set_nonblocking(false).expect("set_nonblocking");
    frame.ok().and_then(Result::ok)
}

/// [`read_frame_within`] a second.
async fn read_frame(far_end: &mut std::net::TcpStream) -> Option<Vec<u8>> {
    read_frame_within(far_end, Duration::from_millis(1000)).await
}

/// [`read_frame`] on `far_end` when there is one.
async fn read_maybe(far_end: Option<&mut std::net::TcpStream>) -> Option<Vec<u8>> {
    match far_end {
        Some(stream) => read_frame(stream).await,
        None => None,
    }
}

/// Read and discard every frame the node writes to `far_end` until none
/// arrives for a while, so a later read sees only what a later send wrote.
/// Promotion follows the msg2 with link announces, which would otherwise be
/// read in place of the frame a test is waiting for.
async fn drain_frames(far_end: &mut std::net::TcpStream) {
    while read_frame_within(far_end, Duration::from_millis(200))
        .await
        .is_some()
    {}
}

/// What one handler call against a TCP reply address did.
#[derive(Debug)]
struct Reply {
    elapsed: Duration,
    connect_timeouts: u64,
    connect_refused: u64,
    connections_established: u64,
}

/// One call into a node that may send on TCP.
enum Trigger {
    /// A frame for the packet handler.
    Packet(ReceivedPacket),
    /// The tick's rekey msg1 check.
    RekeyCheck,
    /// The tick's rekey msg1 resend, with every resend due.
    RekeyResend,
    /// The tick's handshake timers, at this time.
    PeerTimers(u64),
    /// The executor's send of the msg1 armed on this outbound link.
    StoredMsg1(LinkId, TransportAddr),
    /// An encrypted link message (a heartbeat) to this peer.
    LinkMessage(NodeAddr),
}

/// Fire `trigger` once and measure it against the TCP counters.
async fn timed_fire(node: &mut Node, trigger: Trigger) -> Reply {
    let before = tcp_stats(node);
    let t0 = Instant::now();
    match trigger {
        Trigger::Packet(packet) => node.process_packet(packet).await,
        Trigger::RekeyCheck => node.check_rekey().await,
        Trigger::RekeyResend => node.resend_pending_rekeys(Node::now_ms() + 60_000).await,
        Trigger::PeerTimers(now_ms) => node.drive_peer_timers(now_ms).await,
        Trigger::StoredMsg1(link, addr) => {
            node.send_stored_msg1(link, TransportId::new(TCP_ID), &addr, Node::now_ms())
                .await
        }
        Trigger::LinkMessage(peer) => {
            let heartbeat = [LinkMessageType::Heartbeat.to_byte()];
            let _ = node.send_encrypted_link_message(&peer, &heartbeat).await;
        }
    }
    let elapsed = t0.elapsed();
    let after = tcp_stats(node);
    Reply {
        elapsed,
        connect_timeouts: after.connect_timeouts - before.connect_timeouts,
        connect_refused: after.connect_refused - before.connect_refused,
        connections_established: after.connections_established - before.connections_established,
    }
}

/// Run `process_packet` once and measure it against the TCP counters.
async fn timed_process(node: &mut Node, packet: ReceivedPacket) -> Reply {
    timed_fire(node, Trigger::Packet(packet)).await
}

/// Every way a reply to a dead link failed to be fast and dial-free.
fn dial_findings(what: &str, r: &Reply) -> Vec<String> {
    let mut found = Vec::new();
    if r.elapsed >= BOUND {
        found.push(format!(
            "{what}: handler took {:?} (bound {BOUND:?}); a connect timeout is {CONNECT_TIMEOUT_MS} ms",
            r.elapsed
        ));
    }
    if r.connect_timeouts != 0 {
        found.push(format!("{what}: {} connect timeouts", r.connect_timeouts));
    }
    if r.connect_refused != 0 {
        found.push(format!("{what}: {} connects refused", r.connect_refused));
    }
    if r.connections_established != 0 {
        found.push(format!(
            "{what}: {} connections dialed",
            r.connections_established
        ));
    }
    found
}

/// Assert a reply to a dead link failed at once and attempted no connect.
fn assert_no_dial(what: &str, r: &Reply) {
    let found = dial_findings(what, r);
    assert!(found.is_empty(), "{}", found.join("; "));
}

/// A real TCP client connected to the node's listener that has sent one
/// msg1. Returns the client and the frame as the node's receive task
/// delivered it, which carries the client's address as the reply address.
async fn msg1_over_real_tcp(node: &mut Node) -> (tokio::net::TcpStream, ReceivedPacket) {
    let listen = tcp(node).local_addr().expect("TCP listener bound");
    let mut client = tokio::net::TcpStream::connect(listen).await.unwrap();
    let data = craft_msg1(node, &Identity::generate(), 0x51);
    client.write_all(&data).await.unwrap();
    let rx = node.packet_rx.as_mut().expect("packet channel");
    let packet = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("msg1 never reached the packet channel")
        .expect("packet channel closed");
    assert_eq!(packet.transport_id, TransportId::new(TCP_ID));
    (client, packet)
}

/// Whether `client` receives a msg2 within a second.
async fn client_gets_msg2(client: &mut tokio::net::TcpStream) -> bool {
    let mut buf = [0u8; 2048];
    match timeout(Duration::from_secs(1), client.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => CommonPrefix::parse(&buf[..n]).is_some_and(|p| p.phase == PHASE_MSG2),
        _ => false,
    }
}

/// A msg2 reply whose TCP connection is gone fails at once, attempts no
/// connect, and tears down the half-built link. A msg1 on a live inbound
/// connection is still answered on that connection.
#[tokio::test]
async fn msg2_reply_to_dead_tcp_link_returns_without_dialing() {
    // Control: a live inbound connection gets its msg2.
    let (mut node, _tx, _) = node_with_udp_and_tcp(CONNECT_TIMEOUT_MS).await;
    let (mut client, packet) = msg1_over_real_tcp(&mut node).await;
    let r = timed_process(&mut node, packet).await;
    let answered = client_gets_msg2(&mut client).await;
    println!("msg2 control  live inbound connection: {r:?}, msg2 received {answered}");
    assert_no_dial("msg2 control", &r);
    assert!(answered, "control: the live connection got no msg2");
    assert_eq!(node.peer_count(), 1, "control should promote the peer");
    stop_all(&mut node).await;

    // The reply address has no connection and does not answer SYNs.
    let bh = Blackhole::silent();
    let (mut node, _tx, _) = node_with_udp_and_tcp(CONNECT_TIMEOUT_MS).await;
    let data = craft_msg1(&node, &Identity::generate(), 0x11);
    let packet = ReceivedPacket::new(TransportId::new(TCP_ID), bh.transport_addr(), data);
    let r = timed_process(&mut node, packet).await;
    println!("msg2 dead     blackholed reply address: {r:?}");
    assert_no_dial("msg2 to a dead link", &r);
    assert_eq!(
        node.peer_count(),
        0,
        "a failed msg2 send discards the handshake"
    );
    assert!(node.links.is_empty(), "the half-built link is torn down");
    assert!(
        node.addr_to_link.is_empty(),
        "the half-built link is unindexed"
    );
    stop_all(&mut node).await;
}

/// Establish a peer on TCP at `bh`'s address over a live connection the node
/// holds there. Returns the node, the peer's identity and address, and the
/// far end of the connection.
async fn peer_on_tcp(bh: &Blackhole) -> (Node, Identity, NodeAddr, std::net::TcpStream) {
    let (mut node, _tx, _) = node_with_udp_and_tcp(CONNECT_TIMEOUT_MS).await;
    let mut far_end = prime_link(&node, bh).await;
    let sender = Identity::generate();
    let sender_addr = *PeerIdentity::from_pubkey_full(sender.pubkey_full()).node_addr();
    let link = bh.transport_addr();

    let data = craft_msg1(&node, &sender, 0x01);
    node.process_packet(ReceivedPacket::new(
        TransportId::new(TCP_ID),
        link.clone(),
        data,
    ))
    .await;
    assert_eq!(node.peer_count(), 1, "peer established over TCP");
    let p = node.get_peer(&sender_addr).unwrap();
    assert_eq!(p.transport_id(), Some(TransportId::new(TCP_ID)));
    assert_eq!(p.current_addr(), Some(&link));
    assert!(
        read_frame(&mut far_end)
            .await
            .is_some_and(|f| CommonPrefix::parse(&f).is_some_and(|p| p.phase == PHASE_MSG2)),
        "the msg2 went out on the connection"
    );
    drain_frames(&mut far_end).await;
    (node, sender, sender_addr, far_end)
}

/// An address the peer's later frames arrive from: a new connection, with no
/// pool entry of its own.
fn elsewhere() -> TransportAddr {
    TransportAddr::from_string("127.0.0.1:9")
}

/// Record `peer`'s link as one this node dialed at the address it holds,
/// as if the node had been the initiator.
fn make_link_outbound(node: &mut Node, peer: &NodeAddr) {
    let link_id = node.get_peer(peer).unwrap().link_id();
    let old = node.links.get(&link_id).expect("the peer's link");
    let link = Link::new(
        link_id,
        old.transport_id(),
        old.remote_addr().clone(),
        LinkDirection::Outbound,
        old.base_rtt(),
    );
    node.links.insert(link_id, link);
}

/// Age `peer`'s session past the rekey trigger of a default config.
fn age_past_rekey(node: &mut Node, peer: &NodeAddr) {
    let after = node.config().node.rekey.after_secs + crate::node::REKEY_JITTER_SECS as u64 + 1;
    node.get_peer_mut(peer)
        .unwrap()
        .test_backdate_session_established(Duration::from_secs(after));
}

/// Arm an outbound handshake to `addr` on TCP as a dial does: a link this
/// node dialed, a machine that has sent its msg1 and holds the wire, and a
/// retransmit timer due at `due_ms`. Returns the link and the msg1 wire.
fn dial_leg(node: &mut Node, addr: &TransportAddr, now_ms: u64, due_ms: u64) -> (LinkId, Vec<u8>) {
    let tcp_id = TransportId::new(TCP_ID);
    let target = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    let link_id = node.allocate_link_id();
    let mut leg = outbound_leg(link_id, target, now_ms);
    let our_index = node.index_allocator.allocate().unwrap();
    let noise_msg1 = leg
        .start_handshake(node.identity().keypair(), node.startup_epoch(), now_ms)
        .unwrap();
    let wire = build_msg1(our_index, &noise_msg1);
    node.links.insert(
        link_id,
        Link::new(
            link_id,
            tcp_id,
            addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.addr_to_link.insert((tcp_id, addr.clone()), link_id);
    node.pending_outbound.insert(our_index.as_u32(), link_id);
    let mut machine = PeerMachine::new_outbound(link_id, target, now_ms);
    let _ = machine.step(
        PeerEvent::Dial {
            transport_id: tcp_id,
            remote_addr: addr.clone(),
            peer_identity: target,
            connection_oriented: false,
        },
        now_ms,
        &mut node.index_allocator,
    );
    machine.set_conn_handshake_msg1(wire.clone(), due_ms);
    machine.set_conn_our_index(our_index);
    machine.set_conn_transport_id(tcp_id);
    machine.set_conn_source_addr(addr.clone());
    machine.set_leg(leg.take_leg().unwrap());
    assert!(machine.is_handshaking_sent_msg1());
    node.peer_machines.insert(link_id, machine);
    node.peer_timers
        .entry(link_id)
        .or_default()
        .insert(TimerKind::HandshakeRetransmit, due_ms);
    (link_id, wire)
}

/// Whether `frame` is a handshake msg1.
fn is_msg1(frame: &[u8]) -> bool {
    CommonPrefix::parse(frame).is_some_and(|p| p.phase == PHASE_MSG1)
}

/// What a tick's rekey check did to a TCP peer.
#[derive(Debug)]
struct RekeyStart {
    reply: Reply,
    /// The rekey msg1 went out and the cycle is in flight.
    started: bool,
    /// The far end received the msg1.
    delivered: bool,
    /// The transport's connection state for the peer's address afterwards.
    state: ConnectionState,
}

/// Run the tick's rekey check for a TCP peer due to rekey, whose link is
/// alive or (with `dead`) closed, and which this node dialed (`outbound`)
/// or accepted.
async fn rekey_start(dead: bool, outbound: bool) -> RekeyStart {
    let mut bh = Blackhole::open(false);
    let (mut node, _sender, sender_addr, far_end) = peer_on_tcp(&bh).await;
    if outbound {
        make_link_outbound(&mut node, &sender_addr);
    }
    let mut far_end = if dead {
        kill_link(&node, &mut bh, far_end).await;
        None
    } else {
        Some(far_end)
    };
    age_past_rekey(&mut node, &sender_addr);
    let reply = timed_fire(&mut node, Trigger::RekeyCheck).await;
    let started = node
        .get_peer(&sender_addr)
        .is_some_and(|p| p.rekey_in_progress());
    let delivered = read_maybe(far_end.as_mut())
        .await
        .is_some_and(|f| is_msg1(&f));
    let state = tcp(&node).connection_state(&bh.transport_addr());
    stop_all(&mut node).await;
    RekeyStart {
        reply,
        started,
        delivered,
        state,
    }
}

/// The tick's rekey msg1 to a TCP peer whose connection has closed fails at
/// once without dialing. A background connect is started toward a peer this
/// node dialed, and never toward an inbound peer's address. With the link
/// alive the msg1 goes out and the cycle starts.
#[tokio::test]
async fn rekey_msg1_to_dead_tcp_link_does_not_hold_tick() {
    let r = rekey_start(false, false).await;
    println!("rekey msg1 control link alive: {r:?}");
    assert_no_dial("rekey msg1 control", &r.reply);
    assert!(
        r.started && r.delivered,
        "control: the rekey msg1 did not go out"
    );

    let r = rekey_start(true, false).await;
    println!("rekey msg1 dead inbound peer: {r:?}");
    assert_no_dial("rekey msg1 to a closed inbound link", &r.reply);
    assert!(!r.started, "a failed rekey msg1 starts no cycle");
    assert_eq!(
        r.state,
        ConnectionState::None,
        "a connect was started toward an inbound peer's address"
    );

    let r = rekey_start(true, true).await;
    println!("rekey msg1 dead outbound peer: {r:?}");
    assert_no_dial("rekey msg1 to a closed outbound link", &r.reply);
    assert!(!r.started, "a failed rekey msg1 starts no cycle");
    assert_eq!(
        r.state,
        ConnectionState::Connecting,
        "no background connect toward the address this node dialed"
    );
}

/// The tick's msg1 resend on an outbound handshake whose address does not
/// answer fails at once without dialing and starts a background connect.
/// Once the address answers and that connect finishes, a later tick sends
/// the msg1 on it: the connection is not left stranded unused.
#[tokio::test]
async fn msg1_resend_to_dead_outbound_leg_recovers_after_background_connect() {
    let mut bh = Blackhole::silent();
    let (mut node, _tx, _) = node_with_udp_and_tcp(CONNECT_TIMEOUT_MS).await;
    let addr = bh.transport_addr();
    let now_ms = Node::now_ms();
    let (link, wire) = dial_leg(&mut node, &addr, now_ms, now_ms + 1000);

    let r = timed_fire(&mut node, Trigger::PeerTimers(now_ms + 1000)).await;
    println!("msg1 resend  blackholed dial address: {r:?}");
    assert_no_dial("msg1 resend to a dead outbound leg", &r);
    assert_eq!(node.connection_resend_count(link), 0, "nothing was sent");
    assert_eq!(
        tcp(&node).connection_state(&addr),
        ConnectionState::Connecting,
        "no background connect toward the dial address"
    );

    // The address starts answering (`Blackhole::drain`), and the background
    // connect's retransmitted SYN completes.
    let _filler_ends = bh.drain();
    let start = Instant::now();
    let mut tick = 1;
    while node.connection_resend_count(link) == 0 {
        assert!(
            start.elapsed() < Duration::from_secs(4),
            "the msg1 resend never went out over the background connect"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        let r = timed_fire(&mut node, Trigger::PeerTimers(now_ms + 1000 + tick * 100)).await;
        tick += 1;
        assert!(r.elapsed < BOUND, "a tick took {:?}", r.elapsed);
        assert_eq!(r.connect_timeouts, 0, "a tick dialed and timed out");
    }
    let (accepted, _) = bh.listener.accept().unwrap();
    let mut accepted = std::net::TcpStream::from(accepted);
    println!(
        "msg1 resend  sent after {:?} over the background connect",
        start.elapsed()
    );
    assert_eq!(
        read_frame(&mut accepted).await,
        Some(wire),
        "the msg1 did not arrive on the background connection"
    );
    stop_all(&mut node).await;
}

/// Run a same-epoch rekey msg1 for a peer whose established TCP link is gone
/// (or, with `dead` false, still connected). Returns the measurement and
/// whether a pending session was stored.
async fn rekey_reply(dead: bool) -> (Reply, bool) {
    let mut bh = Blackhole::open(false);
    let (mut node, sender, sender_addr, far_end) = peer_on_tcp(&bh).await;
    let _far_end = if dead {
        kill_link(&node, &mut bh, far_end).await;
        None
    } else {
        Some(far_end)
    };
    node.get_peer_mut(&sender_addr)
        .unwrap()
        .test_backdate_session_established(Duration::from_secs(31));

    // With the link gone, the peer has come back on a new connection and
    // sends a rekey msg1 at the same epoch; with it alive, the msg1 comes on
    // the link. The rekey msg2 goes to the established link's address.
    let from = if dead {
        elsewhere()
    } else {
        bh.transport_addr()
    };
    let data = craft_msg1(&node, &sender, 0x02);
    let r = timed_process(
        &mut node,
        ReceivedPacket::new(TransportId::new(TCP_ID), from, data),
    )
    .await;
    let pending = node
        .get_peer(&sender_addr)
        .is_some_and(|p| p.pending_new_session().is_some());
    stop_all(&mut node).await;
    (r, pending)
}

/// A rekey msg2 to a peer whose established TCP link has closed
/// fails at once and stores no pending session; with the link alive the
/// pending session is stored.
#[tokio::test]
async fn rekey_msg2_to_closed_tcp_link_returns_without_dialing() {
    let (r, pending) = rekey_reply(false).await;
    println!("rekey control link alive: {r:?}, pending session {pending}");
    assert_no_dial("rekey control", &r);
    assert!(pending, "control should store the rekey session");

    let (r, pending) = rekey_reply(true).await;
    println!("rekey dead    link closed: {r:?}, pending session {pending}");
    assert_no_dial("rekey msg2 to a closed link", &r);
    assert!(!pending, "a failed rekey msg2 send stores no session");
}

/// Run the node's real rx loop, inject `poisoned` TCP msg1 frames whose reply
/// address is blackholed, then send one genuine msg1 over UDP and return how
/// long the UDP initiator waits for its msg2.
async fn udp_msg2_latency(connect_timeout_ms: u64, poisoned: usize) -> Duration {
    let (mut node, tx, udp_addr) = node_with_udp_and_tcp(connect_timeout_ms).await;
    let holes: Vec<Blackhole> = (0..poisoned).map(|_| Blackhole::silent()).collect();
    let poison: Vec<ReceivedPacket> = holes
        .iter()
        .enumerate()
        .map(|(i, bh)| {
            let data = craft_msg1(&node, &Identity::generate(), 0x100 + i as u32);
            ReceivedPacket::new(TransportId::new(TCP_ID), bh.transport_addr(), data)
        })
        .collect();
    let udp_msg1 = craft_msg1(&node, &Identity::generate(), 0x200);
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Long enough to measure a regression, one timeout per poisoned frame,
    // rather than only reporting that it was slow.
    let budget = Duration::from_millis(connect_timeout_ms * poisoned as u64 + 3000);
    let measure = async {
        for p in poison {
            tx.send(p).await.unwrap();
        }
        // Let the loop pick up the TCP frames before the UDP one arrives.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let t0 = Instant::now();
        peer.send_to(&udp_msg1, udp_addr).await.unwrap();
        let mut buf = [0u8; 2048];
        loop {
            let (n, _) = timeout(budget, peer.recv_from(&mut buf))
                .await
                .expect("no msg2 over UDP within budget")
                .unwrap();
            if CommonPrefix::parse(&buf[..n]).is_some_and(|p| p.phase == PHASE_MSG2) {
                return t0.elapsed();
            }
        }
    };

    let latency = tokio::select! {
        r = node.run_rx_loop() => panic!("rx loop exited: {r:?}"),
        l = measure => l,
    };
    stop_all(&mut node).await;
    drop(holes);
    latency
}

/// Inside the real rx loop, a UDP initiator's msg2 does not wait
/// behind TCP msg1s whose replies have nowhere to go.
#[tokio::test]
async fn udp_handshake_is_not_delayed_by_dead_tcp_replies_in_rx_loop() {
    for poisoned in [0usize, 3] {
        let latency = udp_msg2_latency(CONNECT_TIMEOUT_MS, poisoned).await;
        println!(
            "rx loop       connect_timeout_ms={CONNECT_TIMEOUT_MS} blackholed TCP msg1 ahead={poisoned}: UDP msg2 after {latency:?}"
        );
        assert!(
            latency < BOUND,
            "UDP msg2 took {latency:?} behind {poisoned} dead TCP replies (bound {BOUND:?})"
        );
    }
}

/// A counter from the off-loop `show_transports` view.
fn snapshot_stat(
    handle: &crate::control::read_handle::ControlReadHandle,
    id: u32,
    key: &str,
) -> u64 {
    let v = crate::control::queries::show_transports_from_handle(handle);
    v["transports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["transport_id"] == id)
        .and_then(|t| t["stats"][key].as_u64())
        .unwrap_or_else(|| panic!("no stats.{key} for transport {id}: {v}"))
}

/// The longest the tick may go without publishing during the burst. It
/// runs every second, so a longer gap means a tick was held.
const SNAPSHOT_LAG: Duration = Duration::from_millis(1500);

/// What the off-loop view and the tick did during a burst of UDP traffic.
#[derive(Debug)]
struct TickProgress {
    /// UDP frames sent during the burst.
    sent: u64,
    /// Off-loop reads of UDP `packets_recv` taken once traffic had arrived.
    checks: usize,
    /// The reads that fell outside the live count sampled just before and
    /// just after, as (ms into the burst, live before, view, live after).
    off: Vec<(u128, u64, u64, u64)>,
    /// Entity snapshot publishes seen during the burst.
    publishes: usize,
    /// The longest stretch of the burst with no publish, counting from its
    /// start and to its end.
    max_gap: Duration,
    /// Off-loop TCP `connect_timeouts` at the end of the burst.
    snapshot_timeouts: u64,
    /// Live TCP `connect_timeouts` at the end of the burst.
    live_timeouts: u64,
}

/// Queue `poisoned` TCP msg1s whose replies are blackholed, then send junk
/// UDP for a few seconds while the real rx loop runs. Throughout the burst,
/// read the off-loop `show_transports` view between two live samples, and
/// watch for the tick's entity snapshot publishes.
async fn tick_progress(poisoned: usize) -> TickProgress {
    let ms = 300u64;
    let (mut node, tx, udp_addr) = node_with_udp_and_tcp(ms).await;
    let handle = node.control_read_handle();
    let live_tcp = match tcp(&node) {
        TransportHandle::Tcp(t) => t.stats().clone(),
        _ => unreachable!(),
    };
    let live_udp = match node.transports.get(&TransportId::new(UDP_ID)) {
        Some(TransportHandle::Udp(t)) => t.stats().clone(),
        _ => unreachable!(),
    };
    let bh = Blackhole::silent();
    let poison: Vec<ReceivedPacket> = (0..poisoned)
        .map(|i| {
            let data = craft_msg1(&node, &Identity::generate(), 0x300 + i as u32);
            ReceivedPacket::new(TransportId::new(TCP_ID), bh.transport_addr(), data)
        })
        .collect();
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let measure = async {
        // The interval's first tick fires at once and publishes a snapshot.
        tokio::time::sleep(Duration::from_millis(100)).await;
        for p in poison {
            tx.send(p).await.unwrap();
        }
        // UDP keeps arriving. Junk frames are enough: the transport counts
        // them before the rx loop ever sees them. Fourteen replies that each
        // dialed for 300 ms would hold the loop longer than the whole burst.
        let t0 = Instant::now();
        let mut sent = 0u64;
        let mut checks = 0;
        let mut off = Vec::new();
        // Holding the last publish seen keeps its allocation alive, so a
        // later publish cannot reuse the address and pass for the same one.
        let mut last = std::sync::Arc::clone(&*handle.entities());
        let mut last_at = Duration::ZERO;
        let mut publishes = 0;
        let mut max_gap = Duration::ZERO;
        while t0.elapsed() < Duration::from_millis(3600) {
            peer.send_to(b"junk-frame", udp_addr).await.unwrap();
            sent += 1;
            let before = live_udp.snapshot().packets_recv;
            let view = snapshot_stat(&handle, UDP_ID, "packets_recv");
            let after = live_udp.snapshot().packets_recv;
            let now = t0.elapsed();
            // A zero count says nothing about whether the view is live.
            if before > 0 {
                checks += 1;
                if view < before || view > after {
                    off.push((now.as_millis(), before, view, after));
                }
            }
            let current = std::sync::Arc::clone(&*handle.entities());
            if !std::sync::Arc::ptr_eq(&current, &last) {
                publishes += 1;
                max_gap = max_gap.max(now - last_at);
                last = current;
                last_at = now;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        max_gap = max_gap.max(t0.elapsed() - last_at);
        TickProgress {
            sent,
            checks,
            off,
            publishes,
            max_gap,
            snapshot_timeouts: snapshot_stat(&handle, TCP_ID, "connect_timeouts"),
            live_timeouts: live_tcp.snapshot().connect_timeouts,
        }
    };

    let progress = tokio::select! {
        r = node.run_rx_loop() => panic!("rx loop exited: {r:?}"),
        m = measure => m,
    };
    stop_all(&mut node).await;
    progress
}

/// While dead TCP replies are queued, the rx loop's tick keeps running and
/// publishing, and the off-loop `show_transports` view tracks the live
/// counters throughout: it reads them at request time rather than from the
/// tick's copy, so it would stay current even if the tick were held.
#[tokio::test]
async fn tick_runs_and_snapshot_tracks_live_counters_under_dead_tcp_replies() {
    for poisoned in [0usize, 14] {
        let p = tick_progress(poisoned).await;
        println!("tick          {poisoned} dead TCP replies queued: {p:?}");
        assert!(
            p.checks >= 20,
            "only {} off-loop reads made from {} UDP frames; the burst did not exercise the view",
            p.checks,
            p.sent
        );
        assert!(
            p.off.is_empty(),
            "with {poisoned} dead replies queued the off-loop view did not track the live UDP \
             packets_recv in {} of {} reads, first and last (ms, live before, view, live after) \
             {:?} {:?}",
            p.off.len(),
            p.checks,
            p.off.first(),
            p.off.last()
        );
        assert!(
            p.max_gap < SNAPSHOT_LAG,
            "with {poisoned} dead replies queued the tick was held: {} publishes, longest gap \
             {:?} (bound {SNAPSHOT_LAG:?})",
            p.publishes,
            p.max_gap
        );
        assert_eq!(p.live_timeouts, 0, "a reply dialed and timed out");
        assert_eq!(p.snapshot_timeouts, p.live_timeouts);
    }
}

/// Through the real accept and receive tasks: a client that sends a
/// msg1 and closes before the node answers draws no connect attempt. With
/// the client still connected, the msg2 goes back on its connection.
///
/// Over loopback a SYN to the closed client port is answered with a reset,
/// so a dialing reply fails fast with a refusal here rather than stalling;
/// this checks the trigger, and the counters are what show a dial.
#[tokio::test]
async fn msg1_then_close_over_real_tcp_makes_no_connect_attempt() {
    // Control: the client stays connected.
    let (mut node, _tx, _) = node_with_udp_and_tcp(CONNECT_TIMEOUT_MS).await;
    let (mut client, packet) = msg1_over_real_tcp(&mut node).await;
    let r = timed_process(&mut node, packet).await;
    let answered = client_gets_msg2(&mut client).await;
    println!("open-close control client connected: {r:?}, msg2 received {answered}");
    assert_no_dial("open-close control", &r);
    assert!(answered, "control: the connected client got no msg2");
    stop_all(&mut node).await;

    let (mut node, _tx, _) = node_with_udp_and_tcp(CONNECT_TIMEOUT_MS).await;
    let (client, packet) = msg1_over_real_tcp(&mut node).await;
    drop(client);
    wait_pool_gone(&node, &packet.remote_addr).await;
    let pool_outbound = tcp_stats(&node).pool_outbound;
    let r = timed_process(&mut node, packet).await;
    println!("open-close    client closed first: {r:?}");
    assert_no_dial("msg1 then close", &r);
    assert_eq!(
        tcp_stats(&node).pool_outbound,
        pool_outbound,
        "a new outbound pool entry appeared"
    );
    assert_eq!(node.peer_count(), 0);
    stop_all(&mut node).await;
}

/// The handshake and link sends the rx loop awaits, other than those
/// covered above, that may reach a TCP link which has gone away.
#[derive(Clone, Copy, Debug)]
enum ReplySite {
    /// A second msg1 from the address of a pending inbound handshake: the
    /// stored msg2 is resent before any crypto.
    DuplicateMsg1,
    /// A resend of the setup msg1 from an established peer whose session is
    /// too young to rekey: the stored msg2 is resent on the established link.
    ResendMsg2,
    /// A resend of the rekey msg1 we already answered: the held answer is
    /// resent on the established link.
    ResendRekeyMsg2,
    /// The tick's resend of a rekey msg1 to an inbound peer.
    RekeyMsg1Resend,
    /// The executor's send of the msg1 armed by an outbound dial.
    StoredMsg1,
    /// An encrypted link message to a peer this node dialed.
    LinkMessage,
    /// An encrypted link message to a peer that dialed this node.
    LinkMessageInbound,
}

impl ReplySite {
    /// Whether the site, finding no connection, starts a background
    /// connect: only toward an address this node dialed.
    fn connects(self) -> bool {
        matches!(self, ReplySite::StoredMsg1 | ReplySite::LinkMessage)
    }
}

/// Bring `row`'s site within one call of firing against a live connection
/// at `bh`, and return the node, the far end, and that call.
async fn arm_site(row: ReplySite, bh: &Blackhole) -> (Node, std::net::TcpStream, Trigger) {
    let tcp_id = TransportId::new(TCP_ID);
    let link = bh.transport_addr();
    match row {
        ReplySite::DuplicateMsg1 => {
            let (mut node, _tx, _) = node_with_udp_and_tcp(CONNECT_TIMEOUT_MS).await;
            let far_end = prime_link(&node, bh).await;
            let link_id = node.allocate_link_id();
            node.links.insert(
                link_id,
                Link::new(
                    link_id,
                    tcp_id,
                    link.clone(),
                    LinkDirection::Inbound,
                    Duration::from_millis(100),
                ),
            );
            node.addr_to_link.insert((tcp_id, link.clone()), link_id);
            node.seed_handshake_machine(
                HandshakeSeed::inbound(link_id, 1000)
                    .with_transport_id(tcp_id)
                    .with_source_addr(link.clone()),
            )
            .unwrap();
            let mut stored = vec![0u8; 69];
            stored[0] = PHASE_MSG2;
            stored[2..4].copy_from_slice(&65u16.to_le_bytes());
            node.peer_machines
                .get_mut(&link_id)
                .unwrap()
                .set_conn_handshake_msg2(stored);
            let data = craft_msg1(&node, &Identity::generate(), 0x21);
            let packet = ReceivedPacket::new(tcp_id, link, data);
            (node, far_end, Trigger::Packet(packet))
        }
        ReplySite::ResendMsg2 => {
            let (mut node, sender, sender_addr, far_end) = peer_on_tcp(bh).await;
            let data = craft_msg1(&node, &sender, 0x22);
            node.get_peer_mut(&sender_addr)
                .unwrap()
                .note_setup(crate::proto::fmp::Msg1Digest::of(&data));
            let packet = ReceivedPacket::new(tcp_id, elsewhere(), data);
            (node, far_end, Trigger::Packet(packet))
        }
        ReplySite::ResendRekeyMsg2 => {
            let (mut node, sender, sender_addr, mut far_end) = peer_on_tcp(bh).await;
            node.get_peer_mut(&sender_addr)
                .unwrap()
                .test_backdate_session_established(Duration::from_secs(31));
            let data = craft_msg1(&node, &sender, 0x23);
            node.process_packet(ReceivedPacket::new(tcp_id, link.clone(), data.clone()))
                .await;
            assert!(
                node.get_peer(&sender_addr)
                    .is_some_and(|p| p.pending_new_session().is_some()),
                "the first rekey msg1 armed a pending session"
            );
            assert!(
                read_frame(&mut far_end).await.is_some(),
                "the rekey msg2 went out on the connection"
            );
            let packet = ReceivedPacket::new(tcp_id, link, data);
            (node, far_end, Trigger::Packet(packet))
        }
        ReplySite::RekeyMsg1Resend => {
            let (mut node, _sender, sender_addr, mut far_end) = peer_on_tcp(bh).await;
            age_past_rekey(&mut node, &sender_addr);
            node.check_rekey().await;
            assert!(
                node.get_peer(&sender_addr)
                    .is_some_and(|p| p.rekey_in_progress()),
                "the rekey cycle started"
            );
            assert!(
                read_frame(&mut far_end).await.is_some_and(|f| is_msg1(&f)),
                "the rekey msg1 went out on the connection"
            );
            (node, far_end, Trigger::RekeyResend)
        }
        ReplySite::StoredMsg1 => {
            let (mut node, _tx, _) = node_with_udp_and_tcp(CONNECT_TIMEOUT_MS).await;
            let far_end = prime_link(&node, bh).await;
            let now_ms = Node::now_ms();
            let (link_id, _) = dial_leg(&mut node, &link, now_ms, now_ms + 1000);
            (node, far_end, Trigger::StoredMsg1(link_id, link))
        }
        ReplySite::LinkMessage => {
            let (mut node, _sender, sender_addr, far_end) = peer_on_tcp(bh).await;
            make_link_outbound(&mut node, &sender_addr);
            (node, far_end, Trigger::LinkMessage(sender_addr))
        }
        ReplySite::LinkMessageInbound => {
            let (node, _sender, sender_addr, far_end) = peer_on_tcp(bh).await;
            (node, far_end, Trigger::LinkMessage(sender_addr))
        }
    }
}

/// Fire `row`'s site with its established connection closed (or, with
/// `dead` false, still open). Returns the measurement, whether the far end
/// received the send, and the transport's connection state for the far
/// end's address afterwards.
async fn fire_site(row: ReplySite, dead: bool) -> (Reply, bool, ConnectionState) {
    let mut bh = Blackhole::open(false);
    let (mut node, far_end, trigger) = arm_site(row, &bh).await;
    let mut far_end = if dead {
        kill_link(&node, &mut bh, far_end).await;
        None
    } else {
        Some(far_end)
    };
    let r = timed_fire(&mut node, trigger).await;
    let delivered = read_maybe(far_end.as_mut()).await.is_some();
    let state = tcp(&node).connection_state(&bh.transport_addr());
    stop_all(&mut node).await;
    (r, delivered, state)
}

/// Every send the rx loop awaits on a TCP link that has gone away returns
/// at once without a connect attempt, and with the link alive the send is
/// delivered. Only a send toward an address this node dialed leaves a
/// background connect behind.
#[tokio::test]
async fn every_rx_loop_handshake_send_to_dead_tcp_link_is_bounded() {
    // Every row runs before any assertion, so one red names all the sites
    // that dial rather than only the first.
    let mut found = Vec::new();
    for row in [
        ReplySite::DuplicateMsg1,
        ReplySite::ResendMsg2,
        ReplySite::ResendRekeyMsg2,
        ReplySite::RekeyMsg1Resend,
        ReplySite::StoredMsg1,
        ReplySite::LinkMessage,
        ReplySite::LinkMessageInbound,
    ] {
        let (r, delivered, _) = fire_site(row, false).await;
        println!("{row:?} control link alive: {r:?}, delivered {delivered}");
        found.extend(dial_findings(&format!("{row:?} control"), &r));
        if !delivered {
            found.push(format!("{row:?} control: the send was not delivered"));
        }

        let (r, _, state) = fire_site(row, true).await;
        println!("{row:?} dead link closed: {r:?}, afterwards {state:?}");
        found.extend(dial_findings(&format!("{row:?} to a closed link"), &r));
        let expected = if row.connects() {
            ConnectionState::Connecting
        } else {
            ConnectionState::None
        };
        if state != expected {
            found.push(format!(
                "{row:?} to a closed link: connection state {state:?}, expected {expected:?}"
            ));
        }
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}

/// A rekey msg1 copy that arrives over UDP from an address unrelated to the
/// peer is never answered at its source. While the peer's established TCP
/// connection is up the copy is off that link and refused outright; with the
/// connection gone it is not answered either, since a connectionless source
/// address is whatever the sender wrote.
#[tokio::test]
async fn a_rekey_msg1_copy_over_udp_is_never_answered_at_its_source() {
    for dead in [false, true] {
        let mut bh = Blackhole::open(false);
        let (mut node, sender, sender_addr, far_end) = peer_on_tcp(&bh).await;
        let mut far_end = if dead {
            kill_link(&node, &mut bh, far_end).await;
            None
        } else {
            Some(far_end)
        };
        node.get_peer_mut(&sender_addr)
            .unwrap()
            .test_backdate_session_established(Duration::from_secs(31));

        let source = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let from = TransportAddr::from_string(&source.local_addr().unwrap().to_string());
        let data = craft_msg1(&node, &sender, 0x31);
        let r = timed_process(
            &mut node,
            ReceivedPacket::new(TransportId::new(UDP_ID), from, data),
        )
        .await;
        let mut buf = [0u8; 2048];
        let at_source = timeout(Duration::from_millis(300), source.recv_from(&mut buf))
            .await
            .is_ok();
        let on_link = read_maybe(far_end.as_mut())
            .await
            .is_some_and(|f| CommonPrefix::parse(&f).is_some_and(|p| p.phase == PHASE_MSG2));
        let pending = node
            .get_peer(&sender_addr)
            .is_some_and(|p| p.pending_new_session().is_some());
        stop_all(&mut node).await;
        println!(
            "udp copy     link dead {dead}: {r:?}, msg2 on link {on_link}, at source {at_source}, pending {pending}"
        );

        assert_no_dial("rekey msg1 copy over UDP", &r);
        assert!(!at_source, "a msg2 was sent to the copy's UDP source");
        assert!(
            !on_link,
            "a msg2 went out on the established link for a copy off it"
        );
        assert!(!pending, "an unanswered rekey msg1 stores no session");
    }
}

/// Run one send toward an outbound TCP peer whose current address an
/// authenticated frame has moved away from the address the link was dialed
/// at: the tick's rekey msg1 (`rekey`) or a link message. The connection at
/// the moved address is open, or (with `dead`) closed with the address no
/// longer answering. Returns the measurement, whether the send arrived at
/// the moved address, and the connection state there afterwards.
async fn moved_send(rekey: bool, dead: bool) -> (Reply, bool, ConnectionState) {
    let bh = Blackhole::open(false);
    let (mut node, _sender, sender_addr, _dialed_end) = peer_on_tcp(&bh).await;
    make_link_outbound(&mut node, &sender_addr);
    let mut moved = Blackhole::open(false);
    let moved_end = prime_link(&node, &moved).await;
    node.get_peer_mut(&sender_addr)
        .unwrap()
        .set_current_addr(TransportId::new(TCP_ID), moved.transport_addr());
    let mut moved_end = if dead {
        kill_link(&node, &mut moved, moved_end).await;
        None
    } else {
        Some(moved_end)
    };
    let trigger = if rekey {
        age_past_rekey(&mut node, &sender_addr);
        Trigger::RekeyCheck
    } else {
        Trigger::LinkMessage(sender_addr)
    };
    let r = timed_fire(&mut node, trigger).await;
    let delivered = read_maybe(moved_end.as_mut()).await.is_some();
    let state = tcp(&node).connection_state(&moved.transport_addr());
    stop_all(&mut node).await;
    (r, delivered, state)
}

/// A peer this node dialed, whose current address has moved, is sent to at
/// the moved address. With the connection there gone the send fails at once
/// and starts no connect toward it: only the address the link was dialed at
/// is known to have a listener, and the moved one may be an ephemeral port.
#[tokio::test]
async fn send_to_moved_outbound_peer_does_not_connect_to_its_moved_address() {
    for rekey in [false, true] {
        let what = if rekey { "rekey msg1" } else { "link message" };
        let (r, delivered, _) = moved_send(rekey, false).await;
        println!("moved peer   {what} control connection open: {r:?}, delivered {delivered}");
        assert_no_dial(&format!("moved peer {what} control"), &r);
        assert!(
            delivered,
            "control: the {what} did not go to the moved address"
        );

        let (r, _, state) = moved_send(rekey, true).await;
        println!("moved peer   {what} connection closed: {r:?}, afterwards {state:?}");
        assert_no_dial(&format!("moved peer {what} to a closed connection"), &r);
        assert_eq!(
            state,
            ConnectionState::None,
            "the {what} started a connect toward the peer's moved address"
        );
    }
}

/// A second TCP transport on the node, as a node with two TCP listeners has.
const TCP2_ID: u32 = 3;

/// Add a second, started TCP transport to `node`. Its frames go to a channel
/// of their own, which the caller keeps alive.
async fn add_second_tcp(node: &mut Node) -> PacketRx {
    let (tx, rx) = packet_channel(64);
    let cfg = TcpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1400),
        connect_timeout_ms: Some(CONNECT_TIMEOUT_MS),
        ..Default::default()
    };
    let mut t = TcpTransport::new(TransportId::new(TCP2_ID), None, cfg, tx);
    t.start_async().await.unwrap();
    node.transports
        .insert(TransportId::new(TCP2_ID), TransportHandle::Tcp(t));
    rx
}

/// A real TCP client connected to the listener of transport `tid`, and its
/// address as that transport's connection pool holds it.
async fn client_on(node: &Node, tid: TransportId) -> (tokio::net::TcpStream, TransportAddr) {
    let transport = node.transports.get(&tid).expect("no such transport");
    let listen = transport.local_addr().expect("TCP listener bound");
    let client = tokio::net::TcpStream::connect(listen).await.unwrap();
    let from = TransportAddr::from_string(&client.local_addr().unwrap().to_string());
    let start = Instant::now();
    while transport.connection_state(&from) != ConnectionState::Connected {
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "the client's connection never entered the pool"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (client, from)
}

/// A same-epoch rekey msg1 from a TCP peer whose established connection has
/// gone is answered on the connection it arrived on when that connection is
/// on the established link's transport. Arriving on another TCP transport it
/// is not answered: the new session's index would be registered under a
/// transport the peer's frames are not looked up on, and that the
/// retirement paths do not remove it from.
#[tokio::test]
async fn a_rekey_msg1_is_answered_on_its_connection_only_on_the_established_transport() {
    for other in [false, true] {
        let mut bh = Blackhole::open(false);
        let (mut node, sender, sender_addr, far_end) = peer_on_tcp(&bh).await;
        kill_link(&node, &mut bh, far_end).await;
        node.get_peer_mut(&sender_addr)
            .unwrap()
            .test_backdate_session_established(Duration::from_secs(31));
        let (arrival, _rx) = if other {
            (
                TransportId::new(TCP2_ID),
                Some(add_second_tcp(&mut node).await),
            )
        } else {
            (TransportId::new(TCP_ID), None)
        };

        let (mut client, from) = client_on(&node, arrival).await;
        let data = craft_msg1(&node, &sender, 0x41);
        let r = timed_process(&mut node, ReceivedPacket::new(arrival, from, data)).await;
        let answered = client_gets_msg2(&mut client).await;
        let pending = node
            .get_peer(&sender_addr)
            .is_some_and(|p| p.pending_new_session().is_some());
        let indexed = node
            .get_peer(&sender_addr)
            .and_then(|p| p.pending_our_index())
            .is_some_and(|i| node.peers_by_index.contains_key(&i.as_u32()));
        stop_all(&mut node).await;
        println!(
            "redial       other transport {other}: {r:?}, answered {answered}, pending {pending}, indexed {indexed}"
        );

        assert_no_dial("rekey msg1 on a new connection", &r);
        if other {
            assert!(!answered, "a msg2 went out on another transport");
            assert!(!pending, "an unanswered rekey msg1 stores no session");
            assert!(!indexed, "an unanswered rekey msg1 registers no index");
        } else {
            assert!(answered, "the msg1's own connection got no msg2");
            assert!(pending, "the answered rekey stores its session");
            assert!(indexed, "the new index is registered");
        }
    }
}

/// A rekey msg1 answered on its own connection, because the established
/// connection has gone, logs the established link it could not use, and the
/// rekey answer records that the msg1 did not arrive on that link.
#[tokio::test]
async fn a_rekey_msg1_answered_on_its_own_connection_logs_the_established_link() {
    use crate::testutil::{capture_logs_scoped, log_field};

    let mut bh = Blackhole::open(false);
    let (mut node, sender, sender_addr, far_end) = peer_on_tcp(&bh).await;
    let link = bh.transport_addr();
    kill_link(&node, &mut bh, far_end).await;
    node.get_peer_mut(&sender_addr)
        .unwrap()
        .test_backdate_session_established(Duration::from_secs(31));
    let tcp_id = TransportId::new(TCP_ID);
    let (mut client, from) = client_on(&node, tcp_id).await;
    let data = craft_msg1(&node, &sender, 0x41);

    let (logs, guard) = capture_logs_scoped();
    let r = timed_process(&mut node, ReceivedPacket::new(tcp_id, from.clone(), data)).await;
    drop(guard);
    let answered = client_gets_msg2(&mut client).await;
    stop_all(&mut node).await;
    assert_no_dial("rekey msg1 on a new connection", &r);
    assert!(answered, "the msg1's own connection got no msg2");

    let field = |line: &str, name: &str| {
        log_field(line, name)
            .unwrap_or_else(|| panic!("no field {name} on {line}"))
            .to_string()
    };
    let fallback = logs
        .line("Established link not connected, answered on the msg1's connection")
        .unwrap_or_else(|| panic!("no fallback line in {:#?}", logs.lines()));
    assert_eq!(
        field(&fallback, "transport_id"),
        "transport:2",
        "{fallback}"
    );
    assert_eq!(
        field(&fallback, "remote_addr"),
        from.to_string(),
        "{fallback}"
    );
    assert_eq!(field(&fallback, "link_tid"), "transport:2", "{fallback}");
    assert_eq!(
        field(&fallback, "link_addr"),
        link.to_string(),
        "{fallback}"
    );

    let answer = logs
        .line("Sent rekey msg2 response")
        .unwrap_or_else(|| panic!("no rekey answer line in {:#?}", logs.lines()));
    assert_eq!(field(&answer, "same_path"), "false", "{answer}");
    assert_eq!(field(&answer, "transport_id"), "transport:2", "{answer}");
    assert_eq!(field(&answer, "remote_addr"), from.to_string(), "{answer}");
    assert_eq!(field(&answer, "link_tid"), "transport:2", "{answer}");
    assert_eq!(field(&answer, "link_addr"), link.to_string(), "{answer}");
}

/// `may_dial` allows a connect only toward the address an outbound link was
/// dialed at, on that link's transport: never for an inbound link, an
/// address the link has since moved to, another transport, or an unknown
/// link. A plain test, with no runtime or sockets.
#[test]
fn may_dial_allows_only_an_outbound_link_s_dial_address_on_its_transport() {
    let mut node = make_node();
    let tcp = TransportId::new(1);
    let dialed = TransportAddr::from_string("192.0.2.1:443");
    let moved = TransportAddr::from_string("192.0.2.1:50123");
    let (out, inb) = (LinkId::new(1), LinkId::new(2));
    for (id, dir) in [
        (out, LinkDirection::Outbound),
        (inb, LinkDirection::Inbound),
    ] {
        let link = Link::new(id, tcp, dialed.clone(), dir, Duration::from_millis(100));
        node.links.insert(id, link);
    }

    assert!(node.may_dial(out, tcp, &dialed), "outbound, dial address");
    assert!(!node.may_dial(out, tcp, &moved), "outbound, moved address");
    assert!(
        !node.may_dial(out, TransportId::new(2), &dialed),
        "outbound, other transport"
    );
    assert!(!node.may_dial(inb, tcp, &dialed), "inbound link");
    assert!(!node.may_dial(LinkId::new(3), tcp, &dialed), "unknown link");
}
