//! The link-setup and rekey classification lines carry the fields that let
//! one node's log say where a msg1 came from, which msg1 it was, and which
//! session it produced, and let two nodes' logs be joined line for line.
//!
//! Each test drives the condition a line reports through the real handler,
//! finds the line by its exact message, and checks the discriminating fields
//! against values derived independently: digests from the bytes the test
//! sent, session tags from the session the node holds afterwards, indices
//! and addresses from what the test chose.

use super::establish_chartests::{
    arm_local_rekey, craft_msg1_wire, establish_active_peer_via_msg1,
    register_udp_with_peer_socket, sender_with_addr_relation,
};
use super::*;
use crate::config::UdpConfig;
use crate::noise::NoiseSession;
use crate::proto::fmp::wire::{build_msg1, build_msg2};
use crate::testutil::{LogCapture, capture_logs_scoped, log_field};
use crate::transport::udp::UdpTransport;
use crate::transport::{PacketRx, TransportHandle, packet_channel};
use sha2::{Digest, Sha256};
use tokio::time::timeout;

pub(super) const EPOCH: [u8; 8] = [4u8; 8];

/// The first four bytes of `bytes` as 8 lowercase hex characters.
fn hex4(bytes: &[u8]) -> String {
    bytes[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// The tag a line should carry for the msg1 whose wire bytes are `wire`.
pub(super) fn msg1_tag(wire: &[u8]) -> String {
    hex4(&Sha256::digest(wire))
}

/// The tag a line should carry for `session`.
pub(super) fn session_tag(session: &NoiseSession) -> String {
    hex4(session.handshake_hash())
}

/// A session index as the lines display it.
pub(super) fn index_text(index: SessionIndex) -> String {
    format!("{:08x}", index.as_u32())
}

/// The line whose message is exactly `message`, or a panic listing every
/// captured line.
pub(super) fn expect_line(logs: &LogCapture, message: &str) -> String {
    logs.line(message)
        .unwrap_or_else(|| panic!("no line {message:?} in {:#?}", logs.lines()))
}

/// The value of `name` on `line`, or a panic naming the line.
pub(super) fn field(line: &str, name: &str) -> String {
    log_field(line, name)
        .unwrap_or_else(|| panic!("no field {name} on {line}"))
        .to_string()
}

pub(super) fn packet(
    tid: TransportId,
    from: &TransportAddr,
    data: Vec<u8>,
    ts: u64,
) -> ReceivedPacket {
    ReceivedPacket {
        transport_id: tid,
        remote_addr: from.clone(),
        data,
        timestamp_ms: ts,
    }
}

/// Discard every datagram already queued for `sock`.
pub(super) async fn drain(sock: &tokio::net::UdpSocket) {
    let mut buf = [0u8; 2048];
    while timeout(Duration::from_millis(150), sock.recv_from(&mut buf))
        .await
        .is_ok()
    {}
}

/// Stop the node's transport `tid`, so a send on it fails with `NotStarted`.
pub(super) async fn stop_transport(node: &mut Node, tid: TransportId) {
    node.transports
        .get_mut(&tid)
        .expect("transport registered")
        .stop()
        .await
        .expect("transport stops");
}

/// Run `node.handle_msg1(p)` with its log lines captured.
pub(super) async fn msg1_logged(node: &mut Node, p: ReceivedPacket) -> LogCapture {
    let (logs, guard) = capture_logs_scoped();
    node.handle_msg1(p).await;
    drop(guard);
    logs
}

/// Run `node.handle_msg2(p)` with its log lines captured.
async fn msg2_logged(node: &mut Node, p: ReceivedPacket) -> LogCapture {
    let (logs, guard) = capture_logs_scoped();
    node.handle_msg2(p).await;
    drop(guard);
    logs
}

/// A node with a UDP transport 1 and a peer promoted on it, its session aged
/// `age` seconds.
pub(super) struct Established {
    pub(super) node: Node,
    pub(super) sock: tokio::net::UdpSocket,
    pub(super) addr: TransportAddr,
    pub(super) sender: Identity,
    pub(super) peer: NodeAddr,
}

pub(super) async fn established(age: u64) -> Established {
    let mut node = make_node();
    let tid = TransportId::new(1);
    let (sock, addr) = register_udp_with_peer_socket(&mut node, tid).await;
    let sender = Identity::generate();
    let peer =
        establish_active_peer_via_msg1(&mut node, &sender, EPOCH, tid, &addr, &sock, 1000).await;
    node.get_peer_mut(&peer)
        .expect("peer promoted")
        .test_backdate_session_established(Duration::from_secs(age));
    Established {
        node,
        sock,
        addr,
        sender,
        peer,
    }
}

/// Arm a responder pending on `e` with a rekey msg1 carrying `sender_index`,
/// returning that msg1's wire bytes.
pub(super) async fn arm_pending(e: &mut Established, sender_index: u32) -> Vec<u8> {
    let tid = TransportId::new(1);
    let x = craft_msg1_wire(
        &e.node,
        &e.sender,
        EPOCH,
        SessionIndex::new(sender_index),
        2000,
    );
    e.node
        .handle_msg1(packet(tid, &e.addr, x.clone(), 2000))
        .await;
    assert!(
        e.node
            .get_peer(&e.peer)
            .is_some_and(|p| p.pending_new_session().is_some()),
        "the rekey msg1 armed a pending session"
    );
    drain(&e.sock).await;
    x
}

/// A resend of the setup msg1 inside the rekey age is answered with the
/// stored msg2, and the line says that msg2 answers it. A fresh msg1 at the
/// same epoch is not answered with that msg2, which could not complete it.
#[tokio::test]
async fn a_resent_setup_msg1_inside_the_rekey_age_is_answered_with_the_stored_msg2_and_a_fresh_one_is_not()
 {
    let mut node = make_node();
    let tid = TransportId::new(1);
    let (sock, addr) = register_udp_with_peer_socket(&mut node, tid).await;
    let sender = Identity::generate();
    let peer = *PeerIdentity::from_pubkey_full(sender.pubkey_full()).node_addr();
    let first = craft_msg1_wire(&node, &sender, EPOCH, SessionIndex::new(1), 1000);
    node.handle_msg1(packet(tid, &addr, first.clone(), 1000))
        .await;
    drain(&sock).await;
    node.get_peer_mut(&peer)
        .expect("the first msg1 promoted the peer")
        .test_backdate_session_established(Duration::from_secs(12));

    // Healthy path: the promoting msg1 itself, byte for byte.
    let logs = msg1_logged(&mut node, packet(tid, &addr, first.clone(), 2000)).await;
    let line = expect_line(&logs, "Resent msg2 for duplicate msg1 (same epoch)");
    assert_eq!(field(&line, "msg1_sidx"), "00000001", "{line}");
    assert_eq!(field(&line, "stored_ridx"), "00000001", "{line}");
    assert_eq!(field(&line, "answers_it"), "true", "{line}");
    assert_eq!(field(&line, "age_s"), "12", "{line}");
    assert_eq!(field(&line, "same_path"), "true", "{line}");
    assert_eq!(field(&line, "msg1_dg"), msg1_tag(&first), "{line}");
    assert_eq!(field(&line, "transport_id"), "transport:1", "{line}");
    assert_eq!(field(&line, "remote_addr"), addr.to_string(), "{line}");
    assert_eq!(field(&line, "link_tid"), "transport:1", "{line}");
    assert_eq!(field(&line, "link_addr"), addr.to_string(), "{line}");

    // A fresh msg1 takes the replacement path instead of the stored msg2.
    drain(&sock).await;
    let fresh = craft_msg1_wire(&node, &sender, EPOCH, SessionIndex::new(2), 3000);
    let logs = msg1_logged(&mut node, packet(tid, &addr, fresh, 3000)).await;
    assert!(
        logs.lines()
            .iter()
            .all(|l| !l.contains("Resent msg2 for duplicate msg1")),
        "a fresh msg1 drew the stored msg2: {:#?}",
        logs.lines()
    );
    expect_line(
        &logs,
        "Same-epoch msg1 from a silent peer, replacing its session",
    );

    stop_transport(&mut node, tid).await;
}

/// A failed duplicate resend carries the same fields as a successful one.
#[tokio::test]
async fn a_failed_duplicate_resend_logs_the_msg1_path() {
    let mut node = make_node();
    let tid = TransportId::new(1);
    let (sock, addr) = register_udp_with_peer_socket(&mut node, tid).await;
    let sender = Identity::generate();
    let peer = *PeerIdentity::from_pubkey_full(sender.pubkey_full()).node_addr();
    let first = craft_msg1_wire(&node, &sender, EPOCH, SessionIndex::new(1), 1000);
    node.handle_msg1(packet(tid, &addr, first.clone(), 1000))
        .await;
    drain(&sock).await;
    node.get_peer_mut(&peer)
        .expect("the first msg1 promoted the peer")
        .test_backdate_session_established(Duration::from_secs(12));
    stop_transport(&mut node, tid).await;

    let logs = msg1_logged(&mut node, packet(tid, &addr, first.clone(), 2000)).await;
    let line = expect_line(&logs, "Failed to resend msg2");
    assert_eq!(field(&line, "same_path"), "true", "{line}");
    assert_eq!(field(&line, "link_tid"), "transport:1", "{line}");
    assert_eq!(field(&line, "answers_it"), "true", "{line}");
    assert_eq!(field(&line, "msg1_dg"), msg1_tag(&first), "{line}");
    assert_eq!(field(&line, "transport_id"), "transport:1", "{line}");
}

/// A rekey msg1 that arrives on a transport other than the peer's
/// established link, while that link works, is refused, and the line records
/// that the two paths differ. A rekey msg1 on the link itself reads as the
/// same path and is answered.
#[tokio::test]
async fn a_rekey_msg1_on_a_second_transport_is_refused_and_logs_that_it_is_off_the_established_path()
 {
    let mut e = established(31).await;
    let tid2 = TransportId::new(2);
    let (_sock2, addr2) = register_udp_with_peer_socket(&mut e.node, tid2).await;
    let rekey = craft_msg1_wire(&e.node, &e.sender, EPOCH, SessionIndex::new(0x0B0B), 2000);
    let logs = msg1_logged(&mut e.node, packet(tid2, &addr2, rekey.clone(), 2000)).await;

    let line = expect_line(
        &logs,
        "Same-epoch msg1 off the established link while that link is up, dropping",
    );
    assert_eq!(field(&line, "same_path"), "false", "{line}");
    assert_eq!(field(&line, "transport_id"), "transport:2", "{line}");
    assert_eq!(field(&line, "remote_addr"), addr2.to_string(), "{line}");
    assert_eq!(field(&line, "msg1_dg"), msg1_tag(&rekey), "{line}");
    assert!(
        e.node
            .get_peer(&e.peer)
            .expect("peer present")
            .pending_new_session()
            .is_none(),
        "the refused msg1 armed no pending"
    );
    stop_transport(&mut e.node, TransportId::new(1)).await;
    stop_transport(&mut e.node, tid2).await;

    // Healthy path, on a fresh node: the second copy of the same msg1 on the
    // first node would be a resend of the msg1 that armed its pending.
    let mut e = established(31).await;
    let tid = TransportId::new(1);
    let rekey = craft_msg1_wire(&e.node, &e.sender, EPOCH, SessionIndex::new(0x0B0B), 2000);
    let logs = msg1_logged(&mut e.node, packet(tid, &e.addr, rekey.clone(), 2000)).await;
    let line = expect_line(&logs, "Sent rekey msg2 response");
    assert_eq!(field(&line, "same_path"), "true", "{line}");
    assert_eq!(field(&line, "transport_id"), "transport:1", "{line}");
    assert_eq!(field(&line, "link_tid"), "transport:1", "{line}");
    assert_eq!(field(&line, "msg1_dg"), msg1_tag(&rekey), "{line}");
    stop_transport(&mut e.node, tid).await;
}

/// A rekey answer that cannot be sent carries the msg1's path.
#[tokio::test]
async fn a_failed_rekey_answer_logs_the_msg1_path() {
    let mut e = established(31).await;
    let tid = TransportId::new(1);
    stop_transport(&mut e.node, tid).await;
    let rekey = craft_msg1_wire(&e.node, &e.sender, EPOCH, SessionIndex::new(0x0C0C), 2000);
    let logs = msg1_logged(&mut e.node, packet(tid, &e.addr, rekey.clone(), 2000)).await;

    let line = expect_line(&logs, "Failed to send rekey msg2");
    assert!(line.starts_with("WARN"), "{line}");
    assert_eq!(field(&line, "transport_id"), "transport:1", "{line}");
    assert_eq!(field(&line, "remote_addr"), e.addr.to_string(), "{line}");
    assert_eq!(field(&line, "link_tid"), "transport:1", "{line}");
    assert_eq!(field(&line, "same_path"), "true", "{line}");
    assert_eq!(field(&line, "msg1_sidx"), "00000c0c", "{line}");
    assert_eq!(field(&line, "msg1_dg"), msg1_tag(&rekey), "{line}");
}

/// A second rekey msg1 refused while a pending is held names both msg1s and
/// how long the pending has been held.
#[tokio::test]
async fn a_second_rekey_msg1_while_a_pending_is_held_logs_the_held_digest() {
    let mut e = established(31).await;
    let tid = TransportId::new(1);
    let x = arm_pending(&mut e, 0x0D01).await;
    e.node
        .get_peer_mut(&e.peer)
        .unwrap()
        .backdate_pending(Duration::from_secs(40));
    let y = craft_msg1_wire(&e.node, &e.sender, EPOCH, SessionIndex::new(0x0D02), 3000);
    let logs = msg1_logged(&mut e.node, packet(tid, &e.addr, y.clone(), 3000)).await;

    let line = expect_line(
        &logs,
        "Rekey msg1 received but already have pending session, dropping",
    );
    assert_eq!(field(&line, "msg1_dg"), msg1_tag(&y), "{line}");
    assert_eq!(field(&line, "held_dg"), msg1_tag(&x), "{line}");
    assert_ne!(msg1_tag(&x), msg1_tag(&y));
    assert_eq!(field(&line, "pending_age_s"), "40", "{line}");
    assert_eq!(field(&line, "same_path"), "true", "{line}");
    assert_eq!(field(&line, "transport_id"), "transport:1", "{line}");
    assert_eq!(field(&line, "remote_addr"), e.addr.to_string(), "{line}");
    stop_transport(&mut e.node, tid).await;
}

/// A rekey msg1 dropped because this node wins the dual-initiation
/// tie-break carries its path.
#[tokio::test]
async fn a_rekey_msg1_that_loses_the_dual_initiation_tie_break_logs_its_path() {
    let mut node = make_node();
    let tid = TransportId::new(1);
    let (sock, addr) = register_udp_with_peer_socket(&mut node, tid).await;
    let sender = sender_with_addr_relation(&node, true);
    let peer =
        establish_active_peer_via_msg1(&mut node, &sender, EPOCH, tid, &addr, &sock, 1000).await;
    node.get_peer_mut(&peer)
        .unwrap()
        .test_backdate_session_established(Duration::from_secs(31));
    arm_local_rekey(&mut node, &sender, &peer);

    let theirs = craft_msg1_wire(&node, &sender, EPOCH, SessionIndex::new(0xAAAA), 2000);
    let logs = msg1_logged(&mut node, packet(tid, &addr, theirs.clone(), 2000)).await;
    let line = expect_line(
        &logs,
        "Dual rekey initiation: we win (smaller addr), dropping their msg1",
    );
    assert_eq!(field(&line, "transport_id"), "transport:1", "{line}");
    assert_eq!(field(&line, "remote_addr"), addr.to_string(), "{line}");
    assert_eq!(field(&line, "same_path"), "true", "{line}");
    assert_eq!(field(&line, "msg1_dg"), msg1_tag(&theirs), "{line}");
    stop_transport(&mut node, tid).await;
}

/// A copy of a msg1 whose responder cycle has ended carries its path.
#[tokio::test]
async fn a_msg1_from_an_ended_rekey_cycle_logs_its_path() {
    let mut e = established(31).await;
    let tid = TransportId::new(1);
    let x = arm_pending(&mut e, 0x0E01).await;
    e.node
        .get_peer_mut(&e.peer)
        .unwrap()
        .retire_pending()
        .expect("the responder pending is retired");
    let logs = msg1_logged(&mut e.node, packet(tid, &e.addr, x.clone(), 3000)).await;

    let line = expect_line(
        &logs,
        "Rekey msg1 answered in an ended cycle, dropping the copy",
    );
    assert_eq!(field(&line, "transport_id"), "transport:1", "{line}");
    assert_eq!(field(&line, "remote_addr"), e.addr.to_string(), "{line}");
    assert_eq!(field(&line, "same_path"), "true", "{line}");
    assert_eq!(field(&line, "msg1_dg"), msg1_tag(&x), "{line}");
    stop_transport(&mut e.node, tid).await;
}

/// A resend of the msg1 that armed the held pending is answered again, and
/// both the answer and a failure to send it carry the msg1's path.
#[tokio::test]
async fn a_resent_rekey_msg1_logs_its_path() {
    let mut e = established(31).await;
    let tid = TransportId::new(1);
    let x = arm_pending(&mut e, 0x0F01).await;

    let logs = msg1_logged(&mut e.node, packet(tid, &e.addr, x.clone(), 3000)).await;
    let line = expect_line(&logs, "Resent rekey msg2 for a resent msg1");
    assert_eq!(field(&line, "same_path"), "true", "{line}");
    assert_eq!(field(&line, "transport_id"), "transport:1", "{line}");
    assert_eq!(field(&line, "remote_addr"), e.addr.to_string(), "{line}");

    stop_transport(&mut e.node, tid).await;
    let logs = msg1_logged(&mut e.node, packet(tid, &e.addr, x.clone(), 4000)).await;
    let line = expect_line(&logs, "Failed to resend rekey msg2");
    assert_eq!(field(&line, "same_path"), "true", "{line}");
    assert_eq!(field(&line, "transport_id"), "transport:1", "{line}");
    assert_eq!(field(&line, "remote_addr"), e.addr.to_string(), "{line}");
}

/// A pending inbound link with a stored msg2, as a lost msg2 leaves it.
fn pending_inbound(node: &mut Node, tid: TransportId, addr: &TransportAddr) -> LinkId {
    let link_id = node.allocate_link_id();
    let link = Link::connectionless(
        link_id,
        tid,
        addr.clone(),
        LinkDirection::Inbound,
        Duration::from_millis(100),
    );
    node.links.insert(link_id, link);
    node.addr_to_link.insert((tid, addr.clone()), link_id);
    node.seed_handshake_machine(
        HandshakeSeed::inbound(link_id, 1000)
            .with_transport_id(tid)
            .with_source_addr(addr.clone()),
    )
    .unwrap();
    node.peer_machines
        .get_mut(&link_id)
        .unwrap()
        .set_conn_handshake_msg2(vec![0xC1, 0xC2, 0xC3, 0xC4, 0xC5]);
    link_id
}

/// A duplicate msg1 for a link still pending names the transport and the
/// link it resent the msg2 for.
#[tokio::test]
async fn a_duplicate_msg1_for_a_pending_inbound_link_logs_its_link() {
    let mut node = make_node();
    let tid = TransportId::new(1);
    let (_sock, addr) = register_udp_with_peer_socket(&mut node, tid).await;
    let link_id = pending_inbound(&mut node, tid, &addr);
    let data = craft_msg1_wire(
        &node,
        &Identity::generate(),
        EPOCH,
        SessionIndex::new(5),
        2000,
    );
    let logs = msg1_logged(&mut node, packet(tid, &addr, data, 2000)).await;

    let line = expect_line(&logs, "Resent msg2 for duplicate msg1");
    assert_eq!(field(&line, "transport_id"), "transport:1", "{line}");
    assert_eq!(field(&line, "link_id"), link_id.to_string(), "{line}");
    assert_eq!(field(&line, "remote_addr"), addr.to_string(), "{line}");
    stop_transport(&mut node, tid).await;
}

/// The same resend, failing, names the transport and the link too.
#[tokio::test]
async fn a_failed_resend_to_a_pending_inbound_link_logs_its_link() {
    let mut node = make_node();
    let tid = TransportId::new(1);
    let (_sock, addr) = register_udp_with_peer_socket(&mut node, tid).await;
    stop_transport(&mut node, tid).await;
    let link_id = pending_inbound(&mut node, tid, &addr);
    let data = craft_msg1_wire(
        &node,
        &Identity::generate(),
        EPOCH,
        SessionIndex::new(5),
        2000,
    );
    let logs = msg1_logged(&mut node, packet(tid, &addr, data, 2000)).await;

    let line = expect_line(&logs, "Failed to resend msg2");
    assert_eq!(field(&line, "transport_id"), "transport:1", "{line}");
    assert_eq!(field(&line, "link_id"), link_id.to_string(), "{line}");
}

/// A msg1 that fails the Noise step names where it came from.
#[tokio::test]
async fn a_msg1_that_fails_to_decrypt_logs_where_it_came_from() {
    let mut node = make_node();
    let tid = TransportId::new(7);
    let from = TransportAddr::from_string("10.0.0.2:2121");
    let mut data = craft_msg1_wire(
        &node,
        &Identity::generate(),
        EPOCH,
        SessionIndex::new(5),
        1000,
    );
    let last = data.len() - 1;
    data[last] ^= 0x01;
    let logs = msg1_logged(&mut node, packet(tid, &from, data, 1000)).await;

    let line = expect_line(&logs, "Failed to process msg1");
    assert_eq!(field(&line, "transport_id"), "transport:7", "{line}");
    assert_eq!(field(&line, "remote_addr"), "10.0.0.2:2121", "{line}");
}

/// A msg2 for an index with no pending handshake names where it came from.
#[tokio::test]
async fn a_msg2_for_an_unknown_index_logs_where_it_came_from() {
    let mut node = make_node();
    let tid = TransportId::new(7);
    let from = TransportAddr::from_string("10.0.0.2:2121");
    let data = build_msg2(SessionIndex::new(99), SessionIndex::new(42), &[0u8; 57]);
    let logs = msg2_logged(&mut node, packet(tid, &from, data, 1000)).await;

    let line = expect_line(&logs, "No pending outbound handshake for index");
    assert_eq!(field(&line, "transport_id"), "transport:7", "{line}");
    assert_eq!(field(&line, "remote_addr"), "10.0.0.2:2121", "{line}");
    assert_eq!(field(&line, "receiver_idx"), "0000002a", "{line}");
}

/// One node of a two-node test: the node, its packet channel and its
/// address as the other node sees it.
struct Side {
    node: Node,
    rx: PacketRx,
    addr: TransportAddr,
}

/// Two nodes, each with a started UDP transport 1 on localhost.
async fn two_nodes() -> (Side, Side) {
    let mut sides = Vec::new();
    for _ in 0..2 {
        let mut node = make_node();
        let tid = TransportId::new(1);
        let cfg = UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(1280),
            ..Default::default()
        };
        let (tx, rx) = packet_channel(64);
        let mut transport = UdpTransport::new(tid, None, cfg, tx);
        transport.start_async().await.unwrap();
        let addr = TransportAddr::from_string(&transport.local_addr().unwrap().to_string());
        node.transports.insert(tid, TransportHandle::Udp(transport));
        sides.push(Side { node, rx, addr });
    }
    let b = sides.pop().unwrap();
    let a = sides.pop().unwrap();
    (a, b)
}

/// Start an outbound handshake from `from` to `to` as the dial path does,
/// with the msg1 stored on the machine, and send the msg1. Returns its wire
/// bytes and the index `from` put in it.
async fn dial(from: &mut Side, to: &Side) -> (Vec<u8>, SessionIndex) {
    let tid = TransportId::new(1);
    let target = PeerIdentity::from_pubkey_full(to.node.identity().pubkey_full());
    let link_id = from.node.allocate_link_id();
    let our_index = from.node.index_allocator.allocate().unwrap();
    from.node
        .seed_handshake_machine(
            HandshakeSeed::outbound(link_id, target, 1000)
                .with_our_index(our_index)
                .with_transport_id(tid)
                .with_source_addr(to.addr.clone()),
        )
        .unwrap();
    let keypair = from.node.identity().keypair();
    let epoch = from.node.startup_epoch();
    let machine = from.node.peer_machines.get_mut(&link_id).unwrap();
    let noise_msg1 = machine.start_handshake(keypair, epoch, 1000).unwrap();
    let wire = build_msg1(our_index, &noise_msg1);
    machine.set_conn_handshake_msg1(wire.clone(), 2000);
    from.node.links.insert(
        link_id,
        Link::connectionless(
            link_id,
            tid,
            to.addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    from.node
        .addr_to_link
        .insert((tid, to.addr.clone()), link_id);
    from.node
        .pending_outbound
        .insert(our_index.as_u32(), link_id);
    from.node
        .transports
        .get(&tid)
        .unwrap()
        .send(&to.addr, &wire)
        .await
        .expect("msg1 sent");
    (wire, our_index)
}

/// The next packet on `side`'s channel.
async fn next_packet(side: &mut Side) -> ReceivedPacket {
    timeout(Duration::from_secs(1), side.rx.recv())
        .await
        .expect("a packet arrives")
        .expect("channel open")
}

/// The tag of the session `side` holds for `other`.
fn held_tag(side: &Side, other: &Side) -> String {
    let addr = *PeerIdentity::from_pubkey_full(other.node.identity().pubkey_full()).node_addr();
    session_tag(
        side.node
            .get_peer(&addr)
            .and_then(|p| p.noise_session())
            .expect("a session is held"),
    )
}

async fn stop_sides(sides: [&mut Side; 2]) {
    for side in sides {
        for (_, t) in side.node.transports.iter_mut() {
            t.stop().await.ok();
        }
    }
}

/// When A dials B, both promotion lines carry A's msg1 index and digest
/// and the same session tag, so the two logs join on them.
#[tokio::test]
async fn both_ends_log_the_same_msg1_and_session_tags_when_a_link_is_promoted() {
    let (mut a, mut b) = two_nodes().await;
    let (wire, a_index) = dial(&mut a, &b).await;

    let p = next_packet(&mut b).await;
    let b_logs = msg1_logged(&mut b.node, p).await;
    let p = next_packet(&mut a).await;
    let a_logs = msg2_logged(&mut a.node, p).await;

    let b_line = expect_line(&b_logs, "Connection promoted to active peer");
    let a_line = expect_line(&a_logs, "Connection promoted to active peer");
    assert_eq!(field(&b_line, "direction"), "inbound", "{b_line}");
    assert_eq!(field(&a_line, "direction"), "outbound", "{a_line}");
    for (line, other) in [(&b_line, &a.addr), (&a_line, &b.addr)] {
        assert_eq!(field(line, "msg1_sidx"), index_text(a_index), "{line}");
        assert_eq!(field(line, "msg1_dg"), msg1_tag(&wire), "{line}");
        assert_eq!(field(line, "transport_id"), "transport:1", "{line}");
        assert_eq!(field(line, "remote_addr"), other.to_string(), "{line}");
    }
    assert_eq!(field(&b_line, "epoch"), held_tag(&b, &a), "{b_line}");
    assert_eq!(field(&a_line, "epoch"), held_tag(&a, &b), "{a_line}");
    assert_eq!(field(&a_line, "epoch"), field(&b_line, "epoch"));

    stop_sides([&mut a, &mut b]).await;
}

/// After a simultaneous dial the smaller node swaps to its outbound session
/// and the larger keeps its inbound one, which is the same handshake. The
/// swap and keep lines tag that surviving session, and the swap line's msg1
/// fields match the larger node's promotion of the smaller node's msg1. The
/// smaller node's own promotion tagged the other handshake, which the swap
/// replaced.
#[tokio::test]
async fn a_simultaneous_dial_tags_the_surviving_session_on_both_ends() {
    let (mut a, mut b) = two_nodes().await;
    let (a_wire, a_index) = dial(&mut a, &b).await;
    let (b_wire, b_index) = dial(&mut b, &a).await;

    let p = next_packet(&mut b).await;
    let b_in = msg1_logged(&mut b.node, p).await;
    let p = next_packet(&mut a).await;
    let a_in = msg1_logged(&mut a.node, p).await;
    let p = next_packet(&mut a).await;
    let a_m2 = msg2_logged(&mut a.node, p).await;
    let p = next_packet(&mut b).await;
    let b_m2 = msg2_logged(&mut b.node, p).await;

    let a_smaller = a.node.node_addr() < b.node.node_addr();
    let (s, l) = if a_smaller { (&a, &b) } else { (&b, &a) };
    let (s_wire, s_index) = if a_smaller {
        (&a_wire, a_index)
    } else {
        (&b_wire, b_index)
    };
    let (s_in, s_m2, l_in, l_m2) = if a_smaller {
        (&a_in, &a_m2, &b_in, &b_m2)
    } else {
        (&b_in, &b_m2, &a_in, &a_m2)
    };

    let swap = expect_line(
        s_m2,
        "Cross-connection: swapped to outbound session (our outbound wins)",
    );
    let keep = expect_line(
        l_m2,
        "Cross-connection: keeping inbound session and original their_index (peer outbound wins)",
    );
    let l_promote = expect_line(l_in, "Connection promoted to active peer");
    let s_promote = expect_line(s_in, "Connection promoted to active peer");

    let survivor = field(&swap, "epoch");
    assert_eq!(field(&l_promote, "epoch"), survivor, "{l_promote}");
    assert_eq!(field(&keep, "epoch"), survivor, "{keep}");
    assert_eq!(held_tag(s, l), survivor);
    assert_eq!(held_tag(l, s), survivor);

    assert_eq!(field(&swap, "msg1_sidx"), index_text(s_index), "{swap}");
    assert_eq!(field(&l_promote, "msg1_sidx"), index_text(s_index));
    assert_eq!(field(&swap, "msg1_dg"), msg1_tag(s_wire), "{swap}");
    assert_eq!(field(&l_promote, "msg1_dg"), msg1_tag(s_wire));

    assert_eq!(field(&swap, "transport_id"), "transport:1", "{swap}");
    assert_eq!(field(&swap, "remote_addr"), l.addr.to_string(), "{swap}");
    assert_eq!(field(&keep, "transport_id"), "transport:1", "{keep}");
    assert_eq!(field(&keep, "remote_addr"), s.addr.to_string(), "{keep}");

    // The smaller node's own promotion tagged the handshake the swap replaced.
    assert_ne!(field(&s_promote, "epoch"), survivor, "{s_promote}");

    stop_sides([&mut a, &mut b]).await;
}
