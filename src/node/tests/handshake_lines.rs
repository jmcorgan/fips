//! A peer that keeps sending msg1s with one outcome logs that outcome's line
//! three times per session, then one notice, then nothing, and the number of
//! lines not logged is reported when its session changes or it is removed.
//!
//! Each test drives the repeated outcome through the real handler and counts
//! lines by their exact message. What the node sends and decides is checked
//! beside the line counts, since suppression changes only the log.

use super::establish_chartests::{
    arm_local_rekey, craft_msg1_wire, establish_active_peer_via_msg1,
    register_udp_with_peer_socket, sender_with_addr_relation,
};
use super::heartbeat::set_link_dead_timeout;
use super::link_setup_diag::{
    EPOCH, Established, arm_pending, drain, established, expect_line, field, packet, stop_transport,
};
use super::*;
use crate::testutil::{LogCapture, capture_logs_scoped};
use tokio::time::timeout;

const RESEND: &str = "Resent msg2 for duplicate msg1 (same epoch)";
const REPLACE: &str = "Same-epoch msg1 from a peer heard from within the interval, dropping";
const PENDING: &str = "Rekey msg1 received but already have pending session, dropping";
const OFF_LINK: &str = "Same-epoch msg1 off the established link while that link is up, dropping";
const DUAL_WON: &str = "Dual rekey initiation: we win (smaller addr), dropping their msg1";
const NOTICE: &str = "Suppressing repeated handshake lines for this peer";
const SUMMARY: &str = "Suppressed repeated handshake lines";

/// The kind fields a peer's summary line carries.
const KINDS: [&str; 9] = [
    "resend",
    "resend_failed",
    "rekey_resend",
    "rekey_resend_failed",
    "pending",
    "answered",
    "off_link",
    "replace",
    "restart",
];

/// Count the datagrams queued for `sock`, discarding them.
async fn received(sock: &tokio::net::UdpSocket) -> usize {
    let mut buf = [0u8; 2048];
    let mut n = 0;
    while timeout(Duration::from_millis(150), sock.recv_from(&mut buf))
        .await
        .is_ok()
    {
        n += 1;
    }
    n
}

/// Deliver each of `msg1s` on transport `tid` from `from`, with the log lines
/// of all of them captured.
async fn deliver_logged(
    node: &mut Node,
    tid: TransportId,
    from: &TransportAddr,
    msg1s: Vec<Vec<u8>>,
) -> LogCapture {
    let (logs, guard) = capture_logs_scoped();
    for (i, data) in msg1s.into_iter().enumerate() {
        node.handle_msg1(packet(tid, from, data, 3000 + i as u64))
            .await;
    }
    drop(guard);
    logs
}

/// Distinct rekey msg1s from `e`'s peer, with sender indices from `first`.
fn fresh_msg1s(e: &Established, first: u32, count: u32) -> Vec<Vec<u8>> {
    (first..first + count)
        .map(|i| craft_msg1_wire(&e.node, &e.sender, EPOCH, SessionIndex::new(i), 3000))
        .collect()
}

/// Assert `line` reports `want` for each named kind and 0 for every other.
fn assert_summary(line: &str, want: &[(&str, &str)]) {
    for kind in KINDS {
        let expected = want
            .iter()
            .find(|(k, _)| *k == kind)
            .map_or("0", |(_, v)| v);
        assert_eq!(field(line, kind), expected, "{kind} on {line}");
    }
}

/// A node with a peer promoted from msg1 `first`, its session aged 12 s, so
/// that a copy of `first` is a resend of the setup msg1.
struct Setup {
    node: Node,
    sock: tokio::net::UdpSocket,
    addr: TransportAddr,
    peer: NodeAddr,
    first: Vec<u8>,
}

async fn setup_resent() -> Setup {
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
    Setup {
        node,
        sock,
        addr,
        peer,
        first,
    }
}

/// Resend the setup msg1 `count` times, returning the captured lines.
async fn resend(s: &mut Setup, count: usize) -> LogCapture {
    let copies = vec![s.first.clone(); count];
    deliver_logged(&mut s.node, TransportId::new(1), &s.addr, copies).await
}

/// Run the link-dead reaper on `s`'s peer, returning the captured lines.
async fn reap(s: &mut Setup) -> LogCapture {
    set_link_dead_timeout(&mut s.node, 0);
    let (logs, guard) = capture_logs_scoped();
    s.node.check_link_heartbeats().await;
    drop(guard);
    assert!(s.node.get_peer(&s.peer).is_none(), "the reaper removed it");
    logs
}

#[tokio::test]
async fn repeated_resends_of_the_setup_msg1_log_three_lines_then_one_suppression_notice() {
    let mut s = setup_resent().await;
    let logs = resend(&mut s, 8).await;

    assert_eq!(logs.lines_with(RESEND).len(), 3, "{:#?}", logs.lines());
    let notices = logs.lines_with(NOTICE);
    assert_eq!(notices.len(), 1, "{:#?}", logs.lines());
    assert_eq!(field(&notices[0], "kind"), "resend");
    assert_eq!(received(&s.sock).await, 8, "every resend was answered");
    stop_transport(&mut s.node, TransportId::new(1)).await;
}

#[tokio::test]
async fn the_removal_of_a_peer_reports_how_many_handshake_lines_were_suppressed() {
    let mut s = setup_resent().await;
    resend(&mut s, 8).await;
    let logs = reap(&mut s).await;

    let summaries = logs.lines_with(SUMMARY);
    assert_eq!(summaries.len(), 1, "{:#?}", logs.lines());
    assert_summary(&summaries[0], &[("resend", "5")]);
    stop_transport(&mut s.node, TransportId::new(1)).await;
}

#[tokio::test]
async fn a_peer_with_three_resends_logs_each_and_its_removal_reports_nothing_suppressed() {
    let mut s = setup_resent().await;
    let logs = resend(&mut s, 3).await;
    assert_eq!(logs.lines_with(RESEND).len(), 3, "{:#?}", logs.lines());
    assert!(logs.line(NOTICE).is_none(), "{:#?}", logs.lines());

    let logs = reap(&mut s).await;
    assert!(logs.line(SUMMARY).is_none(), "{:#?}", logs.lines());
    stop_transport(&mut s.node, TransportId::new(1)).await;
}

#[tokio::test]
async fn repeated_msg1s_from_a_peer_heard_within_the_interval_log_three_lines_then_one_notice() {
    let mut e = established(5).await;
    let peer = e.node.get_peer_mut(&e.peer).unwrap();
    peer.test_set_last_seen(Node::now_ms());
    let (link, index) = (peer.link_id(), peer.our_index());

    let msg1s = fresh_msg1s(&e, 0x0A00, 8);
    let logs = deliver_logged(&mut e.node, TransportId::new(1), &e.addr, msg1s).await;

    assert_eq!(logs.lines_with(REPLACE).len(), 3, "{:#?}", logs.lines());
    let notices = logs.lines_with(NOTICE);
    assert_eq!(notices.len(), 1, "{:#?}", logs.lines());
    assert_eq!(field(&notices[0], "kind"), "replace");
    let peer = e.node.get_peer(&e.peer).expect("the peer was kept");
    assert_eq!((peer.link_id(), peer.our_index()), (link, index));
    stop_transport(&mut e.node, TransportId::new(1)).await;
}

/// `e` with a pending armed and five more rekey msg1s refused against it.
async fn five_refused_while_pending(e: &mut Established) -> LogCapture {
    arm_pending(e, 0x0D01).await;
    let msg1s = fresh_msg1s(e, 0x0D10, 5);
    deliver_logged(&mut e.node, TransportId::new(1), &e.addr, msg1s).await
}

#[tokio::test]
async fn a_rekey_cutover_restarts_the_count_and_reports_the_previous_sessions_suppressed_lines() {
    let mut e = established(31).await;
    let logs = five_refused_while_pending(&mut e).await;
    assert_eq!(logs.lines_with(PENDING).len(), 3, "{:#?}", logs.lines());
    assert_eq!(logs.lines_with(NOTICE).len(), 1, "{:#?}", logs.lines());

    // The peer's first frame on the pending adopts it; the next session is
    // old enough to rekey, and holds a pending of its own.
    let peer = e.node.get_peer_mut(&e.peer).unwrap();
    let kbit = !peer.current_k_bit();
    peer.adopt_pending(kbit).expect("the pending was adopted");
    peer.test_backdate_session_established(Duration::from_secs(31));
    arm_pending(&mut e, 0x0D20).await;

    let msg1s = fresh_msg1s(&e, 0x0D30, 1);
    let logs = deliver_logged(&mut e.node, TransportId::new(1), &e.addr, msg1s).await;
    let lines = logs.lines();
    let summary = lines
        .iter()
        .position(|l| logs.lines_with(SUMMARY).contains(l))
        .unwrap_or_else(|| panic!("no summary in {lines:#?}"));
    assert_summary(&lines[summary], &[("pending", "2")]);
    let pending = lines
        .iter()
        .position(|l| logs.lines_with(PENDING).contains(l))
        .unwrap_or_else(|| panic!("the new session's line was suppressed: {lines:#?}"));
    assert!(summary < pending, "the summary comes first: {lines:#?}");
    stop_transport(&mut e.node, TransportId::new(1)).await;
}

#[tokio::test]
async fn suppressing_one_kind_of_line_does_not_hide_the_first_line_of_another() {
    let mut e = established(31).await;
    five_refused_while_pending(&mut e).await;

    let tid2 = TransportId::new(2);
    let (_sock2, addr2) = register_udp_with_peer_socket(&mut e.node, tid2).await;
    let msg1s = fresh_msg1s(&e, 0x0E00, 1);
    let logs = deliver_logged(&mut e.node, tid2, &addr2, msg1s).await;
    expect_line(&logs, OFF_LINK);
    stop_transport(&mut e.node, TransportId::new(1)).await;
    stop_transport(&mut e.node, tid2).await;
}

#[tokio::test]
async fn every_msg1_dropped_by_winning_a_dual_rekey_initiation_is_logged() {
    // An integration check counts this line to detect a dual-initiation loop,
    // so it is never suppressed.
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

    let msg1s = (0xAA00..0xAA06)
        .map(|i| craft_msg1_wire(&node, &sender, EPOCH, SessionIndex::new(i), 2000))
        .collect();
    let logs = deliver_logged(&mut node, tid, &addr, msg1s).await;
    assert_eq!(logs.lines_with(DUAL_WON).len(), 6, "{:#?}", logs.lines());
    assert!(logs.line(NOTICE).is_none(), "{:#?}", logs.lines());
    stop_transport(&mut node, tid).await;
}
