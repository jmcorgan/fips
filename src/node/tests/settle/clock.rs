//! Handshake timers and the restart gate against a forward step of the wall
//! clock, with no time passing.
//!
//! The node's handshake resend, its handshake timeout and the restart gate's
//! "heard within the interval" all read `Node::now_ms`, the wall clock, so a
//! forward step of the system clock looks to them like time passing. These
//! are known defects: each test asserts the behaviour a monotonic clock
//! gives, and fails today. They step the wall clock with the thread-local
//! test hook `crate::time::step_wall`, so they are safe beside other tests.
//!
//! The node's tick is reproduced as `check_timeouts()` followed by
//! `drive_peer_timers(Node::now_ms())`, the order the receive loop runs
//! them in.

use super::super::establish_chartests::craft_msg1_wire;
use super::super::link_setup_diag::{EPOCH, Established, established, packet, stop_transport};
use super::super::spanning_tree::{
    TestNode, cleanup_nodes, drain_all_packets, initiate_handshake, make_test_node,
};
use super::super::*;
use super::tap;
use crate::testutil::{LogCapture, capture_logs_scoped};
use crate::transport::TransportId;

/// The restart gate's refusal line. A copy of `handshake_lines::REPLACE`,
/// which is private.
const REPLACE: &str = "Same-epoch msg1 inside the peering's replacement interval, dropping";

/// Deliver each of `msg1s` on transport `tid` from `from`, with the log lines
/// of all of them captured. A copy of `handshake_lines::deliver_logged`,
/// which is private.
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
/// A copy of `handshake_lines::fresh_msg1s`, which is private.
fn fresh_msg1s(e: &Established, first: u32, count: u32) -> Vec<Vec<u8>> {
    (first..first + count)
        .map(|i| craft_msg1_wire(&e.node, &e.sender, EPOCH, SessionIndex::new(i), 3000))
        .collect()
}

/// Step the wall clock `Node::now_ms` reads forward by `ms`, on this thread.
fn step_wall(ms: i64) {
    crate::time::step_wall(ms);
}

/// One tick's timer work, as the receive loop runs it.
async fn tick(node: &mut Node) {
    node.check_timeouts().await;
    node.drive_peer_timers(Node::now_ms()).await;
}

/// A node dialing a loopback tap that never answers, and the tap.
async fn dial_into_tap() -> (
    TestNode,
    tokio::sync::mpsc::UnboundedReceiver<ReceivedPacket>,
) {
    let mut tn = make_test_node().await;
    let other = make_test_node().await;
    let id = PeerIdentity::from_pubkey_full(other.node.identity().pubkey_full());
    let tid = tn.transport_id;
    let (dialled, tap) = tap(tid);
    tn.node
        .initiate_connection(tid, dialled, id)
        .await
        .expect("precondition: the dial starts");
    let mut other = vec![other];
    cleanup_nodes(&mut other).await;
    (tn, tap)
}

/// Take and count every packet queued on `rx`.
fn drain(rx: &mut tokio::sync::mpsc::UnboundedReceiver<ReceivedPacket>) -> usize {
    std::iter::from_fn(|| rx.try_recv().ok()).count()
}

#[tokio::test]
#[ignore = "known defect: a forward wall-clock step times out a dial started just now"]
async fn a_forward_wall_clock_step_does_not_time_out_a_fresh_dial() {
    let (mut tn, mut tap) = dial_into_tap().await;
    assert_eq!(drain(&mut tap), 1, "precondition: the dial's msg1 went out");
    tick(&mut tn.node).await;
    assert_eq!(
        tn.node.pending_outbound.len(),
        1,
        "precondition: a dial started just now survives a tick"
    );
    let timeout_ms = tn.node.config().node.rate_limit.handshake_timeout_secs * 1000;
    step_wall(i64::try_from(timeout_ms).expect("precondition: the timeout fits an i64") + 1_000);
    tick(&mut tn.node).await;
    let left = tn.node.pending_outbound.len();
    cleanup_nodes(std::slice::from_mut(&mut tn)).await;
    assert_eq!(
        left, 1,
        "defect: a dial started just now timed out because the wall clock stepped forward"
    );
}

#[tokio::test]
#[ignore = "known defect: a forward wall-clock step sends a msg1 resend before its time"]
async fn a_forward_wall_clock_step_sends_no_msg1_resend_early() {
    let (mut tn, mut tap) = dial_into_tap().await;
    assert_eq!(drain(&mut tap), 1, "precondition: the dial's msg1 went out");
    tick(&mut tn.node).await;
    assert_eq!(drain(&mut tap), 0, "precondition: no resend is due yet");
    step_wall(1_500);
    tick(&mut tn.node).await;
    let resent = drain(&mut tap);
    cleanup_nodes(std::slice::from_mut(&mut tn)).await;
    assert_eq!(
        resent, 0,
        "defect: a forward wall-clock step with no time passing sent a msg1 resend"
    );
}

/// The restart gate's "heard within 15 s" against a stepped wall clock,
/// over a real loopback handshake: node 0 dials node 1, frames flow, then
/// node 0 sends a fresh msg1 at the same epoch. The first is refused (the
/// peering was heard just now); after a forward wall step with no time
/// passing, the same must hold.
#[tokio::test]
#[ignore = "known defect: a forward wall-clock step lets a same-epoch msg1 replace a loopback peering heard just now"]
async fn a_forward_wall_clock_step_does_not_let_a_msg1_replace_a_loopback_peering_heard_just_now() {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let a = *nodes[0].node.node_addr();
    let (link, index) = {
        let p = nodes[1]
            .node
            .get_peer(&a)
            .expect("precondition: node 1 holds node 0");
        assert!(p.is_heard(), "precondition: node 1 heard node 0's frames");
        (p.link_id(), p.our_index())
    };
    nodes[1]
        .node
        .get_peer_mut(&a)
        .expect("precondition: node 1 holds node 0")
        .touch(Node::now_ms());

    // A fresh same-epoch msg1 now is refused.
    initiate_handshake(&mut nodes, 0, 1).await;
    let mut m = nodes[1]
        .packet_rx
        .try_recv()
        .expect("precondition: node 0's second msg1 is queued at node 1");
    m.timestamp_ms = Node::now_ms();
    nodes[1].node.handle_msg1(m).await;
    {
        let p = nodes[1]
            .node
            .get_peer(&a)
            .expect("precondition: node 1 kept node 0");
        assert_eq!(
            (p.link_id(), p.our_index()),
            (link, index),
            "precondition: a msg1 inside the interval does not replace the peering"
        );
    }

    step_wall(3_600_000);
    initiate_handshake(&mut nodes, 0, 1).await;
    let mut m = nodes[1]
        .packet_rx
        .try_recv()
        .expect("precondition: node 0's third msg1 is queued at node 1");
    m.timestamp_ms = Node::now_ms();
    nodes[1].node.handle_msg1(m).await;
    let after = nodes[1]
        .node
        .get_peer(&a)
        .map(|p| (p.link_id(), p.our_index()));
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        after,
        Some((link, index)),
        "defect: a peering heard just now was replaced because the wall clock stepped forward"
    );
}

/// The same gate over the UDP harness of `link_setup_diag`, with crafted
/// msg1s from the peer: refused while the peering was heard within the
/// interval, and still refused after a forward wall step with no time
/// passing.
#[tokio::test]
#[ignore = "known defect: a forward wall-clock step lets a same-epoch msg1 replace a peering heard just now"]
async fn a_forward_wall_clock_step_does_not_let_a_msg1_replace_a_peering_heard_just_now() {
    let mut e = established(5).await;
    let peer = e
        .node
        .get_peer_mut(&e.peer)
        .expect("precondition: the node holds the peer");
    peer.touch(Node::now_ms());
    let (link, index) = (peer.link_id(), peer.our_index());

    let msg1s = fresh_msg1s(&e, 0x0A00, 1);
    let logs = deliver_logged(&mut e.node, TransportId::new(1), &e.addr, msg1s).await;
    assert_eq!(
        logs.lines_with(REPLACE).len(),
        1,
        "precondition: a msg1 is refused while the peering was heard within the interval: {:#?}",
        logs.lines()
    );

    step_wall(3_600_000);
    let msg1s = fresh_msg1s(&e, 0x0A10, 1);
    let logs = deliver_logged(&mut e.node, TransportId::new(1), &e.addr, msg1s).await;

    let after = e
        .node
        .get_peer(&e.peer)
        .map(|p| (p.link_id(), p.our_index()));
    stop_transport(&mut e.node, TransportId::new(1)).await;
    assert_eq!(
        after,
        Some((link, index)),
        "defect: a peering heard just now was replaced because the system clock jumped ahead: {:#?}",
        logs.lines()
    );
}
