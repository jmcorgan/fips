//! Crossed dials and a dialer's second dial: which session and which link
//! each end is left on.
//!
//! - Crossed TCP dials between two real TCP nodes on 127.0.0.1: one working
//!   session on one connection (green); the smaller node's link record and
//!   its redial after a drop (known defects), with a control that redials
//!   after a single dial and a run that rewrites the record and redials.
//! - Crossed loopback dials won on another transport or from another
//!   address: the smaller node holds the peer at the pair the winning msg2
//!   came from, and the result is coherent by the audit.
//! - A dialer's second msg1 reaching the responder more than 1 s after its
//!   first: in order, on another transport, and with the second msg2 reaching
//!   the dialer first (known defect, for both address orders, by the
//!   heartbeat check and by the audit).
//! - A larger node's dial on a quiet peer's aged link, which the peer set
//!   up: its next rekey is answered, and no pending is left that it cannot
//!   adopt (known defects).
//! - Two dials to one address with no peer held, the first reaped: the
//!   connection the second runs on stays open, on loopback by its record of
//!   closes and on the BLE mock by its pool.
//!
//! Each test is run once per address order, so each order has its own
//! verdict, and once per setting of `node.path.enabled`: a test's plain name
//! runs multipath off, and its `_with_multipath_on` sibling runs it on, as two
//! tests and not one loop, since a pin that fails in a loop's first pass would
//! never reach the second. Setup checks are marked `precondition:`; the
//! assertion of the behaviour is marked `defect:`.

use super::super::control::quieten;
use super::super::crossed_dial::{Dial, cross_dials_from, hand, phase};
use super::super::rekey_parity::{
    age_link, cutover, deliver, heartbeat, rekey_config, rekey_to_pending, trigger_age,
};
use super::super::spanning_tree::{
    LOOPBACK_REGISTRY, TestNode, cleanup_nodes, drain_all_packets, initiate_handshake,
    make_test_node_with_config, process_available_packets,
};
use super::super::*;
use super::audit::{Breach, Exempt, assert_coherent, audit};
use super::{
    alias, crossed_tcp, heartbeat_reaches, loopback_node, pool, pump, received, resolve_connect,
    settled, with_path,
};
use super::{tcp_dial, tcp_pair};
use crate::proto::fmp::wire::{CommonPrefix, PHASE_ESTABLISHED, PHASE_MSG1, PHASE_MSG2};
use crate::proto::link::LinkMessageType;
use crate::transport::loopback::LoopbackTransport;
use crate::transport::{TransportHandle, TransportId};
use fips_core::proto::rekey::Role;

// ---------------------------------------------------------------------------
// Copied private helpers
// ---------------------------------------------------------------------------

/// The transport `tn` holds its peer `peer` on and the peer's current
/// address there. A copy of `crossed_dial::pair`, which is private.
fn pair(tn: &TestNode, peer: &NodeAddr) -> (Option<TransportId>, Option<TransportAddr>) {
    let peer = tn
        .node
        .get_peer(peer)
        .expect("precondition: the node holds the peer");
    (peer.transport_id(), peer.current_addr().cloned())
}

/// Where one end's link to the other sits, and which session it is on. A
/// copy of `control::LinkView`, which is private.
#[derive(Debug, Clone, PartialEq)]
struct LinkView {
    link_id: LinkId,
    transport_id: Option<TransportId>,
    current_addr: Option<TransportAddr>,
    our_index: Option<SessionIndex>,
}

/// Read `tn`'s view of its link to `peer`. A copy of `control::link_view`,
/// which is private.
fn link_view(tn: &TestNode, peer: &NodeAddr) -> LinkView {
    let p = tn
        .node
        .get_peer(peer)
        .expect("precondition: the node still holds the peer");
    LinkView {
        link_id: p.link_id(),
        transport_id: p.transport_id(),
        current_addr: p.current_addr().cloned(),
        our_index: p.our_index(),
    }
}

// ---------------------------------------------------------------------------
// Crossed TCP dials
// ---------------------------------------------------------------------------

/// Crossed TCP dials must leave one open connection at each end and a
/// session on which a heartbeat authenticates both ways.
async fn working_session(on: bool, zero_smaller: bool) {
    let (mut nodes, s, l) = crossed_tcp(on, zero_smaller).await;
    let mut bad = Vec::new();
    if let Err(e) = heartbeat_reaches(&mut nodes, s, l).await {
        bad.push(format!("smaller to larger heartbeat: {e}"));
    }
    if let Err(e) = heartbeat_reaches(&mut nodes, l, s).await {
        bad.push(format!("larger to smaller heartbeat: {e}"));
    }
    let (si, so) = pool(&nodes[s]);
    let (li, lo) = pool(&nodes[l]);
    if si + so == 0 || li + lo == 0 {
        bad.push(format!(
            "a node holds no connection: smaller {:?} larger {:?}",
            (si, so),
            (li, lo)
        ));
    }
    assert!(
        bad.is_empty(),
        "defect: crossed TCP dials lost the peering: {bad:#?}"
    );
    assert_coherent(
        &mut nodes,
        &[Exempt::CrossedInbound { node: s, peer: l }],
        "the end of crossed TCP dials",
    )
    .await;
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn crossed_tcp_dials_leave_a_working_session_on_one_connection_smaller_first() {
    working_session(false, true).await;
}

/// [`crossed_tcp_dials_leave_a_working_session_on_one_connection_smaller_first`] with multipath on.
#[tokio::test]
async fn crossed_tcp_dials_leave_a_working_session_on_one_connection_smaller_first_with_multipath_on()
 {
    working_session(true, true).await;
}

#[tokio::test]
async fn crossed_tcp_dials_leave_a_working_session_on_one_connection_larger_first() {
    working_session(false, false).await;
}

/// [`crossed_tcp_dials_leave_a_working_session_on_one_connection_larger_first`] with multipath on.
#[tokio::test]
async fn crossed_tcp_dials_leave_a_working_session_on_one_connection_larger_first_with_multipath_on()
 {
    working_session(true, false).await;
}

/// After crossed TCP dials the smaller node's link record for the peer is
/// the link it dialed (direction `Outbound`) at the pair it holds the peer
/// at, and `addr_to_link` names that link there.
async fn smaller_on_its_dialed_link(on: bool, zero_smaller: bool) {
    let (mut nodes, s, l) = crossed_tcp(on, zero_smaller).await;
    let l_addr = *nodes[l].node.node_addr();
    let mut bad = Vec::new();
    {
        let p = nodes[s]
            .node
            .get_peer(&l_addr)
            .expect("precondition: the smaller node holds the larger");
        let tid = p
            .transport_id()
            .expect("precondition: the peer has a transport");
        let at = p
            .current_addr()
            .cloned()
            .expect("precondition: the peer has a current address");
        let link = nodes[s]
            .node
            .links
            .get(&p.link_id())
            .map(|k| (k.direction(), k.transport_id(), k.remote_addr().clone()));
        let want = Some((LinkDirection::Outbound, tid, at.clone()));
        if link != want {
            bad.push(format!(
                "the smaller node's link record is {link:?}, expected {want:?}"
            ));
        }
        let mapped = nodes[s].node.links.index().get(&(tid, at)).copied();
        if mapped != Some(p.link_id()) {
            bad.push(format!(
                "addr_to_link at the peer's pair is {mapped:?}, the peer's link {:?}",
                p.link_id()
            ));
        }
    }
    cleanup_nodes(&mut nodes).await;
    assert!(bad.is_empty(), "defect: {bad:#?}");
}

#[tokio::test]
#[ignore = "known defect: after crossed dials the smaller node keeps the inbound link it was promoted on as the peer's link record"]
async fn crossed_tcp_dials_leave_the_smaller_node_on_the_link_it_dialed_smaller_first() {
    smaller_on_its_dialed_link(false, true).await;
}

/// [`crossed_tcp_dials_leave_the_smaller_node_on_the_link_it_dialed_smaller_first`] with multipath on.
#[tokio::test]
#[ignore = "known defect: after crossed dials the smaller node keeps the inbound link it was promoted on as the peer's link record"]
async fn crossed_tcp_dials_leave_the_smaller_node_on_the_link_it_dialed_smaller_first_with_multipath_on()
 {
    smaller_on_its_dialed_link(true, true).await;
}

#[tokio::test]
#[ignore = "known defect: after crossed dials the smaller node keeps the inbound link it was promoted on as the peer's link record"]
async fn crossed_tcp_dials_leave_the_smaller_node_on_the_link_it_dialed_larger_first() {
    smaller_on_its_dialed_link(false, false).await;
}

/// [`crossed_tcp_dials_leave_the_smaller_node_on_the_link_it_dialed_larger_first`] with multipath on.
#[tokio::test]
#[ignore = "known defect: after crossed dials the smaller node keeps the inbound link it was promoted on as the peer's link record"]
async fn crossed_tcp_dials_leave_the_smaller_node_on_the_link_it_dialed_larger_first_with_multipath_on()
 {
    smaller_on_its_dialed_link(true, false).await;
}

/// Close the smaller node's connection to the larger and report whether a
/// send from the smaller node redials it and reaches the larger within
/// about 3 s.
async fn redial_after_drop(nodes: &mut [TestNode], s: usize, l: usize) -> Result<(), String> {
    let l_addr = *nodes[l].node.node_addr();
    let (tid, at) = {
        let p = nodes[s]
            .node
            .get_peer(&l_addr)
            .expect("precondition: the smaller node holds the larger");
        (
            p.transport_id()
                .expect("precondition: the peer has a transport"),
            p.current_addr()
                .cloned()
                .expect("precondition: the peer has a current address"),
        )
    };
    nodes[s]
        .node
        .transports
        .get(&tid)
        .expect("precondition: the peer's transport is held")
        .close_connection(&at)
        .await;
    // Let the larger node's receive task see the close.
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if pool(&nodes[l]) == (0, 0) {
            break;
        }
    }
    assert_eq!(
        pool(&nodes[s]),
        (0, 0),
        "precondition: the smaller node holds no connection after the close"
    );
    let before = received(nodes, l, s).map(|r| r.0).unwrap_or(0);
    for _ in 0..150 {
        let _ = nodes[s]
            .node
            .send_encrypted_link_message(&l_addr, &[LinkMessageType::Heartbeat.to_byte()])
            .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(nodes).await;
        if received(nodes, l, s).is_some_and(|r| r.0 > before) {
            return Ok(());
        }
    }
    Err(format!(
        "no frame from the smaller node reached the larger; pools smaller {:?} larger {:?}",
        pool(&nodes[s]),
        pool(&nodes[l])
    ))
}

/// After crossed TCP dials, when the one surviving connection drops, a send
/// from the smaller node (which holds the peer at the address it dialed)
/// redials it, as it does after a single dial.
async fn crossed_then_redial(on: bool, zero_smaller: bool) {
    let (mut nodes, s, l) = crossed_tcp(on, zero_smaller).await;
    heartbeat_reaches(&mut nodes, s, l)
        .await
        .expect("precondition: frames authenticate smaller to larger");
    heartbeat_reaches(&mut nodes, l, s)
        .await
        .expect("precondition: frames authenticate larger to smaller");
    let redial = redial_after_drop(&mut nodes, s, l).await;
    cleanup_nodes(&mut nodes).await;
    assert!(redial.is_ok(), "defect: {redial:?}");
}

#[tokio::test]
#[ignore = "known defect: after crossed dials the smaller node cannot redial a dropped connection, because its link record is the inbound link"]
async fn after_crossed_tcp_dials_a_send_from_the_smaller_node_redials_a_dropped_connection_smaller_first()
 {
    crossed_then_redial(false, true).await;
}

/// [`after_crossed_tcp_dials_a_send_from_the_smaller_node_redials_a_dropped_connection_smaller_first`] with multipath on.
#[tokio::test]
#[ignore = "known defect: after crossed dials the smaller node cannot redial a dropped connection, because its link record is the inbound link"]
async fn after_crossed_tcp_dials_a_send_from_the_smaller_node_redials_a_dropped_connection_smaller_first_with_multipath_on()
 {
    crossed_then_redial(true, true).await;
}

#[tokio::test]
#[ignore = "known defect: after crossed dials the smaller node cannot redial a dropped connection, because its link record is the inbound link"]
async fn after_crossed_tcp_dials_a_send_from_the_smaller_node_redials_a_dropped_connection_larger_first()
 {
    crossed_then_redial(false, false).await;
}

/// [`after_crossed_tcp_dials_a_send_from_the_smaller_node_redials_a_dropped_connection_larger_first`] with multipath on.
#[tokio::test]
#[ignore = "known defect: after crossed dials the smaller node cannot redial a dropped connection, because its link record is the inbound link"]
async fn after_crossed_tcp_dials_a_send_from_the_smaller_node_redials_a_dropped_connection_larger_first_with_multipath_on()
 {
    crossed_then_redial(true, false).await;
}

/// The run above with the smaller node's link record rewritten, by the
/// test, to the link it dialed (direction `Outbound` at the peer's pair):
/// it redials, so the stale record is what stops the redial, and the redial
/// pins can pass once the record is right.
async fn rewritten_then_redial(on: bool, zero_smaller: bool) {
    let (mut nodes, s, l) = crossed_tcp(on, zero_smaller).await;
    heartbeat_reaches(&mut nodes, s, l)
        .await
        .expect("precondition: frames authenticate smaller to larger");
    let l_addr = *nodes[l].node.node_addr();
    let (link_id, tid, at) = {
        let p = nodes[s]
            .node
            .get_peer(&l_addr)
            .expect("precondition: the smaller node holds the larger");
        (
            p.link_id(),
            p.transport_id()
                .expect("precondition: the peer has a transport"),
            p.current_addr()
                .cloned()
                .expect("precondition: the peer has a current address"),
        )
    };
    let link = Link::connectionless(
        link_id,
        tid,
        at.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    nodes[s].node.links.raw().insert(link_id, link);
    nodes[s].node.links.raw_index().insert((tid, at), link_id);
    let redial = redial_after_drop(&mut nodes, s, l).await;
    cleanup_nodes(&mut nodes).await;
    assert!(redial.is_ok(), "defect: {redial:?}");
}

#[tokio::test]
async fn with_its_link_record_rewritten_to_outbound_the_smaller_node_redials_smaller_first() {
    rewritten_then_redial(false, true).await;
}

/// [`with_its_link_record_rewritten_to_outbound_the_smaller_node_redials_smaller_first`] with multipath on.
#[tokio::test]
async fn with_its_link_record_rewritten_to_outbound_the_smaller_node_redials_smaller_first_with_multipath_on()
 {
    rewritten_then_redial(true, true).await;
}

#[tokio::test]
async fn with_its_link_record_rewritten_to_outbound_the_smaller_node_redials_larger_first() {
    rewritten_then_redial(false, false).await;
}

/// [`with_its_link_record_rewritten_to_outbound_the_smaller_node_redials_larger_first`] with multipath on.
#[tokio::test]
async fn with_its_link_record_rewritten_to_outbound_the_smaller_node_redials_larger_first_with_multipath_on()
 {
    rewritten_then_redial(true, false).await;
}

/// The control for the redial pins: after a single TCP dial, a send from
/// the dialer redials a dropped connection.
async fn single_then_redial(on: bool, dialer_smaller: bool) {
    let mut nodes = tcp_pair(on, dialer_smaller).await;
    let (d, r) = (0, 1);
    tcp_dial(&mut nodes, d, r).await;
    resolve_connect(&mut nodes[d]).await;
    pump(&mut nodes).await;
    heartbeat_reaches(&mut nodes, d, r)
        .await
        .expect("precondition: frames authenticate dialer to responder");
    let redial = redial_after_drop(&mut nodes, d, r).await;
    cleanup_nodes(&mut nodes).await;
    assert!(redial.is_ok(), "defect: {redial:?}");
}

#[tokio::test]
async fn after_one_tcp_dial_a_send_from_the_dialer_redials_a_dropped_connection_smaller_dialer() {
    single_then_redial(false, true).await;
}

/// [`after_one_tcp_dial_a_send_from_the_dialer_redials_a_dropped_connection_smaller_dialer`] with multipath on.
#[tokio::test]
async fn after_one_tcp_dial_a_send_from_the_dialer_redials_a_dropped_connection_smaller_dialer_with_multipath_on()
 {
    single_then_redial(true, true).await;
}

#[tokio::test]
async fn after_one_tcp_dial_a_send_from_the_dialer_redials_a_dropped_connection_larger_dialer() {
    single_then_redial(false, false).await;
}

/// [`after_one_tcp_dial_a_send_from_the_dialer_redials_a_dropped_connection_larger_dialer`] with multipath on.
#[tokio::test]
async fn after_one_tcp_dial_a_send_from_the_dialer_redials_a_dropped_connection_larger_dialer_with_multipath_on()
 {
    single_then_redial(true, false).await;
}

// ---------------------------------------------------------------------------
// Crossed loopback dials won on another pair
// ---------------------------------------------------------------------------

/// Point the loopback address `at` at `to`'s own receive channel, so what
/// is sent there reaches `to` rather than a test's tap.
fn route(at: &TransportAddr, to: &TestNode) {
    let mut registry = LOOPBACK_REGISTRY
        .lock()
        .expect("precondition: the loopback registry lock");
    let tx = registry
        .get(&to.addr)
        .expect("precondition: the node's own address is registered")
        .clone();
    registry.insert(at.clone(), tx);
}

/// Cross the dials as `dial` says, hand the smaller node the winning msg2,
/// and check it holds the peer at the msg2's transport and source address;
/// then deliver everything and check the audit finds the pair coherent,
/// with the crossing's exemption for the smaller node.
async fn coherent_pair(on: bool, dial: Dial) {
    let crossed = cross_dials_from(dial, with_path(Config::new(), on)).await;
    let (s, l, to) = (crossed.s, crossed.l, crossed.to.clone());
    let dialled = to.1.clone();
    let mut nodes = crossed.nodes;
    let mut tap = crossed.tap;
    let l_addr = *nodes[l].node.node_addr();
    hand(&mut nodes[s].node, crossed.msg2).await;
    assert_eq!(
        nodes[s]
            .node
            .get_peer(&l_addr)
            .expect("precondition: the smaller node keeps the larger")
            .our_index(),
        Some(crossed.outbound),
        "precondition: the smaller node swapped to its outbound session"
    );
    assert_eq!(
        pair(&nodes[s], &l_addr),
        (Some(to.0), Some(to.1.clone())),
        "defect: the smaller node holds the larger at the winning msg2's transport and source"
    );
    for packet in crossed.rest {
        hand(&mut nodes[s].node, packet).await;
    }
    while let Ok(packet) = tap.try_recv() {
        hand(&mut nodes[l].node, packet).await;
    }
    route(&dialled, &nodes[l]);
    pump(&mut nodes).await;
    assert_coherent(
        &mut nodes,
        &[Exempt::CrossedInbound { node: s, peer: l }],
        "the end of a crossed dial won on another pair",
    )
    .await;
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_crossed_dial_won_on_another_transport_leaves_a_coherent_pair() {
    coherent_pair(false, Dial::OtherTransport).await;
}

/// [`a_crossed_dial_won_on_another_transport_leaves_a_coherent_pair`] with multipath on.
#[tokio::test]
async fn a_crossed_dial_won_on_another_transport_leaves_a_coherent_pair_with_multipath_on() {
    coherent_pair(true, Dial::OtherTransport).await;
}

#[tokio::test]
async fn a_crossed_dial_won_from_another_address_leaves_a_coherent_pair() {
    coherent_pair(false, Dial::OtherAddress).await;
}

/// [`a_crossed_dial_won_from_another_address_leaves_a_coherent_pair`] with multipath on.
#[tokio::test]
async fn a_crossed_dial_won_from_another_address_leaves_a_coherent_pair_with_multipath_on() {
    coherent_pair(true, Dial::OtherAddress).await;
}

// ---------------------------------------------------------------------------
// A dialer's second msg1, more than 1 s after its first
// ---------------------------------------------------------------------------

/// Two loopback nodes, with the indices of the dialer and the responder,
/// the dialer's address the larger when `dialer_larger`.
async fn ordered_pair(on: bool, dialer_larger: bool) -> (Vec<TestNode>, usize, usize) {
    let nodes = vec![loopback_node(on).await, loopback_node(on).await];
    let zero_larger = nodes[0].node.node_addr() > nodes[1].node.node_addr();
    if zero_larger == dialer_larger {
        (nodes, 0, 1)
    } else {
        (nodes, 1, 0)
    }
}

/// How the dialer's second dial reaches the responder.
#[derive(Clone, Copy, Debug)]
pub(super) enum Second {
    /// On the same transport and address, msg2s delivered in order.
    InOrder,
    /// On the same transport and address, the second dial's msg2 reaching
    /// the dialer before the first's.
    Reordered,
    /// On a second transport, msg2s in order.
    OtherTransport,
}

/// The state after a dialer's two msg1s, ready to be checked.
pub(super) struct LateDial {
    pub(super) nodes: Vec<TestNode>,
    /// The dialer's index.
    pub(super) d: usize,
    /// The responder's index.
    pub(super) r: usize,
    /// Frames the dialer had received from the responder before the second
    /// msg1 was handled.
    before: u64,
}

/// The dialer sends two msg1s; the first reaches the responder stamped
/// 1.5 s before the second, and nothing the dialer sends on the first
/// peering is read by the responder before the second msg1. Then everything
/// is delivered.
pub(super) async fn second_msg1_late(on: bool, dialer_larger: bool, second: Second) -> LateDial {
    use crate::node::handlers::handshake::UNHEARD_PEERING_MIN_AGE_MS;

    let (mut nodes, d, r) = ordered_pair(on, dialer_larger).await;
    let d_addr = *nodes[d].node.node_addr();
    let r_addr = *nodes[r].node.node_addr();
    initiate_handshake(&mut nodes, d, r).await;
    if let Second::OtherTransport = second {
        let t2 = TransportId::new(2);
        let d2 = alias(&nodes[d].addr, t2);
        let r2 = alias(&nodes[r].addr, t2);
        for (n, a) in [(d, d2), (r, r2.clone())] {
            let lo = crate::transport::loopback::LoopbackTransport::new(
                t2,
                a,
                LOOPBACK_REGISTRY.clone(),
            );
            nodes[n]
                .node
                .transports
                .insert(t2, TransportHandle::Loopback(lo));
        }
        let (t1, r1) = (nodes[d].transport_id, nodes[r].addr.clone());
        nodes[d].transport_id = t2;
        nodes[r].addr = r2;
        initiate_handshake(&mut nodes, d, r).await;
        nodes[d].transport_id = t1;
        nodes[r].addr = r1;
    } else {
        initiate_handshake(&mut nodes, d, r).await;
    }
    let mut first = nodes[r]
        .packet_rx
        .try_recv()
        .expect("precondition: the first msg1 is queued at the responder");
    let mut second_msg1 = nodes[r]
        .packet_rx
        .try_recv()
        .expect("precondition: the second msg1 is queued at the responder");
    if let Second::OtherTransport = second {
        assert_ne!(
            first.transport_id, second_msg1.transport_id,
            "precondition: the two msg1s came on different transports"
        );
    }

    // The second msg1 arrives 1.5 s after the first.
    first.timestamp_ms = Node::now_ms();
    nodes[r].node.handle_msg1(first).await;
    let first_link = nodes[r]
        .node
        .get_peer(&d_addr)
        .map(|p| p.link_id())
        .expect("precondition: the first msg1 promoted the dialer");

    let before;
    match second {
        Second::InOrder | Second::OtherTransport => {
            process_available_packets(std::slice::from_mut(&mut nodes[d])).await;
            before = nodes[d]
                .node
                .get_peer(&r_addr)
                .map(|p| p.link_stats().packets_recv)
                .expect("precondition: the dialer promoted the responder on the first msg2");
            crate::time::advance(Duration::from_millis(UNHEARD_PEERING_MIN_AGE_MS + 500));
            second_msg1.timestamp_ms = Node::now_ms();
            nodes[r].node.handle_msg1(second_msg1).await;
        }
        Second::Reordered => {
            crate::time::advance(Duration::from_millis(UNHEARD_PEERING_MIN_AGE_MS + 500));
            second_msg1.timestamp_ms = Node::now_ms();
            nodes[r].node.handle_msg1(second_msg1).await;
            // Everything the responder sent is at the dialer: msg2(first),
            // frames, msg2(second), frames. Hand the second msg2 first.
            let queued: Vec<ReceivedPacket> =
                std::iter::from_fn(|| nodes[d].packet_rx.try_recv().ok()).collect();
            let msg2s: Vec<usize> = queued
                .iter()
                .enumerate()
                .filter(|(_, p)| {
                    CommonPrefix::parse(&p.data).is_some_and(|c| c.phase == PHASE_MSG2)
                })
                .map(|(i, _)| i)
                .collect();
            assert_eq!(msg2s.len(), 2, "precondition: two msg2s at the dialer");
            let mut queued: Vec<Option<ReceivedPacket>> = queued.into_iter().map(Some).collect();
            let second_msg2 = queued[msg2s[1]]
                .take()
                .expect("precondition: the second msg2 is held");
            let first_msg2 = queued[msg2s[0]]
                .take()
                .expect("precondition: the first msg2 is held");
            hand(&mut nodes[d].node, second_msg2).await;
            hand(&mut nodes[d].node, first_msg2).await;
            for p in queued.into_iter().flatten() {
                assert_eq!(
                    phase(&p),
                    Some(PHASE_ESTABLISHED),
                    "precondition: only frames follow the msg2s"
                );
                hand(&mut nodes[d].node, p).await;
            }
            before = 0;
        }
    }
    assert!(
        nodes[r]
            .node
            .get_peer(&d_addr)
            .is_some_and(|p| p.link_id() != first_link),
        "precondition: the second msg1 replaced the unheard peering"
    );
    drain_all_packets(&mut nodes, false).await;
    LateDial {
        nodes,
        d,
        r,
        before,
    }
}

/// Whether both ends hold one session on which the responder has heard the
/// dialer, the dialer has received frames since its first msg2, and a
/// heartbeat sent now authenticates each way.
async fn working_peering(late: &mut LateDial) -> Result<(), String> {
    let (d, r) = (late.d, late.r);
    let nodes = &mut late.nodes;
    let d_addr = *nodes[d].node.node_addr();
    let r_addr = *nodes[r].node.node_addr();
    let idx_r = nodes[r]
        .node
        .get_peer(&d_addr)
        .map(|p| (p.our_index(), p.their_index()));
    let idx_d = nodes[d]
        .node
        .get_peer(&r_addr)
        .map(|p| (p.our_index(), p.their_index()));
    let heard_r = nodes[r]
        .node
        .get_peer(&d_addr)
        .is_some_and(|p| p.is_heard() && p.link_stats().packets_recv > 0);
    let frames_d = nodes[d]
        .node
        .get_peer(&r_addr)
        .is_some_and(|p| p.link_stats().packets_recv > late.before);
    let same = matches!(
        (idx_r, idx_d),
        (Some((ro, rt)), Some((dl, dt))) if ro.is_some() && ro == dt && rt == dl
    );
    let fresh = [
        heartbeat_reaches(nodes, d, r).await,
        heartbeat_reaches(nodes, r, d).await,
    ];
    if heard_r && frames_d && same && fresh.iter().all(Result::is_ok) {
        Ok(())
    } else {
        Err(format!(
            "same session {same}, responder heard {heard_r}, dialer frames {frames_d}; responder (ours, theirs) {idx_r:?}, dialer (ours, theirs) {idx_d:?}; fresh heartbeats dialer to responder, back: {fresh:?}"
        ))
    }
}

/// The breaches the dialer's own move leaves at the dialer after its
/// second dial.
#[derive(Clone, Copy)]
enum Kept {
    /// None: the held link keeps its index entry, since the retired dial's
    /// link no longer takes it.
    Entry,
    /// The peer's link record stays on the first transport. The move's
    /// renewal of the link's paths on the dial's pair releases the record's
    /// setup pair, which then leaves the index, as a released setup pair
    /// does.
    Record,
}

/// The dialer's second msg1 leaves a working peering, checked by heartbeat
/// and then by the audit. Without an exemption the audit finds exactly the
/// breaches `kept` names at the dialer, which are the documented move;
/// with it, none.
async fn late_dial_works(on: bool, dialer_larger: bool, second: Second, kept: Kept) {
    let mut late = second_msg1_late(on, dialer_larger, second).await;
    let works = working_peering(&mut late).await;
    assert!(works.is_ok(), "defect: {works:?}");
    let (d, r) = (late.d, late.r);
    let unexempt = audit(&mut late.nodes, &[]).await;
    let (expected, exempt) = match kept {
        Kept::Entry => (unexempt.is_empty(), None),
        Kept::Record => (
            unexempt.len() == 1
                && matches!(
                    &unexempt[0],
                    Breach::RightLink { node, peer, .. } if *node == d && *peer == r
                ),
            Some(Exempt::MovedOwnDial { node: d, peer: r }),
        ),
    };
    assert!(
        expected,
        "defect: the audit finds only the dialer's documented breach: {unexempt:#?}"
    );
    let exempt: Vec<Exempt> = exempt.into_iter().collect();
    assert_coherent(&mut late.nodes, &exempt, "the end of a late second dial").await;
    cleanup_nodes(&mut late.nodes).await;
}

#[tokio::test]
async fn a_second_msg1_more_than_1s_later_leaves_a_working_peering_larger_dialer() {
    late_dial_works(false, true, Second::InOrder, Kept::Entry).await;
}

/// [`a_second_msg1_more_than_1s_later_leaves_a_working_peering_larger_dialer`] with multipath on.
#[tokio::test]
async fn a_second_msg1_more_than_1s_later_leaves_a_working_peering_larger_dialer_with_multipath_on()
{
    late_dial_works(true, true, Second::InOrder, Kept::Entry).await;
}

#[tokio::test]
async fn a_second_msg1_more_than_1s_later_leaves_a_working_peering_smaller_dialer() {
    late_dial_works(false, false, Second::InOrder, Kept::Entry).await;
}

/// [`a_second_msg1_more_than_1s_later_leaves_a_working_peering_smaller_dialer`] with multipath on.
#[tokio::test]
async fn a_second_msg1_more_than_1s_later_leaves_a_working_peering_smaller_dialer_with_multipath_on()
 {
    late_dial_works(true, false, Second::InOrder, Kept::Entry).await;
}

#[tokio::test]
async fn a_second_msg1_more_than_1s_later_on_another_transport_leaves_a_working_peering_larger_dialer()
 {
    late_dial_works(false, true, Second::OtherTransport, Kept::Record).await;
}

/// [`a_second_msg1_more_than_1s_later_on_another_transport_leaves_a_working_peering_larger_dialer`] with multipath on.
#[tokio::test]
async fn a_second_msg1_more_than_1s_later_on_another_transport_leaves_a_working_peering_larger_dialer_with_multipath_on()
 {
    late_dial_works(true, true, Second::OtherTransport, Kept::Record).await;
}

#[tokio::test]
async fn a_second_msg1_more_than_1s_later_on_another_transport_leaves_a_working_peering_smaller_dialer()
 {
    late_dial_works(false, false, Second::OtherTransport, Kept::Record).await;
}

/// [`a_second_msg1_more_than_1s_later_on_another_transport_leaves_a_working_peering_smaller_dialer`] with multipath on.
#[tokio::test]
async fn a_second_msg1_more_than_1s_later_on_another_transport_leaves_a_working_peering_smaller_dialer_with_multipath_on()
 {
    late_dial_works(true, false, Second::OtherTransport, Kept::Record).await;
}

/// The reordered case, checked by heartbeat: both ends on one session.
async fn reordered_works(on: bool, dialer_larger: bool) {
    let mut late = second_msg1_late(on, dialer_larger, Second::Reordered).await;
    let works = working_peering(&mut late).await;
    cleanup_nodes(&mut late.nodes).await;
    assert!(works.is_ok(), "defect: {works:?}");
}

#[tokio::test]
#[ignore = "known defect: when the second dial's msg2 reaches the dialer first, the two ends are left on different sessions"]
async fn a_second_msg1_more_than_1s_later_with_its_msg2_first_leaves_a_working_peering_larger_dialer()
 {
    reordered_works(false, true).await;
}

/// [`a_second_msg1_more_than_1s_later_with_its_msg2_first_leaves_a_working_peering_larger_dialer`] with multipath on.
#[tokio::test]
#[ignore = "known defect: when the second dial's msg2 reaches the dialer first, the two ends are left on different sessions"]
async fn a_second_msg1_more_than_1s_later_with_its_msg2_first_leaves_a_working_peering_larger_dialer_with_multipath_on()
 {
    reordered_works(true, true).await;
}

#[tokio::test]
#[ignore = "known defect: when the second dial's msg2 reaches the dialer first, the two ends are left on different sessions"]
async fn a_second_msg1_more_than_1s_later_with_its_msg2_first_leaves_a_working_peering_smaller_dialer()
 {
    reordered_works(false, false).await;
}

/// [`a_second_msg1_more_than_1s_later_with_its_msg2_first_leaves_a_working_peering_smaller_dialer`] with multipath on.
#[tokio::test]
#[ignore = "known defect: when the second dial's msg2 reaches the dialer first, the two ends are left on different sessions"]
async fn a_second_msg1_more_than_1s_later_with_its_msg2_first_leaves_a_working_peering_smaller_dialer_with_multipath_on()
 {
    reordered_works(true, false).await;
}

/// The reordered case, checked by the audit: no breach of `OneSession`'s
/// first clause. Other breaches are not this pin's reason and are ignored.
async fn reordered_one_session(on: bool, dialer_larger: bool) {
    let mut late = second_msg1_late(on, dialer_larger, Second::Reordered).await;
    let breaches = audit(&mut late.nodes, &[]).await;
    cleanup_nodes(&mut late.nodes).await;
    let split: Vec<&Breach> = breaches
        .iter()
        .filter(|b| matches!(b, Breach::Split { .. } | Breach::OneSided { .. }))
        .collect();
    assert!(split.is_empty(), "defect: {split:#?}");
}

#[tokio::test]
#[ignore = "known defect: when the second dial's msg2 reaches the dialer first, the audit finds the two ends on different sessions"]
async fn a_second_msg1_more_than_1s_later_with_its_msg2_first_leaves_one_session_by_the_audit_larger_dialer()
 {
    reordered_one_session(false, true).await;
}

/// [`a_second_msg1_more_than_1s_later_with_its_msg2_first_leaves_one_session_by_the_audit_larger_dialer`] with multipath on.
#[tokio::test]
#[ignore = "known defect: when the second dial's msg2 reaches the dialer first, the audit finds the two ends on different sessions"]
async fn a_second_msg1_more_than_1s_later_with_its_msg2_first_leaves_one_session_by_the_audit_larger_dialer_with_multipath_on()
 {
    reordered_one_session(true, true).await;
}

#[tokio::test]
#[ignore = "known defect: when the second dial's msg2 reaches the dialer first, the audit finds the two ends on different sessions"]
async fn a_second_msg1_more_than_1s_later_with_its_msg2_first_leaves_one_session_by_the_audit_smaller_dialer()
 {
    reordered_one_session(false, false).await;
}

/// [`a_second_msg1_more_than_1s_later_with_its_msg2_first_leaves_one_session_by_the_audit_smaller_dialer`] with multipath on.
#[tokio::test]
#[ignore = "known defect: when the second dial's msg2 reaches the dialer first, the audit finds the two ends on different sessions"]
async fn a_second_msg1_more_than_1s_later_with_its_msg2_first_leaves_one_session_by_the_audit_smaller_dialer_with_multipath_on()
 {
    reordered_one_session(true, false).await;
}

// ---------------------------------------------------------------------------
// A larger node's dial on a quiet peer's aged link
// ---------------------------------------------------------------------------

/// The state after a larger node, holding a peer through a link the peer
/// set up and aged past the rekey floor, dials the quiet peer again from
/// its usual source: the peer answered the msg1 as a rekey and holds a
/// responder pending, which the larger node, keeping its own session by
/// the tie-break, will not adopt.
struct AgedDial {
    nodes: Vec<TestNode>,
    /// The larger node, which dials again.
    d: usize,
    /// The smaller node, which set the link up.
    p: usize,
}

/// Drive the aged-link dial to the point both ends are quiet.
async fn aged_link_dial(on: bool) -> AgedDial {
    let mut nodes = vec![
        make_test_node_with_config(with_path(rekey_config(60), on), 1280).await,
        make_test_node_with_config(with_path(rekey_config(60), on), 1280).await,
    ];
    let zero_smaller = nodes[0].node.node_addr() < nodes[1].node.node_addr();
    let (d, p) = if zero_smaller { (1, 0) } else { (0, 1) };
    let dialer_addr = *nodes[d].node.node_addr();
    let peer_addr = *nodes[p].node.node_addr();
    initiate_handshake(&mut nodes, p, d).await;
    drain_all_packets(&mut nodes, false).await;
    assert!(
        nodes[d].node.get_peer(&peer_addr).is_some()
            && nodes[p].node.get_peer(&dialer_addr).is_some(),
        "precondition: the two nodes are peered"
    );
    let peer_npub = nodes[p].node.npub();
    // Age both ends past the rekey trigger and the 30 s link floor.
    age_link(&mut nodes, d, p, trigger_age());
    quieten(&mut nodes[d], &peer_addr);
    let tid = nodes[p].transport_id;
    let alternate = alias(&nodes[p].addr, tid);
    let dialer_before = link_view(&nodes[d], &peer_addr);
    let peer_before = link_view(&nodes[p], &dialer_addr);

    let data = nodes[d]
        .node
        .api_connect(&peer_npub, &alternate.to_string(), "loopback")
        .await
        .expect("precondition: api_connect on an alternate path succeeds");
    assert_eq!(data["refreshed"], true, "precondition: the dial starts");
    assert_eq!(
        deliver(&mut nodes[p]).await,
        1,
        "precondition: only the dialer's msg1 is queued at the peer"
    );
    assert_eq!(
        nodes[p]
            .node
            .get_peer(&dialer_addr)
            .expect("precondition: the peer holds the dialer")
            .pending_role(),
        Some(Role::Responder),
        "precondition: the peer answered the dial as a rekey"
    );
    for _ in 0..20 {
        if process_available_packets(&mut nodes).await == 0 {
            break;
        }
    }
    assert_eq!(
        link_view(&nodes[d], &peer_addr).our_index,
        dialer_before.our_index,
        "precondition: the larger dialer on the peer's link kept its own session"
    );
    assert_eq!(
        nodes[p]
            .node
            .get_peer(&dialer_addr)
            .expect("precondition: the peer holds the dialer")
            .pending_role(),
        Some(Role::Responder),
        "precondition: the peer still holds the unadopted responder pending"
    );
    assert_eq!(
        link_view(&nodes[p], &dialer_addr),
        peer_before,
        "precondition: the peer stays on its original link and session"
    );
    AgedDial { nodes, d, p }
}

/// After its dial on the peer's aged link, the larger node's own genuine
/// rekey, started inside the pending's hold, is answered by the peer.
async fn rekey_answered(on: bool) {
    let AgedDial { mut nodes, d, p } = aged_link_dial(on).await;
    let peer_addr = *nodes[p].node.node_addr();
    nodes[d].node.poll_link_rekeys().await;
    assert!(
        nodes[d]
            .node
            .get_peer(&peer_addr)
            .expect("precondition: the dialer holds the peer")
            .rekey_in_progress(),
        "precondition: the dialer started its own rekey"
    );
    deliver(&mut nodes[p]).await;
    deliver(&mut nodes[d]).await;
    let dialer_pending = nodes[d]
        .node
        .get_peer(&peer_addr)
        .expect("precondition: the dialer holds the peer")
        .pending_role();
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        dialer_pending,
        Some(Role::Initiator),
        "defect: the peer did not answer the larger node's rekey"
    );
}

#[tokio::test]
#[ignore = "known defect: after a larger node's dial on a quiet peer's aged link, the peer discards that node's next rekey while it holds the pending the dial left"]
async fn a_larger_dialers_rekey_after_its_dial_on_the_peers_aged_link_is_answered() {
    rekey_answered(false).await;
}

/// [`a_larger_dialers_rekey_after_its_dial_on_the_peers_aged_link_is_answered`] with multipath on.
#[tokio::test]
#[ignore = "known defect: after a larger node's dial on a quiet peer's aged link, the peer discards that node's next rekey while it holds the pending the dial left"]
async fn a_larger_dialers_rekey_after_its_dial_on_the_peers_aged_link_is_answered_with_multipath_on()
 {
    rekey_answered(true).await;
}

/// After its dial on the peer's aged link, with both ends quiet, neither
/// end holds a pending the other has no handshake able to adopt: no breach
/// of `OneSession`'s second clause. Other breaches are not this pin's
/// reason and are ignored.
async fn none_unadoptable(on: bool) {
    let AgedDial { mut nodes, .. } = aged_link_dial(on).await;
    let breaches = audit(&mut nodes, &[]).await;
    cleanup_nodes(&mut nodes).await;
    let unadoptable: Vec<&Breach> = breaches
        .iter()
        .filter(|b| matches!(b, Breach::Unadoptable { .. }))
        .collect();
    assert!(unadoptable.is_empty(), "defect: {unadoptable:#?}");
}

#[tokio::test]
#[ignore = "known defect: after a larger node's dial on a quiet peer's aged link, the peer holds a responder pending the larger node never adopts"]
async fn a_larger_dialers_dial_on_the_peers_aged_link_leaves_no_pending_the_peer_cannot_adopt() {
    none_unadoptable(false).await;
}

/// [`a_larger_dialers_dial_on_the_peers_aged_link_leaves_no_pending_the_peer_cannot_adopt`] with multipath on.
#[tokio::test]
#[ignore = "known defect: after a larger node's dial on a quiet peer's aged link, the peer holds a responder pending the larger node never adopts"]
async fn a_larger_dialers_dial_on_the_peers_aged_link_leaves_no_pending_the_peer_cannot_adopt_with_multipath_on()
 {
    none_unadoptable(true).await;
}

// ---------------------------------------------------------------------------
// A crossed msg1 read past the heard floor
// ---------------------------------------------------------------------------

/// Longer than the 15 s heard floor, below which a heard peering is not
/// replaced.
const SILENCE: Duration = Duration::from_secs(16);

/// Give `tn` a loopback transport `id` whose own address is `addr`. A copy
/// of `crossed_dial::add_transport`, which is private.
fn loopback(tn: &mut TestNode, id: TransportId, addr: TransportAddr) {
    let lo = LoopbackTransport::with_mtu(id, addr, 1280, LOOPBACK_REGISTRY.clone());
    tn.node.transports.insert(id, TransportHandle::Loopback(lo));
}

/// Crossed dials whose larger node's msg1 reaches the smaller node late.
/// The larger node reads the smaller node's msg1 and answers it; the
/// smaller node installs from that answer to its own dial, and only then,
/// having last heard the larger node `quiet` ago, reads the larger node's
/// msg1. With `other` the larger node dials from a second transport to a
/// second address of the smaller node's. Whether the two ends are left on
/// one working session.
async fn late_cross(on: bool, other: bool, quiet: Duration) -> Result<(), String> {
    let mut nodes = vec![loopback_node(on).await, loopback_node(on).await];
    let (s, l) = if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        (0, 1)
    } else {
        (1, 0)
    };
    let s_addr = *nodes[s].node.node_addr();
    let l_addr = *nodes[l].node.node_addr();
    let t1 = nodes[s].transport_id;
    let s1 = nodes[s].addr.clone();
    let l1 = nodes[l].addr.clone();
    let s_id = PeerIdentity::from_pubkey_full(nodes[s].node.identity().pubkey_full());
    let l_id = PeerIdentity::from_pubkey_full(nodes[l].node.identity().pubkey_full());
    let (l_tid, l_to) = if other {
        let t2 = TransportId::new(2);
        let s2 = alias(&s1, t2);
        let l2 = alias(&l1, t2);
        loopback(&mut nodes[s], t2, s2.clone());
        loopback(&mut nodes[l], t2, l2);
        (t2, s2)
    } else {
        (t1, s1)
    };
    nodes[s]
        .node
        .initiate_connection(t1, l1, l_id)
        .await
        .expect("precondition: the smaller node's dial starts");
    nodes[l]
        .node
        .initiate_connection(l_tid, l_to, s_id)
        .await
        .expect("precondition: the larger node's dial starts");
    deliver(&mut nodes[l]).await;
    assert!(
        nodes[l].node.get_peer(&s_addr).is_some(),
        "precondition: the larger node promoted on the smaller node's msg1"
    );
    // The smaller node reads the answer to its own dial and what follows
    // it; the larger node's msg1 is held back.
    let queued: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[s].packet_rx.try_recv().ok()).collect();
    let mut late = Vec::new();
    for packet in queued {
        if phase(&packet) == Some(PHASE_MSG1) {
            late.push(packet);
        } else {
            hand(&mut nodes[s].node, packet).await;
        }
    }
    assert_eq!(
        late.len(),
        1,
        "precondition: the larger node's one msg1 is held back"
    );
    nodes[s]
        .node
        .get_peer_mut(&l_addr)
        .expect("precondition: the smaller node installed from its own dial's msg2")
        .test_backdate_heard(quiet);
    for packet in late {
        hand(&mut nodes[s].node, packet).await;
    }
    pump(&mut nodes).await;
    let out = settled(&mut nodes, s, l).await;
    cleanup_nodes(&mut nodes).await;
    out
}

/// A crossed msg1 the larger node sent from another transport, read by the
/// smaller node after it installed from its own dial and heard nothing for
/// longer than the heard floor, leaves one working session.
#[tokio::test]
#[ignore = "known defect: a crossed msg1 read past the heard floor makes the smaller node replace its session while the larger node keeps its own"]
async fn a_crossed_msg1_from_another_transport_read_past_the_heard_floor_leaves_one_session() {
    let out = late_cross(false, true, SILENCE).await;
    assert!(out.is_ok(), "defect: {out:?}");
}

/// [`a_crossed_msg1_from_another_transport_read_past_the_heard_floor_leaves_one_session`] with multipath on.
#[tokio::test]
#[ignore = "known defect: a crossed msg1 read past the heard floor makes the smaller node replace its session while the larger node keeps its own"]
async fn a_crossed_msg1_from_another_transport_read_past_the_heard_floor_leaves_one_session_with_multipath_on()
 {
    let out = late_cross(true, true, SILENCE).await;
    assert!(out.is_ok(), "defect: {out:?}");
}

/// As above, with the larger node's dial on the transport the smaller
/// node's dial used.
#[tokio::test]
#[ignore = "known defect: a crossed msg1 read past the heard floor makes the smaller node replace its session while the larger node keeps its own"]
async fn a_crossed_msg1_on_the_same_transport_read_past_the_heard_floor_leaves_one_session() {
    let out = late_cross(false, false, SILENCE).await;
    assert!(out.is_ok(), "defect: {out:?}");
}

/// [`a_crossed_msg1_on_the_same_transport_read_past_the_heard_floor_leaves_one_session`] with multipath on.
#[tokio::test]
#[ignore = "known defect: a crossed msg1 read past the heard floor makes the smaller node replace its session while the larger node keeps its own"]
async fn a_crossed_msg1_on_the_same_transport_read_past_the_heard_floor_leaves_one_session_with_multipath_on()
 {
    let out = late_cross(true, false, SILENCE).await;
    assert!(out.is_ok(), "defect: {out:?}");
}

/// The same late crossed msg1, read with the larger node heard just now,
/// inside the heard floor, leaves one working session: the assertion the
/// two pins make can pass.
#[tokio::test]
async fn a_crossed_msg1_from_another_transport_read_inside_the_heard_floor_leaves_one_session() {
    let out = late_cross(false, true, Duration::ZERO).await;
    assert!(out.is_ok(), "defect: {out:?}");
}

/// [`a_crossed_msg1_from_another_transport_read_inside_the_heard_floor_leaves_one_session`] with multipath on.
#[tokio::test]
async fn a_crossed_msg1_from_another_transport_read_inside_the_heard_floor_leaves_one_session_with_multipath_on()
 {
    let out = late_cross(true, true, Duration::ZERO).await;
    assert!(out.is_ok(), "defect: {out:?}");
}

// ---------------------------------------------------------------------------
// A larger node's dial on an aged link after the smaller node's own rekey
// ---------------------------------------------------------------------------

/// The smaller node set the link up and, once the link is aged, rekeys it;
/// both ends cut over, so the smaller node's session is younger than the
/// rekey machine's session floor. What the larger node sends after the
/// cutover is lost, and the smaller node last heard it `quiet` ago. Then
/// the larger node dials the smaller node's second address. Whether the
/// two ends are left on one working session.
async fn aged_rekey(on: bool, quiet: Duration) -> Result<(), String> {
    let mut nodes = vec![
        make_test_node_with_config(with_path(rekey_config(60), on), 1280).await,
        make_test_node_with_config(with_path(rekey_config(60), on), 1280).await,
    ];
    let zero_smaller = nodes[0].node.node_addr() < nodes[1].node.node_addr();
    let (d, p) = if zero_smaller { (1, 0) } else { (0, 1) };
    let d_addr = *nodes[d].node.node_addr();
    let p_addr = *nodes[p].node.node_addr();
    initiate_handshake(&mut nodes, p, d).await;
    drain_all_packets(&mut nodes, false).await;
    assert!(
        nodes[d].node.get_peer(&p_addr).is_some() && nodes[p].node.get_peer(&d_addr).is_some(),
        "precondition: the two nodes are peered"
    );
    age_link(&mut nodes, d, p, trigger_age());

    // The smaller node's own rekey, completed at both ends.
    rekey_to_pending(&mut nodes, p, d).await;
    cutover(&mut nodes[p], &d_addr).await;
    heartbeat(&mut nodes[p], &d_addr).await;
    deliver(&mut nodes[d]).await;
    {
        let at_p = nodes[p]
            .node
            .get_peer(&d_addr)
            .expect("precondition: the smaller node holds the larger");
        let at_d = nodes[d]
            .node
            .get_peer(&p_addr)
            .expect("precondition: the larger node holds the smaller");
        assert!(
            at_d.pending_new_session().is_none()
                && at_d.our_index() == at_p.their_index()
                && at_p.our_index() == at_d.their_index(),
            "precondition: both ends cut over to the rekeyed session"
        );
    }
    let rekeyed = link_view(&nodes[p], &d_addr).our_index;
    let _lost = std::iter::from_fn(|| nodes[p].packet_rx.try_recv().ok()).count();
    nodes[p]
        .node
        .get_peer_mut(&d_addr)
        .expect("precondition: the smaller node holds the larger")
        .test_backdate_heard(quiet);

    // The larger node dials the smaller node's second address.
    quieten(&mut nodes[d], &p_addr);
    let tid = nodes[p].transport_id;
    let alternate = alias(&nodes[p].addr, tid);
    let p_npub = nodes[p].node.npub();
    let data = nodes[d]
        .node
        .api_connect(&p_npub, &alternate.to_string(), "loopback")
        .await
        .expect("precondition: api_connect on an alternate path succeeds");
    assert_eq!(data["refreshed"], true, "precondition: the dial starts");
    deliver(&mut nodes[p]).await;
    if quiet >= SILENCE {
        assert_ne!(
            link_view(&nodes[p], &d_addr).our_index,
            rekeyed,
            "precondition: the smaller node took the dial as a replacement of its young session"
        );
    }
    deliver(&mut nodes[d]).await;
    drain_all_packets(&mut nodes, false).await;
    let out = settled(&mut nodes, d, p).await;
    cleanup_nodes(&mut nodes).await;
    out
}

/// A larger node's dial on the aged link the smaller node set up, made
/// after the smaller node's own rekey and longer than the heard floor
/// after the smaller node last heard it, leaves one working session.
#[tokio::test]
#[ignore = "known defect: after the smaller node's own rekey, the larger node's dial on its aged link is taken as a replacement while the larger node keeps its own session"]
async fn a_larger_dialers_dial_on_the_aged_link_after_the_smaller_nodes_rekey_leaves_one_session() {
    let out = aged_rekey(false, SILENCE).await;
    assert!(out.is_ok(), "defect: {out:?}");
}

/// [`a_larger_dialers_dial_on_the_aged_link_after_the_smaller_nodes_rekey_leaves_one_session`] with multipath on.
#[tokio::test]
#[ignore = "known defect: after the smaller node's own rekey, the larger node's dial on its aged link is taken as a replacement while the larger node keeps its own session"]
async fn a_larger_dialers_dial_on_the_aged_link_after_the_smaller_nodes_rekey_leaves_one_session_with_multipath_on()
 {
    let out = aged_rekey(true, SILENCE).await;
    assert!(out.is_ok(), "defect: {out:?}");
}

/// The same dial with the larger node heard just now leaves one working
/// session: the assertion the pin makes can pass.
#[tokio::test]
async fn a_larger_dialers_dial_on_the_aged_link_after_the_smaller_nodes_rekey_inside_the_heard_floor_leaves_one_session()
 {
    let out = aged_rekey(false, Duration::ZERO).await;
    assert!(out.is_ok(), "defect: {out:?}");
}

/// [`a_larger_dialers_dial_on_the_aged_link_after_the_smaller_nodes_rekey_inside_the_heard_floor_leaves_one_session`] with multipath on.
#[tokio::test]
async fn a_larger_dialers_dial_on_the_aged_link_after_the_smaller_nodes_rekey_inside_the_heard_floor_leaves_one_session_with_multipath_on()
 {
    let out = aged_rekey(true, Duration::ZERO).await;
    assert!(out.is_ok(), "defect: {out:?}");
}

// ---------------------------------------------------------------------------
// A dial reaped while another dial at its pair is in flight
// ---------------------------------------------------------------------------

/// Two dials from node 0 to node 1's one address, neither answered, so no
/// peer is held: the first dial's link is returned, with the second's link
/// still at the same pair.
async fn two_dials(nodes: &mut [TestNode]) -> LinkId {
    initiate_handshake(nodes, 0, 1).await;
    let first: Vec<LinkId> = nodes[0].node.links.keys().copied().collect();
    assert_eq!(first.len(), 1, "precondition: the first dial has one link");
    initiate_handshake(nodes, 0, 1).await;
    assert_eq!(
        nodes[0].node.links.len(),
        2,
        "precondition: two dials in flight at one pair"
    );
    assert!(
        nodes[0].node.peers.is_empty(),
        "precondition: no peer is held, so no peer's path keeps the connection"
    );
    first[0]
}

/// Reap the dial whose link is `first` at node 0, as its handshake timeout
/// does.
async fn reap(nodes: &mut [TestNode], first: LinkId) {
    nodes[0].node.cleanup_stale_connection(first, 0).await;
    assert!(
        !nodes[0].node.links.contains_key(&first),
        "precondition: the first dial is reaped"
    );
}

/// On loopback, which records each close: reaping one of two dials at one
/// pair does not close the connection the other dial is running on.
async fn reaped_dial(on: bool) {
    let mut nodes = vec![loopback_node(on).await, loopback_node(on).await];
    let t1 = nodes[0].transport_id;
    let b1 = nodes[1].addr.clone();
    let first = two_dials(&mut nodes).await;
    reap(&mut nodes, first).await;
    let closed = match nodes[0].node.transports.get(&t1) {
        Some(TransportHandle::Loopback(t)) => t.closed(),
        _ => panic!("precondition: node 0's transport is loopback"),
    };
    cleanup_nodes(&mut nodes).await;
    assert!(
        !closed.contains(&b1),
        "defect: reaping a dial closed the connection another dial in flight uses: {closed:?}"
    );
}

/// [`reaped_dial`] with multipath off.
#[tokio::test]
async fn a_reaped_dial_leaves_a_connection_another_dial_in_flight_uses() {
    reaped_dial(false).await;
}

/// [`reaped_dial`] with multipath on.
#[tokio::test]
async fn a_reaped_dial_leaves_a_connection_another_dial_in_flight_uses_with_multipath_on() {
    reaped_dial(true).await;
}

/// On the BLE mock, whose pool holds one channel per address and closes it
/// when asked: reaping one of two dials on a channel leaves the channel
/// pooled for the other. Read with the pool's lock awaited, so a lock held
/// by the transport's own tasks cannot pass for a closed channel.
#[cfg(ble_available)]
async fn ble_reaped(on: bool) {
    use super::super::ble::{base_config, larger_second, link_genuinely, make_test_node_ble_from};
    let config = with_path(Config::new(), on);
    let mut nodes = vec![
        make_test_node_ble_from(1, base_config(), config.clone()).await,
        make_test_node_ble_from(2, base_config(), config).await,
    ];
    larger_second(&mut nodes);
    let _bank = link_genuinely(&nodes).await;
    let tid = nodes[0].transport_id;
    let b = nodes[1].addr.clone();
    let pooled = async |nodes: &[TestNode]| match nodes[0].node.transports.get(&tid) {
        Some(TransportHandle::Ble(t)) => t.is_verified(&b).await.is_some(),
        _ => panic!("precondition: node 0's transport is BLE"),
    };
    assert!(pooled(&nodes).await, "precondition: the BLE channel is up");
    let first = two_dials(&mut nodes).await;
    reap(&mut nodes, first).await;
    let kept = pooled(&nodes).await;
    cleanup_nodes(&mut nodes).await;
    assert!(
        kept,
        "defect: reaping a dial closed the BLE channel another dial in flight uses"
    );
}

/// [`ble_reaped`] with multipath off.
#[cfg(ble_available)]
#[tokio::test]
async fn a_reaped_ble_dial_leaves_the_channel_another_dial_in_flight_uses() {
    ble_reaped(false).await;
}

/// [`ble_reaped`] with multipath on.
#[cfg(ble_available)]
#[tokio::test]
async fn a_reaped_ble_dial_leaves_the_channel_another_dial_in_flight_uses_with_multipath_on() {
    ble_reaped(true).await;
}
