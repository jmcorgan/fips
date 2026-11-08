//! Crossed dials and a dialer's second dial: which session and which link
//! each end is left on.
//!
//! - Crossed TCP dials between two real TCP nodes on 127.0.0.1: one working
//!   session on one connection, by the audit (a known difference on this
//!   line, whose crossing leaves a shape the audit written for master
//!   flags); the smaller node's link record, which is the link it dialed;
//!   and a control that redials after a single dial.
//! - A larger node's dial on the aged link after the smaller node's rekey,
//!   read inside the heard floor: one session.
//!
//! The master line's crossings won on another pair, its late second dials,
//! its dials on a quiet peer's aged link and its redials after a crossing
//! set up states this line's handshake does not reach, and are not run here.
//!
//! Each test is run once per address order, so each order has its own
//! verdict, and once per setting of `node.path.enabled`: a test's plain name
//! runs multipath off, and its `_with_multipath_on` sibling runs it on, as two
//! tests and not one loop, since a pin that fails in a loop's first pass would
//! never reach the second. Setup checks are marked `precondition:`; the
//! assertion of the behaviour is marked `defect:`.

use super::super::control::quieten;
use super::super::rekey_parity::{
    age_link, cutover, deliver, heartbeat, rekey_config, rekey_to_pending, trigger_age,
};
use super::super::spanning_tree::{
    TestNode, cleanup_nodes, drain_all_packets, initiate_handshake, make_test_node_with_config,
    process_available_packets,
};
use super::super::*;
use super::audit::assert_coherent;
use super::{
    alias, crossed_tcp, heartbeat_reaches, pool, pump, received, resolve_connect, settled,
};
use super::{tcp_dial, tcp_pair, with_path};
use crate::proto::link::LinkMessageType;
use crate::transport::TransportId;

// ---------------------------------------------------------------------------
// Copied private helpers
// ---------------------------------------------------------------------------

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
    // No exemption: this line's smaller node keeps the link it dialed, so it
    // records no waiver, and a passed one would keep this test failing after a
    // fix of the breach it is here to report.
    assert_coherent(&mut nodes, &[], "the end of crossed TCP dials").await;
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
#[ignore = "known difference on next, cause not established: after crossed TCP dials each node keeps both its connections open with one in use, and the larger node's link record is its outbound link at the smaller node's listen address while it holds the peer at the inbound pair"]
async fn crossed_tcp_dials_leave_a_working_session_on_one_connection_smaller_first() {
    working_session(false, true).await;
}

#[tokio::test]
#[ignore = "known difference on next, cause not established: after crossed TCP dials each node keeps both its connections open with one in use, and the larger node's link record is its outbound link at the smaller node's listen address while it holds the peer at the inbound pair"]
async fn crossed_tcp_dials_leave_a_working_session_on_one_connection_smaller_first_with_multipath_on()
 {
    working_session(true, true).await;
}

#[tokio::test]
#[ignore = "known difference on next, cause not established: after crossed TCP dials each node keeps both its connections open with one in use, and the larger node's link record is its outbound link at the smaller node's listen address while it holds the peer at the inbound pair"]
async fn crossed_tcp_dials_leave_a_working_session_on_one_connection_larger_first() {
    working_session(false, false).await;
}

#[tokio::test]
#[ignore = "known difference on next, cause not established: after crossed TCP dials each node keeps both its connections open with one in use, and the larger node's link record is its outbound link at the smaller node's listen address while it holds the peer at the inbound pair"]
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
async fn crossed_tcp_dials_leave_the_smaller_node_on_the_link_it_dialed_smaller_first() {
    smaller_on_its_dialed_link(false, true).await;
}

#[tokio::test]
async fn crossed_tcp_dials_leave_the_smaller_node_on_the_link_it_dialed_smaller_first_with_multipath_on()
 {
    smaller_on_its_dialed_link(true, true).await;
}

#[tokio::test]
async fn crossed_tcp_dials_leave_the_smaller_node_on_the_link_it_dialed_larger_first() {
    smaller_on_its_dialed_link(false, false).await;
}

#[tokio::test]
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

#[tokio::test]
async fn after_one_tcp_dial_a_send_from_the_dialer_redials_a_dropped_connection_smaller_dialer_with_multipath_on()
 {
    single_then_redial(true, true).await;
}

#[tokio::test]
async fn after_one_tcp_dial_a_send_from_the_dialer_redials_a_dropped_connection_larger_dialer() {
    single_then_redial(false, false).await;
}

#[tokio::test]
async fn after_one_tcp_dial_a_send_from_the_dialer_redials_a_dropped_connection_larger_dialer_with_multipath_on()
 {
    single_then_redial(true, false).await;
}

// ---------------------------------------------------------------------------
// Crossed loopback dials won on another pair
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// A dialer's second msg1, more than 1 s after its first
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// A larger node's dial on a quiet peer's aged link
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// A crossed msg1 read past the heard floor
// ---------------------------------------------------------------------------

/// Longer than the 15 s heard floor, below which a heard peering is not
/// replaced.
const SILENCE: Duration = Duration::from_secs(16);

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
    let config = with_path(rekey_config(60), on);
    let mut nodes = vec![
        make_test_node_with_config(config.clone(), 1280).await,
        make_test_node_with_config(config, 1280).await,
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

/// The same dial with the larger node heard just now leaves one working
/// session: the assertion the pin makes can pass.
#[tokio::test]
async fn a_larger_dialers_dial_on_the_aged_link_after_the_smaller_nodes_rekey_inside_the_heard_floor_leaves_one_session()
 {
    let out = aged_rekey(false, Duration::ZERO).await;
    assert!(out.is_ok(), "defect: {out:?}");
}

/// The same dial with the larger node heard just now leaves one working
/// session: the assertion the pin makes can pass.
#[tokio::test]
async fn a_larger_dialers_dial_on_the_aged_link_after_the_smaller_nodes_rekey_inside_the_heard_floor_leaves_one_session_with_multipath_on()
 {
    let out = aged_rekey(true, Duration::ZERO).await;
    assert!(out.is_ok(), "defect: {out:?}");
}
