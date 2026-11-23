//! Which direction each end is left holding its link in, after crossed TCP
//! dials and after one end alone drops its peer and redials it.
//!
//! Two real TCP nodes on 127.0.0.1. On this line a redial is never answered
//! at the msg1, which names no one: the redialed node, still holding the
//! peer, answers it on a fresh leg and settles it at the redialer's msg3,
//! where a msg3 with no claim from a held peer at the same epoch is a
//! crossing, which the larger node's inbound wins whoever dialed either
//! link. The redialer, holding no peer, promotes at its own msg2.
//!
//! - Crossed TCP dials: the pair settles on the smaller node's dial, so the
//!   smaller node must hold the link `Outbound` and the larger `Inbound`,
//!   which the chaos edge agreement check reads from the peer listing.
//! - A crossed peer the larger node alone removes, as link-dead does at the
//!   end that stops hearing first after a link flap, closing the connection
//!   the smaller node's link ran on, and then dials again. The smaller node
//!   dialed the link it holds, so it keeps that link at the redial (FRC-2201
//!   Section 5.7 refuses this redial until the old link is declared dead);
//!   after its link-dead reap and its reconnect the pair must end on one
//!   working session, one end holding the link `Outbound` and the other
//!   `Inbound`. These and the next are the counterparts of master's tests of
//!   its redialed TCP link, which master answers at the msg1 as the peer's
//!   rekey.
//! - A peer the larger node dialed, which the smaller node alone removes and
//!   redials, after which the larger node dials again: the pair must end on
//!   one working session on the smaller node's dial.
//! - After the crossing the larger node settles at the peer's msg3 and the
//!   smaller at its own msg2 (the mixed schedule of `crossing.rs`), the
//!   smaller node's redial over a dropped connection must leave the pair on
//!   one working session, the smaller node holding the link `Outbound` and
//!   the larger `Inbound`.
//!
//! Every test here fails today, at one cause: a crossing the larger node
//! settles at the peer's msg3 moves it onto the inbound leg's session and
//! connection but leaves it held on the link record of the link it dialed,
//! so it lists the link `Outbound` beside the smaller node's `Outbound`.
//! Each is a known defect until the msg3 crossing is rewritten.
//!
//! Each test is run once per setting of `node.path.enabled`: a test's plain
//! name runs multipath off, and its `_with_multipath_on` sibling runs it on,
//! as two tests and not one loop, since a pin that fails in a loop's first
//! pass would never reach the second. Setup checks are marked
//! `precondition:`; the assertion of the behaviour is marked `defect:`.

use super::super::spanning_tree::{TestNode, cleanup_nodes, process_available_packets};
use super::super::*;
use super::{
    AGED, crossed_tcp, heartbeat_reaches, pool, pump, received, resolve_connect, settled, tcp_dial,
    tcp_pair,
};
use crate::proto::link::LinkMessageType;
use fips_core::proto::settle::output::Why;

/// The direction `nodes[at]`'s link to `nodes[of]` was set up in, `None`
/// when it does not hold `of` or holds no record of that link.
fn direction(nodes: &[TestNode], at: usize, of: usize) -> Option<LinkDirection> {
    let peer = *nodes[of].node.node_addr();
    let link = nodes[at].node.get_peer(&peer)?.link_id();
    nodes[at].node.links.get(&link).map(|k| k.direction())
}

/// The directions (smaller, larger) hold their links to each other in.
fn directions(
    nodes: &[TestNode],
    s: usize,
    l: usize,
) -> (Option<LinkDirection>, Option<LinkDirection>) {
    (direction(nodes, s, l), direction(nodes, l, s))
}

/// What the pair must hold: the smaller node `Outbound`, the larger
/// `Inbound`.
const SMALLER_DIALED: (Option<LinkDirection>, Option<LinkDirection>) =
    (Some(LinkDirection::Outbound), Some(LinkDirection::Inbound));

// ---------------------------------------------------------------------------
// Crossed TCP dials
// ---------------------------------------------------------------------------

/// Crossed TCP dials leave the smaller node holding the link `Outbound` and
/// the larger `Inbound`, on one working session.
async fn crossed(on: bool, zero_smaller: bool) {
    let (mut nodes, s, l) = crossed_tcp(on, zero_smaller).await;
    let works = settled(&mut nodes, s, l).await;
    let held = directions(&nodes, s, l);
    cleanup_nodes(&mut nodes).await;
    works.expect("precondition: the crossed dials leave one working session");
    assert_eq!(
        held, SMALLER_DIALED,
        "defect: after crossed TCP dials the smaller node must hold the link Outbound and the larger Inbound; (smaller, larger) hold {held:?}"
    );
}

#[tokio::test]
#[ignore = "known defect on next: the larger node's msg3 crossing keeps it on the link record of its own dial, so both ends list the link Outbound"]
async fn crossed_tcp_dials_leave_the_smaller_node_outbound_and_the_larger_inbound_smaller_first() {
    crossed(false, true).await;
}

/// [`crossed_tcp_dials_leave_the_smaller_node_outbound_and_the_larger_inbound_smaller_first`] with multipath on.
#[tokio::test]
#[ignore = "known defect on next: the larger node's msg3 crossing keeps it on the link record of its own dial, so both ends list the link Outbound"]
async fn crossed_tcp_dials_leave_the_smaller_node_outbound_and_the_larger_inbound_smaller_first_with_multipath_on()
 {
    crossed(true, true).await;
}

#[tokio::test]
#[ignore = "known defect on next: the larger node's msg3 crossing keeps it on the link record of its own dial, so both ends list the link Outbound"]
async fn crossed_tcp_dials_leave_the_smaller_node_outbound_and_the_larger_inbound_larger_first() {
    crossed(false, false).await;
}

/// [`crossed_tcp_dials_leave_the_smaller_node_outbound_and_the_larger_inbound_larger_first`] with multipath on.
#[tokio::test]
#[ignore = "known defect on next: the larger node's msg3 crossing keeps it on the link record of its own dial, so both ends list the link Outbound"]
async fn crossed_tcp_dials_leave_the_smaller_node_outbound_and_the_larger_inbound_larger_first_with_multipath_on()
 {
    crossed(true, false).await;
}

// ---------------------------------------------------------------------------
// One end alone drops its peer and redials
// ---------------------------------------------------------------------------

/// `nodes[d]` alone removes `nodes[k]`, as link-dead does at the end that
/// stops hearing first after a link flap, closes the connection `k`'s link
/// ran on, and dials `k` again at its listening address; `k` held the link
/// as its dial and still holds `d`. Everything is delivered.
async fn lone(nodes: &mut [TestNode], d: usize, k: usize) {
    heartbeat_reaches(nodes, k, d)
        .await
        .expect("precondition: frames authenticate from the keeper");
    heartbeat_reaches(nodes, d, k)
        .await
        .expect("precondition: frames authenticate from the dropper");
    assert_eq!(
        direction(nodes, k, d),
        Some(LinkDirection::Outbound),
        "precondition: the keeper holds the link as its dial"
    );
    let d_addr = *nodes[d].node.node_addr();
    let k_addr = *nodes[k].node.node_addr();
    for (at, peer) in [(k, d_addr), (d, k_addr)] {
        nodes[at]
            .node
            .get_peer_mut(&peer)
            .expect("precondition: each end holds the other")
            .test_backdate_session_established(AGED);
    }

    // The removal leaves the keeper's dial connection open, so the test
    // closes it, standing for the chaos run where the keeper's current path
    // ran on a connection the removal did close. After crossed dials this
    // line leaves each node both connections open, so the dropper closes the
    // one it dialed at the keeper's listening address too.
    let (tid, at) = {
        let p = nodes[d]
            .node
            .get_peer(&k_addr)
            .expect("precondition: the dropper holds the keeper");
        (
            p.transport_id()
                .expect("precondition: the peer has a transport"),
            p.current_addr()
                .cloned()
                .expect("precondition: the peer has a current address"),
        )
    };
    nodes[d].node.route_link_dead(k_addr, 0, Why::Dead).await;
    nodes[d].node.drain_closes().await;
    assert!(
        nodes[d].node.get_peer(&k_addr).is_none(),
        "precondition: the dropper removed the keeper"
    );
    let listening = nodes[k].addr.clone();
    for addr in [at, listening] {
        nodes[d]
            .node
            .transports
            .get(&tid)
            .expect("precondition: the dropper's transport is held")
            .close_connection(&addr)
            .await;
    }
    for _ in 0..200 {
        if pool(&nodes[k]) == (0, 0) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        pool(&nodes[k]),
        (0, 0),
        "precondition: the keeper's connection to the dropper closed"
    );
    assert!(
        nodes[k].node.get_peer(&d_addr).is_some(),
        "precondition: the keeper still holds the dropper"
    );

    tcp_dial(nodes, d, k).await;
    resolve_connect(&mut nodes[d]).await;
    pump(nodes).await;
    assert!(
        nodes[d].node.get_peer(&k_addr).is_some(),
        "precondition: the dropper holds the keeper again"
    );
}

/// Crossed dials, then the larger node drops the smaller and redials it.
/// The smaller node dialed the link it holds, so the redial is the case
/// FRC-2201 Section 5.7 refuses until the old link is declared dead, and on
/// this line the smaller node's msg3 crossing keeps its old link by address
/// order: the pair is split until the smaller node's link-dead reap. The
/// test stands for that reap and the smaller node's reconnect, and then the
/// pair must end on one working session, one end holding the link
/// `Outbound` and the other `Inbound`.
async fn lone_drop(on: bool) {
    let (mut nodes, s, l) = crossed_tcp(on, true).await;
    let l_addr = *nodes[l].node.node_addr();
    let old = nodes[s].node.get_peer(&l_addr).map(|p| p.link_id());
    lone(&mut nodes, l, s).await;
    assert_eq!(
        nodes[s].node.get_peer(&l_addr).map(|p| p.link_id()),
        old,
        "precondition: the smaller node keeps the link it dialed at the larger node's redial"
    );
    nodes[s].node.route_link_dead(l_addr, 0, Why::Dead).await;
    nodes[s].node.drain_closes().await;
    assert!(
        nodes[s].node.get_peer(&l_addr).is_none(),
        "precondition: the smaller node's reap removed the larger"
    );
    tcp_dial(&mut nodes, s, l).await;
    resolve_connect(&mut nodes[s]).await;
    pump(&mut nodes).await;
    let works = settled(&mut nodes, s, l).await;
    let held = directions(&nodes, s, l);
    cleanup_nodes(&mut nodes).await;
    let one_each = matches!(
        held,
        (Some(LinkDirection::Outbound), Some(LinkDirection::Inbound))
            | (Some(LinkDirection::Inbound), Some(LinkDirection::Outbound))
    );
    assert!(
        works.is_ok() && one_each,
        "defect: after the larger node's redial and the smaller node's reap the pair must hold one working session, one end Outbound and the other Inbound; (smaller, larger) hold {held:?}, session {works:?}"
    );
}

#[tokio::test]
#[ignore = "known defect on next: the larger node's msg3 crossing keeps it on the link record of its own dial, so both ends list the link Outbound"]
async fn a_crossed_tcp_peer_the_larger_node_alone_drops_and_redials_ends_after_the_smaller_nodes_reap_on_one_session_held_outbound_at_one_end_and_inbound_at_the_other()
 {
    lone_drop(false).await;
}

/// [`a_crossed_tcp_peer_the_larger_node_alone_drops_and_redials_ends_after_the_smaller_nodes_reap_on_one_session_held_outbound_at_one_end_and_inbound_at_the_other`] with multipath on.
#[tokio::test]
#[ignore = "known defect on next: the larger node's msg3 crossing keeps it on the link record of its own dial, so both ends list the link Outbound"]
async fn a_crossed_tcp_peer_the_larger_node_alone_drops_and_redials_ends_after_the_smaller_nodes_reap_on_one_session_held_outbound_at_one_end_and_inbound_at_the_other_with_multipath_on()
 {
    lone_drop(true).await;
}

/// The larger node dials the smaller, which then drops the larger and
/// redials it; then the larger node dials the smaller again. The smaller
/// node's redial is a crossing at the larger node's msg3, which the larger
/// node's inbound wins, so it moves onto the smaller node's dial: the
/// smaller node must hold the link `Outbound` and the larger `Inbound`.
/// The larger node's later dial is then settled by address order, the
/// larger keeping what it holds, so the pair must stay on one working
/// session on the smaller node's dial.
async fn dial_after(on: bool) {
    let mut nodes = tcp_pair(on, true).await;
    let (s, l) = (0, 1);
    tcp_dial(&mut nodes, l, s).await;
    resolve_connect(&mut nodes[l]).await;
    pump(&mut nodes).await;
    lone(&mut nodes, s, l).await;
    let turned = directions(&nodes, s, l);
    let link = nodes[s]
        .node
        .get_peer(nodes[l].node.node_addr())
        .map(|p| p.link_id());
    tcp_dial(&mut nodes, l, s).await;
    resolve_connect(&mut nodes[l]).await;
    pump(&mut nodes).await;
    let works = settled(&mut nodes, s, l).await;
    let held = directions(&nodes, s, l);
    let kept = nodes[s]
        .node
        .get_peer(nodes[l].node.node_addr())
        .map(|p| p.link_id());
    cleanup_nodes(&mut nodes).await;
    let mut bad = Vec::new();
    if turned != SMALLER_DIALED {
        bad.push(format!(
            "after the smaller node's redial (smaller, larger) hold {turned:?}, not the smaller node Outbound and the larger Inbound"
        ));
    }
    if let Err(e) = works {
        bad.push(format!(
            "after the larger node's later dial the pair is not on one working session: {e}"
        ));
    }
    if (held, kept) != (SMALLER_DIALED, link) {
        bad.push(format!(
            "the larger node's later dial moved the pair off the smaller node's dial: (smaller, larger) hold {held:?}, the smaller node's link {kept:?}, was {link:?}"
        ));
    }
    assert!(bad.is_empty(), "defect: {bad:#?}");
}

#[tokio::test]
#[ignore = "known defect on next: the larger node's msg3 crossing keeps it on the link record of its own dial, so both ends list the link Outbound"]
async fn a_peer_the_smaller_node_alone_drops_and_redials_then_the_larger_dials_again_stays_on_one_session_on_the_smaller_nodes_dial()
 {
    dial_after(false).await;
}

/// [`a_peer_the_smaller_node_alone_drops_and_redials_then_the_larger_dials_again_stays_on_one_session_on_the_smaller_nodes_dial`] with multipath on.
#[tokio::test]
#[ignore = "known defect on next: the larger node's msg3 crossing keeps it on the link record of its own dial, so both ends list the link Outbound"]
async fn a_peer_the_smaller_node_alone_drops_and_redials_then_the_larger_dials_again_stays_on_one_session_on_the_smaller_nodes_dial_with_multipath_on()
 {
    dial_after(true).await;
}

// ---------------------------------------------------------------------------
// The smaller node's redial after a mixed-schedule crossing
// ---------------------------------------------------------------------------

/// Close the smaller node's connection to the larger and send from the
/// smaller node until a frame reaches the larger, about 3 s at most: the
/// send redials the dropped connection.
async fn redial_after_drop(nodes: &mut [TestNode], s: usize, l: usize) {
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
            break;
        }
    }
    pump(nodes).await;
}

/// The mixed-schedule crossing of `crossing.rs`, then the smaller node's
/// redial over its dropped connection: the pair must end on one working
/// session, the smaller node holding the link `Outbound` and the larger
/// `Inbound`.
async fn mixed_redial(on: bool, zero_smaller: bool) {
    let (mut nodes, s, l) = super::crossing::moved_at_msg2_over_tcp(on, zero_smaller).await;
    pump(&mut nodes).await;
    redial_after_drop(&mut nodes, s, l).await;
    let works = settled(&mut nodes, s, l).await;
    let held = directions(&nodes, s, l);
    cleanup_nodes(&mut nodes).await;
    assert!(
        works.is_ok() && held == SMALLER_DIALED,
        "defect: after the smaller node's redial the pair must hold one working session, the smaller node Outbound and the larger Inbound; (smaller, larger) hold {held:?}, session {works:?}"
    );
}

#[tokio::test]
#[ignore = "known defect on next: the larger node's msg3 crossing keeps it on the link record of its own dial, so both ends list the link Outbound"]
async fn the_smaller_nodes_redial_after_a_mixed_schedule_crossing_ends_on_one_session_held_outbound_by_the_smaller_node_smaller_first()
 {
    mixed_redial(false, true).await;
}

/// [`the_smaller_nodes_redial_after_a_mixed_schedule_crossing_ends_on_one_session_held_outbound_by_the_smaller_node_smaller_first`] with multipath on.
#[tokio::test]
#[ignore = "known defect on next: the larger node's msg3 crossing keeps it on the link record of its own dial, so both ends list the link Outbound"]
async fn the_smaller_nodes_redial_after_a_mixed_schedule_crossing_ends_on_one_session_held_outbound_by_the_smaller_node_smaller_first_with_multipath_on()
 {
    mixed_redial(true, true).await;
}

#[tokio::test]
#[ignore = "known defect on next: the larger node's msg3 crossing keeps it on the link record of its own dial, so both ends list the link Outbound"]
async fn the_smaller_nodes_redial_after_a_mixed_schedule_crossing_ends_on_one_session_held_outbound_by_the_smaller_node_larger_first()
 {
    mixed_redial(false, false).await;
}

/// [`the_smaller_nodes_redial_after_a_mixed_schedule_crossing_ends_on_one_session_held_outbound_by_the_smaller_node_larger_first`] with multipath on.
#[tokio::test]
#[ignore = "known defect on next: the larger node's msg3 crossing keeps it on the link record of its own dial, so both ends list the link Outbound"]
async fn the_smaller_nodes_redial_after_a_mixed_schedule_crossing_ends_on_one_session_held_outbound_by_the_smaller_node_larger_first_with_multipath_on()
 {
    mixed_redial(true, false).await;
}
