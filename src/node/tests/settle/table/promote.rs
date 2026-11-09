//! Cells at promotion: a peer installed for an identity not held, by a msg2
//! this node initiated or by a msg1 it answered, at the initiator and at the
//! responder, each test a plain one and its `_with_multipath_on` sibling.
//!
//! Before a promotion the peer is not held, so its record reads `no peer` and
//! every row the record or the bundle holds changes. What the node holds per
//! peer is written first through [`dirty`], which reaches those rows with no
//! peer held, so a row the promotion keeps is held to a value it could have
//! changed. Each test reads the node at the site alone: the frames that follow
//! a promotion are not a transition, and the first of them clears the silent
//! note and marks the responder's BLE link.

use super::super::super::spanning_tree::{TestNode, cleanup_nodes, initiate_handshake};
use super::super::super::*;
use super::super::loopback_node;
use super::{Outcome, Seen, assert_cells, dirty};
use crate::node::settle::table::{Row, Transition};
use fips_core::proto::path::PathRef;

/// The first packet queued at `tn` in `phase`, taking every packet before it.
pub(super) fn queued_in(tn: &mut TestNode, phase: u8) -> Option<ReceivedPacket> {
    std::iter::from_fn(|| tn.packet_rx.try_recv().ok()).find(|p| {
        crate::proto::fmp::wire::CommonPrefix::parse(&p.data).is_some_and(|c| c.phase == phase)
    })
}

/// The outcomes of the cells at a promotion that turn on the script, at the
/// initiator when `initiator`, with multipath set as `on`.
fn others(initiator: bool, on: bool) -> Vec<(Row, Outcome)> {
    let changed_if = |c| if c { Outcome::Changed } else { Outcome::Kept };
    let mut others = vec![
        // The link, its paths, its machines and its setup record are the
        // new peer's where none was held.
        (Row::Link, Outcome::Changed),
        // The dial's link already held its entry, which carries over; the
        // responder opens one at the msg1's source.
        (Row::Index, changed_if(!initiator)),
        (Row::Paths, Outcome::Changed),
        (Row::Capability, Outcome::Changed),
        (Row::RekeyMachine, Outcome::Changed),
        (Row::SetupRecord, Outcome::Changed),
        (Row::Identity, Outcome::Changed),
        // The dial's machine survives as the peer's, at the same link.
        (Row::ControlMachine, changed_if(!initiator)),
        // The initiator marks its link; the responder's is marked by the
        // initiator's first frame, after the site.
        (Row::BleMark, changed_if(initiator)),
        // The entry [`dirty`] wrote is tighter than the link and seeded from
        // the same transport, so the seed keeps it: it never loosens within
        // a link.
        (Row::PathMtu, Outcome::Kept),
        (Row::FilterSend, Outcome::Changed),
        (Row::Tree, Outcome::Changed),
        (Row::IdentityCache, Outcome::Changed),
        (Row::LookupBackoff, Outcome::Changed),
        // Forgotten and offered with multipath on; with it off the intake
        // returns at once.
        (Row::PathListings, changed_if(on)),
        // [`dirty`] filed its record at an epoch other than the peer's, so
        // the promotion takes nothing.
        (Row::Records, Outcome::Kept),
    ];
    if initiator {
        // The answered dial is removed.
        others.push((Row::Dials, Outcome::Changed));
    } else {
        // The new peering is not yet heard, so the msg1's ephemeral is
        // noted.
        others.push((Row::Replayed, Outcome::Changed));
    }
    others
}

/// Node 0 dials node 1 with multipath set as `on`, the promoting node's state
/// for the other dirtied first; node 1 answers. Promote at node 0 on the
/// msg2, or at node 1 on the msg1, as `initiator` picks, and hold every row
/// at that node against the table.
async fn promotion(initiator: bool, on: bool) {
    let mut nodes = vec![loopback_node(on).await, loopback_node(on).await];
    let (at, of) = if initiator { (0, 1) } else { (1, 0) };
    let peer = *nodes[of].node.node_addr();
    dirty(&mut nodes[at].node, &peer).await;
    initiate_handshake(&mut nodes, 0, 1).await;
    let dial = *nodes[0]
        .node
        .pending_outbound
        .values()
        .next()
        .expect("precondition: node 0's dial is pending");
    let msg1 = queued_in(&mut nodes[1], crate::proto::fmp::wire::PHASE_MSG1)
        .expect("precondition: node 0's msg1 is queued at node 1");
    let also = [PathRef {
        transport: nodes[at].transport_id,
        addr: nodes[of].addr.clone(),
    }];
    let (before, after) = if initiator {
        nodes[1].node.handle_msg1(msg1).await;
        let msg2 = queued_in(&mut nodes[0], crate::proto::fmp::wire::PHASE_MSG2)
            .expect("precondition: node 1's msg2 is queued at node 0");
        let before = Seen::of(&nodes[0].node, &peer, &also).await;
        nodes[0].node.handle_msg2(msg2).await;
        (before, Seen::of(&nodes[0].node, &peer, &also).await)
    } else {
        let before = Seen::of(&nodes[1].node, &peer, &also).await;
        nodes[1].node.handle_msg1(msg1).await;
        (before, Seen::of(&nodes[1].node, &peer, &also).await)
    };
    let promoted = nodes[at].node.get_peer(&peer).map(|p| p.link_id());
    cleanup_nodes(&mut nodes).await;
    let link = promoted.unwrap_or_else(|| panic!("precondition: node {at} promoted node {of}"));
    if initiator {
        assert_eq!(link, dial, "precondition: the dial's link is the peer's");
    }
    let t = Transition::Promote { link, initiator };
    assert_cells(&before, &after, &t, &others(initiator, on));
}

/// A promotion on the msg2 of this node's own dial does what the table says
/// to every row, with multipath off.
#[tokio::test]
async fn a_promotion_at_the_initiator_does_what_the_table_says() {
    promotion(true, false).await;
}

/// [`a_promotion_at_the_initiator_does_what_the_table_says`] with multipath
/// on.
#[tokio::test]
async fn a_promotion_at_the_initiator_does_what_the_table_says_with_multipath_on() {
    promotion(true, true).await;
}

/// A promotion on a msg1 this node answered does what the table says to
/// every row, with multipath off.
#[tokio::test]
async fn a_promotion_at_the_responder_does_what_the_table_says() {
    promotion(false, false).await;
}

/// [`a_promotion_at_the_responder_does_what_the_table_says`] with multipath
/// on.
#[tokio::test]
async fn a_promotion_at_the_responder_does_what_the_table_says_with_multipath_on() {
    promotion(false, true).await;
}

/// The next packet queued at `tn`, waiting up to 2 s for the BLE mock's
/// background tasks to deliver it.
#[cfg(ble_available)]
pub(super) async fn next_packet(tn: &mut TestNode) -> ReceivedPacket {
    tokio::time::timeout(Duration::from_secs(2), tn.packet_rx.recv())
        .await
        .expect("precondition: a packet arrived within 2 s")
        .expect("precondition: the receive channel is open")
}

/// The BLE mark `tn` holds at `addr` on its first transport.
#[cfg(ble_available)]
pub(super) async fn mark_at(tn: &TestNode, addr: &TransportAddr) -> Option<bool> {
    match tn.node.transports.get(&tn.transport_id) {
        Some(crate::transport::TransportHandle::Ble(t)) => t.is_verified(addr).await,
        _ => panic!("precondition: the node's first transport is BLE"),
    }
}

/// Node 0 dials node 1 over a genuine BLE link, multipath set as `on`, each
/// node's state for the other dirtied first. Node 1 promotes on the msg1 and
/// leaves its link unmarked; node 0 promotes on the msg2 and marks its link;
/// node 0's first frame then marks node 1's.
#[cfg(ble_available)]
async fn ble_promotion(on: bool) {
    use super::super::super::ble::{
        base_config, larger_second, link_genuinely, make_test_node_ble_from,
    };
    use super::super::super::crossed_dial::{hand, phase};
    use super::super::with_path;
    use crate::proto::fmp::wire::{PHASE_MSG1, PHASE_MSG2};

    let config = with_path(Config::new(), on);
    let mut nodes = vec![
        make_test_node_ble_from(1, base_config(), config.clone()).await,
        make_test_node_ble_from(2, base_config(), config).await,
    ];
    larger_second(&mut nodes);
    let _bank = link_genuinely(&nodes).await;
    let (a, b) = (*nodes[0].node.node_addr(), *nodes[1].node.node_addr());
    dirty(&mut nodes[0].node, &b).await;
    dirty(&mut nodes[1].node, &a).await;
    // Both ends key the link at node 1's address.
    let link = nodes[1].addr.clone();
    let at = |tn: &TestNode| {
        [PathRef {
            transport: tn.transport_id,
            addr: link.clone(),
        }]
    };
    initiate_handshake(&mut nodes, 0, 1).await;
    let msg1 = next_packet(&mut nodes[1]).await;
    assert_eq!(
        phase(&msg1),
        Some(PHASE_MSG1),
        "precondition: node 0's msg1 reaches node 1 first"
    );
    let before_r = Seen::of(&nodes[1].node, &a, &at(&nodes[1])).await;
    let unmarked_r = mark_at(&nodes[1], &link).await;
    hand(&mut nodes[1].node, msg1).await;
    let after_r = Seen::of(&nodes[1].node, &a, &at(&nodes[1])).await;
    let promoted_r = nodes[1].node.get_peer(&a).map(|p| p.link_id());
    let msg2 = next_packet(&mut nodes[0]).await;
    assert_eq!(
        phase(&msg2),
        Some(PHASE_MSG2),
        "precondition: node 1's msg2 reaches node 0 first"
    );
    let dial = nodes[0].node.pending_outbound.values().next().copied();
    let before_i = Seen::of(&nodes[0].node, &b, &at(&nodes[0])).await;
    let unmarked_i = mark_at(&nodes[0], &link).await;
    hand(&mut nodes[0].node, msg2).await;
    let after_i = Seen::of(&nodes[0].node, &b, &at(&nodes[0])).await;
    let promoted_i = nodes[0].node.get_peer(&b).map(|p| p.link_id());
    let unmarked_r_still = mark_at(&nodes[1], &link).await;
    let sent = nodes[0]
        .node
        .send_encrypted_link_message(
            &b,
            &[crate::proto::link::LinkMessageType::Heartbeat.to_byte()],
        )
        .await;
    let frame = next_packet(&mut nodes[1]).await;
    hand(&mut nodes[1].node, frame).await;
    let marked_r = mark_at(&nodes[1], &link).await;
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        (unmarked_r, unmarked_i),
        (Some(false), Some(false)),
        "precondition: the link is pooled and not yet marked at either end"
    );
    let (Some(link_r), Some(link_i)) = (promoted_r, promoted_i) else {
        panic!("precondition: each node promoted the other: {promoted_r:?}, {promoted_i:?}");
    };
    assert_eq!(
        dial,
        Some(link_i),
        "precondition: the dial's link is node 0's peer's"
    );
    assert!(
        sent.is_ok(),
        "precondition: node 0's first frame is sent: {sent:?}"
    );
    let initiator = Transition::Promote {
        link: link_i,
        initiator: true,
    };
    assert_cells(&before_i, &after_i, &initiator, &others(true, on));
    let responder = Transition::Promote {
        link: link_r,
        initiator: false,
    };
    assert_cells(&before_r, &after_r, &responder, &others(false, on));
    assert_eq!(
        (unmarked_r_still, marked_r),
        (Some(false), Some(true)),
        "defect: the responder's link is not marked by the initiator's first frame alone"
    );
}

/// On a BLE link, with multipath off, the initiator's promotion marks its
/// link and the responder's leaves its own unmarked until the initiator's
/// first frame, every other row as the table says at each end.
#[cfg(ble_available)]
#[tokio::test]
async fn a_promotion_on_a_ble_link_marks_it_at_the_initiator_and_at_the_responders_first_frame() {
    ble_promotion(false).await;
}

/// [`a_promotion_on_a_ble_link_marks_it_at_the_initiator_and_at_the_responders_first_frame`]
/// with multipath on.
#[cfg(ble_available)]
#[tokio::test]
async fn a_promotion_on_a_ble_link_marks_it_at_the_initiator_and_at_the_responders_first_frame_with_multipath_on()
 {
    ble_promotion(true).await;
}
