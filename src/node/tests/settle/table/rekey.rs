//! Cells at a rekey: the initiator's and the responder's cutover, and a
//! restart found at a rekey, each test a plain one and its
//! `_with_multipath_on` sibling.
//!
//! Every test runs on a loopback pair with rekey on, built with multipath set
//! as the test states. With multipath on the dialler also holds a second
//! path to its peer, on a second transport, and holds the peer as capable,
//! so the operator can pin the link. A cutover is read across the one step
//! that makes it: the initiator's tick that cuts over to its pending
//! session, or the responder's handling of the first frame on the new
//! session. A restart found at a rekey is reported in the same step as the
//! cutover that found it, after it, so its test reads across that step and
//! holds each row against both cells in turn ([`assert_pair_cells`]): what
//! the cutover resets and the restart keeps is changed over the step.
//!
//! The BLE mark is not read here: these sites run on loopback, where it has
//! no state (`src/node/tests/settle/table/README.md`, its coverage gap).

use super::*;
use crate::node::tests::paths::{capable_at, second_transport, state_at, t2};
use crate::node::tests::rekey_parity::{
    age_link, cutover, deliver, heartbeat, linked_pair, pump, rekey_config, rekey_to_pending,
    trigger_age,
};
use crate::node::tests::spanning_tree::restarted_node;
use crate::peer::PathState;
use crate::proto::fmp::wire::{CommonPrefix, PHASE_ESTABLISHED, PHASE_MSG2};

/// The rekey interval of both ends, the one `trigger_age` ages a link past.
const REKEY_AFTER_SECS: u64 = 60;

/// A node configuration with rekey on and multipath set as `on`.
fn config(on: bool) -> Config {
    super::super::with_path(rekey_config(REKEY_AFTER_SECS), on)
}

/// Two loopback nodes with rekey on and multipath set as `on`, node 0 having
/// dialled node 1 and each holding the other. With multipath on, node 0 also
/// holds a Live path to node 1 on a second transport and holds node 1 as
/// capable.
async fn rekeying_pair(on: bool) -> Vec<TestNode> {
    let mut nodes = linked_pair(config(on), config(on)).await;
    if on {
        second_transport(&mut nodes[0], t2(), 1280);
        let b2 = second_transport(&mut nodes[1], t2(), 1280);
        let b = *nodes[1].node.node_addr();
        nodes[0].node.offer_path(&b, t2(), b2.clone()).await;
        pump(&mut nodes).await;
        let (t1, b1) = (nodes[0].transport_id, nodes[1].addr.clone());
        assert_eq!(
            (
                state_at(&nodes[0], &b, t1, &b1),
                state_at(&nodes[0], &b, t2(), &b2),
                capable_at(&nodes[0], &b)
            ),
            (Some(PathState::Live), Some(PathState::Live), true),
            "precondition: node 0 holds two Live paths to node 1, which it holds as capable"
        );
    }
    nodes
}

/// Leave the spin bit of `peer`'s link MMP on `node` set. A restart of the
/// spin state clears it, so a reset reads as a change only from a set bit,
/// and [`dirty`] flips the bit from whatever the peering left. Written as
/// [`dirty`] writes it, through a received frame's bit at a counter past
/// any of the session's.
fn set_spin(node: &mut Node, peer: &NodeAddr) {
    let m = node
        .get_peer_mut(peer)
        .and_then(ActivePeer::mmp_mut)
        .expect("precondition: the peer runs link MMP");
    if !m.spin_bit.tx_bit() {
        let bit = m.spin_bit.tx_bit();
        let seen = if m.spin_bit.is_initiator() { bit } else { !bit };
        m.spin_bit.rx_observe(seen, 1 << 41, crate::time::mono_ms());
    }
    assert!(m.spin_bit.tx_bit(), "precondition: the spin bit is set");
}

/// Count a failed frame on every path of `peer`'s link on `node` that
/// counts one, beyond the one [`dirty`] counts on the active path.
fn charge_every_path(node: &mut Node, peer: &NodeAddr) {
    let p = node
        .get_peer_mut(peer)
        .expect("precondition: the node holds the peer");
    let pairs: Vec<(TransportId, TransportAddr)> = p
        .bundle()
        .map(|b| {
            b.paths()
                .paths()
                .iter()
                .map(|path| (path.transport_id(), path.addr().clone()))
                .collect()
        })
        .unwrap_or_default();
    for (t, addr) in pairs {
        p.charge(crate::peer::peer_now(), t, &addr);
    }
}

/// Each of `peer`'s paths on `node`, by pair, with its failure count.
fn path_fails(node: &Node, peer: &NodeAddr) -> Vec<(TransportId, TransportAddr, u32)> {
    node.get_peer(peer)
        .and_then(ActivePeer::bundle)
        .map(|b| {
            b.paths()
                .paths()
                .iter()
                .map(|path| {
                    (
                        path.transport_id(),
                        path.addr().clone(),
                        path.live().fails(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Hold the tree announce a restart sends `peer` on `node` behind the rate
/// limit: stamp it as sent now, under an interval of an hour. An announce
/// that goes writes the stamp and clears the pending mark, as any send does,
/// and [`dirty`]'s stamp is an early instant of the process's clock, so
/// without this whether the limit holds the restart's announce would turn on
/// how long the test process had run. Held, the record's tree cells read as
/// the table states them.
fn hold_announce(node: &mut Node, peer: &NodeAddr) {
    let p = node
        .get_peer_mut(peer)
        .expect("precondition: the node holds the peer");
    p.set_tree_announce_min_interval_ms(3_600_000);
    p.set_last_tree_announce_sent_ms(Some(crate::time::mono_ms()));
}

/// Hold every row of `before` and `after`, read across one step that made
/// `first` and then `then`, against both cells. A row is changed over the
/// step if either cell changes it and neither turns on the script; kept if
/// both keep it; and otherwise stated by the test in `others`, which may
/// name no other row. A row read on neither side is not checked. Fails at
/// `defect:` on a breach, and at `precondition:` on a cause no site reaches
/// or on `others` that does not match the table.
fn assert_pair_cells(
    before: &Seen,
    after: &Seen,
    first: &Transition,
    then: &Transition,
    others: &[(Row, Outcome)],
) {
    let mut breaches = Vec::new();
    for row in Row::all() {
        let cells = (cell(row, first), cell(row, then));
        let stated = others.iter().find(|(r, _)| *r == row).map(|(_, o)| *o);
        let want = match ((expect(cells.0), expect(cells.1)), stated) {
            ((Expect::NoSite, _) | (_, Expect::NoSite), _) => panic!(
                "precondition: no site reaches {first:?} then {then:?}, so they have no cells at {row:?}"
            ),
            ((Expect::Stated, _) | (_, Expect::Stated), Some(o)) => o,
            ((Expect::Stated, _) | (_, Expect::Stated), None) => panic!(
                "precondition: {row:?} at {first:?} then {then:?} is {cells:?}, which turns on the test's script; the test states it"
            ),
            (_, Some(_)) => panic!(
                "precondition: {row:?} at {first:?} then {then:?} is {cells:?}, which the table decides; the test may not state it"
            ),
            ((Expect::Changed, _) | (_, Expect::Changed), None) => Outcome::Changed,
            ((Expect::Kept, Expect::Kept), None) => Outcome::Kept,
        };
        let (b, a) = (before.get(row), after.get(row));
        if b.is_none() && a.is_none() {
            continue;
        }
        let got = if b == a {
            Outcome::Kept
        } else {
            Outcome::Changed
        };
        if got != want {
            breaches.push(format!(
                "{row:?} at {first:?} then {then:?} is {cells:?}, so {want:?}, but {got:?}: before {b:?}, after {a:?}"
            ));
        }
    }
    assert!(
        breaches.is_empty(),
        "defect: the step does not do what the table says: {breaches:#?}"
    );
}

/// Node 0 starts a rekey of its link to node 1, node 1 answers it, and node
/// 0 cuts over on its next tick. Read at node 0 across that tick.
async fn an_initiators_cutover(on: bool) {
    let mut nodes = rekeying_pair(on).await;
    let b = *nodes[1].node.node_addr();
    age_link(&mut nodes, 0, 1, trigger_age());
    rekey_to_pending(&mut nodes, 0, 1).await;
    dirty(&mut nodes[0].node, &b).await;
    set_spin(&mut nodes[0].node, &b);
    let before = Seen::of(&nodes[0].node, &b, &[]).await;
    cutover(&mut nodes[0], &b).await;
    let after = Seen::of(&nodes[0].node, &b, &[]).await;
    cleanup_nodes(&mut nodes).await;
    let t = Transition::Cutover {
        role: Role::Initiator,
    };
    assert_cells(
        &before,
        &after,
        &t,
        &[(Row::RekeyMachine, Outcome::Changed)],
    );
}

/// The rekey initiator's cutover, multipath off, against the table.
#[tokio::test]
async fn an_initiators_cutover_does_what_its_cells_say() {
    an_initiators_cutover(false).await;
}

/// [`an_initiators_cutover_does_what_its_cells_say`] with multipath on, on a
/// capable link of two paths.
#[tokio::test]
async fn an_initiators_cutover_does_what_its_cells_say_with_multipath_on() {
    an_initiators_cutover(true).await;
}

/// Node 0 rekeys its link to node 1 and cuts over; node 1, the responder,
/// cuts over when node 0's first frame on the new session reaches it. Read
/// at node 1 across the handling of that frame. The responder marks its
/// filter to be sent again, since the msg1 it answered may have been a
/// redial from a peer that dropped it, and its rekey machine files that
/// msg1's ephemeral in its record as the pending ends.
///
/// The frame authenticates, which clears the failure count of the path it
/// came on whatever the cutover does, so that row is held here path by
/// path: the frame's path cleared and every other path's count kept, a
/// failed frame having been counted on each path that counts one. The
/// initiator's cutover holds the same cell with no frame.
async fn a_responders_cutover(on: bool) {
    let mut nodes = rekeying_pair(on).await;
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    age_link(&mut nodes, 0, 1, trigger_age());
    let pending = rekey_to_pending(&mut nodes, 0, 1).await;
    cutover(&mut nodes[0], &b).await;
    dirty(&mut nodes[1].node, &a).await;
    set_spin(&mut nodes[1].node, &a);
    charge_every_path(&mut nodes[1].node, &a);
    let framed = nodes[1].node.get_peer(&a).and_then(|p| {
        let t = p.transport_id()?;
        Some((t, p.current_addr()?.clone()))
    });
    let fails_before = path_fails(&nodes[1].node, &a);
    let before = Seen::of(&nodes[1].node, &a, &[]).await;
    heartbeat(&mut nodes[0], &b).await;
    deliver(&mut nodes[1]).await;
    let after = Seen::of(&nodes[1].node, &a, &[]).await;
    let fails_after = path_fails(&nodes[1].node, &a);
    let ours = nodes[1].node.get_peer(&a).and_then(ActivePeer::our_index);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        ours,
        Some(pending),
        "precondition: the responder cut over to the pending session the frame named"
    );
    let framed = framed.expect("precondition: the responder holds an active path");
    assert!(
        fails_before
            .iter()
            .any(|(t, addr, n)| (*t, addr) == (framed.0, &framed.1) && *n > 0),
        "precondition: a failed frame is counted on the path the frame comes on: {fails_before:?}"
    );
    let kept: Vec<(TransportId, TransportAddr, u32)> = fails_before
        .into_iter()
        .map(|(t, addr, n)| {
            let n = if (t, &addr) == (framed.0, &framed.1) {
                0
            } else {
                n
            };
            (t, addr, n)
        })
        .collect();
    assert_eq!(
        fails_after, kept,
        "defect: the responder's cutover changes a failure count other than the authenticated frame's own path's"
    );
    let t = Transition::Cutover {
        role: Role::Responder,
    };
    let checked = check_cells(
        &before,
        &after,
        &t,
        &[
            (Row::RekeyMachine, Outcome::Changed),
            (Row::SetupRecord, Outcome::Changed),
            (Row::FilterSend, Outcome::Changed),
        ],
    );
    let breaches: Vec<&String> = checked
        .breaches
        .iter()
        .filter(|b| !b.starts_with("PathFailures "))
        .collect();
    assert!(
        breaches.is_empty(),
        "defect: the site does not do what the table says: {breaches:#?}"
    );
}

/// The rekey responder's cutover, multipath off, against the table.
#[tokio::test]
async fn a_responders_cutover_does_what_its_cells_say() {
    a_responders_cutover(false).await;
}

/// [`a_responders_cutover_does_what_its_cells_say`] with multipath on, on a
/// capable link of two paths.
#[tokio::test]
async fn a_responders_cutover_does_what_its_cells_say_with_multipath_on() {
    a_responders_cutover(true).await;
}

/// Restart node 1 of `nodes`, with multipath set as `on`, and let node 0's
/// rekey msg1 reach it: the restarted node promotes it as a fresh link, and
/// node 0 completes the restarted node's msg2 as a rekey, sees its new
/// startup epoch and holds an initiator pending. What the restarted node
/// sent after its msg2 is dropped. This is `rekey_parity::reveal_restart`
/// with the restarted node built at the test's setting.
async fn reveal(nodes: &mut [TestNode], on: bool) {
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    let restarted = restarted_node(&nodes[1], config(on));
    drop(std::mem::replace(&mut nodes[1], restarted));
    nodes[0]
        .node
        .get_peer_mut(&b)
        .expect("precondition: node 0 holds node 1")
        .test_backdate_session_established(trigger_age());
    nodes[0].node.poll_link_rekeys().await;
    assert_eq!(
        deliver(&mut nodes[1]).await,
        1,
        "precondition: only node 0's rekey msg1 is queued at the restarted node"
    );
    assert!(
        nodes[1].node.get_peer(&a).is_some(),
        "precondition: the restarted node promoted the msg1 as a fresh link"
    );
    let queued: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok()).collect();
    let phases: Vec<Option<u8>> = queued
        .iter()
        .map(|p| CommonPrefix::parse(&p.data).map(|c| c.phase))
        .collect();
    let mut msg2 = None;
    for (packet, phase) in queued.into_iter().zip(&phases) {
        match *phase {
            Some(PHASE_MSG2) if msg2.is_none() => msg2 = Some(packet),
            Some(PHASE_ESTABLISHED) => {}
            _ => panic!("precondition: node 0 has queued one msg2 and frames: {phases:?}"),
        }
    }
    nodes[0]
        .node
        .handle_msg2(msg2.expect("precondition: the restarted node's msg2 is queued"))
        .await;
    let peer = nodes[0]
        .node
        .get_peer(&b)
        .expect("precondition: node 0 still holds node 1");
    assert_eq!(
        (peer.pending_role(), peer.remote_epoch()),
        (Some(Role::Initiator), Some(nodes[1].node.startup_epoch())),
        "precondition: node 0 holds an initiator pending and the restarted node's epoch"
    );
}

/// Node 1 restarts, node 0's rekey reveals it, and node 0's next tick cuts
/// over and reports the restart in the same step. Read at node 0 across that
/// tick. With multipath on node 0 holds the operator's pin on the capable
/// link, and the restart ends it. With multipath off the operator cannot
/// pin, so the pin [`dirty`] planted is lifted first, and the restart's
/// unpin steps a bundle that holds none.
async fn a_restart_at_a_rekey(on: bool) {
    let mut nodes = rekeying_pair(on).await;
    let b = *nodes[1].node.node_addr();
    reveal(&mut nodes, on).await;
    dirty(&mut nodes[0].node, &b).await;
    set_spin(&mut nodes[0].node, &b);
    hold_announce(&mut nodes[0].node, &b);
    let npub = nodes[1].node.npub();
    let pinned = nodes[0].node.pin_path(&npub, "1", None).await;
    if on {
        assert!(
            pinned.is_ok(),
            "precondition: the operator pins the capable link: {pinned:?}"
        );
    } else {
        assert!(
            pinned.is_err(),
            "precondition: with multipath off the operator cannot pin: {pinned:?}"
        );
        nodes[0]
            .node
            .step_path(&b, fips_core::proto::path::Input::Unpin)
            .await;
    }
    let held = nodes[0]
        .node
        .get_peer(&b)
        .and_then(|p| p.bundle()?.pin().cloned());
    let before = Seen::of(&nodes[0].node, &b, &[]).await;
    cutover(&mut nodes[0], &b).await;
    let after = Seen::of(&nodes[0].node, &b, &[]).await;
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        held.is_some(),
        on,
        "precondition: a pin is held before the restart exactly when multipath is on: {held:?}"
    );
    let pin_outcome = if on { Outcome::Changed } else { Outcome::Kept };
    assert_pair_cells(
        &before,
        &after,
        &Transition::Cutover {
            role: Role::Initiator,
        },
        &Transition::Restarted,
        &[
            (Row::RekeyMachine, Outcome::Changed),
            (Row::Pin, pin_outcome),
            (Row::PathMtu, Outcome::Changed),
            (Row::FilterSend, Outcome::Changed),
            (Row::Tree, Outcome::Changed),
        ],
    );
}

/// A restart found at a rekey, multipath off, against the table.
#[tokio::test]
async fn a_restart_found_at_a_rekey_does_what_its_cells_say() {
    a_restart_at_a_rekey(false).await;
}

/// [`a_restart_found_at_a_rekey_does_what_its_cells_say`] with multipath on,
/// where the restart ends the operator's pin on the capable link.
#[tokio::test]
async fn a_restart_found_at_a_rekey_does_what_its_cells_say_with_multipath_on() {
    a_restart_at_a_rekey(true).await;
}
