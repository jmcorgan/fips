//! A captured msg1 of a held peer, replayed to the node from an address the
//! replayer chose, against the redial that answers a fresh msg1 off the
//! peer's established link.
//!
//! The capture is a genuine msg1 of the peer's identity and startup epoch,
//! built and then dropped with its handshake state, so no frame can ever
//! follow it: what a replayer holds. It is handed to B from a tap address,
//! which records what B sends there. The pair is the one of `roam_redial`:
//! two loopback nodes on a frozen clock, every receive-loop timer run in its
//! order, A having dialed B.

use super::dialer::Dialer;
use super::establish_chartests::craft_msg1_wire;
use super::roam_redial::{Multipath, OldAddr, Pair, arm_from_tap, phase, since};
use super::spanning_tree::{cleanup_nodes, loopback_tap};
use super::*;
use crate::node::stats::HandshakeStatsSnapshot;
use crate::proto::fmp::wire::{Msg2Header, PHASE_MSG2, build_encrypted, build_established_header};
use tokio::sync::mpsc::UnboundedReceiver;

/// A tap address on B's transport and what reaches it.
struct Tap {
    addr: TransportAddr,
    rx: UnboundedReceiver<ReceivedPacket>,
    /// The msg2s that reached it, in order.
    msg2s: Vec<Vec<u8>>,
}

impl Tap {
    /// A new tap on `pair`'s B.
    fn new(pair: &Pair) -> Tap {
        let (addr, rx) = loopback_tap(pair.nodes[1].transport_id);
        Tap {
            addr,
            rx,
            msg2s: Vec::new(),
        }
    }

    /// Collect what reached the tap since the last call.
    fn gather(&mut self) {
        while let Ok(packet) = self.rx.try_recv() {
            if phase(&packet) == Some(PHASE_MSG2) {
                self.msg2s.push(packet.data);
            }
        }
    }
}

/// A capture of a msg1 of A's identity and epoch to B, sender index `sidx`:
/// genuine, with its handshake state dropped.
fn capture(pair: &Pair, sidx: u32) -> Vec<u8> {
    craft_msg1_wire(
        &pair.nodes[1].node,
        pair.nodes[0].node.identity(),
        pair.nodes[0].node.startup_epoch(),
        SessionIndex::new(sidx),
        Node::now_ms(),
    )
}

/// Hand `data` to B as a msg1 from `from`, then hand over what follows.
async fn replay(pair: &mut Pair, from: &TransportAddr, data: Vec<u8>) {
    let tid = pair.nodes[1].transport_id;
    pair.nodes[1]
        .node
        .process_packet(ReceivedPacket::with_timestamp(
            tid,
            from.clone(),
            data,
            Node::now_ms(),
        ))
        .await;
    pair.pump().await;
}

/// B's handshake counters now.
fn counters(pair: &Pair) -> HandshakeStatsSnapshot {
    pair.nodes[1].node.stats().handshake.snapshot()
}

/// B's link and index for A.
fn b_session(pair: &Pair) -> (LinkId, Option<SessionIndex>) {
    let p = pair.nodes[1]
        .node
        .get_peer(&pair.a_addr())
        .expect("B holds A");
    (p.link_id(), p.our_index())
}

/// A replay against a link `age_secs` old with multipath set as `mp`: one
/// capture from a tap, then 35 s with a heartbeat each way at every step.
/// B answers the capture once, at the tap, into a pending redial; keeps
/// A's link, index and session throughout, with both heartbeats
/// authenticating at every step; replaces nothing and opens no session
/// again; and at the handshake timeout the pending redial is gone: its
/// index back with the allocator, its link and lookup entry removed, and
/// the per-peer maps coherent.
async fn replay_leaves_the_session_and_expires(mp: Multipath, age_secs: u64) {
    replay_expires(mp, age_secs, false).await;
}

/// [`replay_leaves_the_session_and_expires`], with each node's decrypt
/// workers running when `workers`.
async fn replay_expires(mp: Multipath, age_secs: u64, workers: bool) {
    let mut pair = Pair::new(mp, true).await;
    #[cfg(unix)]
    if workers {
        pair.workers_on();
    }
    #[cfg(not(unix))]
    let _ = workers;
    pair.run(age_secs).await;
    let before = b_session(&pair);
    let was = counters(&pair);
    let mut tap = Tap::new(&pair);
    let data = capture(&pair, 0xC0FFEE);
    replay(&mut pair, &tap.addr.clone(), data).await;
    tap.gather();
    let a = pair.a_addr();
    let pending = pair.nodes[1]
        .node
        .redials
        .of(&a)
        .expect("defect: the capture was not answered into a pending redial");
    let armed_at = pair.t;
    let mut gone_at = None;
    for _ in 0..70 {
        pair.step().await;
        tap.gather();
        let both = pair.heartbeat(0, 1).await && pair.heartbeat(1, 0).await;
        assert!(
            both && b_session(&pair) == before,
            "defect: the replay disturbed the peering at {} ms",
            pair.t - armed_at
        );
        if gone_at.is_none() && pair.nodes[1].node.redials.of(&a).is_none() {
            gone_at = Some(pair.t - armed_at);
        }
    }
    let r = since(&counters(&pair), &was);
    let b = &pair.nodes[1].node;
    assert!(
        tap.msg2s.len() == 1
            && r.redials == 1
            && r.redials_proven == 0
            && r.redial_session_reopens == 0
            && gone_at.is_some_and(|t| (29_500..=30_500).contains(&t))
            && !b.index_allocator.is_allocated(pending.index)
            && b.links.get(&pending.link).is_none()
            && !b.links.index().values().any(|link| *link == pending.link)
            && b.peer_machines.get(&pending.link).is_none(),
        "defect: msg2s {} redials {:?} gone at {gone_at:?}",
        tap.msg2s.len(),
        r
    );
    // The audit's own heartbeats are delivered with no decrypt worker's
    // results handed back, so it runs on the pair without workers; with
    // them, the heartbeats of every step above are the check.
    if !workers {
        super::settle::audit::assert_coherent(&mut pair.nodes, "after the replay").await;
    }
    cleanup_nodes(&mut pair.nodes).await;
}

#[tokio::test]
async fn a_replayed_msg1_from_a_spoofed_address_leaves_the_old_session_up_and_delivering_and_its_pending_redial_expires_aged_multipath_off()
 {
    replay_leaves_the_session_and_expires(Multipath::Off, 60).await;
}

#[tokio::test]
async fn a_replayed_msg1_from_a_spoofed_address_leaves_the_old_session_up_and_delivering_and_its_pending_redial_expires_aged_multipath_on()
 {
    replay_leaves_the_session_and_expires(Multipath::On, 60).await;
}

/// The aged case with each node's decrypt workers running, the held
/// session's frames opened on a worker.
#[cfg(unix)]
#[tokio::test]
async fn a_replayed_msg1_from_a_spoofed_address_leaves_the_old_session_up_and_delivering_and_its_pending_redial_expires_with_decrypt_workers()
 {
    replay_expires(Multipath::On, 60, true).await;
}

#[tokio::test]
async fn a_replayed_msg1_from_a_spoofed_address_leaves_the_old_session_up_and_delivering_and_its_pending_redial_expires_young_multipath_off()
 {
    replay_leaves_the_session_and_expires(Multipath::Off, 10).await;
}

#[tokio::test]
async fn a_replayed_msg1_from_a_spoofed_address_leaves_the_old_session_up_and_delivering_and_its_pending_redial_expires_young_multipath_on()
 {
    replay_leaves_the_session_and_expires(Multipath::On, 10).await;
}

/// The same capture sent again 5 s later, from another address, is a copy
/// the held link's record holds: B sends nothing there.
#[tokio::test]
async fn a_replayed_msg1_sent_again_within_15_s_draws_no_second_msg2() {
    let mut pair = Pair::new(Multipath::On, true).await;
    pair.run(60).await;
    let data = capture(&pair, 0xC0FFEE);
    let mut first = Tap::new(&pair);
    replay(&mut pair, &first.addr.clone(), data.clone()).await;
    pair.run(5).await;
    let mut second = Tap::new(&pair);
    replay(&mut pair, &second.addr.clone(), data).await;
    first.gather();
    second.gather();
    assert!(
        first.msg2s.len() == 1 && second.msg2s.is_empty(),
        "defect: first {} second {}",
        first.msg2s.len(),
        second.msg2s.len()
    );
    cleanup_nodes(&mut pair.nodes).await;
}

/// Nine distinct captures, each from its own address 1.5 s after the one
/// before, all inside 15 s: the redial memory answers eight and refuses the
/// ninth.
#[tokio::test]
async fn nine_distinct_replayed_msg1s_within_15_s_draw_at_most_eight_msg2s() {
    let mut pair = Pair::new(Multipath::On, true).await;
    pair.run(60).await;
    let was = counters(&pair);
    let mut taps = Vec::new();
    for n in 0..9u32 {
        let data = capture(&pair, 0xC0FF00 + n);
        let tap = Tap::new(&pair);
        replay(&mut pair, &tap.addr.clone(), data).await;
        taps.push(tap);
        pair.run(1).await;
        pair.step().await;
    }
    let mut msg2s = 0;
    for tap in taps.iter_mut() {
        tap.gather();
        msg2s += tap.msg2s.len();
    }
    let r = since(&counters(&pair), &was);
    assert!(
        msg2s == 8 && r.redials == 8 && r.redial_seen == 1,
        "defect: {msg2s} msg2s, {r:?}"
    );
    cleanup_nodes(&mut pair.nodes).await;
}

/// A capture lands half a second before A's own redial from its new
/// address. A's first msg1 meets the capture's pending redial under 1 s old
/// and is refused; its first resend, a second later, replaces the capture's
/// redial and is answered, and the pair settles on it.
#[tokio::test]
async fn a_genuine_redial_refused_behind_a_capture_is_answered_at_a_later_resend_of_the_same_dial()
{
    let mut pair = Pair::new(Multipath::Off, true).await;
    pair.run(60).await;
    let was = counters(&pair);
    let tid = pair.nodes[0].transport_id;
    pair.nodes[0].node.path_presence(tid, false).await;
    pair.move_a(OldAddr::Blackhole);
    pair.nodes[0].node.path_presence(tid, true).await;
    pair.pump().await;
    // A dials 5 s after the change; the capture lands 0.5 s before.
    for _ in 0..9 {
        pair.step().await;
    }
    let tap = Tap::new(&pair);
    let data = capture(&pair, 0xC0FFEE);
    replay(&mut pair, &tap.addr.clone(), data).await;
    pair.run(10).await;
    let o = pair.outcome().await;
    let r = since(&counters(&pair), &was);
    assert!(
        r.redial_held == 1
            && r.redials == 2
            && r.redials_proven == 1
            && o.settled.is_some_and(|s| (5.5..=6.5).contains(&s))
            && o.works,
        "defect: {r:?} {o:?}"
    );
    cleanup_nodes(&mut pair.nodes).await;
}

/// A frame naming a pending redial's index that does not open under its
/// session, sent from A's own address, where a failure would be charged to
/// A's peering: B counts it, changes nothing, keeps the pending redial, and
/// charges A's peering no decryption failure.
#[tokio::test]
async fn a_frame_that_fails_to_open_under_a_pending_redial_changes_nothing_and_charges_the_held_peer_no_failure()
 {
    let mut pair = Pair::new(Multipath::Off, true).await;
    pair.run(60).await;
    let before = b_session(&pair);
    let tap = Tap::new(&pair);
    let data = capture(&pair, 0xC0FFEE);
    replay(&mut pair, &tap.addr.clone(), data).await;
    let a = pair.a_addr();
    let a_at = pair.nodes[1]
        .node
        .get_peer(&a)
        .and_then(|p| p.current_addr().cloned())
        .expect("precondition: B holds A at an address");
    let pending = pair.nodes[1]
        .node
        .redials
        .of(&a)
        .expect("precondition: armed");
    let unopened = || pair.nodes[1].node.metrics().dataplane.redial_unopened.get();
    let was = unopened();
    let body = [0x5Au8; 48];
    let header = build_established_header(pending.index, 7, 0, (body.len() - 16) as u16);
    let frame = build_encrypted(&header, &body);
    let tid = pair.nodes[1].transport_id;
    for _ in 0..3 {
        pair.nodes[1]
            .node
            .process_packet(ReceivedPacket::with_timestamp(
                tid,
                a_at.clone(),
                frame.clone(),
                Node::now_ms(),
            ))
            .await;
    }
    let failures = pair.nodes[1]
        .node
        .get_peer(&a)
        .map(|p| p.consecutive_decrypt_failures());
    let now = pair.nodes[1].node.metrics().dataplane.redial_unopened.get();
    assert!(
        now - was == 3
            && failures == Some(0)
            && b_session(&pair) == before
            && pair.nodes[1].node.redials.of(&a) == Some(pending),
        "defect: unopened {} failures {failures:?}",
        now - was
    );
    cleanup_nodes(&mut pair.nodes).await;
}

/// A second distinct capture from the address of a pending redial whose
/// msg2 was sent is read and classified, and answered with its own msg2,
/// not the first capture's stored one.
#[tokio::test]
async fn a_fresh_msg1_from_the_address_of_a_sent_unpromoted_leg_is_classified_not_answered_with_its_stored_msg2()
 {
    let mut pair = Pair::new(Multipath::Off, true).await;
    pair.run(60).await;
    let mut tap = Tap::new(&pair);
    let first = capture(&pair, 0xC0FF01);
    replay(&mut pair, &tap.addr.clone(), first).await;
    pair.run(2).await;
    let second = capture(&pair, 0xC0FF02);
    replay(&mut pair, &tap.addr.clone(), second).await;
    tap.gather();
    let ridx: Vec<u32> = tap
        .msg2s
        .iter()
        .filter_map(|m| Msg2Header::parse(m))
        .map(|h| h.receiver_idx.as_u32())
        .collect();
    assert!(
        ridx == vec![0xC0FF01, 0xC0FF02],
        "defect: the msg2s answered sender indices {ridx:x?}"
    );
    cleanup_nodes(&mut pair.nodes).await;
}

/// A byte-identical resend of the msg1 a pending redial was armed by,
/// from the same address, draws the same stored msg2 again.
#[tokio::test]
async fn a_byte_identical_resend_to_a_sent_unpromoted_leg_still_draws_its_stored_msg2() {
    let mut pair = Pair::new(Multipath::Off, true).await;
    pair.run(60).await;
    let mut tap = Tap::new(&pair);
    let data = capture(&pair, 0xC0FF01);
    replay(&mut pair, &tap.addr.clone(), data.clone()).await;
    pair.run(1).await;
    replay(&mut pair, &tap.addr.clone(), data).await;
    tap.gather();
    assert!(
        tap.msg2s.len() == 2 && tap.msg2s[0] == tap.msg2s[1],
        "{} msg2s",
        tap.msg2s.len()
    );
    cleanup_nodes(&mut pair.nodes).await;
}

/// A capture's pending redial whose held peering is gone before it is
/// resent: the byte-identical resend draws the stored msg2 and promotes the
/// leg, as a resend promotes any pending inbound link for an identity not
/// held, and the redial's entry goes with the promotion, leaving the
/// per-peer maps coherent.
#[tokio::test]
async fn a_pending_redial_promoted_by_a_msg2_resend_after_the_old_peering_was_removed_leaves_no_redial_entry_and_a_clean_audit()
 {
    let mut pair = Pair::new(Multipath::Off, true).await;
    pair.run(60).await;
    let tap = Tap::new(&pair);
    let data = capture(&pair, 0xC0FFEE);
    replay(&mut pair, &tap.addr.clone(), data.clone()).await;
    let a = pair.a_addr();
    let pending = pair.nodes[1]
        .node
        .redials
        .of(&a)
        .expect("precondition: armed");
    pair.nodes[1].node.remove_active_peer(&a);
    replay(&mut pair, &tap.addr.clone(), data).await;
    let b = &pair.nodes[1].node;
    assert!(
        b.redials.of(&a).is_none() && b.get_peer(&a).is_some_and(|p| p.link_id() == pending.link),
        "defect: the resend's promotion left the redial's entry or promoted nothing"
    );
    cleanup_nodes(&mut pair.nodes).await;
}

/// A capture of the msg1 the link B held before A's redial was set up from,
/// replayed once the dampener the swap stamped has cleared: the link the
/// swap installed holds that link's record, so the capture is a copy, and
/// arms no redial.
#[tokio::test]
async fn a_capture_of_the_previous_links_setup_msg1_arms_no_redial() {
    let mut pair = Pair::new(Multipath::Off, true).await;
    pair.run(60).await;
    let a = pair.a_addr();
    let setup = pair
        .seen
        .first()
        .cloned()
        .expect("precondition: A's dial's msg1 reached B");
    let tid = pair.nodes[0].transport_id;
    pair.nodes[0].node.path_presence(tid, false).await;
    pair.move_a(OldAddr::Blackhole);
    pair.nodes[0].node.path_presence(tid, true).await;
    pair.pump().await;
    pair.run(20).await;
    let was = counters(&pair);
    assert_eq!(
        was.redials_proven, 1,
        "precondition: A's redial replaced the peering"
    );
    let tap = Tap::new(&pair);
    replay(&mut pair, &tap.addr.clone(), setup).await;
    let r = since(&counters(&pair), &was);
    assert!(
        r.redials == 0 && pair.nodes[1].node.redials.of(&a).is_none(),
        "defect: a capture of the previous link's setup msg1 armed a redial: {r:?}"
    );
    cleanup_nodes(&mut pair.nodes).await;
}

/// B holds A and C. A capture of A's msg1, replayed from C's address, is
/// answered into a redial of A whose msg2 goes to C, which drops it: C's
/// peering, its rekey and its traffic, and A's, are untouched.
#[tokio::test]
async fn a_replayed_msg1_spoofed_from_another_held_peers_address_leaves_that_peers_rekey_and_traffic_untouched()
 {
    use super::settle::heartbeat_reaches;
    use super::spanning_tree::{TestNode, drain_all_packets, initiate_handshake, make_test_node};
    let mut nodes = vec![
        make_test_node().await,
        make_test_node().await,
        make_test_node().await,
    ];
    let (a, b, c) = (0, 1, 2);
    initiate_handshake(&mut nodes, a, b).await;
    initiate_handshake(&mut nodes, c, b).await;
    drain_all_packets(&mut nodes, false).await;
    let a_addr = *nodes[a].node.node_addr();
    let c_addr = *nodes[c].node.node_addr();
    let held = |nodes: &[TestNode], p: &NodeAddr| {
        nodes[b]
            .node
            .get_peer(p)
            .map(|q| (q.link_id(), q.our_index(), q.their_index()))
    };
    let (held_a, held_c) = (held(&nodes, &a_addr), held(&nodes, &c_addr));
    assert!(
        held_a.is_some() && held_c.is_some(),
        "precondition: B holds A and C"
    );
    let c_at = nodes[b]
        .node
        .get_peer(&c_addr)
        .and_then(|p| p.current_addr().cloned())
        .expect("precondition: B holds C at an address");
    super::rekey_parity::age_link(&mut nodes, c, b, std::time::Duration::from_secs(31));
    let b_addr = *nodes[b].node.node_addr();
    super::start_link_rekey(&mut nodes[c].node, &b_addr).await;
    let capture = craft_msg1_wire(
        &nodes[b].node,
        nodes[a].node.identity(),
        nodes[a].node.startup_epoch(),
        SessionIndex::new(0xC0FFEE),
        Node::now_ms(),
    );
    let tid = nodes[b].transport_id;
    nodes[b]
        .node
        .process_packet(ReceivedPacket::with_timestamp(
            tid,
            c_at,
            capture,
            Node::now_ms(),
        ))
        .await;
    let armed = nodes[b].node.redials.of(&a_addr).is_some();
    drain_all_packets(&mut nodes, false).await;
    let rekeyed = nodes[c]
        .node
        .get_peer(&b_addr)
        .is_some_and(|p| !p.rekey_in_progress());
    let traffic = [
        heartbeat_reaches(&mut nodes, c, b).await,
        heartbeat_reaches(&mut nodes, b, c).await,
        heartbeat_reaches(&mut nodes, a, b).await,
        heartbeat_reaches(&mut nodes, b, a).await,
    ];
    let a_kept = held(&nodes, &a_addr) == held_a;
    let c_link = held(&nodes, &c_addr).map(|h| h.0) == held_c.map(|h| h.0);
    cleanup_nodes(&mut nodes).await;
    assert!(armed, "precondition: the capture armed a redial of A");
    assert!(
        rekeyed && c_link && a_kept && traffic.iter().all(Result::is_ok),
        "defect: C's rekey finished {rekeyed}, C's link kept {c_link}, A's peering kept {a_kept}, traffic {traffic:?}"
    );
}

/// A second dial of A's identity from another tap, whose msg1 B is handed
/// `steps` steps after a first redial was armed: whether B answered it at
/// its tap.
async fn second_redial(pair: &mut Pair, steps: usize, sidx: u32) -> (Dialer, Tap, bool) {
    for _ in 0..steps {
        pair.step().await;
    }
    let mut tap = Tap::new(pair);
    let (dialer, data) = Dialer::new(&pair.nodes[0].node, &pair.nodes[1].node, sidx);
    replay(pair, &tap.addr.clone(), data).await;
    tap.gather();
    let answered = !tap.msg2s.is_empty();
    (dialer, tap, answered)
}

/// A redial of A is armed at B from one address, and half a second later
/// a second, from another, while the first is under 1 s old and unproven:
/// the second is refused and answered nothing. The first redial's frame
/// then replaces the peering onto its own link and index.
#[tokio::test]
async fn a_second_redial_within_1_s_of_the_first_is_refused_and_the_first_settles_at_its_frame() {
    let mut pair = Pair::new(Multipath::Off, true).await;
    pair.run(60).await;
    let a = pair.a_addr();
    let tid = pair.nodes[1].transport_id;
    let was = counters(&pair);
    let mut first = arm_from_tap(&mut pair, 0xF1).await;
    let pending = pair.nodes[1]
        .node
        .redials
        .of(&a)
        .expect("precondition: the first redial is pending");
    let (_second, _tap, answered) = second_redial(&mut pair, 1, 0xF2).await;
    let kept = pair.nodes[1].node.redials.of(&a) == Some(pending);
    first.dialer.answered(&first.msg2);
    let frame = first.frame(tid);
    pair.nodes[1].node.process_packet(frame).await;
    pair.pump().await;
    let r = since(&counters(&pair), &was);
    let held = pair.nodes[1]
        .node
        .get_peer(&a)
        .map(|p| (p.link_id(), p.our_index()));
    cleanup_nodes(&mut pair.nodes).await;
    assert!(
        !answered
            && kept
            && r.redial_held == 1
            && r.redials == 1
            && r.redials_proven == 1
            && held == Some((pending.link, Some(pending.index))),
        "defect: second answered {answered}, first kept {kept}, held {held:?} (first {pending:?}) {r:?}"
    );
}

/// A redial of A is armed at B and never proven; a second, from another
/// address 1.5 s later, replaces it: it is answered, the first one's link
/// and index are freed, and the second's frame replaces the peering onto
/// its own link and index.
#[tokio::test]
async fn a_redial_more_than_1_s_after_an_unproven_one_replaces_it_and_frees_its_index() {
    let mut pair = Pair::new(Multipath::Off, true).await;
    pair.run(60).await;
    let a = pair.a_addr();
    let tid = pair.nodes[1].transport_id;
    let was = counters(&pair);
    let _first = arm_from_tap(&mut pair, 0xF1).await;
    let old = pair.nodes[1]
        .node
        .redials
        .of(&a)
        .expect("precondition: the first redial is pending");
    let (mut second, mut tap, answered) = second_redial(&mut pair, 3, 0xF2).await;
    let pending = pair.nodes[1].node.redials.of(&a);
    let b = &pair.nodes[1].node;
    let freed = !b.index_allocator.is_allocated(old.index)
        && b.links.get(&old.link).is_none()
        && b.peer_machines.get(&old.link).is_none();
    let msg2 = tap.msg2s.pop();
    if let Some(msg2) = msg2 {
        second.answered(&msg2);
        let frame =
            ReceivedPacket::with_timestamp(tid, tap.addr.clone(), second.frame(), Node::now_ms());
        pair.nodes[1].node.process_packet(frame).await;
        pair.pump().await;
    }
    let r = since(&counters(&pair), &was);
    let held = pair.nodes[1]
        .node
        .get_peer(&a)
        .map(|p| (p.link_id(), p.our_index()));
    cleanup_nodes(&mut pair.nodes).await;
    assert!(
        answered
            && freed
            && pending.is_some_and(|p| p != old)
            && r.redials == 2
            && r.redials_proven == 1
            && held == pending.map(|p| (p.link, Some(p.index))),
        "defect: answered {answered}, first freed {freed}, pending {old:?} -> {pending:?}, held {held:?} {r:?}"
    );
}
