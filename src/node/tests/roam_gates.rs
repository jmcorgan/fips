//! The gates a redial from a new address passes before it is answered, and
//! what the swap leaves: the transport's admission, the silent-session
//! back-off, the ACL, the restart dampener, the peer cap, the operator's
//! disconnect, and the end-to-end session.
//!
//! The pair is the one of `roam_redial`: two loopback nodes on a frozen
//! clock, every receive-loop timer run in its order, A having dialed B and
//! redialing it from a new address after an interface detach.

use super::dialer::Dialer;
use super::paths::loopback;
use super::roam_redial::{Multipath, OldAddr, Pair, since, workers_if};
use super::spanning_tree::{cleanup_nodes, loopback_tap};
use super::*;
use crate::node::stats::HandshakeStatsSnapshot;
use crate::proto::fmp::wire::PHASE_MSG2;
use std::time::Duration;

/// B's handshake counters now.
fn counters(pair: &Pair) -> HandshakeStatsSnapshot {
    pair.nodes[1].node.stats().handshake.snapshot()
}

/// A's interface goes and comes back at a new address, so A withdraws B
/// and redials it 5 s later from that address.
async fn detach(pair: &mut Pair) {
    let tid = pair.nodes[0].transport_id;
    pair.nodes[0].node.path_presence(tid, false).await;
    pair.move_a(OldAddr::Blackhole);
    pair.nodes[0].node.path_presence(tid, true).await;
    pair.settled = None;
    pair.note();
    pair.pump().await;
}

/// On a transport that accepts no connections, a msg1 from an address no
/// link uses is refused before any crypto, a redial among them: it is
/// never answered, and the pair settles only once B reaps the old peering.
#[tokio::test]
async fn a_redial_on_a_transport_that_accepts_no_connections_is_refused_before_any_crypto() {
    let mut pair = Pair::new(Multipath::Off, true).await;
    pair.run(60).await;
    let tid = pair.nodes[1].transport_id;
    loopback(&pair.nodes[1], tid).set_accepts(false);
    let was = counters(&pair);
    detach(&mut pair).await;
    pair.run(60).await;
    let o = pair.outcome().await;
    let r = since(&counters(&pair), &was);
    assert!(
        r.redials == 0 && r.bad_state >= 1 && o.settled.is_none_or(|s| s > 30.0),
        "{r:?} {o:?}"
    );
    cleanup_nodes(&mut pair.nodes).await;
}

/// A's first redial is proven and replaces the peering 5 s after the
/// change, which stamps the dampener. A detaches again 5 s later and
/// redials 5 s after that, 10 s after the swap: its msg1 and the resends
/// at 1 s and 3 s are refused inside the dampener's 15 s, and its resend
/// at 7 s, 17 s after the swap and 12 s after the second change, is
/// answered and settles. Each refused
/// msg1 is judged afresh at its resend, since only an armed redial is
/// recorded.
#[tokio::test]
async fn a_redial_within_15_s_of_a_swap_is_refused_and_answered_at_its_first_resend_after_the_dampener_clears()
 {
    dampened(false).await;
}

/// [`a_redial_within_15_s_of_a_swap_is_refused_and_answered_at_its_first_resend_after_the_dampener_clears`]
/// with each node's decrypt workers running.
#[cfg(unix)]
#[tokio::test]
async fn a_redial_within_15_s_of_a_swap_is_refused_and_answered_at_its_first_resend_after_the_dampener_clears_with_decrypt_workers()
 {
    dampened(true).await;
}

/// Two redials 10 s apart, the second inside the dampener the first one's
/// swap stamped, with each node's decrypt workers running when `workers`.
async fn dampened(workers: bool) {
    let mut pair = Pair::new(Multipath::Off, true).await;
    workers_if(&mut pair, workers);
    pair.run(60).await;
    let was = counters(&pair);
    detach(&mut pair).await;
    pair.run(10).await;
    let first = pair.settled;
    detach(&mut pair).await;
    pair.run(30).await;
    let o = pair.outcome().await;
    let r = since(&counters(&pair), &was);
    assert!(
        first.is_some()
            && r.redials == 2
            && r.redials_proven == 2
            && r.redial_dampened == 3
            && o.settled.is_some_and(|s| (11.5..=12.5).contains(&s)),
        "defect: {r:?} {o:?}"
    );
    cleanup_nodes(&mut pair.nodes).await;
}

/// At the peer cap, a redial of a peer B holds is not a new peer: it is
/// answered and settles as it does under the cap.
#[tokio::test]
async fn at_max_peers_a_redial_of_a_held_peer_is_answered_and_settles() {
    at_max_peers(false).await;
}

/// [`at_max_peers_a_redial_of_a_held_peer_is_answered_and_settles`] with
/// each node's decrypt workers running.
#[cfg(unix)]
#[tokio::test]
async fn at_max_peers_a_redial_of_a_held_peer_is_answered_and_settles_with_decrypt_workers() {
    at_max_peers(true).await;
}

/// A redial of the one peer B's cap admits, with each node's decrypt
/// workers running when `workers`.
async fn at_max_peers(workers: bool) {
    let mut pair = Pair::with_b(Multipath::Off, true, |c| c.node.limits.max_peers = 1).await;
    workers_if(&mut pair, workers);
    pair.run(60).await;
    let was = counters(&pair);
    detach(&mut pair).await;
    pair.run(20).await;
    let o = pair.outcome().await;
    let r = since(&counters(&pair), &was);
    assert!(
        r.redials == 1
            && r.redials_proven == 1
            && r.max_peers == 0
            && o.settled.is_some_and(|s| s < 10.0)
            && o.works,
        "{r:?} {o:?}"
    );
    cleanup_nodes(&mut pair.nodes).await;
}

/// The operator disconnects A at B while a redial of A is pending: the
/// pending redial goes with the peering, its link and index with it, so the
/// redial's first frame, sent once B has dropped it, promotes nothing.
#[tokio::test]
async fn an_admin_disconnect_of_the_held_peer_drops_its_pending_redial_and_a_later_frame_promotes_nothing()
 {
    let mut pair = Pair::new(Multipath::Off, true).await;
    pair.run(60).await;
    let tid = pair.nodes[1].transport_id;
    let (at, mut rx) = loopback_tap(tid);
    let (mut dialer, data) = Dialer::new(&pair.nodes[0].node, &pair.nodes[1].node, 0xC0FFEE);
    pair.nodes[1]
        .node
        .process_packet(ReceivedPacket::with_timestamp(
            tid,
            at.clone(),
            data,
            Node::now_ms(),
        ))
        .await;
    let msg2 = std::iter::from_fn(|| rx.try_recv().ok())
        .find(|p| super::roam_redial::phase(p) == Some(PHASE_MSG2))
        .expect("precondition: the redial's msg2 reached the dialer");
    dialer.answered(&msg2.data);
    let a = pair.a_addr();
    let pending = pair.nodes[1]
        .node
        .redials
        .of(&a)
        .expect("precondition: armed");
    let npub = pair.nodes[0].node.npub();
    pair.nodes[1]
        .node
        .api_disconnect(&npub)
        .await
        .expect("precondition: the disconnect runs");
    let b = &pair.nodes[1].node;
    assert!(
        b.redials.of(&a).is_none()
            && b.handshakes.get(&pending.link).is_none()
            && b.links.get(&pending.link).is_none()
            && !b.index_allocator.is_allocated(pending.index),
        "defect: the pending redial outlived the disconnect"
    );
    pair.nodes[1]
        .node
        .process_packet(ReceivedPacket::with_timestamp(
            tid,
            at,
            dialer.frame(),
            Node::now_ms(),
        ))
        .await;
    assert!(
        pair.nodes[1].node.get_peer(&a).is_none(),
        "defect: the dropped redial's frame promoted the disconnected peer"
    );
    cleanup_nodes(&mut pair.nodes).await;
}

/// B's ACL denies A once the pair is up. A's redial from its new address
/// is refused at the ACL, before an index is allocated for it: nothing is
/// answered, and the peering is reaped as it was before redials.
#[tokio::test]
async fn a_redial_from_an_identity_the_acl_denies_is_refused_before_an_index_is_allocated() {
    let mut pair = Pair::new(Multipath::Off, true).await;
    pair.run(60).await;
    let dir = tempfile::tempdir().expect("a scratch directory");
    let (allow, deny) = (
        dir.path().join("peers.allow"),
        dir.path().join("peers.deny"),
    );
    std::fs::write(&deny, format!("{}\n", pair.nodes[0].node.npub())).expect("the deny list");
    pair.nodes[1].node.isolate_peer_acl_for_test(allow, deny);
    pair.nodes[1].node.reload_peer_acl().await;
    let was = counters(&pair);
    let allocated = pair.nodes[1].node.index_allocator.count();
    let a = pair.a_addr();
    detach(&mut pair).await;
    let mut most = allocated;
    for _ in 0..20 {
        pair.step().await;
        most = most.max(pair.nodes[1].node.index_allocator.count());
    }
    let r = since(&counters(&pair), &was);
    assert!(
        r.redials == 0
            && r.bad_state >= 1
            && most == allocated
            && pair.nodes[1].node.redials.of(&a).is_none(),
        "defect: {r:?} indices {allocated} -> at most {most}"
    );
    cleanup_nodes(&mut pair.nodes).await;
}

/// B's silent-session back-off holds A's epoch: three sessions of A ended
/// at B without a frame. A's redial from its new address is refused by it,
/// as a replacement would be, and arms nothing.
#[tokio::test]
async fn a_redial_during_the_silent_session_back_off_is_refused() {
    let mut pair = Pair::new(Multipath::Off, true).await;
    pair.run(60).await;
    let a = pair.a_addr();
    let epoch = pair.nodes[0].node.startup_epoch();
    for _ in 0..3 {
        let params = pair.nodes[1].node.gate_params();
        pair.nodes[1].node.gates_mut().ended(
            a,
            Some(epoch),
            None,
            crate::peer::peer_now(),
            None,
            &params,
        );
    }
    let was = counters(&pair);
    detach(&mut pair).await;
    pair.run(10).await;
    let r = since(&counters(&pair), &was);
    assert!(
        r.redials == 0 && r.silent_backoff >= 1 && pair.nodes[1].node.redials.of(&a).is_none(),
        "defect: {r:?}"
    );
    cleanup_nodes(&mut pair.nodes).await;
}

/// Whether `pair`'s node `at` holds an established end-to-end session with
/// node `to`.
fn session(pair: &Pair, at: usize, to: usize) -> bool {
    let peer = *pair.nodes[to].node.node_addr();
    pair.nodes[at]
        .node
        .sessions
        .get(&peer)
        .is_some_and(|s| s.is_established())
}

/// Send one end-to-end datagram from `pair`'s node `from` to node `to`, and
/// say whether `to`'s session with `from` counted it.
pub(super) async fn e2e(pair: &mut Pair, from: usize, to: usize) -> bool {
    let to_addr = *pair.nodes[to].node.node_addr();
    let from_addr = *pair.nodes[from].node.node_addr();
    let recv = |p: &Pair| {
        p.nodes[to]
            .node
            .sessions
            .get(&from_addr)
            .map(|s| s.traffic_counters().1)
    };
    let before = recv(pair);
    let sent = pair.nodes[from]
        .node
        .send_session_data(&to_addr, 0, 0, b"roam")
        .await;
    pair.pump().await;
    let after = recv(pair);
    sent.is_ok() && matches!((before, after), (b, Some(a)) if a > b.unwrap_or(0))
}

/// A and B hold an end-to-end session when A redials from a new address.
/// A's withdrawal closed its side; B's swap closes its heard side and opens
/// the session again, so within a few steps of the swap both ends hold one
/// established session to the other, and datagrams flow on it both ways.
#[tokio::test]
async fn after_a_swap_end_to_end_traffic_flows_both_ways_on_a_reopened_session() {
    swap_reopens(false).await;
}

/// [`after_a_swap_end_to_end_traffic_flows_both_ways_on_a_reopened_session`]
/// with each node's decrypt workers running.
#[cfg(unix)]
#[tokio::test]
async fn after_a_swap_end_to_end_traffic_flows_both_ways_on_a_reopened_session_with_decrypt_workers()
 {
    swap_reopens(true).await;
}

/// The end-to-end session across a swap, with each node's decrypt workers
/// running when `workers`.
async fn swap_reopens(workers: bool) {
    let mut pair = Pair::new(Multipath::Off, true).await;
    #[cfg(unix)]
    if workers {
        pair.workers_on();
    }
    #[cfg(not(unix))]
    let _ = workers;
    let b_key = pair.nodes[1].node.identity().pubkey_full();
    let b = pair.b_addr();
    pair.nodes[0]
        .node
        .initiate_session(b, b_key)
        .await
        .expect("precondition: A opens a session to B");
    pair.pump().await;
    pair.run(60).await;
    assert!(
        session(&pair, 0, 1) && session(&pair, 1, 0),
        "precondition: both ends hold the session"
    );
    let was = counters(&pair);
    detach(&mut pair).await;
    pair.run(10).await;
    let r = since(&counters(&pair), &was);
    let flows = e2e(&mut pair, 0, 1).await && e2e(&mut pair, 1, 0).await;
    assert!(
        r.redials_proven == 1
            && r.redial_session_reopens == 1
            && session(&pair, 0, 1)
            && session(&pair, 1, 0)
            && flows,
        "defect: {r:?} A {} B {} flows {flows}",
        session(&pair, 0, 1),
        session(&pair, 1, 0)
    );
    cleanup_nodes(&mut pair.nodes).await;
}

/// A dial over two paths, the reviewer's ordering: A's msg1 on the fast
/// path F reaches B first and is promoted, unheard, and B's msg2 on F is
/// lost once; A's msg1 on the slow path S, a fresh handshake, reaches B
/// 300 ms later, off the link of a peering no frame has proven and under
/// 1 s old. It is not a redial: it meets the replacement's unheard floor
/// and is refused, arming nothing. A's resend on F draws the stored msg2,
/// A completes on F, and its first frame there proves the one peering B
/// holds, so both ends keep the session on F.
#[tokio::test]
async fn a_second_msg1_of_a_two_path_dial_within_1_s_of_an_unheard_peering_is_refused_and_both_ends_keep_one_session()
 {
    let mut pair = Pair::new(Multipath::Off, true).await;
    pair.run(60).await;
    let a = pair.a_addr();
    pair.nodes[1].node.remove_active_peer(&a);
    let was = counters(&pair);
    let tid = pair.nodes[1].transport_id;
    let (fast, mut fast_rx) = loopback_tap(tid);
    let (slow, mut slow_rx) = loopback_tap(tid);
    let (mut f, f_msg1) = Dialer::new(&pair.nodes[0].node, &pair.nodes[1].node, 0xFA57);
    let (_s, s_msg1) = Dialer::new(&pair.nodes[0].node, &pair.nodes[1].node, 0x510E);
    let deliver = |from: &TransportAddr, data: &[u8]| {
        ReceivedPacket::with_timestamp(tid, from.clone(), data.to_vec(), Node::now_ms())
    };
    pair.nodes[1]
        .node
        .process_packet(deliver(&fast, &f_msg1))
        .await;
    let link_f = pair.nodes[1]
        .node
        .get_peer(&a)
        .filter(|p| !p.heard())
        .map(|p| p.link_id())
        .expect("precondition: F's msg1 promoted an unheard peering");
    let lost = std::iter::from_fn(|| fast_rx.try_recv().ok())
        .filter(|p| super::roam_redial::phase(p) == Some(PHASE_MSG2))
        .count();
    assert_eq!(lost, 1, "precondition: B answered F once, and it is lost");
    crate::time::advance(Duration::from_millis(300));
    pair.nodes[1]
        .node
        .process_packet(deliver(&slow, &s_msg1))
        .await;
    let r = since(&counters(&pair), &was);
    let slow_answered = std::iter::from_fn(|| slow_rx.try_recv().ok())
        .any(|p| super::roam_redial::phase(&p) == Some(PHASE_MSG2));
    assert!(
        r.redials == 0
            && r.bad_state == 1
            && !slow_answered
            && pair.nodes[1].node.redials.of(&a).is_none()
            && pair.nodes[1].node.get_peer(&a).map(|p| p.link_id()) == Some(link_f),
        "defect: S's msg1 inside the unheard floor was not refused as a replacement: {r:?} answered {slow_answered}"
    );
    crate::time::advance(Duration::from_millis(700));
    pair.nodes[1]
        .node
        .process_packet(deliver(&fast, &f_msg1))
        .await;
    let msg2 = std::iter::from_fn(|| fast_rx.try_recv().ok())
        .find(|p| super::roam_redial::phase(p) == Some(PHASE_MSG2))
        .expect("precondition: F's resend drew the stored msg2");
    f.answered(&msg2.data);
    pair.nodes[1]
        .node
        .process_packet(deliver(&fast, &f.frame()))
        .await;
    let b = &pair.nodes[1].node;
    assert!(
        b.get_peer(&a)
            .is_some_and(|p| p.link_id() == link_f && p.heard())
            && b.redials.of(&a).is_none(),
        "defect: B does not hold one proven peering on F"
    );
    cleanup_nodes(&mut pair.nodes).await;
}

/// A's link to B is 60 s old and working when A's timed rekey comes due:
/// its msg1 reaches B on the link and is answered as a rekey, not a
/// redial. Both ends keep the link and move to the rekey's session.
#[tokio::test]
async fn a_held_peers_rekey_msg1_on_the_link_is_still_answered_as_a_rekey() {
    let mut pair = Pair::new(Multipath::Off, true).await;
    pair.run(60).await;
    let (a, b) = (pair.a_addr(), pair.b_addr());
    let held = |p: &Pair| {
        [
            p.nodes[0]
                .node
                .get_peer(&b)
                .map(|p| (p.link_id(), p.our_index())),
            p.nodes[1]
                .node
                .get_peer(&a)
                .map(|p| (p.link_id(), p.our_index())),
        ]
    };
    let before = held(&pair);
    let was = counters(&pair);
    pair.nodes[0]
        .node
        .get_peer_mut(&b)
        .expect("precondition: A holds B")
        .test_backdate_session_established(super::rekey_parity::trigger_age());
    pair.nodes[0].node.poll_link_rekeys().await;
    pair.pump().await;
    pair.run(5).await;
    let after = held(&pair);
    let r = since(&counters(&pair), &was);
    let works = pair.heartbeat(0, 1).await && pair.heartbeat(1, 0).await;
    cleanup_nodes(&mut pair.nodes).await;
    let rekeyed = before
        .iter()
        .zip(after.iter())
        .all(|(x, y)| matches!((x, y), (Some((l0, i0)), Some((l1, i1))) if l0 == l1 && i0 != i1));
    assert!(
        rekeyed && r.redials == 0 && r.off_link == 0 && works,
        "defect: {before:?} -> {after:?} {r:?} works {works}"
    );
}

/// Two loopback nodes dial each other at once, the first at the second's
/// address and the second at another address of the first's. The first
/// node's msg1 therefore reaches the second from an address its own dial's
/// link does not hold: off that link. With the smaller node's msg1 read
/// first, or the larger's, the crossing leaves the two ends on one session
/// on which a heartbeat authenticates each way, and the audit finds no
/// breach.
async fn crossed_off_the_link(smaller_first: bool) {
    let mut nodes = Vec::new();
    for _ in 0..2 {
        let config = super::settle::with_path(Config::new(), false);
        nodes.push(super::spanning_tree::make_test_node_with_config(config, 1280).await);
    }
    let alias = super::spanning_tree::add_loopback_alias(&nodes[0].addr, nodes[0].transport_id);
    let id = |tn: &super::spanning_tree::TestNode| {
        PeerIdentity::from_pubkey_full(tn.node.identity().pubkey_full())
    };
    let (id0, id1) = (id(&nodes[0]), id(&nodes[1]));
    let (t0, t1, at1) = (
        nodes[0].transport_id,
        nodes[1].transport_id,
        nodes[1].addr.clone(),
    );
    nodes[0]
        .node
        .initiate_connection(t0, at1, id1)
        .await
        .expect("precondition: node 0 dials");
    nodes[1]
        .node
        .initiate_connection(t1, alias, id0)
        .await
        .expect("precondition: node 1 dials node 0's other address");
    let smaller = usize::from(nodes[1].node.node_addr() < nodes[0].node.node_addr());
    // The smaller node's msg1 waits at the larger node.
    let reader = if smaller_first { 1 - smaller } else { smaller };
    super::spanning_tree::process_available_packets(std::slice::from_mut(&mut nodes[reader])).await;
    super::spanning_tree::drain_all_packets(&mut nodes, false).await;
    let session = super::settle::settled(&mut nodes, 0, 1).await;
    assert!(
        session.is_ok(),
        "defect: the crossing did not leave one session: {session:?}"
    );
    super::settle::audit::assert_coherent(&mut nodes, "after the crossing").await;
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_crossed_dial_whose_msg1_arrives_off_the_link_leaves_one_session_smaller_first() {
    crossed_off_the_link(true).await;
}

#[tokio::test]
async fn a_crossed_dial_whose_msg1_arrives_off_the_link_leaves_one_session_larger_first() {
    crossed_off_the_link(false).await;
}

/// A and B run multipath off, so neither is capable at the other. A's view
/// of its 60 s old link to B is quiet past the heartbeat interval, and A
/// dials B's address on a second transport. B answers the msg1, off its
/// link, as a redial; A moves onto the link it dialed, which it set the
/// peering up on; and A's first frame there replaces B's peering. Both ends
/// end on the second transport, at the addresses the dial used, on one
/// session.
async fn second_path_to_a_stale_peer(a_smaller: bool) {
    use crate::transport::loopback::LoopbackTransport;
    use crate::transport::{TransportHandle, TransportId};
    let mut pair = Pair::new(Multipath::Off, a_smaller).await;
    pair.run(60).await;
    let (a, b) = (pair.a_addr(), pair.b_addr());
    let t2 = TransportId::new(2);
    let a2 = super::settle::alias(&pair.nodes[0].addr, t2);
    let b2 = super::settle::alias(&pair.nodes[1].addr, t2);
    for (n, at) in [(0, a2.clone()), (1, b2.clone())] {
        let lo = LoopbackTransport::new(t2, at, super::spanning_tree::LOOPBACK_REGISTRY.clone());
        pair.nodes[n]
            .node
            .transports
            .insert(t2, TransportHandle::Loopback(lo));
    }
    super::control::quieten(&mut pair.nodes[0], &b);
    assert!(
        !pair.nodes[0].node.active_peer_link_is_live(&b),
        "precondition: A's link to B reads stale"
    );
    let was = counters(&pair);
    let id = PeerIdentity::from_pubkey_full(pair.nodes[1].node.identity().pubkey_full());
    pair.nodes[0]
        .node
        .initiate_connection(t2, b2.clone(), id)
        .await
        .expect("precondition: A dials B's second address");
    pair.pump().await;
    pair.run(5).await;
    let at = |p: &Pair, n: usize, peer: &NodeAddr| {
        p.nodes[n]
            .node
            .get_peer(peer)
            .map(|p| (p.transport_id(), p.current_addr().cloned()))
    };
    let ends = (at(&pair, 0, &b), at(&pair, 1, &a));
    let r = since(&counters(&pair), &was);
    let session = super::settle::settled(&mut pair.nodes, 0, 1).await;
    cleanup_nodes(&mut pair.nodes).await;
    assert!(
        ends == (Some((Some(t2), Some(b2))), Some((Some(t2), Some(a2))))
            && r.redials == 1
            && r.redials_proven == 1
            && session.is_ok(),
        "defect: (A's B, B's A) {ends:?} {r:?} {session:?}"
    );
}

#[tokio::test]
async fn a_second_path_dial_to_a_stale_non_capable_peer_moves_both_ends_to_the_dialled_address() {
    for a_smaller in [true, false] {
        second_path_to_a_stale_peer(a_smaller).await;
    }
}
