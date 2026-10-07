//! What a same-epoch msg1 from an established peer draws while the link
//! or its session is too young to rekey.
//!
//! For the first 30 s after a link comes up, for the first 10 s after each
//! rekey cutover, and with rekeying off, a same-epoch msg1 from the peer is
//! not a rekey. The msg2 stored when the link was set
//! up answers only the msg1 it was built for: it names that msg1's sender
//! index and completes no other handshake. A peer that lost its side of the
//! link and dials again sends a fresh msg1, which the stored msg2 cannot
//! complete. These tests drive two loopback nodes through those cases and
//! assert on what the receiving node answers, what it keeps, and whether
//! frames still authenticate afterwards.
//!
//! In each test B is the node under test and A its peer. Silence is
//! modelled by stamping B's last authenticated frame from A 16 s back, which
//! is the state the receiver's liveness check reads.

use super::establish_chartests::craft_msg1_wire;
use super::rekey_parity::{
    age_link, cutover, deliver, failures, heartbeat, linked_pair, pump, rekey_config,
    rekey_to_pending, trigger_age,
};
use super::spanning_tree::{
    TestNode, add_loopback_alias, cleanup_nodes, drain_all_packets, initiate_handshake,
    make_test_node_with_config, restarted_node,
};
use super::*;
use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG1};
use crate::proto::fmp::{Msg1Digest, RekeyRole};

/// How far back a silent peer's last authenticated frame is stamped: past
/// the 15 s liveness interval.
const SILENT_MS: u64 = 16_000;

/// How far back a live but slow peer's last frame is stamped: under the
/// 15 s interval, over a 2 s grace.
const RECENT_MS: u64 = 3_000;

/// The node address of `nodes[i]`.
fn addr(nodes: &[TestNode], i: usize) -> NodeAddr {
    *nodes[i].node.node_addr()
}

/// Stamp `tn`'s last authenticated frame from `peer` at `ago_ms` before now.
fn last_heard(tn: &mut TestNode, peer: &NodeAddr, ago_ms: u64) {
    tn.node
        .get_peer_mut(peer)
        .expect("the receiver holds the peer")
        .touch(Node::now_ms() - ago_ms);
}

/// How long ago `tn` last authenticated a frame from `peer`, in ms.
fn idle_ms(tn: &TestNode, peer: &NodeAddr) -> u64 {
    tn.node
        .get_peer(peer)
        .expect("the receiver holds the peer")
        .idle_time(Node::now_ms())
}

/// The node's count of handshake msg1s refused as `BadState`.
fn bad_state(tn: &TestNode) -> u64 {
    tn.node.stats().handshake.bad_state
}

/// `nodes[a]` drops its peer `nodes[b]` without a word and dials it again
/// from the same process, so with the same startup epoch.
async fn drop_and_redial(nodes: &mut [TestNode], a: usize, b: usize) {
    let b_addr = addr(nodes, b);
    nodes[a].node.remove_active_peer(&b_addr);
    assert!(
        nodes[a].node.get_peer(&b_addr).is_none(),
        "precondition: A dropped B"
    );
    initiate_handshake(nodes, a, b).await;
}

/// Deliver A's msg1 at B, then whatever B sent back at A: one exchange.
async fn one_exchange(nodes: &mut [TestNode], a: usize, b: usize) {
    assert_eq!(
        deliver(&mut nodes[b]).await,
        1,
        "precondition: only A's msg1 is queued at B"
    );
    deliver(&mut nodes[a]).await;
}

/// Hand `data` to `tn` as a msg1 that arrived from `remote_addr` now.
async fn msg1_at(tn: &mut TestNode, remote_addr: &TransportAddr, data: Vec<u8>) {
    let transport_id = tn.transport_id;
    tn.node
        .handle_msg1(ReceivedPacket::with_timestamp(
            transport_id,
            remote_addr.clone(),
            data,
            Node::now_ms(),
        ))
        .await;
}

/// One heartbeat from `from` to `to`, delivered at `to`, must decrypt on
/// `to`'s current session with no decryption failure.
async fn heartbeat_decrypts(nodes: &mut [TestNode], from: usize, to: usize, label: &str) {
    let from_addr = addr(nodes, from);
    let to_addr = addr(nodes, to);
    let recv_before = nodes[to]
        .node
        .get_peer(&from_addr)
        .expect("the receiver holds the sender")
        .link_stats()
        .packets_recv;
    heartbeat(&mut nodes[from], &to_addr).await;
    deliver(&mut nodes[to]).await;
    assert_eq!(
        failures(&nodes[to], &from_addr),
        0,
        "{label}: decryption failures after one heartbeat"
    );
    assert_eq!(
        nodes[to]
            .node
            .get_peer(&from_addr)
            .unwrap()
            .link_stats()
            .packets_recv,
        recv_before + 1,
        "{label}: the heartbeat must be received on the current session"
    );
}

/// After one exchange, A must hold B, B's peering must name A's new leg and
/// sit on a new link, and a heartbeat each way must decrypt.
async fn assert_replaced(nodes: &mut [TestNode], a: usize, b: usize, old_link: LinkId) {
    let a_addr = addr(nodes, a);
    let b_addr = addr(nodes, b);
    let a_index = nodes[a]
        .node
        .get_peer(&b_addr)
        .expect("A must hold B as an active peer after one exchange")
        .our_index();
    let b_peer = nodes[b]
        .node
        .get_peer(&a_addr)
        .expect("B must hold A after the exchange");
    assert_eq!(
        b_peer.their_index(),
        a_index,
        "B's peering must name A's new leg's index"
    );
    assert_ne!(
        b_peer.link_id(),
        old_link,
        "B's peering must be a new link, not the one A dropped"
    );
    pump(nodes).await;
    heartbeat_decrypts(nodes, a, b, "A to B").await;
    heartbeat_decrypts(nodes, b, a, "B to A").await;
}

/// A peers with B (A dialling, so B holds the stored msg2), drops its side
/// without a word 16 s after B last heard from it, and dials again. The
/// fresh msg1 must complete in one exchange.
#[tokio::test]
async fn a_peer_that_drops_its_link_silently_and_redials_16_s_after_its_last_frame_completes_in_one_exchange()
 {
    let (a, b) = (0, 1);
    let mut nodes = linked_pair(rekey_config(60), rekey_config(60)).await;
    let a_addr = addr(&nodes, a);
    let old_link = nodes[b].node.get_peer(&a_addr).unwrap().link_id();

    last_heard(&mut nodes[b], &a_addr, SILENT_MS);
    drop_and_redial(&mut nodes, a, b).await;
    one_exchange(&mut nodes, a, b).await;

    assert_replaced(&mut nodes, a, b, old_link).await;
    cleanup_nodes(&mut nodes).await;
}

/// The same with B as the link's dialler, where no msg2 is stored: B's side
/// answered nothing, and must now replace the peering.
#[tokio::test]
async fn a_peer_we_dialled_that_drops_its_link_silently_and_redials_16_s_after_its_last_frame_completes_in_one_exchange()
 {
    let (b, a) = (0, 1);
    let mut nodes = linked_pair(rekey_config(60), rekey_config(60)).await;
    let a_addr = addr(&nodes, a);
    assert!(
        nodes[b]
            .node
            .get_peer(&a_addr)
            .unwrap()
            .handshake_msg2()
            .is_none(),
        "precondition: the dialling side stores no msg2"
    );
    let old_link = nodes[b].node.get_peer(&a_addr).unwrap().link_id();

    last_heard(&mut nodes[b], &a_addr, SILENT_MS);
    drop_and_redial(&mut nodes, a, b).await;
    one_exchange(&mut nodes, a, b).await;

    assert_replaced(&mut nodes, a, b, old_link).await;
    cleanup_nodes(&mut nodes).await;
}

/// After B rekeys as the initiator and cuts over, its session is young
/// again. A frame from A on B's previous session still counts as hearing
/// from A; once A then goes silent for 16 s and dials again, the fresh msg1
/// must complete in one exchange.
#[tokio::test]
async fn after_our_rekey_cutover_a_peer_silent_for_16_s_that_redials_completes_in_one_exchange() {
    let (a, b) = (0, 1);
    let mut nodes = linked_pair(rekey_config(60), rekey_config(60)).await;
    let a_addr = addr(&nodes, a);
    let b_addr = addr(&nodes, b);
    age_link(&mut nodes, a, b, trigger_age());
    rekey_to_pending(&mut nodes, b, a).await;
    cutover(&mut nodes[b], &a_addr).await;
    assert!(
        nodes[b]
            .node
            .get_peer(&a_addr)
            .unwrap()
            .session_established_at()
            .elapsed()
            < Duration::from_secs(30),
        "precondition: B's session is under 30 s after the cutover"
    );

    // A is still on what is B's previous session.
    last_heard(&mut nodes[b], &a_addr, SILENT_MS);
    heartbeat(&mut nodes[a], &b_addr).await;
    assert_eq!(
        deliver(&mut nodes[b]).await,
        1,
        "precondition: only A's heartbeat is queued at B"
    );
    assert!(
        idle_ms(&nodes[b], &a_addr) < 15_000,
        "precondition: a frame on B's previous session refreshes B's last-heard time"
    );
    assert_eq!(
        nodes[b]
            .node
            .get_peer(&a_addr)
            .unwrap()
            .mmp()
            .expect("B has MMP state for A")
            .receiver
            .last_recv_ms(),
        None,
        "precondition: B's MMP receiver has seen nothing on the new session"
    );
    let old_link = nodes[b].node.get_peer(&a_addr).unwrap().link_id();

    last_heard(&mut nodes[b], &a_addr, SILENT_MS);
    drop_and_redial(&mut nodes, a, b).await;
    one_exchange(&mut nodes, a, b).await;

    assert_replaced(&mut nodes, a, b, old_link).await;
    cleanup_nodes(&mut nodes).await;
}

/// A peer B heard from a moment ago sends a fresh same-epoch msg1. It must
/// draw nothing, the peering must be left as it was, and the drop counted.
#[tokio::test]
async fn a_fresh_same_epoch_msg1_from_a_peer_heard_from_within_15_s_is_dropped_unanswered_and_the_link_is_kept()
 {
    let (a, b) = (0, 1);
    let mut nodes = linked_pair(rekey_config(60), rekey_config(60)).await;
    let a_addr = addr(&nodes, a);
    pump(&mut nodes).await;
    assert!(
        idle_ms(&nodes[b], &a_addr) < 15_000,
        "precondition: B heard from A within 15 s"
    );
    let (link, ours, theirs) = {
        let p = nodes[b].node.get_peer(&a_addr).unwrap();
        (p.link_id(), p.our_index(), p.their_index())
    };
    let bad_before = bad_state(&nodes[b]);

    drop_and_redial(&mut nodes, a, b).await;
    assert!(
        nodes[a].packet_rx.is_empty(),
        "precondition: nothing is queued at A before B sees the msg1"
    );
    assert_eq!(
        deliver(&mut nodes[b]).await,
        1,
        "precondition: only A's msg1 is queued at B"
    );

    assert!(
        nodes[a].packet_rx.is_empty(),
        "nothing may answer a msg1 that is not the setup msg1 while the peer is live"
    );
    let p = nodes[b]
        .node
        .get_peer(&a_addr)
        .expect("B must keep its peering with a live A");
    assert_eq!(p.link_id(), link, "B's peering must keep its link");
    assert_eq!(p.our_index(), ours, "B's peering must keep its index");
    assert_eq!(
        p.their_index(),
        theirs,
        "B's peering must keep A's original index"
    );
    assert_eq!(
        bad_state(&nodes[b]),
        bad_before + 1,
        "the dropped msg1 must be counted"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A rekey msg1 that B answered and adopted is copied off the wire. On the
/// young session the adoption started, the copy must be refused even with
/// A silent for 16 s: it must draw nothing and leave the peering in place.
#[tokio::test]
async fn a_copy_of_an_adopted_rekey_msg1_on_a_young_session_is_refused_even_from_a_silent_peer() {
    let (a, b) = (0, 1);
    let mut nodes = linked_pair(rekey_config(60), rekey_config(60)).await;
    let a_addr = addr(&nodes, a);
    let b_addr = addr(&nodes, b);
    age_link(&mut nodes, a, b, trigger_age());

    nodes[a].node.check_rekey().await;
    let msg1 = nodes[b]
        .packet_rx
        .try_recv()
        .expect("precondition: A's rekey msg1 is queued at B");
    assert_eq!(
        CommonPrefix::parse(&msg1.data).map(|c| c.phase),
        Some(PHASE_MSG1),
        "precondition: the queued packet is a msg1"
    );
    assert!(
        nodes[b].packet_rx.is_empty(),
        "precondition: only the rekey msg1 was queued at B"
    );
    let copy = msg1.data.clone();
    let source = msg1.remote_addr.clone();
    nodes[b].node.handle_msg1(msg1).await;
    let adopted = nodes[b]
        .node
        .get_peer(&a_addr)
        .unwrap()
        .pending_our_index()
        .expect("precondition: B answered the rekey msg1 and holds a pending");

    assert_eq!(
        deliver(&mut nodes[a]).await,
        1,
        "precondition: only B's rekey msg2 is queued at A"
    );
    cutover(&mut nodes[a], &b_addr).await;
    heartbeat(&mut nodes[a], &b_addr).await;
    deliver(&mut nodes[b]).await;
    pump(&mut nodes).await;
    {
        let p = nodes[b].node.get_peer(&a_addr).unwrap();
        assert_eq!(
            p.our_index(),
            Some(adopted),
            "precondition: A's first frame on the new session promoted B's pending"
        );
        assert!(
            p.session_established_at().elapsed() < Duration::from_secs(30),
            "precondition: B's session is under 30 s after the adoption"
        );
        assert!(
            p.answered_before(&Msg1Digest::of(&copy)),
            "precondition: B records the adopted msg1 as answered"
        );
    }
    assert!(
        nodes[a].packet_rx.is_empty(),
        "precondition: nothing is queued at A"
    );
    let link = nodes[b].node.get_peer(&a_addr).unwrap().link_id();
    let bad_before = bad_state(&nodes[b]);

    last_heard(&mut nodes[b], &a_addr, SILENT_MS);
    msg1_at(&mut nodes[b], &source, copy).await;

    assert!(
        nodes[a].packet_rx.is_empty(),
        "nothing may answer a copy of an adopted rekey msg1"
    );
    let p = nodes[b]
        .node
        .get_peer(&a_addr)
        .expect("B must keep its peering");
    assert_eq!(p.link_id(), link, "B's peering must keep its link");
    assert_eq!(
        p.our_index(),
        Some(adopted),
        "B's peering must keep the adopted index"
    );
    assert_eq!(
        bad_state(&nodes[b]),
        bad_before + 1,
        "the refused copy must be counted"
    );
    cleanup_nodes(&mut nodes).await;
}

/// An accepted replacement stamps the per-peer dampener that the epoch
/// restart shares. Inside the next 15 s, a second replacement and a
/// restart of the same peer are both refused, even with the peer silent.
#[tokio::test]
async fn a_same_epoch_replacement_stamps_the_shared_dampener_so_a_second_replacement_or_a_restart_inside_15_s_is_refused()
 {
    let (a, b) = (0, 1);
    let mut nodes = linked_pair(rekey_config(60), rekey_config(60)).await;
    let a_addr = addr(&nodes, a);
    let b_addr = addr(&nodes, b);

    last_heard(&mut nodes[b], &a_addr, SILENT_MS);
    drop_and_redial(&mut nodes, a, b).await;
    one_exchange(&mut nodes, a, b).await;
    assert!(
        nodes[a].node.get_peer(&b_addr).is_some(),
        "the first replacement must be accepted"
    );
    let stamped = nodes[b]
        .node
        .restart_dampener_stamp(&a_addr)
        .expect("an accepted replacement must stamp the dampener");
    pump(&mut nodes).await;

    // A second replacement inside the interval.
    let link = nodes[b].node.get_peer(&a_addr).unwrap().link_id();
    let bad_before = bad_state(&nodes[b]);
    last_heard(&mut nodes[b], &a_addr, SILENT_MS);
    drop_and_redial(&mut nodes, a, b).await;
    one_exchange(&mut nodes, a, b).await;
    assert_eq!(
        nodes[b].node.get_peer(&a_addr).unwrap().link_id(),
        link,
        "a second replacement inside 15 s must leave B's peering in place"
    );
    assert!(
        nodes[a].node.get_peer(&b_addr).is_none(),
        "the refused replacement must not complete at A"
    );
    assert_eq!(
        bad_state(&nodes[b]),
        bad_before + 1,
        "the refused replacement must be counted"
    );

    // A restart of the same peer inside the interval.
    let epoch = nodes[b].node.get_peer(&a_addr).unwrap().remote_epoch();
    let restarted = restarted_node(&nodes[a], rekey_config(60));
    drop(std::mem::replace(&mut nodes[a], restarted));
    assert_ne!(
        Some(nodes[a].node.startup_epoch()),
        epoch,
        "precondition: the restarted A has a new epoch"
    );
    last_heard(&mut nodes[b], &a_addr, SILENT_MS);
    initiate_handshake(&mut nodes, a, b).await;
    one_exchange(&mut nodes, a, b).await;
    let p = nodes[b].node.get_peer(&a_addr).unwrap();
    assert_eq!(
        p.link_id(),
        link,
        "a restart inside 15 s of a replacement must leave B's peering in place"
    );
    assert_eq!(
        p.remote_epoch(),
        epoch,
        "B's stored epoch for A must not move to the restarted epoch"
    );
    assert_eq!(
        nodes[b].node.restart_dampener_stamp(&a_addr),
        Some(stamped),
        "the refusals must not restamp the dampener"
    );
    cleanup_nodes(&mut nodes).await;
}

/// An exact resend of the msg1 the link was set up from draws exactly the
/// stored msg2, whether B heard from A a moment ago or 16 s ago, and the
/// peering is left as it was.
#[tokio::test]
async fn an_exact_resend_of_the_link_setup_msg1_draws_the_stored_msg2_whether_the_peer_is_live_or_silent()
 {
    let (a, b) = (0, 1);
    let mut nodes = vec![
        make_test_node_with_config(rekey_config(60), 1280).await,
        make_test_node_with_config(rekey_config(60), 1280).await,
    ];
    let a_addr = addr(&nodes, a);
    initiate_handshake(&mut nodes, a, b).await;
    let setup = nodes[b]
        .packet_rx
        .try_recv()
        .expect("precondition: A's setup msg1 is queued at B");
    let copy = setup.clone();
    nodes[b].node.handle_msg1(setup).await;
    drain_all_packets(&mut nodes, false).await;
    let (stored, link, theirs) = {
        let p = nodes[b]
            .node
            .get_peer(&a_addr)
            .expect("precondition: B promoted A");
        (
            p.handshake_msg2()
                .expect("precondition: B stores the msg2 it answered with")
                .to_vec(),
            p.link_id(),
            p.their_index(),
        )
    };

    let mut found = Vec::new();
    for (label, ago_ms) in [("live", 0), ("silent", SILENT_MS)] {
        last_heard(&mut nodes[b], &a_addr, ago_ms);
        assert!(
            nodes[a].packet_rx.is_empty(),
            "precondition: nothing is queued at A"
        );
        msg1_at(&mut nodes[b], &copy.remote_addr, copy.data.clone()).await;
        let answers: Vec<Vec<u8>> = std::iter::from_fn(|| nodes[a].packet_rx.try_recv().ok())
            .map(|p| p.data)
            .collect();
        if answers != vec![stored.clone()] {
            found.push(format!(
                "{label}: B sent {} packet(s) to A, not exactly the stored msg2",
                answers.len()
            ));
        }
        match nodes[b].node.get_peer(&a_addr) {
            Some(p) if p.link_id() == link && p.their_index() == theirs => {}
            _ => found.push(format!("{label}: B's peering changed")),
        }
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
    cleanup_nodes(&mut nodes).await;
}

/// After B rekeys as the initiator and cuts over, a fresh msg1 from A's
/// identity and epoch arriving off the link, and one from A's link address
/// with B having heard from A 3 s ago, must both leave the link up: the
/// peering keeps its link and index, and the rekey still completes.
#[tokio::test]
async fn after_our_initiator_cutover_an_off_path_msg1_and_an_earlier_link_msg1_3_s_later_leave_the_link_up()
 {
    let (a, b) = (0, 1);
    let mut nodes = linked_pair(rekey_config(60), rekey_config(60)).await;
    let a_addr = addr(&nodes, a);
    let b_addr = addr(&nodes, b);
    age_link(&mut nodes, a, b, trigger_age());
    let a_pending = rekey_to_pending(&mut nodes, b, a).await;
    cutover(&mut nodes[b], &a_addr).await;
    heartbeat(&mut nodes[a], &b_addr).await;
    assert_eq!(
        deliver(&mut nodes[b]).await,
        1,
        "precondition: only A's heartbeat is queued at B"
    );
    assert_eq!(
        nodes[b]
            .node
            .get_peer(&a_addr)
            .unwrap()
            .mmp()
            .expect("B has MMP state for A")
            .receiver
            .last_recv_ms(),
        None,
        "precondition: B's MMP receiver has seen nothing on the new session"
    );
    let (link, ours) = {
        let p = nodes[b].node.get_peer(&a_addr).unwrap();
        (p.link_id(), p.our_index())
    };

    let a_identity = nodes[a].node.identity().clone();
    let a_epoch = nodes[a].node.startup_epoch();
    let off_path = add_loopback_alias(&nodes[a].addr);
    let data = craft_msg1_wire(
        &nodes[b].node,
        &a_identity,
        a_epoch,
        SessionIndex::new(0x5151),
        Node::now_ms(),
    );
    msg1_at(&mut nodes[b], &off_path, data).await;

    last_heard(&mut nodes[b], &a_addr, RECENT_MS);
    let a_link_addr = nodes[a].addr.clone();
    let data = craft_msg1_wire(
        &nodes[b].node,
        &a_identity,
        a_epoch,
        SessionIndex::new(0x5252),
        Node::now_ms(),
    );
    msg1_at(&mut nodes[b], &a_link_addr, data).await;

    {
        let p = nodes[b]
            .node
            .get_peer(&a_addr)
            .expect("B must keep its peering with A");
        assert_eq!(p.link_id(), link, "B's peering must keep its link");
        assert_eq!(
            p.our_index(),
            ours,
            "B's peering must keep its post-cutover index"
        );
    }
    assert_eq!(
        nodes[b].node.connection_count(),
        0,
        "the msg1s must leave no connection behind at B"
    );

    // Whatever reached A (nothing, or stale answers it drops) is processed,
    // then B's first frame on the new session promotes A's pending.
    deliver(&mut nodes[a]).await;
    heartbeat(&mut nodes[b], &a_addr).await;
    deliver(&mut nodes[a]).await;
    {
        let p = nodes[a].node.get_peer(&b_addr).expect("A keeps B");
        assert!(
            p.pending_new_session().is_none() && p.our_index() == Some(a_pending),
            "B's frame on the new session must promote A's pending"
        );
    }
    heartbeat_decrypts(&mut nodes, a, b, "A to B after the cutover").await;
    cleanup_nodes(&mut nodes).await;
}

/// The larger node L dials the smaller S over a slow first path: S promotes
/// L, and L's answer is held. A sibling msg1 from L arrives at S from a
/// second address 3 s later. Once L's queue is delivered, both ends must
/// authenticate each other's frames.
#[tokio::test]
async fn a_sibling_dial_arriving_3_s_after_promotion_on_a_slow_first_path_leaves_both_ends_authenticating()
 {
    let mut nodes = vec![
        make_test_node_with_config(rekey_config(60), 1280).await,
        make_test_node_with_config(rekey_config(60), 1280).await,
    ];
    let (s, l) = if addr(&nodes, 0) < addr(&nodes, 1) {
        (0, 1)
    } else {
        (1, 0)
    };
    let l_addr = addr(&nodes, l);
    initiate_handshake(&mut nodes, l, s).await;
    assert_eq!(
        deliver(&mut nodes[s]).await,
        1,
        "precondition: only L's msg1 is queued at S"
    );
    assert!(
        nodes[s].node.get_peer(&l_addr).is_some(),
        "precondition: S promoted L"
    );

    last_heard(&mut nodes[s], &l_addr, RECENT_MS);
    let l_identity = nodes[l].node.identity().clone();
    let l_epoch = nodes[l].node.startup_epoch();
    let sibling = add_loopback_alias(&nodes[l].addr);
    let data = craft_msg1_wire(
        &nodes[s].node,
        &l_identity,
        l_epoch,
        SessionIndex::new(0x6161),
        Node::now_ms(),
    );
    msg1_at(&mut nodes[s], &sibling, data).await;

    deliver(&mut nodes[l]).await;
    pump(&mut nodes).await;
    heartbeat_decrypts(&mut nodes, l, s, "L to S").await;
    heartbeat_decrypts(&mut nodes, s, l, "S to L").await;
    cleanup_nodes(&mut nodes).await;
}

/// Which rekey put B's current session in place.
#[derive(Clone, Copy, Debug)]
enum LastCycle {
    /// B rekeyed as the initiator and cut over.
    OurCutover,
    /// A rekeyed, and B adopted the session it answered.
    OurAdoption,
}

/// A pair one rekey cycle past a link aged beyond the rekey trigger, B
/// draining the session that cycle replaced.
struct AfterCycle {
    nodes: Vec<TestNode>,
    a: usize,
    b: usize,
    a_addr: NodeAddr,
    b_addr: NodeAddr,
    /// B's index for the session it is draining.
    p0: SessionIndex,
    label: String,
}

/// Link A and B with B the dialler when `b_dialled`, age the link past the
/// rekey trigger, and run one rekey cycle as `last` says, both ends ending
/// on the new session. With `age` set, B's session and the drain the cycle
/// began are then backdated together by it, the state a production node is
/// in once that long has passed and no rekey tick has yet run.
async fn after_cycle(last: LastCycle, b_dialled: bool, age: Option<Duration>) -> AfterCycle {
    let (a, b) = if b_dialled { (1, 0) } else { (0, 1) };
    let label = format!("{last:?}, B dialled {b_dialled}");
    let mut nodes = linked_pair(rekey_config(60), rekey_config(60)).await;
    let a_addr = addr(&nodes, a);
    let b_addr = addr(&nodes, b);
    age_link(&mut nodes, a, b, trigger_age());
    match last {
        LastCycle::OurCutover => {
            rekey_to_pending(&mut nodes, b, a).await;
            cutover(&mut nodes[b], &a_addr).await;
            heartbeat(&mut nodes[b], &a_addr).await;
            deliver(&mut nodes[a]).await;
        }
        LastCycle::OurAdoption => {
            rekey_to_pending(&mut nodes, a, b).await;
            cutover(&mut nodes[a], &b_addr).await;
            heartbeat(&mut nodes[a], &b_addr).await;
            deliver(&mut nodes[b]).await;
        }
    }
    for (x, peer) in [(a, b_addr), (b, a_addr)] {
        let p = nodes[x].node.get_peer(&peer).unwrap();
        assert!(
            p.pending_new_session().is_none() && p.is_draining(),
            "precondition ({label}): both ends are on the new session and draining the old"
        );
    }
    let p0 = nodes[b]
        .node
        .get_peer(&a_addr)
        .unwrap()
        .previous_our_index()
        .expect("precondition: B holds the index of the session it is draining");
    if let Some(age) = age {
        let p = nodes[b].node.get_peer_mut(&a_addr).unwrap();
        p.test_backdate_session_established(age);
        p.test_backdate_drain_started(age);
    }
    AfterCycle {
        nodes,
        a,
        b,
        a_addr,
        b_addr,
        p0,
        label,
    }
}

/// Refresh A at B with a heartbeat, then make A start its next rekey. A's
/// own drain is backdated past its window first, so its tick completes that
/// drain before it initiates. Returns A's rekey msg1, the one packet left
/// queued at B.
async fn peer_rekeys(c: &mut AfterCycle) -> ReceivedPacket {
    let (a, b) = (c.a, c.b);
    heartbeat(&mut c.nodes[a], &c.b_addr).await;
    assert_eq!(
        deliver(&mut c.nodes[b]).await,
        1,
        "precondition ({}): only A's heartbeat is queued at B",
        c.label
    );
    assert!(
        idle_ms(&c.nodes[b], &c.a_addr) < 15_000,
        "precondition ({}): B heard from A within 15 s",
        c.label
    );
    {
        let p = c.nodes[a].node.get_peer_mut(&c.b_addr).unwrap();
        p.test_backdate_session_established(trigger_age());
        p.test_backdate_drain_started(Duration::from_secs(12));
        p.backdate_dampener(Duration::from_secs(31));
    }
    c.nodes[a].node.check_rekey().await;
    let p = c.nodes[a].node.get_peer(&c.b_addr).unwrap();
    assert!(
        p.rekey_in_progress() && !p.is_draining(),
        "precondition ({}): A completed its drain and started a rekey",
        c.label
    );
    let msg1 = c.nodes[b]
        .packet_rx
        .try_recv()
        .expect("precondition: A's rekey msg1 is queued at B");
    assert_eq!(
        CommonPrefix::parse(&msg1.data).map(|p| p.phase),
        Some(PHASE_MSG1),
        "precondition ({}): the packet queued at B is a msg1",
        c.label
    );
    assert!(
        c.nodes[b].packet_rx.is_empty(),
        "precondition ({}): only A's rekey msg1 is queued at B",
        c.label
    );
    msg1
}

/// How many `peers_by_index` entries at `tn` name `peer`.
fn index_entries(tn: &TestNode, peer: &NodeAddr) -> usize {
    tn.node
        .peers_by_index
        .values()
        .filter(|p| *p == peer)
        .count()
}

/// Whether `tn` still maps `index` to `peer`.
fn maps_index(tn: &TestNode, peer: &NodeAddr, index: SessionIndex) -> bool {
    tn.node.peers_by_index.get(&index.as_u32()) == Some(peer)
}

/// B has just handled A's rekey msg1, which it must have answered: check B
/// armed a responder pending, retired its expired drain and freed its index,
/// sent exactly the msg2, and then adopted the session on A's first frame.
/// Returns what went wrong.
async fn answered_and_adopted(c: &mut AfterCycle, bad_before: u64) -> Vec<String> {
    let (a, b, label) = (c.a, c.b, c.label.clone());
    let mut found = Vec::new();
    let pending = {
        let p = c.nodes[b].node.get_peer(&c.a_addr).unwrap();
        if p.pending_role() != Some(RekeyRole::Responder) {
            found.push(format!(
                "{label}: B holds pending role {:?}, not a responder pending",
                p.pending_role()
            ));
        }
        if p.is_draining() {
            found.push(format!("{label}: B is still draining after arming"));
        }
        p.pending_our_index()
    };
    if maps_index(&c.nodes[b], &c.a_addr, c.p0) {
        found.push(format!("{label}: B still maps the drained session's index"));
    }
    if bad_state(&c.nodes[b]) != bad_before {
        found.push(format!("{label}: B counted the rekey msg1 as refused"));
    }
    let queued = deliver(&mut c.nodes[a]).await;
    let a_role = c.nodes[a].node.get_peer(&c.b_addr).unwrap().pending_role();
    if queued != 1 || a_role != Some(RekeyRole::Initiator) {
        found.push(format!(
            "{label}: {queued} packet(s) reached A, leaving it with pending role {a_role:?}"
        ));
    }
    if !found.is_empty() {
        return found;
    }

    let link = c.nodes[b].node.get_peer(&c.a_addr).unwrap().link_id();
    cutover(&mut c.nodes[a], &c.b_addr).await;
    heartbeat(&mut c.nodes[a], &c.b_addr).await;
    deliver(&mut c.nodes[b]).await;
    let p = c.nodes[b].node.get_peer(&c.a_addr).unwrap();
    if p.our_index() != pending {
        found.push(format!(
            "{label}: A's first frame did not promote B's pending"
        ));
    }
    if p.link_id() != link {
        found.push(format!("{label}: B's link changed"));
    }
    if failures(&c.nodes[b], &c.a_addr) != 0 {
        found.push(format!("{label}: B failed to decrypt A's frame"));
    }
    let entries = index_entries(&c.nodes[b], &c.a_addr);
    if entries != 2 {
        found.push(format!(
            "{label}: B maps {entries} indices to A, not its current and previous"
        ));
    }
    found
}

/// Every combination of the last cycle's kind and which end dialled.
fn cycle_cases() -> [(LastCycle, bool); 4] {
    [
        (LastCycle::OurCutover, false),
        (LastCycle::OurCutover, true),
        (LastCycle::OurAdoption, false),
        (LastCycle::OurAdoption, true),
    ]
}

/// On a link far older than 30 s, A rekeys 12 s after B's last cutover or
/// adoption. B must answer it as a rekey, retiring the drain that has
/// passed but that no tick has completed, and adopt the new session on A's
/// first frame, leaving only its current and previous indices mapped.
#[tokio::test]
async fn a_peers_rekey_msg1_12_s_after_our_last_cutover_on_a_link_older_than_30_s_is_answered_adopted_and_leaks_no_index()
 {
    let mut found = Vec::new();
    for (last, b_dialled) in cycle_cases() {
        let mut c = after_cycle(last, b_dialled, Some(Duration::from_secs(12))).await;
        let msg1 = peer_rekeys(&mut c).await;
        let bad_before = bad_state(&c.nodes[c.b]);
        c.nodes[c.b].node.handle_msg1(msg1).await;
        found.extend(answered_and_adopted(&mut c, bad_before).await);
        cleanup_nodes(&mut c.nodes).await;
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}

/// B has just handled A's rekey msg1 inside the drain window: check it was
/// dropped, and that B's draining session is still registered. Returns what
/// went wrong.
fn dropped_inside_the_drain(c: &AfterCycle, bad_before: u64) -> Vec<String> {
    let label = &c.label;
    let mut found = Vec::new();
    let p = c.nodes[c.b].node.get_peer(&c.a_addr).unwrap();
    if p.pending_new_session().is_some() {
        found.push(format!("{label}: B armed a pending inside the drain"));
    }
    if !p.is_draining() || !maps_index(&c.nodes[c.b], &c.a_addr, c.p0) {
        found.push(format!(
            "{label}: B's draining session lost its registration"
        ));
    }
    if !c.nodes[c.a].packet_rx.is_empty() {
        found.push(format!("{label}: B answered the msg1"));
    }
    if bad_state(&c.nodes[c.b]) != bad_before + 1 {
        found.push(format!("{label}: B did not count the dropped msg1"));
    }
    found
}

/// Under 10 s after B's last cutover or adoption, A's rekey msg1 is dropped
/// while A is live, and the session B is draining stays registered.
#[tokio::test]
async fn a_peers_rekey_msg1_inside_10_s_of_our_last_cutover_is_dropped_and_leaves_the_draining_session_registered()
 {
    let mut found = Vec::new();
    for (last, b_dialled) in cycle_cases() {
        let mut c = after_cycle(last, b_dialled, None).await;
        let msg1 = peer_rekeys(&mut c).await;
        let bad_before = bad_state(&c.nodes[c.b]);
        c.nodes[c.b].node.handle_msg1(msg1).await;
        found.extend(dropped_inside_the_drain(&c, bad_before));
        cleanup_nodes(&mut c.nodes).await;
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}

/// A's rekey msg1, dropped under 10 s after B's last cutover or adoption, is
/// resent once B's session and drain read 12 s. The resend must be answered
/// and adopted: the dropped copy left nothing in B's record of answered
/// msg1s.
#[tokio::test]
async fn a_peers_rekey_msg1_dropped_inside_10_s_of_our_cutover_is_answered_and_adopted_when_resent_after_10_s()
 {
    let mut found = Vec::new();
    for (last, b_dialled) in cycle_cases() {
        let mut c = after_cycle(last, b_dialled, None).await;
        let msg1 = peer_rekeys(&mut c).await;
        let (source, bytes) = (msg1.remote_addr.clone(), msg1.data.clone());
        let bad_before = bad_state(&c.nodes[c.b]);
        c.nodes[c.b].node.handle_msg1(msg1).await;
        let dropped = dropped_inside_the_drain(&c, bad_before);
        if !dropped.is_empty() {
            found.extend(dropped);
            cleanup_nodes(&mut c.nodes).await;
            continue;
        }

        {
            let p = c.nodes[c.b].node.get_peer_mut(&c.a_addr).unwrap();
            p.test_backdate_session_established(Duration::from_secs(12));
            p.test_backdate_drain_started(Duration::from_secs(12));
        }
        let bad_before = bad_state(&c.nodes[c.b]);
        msg1_at(&mut c.nodes[c.b], &source, bytes).await;
        found.extend(answered_and_adopted(&mut c, bad_before).await);
        cleanup_nodes(&mut c.nodes).await;
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}

/// 12 s after B's own cutover on an aged link, a fresh msg1 with A's
/// identity and epoch arrives off the link while the link works. Whether A
/// is silent at B or live, it must be refused: B keeps its link and index,
/// arms nothing and answers nothing, and B's frames still decrypt at A.
#[tokio::test]
async fn an_off_link_msg1_from_a_peer_silent_for_16_s_12_s_after_our_cutover_on_an_aged_link_is_refused_and_keeps_the_peering()
 {
    let mut found = Vec::new();
    for b_dialled in [false, true] {
        for (heard, ago_ms) in [("silent", SILENT_MS), ("live", RECENT_MS)] {
            let mut c = after_cycle(
                LastCycle::OurCutover,
                b_dialled,
                Some(Duration::from_secs(12)),
            )
            .await;
            let (a, b) = (c.a, c.b);
            let label = format!("{}, {heard}", c.label);
            let (link, ours) = {
                let p = c.nodes[b].node.get_peer(&c.a_addr).unwrap();
                (p.link_id(), p.our_index())
            };
            let bad_before = bad_state(&c.nodes[b]);
            last_heard(&mut c.nodes[b], &c.a_addr, ago_ms);
            let a_identity = c.nodes[a].node.identity().clone();
            let a_epoch = c.nodes[a].node.startup_epoch();
            let off_link = add_loopback_alias(&c.nodes[a].addr);
            let data = craft_msg1_wire(
                &c.nodes[b].node,
                &a_identity,
                a_epoch,
                SessionIndex::new(0x5353),
                Node::now_ms(),
            );
            msg1_at(&mut c.nodes[b], &off_link, data).await;

            let before = found.len();
            match c.nodes[b].node.get_peer(&c.a_addr) {
                Some(p) if p.link_id() == link && p.our_index() == ours => {
                    if p.pending_new_session().is_some() {
                        found.push(format!("{label}: B armed a pending"));
                    }
                }
                _ => found.push(format!("{label}: B's peering changed")),
            }
            if !c.nodes[a].packet_rx.is_empty() {
                found.push(format!("{label}: the off-link msg1 drew an answer"));
            }
            if c.nodes[b].node.connection_count() != 0 {
                found.push(format!("{label}: the msg1 left a connection at B"));
            }
            if bad_state(&c.nodes[b]) != bad_before + 1 {
                found.push(format!("{label}: B did not count the refused msg1"));
            }
            if found.len() == before {
                heartbeat_decrypts(&mut c.nodes, b, a, &label).await;
            }
            cleanup_nodes(&mut c.nodes).await;
        }
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}
