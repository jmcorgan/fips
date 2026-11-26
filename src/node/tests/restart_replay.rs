//! A captured msg1 of a held peer from an earlier run of that peer (another
//! startup epoch), replayed to the node against the peer's live link.
//!
//! The capture is a genuine msg1 of the peer's identity at an epoch the
//! peering does not carry, built and then dropped with its handshake state,
//! so no frame can ever follow it: what a replayer who recorded the peer's
//! dial before its last restart holds. It reaches B from a tap address. The
//! pair is the one of `roam_redial`: two loopback nodes on a frozen clock,
//! every receive-loop timer run in its order, A having dialed B.
//!
//! The link is live throughout: B's link-dead timeout (30 s) never passes
//! without a frame from A, and A's next heartbeat after the replay is one of
//! the same session. A replay must leave B's peering with A, its link and its
//! index, as they were.
//!
//! A replay that passes the restart gates is held as a leg beside the
//! peering, which only a frame under the leg's session replaces, so the
//! memory of restart legs bounds what B answers: a copy from another
//! address draws nothing, a copy from the leg's own address draws the stored
//! msg2, and at most eight distinct captures are answered within 15 s. A
//! genuine restart of A, rebuilt from its identity at a new epoch, is
//! replaced at its first frame, and a replay before it, which stamped
//! nothing, does not dampen it.

use super::establish_chartests::craft_msg1_wire;
use super::rekey_parity::stale_session;
use super::roam_redial::{Multipath, Pair, phase, since};
use super::settle::with_path;
use super::spanning_tree::{cleanup_nodes, loopback_tap, restarted_node};
use super::*;
use crate::proto::fmp::wire::{PHASE_MSG1, PHASE_MSG2};
use tokio::sync::mpsc::UnboundedReceiver;

/// An epoch A's current run does not carry: A's run before its last restart.
const EARLIER_EPOCH: [u8; 8] = [0x5A; 8];

/// A capture of a msg1 of A's identity to B at `epoch`, sender index
/// `sidx`: genuine, with its handshake state dropped.
fn capture(pair: &Pair, epoch: [u8; 8], sidx: u32) -> Vec<u8> {
    craft_msg1_wire(
        &pair.nodes[1].node,
        pair.nodes[0].node.identity(),
        epoch,
        SessionIndex::new(sidx),
        Node::now_ms(),
    )
}

/// Hand `data` to B as a msg1 from a fresh tap address, then hand over what
/// follows. The tap stays open, so B's answer there is delivered and lost.
async fn replay(pair: &mut Pair, data: Vec<u8>) -> UnboundedReceiver<ReceivedPacket> {
    let tid = pair.nodes[1].transport_id;
    let (from, rx) = loopback_tap(tid);
    replay_at(pair, &from, data).await;
    rx
}

/// Hand `data` to B as a msg1 from `from`, then hand over what follows.
async fn replay_at(pair: &mut Pair, from: &TransportAddr, data: Vec<u8>) {
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

/// How many msg2s reached a tap through `rx` since the last call.
fn msg2s(rx: &mut UnboundedReceiver<ReceivedPacket>) -> usize {
    std::iter::from_fn(|| rx.try_recv().ok())
        .filter(|p| phase(p) == Some(PHASE_MSG2))
        .count()
}

/// B's view of A once A's frames have not reached B for 16 s: past the
/// heard floor of a restart, inside B's 30 s link-dead timeout. The cut is
/// left on, so A's frames keep being lost until the caller lifts it.
async fn quiet_for_16_s(pair: &mut Pair) {
    pair.cut_b(true);
    pair.run(16).await;
    assert!(pair.b_holds_a(), "precondition: B still holds A");
}

/// A's genuine restart: A, rebuilt from its identity at a new startup
/// epoch at the same address, the old run gone and the cut on what reaches
/// B lifted, dials B. Returns A's new epoch. The caller hands the dial
/// over.
async fn restart_a(pair: &mut Pair) -> [u8; 8] {
    let restarted = restarted_node(&pair.nodes[0], with_path(Config::new(), true));
    let mut old = std::mem::replace(&mut pair.nodes[0], restarted);
    cleanup_nodes(std::slice::from_mut(&mut old)).await;
    pair.cut_b(false);
    pair.nodes[0].node.supervisor.state = crate::node::NodeState::Running;
    let id = PeerIdentity::from_pubkey_full(pair.nodes[1].node.identity().pubkey_full());
    let (tid, b_addr) = (pair.nodes[0].transport_id, pair.nodes[1].addr.clone());
    pair.nodes[0]
        .node
        .initiate_connection(tid, b_addr, id)
        .await
        .expect("precondition: the restarted A's dial starts");
    pair.nodes[0].node.startup_epoch()
}

/// Hand each packet queued at `pair.nodes[at]` of the FMP phase `want` to
/// that node, and drop the rest. How many it handled.
async fn hand(pair: &mut Pair, at: usize, want: u8) -> usize {
    let tn = &mut pair.nodes[at];
    let queued: Vec<ReceivedPacket> = std::iter::from_fn(|| tn.packet_rx.try_recv().ok()).collect();
    let mut n = 0;
    for packet in queued {
        if phase(&packet) != Some(want) {
            continue;
        }
        n += 1;
        match want {
            PHASE_MSG1 => tn.node.handle_msg1(packet).await,
            _ => tn.node.handle_msg2(packet).await,
        }
    }
    n
}

/// B's link and index for A, if B holds A.
fn b_session(pair: &Pair) -> Option<(LinkId, Option<SessionIndex>)> {
    pair.nodes[1]
        .node
        .get_peer(&pair.a_addr())
        .map(|p| (p.link_id(), p.our_index()))
}

/// Healthy path: on a link heartbeating at the default 10 s, a capture
/// replayed at every 0.5 s phase of one heartbeat cycle is refused, and the
/// peering stands.
#[tokio::test]
async fn an_earlier_epoch_msg1_replayed_at_every_phase_of_a_heartbeating_link_leaves_the_peering() {
    let mut pair = Pair::new(Multipath::On, true).await;
    pair.run(60).await;
    let before = b_session(&pair);
    let data = capture(&pair, EARLIER_EPOCH, 0xC0FFEE);
    let mut taps = Vec::new();
    for n in 0..20 {
        taps.push(replay(&mut pair, data.clone()).await);
        assert_eq!(
            b_session(&pair),
            before,
            "defect: replay {n} moved B's peering with A"
        );
        pair.step().await;
    }
    assert!(
        pair.heartbeat(0, 1).await && pair.heartbeat(1, 0).await,
        "defect: the session no longer carries heartbeats after the replays"
    );
    cleanup_nodes(&mut pair.nodes).await;
}

/// A live link whose peer has not been heard for 16 s (one or two of A's
/// heartbeats lost, well inside B's 30 s link-dead timeout): a capture
/// replayed then must leave the peering, and A's next heartbeat must
/// authenticate at B on the same session.
#[tokio::test]
async fn an_earlier_epoch_msg1_replayed_while_the_peers_heartbeats_are_lost_for_16_s_leaves_the_live_peering()
 {
    let mut pair = Pair::new(Multipath::On, true).await;
    pair.run(60).await;
    let before = b_session(&pair);
    assert!(before.is_some(), "precondition: B holds A");
    let data = capture(&pair, EARLIER_EPOCH, 0xC0FFEE);
    // Lose what A sends to B for 16 s.
    pair.cut_b(true);
    pair.run(16).await;
    assert_eq!(
        b_session(&pair),
        before,
        "precondition: B still holds A's link inside its link-dead timeout"
    );
    pair.cut_b(false);
    let _tap = replay(&mut pair, data).await;
    let after = b_session(&pair);
    let hb = pair.heartbeat(0, 1).await;
    assert!(
        after == before && hb,
        "defect: a replayed earlier-epoch msg1 tore down B's live peering with A \
         before any frame authenticated under new keys: before {before:?} after \
         {after:?}, A's next heartbeat authenticates at B: {hb}"
    );
    cleanup_nodes(&mut pair.nodes).await;
}

/// Control for the case above: the same 16 s loss with no replay leaves the
/// peering, and A's next heartbeat authenticates at B, so the loss alone
/// does not end the link.
#[tokio::test]
async fn sixteen_seconds_of_lost_heartbeats_with_no_replay_leave_the_live_peering() {
    let mut pair = Pair::new(Multipath::On, true).await;
    pair.run(60).await;
    let before = b_session(&pair);
    pair.cut_b(true);
    pair.run(16).await;
    pair.cut_b(false);
    let after = b_session(&pair);
    let hb = pair.heartbeat(0, 1).await;
    assert!(
        before.is_some() && after == before && hb,
        "precondition: before {before:?} after {after:?} heartbeat {hb}"
    );
    cleanup_nodes(&mut pair.nodes).await;
}

/// A genuine restart of A within 15 s of a replayed restart msg1 of A's
/// earlier run, from a tap address: the replay was held as a leg and
/// stamped nothing, so the genuine restart is held as a leg in its place and
/// A's first frame under it re-peers A at B, on A's new epoch, with frames
/// authenticating both ways.
#[tokio::test]
async fn a_genuine_restart_within_15_s_of_a_replayed_one_re_peers_at_its_first_frame() {
    let mut pair = Pair::new(Multipath::On, true).await;
    pair.run(60).await;
    let a = pair.a_addr();
    let data = capture(&pair, EARLIER_EPOCH, 0xC0FFEE);
    quiet_for_16_s(&mut pair).await;
    let _tap = replay(&mut pair, data).await;
    assert!(
        pair.nodes[1].node.redials.of(&a).is_some(),
        "precondition: the replay is held as a leg"
    );
    // A's process dies with its frames still lost, and a new run of it
    // dials B 5 s after the replay.
    pair.run(5).await;
    let epoch = restart_a(&mut pair).await;
    pair.pump().await;
    let held = pair.nodes[1]
        .node
        .get_peer(&a)
        .and_then(|p| p.remote_epoch());
    let hb = pair.heartbeat(0, 1).await && pair.heartbeat(1, 0).await;
    cleanup_nodes(&mut pair.nodes).await;
    assert!(
        held == Some(epoch) && hb,
        "defect: a genuine restart 5 s after a replayed one did not re-peer at its first frame: \
         B holds A at epoch {held:?} (A's new epoch {epoch:?}), heartbeats both ways {hb}"
    );
}

/// The same replayed restart msg1 sent again 5 s later from another
/// address: its ephemeral is in the memory of restart legs, so B sends
/// nothing there.
#[tokio::test]
async fn a_replayed_restart_msg1_sent_again_within_15_s_from_another_address_draws_no_second_msg2()
{
    let mut pair = Pair::new(Multipath::On, true).await;
    pair.run(60).await;
    let data = capture(&pair, EARLIER_EPOCH, 0xC0FFEE);
    quiet_for_16_s(&mut pair).await;
    let mut first = replay(&mut pair, data.clone()).await;
    pair.run(5).await;
    let mut second = replay(&mut pair, data).await;
    let (one, two) = (msg2s(&mut first), msg2s(&mut second));
    cleanup_nodes(&mut pair.nodes).await;
    assert!(
        one == 1 && two == 0,
        "defect: the first address drew {one} msg2s, the second {two}"
    );
}

/// The same replayed restart msg1 sent again 5 s later from its own
/// address is a copy of the pending leg's msg1: it draws the leg's stored
/// msg2 again and nothing new.
#[tokio::test]
async fn a_replayed_restart_msg1_sent_again_from_its_own_address_draws_only_the_stored_msg2() {
    let mut pair = Pair::new(Multipath::On, true).await;
    pair.run(60).await;
    let a = pair.a_addr();
    let data = capture(&pair, EARLIER_EPOCH, 0xC0FFEE);
    quiet_for_16_s(&mut pair).await;
    let (from, mut rx) = loopback_tap(pair.nodes[1].transport_id);
    replay_at(&mut pair, &from, data.clone()).await;
    let leg = pair.nodes[1].node.redials.of(&a).map(|r| r.link);
    let first: Vec<Vec<u8>> = std::iter::from_fn(|| rx.try_recv().ok())
        .filter(|p| phase(p) == Some(PHASE_MSG2))
        .map(|p| p.data)
        .collect();
    pair.run(5).await;
    replay_at(&mut pair, &from, data).await;
    let again: Vec<Vec<u8>> = std::iter::from_fn(|| rx.try_recv().ok())
        .filter(|p| phase(p) == Some(PHASE_MSG2))
        .map(|p| p.data)
        .collect();
    let after = pair.nodes[1].node.redials.of(&a).map(|r| r.link);
    cleanup_nodes(&mut pair.nodes).await;
    assert!(
        leg.is_some() && first.len() == 1,
        "precondition: the replay is held as a leg and answered once"
    );
    assert!(
        again == first && after == leg,
        "defect: the copy from the leg's own address drew {} msg2s (the stored one: {}), leg {leg:?} then {after:?}",
        again.len(),
        again == first
    );
}

/// Nine distinct replayed restart msg1s, each from its own address a
/// second after the one before, all inside 15 s: each is held as a leg in
/// place of the one before, and the memory of restart legs answers eight
/// and refuses the ninth.
#[tokio::test]
async fn nine_distinct_replayed_restart_msg1s_within_15_s_draw_at_most_eight_msg2s() {
    let mut pair = Pair::new(Multipath::On, true).await;
    pair.run(60).await;
    quiet_for_16_s(&mut pair).await;
    let was = pair.nodes[1].node.stats().handshake.snapshot();
    let mut taps = Vec::new();
    for n in 0..9u32 {
        let data = capture(&pair, EARLIER_EPOCH, 0xC0FF00 + n);
        taps.push(replay(&mut pair, data).await);
        pair.run(1).await;
    }
    let drawn: usize = taps.iter_mut().map(msg2s).sum();
    let r = since(&pair.nodes[1].node.stats().handshake.snapshot(), &was);
    let held = pair.b_holds_a();
    cleanup_nodes(&mut pair.nodes).await;
    assert!(held, "precondition: B still holds A");
    assert!(
        drawn == 8 && r.restarts_held == 8 && r.restarts_proven == 0,
        "defect: {drawn} msg2s, {r:?}"
    );
}

/// A genuine restart of A after its frames have been lost for 16 s: B
/// answers A's new run's msg1 into a leg and keeps A's old peering, its
/// link, index and end-to-end session, through A's reading of the answer;
/// A's first frame under the new session replaces the peering as a restart,
/// on A's new epoch, ending the end-to-end session of A's previous run.
#[tokio::test]
async fn a_genuine_restart_replaces_the_peering_at_its_first_frame() {
    let mut pair = Pair::new(Multipath::On, true).await;
    pair.run(60).await;
    let a = pair.a_addr();
    quiet_for_16_s(&mut pair).await;
    stale_session(&mut pair.nodes[1].node, a);
    let before = b_session(&pair);
    let open = pair.nodes[1].node.get_session(&a).is_some();
    let epoch = restart_a(&mut pair).await;
    let was = pair.nodes[1].node.stats().handshake.snapshot();
    let msg1s = hand(&mut pair, 1, PHASE_MSG1).await;
    let at_msg1 = (
        b_session(&pair),
        pair.nodes[1].node.get_session(&a).is_some(),
    );
    let msg2s = hand(&mut pair, 0, PHASE_MSG2).await;
    let at_msg2 = (
        b_session(&pair),
        pair.nodes[1].node.get_session(&a).is_some(),
    );
    pair.pump().await;
    let after = b_session(&pair);
    let held = pair.nodes[1]
        .node
        .get_peer(&a)
        .and_then(|p| p.remote_epoch());
    let session = pair.nodes[1].node.get_session(&a).is_some();
    let r = since(&pair.nodes[1].node.stats().handshake.snapshot(), &was);
    let hb = pair.heartbeat(0, 1).await && pair.heartbeat(1, 0).await;
    cleanup_nodes(&mut pair.nodes).await;
    assert!(
        msg1s == 1 && msg2s == 1 && before.is_some() && open,
        "precondition: B holds A with an end-to-end session, and read A's msg1, and A B's answer \
         ({open}, {msg1s}, {msg2s})"
    );
    assert!(
        at_msg1 == (before, true) && at_msg2 == (before, true),
        "defect: B left A's old peering or its end-to-end session before A's first frame: \
         before {before:?}, at the msg1 {at_msg1:?}, at A's msg2 {at_msg2:?}"
    );
    assert!(
        after != before && held == Some(epoch) && !session && r.restarts_proven == 1 && hb,
        "defect: A's first frame did not replace the peering as a restart: before {before:?} after \
         {after:?}, epoch {held:?} (A's {epoch:?}), end-to-end session kept {session}, {r:?}, \
         heartbeats both ways {hb}"
    );
}

/// The pair `node`'s link `id` is set up at, if `node` has the link.
fn pair_of(node: &Node, id: LinkId) -> Option<(TransportId, TransportAddr)> {
    node.links
        .iter()
        .find(|(l, _)| **l == id)
        .map(|(_, link)| (link.transport_id(), link.remote_addr().clone()))
}

/// A replayed restart msg1 of A's earlier run from A's own address, the
/// pair B holds A's link at, is held as a leg whose newer link shares that
/// pair. A, still running, then starts a rekey, and its msg1 reaches B from
/// the shared pair: B judges it on the held link and answers it as a rekey,
/// a responder pending for A, leaving the restart leg as it was.
#[tokio::test]
async fn a_rekey_msg1_at_the_pair_a_restart_leg_shares_with_the_held_link_is_answered_on_the_held_link()
 {
    let mut pair = Pair::new(Multipath::On, true).await;
    pair.run(60).await;
    let a = pair.a_addr();
    let b = pair.b_addr();
    let a_at = pair.nodes[0].addr.clone();
    let data = capture(&pair, EARLIER_EPOCH, 0xC0FFEE);
    quiet_for_16_s(&mut pair).await;
    replay_at(&mut pair, &a_at, data).await;
    pair.cut_b(false);
    let node = &pair.nodes[1].node;
    let (Some(leg), Some(held)) = (
        node.redials.of(&a).map(|r| r.link),
        node.get_peer(&a).map(|p| p.link_id()),
    ) else {
        panic!("precondition: B holds A beside a pending restart leg");
    };
    let shared = pair_of(node, held);
    assert!(
        shared.is_some() && shared == pair_of(node, leg),
        "precondition: the leg is at the held link's pair"
    );
    // A's session aged past its rekey trigger, and B's end past the floor
    // below which a msg1 on the link is a duplicate.
    let after = pair.nodes[0].node.config().node.rekey.after_secs;
    let age = Duration::from_secs(after + crate::node::REKEY_JITTER_SECS as u64 + 1);
    let floor = fips_core::proto::rekey::DEPLOYED_SESSION_FLOOR + Duration::from_secs(5);
    pair.nodes[0]
        .node
        .get_peer_mut(&b)
        .expect("precondition: A holds B")
        .test_backdate_session_established(age);
    pair.nodes[1]
        .node
        .get_peer_mut(&a)
        .expect("precondition: B holds A")
        .test_backdate_session_established(floor);
    let was = pair.nodes[1].node.stats().handshake.snapshot();
    pair.nodes[0].node.poll_link_rekeys().await;
    let msg1s = hand(&mut pair, 1, PHASE_MSG1).await;
    let node = &pair.nodes[1].node;
    let d = since(&node.stats().handshake.snapshot(), &was);
    let pending = node.get_peer(&a).and_then(|p| p.pending_role());
    let left = node.redials.of(&a).map(|r| r.link);
    cleanup_nodes(&mut pair.nodes).await;
    assert_eq!(msg1s, 1, "precondition: A's rekey msg1 reached B");
    // Off the held link, the msg1 is a redial, held back by the pending
    // leg's slot, or refused as off the link; on it, the rekey machine
    // answers it, or refuses it for its own rekey in flight.
    let off = d.redial_held + d.redial_seen + d.redial_dampened + d.redials + d.off_link;
    let rekeyed = pending == Some(fips_core::proto::rekey::Role::Responder)
        || d.rekey_tiebreak + d.rekey_pending > 0;
    assert!(
        off == 0 && rekeyed,
        "defect: A's rekey msg1 at the pair a pending restart leg shares with the held link was not judged on the held link: counters moved by {d:?}, pending {pending:?}"
    );
    assert_eq!(left, Some(leg), "the restart leg is left as it was");
}
