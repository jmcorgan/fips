//! Settlement intervals against steps of the wall clock.
//!
//! A link handshake's msg1 resend and its timeout read the interval clock,
//! the monotonic `Node::interval_ms`: a forward step of the wall clock does
//! not time out a dial or resend early, a backward one does not keep a
//! stalled handshake past its timeout, and the start and idle times shown
//! for a pending handshake stay on the wall clock. The restart gate measures
//! a heard peering's quiet time, and an unheard one's age, on the peer
//! clock, so a forward wall step does not let a msg1 replace a peering heard
//! just now, and a real frame refreshes the instant it measures from; the
//! promotion time shown for a peer stays on the wall clock. The memory of
//! the msg1s that promoted an unheard peering keeps its entries across a
//! forward wall step, and ages them out once the interval has passed on the
//! monotonic clock, across a backward one. The tests step the wall clock
//! with the thread-local test hook `crate::time::step_wall` and advance the
//! monotonic one with `crate::time::advance`, so they are safe beside other
//! tests.
//!
//! The per-peer TreeAnnounce rate limit reads the monotonic clock: a backward
//! wall step does not hold an announce whose interval has passed, and a peer
//! never sent one is not rate-limited at the clock's first instants.
//!
//! The node's tick is reproduced as `check_timeouts()` followed by
//! `drive_peer_timers(Node::interval_ms())`, the order the receive loop runs
//! them in.

use super::super::establish_chartests::craft_msg1_wire;
use super::super::link_setup_diag::{EPOCH, Established, established_from, packet, stop_transport};
use super::super::spanning_tree::{
    TestNode, cleanup_nodes, drain_all_packets, initiate_handshake, restarted_node,
};
use super::super::*;
use super::{loopback_node, tap, with_path};
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
    node.drive_peer_timers(Node::interval_ms()).await;
}

/// A node dialing a loopback tap that never answers, and the tap.
async fn dial_into_tap() -> (
    TestNode,
    tokio::sync::mpsc::UnboundedReceiver<ReceivedPacket>,
) {
    let mut tn = loopback_node(false).await;
    let other = loopback_node(false).await;
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
async fn a_forward_wall_clock_step_does_not_let_a_msg1_replace_a_loopback_peering_heard_just_now() {
    let mut nodes = vec![loopback_node(false).await, loopback_node(false).await];
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
async fn a_forward_wall_clock_step_does_not_let_a_msg1_replace_a_peering_heard_just_now() {
    let mut e = established_from(5, with_path(Config::new(), false)).await;
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

/// A peer never sent a TreeAnnounce may be sent one at any instant of the
/// rate limit's clock, its first instants included: on the monotonic clock
/// those are the first moments of the process.
#[test]
fn a_peer_never_sent_a_tree_announce_may_be_sent_one_at_the_clocks_first_instants() {
    let identity = PeerIdentity::from_pubkey(crate::Identity::generate().pubkey());
    let peer = crate::peer::ActivePeer::new(identity, LinkId::new(1), 1000);
    assert!(
        peer.last_tree_announce_sent_ms().is_none(),
        "precondition: a new peer has been sent no TreeAnnounce"
    );
    for now in [0, 499] {
        assert!(
            peer.can_send_tree_announce(now),
            "defect: a peer never sent a TreeAnnounce is rate-limited at {now} ms"
        );
    }
}

/// The indices of the attached child and of the root in a converged
/// two-node tree.
fn tree_roles(nodes: &[TestNode]) -> (usize, usize) {
    if nodes[0].node.tree_state().is_root() {
        (1, 0)
    } else {
        (0, 1)
    }
}

/// A TreeAnnounce whose interval has passed goes out after the wall clock
/// steps back an hour, as an NTP or RTC correction would.
#[tokio::test]
async fn a_backward_wall_step_does_not_hold_a_tree_announce_past_its_interval() {
    let configs = (0..2).map(|_| with_path(Config::new(), false)).collect();
    let mut nodes =
        super::super::spanning_tree::run_tree_test_with_configs(configs, &[(0, 1)]).await;
    let (s, r) = tree_roles(&nodes);
    let parent = *nodes[r].node.node_addr();
    let interval = nodes[s].node.config().node.tree.announce_min_interval_ms;
    crate::time::advance(Duration::from_millis(interval + 200));
    let sent = nodes[s].node.metrics().tree.sent.get();
    nodes[s]
        .node
        .send_tree_announce_to_peer(&parent)
        .await
        .expect("precondition: the announce is sent");
    assert_eq!(
        nodes[s].node.metrics().tree.sent.get(),
        sent + 1,
        "precondition: with the interval passed, the announce goes out at once"
    );
    crate::time::advance(Duration::from_millis(interval + 200));
    step_wall(-3_600_000);
    let sent = nodes[s].node.metrics().tree.sent.get();
    nodes[s]
        .node
        .send_tree_announce_to_peer(&parent)
        .await
        .expect("precondition: the announce is sent or held");
    nodes[s].node.send_pending_tree_announces().await;
    let pending = nodes[s]
        .node
        .get_peer(&parent)
        .expect("precondition: the child holds its parent")
        .has_pending_tree_announce();
    let sent_now = nodes[s].node.metrics().tree.sent.get();
    cleanup_nodes(&mut nodes).await;
    assert!(
        sent_now > sent && !pending,
        "defect: a TreeAnnounce whose interval has passed is held after a backward wall step: \
         sent {}, pending {pending}",
        sent_now - sent
    );
}

/// A node holding a pending inbound handshake leg with its msg2 stored: a
/// genuine msg1, stamped as intake stamps a received packet, whose msg2
/// could not be sent, because the transport is on an interface no host has.
/// The leg stays for the initiator's resend, as after an interface flap.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn pending_inbound_leg_holding_its_msg2() -> (Node, LinkId) {
    use crate::config::EthernetConfig;
    use crate::proto::fmp::wire::build_msg1;
    use crate::transport::TransportHandle;
    use crate::transport::ethernet::EthernetTransport;

    let mut node = make_node_with(with_path(Config::new(), false));
    let initiator = make_node_with(with_path(Config::new(), false));
    let transport_id = TransportId::new(1);
    node.supervisor.state = NodeState::Running;
    let config = EthernetConfig {
        interface: "fips-absent-x0".to_string(),
        ethertype: None,
        mtu: None,
        recv_buf_size: None,
        send_buf_size: None,
        listen: Some(true),
        announce: Some(false),
        auto_connect: None,
        accept_connections: Some(true),
        beacon_interval_secs: None,
        optional: Some(true),
        role: crate::config::TransportRole::default(),
    };
    let (tx, _rx) = crate::transport::packet_channel(8);
    let mut eth = EthernetTransport::new(transport_id, Some("lab".into()), config, tx);
    eth.start_async()
        .await
        .expect("precondition: an absent interface is not a start failure");
    node.transports
        .insert(transport_id, TransportHandle::Ethernet(eth));

    let target = PeerIdentity::from_pubkey_full(node.identity().pubkey_full());
    let mut leg = outbound_leg(LinkId::new(1), target, 1000);
    let noise_msg1 = leg
        .start_handshake(
            initiator.identity().keypair(),
            initiator.startup_epoch(),
            LegStamp::at(1000),
        )
        .expect("precondition: the initiator writes its msg1");
    let packet = ReceivedPacket::new(
        transport_id,
        TransportAddr::from_string("aa:bb:cc:dd:ee:ff"),
        build_msg1(SessionIndex::new(7), &noise_msg1),
    );
    node.handle_msg1(packet).await;
    let link = node
        .connections()
        .map(|(link, _)| *link)
        .next()
        .expect("precondition: the msg1 left a pending inbound leg");
    assert!(
        node.peer_machines[&link].conn_handshake_msg2().is_some(),
        "precondition: the pending leg holds its msg2"
    );
    (node, link)
}

/// The handshake timeout plus a second.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn past_the_handshake_timeout(node: &Node) -> u64 {
    node.config().node.rate_limit.handshake_timeout_secs * 1000 + 1000
}

/// An inbound leg holding a stored msg2 is reaped once it has been idle past
/// the handshake timeout, with both clocks moved by that much: the leg's
/// timeout stamp and the reaping's reading are on one clock.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn an_inbound_leg_holding_a_stored_msg2_is_reaped_within_the_handshake_timeout() {
    let (mut node, link) = pending_inbound_leg_holding_its_msg2().await;
    node.check_timeouts().await;
    assert!(
        node.peer_machines.contains_key(&link),
        "precondition: a fresh inbound leg is not reaped"
    );
    let past = past_the_handshake_timeout(&node);
    step_wall(i64::try_from(past).expect("precondition: the timeout fits an i64"));
    crate::time::advance(Duration::from_millis(past));
    node.check_timeouts().await;
    assert!(
        !node.peer_machines.contains_key(&link),
        "defect: an inbound leg idle past the handshake timeout was not reaped"
    );
}

/// A stalled inbound handshake is kept across a backward step of the wall
/// clock while it is inside its timeout, and reaped once the timeout has
/// passed on the monotonic clock, for all the step.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn a_stalled_inbound_handshake_is_reaped_at_its_timeout_across_a_backward_wall_step() {
    let (mut node, link) = pending_inbound_leg_holding_its_msg2().await;
    step_wall(-3_600_000);
    node.check_timeouts().await;
    assert!(
        node.peer_machines.contains_key(&link),
        "defect: a stalled inbound handshake inside its timeout was reaped after a backward wall step"
    );
    crate::time::advance(Duration::from_millis(past_the_handshake_timeout(&node)));
    node.check_timeouts().await;
    assert!(
        !node.peer_machines.contains_key(&link),
        "defect: a stalled inbound handshake past its timeout was kept after a backward wall step"
    );
}

/// The start and idle times `show_connections` reports for a pending
/// handshake are wall-clock readings: they do not move when only the
/// monotonic clock does.
#[tokio::test]
async fn a_pending_handshakes_shown_start_and_idle_do_not_move_with_the_monotonic_clock() {
    let (mut tn, _tap) = dial_into_tap().await;
    let shown = |node: &Node| {
        let v = crate::control::queries::show_connections(node);
        let c = &v["connections"][0];
        (c["started_at_ms"].as_u64(), c["idle_ms"].as_u64())
    };
    let (first_start, _) = shown(&tn.node);
    let first_start = first_start.expect("precondition: the dial is shown with a start time");
    crate::time::advance(Duration::from_secs(5));
    let (start, idle) = shown(&tn.node);
    let wall = crate::time::wall_ms();
    cleanup_nodes(std::slice::from_mut(&mut tn)).await;
    let (start, idle) = (
        start.expect("precondition: the dial is still shown"),
        idle.expect("precondition: the dial is shown with an idle time"),
    );
    assert!(
        start == first_start && wall.abs_diff(start) < 60_000 && idle < 1000,
        "defect: the shown start {start} (first {first_start}, wall {wall}) or idle {idle} ms \
         moved with the monotonic clock"
    );
}

/// The restart interval, `EPOCH_RESTART_MIN_INTERVAL_SECS`, plus a second.
/// A copy of the constant's value, which is private to the handshake
/// handler.
const PAST_THE_RESTART_INTERVAL: Duration = Duration::from_secs(15 + 1);

/// Node 0 dials node 1 over loopback and frames flow, so node 1 holds node 0
/// heard. Returns the nodes and node 0's address, link and index at node 1.
async fn heard_loopback_peering() -> (Vec<TestNode>, NodeAddr, LinkId, Option<SessionIndex>) {
    let mut nodes = vec![loopback_node(false).await, loopback_node(false).await];
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let a = *nodes[0].node.node_addr();
    let p = nodes[1]
        .node
        .get_peer(&a)
        .expect("precondition: node 1 holds node 0");
    assert!(p.is_heard(), "precondition: node 1 heard node 0's frames");
    let (link, index) = (p.link_id(), p.our_index());
    (nodes, a, link, index)
}

/// Node 0 restarts and sends node 1 its msg1, at a new epoch; node 1
/// handles it. Returns node 0's peering at node 1 afterwards.
async fn restart_msg1(
    nodes: &mut [TestNode],
    a: &NodeAddr,
) -> Option<(LinkId, Option<SessionIndex>)> {
    let restarted = restarted_node(&nodes[0], with_path(Config::new(), false));
    let mut old = std::mem::replace(&mut nodes[0], restarted);
    cleanup_nodes(std::slice::from_mut(&mut old)).await;
    initiate_handshake(nodes, 0, 1).await;
    let mut m = nodes[1]
        .packet_rx
        .try_recv()
        .expect("precondition: the restarted node's msg1 is queued at node 1");
    m.timestamp_ms = Node::now_ms();
    nodes[1].node.handle_msg1(m).await;
    nodes[1]
        .node
        .get_peer(a)
        .map(|p| (p.link_id(), p.our_index()))
}

/// A heard peering whose last frame is older than the restart interval, by
/// the monotonic clock, is replaced by the peer's restart msg1. Nothing has
/// stamped the restart dampener, whose clock the test cannot advance.
#[tokio::test]
async fn a_heard_peering_quiet_past_the_restart_interval_is_replaced_by_a_restart_msg1() {
    let (mut nodes, a, link, index) = heard_loopback_peering().await;
    crate::time::advance(PAST_THE_RESTART_INTERVAL);
    let after = restart_msg1(&mut nodes, &a).await;
    cleanup_nodes(&mut nodes).await;
    assert!(
        after.is_some_and(|p| p != (link, index)),
        "defect: a peering quiet past the restart interval was not replaced by a restart msg1: {after:?}"
    );
}

/// A peering promoted, and last heard, long ago, then heard just now, is
/// not replaced by a restart msg1: the frame refreshes the instant the gate
/// measures quiet from.
#[tokio::test]
async fn a_peering_heard_just_now_after_an_old_promotion_is_not_replaced_by_a_restart_msg1() {
    let (mut nodes, a, link, index) = heard_loopback_peering().await;
    let b = *nodes[1].node.node_addr();
    {
        let p = nodes[1]
            .node
            .get_peer_mut(&a)
            .expect("precondition: node 1 holds node 0");
        p.test_backdate_promoted(Duration::from_secs(60));
        p.test_backdate_heard(Duration::from_secs(60));
    }
    // One real frame from node 0, past its TreeAnnounce interval.
    crate::time::advance(Duration::from_millis(700));
    nodes[0]
        .node
        .send_tree_announce_to_peer(&b)
        .await
        .expect("precondition: node 0 sends node 1 a TreeAnnounce");
    drain_all_packets(&mut nodes, false).await;
    assert!(
        nodes[1]
            .node
            .get_peer(&a)
            .map(|p| p.link_stats().packets_recv)
            > Some(0),
        "precondition: node 1 received node 0's frame"
    );
    let after = restart_msg1(&mut nodes, &a).await;
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        after,
        Some((link, index)),
        "defect: a peering heard just now after an old promotion was replaced by a restart msg1"
    );
}

/// A peering promoted on a msg1 just now, and not yet heard from, is not
/// replaced by a second msg1 after a forward step of the wall clock with no
/// time passing: its age is measured on the monotonic clock.
#[tokio::test]
async fn a_forward_wall_clock_step_does_not_let_a_msg1_replace_an_unheard_peering_promoted_just_now()
 {
    let mut nodes = vec![loopback_node(false).await, loopback_node(false).await];
    let a = *nodes[0].node.node_addr();
    initiate_handshake(&mut nodes, 0, 1).await;
    let mut first = nodes[1]
        .packet_rx
        .try_recv()
        .expect("precondition: node 0's msg1 is queued at node 1");
    first.timestamp_ms = Node::now_ms();
    nodes[1].node.handle_msg1(first).await;
    let promoted = {
        let p = nodes[1]
            .node
            .get_peer(&a)
            .expect("precondition: node 1 promoted node 0");
        assert!(
            !p.is_heard(),
            "precondition: node 1 has heard nothing from node 0"
        );
        (p.link_id(), p.our_index())
    };

    step_wall(3_600_000);
    initiate_handshake(&mut nodes, 0, 1).await;
    let mut second = nodes[1]
        .packet_rx
        .try_recv()
        .expect("precondition: node 0's second msg1 is queued at node 1");
    second.timestamp_ms = Node::now_ms();
    nodes[1].node.handle_msg1(second).await;
    let after = nodes[1]
        .node
        .get_peer(&a)
        .map(|p| (p.link_id(), p.our_index()));
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        after,
        Some(promoted),
        "defect: an unheard peering promoted just now was replaced because the wall clock stepped forward"
    );
}

/// The promotion time `show_peers` reports is a wall-clock reading: a peer
/// promoted after a forward step of the wall clock is shown promoted at the
/// stepped time.
#[tokio::test]
async fn a_shown_authenticated_at_follows_a_wall_step() {
    let mut nodes = vec![loopback_node(false).await, loopback_node(false).await];
    step_wall(3_600_000);
    initiate_handshake(&mut nodes, 0, 1).await;
    let mut m = nodes[1]
        .packet_rx
        .try_recv()
        .expect("precondition: node 0's msg1 is queued at node 1");
    m.timestamp_ms = Node::now_ms();
    nodes[1].node.handle_msg1(m).await;
    let wall = crate::time::wall_ms();
    let shown = crate::control::queries::show_peers(&nodes[1].node)["peers"]
        .as_array()
        .and_then(|peers| {
            peers
                .iter()
                .find(|p| p["npub"].as_str() == Some(nodes[0].node.npub().as_str()))
                .and_then(|p| p["authenticated_at_ms"].as_u64())
        });
    cleanup_nodes(&mut nodes).await;
    let shown = shown.expect("precondition: node 1 shows node 0 with a promotion time");
    assert!(
        wall.abs_diff(shown) < 60_000,
        "defect: the shown promotion time {shown} is not the stepped wall clock {wall}"
    );
}

/// A genuine msg1 from `initiator` to `responder`. A copy of
/// `handshake::genuine_msg1`, which is private.
fn genuine_msg1(initiator: &Node, responder: &Node) -> Vec<u8> {
    use crate::proto::fmp::wire::build_msg1;

    let responder_identity = PeerIdentity::from_pubkey_full(responder.identity().pubkey_full());
    let mut machine = outbound_leg(LinkId::new(9_999), responder_identity, 1_000);
    let noise_msg1 = machine
        .start_handshake(
            initiator.identity().keypair(),
            initiator.startup_epoch(),
            LegStamp::at(1_000),
        )
        .expect("precondition: the initiator side of a real msg1 builds");
    build_msg1(SessionIndex::new(7), &noise_msg1)
}

/// Deliver `msg1` to `node` from `addr` at `at_ms`, and report whether it
/// promoted a new peering for `peer`. A copy of `handshake::promotes`, which
/// is private.
async fn promotes(
    node: &mut Node,
    peer: &NodeAddr,
    addr: &TransportAddr,
    msg1: Vec<u8>,
    at_ms: u64,
) -> bool {
    let link = |node: &Node| node.get_peer(peer).map(|p| p.link_id());
    let before = link(node);
    node.handle_msg1(ReceivedPacket::with_timestamp(
        TransportId::new(1),
        addr.clone(),
        msg1,
        at_ms,
    ))
    .await;
    let after = link(node);
    after.is_some() && after != before
}

/// Two distinct captures promote in turn, the second once the first's
/// phantom has the minimum age and after a forward step of the wall clock.
/// The replay memory holds both ephemerals: a wall step is not time
/// passing.
#[tokio::test]
async fn a_forward_wall_step_does_not_empty_the_replay_memory() {
    let mut node = make_node_with(with_path(Config::new(), false));
    let initiator = make_node_with(with_path(Config::new(), false));
    let peer = *PeerIdentity::from_pubkey_full(initiator.identity().pubkey_full()).node_addr();
    let a = genuine_msg1(&initiator, &node);
    let b = genuine_msg1(&initiator, &node);
    assert!(
        promotes(
            &mut node,
            &peer,
            &TransportAddr::from_string("127.0.0.1:41101"),
            a,
            Node::now_ms(),
        )
        .await,
        "precondition: capture A promoted a phantom"
    );
    assert_eq!(
        node.replayed_msg1_count(&peer),
        1,
        "precondition: A's ephemeral is remembered"
    );
    crate::time::advance(Duration::from_millis(1_100));
    step_wall(3_600_000);
    assert!(
        promotes(
            &mut node,
            &peer,
            &TransportAddr::from_string("127.0.0.1:41103"),
            b,
            Node::now_ms(),
        )
        .await,
        "precondition: capture B replaced A's phantom"
    );
    assert_eq!(
        node.replayed_msg1_count(&peer),
        2,
        "defect: a forward wall step emptied the replay memory"
    );
}

/// A capture's entry in the replay memory ages out once the interval has
/// passed on the monotonic clock, even when the wall clock has stepped back
/// meanwhile: a second capture promoting after that leaves only its own
/// ephemeral remembered.
#[tokio::test]
async fn a_replay_memory_entry_ages_out_after_the_interval_across_a_backward_wall_step() {
    let mut node = make_node_with(with_path(Config::new(), false));
    let initiator = make_node_with(with_path(Config::new(), false));
    let peer = *PeerIdentity::from_pubkey_full(initiator.identity().pubkey_full()).node_addr();
    let a = genuine_msg1(&initiator, &node);
    let b = genuine_msg1(&initiator, &node);
    assert!(
        promotes(
            &mut node,
            &peer,
            &TransportAddr::from_string("127.0.0.1:41105"),
            a,
            Node::now_ms(),
        )
        .await,
        "precondition: capture A promoted a phantom"
    );
    assert_eq!(
        node.replayed_msg1_count(&peer),
        1,
        "precondition: A's ephemeral is remembered"
    );
    step_wall(-3_600_000);
    crate::time::advance(PAST_THE_RESTART_INTERVAL);
    assert!(
        promotes(
            &mut node,
            &peer,
            &TransportAddr::from_string("127.0.0.1:41107"),
            b,
            Node::now_ms(),
        )
        .await,
        "precondition: capture B replaced A's phantom"
    );
    assert_eq!(
        node.replayed_msg1_count(&peer),
        1,
        "defect: A's entry outlived the interval on the monotonic clock"
    );
}
