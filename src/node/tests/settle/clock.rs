//! Settlement intervals against steps of the wall clock.
//!
//! A link handshake's msg1 resend and its timeout read the interval clock,
//! the monotonic `Node::interval_ms`: a forward step of the wall clock does
//! not time out a dial or resend early, a backward one does not keep a
//! stalled handshake past its timeout, and the start and idle times shown
//! for a pending handshake stay on the wall clock. The tests step the wall clock
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

use super::super::spanning_tree::{TestNode, cleanup_nodes};
use super::super::*;
use super::{loopback_node, tap, with_path};
use crate::transport::TransportId;

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
        .initiate_connection(tid, dialled, Some(id))
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
