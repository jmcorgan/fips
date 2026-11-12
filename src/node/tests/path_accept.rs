//! The multipath draft's switchover rules at the node, one test per
//! case: a carrier loss, a failure in one direction, a standby
//! starved behind the active path's load, a preferred cable, garbage on a
//! standby or a second transport, two transports to a peer with one, a
//! switch during a rekey, the loss of an interface, a `PathClose` from
//! either end, and a backup wire. Each test runs two loopback nodes with multipath
//! on, moves time only by `crate::time::advance`, and hands frames between
//! the nodes itself, so it controls what each end has seen when it asserts.

use super::paths::{
    active_of, capable_at, carrier, enabled, excessive, exchange, hand, loopback_mut, phase, probe,
    same_transport, second_transport, state_at, t2, take_packets, two_transports,
};
use super::spanning_tree::{TestNode, cleanup_nodes, delay_loopback_delivery};
use super::*;
use crate::config::TransportRole;
use crate::peer::PathState;
use crate::proto::fmp::wire::{PHASE_MSG1, PHASE_MSG2};
use fips_core::proto::path::wire::{PathClose, PathCloseReason};
use fips_core::proto::path::{Config as PathConfig, PathRef};

/// Run 50 ms path ticks at both nodes, each followed by an exchange, until
/// B (node 1) holds its path to A at (`t2()`, `a2`) Live. Panics, naming
/// the state last read, if that takes more than 40 ticks.
async fn settle(nodes: &mut [TestNode], a2: &TransportAddr) {
    let a = *nodes[0].node.node_addr();
    for _ in 0..40 {
        if state_at(&nodes[1], &a, t2(), a2) == Some(PathState::Live) {
            return;
        }
        crate::time::advance(Duration::from_millis(50));
        nodes[0].node.path_tick().await;
        nodes[1].node.path_tick().await;
        exchange(nodes).await;
    }
    panic!(
        "setup bound: B's path at (t2, A2) is {:?} after 40 ticks",
        state_at(&nodes[1], &a, t2(), a2)
    );
}

/// Take every packet queued at `tn`, hand it those that did not arrive on
/// `transport`, and return the rest unhandled. Panics on a msg1, since no
/// test here expects a new link to be dialled.
async fn hand_except(tn: &mut TestNode, transport: TransportId) -> Vec<ReceivedPacket> {
    let mut kept = Vec::new();
    for packet in take_packets(tn) {
        assert_ne!(phase(&packet), Some(PHASE_MSG1), "no msg1 for a new link");
        if packet.transport_id == transport {
            kept.push(packet);
        } else {
            hand(tn, packet).await;
        }
    }
    kept
}

/// Hand the frames queued at either node to it, B (node 1) first, until a
/// round moves none, at most ten rounds. Panics on a msg1.
async fn swap(nodes: &mut [TestNode]) {
    pass(nodes, None).await;
}

/// [`swap`], holding back in `held`, when given, every frame that arrived
/// on `t2()`, with the index of the node it was queued at.
async fn pass(nodes: &mut [TestNode], mut held: Option<&mut Vec<(usize, ReceivedPacket)>>) {
    for _ in 0..10 {
        let mut moved = 0;
        for i in [1, 0] {
            for packet in take_packets(&mut nodes[i]) {
                assert_ne!(phase(&packet), Some(PHASE_MSG1), "no msg1 for a new link");
                match held.as_deref_mut() {
                    Some(held) if packet.transport_id == t2() => held.push((i, packet)),
                    _ => {
                        hand(&mut nodes[i], packet).await;
                        moved += 1;
                    }
                }
            }
        }
        if moved == 0 {
            return;
        }
    }
}

/// A carrier loss on the active path's transport moves the link to the
/// standby in the tick that reads it (draft Sections 5.6 and 5.7), and the
/// peer is told by a `PathClose` that travels on the standby, not on the
/// closing path (Section 5.8): the peer marks its side of the path Dead and
/// moves its own traffic too. A frame sent after the move goes on the
/// standby and authenticates; no new link is dialled and neither end loses
/// its peer. The clock moves 50 ms from the loss to the last assertion.
#[tokio::test]
async fn carrier_loss_on_the_active_path_moves_the_link_in_one_tick_and_tells_the_peer() {
    // Each node probes its active path every 200 ms. With the clock running,
    // time the test spends descheduled can bring one of those probes due in
    // the window asserted on, and its answer is then a second frame at B.
    crate::time::freeze();
    let (mut nodes, b, a2, b2) = two_transports(1280).await;
    let a = *nodes[0].node.node_addr();
    let t1 = nodes[0].transport_id;
    let (a1, b1) = (nodes[0].addr.clone(), nodes[1].addr.clone());
    settle(&mut nodes, &a2).await;
    // The first reading of carrier, with carrier up, so the drop is an edge.
    carrier(&mut nodes, t1, true).await;
    exchange(&mut nodes).await;
    assert_eq!(active_of(&nodes[0], &b), (t1, b1.clone()), "precondition");
    assert_eq!(active_of(&nodes[1], &a), (t1, a1.clone()), "precondition");
    assert_eq!(
        state_at(&nodes[1], &a, t2(), &a2),
        Some(PathState::Live),
        "precondition: B's standby is Live"
    );

    let (logs, guard) = crate::testutil::capture_logs_scoped();
    carrier(&mut nodes, t1, false).await;
    let switched = logs.lines_with("Path switched");
    assert_eq!(
        state_at(&nodes[0], &b, t1, &b1),
        Some(PathState::Suspect),
        "p in the tick of the loss"
    );
    assert_eq!(switched.len(), 1, "{switched:?}");
    assert!(switched[0].contains("why=\"mandatory\""), "{}", switched[0]);
    assert_eq!(active_of(&nodes[0], &b), (t2(), b2.clone()), "A moved");

    // B takes what A sent in that tick, all of it on t2: nothing goes on
    // the closing path. Frames on t1 from here on are held back.
    let on_t1 = hand_except(&mut nodes[1], t1).await;
    assert!(on_t1.is_empty(), "nothing on the closing path: {on_t1:?}");
    assert_eq!(
        state_at(&nodes[1], &a, t1, &a1),
        Some(PathState::Dead),
        "B marked its side of p Dead on A's close"
    );
    assert_eq!(active_of(&nodes[1], &a), (t2(), a2.clone()), "B moved too");
    hand_except(&mut nodes[0], t1).await;

    // A frame A sends now goes on q and authenticates at B.
    let received = nodes[1]
        .node
        .get_peer(&a)
        .unwrap()
        .link_stats()
        .packets_recv;
    super::rekey_parity::heartbeat(&mut nodes[0], &b).await;
    let queued = take_packets(&mut nodes[1]);
    assert_eq!(queued.len(), 1, "one frame at B: {queued:?}");
    assert_eq!(
        (queued[0].transport_id, &queued[0].remote_addr),
        (t2(), &a2),
        "on q"
    );
    for packet in queued {
        hand(&mut nodes[1], packet).await;
    }
    let peer = nodes[1].node.get_peer(&a).expect("B keeps A");
    assert_eq!(peer.consecutive_decrypt_failures(), 0);
    assert!(
        peer.link_stats().packets_recv > received,
        "it authenticated"
    );
    assert!(nodes[0].node.get_peer(&b).is_some(), "A keeps B");
    hand_except(&mut nodes[0], t1).await;
    drop(guard);
    cleanup_nodes(&mut nodes).await;
}

/// The path state of `tn`'s path to `peer` at (`transport`, `addr`), with
/// its count of consecutive unanswered probes and of frames attributed to
/// it. Panics if the path is not held.
fn path_at(
    tn: &TestNode,
    peer: &NodeAddr,
    transport: TransportId,
    addr: &TransportAddr,
) -> (PathState, u32, u32) {
    let paths = tn.node.get_peer(peer).unwrap().bundle().unwrap().paths();
    let path = paths.get(paths.find(transport, addr).unwrap()).unwrap();
    (path.state(), path.live().misses(), path.live().frames())
}

/// A path that stops carrying our frames while it still brings the peer's
/// is left once K probes on it go unanswered (draft Section 5.6): the
/// switch is mandatory, comes no earlier than the third unanswered probe's
/// deadline and within K probe intervals, one timeout and one tick of the
/// cut, and the peer's frames on the path, which go on arriving, do not
/// hold it. No new link is dialled and A keeps its peer.
#[tokio::test]
async fn a_path_that_stops_carrying_our_frames_but_still_brings_the_peers_is_left_after_k_unanswered_probes()
 {
    // The switch is timed in 50 ms ticks. With the clock running, time the
    // test spends descheduled brings probes due and deadlines past sooner
    // than the ticks say, and the switch reads as early.
    crate::time::freeze();
    let (mut nodes, b, _, b2) = two_transports(1280).await;
    let a = *nodes[0].node.node_addr();
    let t1 = nodes[0].transport_id;
    let (a1, b1) = (nodes[0].addr.clone(), nodes[1].addr.clone());
    swap(&mut nodes).await;
    assert_eq!(active_of(&nodes[0], &b), (t1, b1.clone()), "precondition");
    assert_eq!(active_of(&nodes[1], &a), (t1, a1.clone()), "precondition");
    let (_, misses, before) = path_at(&nodes[0], &b, t1, &b1);
    assert_eq!(misses, 0, "precondition: p answers");
    let cfg = PathConfig::draft();
    let k = u32::from(cfg.suspect);
    let tick = Duration::from_millis(50);
    let earliest = cfg.active_interval * (k - 1) + cfg.timeout;
    let latest = cfg.active_interval * k + cfg.timeout + tick;

    // From here every frame to B's first address is lost; B's frames to
    // A's first address still arrive.
    delay_loopback_delivery(&nodes[1], None);
    let via = PathRef {
        transport: t1,
        addr: a1.clone(),
    };
    let heartbeat = [crate::proto::link::LinkMessageType::Heartbeat.to_byte()];
    let (logs, guard) = crate::testutil::capture_logs_scoped();
    let mut moved = None;
    let mut last = 0;
    for n in 0..60 {
        crate::time::advance(tick);
        if n % 2 == 0 {
            nodes[1]
                .node
                .send_via(&a, &heartbeat, false, Some(&via))
                .await
                .expect("B's frame on p goes out");
        }
        nodes[0].node.path_tick().await;
        swap(&mut nodes).await;
        if active_of(&nodes[0], &b).0 == t2() {
            // Elapsed time by the ticks run: the clock is frozen, so it
            // has moved by those alone.
            moved = Some(tick * (n + 1));
            break;
        }
        last = path_at(&nodes[0], &b, t1, &b1).1;
    }
    let switched = logs.lines_with("Path switched");
    drop(guard);
    let (_, _, after) = path_at(&nodes[0], &b, t1, &b1);
    assert!(
        after > before,
        "B's frames reached A on p during the outage"
    );
    let moved = moved.expect("A left p within 3 s of the cut");
    assert_eq!(
        last,
        k - 1,
        "the tick before the switch counted K - 1 misses"
    );
    assert!(
        moved >= earliest,
        "no earlier than the third probe's deadline: {moved:?} < {earliest:?}"
    );
    assert!(
        moved <= latest,
        "within K intervals, T and a tick: {moved:?}"
    );
    assert_eq!(switched.len(), 1, "{switched:?}");
    assert!(switched[0].contains("why=\"mandatory\""), "{}", switched[0]);
    assert_eq!(active_of(&nodes[0], &b), (t2(), b2));
    assert!(nodes[0].node.get_peer(&b).is_some(), "A keeps B");
    cleanup_nodes(&mut nodes).await;
}

/// One step of `step` with the standby starved: the clock moves, both nodes
/// run a path tick, each sends the other a heartbeat on its active path,
/// and the frames are handed between them with every frame on `t2()` held
/// back in `held`.
async fn starve(nodes: &mut [TestNode], step: Duration, held: &mut Vec<(usize, ReceivedPacket)>) {
    let (a, b) = (*nodes[0].node.node_addr(), *nodes[1].node.node_addr());
    crate::time::advance(step);
    nodes[0].node.path_tick().await;
    nodes[1].node.path_tick().await;
    super::rekey_parity::heartbeat(&mut nodes[0], &b).await;
    super::rekey_parity::heartbeat(&mut nodes[1], &a).await;
    pass(nodes, Some(held)).await;
}

/// Bury the frames in `held` as heavy load on the active path does: each
/// node sends the other one frame more than the anti-replay window spans,
/// all of which are handed over, and then every held frame is handed to the
/// node it was meant for. Returns, per node, how many of those the node
/// refused as replays. Frames sent on `t2()` meanwhile are dropped.
async fn bury(nodes: &mut [TestNode], held: Vec<(usize, ReceivedPacket)>) -> [u32; 2] {
    let (a, b) = (*nodes[0].node.node_addr(), *nodes[1].node.node_addr());
    for _ in 0..=fips_core::noise::REPLAY_WINDOW_SIZE {
        super::rekey_parity::heartbeat(&mut nodes[0], &b).await;
        super::rekey_parity::heartbeat(&mut nodes[1], &a).await;
    }
    pass(nodes, Some(&mut Vec::new())).await;
    let replays = |nodes: &[TestNode]| {
        [
            nodes[0]
                .node
                .get_peer(&b)
                .unwrap()
                .replay_suppressed_count(),
            nodes[1]
                .node
                .get_peer(&a)
                .unwrap()
                .replay_suppressed_count(),
        ]
    };
    let before = replays(nodes);
    for (i, packet) in held {
        hand(&mut nodes[i], packet).await;
    }
    let after = replays(nodes);
    [after[0] - before[0], after[1] - before[1]]
}

/// Starve the standby q of a [`two_transports`] link in 1 s steps until A
/// holds it Dead, at most 30 steps (K + retire unanswered standby probes
/// need at least 14), then bury the held frames, and return them per node
/// with how many were refused as replays.
async fn starve_out(nodes: &mut [TestNode], b2: &TransportAddr) -> ([usize; 2], [u32; 2]) {
    let b = *nodes[1].node.node_addr();
    let mut held = Vec::new();
    for n in 0.. {
        if state_at(&nodes[0], &b, t2(), b2) == Some(PathState::Dead) {
            break;
        }
        assert!(
            n < 30,
            "setup bound: q is {:?} at A after {n} steps",
            state_at(&nodes[0], &b, t2(), b2)
        );
        starve(nodes, Duration::from_secs(1), &mut held).await;
    }
    let count = |i| held.iter().filter(|(at, _)| *at == i).count();
    let counts = [count(0), count(1)];
    (counts, bury(nodes, held).await)
}

/// A standby starved behind the active path's load, its probes held until
/// heavy traffic on the active path has moved the anti-replay window past
/// them, so that each arrives late and is refused as under load, is retired
/// to Dead (draft Section 5.6's second Note). When the active path's
/// interface then goes, before the grace, the standby becomes active and is
/// probed in that same step, the at-once probe exempt from the floor
/// (Section 5.7, bullet 4); its answer makes it Live and the link survives
/// on it, with no new link dialled.
#[tokio::test]
async fn a_starved_standby_retired_to_dead_carries_the_link_when_the_active_interface_goes() {
    let (mut nodes, b, a2, b2) = two_transports(1280).await;
    let t1 = nodes[0].transport_id;
    swap(&mut nodes).await;
    let (held, refused) = starve_out(&mut nodes, &b2).await;
    assert!(held[0] > 0 && held[1] > 0, "probes were held: {held:?}");
    assert_eq!(
        [refused[0] as usize, refused[1] as usize],
        held,
        "every held frame arrived late and was refused as a replay"
    );
    assert_eq!(state_at(&nodes[0], &b, t2(), &b2), Some(PathState::Dead));
    let outstanding = {
        let paths = nodes[0]
            .node
            .get_peer(&b)
            .unwrap()
            .bundle()
            .unwrap()
            .paths();
        paths
            .get(paths.find(t2(), &b2).unwrap())
            .unwrap()
            .live()
            .outstanding()
    };
    assert_eq!(outstanding, 0, "precondition: no probe outstanding on q");

    assert_eq!(nodes[0].node.path_presence(t1, false).await, 0, "A keeps B");
    assert_eq!(active_of(&nodes[0], &b), (t2(), b2.clone()), "q is active");
    let at_b = take_packets(&mut nodes[1]);
    let on_q: Vec<_> = at_b
        .iter()
        .filter(|p| p.transport_id == t2() && p.remote_addr == a2)
        .collect();
    assert_eq!(on_q.len(), 1, "A's probe on q in that step: {at_b:?}");
    for packet in at_b {
        assert_ne!(phase(&packet), Some(PHASE_MSG1), "no msg1 for a new link");
        hand(&mut nodes[1], packet).await;
    }
    swap(&mut nodes).await;
    assert_eq!(state_at(&nodes[0], &b, t2(), &b2), Some(PathState::Live));
    assert!(nodes[0].node.get_peer(&b).is_some(), "A keeps B");
    cleanup_nodes(&mut nodes).await;
}

/// A standby starved past the grace, counted from the instant it became
/// Dead, is discarded while the active path is Live, so when the active
/// path's interface goes nothing is left and the peer is removed, as a link
/// of one path that loses its interface is (draft Section 5.6).
#[tokio::test]
async fn a_standby_dead_past_the_grace_is_gone_and_the_link_with_it_when_the_active_interface_goes()
{
    let (mut nodes, b, _, b2) = two_transports(1280).await;
    let t1 = nodes[0].transport_id;
    swap(&mut nodes).await;
    let mut held = Vec::new();
    for n in 0.. {
        if state_at(&nodes[0], &b, t2(), &b2) == Some(PathState::Dead) {
            break;
        }
        assert!(n < 30, "setup bound: q not Dead after {n} steps");
        starve(&mut nodes, Duration::from_secs(1), &mut held).await;
    }
    let step = Duration::from_secs(10);
    let mut since = Duration::ZERO;
    while since < PathConfig::draft().grace + step {
        starve(&mut nodes, step, &mut held).await;
        since += step;
        assert!(nodes[0].node.get_peer(&b).is_some(), "the link stays up");
    }
    bury(&mut nodes, held).await;
    assert_eq!(
        state_at(&nodes[0], &b, t2(), &b2),
        None,
        "q is discarded at the grace"
    );
    assert_eq!(nodes[0].node.path_presence(t1, false).await, 1);
    assert!(nodes[0].node.get_peer(&b).is_none(), "the peer is removed");
    cleanup_nodes(&mut nodes).await;
}

/// Run a [`two_transports`] link whose cable, the transport `cable` at both
/// nodes, is `preferred` and whose other transport is `normal`, both on
/// loopback, so their round trips are equal. Ticks of 50 ms at both nodes,
/// each followed by an exchange, run until the dwell has passed after
/// enough probes for the samples selection needs, and then a dwell more.
/// Returns, per node, the transport its link is on at the end, how many
/// times its active path changed, and the tick of the first change; and
/// the "Path switched" lines.
async fn settle_on(cable: TransportId) -> ([(TransportId, usize, Option<u32>); 2], Vec<String>) {
    let (mut nodes, b, _, _) = two_transports(1280).await;
    let a = *nodes[0].node.node_addr();
    let t1 = nodes[0].transport_id;
    for tn in nodes.iter_mut() {
        for t in [t1, t2()] {
            let role = if t == cable {
                TransportRole::Preferred
            } else {
                TransportRole::Normal
            };
            loopback_mut(tn, t).set_role(role);
        }
    }
    swap(&mut nodes).await;
    assert_eq!(active_of(&nodes[0], &b).0, t1, "precondition: made on t1");
    assert_eq!(active_of(&nodes[1], &a).0, t1, "precondition: made on t1");
    let cfg = PathConfig::draft();
    let tick = Duration::from_millis(50);
    let span = cfg.standby_interval * (u32::from(cfg.min_samples) + 2) + cfg.switch_dwell * 2;
    let ticks = span.as_millis() / tick.as_millis();
    let mut on = [t1, t1];
    let mut moves = [0, 0];
    let mut first = [None, None];
    let (logs, guard) = crate::testutil::capture_logs_scoped();
    for n in 0..ticks as u32 {
        crate::time::advance(tick);
        nodes[0].node.path_tick().await;
        nodes[1].node.path_tick().await;
        swap(&mut nodes).await;
        let now = [active_of(&nodes[0], &b).0, active_of(&nodes[1], &a).0];
        for i in 0..2 {
            if now[i] != on[i] {
                moves[i] += 1;
                first[i] = first[i].or(Some(n + 1));
                on[i] = now[i];
            }
        }
    }
    let switched = logs.lines_with("Path switched");
    drop(guard);
    cleanup_nodes(&mut nodes).await;
    (
        [(on[0], moves[0], first[0]), (on[1], moves[1], first[1])],
        switched,
    )
}

/// With equal round trips, a `preferred` cable carries the link at both
/// ends in both handshake orders:
/// made on the cable, the link stays there with the other transport Live
/// beside it; made on the other transport, both ends move to the cable by
/// one discretionary switch each, no sooner than the switch dwell, and
/// stay.
#[tokio::test]
async fn with_equal_round_trips_a_preferred_cable_carries_the_link_at_the_node_in_both_orders() {
    // The first move is timed in 50 ms ticks against the dwell. With the
    // clock running, time the test spends descheduled runs the dwell down
    // sooner than the ticks say, and the move reads as before it.
    crate::time::freeze();
    let t1 = TransportId::new(1);
    let dwell = PathConfig::draft().switch_dwell;
    let tick = Duration::from_millis(50);

    let (ends, switched) = settle_on(t1).await;
    for (i, (on, moves, _)) in ends.iter().enumerate() {
        assert_eq!(*on, t1, "made on the cable, node {i} stays on it");
        assert_eq!(*moves, 0, "node {i} never moves");
    }
    assert!(switched.is_empty(), "{switched:?}");

    let (ends, switched) = settle_on(t2()).await;
    for (i, (on, moves, first)) in ends.iter().enumerate() {
        assert_eq!(*on, t2(), "made on the other, node {i} ends on the cable");
        assert_eq!(*moves, 1, "node {i} moves once and stays");
        let at = tick * first.unwrap();
        assert!(at >= dwell, "node {i} moved at {at:?}, before the dwell");
    }
    assert_eq!(switched.len(), 2, "{switched:?}");
    for line in &switched {
        assert!(line.contains("why=\"discretionary\""), "{line}");
    }
}

/// Hand node `to` `k` frames that name the receiver index it gave the other
/// node and fail to authenticate, arriving on its transport `transport`
/// from `from`.
async fn garbage_to(
    nodes: &mut [TestNode],
    to: usize,
    transport: TransportId,
    from: &TransportAddr,
    k: u32,
) {
    let other = *nodes[1 - to].node.node_addr();
    let index = nodes[to]
        .node
        .get_peer(&other)
        .unwrap()
        .our_index()
        .unwrap();
    for n in 0..k {
        let frame = super::decrypt_forged::forged_frame(index, 1_000_000 + u64::from(n));
        let packet = ReceivedPacket::new(transport, from.clone(), frame);
        nodes[to].node.handle_encrypted_frame(packet).await;
    }
}

/// Twenty frames that fail to authenticate on an acked standby mark it Dead
/// (draft Section 5.3): the standby is tripped, which
/// logs no warning, while the active path, on the same transport at
/// another address of the peer's, stays Live and active with nothing
/// counted against it, and the peer is kept.
#[tokio::test]
async fn twenty_garbage_frames_on_an_acked_standby_mark_it_dead_and_leave_the_active_path_alone() {
    let (mut nodes, b, b2) = same_transport().await;
    let (t1, b1) = (nodes[0].transport_id, nodes[1].addr.clone());
    assert_eq!(active_of(&nodes[0], &b), (t1, b1.clone()), "precondition");
    let limit = u32::from(PathConfig::draft().auth_limit);
    let (logs, guard) = crate::testutil::capture_logs_scoped();
    garbage_to(&mut nodes, 0, t1, &b2, limit).await;
    let warned = excessive(&logs);
    drop(guard);
    assert_eq!(state_at(&nodes[0], &b, t1, &b2), Some(PathState::Dead), "q");
    let (state, _, _) = path_at(&nodes[0], &b, t1, &b1);
    let fails = {
        let paths = nodes[0]
            .node
            .get_peer(&b)
            .unwrap()
            .bundle()
            .unwrap()
            .paths();
        paths
            .get(paths.find(t1, &b1).unwrap())
            .unwrap()
            .live()
            .fails()
    };
    assert_eq!(state, PathState::Live, "p");
    assert_eq!(fails, 0, "nothing counted against p");
    assert_eq!(active_of(&nodes[0], &b), (t1, b1), "p stays active");
    assert_eq!(warned, 0, "a tripped standby logs no warning");
    assert!(nodes[0].node.get_peer(&b).is_some(), "A keeps B");
    cleanup_nodes(&mut nodes).await;
}

/// Have node `from` send `k` heartbeats to its peer on its path at `via`,
/// and hand them to the other node.
async fn beats(nodes: &mut [TestNode], from: usize, via: &PathRef, k: usize) {
    let to = *nodes[1 - from].node.node_addr();
    let heartbeat = [crate::proto::link::LinkMessageType::Heartbeat.to_byte()];
    for _ in 0..k {
        nodes[from]
            .node
            .send_via(&to, &heartbeat, false, Some(via))
            .await
            .expect("the heartbeat goes out");
    }
    swap(nodes).await;
}

/// A node with two transports to a peer with one: A
/// holds t1 and t2, B holds t1 alone, so A's paths p (t1, B1) and q (t2,
/// B1) arrive at B as two paths on its one transport, at A's two
/// addresses. Both go Live at both ends; B counts the frames of each apart,
/// by the pair they arrive from; and a `PathClose` of q, sent on p, marks
/// q Dead at B and leaves p Live at both ends.
#[tokio::test]
async fn two_transports_to_a_peer_with_one_give_two_live_paths_at_both_ends_counted_apart() {
    let mut nodes = super::rekey_parity::linked_pair(enabled(), enabled()).await;
    let a2 = second_transport(&mut nodes[0], t2(), 1280);
    let (a, b) = (*nodes[0].node.node_addr(), *nodes[1].node.node_addr());
    let t1 = nodes[0].transport_id;
    let (a1, b1) = (nodes[0].addr.clone(), nodes[1].addr.clone());
    nodes[0].node.offer_path(&b, t2(), b1.clone()).await;
    let live = |nodes: &[TestNode]| {
        [
            state_at(&nodes[0], &b, t1, &b1),
            state_at(&nodes[0], &b, t2(), &b1),
            state_at(&nodes[1], &a, t1, &a1),
            state_at(&nodes[1], &a, t1, &a2),
        ]
    };
    for n in 0.. {
        swap(&mut nodes).await;
        if live(&nodes).iter().all(|s| *s == Some(PathState::Live)) {
            break;
        }
        assert!(n < 40, "setup bound: {:?} after {n} ticks", live(&nodes));
        crate::time::advance(Duration::from_millis(50));
        nodes[0].node.path_tick().await;
        nodes[1].node.path_tick().await;
    }

    let (_, _, p0) = path_at(&nodes[1], &a, t1, &a1);
    let (_, _, q0) = path_at(&nodes[1], &a, t1, &a2);
    let p = PathRef {
        transport: t1,
        addr: b1.clone(),
    };
    let q = PathRef {
        transport: t2(),
        addr: b1.clone(),
    };
    let (n, m) = (5, 3);
    beats(&mut nodes, 0, &p, n).await;
    beats(&mut nodes, 0, &q, m).await;
    let (_, _, p1) = path_at(&nodes[1], &a, t1, &a1);
    let (_, _, q1) = path_at(&nodes[1], &a, t1, &a2);
    assert_eq!(p1 - p0, n as u32, "B counts A's frames on p to p");
    assert_eq!(q1 - q0, m as u32, "and those on q to q");

    let peer_id = {
        let paths = nodes[0]
            .node
            .get_peer(&b)
            .unwrap()
            .bundle()
            .unwrap()
            .paths();
        let q = paths.get(paths.find(t2(), &b1).unwrap()).unwrap();
        q.peer_id().expect("precondition: A holds B's id for q")
    };
    let close = PathClose {
        path_id: peer_id,
        reason: PathCloseReason::Operator,
    };
    nodes[0]
        .node
        .send_via(&b, &close.encode(), false, Some(&p))
        .await
        .expect("A's close goes out on p");
    swap(&mut nodes).await;
    assert_eq!(
        state_at(&nodes[1], &a, t1, &a2),
        Some(PathState::Dead),
        "q at B"
    );
    assert_eq!(
        state_at(&nodes[1], &a, t1, &a1),
        Some(PathState::Live),
        "p at B"
    );
    assert_eq!(
        state_at(&nodes[0], &b, t1, &b1),
        Some(PathState::Live),
        "p at A"
    );
    cleanup_nodes(&mut nodes).await;
}

/// Frames that fail to authenticate on a transport a capable link of one
/// path does not use count nothing against its path and log no warning,
/// even from the peer's own address:
/// the link stays capable with its one path, and the peer is kept.
#[tokio::test]
async fn garbage_on_a_second_transport_counts_nothing_against_a_capable_one_path_link() {
    let mut nodes = super::rekey_parity::linked_pair(enabled(), enabled()).await;
    let (a, b) = (*nodes[0].node.node_addr(), *nodes[1].node.node_addr());
    let (t1, b1) = (nodes[0].transport_id, nodes[1].addr.clone());
    // B shows A it implements multipath: one probe from B on p.
    let id = nodes[1]
        .node
        .get_peer(&a)
        .unwrap()
        .paths()
        .first()
        .unwrap()
        .path_id();
    nodes[1]
        .node
        .send_encrypted_link_message(&a, &probe(id, 64))
        .await
        .expect("B's probe goes out");
    swap(&mut nodes).await;
    assert!(capable_at(&nodes[0], &b), "precondition: B capable at A");
    assert_eq!(nodes[0].node.get_peer(&b).unwrap().paths().len(), 1);
    second_transport(&mut nodes[0], t2(), 1280);

    let (logs, guard) = crate::testutil::capture_logs_scoped();
    // From B's own address, so only the transport tells the pairs apart.
    let limit = u32::from(PathConfig::draft().auth_limit);
    garbage_to(&mut nodes, 0, t2(), &b1, limit).await;
    let warned = excessive(&logs);
    drop(guard);
    let peer = nodes[0].node.get_peer(&b).expect("A keeps B");
    let (state, _, _) = path_at(&nodes[0], &b, t1, &b1);
    let fails = peer.paths().first().unwrap().live().fails();
    assert_eq!(fails, 0, "nothing counted against p");
    assert_eq!(peer.consecutive_decrypt_failures(), 0);
    assert_eq!(warned, 0, "no warning");
    assert_eq!(state, PathState::Live);
    assert!(capable_at(&nodes[0], &b), "still capable");
    assert_eq!(peer.paths().len(), 1, "still one path");
    cleanup_nodes(&mut nodes).await;
}

/// The rekey interval `rekey_parity::trigger_age()` is cut for.
const REKEY_SECS: u64 = 60;

/// [`two_transports`] with both nodes built from one configuration, rekey
/// on after `after_secs` and multipath enabled: A (0) holds p (t1, B1) and
/// q (`t2()`, B2), both Live, p active. Returns the nodes, B's address, and
/// A's and B's second addresses.
async fn rekeyed_transports(
    after_secs: u64,
) -> (Vec<TestNode>, NodeAddr, TransportAddr, TransportAddr) {
    let mut cfg = super::rekey_parity::rekey_config(after_secs);
    cfg.node.path.enabled = true;
    let mut nodes = super::rekey_parity::linked_pair(cfg.clone(), cfg).await;
    let a2 = second_transport(&mut nodes[0], t2(), 1280);
    let b2 = second_transport(&mut nodes[1], t2(), 1280);
    let b = *nodes[1].node.node_addr();
    nodes[0].node.offer_path(&b, t2(), b2.clone()).await;
    super::rekey_parity::pump(&mut nodes).await;
    assert_eq!(
        state_at(&nodes[0], &b, t2(), &b2),
        Some(PathState::Live),
        "precondition: q is Live at A"
    );
    (nodes, b, a2, b2)
}

/// Run A's rekey to B up to the msg2 (A's msg1 on p, B's answer), switch A
/// to q by a carrier loss on t1 before A takes the msg2, then hand A the
/// msg2 as arriving on `on` (B's address on that transport): returns
/// whether the rekey completed with its index registered for dispatch,
/// and whether, after the cutover, a frame A sends goes on q and
/// authenticates at B.
async fn switch_rekeying(on: TransportId) -> (bool, bool) {
    let (mut nodes, b, a2, b2) = rekeyed_transports(REKEY_SECS).await;
    let a = *nodes[0].node.node_addr();
    let t1 = nodes[0].transport_id;
    let (a1, b1) = (nodes[0].addr.clone(), nodes[1].addr.clone());
    carrier(&mut nodes, t1, true).await;
    swap(&mut nodes).await;
    super::rekey_parity::age_link(&mut nodes, 0, 1, super::rekey_parity::trigger_age());

    nodes[0].node.poll_link_rekeys().await;
    let index = {
        let peer = nodes[0].node.get_peer(&b).unwrap();
        assert!(peer.rekey_in_progress(), "precondition: A started a rekey");
        peer.rekey_our_index().unwrap()
    };
    let at_b = take_packets(&mut nodes[1]);
    assert_eq!(at_b.len(), 1, "precondition: one packet at B");
    assert_eq!(phase(&at_b[0]), Some(PHASE_MSG1), "precondition: a msg1");
    assert_eq!(
        (at_b[0].transport_id, &at_b[0].remote_addr),
        (t1, &a1),
        "precondition: A's rekey msg1 went on p"
    );
    for packet in at_b {
        hand(&mut nodes[1], packet).await;
    }
    let mut at_a = take_packets(&mut nodes[0]);
    let msg2 = at_a
        .iter()
        .position(|p| phase(p) == Some(PHASE_MSG2))
        .map(|i| at_a.remove(i))
        .expect("precondition: B's rekey msg2 is queued at A");
    assert_eq!(
        (msg2.transport_id, &msg2.remote_addr),
        (t1, &b1),
        "precondition: B answered on p"
    );
    for packet in at_a {
        hand(&mut nodes[0], packet).await;
    }

    carrier(&mut nodes, t1, false).await;
    assert_eq!(
        active_of(&nodes[0], &b),
        (t2(), b2.clone()),
        "precondition: A switched to q between the msg1 and the msg2"
    );
    swap(&mut nodes).await;
    let mut msg2 = msg2;
    if on == t2() {
        msg2.transport_id = t2();
        msg2.remote_addr = b2.clone();
    }
    hand(&mut nodes[0], msg2).await;
    let completed = {
        let peer = nodes[0].node.get_peer(&b).expect("A keeps B");
        !peer.rekey_in_progress()
            && peer.pending_our_index() == Some(index)
            && nodes[0].node.peers_by_index.get(&index.as_u32()) == Some(&b)
    };
    if !completed {
        cleanup_nodes(&mut nodes).await;
        return (false, false);
    }

    super::rekey_parity::cutover(&mut nodes[0], &b).await;
    swap(&mut nodes).await;
    let received = nodes[1]
        .node
        .get_peer(&a)
        .unwrap()
        .link_stats()
        .packets_recv;
    super::rekey_parity::heartbeat(&mut nodes[0], &b).await;
    let queued = take_packets(&mut nodes[1]);
    let on_q = queued.len() == 1 && (queued[0].transport_id, &queued[0].remote_addr) == (t2(), &a2);
    for packet in queued {
        assert_ne!(phase(&packet), Some(PHASE_MSG1), "no msg1 for a new link");
        hand(&mut nodes[1], packet).await;
    }
    let peer = nodes[1].node.get_peer(&a).expect("B keeps A");
    let authentic = on_q
        && peer.consecutive_decrypt_failures() == 0
        && peer.link_stats().packets_recv > received;
    swap(&mut nodes).await;
    assert!(nodes[0].node.get_peer(&b).is_some(), "A keeps B");
    cleanup_nodes(&mut nodes).await;
    (completed, authentic)
}

/// A switch of the active path between a rekey's msg1 and its msg2 leaves
/// the rekey to complete (draft Section 5.10): the msg2 is matched by its
/// index alone wherever it arrives, on the pair the msg1 went out on, where
/// the peer answers, or on the new active path. The rekey completes with
/// its index registered for dispatch, and after the cutover A's frames go
/// on the new path and authenticate at B. No new link is dialled.
///
/// A's msg3 goes on the new active path, another transport than the msg1's,
/// and B drops it: B's leg is keyed by the msg1's transport and the index,
/// so B never takes the new session.
#[tokio::test]
#[ignore = "known defect: a rekey msg3 sent on a new active path on another transport is dropped, the responder's leg keyed by the msg1's transport"]
async fn a_switch_between_rekey_msg1_and_msg2_leaves_the_rekey_to_complete_on_the_new_path() {
    let t1 = TransportId::new(1);
    let cases = [
        (t1, switch_rekeying(t1).await),
        (t2(), switch_rekeying(t2()).await),
    ];
    let failed: Vec<String> = cases
        .iter()
        .filter(|(_, (completed, authentic))| !(*completed && *authentic))
        .map(|(on, (completed, authentic))| {
            format!(
                "msg2 on {on}: completed {completed}, authentic on q after the cutover {authentic}"
            )
        })
        .collect();
    assert!(failed.is_empty(), "defect: {failed:?}");
}

/// The initiator's half of the test above, which holds today: a switch of
/// the active path between a rekey's msg1 and its msg2 leaves A's side of
/// the rekey to complete, the msg2 matched by its index alone whether it
/// arrives on the pair the msg1 went out on or on the new active path, with
/// the new index registered for dispatch.
#[tokio::test]
async fn a_switch_between_rekey_msg1_and_msg2_leaves_the_initiator_to_complete_the_rekey() {
    let t1 = TransportId::new(1);
    let cases = [
        (t1, switch_rekeying(t1).await.0),
        (t2(), switch_rekeying(t2()).await.0),
    ];
    let failed: Vec<String> = cases
        .iter()
        .filter(|(_, completed)| !*completed)
        .map(|(on, _)| format!("msg2 on {on}: not completed"))
        .collect();
    assert!(failed.is_empty(), "{failed:?}");
}

/// One advance of the clock brings both a path switch and a rekey:
/// the link's path timers and its rekey timer run on one clock, the one
/// `crate::time::advance` moves. With A's frames on p lost from the cut,
/// 50 ms ticks run until two of A's probes on p have timed out and a third
/// is outstanding, with the rekey not yet due. Then one advance, longer
/// than the whole jitter window, passes both that probe's deadline and A's
/// rekey trigger, and one path tick and one rekey poll give both a
/// mandatory switch to q and a rekey msg1, which goes out on q.
#[tokio::test]
async fn one_advance_of_the_clock_brings_both_a_path_switch_and_a_rekey() {
    let (mut nodes, b, a2, b2) = rekeyed_transports(REKEY_SECS).await;
    let t1 = nodes[0].transport_id;
    let b1 = nodes[1].addr.clone();
    let cfg = PathConfig::draft();
    let tick = Duration::from_millis(50);
    let after = Duration::from_secs(REKEY_SECS);
    let jitter = Duration::from_secs(crate::node::REKEY_JITTER_SECS as u64);
    let offset = nodes[0].node.get_peer(&b).unwrap().rekey_jitter_secs();
    let trigger = Duration::from_secs(REKEY_SECS.checked_add_signed(offset).unwrap());
    // 5 s before the earliest trigger: more than the setup loop's bound.
    let mut age = after - jitter - Duration::from_secs(5);
    swap(&mut nodes).await;
    super::rekey_parity::age_link(&mut nodes, 0, 1, age);
    let (state, misses, _) = path_at(&nodes[0], &b, t1, &b1);
    assert_eq!(
        (state, misses),
        (PathState::Live, 0),
        "precondition at the cut"
    );

    // From here every frame to B's first address is lost.
    delay_loopback_delivery(&nodes[1], None);
    let mut since = Duration::ZERO;
    for n in 0.. {
        let paths = nodes[0]
            .node
            .get_peer(&b)
            .unwrap()
            .bundle()
            .unwrap()
            .paths();
        let live = paths.get(paths.find(t1, &b1).unwrap()).unwrap().live();
        let (misses, outstanding) = (live.misses(), live.outstanding());
        if misses == 2 && outstanding >= 1 {
            break;
        }
        assert!(
            n < 40,
            "setup bound: misses {misses}, outstanding {outstanding}, after {n} steps"
        );
        crate::time::advance(tick);
        since += tick;
        age += tick;
        nodes[0].node.path_tick().await;
        nodes[0].node.poll_link_rekeys().await;
        swap(&mut nodes).await;
        let peer = nodes[0].node.get_peer(&b).unwrap();
        assert!(!peer.rekey_in_progress(), "no rekey yet, at {age:?}");
    }
    assert_eq!(active_of(&nodes[0], &b), (t1, b1.clone()), "still on p");

    // The third probe's deadline is at most the cut plus its send instant,
    // three intervals in, plus the timeout.
    let deadline = cfg.active_interval * 3 + cfg.timeout;
    let step = jitter * 2 + Duration::from_secs(6);
    assert!(step > jitter * 2, "longer than the jitter window");
    assert!(since + step > deadline, "past the third probe's deadline");
    assert!(age + step > trigger, "past A's rekey trigger");
    let (logs, guard) = crate::testutil::capture_logs_scoped();
    crate::time::advance(step);
    nodes[0].node.path_tick().await;
    nodes[0].node.poll_link_rekeys().await;
    let switched = logs.lines_with("Path switched");
    drop(guard);
    assert_eq!(switched.len(), 1, "{switched:?}");
    assert!(switched[0].contains("why=\"mandatory\""), "{}", switched[0]);
    assert_eq!(active_of(&nodes[0], &b), (t2(), b2), "A moved to q");
    assert!(
        nodes[0].node.get_peer(&b).unwrap().rekey_in_progress(),
        "A started its rekey"
    );
    let at_b = take_packets(&mut nodes[1]);
    let msg1s: Vec<_> = at_b
        .iter()
        .filter(|p| phase(p) == Some(PHASE_MSG1))
        .map(|p| (p.transport_id, p.remote_addr.clone()))
        .collect();
    assert_eq!(msg1s, vec![(t2(), a2)], "the rekey msg1 went out on q");
    cleanup_nodes(&mut nodes).await;
}

/// When the active path's interface goes and a Live standby is held, the
/// active path is discarded and the standby takes the link at once (draft
/// Sections 5.6 and 5.7), and the peer is told by a `PathClose` that travels
/// on the standby, never on the path closing (Section 5.8): the peer marks
/// its side of the path Dead and moves its own traffic too. No new link is
/// dialled and both ends keep their peer.
#[tokio::test]
async fn an_active_interface_lost_hands_the_link_to_the_live_standby_and_tells_the_peer() {
    let (mut nodes, b, a2, b2) = two_transports(1280).await;
    let a = *nodes[0].node.node_addr();
    let t1 = nodes[0].transport_id;
    let (a1, b1) = (nodes[0].addr.clone(), nodes[1].addr.clone());
    settle(&mut nodes, &a2).await;
    assert_eq!(active_of(&nodes[0], &b), (t1, b1.clone()), "precondition");
    assert_eq!(active_of(&nodes[1], &a), (t1, a1.clone()), "precondition");

    let (logs, guard) = crate::testutil::capture_logs_scoped();
    assert_eq!(nodes[0].node.path_presence(t1, false).await, 0, "A keeps B");
    let switched = logs.lines_with("Path switched");
    drop(guard);
    assert_eq!(state_at(&nodes[0], &b, t1, &b1), None, "p discarded at A");
    assert_eq!(active_of(&nodes[0], &b), (t2(), b2), "A moved to q");
    assert_eq!(switched.len(), 1, "{switched:?}");
    assert!(switched[0].contains("why=\"handover\""), "{}", switched[0]);

    // Everything A sent in that step reached B on t2.
    let on_t1 = hand_except(&mut nodes[1], t1).await;
    assert!(on_t1.is_empty(), "nothing on the closing path: {on_t1:?}");
    assert_eq!(
        state_at(&nodes[1], &a, t1, &a1),
        Some(PathState::Dead),
        "B marked its side of p Dead on A's close"
    );
    assert_eq!(active_of(&nodes[1], &a), (t2(), a2), "B moved too");
    hand_except(&mut nodes[0], t1).await;
    assert!(nodes[0].node.get_peer(&b).is_some(), "A keeps B");
    assert!(nodes[1].node.get_peer(&a).is_some(), "B keeps A");
    cleanup_nodes(&mut nodes).await;
}

/// When the active path's interface goes and the only other path is still
/// Probing, never answered, nothing proven is left to carry the link: the
/// bundle is orphaned and the peer removed, as a link of one path that
/// loses its interface is (draft Sections 5.7 and 5.9).
#[tokio::test]
async fn an_active_interface_lost_with_only_a_probing_standby_removes_the_peer() {
    let mut nodes = super::rekey_parity::linked_pair(enabled(), enabled()).await;
    let b = *nodes[1].node.node_addr();
    let t1 = nodes[0].transport_id;
    second_transport(&mut nodes[0], t2(), 1280);
    let b2 = second_transport(&mut nodes[1], t2(), 1280);
    nodes[0].node.offer_path(&b, t2(), b2.clone()).await;
    // The capability exchange runs on p; every frame on t2, q's probe among
    // them, is held back, so q is never answered.
    let mut held = Vec::new();
    pass(&mut nodes, Some(&mut held)).await;
    assert!(capable_at(&nodes[0], &b), "precondition: B capable at A");
    assert!(!held.is_empty(), "precondition: q was probed");
    let q = {
        let paths = nodes[0]
            .node
            .get_peer(&b)
            .unwrap()
            .bundle()
            .unwrap()
            .paths();
        let q = paths.get(paths.find(t2(), &b2).unwrap()).unwrap();
        (q.state(), q.acked())
    };
    assert_eq!(q, (PathState::Probing, false), "precondition: q unproven");

    assert_eq!(nodes[0].node.path_presence(t1, false).await, 1);
    assert!(nodes[0].node.get_peer(&b).is_none(), "the peer is removed");
    cleanup_nodes(&mut nodes).await;
}

/// When a standby's interface goes, the standby is discarded and the link
/// stays on its active path (draft Section 5.6), and the peer is told by a
/// `PathClose` on the active path (Section 5.8), marking its side of the
/// standby Dead while keeping its own traffic where it is.
#[tokio::test]
async fn a_standby_interface_lost_leaves_the_link_on_its_active_path() {
    let (mut nodes, b, a2, b2) = two_transports(1280).await;
    let a = *nodes[0].node.node_addr();
    let t1 = nodes[0].transport_id;
    let (a1, b1) = (nodes[0].addr.clone(), nodes[1].addr.clone());
    settle(&mut nodes, &a2).await;

    assert_eq!(
        nodes[0].node.path_presence(t2(), false).await,
        0,
        "A keeps B"
    );
    assert_eq!(state_at(&nodes[0], &b, t2(), &b2), None, "q discarded at A");
    assert_eq!(state_at(&nodes[0], &b, t1, &b1), Some(PathState::Live));
    assert_eq!(active_of(&nodes[0], &b), (t1, b1), "A stays on p");

    let on_t2 = hand_except(&mut nodes[1], t2()).await;
    assert!(on_t2.is_empty(), "nothing on the closing path: {on_t2:?}");
    assert_eq!(
        state_at(&nodes[1], &a, t2(), &a2),
        Some(PathState::Dead),
        "B marked its side of q Dead on A's close"
    );
    assert_eq!(active_of(&nodes[1], &a), (t1, a1), "B stays on p");
    cleanup_nodes(&mut nodes).await;
}

/// A `PathClose` from the peer naming our active path, which arrives on the
/// standby, marks the active path Dead and moves the link to the standby in
/// the step that takes it (draft Sections 5.7 and 5.8), by a mandatory
/// switch, without waiting for a probe to go unanswered.
#[tokio::test]
async fn a_peer_closing_our_active_path_moves_our_link_at_once() {
    let (mut nodes, b, a2, b2) = two_transports(1280).await;
    let a = *nodes[0].node.node_addr();
    let t1 = nodes[0].transport_id;
    let (a1, b1) = (nodes[0].addr.clone(), nodes[1].addr.clone());
    settle(&mut nodes, &a2).await;
    assert_eq!(active_of(&nodes[0], &b), (t1, b1.clone()), "precondition");
    // B names p by A's identifier for it.
    let ours = {
        let paths = nodes[1]
            .node
            .get_peer(&a)
            .unwrap()
            .bundle()
            .unwrap()
            .paths();
        let p = paths.get(paths.find(t1, &a1).unwrap()).unwrap();
        p.peer_id().expect("precondition: B holds A's id for p")
    };
    let close = PathClose {
        path_id: ours,
        reason: PathCloseReason::InterfaceGone,
    };
    let q = PathRef {
        transport: t2(),
        addr: a2.clone(),
    };
    nodes[1]
        .node
        .send_via(&a, &close.encode(), false, Some(&q))
        .await
        .expect("B's close goes out on q");
    let queued = take_packets(&mut nodes[0]);
    assert_eq!(queued.len(), 1, "precondition: one frame at A: {queued:?}");
    assert_eq!(
        (queued[0].transport_id, &queued[0].remote_addr),
        (t2(), &b2),
        "precondition: on q"
    );

    let (logs, guard) = crate::testutil::capture_logs_scoped();
    for packet in queued {
        hand(&mut nodes[0], packet).await;
    }
    let switched = logs.lines_with("Path switched");
    drop(guard);
    assert_eq!(state_at(&nodes[0], &b, t1, &b1), Some(PathState::Dead), "p");
    assert_eq!(active_of(&nodes[0], &b), (t2(), b2), "A moved to q");
    assert_eq!(switched.len(), 1, "{switched:?}");
    assert!(switched[0].contains("why=\"mandatory\""), "{}", switched[0]);
    assert!(nodes[0].node.get_peer(&b).is_some(), "A keeps B");
    cleanup_nodes(&mut nodes).await;
}

/// A transport removed under a link tells the peer of each path on it by a
/// `PathClose` on another Live path (draft Section 5.8), and the peer closes
/// its side: the one frame it takes, on the active path, marks its side of
/// the standby Dead, and its own traffic stays where it is.
#[tokio::test]
async fn a_removed_transport_tells_the_peer_which_closes_its_side() {
    let (mut nodes, b, a2, b2) = two_transports(1280).await;
    let a = *nodes[0].node.node_addr();
    let t1 = nodes[0].transport_id;
    let a1 = nodes[0].addr.clone();
    settle(&mut nodes, &a2).await;

    nodes[0].node.path_removed(t2()).await;
    assert_eq!(state_at(&nodes[0], &b, t2(), &b2), None, "q discarded at A");
    let queued = take_packets(&mut nodes[1]);
    assert_eq!(queued.len(), 1, "one frame at B: {queued:?}");
    assert_eq!(
        (queued[0].transport_id, &queued[0].remote_addr),
        (t1, &a1),
        "on p"
    );
    for packet in queued {
        hand(&mut nodes[1], packet).await;
    }
    assert_eq!(
        state_at(&nodes[1], &a, t2(), &a2),
        Some(PathState::Dead),
        "B closed its side of q"
    );
    assert_eq!(active_of(&nodes[1], &a), (t1, a1), "B stays on p");
    assert!(nodes[1].node.get_peer(&a).is_some(), "B keeps A");
    cleanup_nodes(&mut nodes).await;
}

/// A `backup` wire carries the link only while no path of a higher tier is
/// Live (draft Section 5.7): with a `normal` cable and a `backup` wire both
/// Live, the link stays on the cable; when the cable loses carrier the link
/// moves to the wire; and when the cable's path is Live again, the link
/// returns to it in that same step, not after a dwell. Loopback delivers
/// whatever carrier reads, so every frame on the cable is dropped from the
/// loss until carrier returns, and the cable's path cannot be answered
/// while carrier is down.
#[tokio::test]
async fn a_backup_wire_carries_the_link_only_while_nothing_else_is_live() {
    // With the clock running, time the test spends descheduled can bring
    // B's own switch back to p into the window asserted on, as a second
    // "Path switched" line.
    crate::time::freeze();
    let (mut nodes, b, a2, b2) = two_transports(1280).await;
    let t1 = nodes[0].transport_id;
    let b1 = nodes[1].addr.clone();
    for tn in nodes.iter_mut() {
        loopback_mut(tn, t2()).set_role(TransportRole::Backup);
    }
    settle(&mut nodes, &a2).await;
    let cfg = PathConfig::draft();
    let tick = Duration::from_millis(50);

    // Both Live, past enough samples and a dwell: the link stays on t1.
    let span = cfg.standby_interval * (u32::from(cfg.min_samples) + 2) + cfg.switch_dwell;
    for _ in 0..span.as_millis() / tick.as_millis() {
        crate::time::advance(tick);
        nodes[0].node.path_tick().await;
        nodes[1].node.path_tick().await;
        swap(&mut nodes).await;
        assert_eq!(active_of(&nodes[0], &b).0, t1, "the link stays on t1");
    }
    assert_eq!(state_at(&nodes[0], &b, t2(), &b2), Some(PathState::Live));
    carrier(&mut nodes, t1, true).await;
    swap(&mut nodes).await;
    assert_eq!(active_of(&nodes[0], &b), (t1, b1.clone()), "precondition");

    // Carrier lost on t1: the link moves to the wire, and t1 carries
    // nothing until carrier returns.
    carrier(&mut nodes, t1, false).await;
    assert_eq!(active_of(&nodes[0], &b), (t2(), b2.clone()), "moved to q");
    for _ in 0..20 {
        crate::time::advance(tick);
        nodes[0].node.path_tick().await;
        nodes[1].node.path_tick().await;
        for _ in 0..10 {
            hand_except(&mut nodes[1], t1).await;
            hand_except(&mut nodes[0], t1).await;
            if nodes[0].packet_rx.is_empty() && nodes[1].packet_rx.is_empty() {
                break;
            }
        }
    }
    assert_ne!(
        state_at(&nodes[0], &b, t1, &b1),
        Some(PathState::Live),
        "precondition: p not Live while carrier is down"
    );
    assert_eq!(active_of(&nodes[0], &b), (t2(), b2), "still on q");

    // Carrier returns and t1 delivers again: in the step at which p is
    // Live again, A's link is back on p.
    let (logs, guard) = crate::testutil::capture_logs_scoped();
    carrier(&mut nodes, t1, true).await;
    let mut back = None;
    'ticks: for _ in 0..40 {
        crate::time::advance(tick);
        nodes[0].node.path_tick().await;
        nodes[1].node.path_tick().await;
        for _ in 0..10 {
            let mut moved = 0;
            for packet in take_packets(&mut nodes[1]) {
                assert_ne!(phase(&packet), Some(PHASE_MSG1), "no msg1 for a new link");
                hand(&mut nodes[1], packet).await;
                moved += 1;
            }
            for packet in take_packets(&mut nodes[0]) {
                assert_ne!(phase(&packet), Some(PHASE_MSG1), "no msg1 for a new link");
                hand(&mut nodes[0], packet).await;
                moved += 1;
                if state_at(&nodes[0], &b, t1, &b1) == Some(PathState::Live) {
                    back = Some(active_of(&nodes[0], &b));
                    break 'ticks;
                }
            }
            if moved == 0 {
                break;
            }
        }
    }
    let switched = logs.lines_with("Path switched");
    drop(guard);
    let back = back.expect("p Live again within 2 s of carrier's return");
    assert_eq!(back, (t1, b1), "the link returns to p at once");
    assert_eq!(switched.len(), 1, "{switched:?}");
    assert!(
        switched[0].contains("why=\"discretionary\""),
        "{}",
        switched[0]
    );
    assert!(nodes[0].node.get_peer(&b).is_some(), "A keeps B");
    cleanup_nodes(&mut nodes).await;
}
