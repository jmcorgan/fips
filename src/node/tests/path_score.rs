//! Which of two Live paths carries a link when one is a cable with a round
//! trip of about a millisecond and the other Wi-Fi with a round trip of 6
//! to 16 ms, at equal loss, under the default selection settings (margin
//! 1.3, dwell 2 s, two samples). Two loopback nodes with multipath on, the
//! clock moved only by `crate::time::advance`, and every frame held back
//! for its lane's one-way delay before it is handed over, so each path's
//! round trip is exactly twice its lane's delay.
//!
//! The link is made on the Wi-Fi transport, as when a cable is plugged in
//! beside a link already up, and the cable's path is offered afterwards.
//! Each lane reports a medium, as an interface-bound transport does once it
//! has read its interface: Wi-Fi wireless and the cable wired, unless a
//! test leaves both unknown, as UDP and TCP report. In the field both paths
//! are often on the Ethernet transport, one on a Wi-Fi interface and one on
//! a wired one, so they report the same type and only the medium tells them
//! apart.

use super::paths::{active_of, enabled, hand, loopback_mut, second_transport, state_at, t2};
use super::spanning_tree::{
    TestNode, cleanup_nodes, drain_all_packets, initiate_handshake, make_test_node_with_config,
};
use super::*;
use crate::config::TransportRole;
use crate::peer::PathState;
use crate::proto::path::Medium;
use crate::transport::TransportType;

/// The step the clock moves by between deliveries.
const STEP: Duration = Duration::from_micros(250);

/// The gap between path ticks at each node.
const TICK: Duration = Duration::from_millis(50);

/// One transport of the pair, the same at both nodes.
#[derive(Clone, Copy)]
struct Lane {
    /// The type the transport reports.
    ty: &'static TransportType,
    /// Its configured role at both nodes.
    role: TransportRole,
    /// The medium it reports at both nodes.
    medium: Medium,
    /// The round trip of a path on it: each frame is held for half.
    rtt: Duration,
}

impl Lane {
    /// Wi-Fi with round trip `rtt`, role `normal`, wireless, no loss.
    fn wifi(rtt_ms: u64) -> Self {
        Self {
            ty: &TransportType::WIFI,
            role: TransportRole::Normal,
            medium: Medium::Wireless,
            rtt: Duration::from_millis(rtt_ms),
        }
    }

    /// A cable with a round trip of 1 ms, role `normal`, wired, no loss.
    fn cable() -> Self {
        Self {
            ty: &TransportType::ETHERNET,
            role: TransportRole::Normal,
            medium: Medium::Wired,
            rtt: Duration::from_millis(1),
        }
    }

    /// Wi-Fi under the Ethernet transport, as on a Wi-Fi interface such
    /// as macOS `en0`: it reports the `ethernet` type, as the cable does,
    /// and the wireless medium its interface reads as.
    fn wifi_on_ethernet(rtt_ms: u64) -> Self {
        Self {
            ty: &TransportType::ETHERNET,
            ..Self::wifi(rtt_ms)
        }
    }

    /// This lane with role `role`.
    fn role(self, role: TransportRole) -> Self {
        Self { role, ..self }
    }

    /// This lane with its medium unknown, as a transport that cannot tell
    /// which interface its paths leave by reports it.
    fn unknown(self) -> Self {
        Self {
            medium: Medium::Unknown,
            ..self
        }
    }
}

/// What a run ends with at one node.
#[derive(Debug)]
struct End {
    /// The transport its link is on at the end.
    on: TransportId,
    /// How many times its active path changed.
    moves: usize,
    /// Per transport (t1, then t2): the path's state, its least round trip
    /// in ms, its ETX, and its score.
    paths: [(Option<PathState>, f64, f64, f64); 2],
}

/// The state, least round trip, ETX and score of `tn`'s path to `peer` on
/// `transport` at `addr`.
fn path_of(
    tn: &TestNode,
    peer: &NodeAddr,
    transport: TransportId,
    addr: &TransportAddr,
) -> (Option<PathState>, f64, f64, f64) {
    let state = state_at(tn, peer, transport, addr);
    let paths = tn.node.get_peer(peer).unwrap().bundle().unwrap().paths();
    let Some(i) = paths.find(transport, addr) else {
        return (state, f64::NAN, f64::NAN, f64::NAN);
    };
    let live = paths.get(i).unwrap().live();
    let rtt = live
        .min_rtt()
        .map_or(f64::NAN, |d| d.as_secs_f64() * 1000.0);
    let etx = live.etx();
    let score = crate::proto::mmp::quality_index(etx, rtt);
    (state, rtt, etx, score)
}

/// Link two nodes with multipath on over their first transport, `first`,
/// give each a second transport, `second`, have A offer its path to B's
/// second address, and run `secs` seconds of path ticks with every frame
/// held for its lane's one-way delay. Returns each node's end.
async fn run(first: Lane, second: Lane, secs: u64) -> [End; 2] {
    crate::time::freeze();
    let mut nodes = vec![
        make_test_node_with_config(enabled(), 1280).await,
        make_test_node_with_config(enabled(), 1280).await,
    ];
    let t1 = nodes[0].transport_id;
    for tn in nodes.iter_mut() {
        let lo = loopback_mut(tn, t1);
        lo.typed((*first.ty).clone());
        lo.set_role(first.role);
        lo.set_medium(first.medium);
    }
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    assert!(nodes[0].node.get_peer(&b).is_some(), "precondition: peered");
    let a2 = second_transport(&mut nodes[0], t2(), 1280);
    let b2 = second_transport(&mut nodes[1], t2(), 1280);
    for tn in nodes.iter_mut() {
        let lo = loopback_mut(tn, t2());
        lo.typed((*second.ty).clone());
        lo.set_role(second.role);
        lo.set_medium(second.medium);
    }
    let (a1, b1) = (nodes[0].addr.clone(), nodes[1].addr.clone());
    assert_eq!(active_of(&nodes[0], &b).0, t1, "precondition: made on t1");
    assert_eq!(active_of(&nodes[1], &a).0, t1, "precondition: made on t1");
    nodes[0].node.offer_path(&b, t2(), b2.clone()).await;

    let lane = |t: TransportId| if t == t1 { first } else { second };
    let mut held: Vec<(Duration, usize, ReceivedPacket)> = Vec::new();
    let mut now = Duration::ZERO;
    let mut on = [t1, t1];
    let mut moves = [0, 0];
    let end = Duration::from_secs(secs);
    while now < end {
        crate::time::advance(STEP);
        now += STEP;
        if now.as_micros().is_multiple_of(TICK.as_micros()) {
            nodes[0].node.path_tick().await;
            nodes[1].node.path_tick().await;
        }
        loop {
            for (i, tn) in nodes.iter_mut().enumerate() {
                while let Ok(packet) = tn.packet_rx.try_recv() {
                    let delay = lane(packet.transport_id).rtt / 2;
                    held.push((now + delay, i, packet));
                }
            }
            let (due, rest): (Vec<_>, Vec<_>) = held.drain(..).partition(|(at, _, _)| *at <= now);
            held = rest;
            if due.is_empty() {
                break;
            }
            for (_, i, packet) in due {
                hand(&mut nodes[i], packet).await;
            }
        }
        let active = [active_of(&nodes[0], &b).0, active_of(&nodes[1], &a).0];
        for i in 0..2 {
            if active[i] != on[i] {
                moves[i] += 1;
                on[i] = active[i];
            }
        }
    }
    let ends = [
        End {
            on: on[0],
            moves: moves[0],
            paths: [
                path_of(&nodes[0], &b, t1, &b1),
                path_of(&nodes[0], &b, t2(), &b2),
            ],
        },
        End {
            on: on[1],
            moves: moves[1],
            paths: [
                path_of(&nodes[1], &a, t1, &a1),
                path_of(&nodes[1], &a, t2(), &a2),
            ],
        },
    ];
    for (i, e) in ends.iter().enumerate() {
        println!(
            "node {i}: on {} after {} moves; t1 {:?}; t2 {:?}",
            e.on, e.moves, e.paths[0], e.paths[1]
        );
    }
    cleanup_nodes(&mut nodes).await;
    ends
}

/// Assert both ends' paths on t1 and t2 are Live, so the outcome is a
/// choice between two Live paths and not a failover.
fn both_live(ends: &[End; 2]) {
    for (i, e) in ends.iter().enumerate() {
        for (t, p) in e.paths.iter().enumerate() {
            assert_eq!(p.0, Some(PathState::Live), "node {i}'s path on t{}", t + 1);
        }
    }
}

/// Wi-Fi and a cable between two nodes: a cable with a tenth to a sixteenth
/// of Wi-Fi's round trip never took a link made on Wi-Fi, at either end,
/// since the cable had to score better by the margin 1.3: Wi-Fi at 10 ms
/// scores 1.10 against the cable's 1.01, and at 16 ms 1.16. Neither lane
/// loses a frame, so both ETXs are 1.0. With each transport reporting its
/// medium, the cable, within the margin of the best score and on the
/// faster medium, takes the link at both ends by one move after the dwell.
#[tokio::test]
async fn a_cable_with_a_tenth_to_a_sixteenth_of_wifis_round_trip_takes_a_link_made_on_wifi_at_both_ends()
 {
    let mut wrong = Vec::new();
    for rtt in [10, 16] {
        let label = format!("Wi-Fi at {rtt} ms");
        let ends = run(Lane::wifi(rtt), Lane::cable(), 60).await;
        both_live(&ends);
        for (i, e) in ends.iter().enumerate() {
            if e.on != t2() || e.moves != 1 {
                wrong.push(format!(
                    "{label}: node {i} is on {} after {} moves in 60 s with the cable Live; \
                     Wi-Fi (state, rtt ms, etx, score) {:?}, cable {:?}",
                    e.on, e.moves, e.paths[0], e.paths[1]
                ));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "defect: the cable does not take the link from Wi-Fi by one move\n{}",
        wrong.join("\n")
    );
}

/// The workaround before the medium ranked paths, which still holds: with
/// `role: preferred` on the cable at both nodes, the same cable takes the
/// link made on Wi-Fi at both ends, by one move each, and keeps it.
#[tokio::test]
async fn with_role_preferred_on_the_cable_it_takes_a_link_made_on_wifi_at_both_ends() {
    let ends = run(
        Lane::wifi(10),
        Lane::cable().role(TransportRole::Preferred),
        20,
    )
    .await;
    both_live(&ends);
    for (i, e) in ends.iter().enumerate() {
        assert_eq!(e.on, t2(), "node {i} ends on the cable");
        assert_eq!(e.moves, 1, "node {i} moves once");
    }
}

/// The switch rule where neither medium is known, as on UDP: with the
/// cable at 1 ms, a link made on Wi-Fi stays there while Wi-Fi's round trip
/// is at most 30 ms, and moves to the cable once it is 32 ms. The boundary
/// is where Wi-Fi's score, 1 + rtt/100, passes 1.3 times the cable's 1.01,
/// at 31.3 ms; round trip is the only thing that differs between the two
/// paths, so it alone decides.
#[tokio::test]
async fn with_neither_medium_known_a_normal_cable_takes_a_link_made_on_wifi_only_once_wifis_round_trip_passes_the_margin()
 {
    for (rtt, moves) in [(10, false), (16, false), (30, false), (32, true)] {
        let ends = run(Lane::wifi(rtt).unknown(), Lane::cable().unknown(), 20).await;
        both_live(&ends);
        for (i, e) in ends.iter().enumerate() {
            let want = if moves { t2() } else { TransportId::new(1) };
            assert_eq!(
                e.on, want,
                "Wi-Fi at {rtt} ms: node {i}; Wi-Fi {:?}, cable {:?}",
                e.paths[0], e.paths[1]
            );
        }
    }
}

/// Made on the cable, the link stays on the cable with Wi-Fi Live beside
/// it: the cable scores best and runs over the faster medium.
#[tokio::test]
async fn a_link_made_on_the_cable_stays_there_with_wifi_live_beside_it() {
    let ends = run(Lane::cable(), Lane::wifi(10), 20).await;
    both_live(&ends);
    for (i, e) in ends.iter().enumerate() {
        assert_eq!(e.on, TransportId::new(1), "node {i} stays on the cable");
        assert_eq!(e.moves, 0, "node {i} never moves");
    }
}

/// Wi-Fi and a cable, both on the Ethernet transport: one path over a Wi-Fi
/// interface and one over a cable, so both report the `ethernet` type and
/// a rank by transport type could not tell them apart. The media the
/// transport reads from its two interfaces do: the link made on Wi-Fi moves
/// to the cable at both ends, once.
#[tokio::test]
async fn with_both_paths_on_the_ethernet_transport_the_detected_media_tell_the_cable_from_wifi() {
    let ends = run(Lane::wifi_on_ethernet(10), Lane::cable(), 20).await;
    both_live(&ends);
    for (i, e) in ends.iter().enumerate() {
        assert!(
            e.on == t2() && e.moves == 1,
            "defect: node {i} is on {} after {} moves, not on the cable after one; \
             Wi-Fi {:?}, cable {:?}",
            e.on,
            e.moves,
            e.paths[0],
            e.paths[1]
        );
    }
}
