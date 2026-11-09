//! Known-defect pins of what the joint world found.
//!
//! Each test asserts what the node does and fails today at its `defect:`
//! assertion; it is ignored, listed as a known defect in
//! `testing/ignored-tests.txt`, and run by the known-defect lane, which
//! reds when one passes, so the fix removes both. A pin's preconditions
//! state the shape it needs and fail as `precondition:`, which the lane
//! counts as the pin no longer showing its defect.

use alloc::string::String;
use alloc::vec::Vec;

use super::super::explore::{Act, apply, replay};
use super::super::oracle::{Breach, Oracle, heal, healed};
use super::super::starts::{BLE, TCP, second};
use super::super::world::{Dir, State, World};

#[test]
#[ignore = "known defect: a crossing whose own dial is answered over the peer's dial connection moves the peering onto that connection's pair and closes the connection in the same step, so both ends then lose the link"]
fn a_crossing_moved_onto_the_pair_of_the_peers_dial_keeps_that_connection_open() {
    // The named start with two paths as `../starts.rs` writes it, with no
    // paths, its nodes joint nodes at Off at both ends: node 0 dials node 1
    // on BLE, and node 1 dials node 0 from its second BLE address. Its first three script steps: node 1 reads node 0's msg1
    // and answers, node 0 reads node 1's msg1 and answers, and node 0 reads
    // the answer to its own dial, which came over node 1's dial connection.
    let mut st = super::super::starts::starts()
        .into_iter()
        .find(|s| s.number == 12)
        .expect("the named start with two paths");
    st.maker = super::off;
    let mut scratch = replay(&st, &[]);
    let script = (st.script)(&mut scratch);
    let mut w = replay(&st, &[]);
    let dialed = w
        .net
        .conns
        .iter()
        .find(|c| c.ends[0].node == 1 && c.ends[1].node == 0)
        .map(|c| c.id)
        .expect("precondition: node 1's dial connection to node 0");
    for &a in script.iter().take(3) {
        apply(&mut w, a);
    }
    let id = w.ids[1];
    let p = w.parties[0]
        .view()
        .peers
        .into_iter()
        .find(|p| p.peer == id)
        .expect("precondition: node 0 holds node 1");
    assert_eq!(
        (p.dir, p.current),
        (Dir::Outbound, second(1, BLE)),
        "precondition: node 0 moved node 1 onto its own dial's link, at the pair node 1's dial connection comes from"
    );
    let state = w.net.conns[dialed as usize].state;
    assert_eq!(
        state,
        State::Open,
        "defect: node 0 closed the connection its peering was just moved onto"
    );
}

/// Start `number` at On with On.
fn on(number: u8) -> super::super::starts::Start {
    super::starts::on()
        .into_iter()
        .find(|s| s.number == number)
        .expect("the start")
}

#[test]
#[ignore = "known defect: the bundle asks for a connection only for a path it admitted from a candidate or whose connect failed, never after a failed send, so a proven path whose connection fails is not connected again and stays acknowledged and counted, with no connection, until its Dead grace ends"]
fn a_proven_path_whose_connection_failed_is_not_counted_in_use_without_a_connection() {
    // The crossing over two transports, multipath on at both ends. Node 1
    // holds node 0 on UDP, turns capable, and asks for a connection to node
    // 0's configured TCP home, which is its own crossing dial's connection;
    // the two bundles prove a TCP path over it. Then that connection fails,
    // and the link lives on over UDP.
    use super::super::explore::Act::{Connect, Deliver, Leap};
    let st = on(2);
    let mut w = replay(
        &st,
        &[
            Deliver(0),
            Deliver(1),
            Deliver(2),
            Deliver(5),
            Connect(0, true),
            Leap,
        ],
    );
    let c = w.net.conns[0].clone();
    assert_eq!(
        (c.state, c.ends[0].remote.transport),
        (State::Open, TCP),
        "precondition: the TCP connection is open"
    );
    for e in c.ends {
        assert!(
            w.parties[e.node].view().needs.contains(&e.remote),
            "precondition: node {} counts its TCP path at {:?}",
            e.node,
            e.remote
        );
    }
    apply(&mut w, Act::Fail(0, 0));
    heal(&mut w);
    for x in [0, 1] {
        let y = w.ids[1 - x];
        assert!(
            w.parties[x].held().contains(&y),
            "precondition: node {x} still holds its peer over UDP"
        );
    }
    let closed: Vec<Breach> = healed(&w)
        .into_iter()
        .filter(|b| {
            b.oracle == Oracle::ConnectionsInUse && b.what.ends_with("its connection closed")
        })
        .collect();
    assert!(
        closed.is_empty(),
        "defect: once healed, a node counts a TCP path in use whose connection failed and was never opened again: {closed:?}"
    );
}

/// The pinned clauses of the joint world's oracles that node `x` of `w`
/// shows, of `pin`.
fn shown(w: &World, x: usize, pin: super::oracle::Pin) -> Vec<String> {
    super::oracle::pinned_in(w)
        .into_iter()
        .filter(|(y, p, _)| *y == x && *p == pin)
        .map(|(_, _, what)| what)
        .collect()
}

/// What node `x`'s shell holds for its one held peer.
fn shell(w: &World, x: usize) -> super::oracle::Shell {
    w.parties[x]
        .joint()
        .and_then(|f| f.peers.into_iter().next())
        .and_then(|p| p.shell)
        .unwrap_or_else(|| panic!("precondition: node {x} holds a peer with machines"))
}

/// Start 2's world at Off with Off after its script, settled; then node
/// 1's heartbeat arriving at node 0 from node 1's TCP address on the link
/// the crossing left, `TCP 1001`.
fn crossed_off() -> World {
    use super::super::starts::{TCP, settle};
    let st = super::starts::off()
        .into_iter()
        .find(|s| s.number == 2)
        .expect("the start");
    let mut w = replay(&st, &[]);
    let _ = (st.script)(&mut w);
    settle(&mut w);
    super::super::starts::age(&mut w, 40_000);
    let pkt = super::feeds::beat(&mut w, 1, 0);
    let off = super::super::super::model::history::Addr {
        transport: TCP,
        at: 1001,
    };
    super::feeds::arrive(&mut w, 0, off, pkt);
    w
}

/// The first rekey msg1 node 1 sends node 0, taken out of flight.
fn rekey_msg1(w: &mut World) -> super::super::world::Pkt {
    use super::super::world::{Input, Pkt};
    w.net.flight.clear();
    let peer = w.ids[0];
    w.input(1, Input::Rekey { peer });
    let i = w
        .net
        .flight
        .iter()
        .position(|f| f.to == 0 && matches!(f.pkt, Pkt::Msg1 { .. }))
        .expect("precondition: node 1 sends a rekey msg1");
    w.net.flight.remove(i).pkt
}

#[test]
#[ignore = "known defect in the unwired core: a frame from a pair other than the active path moves the core's record of where the peer is there, where the bundle and the node keep the peer at the active path"]
fn a_frame_from_another_transport_leaves_the_cores_record_of_the_peer_at_the_active_path() {
    // The crossing over two transports at Off with Off: node 0 holds node
    // 1 over UDP, and a heartbeat of node 1's arrives from the TCP address
    // of the link the crossing left. A one-path bundle does not roam
    // across transports.
    let w = crossed_off();
    let s = shell(&w, 0);
    assert_eq!(
        s.active,
        Some(super::super::starts::home(1, super::super::starts::UDP)),
        "precondition: node 0's bundle keeps its one path on UDP"
    );
    let wrong = shown(&w, 0, super::oracle::Pin::Current);
    assert!(
        wrong.is_empty(),
        "defect: the core's record of the peer followed the frame off the active path: {wrong:?}"
    );
}

#[test]
#[ignore = "known defect in the unwired core: a switch of the active path updates the path's state only, so the core's record of where the peer is stays at the old active path"]
fn a_switch_moves_the_cores_record_of_the_peer_to_the_new_active_path() {
    // Two Live paths at On with On, UDP active; node 0's UDP transport
    // loses carrier, and its bundle switches to the TCP path.
    use super::super::starts::{TCP, UDP, home};
    use super::super::world::{Input, PathEv};
    let mut w = super::feeds::crossed(super::on);
    assert_eq!(
        shell(&w, 0).active,
        Some(home(1, UDP)),
        "precondition: node 0's active path is UDP"
    );
    w.input(
        0,
        Input::Path(PathEv::Carrier {
            transport: UDP,
            up: false,
        }),
    );
    assert_eq!(
        shell(&w, 0).active,
        Some(home(1, TCP)),
        "precondition: node 0's bundle switched to the TCP path"
    );
    let wrong = shown(&w, 0, super::oracle::Pin::Current);
    assert!(
        wrong.is_empty(),
        "defect: the core still has the peer at the path switched away from: {wrong:?}"
    );
}

#[test]
#[ignore = "known defect in the unwired core: the core counts a held link's setup pair as on the link for life, where the node counts a capable peer's pair that no path holds as off it"]
fn a_msg1_from_a_capable_peers_setup_pair_with_no_path_is_off_the_link() {
    // Two Live paths at On with On; node 0's UDP transport goes, taking
    // the setup pair's path, and the link lives on over TCP. Node 1's
    // rekey msg1 then arrives at node 0 from the setup pair.
    use super::super::starts::{TCP, UDP, home};
    use super::super::world::{Input, PathEv};
    let mut w = super::feeds::crossed(super::on);
    w.input(0, Input::Path(PathEv::Gone { transport: UDP }));
    let s = shell(&w, 0);
    assert!(
        s.active == Some(home(1, TCP)) && s.paths.iter().all(|(a, _)| *a != home(1, UDP)),
        "precondition: node 0's link lives on over TCP with no path at the setup pair: {s:?}"
    );
    let msg1 = rekey_msg1(&mut w);
    super::feeds::arrive(&mut w, 0, home(1, UDP), msg1);
    let wrong = shown(&w, 0, super::oracle::Pin::Attribution);
    assert!(
        wrong.is_empty(),
        "defect: the core took a msg1 from a capable peer's setup pair, at which no path is held, as on the link: {wrong:?}"
    );
}

#[test]
#[ignore = "known defect in the unwired core: a switch records the path switched to as Live whatever its state, where the bundle holds an acknowledged path that is not Live"]
fn a_switch_to_a_path_that_is_not_live_leaves_it_acknowledged_in_the_core() {
    // Two Live paths at On with On, UDP active: node 0's TCP transport
    // loses carrier, so the TCP path goes Suspect, and then its UDP
    // transport goes, so the bundle hands over to the Suspect TCP path.
    use super::super::starts::{TCP, UDP, home};
    use super::super::world::{Input, PathEv};
    use crate::proto::settle::links::Proven;
    let mut w = super::feeds::crossed(super::on);
    w.input(
        0,
        Input::Path(PathEv::Carrier {
            transport: TCP,
            up: false,
        }),
    );
    w.input(0, Input::Path(PathEv::Gone { transport: UDP }));
    let s = shell(&w, 0);
    assert!(
        s.active == Some(home(1, TCP)) && s.paths.contains(&(home(1, TCP), Proven::Acked)),
        "precondition: node 0's bundle handed over to its TCP path, acknowledged and not Live: {s:?}"
    );
    let wrong = shown(&w, 0, super::oracle::Pin::SwitchedLive);
    assert!(
        wrong.is_empty(),
        "defect: the core records the path switched to as Live: {wrong:?}"
    );
}

#[test]
#[ignore = "known defect in the unwired core: the core counts the pair its record of the peer followed a frame to as on the link, where the node counts a pair no path or index entry holds as off it"]
fn a_msg1_from_the_pair_a_frame_from_another_transport_came_from_is_off_the_link() {
    // As the frame's pin: node 0's core has followed node 1's heartbeat to
    // the TCP address of the link the crossing left. Node 1's rekey msg1
    // then arrives from there.
    let mut w = crossed_off();
    let off = super::super::super::model::history::Addr {
        transport: super::super::starts::TCP,
        at: 1001,
    };
    let id = w.ids[1];
    let current = w.parties[0]
        .view()
        .peers
        .into_iter()
        .find(|p| p.peer == id)
        .map(|p| p.current);
    assert_eq!(
        current,
        Some(off),
        "precondition: node 0's core has node 1 at the frame's source"
    );
    let msg1 = rekey_msg1(&mut w);
    super::feeds::arrive(&mut w, 0, off, msg1);
    let wrong = shown(&w, 0, super::oracle::Pin::Attribution);
    assert!(
        wrong.is_empty(),
        "defect: the core took a msg1 from a pair no path or index entry holds as on the link: {wrong:?}"
    );
}

#[test]
#[ignore = "known defect in the unwired core: the core counts the pair its record of the peer followed a frame to as on the link, where the node counts a pair whose path is still probing as off it"]
fn a_msg1_from_the_pair_a_frame_moved_the_cores_record_to_whose_path_is_probing_is_off_the_link() {
    // Found by the sweep of the crossing over two transports at On with
    // On. Node 1 holds node 0 on its own TCP dial's link; a frame of node
    // 0's from its UDP home moves node 1's core's record of node 0 there,
    // and node 1's bundle holds a probing path at that pair. Node 0's dial
    // msg1, resent from the UDP home during the heal, then reaches node 1.
    use super::super::explore::Act::{Connect, Deliver};
    use super::super::starts::{UDP, home};
    use crate::proto::settle::links::Proven;
    let st = on(2);
    let mut w = replay(
        &st,
        &[
            Connect(0, true),
            Deliver(1),
            Deliver(2),
            Deliver(3),
            Deliver(5),
            Deliver(6),
            Deliver(8),
        ],
    );
    let id = w.ids[0];
    let current = w.parties[1]
        .view()
        .peers
        .into_iter()
        .find(|p| p.peer == id)
        .map(|p| p.current);
    let s = shell(&w, 1);
    assert!(
        current == Some(home(0, UDP)) && s.paths.contains(&(home(0, UDP), Proven::Probing)),
        "precondition: node 1's core has node 0 at its UDP home, where node 1's bundle holds a probing path: {current:?}, {s:?}"
    );
    heal(&mut w);
    let wrong = shown(&w, 1, super::oracle::Pin::Attribution);
    assert!(
        wrong.is_empty(),
        "defect: the core took a msg1 from a pair whose path is still probing as on the link: {wrong:?}"
    );
}
