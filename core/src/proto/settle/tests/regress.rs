//! Scripted schedules of the settlement core in the world, on joint nodes
//! with multipath off: the two late-dial cases left for later, pinned as known defects, each beside a control;
//! and one schedule per earlier settlement defect the core can see, each
//! reaching the state the defect broke and asserting it holds (the
//! defect's shape is a switch that turns the schedule red).
//!
//! - A late second dial answered in the other order: the dialer reads its
//!   second dial's msg2 first and then moves onto the first, which the
//!   responder has replaced, so the two ends split. The operator's rule for
//!   it (the dialer keeps the session it moved off until the peer's first
//!   frame) is built later; until then the pin fails at its defect. Its
//!   control is the same dials answered in order, which settle.
//! - A dial on the peer's aged link: the larger node dials again while the
//!   smaller node holds it on a link old enough to rekey, so the smaller
//!   node takes the dial for a rekey and arms a pending, which the larger
//!   node never adopts, keeping its inbound session by the tie-break; the
//!   smaller node then leaves the larger node's own rekey unanswered while
//!   the pending is held. Its control dials on a link too young to rekey,
//!   and the larger node's later rekey is answered.

use alloc::vec::Vec;

use super::explore::Act;
use super::joint::off;
use super::oracle::{Oracle, heal, healed};
use super::starts::{Do, Maker, Want, age, dial, run, second, starts};
use super::world::{Pkt, World};

/// Start `number`'s variant named with `name`, with nodes made by `mk`.
fn built(mk: Maker, number: u8, name: &str) -> World {
    let st = starts()
        .into_iter()
        .find(|s| s.number == number && s.name.contains(name))
        .expect("the start exists");
    (st.build)(mk)
}

/// Start `number`'s variant named with `name` with nodes made by `mk`, after
/// its own script and a heal.
fn scripted(mk: Maker, number: u8, name: &str) -> World {
    let st = starts()
        .into_iter()
        .find(|s| s.number == number && s.name.contains(name))
        .expect("the start exists");
    let mut w = (st.build)(mk);
    let _ = (st.script)(&mut w);
    heal(&mut w);
    w
}

/// The splits a healed world shows.
fn splits(w: &World) -> Vec<alloc::string::String> {
    healed(w)
        .into_iter()
        .filter(|b| b.oracle == Oracle::OneSession && b.what.starts_with("split:"))
        .map(|b| b.what)
        .collect()
}

/// The splits joint nodes at multipath off at both ends show after the
/// late second dial of start `number`'s variant named with `name`, for the
/// candidate rules, which a joint node runs as the test chooses.
#[cfg(feature = "slow-tests")]
pub(super) fn late_dial_splits(number: u8, name: &str) -> Vec<alloc::string::String> {
    dial_splits(off, number, name)
}

/// The splits nodes made by `mk` show after the late second dial of start
/// `number`'s variant named with `name`, its preconditions held.
fn dial_splits(mk: Maker, number: u8, name: &str) -> Vec<alloc::string::String> {
    let w = scripted(mk, number, name);
    assert!(
        w.parties[0].held().len() == 1 && w.parties[1].held().len() == 1,
        "precondition: both ends hold the other after the schedule"
    );
    splits(&w)
}

fn one_session_after_a_late_second_dial(number: u8, name: &str) {
    let t = std::time::Instant::now();
    let split = dial_splits(off, number, name);
    std::eprintln!("{name}: {} ms", t.elapsed().as_millis());
    assert!(
        split.is_empty(),
        "defect: {name}: the two ends of a late second dial hold different sessions: {split:?}"
    );
}

#[test]
fn after_a_late_second_dial_answered_in_order_both_ends_hold_one_session_larger_dialer() {
    one_session_after_a_late_second_dial(5, "in order, larger dialer");
}

#[test]
fn after_a_late_second_dial_answered_in_order_both_ends_hold_one_session_smaller_dialer() {
    one_session_after_a_late_second_dial(5, "in order, smaller dialer");
}

#[test]
#[ignore = "known defect: a late second dial whose msg2s are read in the other order leaves the two ends on different sessions, until the dialer keeps the session it moved off"]
fn after_a_late_second_dial_answered_in_the_other_order_both_ends_hold_one_session_larger_dialer() {
    one_session_after_a_late_second_dial(6, "second msg2 first, larger dialer");
}

#[test]
#[ignore = "known defect: a late second dial whose msg2s are read in the other order leaves the two ends on different sessions, until the dialer keeps the session it moved off"]
fn after_a_late_second_dial_answered_in_the_other_order_both_ends_hold_one_session_smaller_dialer()
{
    one_session_after_a_late_second_dial(6, "second msg2 first, smaller dialer");
}

/// Node 1 (the larger) has dialed node 0 (the smaller) again, at node 0's
/// second address, on the link node 0 dialed; node 0 reads it. On the aged
/// link node 0 answers and node 1 reads the answer. On a young link node 0
/// refuses it, and the link is left to age until node 1 may rekey. Then
/// node 1 starts its own rekey and node 0 reads it. Whether node 0 answered
/// that rekey.
fn rekey_answered_after_a_second_dial(w: &mut World, aged: bool) -> bool {
    rekey_answered_after(w, aged, false)
}

/// Whether node 0 answers node 1's rekey after node 1's dial on the aged
/// link, with joint nodes at multipath off at both ends, for the candidate
/// rules, which a joint node runs as the test chooses; with `frame_first`,
/// node 1's frames sent once it read the dial's answer reach node 0, and
/// 15 s pass, before node 1 starts its rekey.
#[cfg(feature = "slow-tests")]
pub(super) fn aged_rekey_answered(frame_first: bool) -> bool {
    aged_answered(off, frame_first)
}

/// Whether node 0 answers node 1's rekey after node 1's dial on the aged
/// link, with nodes made by `mk`; `frame_first` as above.
fn aged_answered(mk: Maker, frame_first: bool) -> bool {
    let mut w = built(mk, 7, "aged link");
    assert!(
        w.parties[0].held().len() == 1 && w.parties[1].held().len() == 1,
        "precondition: the pair is up on node 0's dial"
    );
    rekey_answered_after(&mut w, true, frame_first)
}

fn rekey_answered_after(w: &mut World, aged: bool, frame_first: bool) -> bool {
    run(w, &[Do::Get(0, Want::Msg1, Some(1))]);
    if aged {
        assert!(
            w.parties[0]
                .view()
                .peers
                .first()
                .is_some_and(|p| p.pending.is_some_and(|(_, mine)| !mine)),
            "precondition: node 0 took the dial on the aged link for a rekey and holds its pending"
        );
        run(w, &[Do::Get(1, Want::Msg2, Some(0))]);
        if frame_first {
            let frames: Vec<u64> = w
                .net
                .flight
                .iter()
                .filter(|f| f.to == 0 && matches!(f.pkt, Pkt::Frame { .. }))
                .map(|f| f.id)
                .collect();
            assert!(
                !frames.is_empty(),
                "precondition: node 1 sent a frame once it read the answer"
            );
            for id in frames {
                run(w, &[Do::Then(Act::Deliver(id))]);
            }
            // Past the rekey machine's session age, so a session the
            // frame cut over to may be rekeyed.
            age(w, 15_000);
        }
    } else {
        assert!(
            !w.net
                .flight
                .iter()
                .any(|f| f.to == 1 && matches!(f.pkt, Pkt::Msg2 { .. })),
            "precondition: node 0 refuses the dial on a link too young to rekey"
        );
        age(w, 40_000);
    }
    run(w, &[Do::Then(Act::Rekey(1, 0))]);
    let rekey = w.parties[1]
        .view()
        .peers
        .first()
        .and_then(|p| p.rekey)
        .expect("precondition: node 1's own rekey is in flight");
    run(w, &[Do::Get(0, Want::Msg1, Some(1))]);
    w.net
        .flight
        .iter()
        .any(|f| f.to == 1 && matches!(f.pkt, Pkt::Msg2 { hs, .. } if hs == rekey))
}

#[test]
#[ignore = "known defect: the smaller node takes the larger node's dial on its aged link for a rekey and holds a pending the larger node never adopts, so it leaves the larger node's own rekey unanswered"]
fn after_a_dial_on_the_peers_aged_link_the_peer_answers_the_larger_nodes_rekey() {
    let t = std::time::Instant::now();
    let answered = aged_answered(off, false);
    std::eprintln!("aged link: {} ms", t.elapsed().as_millis());
    assert!(
        answered,
        "defect: node 0 left node 1's rekey unanswered after node 1's dial on the aged link"
    );
}

#[test]
fn after_a_dial_on_the_peers_young_link_the_peer_answers_the_larger_nodes_rekey() {
    // The aged-link start's world, with node 1's dial made while the link is
    // younger than the rekey machine's link age.
    let mut w = super::starts::world_of(
        off,
        &[super::starts::A, super::starts::B],
        &[&[(1, super::starts::UDP)], &[]],
    );
    super::starts::dial_home(&mut w, 0, 1, super::starts::UDP);
    super::starts::settle(&mut w);
    age(&mut w, 15_000);
    dial(&mut w, 1, 0, second(0, super::starts::UDP), None);
    assert!(
        rekey_answered_after_a_second_dial(&mut w, false),
        "node 0 answers node 1's rekey"
    );
}

/// Every breach joint nodes at both ends show on start `number`'s variant
/// named with `name`, along its script and once healed.
fn breaches(number: u8, name: &str) -> Vec<alloc::string::String> {
    let mut st = starts()
        .into_iter()
        .find(|s| s.number == number && s.name.contains(name))
        .expect("the start exists");
    st.maker = off;
    super::oracle::scripted(&st)
        .into_iter()
        .map(|b| alloc::format!("{:?} at n{}: {}", b.oracle, b.node, b.what))
        .collect()
}

/// The session node `x` holds node `y` on.
fn session(w: &World, x: usize, y: usize) -> Option<super::super::model::history::Hs> {
    let id = w.ids[y];
    w.parties[x]
        .view()
        .peers
        .iter()
        .find(|p| p.peer == id)
        .map(|p| p.cur)
}

/// Two nodes on one connection-oriented transport, node 0 dialing node 1,
/// settled.
fn stream_pair() -> World {
    let mut w = super::starts::world_of(
        off,
        &[super::starts::A, super::starts::B],
        &[&[(1, super::starts::TCP)], &[]],
    );
    super::starts::dial_home(&mut w, 0, 1, super::starts::TCP);
    super::starts::settle(&mut w);
    w
}

#[test]
fn a_removed_peers_link_leaves_no_entry_in_the_address_index() {
    // A connection-oriented pair, then the connection fails at node 0: the
    // link is retired and its address must leave the index with it.
    let mut w = stream_pair();
    assert!(
        session(&w, 1, 0).is_some(),
        "node 1 holds node 0 before the failure"
    );
    let c = w.net.conns[0].id;
    w.fail(c, 0);
    super::starts::settle(&mut w);
    let wrong: Vec<_> = super::oracle::every_step(&w)
        .into_iter()
        .filter(|b| b.oracle == Oracle::MapsAgree)
        .collect();
    assert!(wrong.is_empty(), "{wrong:?}");
}

#[test]
fn a_crossing_over_two_transports_settles_on_one_session() {
    let found = breaches(2, "two transports");
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn a_crossing_moves_the_smaller_node_with_a_reset_and_keeps_the_maps() {
    let found = breaches(1, "connectionless");
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn a_stored_answer_whose_send_failed_installs_at_the_resend() {
    let found = breaches(10, "stored msg2");
    assert!(found.is_empty(), "{found:#?}");
    let mut w = built(off, 10, "stored msg2");
    let st = starts()
        .into_iter()
        .find(|s| s.number == 10)
        .expect("the start exists");
    let _ = (st.script)(&mut w);
    assert!(
        session(&w, 1, 0).is_some() && session(&w, 0, 1) == session(&w, 1, 0),
        "the resend's answer installed one session at both ends"
    );
}

#[test]
fn a_restart_dial_inside_the_heard_floor_is_judged_on_one_clock() {
    let found = breaches(14, "wall step");
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn a_replayed_msg1_that_promoted_an_unheard_peering_stays_refused() {
    // Node 0's first msg1 promotes an unheard peering at node 1; 1.5 s
    // later node 0 restarts and its next dial replaces it; then an attacker
    // replays the first msg1. On one epoch the replaced peering's filed
    // record would refuse the replay at the rekey machine; across a restart
    // the replay comes to the core's gates, as a restart, and only the
    // replay memory can refuse it.
    let mut w = super::starts::world_of(off, &[super::starts::A, super::starts::B], &[&[], &[]]);
    super::starts::dial_home(&mut w, 0, 1, super::starts::UDP);
    run(&mut w, &[Do::Get(1, Want::Msg1, Some(0))]);
    let first = session(&w, 1, 0).expect("precondition: the first msg1 promoted node 0");
    w.run_until(1_500);
    run(&mut w, &[Do::Then(Act::Restart(0))]);
    super::starts::dial_home(&mut w, 0, 1, super::starts::UDP);
    run(&mut w, &[Do::Get(1, Want::Msg1, Some(0))]);
    let second = session(&w, 1, 0).expect("node 1 holds node 0");
    assert_ne!(
        first, second,
        "precondition: the second msg1 replaced the first"
    );
    // Past the unheard floor of the second peering.
    w.run_until(2_700);
    run(
        &mut w,
        &[Do::Then(Act::Replay(0)), Do::Get(1, Want::Msg1, Some(0))],
    );
    assert_eq!(
        session(&w, 1, 0),
        Some(second),
        "the replayed first msg1 left node 1 on the second session"
    );
}

#[test]
fn an_own_dial_answered_from_a_restarted_peer_replaces_the_stale_session() {
    // Node 0 dialed node 1, which answered and was heard; node 1 restarts
    // unnoticed, and node 0 dials it again one second after its last
    // frame. The answer carries node 1's new epoch: node 0 must take it
    // as a restart and hold the new session, inside the heard floor too.
    let mut w = super::starts::world_of(off, &[super::starts::A, super::starts::B], &[&[], &[]]);
    super::starts::dial_home(&mut w, 0, 1, super::starts::UDP);
    super::starts::settle(&mut w);
    w.run_until(2_000);
    super::starts::settle(&mut w);
    let old = session(&w, 0, 1).expect("precondition: node 0 holds node 1");
    run(&mut w, &[Do::Then(Act::Frame(1))]);
    super::starts::settle(&mut w);
    run(&mut w, &[Do::Then(Act::Restart(1))]);
    super::starts::dial_home(&mut w, 0, 1, super::starts::UDP);
    run(
        &mut w,
        &[
            Do::Get(1, Want::Msg1, Some(0)),
            Do::Get(0, Want::Msg2, Some(1)),
        ],
    );
    let new = session(&w, 1, 0).expect("precondition: node 1 answered the dial");
    assert_ne!(new, old, "precondition: node 1's session is new");
    assert_eq!(
        session(&w, 0, 1),
        Some(new),
        "node 0 replaced the stale session with the restarted peer's"
    );
}

#[test]
fn a_second_restart_inside_the_dampener_interval_is_refused() {
    // Node 0 holds node 1, heard. Node 1 restarts and dials once the heard
    // floor has passed and before node 0's liveness timer would remove it,
    // and node 0 takes the restart, which stamps the dampener. Ten seconds
    // later node 1 restarts and dials again,
    // past the new peering's unheard floor and inside the dampener's
    // interval: node 0 refuses it and keeps the first restart's session.
    let mut w = super::starts::world_of(off, &[super::starts::A, super::starts::B], &[&[], &[]]);
    super::starts::dial_home(&mut w, 0, 1, super::starts::UDP);
    super::starts::settle(&mut w);
    age(&mut w, 2_000);
    run(&mut w, &[Do::Then(Act::Restart(1))]);
    age(&mut w, 20_000);
    super::starts::dial_home(&mut w, 1, 0, super::starts::UDP);
    run(&mut w, &[Do::Get(0, Want::Msg1, Some(1))]);
    let first = session(&w, 0, 1).expect("node 0 holds node 1");
    assert!(
        w.parties[1].view().peers.is_empty(),
        "precondition: node 1 has not read node 0's answer"
    );
    let at = w.net.now + 10_000;
    w.run_until(at);
    run(&mut w, &[Do::Then(Act::Restart(1))]);
    super::starts::dial_home(&mut w, 1, 0, super::starts::UDP);
    run(&mut w, &[Do::Get(0, Want::Msg1, Some(1))]);
    assert_eq!(
        session(&w, 0, 1),
        Some(first),
        "node 0 refused the second restart inside the dampener interval"
    );
}
