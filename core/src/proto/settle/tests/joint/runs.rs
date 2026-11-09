//! The per-start runs of the joint world that the switches' rows name: the
//! cheapest test that shows each guard of the core can fail in a world of
//! joint nodes, and the two rekey schedules that reach the rekey machine's
//! own rules on simultaneous rekeys and on a refused msg1 coming again.
//!
//! A switch the scripts red is named on every start's script at both
//! settings, here at On with On and in `party.rs` at Off with Off. A
//! switch only a sweep reds is named on the one start's sweep with the
//! fewest states that reds it, at Off with Off. The rekey schedules are
//! written out step by step, since no explored path holds them: a start
//! offers one rekey per path, and none delivers a rekey msg1 from a pair
//! the link holds no path at.

use alloc::format;
use alloc::vec::Vec;

use super::super::super::model::history::{Addr, Event, Hs};
use super::super::super::model::judge::Class;
use super::super::explore::{Act, apply, reached, replay};
use super::super::oracle::{Breach, every_step, heal, healed, scripted};
use super::super::shadow::{Entry, Rec};
use super::super::starts::Start;
use super::super::starts::{B, Do, UDP, Want, age, flipped, home, run, second, settle, starts};
use super::super::world::{Pkt, World};
use super::Mode;
use super::explore::{chosen, pairing, swept};
use super::feeds::{arrive, paired, peer};

/// The sweep at Off with Off of the start named `name` alone, with every
/// breach it finds.
fn sweep_off(name: &str) -> Vec<alloc::string::String> {
    swept(
        &chosen(super::starts::off(), |s| s.name == name),
        &pairing(Mode::Off, Mode::Off),
    )
}

/// The wall step start alone, from the starts of one pairing.
const WALL: &str = "wall step inside the heard floor";

/// What is wrong with the reach of the wall step start, alone, at the
/// pairing whose starts `starts` gives and whose label is `label`.
fn reach_wall(starts: Vec<Start>, label: &str) -> Vec<alloc::string::String> {
    let st: Vec<Start> = starts.into_iter().filter(|s| s.name == WALL).collect();
    assert_eq!(st.len(), 1, "the wall step start is one start");
    reached(&st, label)
}

/// What node `x` logged for the msg1 of handshake `hs`, the first time.
fn logged(w: &World, x: usize, hs: Hs) -> Option<Rec> {
    w.parties[x].view().log.into_iter().find_map(|e| match e {
        Entry::Ev {
            ev: Event::Msg1 { hs: h, .. },
            rec,
            ..
        } if h == hs => Some(rec),
        Entry::Ev { .. }
        | Entry::Abandon { .. }
        | Entry::Unadopted { .. }
        | Entry::Restart
        | Entry::Fallback => None,
    })
}

/// The msg1 node `x` sends node `y`, taken out of flight with the address
/// it was sent from.
fn msg1_of(w: &mut World, x: usize, y: usize) -> (Addr, Pkt) {
    let id = w.ids[x];
    let i = w
        .net
        .flight
        .iter()
        .position(|f| f.to == y && matches!(f.pkt, Pkt::Msg1 { id: s, .. } if s == id))
        .unwrap_or_else(|| panic!("n{x} sends n{y} a msg1"));
    let f = w.net.flight.remove(i);
    (f.src, f.pkt)
}

/// Whether node `x` has a msg2 for node `y` in flight.
fn answers(w: &World, x: usize, y: usize) -> bool {
    let id = w.ids[x];
    w.net
        .flight
        .iter()
        .any(|f| f.to == y && matches!(f.pkt, Pkt::Msg2 { id: s, .. } if s == id))
}

/// The handshake a msg1 names.
fn named(pkt: Pkt) -> Hs {
    match pkt {
        Pkt::Msg1 { hs, .. } => hs,
        other @ (Pkt::Msg2 { .. } | Pkt::Frame { .. } | Pkt::Eof) => panic!("a msg1: {other:?}"),
    }
}

#[test]
fn every_start_settles_scripted_on_with_on() {
    let mut wrong = Vec::new();
    for st in starts().into_iter().filter(|s| !matches!(s.number, 6 | 7)) {
        let mut st = st;
        st.maker = super::on;
        for b in scripted(&st) {
            wrong.push(format!(
                "{} (on with on): {:?} at n{}: {}",
                st.name, b.oracle, b.node, b.what
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_reach_of_start_14_stays_within_its_cap_off_with_off() {
    let wrong = reach_wall(super::starts::off(), &pairing(Mode::Off, Mode::Off));
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_reach_of_start_14_stays_within_its_cap_on_with_on() {
    let wrong = reach_wall(super::starts::on(), &pairing(Mode::On, Mode::On));
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_reach_of_start_14_stays_within_its_cap_on_with_off() {
    let wrong = reach_wall(super::starts::on_off(), &pairing(Mode::On, Mode::Off));
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_reach_of_start_14_stays_within_its_cap_off_with_on() {
    let wrong = reach_wall(super::starts::off_on(), &pairing(Mode::Off, Mode::On));
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_sweep_of_start_14_keeps_the_properties_off_with_off() {
    let wrong = sweep_off(WALL);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_sweep_of_the_drain_start_keeps_the_properties_off_with_off() {
    let wrong = sweep_off("crossing during a rekey's drain");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_sweep_of_start_10_keeps_the_properties_off_with_off() {
    let wrong = sweep_off("stored msg2 whose send failed, then a resend");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_sweep_of_start_12_keeps_the_properties_on_with_on() {
    let wrong = swept(
        &chosen(super::starts::on(), |s| s.number == 12),
        &pairing(Mode::On, Mode::On),
    );
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn simultaneous_rekeys_settle_on_one_session() {
    let mut st = starts()
        .into_iter()
        .find(|s| s.number == 1)
        .expect("start 1 exists");
    st.maker = super::off;
    let mut scratch = replay(&st, &[]);
    let script = (st.script)(&mut scratch);
    let mut w = replay(&st, &script);
    settle(&mut w);
    age(&mut w, 40_000);
    let first = peer(&w, 0, 1).cur;
    assert_eq!(peer(&w, 1, 0).cur, first, "precondition: one session");
    assert!(
        w.parties[0].rekeyable(w.ids[1]) && w.parties[1].rekeyable(w.ids[0]),
        "precondition: both ends past both floors"
    );
    apply(&mut w, Act::Rekey(0, 1));
    apply(&mut w, Act::Rekey(1, 0));
    let smaller = peer(&w, 0, 1).rekey.expect("node 0's own rekey is out");
    let larger = peer(&w, 1, 0).rekey.expect("node 1's own rekey is out");
    assert_ne!(smaller, larger, "precondition: two rekeys");
    // Both msg1s arrive before either answer: each node reads the other's
    // while its own attempt is unanswered.
    let (from0, to1) = msg1_of(&mut w, 0, 1);
    let (from1, to0) = msg1_of(&mut w, 1, 0);
    arrive(&mut w, 1, from0, to1);
    arrive(&mut w, 0, from1, to0);
    settle(&mut w);
    w.run_until(w.net.now + 1_000);
    settle(&mut w);
    let (p, q) = (peer(&w, 0, 1), peer(&w, 1, 0));
    assert_eq!(
        (p.cur, q.cur),
        (smaller, smaller),
        "both ends cut over to the smaller node's rekey, the larger node's given up"
    );
    heal(&mut w);
    let left: Vec<Breach> = every_step(&w).into_iter().chain(healed(&w)).collect();
    assert!(left.is_empty(), "every property holds after: {left:?}");
}

#[test]
fn a_refused_rekey_msg1_stays_refused_when_it_comes_again() {
    let mut w = paired(super::off);
    age(&mut w, 40_000);
    assert!(
        w.parties[0].rekeyable(B),
        "precondition: node 0 is past both floors"
    );
    apply(&mut w, Act::Rekey(0, 1));
    let (from, msg1) = msg1_of(&mut w, 0, 1);
    assert_eq!(from, home(0, UDP), "precondition: sent on the link");
    let hs = named(msg1);
    // First from a pair node 1's link holds no path at.
    arrive(&mut w, 1, second(0, UDP), msg1);
    assert_eq!(
        logged(&w, 1, hs).and_then(|r| r.class),
        Some(Class::OffLink),
        "precondition: the msg1 from a pair no path holds is refused as off the link"
    );
    assert!(!answers(&w, 1, 0), "precondition: and draws no answer");
    // Then the same msg1 on the link.
    arrive(&mut w, 1, from, msg1);
    assert!(
        !answers(&w, 1, 0),
        "a msg1 refused once is refused again when it comes on the link"
    );
    let left: Vec<Breach> = every_step(&w);
    assert!(left.is_empty(), "every property holds: {left:?}");
}

/// The last msg1 of handshake `hs` node `x` logged, with what was decided.
fn last(w: &World, x: usize, hs: Hs) -> Option<Rec> {
    w.parties[x]
        .view()
        .log
        .into_iter()
        .filter_map(|e| match e {
            Entry::Ev {
                ev: Event::Msg1 { hs: h, .. },
                rec,
                ..
            } if h == hs => Some(rec),
            Entry::Ev { .. }
            | Entry::Abandon { .. }
            | Entry::Unadopted { .. }
            | Entry::Restart
            | Entry::Fallback => None,
        })
        .next_back()
}

/// The handshake of the first handshake message of kind `want` in flight
/// from node `x` to node `y`.
fn sent(w: &World, x: usize, y: usize, want: Want) -> Option<Hs> {
    w.net.flight.iter().find_map(|f| match (want, f.pkt) {
        (Want::Msg1, Pkt::Msg1 { id, hs, .. }) | (Want::Msg2, Pkt::Msg2 { id, hs, .. })
            if f.to == y && id == w.ids[x] =>
        {
            Some(hs)
        }
        _ => None,
    })
}

/// How many msg2s of handshake `hs` node `x` has sent.
fn msg2s(w: &World, x: usize, hs: Hs) -> usize {
    let me = w.ids[x];
    w.net
        .log
        .iter()
        .filter(|l| l.contains(&format!("n{x} sends Msg2 {{ id: {me:?}, hs: {hs:?},")))
        .count()
}

#[test]
fn a_copy_of_an_answered_rekey_msg1_after_a_move_is_refused_as_answered_before() {
    // The larger node, node 0 here, holds the smaller on an aged link and
    // starts its own rekey; the smaller node's dial of the larger node's
    // second address reaches it; a copy of the rekey msg1 is made; the
    // smaller node answers the rekey, then reads the larger node's answer to
    // its dial and moves onto that session, which closes its rekey machine
    // with the pending it had armed and builds another from what it
    // carried; then the copy arrives. Joint nodes at Off with Off.
    let st = super::starts::off()
        .into_iter()
        .find(|s| s.name == "dial on the peer's aged link, then own rekey")
        .expect("the aged-link start");
    let mut w = flipped(|| (st.build)(super::off));
    w.net.logging = true;
    assert!(
        w.ids[0] > w.ids[1],
        "precondition: node 0 is the larger node"
    );
    run(&mut w, &[Do::Then(Act::Rekey(0, 1))]);
    let rekey = sent(&w, 0, 1, Want::Msg1).expect("precondition: node 0's own rekey is out");
    run(
        &mut w,
        &[
            Do::Get(0, Want::Msg1, Some(1)),
            Do::Copy(1, Want::Msg1, Some(0)),
            Do::Get(1, Want::Msg1, Some(0)),
        ],
    );
    assert_eq!(
        msg2s(&w, 1, rekey),
        1,
        "precondition: the smaller node answered the rekey"
    );
    let dial = sent(&w, 0, 1, Want::Msg2).expect("precondition: the larger node answered the dial");
    run(&mut w, &[Do::Get(1, Want::Msg2, Some(0))]);
    let v = w.parties[1].view();
    let p = v.peers.iter().find(|p| p.peer == w.ids[0]).expect("held");
    assert_eq!(
        p.cur, dial,
        "precondition: the smaller node moved onto its dial's session"
    );
    run(&mut w, &[Do::Get(1, Want::Msg1, Some(0))]);
    let rec = last(&w, 1, rekey).expect("the copy is logged");
    let v = w.parties[1].view();
    let p = v.peers.iter().find(|p| p.peer == w.ids[0]).expect("held");
    assert_eq!(
        (rec.class, msg2s(&w, 1, rekey), p.pending),
        (Some(Class::Recorded), 1, None),
        "the copy is refused as answered before: no second answer and no pending\n{}",
        w.net.log.join("\n")
    );
}
