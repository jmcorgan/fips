//! An unauthenticated beacon at a Probing path (`Input::Beacon`): a path
//! held at the beacon's pair that is Probing and was never acked has its
//! next probe brought forward to now, once each time it enters Probing,
//! only while none of its probes is outstanding and the next is not
//! already due. The probe keeps the Probing cap, the discovery limit and
//! the floor of a path that has stopped answering, so beacons, however
//! many, add no probe to a Probing episode. A beacon anywhere else changes
//! nothing, and no beacon makes the peer capable.
//!
//! With the draft values a never-answered Probing path is probed at 0,
//! 400 and 800 ms from its admission, and the third probe times out at
//! 1200 ms with the fourth due at 1600 ms: the first instant at which no
//! probe is outstanding and the next is still ahead. The tests that look
//! for a probe a beacon brought forward step it in that window, where the
//! cadence sends nothing, so only the beacon can account for the probe.
//! Every test drives a `Bundle` in the shell, which checks every step.

use alloc::format;
use alloc::vec::Vec;

use super::shell::*;
use crate::proto::path::{Input, PathRef, PathState, Source, Why};
use crate::testutil::TestInstant;

/// A beacon heard from `to`.
fn beacon(to: &PathRef) -> Input {
    Input::Beacon {
        transport: to.transport,
        addr: to.addr.clone(),
    }
}

/// Probes on the original path only are answered.
fn only_p(_: u64, to: &PathRef) -> bool {
    *to == p()
}

/// The number of probes on q in `out`.
fn on_q(out: &[Out]) -> usize {
    probes(out).iter().filter(|(to, _)| *to == q()).count()
}

/// A capable node whose candidate q, on transport 2, was admitted at 0 ms
/// and is never answered, polled at every wake up to `ms` with only the
/// original path's probes answered. Returns the node and its log.
fn probing(seed: u64, ms: u64) -> (Node, Log) {
    let mut n = Node::capable(seed);
    let mut log = Log::default();
    let out = n.candidate(t(2), addr(2));
    handle(&mut n, &mut log, out, &mut only_p);
    assert_eq!(state(&n, &q()), PathState::Probing, "precondition");
    run(&mut n, &mut log, ms, &mut only_p);
    (n, log)
}

/// Assert that q, at `ms`, is Probing and never acked with no probe
/// outstanding and its next probe after `ms`: a beacon then is the only
/// thing that can send one.
fn assert_window(n: &Node, ms: u64) {
    let held = path(n, &q());
    assert_eq!(held.state(), PathState::Probing, "precondition: q Probing");
    assert!(!held.acked(), "precondition: q never acked");
    let live = held.live();
    assert_eq!(live.outstanding(), 0, "precondition: none outstanding");
    let next = live.next_at().expect("precondition: a next probe");
    assert!(
        next.0 > ms,
        "precondition: q's next probe, at {}, is after {ms}",
        next.0
    );
}

/// Step a beacon from `to` at `ms` and log it.
fn beacon_at(n: &mut Node, log: &mut Log, ms: u64, to: &PathRef) -> Vec<Out> {
    at(n, log, ms, beacon(to))
}

/// The instant q became Dead, if it has.
fn dead_at(log: &Log) -> Option<u64> {
    log.changes(&q())
        .iter()
        .find(|c| c.2 == Some(PathState::Dead))
        .map(|c| c.0)
}

/// Poll `n` at each wake, answering only the original path, until q has
/// become Dead, polling no further than that step. Returns the instant.
fn until_dead(n: &mut Node, log: &mut Log) -> u64 {
    while dead_at(log).is_none() {
        let out = n.tick(TestInstant(120_000)).expect("a wake before 120 s");
        handle(n, log, out, &mut only_p);
    }
    let dead = dead_at(log).expect("q went Dead");
    assert_eq!(state(n, &q()), PathState::Dead, "precondition: q Dead");
    dead
}

#[test]
fn a_beacon_at_a_probing_path_with_no_probe_outstanding_sends_its_probe_in_the_step() {
    let (mut n, mut log) = probing(1, 1300);
    assert_eq!(log.on(&q()), [0, 400, 800], "precondition: the ladder");
    assert_window(&n, 1300);
    let out = beacon_at(&mut n, &mut log, 1300, &q());
    assert_eq!(
        on_q(&out),
        1,
        "the beacon brought q's probe forward: {out:?}"
    );
    assert!(states(&out).is_empty(), "no state changed: {out:?}");
}

#[test]
fn a_second_beacon_in_the_same_probing_state_brings_nothing_forward() {
    let (mut n, mut log) = probing(2, 1300);
    assert_window(&n, 1300);
    let out = beacon_at(&mut n, &mut log, 1300, &q());
    assert_eq!(on_q(&out), 1, "precondition: the first beacon's probe");
    // The beacon's probe times out at 1700 ms; the next is due at 2900 ms.
    run(&mut n, &mut log, 1800, &mut only_p);
    assert_window(&n, 1800);
    let next = path(&n, &q()).live().next_at();
    let out = beacon_at(&mut n, &mut log, 1800, &q());
    assert_eq!(on_q(&out), 0, "a second beacon sent a probe: {out:?}");
    assert_eq!(
        path(&n, &q()).live().next_at(),
        next,
        "the next probe stays where the cadence put it"
    );
}

#[test]
fn a_path_entering_probing_again_takes_a_beacon_again() {
    let (mut n, mut log) = probing(3, 1300);
    let out = beacon_at(&mut n, &mut log, 1300, &q());
    assert_eq!(on_q(&out), 1, "precondition: the first beacon's probe");
    let dead = until_dead(&mut n, &mut log);
    // The peer's probe brings q back to Probing afresh, probed at once.
    n.now = TestInstant(dead + 100);
    let out = n.probe(t(2), addr(2), marked(peer(&q()), 1, true));
    log.add(n.now, &out);
    assert_eq!(state(&n, &q()), PathState::Probing, "precondition: revived");
    assert_eq!(on_q(&out), 1, "precondition: probed at once");
    let back = dead + 100;
    run(&mut n, &mut log, back + 1300, &mut only_p);
    assert_window(&n, back + 1300);
    let out = beacon_at(&mut n, &mut log, back + 1300, &q());
    assert_eq!(
        on_q(&out),
        1,
        "a beacon in the new Probing state brought q's probe forward: {out:?}"
    );
}

#[test]
fn a_beacon_while_a_probe_is_outstanding_sends_nothing_and_is_not_spent() {
    let (mut n, mut log) = probing(4, 900);
    let live = path(&n, &q()).live();
    assert_eq!(live.outstanding(), 1, "precondition: one outstanding");
    assert!(
        live.next_at().is_some_and(|at| at.0 > 900),
        "precondition: the next probe is ahead"
    );
    let out = beacon_at(&mut n, &mut log, 900, &q());
    assert_eq!(on_q(&out), 0, "a probe beside the outstanding one: {out:?}");
    run(&mut n, &mut log, 1300, &mut only_p);
    assert_eq!(log.on(&q()), [0, 400, 800], "the cadence was not moved");
    assert_window(&n, 1300);
    let out = beacon_at(&mut n, &mut log, 1300, &q());
    assert_eq!(on_q(&out), 1, "the later beacon still counts: {out:?}");
}

#[test]
fn a_beacon_when_the_next_probe_is_already_due_is_not_spent() {
    // Not polled at 400 ms, when q's first probe timed out and its second
    // came due, so the beacon at 401 ms finds nothing outstanding and the
    // probe due: the send phase sends it whatever the beacon does.
    let (mut n, mut log) = probing(5, 399);
    let out = beacon_at(&mut n, &mut log, 401, &q());
    assert_eq!(on_q(&out), 1, "precondition: the cadence's probe");
    // That probe went at 401 ms and the next at 801 ms, which times out at
    // 1201 ms with the one after due at 1601 ms.
    run(&mut n, &mut log, 1300, &mut only_p);
    assert_eq!(log.on(&q()), [0, 401, 801], "precondition: the ladder");
    assert_window(&n, 1300);
    let out = beacon_at(&mut n, &mut log, 1300, &q());
    assert_eq!(
        on_q(&out),
        1,
        "the beacon that moved nothing was taken as q's one: {out:?}"
    );
}

#[test]
fn a_beacon_at_a_probing_path_that_has_stopped_answering_waits_for_the_floor() {
    let (mut n, mut log) = probing(6, 0);
    let dead = until_dead(&mut n, &mut log);
    // Carrier's return brings q back to Probing keeping its stop, so its
    // first probe waits for the floor's instant, 1 s after it became Dead.
    at(
        &mut n,
        &mut log,
        dead + 150,
        Input::Carrier {
            transport: t(2),
            up: true,
        },
    );
    assert_eq!(state(&n, &q()), PathState::Probing, "precondition: revived");
    assert_window(&n, dead + 500);
    let out = beacon_at(&mut n, &mut log, dead + 500, &q());
    assert_eq!(
        on_q(&out),
        0,
        "the beacon's probe skipped the floor: {out:?}"
    );
    run(&mut n, &mut log, dead + 1500, &mut only_p);
    let after: Vec<u64> = log.on(&q()).into_iter().filter(|at| *at > dead).collect();
    assert_eq!(
        after,
        [dead + FLOOR_MIN],
        "q is probed at the floor's instant"
    );
}

#[test]
fn a_beacon_at_an_unconnected_probing_path_asks_for_its_connection_now() {
    let mut n = Node::capable(7).with(Stub::default().oriented(t(2)));
    let mut log = Log::default();
    let found = Input::Candidate {
        transport: t(2),
        addr: addr(2),
        source: Source::Config,
    };
    let out = at(&mut n, &mut log, 0, found);
    assert_eq!(asked(&out), [q()], "precondition: the connection asked for");
    // While it is pending, the path's next step is already due, so a beacon
    // changes nothing.
    let was = format!("{:?}", n.b);
    let out = beacon_at(&mut n, &mut log, 20, &q());
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(format!("{:?}", n.b), was, "a pending path took the beacon");
    // It fails, which counts as a miss and puts the next connection a
    // discovery interval on.
    let out = at(
        &mut n,
        &mut log,
        50,
        Input::Connected {
            transport: t(2),
            addr: addr(2),
            ok: false,
        },
    );
    assert!(asked(&out).is_empty(), "precondition: {out:?}");
    assert_window(&n, 100);
    let out = beacon_at(&mut n, &mut log, 100, &q());
    assert_eq!(
        asked(&out),
        [q()],
        "the connection is asked for now: {out:?}"
    );
}

#[test]
fn a_beacon_at_a_live_suspect_dead_acked_or_unheld_pair_changes_nothing() {
    /// Step a beacon from `to` at `n`'s instant, after every wake up to it
    /// has been polled, and assert it changed nothing.
    fn unchanged(n: &mut Node, to: &PathRef, what: &str) {
        let was = format!("{:?}", n.b);
        let out = n.step(beacon(to));
        assert!(out.is_empty(), "a beacon at {what} gave {out:?}");
        assert_eq!(format!("{:?}", n.b), was, "a beacon at {what} changed it");
    }
    let mut n = two(8);
    let mut log = Log::default();
    run(&mut n, &mut log, 5_000, &mut all);
    unchanged(&mut n, &p(), "the Live original path");
    unchanged(&mut n, &q(), "a Live standby");
    unchanged(&mut n, &r(), "an unheld pair");
    let now = n.now.0;
    at(&mut n, &mut log, now, down(2));
    assert_eq!(state(&n, &q()), PathState::Suspect, "precondition");
    unchanged(&mut n, &q(), "a Suspect path");

    let mut n = two(9);
    let mut log = Log::default();
    run(&mut n, &mut log, 999, &mut all);
    run(&mut n, &mut log, 83_500, &mut only_p);
    assert_eq!(state(&n, &q()), PathState::Dead, "precondition");
    assert!(path(&n, &q()).acked(), "precondition: acked");
    unchanged(&mut n, &q(), "an acked Dead path");
    let up = Input::Carrier {
        transport: t(2),
        up: true,
    };
    let now = n.now.0 + 10;
    at(&mut n, &mut log, now, up);
    assert_eq!(state(&n, &q()), PathState::Probing, "precondition");
    assert_eq!(
        log.changes(&q()).last().map(|c| c.3),
        Some(Why::Returned),
        "precondition: brought back by carrier"
    );
    unchanged(&mut n, &q(), "an acked Probing path");

    // At the step q becomes Dead, its first Dead probe a standby interval
    // on, though a Dead path never acked is not probed.
    let (mut n, mut log) = probing(10, 0);
    until_dead(&mut n, &mut log);
    assert!(!path(&n, &q()).acked(), "precondition: never acked");
    assert!(
        path(&n, &q()).live().next_at().is_some_and(|at| at > n.now),
        "precondition: its next probe is ahead"
    );
    unchanged(&mut n, &q(), "a Dead path never acked");
}

#[test]
fn a_beacon_makes_no_peer_capable() {
    let mut n = Node::new(11);
    for to in [p(), q()] {
        let out = step(&mut n, 0, beacon(&to));
        assert!(out.is_empty(), "{out:?}");
        assert!(!n.b.capable(), "a beacon made the peer capable");
    }
}

#[test]
fn a_beacon_is_discarded_with_multipath_disabled() {
    let mut n = Node::disabled(12);
    let was = format!("{:?}", n.b);
    let out = step(&mut n, 0, beacon(&p()));
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(format!("{:?}", n.b), was, "a disabled bundle took a beacon");
}

/// [`probing`]'s node driven to `until` ms, with a beacon from q every
/// `every` ms when `every` is not 0, stepped after any wake at the same
/// instant. Returns its log.
fn flood(seed: u64, until: u64, every: u64) -> Log {
    let (mut n, mut log) = probing(seed, 0);
    let mut next = every;
    loop {
        let wake = n.b.next_wake().map(|w| w.0);
        let (ms, is_beacon) = match wake {
            Some(w) if every == 0 || w <= next => (w, false),
            _ if every != 0 => (next, true),
            _ => break,
        };
        if ms > until {
            break;
        }
        n.now = TestInstant(ms);
        let out = if is_beacon {
            next += every;
            n.step(beacon(&q()))
        } else {
            n.poll()
        };
        handle(&mut n, &mut log, out, &mut only_p);
    }
    log
}

/// The gaps between successive instants of `at`.
fn gaps(at: &[u64]) -> Vec<u64> {
    at.windows(2).map(|w| w[1] - w[0]).collect()
}

#[test]
fn beacons_at_every_poll_of_a_probing_episode_add_no_probe() {
    let quiet = flood(13, 60_000, 0);
    let loud = flood(13, 60_000, 50);
    let (calm, storm) = (quiet.on(&q()), loud.on(&q()));
    let discovery = 8;
    assert_eq!(calm.len(), discovery, "precondition: the ladder: {calm:?}");
    assert_eq!(storm.len(), discovery, "beacons added probes: {storm:?}");
    let (died, fell) = (dead_at(&quiet), dead_at(&loud));
    assert!(died.is_some() && fell.is_some(), "both episodes end Dead");
    // One gap of the ladder is cut short, and every other is as without
    // beacons, so the episode ends Dead earlier by that cut alone.
    let (want, got) = (gaps(&calm), gaps(&storm));
    let cut: Vec<usize> = (0..want.len()).filter(|&k| want[k] != got[k]).collect();
    assert_eq!(cut.len(), 1, "gaps without beacons {want:?}, with {got:?}");
    let k = cut[0];
    assert!(got[k] < want[k], "the cut gap is shorter: {got:?}");
    assert_eq!(
        died.unwrap() - fell.unwrap(),
        want[k] - got[k],
        "Dead came earlier by the cut alone"
    );
}
