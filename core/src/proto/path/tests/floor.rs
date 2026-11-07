//! The floor on a path that has stopped answering (multipath v1 draft,
//! Section 5.6): a path that is not Probing stops answering once it is
//! Dead, or once `PATH_SILENCE_MAX` (60 s) has passed since the earliest
//! probe no matching answer has followed. While stopped, its first two
//! probes on its own cadence each wait at least
//! `PATH_DEAD_PROBE_INTERVAL_MIN` (1 s) and each later gap at least
//! doubles, up to `PATH_DEAD_PROBE_INTERVAL_MAX` (30 s), whatever its state.
//! A revival by the peer's own probe ends the stop; one by carrier's return
//! or by finding the peer again keeps it over the discovery probes that
//! follow, the revival's own first among them, until a matching answer.
//! The probe at once when the peer's probe brings a path back, those
//! Section 5.7 requires at once, the early probe when the peer clears
//! `ACTIVE` and the probe sent when a connection opens are neither held
//! nor counted.
//! Every test drives a `Bundle` in the shell, which checks every step.

use alloc::vec::Vec;
use core::cell::RefCell;

use super::shell::*;
use crate::proto::path::{Config, Input, Params, PathRef, PathState, Source, Why};
use crate::testutil::TestInstant;
use crate::time::Duration;

/// `PATH_SILENCE_MAX`, in milliseconds (Appendix A).
const SILENCE: u64 = 60_000;

/// `PATH_DEAD_PROBE_INTERVAL_MIN`, in milliseconds (Appendix A).
const MIN: u64 = FLOOR_MIN;

/// A capable node under `cfg` whose candidate q, on transport 2, is Live.
fn two_with(seed: u64, cfg: Config) -> Node {
    let mut n = Node::on(seed, Params::new(cfg).unwrap(), Stub::default(), p());
    n.heard();
    let out = n.candidate(t(2), addr(2));
    handle(&mut n, &mut Log::default(), out, &mut all);
    assert_eq!(state(&n, &q()), PathState::Live, "precondition: q Live");
    n
}

/// `two` with the standby interval `standby` ms.
fn two_at(seed: u64, standby: u64) -> Node {
    let cfg = Config {
        standby_interval: Duration::from_millis(standby),
        ..Config::draft()
    };
    two_with(seed, cfg)
}

/// Probes on the original path only are answered.
fn only_p(_: u64, to: &PathRef) -> bool {
    *to == p()
}

/// The instants at which the path on `to` became Dead, with the reason.
fn deaths(log: &Log, to: &PathRef) -> Vec<(u64, Why)> {
    log.changes(to)
        .iter()
        .filter(|c| c.2 == Some(PathState::Dead))
        .map(|c| (c.0, c.3))
        .collect()
}

/// The instants of the probes on q strictly after `from` ms.
fn on_q_after(log: &Log, from: u64) -> Vec<u64> {
    log.on(&q()).into_iter().filter(|at| *at > from).collect()
}

/// The number of probes on q in `out`.
fn on_q(out: &[Out]) -> usize {
    probes(out).iter().filter(|(to, _)| *to == q()).count()
}

/// A node `seed` at the defaults whose q, answered until 999 ms and then
/// not, is Dead by 83.5 s. Returns the node, its log and the instant q
/// became Dead.
fn dead_q(seed: u64) -> (Node, Log, u64) {
    let mut n = two(seed);
    let mut log = Log::default();
    run(&mut n, &mut log, 999, &mut all);
    run(&mut n, &mut log, 83_500, &mut only_p);
    let dead = deaths(&log, &q())
        .first()
        .map(|d| d.0)
        .expect("precondition: q went Dead");
    assert_eq!(state(&n, &q()), PathState::Dead, "precondition: q Dead");
    (n, log, dead)
}

/// A node at `standby` ms whose q, answered until 999 ms and then not, has
/// become Dead. Returns the node, its log and the instant q became Dead,
/// polled no further than that step.
fn dead_q_at(seed: u64, standby: u64) -> (Node, Log, u64) {
    let mut n = two_at(seed, standby);
    let mut log = Log::default();
    run(&mut n, &mut log, 999, &mut all);
    while deaths(&log, &q()).is_empty() {
        let out = n.tick(TestInstant(120_000)).expect("a wake before 120 s");
        handle(&mut n, &mut log, out, &mut only_p);
    }
    let dead = deaths(&log, &q())[0].0;
    (n, log, dead)
}

/// Carrier's return on transport 2 at `ms`.
fn up2() -> Input {
    Input::Carrier {
        transport: t(2),
        up: true,
    }
}

#[test]
fn a_dead_path_under_a_100_ms_standby_interval_is_probed_no_sooner_than_the_floor() {
    let mut n = two_at(60, 100);
    let mut log = Log::default();
    run(&mut n, &mut log, 999, &mut all);
    run(&mut n, &mut log, 60_000, &mut only_p);
    let dead = deaths(&log, &q())
        .first()
        .map(|d| d.0)
        .expect("q went Dead");
    let after = on_q_after(&log, dead);
    assert!(
        after.len() >= 3,
        "precondition: q probed while Dead: {after:?}"
    );
    if let Some(e) = floor_breaks(dead, &after) {
        panic!("{e}");
    }
}

#[test]
fn a_path_silent_for_path_silence_max_is_held_to_the_floor_while_live_or_suspect() {
    let mut n = two_at(61, 10_000);
    let mut log = Log::default();
    run(&mut n, &mut log, 999, &mut all);
    run(&mut n, &mut log, 200_000, &mut only_p);
    let quiet = on_q_after(&log, 999)
        .first()
        .copied()
        .expect("precondition: an unanswered probe on q");
    let dead = deaths(&log, &q()).first().map_or(u64::MAX, |d| d.0);
    let stop = (quiet + SILENCE).min(dead);
    assert!(
        stop < dead,
        "precondition: q stops answering before Dead ({quiet}, {dead})"
    );
    let after: Vec<u64> = log.on(&q()).into_iter().filter(|at| *at >= stop).collect();
    if let Some(e) = floor_breaks(stop, &after) {
        panic!("{e}; Dead at {dead} ms");
    }
}

/// Assert the floor of a path brought back from Dead at 83.6 s by `why`,
/// whose stop began at `dead`: no probe on q in the revival's step, since
/// the floor's next instant is later; the revival's own probe at that
/// instant; the floor kept over every probe on q, the revival's counted;
/// and eight probes while Probing, then Dead again for want of an answer.
fn kept_over_the_ladder(n: &mut Node, log: &mut Log, dead: u64, out: &[Out], why: Why) {
    let back = log.changes(&q());
    assert_eq!(
        back.last().map(|c| (c.0, c.1, c.2, c.3)),
        Some((83_600, Some(PathState::Dead), Some(PathState::Probing), why)),
        "precondition: q revived"
    );
    let free = free_after(dead, &on_q_after(log, dead));
    assert!(
        free > 83_600,
        "precondition: the floor's next instant is after the revival ({free})"
    );
    assert_eq!(
        on_q(out),
        0,
        "the revival's own probe waits for the floor: {out:?}"
    );
    run(n, log, 400_000, &mut only_p);
    let cadence = on_q_after(log, dead);
    assert_eq!(
        on_q_after(log, 83_600).first(),
        Some(&free),
        "the revival's own probe goes at the floor's instant: {cadence:?}"
    );
    if let Some(e) = floor_breaks(dead, &cadence) {
        panic!("{e}");
    }
    let again = deaths(log, &q());
    let (gone, how) = *again.get(1).expect("q went Dead again");
    assert_eq!(how, Why::Exhausted, "{again:?}");
    let probing: Vec<u64> = log
        .on(&q())
        .into_iter()
        .filter(|at| (83_600..=gone).contains(at))
        .collect();
    assert_eq!(probing.len(), 8, "{probing:?}");
}

#[test]
fn a_path_brought_back_by_carrier_keeps_the_floor_over_its_discovery_probes() {
    let (mut n, mut log, dead) = dead_q(62);
    at(&mut n, &mut log, 83_500, down(2));
    let out = at(&mut n, &mut log, 83_600, up2());
    kept_over_the_ladder(&mut n, &mut log, dead, &out, Why::Returned);
}

#[test]
fn a_path_brought_back_by_rediscovery_keeps_the_floor_over_its_discovery_probes() {
    let (mut n, mut log, dead) = dead_q(62);
    let found = Input::Candidate {
        transport: t(2),
        addr: addr(2),
        source: Source::Discovery,
    };
    let out = at(&mut n, &mut log, 83_600, found);
    kept_over_the_ladder(&mut n, &mut log, dead, &out, Why::Found);
}

#[test]
fn a_path_brought_back_by_the_peers_probe_starts_afresh() {
    let (mut n, mut log, _) = dead_q(62);
    let found = Input::Probe {
        transport: t(2),
        addr: addr(2),
        msg: probe_from(0xB, 1, 1200),
    };
    let out = at(&mut n, &mut log, 83_600, found);
    assert_eq!(sent_acks(&out).len(), 1, "{out:?}");
    assert_eq!(state(&n, &q()), PathState::Probing, "precondition: revived");
    run(&mut n, &mut log, 120_000, &mut only_p);
    let again = deaths(&log, &q());
    let (gone, how) = *again.get(1).expect("q went Dead again");
    assert_eq!((gone, how), (106_800, Why::Exhausted), "{again:?}");
    let ladder: Vec<u64> = log
        .on(&q())
        .into_iter()
        .filter(|at| (83_600..=gone).contains(at))
        .collect();
    assert_eq!(
        ladder,
        [
            83_600, 84_000, 84_400, 85_200, 86_800, 90_000, 96_400, 106_400
        ],
        "the normal discovery ladder"
    );
    assert_eq!(
        on_q_after(&log, gone).first(),
        Some(&(gone + MIN)),
        "the new stop's first probe"
    );
}

#[test]
fn an_answer_in_time_ends_the_stop() {
    let (mut n, mut log, dead) = dead_q_at(63, 100);
    // Each probe on q from the floor's first instant on is answered.
    let mut answers = |ms: u64, to: &PathRef| *to == p() || ms >= dead + MIN;
    run(&mut n, &mut log, dead + 5_000, &mut answers);
    assert_eq!(state(&n, &q()), PathState::Live, "the answer made q Live");
    let after = on_q_after(&log, dead + MIN - 1);
    let next: Vec<u64> = after.windows(2).take(5).map(|w| w[1] - w[0]).collect();
    assert_eq!(next, [100; 5], "q's cadence once Live: {after:?}");
}

#[test]
fn a_late_answer_leaves_the_stop_in_force() {
    let (mut n, mut log, dead) = dead_q_at(64, 100);
    run(&mut n, &mut log, dead + MIN, &mut only_p);
    let (sent, _, probe) = log
        .probes
        .iter()
        .rev()
        .find(|(_, to, _)| *to == q())
        .cloned()
        .expect("a probe on q");
    // Answered 500 ms on, past the 400 ms probe timeout.
    run(&mut n, &mut log, sent + 500, &mut only_p);
    n.now = TestInstant(sent + 500);
    let out = n.ack(t(2), addr(2), ack_for(&probe, peer(&q())));
    handle(&mut n, &mut log, out, &mut only_p);
    assert_eq!(
        state(&n, &q()),
        PathState::Dead,
        "a late answer changes no state"
    );
    run(&mut n, &mut log, dead + 60_000, &mut only_p);
    if let Some(e) = floor_breaks(dead, &on_q_after(&log, dead)) {
        panic!("{e}");
    }
}

#[test]
fn an_active_flag_clearing_on_a_stopped_path_probes_at_once_outside_the_floor() {
    let mut n = two_at(65, 10_000);
    let mut log = Log::default();
    run(&mut n, &mut log, 999, &mut all);
    run(&mut n, &mut log, 20_000, &mut only_p);
    let quiet = on_q_after(&log, 999)
        .first()
        .copied()
        .expect("precondition: an unanswered probe on q");
    let stop = quiet + SILENCE;
    // Run until q has sent five probes at or after its stop.
    let since =
        |log: &Log| -> Vec<u64> { log.on(&q()).into_iter().filter(|at| *at >= stop).collect() };
    while since(&log).len() < 5 {
        let out = n.tick(TestInstant(300_000)).expect("a wake before 300 s");
        handle(&mut n, &mut log, out, &mut only_p);
    }
    let five = since(&log);
    let last = five[4];
    assert_eq!(
        state(&n, &q()),
        PathState::Suspect,
        "precondition: q Suspect"
    );
    let free = free_after(stop, &five);
    let set = Input::Probe {
        transport: t(2),
        addr: addr(2),
        msg: marked(0xB, 100, true),
    };
    run(&mut n, &mut log, last + 1_000, &mut only_p);
    let out = at(&mut n, &mut log, last + 1_000, set);
    assert_eq!(on_q(&out), 0, "precondition: no probe at the set");
    let clear = Input::Probe {
        transport: t(2),
        addr: addr(2),
        msg: marked(0xB, 101, false),
    };
    run(&mut n, &mut log, last + 1_050, &mut only_p);
    let out = at(&mut n, &mut log, last + 1_050, clear);
    assert_eq!(on_q(&out), 1, "the clearing's probe goes at once: {out:?}");
    run(&mut n, &mut log, last + 40_000, &mut only_p);
    let next = on_q_after(&log, last + 1_050).first().copied();
    assert_eq!(
        next,
        Some(free),
        "the next probe after the clearing waits for the floor (stopped at {stop} ms, \
         probes {five:?})"
    );
    assert_eq!(state_then(&log, last + 1_050), PathState::Suspect);
}

/// The state of q at `at` ms, from the changes logged.
fn state_then(log: &Log, at: u64) -> PathState {
    log.changes(&q())
        .iter()
        .rev()
        .find(|c| c.0 <= at)
        .and_then(|c| c.2)
        .unwrap_or(PathState::Live)
}

#[test]
fn a_probe_held_by_the_floor_waits_without_waking_at_each_interval() {
    let (mut n, mut log, dead) = dead_q_at(66, 100);
    while on_q_after(&log, dead).is_empty() {
        let out = n.tick(TestInstant(dead + 5_000)).expect("a wake");
        handle(&mut n, &mut log, out, &mut only_p);
    }
    let first = on_q_after(&log, dead)[0];
    let due = |n: &Node| path(n, &q()).live().next_at();
    assert_eq!(first, dead + MIN, "the floor's first probe");
    assert_eq!(
        due(&n),
        Some(TestInstant(dead + 2 * MIN)),
        "after the first"
    );
    while let Some(out) = n.tick(TestInstant(dead + 2 * MIN - 1)) {
        handle(&mut n, &mut log, out, &mut only_p);
        assert_eq!(
            due(&n),
            Some(TestInstant(dead + 2 * MIN)),
            "q's next probe at the poll of {} ms",
            n.now.0
        );
    }
}

#[test]
fn the_probe_at_once_when_the_active_path_leaves_live_is_not_held_to_the_floor() {
    let (mut n, mut log, dead) = dead_q_at(67, 100);
    let c = dead + 5_000;
    run(&mut n, &mut log, c - 1, &mut only_p);
    let before = on_q_after(&log, dead);
    let out = at(&mut n, &mut log, c, down(1));
    assert_eq!(on_q(&out), 1, "q probed at once (Section 5.7): {out:?}");
    run(&mut n, &mut log, c + 20_000, &mut only_p);
    let next = on_q_after(&log, c).first().copied();
    assert_eq!(
        next,
        Some(free_after(dead, &before)),
        "the probe at once is not counted (probes before: {before:?})"
    );
}

#[test]
fn the_floors_cap_is_the_bound_not_the_configured_dead_interval() {
    let cfg = Config {
        dead_interval: Duration::from_secs(5),
        ..Config::draft()
    };
    let mut n = two_with(68, cfg);
    let mut log = Log::default();
    run(&mut n, &mut log, 999, &mut all);
    run(&mut n, &mut log, 200_000, &mut only_p);
    let dead = deaths(&log, &q())
        .first()
        .map(|d| d.0)
        .expect("q went Dead");
    let after = on_q_after(&log, dead);
    assert!(
        after.len() >= 6,
        "precondition: q probed while Dead: {after:?}"
    );
    if let Some(e) = floor_breaks(dead, &after) {
        panic!("{e}");
    }
}

#[test]
fn a_connection_opened_for_a_held_slot_starts_the_next_gap_at_its_probe() {
    let mut n = Node::capable(69).with(Stub::default().oriented(t(2)));
    let mut log = Log::default();
    let settled = |ok: bool| Input::Connected {
        transport: t(2),
        addr: addr(2),
        ok,
    };
    let asks = |log: &Log| log.connects.iter().filter(|(_, to)| *to == q()).count();
    at(
        &mut n,
        &mut log,
        0,
        Input::Candidate {
            transport: t(2),
            addr: addr(2),
            source: Source::Config,
        },
    );
    // Each connection fails 30 ms after it is asked for, until q is Dead.
    while deaths(&log, &q()).is_empty() {
        let asked = log.connects.last().expect("a connection asked for").0;
        at(&mut n, &mut log, asked + 30, settled(false));
        if !deaths(&log, &q()).is_empty() {
            break;
        }
        let k = asks(&log);
        while asks(&log) == k {
            let out = n.tick(TestInstant(120_000)).expect("a wake");
            handle(&mut n, &mut log, out, &mut all);
        }
    }
    let (dead, why) = deaths(&log, &q())[0];
    assert_eq!(why, Why::Connect, "precondition");
    assert!(!path(&n, &q()).acked(), "precondition: never acked");
    // Carrier on transport 2 goes and returns: q is back, its stop kept.
    // The floor's first instant has passed, so the revival's connection
    // goes in its step, and takes the floor's first slot.
    at(&mut n, &mut log, dead + 2_000, down(2));
    let out = at(&mut n, &mut log, dead + 2_100, up2());
    assert_eq!(asked(&out), [q()], "the revival's connection, at once");
    at(&mut n, &mut log, dead + 2_130, settled(false));
    let k = asks(&log);
    while asks(&log) == k {
        let out = n.tick(TestInstant(dead + 60_000)).expect("a wake");
        handle(&mut n, &mut log, out, &mut all);
    }
    let r = log.connects.last().unwrap().0;
    assert!(
        r >= dead + 2_100 + MIN,
        "the next connection waits the 1 s gap after the revival's: {r} ms"
    );
    let out = at(&mut n, &mut log, r + 900, settled(true));
    assert_eq!(on_q(&out), 1, "the opening's probe: {out:?}");
    run(&mut n, &mut log, r + 30_000, &mut only_p);
    let after = on_q_after(&log, r + 900);
    assert_eq!(
        after.first(),
        Some(&(r + 2_900)),
        "the next gap after the opening is the 2 s the slot used: {after:?}"
    );
    assert_eq!(
        after.get(1),
        Some(&(r + 6_900)),
        "the gap after that is 4 s: {after:?}"
    );
}

#[test]
fn a_stopped_probing_path_keeps_its_stop_when_the_peers_probe_arrives() {
    let (mut n, mut log, dead) = dead_q(62);
    at(&mut n, &mut log, 83_500, down(2));
    at(&mut n, &mut log, 83_600, up2());
    assert_eq!(state(&n, &q()), PathState::Probing, "precondition: revived");
    run(&mut n, &mut log, 84_100, &mut only_p);
    let found = Input::Probe {
        transport: t(2),
        addr: addr(2),
        msg: probe_from(0xB, 1, 1200),
    };
    let out = at(&mut n, &mut log, 84_100, found);
    assert_eq!(sent_acks(&out).len(), 1, "{out:?}");
    assert_eq!(on_q(&out), 0, "no probe of the node's own: {out:?}");
    assert_eq!(state(&n, &q()), PathState::Probing);
    run(&mut n, &mut log, 300_000, &mut only_p);
    if let Some(e) = floor_breaks(dead, &on_q_after(&log, dead)) {
        panic!("{e}");
    }
}

#[test]
fn a_path_brought_back_by_carrier_once_the_floor_allows_is_probed_in_the_step_and_counted() {
    // A Dead cadence capped at 120 s outruns the floor's 30 s, so q's next
    // Dead probe can lie past the floor's instant.
    let cfg = Config {
        dead_interval: Duration::from_secs(120),
        ..Config::draft()
    };
    let mut n = two_with(70, cfg);
    let mut log = Log::default();
    run(&mut n, &mut log, 999, &mut all);
    // Poll until q is Dead with its next probe over 32 s after its last.
    let last = loop {
        let out = n.tick(TestInstant(600_000)).expect("a wake before 600 s");
        handle(&mut n, &mut log, out, &mut only_p);
        let last = log.on(&q()).last().copied().unwrap_or(0);
        let next = path(&n, &q()).live().next_at().map_or(0, |at| at.0);
        if state(&n, &q()) == PathState::Dead && next > last + 32_000 {
            break last;
        }
    };
    let quiet = on_q_after(&log, 999)
        .first()
        .copied()
        .expect("precondition: an unanswered probe on q");
    let dead = deaths(&log, &q())[0].0;
    let stop = (quiet + SILENCE).min(dead);
    let back = last + 31_000;
    let held =
        |log: &Log| -> Vec<u64> { log.on(&q()).into_iter().filter(|at| *at >= stop).collect() };
    let free = free_after(stop, &held(&log));
    assert!(
        free <= back,
        "precondition: the floor allows a probe ({free})"
    );
    at(&mut n, &mut log, last + 30_500, down(2));
    let out = at(&mut n, &mut log, back, up2());
    assert_eq!(state(&n, &q()), PathState::Probing, "precondition: revived");
    assert_eq!(
        on_q(&out),
        1,
        "the revival's own probe goes in its step: {out:?}"
    );
    run(&mut n, &mut log, back + 120_000, &mut only_p);
    if let Some(e) = floor_breaks(stop, &held(&log)) {
        panic!("{e}");
    }
}

/// The round trip, in milliseconds, of a probe on q in the C10 test sent
/// at `at` ms: 100 ms at the start, growing by one eighth of the time
/// passed, up to `R`. Slow enough that each answer comes before its
/// probe's timeout: the timeout is three times the latest round trip,
/// which is at most a probe gap and one round trip old.
fn ramp(at: u64) -> u64 {
    (100 + at / 8).min(R)
}

/// The round trip q's answers reach before the cut in the C10 test, in
/// milliseconds.
const R: u64 = 20_000;

/// The instant, in milliseconds, after which no answer on q arrives in
/// the C10 test: the cut.
const CUT: u64 = 200_000;

/// One probe on q in the C10 test: when it went, its answer's round
/// trip (`None` if the cut drops it), and q's latest round trip when it
/// went, from which its timeout was set.
type Went = (u64, Option<u64>, Option<Duration>);

#[test]
fn a_standby_answered_in_time_at_a_long_round_trip_then_cut_is_held_to_the_floor_from_its_silence_stop()
 {
    // Draft Section 5.6: a path that is not Probing stops answering once
    // PATH_SILENCE_MAX has passed since the earliest probe after which no
    // matching answer has arrived, whatever its round trip. q, a standby,
    // is answered in time while its round trip grows to R = 20 s by 159.2
    // s, so its probe timeout grows to 3R = 60 s and its ring of eight is
    // full, a probe going as each answer frees a slot. From the cut at 200
    // s nothing on q is answered. The last answer arrives at A <= 200 s
    // and frees a slot, whose probe goes at A: the stop is A + 60 s. The
    // eight probes outstanding then were sent in [A - 20 s, A], so they
    // time out in [A + 40 s, A + 60 s]: eight misses, Suspect at the
    // third. Dead needs thirteen; the other five are probes sent after A
    // + 40 s, which time out 60 s after they go, after A + 100 s. So the
    // stop by silence comes some 40 s before Dead: in this run A is 198.8
    // s, the stop 258.8 s and Dead 311.1 s. At a round trip of 10 s the
    // timeouts of 30 s can bring Dead first, and the stop is then Dead's.
    let sent: RefCell<Vec<Went>> = RefCell::new(Vec::new());
    let rtt = |at: u64, to: &PathRef| {
        if *to != q() {
            return Some(0);
        }
        let r = Some(ramp(at)).filter(|r| at + r <= CUT);
        sent.borrow_mut().push((at, r, None));
        r
    };
    let mut net = Net::new(&rtt);
    let mut n = two(63);
    let mut dead = None;
    let mut watch = |n: &Node, at: u64| {
        let latest = path(n, &q()).live().rtt();
        for w in sent.borrow_mut().iter_mut().filter(|w| w.0 == at) {
            w.2.get_or_insert(latest.unwrap_or_default());
        }
        let s = state(n, &q());
        if at <= CUT {
            assert_eq!(s, PathState::Live, "precondition: q Live at {at} ms");
        }
        if s == PathState::Dead {
            dead.get_or_insert(at);
        }
    };
    net.run(&mut n, CUT + 400_000, &mut watch);
    let sent = sent.into_inner();
    let dead = dead.expect("precondition: q went Dead after the cut");
    let floor = Config::draft().timeout;
    for &(at, r, latest) in &sent {
        let (Some(r), Some(latest)) = (r, latest) else {
            continue;
        };
        let timeout = floor.max(latest * 3).as_millis() as u64;
        assert!(
            r < timeout,
            "precondition: the answer to q's probe at {at} ms is late ({r} ms, timeout {timeout} ms)"
        );
    }
    assert!(
        sent.iter().any(|w| w.1 == Some(R)),
        "precondition: q's round trip reached {R} ms"
    );
    let last = sent
        .iter()
        .filter_map(|w| w.1.map(|r| w.0 + r))
        .max()
        .expect("q was answered");
    let first = sent
        .iter()
        .map(|w| w.0)
        .find(|at| *at >= last)
        .expect("a probe on q after the last answer");
    let stop = first + SILENCE;
    assert!(
        stop < dead,
        "precondition: q stops answering by silence ({stop} ms) before Dead ({dead} ms)"
    );
    let after: Vec<u64> = sent.iter().map(|w| w.0).filter(|at| *at >= stop).collect();
    assert!(
        after.iter().filter(|at| **at < dead).count() >= 2,
        "precondition: q probed between its stop and Dead: {after:?}"
    );
    if let Some(e) = floor_breaks(stop, &after) {
        panic!("{e}; last answer at {last} ms, Dead at {dead} ms");
    }
}
