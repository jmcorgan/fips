//! A probe's verdict under load (multipath v1 draft, Section 5.6, which
//! leaves the probe timeout to the node): the timeout follows the largest
//! round trip in the path's window up to the verdict cap, and a probe whose
//! timeout passes while the peer's session datagrams keep arriving on its
//! path is judged only at the cap from its sending. Heartbeats, reports and
//! the peer's path messages hold no verdict, so a failure of this node's
//! own direction on an idle link is found as before. Each test drives a
//! `Bundle` in the shell, the original path `p` active and `q` a Live
//! standby, with every probe on `p` lost from 1 s.

use alloc::vec::Vec;

use super::shell::*;
use crate::proto::path::live::Liveness;
use crate::proto::path::params::Config;
use crate::proto::path::wire::PATH_PROBE_MIN_SIZE;
use crate::proto::path::{PathRef, PathState, Why};
use crate::testutil::TestInstant;
use crate::time::Duration;

/// The type byte of a session datagram.
const DATAGRAM: u8 = 0x00;

/// The type byte of a sender report.
const REPORT: u8 = 0x01;

/// The type byte of a heartbeat.
const HEARTBEAT: u8 = 0x51;

/// The type byte of a path probe.
const PROBE: u8 = 0x52;

/// The frames that arrive on `p` while its probes are lost.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Frames {
    /// None.
    None,
    /// A session datagram every 50 ms.
    Data,
    /// A heartbeat and a sender report in turn every 50 ms, and the peer's
    /// probe on `p` every 200 ms.
    Control,
}

/// Lose every probe on `p` from 1 s, with `frames` arriving on `p` from
/// then, and run to `until` milliseconds. Returns `p`'s state changes.
fn lose(seed: u64, frames: Frames, until: u64) -> Vec<Timed> {
    lost(seed, frames, until).changes(&p())
}

/// As [`lose`], returning the whole log.
fn lost(seed: u64, frames: Frames, until: u64) -> Log {
    let mut n = two(seed);
    let mut log = Log::default();
    run(&mut n, &mut log, 999, &mut all);
    let mut answers = |_: u64, to: &PathRef| *to != p();
    let mut next = 1_000;
    let mut probe_id = 1;
    loop {
        let wake = n.b.next_wake().map(|w| w.0);
        let frame = (frames != Frames::None).then_some(next);
        let Some(at) = [wake, frame].into_iter().flatten().min() else {
            break;
        };
        if at > until {
            break;
        }
        n.now = TestInstant(at);
        if frame == Some(at) {
            match frames {
                Frames::None => {}
                Frames::Data => {
                    n.account(t(1), &addr(1), 100, DATAGRAM);
                }
                Frames::Control => {
                    let ty = if (at / 50) % 2 == 0 {
                        HEARTBEAT
                    } else {
                        REPORT
                    };
                    n.account(t(1), &addr(1), 100, ty);
                    if at % 200 == 100 {
                        n.account(t(1), &addr(1), PATH_PROBE_MIN_SIZE, PROBE);
                        let msg = probe_from(peer(&p()), probe_id, PATH_PROBE_MIN_SIZE);
                        probe_id += 1;
                        let out = n.probe(t(1), addr(1), msg);
                        handle(&mut n, &mut log, out, &mut answers);
                    }
                }
            }
            next += 50;
        }
        if wake == Some(at) {
            let out = n.poll();
            handle(&mut n, &mut log, out, &mut answers);
        }
    }
    log
}

/// The probe timeouts `p`'s changes to Suspect for unanswered probes
/// carried in `log`, each at its instant in milliseconds.
fn suspect_waits(log: &[(u64, Waited)]) -> Vec<(u64, Duration)> {
    log.iter()
        .filter(|(_, (to, from, next, why, _))| {
            *to == p()
                && *from == Some(PathState::Live)
                && *next == Some(PathState::Suspect)
                && *why == Why::Timeout
        })
        .map(|&(at, (_, _, _, _, wait))| (at, wait))
        .collect()
}

/// `p` turning Suspect at `at` milliseconds for unanswered probes.
fn suspect(at: u64) -> Vec<Timed> {
    alloc::vec![(
        at,
        Some(PathState::Live),
        Some(PathState::Suspect),
        Why::Timeout
    )]
}

#[test]
fn a_probe_whose_timeout_passes_while_session_datagrams_keep_arriving_is_counted_only_at_the_cap() {
    // The probes on p at 1.0, 1.2 and 1.4 s time out at 1.4, 1.6 and 1.8 s,
    // after session datagrams have arrived on p, so each waits until 3 s
    // from its sending: the third is counted at 4.4 s.
    let cap = Config::draft().verdict_cap.as_millis() as u64;
    assert_eq!(cap, 3_000, "precondition: the cap is 3 s");
    assert_eq!(
        lose(71, Frames::Data, 6_000),
        suspect(1_400 + cap),
        "defect: a probe followed by session datagrams was not judged at the cap from its sending"
    );
}

#[test]
fn heartbeats_reports_and_the_peers_probes_arriving_after_a_probe_do_not_hold_its_verdict() {
    // Link control and the peer's path messages show only that the peer
    // still sends, not that the path carries data: p goes Suspect at 1.8 s,
    // as with nothing arriving.
    assert_eq!(
        lose(72, Frames::Control, 6_000),
        suspect(1_800),
        "defect: link control or the peer's probes held a probe's verdict"
    );
}

#[test]
fn with_nothing_arriving_and_no_long_round_trip_a_probe_is_counted_at_the_timeout_floor() {
    assert_eq!(lose(73, Frames::None, 6_000), suspect(1_800));
}

#[test]
fn the_timeout_follows_the_largest_round_trip_in_the_window_up_to_the_cap() {
    let floor = Duration::from_millis(400);
    let cap = Duration::from_secs(3);
    let window = Duration::from_secs(30);
    let mut live: Liveness<TestInstant> = Liveness::new();
    assert_eq!(live.timeout(floor, cap), floor, "no sample: the floor");
    live.sample(
        TestInstant(0),
        Duration::from_millis(10),
        window,
        window * 2,
    );
    assert_eq!(
        live.timeout(floor, cap),
        floor,
        "short round trips: the floor"
    );
    live.sample(
        TestInstant(100),
        Duration::from_millis(900),
        window,
        window * 2,
    );
    live.sample(
        TestInstant(200),
        Duration::from_millis(10),
        window,
        window * 2,
    );
    assert_eq!(
        live.timeout(floor, cap),
        Duration::from_millis(2_700),
        "defect: the timeout is not three times the largest round trip in the window"
    );
    live.sample(TestInstant(300), Duration::from_secs(2), window, window * 2);
    live.sample(
        TestInstant(400),
        Duration::from_millis(10),
        window,
        window * 2,
    );
    assert_eq!(
        live.timeout(floor, cap),
        cap,
        "defect: the term from the largest round trip is not capped"
    );
    // A latest round trip above the cap keeps today's timeout of three
    // times it, uncapped.
    live.sample(
        TestInstant(500),
        Duration::from_secs(20),
        window,
        window * 2,
    );
    assert_eq!(live.timeout(floor, cap), Duration::from_secs(60));
    // A sample older than the window no longer counts.
    let mut aged: Liveness<TestInstant> = Liveness::new();
    aged.sample(
        TestInstant(0),
        Duration::from_millis(900),
        window,
        window * 2,
    );
    aged.sample(
        TestInstant(31_000),
        Duration::from_millis(10),
        window,
        window * 2,
    );
    assert_eq!(aged.timeout(floor, cap), floor);
}

#[test]
fn a_probe_sent_after_a_long_round_trip_in_the_window_is_counted_at_three_times_it() {
    // p's probes are answered at once, except the one at 1 s, answered after
    // 900 ms, late for its 400 ms timeout. Every probe on p from 3 s is
    // lost: the three at 3.0, 3.2 and 3.4 s are counted at 2.7 s from their
    // sending, the third at 6.1 s, not at 3.8 s.
    let rtt = |at: u64, to: &PathRef| {
        if *to != p() {
            return Some(0);
        }
        match at {
            1_000 => Some(900),
            a if a >= 3_000 => None,
            _ => Some(0),
        }
    };
    let mut net = Net::new(&rtt);
    let mut n = two(74);
    let mut changes = Vec::new();
    let mut watch = |n: &Node, at: u64| {
        let s = state(n, &p());
        if changes.last().is_none_or(|&(_, last)| last != s) {
            changes.push((at, s));
        }
    };
    net.run(&mut n, 10_000, &mut watch);
    assert_eq!(
        path(&n, &p()).live().max_rtt(),
        Some(Duration::from_millis(900)),
        "precondition: the late answer gave the window its largest sample"
    );
    assert_eq!(
        changes.iter().find(|(_, s)| *s == PathState::Suspect),
        Some(&(6_100, PathState::Suspect)),
        "defect: a probe sent after a long round trip was not given three times it: {changes:?}"
    );
}

#[test]
fn a_change_to_suspect_carries_the_timeout_its_probe_was_sent_under_and_not_the_held_verdicts_wait()
{
    // As the first test: the third probe on p, sent at 1.4 s under the
    // 400 ms floor, is held to the cap by the datagrams and counted at
    // 4.4 s. Its due instant then is 3 s from its sending; the change
    // carries the 400 ms it was sent under, not that.
    let cap = Config::draft().verdict_cap.as_millis() as u64;
    let log = lost(71, Frames::Data, 6_000);
    assert_eq!(
        log.changes(&p()),
        suspect(1_400 + cap),
        "precondition: the verdict was held to the cap"
    );
    assert_eq!(
        suspect_waits(&log.waits),
        alloc::vec![(1_400 + cap, Duration::from_millis(400))],
        "defect: the change did not carry the timeout its probe was sent under"
    );
}

#[test]
fn a_change_to_suspect_at_the_floor_carries_the_floor() {
    let log = lost(73, Frames::None, 6_000);
    assert_eq!(
        suspect_waits(&log.waits),
        alloc::vec![(1_800, Config::draft().timeout)],
        "defect: a change at the floor did not carry the floor"
    );
}

#[test]
fn every_change_a_probe_timeout_makes_carries_a_timeout_and_no_other_change_does() {
    // With nothing arriving, p goes Suspect, then Dead after ten more: two
    // changes for timeouts, each carrying the floor its probe went under.
    let log = lost(73, Frames::None, 30_000);
    assert_eq!(
        log.changes(&p()).iter().map(|c| c.3).collect::<Vec<_>>(),
        alloc::vec![Why::Timeout, Why::Retired],
        "precondition: p went Suspect and Dead for unanswered probes"
    );
    let waits: Vec<(Why, Duration)> = log.waits.iter().map(|(_, w)| (w.3, w.4)).collect();
    let floor = Config::draft().timeout;
    assert_eq!(
        waits,
        alloc::vec![(Why::Timeout, floor), (Why::Retired, floor)],
        "defect: a change for unanswered probes did not carry the floor its probe went under"
    );
    // A candidate admitted, probed and answered: changes for no timeout.
    let mut n = Node::capable(73);
    let mut log = Log::default();
    let out = n.candidate(t(2), addr(2));
    handle(&mut n, &mut log, out, &mut all);
    assert!(
        log.states.len() >= 2,
        "precondition: the candidate was admitted and answered: {:?}",
        log.states
    );
    assert_eq!(
        log.waits,
        Vec::new(),
        "defect: a change no probe timeout made carried a timeout"
    );
}

/// A change of p's state at an instant in milliseconds, with the probe
/// timeout p would give a probe sent then.
type Seen = (u64, PathState, Duration);

/// Run `two` under `rtt` to `until` milliseconds, and return the changes
/// that carried a probe timeout and, at each change of p's state, the probe
/// timeout p would give a probe sent then.
fn timed(
    rtt: &dyn Fn(u64, &PathRef) -> Option<u64>,
    until: u64,
) -> (Vec<(u64, Waited)>, Vec<Seen>) {
    let cfg = Config::draft();
    let mut net = Net::new(rtt);
    let mut n = two(74);
    let mut changes: Vec<Seen> = Vec::new();
    let mut watch = |n: &Node, at: u64| {
        let s = state(n, &p());
        if changes.last().is_none_or(|&(_, last, _)| last != s) {
            let now = path(n, &p()).live().timeout(cfg.timeout, cfg.verdict_cap);
            changes.push((at, s, now));
        }
    };
    net.run(&mut n, until, &mut watch);
    (net.waits, changes)
}

#[test]
fn a_change_to_suspect_after_a_long_round_trip_in_the_window_carries_three_times_it() {
    // As the test before: the third lost probe, sent at 3.4 s under 2.7 s,
    // makes p Suspect at 6.1 s and the change carries 2.7 s.
    let rtt = |at: u64, to: &PathRef| {
        if *to != p() {
            return Some(0);
        }
        match at {
            1_000 => Some(900),
            a if a >= 3_000 => None,
            _ => Some(0),
        }
    };
    let (waits, _) = timed(&rtt, 10_000);
    assert_eq!(
        suspect_waits(&waits),
        alloc::vec![(6_100, Duration::from_millis(2_700))],
        "defect: the change did not carry three times the window's largest round trip"
    );
}

#[test]
fn a_round_trip_learned_after_the_judged_probes_went_does_not_reach_the_timeout_the_change_carries()
{
    // Every probe on p from 3 s is lost but the one at 3.0 s, answered
    // 700 ms later, at 3.7 s, after its 400 ms timeout. The probes at 3.0,
    // 3.2 and 3.4 s, each sent under the floor, are counted at 3.4, 3.6 and
    // 3.8 s, so p is Suspect at 3.8 s. The late answer has by then raised
    // the timeout a probe sent at 3.8 s would get to three times 700 ms;
    // the change carries the 400 ms the judged probes went under.
    let rtt = |at: u64, to: &PathRef| {
        if *to != p() {
            return Some(0);
        }
        match at {
            3_000 => Some(700),
            a if a > 3_000 => None,
            _ => Some(0),
        }
    };
    let (waits, changes) = timed(&rtt, 6_000);
    let at_suspect = changes
        .iter()
        .find(|(_, s, _)| *s == PathState::Suspect)
        .copied();
    assert_eq!(
        at_suspect,
        Some((3_800, PathState::Suspect, Duration::from_millis(2_100))),
        "precondition: p went Suspect at 3.8 s after the late answer raised its timeout: {changes:?}"
    );
    assert_eq!(
        suspect_waits(&waits),
        alloc::vec![(3_800, Duration::from_millis(400))],
        "defect: the change carried a timeout later than the one its probes were sent under"
    );
}
