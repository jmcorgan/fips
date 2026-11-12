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
    log.changes(&p())
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
