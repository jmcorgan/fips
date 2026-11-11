//! Each path's liveness (multipath v1 draft, Section 5.6): the probe
//! cadence, the probe timeout, the unanswered counts and the state changes
//! they cause, the Dead cadence and grace, carrier and unreachable sends,
//! the peer's `ACTIVE` flag and `Bundle::next_wake`. Every test drives a
//! `Bundle` in the shell, which also checks after every step that a poll
//! before the next wake does nothing and that the next wake lies ahead.
//!
//! Runs answer each probe at the instant it is sent: a round trip of 0.

use alloc::vec::Vec;

use super::shell::*;
use crate::proto::fmp::wire::FRAME_OVERHEAD;
use crate::proto::path::wire::{PATH_PROBE_MIN_SIZE, PathAck, PathFlags, PathProbe};
use crate::proto::path::{Input, PathRef, PathState, Source, Why};
use crate::testutil::TestInstant;
use crate::time::Duration;

/// The type byte of a heartbeat.
const HEARTBEAT: u8 = 0x51;

/// A padded probe's length on a link MTU of 1280.
const PADDED: usize = 1280 - FRAME_OVERHEAD;

/// The peer's answer to `probe` on `to`, with `ACTIVE` set or clear.
fn answer(probe: &PathProbe, to: &PathRef, active: bool) -> PathAck {
    PathAck {
        flags: PathFlags::with_active(active),
        ..ack_for(probe, peer(to))
    }
}

/// The lengths a Probing or Dead path whose probes all go unanswered sends
/// in one state, `n` of them: padded to `padded` first, and once that one
/// has timed out stepping down the ladder, three quarters and half of
/// `padded`, then the smallest, and starting again from `padded` (Section
/// 5.1, padding being local).
fn ladder(n: usize, padded: usize) -> Vec<usize> {
    let cycle = [padded, padded * 3 / 4, padded / 2, PATH_PROBE_MIN_SIZE];
    cycle.iter().copied().cycle().take(n).collect()
}

/// The successive differences of `v`.
fn gaps(v: &[u64]) -> Vec<u64> {
    v.windows(2).map(|w| w[1] - w[0]).collect()
}

#[test]
fn probes_go_every_200_ms_on_the_active_path_and_every_second_on_a_standby() {
    let mut n = two(41);
    let mut log = Log::default();
    run(&mut n, &mut log, 5_000, &mut all);
    let active = log.on(&p());
    assert_eq!(active.len(), 25, "{active:?}");
    assert!(gaps(&active).iter().all(|g| *g == 200), "{active:?}");
    // The standby's first probe after its answer keeps the schedule it had
    // while Probing; from then on it goes once a second.
    let standby = log.on(&q());
    assert_eq!(standby, [200, 1_200, 2_200, 3_200, 4_200]);
    assert!(log.states.is_empty());
}

#[test]
fn a_standby_the_peer_marks_active_is_probed_every_200_ms() {
    let mut n = two(42);
    let mut log = Log::default();
    let out = at(
        &mut n,
        &mut log,
        100,
        Input::Probe {
            transport: t(2),
            addr: addr(2),
            msg: marked(0xB, 1, true),
        },
    );
    assert!(probes(&out).is_empty());
    // The peer's answers on the path carry ACTIVE too.
    while let Some(out) = n.tick(TestInstant(3_000)) {
        log.add(n.now, &out);
        for (to, probe) in probes(&out) {
            let active = to == q();
            n.ack(to.transport, to.addr.clone(), answer(&probe, &to, active));
        }
    }
    let standby = log.on(&q());
    assert_eq!(standby.len(), 15, "{standby:?}");
    assert!(gaps(&standby).iter().all(|g| *g == 200), "{standby:?}");
}

#[test]
fn a_link_with_one_live_path_and_nothing_else_sends_no_probes() {
    let mut n = Node::capable(43);
    assert_eq!(n.b.next_wake(), None);
    for k in 1..=50 {
        n.now = TestInstant(k * 200);
        assert!(n.poll().is_empty());
    }
    assert_eq!(n.b.next_wake(), None);
    // A candidate makes two paths: probes start on both, the original's of
    // the smallest size, since the handshake proved it.
    let out = n.candidate(t(2), addr(2));
    assert_eq!(probe_on(&out, &p()).len, 27);
    assert_eq!(probe_on(&out, &q()).len, PADDED);
    assert!(n.b.next_wake().is_some());
}

#[test]
fn three_unanswered_probes_make_a_live_path_suspect_while_frames_still_arrive_on_it() {
    let mut n = two(44);
    let mut log = Log::default();
    run(&mut n, &mut log, 999, &mut all);
    // From 1 s our probes on the active path are lost, while the peer's
    // frames still arrive on it.
    while let Some(out) = n.tick(TestInstant(3_000)) {
        n.account(t(1), &addr(1), 100, HEARTBEAT);
        handle(&mut n, &mut log, out, &mut |_, to| *to != p());
    }
    assert_eq!(
        log.changes(&p()),
        [(
            1_800,
            Some(PathState::Live),
            Some(PathState::Suspect),
            Why::Timeout
        )]
    );
    assert!(path(&n, &p()).live().frames() > 0);
}

#[test]
fn one_or_two_unanswered_probes_leave_a_live_path_live() {
    for lost in [1, 2] {
        let mut n = two(45);
        let mut log = Log::default();
        run(&mut n, &mut log, 999, &mut all);
        // The standby's probes at 1.2 s and 2.2 s go unanswered, each
        // timing out before the next is sent.
        let mut dropped = 0;
        let mut answers = |at: u64, to: &PathRef| {
            let drop = *to == q() && at >= 1_000 && dropped < lost;
            dropped += u32::from(drop);
            !drop
        };
        run(
            &mut n,
            &mut log,
            999 + 1_000 * u64::from(lost),
            &mut answers,
        );
        assert_eq!(path(&n, &q()).live().misses(), lost);
        run(&mut n, &mut log, 5_000, &mut answers);
        assert_eq!(state(&n, &q()), PathState::Live);
        assert_eq!(path(&n, &q()).live().misses(), 0);
        assert!(log.changes(&q()).is_empty(), "{lost} lost");
    }
}

/// A run at a round trip of 0, with acks at the instant of the probe they
/// answer. With a round trip `r` and a failure in both directions, the
/// acks in flight at the failure are lost too, and detection can come as
/// early as 0.8 s less `r` after it.
#[test]
fn a_failure_is_detected_between_800_and_1000_ms_after_it_starts() {
    let mut seen = Vec::new();
    for offset in [0, 50, 120, 199] {
        let mut n = two(46);
        let mut log = Log::default();
        let fail = 5_000 + offset;
        run(&mut n, &mut log, 7_000, &mut |at, to| {
            *to != p() || at < fail
        });
        let [(at, Some(PathState::Live), Some(PathState::Suspect), Why::Timeout)] =
            log.changes(&p())[..]
        else {
            panic!("one change to Suspect: {:?}", log.changes(&p()));
        };
        let after = at - fail;
        assert!(
            (800..1_000).contains(&after),
            "a failure at {fail} found at {at}"
        );
        seen.push(after);
    }
    // The first probe lost is the first sent at or after the failure, and
    // the third after it times out 800 ms after that probe.
    assert_eq!(seen, [800, 950, 880, 801]);
}

#[test]
fn ten_unanswered_probes_in_suspect_retire_a_path_then_it_is_probed_at_the_dead_cadence() {
    let mut n = two(47);
    let mut log = Log::default();
    run(&mut n, &mut log, 999, &mut all);
    run(&mut n, &mut log, 80_000, &mut |_, to| *to != q());
    // Three standby probes, at 1.2, 2.2 and 3.2 s, time out by 3.6 s; ten
    // more, a second apart, by 13.6 s.
    assert_eq!(
        log.changes(&q()),
        [
            (
                3_600,
                Some(PathState::Live),
                Some(PathState::Suspect),
                Why::Timeout
            ),
            (
                13_600,
                Some(PathState::Suspect),
                Some(PathState::Dead),
                Why::Retired
            ),
        ]
    );
    let dead: Vec<u64> = log.on(&q()).into_iter().filter(|at| *at > 13_600).collect();
    let since: Vec<u64> = dead.iter().map(|at| at - 13_600).collect();
    assert_eq!(since, [1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 62_000]);
    let lens: Vec<usize> = log
        .probes
        .iter()
        .filter(|(at, to, _)| *at > 13_600 && *to == q())
        .map(|(_, _, probe)| probe.len)
        .collect();
    assert_eq!(lens, ladder(7, PADDED));
}

#[test]
fn an_answer_brings_a_suspect_path_back_to_live() {
    let mut n = two(48);
    let mut log = Log::default();
    run(&mut n, &mut log, 999, &mut all);
    run(&mut n, &mut log, 3_999, &mut |_, to| *to != q());
    assert_eq!(state(&n, &q()), PathState::Suspect);
    run(&mut n, &mut log, 5_000, &mut all);
    assert_eq!(
        log.changes(&q()),
        [
            (
                3_600,
                Some(PathState::Live),
                Some(PathState::Suspect),
                Why::Timeout
            ),
            (
                4_200,
                Some(PathState::Suspect),
                Some(PathState::Live),
                Why::Answered
            ),
        ]
    );
}

#[test]
fn an_answer_brings_an_acked_dead_path_back_to_live() {
    let mut n = two(49);
    let mut log = Log::default();
    let id = path(&n, &q()).path_id();
    let out = at(
        &mut n,
        &mut log,
        100,
        Input::Close {
            transport: t(2),
            addr: addr(2),
            msg: close_from(id),
        },
    );
    assert!(probes(&out).iter().all(|(to, _)| *to != q()));
    run(&mut n, &mut log, 3_000, &mut all);
    assert_eq!(
        log.changes(&q()),
        [
            (
                100,
                Some(PathState::Live),
                Some(PathState::Dead),
                Why::Closed
            ),
            (
                1_100,
                Some(PathState::Dead),
                Some(PathState::Live),
                Why::Answered
            ),
        ]
    );
}

#[test]
fn a_path_answered_back_to_live_is_probed_at_its_live_cadence_from_then_on() {
    let mut n = two(50);
    let mut log = Log::default();
    run(&mut n, &mut log, 999, &mut all);
    // As above: Dead at 13.6 s, then probed at 14.6, 15.6, 17.6, 21.6,
    // 29.6 and 45.6 s, and the next due 30 s on.
    run(&mut n, &mut log, 45_000, &mut |_, to| *to != q());
    assert_eq!(state(&n, &q()), PathState::Dead);
    run(&mut n, &mut log, 50_000, &mut all);
    assert_eq!(state(&n, &q()), PathState::Live);
    // The Dead probe answered at 45.6 s, a rung of the ladder, proves a
    // size below the link MTU, so a padded search probe goes beside the
    // next cadence probe; it is no cadence probe and is not counted.
    let after: Vec<u64> = log
        .probes
        .iter()
        .filter(|(at, to, probe)| {
            *to == q() && (*at == 45_600 || (*at > 45_600 && probe.len == PATH_PROBE_MIN_SIZE))
        })
        .map(|(at, _, _)| *at)
        .collect();
    assert_eq!(after, [45_600, 46_600, 47_600, 48_600, 49_600]);
}

#[test]
fn a_path_never_answered_is_given_up_after_eight_probes_doubling_up_to_the_heartbeat() {
    let mut n = Node::capable(50);
    let mut log = Log::default();
    let out = n.candidate(t(2), addr(2));
    handle(&mut n, &mut log, out, &mut |_, to| *to != q());
    run(&mut n, &mut log, 60_000, &mut |_, to| *to != q());
    assert_eq!(
        log.on(&q()),
        [0, 400, 800, 1_600, 3_200, 6_400, 12_800, 22_800]
    );
    assert_eq!(
        log.changes(&q()),
        [
            (0, None, Some(PathState::Probing), Why::Candidate),
            (
                23_200,
                Some(PathState::Probing),
                Some(PathState::Dead),
                Why::Exhausted
            ),
        ]
    );
    let probed: Vec<usize> = log
        .probes
        .iter()
        .filter(|(_, to, _)| *to == q())
        .map(|(_, _, probe)| probe.len)
        .collect();
    assert_eq!(probed, ladder(8, PADDED));
}

#[test]
fn a_probing_path_never_goes_suspect() {
    let mut n = Node::capable(51);
    let mut log = Log::default();
    let created = pair(t(3), addr(3));
    let out = n.probe(t(3), addr(3), probe_from(0xC, 1, 27));
    handle(&mut n, &mut log, out, &mut |_, to| {
        *to != pair(t(3), addr(3))
    });
    while let Some(out) = n.tick(TestInstant(60_000)) {
        let s = state(&n, &created);
        assert!(matches!(s, PathState::Probing | PathState::Dead), "{s:?}");
        handle(&mut n, &mut log, out, &mut |_, to| {
            *to != pair(t(3), addr(3))
        });
    }
    assert_eq!(
        log.changes(&created),
        [
            (0, None, Some(PathState::Probing), Why::Probed),
            (
                23_200,
                Some(PathState::Probing),
                Some(PathState::Dead),
                Why::Exhausted
            ),
        ]
    );
}

#[test]
fn a_late_answer_samples_the_round_trip_and_still_counts_as_unanswered() {
    let mut n = Node::capable(52);
    let mut log = Log::default();
    let out = n.candidate(t(2), addr(2));
    let first = probe_on(&out, &q());
    handle(&mut n, &mut log, out, &mut |_, to| *to != q());
    run(&mut n, &mut log, 400, &mut |_, to| *to != q());
    let before = path(&n, &q()).live().clone();
    assert_eq!(before.misses(), 1, "the first probe timed out at 400 ms");
    assert_eq!(before.outstanding(), 1, "the second went at 400 ms");
    run(&mut n, &mut log, 649, &mut |_, to| *to != q());
    let out = at(
        &mut n,
        &mut log,
        650,
        Input::Ack {
            transport: t(2),
            addr: addr(2),
            msg: PathAck {
                len: 600,
                ..ack_for(&first, 0xB)
            },
        },
    );
    assert!(out.is_empty(), "{out:?}");
    let q_path = path(&n, &q());
    let live = q_path.live();
    assert_eq!(live.rtt(), Some(Duration::from_millis(650)));
    assert_eq!(live.samples(), 1);
    assert_eq!(live.misses(), 1, "the timeout still counts");
    assert_eq!(live.outstanding(), 1);
    assert_eq!(live.mtu(), None, "no MTU proven");
    assert_eq!(q_path.state(), PathState::Probing);
    assert_eq!(q_path.peer_id(), None, "no identifier learned");
    assert!(!q_path.acked());
    // The same answer again matches nothing.
    let out = at(
        &mut n,
        &mut log,
        660,
        Input::Ack {
            transport: t(2),
            addr: addr(2),
            msg: ack_for(&first, 0xB),
        },
    );
    assert_eq!(refusals(&out).len(), 1, "{out:?}");
}

#[test]
fn an_answer_after_its_probes_timeout_is_late_whether_or_not_the_host_polled() {
    // A candidate's first probe goes at 0 ms and goes unanswered at 400 ms;
    // its answer comes at 500 ms, to a host that polled at each wake and to
    // one that did not.
    let late = |polls: bool| {
        let mut n = Node::capable(55);
        let out = n.candidate(t(2), addr(2));
        let probe = probe_on(&out, &q());
        if polls {
            while n.tick(TestInstant(499)).is_some() {}
        }
        n.now = TestInstant(500);
        n.ack(t(2), addr(2), ack_for(&probe, 0xB));
        let p = path(&n, &q());
        (p.state(), p.live().misses(), p.live().rtt())
    };
    let want = (PathState::Probing, 1, Some(Duration::from_millis(500)));
    assert_eq!(late(true), want, "polled at each wake");
    assert_eq!(late(false), want, "not polled");
}

#[test]
fn a_timeout_counts_only_if_no_later_probe_was_answered() {
    let mut n = two(53);
    let mut log = Log::default();
    run(&mut n, &mut log, 999, &mut all);
    // The probe at 1 s is lost and the one at 1.2 s answered: the first's
    // timeout at 1.4 s does not count. The ones at 1.4 s and 1.6 s are lost:
    // the first of them counts at 1.8 s.
    let mut answers = |at: u64, to: &PathRef| *to != p() || at == 1_200;
    run(&mut n, &mut log, 1_400, &mut answers);
    assert_eq!(path(&n, &p()).live().misses(), 0);
    run(&mut n, &mut log, 1_800, &mut answers);
    assert_eq!(path(&n, &p()).live().misses(), 1);
    assert_eq!(state(&n, &p()), PathState::Live);
}

#[test]
fn the_probe_timeout_is_three_round_trips_once_that_exceeds_400_ms() {
    let mut n = two(54);
    let mut log = Log::default();
    let standby = &mut |_: u64, to: &PathRef| *to == q();
    let due = |n: &Node| path(n, &p()).live().earliest_due();
    // A round trip of 100 ms: three of them are under the 400 ms floor.
    n.now = TestInstant(200);
    let out = n.poll();
    let first = probe_on(&out, &p());
    handle(&mut n, &mut log, out, standby);
    assert_eq!(due(&n), Some(TestInstant(600)));
    at(
        &mut n,
        &mut log,
        300,
        Input::Ack {
            transport: t(1),
            addr: addr(1),
            msg: ack_for(&first, 0xA),
        },
    );
    let out = at(&mut n, &mut log, 400, Input::Poll);
    let second = probe_on(&out, &p());
    assert_eq!(due(&n), Some(TestInstant(800)));
    // A round trip of 200 ms: the probe sent next waits 600 ms.
    let out = at(
        &mut n,
        &mut log,
        600,
        Input::Ack {
            transport: t(1),
            addr: addr(1),
            msg: ack_for(&second, 0xA),
        },
    );
    probe_on(&out, &p());
    assert_eq!(due(&n), Some(TestInstant(1_200)));
}

#[test]
fn a_dead_path_is_discarded_at_the_grace_unless_it_is_acked_and_nothing_is_live() {
    let mut n = Node::capable(55);
    let mut log = Log::default();
    let (r, s) = (pair(t(3), addr(3)), pair(t(4), addr(4)));
    live_path(&mut n, t(2), addr(2), 0xB);
    live_path(&mut n, t(3), addr(3), 0xC);
    // Every acked path closed by the peer: nothing is Live.
    for to in [p(), q(), r.clone()] {
        let id = path(&n, &to).path_id();
        at(
            &mut n,
            &mut log,
            0,
            Input::Close {
                transport: to.transport,
                addr: to.addr.clone(),
                msg: close_from(id),
            },
        );
    }
    // A candidate that never answers is given up at 23.2 s.
    at(
        &mut n,
        &mut log,
        0,
        Input::Candidate {
            transport: t(4),
            addr: addr(4),
            source: Source::Config,
        },
    );
    run(&mut n, &mut log, 700_000, &mut |_, _| false);
    assert_eq!(
        log.changes(&s).last(),
        Some(&(623_200, Some(PathState::Dead), None, Why::Grace))
    );
    let held: Vec<PathRef> =
        n.b.paths()
            .paths()
            .iter()
            .map(|path| pair(path.transport_id(), path.addr().clone()))
            .collect();
    assert_eq!(held, [p(), q(), r], "the acked Dead paths are kept");
}

#[test]
fn an_acked_dead_path_past_its_grace_is_discarded_once_a_path_is_live() {
    let mut n = Node::capable(56);
    let mut log = Log::default();
    live_path(&mut n, t(2), addr(2), 0xB);
    for to in [p(), q()] {
        let id = path(&n, &to).path_id();
        at(
            &mut n,
            &mut log,
            0,
            Input::Close {
                transport: to.transport,
                addr: to.addr.clone(),
                msg: close_from(id),
            },
        );
    }
    run(&mut n, &mut log, 650_000, &mut |_, _| false);
    assert_eq!(state(&n, &q()), PathState::Dead, "kept past its grace");
    // The original answers its next Dead probe and is Live: the other goes
    // in the same step.
    run(&mut n, &mut log, 700_000, &mut |_, to| *to == p());
    let [(live, _, _, Why::Answered)] = log.changes(&p())[1..] else {
        panic!("the original answered: {:?}", log.changes(&p()));
    };
    assert_eq!(
        log.changes(&q()).last(),
        Some(&(live, Some(PathState::Dead), None, Why::Grace))
    );
    assert_eq!(n.b.paths().len(), 1);
}

#[test]
fn a_forgotten_path_is_not_probed_again_until_it_is_reported_again() {
    let mut n = Node::capable(57);
    let mut log = Log::default();
    let out = n.candidate(t(2), addr(2));
    handle(&mut n, &mut log, out, &mut |_, to| *to != q());
    run(&mut n, &mut log, 700_000, &mut |_, to| *to != q());
    assert_eq!(
        log.changes(&q()).last(),
        Some(&(623_200, Some(PathState::Dead), None, Why::Grace))
    );
    assert_eq!(
        log.on(&q()).last(),
        Some(&22_800),
        "none after it was given up"
    );
    // Hours of polls: a link of one Live path sends nothing.
    assert_eq!(n.b.next_wake(), None);
    for k in 0..180 {
        n.now = TestInstant(700_000 + k * 60_000);
        assert!(n.poll().is_empty());
    }
    // Its pair is held back: a repeat of it sends nothing. Its source
    // drops it and lists it again: that report is fresh, and the pair is a
    // new path, probed at once.
    assert!(n.candidate(t(2), addr(2)).is_empty());
    assert!(n.unlist(t(2), addr(2), Source::Config).is_empty());
    let out = n.candidate(t(2), addr(2));
    let [(_, next, None, Some(PathState::Probing), Why::Candidate)] = states(&out)[..] else {
        panic!("a new path: {out:?}");
    };
    assert_eq!(probe_on(&out, &q()).path_id, next);
}

#[test]
fn a_held_dead_path_is_probed_when_its_transport_regains_carrier() {
    let mut n = Node::capable(58);
    let mut log = Log::default();
    let r = pair(t(3), addr(3));
    live_path(&mut n, t(3), addr(3), 0xC);
    let id = path(&n, &r).path_id();
    at(
        &mut n,
        &mut log,
        0,
        Input::Close {
            transport: t(3),
            addr: addr(3),
            msg: close_from(id),
        },
    );
    let out = n.candidate(t(2), addr(2));
    let answers = &mut |_: u64, to: &PathRef| *to == p();
    handle(&mut n, &mut log, out, answers);
    run(&mut n, &mut log, 29_999, answers);
    assert_eq!(state(&n, &q()), PathState::Dead, "never acked, given up");
    // Carrier returns on transport 2: the never-acked Dead path, not probed
    // since it was given up, is probed in the step, the floor's first
    // instant having passed.
    let out = at(
        &mut n,
        &mut log,
        30_000,
        Input::Carrier {
            transport: t(2),
            up: true,
        },
    );
    let [(_, _, Some(PathState::Dead), Some(PathState::Probing), Why::Returned)] = states(&out)[..]
    else {
        panic!("revived: {out:?}");
    };
    assert_eq!(probe_on(&out, &q()).len, PADDED);
    // On transport 3 the acked Dead path, stopped at 0, has a probe out at
    // the Dead cadence. Brought back by carrier it keeps its stop, so its
    // first probe waits for the floor's next instant.
    run(&mut n, &mut log, 32_099, answers);
    assert_eq!(path(&n, &r).live().outstanding(), 1);
    let free = free_after(0, &log.on(&r));
    assert!(
        free > 32_100,
        "precondition: the floor's next instant {free}"
    );
    let out = at(
        &mut n,
        &mut log,
        32_100,
        Input::Carrier {
            transport: t(3),
            up: true,
        },
    );
    let [(_, _, Some(PathState::Dead), Some(PathState::Probing), Why::Returned)] = states(&out)[..]
    else {
        panic!("revived: {out:?}");
    };
    assert!(
        probes(&out).iter().all(|(to, _)| *to != r),
        "r probed at once: {out:?}"
    );
    run(&mut n, &mut log, free, answers);
    let next = log.on(&r).into_iter().find(|at| *at > 32_100);
    assert_eq!(next, Some(free), "r's first probe once back");
}

#[test]
fn a_path_leaving_dead_starts_with_no_unanswered_probes() {
    let mut n = Node::capable(59);
    let mut log = Log::default();
    live_path(&mut n, t(2), addr(2), 0xB);
    let id = path(&n, &q()).path_id();
    at(
        &mut n,
        &mut log,
        0,
        Input::Close {
            transport: t(2),
            addr: addr(2),
            msg: close_from(id),
        },
    );
    let answers = &mut |_: u64, to: &PathRef| *to == p();
    run(&mut n, &mut log, 20_000, answers);
    // Dead probes at 1, 2, 4, 8 and 16 s, each unanswered.
    assert_eq!(path(&n, &q()).live().misses(), 5);
    at(
        &mut n,
        &mut log,
        20_000,
        Input::Carrier {
            transport: t(2),
            up: true,
        },
    );
    assert_eq!(path(&n, &q()).live().misses(), 0);
    run(&mut n, &mut log, 260_000, answers);
    // Eight unanswered discovery probes give it up again; acked in this
    // link, it then goes on at the Dead cadence. The return of carrier
    // does not end the stop q has held since it became Dead at 0 s, so its
    // discovery probes after the one at once keep the floor (Section 5.6).
    let held: Vec<u64> = log
        .on(&q())
        .into_iter()
        .filter(|at| *at != 20_000)
        .collect();
    if let Some(e) = floor_breaks(0, &held) {
        panic!("{e}");
    }
    let changes = log.changes(&q());
    let Some(&(gone, Some(PathState::Probing), Some(PathState::Dead), Why::Exhausted)) =
        changes.last()
    else {
        panic!("given up again: {changes:?}");
    };
    let probing: Vec<u64> = log
        .on(&q())
        .into_iter()
        .filter(|at| (20_000..gone).contains(at))
        .collect();
    assert_eq!(probing.len(), 8, "a full discovery budget: {probing:?}");
}

#[test]
fn carrier_loss_or_an_unreachable_send_makes_a_live_path_suspect_and_nothing_else() {
    let mut n = Node::capable(60);
    let mut log = Log::default();
    live_path(&mut n, t(2), addr(2), 0xB);
    n.candidate(t(3), addr(3));
    let dead = pair(t(4), addr(4));
    live_path(&mut n, t(4), addr(4), 0xD);
    let id = path(&n, &dead).path_id();
    n.closed(t(4), addr(4), close_from(id));
    let carrier = |transport, up| Input::Carrier { transport, up };
    let out = at(&mut n, &mut log, 10, carrier(t(2), false));
    let ours = path(&n, &q()).path_id();
    assert_eq!(
        states(&out),
        [(
            q(),
            ours,
            Some(PathState::Live),
            Some(PathState::Suspect),
            Why::Carrier
        )]
    );
    // Probing, Dead and already Suspect paths are left as they are.
    for transport in [t(3), t(4), t(2)] {
        let out = at(&mut n, &mut log, 20, carrier(transport, false));
        assert!(states(&out).is_empty(), "{out:?}");
    }
    let unreachable = |transport, a| Input::SendFailed { transport, addr: a };
    let out = at(&mut n, &mut log, 30, unreachable(t(1), addr(1)));
    let orig = n.id(0);
    assert_eq!(
        states(&out),
        [(
            p(),
            orig,
            Some(PathState::Live),
            Some(PathState::Suspect),
            Why::Unreachable
        )]
    );
    for (transport, a) in [(t(3), addr(3)), (t(4), addr(4)), (t(1), addr(9))] {
        let out = at(&mut n, &mut log, 40, unreachable(transport, a));
        assert!(states(&out).is_empty(), "{out:?}");
    }
    assert_eq!(state(&n, &pair(t(3), addr(3))), PathState::Probing);
    assert_eq!(state(&n, &dead), PathState::Dead);
    assert_eq!(n.b.paths().active_index(), Some(0));
}

#[test]
fn a_path_close_marks_a_suspect_path_dead() {
    let mut n = Node::capable(61);
    live_path(&mut n, t(2), addr(2), 0xB);
    n.step(Input::Carrier {
        transport: t(2),
        up: false,
    });
    assert_eq!(state(&n, &q()), PathState::Suspect);
    let id = path(&n, &q()).path_id();
    let out = n.closed(t(2), addr(2), close_from(id));
    assert_eq!(
        states(&out),
        [(
            q(),
            id,
            Some(PathState::Suspect),
            Some(PathState::Dead),
            Why::Closed
        )]
    );
}

#[test]
fn a_suspect_path_of_a_peer_not_known_to_be_capable_is_never_probed() {
    let mut n = Node::new(62);
    let out = n.step(Input::Carrier {
        transport: t(1),
        up: false,
    });
    assert_eq!(
        states(&out),
        [(
            p(),
            n.id(0),
            Some(PathState::Live),
            Some(PathState::Suspect),
            Why::Carrier
        )]
    );
    assert!(probes(&out).is_empty());
    assert_eq!(n.b.next_wake(), None);
    for k in 1..=60 {
        n.now = TestInstant(k * 1_000);
        assert!(n.poll().is_empty());
    }
    assert_eq!(n.b.next_wake(), None);
    assert_eq!(state(&n, &p()), PathState::Suspect);
}

#[test]
fn the_peer_turning_active_off_prompts_a_probe_and_no_state_change() {
    // By the peer's probes.
    let mut n = two(63);
    let mut log = Log::default();
    let probe = |active| Input::Probe {
        transport: t(2),
        addr: addr(2),
        msg: marked(0xB, 1, active),
    };
    let out = at(&mut n, &mut log, 100, probe(true));
    assert!(probes(&out).is_empty());
    let out = at(&mut n, &mut log, 150, probe(false));
    probe_on(&out, &q());
    assert!(states(&out).is_empty());
    assert_eq!(state(&n, &q()), PathState::Live);
    // By the peer's answers to ours.
    let mut n = two(64);
    let mut log = Log::default();
    let out = at(&mut n, &mut log, 200, Input::Poll);
    let ours = probe_on(&out, &q());
    let reply = |probe: &PathProbe, active| Input::Ack {
        transport: t(2),
        addr: addr(2),
        msg: answer(probe, &q(), active),
    };
    let out = at(&mut n, &mut log, 200, reply(&ours, true));
    assert!(probes(&out).is_empty());
    // The peer's answers on the path carry ACTIVE, so it goes at the
    // active cadence from the first of them.
    while let Some(out) = n.tick(TestInstant(1_199)) {
        log.add(n.now, &out);
        for (to, probe) in probes(&out) {
            n.ack(
                to.transport,
                to.addr.clone(),
                answer(&probe, &to, to == q()),
            );
        }
    }
    assert_eq!(log.on(&q()), [200, 400, 600, 800, 1_000]);
    let out = at(&mut n, &mut log, 1_200, Input::Poll);
    let ours = probe_on(&out, &q());
    let out = at(&mut n, &mut log, 1_200, reply(&ours, false));
    probe_on(&out, &q());
    assert!(states(&out).is_empty());
    assert_eq!(state(&n, &q()), PathState::Live);
}

#[test]
fn an_early_probe_that_finds_the_ring_full_is_dropped_not_deferred() {
    let mut n = two(65);
    let mut log = Log::default();
    let reply = |probe: &PathProbe| Input::Ack {
        transport: t(1),
        addr: addr(1),
        msg: ack_for(probe, 0xA),
    };
    let standby = &mut |_: u64, to: &PathRef| *to == q();
    // A round trip of 600 ms, from a late answer: the probe at 200 ms times
    // out at 600 ms without counting, since the one at 400 ms was answered.
    n.now = TestInstant(200);
    let out = n.poll();
    let slow = probe_on(&out, &p());
    handle(&mut n, &mut log, out, standby);
    for ms in [400, 600] {
        let out = at(&mut n, &mut log, ms, Input::Poll);
        let probe = probe_on(&out, &p());
        at(&mut n, &mut log, ms, reply(&probe));
    }
    let out = at(&mut n, &mut log, 800, reply(&slow));
    let first = probe_on(&out, &p());
    assert_eq!(
        path(&n, &p()).live().rtt(),
        Some(Duration::from_millis(600))
    );
    assert_eq!(path(&n, &p()).live().misses(), 0);
    // The timeout is 1.8 s: eight probes are in flight by 2.2 s.
    run(&mut n, &mut log, 2_299, standby);
    assert_eq!(path(&n, &p()).live().outstanding(), 8);
    // The probe due at 2.4 s has no room: the next wake is the first
    // probe's timeout.
    assert_eq!(n.b.next_wake(), Some(TestInstant(2_600)));
    // The peer turns ACTIVE off on the path: no room for the early probe.
    let probe = |active| Input::Probe {
        transport: t(1),
        addr: addr(1),
        msg: marked(0xA, 1, active),
    };
    at(&mut n, &mut log, 2_250, probe(true));
    let out = at(&mut n, &mut log, 2_300, probe(false));
    assert!(probes(&out).is_empty(), "{out:?}");
    // An answer frees a slot before the next probe is due: nothing goes
    // until the cadence says so.
    let out = at(&mut n, &mut log, 2_350, reply(&first));
    assert!(probes(&out).is_empty(), "{out:?}");
    assert_eq!(n.b.next_wake(), Some(TestInstant(2_400)));
    let out = n.tick(TestInstant(2_400)).expect("a wake at 2.4 s");
    probe_on(&out, &p());
}

#[test]
fn timeouts_while_suspect_charge_the_etx_nothing() {
    let mut n = two(66);
    let mut log = Log::default();
    run(&mut n, &mut log, 999, &mut all);
    assert_eq!(path(&n, &q()).live().etx(), 1.0);
    run(&mut n, &mut log, 3_600, &mut |_, to| *to != q());
    assert_eq!(state(&n, &q()), PathState::Suspect);
    let etx = path(&n, &q()).live().etx();
    assert!(etx > 1.0, "three timeouts while Live: etx {etx}");
    run(&mut n, &mut log, 12_000, &mut |_, to| *to != q());
    assert_eq!(state(&n, &q()), PathState::Suspect);
    assert_eq!(path(&n, &q()).live().etx(), etx);
}

#[test]
fn the_next_wake_is_the_earliest_deadline_or_due_probe() {
    let mut n = Node::capable(67);
    let mut log = Log::default();
    // The original closed by the peer: Dead, still active, its first Dead
    // probe due at 1 s.
    let orig = n.id(0);
    at(
        &mut n,
        &mut log,
        0,
        Input::Close {
            transport: t(1),
            addr: addr(1),
            msg: close_from(orig),
        },
    );
    // A candidate's first probe goes at once and is unanswered at 400 ms;
    // its next is due at 200 ms but waits for it.
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
    assert_eq!(path(&n, &q()).live().next_at(), Some(TestInstant(200)));
    assert_eq!(n.b.next_wake(), Some(TestInstant(400)));
    // At 400 ms it goes again, unanswered at 800 ms, the next due at 800 ms.
    n.tick(TestInstant(400)).expect("a wake at 400 ms");
    assert_eq!(n.b.next_wake(), Some(TestInstant(800)));
    // At 800 ms the next is due at 1.6 s and unanswered at 1.2 s; the
    // original's next Dead probe, due at 1 s, comes first. Its probe at 0,
    // padded, has gone unanswered, so this one steps down the ladder, to
    // three quarters of the padded size.
    n.tick(TestInstant(800)).expect("a wake at 800 ms");
    assert_eq!(n.b.next_wake(), Some(TestInstant(1_000)));
    let out = n.tick(TestInstant(1_000)).expect("a wake at 1 s");
    assert_eq!(probe_on(&out, &p()).len, PADDED * 3 / 4);
}

#[test]
fn no_probe_exceeds_the_paths_link_mtu() {
    let facts = Stub::default().mtu(t(2), 1000);
    let mut n = Node::capable(68).with(facts);
    let mut log = Log::default();
    let r = pair(t(3), addr(3));
    live_path(&mut n, t(3), addr(3), 0xC);
    let id = path(&n, &r).path_id();
    at(
        &mut n,
        &mut log,
        0,
        Input::Close {
            transport: t(3),
            addr: addr(3),
            msg: close_from(id),
        },
    );
    let out = n.candidate(t(2), addr(2));
    handle(&mut n, &mut log, out, &mut |_, to| *to == p());
    let out = n.probe(t(2), addr(5), probe_from(0xE, 1, 1200));
    handle(&mut n, &mut log, out, &mut |_, to| *to == p());
    run(&mut n, &mut log, 60_000, &mut |_, to| *to == p());
    let on = |to: &PathRef| -> Vec<usize> {
        log.probes
            .iter()
            .filter(|(_, p, _)| p == to)
            .map(|(_, _, probe)| probe.len)
            .collect()
    };
    for to in [q(), pair(t(2), addr(5))] {
        let lens = on(&to);
        assert_eq!(lens, ladder(8, 1000 - FRAME_OVERHEAD));
    }
    let dead = on(&r);
    assert!(dead.len() >= 6);
    assert_eq!(dead, ladder(dead.len(), PADDED));
}

/// Drive the candidate q of a capable node `seed` while its probes go
/// unanswered and the peer's probes on q arrive every `every` ms, the
/// `k`-th with `ACTIVE` set where `active(k)` says so, until q is no
/// longer Probing or 40 s pass. Returns the instants of the probes on q up
/// to the instant it became Dead.
fn probing_under_peer_probes(seed: u64, every: u64, active: fn(u32) -> bool) -> Vec<u64> {
    let mut n = Node::capable(seed);
    let mut log = Log::default();
    let out = n.candidate(t(2), addr(2));
    handle(&mut n, &mut log, out, &mut |_, to| *to != q());
    assert_eq!(
        state(&n, &q()),
        PathState::Probing,
        "precondition: q Probing"
    );
    let mut k = 0u32;
    let mut ms = 0u64;
    while ms < 40_000 && state(&n, &q()) == PathState::Probing {
        ms += every;
        run(&mut n, &mut log, ms, &mut |_, to| *to != q());
        if state(&n, &q()) != PathState::Probing {
            break;
        }
        k += 1;
        n.now = TestInstant(ms);
        let out = n.step(Input::Probe {
            transport: t(2),
            addr: addr(2),
            msg: marked(0xB, k, active(k)),
        });
        handle(&mut n, &mut log, out, &mut |_, to| *to != q());
    }
    let dead = log
        .changes(&q())
        .iter()
        .find(|c| c.2 == Some(PathState::Dead))
        .map(|c| c.0)
        .expect("precondition: q went Dead");
    log.on(&q()).into_iter().filter(|at| *at <= dead).collect()
}

#[test]
fn a_probing_path_sends_no_more_than_eight_probes_when_the_peers_active_flag_clears() {
    // Section 5.6, the Probing rows, and Appendix A: a Probing path sends
    // at most MAX_DISCOVERY_PROBES (8) probes and becomes Dead when they
    // go unanswered, the early probe on the peer clearing ACTIVE counted
    // among them. Here the flag changes every 150 ms.
    let sent = probing_under_peer_probes(70, 150, |k| k % 2 == 1);
    assert!(
        sent.len() <= 8,
        "{} probes on q while Probing: {sent:?}",
        sent.len()
    );
}

#[test]
fn a_probing_path_sends_no_more_than_eight_probes_when_the_flag_clears_every_40_ms() {
    // As above, with the flag set and cleared every 40 ms.
    let sent = probing_under_peer_probes(70, 20, |k| k % 2 == 1);
    assert!(
        sent.len() <= 8,
        "{} probes on q while Probing: {sent:?}",
        sent.len()
    );
}

#[test]
fn a_probing_path_whose_peer_never_sets_active_sends_eight_probes() {
    // The healthy case beside the two above: with the peer's probes always
    // clear of ACTIVE, the Probing path sends all eight (Section 5.6).
    let sent = probing_under_peer_probes(70, 150, |_| false);
    assert_eq!(sent.len(), 8, "{sent:?}");
}

#[test]
fn a_probe_asked_for_at_once_after_eight_sent_on_a_probing_path_is_dropped() {
    // q, Probing and unanswered, has sent its eighth probe, the last
    // MAX_DISCOVERY_PROBES allows (Section 5.6, Appendix A). The peer then
    // sets and clears ACTIVE on q, which asks for a probe at once: none
    // goes, and q becomes Dead when the eighth times out.
    let mut n = Node::capable(72);
    let mut log = Log::default();
    let out = n.candidate(t(2), addr(2));
    handle(&mut n, &mut log, out, &mut |_, to| *to != q());
    while log.on(&q()).len() < 8 {
        let out = n.tick(TestInstant(40_000)).expect("a wake");
        handle(&mut n, &mut log, out, &mut |_, to| *to != q());
    }
    assert_eq!(
        state(&n, &q()),
        PathState::Probing,
        "precondition: q Probing"
    );
    assert_eq!(
        path(&n, &q()).live().misses(),
        7,
        "precondition: seven missed"
    );
    assert_eq!(
        path(&n, &q()).live().outstanding(),
        1,
        "precondition: one out"
    );
    let eighth = *log.on(&q()).last().unwrap();
    for (dt, k, active) in [(10, 1, true), (20, 2, false)] {
        n.now = TestInstant(eighth + dt);
        let out = n.step(Input::Probe {
            transport: t(2),
            addr: addr(2),
            msg: marked(0xB, k, active),
        });
        handle(&mut n, &mut log, out, &mut |_, to| *to != q());
    }
    run(&mut n, &mut log, 60_000, &mut |_, to| *to != q());
    let dead = log
        .changes(&q())
        .iter()
        .find(|c| c.2 == Some(PathState::Dead))
        .cloned()
        .expect("q went Dead");
    assert_eq!(dead.3, Why::Exhausted, "{dead:?}");
    let sent: Vec<u64> = log
        .on(&q())
        .into_iter()
        .filter(|at| *at <= dead.0)
        .collect();
    assert_eq!(sent.len(), 8, "a ninth probe went on q: {sent:?}");
}

/// How a Dead path is brought back to Probing in [`revived_count`].
#[derive(Clone, Copy, Debug)]
enum Revival {
    /// Its transport loses carrier and regains it.
    Carrier,
    /// The peer's probe arrives on it and is accepted.
    Probe,
}

/// q, acked and Live, goes unanswered until it is Dead, and on into its
/// Dead cadence until a Dead-cadence probe is outstanding; 100 ms later,
/// with that probe still outstanding, it is brought back by `how`. Returns
/// the node, its log, the instant q went Dead, the probe outstanding at
/// the revival and the revival's instant.
fn revived(seed: u64, how: Revival) -> (Node, Log, u64, PathProbe, u64) {
    let mut n = two(seed);
    let mut log = Log::default();
    let only_p = &mut |_: u64, to: &PathRef| *to != q();
    run(&mut n, &mut log, 999, &mut all);
    // Unanswered from 1 s: Suspect, then Dead after the retire count.
    while state(&n, &q()) != PathState::Dead {
        let out = n.tick(TestInstant(60_000)).expect("q goes Dead");
        handle(&mut n, &mut log, out, only_p);
    }
    let dead = log.changes(&q()).last().expect("q went Dead").0;
    assert_eq!(
        log.changes(&q()).last().map(|c| (c.2, c.3)),
        Some((Some(PathState::Dead), Why::Retired)),
        "precondition: q retired from Suspect"
    );
    assert!(path(&n, &q()).acked(), "precondition: q acked");
    // On to the first probe of the Dead cadence, then 100 ms more.
    let before = log.on(&q()).len();
    let mut old = None;
    while log.on(&q()).len() == before {
        let out = n.tick(TestInstant(120_000)).expect("q's Dead cadence");
        old = probes(&out).into_iter().find(|(to, _)| *to == q());
        handle(&mut n, &mut log, out, only_p);
    }
    let (_, old) = old.expect("the Dead-cadence probe");
    let last = *log.on(&q()).last().expect("a Dead-cadence probe");
    assert!(last > dead, "precondition: a probe of the Dead cadence");
    let revival = last + 100;
    run(&mut n, &mut log, revival - 1, only_p);
    assert_eq!(state(&n, &q()), PathState::Dead, "precondition: q Dead");
    assert_eq!(
        path(&n, &q()).live().outstanding(),
        1,
        "precondition: q's Dead-cadence probe outstanding at the revival"
    );
    assert_eq!(
        log.on(&q()).last(),
        Some(&last),
        "precondition: no probe on q since"
    );
    let out = match how {
        Revival::Carrier => {
            let lost = step(&mut n, revival, down(2));
            handle(&mut n, &mut log, lost, only_p);
            assert_eq!(state(&n, &q()), PathState::Dead, "still Dead");
            step(
                &mut n,
                revival,
                Input::Carrier {
                    transport: t(2),
                    up: true,
                },
            )
        }
        Revival::Probe => step(
            &mut n,
            revival,
            Input::Probe {
                transport: t(2),
                addr: addr(2),
                msg: probe_from(peer(&q()), 1, PATH_PROBE_MIN_SIZE),
            },
        ),
    };
    let why = match how {
        Revival::Carrier => Why::Returned,
        Revival::Probe => Why::Probed,
    };
    let [(_, _, Some(PathState::Dead), Some(PathState::Probing), w)] = states(&out)[..] else {
        panic!("precondition: q revived: {out:?}");
    };
    assert_eq!(w, why, "precondition: revived by {how:?}");
    handle(&mut n, &mut log, out, only_p);
    (n, log, dead, old, revival)
}

/// q brought back by `how` as [`revived`] describes, and every probe on it
/// from then on unanswered. Returns the instants of the probes q sends
/// from the revival until it is Dead again, and the revival's instant.
/// Brought back by carrier, q keeps the stop it took on entering Dead, so
/// every probe it sends from then on is checked against the floor; the
/// peer's probe ends the stop.
fn revived_count(seed: u64, how: Revival) -> (Vec<u64>, u64) {
    let (mut n, mut log, dead, _, revival) = revived(seed, how);
    let only_p = &mut |_: u64, to: &PathRef| *to != q();
    run(&mut n, &mut log, revival + 300_000, only_p);
    let again = log
        .changes(&q())
        .into_iter()
        .find(|c| c.0 >= revival && c.2 == Some(PathState::Dead))
        .expect("q Dead again");
    assert_eq!(
        (again.1, again.3),
        (Some(PathState::Probing), Why::Exhausted),
        "Dead again by the discovery limit: {again:?}"
    );
    let probing: Vec<u64> = log
        .on(&q())
        .into_iter()
        .filter(|at| (revival..=again.0).contains(at))
        .collect();
    let held: Vec<u64> = log
        .on(&q())
        .into_iter()
        .filter(|at| (dead..=again.0).contains(at))
        .collect();
    if let Revival::Carrier = how
        && let Some(e) = floor_breaks(dead, &held)
    {
        panic!("{e}");
    }
    (probing, revival)
}

#[test]
fn a_path_revived_from_dead_by_carrier_sends_eight_probes_while_probing_whatever_was_outstanding_when_it_left_dead()
 {
    // Section 5.6: a path leaving Dead "MUST start with no unanswered
    // probes counted toward MAX_DISCOVERY_PROBES", and the discovery limit
    // counts the probes sent while Probing "from when it last became
    // Probing". So a path brought back by carrier, with a probe of its
    // Dead cadence still outstanding, sends eight probes before it is
    // given up again. Brought back by carrier it keeps its stop, so the
    // floor holds those probes, from the stop q took on entering Dead
    // (checked from the log, not assumed).
    let (probing, _) = revived_count(73, Revival::Carrier);
    assert_eq!(probing.len(), 8, "probes while Probing: {probing:?}");
}

#[test]
fn a_path_revived_from_dead_by_the_peers_probe_sends_eight_probes_while_probing_whatever_was_outstanding_when_it_left_dead()
 {
    // As above, brought back by the peer's accepted probe, which ends the
    // stop and is answered by a probe at once.
    let (probing, revival) = revived_count(74, Revival::Probe);
    assert_eq!(probing.first(), Some(&revival), "a probe at once");
    assert_eq!(probing.len(), 8, "probes while Probing: {probing:?}");
}

#[test]
fn a_probe_outstanding_when_a_path_leaves_dead_is_still_matched_by_an_answer_in_time_and_not_by_a_late_one()
 {
    // Section 5.6: a path leaving Dead counts no unanswered probe toward
    // its limits, and a probe is unanswered only once its timeout passes
    // with no matching answer. So the probe of q's Dead cadence that is
    // outstanding when carrier brings q back is not given up: its answer
    // before its timeout (400 ms, at a round trip of 0) is a matching one
    // and makes q Live, and an answer after it is late, a round trip and
    // nothing else, leaving q Probing. Giving the probe up at the revival
    // would lose the first.
    for (wait, live) in [(50, true), (450, false)] {
        let (mut n, mut log, _, old, revival) = revived(75, Revival::Carrier);
        let only_p = &mut |_: u64, to: &PathRef| *to != q();
        run(&mut n, &mut log, revival + wait - 1, only_p);
        assert_eq!(state(&n, &q()), PathState::Probing, "precondition");
        let out = step(
            &mut n,
            revival + wait,
            Input::Ack {
                transport: t(2),
                addr: addr(2),
                msg: ack_for(&old, peer(&q())),
            },
        );
        let became = states(&out)
            .into_iter()
            .find(|c| c.0 == q())
            .map(|c| (c.2, c.3, c.4));
        // Either way the answer pairs with the probe and gives its round
        // trip, from 100 ms before the revival.
        assert_eq!(
            path(&n, &q()).live().rtt(),
            Some(Duration::from_millis(wait + 100)),
            "the old probe's round trip"
        );
        if live {
            assert_eq!(
                became,
                Some((
                    Some(PathState::Probing),
                    Some(PathState::Live),
                    Why::Answered
                )),
                "an answer {wait} ms after the revival matches"
            );
        } else {
            assert_eq!(became, None, "an answer {wait} ms after is late");
            assert_eq!(state(&n, &q()), PathState::Probing);
        }
    }
}
