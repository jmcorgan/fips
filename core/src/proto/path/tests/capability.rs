//! Learning that a peer is capable (multipath v1 draft, Sections 5.2 and
//! 8.1): the capability probe on the original path, of 27 bytes; sent only
//! while a candidate allows it, three over the span and then at a gap
//! doubling to the cap, one at a time; the link reported not capable once
//! when the first round goes unanswered; an answer in time or late; and
//! the original path's liveness untouched. Every test drives a `Bundle`
//! in the shell, which also checks after every call that nothing but
//! capability probes leaves a node before its peer is capable, at the
//! schedule's spacing and only while a candidate allows them.

use alloc::vec::Vec;

use super::shell::*;
use crate::proto::link::LinkMessageType;
use crate::proto::path::wire::{PATH_PROBE_MIN_SIZE, PathCaps, PathProbe};
use crate::proto::path::{Config, Input, Output, Params, PathRef, PathState, Role, Source, Why};
use crate::testutil::TestInstant;
use crate::time::Duration;

/// The type byte of a heartbeat.
const HEARTBEAT: u8 = 0x51;

/// Never answer a probe.
fn none(_: u64, _: &PathRef) -> bool {
    false
}

/// The capability probes `log` holds, on the original path, with their
/// instants in milliseconds.
fn asked(log: &Log) -> Vec<(u64, PathProbe)> {
    log.probes
        .iter()
        .filter(|(_, to, _)| *to == p())
        .map(|(at, _, probe)| (*at, *probe))
        .collect()
}

/// How often `out` reports the link not capable.
fn told(out: &[Out]) -> usize {
    out.iter()
        .filter(|o| matches!(o, Output::NotCapable))
        .count()
}

/// A node whose peer is not known to be capable, holding the candidate
/// `q()` since instant 0, with its first capability probe sent then and
/// returned.
fn asking(seed: u64) -> (Node, PathProbe) {
    let mut n = Node::new(seed);
    let out = n.candidate(t(2), addr(2));
    let probe = probe_on(&out, &p());
    (n, probe)
}

#[test]
fn a_capability_probe_is_27_bytes_on_the_original_path() {
    let mut n = Node::new(301);
    let out = n.candidate(t(2), addr(2));
    let [Output::Send { to, bytes }] = &out[..] else {
        panic!("one send: {out:?}");
    };
    assert_eq!(to, &p());
    assert_eq!(bytes.len(), PATH_PROBE_MIN_SIZE);
    let probe = probe_on(&out, &p());
    assert_eq!(probe.len, PATH_PROBE_MIN_SIZE);
    assert_eq!(probe.path_id, n.id(0), "the original path's identifier");
    assert!(probe.flags.active());
    assert_eq!(probe.caps, PathCaps::default());
    assert_eq!(n.b.capability().sent(), 1);
    assert_eq!(n.b.paths().len(), 1, "no path admitted");
}

#[test]
fn no_capability_probe_goes_and_nothing_wakes_while_no_candidate_is_held() {
    let mut n = Node::new(302);
    assert_eq!(n.b.next_wake(), None);
    // Two simulated hours of polls and of the peer's heartbeats.
    for s in (1..=7_200).step_by(10) {
        n.now = TestInstant(s * 1_000);
        n.account(t(1), &addr(1), 100, HEARTBEAT);
        let out = n.poll();
        assert!(out.is_empty(), "{out:?}");
        assert_eq!(n.b.next_wake(), None);
    }
    assert_eq!(n.b.capability().sent(), 0);
}

#[test]
fn candidates_the_rules_refuse_or_that_are_held_back_start_no_capability_probe() {
    let facts = Stub::default()
        .fact(t(3), Fact::Class(crate::proto::path::Class::Tor))
        .fact(t(2), Fact::Dials(false));
    let mut n = Node::new(303).with(facts);
    // A Tor candidate on a clear link, and one on a transport not dialled.
    assert!(n.candidate(t(3), addr(3)).is_empty());
    assert!(n.candidate(t(2), addr(2)).is_empty());
    // Transport 2's interface leaves: its candidate is held back, and the
    // dial fact no longer stops it.
    let left = Input::Present {
        transport: t(2),
        present: false,
    };
    assert!(step(&mut n, 1_000, left).is_empty());
    n.facts.change(t(2), Fact::Dials(true));
    for s in 2..=600 {
        let out = step(&mut n, s * 1_000, Input::Poll);
        assert!(out.is_empty(), "{out:?}");
    }
    assert_eq!(n.b.next_wake(), None);
    // Its return releases the candidate, which opens the gate.
    let back = Input::Present {
        transport: t(2),
        present: true,
    };
    let out = step(&mut n, 601_000, back);
    probe_on(&out, &p());
    assert_eq!(n.b.capability().sent(), 1);
}

#[test]
fn capability_probing_stops_when_the_last_candidate_is_unlisted_and_resumes_where_it_stopped() {
    let (mut n, _) = asking(304);
    let mut log = Log::default();
    run(&mut n, &mut log, 15_000, &mut none);
    let two: Vec<u64> = asked(&log).iter().map(|(at, _)| *at).collect();
    assert_eq!(two, [10_000], "the second, at 10 s");
    n.now = TestInstant(15_000);
    assert!(n.unlist(t(2), addr(2), Source::Config).is_empty());
    assert_eq!(n.b.next_wake(), None);
    // An hour of silence.
    let mut quiet = Log::default();
    run(&mut n, &mut quiet, 3_615_000, &mut none);
    assert!(quiet.probes.is_empty());
    // Reported again: the third goes at once, the fourth 30 s later.
    n.now = TestInstant(3_615_000);
    let out = n.candidate(t(2), addr(2));
    probe_on(&out, &p());
    let mut log = Log::default();
    run(&mut n, &mut log, 3_700_000, &mut none);
    let next: Vec<u64> = asked(&log).iter().map(|(at, _)| *at).collect();
    assert_eq!(next, [3_645_000], "the fourth 30 s after the third");
    assert_eq!(n.b.capability().sent(), 4);
}

#[test]
fn a_change_in_the_facts_takes_effect_at_the_next_gate_and_admission() {
    let (mut n, _) = asking(305);
    let mut log = Log::default();
    // The first probe times out; then transport 2's role becomes never.
    run(&mut n, &mut log, 500, &mut none);
    n.facts.change(t(2), Fact::Role(Role::Never));
    let wake = n.b.next_wake().expect("the next probe's time");
    assert_eq!(wake, TestInstant(10_000));
    n.now = wake;
    let out = n.poll();
    assert!(out.is_empty(), "the gate is read again: {out:?}");
    assert_eq!(n.b.next_wake(), None);
    // Back to normal, and the candidate reported afresh: the next goes.
    n.facts.change(t(2), Fact::Role(Role::Normal));
    n.now = TestInstant(20_000);
    let out = n.report(t(2), addr(2), Source::Request);
    probe_on(&out, &p());
    assert_eq!(n.b.capability().sent(), 2);

    // Once the peer is capable, the same for admission.
    n.facts.change(t(2), Fact::Role(Role::Never));
    n.now = TestInstant(20_100);
    let out = n.heard();
    assert!(states(&out).is_empty(), "{out:?}");
    assert_eq!(n.b.paths().len(), 1);
    n.facts.change(t(2), Fact::Role(Role::Normal));
    n.now = TestInstant(20_200);
    let out = n.report(t(2), addr(2), Source::Request);
    let admitted: Vec<Why> = states(&out).into_iter().map(|c| c.4).collect();
    assert_eq!(admitted, [Why::Candidate]);
    probe_on(&out, &q());
}

#[test]
fn a_roam_off_a_candidates_pair_wakes_the_capability_probe() {
    let mut n = Node::new(306);
    // A configured candidate at the original pair is a path already.
    assert!(n.candidate(t(1), addr(1)).is_empty());
    assert_eq!(n.b.next_wake(), None);
    // The original path roams elsewhere, which frees the candidate's pair.
    n.now = TestInstant(5_000);
    n.account(t(1), &addr(7), 100, HEARTBEAT);
    let roamed = pair(t(1), addr(7));
    assert_eq!(n.b.paths().find(t(1), &addr(7)), Some(0));
    let wake = n.b.next_wake().expect("a wake for the capability probe");
    assert!(wake <= n.now);
    let out = n.poll();
    probe_on(&out, &roamed);
    assert_eq!(n.b.capability().sent(), 1);
}

#[test]
fn three_probes_over_thirty_seconds_then_a_gap_doubling_to_ten_minutes() {
    let (mut n, _) = asking(307);
    let mut log = Log::default();
    run(&mut n, &mut log, 7_200_000, &mut none);
    let mut at: Vec<u64> = asked(&log).iter().map(|(ms, _)| ms / 1_000).collect();
    at.insert(0, 0);
    assert_eq!(
        at,
        [
            0, 10, 20, 50, 110, 230, 470, 950, 1_550, 2_150, 2_750, 3_350, 3_950, 4_550, 5_150,
            5_750, 6_350, 6_950
        ]
    );
    assert_eq!(at.iter().filter(|s| **s < 3_600).count(), 12);
    assert_eq!(at.iter().filter(|s| **s >= 3_600).count(), 6);
    assert_eq!(n.b.paths().len(), 1);
    assert!(!n.b.capable());
}

#[test]
fn an_unanswered_first_round_reports_the_link_not_capable_once() {
    let (mut n, _) = asking(308);
    let mut reports = Vec::new();
    while let Some(out) = n.tick(TestInstant(7_200_000)) {
        if told(&out) > 0 {
            reports.push((n.now.0, told(&out)));
        }
    }
    assert_eq!(reports, [(20_400, 1)]);
    assert!(n.b.capability().told());
    assert!(!n.b.capable());
}

#[test]
fn a_matching_answer_makes_the_peer_capable_learns_its_id_and_round_trip_and_probes_candidates() {
    let (mut n, probe) = asking(309);
    n.now = TestInstant(30);
    let out = n.ack(t(1), addr(1), ack_for(&probe, 0xA));
    assert!(matches!(out.first(), Some(Output::Capable)), "{out:?}");
    assert!(n.b.capable());
    assert!(refusals(&out).is_empty(), "{out:?}");
    let admitted: Vec<(PathRef, Why)> = states(&out).into_iter().map(|c| (c.0, c.4)).collect();
    assert_eq!(admitted, [(q(), Why::Candidate)]);
    probe_on(&out, &q());
    let original = path(&n, &p());
    assert_eq!(original.peer_id(), Some(0xA), "the peer's id learned");
    assert_eq!(original.live().rtt(), Some(Duration::from_millis(30)));
    assert_eq!(original.live().samples(), 1);
    assert_eq!(original.live().mtu(), None, "a 27-byte probe proves no MTU");
    assert_eq!(original.state(), PathState::Live);
}

#[test]
fn a_late_answer_makes_the_peer_capable_and_gives_only_a_round_trip_sample() {
    let (mut n, _) = asking(310);
    let mut log = Log::default();
    run(&mut n, &mut log, 20_000, &mut none);
    let third = asked(&log).last().expect("the third probe").1;
    // Its timeout passes: the link is reported not capable.
    n.now = TestInstant(20_400);
    let out = n.poll();
    assert_eq!(told(&out), 1, "{out:?}");
    // Its answer comes late.
    n.now = TestInstant(20_500);
    let out = n.ack(t(1), addr(1), ack_for(&third, 0xA));
    assert!(matches!(out.first(), Some(Output::Capable)), "{out:?}");
    assert!(refusals(&out).is_empty(), "{out:?}");
    assert!(
        states(&out).iter().all(|c| c.0 != p()),
        "no change to the original path: {out:?}"
    );
    let original = path(&n, &p());
    assert_eq!(original.peer_id(), None, "no id learned from a late answer");
    assert_eq!(original.live().rtt(), Some(Duration::from_millis(500)));
    assert_eq!(original.state(), PathState::Live);
}

#[test]
fn a_peer_turning_capable_with_a_capability_probe_outstanding_is_never_reported_not_capable() {
    let (mut n, _) = asking(311);
    let mut log = Log::default();
    run(&mut n, &mut log, 20_000, &mut none);
    let third = asked(&log).last().expect("the third probe").1;
    // The peer's probe arrives with the third outstanding.
    n.now = TestInstant(20_100);
    let out = n.probe(t(1), addr(1), probe_from(0xA, 1, 27));
    assert!(matches!(out.first(), Some(Output::Capable)), "{out:?}");
    // Past the third's timeout, nothing reports the link not capable.
    let mut after = Log::default();
    let answers = &mut |_: u64, to: &PathRef| *to == p();
    run(&mut n, &mut after, 25_000, answers);
    assert!(n.b.capable());
    // The third's answer gives a round trip and nothing else.
    n.now = TestInstant(25_000);
    let before = n.b.paths().len();
    let out = n.ack(t(1), addr(1), ack_for(&third, 0xA));
    assert!(refusals(&out).is_empty(), "{out:?}");
    assert!(states(&out).iter().all(|c| c.0 != p()), "{out:?}");
    assert_eq!(
        path(&n, &p()).live().rtt(),
        Some(Duration::from_millis(5_000))
    );
    assert_eq!(n.b.paths().len(), before);
}

#[test]
fn unanswered_capability_probes_leave_the_original_path_live() {
    let (mut n, _) = asking(312);
    let mut log = Log::default();
    run(&mut n, &mut log, 115_000, &mut none);
    assert_eq!(n.b.capability().sent(), 5);
    let original = path(&n, &p());
    assert_eq!(original.state(), PathState::Live);
    assert_eq!(original.live().misses(), 0);
    assert_eq!(original.live().outstanding(), 0);
    assert!(log.states.is_empty(), "{:?}", log.states);
}

#[test]
fn capability_probes_go_one_at_a_time() {
    let cfg = Config {
        span: Duration::from_millis(900),
        ..Config::draft()
    };
    let params = Params::new(cfg).expect("valid");
    let mut n = Node::on(313, params, Stub::default(), p());
    let out = n.candidate(t(2), addr(2));
    probe_on(&out, &p());
    // Polled every 100 ms, past each gap of 300 ms.
    let mut log = Log::default();
    for ms in (100..=2_000).step_by(100) {
        at(&mut n, &mut log, ms, Input::Poll);
    }
    let sent: Vec<u64> = asked(&log).iter().map(|(ms, _)| *ms).collect();
    assert_eq!(sent, [400, 800, 1_700], "each after the last timed out");
}

#[test]
fn once_capable_no_capability_probe_goes() {
    let mut n = Node::capable(314);
    // Transport 2 holds four paths at most: the fifth candidate on it is
    // held and refused for room, and would allow a capability probe.
    for k in 2..=5 {
        n.candidate(t(2), addr(k));
    }
    let out = n.candidate(t(2), addr(6));
    assert_eq!(refusals(&out).len(), 1, "{out:?}");
    let mut log = Log::default();
    run(&mut n, &mut log, 120_000, &mut all);
    assert_eq!(n.b.capability().sent(), 0);
    assert_eq!(n.b.capability().next_at(), None);
}

#[test]
fn a_new_link_starts_a_new_first_round() {
    let (mut n, _) = asking(315);
    let mut log = Log::default();
    run(&mut n, &mut log, 15_000, &mut none);
    assert_eq!(n.b.capability().sent(), 2);
    n.close();
    // A new link to the same peer, on the same pair.
    let (mut m, _) = asking(315);
    let mut log = Log::default();
    run(&mut m, &mut log, 29_999, &mut none);
    let at: Vec<u64> = asked(&log).iter().map(|(ms, _)| *ms).collect();
    assert_eq!(at, [10_000, 20_000], "three in its first 30 s");
}

#[test]
fn an_answer_after_its_timeout_with_no_poll_between_is_late() {
    // The probe sent at 0 goes unanswered at 400 ms; its answer comes at
    // 1 s with no poll between.
    let (mut n, probe) = asking(320);
    n.now = TestInstant(1_000);
    let out = n.ack(t(1), addr(1), ack_for(&probe, 0xA));
    assert!(matches!(out.first(), Some(Output::Capable)), "{out:?}");
    assert!(refusals(&out).is_empty(), "{out:?}");
    let original = path(&n, &p());
    assert_eq!(original.peer_id(), None, "no id learned from a late answer");
    assert_eq!(original.live().rtt(), Some(Duration::from_millis(1_000)));
}

#[test]
fn capability_probes_take_consecutive_ids_of_the_original_paths_sequence() {
    let (mut n, first) = asking(321);
    let mut log = Log::default();
    run(&mut n, &mut log, 60_000, &mut none);
    let ids: Vec<u32> = asked(&log)
        .iter()
        .map(|(_, probe)| probe.probe_id)
        .collect();
    assert!(ids.len() >= 3, "{ids:?}");
    let mut want = first.probe_id;
    for id in ids {
        want = want.wrapping_add(1);
        assert_eq!(id, want, "the next of the original path's sequence");
    }
}

#[test]
fn a_capability_answer_from_a_new_address_moves_the_original_and_counts_there() {
    // Transport 1 takes the kind of the peer's address, so the rules would
    // refuse any other path a move to an Internet address.
    let facts = Stub::default().fact(t(1), Fact::Kind(None));
    let mut n = Node::new(322).with(facts);
    let out = n.candidate(t(2), addr(2));
    let probe = probe_on(&out, &p());
    n.now = TestInstant(100);
    let far = public(9);
    n.account(t(1), &far, 60, LinkMessageType::PathAck.to_byte());
    let out = n.ack(t(1), far.clone(), ack_for(&probe, 0xA));
    assert!(refusals(&out).is_empty(), "{out:?}");
    assert_eq!(moved(&out).len(), 1, "{out:?}");
    let original = path(&n, &pair(t(1), far));
    assert_eq!(original.peer_id(), Some(0xA));
    assert_eq!(
        original.live().frames(),
        1,
        "the answer counts on the original"
    );
}

#[test]
fn a_capability_answer_in_time_makes_a_suspect_original_live() {
    let (mut n, probe) = asking(323);
    step(&mut n, 100, down(1));
    assert_eq!(state(&n, &p()), PathState::Suspect);
    n.now = TestInstant(200);
    let out = n.ack(t(1), addr(1), ack_for(&probe, 0xA));
    assert!(matches!(out.first(), Some(Output::Capable)), "{out:?}");
    assert_eq!(state(&n, &p()), PathState::Live);
}

#[test]
fn a_candidate_unlisted_while_held_back_starts_no_capability_probe_after_its_return() {
    // Its source drops it while its interface is away; the interface's
    // return then leaves no candidate any source lists.
    let mut n = Node::new(324);
    n.candidate(t(2), addr(2));
    let presence = |present| Input::Present {
        transport: t(2),
        present,
    };
    step(&mut n, 1_000, presence(false));
    let unlisted = Input::Unlisted {
        transport: t(2),
        addr: addr(2),
        source: Source::Config,
    };
    step(&mut n, 2_000, unlisted);
    step(&mut n, 3_000, presence(true));
    let mut log = Log::default();
    run(&mut n, &mut log, 3_600_000, &mut none);
    assert!(asked(&log).is_empty(), "{:?}", asked(&log));
    assert_eq!(n.b.next_wake(), None);
}
