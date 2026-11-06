//! Tests of `live.rs`: the probe ring, the round-trip window, the ETX
//! fold and the receive counts.

use super::*;
use crate::testutil::TestInstant;
use alloc::vec::Vec;

/// The instant `ms` milliseconds after the test clock's epoch.
fn at(ms: u64) -> TestInstant {
    TestInstant(ms)
}

/// The `probe_id`s outstanding, in ring order.
fn ring(l: &Liveness<TestInstant>) -> Vec<Option<u32>> {
    l.ring.iter().map(|s| s.map(|s| s.probe_id)).collect()
}

#[test]
fn a_full_ring_takes_no_more_probes() {
    let mut l = Liveness::new();
    for n in 0..RING as u64 {
        assert!(
            l.send(at(n), at(n + 400), 27, || 100).is_some(),
            "probe {n} fits"
        );
    }
    assert_eq!(l.outstanding(), RING);
    assert_eq!(
        l.send(at(99), at(99 + 400), 27, || 100),
        None,
        "a ninth probe is refused"
    );
    assert_eq!(l.outstanding(), RING);
    // The refused probe used no identifier: the next one sent takes it.
    assert!(l.answer(100).is_some());
    assert_eq!(
        l.send(at(100), at(100 + 400), 27, || 100),
        Some(100 + RING as u32)
    );
}

#[test]
fn an_answer_takes_its_probe_and_keeps_the_rest_in_send_order() {
    let mut l = Liveness::new();
    for n in 0..4 {
        l.send(at(n), at(n + 400), 27, || 10);
    }
    let Some(Answer::InTime(sent)) = l.answer(11) else {
        panic!("the second probe is outstanding");
    };
    assert_eq!(sent.probe_id, 11);
    assert_eq!(sent.at, at(1));
    assert_eq!(l.answer(11), None, "an answer takes its probe once");
    l.send(at(4), at(4 + 400), 27, || 10);
    let mut expected = alloc::vec![Some(10), Some(12), Some(13), Some(14)];
    expected.resize(RING, None);
    assert_eq!(ring(&l), expected, "the ring stays packed in send order");
}

#[test]
fn the_window_keeps_the_least_round_trip_of_its_span() {
    let window = Duration::from_secs(30);
    let ms = Duration::from_millis;
    let mut l = Liveness::new();
    l.sample(at(0), ms(50), window);
    l.sample(at(1_000), ms(80), window);
    l.sample(at(2_000), ms(30), window);
    l.sample(at(3_000), ms(70), window);
    assert_eq!(l.min_rtt(), Some(ms(30)));
    assert_eq!(l.rtt(), Some(ms(70)), "the latest sample is kept apart");
    assert_eq!(l.samples(), 4);
    // At 33 s the first three samples are older than the window.
    l.sample(at(33_000), ms(90), window);
    assert_eq!(l.samples(), 2);
    assert_eq!(l.min_rtt(), Some(ms(70)));
    // A full window gives up its oldest sample.
    for n in 0..40 {
        l.sample(at(34_000 + n), ms(200 + n), window);
    }
    assert_eq!(l.samples(), SAMPLES);
    assert_eq!(l.min_rtt(), Some(ms(208)));
}

#[test]
fn delivered_probes_bring_the_etx_toward_one() {
    let mut l = Liveness::<TestInstant>::new();
    assert_eq!(l.etx(), 1.0, "a new path expects every probe through");
    l.etx = 4.0;
    l.fold(true);
    // The delivery ratio 1/4 moves 1/32 of the way to 1.
    let ratio = 0.25 + (1.0 - 0.25) / 32.0;
    assert!((l.etx() - 1.0 / ratio).abs() < 1e-9, "etx {}", l.etx());
    let mut last = l.etx();
    for _ in 0..200 {
        l.fold(true);
        assert!(l.etx() < last || l.etx() == 1.0);
        last = l.etx();
    }
    assert!(l.etx() < 1.01, "etx {} after 200 deliveries", l.etx());
}

#[test]
fn the_receive_counts_wrap_modulo_2_32_and_note_the_latest_frame() {
    let mut l = Liveness::new();
    l.heard(100, at(5));
    assert_eq!((l.frames(), l.bytes(), l.heard_at()), (1, 100, Some(at(5))));
    l.frames = u32::MAX;
    l.bytes = u32::MAX - 10;
    l.heard(20, at(9));
    assert_eq!((l.frames(), l.bytes(), l.heard_at()), (0, 9, Some(at(9))));
}

/// A run of authentication failures longer than a `u32` counts stays at
/// its largest value rather than wrapping to zero, which would read as a
/// fresh path.
#[test]
fn a_paths_failure_count_saturates() {
    let mut l: Liveness<TestInstant> = Liveness::new();
    l.fails = u32::MAX - 1;
    assert_eq!(l.fail(), u32::MAX);
    assert_eq!(l.fail(), u32::MAX);
    assert_eq!(l.fails(), u32::MAX);
}

#[test]
fn a_stop_keeps_its_first_instant_and_its_gaps_double_up_to_the_bound() {
    let mut l: Liveness<TestInstant> = Liveness::new();
    assert!(!l.stopped());
    l.halt(at(0));
    l.halt(at(500));
    assert!(l.stopped());
    assert_eq!(l.held(), Some(at(1_000)), "the first stop's instant holds");
    // Each probe counted at the instant the floor frees: the gap after it
    // is 1 s, then doubles up to 30 s (draft Section 5.6).
    let mut gaps = Vec::new();
    for _ in 0..7 {
        let sent = l.held().unwrap();
        l.spend(sent);
        gaps.push(l.held().unwrap().0 - sent.0);
    }
    assert_eq!(gaps, [1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000]);
}

#[test]
fn the_silence_clock_starts_at_the_earliest_probe_since_the_last_matching_answer() {
    let mut l: Liveness<TestInstant> = Liveness::new();
    assert_eq!(l.quiet(), None);
    l.send(at(0), at(400), 27, || 1).unwrap();
    l.send(at(5), at(405), 27, || 1).unwrap();
    assert_eq!(l.quiet(), Some(at(0)), "the earliest probe sets the clock");
    l.halt(at(60_000));
    l.resume();
    assert_eq!((l.quiet(), l.held()), (None, None), "resumed");
    l.send(at(7), at(407), 27, || 1).unwrap();
    assert_eq!(l.quiet(), Some(at(7)));
}

#[test]
fn only_an_answer_in_time_is_a_matching_one() {
    let mut l: Liveness<TestInstant> = Liveness::new();
    let first = l.send(at(0), at(400), 27, || 10).unwrap();
    let second = l.send(at(1), at(401), 27, || 10).unwrap();
    assert_eq!(l.expire(at(400), false), Some(true));
    let late = l.answer(first).expect("a late answer");
    assert!(matches!(late, Answer::Late(_)));
    assert!(!late.matching(), "a late answer is not a matching one");
    let in_time = l.answer(second).expect("an answer in time");
    assert!(matches!(in_time, Answer::InTime(_)));
    assert!(in_time.matching());
}

#[test]
fn a_connection_slot_moves_the_next_free_instant_to_its_opening_without_doubling() {
    let counted = || {
        let mut l: Liveness<TestInstant> = Liveness::new();
        l.halt(at(0));
        l.spend(at(10_000));
        l
    };
    // A slot that went to a connection, opened 900 ms on: the next probe
    // waits the slot's 1 s gap from the opening, and the gap after it is
    // 2 s, not doubled again.
    let mut l = counted();
    l.owe();
    l.rebase(at(10_900), true);
    assert_eq!(l.held(), Some(at(11_900)));
    l.spend(at(11_900));
    assert_eq!(l.held(), Some(at(13_900)));
    // A failed connection moves nothing.
    let mut l = counted();
    l.owe();
    l.rebase(at(10_900), false);
    assert_eq!(l.held(), Some(at(11_000)));
    // Nor does an opening for a slot that was not a connection's.
    let mut l = counted();
    l.rebase(at(10_900), true);
    assert_eq!(l.held(), Some(at(11_000)));
}

#[test]
fn a_probe_sent_before_a_path_leaves_dead_times_out_uncounted_and_an_answer_in_time_still_matches_it()
 {
    let mut l: Liveness<TestInstant> = Liveness::new();
    let first = l.send(at(0), at(400), 27, || 10).unwrap();
    let second = l.send(at(1), at(401), 27, || 10).unwrap();
    // The path leaves Dead with both outstanding.
    l.fresh();
    l.thaw();
    assert_eq!(l.expire(at(400), false), Some(false), "not counted");
    assert_eq!(l.misses(), 0);
    let Some(Answer::InTime(sent)) = l.answer(second) else {
        panic!("an answer in time to a probe from before still matches");
    };
    assert_eq!(sent.probe_id, second);
    assert!(matches!(l.answer(first), Some(Answer::Late(_))));
    // A probe sent since counts as before.
    l.send(at(500), at(900), 27, || 10).unwrap();
    assert_eq!(l.expire(at(900), false), Some(true));
    assert_eq!(l.misses(), 1);
}

#[test]
fn the_first_counted_probe_id_is_dropped_once_no_probe_before_it_is_outstanding() {
    let mut l: Liveness<TestInstant> = Liveness::new();
    l.send(at(0), at(400), 27, || 10).unwrap();
    l.fresh();
    l.thaw();
    assert_eq!(l.since, Some(11));
    // Kept while the probe from before is outstanding, so its timeout is
    // still told apart.
    l.send(at(100), at(500), 27, || 10).unwrap();
    assert_eq!(l.since, Some(11));
    assert_eq!(l.expire(at(400), false), Some(false));
    // Dropped at the next probe, so the comparison never spans half the
    // `probe_id` space however long the path lives.
    l.send(at(450), at(850), 27, || 10).unwrap();
    assert_eq!(l.since, None);
    assert_eq!(l.expire(at(500), false), Some(true));
}
