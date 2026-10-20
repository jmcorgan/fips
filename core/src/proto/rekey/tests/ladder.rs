//! Tests of `ladder.rs`: schedules are integer offsets truncated at their
//! deadline, keepalives fill long gaps, and a late take passes every
//! overdue rung at once.

use super::*;
use crate::testutil::TestInstant;

/// Offsets of a schedule, in whole seconds.
fn secs(s: &Schedule) -> alloc::vec::Vec<u64> {
    s.offsets().map(|ms| ms / 1000).collect()
}

#[test]
fn doubling_ladder_keeps_only_rungs_before_its_deadline_and_counts_the_rest() {
    let (s, dropped) = Schedule::doubling(Duration::from_secs(1), 5, Some(Duration::from_secs(30)));
    assert_eq!(
        secs(&s),
        [1, 3, 7, 15],
        "the 31 s rung falls after a 30 s deadline"
    );
    assert_eq!(dropped, 1, "the truncated rung is reported");
    let (s, dropped) =
        Schedule::doubling(Duration::from_secs(9), 16, Some(Duration::from_secs(30)));
    assert_eq!(
        secs(&s),
        [9, 27],
        "a 9 s first rung keeps two resends inside 30 s"
    );
    assert_eq!(dropped, 14);
    let (s, _) = Schedule::doubling(Duration::from_secs(1), 5, None);
    assert_eq!(
        secs(&s),
        [1, 3, 7, 15, 31],
        "with no deadline every rung is kept"
    );
}

#[test]
fn probe_ladder_fills_every_gap_longer_than_the_keepalive_gap_before_its_deadline() {
    let (s, dropped) = Schedule::probes(
        Duration::from_secs(1),
        5,
        Duration::from_secs(31),
        Duration::from_secs(4),
    );
    assert_eq!(secs(&s), [1, 3, 7, 11, 15, 19, 23, 27]);
    let sends: alloc::vec::Vec<_> = (0..s.len()).map(|i| s.rung(i) == Rung::Send).collect();
    assert_eq!(sends, [true, true, true, false, true, false, false, false]);
    assert_eq!(
        dropped, 1,
        "the 31 s probe falls at the confirmation deadline"
    );
    assert_eq!(s.last_send(), Some(15_000));
    // A short keepalive gap needs 61 rungs; the 45 past the schedule's
    // room are reported with the truncated probe.
    let (s, dropped) = Schedule::probes(
        Duration::from_secs(1),
        5,
        Duration::from_secs(31),
        Duration::from_millis(500),
    );
    assert_eq!(s.len(), MAX_RUNGS);
    assert_eq!(dropped, 1 + 45, "every rung that does not fit is reported");
}

#[test]
fn a_late_take_passes_every_overdue_rung_and_reports_one_send() {
    let (s, _) = Schedule::probes(
        Duration::from_secs(1),
        5,
        Duration::from_secs(31),
        Duration::from_secs(4),
    );
    let mut l = Ladder::new(TestInstant(0), s);
    assert_eq!(l.next_at(), Some(TestInstant(1_000)));
    assert_eq!(
        l.take(TestInstant(999)),
        None,
        "nothing is due before the first rung"
    );
    let t = l.take(TestInstant(12_000)).expect("rungs are due");
    assert!(t.send, "an overdue probe rung makes the take a probe");
    assert_eq!(
        t.latest, 11_000,
        "the latest overdue rung was the 11 s keepalive"
    );
    assert!(!t.last);
    assert_eq!(
        l.next_at(),
        Some(TestInstant(15_000)),
        "every overdue rung was passed"
    );
    let t = l.take(TestInstant(20_000)).expect("two rungs are due");
    assert!(t.send);
    let t = l.take(TestInstant(28_000)).expect("keepalives are due");
    assert!(!t.send, "only keepalive rungs were overdue");
    assert!(t.last);
    assert_eq!(l.next_at(), None);
}
