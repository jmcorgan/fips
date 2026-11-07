//! Tests of the capability record (`proto::path::capable::tests::...`):
//! the draft's schedule, one probe outstanding at a time, matching an
//! answer, and the first round reported unanswered once.

use alloc::vec::Vec;

use super::*;
use crate::testutil::TestInstant;

/// The instant `ms` milliseconds after the test clock's epoch.
fn at(ms: u64) -> TestInstant {
    TestInstant(ms)
}

/// The draft's probe timeout floor, 400 ms, as each probe's timeout.
const TIMEOUT: Duration = Duration::from_millis(400);

/// The instants, in milliseconds, of the first `n` probes of a record
/// whose probes all go unanswered, each sent as soon as it may go.
fn schedule(cfg: &Config, n: usize) -> Vec<u64> {
    let mut c = Capability::<TestInstant>::new();
    let mut sent = Vec::new();
    let mut now = at(0);
    while sent.len() < n {
        if let Some((s, _)) = c.expire(now, false, cfg) {
            assert!(s.due <= now);
        }
        if c.due(now) {
            c.send(now, 7, sent.len() as u32, TIMEOUT, cfg);
            sent.push(now.0);
        }
        now = c
            .wake(true)
            .expect("a record with probes left always has a wake");
    }
    sent
}

#[test]
fn the_draft_schedule_spreads_three_then_doubles_from_the_span_to_the_cap() {
    let cfg = Config::draft();
    let sent = schedule(&cfg, 40);
    let secs: Vec<u64> = sent.iter().take(13).map(|ms| ms / 1000).collect();
    assert_eq!(
        secs,
        [
            0, 10, 20, 50, 110, 230, 470, 950, 1550, 2150, 2750, 3350, 3950
        ]
    );
    assert!(sent.iter().all(|ms| ms % 1000 == 0), "{sent:?}");
    let within = |from: u64, to: u64| sent.iter().filter(|&&ms| ms >= from && ms < to).count();
    assert_eq!(within(0, 3_600_000), 12, "twelve in the first hour");
    assert_eq!(within(3_600_000, 7_200_000), 6, "six in the second");
    for w in sent[7..].windows(2) {
        assert_eq!(w[1] - w[0], 600_000, "every later gap is the cap");
    }
}

#[test]
fn nothing_is_due_while_one_is_outstanding() {
    let cfg = Config {
        span: Duration::from_millis(900),
        ..Config::draft()
    };
    let mut c = Capability::<TestInstant>::new();
    assert!(c.due(at(0)), "the first goes at once");
    c.send(at(0), 7, 1, TIMEOUT, &cfg);
    assert_eq!(c.next_at(), Some(at(300)));
    // The gap has passed, but the first is still outstanding.
    assert!(!c.due(at(300)));
    assert!(!c.due(at(399)));
    assert_eq!(c.wake(true), Some(at(400)), "the timeout comes first");
    assert!(
        c.expire(at(400), true, &cfg).is_none(),
        "not overdue at 400"
    );
    assert!(c.expire(at(400), false, &cfg).is_some());
    assert!(c.due(at(400)));
    assert_eq!(c.sent(), 1);
}

#[test]
fn an_answer_takes_only_the_outstanding_probe_of_its_path_in_time() {
    let cfg = Config::draft();
    let mut c = Capability::<TestInstant>::new();
    c.send(at(0), 7, 41, TIMEOUT, &cfg);
    assert_eq!(c.answer(8, 41), None, "another path");
    assert_eq!(c.answer(7, 40), None, "another probe");
    let sent = c.answer(7, 41).expect("the outstanding probe");
    assert_eq!((sent.probe_id, sent.at, sent.due), (41, at(0), at(400)));
    assert_eq!(sent.len, PATH_PROBE_MIN_SIZE);
    assert_eq!(c.answer(7, 41), None, "taken once");
    assert_eq!(c.wake(false), None);

    // Past its timeout it is no longer held: the answer is late.
    c.send(at(10_000), 7, 42, TIMEOUT, &cfg);
    let (gone, round) = c.expire(at(10_400), false, &cfg).expect("timed out");
    assert_eq!(gone.probe_id, 42);
    assert!(!round);
    assert_eq!(c.answer(7, 42), None);
    assert_eq!(c.take(), None);
}

#[test]
fn the_first_round_is_reported_unanswered_once() {
    let cfg = Config::draft();
    let mut c = Capability::<TestInstant>::new();
    let mut rounds = Vec::new();
    let mut now = at(0);
    for k in 0..6 {
        c.send(now, 7, k, TIMEOUT, &cfg);
        let due = c.wake(false).expect("the timeout");
        let (_, round) = c.expire(due, false, &cfg).expect("timed out");
        rounds.push(round);
        now = c.next_at().expect("the next");
    }
    assert_eq!(rounds, [false, false, true, false, false, false]);
    assert!(c.told());
    assert_eq!(c.sent(), 6);
}
