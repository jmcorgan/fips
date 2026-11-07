//! Tests of `select.rs`: a path's score and the ranking of a choice's
//! rivals, the size of the frame that carries a filter, and the hold on a
//! link's cost.

use super::*;
use crate::proto::bloom::{BloomFilter, FilterAnnounce};
use crate::testutil::TestInstant;

/// `ms` milliseconds.
fn ms(ms: u64) -> Duration {
    Duration::from_millis(ms)
}

/// Whether `a` and `b` agree to well within any score difference that
/// matters.
fn close(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-9
}

/// The switch margin of the draft.
const MARGIN: f64 = 1.3;

/// A rival at `index` with `score` and the latest round trip `rtt` in
/// milliseconds, on a transport whose role is `Normal`.
fn rival(index: usize, score: Option<f64>, rtt: Option<u64>) -> Rival {
    on(Role::Normal, index, score, rtt)
}

/// A rival as [`rival`] makes it, on a transport whose role is `role`,
/// whose link MTU carries a filter.
fn on(role: Role, index: usize, score: Option<f64>, rtt: Option<u64>) -> Rival {
    Rival {
        index,
        score,
        rtt: rtt.map(ms),
        tier: tier(role),
        preferred: role == Role::Preferred,
        pinned: false,
        fits: true,
    }
}

/// `rival` on a link MTU too small to carry a filter.
fn small(rival: Rival) -> Rival {
    Rival {
        fits: false,
        ..rival
    }
}

/// The field holding `rivals`, each in its own slot.
fn field(rivals: &[Rival]) -> Field {
    let mut field: Field = [None; PATH_MAX_PER_PEER];
    for r in rivals {
        field[r.index] = Some(*r);
    }
    field
}

#[test]
fn the_score_is_the_etx_times_one_plus_the_least_round_trip_over_100_ms() {
    let mut live: Liveness<TestInstant> = Liveness::new();
    assert_eq!(score(&live), None, "no round trip measured, no score");
    let window = Duration::from_secs(30);
    for (at, rtt) in [(1_000, 250), (2_000, 200), (3_000, 300)] {
        live.sample(TestInstant(at), ms(rtt), window);
    }
    let first = score(&live).expect("a score once measured");
    assert!(close(first, 3.0), "1 x (1 + 200 / 100), not {first}");
    live.fold(false);
    assert!(live.etx() > 1.0, "a lost probe raises the ETX");
    let lossy = score(&live).expect("a score once measured");
    assert!(
        close(lossy, live.etx() * 3.0),
        "the ETX scales the score: {lossy} against {}",
        live.etx() * 3.0
    );
}

#[test]
fn choose_takes_the_best_score_and_the_least_latest_round_trip_only_when_nothing_is_scored() {
    // A scored rival beats an unscored one with a smaller latest round
    // trip.
    let mixed = field(&[rival(0, None, Some(1)), rival(1, Some(2.0), Some(50))]);
    assert_eq!(choose(&mixed, MARGIN), Some(1));
    // The least score wins.
    let scored = field(&[
        rival(0, Some(1.5), Some(1)),
        rival(1, Some(1.2), Some(90)),
        rival(2, Some(1.4), Some(2)),
    ]);
    assert_eq!(choose(&scored, MARGIN), Some(1));
    // A score tie goes to the lower index.
    let tied = field(&[
        rival(2, Some(1.2), Some(9)),
        rival(4, Some(1.2), Some(1)),
        rival(5, Some(1.3), Some(1)),
    ]);
    assert_eq!(choose(&tied, MARGIN), Some(2));
    // With none scored, the least latest round trip, none measured last,
    // the lower index on a tie.
    let unscored = field(&[
        rival(0, None, None),
        rival(1, None, Some(9)),
        rival(2, None, Some(3)),
        rival(3, None, Some(3)),
    ]);
    assert_eq!(choose(&unscored, MARGIN), Some(2));
    let unmeasured = field(&[rival(0, None, None), rival(1, None, Some(50))]);
    assert_eq!(choose(&unmeasured, MARGIN), Some(1));
    let blank = field(&[rival(3, None, None), rival(6, None, None)]);
    assert_eq!(choose(&blank, MARGIN), Some(3));
    // No rival, no choice.
    assert_eq!(choose(&field(&[]), MARGIN), None);
}

#[test]
fn choose_keeps_the_highest_tier_and_gives_a_preferred_path_the_margin() {
    // A backup rival with a better score loses to a normal one, and an
    // unscored normal one beats a scored backup one.
    let backup = field(&[
        on(Role::Backup, 0, Some(1.0), Some(1)),
        rival(1, Some(2.0), Some(50)),
    ]);
    assert_eq!(choose(&backup, MARGIN), Some(1));
    let unscored = field(&[
        on(Role::Backup, 0, Some(1.0), Some(1)),
        rival(1, None, Some(50)),
    ]);
    assert_eq!(choose(&unscored, MARGIN), Some(1));
    // With only backup and never rivals, the backup one wins, whatever the
    // never one scores.
    let low = field(&[
        on(Role::Never, 0, Some(1.0), Some(1)),
        on(Role::Backup, 1, Some(2.0), Some(50)),
    ]);
    assert_eq!(choose(&low, MARGIN), Some(1));
    assert_eq!(
        choose(&field(&[on(Role::Never, 2, Some(1.0), Some(1))]), MARGIN),
        Some(2),
        "a never rival is still taken when it is the only one"
    );
    // A preferred rival within the margin of the best wins; outside it,
    // it loses.
    let best = rival(0, Some(1.0), Some(1));
    let within = field(&[best, on(Role::Preferred, 1, Some(1.25), Some(9))]);
    assert_eq!(choose(&within, MARGIN), Some(1));
    let edge = field(&[best, on(Role::Preferred, 1, Some(1.3), Some(9))]);
    assert_eq!(choose(&edge, MARGIN), Some(1), "at most the margin");
    let outside = field(&[best, on(Role::Preferred, 1, Some(1.35), Some(9))]);
    assert_eq!(choose(&outside, MARGIN), Some(0));
    // An unscored preferred rival takes no precedence over a scored one.
    let unready = field(&[best, on(Role::Preferred, 1, None, Some(1))]);
    assert_eq!(choose(&unready, MARGIN), Some(0));
    // Two preferred rivals within the margin: the lower score, then the
    // lower index.
    let two = field(&[
        best,
        on(Role::Preferred, 1, Some(1.2), Some(9)),
        on(Role::Preferred, 2, Some(1.1), Some(9)),
        on(Role::Preferred, 3, Some(1.1), Some(9)),
    ]);
    assert_eq!(choose(&two, MARGIN), Some(2));
    // A preferred rival that scores best wins as it would anyway.
    let first = field(&[
        rival(0, Some(1.5), Some(1)),
        on(Role::Preferred, 1, Some(1.0), None),
    ]);
    assert_eq!(choose(&first, MARGIN), Some(1));
}

#[test]
fn best_is_the_least_score_among_the_scored_rivals_of_the_highest_tier() {
    // A backup rival's better score is not the best while a normal one is
    // a rival, and an unscored rival has none.
    let mixed = field(&[
        on(Role::Backup, 0, Some(1.0), Some(1)),
        on(Role::Preferred, 1, Some(1.6), Some(9)),
        rival(2, Some(1.4), Some(9)),
        rival(3, None, Some(1)),
    ]);
    assert_eq!(best(&mixed), Some(1.4));
    assert_eq!(best(&field(&[rival(0, None, Some(1))])), None);
    assert_eq!(best(&field(&[])), None);
}

#[test]
fn the_filter_frame_is_a_filter_announce_and_the_frame_overhead() {
    let message = FilterAnnounce::new(BloomFilter::new(), 0)
        .encode()
        .expect("a v1 filter encodes");
    assert_eq!(message.len() + FRAME_OVERHEAD, FILTER_FRAME);
    assert_eq!(FILTER_FRAME, 1_071);
}

#[test]
fn choose_prefers_rivals_that_carry_a_filter_announce_within_the_top_tier() {
    // A fitting rival beats a better-scoring one that does not fit.
    let fitting = field(&[
        small(rival(0, Some(1.0), Some(1))),
        rival(1, Some(3.0), Some(200)),
    ]);
    assert_eq!(choose(&fitting, MARGIN), Some(1));
    // With none fitting, the score decides.
    let none = field(&[
        small(rival(0, Some(3.0), Some(200))),
        small(rival(1, Some(1.0), Some(1))),
    ]);
    assert_eq!(choose(&none, MARGIN), Some(1));
    // A normal rival that does not fit beats a backup one that does.
    let backup = field(&[
        small(rival(0, Some(3.0), Some(200))),
        on(Role::Backup, 1, Some(1.0), Some(1)),
    ]);
    assert_eq!(choose(&backup, MARGIN), Some(0));
    // A fitting normal rival beats a preferred one within the margin that
    // does not fit.
    let preferred = field(&[
        rival(0, Some(1.0), Some(1)),
        small(on(Role::Preferred, 1, Some(1.1), Some(1))),
    ]);
    assert_eq!(choose(&preferred, MARGIN), Some(0));
    // A pinned rival that does not fit beats a fitting one.
    let pinned = field(&[
        rival(0, Some(1.0), Some(1)),
        Rival {
            pinned: true,
            ..small(rival(1, Some(3.0), Some(200)))
        },
    ]);
    assert_eq!(choose(&pinned, MARGIN), Some(1));
}

#[test]
fn a_hold_ends_only_when_both_the_dwell_and_two_reports_have_passed() {
    let dwell = ms(2_000);
    let at = |ms: u64| TestInstant(ms);
    let reported = |n: usize| {
        let mut hold = Hold::new(1.5, at(1_000));
        for _ in 0..n {
            hold.report();
        }
        hold
    };
    // At the dwell's end, the hold lasts until the second report.
    assert_eq!(reported(0).held(at(3_000), dwell), Some(1.5), "no report");
    assert_eq!(reported(1).held(at(3_000), dwell), Some(1.5), "one report");
    assert_eq!(reported(2).held(at(3_000), dwell), None, "both reports");
    assert_eq!(reported(3).held(at(3_000), dwell), None, "a third report");
    // Before the dwell's end, both reports do not end it.
    assert_eq!(reported(2).held(at(2_999), dwell), Some(1.5));
    assert_eq!(reported(0).held(at(1_000), dwell), Some(1.5));
}
