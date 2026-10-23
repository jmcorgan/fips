//! Source-side `PathMtuState` tests: the actionable floor on a remote-supplied
//! value, the increase-sequence counter, the one-way reactive decrease, and
//! the pending increase value that either decrease must clear.

use crate::proto::mmp::MIN_ACTIONABLE_PATH_MTU;
use crate::proto::mmp::path_mtu::PathMtuState;

#[test]
fn apply_notification_ignores_a_decrease_below_the_actionable_floor() {
    // The reported value comes from a remote party. Driving current_mtu into
    // this band turns the TUN send gate into a blackhole: every packet is
    // answered with a Packet Too Big instead of being sent. Sub-floor values
    // are ignored outright, not clamped, so the locally seeded value survives
    // untouched.
    for reported in [0u16, 1, 137, 138, 200, 255] {
        let mut state = PathMtuState::new();
        state.seed_source_mtu(1400);

        let changed = state.apply_notification(reported, 1_000);

        assert!(
            !changed,
            "reported path MTU {reported} is below the floor and must report no change"
        );
        assert_eq!(
            state.current_mtu(),
            1400,
            "reported path MTU {reported} must leave the seeded value intact"
        );
    }
}

#[test]
fn apply_notification_accepts_a_decrease_at_the_actionable_floor() {
    // The floor must not swallow the smallest value the node does act on, nor
    // the legitimately narrow hops the mesh actually carries.
    for reported in [MIN_ACTIONABLE_PATH_MTU, 576, 800] {
        let mut state = PathMtuState::new();
        state.seed_source_mtu(1400);

        let changed = state.apply_notification(reported, 1_000);

        assert!(changed, "reported path MTU {reported} must be applied");
        assert_eq!(state.current_mtu(), reported);
    }
}

#[test]
fn apply_notification_increase_counter_does_not_overflow_on_a_repeated_value() {
    // The counter is a u8 and resets only when the value changes or the
    // increase is accepted. Acceptance additionally requires the sequence to
    // span two notification intervals, so a peer repeating one higher value
    // fast enough stays in the increase branch indefinitely.
    let mut state = PathMtuState::new();
    state.seed_source_mtu(1000);

    for _ in 0..600 {
        state.apply_notification(1200, 1_000);
    }

    assert_eq!(
        state.current_mtu(),
        1000,
        "the increase is not yet due, so the effective MTU must be unchanged"
    );
}

#[test]
fn reset_source_mtu_returns_to_the_no_measurement_state_and_clears_the_increase_ladder() {
    // Two halves. The value half is trivially observable; the ladder half is
    // not, because immediately after a reset every reported value is a
    // decrease from u16::MAX and the decrease branch reads none of the
    // increase counters. Observing them takes a later decrease followed by a
    // full three-notification increase sequence: a stale
    // `pending_increase_mtu` makes the first of those three take the "same
    // value as pending" arm, which never sets `first_increase_ms`, so the
    // increase can never be accepted at all.
    let t0 = 100_000u64;
    let mut state = PathMtuState::new();

    // Tighten, then part-build an increase sequence on top of it.
    assert!(state.apply_notification(800, t0));
    state.apply_notification(1400, t0);
    state.apply_notification(1400, t0 + 11_000);
    assert_eq!(
        state.current_mtu(),
        800,
        "precondition: the tightened value is in place and the increase is pending"
    );

    state.reset_source_mtu();

    assert_eq!(
        state.current_mtu(),
        u16::MAX,
        "the reset must return the source side to the no-measurement state"
    );

    // A fresh decrease, which zeroes the count and the first-increase time but
    // would leave a stale pending value behind if the reset had not cleared it.
    assert!(state.apply_notification(1000, t0 + 20_000));
    assert_eq!(state.current_mtu(), 1000);

    // Three matching higher values spanning two notification intervals. This
    // is accepted only if the sequence starts from a cleared ladder.
    let t1 = t0 + 30_000;
    state.apply_notification(1400, t1);
    state.apply_notification(1400, t1 + 11_000);
    state.apply_notification(1400, t1 + 21_000);

    assert_eq!(
        state.current_mtu(),
        1400,
        "a reset that left the increase ladder behind strands the first of \
         the three notifications, so the increase is never accepted"
    );
}

#[test]
fn apply_reactive_decrease_at_or_above_the_estimate_changes_nothing_and_keeps_the_pending_increase()
{
    // A reactive report can only say a hop is too small. One at or above the
    // estimate must leave both the estimate and the destination's increase
    // ladder exactly as they were, so the ladder still completes on schedule.
    let t0 = 100_000u64;
    let mut state = PathMtuState::new();
    state.seed_source_mtu(1200);
    state.apply_notification(1400, t0);
    state.apply_notification(1400, t0 + 10_000);

    assert!(
        !state.apply_reactive_decrease(1200),
        "equal to the estimate"
    );
    assert!(!state.apply_reactive_decrease(1300), "above the estimate");
    assert!(
        !state.apply_reactive_decrease(1400),
        "equal to the pending value"
    );
    assert_eq!(state.current_mtu(), 1200);

    assert!(
        state.apply_notification(1400, t0 + 25_000),
        "the third matching notification must still complete the increase"
    );
    assert_eq!(state.current_mtu(), 1400);
}

#[test]
fn apply_reactive_decrease_below_the_estimate_lowers_it_at_once_and_clears_the_ladder() {
    let t0 = 100_000u64;
    let mut state = PathMtuState::new();
    state.seed_source_mtu(1200);
    state.apply_notification(1400, t0);
    state.apply_notification(1400, t0 + 10_000);

    assert!(
        !state.apply_reactive_decrease(MIN_ACTIONABLE_PATH_MTU - 1),
        "a value below the actionable floor is ignored"
    );
    assert_eq!(state.current_mtu(), 1200);

    assert!(state.apply_reactive_decrease(1000));
    assert_eq!(state.current_mtu(), 1000, "a decrease applies at once");

    // The interrupted sequence must not resume: its third notification is now
    // the first of a new sequence, not the completion of the old one.
    assert!(!state.apply_notification(1400, t0 + 25_000));
    assert_eq!(
        state.current_mtu(),
        1000,
        "the decrease must abandon the increase that was in progress"
    );

    // And a fresh sequence starting from the cleared ladder is accepted.
    let t1 = t0 + 30_000;
    state.apply_notification(1300, t1);
    state.apply_notification(1300, t1 + 11_000);
    state.apply_notification(1300, t1 + 21_000);
    assert_eq!(state.current_mtu(), 1300);
}

/// Prime a pending increase to 1400, lower the estimate with `decrease`, then
/// report 1400 three times over more than two notification intervals.
fn decrease_then_report_the_pending_value_again(decrease: impl FnOnce(&mut PathMtuState)) -> u16 {
    let t0 = 100_000u64;
    let mut state = PathMtuState::new();
    state.seed_source_mtu(1200);
    assert!(!state.apply_notification(1400, t0), "1400 is only pending");

    decrease(&mut state);
    assert_eq!(state.current_mtu(), 1000);

    state.apply_notification(1400, t0 + 10_000);
    state.apply_notification(1400, t0 + 20_000);
    state.apply_notification(1400, t0 + 31_000);
    state.current_mtu()
}

#[test]
fn apply_notification_decrease_lets_the_previously_pending_value_be_accepted_later() {
    // A decrease that left the pending value behind sent the next matching
    // notification down the same-value arm, which never records when the
    // sequence began, so the increase could never be accepted.
    let mtu = decrease_then_report_the_pending_value_again(|state| {
        assert!(state.apply_notification(1000, 105_000));
    });
    assert_eq!(
        mtu, 1400,
        "a decrease must clear the pending value so a later increase to it completes"
    );
}

#[test]
fn apply_reactive_decrease_lets_the_previously_pending_value_be_accepted_later() {
    let mtu = decrease_then_report_the_pending_value_again(|state| {
        assert!(state.apply_reactive_decrease(1000));
    });
    assert_eq!(
        mtu, 1400,
        "a reactive decrease must clear the pending value so a later increase to it completes"
    );
}
