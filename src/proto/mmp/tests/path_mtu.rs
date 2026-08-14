//! Source-side `PathMtuState::apply_notification` tests: the actionable floor
//! on a remote-supplied value, and the increase-sequence counter.

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
