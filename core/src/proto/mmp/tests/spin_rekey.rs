//! The MMP spin bit after a rekey cutover whose counters start again.
//!
//! Two MMP states, one per end, exchange frames: the initiator's carry its
//! `tx_bit`, the responder observes them with the frame counter and reflects
//! its own `tx_bit`, which the initiator observes. A spinning bit flips at
//! the initiator once per round trip. The old session runs long enough that
//! its counters pass every counter the new session reaches in the window
//! checked, which is the real case: a session's counters restart near 0 at
//! a cutover (the Noise nonce starts again), and both reset hooks
//! (`reset_for_rekey`) are what the cutover calls. Both resets restart the
//! spin bit state, keeping its role, so the bit spins on the new session.

use crate::proto::mmp::{DEFAULT_LOG_INTERVAL_SECS, DEFAULT_OWD_WINDOW_SIZE, MmpMode};
use crate::proto::mmp::{MmpPeerState, MmpSessionState};

/// Frames each end sends on the old session before the cutover.
const OLD_FRAMES: u64 = 200;
/// Round trips checked on the new session, far below `OLD_FRAMES`.
const NEW_TRIPS: u64 = 20;

/// Run `trips` round trips with counters from `first`, starting at `now`.
/// Returns how many times the initiator's bit flipped and whether the
/// responder ended reflecting the initiator's last bit.
macro_rules! spin {
    ($init:expr, $resp:expr, $first:expr, $trips:expr, $now:expr) => {{
        let mut flips = 0u64;
        let mut reflected = true;
        for i in 0..$trips {
            let counter = $first + i;
            let now = $now + i * 10;
            let sent = $init.spin_bit.tx_bit();
            $resp.spin_bit.rx_observe(sent, counter, now);
            reflected = $resp.spin_bit.tx_bit() == sent;
            let back = $resp.spin_bit.tx_bit();
            let before = $init.spin_bit.tx_bit();
            $init.spin_bit.rx_observe(back, counter, now + 5);
            if $init.spin_bit.tx_bit() != before {
                flips += 1;
            }
        }
        (flips, reflected)
    }};
}

/// Drive a pair through an old session, a cutover, and a new session, and
/// assert the bit keeps spinning on the new session.
macro_rules! check_pair {
    ($ty:ty, $what:expr) => {{
        let mode = MmpMode::Full;
        let mut init = <$ty>::new(
            mode,
            DEFAULT_LOG_INTERVAL_SECS,
            DEFAULT_OWD_WINDOW_SIZE,
            true,
        );
        let mut resp = <$ty>::new(
            mode,
            DEFAULT_LOG_INTERVAL_SECS,
            DEFAULT_OWD_WINDOW_SIZE,
            false,
        );
        assert!(
            init.spin_bit.is_initiator() && !resp.spin_bit.is_initiator(),
            "precondition: one initiator and one responder"
        );

        let (old_flips, old_reflected) = spin!(init, resp, 1u64, OLD_FRAMES, 1_000u64);
        assert!(
            old_flips >= OLD_FRAMES / 2 && old_reflected,
            "precondition: the bit spins on the old session ({} flips in {} round trips)",
            old_flips,
            OLD_FRAMES
        );

        // The cutover: both ends reset for the rekey, and the new session's
        // counters start again at 1, below the old session's last counter.
        init.reset_for_rekey(10_000);
        resp.reset_for_rekey(10_000);
        assert!(
            1 + NEW_TRIPS < OLD_FRAMES,
            "precondition: the new session's counters stay below the old session's"
        );

        let (new_flips, new_reflected) = spin!(init, resp, 1u64, NEW_TRIPS, 20_000u64);
        assert!(
            new_flips >= NEW_TRIPS / 2 && new_reflected,
            "defect: {}: the spin bit stopped spinning after a rekey cutover: {} flips in {} \
             round trips on the new session (responder reflecting: {})",
            $what,
            new_flips,
            NEW_TRIPS,
            new_reflected
        );
    }};
}

#[test]
fn link_spin_bit_keeps_spinning_after_a_rekey_cutover_whose_counters_start_again() {
    check_pair!(MmpPeerState, "link (MmpPeerState, the FMP SP flag)");
}

#[test]
fn session_spin_bit_keeps_spinning_after_a_rekey_cutover_whose_counters_start_again() {
    check_pair!(
        MmpSessionState,
        "session (MmpSessionState, the FSP inner flag)"
    );
}
