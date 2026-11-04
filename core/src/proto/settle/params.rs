//! The intervals and bounds the settlement core reads, and the two pieces
//! of time arithmetic its timers share.
//!
//! [`Params::default`] holds FRC-1201 Section 5.5's intervals, and the
//! node's own bounds and handshake timers as the current node has them.
//! Each is repeated here with the line it comes from. The handshake
//! handler's constants are private to it, and its copies go once the node
//! calls the core; the handshake timers are configuration defaults, which
//! the node will pass in.

use crate::time::{Duration, Instant};

/// The settlement core's intervals and bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// `UNHEARD_PEERING_MIN_AGE`: the first restart-gate floor, the age an
    /// unheard peering must reach before a restart or replacement may tear
    /// it down (1 s; `src/node/handlers/handshake.rs:84`).
    pub unheard: Duration,
    /// `EPOCH_RESTART_MIN_INTERVAL`: the second floor, counted from a
    /// heard peering's last frame, and the dampener's ceiling (15 s;
    /// `handshake.rs:58`). It is also the replay memory's window.
    pub interval: Duration,
    /// The most msg1 ephemerals per peer whose promotion of an unheard
    /// peering is remembered (8; `handshake.rs:103`).
    pub replays: usize,
    /// Silent sessions in a row at one epoch before the peer's msg1s at
    /// that epoch are refused (3; `core/src/proto/fmp/silent.rs:24`).
    pub silent: u32,
    /// The first silent-session refusal's length (30 s; `silent.rs:30`).
    pub silentbase: Duration,
    /// The longest silent-session refusal (600 s; `silent.rs:33`).
    pub silentcap: Duration,
    /// How long a silent-session record outlives its refusal, or its last
    /// session when it started none (600 s; `silent.rs:38`).
    pub horizon: Duration,
    /// Setup ephemerals a silent-session record remembers, so a replayed
    /// msg1's session is counted once (8; `silent.rs:44`).
    pub counted: usize,
    /// How long a handshake leg may take before it is reaped (30 s;
    /// `src/config/node.rs:147`).
    pub handshake: Duration,
    /// The first msg1 resend's delay; each later one doubles it (1 s and a
    /// factor of 2; `node.rs:148-149`).
    pub resend: Duration,
    /// The most msg1 resends of one dial (5; `node.rs:150`).
    pub resends: u32,
    /// The most answers in flight to msg1s not yet installed, the
    /// admission cap (1000, `max_pending_inbound`; `node.rs:54`).
    pub pending: usize,
}

impl Default for Params {
    /// FRC-1201's intervals and the current node's bounds.
    fn default() -> Self {
        let interval = if fault!(IntervalTen) { 10 } else { 15 };
        Self {
            unheard: Duration::from_secs(1),
            interval: Duration::from_secs(interval),
            replays: 8,
            silent: 3,
            silentbase: Duration::from_secs(30),
            silentcap: Duration::from_secs(600),
            horizon: Duration::from_secs(600),
            counted: 8,
            handshake: Duration::from_secs(30),
            resend: Duration::from_secs(1),
            resends: 5,
            pending: 1000,
        }
    }
}

/// The furthest a [`deadline`] reaches: 100 years. No host instant type
/// overflows that far from a current reading.
const CEILING: Duration = Duration::from_secs(100 * 365 * 24 * 60 * 60);

/// `now + d`, with `d` capped at [`CEILING`]. An instant type whose range
/// ends sooner gets a deadline at or before that end, never a panic: the
/// step is halved until it fits.
///
/// The multipath work adds the same function to `crate::time`; once both
/// are on one branch this copy folds onto it.
pub(super) fn deadline<I: Instant>(now: I, d: Duration) -> I {
    if fault!(DeadlineWraps) {
        return now.checked_add(d).expect("an unchecked deadline fits");
    }
    let mut step = d.min(CEILING);
    loop {
        if let Some(at) = now.checked_add(step) {
            return at;
        }
        if step.is_zero() {
            return now;
        }
        step /= 2;
    }
}

/// `base` doubled `exponent` times, capped at `cap`; the doubling and the
/// product saturate, so a large exponent gives the cap.
///
/// Folds onto the multipath work's `crate::time::backoff` as
/// [`deadline`] does.
pub(super) fn backoff(exponent: u32, base: Duration, cap: Duration) -> Duration {
    let factor = 1u32.checked_shl(exponent).unwrap_or(u32::MAX);
    base.saturating_mul(factor).min(cap)
}
