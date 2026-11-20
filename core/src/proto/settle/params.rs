//! The intervals and bounds the settlement core reads, and the two pieces
//! of time arithmetic its timers share.
//!
//! [`Params::default`] holds FRC-1201 Section 5.5's intervals, and the
//! node's own bounds and handshake timers as the current node has them.
//! The restart gates' intervals and bounds are the node's own: its restart
//! gates are these ([`super::gates::Gates`]). The handshake timers and the
//! admission cap are configuration defaults, each repeated here with the
//! line it comes from, which the node passes in from its own configuration
//! (`src/node/settle/params.rs`).

use crate::time::{Duration, Instant};

/// The settlement core's intervals and bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// The first restart-gate floor, the age an unheard peering must reach
    /// before a restart or replacement may tear it down (1 s).
    ///
    /// An unheard responder peering may have come from a captured msg1, so
    /// the genuine peer's own msg1 has to be able to replace it, but not at
    /// once. A dialer that opens two paths to this node in one tick sends
    /// two fresh msg1s, and the second reaches this node before the
    /// dialer's first frame on the session the first one opened. Replacing
    /// on it would tear down the session the dialer may keep when it
    /// resolves its two completions by address order, and neither end could
    /// then read the other. The second msg1 of such a dial arrives within
    /// about one round trip of the first.
    ///
    /// A genuine msg1 that meets a phantom promoted inside this age is
    /// refused, and the phantom's link records its ephemeral, as a link
    /// records every msg1 it refuses, so the msg1's resends are refused too:
    /// the peer's next dial, with a fresh msg1, replaces the phantom. A
    /// parallel dial over a path whose first frame takes longer than this
    /// can still be split. An attacker holding k distinct captures of a
    /// peer, each timed to land just ahead of the peer's own msg1, holds
    /// that peer's reconnect off for about k of its dials per interval. Each
    /// replaced unheard peering also ends a session that never authenticated
    /// a frame, which the silent-session record counts, so about four
    /// distinct captures a second apart ([`Params::silent`] plus one) start
    /// that back-off of the peer's same-epoch msg1s. No measured basis.
    pub unheard: Duration,
    /// The second floor, counted from a heard peering's last frame, and the
    /// dampener's ceiling, the least time between accepted restarts or
    /// replacements of one identity (15 s). It is also the replay memory's
    /// window.
    ///
    /// A restart or replacement msg1 is authentic but replayable: a captured
    /// one stays valid indefinitely, and accepting it tears down a working
    /// peering. Both conditions are receiver-local. The liveness half is the
    /// one that closes the replay, since a peering under attack is by
    /// construction still heartbeating; the interval half bounds the churn a
    /// peer can drive on its own.
    ///
    /// Sized against the peer's own recovery rather than against a round
    /// number: a genuinely restarting peer's msg1 resends fire at roughly
    /// t+1, t+3, t+7 and t+15 seconds and its attempt is reaped at the
    /// handshake timeout (30 s), so 15 is the largest value at which a real
    /// restart still re-peers inside its first handshake window with no
    /// reconnect backoff. It also sits below the link-dead timeout (30 s),
    /// so the liveness gate can never outlive the reaper that would have
    /// removed the peering anyway. Raising it lengthens the outage an
    /// attacker's accepted replay causes, because the genuine peer's
    /// recovery msg1 hits the same gate. Lowering it weakens both halves
    /// and, below the resend ladder, buys nothing. The dampener is per
    /// identity and shared by restarts and replacements, so one of each
    /// inside the interval count as two teardowns.
    pub interval: Duration,
    /// The most msg1 ephemerals per peer whose promotion of an unheard
    /// peering is remembered (8).
    ///
    /// A msg1 carries nothing fresh, so a captured one promotes a peering
    /// that nothing proves is live, and the genuine peer's own msg1 must be
    /// able to replace it. Each distinct capture can then replace the one
    /// before, and every replacement costs the node a DH, a teardown, and a
    /// msg2 and initial TreeAnnounce sent to the msg1's source address,
    /// which the replayer chose. Remembering the ephemerals already used
    /// stops a capture from being spent twice inside [`Params::interval`];
    /// at this bound a further replacement of an unheard peering is refused,
    /// as the dampener refuses. This is the most replay-driven msg2s per
    /// peer per interval (one without the memory). It does not bound what
    /// blocking the genuine peer's reconnect costs: the silent-session
    /// back-off starts after fewer captures (see [`Params::unheard`]). A
    /// genuine peer uses one or two (its first msg1 and, if that peering was
    /// replaced before its first frame, its next). No measured basis.
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
    /// The first msg1 resend's delay, counted from the dial's msg1: one
    /// second whatever the configured resend interval, as the node has sent
    /// its first resend since version 0.5.0, when its control machine
    /// stopped reading the configured interval for it. The configuration
    /// has no key for it, so the node takes this default.
    pub first: Duration,
    /// The configured msg1 resend interval (1 s; `node.rs:148`), the base of
    /// every resend wait after the first: after `n` resends the wait is
    /// this times [`Params::backoff`] to the power of `n` ([`Params::wait`]).
    pub resend: Duration,
    /// The resend wait's multiplier, as the bits of an `f64`
    /// (`f64::to_bits`), so that the parameters stay `Eq` (2.0;
    /// `node.rs:149`). [`Params::multiplier`] reads it.
    pub backoff: u64,
    /// The most msg1 resends of one dial (5; `node.rs:150`). A dial may
    /// carry a lower cap of its own (`legs::Start::resends`), as the node
    /// caps an mDNS-directed dial.
    pub resends: u32,
    /// The node's timer cadence, one tick (1 s; `TICK`,
    /// `src/node/mod.rs:64`). A dial resend whose send failed is tried
    /// again at the next poll, as the node re-arms one for its next tick,
    /// and this is how far on the wake the core reports for it lies.
    pub retry: Duration,
    /// The most answers in flight to msg1s not yet installed, the
    /// admission cap (1000, `max_pending_inbound`; `node.rs:54`).
    pub pending: usize,
    /// The most peers held at once, the max-peers cap; 0 holds any number
    /// (128, `max_peers`; `node.rs:52`).
    pub peers: usize,
}

impl Default for Params {
    /// FRC-1201's intervals and the current node's bounds.
    fn default() -> Self {
        let interval = if fault!(IntervalTen) || node_fault!(IntervalTen) {
            10
        } else {
            15
        };
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
            first: Duration::from_secs(1),
            resend: Duration::from_secs(1),
            backoff: 2.0_f64.to_bits(),
            resends: 5,
            retry: Duration::from_secs(1),
            pending: 1000,
            peers: 128,
        }
    }
}

impl Params {
    /// The resend wait's multiplier, [`Params::backoff`] read back.
    pub fn multiplier(&self) -> f64 {
        f64::from_bits(self.backoff)
    }

    /// The wait before a dial's next msg1 resend once it has made `sent`
    /// resends, one or more: the resend interval times the multiplier to the
    /// power of `sent`, truncated to the millisecond, as the node computed
    /// it before its dials' resends were the legs'.
    pub fn wait(&self, sent: u32) -> Duration {
        if fault!(BackoffDoubles) || node_fault!(BackoffDoubles) {
            return backoff(sent, self.resend, Duration::MAX);
        }
        let base = u64::try_from(self.resend.as_millis()).unwrap_or(u64::MAX);
        let factor = crate::proto::math::powi(self.multiplier(), sent);
        Duration::from_millis((base as f64 * factor) as u64)
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
