//! Parent-switch flap dampening and hold-down.
//!
//! Suppresses excessive parent churn in the spanning tree via two
//! complementary mechanisms, both owned by [`TreeState`](super::TreeState):
//!
//! - **Hold-down**: after a parent switch, non-mandatory re-evaluation is
//!   suppressed for a configurable window (`0` = disabled). Mandatory
//!   switches (parent lost, smaller root found) bypass it.
//! - **Flap dampening**: if more than `flap_threshold` switches occur within
//!   `flap_window`, further non-mandatory switches are suppressed for
//!   `flap_dampening_duration`.
//!
//! The monotonic clock is injected: every timing method takes a `now_ms: u64`
//! (monotonic milliseconds, read by the shell from `crate::time::mono_ms`), and
//! all timers/durations are stored as plain `u64` milliseconds. Configuration
//! setters accept seconds (matching the node config) and store the value scaled
//! to milliseconds so the comparisons stay in one unit.

/// Flap-dampening / hold-down state for a node's parent selection.
///
/// Groups the flap-detection timers behind a single struct so the tree
/// ranking in [`TreeState`](super::TreeState) drives them through a small
/// method surface, mirroring the routing / discovery limiter idiom. All
/// timers are monotonic milliseconds; the shell injects `now_ms`.
pub(crate) struct FlapDampener {
    /// Hold-down period after a parent switch, in ms (0 = disabled).
    hold_down: u64,
    /// Monotonic ms of last parent switch (for hold-down enforcement).
    last_parent_switch: Option<u64>,
    /// Number of parent switches in the current flap window.
    flap_count: u32,
    /// Monotonic ms of the start of the current flap counting window.
    flap_window_start: Option<u64>,
    /// If dampened, suppressed until this monotonic ms.
    flap_dampening_until: Option<u64>,
    /// Flap threshold: max switches before dampening engages.
    flap_threshold: u32,
    /// Flap window duration, in ms.
    flap_window: u64,
    /// Dampening duration when threshold exceeded, in ms.
    flap_dampening_duration: u64,
}

impl FlapDampener {
    /// Create with the default flap parameters (hold-down disabled).
    pub(crate) fn new() -> Self {
        Self {
            hold_down: 0,
            last_parent_switch: None,
            flap_count: 0,
            flap_window_start: None,
            flap_dampening_until: None,
            flap_threshold: 4,
            flap_window: 60_000,
            flap_dampening_duration: 120_000,
        }
    }

    /// Set the hold-down duration after parent switches (seconds).
    pub(crate) fn set_hold_down(&mut self, secs: u64) {
        self.hold_down = secs.saturating_mul(1000);
    }

    /// Configure flap dampening parameters (durations in seconds).
    pub(crate) fn set_flap_dampening(
        &mut self,
        threshold: u32,
        window_secs: u64,
        dampening_secs: u64,
    ) {
        self.flap_threshold = threshold;
        self.flap_window = window_secs.saturating_mul(1000);
        self.flap_dampening_duration = dampening_secs.saturating_mul(1000);
    }

    /// Stamp the time of a parent switch (called on every `set_parent`,
    /// whether or not the parent actually changed). `now_ms` is the injected
    /// monotonic time in milliseconds.
    pub(crate) fn mark_switch(&mut self, now_ms: u64) {
        self.last_parent_switch = Some(now_ms);
    }

    /// Record a parent switch for flap detection.
    /// Returns true if dampening was just engaged. `now_ms` is the injected
    /// monotonic time in milliseconds.
    pub(crate) fn record_parent_switch(&mut self, now_ms: u64) -> bool {
        // Reset window if expired or not started
        match self.flap_window_start {
            Some(start) if now_ms.saturating_sub(start) < self.flap_window => {
                self.flap_count += 1;
            }
            _ => {
                self.flap_window_start = Some(now_ms);
                self.flap_count = 1;
            }
        }

        // Check threshold
        if self.flap_count >= self.flap_threshold && self.flap_dampening_until.is_none() {
            self.flap_dampening_until = Some(now_ms + self.flap_dampening_duration);
            return true;
        }
        false
    }

    /// Check if flap dampening is currently active. `now_ms` is the injected
    /// monotonic time in milliseconds.
    pub(crate) fn is_flap_dampened(&self, now_ms: u64) -> bool {
        match self.flap_dampening_until {
            Some(until) => now_ms < until,
            None => false,
        }
    }

    /// Whether hold-down currently suppresses a non-mandatory re-evaluation.
    /// `now_ms` is the injected monotonic time in milliseconds.
    pub(crate) fn is_hold_down_active(&self, now_ms: u64) -> bool {
        self.hold_down != 0
            && self
                .last_parent_switch
                .is_some_and(|last| now_ms.saturating_sub(last) < self.hold_down)
    }
}
