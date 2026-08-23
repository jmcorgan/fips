//! Routing error signal rate limiting.
//!
//! Prevents routing error floods (CoordsRequired / PathBroken) by
//! rate-limiting error signals per destination address at transit nodes.
//!
//! Runtime-agnostic: the clock is injected as `now_ms` (Unix milliseconds,
//! the `Node::now_ms()` wall-clock basis) rather than read internally, and
//! per-destination state lives in an `alloc` `BTreeMap` for `no_std`
//! portability and deterministic ordering.

use crate::NodeAddr;
use crate::proto::rate_limit::{PerAddrRateLimiter, RecordOutcome};

/// Default minimum interval between error signals: 100 ms (max 10 errors/sec
/// per destination).
const DEFAULT_MIN_INTERVAL_MS: u64 = 100;

/// Maximum age of a per-destination entry before cleanup: 10 s.
const MAX_AGE_MS: u64 = 10_000;

/// Rate limiter for routing error signals (CoordsRequired / PathBroken).
///
/// Tracks the last time a routing error was sent for each destination
/// address and enforces a minimum interval to prevent floods.
/// What the limiter decided about one candidate routing-error signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitVerdict {
    /// Send it; the destination was recorded.
    Admit,
    /// Send it, but the destination map was full so the destination was not
    /// recorded and the interval will not suppress its successor. Emission
    /// stays bounded by the per-peer error budget in this state.
    AdmitAtCapacity,
    /// Suppress it; an error for this destination went out within the interval.
    Suppress,
}

pub struct RoutingErrorRateLimiter(PerAddrRateLimiter);

impl RoutingErrorRateLimiter {
    /// Create a new rate limiter.
    ///
    /// Default: max 10 errors/sec per destination (100ms interval).
    pub fn new() -> Self {
        Self(PerAddrRateLimiter::new(DEFAULT_MIN_INTERVAL_MS, MAX_AGE_MS))
    }

    /// Create a rate limiter with a custom minimum interval in milliseconds.
    pub fn with_interval_ms(min_interval_ms: u64) -> Self {
        Self(PerAddrRateLimiter::new(min_interval_ms, MAX_AGE_MS))
    }

    /// Check if we should send a routing error for this destination at
    /// `now_ms` (Unix milliseconds).
    ///
    /// Returns true if enough time has passed since the last error for
    /// this destination, or if this is the first error. Updates internal
    /// state when returning true.
    pub fn should_send(&mut self, dest_addr: &NodeAddr, now_ms: u64) -> bool {
        self.check(dest_addr, now_ms) != LimitVerdict::Suppress
    }

    /// Decide one candidate error signal, distinguishing an ordinary admit
    /// from one made only because the destination map was full.
    ///
    /// The caller needs the difference because the two say different things
    /// about the node: `AdmitAtCapacity` means the interval gate is no longer
    /// suppressing anything for this destination, and only the per-peer budget
    /// is bounding emission.
    pub fn check(&mut self, dest_addr: &NodeAddr, now_ms: u64) -> LimitVerdict {
        match self.0.check_and_record(dest_addr, now_ms) {
            RecordOutcome::Admit => LimitVerdict::Admit,
            RecordOutcome::AdmitAtCapacity => LimitVerdict::AdmitAtCapacity,
            RecordOutcome::Suppress => LimitVerdict::Suppress,
        }
    }

    /// Remove entries older than max_age.
    #[cfg(test)]
    pub(crate) fn cleanup(&mut self, now_ms: u64) {
        self.0.cleanup(now_ms);
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Sweeps the inner map has run since construction. Read by the test
    /// holding the amortization property.
    #[cfg(test)]
    pub(crate) fn sweeps(&self) -> u64 {
        self.0.sweeps()
    }
}

impl Default for RoutingErrorRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}
