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
use crate::proto::rate_limit::PerAddrRateLimiter;

/// Default minimum interval between error signals: 100 ms (max 10 errors/sec
/// per destination).
const DEFAULT_MIN_INTERVAL_MS: u64 = 100;

/// Maximum age of a per-destination entry before cleanup: 10 s.
const MAX_AGE_MS: u64 = 10_000;

/// Rate limiter for routing error signals (CoordsRequired / PathBroken).
///
/// Tracks the last time a routing error was sent for each destination
/// address and enforces a minimum interval to prevent floods.
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
        self.0.check_and_record(dest_addr, now_ms)
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
}

impl Default for RoutingErrorRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}
