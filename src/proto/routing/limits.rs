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
use alloc::collections::BTreeMap;

/// Default minimum interval between error signals: 100 ms (max 10 errors/sec
/// per destination).
const DEFAULT_MIN_INTERVAL_MS: u64 = 100;

/// Maximum age of a per-destination entry before cleanup: 10 s.
const MAX_AGE_MS: u64 = 10_000;

/// Rate limiter for routing error signals (CoordsRequired / PathBroken).
///
/// Tracks the last time a routing error was sent for each destination
/// address and enforces a minimum interval to prevent floods.
pub struct RoutingErrorRateLimiter {
    /// Maps destination NodeAddr to the last time (Unix ms) we sent an error
    /// about it.
    last_sent: BTreeMap<NodeAddr, u64>,
    /// Minimum interval between error signals for the same destination (ms).
    min_interval_ms: u64,
    /// Maximum age of entries before cleanup (ms).
    max_age_ms: u64,
}

impl RoutingErrorRateLimiter {
    /// Create a new rate limiter.
    ///
    /// Default: max 10 errors/sec per destination (100ms interval).
    pub fn new() -> Self {
        Self {
            last_sent: BTreeMap::new(),
            min_interval_ms: DEFAULT_MIN_INTERVAL_MS,
            max_age_ms: MAX_AGE_MS,
        }
    }

    /// Create a rate limiter with a custom minimum interval in milliseconds.
    pub fn with_interval_ms(min_interval_ms: u64) -> Self {
        Self {
            last_sent: BTreeMap::new(),
            min_interval_ms,
            max_age_ms: MAX_AGE_MS,
        }
    }

    /// Check if we should send a routing error for this destination at
    /// `now_ms` (Unix milliseconds).
    ///
    /// Returns true if enough time has passed since the last error for
    /// this destination, or if this is the first error. Updates internal
    /// state when returning true.
    pub fn should_send(&mut self, dest_addr: &NodeAddr, now_ms: u64) -> bool {
        if let Some(&last) = self.last_sent.get(dest_addr)
            && now_ms.saturating_sub(last) < self.min_interval_ms
        {
            return false;
        }

        self.last_sent.insert(*dest_addr, now_ms);
        self.cleanup(now_ms);
        true
    }

    /// Remove entries older than max_age.
    pub(crate) fn cleanup(&mut self, now_ms: u64) {
        self.last_sent
            .retain(|_, &mut last| now_ms.saturating_sub(last) < self.max_age_ms);
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.last_sent.len()
    }
}

impl Default for RoutingErrorRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}
