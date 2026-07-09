//! Mesh lookup protocol rate limiting and backoff.
//!
//! Two complementary mechanisms:
//!
//! - **`LookupBackoff`** (originator-side, optional): Exponential
//!   suppression of fresh lookups after the per-attempt sequence in
//!   `node.lookup.attempt_timeouts_secs` has been exhausted.
//!   **Disabled by default** (base/cap = 0); the per-attempt sequence
//!   is the only retry pacing in the standard configuration. Reset on
//!   topology changes (parent change, new peer, first RTT, reconnection).
//!
//! - **`LookupForwardRateLimiter`** (transit-side): Per-target minimum
//!   interval for forwarded requests. Defense-in-depth against misbehaving
//!   nodes generating fresh request_ids at high rate.

use crate::NodeAddr;
use crate::proto::rate_limit::PerAddrRateLimiter;
use alloc::collections::BTreeMap;

// ============================================================================
// Receive-side: Request dedup cache bound
// ============================================================================

/// Maximum number of recent LookupRequests retained for dedup and
/// reverse-path routing before the cache is treated as full.
pub(crate) const MAX_RECENT_LOOKUP_REQUESTS: usize = 4096;

// ============================================================================
// Originator-side: Lookup Backoff
// ============================================================================

/// Default base backoff after first lookup failure. `0` = disabled.
const DEFAULT_BACKOFF_BASE_SECS: u64 = 0;

/// Default maximum backoff cap. `0` = disabled.
const DEFAULT_BACKOFF_MAX_SECS: u64 = 0;

/// Exponential backoff for failed lookups.
///
/// Tracks targets whose lookups have timed out and suppresses
/// re-initiation with increasing delays. Cleared on topology changes.
pub struct LookupBackoff {
    /// Maps target → (suppress_until, consecutive_failures).
    pub(crate) entries: BTreeMap<NodeAddr, BackoffEntry>,
    /// Base backoff in milliseconds (first failure).
    base_ms: u64,
    /// Maximum backoff cap in milliseconds.
    max_ms: u64,
}

pub(crate) struct BackoffEntry {
    /// Don't re-initiate until this time (injected `now_ms`).
    pub(crate) suppress_until_ms: u64,
    /// Consecutive failures (drives exponential backoff).
    failures: u32,
}

impl LookupBackoff {
    /// Create with default parameters (disabled — base/cap = 0).
    pub fn new() -> Self {
        Self::with_params(DEFAULT_BACKOFF_BASE_SECS, DEFAULT_BACKOFF_MAX_SECS)
    }

    /// Create with custom base and max backoff in seconds.
    pub fn with_params(base_secs: u64, max_secs: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            base_ms: base_secs * 1000,
            max_ms: max_secs * 1000,
        }
    }

    /// Check if a lookup for this target is suppressed.
    ///
    /// Returns true if the target is in backoff and should not be
    /// looked up yet.
    pub fn is_suppressed(&self, target: &NodeAddr, now_ms: u64) -> bool {
        if let Some(e) = self.entries.get(target) {
            now_ms < e.suppress_until_ms
        } else {
            false
        }
    }

    /// Record a lookup failure (timeout) for a target.
    ///
    /// Increments the failure count and sets the next suppression
    /// window using exponential backoff.
    pub fn record_failure(&mut self, target: &NodeAddr, now_ms: u64) {
        let failures = self.entries.get(target).map_or(0, |e| e.failures) + 1;

        let backoff_ms = crate::proto::rate_limit::backoff_ms(
            failures.saturating_sub(1),
            self.base_ms,
            self.max_ms,
        );

        self.entries.insert(
            *target,
            BackoffEntry {
                suppress_until_ms: now_ms + backoff_ms,
                failures,
            },
        );
    }

    /// Record a successful lookup — remove backoff for this target.
    pub fn record_success(&mut self, target: &NodeAddr) {
        self.entries.remove(target);
    }

    /// Clear all backoff entries.
    ///
    /// Called on topology changes that might make previously-unreachable
    /// targets reachable (parent change, new peer, first RTT, reconnection).
    pub fn reset_all(&mut self) {
        self.entries.clear();
    }

    /// Whether any entries exist.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Current number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get the failure count for a target (for logging).
    pub fn failure_count(&self, target: &NodeAddr) -> u32 {
        self.entries.get(target).map_or(0, |e| e.failures)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

impl Default for LookupBackoff {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Transit-side: Lookup Forward Rate Limiter
// ============================================================================

/// Default minimum interval between forwarded lookups for the same target.
const DEFAULT_FORWARD_MIN_INTERVAL_MS: u64 = 2_000;

/// Maximum age of entries before cleanup.
const FORWARD_MAX_AGE_MS: u64 = 60_000;

/// Rate limiter for forwarded lookup requests.
///
/// Tracks the last time a LookupRequest was forwarded for each target
/// and enforces a minimum interval to prevent floods from misbehaving
/// nodes generating fresh request_ids.
pub struct LookupForwardRateLimiter(PerAddrRateLimiter);

impl LookupForwardRateLimiter {
    /// Create with default parameters (2s interval).
    pub fn new() -> Self {
        Self(PerAddrRateLimiter::new(
            DEFAULT_FORWARD_MIN_INTERVAL_MS,
            FORWARD_MAX_AGE_MS,
        ))
    }

    /// Create with a custom minimum interval in milliseconds.
    pub fn with_interval_ms(min_interval_ms: u64) -> Self {
        Self(PerAddrRateLimiter::new(min_interval_ms, FORWARD_MAX_AGE_MS))
    }

    /// Check if we should forward a lookup for this target.
    ///
    /// Returns true if enough time has passed since the last forward
    /// for this target. Updates internal state when returning true.
    pub fn should_forward(&mut self, target: &NodeAddr, now_ms: u64) -> bool {
        self.0.check_and_record(target, now_ms)
    }

    /// Replace the minimum interval in milliseconds (e.g., set to zero to disable).
    #[cfg(test)]
    pub fn set_interval_ms(&mut self, interval_ms: u64) {
        self.0.set_interval_ms(interval_ms);
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

impl Default for LookupForwardRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}
