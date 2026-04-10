//! Discovery protocol rate limiting and backoff.
//!
//! Two complementary mechanisms:
//!
//! - **`DiscoveryBackoff`** (originator-side): Exponential backoff for failed
//!   lookups. After a lookup times out, suppresses re-initiation with
//!   increasing delays (30s → 60s → 300s cap). Reset on topology changes
//!   (parent change, new peer, first RTT, reconnection).
//!
//! - **`DiscoveryForwardRateLimiter`** (transit-side): Per-target minimum
//!   interval for forwarded requests. Defense-in-depth against misbehaving
//!   nodes generating fresh request_ids at high rate.

use crate::NodeAddr;
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ============================================================================
// Originator-side: Discovery Backoff
// ============================================================================

/// Default base backoff after first lookup failure.
const DEFAULT_BACKOFF_BASE_SECS: u64 = 30;

/// Default maximum backoff cap.
const DEFAULT_BACKOFF_MAX_SECS: u64 = 300;

/// Backoff multiplier per consecutive failure.
const BACKOFF_MULTIPLIER: u64 = 2;

/// Exponential backoff for failed discovery lookups.
///
/// Tracks targets whose lookups have timed out and suppresses
/// re-initiation with increasing delays. Cleared on topology changes.
pub struct DiscoveryBackoff {
    /// Maps target → (suppress_until, consecutive_failures).
    entries: HashMap<NodeAddr, BackoffEntry>,
    /// Base backoff duration (first failure).
    base: Duration,
    /// Maximum backoff cap.
    max: Duration,
}

struct BackoffEntry {
    /// Don't re-initiate until this instant.
    suppress_until: Instant,
    /// Consecutive failures (drives exponential backoff).
    failures: u32,
}

impl DiscoveryBackoff {
    /// Create with default parameters (30s base, 300s cap).
    pub fn new() -> Self {
        Self::with_params(DEFAULT_BACKOFF_BASE_SECS, DEFAULT_BACKOFF_MAX_SECS)
    }

    /// Create with custom base and max backoff in seconds.
    pub fn with_params(base_secs: u64, max_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            base: Duration::from_secs(base_secs),
            max: Duration::from_secs(max_secs),
        }
    }

    /// Check if a lookup for this target is suppressed.
    ///
    /// Returns true if the target is in backoff and should not be
    /// looked up yet.
    pub fn is_suppressed(&self, target: &NodeAddr) -> bool {
        if let Some(entry) = self.entries.get(target) {
            Instant::now() < entry.suppress_until
        } else {
            false
        }
    }

    /// Record a lookup failure (timeout) for a target.
    ///
    /// Increments the failure count and sets the next suppression
    /// window using exponential backoff.
    pub fn record_failure(&mut self, target: &NodeAddr) {
        let now = Instant::now();
        let failures = self.entries.get(target).map_or(0, |e| e.failures) + 1;

        let backoff_secs = self
            .base
            .as_secs()
            .saturating_mul(BACKOFF_MULTIPLIER.saturating_pow(failures.saturating_sub(1)));
        let backoff = Duration::from_secs(backoff_secs.min(self.max.as_secs()));

        self.entries.insert(
            *target,
            BackoffEntry {
                suppress_until: now + backoff,
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

impl Default for DiscoveryBackoff {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Transit-side: Discovery Forward Rate Limiter
// ============================================================================

/// Default minimum interval between forwarded lookups for the same target.
const DEFAULT_FORWARD_MIN_INTERVAL: Duration = Duration::from_secs(2);

/// Maximum age of entries before cleanup.
const FORWARD_MAX_AGE: Duration = Duration::from_secs(60);

/// Rate limiter for forwarded discovery requests.
///
/// Tracks the last time a LookupRequest was forwarded for each target
/// and enforces a minimum interval to prevent floods from misbehaving
/// nodes generating fresh request_ids.
pub struct DiscoveryForwardRateLimiter {
    last_forwarded: HashMap<NodeAddr, Instant>,
    min_interval: Duration,
    max_age: Duration,
}

impl DiscoveryForwardRateLimiter {
    /// Create with default parameters (2s interval).
    pub fn new() -> Self {
        Self {
            last_forwarded: HashMap::new(),
            min_interval: DEFAULT_FORWARD_MIN_INTERVAL,
            max_age: FORWARD_MAX_AGE,
        }
    }

    /// Create with a custom minimum interval.
    pub fn with_interval(min_interval: Duration) -> Self {
        Self {
            last_forwarded: HashMap::new(),
            min_interval,
            max_age: FORWARD_MAX_AGE,
        }
    }

    /// Check if we should forward a lookup for this target.
    ///
    /// Returns true if enough time has passed since the last forward
    /// for this target. Updates internal state when returning true.
    pub fn should_forward(&mut self, target: &NodeAddr) -> bool {
        let now = Instant::now();

        if let Some(&last) = self.last_forwarded.get(target)
            && now.duration_since(last) < self.min_interval
        {
            return false;
        }

        self.last_forwarded.insert(*target, now);
        self.cleanup(now);
        true
    }

    /// Replace the minimum interval (e.g., set to zero to disable).
    #[cfg(test)]
    pub fn set_interval(&mut self, interval: Duration) {
        self.min_interval = interval;
    }

    /// Remove entries older than max_age.
    fn cleanup(&mut self, now: Instant) {
        self.last_forwarded
            .retain(|_, &mut last| now.duration_since(last) < self.max_age);
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.last_forwarded.len()
    }
}

impl Default for DiscoveryForwardRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    // --- DiscoveryBackoff tests ---

    #[test]
    fn test_backoff_not_suppressed_initially() {
        let backoff = DiscoveryBackoff::new();
        assert!(!backoff.is_suppressed(&addr(1)));
    }

    #[test]
    fn test_backoff_suppressed_after_failure() {
        let mut backoff = DiscoveryBackoff::new();
        backoff.record_failure(&addr(1));
        assert!(backoff.is_suppressed(&addr(1)));
        // Different target not affected
        assert!(!backoff.is_suppressed(&addr(2)));
    }

    #[test]
    fn test_backoff_cleared_on_success() {
        let mut backoff = DiscoveryBackoff::new();
        backoff.record_failure(&addr(1));
        assert!(backoff.is_suppressed(&addr(1)));

        backoff.record_success(&addr(1));
        assert!(!backoff.is_suppressed(&addr(1)));
    }

    #[test]
    fn test_backoff_reset_all() {
        let mut backoff = DiscoveryBackoff::new();
        backoff.record_failure(&addr(1));
        backoff.record_failure(&addr(2));
        assert_eq!(backoff.len(), 2);

        backoff.reset_all();
        assert_eq!(backoff.len(), 0);
        assert!(!backoff.is_suppressed(&addr(1)));
    }

    #[test]
    fn test_backoff_exponential() {
        let mut backoff = DiscoveryBackoff::with_params(1, 300);

        // First failure: 1s backoff
        backoff.record_failure(&addr(1));
        assert_eq!(backoff.failure_count(&addr(1)), 1);

        // Second failure: 2s backoff
        backoff.record_failure(&addr(1));
        assert_eq!(backoff.failure_count(&addr(1)), 2);

        // Third failure: 4s backoff
        backoff.record_failure(&addr(1));
        assert_eq!(backoff.failure_count(&addr(1)), 3);
    }

    #[test]
    fn test_backoff_expires() {
        let mut backoff = DiscoveryBackoff::with_params(0, 0);
        backoff.record_failure(&addr(1));
        // With 0s backoff, should not be suppressed
        assert!(!backoff.is_suppressed(&addr(1)));
    }

    #[test]
    fn test_backoff_capped() {
        let mut backoff = DiscoveryBackoff::with_params(1, 10);

        // Record many failures
        for _ in 0..20 {
            backoff.record_failure(&addr(1));
        }

        // Backoff should be capped at max (10s), not overflow
        let entry = backoff.entries.get(&addr(1)).unwrap();
        let remaining = entry.suppress_until.duration_since(Instant::now());
        assert!(remaining <= Duration::from_secs(11));
    }

    // --- DiscoveryForwardRateLimiter tests ---

    #[test]
    fn test_forward_first_allowed() {
        let mut limiter = DiscoveryForwardRateLimiter::new();
        assert!(limiter.should_forward(&addr(1)));
    }

    #[test]
    fn test_forward_rapid_rate_limited() {
        let mut limiter = DiscoveryForwardRateLimiter::new();
        assert!(limiter.should_forward(&addr(1)));
        assert!(!limiter.should_forward(&addr(1)));
        assert!(!limiter.should_forward(&addr(1)));
    }

    #[test]
    fn test_forward_different_targets_independent() {
        let mut limiter = DiscoveryForwardRateLimiter::new();
        assert!(limiter.should_forward(&addr(1)));
        assert!(limiter.should_forward(&addr(2)));
        assert!(!limiter.should_forward(&addr(1)));
        assert!(!limiter.should_forward(&addr(2)));
    }

    #[test]
    fn test_forward_allowed_after_interval() {
        let mut limiter = DiscoveryForwardRateLimiter::with_interval(Duration::from_millis(100));
        assert!(limiter.should_forward(&addr(1)));

        thread::sleep(Duration::from_millis(110));

        assert!(limiter.should_forward(&addr(1)));
    }

    #[test]
    fn test_forward_cleanup_removes_old() {
        let mut limiter = DiscoveryForwardRateLimiter::new();
        assert!(limiter.should_forward(&addr(1)));
        assert!(limiter.should_forward(&addr(2)));
        assert_eq!(limiter.len(), 2);

        let future = Instant::now() + Duration::from_secs(61);
        limiter.cleanup(future);
        assert_eq!(limiter.len(), 0);
    }

    #[test]
    fn test_forward_cleanup_preserves_recent() {
        let mut limiter = DiscoveryForwardRateLimiter::new();
        assert!(limiter.should_forward(&addr(1)));
        assert_eq!(limiter.len(), 1);

        limiter.cleanup(Instant::now());
        assert_eq!(limiter.len(), 1);
    }
}
