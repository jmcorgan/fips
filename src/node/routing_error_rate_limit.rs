//! Routing error signal rate limiting.
//!
//! Prevents routing error floods (CoordsRequired / PathBroken) by
//! rate-limiting error signals per destination address at transit nodes.

use crate::NodeAddr;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Rate limiter for routing error signals (CoordsRequired / PathBroken).
///
/// Tracks the last time a routing error was sent for each destination
/// address and enforces a minimum interval to prevent floods.
pub struct RoutingErrorRateLimiter {
    /// Maps destination NodeAddr to the last time we sent an error about it.
    last_sent: HashMap<NodeAddr, Instant>,
    /// Minimum interval between error signals for the same destination.
    min_interval: Duration,
    /// Maximum age of entries before cleanup.
    max_age: Duration,
}

impl RoutingErrorRateLimiter {
    /// Create a new rate limiter.
    ///
    /// Default: max 10 errors/sec per destination (100ms interval).
    pub fn new() -> Self {
        Self {
            last_sent: HashMap::new(),
            min_interval: Duration::from_millis(100),
            max_age: Duration::from_secs(10),
        }
    }

    /// Create a rate limiter with a custom minimum interval.
    pub fn with_interval(min_interval: Duration) -> Self {
        Self {
            last_sent: HashMap::new(),
            min_interval,
            max_age: Duration::from_secs(10),
        }
    }

    /// Check if we should send a routing error for this destination.
    ///
    /// Returns true if enough time has passed since the last error for
    /// this destination, or if this is the first error. Updates internal
    /// state when returning true.
    pub fn should_send(&mut self, dest_addr: &NodeAddr) -> bool {
        let now = Instant::now();

        if let Some(&last) = self.last_sent.get(dest_addr)
            && now.duration_since(last) < self.min_interval
        {
            return false;
        }

        self.last_sent.insert(*dest_addr, now);
        self.cleanup(now);
        true
    }

    /// Remove entries older than max_age.
    fn cleanup(&mut self, now: Instant) {
        self.last_sent
            .retain(|_, &mut last| now.duration_since(last) < self.max_age);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    #[test]
    fn test_first_send_allowed() {
        let mut limiter = RoutingErrorRateLimiter::new();
        assert!(limiter.should_send(&addr(1)));
    }

    #[test]
    fn test_rapid_sends_rate_limited() {
        let mut limiter = RoutingErrorRateLimiter::new();
        assert!(limiter.should_send(&addr(1)));
        assert!(!limiter.should_send(&addr(1)));
        assert!(!limiter.should_send(&addr(1)));
    }

    #[test]
    fn test_different_destinations_independent() {
        let mut limiter = RoutingErrorRateLimiter::new();
        assert!(limiter.should_send(&addr(1)));
        assert!(limiter.should_send(&addr(2)));
        assert!(!limiter.should_send(&addr(1)));
        assert!(!limiter.should_send(&addr(2)));
    }

    #[test]
    fn test_send_allowed_after_interval() {
        let mut limiter = RoutingErrorRateLimiter::new();
        assert!(limiter.should_send(&addr(1)));

        thread::sleep(Duration::from_millis(110));

        assert!(limiter.should_send(&addr(1)));
    }

    #[test]
    fn test_cleanup_removes_old_entries() {
        let mut limiter = RoutingErrorRateLimiter::new();
        assert!(limiter.should_send(&addr(1)));
        assert!(limiter.should_send(&addr(2)));
        assert_eq!(limiter.len(), 2);

        let future = Instant::now() + Duration::from_secs(11);
        limiter.cleanup(future);
        assert_eq!(limiter.len(), 0);
    }

    #[test]
    fn test_cleanup_preserves_recent_entries() {
        let mut limiter = RoutingErrorRateLimiter::new();
        assert!(limiter.should_send(&addr(1)));
        assert_eq!(limiter.len(), 1);

        limiter.cleanup(Instant::now());
        assert_eq!(limiter.len(), 1);
    }

    #[test]
    fn test_with_interval_custom_rate() {
        let mut limiter = RoutingErrorRateLimiter::with_interval(Duration::from_millis(500));
        assert!(limiter.should_send(&addr(1)));
        assert!(!limiter.should_send(&addr(1)));

        // Still rate-limited after 200ms (would pass with default 100ms)
        thread::sleep(Duration::from_millis(200));
        assert!(!limiter.should_send(&addr(1)));

        // Allowed after 500ms total
        thread::sleep(Duration::from_millis(350));
        assert!(limiter.should_send(&addr(1)));
    }
}
