//! ICMP Packet Too Big rate limiting.
//!
//! Prevents ICMP flood from repeated oversized packets by rate-limiting
//! ICMP Packet Too Big messages per source address.

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

/// Rate limiter for ICMP Packet Too Big messages.
///
/// Tracks the last time an ICMP PTB was sent to each source address
/// and enforces a minimum interval between messages to prevent floods.
pub struct IcmpRateLimiter {
    /// Maps source IPv6 address to the last time we sent ICMP PTB to it.
    last_sent: HashMap<Ipv6Addr, Instant>,
    /// Minimum interval between ICMP messages to the same source.
    min_interval: Duration,
    /// Maximum age of entries before cleanup (prevents unbounded growth).
    max_age: Duration,
}

impl IcmpRateLimiter {
    /// Create a new rate limiter.
    ///
    /// Default: max 10 ICMP/sec per source (100ms interval).
    pub fn new() -> Self {
        Self {
            last_sent: HashMap::new(),
            min_interval: Duration::from_millis(100),
            max_age: Duration::from_secs(10),
        }
    }

    /// Create a rate limiter with custom interval.
    pub fn with_interval(min_interval: Duration) -> Self {
        Self {
            last_sent: HashMap::new(),
            min_interval,
            max_age: Duration::from_secs(10),
        }
    }

    /// Check if we should send an ICMP PTB to this source address.
    ///
    /// Returns true if enough time has passed since the last ICMP to this source,
    /// or if this is the first ICMP to this source.
    ///
    /// If true is returned, the internal state is updated to record this send.
    pub fn should_send(&mut self, src_addr: Ipv6Addr) -> bool {
        let now = Instant::now();

        // Check if we've sent to this source recently
        if let Some(&last) = self.last_sent.get(&src_addr)
            && now.duration_since(last) < self.min_interval
        {
            return false; // Too soon, rate limit
        }

        // Update last sent time
        self.last_sent.insert(src_addr, now);

        // Cleanup old entries to prevent unbounded growth
        self.cleanup(now);

        true
    }

    /// Remove entries older than max_age.
    fn cleanup(&mut self, now: Instant) {
        self.last_sent.retain(|_, &mut last| {
            now.duration_since(last) < self.max_age
        });
    }

    /// Get the number of tracked sources.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.last_sent.len()
    }

    /// Check if there are no tracked sources.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.last_sent.is_empty()
    }
}

impl Default for IcmpRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_first_send_allowed() {
        let mut limiter = IcmpRateLimiter::new();
        let addr: Ipv6Addr = "fd00::1".parse().unwrap();

        assert!(limiter.should_send(addr));
    }

    #[test]
    fn test_rapid_sends_rate_limited() {
        let mut limiter = IcmpRateLimiter::new();
        let addr: Ipv6Addr = "fd00::1".parse().unwrap();

        // First send should succeed
        assert!(limiter.should_send(addr));

        // Immediate second send should be rate limited
        assert!(!limiter.should_send(addr));
        assert!(!limiter.should_send(addr));
    }

    #[test]
    fn test_different_sources_independent() {
        let mut limiter = IcmpRateLimiter::new();
        let addr1: Ipv6Addr = "fd00::1".parse().unwrap();
        let addr2: Ipv6Addr = "fd00::2".parse().unwrap();

        // Both sources should be allowed independently
        assert!(limiter.should_send(addr1));
        assert!(limiter.should_send(addr2));

        // But rapid resends to same source are limited
        assert!(!limiter.should_send(addr1));
        assert!(!limiter.should_send(addr2));
    }

    #[test]
    fn test_send_allowed_after_interval() {
        let mut limiter = IcmpRateLimiter::with_interval(Duration::from_millis(50));
        let addr: Ipv6Addr = "fd00::1".parse().unwrap();

        // First send
        assert!(limiter.should_send(addr));

        // Wait for interval to pass
        thread::sleep(Duration::from_millis(60));

        // Second send should now be allowed
        assert!(limiter.should_send(addr));
    }

    #[test]
    fn test_cleanup_removes_old_entries() {
        let mut limiter = IcmpRateLimiter::new();
        let addr1: Ipv6Addr = "fd00::1".parse().unwrap();
        let addr2: Ipv6Addr = "fd00::2".parse().unwrap();

        // Send to both addresses
        assert!(limiter.should_send(addr1));
        assert!(limiter.should_send(addr2));
        assert_eq!(limiter.len(), 2);

        // Manually trigger cleanup with a future timestamp
        let future = Instant::now() + Duration::from_secs(11);
        limiter.cleanup(future);

        // All entries should be cleaned up
        assert_eq!(limiter.len(), 0);
    }

    #[test]
    fn test_cleanup_preserves_recent_entries() {
        let mut limiter = IcmpRateLimiter::new();
        let addr: Ipv6Addr = "fd00::1".parse().unwrap();

        assert!(limiter.should_send(addr));
        assert_eq!(limiter.len(), 1);

        // Cleanup with current time shouldn't remove recent entry
        limiter.cleanup(Instant::now());
        assert_eq!(limiter.len(), 1);
    }
}