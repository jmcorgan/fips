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

    /// Check if we should send an ICMP PTB to this source address now.
    ///
    /// Reads the clock and judges by it, as [`Self::check`] does with the
    /// time it is given.
    pub fn should_send(&mut self, src_addr: Ipv6Addr) -> bool {
        self.check(src_addr, Instant::now())
    }

    /// Check if we should send an ICMP PTB to this source address at `now`.
    ///
    /// Returns true if at least the minimum interval has passed since the
    /// last ICMP to this source, or if this is the first ICMP to it. If true
    /// is returned, `now` is recorded as this source's last send, and entries
    /// older than the maximum age at `now` are dropped.
    pub(crate) fn check(&mut self, src_addr: Ipv6Addr, now: Instant) -> bool {
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
        self.last_sent
            .retain(|_, &mut last| now.duration_since(last) < self.max_age);
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
#[path = "tests/icmp_rate_limit.rs"]
mod tests;
