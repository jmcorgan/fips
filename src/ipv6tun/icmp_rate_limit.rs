//! ICMP Packet Too Big rate limiting.
//!
//! Prevents ICMP flood from repeated oversized packets by rate-limiting
//! ICMP Packet Too Big messages per source address, with a token bucket for
//! each source (RFC 4443 Section 2.4 (f)).

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use crate::time::HostInstant;
use fips_core::node::rate_limit::TokenBucket;

/// The Packet Too Big a source may be sent at once after a quiet spell: the
/// bucket size RFC 4443 Section 2.4 (f) gives as a default for a small or
/// mid-size device, as for Destination Unreachable.
pub(crate) const PACKET_TOO_BIG_BURST: u32 = 10;

/// The time in which a source's bucket regains one Packet Too Big once its
/// burst is spent: ten a second, the long-term rate RFC 4443 Section 2.4 (f)
/// suggests.
pub(crate) const PACKET_TOO_BIG_INTERVAL: Duration = Duration::from_millis(100);

/// How long a source is kept after its last check, at the least. A bucket
/// left this long has refilled, so dropping it changes no answer.
const MAX_AGE: Duration = Duration::from_secs(10);

/// One source's bucket. It counts the instants it is given on the host's
/// monotonic clock and never reads the clock itself.
type Bucket = TokenBucket<crate::time::HostClock>;

/// Rate limiter for ICMP Packet Too Big messages.
///
/// Each source address has a token bucket of [`PACKET_TOO_BIG_BURST`],
/// refilled at one per interval ([`PACKET_TOO_BIG_INTERVAL`] by default), so
/// a burst of oversized packets is answered for each while a flood is held
/// to the refill rate.
pub struct IcmpRateLimiter {
    /// Each source's bucket, and when the source was last checked.
    sources: HashMap<Ipv6Addr, (Bucket, Instant)>,
    /// Tokens each bucket regains a second.
    rate: f64,
    /// Maximum age of entries before cleanup (prevents unbounded growth).
    max_age: Duration,
}

impl IcmpRateLimiter {
    /// Create a new rate limiter: a burst of ten for each source, then ten a
    /// second.
    pub fn new() -> Self {
        Self::with_interval(PACKET_TOO_BIG_INTERVAL)
    }

    /// Create a rate limiter whose buckets regain one token per `interval`.
    /// An interval of zero is taken as one nanosecond.
    pub fn with_interval(interval: Duration) -> Self {
        let interval = interval.max(Duration::from_nanos(1));
        Self {
            sources: HashMap::new(),
            rate: 1.0 / interval.as_secs_f64(),
            max_age: MAX_AGE.max(interval.saturating_mul(PACKET_TOO_BIG_BURST)),
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
    /// Returns true if the source's bucket, refilled up to `now`, holds a
    /// token, and spends it; a source checked for the first time has a full
    /// bucket. If true is returned, entries not checked within the maximum
    /// age at `now` are dropped.
    pub(crate) fn check(&mut self, src_addr: Ipv6Addr, now: Instant) -> bool {
        let at = HostInstant::from(now);
        let rate = self.rate;
        let (bucket, last) = self
            .sources
            .entry(src_addr)
            .or_insert_with(|| (Bucket::with_params(PACKET_TOO_BIG_BURST, rate, at), now));
        *last = now;
        if !bucket.try_acquire(at) {
            return false;
        }

        // Cleanup old entries to prevent unbounded growth
        self.cleanup(now);

        true
    }

    /// Remove entries older than max_age.
    fn cleanup(&mut self, now: Instant) {
        self.sources
            .retain(|_, (_, last)| now.duration_since(*last) < self.max_age);
    }

    /// Get the number of tracked sources.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    /// Check if there are no tracked sources.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
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
