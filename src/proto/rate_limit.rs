//! Shared `proto` rate-limiting / backoff primitives: a per-address
//! minimum-interval limiter and an exponential backoff helper, hoisted out of
//! the subsystem `limits.rs` files.

use crate::NodeAddr;
use alloc::collections::BTreeMap;

/// Per-address minimum-interval rate limiter. Tracks the last event time per
/// address and enforces a minimum interval, evicting entries older than a max age.
pub(crate) struct PerAddrRateLimiter {
    last: BTreeMap<NodeAddr, u64>,
    min_interval_ms: u64,
    max_age_ms: u64,
}

impl PerAddrRateLimiter {
    pub(crate) fn new(min_interval_ms: u64, max_age_ms: u64) -> Self {
        Self {
            last: BTreeMap::new(),
            min_interval_ms,
            max_age_ms,
        }
    }

    /// Returns true (and records `now_ms`) if enough time has elapsed since the
    /// last event for `addr`, or this is the first; false if within the interval.
    pub(crate) fn check_and_record(&mut self, addr: &NodeAddr, now_ms: u64) -> bool {
        if let Some(&last) = self.last.get(addr)
            && now_ms.saturating_sub(last) < self.min_interval_ms
        {
            return false;
        }
        self.last.insert(*addr, now_ms);
        self.cleanup(now_ms);
        true
    }

    pub(crate) fn cleanup(&mut self, now_ms: u64) {
        self.last
            .retain(|_, &mut last| now_ms.saturating_sub(last) < self.max_age_ms);
    }

    #[cfg(test)]
    pub(crate) fn set_interval_ms(&mut self, interval_ms: u64) {
        self.min_interval_ms = interval_ms;
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.last.len()
    }
}

/// Exponential (base-2) backoff: `base_ms * 2^exponent`, saturating, capped at
/// `cap_ms`. Shared by the discovery originator backoff (exponent = failures-1)
/// and the FMP retry scheduler (exponent = retry_count).
pub(crate) fn backoff_ms(exponent: u32, base_ms: u64, cap_ms: u64) -> u64 {
    let multiplier = 1u64.checked_shl(exponent).unwrap_or(u64::MAX);
    base_ms.saturating_mul(multiplier).min(cap_ms)
}
