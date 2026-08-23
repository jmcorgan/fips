//! Shared `proto` rate-limiting / backoff primitives: a per-address
//! minimum-interval limiter and an exponential backoff helper, hoisted out of
//! the subsystem `limits.rs` files.

use crate::NodeAddr;
use alloc::collections::BTreeMap;

/// Maximum number of addresses one limiter remembers at once.
///
/// A hard ceiling on the map a sender can grow by varying the address it keys
/// on, which for the routing-error limiter is a field the sender picks freely.
/// Raising it costs one `NodeAddr` plus one `u64` per entry and buys interval
/// suppression across more simultaneously-active addresses; lowering it makes
/// [`RecordOutcome::AdmitAtCapacity`] the common case sooner, which weakens the
/// interval gate but never the caller's own budget.
pub(crate) const MAX_ENTRIES: usize = 4096;

/// Fraction of `max_age_ms` between amortized sweeps.
///
/// The sweep is a full-map `retain`, so running it on every admit made
/// per-event cost linear in a map the sender sizes. Eight sweeps per entry
/// lifetime keeps expired entries from accumulating without putting the scan on
/// the per-event path.
const SWEEPS_PER_MAX_AGE: u64 = 8;

/// What the limiter decided about one candidate event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordOutcome {
    /// Admit it; the address was recorded.
    Admit,
    /// Admit it, but the map was full so the address was not recorded and the
    /// interval will not suppress its successor.
    ///
    /// This gate fails open deliberately. Failing closed would turn a full map
    /// into node-wide silence, and the map is fullest exactly during partition
    /// healing, when many destinations are legitimately unroutable at once and
    /// sources most need the signal.
    AdmitAtCapacity,
    /// Suppress it; an event for this address occurred within the interval.
    Suppress,
}

/// Per-address minimum-interval rate limiter. Tracks the last event time per
/// address and enforces a minimum interval, evicting entries older than a max
/// age. The map is bounded and its sweep is amortized; see [`MAX_ENTRIES`] and
/// [`SWEEPS_PER_MAX_AGE`].
pub(crate) struct PerAddrRateLimiter {
    last: BTreeMap<NodeAddr, u64>,
    min_interval_ms: u64,
    max_age_ms: u64,
    last_sweep_ms: u64,
    /// Sweeps run since construction. Read by the test that holds the
    /// amortization property: a full-map scan per admit is the denial-of-
    /// service multiplier this counter exists to catch coming back.
    sweeps: u64,
}

impl PerAddrRateLimiter {
    pub(crate) fn new(min_interval_ms: u64, max_age_ms: u64) -> Self {
        Self {
            last: BTreeMap::new(),
            min_interval_ms,
            max_age_ms,
            last_sweep_ms: 0,
            sweeps: 0,
        }
    }

    /// Decide one event for `addr`, recording `now_ms` when it is admitted and
    /// there is room. See [`RecordOutcome`] for why a full map admits rather
    /// than refuses.
    pub(crate) fn check_and_record(&mut self, addr: &NodeAddr, now_ms: u64) -> RecordOutcome {
        let known = self.last.get(addr).copied();
        if let Some(last) = known
            && now_ms.saturating_sub(last) < self.min_interval_ms
        {
            return RecordOutcome::Suppress;
        }
        self.maybe_sweep(now_ms);
        if known.is_none() && self.last.len() >= MAX_ENTRIES {
            return RecordOutcome::AdmitAtCapacity;
        }
        self.last.insert(*addr, now_ms);
        RecordOutcome::Admit
    }

    /// Run the expiry sweep at most once per `max_age_ms / SWEEPS_PER_MAX_AGE`.
    fn maybe_sweep(&mut self, now_ms: u64) {
        let interval = (self.max_age_ms / SWEEPS_PER_MAX_AGE).max(1);
        if now_ms.saturating_sub(self.last_sweep_ms) < interval && self.last_sweep_ms != 0 {
            return;
        }
        self.last_sweep_ms = now_ms;
        self.sweeps = self.sweeps.saturating_add(1);
        self.cleanup(now_ms);
    }

    pub(crate) fn cleanup(&mut self, now_ms: u64) {
        self.last
            .retain(|_, &mut last| now_ms.saturating_sub(last) < self.max_age_ms);
    }

    #[cfg(test)]
    pub(crate) fn sweeps(&self) -> u64 {
        self.sweeps
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
