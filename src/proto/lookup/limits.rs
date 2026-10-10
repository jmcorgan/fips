//! Mesh lookup protocol rate limiting and backoff.
//!
//! Two complementary mechanisms:
//!
//! - **`LookupBackoff`** (originator-side, optional): Exponential
//!   suppression of fresh lookups after the per-attempt sequence in
//!   `node.lookup.attempt_timeouts_secs` has been exhausted.
//!   **Disabled by default** (base/cap = 0); the per-attempt sequence
//!   is the only retry pacing in the standard configuration, and nothing
//!   is recorded while it is disabled. Reset on topology changes (parent
//!   change, new peer, first RTT, reconnection). The table is bounded at
//!   [`MAX_BACKOFF_ENTRIES`]: an entry is forgotten one maximum backoff
//!   interval after its window ends, and at the bound the entry nearest
//!   expiry is evicted.
//!
//! - **`LookupForwardRateLimiter`** (transit-side): Per-target minimum
//!   interval for forwarded requests. Defense-in-depth against misbehaving
//!   nodes generating fresh request_ids at high rate.

use crate::NodeAddr;
use crate::proto::rate_limit::{PerAddrRateLimiter, RecordOutcome};
use alloc::collections::{BTreeMap, BTreeSet};

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

/// Most targets the post-failure backoff table holds at once.
///
/// The legitimate load is the number of distinct targets that failed within
/// one backoff window plus one cap interval, which an ordinary node does not
/// approach; the value has no measured basis and matches
/// [`MAX_RECENT_LOOKUP_REQUESTS`]. At roughly 80 to 100 bytes an entry with
/// its expiry index (estimated) the table stays under about 400 KB. A sender
/// that fails more targets than this only evicts the entries nearest expiry,
/// and eviction fails open: an evicted target can only be retried sooner.
pub(crate) const MAX_BACKOFF_ENTRIES: usize = 4096;

/// Exponential backoff for failed lookups.
///
/// Tracks targets whose lookups have timed out and suppresses
/// re-initiation with increasing delays. Cleared on topology changes.
/// Records nothing while backoff is disabled (a zero base or cap), and
/// holds at most [`MAX_BACKOFF_ENTRIES`] targets.
pub struct LookupBackoff {
    /// Maps target → (suppress_until, consecutive_failures).
    pub(crate) entries: BTreeMap<NodeAddr, BackoffEntry>,
    /// The same targets ordered by when their windows end, so the entry
    /// nearest expiry and the forgettable ones are found without scanning
    /// the table. Holds exactly one `(suppress_until_ms, target)` per entry.
    by_expiry: BTreeSet<(u64, NodeAddr)>,
    /// Base backoff in milliseconds (first failure).
    base_ms: u64,
    /// Maximum backoff cap in milliseconds.
    max_ms: u64,
    /// Entries evicted at the bound since the shell last took the count.
    evicted: u64,
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
            by_expiry: BTreeSet::new(),
            base_ms: base_secs * 1000,
            max_ms: max_secs * 1000,
            evicted: 0,
        }
    }

    /// Whether a failure can suppress anything.
    ///
    /// The window is `base * 2^k` capped at the maximum, so a zero base or a
    /// zero cap both mean no suppression, and nothing is worth recording.
    pub fn is_enabled(&self) -> bool {
        self.base_ms > 0 && self.max_ms > 0
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
    /// window using exponential backoff. Does nothing while backoff is
    /// disabled. A new target arriving at [`MAX_BACKOFF_ENTRIES`] first
    /// prunes forgotten entries and, if the table is still full, evicts the
    /// entry nearest expiry.
    pub fn record_failure(&mut self, target: &NodeAddr, now_ms: u64) {
        if !self.is_enabled() {
            return;
        }
        if !self.entries.contains_key(target) && self.entries.len() >= MAX_BACKOFF_ENTRIES {
            self.prune(now_ms);
            if self.entries.len() >= MAX_BACKOFF_ENTRIES {
                self.evict_nearest_expiry();
            }
        }

        let failures = self.entries.get(target).map_or(0, |e| e.failures) + 1;

        let backoff_ms = crate::proto::rate_limit::backoff_ms(
            failures.saturating_sub(1),
            self.base_ms,
            self.max_ms,
        );

        let suppress_until_ms = now_ms + backoff_ms;
        if let Some(old) = self.entries.insert(
            *target,
            BackoffEntry {
                suppress_until_ms,
                failures,
            },
        ) {
            self.by_expiry.remove(&(old.suppress_until_ms, *target));
        }
        self.by_expiry.insert((suppress_until_ms, *target));
    }

    /// Forget entries whose window ended more than one maximum backoff
    /// interval ago.
    ///
    /// The grace keeps a target that fails again soon after its window
    /// escalating; once it has passed, the target's count starts over,
    /// which can only shorten its next window.
    pub fn prune(&mut self, now_ms: u64) {
        let grace_ms = self.max_ms;
        while let Some(&(until, target)) = self.by_expiry.first() {
            if now_ms < until.saturating_add(grace_ms) {
                break;
            }
            self.by_expiry.pop_first();
            self.entries.remove(&target);
        }
    }

    /// Return and reset the count of entries evicted at the bound.
    pub fn take_evicted(&mut self) -> u64 {
        ::core::mem::take(&mut self.evicted)
    }

    /// Drop the entry whose window ends first; it is the one an eviction
    /// costs least, since it would have been retryable soonest anyway.
    fn evict_nearest_expiry(&mut self) {
        if let Some((_, target)) = self.by_expiry.pop_first() {
            self.entries.remove(&target);
            self.evicted += 1;
        }
    }

    /// Record a successful lookup — remove backoff for this target.
    pub fn record_success(&mut self, target: &NodeAddr) {
        if let Some(old) = self.entries.remove(target) {
            self.by_expiry.remove(&(old.suppress_until_ms, *target));
        }
    }

    /// Clear all backoff entries.
    ///
    /// Called on topology changes that might make previously-unreachable
    /// targets reachable (parent change, new peer, first RTT, reconnection).
    pub fn reset_all(&mut self) {
        self.entries.clear();
        self.by_expiry.clear();
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
        // A full map admits rather than refuses; for forwarding that is the
        // same fail-open direction the routing-error limiter takes, and the
        // per-target interval is the only thing lost.
        self.0.check_and_record(target, now_ms) != RecordOutcome::Suppress
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
