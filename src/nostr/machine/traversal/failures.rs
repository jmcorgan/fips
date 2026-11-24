//! Per-npub NAT-traversal failure tracking.
//!
//! Records consecutive offer/answer signal-timeout (and other) failures
//! against each peer. Drives three operator-visible behaviors:
//!
//! - **WARN log rate-limit (B1).** Suppresses repeat WARN lines for the
//!   same peer inside a configurable window; subsequent failures inside
//!   the window log at DEBUG instead.
//! - **Extended cooldown (B2).** Once a peer accumulates
//!   `failure_streak_threshold` consecutive failures, the next
//!   `extended_cooldown_secs` worth of attempts are suppressed by pushing
//!   the retry timer out, capping how aggressively a public-test node can
//!   hammer Nostr relays with offers to dead peers.
//! - **Stale-advert eviction (B6).** At streak threshold, the daemon
//!   actively re-fetches the peer's advert; outcomes (`Evicted`,
//!   `Refreshed`, `SameAdvert`, `Skipped`) feed back into the cache so
//!   peers that have actually disappeared stop being retried after
//!   eviction (`prune_advert_cache` semantics).
//!
//! Also stores last-observed clock skew (from B5a) so operators can
//! surface it via `fipsctl show peers` (B3).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use fips_core::utils::hash::{HashMap, KeyedHasher};

/// One peer's failure-tracking state. Keyed by bech32 npub string in the
/// owning `FailureState` map.
#[derive(Debug, Clone)]
pub struct NpubFailureRecord {
    /// Number of consecutive failures since the last success (or fresh
    /// advert that reset the streak).
    pub consecutive_failures: u32,
    /// When this entry was last touched, used for size-cap eviction.
    pub last_failure_at_ms: u64,
    /// When the last WARN was emitted for this peer; controls WARN
    /// rate-limit (B1).
    pub last_warn_at_ms: Option<u64>,
    /// When the extended cooldown was applied; while
    /// `cooldown_until_ms.is_some_and(|t| t > now)`, retries are
    /// suppressed.
    pub cooldown_until_ms: Option<u64>,
    /// When the cooldown set by the first protocol-mismatch observation
    /// ends. Held apart from `cooldown_until_ms`, which a transient failure
    /// also writes, so a repeat mismatch can restore it without extending
    /// it.
    pub mismatch_until_ms: Option<u64>,
    /// Most recent NTP-style skew estimate (B5a), in ms (positive =
    /// peer ahead of us). `None` if the peer hasn't successfully
    /// answered an offer with `offerReceivedAt` populated, or if
    /// successful traversal cleared the streak (we keep the last-seen
    /// skew, but only on records that are still in the map).
    pub last_observed_skew_ms: Option<i64>,
}

impl NpubFailureRecord {
    fn new(now_ms: u64) -> Self {
        Self {
            consecutive_failures: 0,
            last_failure_at_ms: now_ms,
            last_warn_at_ms: None,
            cooldown_until_ms: None,
            mismatch_until_ms: None,
            last_observed_skew_ms: None,
        }
    }
}

/// What the lifecycle layer should do based on the recorded failure.
#[derive(Debug, Clone, Copy)]
pub struct FailureDecision {
    /// Updated streak count (post-increment).
    pub consecutive_failures: u32,
    /// True iff lifecycle should log at WARN; false → log at DEBUG.
    pub should_warn: bool,
    /// If set, the peer's scheduled retry should not fire before this
    /// wall-clock ms.
    pub cooldown_until_ms: Option<u64>,
    /// True only on the streak-threshold-crossing transition. Lifecycle
    /// should run a one-shot stale-advert check (B6) when this fires.
    pub crossed_threshold: bool,
}

pub struct FailureState {
    inner: HashMap<String, NpubFailureRecord>,
    threshold: u32,
    extended_cooldown_ms: u64,
    warn_log_interval_ms: u64,
    max_entries: usize,
}

impl FailureState {
    pub fn new(
        threshold: u32,
        extended_cooldown_secs: u64,
        warn_log_interval_secs: u64,
        max_entries: usize,
        hasher: KeyedHasher,
    ) -> Self {
        Self {
            inner: HashMap::with_hasher(hasher),
            threshold,
            extended_cooldown_ms: extended_cooldown_secs.saturating_mul(1000),
            warn_log_interval_ms: warn_log_interval_secs.saturating_mul(1000),
            max_entries,
        }
    }

    /// Record a traversal failure against `npub`. Returns the resulting
    /// FailureDecision for the lifecycle layer to act on.
    pub fn record_failure(&mut self, npub: &str, now_ms: u64) -> FailureDecision {
        let map = &mut self.inner;
        let entry = map
            .entry(npub.to_string())
            .or_insert_with(|| NpubFailureRecord::new(now_ms));
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        entry.last_failure_at_ms = now_ms;

        let crossed_threshold = entry.consecutive_failures == self.threshold;
        let cooldown_until_ms = if entry.consecutive_failures >= self.threshold {
            let cooldown = now_ms.saturating_add(self.extended_cooldown_ms);
            entry.cooldown_until_ms = Some(cooldown);
            Some(cooldown)
        } else {
            None
        };

        let should_warn = !matches!(
            entry.last_warn_at_ms,
            Some(last) if now_ms.saturating_sub(last) < self.warn_log_interval_ms
        );
        if should_warn {
            entry.last_warn_at_ms = Some(now_ms);
        }

        let decision = FailureDecision {
            consecutive_failures: entry.consecutive_failures,
            should_warn,
            cooldown_until_ms,
            crossed_threshold,
        };

        if map.len() > self.max_entries {
            evict_oldest(map, self.max_entries);
        }

        decision
    }

    /// Record a successful traversal — clears the streak and cooldown.
    /// Last-observed skew is retained until next eviction since it's
    /// useful to display in `show_peers` even for healthy peers.
    pub fn record_success(&mut self, npub: &str, now_ms: u64) {
        let map = &mut self.inner;
        if let Some(entry) = map.get_mut(npub) {
            entry.consecutive_failures = 0;
            entry.cooldown_until_ms = None;
            entry.mismatch_until_ms = None;
            entry.last_failure_at_ms = now_ms;
        }
        // No insert if absent — successful peers don't need a record.
    }

    /// Record an observed clock-skew estimate from a successful answer
    /// receipt (B5a). Creates an entry if needed so we can surface the
    /// skew via `show_peers` even when the peer is healthy.
    pub fn note_observed_skew(&mut self, npub: &str, skew_ms: i64, now_ms: u64) {
        let map = &mut self.inner;
        let entry = map
            .entry(npub.to_string())
            .or_insert_with(|| NpubFailureRecord::new(now_ms));
        entry.last_observed_skew_ms = Some(skew_ms);

        if map.len() > self.max_entries {
            evict_oldest(map, self.max_entries);
        }
    }

    /// Reset streak/cooldown after a successful B6 advert refresh.
    pub fn reset_streak_after_refresh(&mut self, npub: &str) {
        let map = &mut self.inner;
        if let Some(entry) = map.get_mut(npub) {
            entry.consecutive_failures = 0;
            entry.cooldown_until_ms = None;
            entry.mismatch_until_ms = None;
        }
    }

    /// Record a fatal protocol mismatch against `npub` and apply
    /// `cooldown_ms` immediately (independent of the streak threshold).
    ///
    /// Returns `true` when this is a fresh mismatch entry (caller should
    /// log a one-shot WARN) or `false` while the cooldown the first
    /// observation set is still running (caller should remain silent). A
    /// repeat inside that cooldown never extends it, at any point in the
    /// window; it only restores it if a transient failure shortened it.
    ///
    /// Used when the rx loop sees an unhandshakable packet (e.g.,
    /// `Unknown FMP version`) on a Nostr-adopted bootstrap transport:
    /// re-traversing the peer at the next sweep cycle is wasted effort
    /// because the peer cannot accept our handshake until one side
    /// upgrades. The cooldown is much longer than the transient-failure
    /// `extended_cooldown_ms` because the mismatch is structural.
    pub fn record_protocol_mismatch(&mut self, npub: &str, now_ms: u64, cooldown_ms: u64) -> bool {
        let map = &mut self.inner;
        let entry = map
            .entry(npub.to_string())
            .or_insert_with(|| NpubFailureRecord::new(now_ms));
        // Treat the mismatch as crossing the streak threshold so other
        // visibility paths (e.g. show_peers JSON) reflect the failed state.
        entry.consecutive_failures = entry.consecutive_failures.max(self.threshold);
        // Refreshed even on a repeat: it orders size-cap eviction, and a
        // peer that keeps sending must not be evicted early, which would end
        // its cooldown.
        entry.last_failure_at_ms = now_ms;

        if let Some(until) = entry.mismatch_until_ms.filter(|&t| t > now_ms) {
            entry.cooldown_until_ms = Some(entry.cooldown_until_ms.map_or(until, |t| t.max(until)));
            return false;
        }
        let cooldown_until = now_ms.saturating_add(cooldown_ms);
        entry.cooldown_until_ms = Some(cooldown_until);
        entry.mismatch_until_ms = Some(cooldown_until);

        if map.len() > self.max_entries {
            evict_oldest(map, self.max_entries);
        }

        true
    }

    /// Return cooldown_until_ms if the peer is currently in extended
    /// cooldown.
    pub fn cooldown_until(&self, npub: &str, now_ms: u64) -> Option<u64> {
        let map = &self.inner;
        map.get(npub)
            .and_then(|e| e.cooldown_until_ms)
            .filter(|&t| t > now_ms)
    }

    /// Snapshot for `show_peers` rendering (B3).
    pub fn snapshot(&self) -> Vec<(String, NpubFailureRecord)> {
        let map = &self.inner;
        map.iter()
            .map(|(npub, rec)| (npub.clone(), rec.clone()))
            .collect()
    }
}

fn evict_oldest(map: &mut HashMap<String, NpubFailureRecord>, target: usize) {
    if map.len() <= target {
        return;
    }
    let overflow = map.len() - target;
    let mut entries: Vec<(String, u64)> = map
        .iter()
        .map(|(k, v)| (k.clone(), v.last_failure_at_ms))
        .collect();
    entries.sort_by_key(|(_, t)| *t);
    for (k, _) in entries.into_iter().take(overflow) {
        map.remove(&k);
    }
}

#[cfg(test)]
#[path = "tests/failures.rs"]
mod tests;
