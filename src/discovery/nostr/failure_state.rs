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

use std::collections::HashMap;
use std::sync::Mutex;

/// One peer's failure-tracking state. Keyed by bech32 npub string in the
/// owning `FailureState` map.
#[derive(Debug, Clone)]
pub(super) struct NpubFailureRecord {
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
            last_observed_skew_ms: None,
        }
    }
}

/// What the lifecycle layer should do based on the recorded failure.
#[derive(Debug, Clone, Copy)]
pub(super) struct FailureDecision {
    /// Updated streak count (post-increment).
    pub consecutive_failures: u32,
    /// True iff lifecycle should log at WARN; false → log at DEBUG.
    pub should_warn: bool,
    /// If set, retry_after_ms for this peer should not fire before this
    /// wall-clock ms.
    pub cooldown_until_ms: Option<u64>,
    /// True only on the streak-threshold-crossing transition. Lifecycle
    /// should run a one-shot stale-advert check (B6) when this fires.
    pub crossed_threshold: bool,
}

pub(super) struct FailureState {
    inner: Mutex<HashMap<String, NpubFailureRecord>>,
    threshold: u32,
    extended_cooldown_ms: u64,
    warn_log_interval_ms: u64,
    max_entries: usize,
}

impl FailureState {
    pub(super) fn new(
        threshold: u32,
        extended_cooldown_secs: u64,
        warn_log_interval_secs: u64,
        max_entries: usize,
    ) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            threshold,
            extended_cooldown_ms: extended_cooldown_secs.saturating_mul(1000),
            warn_log_interval_ms: warn_log_interval_secs.saturating_mul(1000),
            max_entries,
        }
    }

    /// Record a traversal failure against `npub`. Returns the resulting
    /// FailureDecision for the lifecycle layer to act on.
    pub(super) fn record_failure(&self, npub: &str, now_ms: u64) -> FailureDecision {
        let mut map = self.inner.lock().expect("failure-state mutex poisoned");
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
            evict_oldest(&mut map, self.max_entries);
        }

        decision
    }

    /// Record a successful traversal — clears the streak and cooldown.
    /// Last-observed skew is retained until next eviction since it's
    /// useful to display in `show_peers` even for healthy peers.
    pub(super) fn record_success(&self, npub: &str, now_ms: u64) {
        let mut map = self.inner.lock().expect("failure-state mutex poisoned");
        if let Some(entry) = map.get_mut(npub) {
            entry.consecutive_failures = 0;
            entry.cooldown_until_ms = None;
            entry.last_failure_at_ms = now_ms;
        }
        // No insert if absent — successful peers don't need a record.
    }

    /// Record an observed clock-skew estimate from a successful answer
    /// receipt (B5a). Creates an entry if needed so we can surface the
    /// skew via `show_peers` even when the peer is healthy.
    pub(super) fn note_observed_skew(&self, npub: &str, skew_ms: i64, now_ms: u64) {
        let mut map = self.inner.lock().expect("failure-state mutex poisoned");
        let entry = map
            .entry(npub.to_string())
            .or_insert_with(|| NpubFailureRecord::new(now_ms));
        entry.last_observed_skew_ms = Some(skew_ms);

        if map.len() > self.max_entries {
            evict_oldest(&mut map, self.max_entries);
        }
    }

    /// Reset streak/cooldown after a successful B6 advert refresh.
    pub(super) fn reset_streak_after_refresh(&self, npub: &str) {
        let mut map = self.inner.lock().expect("failure-state mutex poisoned");
        if let Some(entry) = map.get_mut(npub) {
            entry.consecutive_failures = 0;
            entry.cooldown_until_ms = None;
        }
    }

    /// Return cooldown_until_ms if the peer is currently in extended
    /// cooldown.
    pub(super) fn cooldown_until(&self, npub: &str, now_ms: u64) -> Option<u64> {
        let map = self.inner.lock().expect("failure-state mutex poisoned");
        map.get(npub)
            .and_then(|e| e.cooldown_until_ms)
            .filter(|&t| t > now_ms)
    }

    /// Snapshot for `show_peers` rendering (B3).
    pub(super) fn snapshot(&self) -> Vec<(String, NpubFailureRecord)> {
        let map = self.inner.lock().expect("failure-state mutex poisoned");
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
mod tests {
    use super::*;

    fn fs() -> FailureState {
        // threshold=3, cooldown=10s, warn-interval=5s, cap=8
        FailureState::new(3, 10, 5, 8)
    }

    #[test]
    fn first_failure_warns_and_no_cooldown() {
        let s = fs();
        let d = s.record_failure("npub1a", 1000);
        assert_eq!(d.consecutive_failures, 1);
        assert!(d.should_warn);
        assert!(d.cooldown_until_ms.is_none());
        assert!(!d.crossed_threshold);
    }

    #[test]
    fn warn_suppressed_inside_window_then_unsuppressed_after() {
        let s = fs();
        let d1 = s.record_failure("npub1a", 1000);
        let d2 = s.record_failure("npub1a", 1500);
        assert!(d1.should_warn);
        assert!(
            !d2.should_warn,
            "second failure inside 5s window must DEBUG"
        );
        // 5s warn-interval = 5000 ms; bump beyond.
        let d3 = s.record_failure("npub1a", 1000 + 5_500);
        assert!(d3.should_warn, "after window, must WARN again");
    }

    #[test]
    fn streak_threshold_triggers_cooldown_and_signals_crossing() {
        let s = fs();
        let _ = s.record_failure("npub1a", 1000);
        let _ = s.record_failure("npub1a", 1100);
        let d3 = s.record_failure("npub1a", 1200);
        assert_eq!(d3.consecutive_failures, 3);
        assert!(d3.crossed_threshold);
        assert_eq!(d3.cooldown_until_ms, Some(1200 + 10_000));
        // Subsequent failure does NOT re-fire crossed_threshold.
        let d4 = s.record_failure("npub1a", 1300);
        assert!(!d4.crossed_threshold);
        assert!(d4.cooldown_until_ms.is_some());
    }

    #[test]
    fn record_success_clears_streak() {
        let s = fs();
        for t in [1000u64, 1100, 1200, 1300] {
            let _ = s.record_failure("npub1a", t);
        }
        s.record_success("npub1a", 2000);
        let d = s.record_failure("npub1a", 3000);
        assert_eq!(d.consecutive_failures, 1, "streak reset after success");
        assert!(!d.crossed_threshold);
    }

    #[test]
    fn cooldown_until_returns_only_active_cooldowns() {
        let s = fs();
        for t in [1000u64, 1100, 1200] {
            let _ = s.record_failure("npub1a", t);
        }
        // Mid-cooldown
        assert!(s.cooldown_until("npub1a", 5_000).is_some());
        // Past cooldown
        assert!(s.cooldown_until("npub1a", 1200 + 10_001).is_none());
    }

    #[test]
    fn note_observed_skew_creates_entry_for_healthy_peer() {
        let s = fs();
        s.note_observed_skew("npub1healthy", 250, 1000);
        let snap = s.snapshot();
        assert_eq!(snap.len(), 1);
        let (npub, rec) = &snap[0];
        assert_eq!(npub, "npub1healthy");
        assert_eq!(rec.last_observed_skew_ms, Some(250));
        assert_eq!(rec.consecutive_failures, 0);
    }

    #[test]
    fn size_cap_evicts_oldest_by_last_failure_at() {
        let s = fs(); // cap = 8
        for i in 0..10 {
            let npub = format!("npub1{i}");
            let _ = s.record_failure(&npub, 1000 + i as u64);
        }
        let snap = s.snapshot();
        assert!(snap.len() <= 8, "cap not enforced: {}", snap.len());
        // Oldest two (npub10, npub11) should be evicted; newer kept.
        let names: std::collections::HashSet<_> = snap.iter().map(|(n, _)| n.clone()).collect();
        assert!(!names.contains("npub10"));
        assert!(names.contains("npub19"));
    }
}
