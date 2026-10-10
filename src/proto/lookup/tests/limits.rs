//! Tests for lookup rate limiting and backoff.

use super::util::distinct_addr as nth;
use crate::proto::lookup::{LookupBackoff, LookupForwardRateLimiter, MAX_BACKOFF_ENTRIES};
use crate::testutil::make_node_addr as addr;

// --- LookupBackoff tests ---

#[test]
fn test_backoff_not_suppressed_initially() {
    let backoff = LookupBackoff::new();
    assert!(!backoff.is_suppressed(&addr(1), 0));
}

#[test]
fn test_backoff_suppressed_after_failure() {
    // Backoff is opt-in; exercise the suppression path with explicit params.
    let now = 1_000;
    let mut backoff = LookupBackoff::with_params(30, 300);
    backoff.record_failure(&addr(1), now);
    assert!(backoff.is_suppressed(&addr(1), now));
    // Different target not affected
    assert!(!backoff.is_suppressed(&addr(2), now));
}

#[test]
fn test_backoff_cleared_on_success() {
    let now = 1_000;
    let mut backoff = LookupBackoff::with_params(30, 300);
    backoff.record_failure(&addr(1), now);
    assert!(backoff.is_suppressed(&addr(1), now));

    backoff.record_success(&addr(1));
    assert!(!backoff.is_suppressed(&addr(1), now));
}

#[test]
fn test_backoff_reset_all() {
    let now = 1_000;
    let mut backoff = LookupBackoff::with_params(30, 300);
    backoff.record_failure(&addr(1), now);
    backoff.record_failure(&addr(2), now);
    assert_eq!(backoff.len(), 2);

    backoff.reset_all();
    assert_eq!(backoff.len(), 0);
    assert!(!backoff.is_suppressed(&addr(1), now));
}

#[test]
fn test_backoff_exponential() {
    let now = 1_000;
    let mut backoff = LookupBackoff::with_params(1, 300);

    // First failure: 1s backoff
    backoff.record_failure(&addr(1), now);
    assert_eq!(backoff.failure_count(&addr(1)), 1);

    // Second failure: 2s backoff
    backoff.record_failure(&addr(1), now);
    assert_eq!(backoff.failure_count(&addr(1)), 2);

    // Third failure: 4s backoff
    backoff.record_failure(&addr(1), now);
    assert_eq!(backoff.failure_count(&addr(1)), 3);
}

#[test]
fn test_backoff_expires() {
    let now = 1_000;
    let mut backoff = LookupBackoff::with_params(0, 0);
    backoff.record_failure(&addr(1), now);
    // With 0s backoff, should not be suppressed
    assert!(!backoff.is_suppressed(&addr(1), now));
    // and nothing is recorded while backoff is disabled.
    assert_eq!(backoff.entry_count(), 0);
}

#[test]
fn test_backoff_capped() {
    let now = 1_000;
    let mut backoff = LookupBackoff::with_params(1, 10);

    // Record many failures
    for _ in 0..20 {
        backoff.record_failure(&addr(1), now);
    }

    // Backoff should be capped at max (10s = 10_000ms), not overflow
    let entry = backoff.entries.get(&addr(1)).unwrap();
    let remaining = entry.suppress_until_ms - now;
    assert!(remaining <= 11_000);
}

#[test]
fn with_backoff_enabled_five_thousand_distinct_failures_never_hold_more_than_max_backoff_entries() {
    let mut backoff = LookupBackoff::with_params(30, 300);
    let mut largest = 0;
    // 1 ms steps: no entry reaches its forget time, so pruning removes
    // nothing and only the bound can hold the table.
    for i in 0..5_000u32 {
        backoff.record_failure(&nth(i), 1_000 + u64::from(i));
        largest = largest.max(backoff.entry_count());
    }
    assert!(
        largest <= MAX_BACKOFF_ENTRIES,
        "the failure table grew to {largest} entries, past its bound of {MAX_BACKOFF_ENTRIES}"
    );
    assert_eq!(backoff.entry_count(), MAX_BACKOFF_ENTRIES);
}

#[test]
fn at_the_failure_table_bound_the_entry_nearest_expiry_is_evicted_and_the_newest_is_kept() {
    let mut backoff = LookupBackoff::with_params(30, 300);
    let bound = MAX_BACKOFF_ENTRIES as u32;
    for i in 0..bound {
        backoff.record_failure(&nth(i), 1_000 + u64::from(i));
    }
    assert_eq!(
        backoff.entry_count(),
        MAX_BACKOFF_ENTRIES,
        "precondition: full"
    );
    assert_eq!(
        backoff.take_evicted(),
        0,
        "precondition: nothing evicted yet"
    );

    let newest = nth(bound);
    backoff.record_failure(&newest, 1_000 + u64::from(bound));
    assert!(
        !backoff.entries.contains_key(&nth(0)),
        "the entry with the earliest window end must be evicted"
    );
    assert!(backoff.entries.contains_key(&newest));
    assert!(backoff.entries.contains_key(&nth(1)));
    assert_eq!(backoff.take_evicted(), 1);
    assert_eq!(backoff.take_evicted(), 0, "taking the count resets it");
}

#[test]
fn at_the_failure_table_bound_eviction_follows_windows_moved_by_a_repeat_failure_and_skips_targets_cleared_by_success()
 {
    let mut backoff = LookupBackoff::with_params(30, 300);
    let bound = MAX_BACKOFF_ENTRIES as u32;
    for i in 0..bound {
        backoff.record_failure(&nth(i), 1_000 + u64::from(i));
    }
    let later = 1_000 + u64::from(bound);
    // The earliest window moves later on a second failure, and the next one
    // is cleared by a success, leaving one free slot.
    backoff.record_failure(&nth(0), later);
    backoff.record_success(&nth(1));
    assert_eq!(backoff.entry_count(), MAX_BACKOFF_ENTRIES - 1);

    backoff.record_failure(&nth(bound), later);
    assert_eq!(
        backoff.take_evicted(),
        0,
        "the free slot is used before anything is evicted"
    );
    backoff.record_failure(&nth(bound + 1), later);

    assert_eq!(backoff.entry_count(), MAX_BACKOFF_ENTRIES);
    assert_eq!(backoff.take_evicted(), 1);
    assert!(
        backoff.entries.contains_key(&nth(0)),
        "a target whose window moved later keeps its entry"
    );
    assert!(
        !backoff.entries.contains_key(&nth(2)),
        "the entry with the earliest window end now is the one evicted"
    );
    assert!(backoff.entries.contains_key(&nth(3)));
    assert!(backoff.entries.contains_key(&nth(bound)));
    assert!(backoff.entries.contains_key(&nth(bound + 1)));
}

#[test]
fn with_a_zero_backoff_cap_and_a_nonzero_base_one_hundred_distinct_failures_record_nothing() {
    // Control: the same calls with a working cap record every target, so
    // the zero below is not a dead path.
    let mut enabled = LookupBackoff::with_params(30, 300);
    for i in 0..100u32 {
        enabled.record_failure(&nth(i), 1_000);
    }
    assert_eq!(enabled.entry_count(), 100);

    let mut capped_to_zero = LookupBackoff::with_params(30, 0);
    for i in 0..100u32 {
        capped_to_zero.record_failure(&nth(i), 1_000);
    }
    assert_eq!(
        capped_to_zero.entry_count(),
        0,
        "a zero cap suppresses nothing, so nothing may be recorded"
    );
    assert!(!capped_to_zero.is_enabled());
}

// --- LookupForwardRateLimiter tests ---

#[test]
fn test_forward_first_allowed() {
    let mut limiter = LookupForwardRateLimiter::new();
    assert!(limiter.should_forward(&addr(1), 0));
}

#[test]
fn test_forward_rapid_rate_limited() {
    let now = 1_000;
    let mut limiter = LookupForwardRateLimiter::new();
    assert!(limiter.should_forward(&addr(1), now));
    assert!(!limiter.should_forward(&addr(1), now));
    assert!(!limiter.should_forward(&addr(1), now));
}

#[test]
fn test_forward_different_targets_independent() {
    let now = 1_000;
    let mut limiter = LookupForwardRateLimiter::new();
    assert!(limiter.should_forward(&addr(1), now));
    assert!(limiter.should_forward(&addr(2), now));
    assert!(!limiter.should_forward(&addr(1), now));
    assert!(!limiter.should_forward(&addr(2), now));
}

#[test]
fn test_forward_allowed_after_interval() {
    let now = 1_000;
    let mut limiter = LookupForwardRateLimiter::with_interval_ms(100);
    assert!(limiter.should_forward(&addr(1), now));

    // Advance past the minimum interval.
    assert!(limiter.should_forward(&addr(1), now + 110));
}

#[test]
fn test_forward_cleanup_removes_old() {
    let now = 1_000;
    let mut limiter = LookupForwardRateLimiter::new();
    assert!(limiter.should_forward(&addr(1), now));
    assert!(limiter.should_forward(&addr(2), now));
    assert_eq!(limiter.len(), 2);

    let future = now + 61_000;
    limiter.cleanup(future);
    assert_eq!(limiter.len(), 0);
}

#[test]
fn test_forward_cleanup_preserves_recent() {
    let now = 1_000;
    let mut limiter = LookupForwardRateLimiter::new();
    assert!(limiter.should_forward(&addr(1), now));
    assert_eq!(limiter.len(), 1);

    limiter.cleanup(now);
    assert_eq!(limiter.len(), 1);
}
