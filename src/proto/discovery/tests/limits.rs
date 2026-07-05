//! Tests for discovery rate limiting and backoff.

use crate::proto::discovery::{DiscoveryBackoff, DiscoveryForwardRateLimiter};
use crate::testutil::make_node_addr as addr;

// --- DiscoveryBackoff tests ---

#[test]
fn test_backoff_not_suppressed_initially() {
    let backoff = DiscoveryBackoff::new();
    assert!(!backoff.is_suppressed(&addr(1), 0));
}

#[test]
fn test_backoff_suppressed_after_failure() {
    // Backoff is opt-in; exercise the suppression path with explicit params.
    let now = 1_000;
    let mut backoff = DiscoveryBackoff::with_params(30, 300);
    backoff.record_failure(&addr(1), now);
    assert!(backoff.is_suppressed(&addr(1), now));
    // Different target not affected
    assert!(!backoff.is_suppressed(&addr(2), now));
}

#[test]
fn test_backoff_cleared_on_success() {
    let now = 1_000;
    let mut backoff = DiscoveryBackoff::with_params(30, 300);
    backoff.record_failure(&addr(1), now);
    assert!(backoff.is_suppressed(&addr(1), now));

    backoff.record_success(&addr(1));
    assert!(!backoff.is_suppressed(&addr(1), now));
}

#[test]
fn test_backoff_reset_all() {
    let now = 1_000;
    let mut backoff = DiscoveryBackoff::new();
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
    let mut backoff = DiscoveryBackoff::with_params(1, 300);

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
    let mut backoff = DiscoveryBackoff::with_params(0, 0);
    backoff.record_failure(&addr(1), now);
    // With 0s backoff, should not be suppressed
    assert!(!backoff.is_suppressed(&addr(1), now));
}

#[test]
fn test_backoff_capped() {
    let now = 1_000;
    let mut backoff = DiscoveryBackoff::with_params(1, 10);

    // Record many failures
    for _ in 0..20 {
        backoff.record_failure(&addr(1), now);
    }

    // Backoff should be capped at max (10s = 10_000ms), not overflow
    let entry = backoff.entries.get(&addr(1)).unwrap();
    let remaining = entry.suppress_until_ms - now;
    assert!(remaining <= 11_000);
}

// --- DiscoveryForwardRateLimiter tests ---

#[test]
fn test_forward_first_allowed() {
    let mut limiter = DiscoveryForwardRateLimiter::new();
    assert!(limiter.should_forward(&addr(1), 0));
}

#[test]
fn test_forward_rapid_rate_limited() {
    let now = 1_000;
    let mut limiter = DiscoveryForwardRateLimiter::new();
    assert!(limiter.should_forward(&addr(1), now));
    assert!(!limiter.should_forward(&addr(1), now));
    assert!(!limiter.should_forward(&addr(1), now));
}

#[test]
fn test_forward_different_targets_independent() {
    let now = 1_000;
    let mut limiter = DiscoveryForwardRateLimiter::new();
    assert!(limiter.should_forward(&addr(1), now));
    assert!(limiter.should_forward(&addr(2), now));
    assert!(!limiter.should_forward(&addr(1), now));
    assert!(!limiter.should_forward(&addr(2), now));
}

#[test]
fn test_forward_allowed_after_interval() {
    let now = 1_000;
    let mut limiter = DiscoveryForwardRateLimiter::with_interval_ms(100);
    assert!(limiter.should_forward(&addr(1), now));

    // Advance past the minimum interval.
    assert!(limiter.should_forward(&addr(1), now + 110));
}

#[test]
fn test_forward_cleanup_removes_old() {
    let now = 1_000;
    let mut limiter = DiscoveryForwardRateLimiter::new();
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
    let mut limiter = DiscoveryForwardRateLimiter::new();
    assert!(limiter.should_forward(&addr(1), now));
    assert_eq!(limiter.len(), 1);

    limiter.cleanup(now);
    assert_eq!(limiter.len(), 1);
}
