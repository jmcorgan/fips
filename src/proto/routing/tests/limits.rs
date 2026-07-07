//! Tests for routing error-signal rate limiting.

use crate::proto::routing::RoutingErrorRateLimiter;
use crate::testutil::make_node_addr as addr;

#[test]
fn test_first_send_allowed() {
    let mut limiter = RoutingErrorRateLimiter::new();
    assert!(limiter.should_send(&addr(1), 0));
}

#[test]
fn test_rapid_sends_rate_limited() {
    let mut limiter = RoutingErrorRateLimiter::new();
    assert!(limiter.should_send(&addr(1), 0));
    assert!(!limiter.should_send(&addr(1), 0));
    assert!(!limiter.should_send(&addr(1), 50));
}

#[test]
fn test_different_destinations_independent() {
    let mut limiter = RoutingErrorRateLimiter::new();
    assert!(limiter.should_send(&addr(1), 0));
    assert!(limiter.should_send(&addr(2), 0));
    assert!(!limiter.should_send(&addr(1), 0));
    assert!(!limiter.should_send(&addr(2), 0));
}

#[test]
fn test_send_allowed_after_interval() {
    let mut limiter = RoutingErrorRateLimiter::new();
    assert!(limiter.should_send(&addr(1), 0));
    // 110 ms later, past the 100 ms window.
    assert!(limiter.should_send(&addr(1), 110));
}

#[test]
fn test_cleanup_removes_old_entries() {
    let mut limiter = RoutingErrorRateLimiter::new();
    assert!(limiter.should_send(&addr(1), 0));
    assert!(limiter.should_send(&addr(2), 0));
    assert_eq!(limiter.len(), 2);

    // 11 s later, both entries exceed the 10 s max age.
    limiter.cleanup(11_000);
    assert_eq!(limiter.len(), 0);
}

#[test]
fn test_cleanup_preserves_recent_entries() {
    let mut limiter = RoutingErrorRateLimiter::new();
    assert!(limiter.should_send(&addr(1), 0));
    assert_eq!(limiter.len(), 1);

    limiter.cleanup(0);
    assert_eq!(limiter.len(), 1);
}

#[test]
fn test_with_interval_custom_rate() {
    let mut limiter = RoutingErrorRateLimiter::with_interval_ms(500);
    assert!(limiter.should_send(&addr(1), 0));
    assert!(!limiter.should_send(&addr(1), 0));

    // Still rate-limited at 200 ms (would pass with the default 100 ms).
    assert!(!limiter.should_send(&addr(1), 200));

    // Allowed at 500 ms.
    assert!(limiter.should_send(&addr(1), 500));
}
