//! Tests of the Packet Too Big limiter: at exact times, through the check that
//! takes the time rather than reading the clock, and through the wrapper that
//! reads it (`should_send`).

use super::*;

/// The source these tests limit.
fn src() -> Ipv6Addr {
    "fd00::1".parse().unwrap()
}

/// A source is held back for the whole interval after a send, to the
/// millisecond, and allowed again once the interval has passed.
#[test]
fn a_source_is_held_back_until_the_interval_has_passed_and_not_after() {
    let mut limiter = IcmpRateLimiter::new();
    let t0 = Instant::now();
    assert!(limiter.check(src(), t0));
    assert!(!limiter.check(src(), t0));
    assert!(!limiter.check(src(), t0 + Duration::from_millis(99)));
    assert!(limiter.check(src(), t0 + Duration::from_millis(100)));
    assert!(!limiter.check(src(), t0 + Duration::from_millis(199)));
}

/// A source held back is not recorded as sent, so the interval runs from
/// the send it was allowed, not from the attempt.
#[test]
fn a_held_back_attempt_does_not_restart_the_interval() {
    let mut limiter = IcmpRateLimiter::new();
    let t0 = Instant::now();
    assert!(limiter.check(src(), t0));
    assert!(!limiter.check(src(), t0 + Duration::from_millis(60)));
    assert!(limiter.check(src(), t0 + Duration::from_millis(100)));
}

/// An entry is dropped by the first allowed check at its maximum age, and
/// kept by one just short of it.
#[test]
fn an_entry_expires_at_its_maximum_age_through_a_later_check() {
    let [b, c]: [Ipv6Addr; 2] = ["fd00::2".parse().unwrap(), "fd00::3".parse().unwrap()];
    let mut limiter = IcmpRateLimiter::new();
    let t0 = Instant::now();
    assert!(limiter.check(src(), t0));
    assert!(limiter.check(b, t0 + Duration::from_millis(9_999)));
    assert_eq!(limiter.len(), 2, "kept just short of ten seconds");
    assert!(limiter.check(c, t0 + Duration::from_secs(10)));
    assert_eq!(limiter.len(), 2, "the first source dropped at ten seconds");
}

/// The interval a limiter is built with is the one it judges by.
#[test]
fn a_custom_interval_is_judged_to_the_millisecond() {
    let mut limiter = IcmpRateLimiter::with_interval(Duration::from_millis(50));
    let t0 = Instant::now();
    assert!(limiter.check(src(), t0));
    assert!(!limiter.check(src(), t0 + Duration::from_millis(49)));
    assert!(limiter.check(src(), t0 + Duration::from_millis(50)));
}

#[test]
fn test_first_send_allowed() {
    let mut limiter = IcmpRateLimiter::new();
    let addr: Ipv6Addr = "fd00::1".parse().unwrap();

    assert!(limiter.should_send(addr));
}

#[test]
fn test_rapid_sends_rate_limited() {
    let mut limiter = IcmpRateLimiter::new();
    let addr: Ipv6Addr = "fd00::1".parse().unwrap();

    // First send should succeed
    assert!(limiter.should_send(addr));

    // Immediate second send should be rate limited
    assert!(!limiter.should_send(addr));
    assert!(!limiter.should_send(addr));
}

#[test]
fn test_different_sources_independent() {
    let mut limiter = IcmpRateLimiter::new();
    let addr1: Ipv6Addr = "fd00::1".parse().unwrap();
    let addr2: Ipv6Addr = "fd00::2".parse().unwrap();

    // Both sources should be allowed independently
    assert!(limiter.should_send(addr1));
    assert!(limiter.should_send(addr2));

    // But rapid resends to same source are limited
    assert!(!limiter.should_send(addr1));
    assert!(!limiter.should_send(addr2));
}

#[test]
fn test_cleanup_removes_old_entries() {
    let mut limiter = IcmpRateLimiter::new();
    let addr1: Ipv6Addr = "fd00::1".parse().unwrap();
    let addr2: Ipv6Addr = "fd00::2".parse().unwrap();

    // Send to both addresses
    assert!(limiter.should_send(addr1));
    assert!(limiter.should_send(addr2));
    assert_eq!(limiter.len(), 2);

    // Manually trigger cleanup with a future timestamp
    let future = Instant::now() + Duration::from_secs(11);
    limiter.cleanup(future);

    // All entries should be cleaned up
    assert_eq!(limiter.len(), 0);
}

#[test]
fn test_cleanup_preserves_recent_entries() {
    let mut limiter = IcmpRateLimiter::new();
    let addr: Ipv6Addr = "fd00::1".parse().unwrap();

    assert!(limiter.should_send(addr));
    assert_eq!(limiter.len(), 1);

    // Cleanup with current time shouldn't remove recent entry
    limiter.cleanup(Instant::now());
    assert_eq!(limiter.len(), 1);
}
