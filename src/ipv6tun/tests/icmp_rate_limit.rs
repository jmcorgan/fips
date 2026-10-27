//! Tests of the Packet Too Big limiter at exact times, through the check that
//! takes the time rather than reading the clock.

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
