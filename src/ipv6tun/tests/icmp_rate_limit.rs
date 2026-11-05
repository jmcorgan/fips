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

/// Two oversized packets from one source within 100 ms both draw a Packet
/// Too Big: RFC 4443 Section 2.4 (f) calls one error per interval an
/// unreasonable limit and recommends a token bucket.
#[test]
#[ignore = "known defect: a second Packet Too Big to one source within 100 ms is withheld"]
fn a_second_packet_too_big_to_one_source_1_ms_after_the_first_is_allowed() {
    let mut limiter = IcmpRateLimiter::new();
    let t0 = Instant::now();
    assert!(limiter.check(src(), t0), "the first is allowed");
    assert!(
        limiter.check(src(), t0 + Duration::from_millis(1)),
        "the second, 1 ms later, is withheld"
    );
}

/// A source quiet for ten seconds that then sends five oversized packets at
/// once, as a traceroute or a burst of sends to new destinations does, is
/// answered for each.
#[test]
#[ignore = "known defect: a burst after a quiet spell draws one Packet Too Big, not one each"]
fn a_burst_of_five_after_ten_quiet_seconds_is_answered_for_every_packet() {
    let mut limiter = IcmpRateLimiter::new();
    let t0 = Instant::now();
    assert!(limiter.check(src(), t0));
    let later = t0 + Duration::from_secs(10);
    let allowed = (0..5).filter(|_| limiter.check(src(), later)).count();
    assert_eq!(
        allowed, 5,
        "answers to a burst of five after ten quiet seconds"
    );
}

/// A flood from one source stays limited, to at most ten at one instant and
/// to between ten and twenty-one over one second.
#[test]
fn a_flood_from_one_source_is_held_to_ten_at_once_and_about_ten_more_a_second() {
    let mut limiter = IcmpRateLimiter::new();
    let t0 = Instant::now();
    let at_once = (0..1000).filter(|_| limiter.check(src(), t0)).count();
    assert!((1..=10).contains(&at_once), "{at_once} at one instant");
    let mut limiter = IcmpRateLimiter::new();
    let over_a_second = (0..1000)
        .filter(|ms| limiter.check(src(), t0 + Duration::from_millis(*ms)))
        .count();
    assert!(
        (10..=21).contains(&over_a_second),
        "{over_a_second} over one second"
    );
}
