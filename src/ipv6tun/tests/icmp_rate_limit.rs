//! Tests of the Packet Too Big limiter: at exact times, through the check that
//! takes the time rather than reading the clock, and through the wrapper that
//! reads it (`should_send`).

use super::*;

/// The source these tests limit.
fn src() -> Ipv6Addr {
    "fd00::1".parse().unwrap()
}

/// Spend `src`'s whole burst at `at`, checking each answer is allowed.
fn spend_burst(limiter: &mut IcmpRateLimiter, src: Ipv6Addr, at: Instant) {
    for n in 0..PACKET_TOO_BIG_BURST {
        assert!(limiter.check(src, at), "answer {n} of the burst");
    }
}

/// A source that has spent its burst is held back until its bucket regains
/// a token one interval later, to the millisecond, and again until the next.
#[test]
fn a_source_that_spent_its_burst_is_held_back_until_one_interval_has_passed_and_not_after() {
    let mut limiter = IcmpRateLimiter::new();
    let t0 = Instant::now();
    let ms = |n| t0 + Duration::from_millis(n);
    spend_burst(&mut limiter, src(), t0);
    assert!(!limiter.check(src(), t0));
    assert!(!limiter.check(src(), ms(99)));
    assert!(limiter.check(src(), ms(100)));
    assert!(!limiter.check(src(), ms(199)));
    assert!(limiter.check(src(), ms(200)));
}

/// A source held back spends no token, so an attempt held back part way
/// through an interval does not delay the next answer.
#[test]
fn a_held_back_attempt_does_not_restart_the_interval() {
    let mut limiter = IcmpRateLimiter::new();
    let t0 = Instant::now();
    spend_burst(&mut limiter, src(), t0);
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

/// The interval a limiter is built with is the one its buckets refill by.
#[test]
fn a_custom_interval_is_judged_to_the_millisecond() {
    let mut limiter = IcmpRateLimiter::with_interval(Duration::from_millis(50));
    let t0 = Instant::now();
    spend_burst(&mut limiter, src(), t0);
    assert!(!limiter.check(src(), t0));
    assert!(!limiter.check(src(), t0 + Duration::from_millis(49)));
    assert!(limiter.check(src(), t0 + Duration::from_millis(50)));
}

/// A source whose bucket refills more slowly than the maximum age is kept
/// until it has refilled, so cleanup never hands it a fresh burst early.
#[test]
fn a_source_is_kept_past_the_maximum_age_until_its_bucket_has_refilled() {
    let mut limiter = IcmpRateLimiter::with_interval(Duration::from_secs(2));
    let t0 = Instant::now();
    spend_burst(&mut limiter, src(), t0);
    let other: Ipv6Addr = "fd00::2".parse().unwrap();
    assert!(limiter.check(other, t0 + Duration::from_secs(10)));
    assert_eq!(limiter.len(), 2, "kept at ten seconds, two tokens back");
    assert!(!limiter.check(src(), t0 + Duration::from_millis(1_999)));
    assert!(limiter.check(src(), t0 + Duration::from_secs(2)));
}

/// A zero interval is taken as one nanosecond: the bucket refills almost at
/// once rather than never.
#[test]
fn a_zero_interval_refills_within_a_microsecond() {
    let mut limiter = IcmpRateLimiter::with_interval(Duration::ZERO);
    let t0 = Instant::now();
    spend_burst(&mut limiter, src(), t0);
    assert!(!limiter.check(src(), t0));
    assert!(limiter.check(src(), t0 + Duration::from_micros(1)));
}

#[test]
fn test_first_send_allowed() {
    let mut limiter = IcmpRateLimiter::new();
    let addr: Ipv6Addr = "fd00::1".parse().unwrap();

    assert!(limiter.should_send(addr));
}

/// Rapid sends through the wrapper that reads the clock draw the burst and
/// no more than the bucket refills while they run.
#[test]
fn rapid_sends_to_one_source_through_the_clock_reading_wrapper_draw_the_burst_and_no_more() {
    let mut limiter = IcmpRateLimiter::new();
    let addr: Ipv6Addr = "fd00::1".parse().unwrap();
    let start = Instant::now();
    let allowed = (0..100).filter(|_| limiter.should_send(addr)).count();
    let refilled = (start.elapsed().as_secs_f64() * 10.0).ceil() as usize;
    let burst = PACKET_TOO_BIG_BURST as usize;
    assert!(
        (burst..=burst + refilled).contains(&allowed),
        "{allowed} allowed, burst {burst}, {refilled} refilled"
    );
}

/// Each source has a bucket of its own: one source spending its burst
/// leaves another's whole.
#[test]
fn each_source_has_a_bucket_of_its_own() {
    let mut limiter = IcmpRateLimiter::new();
    let other: Ipv6Addr = "fd00::2".parse().unwrap();
    let t0 = Instant::now();
    spend_burst(&mut limiter, src(), t0);
    assert!(!limiter.check(src(), t0));
    spend_burst(&mut limiter, other, t0);
    assert!(!limiter.check(other, t0));
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
