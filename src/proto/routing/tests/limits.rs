//! Tests for routing error-signal rate limiting.

use crate::NodeAddr;
use crate::proto::rate_limit::MAX_ENTRIES;
use crate::proto::routing::{LimitVerdict, RoutingErrorRateLimiter};
use crate::testutil::make_node_addr as addr;

/// A distinct destination address per index, standing for the fresh
/// `dest_addr` a flooding sender puts on every datagram.
fn minted_addr(val: u32) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[..4].copy_from_slice(&val.to_le_bytes());
    bytes[15] = 0xff;
    NodeAddr::from_bytes(bytes)
}

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

#[test]
fn the_map_stays_bounded_when_a_sender_mints_distinct_destination_keys() {
    // `dest_addr` is a field the sender picks, so an unbounded map is memory
    // the sender sizes.
    let mut limiter = RoutingErrorRateLimiter::new();

    for i in 0..100_000u32 {
        limiter.check(&minted_addr(i), 0);
    }

    assert!(
        limiter.len() <= MAX_ENTRIES,
        "limiter held {} entries, above the {MAX_ENTRIES} ceiling",
        limiter.len()
    );
}

#[test]
fn an_admission_at_capacity_still_sends_rather_than_going_silent() {
    // The ceiling fails open on purpose: the map is fullest during partition
    // healing, when sources most need the signal.
    let mut limiter = RoutingErrorRateLimiter::new();

    for i in 0..MAX_ENTRIES as u32 {
        assert_eq!(limiter.check(&minted_addr(i), 0), LimitVerdict::Admit);
    }

    // The map is full and nothing in it is old enough to evict, so the next
    // distinct destination cannot be recorded. It must still be sent.
    assert_eq!(
        limiter.check(&minted_addr(MAX_ENTRIES as u32), 0),
        LimitVerdict::AdmitAtCapacity
    );
}

#[test]
fn the_map_scan_does_not_run_once_per_admitted_destination() {
    // The sweep is a full-map retain. Running it per admit would make the
    // per-event cost linear in a map the sender sizes, which is the denial of
    // service the ceiling above exists to prevent.
    let mut limiter = RoutingErrorRateLimiter::new();
    limiter.check(&minted_addr(0), 1);
    let before = limiter.sweeps();

    for i in 1..1_000u32 {
        limiter.check(&minted_addr(i), 1);
    }

    assert_eq!(
        limiter.sweeps() - before,
        0,
        "the full-map scan ran inside a single sweep interval"
    );
}

#[test]
fn the_map_scan_still_runs_once_a_sweep_interval_has_passed() {
    let mut limiter = RoutingErrorRateLimiter::new();
    limiter.check(&minted_addr(0), 1);
    let before = limiter.sweeps();

    // 11 s later: past both the sweep interval and the 10 s max age.
    limiter.check(&minted_addr(1), 11_000);

    assert_eq!(limiter.sweeps() - before, 1);
    // The first destination aged out, so the sweep did its job.
    assert_eq!(limiter.len(), 1);
}
