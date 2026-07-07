//! Tests for the FMP connection-retry backoff timing helper.

use crate::proto::fmp::backoff_ms;

const TEST_MAX_BACKOFF_MS: u64 = 300_000;

#[test]
fn test_backoff_exponential() {
    assert_eq!(backoff_ms(0, 5000, TEST_MAX_BACKOFF_MS), 5000); // 5s * 2^0
    assert_eq!(backoff_ms(1, 5000, TEST_MAX_BACKOFF_MS), 10_000); // 5s * 2^1
    assert_eq!(backoff_ms(2, 5000, TEST_MAX_BACKOFF_MS), 20_000); // 5s * 2^2
    assert_eq!(backoff_ms(3, 5000, TEST_MAX_BACKOFF_MS), 40_000); // 5s * 2^3
    assert_eq!(backoff_ms(4, 5000, TEST_MAX_BACKOFF_MS), 80_000); // 5s * 2^4
}

#[test]
fn test_backoff_cap() {
    // 2^20 * 5000 would be huge; capped at the max.
    assert_eq!(
        backoff_ms(20, 5000, TEST_MAX_BACKOFF_MS),
        TEST_MAX_BACKOFF_MS
    );
}

#[test]
fn test_backoff_zero_base() {
    assert_eq!(backoff_ms(3, 0, TEST_MAX_BACKOFF_MS), 0);
}
