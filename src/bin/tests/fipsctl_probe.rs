//! Tests for `fipsctl`'s probe client ceiling.

use super::probe_ceiling_ms;

#[test]
fn probe_ceiling_adds_a_margin_to_the_daemon_budget() {
    assert_eq!(probe_ceiling_ms(30_000, None), 35_000);
}

#[test]
fn probe_ceiling_takes_an_explicit_timeout_over_the_budget() {
    assert_eq!(probe_ceiling_ms(30_000, Some(2)), 2_000);
}

#[test]
fn probe_ceiling_saturates_instead_of_overflowing_for_a_huge_daemon_budget() {
    // A daemon with a huge lookup ladder entry reports a saturated budget.
    assert_eq!(probe_ceiling_ms(u64::MAX, None), u64::MAX);
}

#[test]
fn probe_ceiling_saturates_instead_of_overflowing_for_a_huge_timeout() {
    assert_eq!(probe_ceiling_ms(30_000, Some(u64::MAX)), u64::MAX);
}
