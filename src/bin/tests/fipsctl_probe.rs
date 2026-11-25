//! Tests for `fipsctl`'s probe client ceiling and its cleanup lines.

use super::{probe_ceiling_ms, probe_cleanup_lines};

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

#[test]
fn a_session_the_probe_opened_and_left_is_described_as_its_own_with_no_warmup_note() {
    let lines = probe_cleanup_lines(&serde_json::json!({
        "session_created_and_torn_down": false,
        "session_left_intact": true,
        "left_intact_reason": "idle_timeout",
        "warmups_sent": 1,
    }));
    assert_eq!(
        lines,
        vec![
            "  cleanup    session was opened by this probe and is left for the idle timeout \
             to close"
                .to_string()
        ]
    );
}

#[test]
fn warmups_on_a_preexisting_session_are_noted() {
    let lines = probe_cleanup_lines(&serde_json::json!({
        "session_created_and_torn_down": false,
        "session_left_intact": true,
        "left_intact_reason": "preexisting",
        "warmups_sent": 2,
    }));
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[0], "  cleanup    session left in place (preexisting)");
    assert!(lines[1].contains("2 coords-warmup message(s)"), "{lines:?}");
}

#[test]
fn a_removed_session_is_described_as_torn_down() {
    let lines = probe_cleanup_lines(&serde_json::json!({
        "session_created_and_torn_down": true,
        "session_left_intact": false,
        "left_intact_reason": null,
        "warmups_sent": 0,
    }));
    assert_eq!(
        lines,
        vec!["  cleanup    session was opened by this probe and has been torn down".to_string()]
    );
}
