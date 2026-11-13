use super::*;

fn fs() -> FailureState {
    // threshold=3, cooldown=10s, warn-interval=5s, cap=8
    FailureState::new(3, 10, 5, 8)
}

#[test]
fn first_failure_warns_and_no_cooldown() {
    let s = fs();
    let d = s.record_failure("npub1a", 1000);
    assert_eq!(d.consecutive_failures, 1);
    assert!(d.should_warn);
    assert!(d.cooldown_until_ms.is_none());
    assert!(!d.crossed_threshold);
}

#[test]
fn warn_suppressed_inside_window_then_unsuppressed_after() {
    let s = fs();
    let d1 = s.record_failure("npub1a", 1000);
    let d2 = s.record_failure("npub1a", 1500);
    assert!(d1.should_warn);
    assert!(
        !d2.should_warn,
        "second failure inside 5s window must DEBUG"
    );
    // 5s warn-interval = 5000 ms; bump beyond.
    let d3 = s.record_failure("npub1a", 1000 + 5_500);
    assert!(d3.should_warn, "after window, must WARN again");
}

#[test]
fn streak_threshold_triggers_cooldown_and_signals_crossing() {
    let s = fs();
    let _ = s.record_failure("npub1a", 1000);
    let _ = s.record_failure("npub1a", 1100);
    let d3 = s.record_failure("npub1a", 1200);
    assert_eq!(d3.consecutive_failures, 3);
    assert!(d3.crossed_threshold);
    assert_eq!(d3.cooldown_until_ms, Some(1200 + 10_000));
    // Subsequent failure does NOT re-fire crossed_threshold.
    let d4 = s.record_failure("npub1a", 1300);
    assert!(!d4.crossed_threshold);
    assert!(d4.cooldown_until_ms.is_some());
}

#[test]
fn record_success_clears_streak() {
    let s = fs();
    for t in [1000u64, 1100, 1200, 1300] {
        let _ = s.record_failure("npub1a", t);
    }
    s.record_success("npub1a", 2000);
    let d = s.record_failure("npub1a", 3000);
    assert_eq!(d.consecutive_failures, 1, "streak reset after success");
    assert!(!d.crossed_threshold);
}

#[test]
fn cooldown_until_returns_only_active_cooldowns() {
    let s = fs();
    for t in [1000u64, 1100, 1200] {
        let _ = s.record_failure("npub1a", t);
    }
    // Mid-cooldown
    assert!(s.cooldown_until("npub1a", 5_000).is_some());
    // Past cooldown
    assert!(s.cooldown_until("npub1a", 1200 + 10_001).is_none());
}

#[test]
fn note_observed_skew_creates_entry_for_healthy_peer() {
    let s = fs();
    s.note_observed_skew("npub1healthy", 250, 1000);
    let snap = s.snapshot();
    assert_eq!(snap.len(), 1);
    let (npub, rec) = &snap[0];
    assert_eq!(npub, "npub1healthy");
    assert_eq!(rec.last_observed_skew_ms, Some(250));
    assert_eq!(rec.consecutive_failures, 0);
}

#[test]
fn record_protocol_mismatch_fresh_entry_returns_true() {
    let s = fs();
    // 24h cooldown
    let cooldown_ms = 24 * 60 * 60 * 1000;
    assert!(
        s.record_protocol_mismatch("npub1mismatch", 1000, cooldown_ms),
        "first mismatch must signal fresh — caller should WARN"
    );
    assert_eq!(
        s.cooldown_until("npub1mismatch", 2000),
        Some(1000 + cooldown_ms),
        "cooldown applied immediately"
    );
}

#[test]
fn a_repeat_protocol_mismatch_inside_the_cooldown_does_not_extend_it() {
    let s = fs();
    let cooldown_ms = 24 * 60 * 60 * 1000;
    s.record_protocol_mismatch("npub1mismatch", 1000, cooldown_ms);
    for repeat in [
        31_000,
        1000 + cooldown_ms / 2 + 1,
        1000 + cooldown_ms * 6 / 10,
    ] {
        assert!(
            !s.record_protocol_mismatch("npub1mismatch", repeat, cooldown_ms),
            "a repeat inside the cooldown must NOT signal fresh"
        );
        assert_eq!(
            s.cooldown_until("npub1mismatch", repeat),
            Some(1000 + cooldown_ms),
            "a repeat at {repeat} moved the cooldown"
        );
        let snap = s.snapshot();
        let (_, rec) = snap
            .iter()
            .find(|(n, _)| n == "npub1mismatch")
            .expect("entry present");
        assert_eq!(rec.last_failure_at_ms, repeat);
    }
}

#[test]
fn a_transient_failure_inside_a_mismatch_cooldown_does_not_shorten_it_past_the_next_mismatch() {
    let s = fs();
    let cooldown_ms = 24 * 60 * 60 * 1000;
    s.record_protocol_mismatch("npub1mismatch", 1000, cooldown_ms);
    // A transient failure past the streak threshold writes its own,
    // much shorter, cooldown over the mismatch one.
    let _ = s.record_failure("npub1mismatch", 2000);
    assert!(!s.record_protocol_mismatch("npub1mismatch", 3000, cooldown_ms));
    assert_eq!(
        s.cooldown_until("npub1mismatch", 3000),
        Some(1000 + cooldown_ms)
    );
}

#[test]
fn record_protocol_mismatch_pins_streak_at_threshold() {
    let s = fs();
    s.record_protocol_mismatch("npub1mismatch", 1000, 60_000);
    // Snapshot reflects the threshold pin so show_peers renders the
    // entry as crossed-threshold.
    let snap = s.snapshot();
    let (_, rec) = snap
        .iter()
        .find(|(n, _)| n == "npub1mismatch")
        .expect("entry present");
    assert!(rec.consecutive_failures >= 3);
}

#[test]
fn record_protocol_mismatch_after_old_cooldown_lapsed_signals_fresh() {
    let s = fs();
    let cooldown_ms = 24 * 60 * 60 * 1000;
    s.record_protocol_mismatch("npub1mismatch", 1000, cooldown_ms);
    // Far in the future after cooldown elapsed: a *new* observation
    // is fresh again so the operator gets a fresh WARN log.
    let later = 1000 + cooldown_ms + 1;
    assert!(
        s.record_protocol_mismatch("npub1mismatch", later, cooldown_ms),
        "after the cooldown window has elapsed, the next mismatch is fresh"
    );
}

#[test]
fn size_cap_evicts_oldest_by_last_failure_at() {
    let s = fs(); // cap = 8
    for i in 0..10 {
        let npub = format!("npub1{i}");
        let _ = s.record_failure(&npub, 1000 + i as u64);
    }
    let snap = s.snapshot();
    assert!(snap.len() <= 8, "cap not enforced: {}", snap.len());
    // Oldest two (npub10, npub11) should be evicted; newer kept.
    let names: std::collections::HashSet<_> = snap.iter().map(|(n, _)| n.clone()).collect();
    assert!(!names.contains("npub10"));
    assert!(names.contains("npub19"));
}
