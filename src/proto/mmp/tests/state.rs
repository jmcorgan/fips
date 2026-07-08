//! Tests for the owned MMP protocol state machines.

use crate::proto::mmp::receiver::{GapTracker, ReceiverState};
use crate::proto::mmp::sender::SenderState;
use crate::proto::mmp::{
    COLD_START_SAMPLES, DEFAULT_LOG_INTERVAL_SECS, DEFAULT_OWD_WINDOW_SIZE, MAX_REPORT_INTERVAL_MS,
    MIN_REPORT_INTERVAL_MS, MmpMetrics, MmpMode, ReceiverReport,
};

// ===========================================================================
// MmpMode
// ===========================================================================

#[test]
fn test_mode_default() {
    assert_eq!(MmpMode::default(), MmpMode::Full);
}

#[test]
fn test_mode_display() {
    assert_eq!(MmpMode::Full.to_string(), "full");
    assert_eq!(MmpMode::Lightweight.to_string(), "lightweight");
    assert_eq!(MmpMode::Minimal.to_string(), "minimal");
}

#[test]
fn test_mode_serde_roundtrip() {
    let yaml = "full";
    let mode: MmpMode = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(mode, MmpMode::Full);

    let yaml = "lightweight";
    let mode: MmpMode = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(mode, MmpMode::Lightweight);

    let yaml = "minimal";
    let mode: MmpMode = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(mode, MmpMode::Minimal);
}

// Sanity: the config defaults that back `MmpConfig`/`SessionMmpConfig` are the
// values the state constructors expect.
#[test]
fn test_config_default_consts() {
    assert_eq!(DEFAULT_LOG_INTERVAL_SECS, 30);
    assert_eq!(DEFAULT_OWD_WINDOW_SIZE, 32);
}

// ===========================================================================
// SenderState
// ===========================================================================

#[test]
fn test_new_sender_state() {
    let s = SenderState::new();
    assert_eq!(s.cumulative_packets_sent(), 0);
}

#[test]
fn test_record_sent() {
    let mut s = SenderState::new();
    s.record_sent(1, 100, 500);
    s.record_sent(2, 200, 600);
    assert_eq!(s.cumulative_packets_sent(), 2);
}

#[test]
fn test_build_report_empty() {
    let mut s = SenderState::new();
    assert!(s.build_report(0).is_none());
}

#[test]
fn test_build_report() {
    let mut s = SenderState::new();
    s.record_sent(10, 1000, 500);
    s.record_sent(11, 1100, 600);
    s.record_sent(12, 1200, 400);

    let report = s.build_report(0).unwrap();
    assert_eq!(report.interval_packets_sent, 3);
    assert_eq!(report.interval_bytes_sent, 1500);
    assert_eq!(report.cumulative_packets_sent, 3);
}

#[test]
fn test_build_report_resets_interval() {
    let mut s = SenderState::new();
    s.record_sent(1, 100, 500);
    let _ = s.build_report(0);

    // Second report with no new data returns None
    assert!(s.build_report(0).is_none());

    // New data starts a fresh interval
    s.record_sent(2, 200, 300);
    let report = s.build_report(0).unwrap();
    assert_eq!(report.interval_packets_sent, 1);
    assert_eq!(report.interval_bytes_sent, 300);
    // Cumulative continues
    assert_eq!(report.cumulative_packets_sent, 2);
}

#[test]
fn test_should_send_report_no_data() {
    let s = SenderState::new();
    assert!(!s.should_send_report(0));
}

#[test]
fn test_should_send_report_first_time() {
    let mut s = SenderState::new();
    s.record_sent(1, 100, 500);
    assert!(s.should_send_report(0));
}

#[test]
fn test_should_send_report_respects_interval() {
    let mut s = SenderState::new();
    let t0 = 0u64;
    s.record_sent(1, 100, 500);
    let _ = s.build_report(t0);

    s.record_sent(2, 200, 500);
    // Immediately after report — should not send
    assert!(!s.should_send_report(t0));

    // After interval elapses
    let t1 = t0 + s.report_interval_ms() + 1;
    assert!(s.should_send_report(t1));
}

#[test]
fn test_update_report_interval_cold_start() {
    let mut s = SenderState::new();
    // During cold-start, floor is 200ms (DEFAULT_COLD_START_INTERVAL_MS)
    // 50ms RTT → 100ms sender interval (2× SRTT), clamped to cold-start floor 200ms
    s.update_report_interval_from_srtt(50_000);
    assert_eq!(s.report_interval_ms(), 200);

    // 500ms RTT → 1000ms sender interval (above cold-start floor)
    s.update_report_interval_from_srtt(500_000);
    assert_eq!(s.report_interval_ms(), 1000);
}

#[test]
fn test_update_report_interval_after_cold_start() {
    let mut s = SenderState::new();
    // Burn through cold-start samples (COLD_START_SAMPLES = 5)
    for _ in 0..COLD_START_SAMPLES {
        s.update_report_interval_from_srtt(500_000);
    }

    // 6th sample: now in steady state, floor is MIN_REPORT_INTERVAL_MS (1000ms)
    // 50ms RTT → 100ms sender interval (2× SRTT), clamped to 1000ms
    s.update_report_interval_from_srtt(50_000);
    assert_eq!(s.report_interval_ms(), MIN_REPORT_INTERVAL_MS);

    // 3s RTT → 6s, clamped to max 5s
    s.update_report_interval_from_srtt(3_000_000);
    assert_eq!(s.report_interval_ms(), MAX_REPORT_INTERVAL_MS);
}

#[test]
fn test_backoff_multiplier_progression() {
    let mut s = SenderState::new();

    // No failures → multiplier 1.0
    assert_eq!(s.send_failure_backoff_multiplier(), 1.0);
    assert_eq!(s.consecutive_send_failures(), 0);

    // Progressive failures: 2^1, 2^2, 2^3, 2^4, 2^5
    let expected = [2.0, 4.0, 8.0, 16.0, 32.0];
    for (i, &exp) in expected.iter().enumerate() {
        let count = s.record_send_failure();
        assert_eq!(count, (i + 1) as u32);
        assert_eq!(s.send_failure_backoff_multiplier(), exp);
    }

    // Beyond 5 failures: stays capped at 32.0
    s.record_send_failure(); // 6th
    assert_eq!(s.send_failure_backoff_multiplier(), 32.0);
    s.record_send_failure(); // 7th
    assert_eq!(s.send_failure_backoff_multiplier(), 32.0);
}

#[test]
fn test_backoff_reset_on_success() {
    let mut s = SenderState::new();

    // Accumulate failures
    s.record_send_failure();
    s.record_send_failure();
    s.record_send_failure();
    assert_eq!(s.consecutive_send_failures(), 3);
    assert_eq!(s.send_failure_backoff_multiplier(), 8.0);

    // Success resets and returns previous count
    let prev = s.record_send_success();
    assert_eq!(prev, 3);
    assert_eq!(s.consecutive_send_failures(), 0);
    assert_eq!(s.send_failure_backoff_multiplier(), 1.0);
}

#[test]
fn test_backoff_success_with_no_prior_failures() {
    let mut s = SenderState::new();

    // Success with no failures returns 0
    let prev = s.record_send_success();
    assert_eq!(prev, 0);
    assert_eq!(s.consecutive_send_failures(), 0);
}

#[test]
fn test_should_send_report_respects_backoff() {
    let mut s = SenderState::new();
    let t0 = 0u64;
    s.record_sent(1, 100, 500);
    let _ = s.build_report(t0);

    // Record a failure: multiplier becomes 2.0
    s.record_send_failure();

    s.record_sent(2, 200, 500);

    // At 1× interval: should NOT send (backoff requires 2×)
    let t1 = t0 + s.report_interval_ms() + 1;
    assert!(!s.should_send_report(t1));

    // At 2× interval: should send
    let t2 = t0 + s.report_interval_ms() * 2 + 1;
    assert!(s.should_send_report(t2));
}

// ===========================================================================
// ReceiverState
// ===========================================================================

#[test]
fn test_new_receiver_state() {
    let r = ReceiverState::new(32);
    assert_eq!(r.cumulative_packets_recv(), 0);
    assert_eq!(r.cumulative_bytes_recv(), 0);
    assert_eq!(r.highest_counter(), 0);
}

#[test]
fn test_record_recv_basic() {
    let mut r = ReceiverState::new(32);
    r.record_recv(1, 100, 500, false, 0);
    r.record_recv(2, 200, 600, false, 100);

    assert_eq!(r.cumulative_packets_recv(), 2);
    assert_eq!(r.cumulative_bytes_recv(), 1100);
    assert_eq!(r.highest_counter(), 2);
}

#[test]
fn test_reorder_detection() {
    let mut r = ReceiverState::new(32);
    r.record_recv(5, 500, 100, false, 0);
    r.record_recv(3, 300, 100, false, 10);

    // Reorder count is surfaced through the report (no direct field accessor).
    let rr = r.build_report(20).unwrap();
    assert_eq!(rr.cumulative_reorder_count, 1);
    assert_eq!(r.highest_counter(), 5); // not changed by out-of-order
}

#[test]
fn test_ecn_counting() {
    let mut r = ReceiverState::new(32);
    r.record_recv(1, 100, 100, true, 0);
    r.record_recv(2, 200, 100, false, 0);
    r.record_recv(3, 300, 100, true, 0);

    assert_eq!(r.ecn_ce_count(), 2);
}

#[test]
fn test_receiver_build_report_empty() {
    let mut r = ReceiverState::new(32);
    assert!(r.build_report(0).is_none());
}

#[test]
fn test_receiver_build_report() {
    let mut r = ReceiverState::new(32);
    let t0 = 0u64;
    r.record_recv(1, 100, 500, false, t0);
    r.record_recv(2, 200, 600, false, t0 + 100);

    let report = r.build_report(t0 + 150).unwrap();
    assert_eq!(report.highest_counter, 2);
    assert_eq!(report.cumulative_packets_recv, 2);
    assert_eq!(report.cumulative_bytes_recv, 1100);
    assert_eq!(report.timestamp_echo, 200); // last sender timestamp
}

#[test]
fn test_build_report_suppresses_rtt_echo_when_dwell_overflows() {
    let mut r = ReceiverState::new(32);
    let t0 = 0u64;
    r.record_recv(1, 100, 500, false, t0);

    let report = r.build_report(t0 + u64::from(u16::MAX) + 1).unwrap();

    assert_eq!(report.timestamp_echo, 0);
    assert_eq!(report.dwell_time, u16::MAX);
    assert_eq!(report.cumulative_packets_recv, 1);
}

#[test]
fn test_receiver_build_report_resets_interval() {
    let mut r = ReceiverState::new(32);
    let t0 = 0u64;
    r.record_recv(1, 100, 500, false, t0);
    let _ = r.build_report(t0);

    // No new data
    assert!(r.build_report(t0).is_none());

    // New data
    r.record_recv(2, 200, 300, false, t0 + 100);
    let report = r.build_report(t0 + 150).unwrap();
    // Cumulative continues
    assert_eq!(report.cumulative_packets_recv, 2);
}

// The private `GapTracker` burst detection is exercised directly through its
// `observe`/`take_interval_stats` surface (counter gaps -> burst-loss stats).

#[test]
fn test_gap_tracker_no_loss() {
    let mut g = GapTracker::new();
    g.observe(1);
    g.observe(2);
    g.observe(3);
    let (count, max, mean) = g.take_interval_stats();
    assert_eq!(count, 0);
    assert_eq!(max, 0);
    assert_eq!(mean, 0);
}

#[test]
fn test_gap_tracker_single_burst() {
    let mut g = GapTracker::new();
    g.observe(1);
    // frames 2, 3 lost
    g.observe(4);
    g.observe(5);
    let (count, max, _mean) = g.take_interval_stats();
    assert_eq!(count, 1);
    assert_eq!(max, 2);
}

#[test]
fn test_gap_tracker_multiple_bursts() {
    let mut g = GapTracker::new();
    g.observe(1);
    g.observe(4); // burst of 2 (frames 2,3 lost)
    g.observe(5);
    g.observe(8); // burst of 2 (frames 6,7 lost)
    g.observe(9);
    let (count, max, mean) = g.take_interval_stats();
    assert_eq!(count, 2);
    assert_eq!(max, 2);
    // mean = 2.0 in u8.8 = 512
    assert_eq!(mean, 512);
}

#[test]
fn test_should_send_report_timing() {
    let mut r = ReceiverState::new(32);
    let t0 = 0u64;

    assert!(!r.should_send_report(t0)); // no data

    r.record_recv(1, 100, 500, false, t0);
    assert!(r.should_send_report(t0)); // first time, has data

    let _ = r.build_report(t0);
    r.record_recv(2, 200, 500, false, t0);
    assert!(!r.should_send_report(t0)); // just reported

    let t1 = t0 + r.report_interval_ms() + 1;
    assert!(r.should_send_report(t1));
}

#[test]
fn test_receiver_update_report_interval_cold_start() {
    let mut r = ReceiverState::new(32);
    // During cold-start, floor is 200ms (DEFAULT_COLD_START_INTERVAL_MS)
    // 50ms SRTT → 50ms receiver interval (1× SRTT), clamped to cold-start floor 200ms
    r.update_report_interval_from_srtt(50_000);
    assert_eq!(r.report_interval_ms(), 200);

    // 500ms SRTT → 500ms (above cold-start floor)
    r.update_report_interval_from_srtt(500_000);
    assert_eq!(r.report_interval_ms(), 500);
}

#[test]
fn test_receiver_update_report_interval_after_cold_start() {
    let mut r = ReceiverState::new(32);
    // Burn through cold-start samples
    for _ in 0..COLD_START_SAMPLES {
        r.update_report_interval_from_srtt(500_000);
    }

    // 6th sample: steady state, floor is MIN_REPORT_INTERVAL_MS (1000ms)
    // 50ms SRTT → 50ms receiver interval (1× SRTT), clamped to 1000ms
    r.update_report_interval_from_srtt(50_000);
    assert_eq!(r.report_interval_ms(), MIN_REPORT_INTERVAL_MS);

    // 3s SRTT → 3000ms, within [1000, 5000]
    r.update_report_interval_from_srtt(3_000_000);
    assert_eq!(r.report_interval_ms(), 3000);
}

#[test]
fn test_rekey_jitter_grace_suppresses_spikes() {
    let mut r = ReceiverState::new(32);
    let t0 = 0u64;

    // Establish baseline with two frames so jitter starts updating
    r.record_recv(1, 1000, 100, false, t0);
    r.record_recv(2, 2000, 100, false, t0 + 1000);
    assert_eq!(r.jitter_us(), 0); // perfect 1s spacing → 0 jitter

    // Simulate rekey: reset, then send a frame with a large old-session
    // timestamp followed by a new-session timestamp near zero.
    // Without grace, this would produce a huge jitter spike.
    r.reset_for_rekey(t0 + 2000);

    // Frame arrives during grace period with old-session timestamp
    r.record_recv(0, 120_000, 100, false, t0 + 3000);
    // Next frame with new-session timestamp near zero
    r.record_recv(1, 100, 100, false, t0 + 4000);
    // Jitter should still be zero — updates suppressed during grace
    assert_eq!(r.jitter_us(), 0);

    // After grace expires, jitter updates resume. Grace = 15s from reset.
    let after_grace = t0 + 2000 + (15 + 1) * 1000;
    r.record_recv(2, 200, 100, false, after_grace);
    r.record_recv(3, 300, 100, false, after_grace + 100);
    // Now jitter should be updating (non-zero or zero depending on timing)
    // The key assertion is that it's not a multi-second spike
    assert!(r.jitter_us() < 1_000_000); // less than 1 second
}

// ===========================================================================
// MmpMetrics
// ===========================================================================

fn make_rr(
    highest_counter: u64,
    cum_packets: u64,
    cum_bytes: u64,
    timestamp_echo: u32,
    dwell: u16,
    jitter: u32,
) -> ReceiverReport {
    ReceiverReport {
        timestamp_echo,
        dwell_time: dwell,
        highest_counter,
        cumulative_packets_recv: cum_packets,
        cumulative_bytes_recv: cum_bytes,
        jitter,
        ecn_ce_count: 0,
        owd_trend: 0,
        burst_loss_count: 0,
        cumulative_reorder_count: 0,
    }
}

#[test]
fn test_rtt_from_echo() {
    let mut m = MmpMetrics::new();
    // Peer echoes timestamp 1000ms, dwell=5ms, our current time=1050ms
    let rr = make_rr(10, 10, 5000, 1000, 5, 0);
    m.process_receiver_report(&rr, 1050, 0);

    assert!(m.srtt.initialized());
    // RTT = 1050 - 1000 - 5 = 45ms
    let srtt_ms = m.srtt_ms().unwrap();
    assert!((srtt_ms - 45.0).abs() < 1.0, "srtt={srtt_ms}, expected ~45");
}

#[test]
fn test_ignores_duplicate_receiver_report_after_valid_sample() {
    let mut m = MmpMetrics::new();
    let t0 = 0u64;

    let rr1 = make_rr(10, 10, 5_000, 1_000, 5, 0);
    m.process_receiver_report(&rr1, 1_050, t0);

    let rr2 = make_rr(20, 18, 14_000, 1_100, 5, 0);
    m.process_receiver_report(&rr2, 1_150, t0 + 1000);
    let baseline_srtt_ms = m.srtt_ms().unwrap();
    let baseline_loss = m.loss_rate();
    let baseline_goodput = m.goodput_bps();

    assert!(baseline_loss > 0.0);
    assert!(baseline_goodput > 0.0);

    // A duplicate of the same counters arriving later would be a 4.895s
    // RTT sample if accepted. It is stale and must not move metrics.
    m.process_receiver_report(&rr2, 6_000, t0 + 5000);

    assert_eq!(m.srtt_ms().unwrap(), baseline_srtt_ms);
    assert_eq!(m.loss_rate(), baseline_loss);
    assert_eq!(m.goodput_bps(), baseline_goodput);
}

#[test]
fn test_ignores_out_of_order_receiver_report_after_valid_sample() {
    let mut m = MmpMetrics::new();

    let valid_rr = make_rr(20, 20, 10000, 1000, 5, 0);
    m.process_receiver_report(&valid_rr, 1050, 0);
    let baseline_srtt_ms = m.srtt_ms().unwrap();

    let old_rr = make_rr(10, 10, 5000, 1000, 0, 0);
    m.process_receiver_report(&old_rr, 6000, 5000);

    let srtt_ms = m.srtt_ms().unwrap();
    assert_eq!(srtt_ms, baseline_srtt_ms);
}

#[test]
fn test_ignores_wrapped_rtt_sample() {
    let mut m = MmpMetrics::new();

    let wrapped_rr = make_rr(10, 10, 5000, u32::MAX - 10, 20, 0);
    m.process_receiver_report(&wrapped_rr, 15, 0);

    assert!(m.srtt_ms().is_none());
}

#[test]
fn test_ignores_future_rtt_sample() {
    let mut m = MmpMetrics::new();

    let future_rr = make_rr(10, 10, 5_000, 2_000, 5, 0);
    m.process_receiver_report(&future_rr, 1_000, 0);

    assert!(m.srtt_ms().is_none());
}

#[test]
fn test_loss_rate_computation() {
    let mut m = MmpMetrics::new();
    let t0 = 0u64;

    // First report: baseline
    let rr1 = make_rr(100, 100, 50000, 0, 0, 0);
    m.process_receiver_report(&rr1, 0, t0);

    // Second report: 200 counters sent, 190 received (5% loss)
    let rr2 = make_rr(300, 290, 145000, 0, 0, 0);
    m.process_receiver_report(&rr2, 0, t0 + 1000);

    let loss = m.loss_rate();
    assert!((loss - 0.05).abs() < 0.01, "loss={loss}, expected ~0.05");
}

#[test]
fn test_etx_updates() {
    let mut m = MmpMetrics::new();
    assert_eq!(m.etx, 1.0); // initial: perfect

    // Simulate some loss via forward ratio
    m.delivery_ratio_forward = 0.9;

    // First call establishes the baseline (no ETX update yet)
    m.update_reverse_delivery(100, 100);
    assert_eq!(m.etx, 1.0); // still perfect — baseline only

    // Second call: 190 of 200 frames received (5% loss)
    m.update_reverse_delivery(290, 300);
    assert!(m.etx > 1.0);
    assert!(m.etx < 2.0);
}

#[test]
fn test_no_rtt_without_echo() {
    let mut m = MmpMetrics::new();
    let rr = make_rr(10, 10, 5000, 0, 0, 0);
    m.process_receiver_report(&rr, 1000, 0);
    assert!(m.srtt_ms().is_none());
}

#[test]
fn test_jitter_trend() {
    let mut m = MmpMetrics::new();
    let t0 = 0u64;
    let rr1 = make_rr(10, 10, 5000, 0, 0, 100);
    m.process_receiver_report(&rr1, 0, t0);

    let rr2 = make_rr(20, 20, 10000, 0, 0, 500);
    m.process_receiver_report(&rr2, 0, t0 + 1000);

    assert!(m.jitter_trend.initialized());
    // Short-term should be closer to 500 than long-term
    assert!(m.jitter_trend.short() > m.jitter_trend.long());
}

#[test]
fn test_goodput_bps() {
    let mut m = MmpMetrics::new();
    let t0 = 0u64;

    // First report: baseline (50KB received)
    let rr1 = make_rr(100, 100, 50_000, 0, 0, 0);
    m.process_receiver_report(&rr1, 0, t0);
    assert_eq!(m.goodput_bps(), 0.0); // no rate yet (first report)

    // Second report 1s later: 150KB total (100KB delta in 1s = 100KB/s)
    let rr2 = make_rr(300, 290, 150_000, 0, 0, 0);
    m.process_receiver_report(&rr2, 0, t0 + 1000);
    assert!(
        m.goodput_bps() > 90_000.0,
        "goodput={}, expected ~100000",
        m.goodput_bps()
    );
    assert!(
        m.goodput_bps() < 110_000.0,
        "goodput={}, expected ~100000",
        m.goodput_bps()
    );
}

#[test]
fn test_reverse_delivery_delta() {
    let mut m = MmpMetrics::new();

    // First call: baseline only, no ratio update
    m.update_reverse_delivery(100, 100);
    assert_eq!(m.delivery_ratio_reverse, 1.0); // unchanged from default

    // Second call: perfect delivery (200 new frames, all received)
    m.update_reverse_delivery(300, 300);
    assert!((m.delivery_ratio_reverse - 1.0).abs() < 0.001);

    // Third call: 50% loss (100 frames sent, 50 received)
    m.update_reverse_delivery(350, 400);
    assert!(
        (m.delivery_ratio_reverse - 0.5).abs() < 0.001,
        "reverse={}, expected 0.5",
        m.delivery_ratio_reverse
    );
}

#[test]
fn test_reverse_delivery_rekey_reset() {
    let mut m = MmpMetrics::new();

    // Establish baseline and one measurement
    m.update_reverse_delivery(100, 100);
    m.update_reverse_delivery(300, 300);
    assert!((m.delivery_ratio_reverse - 1.0).abs() < 0.001);

    // Rekey resets reverse state
    m.reset_for_rekey();

    // First call after rekey: baseline only
    m.update_reverse_delivery(50, 50);
    // delivery_ratio_reverse was reset to 1.0 by reset_for_rekey's
    // clearing of delivery_ratio_forward; reverse is not explicitly
    // reset — but the delta state is, so next call computes fresh.
    assert_eq!(m.delivery_ratio_reverse, 1.0);

    // Second call after rekey: 80% delivery
    m.update_reverse_delivery(90, 100);
    assert!(
        (m.delivery_ratio_reverse - 0.8).abs() < 0.001,
        "reverse={}, expected 0.8",
        m.delivery_ratio_reverse
    );
}
