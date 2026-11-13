//! One-way delay trend tests: the bound on the detector's window, and the
//! trend a receiver reports, through `ReceiverState::record_recv` and
//! `build_report`. The trend is the slope of one-way delay against receive
//! time in µs/s: 0 for a steady path at any spacing, and the rate of queue
//! growth when delay rises.

use crate::proto::mmp::algorithms::OwdTrendDetector;
use crate::proto::mmp::receiver::ReceiverState;

/// Feed `frames` frames received every `recv_ms` and sent every `send_ms`,
/// starting at local time `t0` and sender time `ts0`, then build a report at
/// the last arrival and return its `owd_trend`.
fn trend_after(
    rx: &mut ReceiverState,
    frames: u64,
    t0: u64,
    recv_ms: u64,
    ts0: u32,
    send_ms: u32,
) -> i32 {
    let mut now = t0;
    for i in 0..frames {
        now = t0 + i * recv_ms;
        let ts = ts0.wrapping_add(send_ms.wrapping_mul(i as u32));
        rx.record_recv(i + 1, ts, 100, false, now);
    }
    rx.build_report(now)
        .expect("precondition: frames were received, so a report is due")
        .owd_trend
}

#[test]
fn an_owd_detector_asked_for_a_huge_window_does_not_allocate_it() {
    // At base this panics with "capacity overflow" in VecDeque::with_capacity.
    let mut detector = OwdTrendDetector::new(usize::MAX);
    detector.push(0, 0);
    detector.push(1, 1000);
    assert!(detector.trend_us_per_sec() > 0);
}

#[test]
fn an_owd_detector_asked_for_a_zero_window_keeps_two_samples() {
    // With a window of two, the slope comes from the last two samples only:
    // from 1000 µs at x = 1 to 0 at x = 2 is -1000 µs per ms, -1_000_000 µs/s.
    // Over all three samples the regression slope is 0.
    let mut detector = OwdTrendDetector::new(0);
    detector.push(0, 0);
    detector.push(1, 1000);
    detector.push(2, 0);
    assert_eq!(
        detector.trend_us_per_sec(),
        -1_000_000,
        "defect: a zero window must keep the last two samples, not grow"
    );
}

#[test]
fn a_flat_one_way_delay_reports_a_zero_trend_at_any_frame_spacing() {
    for spacing in [10u64, 100, 1000, 3000] {
        let mut rx = ReceiverState::new(32);
        let trend = trend_after(&mut rx, 40, 50_000, spacing, 7, spacing as u32);
        assert_eq!(
            trend, 0,
            "defect: a steady path at {spacing} ms spacing must report a zero trend"
        );
    }
}

#[test]
fn a_one_way_delay_growing_one_ms_per_100_ms_reports_10000_us_per_s() {
    // Received every 100 ms, sent every 99 ms: the delay grows by 1 ms for
    // every 100 ms of receive time, 10 ms per second, 10 000 µs/s.
    let mut rx = ReceiverState::new(32);
    let trend = trend_after(&mut rx, 40, 50_000, 100, 7, 99);
    assert!(
        (trend - 10_000).abs() <= 1,
        "defect: a delay growing 10 ms per second must report 10000 µs/s, got {trend}"
    );
}

#[test]
fn an_old_session_straggler_inside_the_rekey_grace_does_not_skew_the_new_session_trend() {
    // The session layer records old-session stragglers delivered after a
    // cutover. Their sender timestamps belong to the old session's clock, so
    // a straggler taken as the reference would offset every later sample.
    let mut rx = ReceiverState::new(32);
    trend_after(&mut rx, 40, 50_000, 100, 7, 100);
    let t = 60_000;
    rx.reset_for_rekey(t);
    rx.record_recv(900, 5_000_000, 100, false, t + 1_000);
    let trend = trend_after(&mut rx, 20, t + 16_000, 100, 1_000, 100);
    assert_eq!(
        trend, 0,
        "defect: a straggler inside the rekey grace must not skew a flat new-session trend"
    );
}

#[test]
fn a_flat_one_way_delay_still_reports_a_zero_trend_after_2_pow_31_ms_on_one_reference() {
    // The sender-time difference from the reference changes sign as an i32
    // at 2^31 ms, so the reference must restart before then.
    let mut rx = ReceiverState::new(32);
    let t0 = 1_000;
    trend_after(&mut rx, 10, t0, 100, 7, 100);
    let late = 1u64 << 31;
    let trend = trend_after(
        &mut rx,
        10,
        t0 + late,
        100,
        7u32.wrapping_add(late as u32),
        100,
    );
    assert_eq!(
        trend, 0,
        "defect: a steady path must report a zero trend {late} ms after the reference"
    );
}
