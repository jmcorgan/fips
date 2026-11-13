//! The cumulative reorder count in a receiver report saturates at the
//! field's `u32` width instead of wrapping, so a peer never sees it fall.

use crate::proto::mmp::receiver::ReceiverState;
use crate::proto::mmp::{MmpMetrics, ReceiverReport, RrLog};

/// Receive `frames` in-order frames from `first`, set the reorder count to
/// `count`, and build a report at the last arrival.
fn report_with(rx: &mut ReceiverState, first: u64, frames: u64, count: u64) -> ReceiverReport {
    let mut now = 0;
    for c in first..first + frames {
        now = 1_000 + c * 10;
        rx.record_recv(c, c as u32 * 10, 100, false, now);
    }
    rx.set_reorder_count(count);
    rx.build_report(now)
        .expect("precondition: frames were received, so a report is due")
}

#[test]
fn a_reorder_count_past_u32_max_reports_u32_max() {
    let mut rx = ReceiverState::new(32);
    let rr = report_with(&mut rx, 1, 5, u64::from(u32::MAX) + 5);
    assert_eq!(
        rr.cumulative_reorder_count,
        u32::MAX,
        "defect: a reorder count past u32::MAX must saturate, not wrap"
    );
}

#[test]
fn a_reorder_count_crossing_u32_max_does_not_make_the_next_report_stale() {
    let mut rx = ReceiverState::new(32);
    let mut metrics = MmpMetrics::new();
    let first = report_with(&mut rx, 1, 5, u64::from(u32::MAX) - 1);
    let (_, log) = metrics.process_receiver_report(&first, 100_000, 2_000);
    assert!(
        !matches!(log, RrLog::Stale { .. }),
        "precondition: the first report is accepted"
    );
    let second = report_with(&mut rx, 6, 5, u64::from(u32::MAX) + 5);
    assert!(
        second.cumulative_packets_recv > first.cumulative_packets_recv,
        "precondition: the packet counters advance"
    );
    let (_, log) = metrics.process_receiver_report(&second, 100_000, 3_000);
    assert!(
        !matches!(log, RrLog::Stale { .. }),
        "defect: a reorder count crossing u32::MAX made a fresh report look stale"
    );
}
