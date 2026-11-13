//! The smoothed ETX moves once per accepted receiver report: not again when
//! the reverse delivery ratio is refreshed after it, and not on a stale
//! report.

use crate::proto::mmp::algorithms::{DualEwma, compute_etx};
use crate::proto::mmp::{MmpMetrics, ReceiverReport};

/// A report with the given counters and nothing else.
fn rr(highest_counter: u64, packets: u64) -> ReceiverReport {
    ReceiverReport {
        highest_counter,
        cumulative_packets_recv: packets,
        cumulative_bytes_recv: packets * 100,
        timestamp_echo: 0,
        dwell_time: 0,
        max_burst_loss: 0,
        mean_burst_loss: 0,
        jitter: 0,
        ecn_ce_count: 0,
        owd_trend: 0,
        burst_loss_count: 0,
        cumulative_reorder_count: 0,
        interval_packets_recv: 0,
        interval_bytes_recv: 0,
    }
}

/// The trend's observable state: initialized, short and long averages.
fn snapshot(e: &DualEwma) -> (bool, f64, f64) {
    (e.initialized(), e.short(), e.long())
}

#[test]
fn refreshing_the_reverse_delivery_ratio_alone_leaves_the_etx_trend_unchanged() {
    let mut m = MmpMetrics::new();
    m.update_reverse_delivery(100, 100);
    let before = snapshot(&m.etx_trend);
    m.update_reverse_delivery(150, 200);
    let first = m.delivery_ratio_reverse;
    m.update_reverse_delivery(240, 300);
    let second = m.delivery_ratio_reverse;
    assert!(
        first < 1.0 && second < 1.0 && first != second,
        "precondition: each refresh changed the reverse ratio ({first}, {second})"
    );
    assert_eq!(
        snapshot(&m.etx_trend),
        before,
        "defect: a reverse ratio refresh moved the smoothed ETX outside a report"
    );
}

#[test]
fn a_stale_receiver_report_followed_by_a_reverse_refresh_leaves_the_etx_trend_unchanged() {
    let mut m = MmpMetrics::new();
    m.update_reverse_delivery(100, 100);
    m.process_receiver_report(&rr(100, 100), 0, 1_000);
    m.process_receiver_report(&rr(200, 180), 0, 2_000);
    assert!(
        m.etx_trend.initialized(),
        "precondition: an accepted report fed the trend"
    );
    let before = snapshot(&m.etx_trend);
    // The same counters again: a duplicate, ignored as stale.
    m.process_receiver_report(&rr(200, 180), 0, 3_000);
    m.update_reverse_delivery(150, 200);
    assert!(
        m.delivery_ratio_reverse < 1.0,
        "precondition: the reverse ratio changed"
    );
    assert_eq!(
        snapshot(&m.etx_trend),
        before,
        "defect: a stale report and the reverse refresh after it moved the smoothed ETX"
    );
}

#[test]
fn one_accepted_receiver_report_steps_the_etx_trend_exactly_once() {
    // The handler order: each report is processed, then the reverse ratio
    // is refreshed from this node's own receiver counters.
    let mut m = MmpMetrics::new();
    m.update_reverse_delivery(100, 100);
    m.process_receiver_report(&rr(100, 100), 0, 1_000);
    m.update_reverse_delivery(190, 200);
    let reverse = m.delivery_ratio_reverse;
    m.process_receiver_report(&rr(200, 180), 0, 2_000);
    m.update_reverse_delivery(290, 300);

    let mut expected = DualEwma::new();
    expected.update(compute_etx(0.8, reverse));
    assert_eq!(
        snapshot(&m.etx_trend),
        snapshot(&expected),
        "defect: the smoothed ETX must take one step per accepted report"
    );
}
