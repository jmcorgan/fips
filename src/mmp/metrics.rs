//! MMP derived metrics.
//!
//! `MmpMetrics` processes incoming ReceiverReports (from our peer) and
//! maintains derived metrics: SRTT, loss rate, goodput, ETX, and dual
//! EWMA trend indicators. Updated by the sender side when it receives
//! a ReceiverReport about its own traffic.

use crate::mmp::algorithms::{DualEwma, SrttEstimator, compute_etx};
use crate::mmp::report::ReceiverReport;
use std::time::Instant;

/// Derived MMP metrics, updated from incoming ReceiverReports.
///
/// This lives on the sender side: when we receive a ReceiverReport from
/// our peer describing what they observed about our traffic, we process
/// it here to compute RTT, loss, goodput, and trend indicators.
pub struct MmpMetrics {
    /// Smoothed RTT from timestamp echo.
    pub srtt: SrttEstimator,

    /// Dual EWMA trend detectors.
    pub rtt_trend: DualEwma,
    pub loss_trend: DualEwma,
    pub goodput_trend: DualEwma,
    pub jitter_trend: DualEwma,

    /// Forward delivery ratio (what fraction of our frames the peer received).
    pub delivery_ratio_forward: f64,
    /// Reverse delivery ratio (set when we compute from our own receiver state).
    pub delivery_ratio_reverse: f64,
    /// ETX computed from bidirectional delivery ratios.
    pub etx: f64,

    /// Smoothed goodput in bytes/sec (forward direction: what the peer received from us).
    pub goodput_bps: f64,

    // --- State for delta computation ---
    /// Previous ReceiverReport's cumulative counters (for computing interval deltas).
    prev_rr_cum_packets: u64,
    prev_rr_cum_bytes: u64,
    prev_rr_highest_counter: u64,
    prev_rr_ecn_ce: u32,
    prev_rr_reorder: u32,
    /// Time of previous ReceiverReport (for goodput rate computation).
    prev_rr_time: Option<Instant>,
}

impl MmpMetrics {
    pub fn new() -> Self {
        Self {
            srtt: SrttEstimator::new(),
            rtt_trend: DualEwma::new(),
            loss_trend: DualEwma::new(),
            goodput_trend: DualEwma::new(),
            jitter_trend: DualEwma::new(),
            delivery_ratio_forward: 1.0,
            delivery_ratio_reverse: 1.0,
            etx: 1.0,
            goodput_bps: 0.0,
            prev_rr_cum_packets: 0,
            prev_rr_cum_bytes: 0,
            prev_rr_highest_counter: 0,
            prev_rr_ecn_ce: 0,
            prev_rr_reorder: 0,
            prev_rr_time: None,
        }
    }

    /// Process an incoming ReceiverReport (from the peer about our traffic).
    ///
    /// `our_timestamp_ms` is the current session-relative time in ms (for RTT).
    /// `now` is the current monotonic time (for goodput rate computation).
    pub fn process_receiver_report(&mut self, rr: &ReceiverReport, our_timestamp_ms: u32, now: Instant) {
        // --- RTT from timestamp echo ---
        // RTT = now - echoed_timestamp - dwell_time
        if rr.timestamp_echo > 0 {
            let echo_ms = rr.timestamp_echo;
            let dwell_ms = rr.dwell_time as u32;
            // Guard against timestamp wrap or bogus values
            if our_timestamp_ms > echo_ms + dwell_ms {
                let rtt_ms = our_timestamp_ms - echo_ms - dwell_ms;
                let rtt_us = (rtt_ms as i64) * 1000;
                self.srtt.update(rtt_us);
                self.rtt_trend.update(rtt_us as f64);
            }
        }

        // --- Loss rate from cumulative counters ---
        // Delta: frames the peer should have received vs. actually received
        if self.prev_rr_highest_counter > 0 {
            let counter_span = rr.highest_counter.saturating_sub(self.prev_rr_highest_counter);
            let packets_delta = rr.cumulative_packets_recv.saturating_sub(self.prev_rr_cum_packets);

            if counter_span > 0 {
                let delivery = (packets_delta as f64) / (counter_span as f64);
                self.delivery_ratio_forward = delivery.clamp(0.0, 1.0);
                let loss_rate = 1.0 - self.delivery_ratio_forward;
                self.loss_trend.update(loss_rate);
                self.etx = compute_etx(self.delivery_ratio_forward, self.delivery_ratio_reverse);
            }
        }

        // --- Goodput from cumulative bytes + time delta ---
        if self.prev_rr_cum_bytes > 0 {
            let bytes_delta = rr.cumulative_bytes_recv.saturating_sub(self.prev_rr_cum_bytes);
            self.goodput_trend.update(bytes_delta as f64);

            // Compute bytes/sec if we have a time reference
            if let Some(prev_time) = self.prev_rr_time {
                let elapsed = now.duration_since(prev_time);
                let secs = elapsed.as_secs_f64();
                if secs > 0.0 {
                    let bps = bytes_delta as f64 / secs;
                    // EWMA smoothing: α = 1/4
                    if self.goodput_bps == 0.0 {
                        self.goodput_bps = bps;
                    } else {
                        self.goodput_bps += (bps - self.goodput_bps) * 0.25;
                    }
                }
            }
        }

        // --- Jitter trend ---
        self.jitter_trend.update(rr.jitter as f64);

        // --- Save for next delta ---
        self.prev_rr_cum_packets = rr.cumulative_packets_recv;
        self.prev_rr_cum_bytes = rr.cumulative_bytes_recv;
        self.prev_rr_highest_counter = rr.highest_counter;
        self.prev_rr_ecn_ce = rr.ecn_ce_count;
        self.prev_rr_reorder = rr.cumulative_reorder_count;
        self.prev_rr_time = Some(now);
    }

    /// Update the reverse delivery ratio (from our own receiver state about the peer's traffic).
    pub fn set_delivery_ratio_reverse(&mut self, ratio: f64) {
        self.delivery_ratio_reverse = ratio.clamp(0.0, 1.0);
        self.etx = compute_etx(self.delivery_ratio_forward, self.delivery_ratio_reverse);
    }

    /// Current smoothed RTT in milliseconds, or `None` if not yet measured.
    pub fn srtt_ms(&self) -> Option<f64> {
        if self.srtt.initialized() {
            Some(self.srtt.srtt_us() as f64 / 1000.0)
        } else {
            None
        }
    }

    /// Current loss rate (0.0 = no loss, 1.0 = total loss).
    pub fn loss_rate(&self) -> f64 {
        1.0 - self.delivery_ratio_forward
    }

    /// Current smoothed goodput in bytes/sec, or 0 if not yet measured.
    pub fn goodput_bps(&self) -> f64 {
        self.goodput_bps
    }
}

impl Default for MmpMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_rr(
        highest_counter: u64,
        cum_packets: u64,
        cum_bytes: u64,
        timestamp_echo: u32,
        dwell: u16,
        jitter: u32,
    ) -> ReceiverReport {
        ReceiverReport {
            highest_counter,
            cumulative_packets_recv: cum_packets,
            cumulative_bytes_recv: cum_bytes,
            timestamp_echo,
            dwell_time: dwell,
            max_burst_loss: 0,
            mean_burst_loss: 0,
            jitter,
            ecn_ce_count: 0,
            owd_trend: 0,
            burst_loss_count: 0,
            cumulative_reorder_count: 0,
            interval_packets_recv: 0,
            interval_bytes_recv: 0,
        }
    }

    #[test]
    fn test_rtt_from_echo() {
        let mut m = MmpMetrics::new();
        let now = Instant::now();
        // Peer echoes timestamp 1000ms, dwell=5ms, our current time=1050ms
        let rr = make_rr(10, 10, 5000, 1000, 5, 0);
        m.process_receiver_report(&rr, 1050, now);

        assert!(m.srtt.initialized());
        // RTT = 1050 - 1000 - 5 = 45ms
        let srtt_ms = m.srtt_ms().unwrap();
        assert!((srtt_ms - 45.0).abs() < 1.0, "srtt={srtt_ms}, expected ~45");
    }

    #[test]
    fn test_loss_rate_computation() {
        let mut m = MmpMetrics::new();
        let t0 = Instant::now();

        // First report: baseline
        let rr1 = make_rr(100, 100, 50000, 0, 0, 0);
        m.process_receiver_report(&rr1, 0, t0);

        // Second report: 200 counters sent, 190 received (5% loss)
        let rr2 = make_rr(300, 290, 145000, 0, 0, 0);
        m.process_receiver_report(&rr2, 0, t0 + Duration::from_secs(1));

        let loss = m.loss_rate();
        assert!((loss - 0.05).abs() < 0.01, "loss={loss}, expected ~0.05");
    }

    #[test]
    fn test_etx_updates() {
        let mut m = MmpMetrics::new();
        assert_eq!(m.etx, 1.0); // initial: perfect

        // Simulate some loss
        m.delivery_ratio_forward = 0.9;
        m.set_delivery_ratio_reverse(0.95);
        assert!(m.etx > 1.0);
        assert!(m.etx < 2.0);
    }

    #[test]
    fn test_no_rtt_without_echo() {
        let mut m = MmpMetrics::new();
        let now = Instant::now();
        let rr = make_rr(10, 10, 5000, 0, 0, 0);
        m.process_receiver_report(&rr, 1000, now);
        assert!(m.srtt_ms().is_none());
    }

    #[test]
    fn test_jitter_trend() {
        let mut m = MmpMetrics::new();
        let t0 = Instant::now();
        let rr1 = make_rr(10, 10, 5000, 0, 0, 100);
        m.process_receiver_report(&rr1, 0, t0);

        let rr2 = make_rr(20, 20, 10000, 0, 0, 500);
        m.process_receiver_report(&rr2, 0, t0 + Duration::from_secs(1));

        assert!(m.jitter_trend.initialized());
        // Short-term should be closer to 500 than long-term
        assert!(m.jitter_trend.short() > m.jitter_trend.long());
    }

    #[test]
    fn test_goodput_bps() {
        let mut m = MmpMetrics::new();
        let t0 = Instant::now();

        // First report: baseline (50KB received)
        let rr1 = make_rr(100, 100, 50_000, 0, 0, 0);
        m.process_receiver_report(&rr1, 0, t0);
        assert_eq!(m.goodput_bps(), 0.0); // no rate yet (first report)

        // Second report 1s later: 150KB total (100KB delta in 1s = 100KB/s)
        let rr2 = make_rr(300, 290, 150_000, 0, 0, 0);
        m.process_receiver_report(&rr2, 0, t0 + Duration::from_secs(1));
        assert!(m.goodput_bps() > 90_000.0, "goodput={}, expected ~100000", m.goodput_bps());
        assert!(m.goodput_bps() < 110_000.0, "goodput={}, expected ~100000", m.goodput_bps());
    }
}
