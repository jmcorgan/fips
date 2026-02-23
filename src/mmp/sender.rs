//! MMP sender state machine.
//!
//! Tracks what this node has sent to a specific peer and produces
//! SenderReport messages on demand. One `SenderState` per active peer.

use std::time::{Duration, Instant};

use crate::mmp::report::SenderReport;
use crate::mmp::{DEFAULT_COLD_START_INTERVAL_MS, MAX_REPORT_INTERVAL_MS, MIN_REPORT_INTERVAL_MS};

/// Per-peer sender-side MMP state.
///
/// Records cumulative and interval counters for every frame transmitted
/// to this peer. Produces `SenderReport` snapshots on demand.
pub struct SenderState {
    // --- Cumulative (lifetime) ---
    cumulative_packets_sent: u64,
    cumulative_bytes_sent: u64,

    // --- Current interval ---
    interval_start_counter: u64,
    interval_start_timestamp: u32,
    interval_bytes_sent: u32,
    /// Counter of the most recently sent frame.
    last_counter: u64,
    /// Timestamp of the most recently sent frame.
    last_timestamp: u32,
    /// Whether any frames have been sent in the current interval.
    interval_has_data: bool,

    // --- Report timing ---
    last_report_time: Option<Instant>,
    report_interval: Duration,

    // --- Send failure backoff ---
    /// Consecutive send failure count for backoff calculation.
    consecutive_send_failures: u32,
}

impl SenderState {
    pub fn new() -> Self {
        Self::new_with_cold_start(DEFAULT_COLD_START_INTERVAL_MS)
    }

    /// Create with a custom cold-start interval (ms).
    ///
    /// Used by session-layer MMP which needs a longer initial interval
    /// since reports consume bandwidth on every transit link.
    pub fn new_with_cold_start(cold_start_ms: u64) -> Self {
        Self {
            cumulative_packets_sent: 0,
            cumulative_bytes_sent: 0,
            interval_start_counter: 0,
            interval_start_timestamp: 0,
            interval_bytes_sent: 0,
            last_counter: 0,
            last_timestamp: 0,
            interval_has_data: false,
            last_report_time: None,
            report_interval: Duration::from_millis(cold_start_ms),
            consecutive_send_failures: 0,
        }
    }

    /// Record a frame sent to this peer.
    ///
    /// Called on the TX path for every encrypted link message.
    /// `counter` is the AEAD nonce/counter, `timestamp` is the inner header
    /// session-relative timestamp (ms), `bytes` is the wire payload size.
    pub fn record_sent(&mut self, counter: u64, timestamp: u32, bytes: usize) {
        if !self.interval_has_data {
            self.interval_start_counter = counter;
            self.interval_start_timestamp = timestamp;
            self.interval_has_data = true;
        }
        self.last_counter = counter;
        self.last_timestamp = timestamp;
        self.interval_bytes_sent = self.interval_bytes_sent.saturating_add(bytes as u32);
        self.cumulative_packets_sent += 1;
        self.cumulative_bytes_sent += bytes as u64;
    }

    /// Build a SenderReport from current state and reset the interval.
    ///
    /// Returns `None` if no frames have been sent since the last report.
    pub fn build_report(&mut self, now: Instant) -> Option<SenderReport> {
        if !self.interval_has_data {
            return None;
        }

        let report = SenderReport {
            interval_start_counter: self.interval_start_counter,
            interval_end_counter: self.last_counter,
            interval_start_timestamp: self.interval_start_timestamp,
            interval_end_timestamp: self.last_timestamp,
            interval_bytes_sent: self.interval_bytes_sent,
            cumulative_packets_sent: self.cumulative_packets_sent,
            cumulative_bytes_sent: self.cumulative_bytes_sent,
        };

        // Reset interval
        self.interval_has_data = false;
        self.interval_bytes_sent = 0;
        self.last_report_time = Some(now);

        Some(report)
    }

    /// Check if it's time to send a report.
    ///
    /// When consecutive send failures have occurred, the effective interval
    /// is multiplied by an exponential backoff factor (2^failures, capped at 32×).
    pub fn should_send_report(&self, now: Instant) -> bool {
        if !self.interval_has_data {
            return false;
        }
        match self.last_report_time {
            None => true, // Never sent a report — send immediately
            Some(last) => {
                let effective = self.report_interval.mul_f64(self.send_failure_backoff_multiplier());
                now.duration_since(last) >= effective
            }
        }
    }

    /// Record a send failure. Returns the new consecutive failure count.
    pub fn record_send_failure(&mut self) -> u32 {
        self.consecutive_send_failures += 1;
        self.consecutive_send_failures
    }

    /// Record a successful send. Returns the previous failure count (for summary logging).
    pub fn record_send_success(&mut self) -> u32 {
        let prev = self.consecutive_send_failures;
        self.consecutive_send_failures = 0;
        prev
    }

    /// Get the backoff multiplier based on consecutive failures.
    ///
    /// Returns 1.0 for no failures, 2.0 for 1 failure, 4.0 for 2, ...
    /// capped at 32.0 (5 failures).
    pub fn send_failure_backoff_multiplier(&self) -> f64 {
        if self.consecutive_send_failures == 0 {
            1.0
        } else {
            2.0_f64.powi(self.consecutive_send_failures.min(5) as i32)
        }
    }

    /// Update the report interval based on SRTT (link-layer defaults).
    ///
    /// Sender reports at 2× SRTT clamped to [MIN, MAX].
    pub fn update_report_interval_from_srtt(&mut self, srtt_us: i64) {
        self.update_report_interval_with_bounds(srtt_us, MIN_REPORT_INTERVAL_MS, MAX_REPORT_INTERVAL_MS);
    }

    /// Update the report interval based on SRTT with custom bounds.
    ///
    /// Used by session-layer MMP which needs higher clamp values since
    /// each report consumes bandwidth on every transit link.
    pub fn update_report_interval_with_bounds(&mut self, srtt_us: i64, min_ms: u64, max_ms: u64) {
        if srtt_us <= 0 {
            return;
        }
        let interval_us = (srtt_us * 2) as u64;
        let interval_ms = (interval_us / 1000).clamp(min_ms, max_ms);
        self.report_interval = Duration::from_millis(interval_ms);
    }

    // --- Accessors ---

    pub fn cumulative_packets_sent(&self) -> u64 {
        self.cumulative_packets_sent
    }

    pub fn cumulative_bytes_sent(&self) -> u64 {
        self.cumulative_bytes_sent
    }

    pub fn report_interval(&self) -> Duration {
        self.report_interval
    }

    pub fn consecutive_send_failures(&self) -> u32 {
        self.consecutive_send_failures
    }
}

impl Default for SenderState {
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

    #[test]
    fn test_new_sender_state() {
        let s = SenderState::new();
        assert_eq!(s.cumulative_packets_sent(), 0);
        assert_eq!(s.cumulative_bytes_sent(), 0);
    }

    #[test]
    fn test_record_sent() {
        let mut s = SenderState::new();
        s.record_sent(1, 100, 500);
        s.record_sent(2, 200, 600);
        assert_eq!(s.cumulative_packets_sent(), 2);
        assert_eq!(s.cumulative_bytes_sent(), 1100);
    }

    #[test]
    fn test_build_report_empty() {
        let mut s = SenderState::new();
        assert!(s.build_report(Instant::now()).is_none());
    }

    #[test]
    fn test_build_report() {
        let mut s = SenderState::new();
        s.record_sent(10, 1000, 500);
        s.record_sent(11, 1100, 600);
        s.record_sent(12, 1200, 400);

        let report = s.build_report(Instant::now()).unwrap();
        assert_eq!(report.interval_start_counter, 10);
        assert_eq!(report.interval_end_counter, 12);
        assert_eq!(report.interval_start_timestamp, 1000);
        assert_eq!(report.interval_end_timestamp, 1200);
        assert_eq!(report.interval_bytes_sent, 1500);
        assert_eq!(report.cumulative_packets_sent, 3);
        assert_eq!(report.cumulative_bytes_sent, 1500);
    }

    #[test]
    fn test_build_report_resets_interval() {
        let mut s = SenderState::new();
        s.record_sent(1, 100, 500);
        let _ = s.build_report(Instant::now());

        // Second report with no new data returns None
        assert!(s.build_report(Instant::now()).is_none());

        // New data starts a fresh interval
        s.record_sent(2, 200, 300);
        let report = s.build_report(Instant::now()).unwrap();
        assert_eq!(report.interval_start_counter, 2);
        assert_eq!(report.interval_bytes_sent, 300);
        // Cumulative continues
        assert_eq!(report.cumulative_packets_sent, 2);
        assert_eq!(report.cumulative_bytes_sent, 800);
    }

    #[test]
    fn test_should_send_report_no_data() {
        let s = SenderState::new();
        assert!(!s.should_send_report(Instant::now()));
    }

    #[test]
    fn test_should_send_report_first_time() {
        let mut s = SenderState::new();
        s.record_sent(1, 100, 500);
        assert!(s.should_send_report(Instant::now()));
    }

    #[test]
    fn test_should_send_report_respects_interval() {
        let mut s = SenderState::new();
        let t0 = Instant::now();
        s.record_sent(1, 100, 500);
        let _ = s.build_report(t0);

        s.record_sent(2, 200, 500);
        // Immediately after report — should not send
        assert!(!s.should_send_report(t0));

        // After interval elapses
        let t1 = t0 + s.report_interval() + Duration::from_millis(1);
        assert!(s.should_send_report(t1));
    }

    #[test]
    fn test_update_report_interval() {
        let mut s = SenderState::new();
        // 50ms RTT → 100ms sender interval (2× SRTT), clamped to min 100ms
        s.update_report_interval_from_srtt(50_000);
        assert_eq!(s.report_interval(), Duration::from_millis(100));

        // 500ms RTT → 1000ms sender interval
        s.update_report_interval_from_srtt(500_000);
        assert_eq!(s.report_interval(), Duration::from_millis(1000));

        // 2s RTT → 4s, clamped to max 2s
        s.update_report_interval_from_srtt(2_000_000);
        assert_eq!(s.report_interval(), Duration::from_millis(MAX_REPORT_INTERVAL_MS));
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
        let t0 = Instant::now();
        s.record_sent(1, 100, 500);
        let _ = s.build_report(t0);

        // Record a failure: multiplier becomes 2.0
        s.record_send_failure();

        s.record_sent(2, 200, 500);

        // At 1× interval: should NOT send (backoff requires 2×)
        let t1 = t0 + s.report_interval() + Duration::from_millis(1);
        assert!(!s.should_send_report(t1));

        // At 2× interval: should send
        let t2 = t0 + s.report_interval() * 2 + Duration::from_millis(1);
        assert!(s.should_send_report(t2));
    }
}
