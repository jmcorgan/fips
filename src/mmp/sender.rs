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
}

impl SenderState {
    pub fn new() -> Self {
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
            report_interval: Duration::from_millis(DEFAULT_COLD_START_INTERVAL_MS),
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
    pub fn should_send_report(&self, now: Instant) -> bool {
        if !self.interval_has_data {
            return false;
        }
        match self.last_report_time {
            None => true, // Never sent a report — send immediately
            Some(last) => now.duration_since(last) >= self.report_interval,
        }
    }

    /// Update the report interval based on SRTT.
    ///
    /// Sender reports at 2-5× the receiver report interval. For simplicity,
    /// we use 2× SRTT clamped to [MIN, MAX].
    pub fn update_report_interval_from_srtt(&mut self, srtt_us: i64) {
        if srtt_us <= 0 {
            return;
        }
        let interval_us = (srtt_us * 2) as u64;
        let interval_ms = (interval_us / 1000)
            .clamp(MIN_REPORT_INTERVAL_MS, MAX_REPORT_INTERVAL_MS);
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
}
