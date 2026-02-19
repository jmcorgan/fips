//! MMP receiver state machine.
//!
//! Tracks what this node has received from a specific peer and produces
//! ReceiverReport messages on demand. One `ReceiverState` per active peer.

use std::time::{Duration, Instant};

use crate::mmp::algorithms::{JitterEstimator, OwdTrendDetector};
use crate::mmp::report::ReceiverReport;
use crate::mmp::{DEFAULT_COLD_START_INTERVAL_MS, DEFAULT_OWD_WINDOW_SIZE,
                  MAX_REPORT_INTERVAL_MS, MIN_REPORT_INTERVAL_MS};

// ============================================================================
// Gap Tracker (burst loss detection)
// ============================================================================

/// Tracks counter gaps to detect loss bursts.
///
/// Each gap in the counter sequence is a burst of lost frames.
/// Maintains per-interval statistics that are reset when a report is built.
struct GapTracker {
    /// Next expected counter value.
    expected_next: Option<u64>,
    /// Whether we are currently in a burst (gap).
    in_burst: bool,
    /// Length of the current burst.
    current_burst_len: u16,

    // --- Per-interval stats (reset on report) ---
    /// Number of distinct burst events this interval.
    burst_count: u32,
    /// Longest burst in this interval.
    max_burst_len: u16,
    /// Sum of all burst lengths (for mean computation).
    total_burst_len: u64,
}

impl GapTracker {
    fn new() -> Self {
        Self {
            expected_next: None,
            in_burst: false,
            current_burst_len: 0,
            burst_count: 0,
            max_burst_len: 0,
            total_burst_len: 0,
        }
    }

    /// Process a received counter value. Returns the number of lost frames
    /// detected (0 if in order or first frame).
    fn observe(&mut self, counter: u64) -> u64 {
        let Some(expected) = self.expected_next else {
            // First frame: initialize
            self.expected_next = Some(counter + 1);
            return 0;
        };

        let lost = if counter > expected {
            // Gap detected
            let gap = counter - expected;
            if self.in_burst {
                // Extend current burst
                self.current_burst_len = self.current_burst_len.saturating_add(gap as u16);
            } else {
                // New burst
                self.in_burst = true;
                self.current_burst_len = gap as u16;
                self.burst_count += 1;
            }
            gap
        } else {
            // In-order or duplicate (counter <= expected)
            if self.in_burst {
                // End current burst
                self.finish_burst();
            }
            0
        };

        // Update expected (always advance to counter+1 or keep expected if
        // this was a late/reordered frame)
        if counter >= expected {
            self.expected_next = Some(counter + 1);
        }

        lost
    }

    /// Finish the current burst and record its stats.
    fn finish_burst(&mut self) {
        if self.in_burst {
            self.max_burst_len = self.max_burst_len.max(self.current_burst_len);
            self.total_burst_len += self.current_burst_len as u64;
            self.in_burst = false;
            self.current_burst_len = 0;
        }
    }

    /// Get interval stats and reset for next interval.
    fn take_interval_stats(&mut self) -> (u32, u16, u16) {
        // Finish any in-progress burst
        self.finish_burst();

        let count = self.burst_count;
        let max_len = self.max_burst_len;
        let mean_len = if count > 0 {
            // u8.8 fixed-point: (total / count) * 256
            let mean_f = (self.total_burst_len as f64) / (count as f64);
            (mean_f * 256.0) as u16
        } else {
            0
        };

        // Reset interval
        self.burst_count = 0;
        self.max_burst_len = 0;
        self.total_burst_len = 0;

        (count, max_len, mean_len)
    }
}

// ============================================================================
// ReceiverState
// ============================================================================

/// Per-peer receiver-side MMP state.
///
/// Accumulates per-frame observations and produces `ReceiverReport` snapshots.
pub struct ReceiverState {
    // --- Cumulative (lifetime) ---
    cumulative_packets_recv: u64,
    cumulative_bytes_recv: u64,
    cumulative_reorder_count: u64,

    /// Highest counter value ever received.
    highest_counter: u64,

    // --- Current interval ---
    interval_packets_recv: u32,
    interval_bytes_recv: u32,

    // --- Jitter ---
    jitter: JitterEstimator,

    // --- OWD trend ---
    owd_trend: OwdTrendDetector,
    /// Monotonic sequence counter for OWD samples.
    owd_seq: u32,

    // --- Loss tracking ---
    gap_tracker: GapTracker,

    // --- ECN ---
    ecn_ce_count: u32,

    // --- Timestamp echo ---
    /// Sender timestamp from the most recent frame (for echo).
    last_sender_timestamp: u32,
    /// Local time when the most recent frame was received (for dwell computation).
    last_recv_time: Option<Instant>,

    // --- Report timing ---
    last_report_time: Option<Instant>,
    report_interval: Duration,
    /// Whether any frames have been received since the last report.
    interval_has_data: bool,
}

impl ReceiverState {
    pub fn new(owd_window_size: usize) -> Self {
        Self::new_with_cold_start(owd_window_size, DEFAULT_COLD_START_INTERVAL_MS)
    }

    /// Create with a custom cold-start interval (ms).
    ///
    /// Used by session-layer MMP which needs a longer initial interval
    /// since reports consume bandwidth on every transit link.
    pub fn new_with_cold_start(owd_window_size: usize, cold_start_ms: u64) -> Self {
        Self {
            cumulative_packets_recv: 0,
            cumulative_bytes_recv: 0,
            cumulative_reorder_count: 0,
            highest_counter: 0,
            interval_packets_recv: 0,
            interval_bytes_recv: 0,
            jitter: JitterEstimator::new(),
            owd_trend: OwdTrendDetector::new(owd_window_size),
            owd_seq: 0,
            gap_tracker: GapTracker::new(),
            ecn_ce_count: 0,
            last_sender_timestamp: 0,
            last_recv_time: None,
            last_report_time: None,
            report_interval: Duration::from_millis(cold_start_ms),
            interval_has_data: false,
        }
    }

    /// Record a received frame from this peer.
    ///
    /// Called on the RX path after AEAD decryption, before message dispatch.
    ///
    /// - `counter`: AEAD counter from outer header
    /// - `sender_timestamp_ms`: session-relative timestamp from inner header (ms)
    /// - `bytes`: wire payload size
    /// - `ce_flag`: CE bit from flags byte
    /// - `now`: current local time
    pub fn record_recv(
        &mut self,
        counter: u64,
        sender_timestamp_ms: u32,
        bytes: usize,
        ce_flag: bool,
        now: Instant,
    ) {
        self.interval_has_data = true;
        self.cumulative_packets_recv += 1;
        self.cumulative_bytes_recv += bytes as u64;
        self.interval_packets_recv = self.interval_packets_recv.saturating_add(1);
        self.interval_bytes_recv = self.interval_bytes_recv.saturating_add(bytes as u32);

        // Reordering detection: counter < highest means out-of-order
        if counter < self.highest_counter {
            self.cumulative_reorder_count += 1;
        } else {
            self.highest_counter = counter;
        }

        // Loss/burst detection
        let _lost = self.gap_tracker.observe(counter);

        // ECN
        if ce_flag {
            self.ecn_ce_count = self.ecn_ce_count.saturating_add(1);
        }

        // Jitter: compute transit time delta
        // Transit = recv_local - sender_timestamp (in µs for precision)
        // We use a monotonic local reference derived from Instant offsets.
        let sender_us = (sender_timestamp_ms as i64) * 1000;
        // We can't get absolute µs from Instant, but we can compute the delta
        // between consecutive transits using relative Instant differences.
        if let Some(prev_recv) = self.last_recv_time {
            let recv_delta_us = now.duration_since(prev_recv).as_micros() as i64;
            let send_delta_us = sender_us - (self.last_sender_timestamp as i64 * 1000);
            let transit_delta = (recv_delta_us - send_delta_us) as i32;
            self.jitter.update(transit_delta);
        }

        // OWD trend: use sender timestamp as a proxy for send time
        // and Instant delta from a fixed reference as receive time.
        // Since we only need the *trend* (slope), absolute offsets cancel out.
        if let Some(first_recv) = self.last_recv_time.or(Some(now)) {
            let recv_offset_us = now.duration_since(first_recv).as_micros() as i64;
            let owd_us = recv_offset_us - sender_us;
            self.owd_seq = self.owd_seq.wrapping_add(1);
            self.owd_trend.push(self.owd_seq, owd_us);
        }

        // Timestamp echo state
        self.last_sender_timestamp = sender_timestamp_ms;
        self.last_recv_time = Some(now);
    }

    /// Build a ReceiverReport from current state and reset the interval.
    ///
    /// Returns `None` if no frames have been received since the last report.
    pub fn build_report(&mut self, now: Instant) -> Option<ReceiverReport> {
        if !self.interval_has_data {
            return None;
        }

        // Dwell time: ms between last frame reception and report generation
        let dwell_time = self.last_recv_time
            .map(|t| now.duration_since(t).as_millis() as u16)
            .unwrap_or(0);

        let (burst_count, max_burst, mean_burst) = self.gap_tracker.take_interval_stats();

        let report = ReceiverReport {
            highest_counter: self.highest_counter,
            cumulative_packets_recv: self.cumulative_packets_recv,
            cumulative_bytes_recv: self.cumulative_bytes_recv,
            timestamp_echo: self.last_sender_timestamp,
            dwell_time,
            max_burst_loss: max_burst,
            mean_burst_loss: mean_burst,
            jitter: self.jitter.jitter_us(),
            ecn_ce_count: self.ecn_ce_count,
            owd_trend: self.owd_trend.trend_us_per_sec(),
            burst_loss_count: burst_count,
            cumulative_reorder_count: self.cumulative_reorder_count as u32,
            interval_packets_recv: self.interval_packets_recv,
            interval_bytes_recv: self.interval_bytes_recv,
        };

        // Reset interval
        self.interval_packets_recv = 0;
        self.interval_bytes_recv = 0;
        self.interval_has_data = false;
        self.last_report_time = Some(now);

        Some(report)
    }

    /// Check if it's time to send a report.
    pub fn should_send_report(&self, now: Instant) -> bool {
        if !self.interval_has_data {
            return false;
        }
        match self.last_report_time {
            None => true,
            Some(last) => now.duration_since(last) >= self.report_interval,
        }
    }

    /// Update the report interval based on SRTT (link-layer defaults).
    ///
    /// Receiver reports at 1× SRTT, clamped to [MIN, MAX].
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
        let interval_ms = ((srtt_us as u64) / 1000).clamp(min_ms, max_ms);
        self.report_interval = Duration::from_millis(interval_ms);
    }

    // --- Accessors ---

    pub fn cumulative_packets_recv(&self) -> u64 {
        self.cumulative_packets_recv
    }

    pub fn cumulative_bytes_recv(&self) -> u64 {
        self.cumulative_bytes_recv
    }

    pub fn highest_counter(&self) -> u64 {
        self.highest_counter
    }

    pub fn jitter_us(&self) -> u32 {
        self.jitter.jitter_us()
    }

    pub fn report_interval(&self) -> Duration {
        self.report_interval
    }

    pub fn last_recv_time(&self) -> Option<Instant> {
        self.last_recv_time
    }
}

impl Default for ReceiverState {
    fn default() -> Self {
        Self::new(DEFAULT_OWD_WINDOW_SIZE)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
        let now = Instant::now();
        r.record_recv(1, 100, 500, false, now);
        r.record_recv(2, 200, 600, false, now + Duration::from_millis(100));

        assert_eq!(r.cumulative_packets_recv(), 2);
        assert_eq!(r.cumulative_bytes_recv(), 1100);
        assert_eq!(r.highest_counter(), 2);
    }

    #[test]
    fn test_reorder_detection() {
        let mut r = ReceiverState::new(32);
        let now = Instant::now();
        r.record_recv(5, 500, 100, false, now);
        r.record_recv(3, 300, 100, false, now + Duration::from_millis(10));

        assert_eq!(r.cumulative_reorder_count, 1);
        assert_eq!(r.highest_counter(), 5); // not changed by out-of-order
    }

    #[test]
    fn test_ecn_counting() {
        let mut r = ReceiverState::new(32);
        let now = Instant::now();
        r.record_recv(1, 100, 100, true, now);
        r.record_recv(2, 200, 100, false, now);
        r.record_recv(3, 300, 100, true, now);

        assert_eq!(r.ecn_ce_count, 2);
    }

    #[test]
    fn test_build_report_empty() {
        let mut r = ReceiverState::new(32);
        assert!(r.build_report(Instant::now()).is_none());
    }

    #[test]
    fn test_build_report() {
        let mut r = ReceiverState::new(32);
        let t0 = Instant::now();
        r.record_recv(1, 100, 500, false, t0);
        r.record_recv(2, 200, 600, false, t0 + Duration::from_millis(100));

        let report = r.build_report(t0 + Duration::from_millis(150)).unwrap();
        assert_eq!(report.highest_counter, 2);
        assert_eq!(report.cumulative_packets_recv, 2);
        assert_eq!(report.cumulative_bytes_recv, 1100);
        assert_eq!(report.timestamp_echo, 200); // last sender timestamp
        assert_eq!(report.interval_packets_recv, 2);
        assert_eq!(report.interval_bytes_recv, 1100);
    }

    #[test]
    fn test_build_report_resets_interval() {
        let mut r = ReceiverState::new(32);
        let t0 = Instant::now();
        r.record_recv(1, 100, 500, false, t0);
        let _ = r.build_report(t0);

        // No new data
        assert!(r.build_report(t0).is_none());

        // New data
        r.record_recv(2, 200, 300, false, t0 + Duration::from_millis(100));
        let report = r.build_report(t0 + Duration::from_millis(150)).unwrap();
        assert_eq!(report.interval_packets_recv, 1);
        assert_eq!(report.interval_bytes_recv, 300);
        // Cumulative continues
        assert_eq!(report.cumulative_packets_recv, 2);
    }

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
        let t0 = Instant::now();

        assert!(!r.should_send_report(t0)); // no data

        r.record_recv(1, 100, 500, false, t0);
        assert!(r.should_send_report(t0)); // first time, has data

        let _ = r.build_report(t0);
        r.record_recv(2, 200, 500, false, t0);
        assert!(!r.should_send_report(t0)); // just reported

        let t1 = t0 + r.report_interval() + Duration::from_millis(1);
        assert!(r.should_send_report(t1));
    }

    #[test]
    fn test_update_report_interval() {
        let mut r = ReceiverState::new(32);
        // 50ms SRTT → 100ms receiver interval (1× SRTT, clamped to min)
        r.update_report_interval_from_srtt(50_000);
        assert_eq!(r.report_interval(), Duration::from_millis(100));

        // 500ms SRTT → 500ms
        r.update_report_interval_from_srtt(500_000);
        assert_eq!(r.report_interval(), Duration::from_millis(500));
    }
}
