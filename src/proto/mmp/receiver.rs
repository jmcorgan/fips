//! Per-peer receiver-side MMP state (sans-IO).
//!
//! Accumulates per-frame observations (loss bursts, jitter, OWD trend, ECN)
//! and produces `ReceiverReport` snapshots. All time inputs are injected `u64`
//! milliseconds.

use super::algorithms::{JitterEstimator, OwdTrendDetector};
use super::wire::ReceiverReport;
use super::{
    COLD_START_SAMPLES, DEFAULT_COLD_START_INTERVAL_MS, DEFAULT_OWD_WINDOW_SIZE,
    MAX_REPORT_INTERVAL_MS, MIN_REPORT_INTERVAL_MS,
};

/// Grace period after rekey before resuming jitter calculation.
///
/// During rekey cutover, frames from the old session may still arrive via the
/// drain window (DRAIN_WINDOW_SECS = 10s). These carry large sender timestamps
/// from the old session, producing enormous transit deltas that spike the EWMA
/// jitter estimator. We suppress jitter updates for drain window + 5s margin.
const REKEY_JITTER_GRACE_SECS: u64 = 15;

// ============================================================================
// Gap Tracker (burst loss detection)
// ============================================================================

/// Tracks counter gaps to detect loss bursts.
///
/// Each gap in the counter sequence is a burst of lost frames.
/// Maintains per-interval statistics that are reset when a report is built.
pub(crate) struct GapTracker {
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
    pub(crate) fn new() -> Self {
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
    pub(crate) fn observe(&mut self, counter: u64) -> u64 {
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
    pub(crate) fn take_interval_stats(&mut self) -> (u32, u16, u16) {
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
    /// Local time (injected `u64` ms) when the most recent frame was received
    /// (for dwell / jitter computation).
    last_recv_ms: Option<u64>,

    // --- Rekey grace ---
    /// When set, jitter updates are suppressed until this injected-ms instant
    /// passes. Prevents drain-window frames from spiking the jitter estimator.
    rekey_jitter_grace_until_ms: Option<u64>,

    // --- Report timing (injected `u64` ms) ---
    last_report_ms: Option<u64>,
    report_interval_ms: u64,
    /// Whether any frames have been received since the last report.
    interval_has_data: bool,

    // --- Cold-start tracking ---
    /// Number of SRTT-based interval updates received.
    srtt_sample_count: u32,
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
            last_recv_ms: None,
            rekey_jitter_grace_until_ms: None,
            last_report_ms: None,
            report_interval_ms: cold_start_ms,
            interval_has_data: false,
            srtt_sample_count: 0,
        }
    }

    /// Reset counter-dependent state for rekey cutover.
    ///
    /// After cutover, the new session starts with counter 0 and reset
    /// timestamps. Without resetting, the old `highest_counter` and
    /// `GapTracker.expected_next` cause false reorder/loss detection.
    /// `now_ms` is the injected monotonic time in milliseconds.
    pub fn reset_for_rekey(&mut self, now_ms: u64) {
        self.highest_counter = 0;
        self.cumulative_reorder_count = 0;
        self.gap_tracker = GapTracker::new();
        self.interval_packets_recv = 0;
        self.interval_bytes_recv = 0;
        self.jitter = JitterEstimator::new();
        self.owd_trend.clear();
        self.owd_seq = 0;
        self.last_sender_timestamp = 0;
        self.last_recv_ms = None;
        self.rekey_jitter_grace_until_ms = Some(now_ms + REKEY_JITTER_GRACE_SECS * 1000);
        self.ecn_ce_count = 0;
        self.interval_has_data = false;
        // Keep cumulative_packets_recv, cumulative_bytes_recv (lifetime stats)
        // Keep last_report_ms, report_interval_ms (report scheduling)
    }

    /// Record a received frame from this peer.
    ///
    /// Called on the RX path after AEAD decryption, before message dispatch.
    ///
    /// - `counter`: AEAD counter from outer header
    /// - `sender_timestamp_ms`: session-relative timestamp from inner header (ms)
    /// - `bytes`: wire payload size
    /// - `ce_flag`: CE bit from flags byte
    /// - `now_ms`: injected monotonic local time in milliseconds
    pub fn record_recv(
        &mut self,
        counter: u64,
        sender_timestamp_ms: u32,
        bytes: usize,
        ce_flag: bool,
        now_ms: u64,
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
        // We use the injected monotonic ms clock for the local reference.
        let sender_us = (sender_timestamp_ms as i64) * 1000;
        // We compute the delta between consecutive transits using relative
        // millisecond differences (scaled to µs to match the estimator input).
        // Skip during post-rekey grace period to avoid drain-window spikes.
        let in_grace = self
            .rekey_jitter_grace_until_ms
            .is_some_and(|deadline| now_ms < deadline);
        if !in_grace {
            self.rekey_jitter_grace_until_ms = None; // clear expired grace
            if let Some(prev_recv) = self.last_recv_ms {
                let recv_delta_us = (now_ms.saturating_sub(prev_recv) as i64) * 1000;
                let send_delta_us = sender_us - (self.last_sender_timestamp as i64 * 1000);
                let transit_delta = (recv_delta_us - send_delta_us) as i32;
                self.jitter.update(transit_delta);
            }
        }

        // OWD trend: use sender timestamp as a proxy for send time
        // and the injected ms delta from a fixed reference as receive time.
        // Since we only need the *trend* (slope), absolute offsets cancel out.
        if let Some(first_recv) = self.last_recv_ms.or(Some(now_ms)) {
            let recv_offset_us = (now_ms.saturating_sub(first_recv) as i64) * 1000;
            let owd_us = recv_offset_us - sender_us;
            self.owd_seq = self.owd_seq.wrapping_add(1);
            self.owd_trend.push(self.owd_seq, owd_us);
        }

        // Timestamp echo state
        self.last_sender_timestamp = sender_timestamp_ms;
        self.last_recv_ms = Some(now_ms);
    }

    /// Build a ReceiverReport from current state and reset the interval.
    ///
    /// Returns `None` if no frames have been received since the last report.
    /// `now_ms` is the injected monotonic time in milliseconds.
    pub fn build_report(&mut self, now_ms: u64) -> Option<ReceiverReport> {
        if !self.interval_has_data {
            return None;
        }

        // Dwell time: ms between last frame reception and report generation.
        // If it no longer fits on the wire, the timestamp echo cannot produce
        // a valid RTT sample. Preserve the counters but suppress the echo.
        let (timestamp_echo, dwell_time) = self
            .last_recv_ms
            .map(|t| {
                let dwell_ms = now_ms.saturating_sub(t);
                if dwell_ms > u64::from(u16::MAX) {
                    (0, u16::MAX)
                } else {
                    (self.last_sender_timestamp, dwell_ms as u16)
                }
            })
            .unwrap_or((0, 0));

        let (burst_count, _max_burst, _mean_burst) = self.gap_tracker.take_interval_stats();

        let report = ReceiverReport {
            timestamp_echo,
            dwell_time,
            highest_counter: self.highest_counter,
            cumulative_packets_recv: self.cumulative_packets_recv,
            cumulative_bytes_recv: self.cumulative_bytes_recv,
            jitter: self.jitter.jitter_us(),
            ecn_ce_count: self.ecn_ce_count,
            owd_trend: self.owd_trend.trend_us_per_sec(),
            burst_loss_count: burst_count,
            cumulative_reorder_count: self.cumulative_reorder_count as u32,
        };

        // Reset interval
        self.interval_packets_recv = 0;
        self.interval_bytes_recv = 0;
        self.interval_has_data = false;
        self.last_report_ms = Some(now_ms);

        Some(report)
    }

    /// Check if it's time to send a report.
    pub fn should_send_report(&self, now_ms: u64) -> bool {
        if !self.interval_has_data {
            return false;
        }
        match self.last_report_ms {
            None => true,
            Some(last) => now_ms.saturating_sub(last) >= self.report_interval_ms,
        }
    }

    /// Update the report interval based on SRTT (link-layer defaults).
    ///
    /// Receiver reports at 1× SRTT clamped to [floor, MAX]. During cold-start
    /// (first `COLD_START_SAMPLES` updates), the floor is the cold-start
    /// interval (200ms) for fast SRTT convergence. After that, it rises to
    /// `MIN_REPORT_INTERVAL_MS` (1000ms) for steady-state efficiency.
    pub fn update_report_interval_from_srtt(&mut self, srtt_us: i64) {
        self.srtt_sample_count = self.srtt_sample_count.saturating_add(1);
        let floor = if self.srtt_sample_count <= COLD_START_SAMPLES {
            DEFAULT_COLD_START_INTERVAL_MS
        } else {
            MIN_REPORT_INTERVAL_MS
        };
        self.update_report_interval_with_bounds(srtt_us, floor, MAX_REPORT_INTERVAL_MS);
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
        self.report_interval_ms = interval_ms;
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

    pub fn report_interval_ms(&self) -> u64 {
        self.report_interval_ms
    }

    /// Local monotonic time (injected `u64` ms) of the most recent received
    /// frame, or `None` if none has been received.
    pub fn last_recv_ms(&self) -> Option<u64> {
        self.last_recv_ms
    }

    pub fn ecn_ce_count(&self) -> u32 {
        self.ecn_ce_count
    }
}

impl Default for ReceiverState {
    fn default() -> Self {
        Self::new(DEFAULT_OWD_WINDOW_SIZE)
    }
}
