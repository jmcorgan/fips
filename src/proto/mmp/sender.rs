//! Per-peer sender-side MMP state (sans-IO).
//!
//! Records cumulative and interval TX counters and produces `SenderReport`
//! snapshots on demand. All time inputs are injected `u64` milliseconds.

use super::wire::SenderReport;
use super::{
    COLD_START_SAMPLES, DEFAULT_COLD_START_INTERVAL_MS, MAX_REPORT_INTERVAL_MS,
    MIN_REPORT_INTERVAL_MS,
};

/// Per-peer sender-side MMP state.
///
/// Records cumulative and interval counters for every frame transmitted
/// to this peer. Produces `SenderReport` snapshots on demand.
pub struct SenderState {
    // --- Cumulative (lifetime) ---
    cumulative_packets_sent: u64,

    // --- Current interval ---
    interval_packets_sent: u32,
    interval_bytes_sent: u32,
    /// Whether any frames have been sent in the current interval.
    interval_has_data: bool,

    // --- Report timing (injected `u64` ms) ---
    last_report_ms: Option<u64>,
    report_interval_ms: u64,

    // --- Send failure backoff ---
    /// Consecutive send failure count for backoff calculation.
    consecutive_send_failures: u32,

    // --- Cold-start tracking ---
    /// Number of SRTT-based interval updates received.
    srtt_sample_count: u32,
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
            interval_packets_sent: 0,
            interval_bytes_sent: 0,
            interval_has_data: false,
            last_report_ms: None,
            report_interval_ms: cold_start_ms,
            consecutive_send_failures: 0,
            srtt_sample_count: 0,
        }
    }

    /// Record a frame sent to this peer.
    ///
    /// Called on the TX path for every encrypted link message.
    /// `counter` is the AEAD nonce/counter, `timestamp` is the inner header
    /// session-relative timestamp (ms), `bytes` is the wire payload size.
    pub fn record_sent(&mut self, _counter: u64, _timestamp: u32, bytes: usize) {
        self.interval_has_data = true;
        self.interval_packets_sent = self.interval_packets_sent.saturating_add(1);
        self.interval_bytes_sent = self.interval_bytes_sent.saturating_add(bytes as u32);
        self.cumulative_packets_sent += 1;
    }

    /// Build a SenderReport from current state and reset the interval.
    ///
    /// Returns `None` if no frames have been sent since the last report.
    /// `now_ms` is the injected monotonic time in milliseconds.
    pub fn build_report(&mut self, now_ms: u64) -> Option<SenderReport> {
        if !self.interval_has_data {
            return None;
        }

        let report = SenderReport {
            interval_packets_sent: self.interval_packets_sent,
            interval_bytes_sent: self.interval_bytes_sent,
            cumulative_packets_sent: self.cumulative_packets_sent,
        };

        // Reset interval
        self.interval_has_data = false;
        self.interval_packets_sent = 0;
        self.interval_bytes_sent = 0;
        self.last_report_ms = Some(now_ms);

        Some(report)
    }

    /// Check if it's time to send a report.
    ///
    /// When consecutive send failures have occurred, the effective interval
    /// is multiplied by an exponential backoff factor (2^failures, capped at 32×).
    pub fn should_send_report(&self, now_ms: u64) -> bool {
        if !self.interval_has_data {
            return false;
        }
        match self.last_report_ms {
            None => true, // Never sent a report — send immediately
            Some(last) => {
                let effective_ms = (self.report_interval_ms as f64
                    * self.send_failure_backoff_multiplier())
                    as u64;
                now_ms.saturating_sub(last) >= effective_ms
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
    /// capped at 32.0 (5 failures). Computed as an exact power-of-two bit shift
    /// (`2^k == 1 << k`), keeping the module `core`-only (no `libm` for `powi`).
    pub fn send_failure_backoff_multiplier(&self) -> f64 {
        if self.consecutive_send_failures == 0 {
            1.0
        } else {
            (1u64 << self.consecutive_send_failures.min(5)) as f64
        }
    }

    /// Update the report interval based on SRTT (link-layer defaults).
    ///
    /// Sender reports at 2× SRTT clamped to [floor, MAX]. During cold-start
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
        let interval_us = (srtt_us * 2) as u64;
        let interval_ms = (interval_us / 1000).clamp(min_ms, max_ms);
        self.report_interval_ms = interval_ms;
    }

    // --- Accessors ---

    pub fn cumulative_packets_sent(&self) -> u64 {
        self.cumulative_packets_sent
    }

    pub fn report_interval_ms(&self) -> u64 {
        self.report_interval_ms
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
