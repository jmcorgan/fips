//! Owned MMP protocol state (sans-IO).
//!
//! The per-peer/per-session sender, receiver, derived-metrics and
//! path-MTU state machines migrated out of the async node shell. All time
//! inputs are injected `u64` milliseconds (the shell reads its monotonic clock
//! at the edge and passes the value in); nothing here reads a clock, logs, or
//! bumps a counter. `no_std`+`alloc`-clean: `core` arithmetic only, the ring
//! buffer comes from `super::algorithms` (which uses `alloc`), and observability
//! is returned to the shell as an [`RrLog`] outcome rather than emitted here.
//!
//! [`Mmp`] itself remains the stateless reporting anchor owned by `Node` (the
//! live per-entity state lives on the peers'/sessions' shell structs); it exists
//! so the reporting decisions can hang off a `Node` field in the same shape the
//! other migrated subsystems use.

use core::fmt::{self, Debug};

use super::algorithms::{DualEwma, JitterEstimator, OwdTrendDetector, SrttEstimator, compute_etx};
use super::wire::{ReceiverReport, SenderReport};
use super::{
    COLD_START_SAMPLES, DEFAULT_COLD_START_INTERVAL_MS, DEFAULT_OWD_WINDOW_SIZE,
    MAX_REPORT_INTERVAL_MS, MIN_REPORT_INTERVAL_MS, MmpMode, SESSION_COLD_START_INTERVAL_MS,
};

/// Grace period after rekey before resuming jitter calculation.
///
/// During rekey cutover, frames from the old session may still arrive via the
/// drain window (DRAIN_WINDOW_SECS = 10s). These carry large sender timestamps
/// from the old session, producing enormous transit deltas that spike the EWMA
/// jitter estimator. We suppress jitter updates for drain window + 5s margin.
const REKEY_JITTER_GRACE_SECS: u64 = 15;

/// MMP reporting subsystem anchor owned by [`Node`](crate::node::Node).
///
/// Like [`Fmp`](crate::proto::fmp::Fmp), the MMP reporting core owns **no**
/// mutable state: the per-peer/per-session timing and backoff state lives on
/// the peers'/sessions' [`MmpPeerState`]/[`MmpSessionState`] structs (defined in
/// this module, held shell-side), and every registry mutation and send stays
/// shell-side, driven by the [`MmpAction`](super::MmpAction)s the pure `plan_*`
/// decisions emit. `Mmp` is therefore an empty namespace anchor: it exists so
/// the reporting decisions can hang off a `Node` field (`self.mmp`) in the same
/// shape the other migrated subsystems use, not to hold data.
pub(crate) struct Mmp;

impl Mmp {
    /// Create the (stateless) MMP reporting anchor.
    pub(crate) fn new() -> Self {
        Self
    }
}

// ============================================================================
// ReceiverReport processing outcome (observability hoisted to the shell)
// ============================================================================

/// The observability outcome of [`MmpMetrics::process_receiver_report`], returned
/// so the async shell can emit the operator `trace!` points that used to live
/// mid-decision (per the sans-IO rule that migrated code carries no `tracing`).
///
/// Exactly one variant applies per call; the shell has the incoming report and
/// our timestamp, so this only carries the values the shell cannot otherwise
/// reconstruct (the previous cumulative snapshot / the derived RTT).
pub enum RrLog {
    /// No RTT log point fires (the report carried no timestamp echo).
    None,
    /// The report was ignored as stale/duplicate. Carries the previous
    /// cumulative snapshot for the operator trace.
    Stale {
        prev_highest: u64,
        prev_packets: u64,
        prev_bytes: u64,
    },
    /// A valid RTT sample was taken; carries the derived RTT and the SRTT as it
    /// stood **before** this sample was folded in (matching the original log,
    /// which read `srtt` before `update`).
    RttSample { rtt_ms: u32, srtt_ms: f64 },
    /// The report carried an echo but the derived RTT was invalid (wrapped /
    /// non-positive).
    InvalidRtt,
}

// ============================================================================
// SenderState
// ============================================================================

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

// ============================================================================
// MmpMetrics (derived metrics)
// ============================================================================

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
    pub etx_trend: DualEwma,

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
    /// Time (injected `u64` ms) of previous ReceiverReport (for goodput rate).
    prev_rr_ms: Option<u64>,
    /// Whether we have a previous ReceiverReport for delta computation.
    has_prev_rr: bool,

    // --- State for reverse delivery ratio delta computation ---
    /// Previous reverse-side cumulative packets received (our receiver state).
    prev_reverse_packets: u64,
    /// Previous reverse-side highest counter (our receiver state).
    prev_reverse_highest: u64,
    /// Whether we have a previous reverse-side snapshot for delta computation.
    has_prev_reverse: bool,
}

impl MmpMetrics {
    /// Reset state derived from ReceiverReport counters for rekey cutover.
    ///
    /// The new session starts with counter 0, so the prev_rr deltas must
    /// be reset to avoid computing bogus loss/goodput from the counter
    /// discontinuity. RTT (SRTT) is preserved since it remains valid.
    pub fn reset_for_rekey(&mut self) {
        self.prev_rr_cum_packets = 0;
        self.prev_rr_cum_bytes = 0;
        self.prev_rr_highest_counter = 0;
        self.prev_rr_ecn_ce = 0;
        self.prev_rr_reorder = 0;
        self.prev_rr_ms = None;
        self.has_prev_rr = false;
        self.delivery_ratio_forward = 1.0;
        self.prev_reverse_packets = 0;
        self.prev_reverse_highest = 0;
        self.has_prev_reverse = false;
        // Keep srtt, etx, trends, goodput_bps — they'll refresh from data
    }

    pub fn new() -> Self {
        Self {
            srtt: SrttEstimator::new(),
            rtt_trend: DualEwma::new(),
            loss_trend: DualEwma::new(),
            goodput_trend: DualEwma::new(),
            jitter_trend: DualEwma::new(),
            etx_trend: DualEwma::new(),
            delivery_ratio_forward: 1.0,
            delivery_ratio_reverse: 1.0,
            etx: 1.0,
            goodput_bps: 0.0,
            prev_rr_cum_packets: 0,
            prev_rr_cum_bytes: 0,
            prev_rr_highest_counter: 0,
            prev_rr_ecn_ce: 0,
            prev_rr_reorder: 0,
            prev_rr_ms: None,
            has_prev_rr: false,
            prev_reverse_packets: 0,
            prev_reverse_highest: 0,
            has_prev_reverse: false,
        }
    }

    /// Process an incoming ReceiverReport (from the peer about our traffic).
    ///
    /// `our_timestamp_ms` is the current session-relative time in ms (for RTT).
    /// `now_ms` is the injected monotonic time in ms (for goodput rate).
    ///
    /// Returns `(first_srtt, log)`: `first_srtt` is `true` if this report
    /// produced the first SRTT measurement (transition from uninitialized to
    /// initialized); `log` is the [`RrLog`] observability outcome the shell
    /// emits (the `tracing` that used to fire here now lives shell-side).
    pub fn process_receiver_report(
        &mut self,
        rr: &ReceiverReport,
        our_timestamp_ms: u32,
        now_ms: u64,
    ) -> (bool, RrLog) {
        let had_srtt = self.srtt.initialized();

        if self.has_prev_rr {
            let counters_regressed = rr.highest_counter < self.prev_rr_highest_counter
                || rr.cumulative_packets_recv < self.prev_rr_cum_packets
                || rr.cumulative_bytes_recv < self.prev_rr_cum_bytes
                || rr.ecn_ce_count < self.prev_rr_ecn_ce
                || rr.cumulative_reorder_count < self.prev_rr_reorder;
            let duplicate_counters = rr.highest_counter == self.prev_rr_highest_counter
                && rr.cumulative_packets_recv == self.prev_rr_cum_packets
                && rr.cumulative_bytes_recv == self.prev_rr_cum_bytes
                && rr.ecn_ce_count == self.prev_rr_ecn_ce
                && rr.cumulative_reorder_count == self.prev_rr_reorder;
            // Safe to drop: reports are only built after interval data, so
            // a fresh report always advances at least one cumulative counter.
            if counters_regressed || duplicate_counters {
                return (
                    false,
                    RrLog::Stale {
                        prev_highest: self.prev_rr_highest_counter,
                        prev_packets: self.prev_rr_cum_packets,
                        prev_bytes: self.prev_rr_cum_bytes,
                    },
                );
            }
        }

        let mut log = RrLog::None;

        // --- RTT from timestamp echo ---
        // RTT = now - echoed_timestamp - dwell_time
        if rr.timestamp_echo > 0 {
            let echo_ms = rr.timestamp_echo;
            let dwell_ms = u32::from(rr.dwell_time);
            let rtt_sample_ms = echo_ms
                .checked_add(dwell_ms)
                .and_then(|send_done_ms| our_timestamp_ms.checked_sub(send_done_ms));

            match rtt_sample_ms {
                Some(rtt_ms) if rtt_ms > 0 => {
                    let rtt_us = (rtt_ms as i64) * 1000;
                    // Capture SRTT before folding in this sample (the original
                    // trace read `srtt` before `update`).
                    let srtt_ms = self.srtt.srtt_us() as f64 / 1000.0;
                    log = RrLog::RttSample { rtt_ms, srtt_ms };
                    self.srtt.update(rtt_us);
                    self.rtt_trend.update(rtt_us as f64);
                }
                _ => {
                    log = RrLog::InvalidRtt;
                }
            }
        }

        // --- Loss rate from cumulative counters ---
        // Delta: frames the peer should have received vs. actually received
        if self.has_prev_rr {
            let counter_span = rr
                .highest_counter
                .saturating_sub(self.prev_rr_highest_counter);
            let packets_delta = rr
                .cumulative_packets_recv
                .saturating_sub(self.prev_rr_cum_packets);

            if counter_span > 0 {
                let delivery = (packets_delta as f64) / (counter_span as f64);
                self.delivery_ratio_forward = delivery.clamp(0.0, 1.0);
                let loss_rate = 1.0 - self.delivery_ratio_forward;
                self.loss_trend.update(loss_rate);
                self.etx = compute_etx(self.delivery_ratio_forward, self.delivery_ratio_reverse);
                self.etx_trend.update(self.etx);
            }
        }

        // --- Goodput from cumulative bytes + time delta ---
        if self.has_prev_rr {
            let bytes_delta = rr
                .cumulative_bytes_recv
                .saturating_sub(self.prev_rr_cum_bytes);
            self.goodput_trend.update(bytes_delta as f64);

            // Compute bytes/sec if we have a time reference
            if let Some(prev_ms) = self.prev_rr_ms {
                let secs = (now_ms.saturating_sub(prev_ms) as f64) / 1000.0;
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
        self.prev_rr_ms = Some(now_ms);
        self.has_prev_rr = true;

        (!had_srtt && self.srtt.initialized(), log)
    }

    /// Update the reverse delivery ratio from our own receiver state.
    ///
    /// Computes a per-interval delta (same as forward ratio) rather than
    /// a lifetime cumulative ratio, so ETX responds to recent conditions.
    pub fn update_reverse_delivery(&mut self, our_recv_packets: u64, peer_highest: u64) {
        if self.has_prev_reverse {
            let counter_span = peer_highest.saturating_sub(self.prev_reverse_highest);
            let packets_delta = our_recv_packets.saturating_sub(self.prev_reverse_packets);

            if counter_span > 0 {
                let delivery = (packets_delta as f64) / (counter_span as f64);
                self.delivery_ratio_reverse = delivery.clamp(0.0, 1.0);
                self.etx = compute_etx(self.delivery_ratio_forward, self.delivery_ratio_reverse);
                self.etx_trend.update(self.etx);
            }
        }

        self.prev_reverse_packets = our_recv_packets;
        self.prev_reverse_highest = peer_highest;
        self.has_prev_reverse = true;
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

    /// Smoothed loss rate (long-term EWMA), or `None` if not yet initialized.
    pub fn smoothed_loss(&self) -> Option<f64> {
        if self.loss_trend.initialized() {
            Some(self.loss_trend.long())
        } else {
            None
        }
    }

    /// Smoothed ETX (long-term EWMA), or `None` if not yet initialized.
    pub fn smoothed_etx(&self) -> Option<f64> {
        if self.etx_trend.initialized() {
            Some(self.etx_trend.long())
        } else {
            None
        }
    }

    /// Current smoothed goodput in bytes/sec, or 0 if not yet measured.
    pub fn goodput_bps(&self) -> f64 {
        self.goodput_bps
    }

    /// Cumulative ECN CE count from the most recent ReceiverReport.
    pub fn last_ecn_ce_count(&self) -> u32 {
        self.prev_rr_ecn_ce
    }
}

impl Default for MmpMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Per-Peer MMP State
// ============================================================================

/// Combined MMP state for a single peer link.
///
/// Wraps sender, receiver, and metrics. One instance
/// per `ActivePeer`.
pub struct MmpPeerState {
    pub sender: SenderState,
    pub receiver: ReceiverState,
    pub metrics: MmpMetrics,
    mode: MmpMode,
    log_interval_ms: u64,
    last_log_ms: Option<u64>,
}

impl MmpPeerState {
    /// Create MMP state for a new peer link.
    ///
    /// `mode`/`log_interval_secs`/`owd_window_size`
    /// are the shell's config values, passed as plain data so this owned state
    /// carries no dependency on the shell config struct.
    pub fn new(mode: MmpMode, log_interval_secs: u64, owd_window_size: usize) -> Self {
        Self {
            sender: SenderState::new(),
            receiver: ReceiverState::new(owd_window_size),
            metrics: MmpMetrics::new(),
            mode,
            log_interval_ms: log_interval_secs * 1000,
            last_log_ms: None,
        }
    }

    /// Reset counter-dependent state for rekey cutover.
    pub fn reset_for_rekey(&mut self, now_ms: u64) {
        self.receiver.reset_for_rekey(now_ms);
        self.metrics.reset_for_rekey();
    }

    /// Current operating mode.
    pub fn mode(&self) -> MmpMode {
        self.mode
    }

    /// Check if it's time to emit a periodic metrics log.
    pub fn should_log(&self, now_ms: u64) -> bool {
        match self.last_log_ms {
            None => true,
            Some(last) => now_ms.saturating_sub(last) >= self.log_interval_ms,
        }
    }

    /// Mark that a periodic log was emitted.
    pub fn mark_logged(&mut self, now_ms: u64) {
        self.last_log_ms = Some(now_ms);
    }
}

impl Debug for MmpPeerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MmpPeerState")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Per-Session MMP State (session-layer instantiation)
// ============================================================================

/// Combined MMP state for a single end-to-end session.
///
/// Wraps sender, receiver, metrics, and path MTU state.
/// One instance per established `SessionEntry`.
pub struct MmpSessionState {
    pub sender: SenderState,
    pub receiver: ReceiverState,
    pub metrics: MmpMetrics,
    mode: MmpMode,
    log_interval_ms: u64,
    last_log_ms: Option<u64>,
    pub path_mtu: PathMtuState,
}

impl MmpSessionState {
    /// Create MMP state for a new session.
    ///
    /// `mode`/`log_interval_secs`/`owd_window_size`
    /// are the shell's config values, passed as plain data.
    pub fn new(mode: MmpMode, log_interval_secs: u64, owd_window_size: usize) -> Self {
        Self {
            sender: SenderState::new_with_cold_start(SESSION_COLD_START_INTERVAL_MS),
            receiver: ReceiverState::new_with_cold_start(
                owd_window_size,
                SESSION_COLD_START_INTERVAL_MS,
            ),
            metrics: MmpMetrics::new(),
            mode,
            log_interval_ms: log_interval_secs * 1000,
            last_log_ms: None,
            path_mtu: PathMtuState::new(),
        }
    }

    /// Reset counter-dependent state for rekey cutover.
    pub fn reset_for_rekey(&mut self, now_ms: u64) {
        self.receiver.reset_for_rekey(now_ms);
        self.metrics.reset_for_rekey();
    }

    /// Current operating mode.
    pub fn mode(&self) -> MmpMode {
        self.mode
    }

    /// Check if it's time to emit a periodic metrics log.
    pub fn should_log(&self, now_ms: u64) -> bool {
        match self.last_log_ms {
            None => true,
            Some(last) => now_ms.saturating_sub(last) >= self.log_interval_ms,
        }
    }

    /// Mark that a periodic log was emitted.
    pub fn mark_logged(&mut self, now_ms: u64) {
        self.last_log_ms = Some(now_ms);
    }
}

impl Debug for MmpSessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MmpSessionState")
            .field("mode", &self.mode)
            .field("path_mtu", &self.path_mtu.current_mtu())
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Path MTU State (session-layer only)
// ============================================================================

/// Path MTU tracking for a single session.
///
/// Destination side: observes `path_mtu` from incoming SessionDatagram envelopes
/// and generates PathMtuNotification messages back to the source.
///
/// Source side: applies received PathMtuNotification to limit outbound datagram
/// size. Decrease is immediate; increase requires 3 consecutive notifications.
pub struct PathMtuState {
    /// Current effective path MTU (what we use for sending).
    current_mtu: u16,
    /// Last observed path MTU from incoming datagrams (destination-side).
    last_observed_mtu: u16,
    /// Whether the observed MTU has changed since the last notification.
    observed_changed: bool,
    /// Last time (injected `u64` ms) a PathMtuNotification was sent.
    last_notification_ms: Option<u64>,
    /// Notification interval in ms: max(10s, 5 * SRTT). Default 10s.
    notification_interval_ms: u64,
    /// For source-side increase tracking: consecutive higher-value notifications.
    consecutive_increase_count: u8,
    /// Time (injected `u64` ms) of the first notification in the current
    /// increase sequence.
    first_increase_ms: Option<u64>,
    /// The MTU value being proposed for increase.
    pending_increase_mtu: u16,
}

impl PathMtuState {
    /// Create path MTU state with no initial measurement.
    pub fn new() -> Self {
        Self {
            current_mtu: u16::MAX,
            last_observed_mtu: u16::MAX,
            observed_changed: false,
            last_notification_ms: None,
            notification_interval_ms: 10_000,
            consecutive_increase_count: 0,
            first_increase_ms: None,
            pending_increase_mtu: 0,
        }
    }

    /// Current effective path MTU (source-side, for sending).
    pub fn current_mtu(&self) -> u16 {
        self.current_mtu
    }

    /// Last observed incoming path MTU (destination-side).
    pub fn last_observed_mtu(&self) -> u16 {
        self.last_observed_mtu
    }

    /// Update notification interval from SRTT: max(10s, 5 * SRTT).
    pub fn update_interval_from_srtt(&mut self, srtt_ms: f64) {
        self.notification_interval_ms = ((srtt_ms * 5.0) as u64).max(10_000);
    }

    /// Seed source-side current_mtu from outbound transport MTU.
    ///
    /// Called on each send. Only decreases (never increases) the current_mtu
    /// so the destination's PathMtuNotification can still raise it later.
    /// Ensures current_mtu doesn't stay at u16::MAX before any notification
    /// arrives from the destination.
    pub fn seed_source_mtu(&mut self, outbound_mtu: u16) {
        if outbound_mtu < self.current_mtu {
            self.current_mtu = outbound_mtu;
        }
    }

    // --- Destination side ---

    /// Observe the path_mtu from an incoming SessionDatagram envelope.
    ///
    /// Called on the destination (receiver) side for every session message.
    pub fn observe_incoming_mtu(&mut self, path_mtu: u16) {
        if path_mtu != self.last_observed_mtu {
            self.observed_changed = true;
            self.last_observed_mtu = path_mtu;
        }
    }

    /// Check if a PathMtuNotification should be sent.
    ///
    /// Send on first measurement, on decrease (immediate), or periodic
    /// confirmation at the notification interval. `now_ms` is the injected
    /// monotonic time in milliseconds.
    pub fn should_send_notification(&self, now_ms: u64) -> bool {
        if self.last_observed_mtu == u16::MAX {
            return false; // No measurement yet
        }
        match self.last_notification_ms {
            None => true, // First measurement
            Some(last) => {
                // Immediate on decrease
                if self.observed_changed && self.last_observed_mtu < self.current_mtu {
                    return true;
                }
                // Periodic confirmation
                now_ms.saturating_sub(last) >= self.notification_interval_ms
            }
        }
    }

    /// Build a PathMtuNotification from current state.
    ///
    /// Returns the path_mtu value to send. Caller handles encoding.
    pub fn build_notification(&mut self, now_ms: u64) -> Option<u16> {
        if self.last_observed_mtu == u16::MAX {
            return None;
        }
        self.last_notification_ms = Some(now_ms);
        self.observed_changed = false;
        Some(self.last_observed_mtu)
    }

    // --- Source side ---

    /// Apply a received PathMtuNotification.
    ///
    /// - Decrease: immediate (take the lower value).
    /// - Increase: require 3 consecutive notifications with the same higher
    ///   value, spanning at least 2 * notification_interval.
    ///
    /// `now_ms` is the injected monotonic time in milliseconds. Returns `true`
    /// if the effective MTU changed.
    pub fn apply_notification(&mut self, reported_mtu: u16, now_ms: u64) -> bool {
        if reported_mtu < self.current_mtu {
            // Decrease: immediate
            self.current_mtu = reported_mtu;
            self.consecutive_increase_count = 0;
            self.first_increase_ms = None;
            return true;
        }

        if reported_mtu > self.current_mtu {
            // Increase: track consecutive notifications
            if reported_mtu == self.pending_increase_mtu {
                self.consecutive_increase_count += 1;
            } else {
                // Different value: reset sequence
                self.pending_increase_mtu = reported_mtu;
                self.consecutive_increase_count = 1;
                self.first_increase_ms = Some(now_ms);
            }

            // Accept increase after 3 consecutive spanning 2 * interval
            if self.consecutive_increase_count >= 3
                && let Some(first_ms) = self.first_increase_ms
            {
                let required_ms = self.notification_interval_ms * 2;
                if now_ms.saturating_sub(first_ms) >= required_ms {
                    self.current_mtu = reported_mtu;
                    self.consecutive_increase_count = 0;
                    self.first_increase_ms = None;
                    return true;
                }
            }
        }

        // No change (equal or increase not yet confirmed)
        false
    }
}

impl Default for PathMtuState {
    fn default() -> Self {
        Self::new()
    }
}
