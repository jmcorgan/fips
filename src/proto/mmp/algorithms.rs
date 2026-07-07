//! MMP algorithmic building blocks.
//!
//! Pure computational types with no dependency on peer or node state.
//! Each is independently testable. `no_std`+`alloc`-clean: the ring buffer
//! comes from `alloc`, all arithmetic is `core`, and the spin-bit RTT clock is
//! an injected `u64` millisecond value (never a `std::time` read).

use alloc::collections::VecDeque;

use super::{EWMA_LONG_ALPHA, EWMA_SHORT_ALPHA};

// ============================================================================
// Jitter Estimator (RFC 3550 §6.4.1)
// ============================================================================

/// Interarrival jitter estimator using RFC 3550 algorithm.
///
/// Maintains a smoothed jitter estimate (α = 1/16) from the absolute
/// difference in one-way transit times between consecutive frames.
/// Uses integer arithmetic scaled by 16 to avoid floating-point.
pub struct JitterEstimator {
    /// Scaled jitter estimate (×16 for integer arithmetic).
    jitter_q4: i64,
}

impl JitterEstimator {
    pub fn new() -> Self {
        Self { jitter_q4: 0 }
    }

    /// Update with transit time delta between consecutive frames.
    ///
    /// `transit_delta` = (R_i - R_{i-1}) - (S_i - S_{i-1}) in microseconds.
    pub fn update(&mut self, transit_delta: i32) {
        // RFC 3550: J = J + (1/16)(|D(i)| - J)
        // Scaled: J_q4 = J_q4 + (|D| - J_q4/16)
        //       = J_q4 + |D| - J_q4 >> 4
        let abs_d = (transit_delta as i64).unsigned_abs() as i64;
        self.jitter_q4 += abs_d - (self.jitter_q4 >> 4);
    }

    /// Current jitter estimate in microseconds.
    pub fn jitter_us(&self) -> u32 {
        (self.jitter_q4 >> 4) as u32
    }
}

impl Default for JitterEstimator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SRTT Estimator (Jacobson, RFC 6298)
// ============================================================================

/// Smoothed RTT estimator using Jacobson's algorithm.
///
/// SRTT and RTTVAR are maintained in microseconds using integer arithmetic.
pub struct SrttEstimator {
    /// Smoothed RTT (microseconds).
    srtt_us: i64,
    /// RTT variance (microseconds).
    rttvar_us: i64,
    /// Whether the first sample has been applied.
    initialized: bool,
}

impl SrttEstimator {
    pub fn new() -> Self {
        Self {
            srtt_us: 0,
            rttvar_us: 0,
            initialized: false,
        }
    }

    /// Feed an RTT sample in microseconds.
    pub fn update(&mut self, rtt_us: i64) {
        if !self.initialized {
            // RFC 6298 §2.2: first measurement
            self.srtt_us = rtt_us;
            self.rttvar_us = rtt_us / 2;
            self.initialized = true;
        } else {
            // RFC 6298 §2.3:
            // RTTVAR = (1 - β) * RTTVAR + β * |SRTT - R'|    β = 1/4
            // SRTT   = (1 - α) * SRTT   + α * R'             α = 1/8
            let err = (self.srtt_us - rtt_us).abs();
            self.rttvar_us = self.rttvar_us - (self.rttvar_us >> 2) + (err >> 2);
            self.srtt_us = self.srtt_us - (self.srtt_us >> 3) + (rtt_us >> 3);
        }
    }

    pub fn srtt_us(&self) -> i64 {
        self.srtt_us
    }

    pub fn rttvar_us(&self) -> i64 {
        self.rttvar_us
    }

    pub fn initialized(&self) -> bool {
        self.initialized
    }

    /// Retransmission timeout = SRTT + max(4 * RTTVAR, 1s), floored at 1s.
    pub fn rto_us(&self) -> i64 {
        let rto = self.srtt_us + (self.rttvar_us << 2).max(1_000_000);
        rto.max(1_000_000)
    }
}

impl Default for SrttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Dual EWMA Trend Detector
// ============================================================================

/// Dual EWMA for trend detection on a single metric.
///
/// Short-term (α=1/4) tracks recent conditions; long-term (α=1/32)
/// establishes a stable baseline. Divergence indicates trend direction.
pub struct DualEwma {
    short: f64,
    long: f64,
    initialized: bool,
}

impl DualEwma {
    pub fn new() -> Self {
        Self {
            short: 0.0,
            long: 0.0,
            initialized: false,
        }
    }

    pub fn update(&mut self, sample: f64) {
        if !self.initialized {
            self.short = sample;
            self.long = sample;
            self.initialized = true;
        } else {
            self.short += EWMA_SHORT_ALPHA * (sample - self.short);
            self.long += EWMA_LONG_ALPHA * (sample - self.long);
        }
    }

    pub fn short(&self) -> f64 {
        self.short
    }

    pub fn long(&self) -> f64 {
        self.long
    }

    pub fn initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for DualEwma {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// One-Way Delay Trend Detector
// ============================================================================

/// OWD trend detector using linear regression over a ring buffer.
///
/// Stores (sequence, owd_us) samples and computes the slope via
/// least-squares regression. The slope (µs/s) indicates whether
/// queuing delay is increasing (congestion) or stable.
pub struct OwdTrendDetector {
    samples: VecDeque<(u32, i64)>,
    capacity: usize,
}

impl OwdTrendDetector {
    pub fn new(capacity: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Clear all samples, keeping the same capacity.
    pub fn clear(&mut self) {
        self.samples.clear();
    }

    /// Add an OWD sample.
    ///
    /// `seq` is a monotonic sequence number (e.g., truncated frame counter).
    /// `owd_us` is the relative one-way delay in microseconds (R_i - S_i).
    pub fn push(&mut self, seq: u32, owd_us: i64) {
        if self.samples.len() == self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back((seq, owd_us));
    }

    /// Compute the OWD trend as a slope in µs/second.
    ///
    /// Uses simple linear regression: slope = Σ((x-x̄)(y-ȳ)) / Σ((x-x̄)²)
    /// where x = sequence number and y = owd_us.
    ///
    /// Returns 0 if fewer than 2 samples.
    pub fn trend_us_per_sec(&self) -> i32 {
        let n = self.samples.len();
        if n < 2 {
            return 0;
        }

        let n_f = n as f64;
        let sum_x: f64 = self.samples.iter().map(|(s, _)| *s as f64).sum();
        let sum_y: f64 = self.samples.iter().map(|(_, y)| *y as f64).sum();
        let mean_x = sum_x / n_f;
        let mean_y = sum_y / n_f;

        let mut num = 0.0;
        let mut den = 0.0;
        for &(x, y) in &self.samples {
            let dx = x as f64 - mean_x;
            let dy = y as f64 - mean_y;
            num += dx * dy;
            den += dx * dx;
        }

        // `den` is a sum of squares, so it is always non-negative; comparing it
        // directly against EPSILON is equivalent to the original `den.abs()`
        // guard while staying `core`-only (no `libm`).
        if den < f64::EPSILON {
            return 0;
        }

        // slope is in µs/packet. Convert to µs/second assuming ~1ms inter-packet
        // spacing as a rough estimate. The raw slope per packet is more useful
        // for trend detection than an absolute rate, but the wire format specifies
        // µs/s. We report the raw per-packet slope scaled by 1000.
        let slope_per_packet = num / den;
        (slope_per_packet * 1000.0) as i32
    }
}

// ============================================================================
// ETX
// ============================================================================

/// Compute Expected Transmission Count from bidirectional delivery ratios.
///
/// ETX = 1 / (d_f × d_r) where d_f and d_r are forward and reverse
/// delivery probabilities (1.0 = perfect, 0.0 = no delivery).
///
/// Clamped to [1.0, 100.0].
pub fn compute_etx(d_forward: f64, d_reverse: f64) -> f64 {
    let product = d_forward * d_reverse;
    if product <= 0.0 {
        return 100.0;
    }
    (1.0 / product).clamp(1.0, 100.0)
}

// ============================================================================
// Spin Bit
// ============================================================================

/// Spin bit state for passive RTT estimation.
///
/// Uses asymmetric roles (initiator/responder) per the MMP design:
/// - **Initiator**: flips spin value on each received frame; measures RTT
///   from edge-to-edge intervals.
/// - **Responder**: copies received spin bit into outgoing frames, with a
///   counter guard to filter reordered frames.
pub struct SpinBitState {
    is_initiator: bool,
    current_value: bool,
    /// Highest counter observed with a spin edge (responder guard).
    highest_counter_for_spin: u64,
    /// Time of last spin edge in injected `u64` milliseconds (initiator only,
    /// for RTT measurement).
    last_edge_ms: Option<u64>,
}

impl SpinBitState {
    pub fn new(is_initiator: bool) -> Self {
        Self {
            is_initiator,
            current_value: false,
            highest_counter_for_spin: 0,
            last_edge_ms: None,
        }
    }

    /// Check if this is the spin bit initiator.
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Get the spin bit value to set on an outgoing frame.
    pub fn tx_bit(&self) -> bool {
        self.current_value
    }

    /// Process a received frame's spin bit.
    ///
    /// `now_ms` is the injected monotonic time in milliseconds. Returns an RTT
    /// sample in milliseconds if an edge was detected (initiator only).
    pub fn rx_observe(&mut self, received_bit: bool, counter: u64, now_ms: u64) -> Option<u64> {
        if self.is_initiator {
            // Initiator: when the reflected bit matches what we sent,
            // that completes a round trip. Record the edge time, then
            // flip for the next cycle.
            if received_bit == self.current_value {
                let rtt = self.last_edge_ms.map(|t| now_ms.saturating_sub(t));
                self.last_edge_ms = Some(now_ms);
                self.current_value = !self.current_value;
                rtt
            } else {
                None
            }
        } else {
            // Responder: copy received bit, but only if counter is higher
            // (reordering guard)
            if counter > self.highest_counter_for_spin {
                self.highest_counter_for_spin = counter;
                self.current_value = received_bit;
            }
            None
        }
    }
}
