//! MMP tuning constants (EWMA parameters, report-interval bounds, defaults).
//!
//! The plain values the owned sender/receiver/metrics state machines and the
//! shell config clamp against. Re-exported from the module root so external
//! callers keep the `crate::proto::mmp::<CONST>` path.

// --- EWMA parameters ---

/// Dual EWMA short-term: α = 1/4.
pub const EWMA_SHORT_ALPHA: f64 = 0.25;

/// Dual EWMA long-term: α = 1/32.
pub const EWMA_LONG_ALPHA: f64 = 1.0 / 32.0;

// --- Timing defaults (milliseconds) ---

/// Default report interval before SRTT is available (cold start).
pub const DEFAULT_COLD_START_INTERVAL_MS: u64 = 200;

/// Minimum report interval (SRTT clamp floor).
///
/// Raised from 100ms to 1000ms: parent re-evaluation runs every 60s,
/// so 60 samples/cycle is more than sufficient for EWMA convergence (~10).
/// The cold-start phase uses `DEFAULT_COLD_START_INTERVAL_MS` (200ms) for
/// fast initial SRTT convergence before transitioning to this floor.
pub const MIN_REPORT_INTERVAL_MS: u64 = 1_000;

/// Maximum report interval (SRTT clamp ceiling).
pub const MAX_REPORT_INTERVAL_MS: u64 = 5_000;

/// Number of SRTT samples before transitioning from cold-start to normal floor.
///
/// During cold-start, report intervals use `DEFAULT_COLD_START_INTERVAL_MS` as
/// the floor to gather SRTT samples quickly. After this many updates, the floor
/// switches to `MIN_REPORT_INTERVAL_MS`.
pub const COLD_START_SAMPLES: u32 = 5;

/// Default OWD ring buffer capacity.
pub const DEFAULT_OWD_WINDOW_SIZE: usize = 32;

/// Default operator log interval in seconds.
pub const DEFAULT_LOG_INTERVAL_SECS: u64 = 30;

// --- Session-layer timing defaults ---
// Session reports are routed end-to-end (bandwidth cost on every transit link),
// so intervals are higher than link-layer.

/// Session-layer minimum report interval.
pub const MIN_SESSION_REPORT_INTERVAL_MS: u64 = 500;

/// Session-layer maximum report interval.
pub const MAX_SESSION_REPORT_INTERVAL_MS: u64 = 10_000;

/// Session-layer cold-start report interval (before SRTT is available).
pub const SESSION_COLD_START_INTERVAL_MS: u64 = 1_000;
