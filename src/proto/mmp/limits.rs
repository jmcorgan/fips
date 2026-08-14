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

// --- Path MTU ---

/// Smallest remote-supplied transport path MTU this node will act on.
///
/// The `path_mtu` field is an unsigned per-hop transit annotation carried
/// outside `proof_bytes`, and the `MtuExceeded` and `PathBroken` signals
/// arrive unencrypted, so any forwarder on the path can lower it. Below this
/// value the quantities derived from it degenerate: at a transport MTU of 137
/// or less, [`mss_ceiling`] saturates to a TCP MSS of zero, at 138 it is a
/// single byte, and the derived MSS stays under a hundred all the way to 236.
/// At the floor itself the derived inner IPv6 MTU is 179 and the TCP MSS is
/// 119, clear of both the zero cliff and that band.
///
/// A candidate below the floor is ignored — treated as no information at all,
/// never applied and never stored — rather than clamped, because clamping
/// would fabricate an estimate the node has no basis for. Locally derived link
/// MTUs are not subject to the floor; it applies only to values a remote party
/// supplied. A local value is exact, so the SYN-time clamp honours it however
/// small and refuses only the zero cliff, which no provenance makes usable.
///
/// It lives here rather than beside the arithmetic that consumes it because it
/// is a protocol policy decision — how little a remote party may claim before
/// this node stops believing it — and the path-MTU state machine that owns
/// that rule is in this module. The upper layer re-exports it, so
/// `crate::upper::icmp::MIN_ACTIONABLE_PATH_MTU` continues to resolve.
///
/// [`mss_ceiling`]: crate::upper::icmp::mss_ceiling
pub const MIN_ACTIONABLE_PATH_MTU: u16 = 256;
