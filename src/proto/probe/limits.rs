//! Probe budget floors and latch counts.
//!
//! Every value here is either derived from a protocol constant or from the
//! rx-loop tick period. Budgets are **monotonic** (never wall-clock) and
//! tick-quantized: the shell computes each stage budget as
//! `max(floor, N * tick_ms)` so a node with a long `tick_interval_secs` does
//! not expire a stage between two consecutive observations.

/// Floor for the session (handshake) stage. `handshake_resend_interval_ms`
/// is 1000 with `handshake_resend_backoff` 2.0, putting resends at t=1s and
/// t=3s, so 5s covers two resends. The node's own `handshake_timeout_secs`
/// is far longer; the probe cuts sooner on purpose.
pub(crate) const SESSION_FLOOR_MS: u64 = 5_000;

/// Floor for the rtt stage. The remote's session receiver cold-starts at
/// `SESSION_COLD_START_INTERVAL_MS` (1000 ms) and emits on its own tick, so
/// 3s covers two remote ticks plus the cold start. It does not cover a peer
/// sitting at the 10s report-interval ceiling; that is a deliberate trade.
pub(crate) const RTT_FLOOR_MS: u64 = 3_000;

/// Ticks added to `sum(attempt_timeouts_secs)` for the discovery budget, so
/// the ladder's own final attempt can land before the budget cuts it off.
pub(crate) const RESOLVE_SLACK_TICKS: u64 = 2;

/// Ticks allowed for the bloom stage. Nothing here waits on the wire: the
/// gate's answer is produced by the action the stage emits, and the shell
/// performs that after the step returns, so the verdict lands on the next
/// observation. Two ticks is one spare, and the total deadline backstops it.
pub(crate) const BLOOM_MIN_TICKS: u64 = 2;

/// Minimum session-stage budget in ticks.
pub(crate) const SESSION_MIN_TICKS: u64 = 3;

/// Minimum rtt-stage budget in ticks.
pub(crate) const RTT_MIN_TICKS: u64 = 4;

/// Delay before the single allowed warmup retransmit. FSP rides UDP, so one
/// lost datagram would otherwise leave the remote's `interval_has_data`
/// unlatched and report `no_report` against a healthy peer. Two packets total
/// is the whole allowance — resending every tick would make a diagnostic into
/// a traffic source.
pub(crate) const WARMUP_RETRY_MS: u64 = 1_000;

/// Ticks between the last observation and the teardown of a probe-created
/// session. The remote may have a receiver report in flight; tearing down
/// first makes that report land as an `UnknownSession` reject here.
pub(crate) const TEARDOWN_GRACE_TICKS: u64 = 1;

/// How long a terminal job is retained so a late `probe_poll` can read it.
pub(crate) const REAP_MS: u64 = 30_000;

/// Registry-wide cap on jobs in flight.
pub(crate) const MAX_CONCURRENT_PROBES: usize = 4;
