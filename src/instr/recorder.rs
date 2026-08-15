//! Fixed-footprint recorder: exact count / max / total per (domain, step).
//!
//! All state is process statics, not `Node` state, because the `fipsctl`
//! handler that arms and disarms a capture runs in the control accept task and
//! has no `&Node` — that is the whole point of serving it off-loop, so it
//! cannot queue behind the behavior it is measuring.
//!
//! The writer thread is the only reader. It takes each interval's figures with
//! `swap(0)`, so there are no "previous value" arrays to carry and the counters
//! are per-interval by construction.

use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

/// Measurement domain. Structural only: one variant today.
///
/// A data-path domain is deliberately **not** declared until something records
/// into it. What generalizes here is the enum, the counter table and the
/// writer; the per-tick gate hoist does not, so a data-path domain will need
/// its own gate strategy.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum Domain {
    Tick = 0,
}

pub(crate) const N_DOMAINS: usize = 1;
pub(crate) const DOMAINS: [Domain; N_DOMAINS] = [Domain::Tick];

impl Domain {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Domain::Tick => "tick",
        }
    }
}

/// One measured step of the rx-loop tick arm, in call order, plus the
/// whole-body span.
///
/// `as usize` indexes the counter arrays, so the discriminants are dense and
/// `WholeTick` is last (it defines `N_STEPS`). Variants are declared
/// unconditionally — see [`Step::emitted`] for how the two platform- and
/// profile-conditional steps are kept out of the emitted table.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum Step {
    CheckTimeouts = 0,
    ReloadPeerAcl,
    ReloadHostMap,
    PollPendingConnects,
    PollNostrRendezvous,
    PollLanRendezvous,
    DrivePeerTimers,
    ResendPendingRekeys,
    /// `next`-only: the FMP rekey msg3 resend driver has no master-line
    /// counterpart, so this variant exists on this line alone.
    ResendPendingFmpRekeyMsg3,
    ResendPendingSessionHandshakes,
    ResendPendingSessionMsg3,
    PurgeIdleSessions,
    PurgeExpiredPathMtu,
    ProcessPendingRetries,
    CheckTreeState,
    CheckBloomState,
    ComputeMeshSize,
    RecordStatsHistory,
    CheckMmpReports,
    CheckSessionMmpReports,
    CheckLinkHeartbeats,
    CheckRekey,
    CheckSessionRekey,
    CheckPendingLookups,
    PollTransportDiscovery,
    SampleTransportCongestion,
    ActivateConnectedUdpSessions,
    DebugAssertPeerMapsCoherent,
    /// The whole tick-arm body, from before `check_timeouts` to after the last
    /// step. Composes safely with the per-step spans because the macro
    /// evaluates its measured expression exactly once.
    WholeTick,
}

pub(crate) const N_STEPS: usize = Step::WholeTick as usize + 1;

/// Every step, in emission order. Index `i` of this table is `STEPS[i] as
/// usize`; `steps_table_is_dense` asserts it.
pub(crate) const STEPS: [Step; N_STEPS] = [
    Step::CheckTimeouts,
    Step::ReloadPeerAcl,
    Step::ReloadHostMap,
    Step::PollPendingConnects,
    Step::PollNostrRendezvous,
    Step::PollLanRendezvous,
    Step::DrivePeerTimers,
    Step::ResendPendingRekeys,
    Step::ResendPendingFmpRekeyMsg3,
    Step::ResendPendingSessionHandshakes,
    Step::ResendPendingSessionMsg3,
    Step::PurgeIdleSessions,
    Step::PurgeExpiredPathMtu,
    Step::ProcessPendingRetries,
    Step::CheckTreeState,
    Step::CheckBloomState,
    Step::ComputeMeshSize,
    Step::RecordStatsHistory,
    Step::CheckMmpReports,
    Step::CheckSessionMmpReports,
    Step::CheckLinkHeartbeats,
    Step::CheckRekey,
    Step::CheckSessionRekey,
    Step::CheckPendingLookups,
    Step::PollTransportDiscovery,
    Step::SampleTransportCongestion,
    Step::ActivateConnectedUdpSessions,
    Step::DebugAssertPeerMapsCoherent,
    Step::WholeTick,
];

impl Step {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Step::CheckTimeouts => "check_timeouts",
            Step::ReloadPeerAcl => "reload_peer_acl",
            Step::ReloadHostMap => "reload_host_map",
            Step::PollPendingConnects => "poll_pending_connects",
            Step::PollNostrRendezvous => "poll_nostr_rendezvous",
            Step::PollLanRendezvous => "poll_lan_rendezvous",
            Step::DrivePeerTimers => "drive_peer_timers",
            Step::ResendPendingRekeys => "resend_pending_rekeys",
            Step::ResendPendingFmpRekeyMsg3 => "resend_pending_fmp_rekey_msg3",
            Step::ResendPendingSessionHandshakes => "resend_pending_session_handshakes",
            Step::ResendPendingSessionMsg3 => "resend_pending_session_msg3",
            Step::PurgeIdleSessions => "purge_idle_sessions",
            Step::PurgeExpiredPathMtu => "purge_expired_path_mtu",
            Step::ProcessPendingRetries => "process_pending_retries",
            Step::CheckTreeState => "check_tree_state",
            Step::CheckBloomState => "check_bloom_state",
            Step::ComputeMeshSize => "compute_mesh_size",
            Step::RecordStatsHistory => "record_stats_history",
            Step::CheckMmpReports => "check_mmp_reports",
            Step::CheckSessionMmpReports => "check_session_mmp_reports",
            Step::CheckLinkHeartbeats => "check_link_heartbeats",
            Step::CheckRekey => "check_rekey",
            Step::CheckSessionRekey => "check_session_rekey",
            Step::CheckPendingLookups => "check_pending_lookups",
            Step::PollTransportDiscovery => "poll_transport_discovery",
            Step::SampleTransportCongestion => "sample_transport_congestion",
            Step::ActivateConnectedUdpSessions => "activate_connected_udp_sessions",
            Step::DebugAssertPeerMapsCoherent => "debug_assert_peer_maps_coherent",
            Step::WholeTick => "whole_tick",
        }
    }

    /// Whether this step gets a row in this build.
    ///
    /// Two steps are conditionally compiled at their call sites. Emitting a row
    /// for them in a build where the call site does not exist would publish a
    /// count that is structurally zero forever, which reads as "this step never
    /// runs" rather than "this step is not in this build". The predicates below
    /// are the same `cfg` expressions that gate the call sites in
    /// `node::dataplane::rx_loop`; keep them in step.
    pub(crate) const fn emitted(self) -> bool {
        match self {
            Step::ActivateConnectedUdpSessions => {
                cfg!(any(target_os = "linux", target_os = "macos"))
            }
            Step::DebugAssertPeerMapsCoherent => cfg!(debug_assertions),
            _ => true,
        }
    }
}

/// A scalar sampled once per tick, as opposed to a duration.
///
/// Gauges carry their own row kind and their own unit in the output so a gauge
/// value can never be read as a duration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum Gauge {
    Ticks = 0,
    Peers,
    TickGap,
    ArmStarvation,
}

pub(crate) const N_GAUGES: usize = Gauge::ArmStarvation as usize + 1;

pub(crate) const GAUGES: [Gauge; N_GAUGES] = [
    Gauge::Ticks,
    Gauge::Peers,
    Gauge::TickGap,
    Gauge::ArmStarvation,
];

impl Gauge {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Gauge::Ticks => "ticks",
            Gauge::Peers => "peers",
            Gauge::TickGap => "tick_entry_gap",
            Gauge::ArmStarvation => "arm_starvation",
        }
    }

    /// Unit of the `max` and `total` columns for this gauge.
    pub(crate) const fn unit(self) -> &'static str {
        match self {
            Gauge::Ticks => "ticks",
            Gauge::Peers => "peers",
            Gauge::TickGap | Gauge::ArmStarvation => "us",
        }
    }

    /// Whether the gauge's stored values are nanosecond durations that the
    /// writer converts to microseconds.
    pub(crate) const fn is_duration(self) -> bool {
        matches!(self, Gauge::TickGap | Gauge::ArmStarvation)
    }
}

const N_SLOTS: usize = N_DOMAINS * N_STEPS;

static COUNT: [AtomicU64; N_SLOTS] = [const { AtomicU64::new(0) }; N_SLOTS];
static MAX_NS: [AtomicU64; N_SLOTS] = [const { AtomicU64::new(0) }; N_SLOTS];
static TOTAL_NS: [AtomicU64; N_SLOTS] = [const { AtomicU64::new(0) }; N_SLOTS];

static G_COUNT: [AtomicU64; N_GAUGES] = [const { AtomicU64::new(0) }; N_GAUGES];
static G_MAX: [AtomicU64; N_GAUGES] = [const { AtomicU64::new(0) }; N_GAUGES];
static G_TOTAL: [AtomicU64; N_GAUGES] = [const { AtomicU64::new(0) }; N_GAUGES];

/// Monotonic baseline so tick-arm entry times fit in an atomic. Offset by one
/// on store so that zero can mean "no previous entry".
static BASE: LazyLock<Instant> = LazyLock::new(Instant::now);
static PREV_ENTRY_NS: AtomicU64 = AtomicU64::new(0);

#[inline]
const fn slot(domain: Domain, step: Step) -> usize {
    (domain as usize * N_STEPS) + step as usize
}

/// Read the clock for a step span.
#[inline]
pub(crate) fn now() -> Instant {
    Instant::now()
}

/// Record one observation of `step`.
#[inline]
pub(crate) fn record(domain: Domain, step: Step, elapsed: Duration) {
    let ns = elapsed.as_nanos() as u64;
    let idx = slot(domain, step);
    COUNT[idx].fetch_add(1, Relaxed);
    TOTAL_NS[idx].fetch_add(ns, Relaxed);
    MAX_NS[idx].fetch_max(ns, Relaxed);
}

#[inline]
fn record_gauge(gauge: Gauge, value: u64) {
    let idx = gauge as usize;
    G_COUNT[idx].fetch_add(1, Relaxed);
    G_TOTAL[idx].fetch_add(value, Relaxed);
    G_MAX[idx].fetch_max(value, Relaxed);
}

/// Sample the inter-entry gap and the measured arm-starvation delay.
pub(crate) fn tick_entry(on: bool, deadline: Instant, now: Instant) {
    if !on {
        return;
    }
    // Offset by one so that a stored zero unambiguously means "no previous
    // entry", even for an entry that lands on the baseline instant.
    let stamp = BASE.elapsed().as_nanos() as u64 + 1;
    let late = now.saturating_duration_since(deadline).as_nanos() as u64;
    tick_entry_at(stamp, late);
}

/// The clock-free half of [`tick_entry`]: both times are inputs, so the
/// arithmetic can be driven with synthetic stamps in a test.
///
/// `late_ns` is how far past its scheduled deadline this entry was, measured
/// directly rather than derived. Two earlier designs derived it from the
/// inter-entry gap and were both wrong: subtracting the previous body
/// understated it by exactly the body, and subtracting `max(period, body)`
/// reported the *first difference* of the delay, so a sustained stall — the
/// overload regime this measurement exists to characterize — read as zero
/// forever. `tokio::time::interval::tick` hands back the deadline it was
/// scheduled for, so the delay is a subtraction with no model behind it.
fn tick_entry_at(stamp: u64, late_ns: u64) {
    let prev = PREV_ENTRY_NS.swap(stamp, Relaxed);
    record_gauge(Gauge::Ticks, 1);
    record_gauge(Gauge::ArmStarvation, late_ns);
    if prev == 0 {
        // First entry of this capture: there is no previous entry to measure a
        // gap against, and the idle interval before arming is not a gap. The
        // lateness above does not depend on a previous entry, so it still counts.
        return;
    }
    record_gauge(Gauge::TickGap, stamp.saturating_sub(prev));
}

/// Sample the gauges that come from node state.
pub(crate) fn tick_gauges(on: bool, peers: u64) {
    if !on {
        return;
    }
    record_gauge(Gauge::Peers, peers);
}

/// Take (and clear) this interval's figures for one step: count, max ns, total
/// ns. Called only by the writer thread.
pub(crate) fn take_step(domain: Domain, step: Step) -> (u64, u64, u64) {
    let idx = slot(domain, step);
    (
        COUNT[idx].swap(0, Relaxed),
        MAX_NS[idx].swap(0, Relaxed),
        TOTAL_NS[idx].swap(0, Relaxed),
    )
}

/// Take (and clear) this interval's figures for one gauge.
pub(crate) fn take_gauge(gauge: Gauge) -> (u64, u64, u64) {
    let idx = gauge as usize;
    (
        G_COUNT[idx].swap(0, Relaxed),
        G_MAX[idx].swap(0, Relaxed),
        G_TOTAL[idx].swap(0, Relaxed),
    )
}

/// Zero every counter so a capture starts from a clean slate.
pub(crate) fn reset() {
    for i in 0..N_SLOTS {
        COUNT[i].store(0, Relaxed);
        MAX_NS[i].store(0, Relaxed);
        TOTAL_NS[i].store(0, Relaxed);
    }
    for i in 0..N_GAUGES {
        G_COUNT[i].store(0, Relaxed);
        G_MAX[i].store(0, Relaxed);
        G_TOTAL[i].store(0, Relaxed);
    }
    PREV_ENTRY_NS.store(0, Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::MutexGuard;

    /// Shared with the capture tests: they mutate the same statics. See
    /// `crate::instr::test_serial`.
    fn serial() -> MutexGuard<'static, ()> {
        crate::instr::test_serial()
    }

    #[test]
    fn steps_table_is_dense() {
        for (i, step) in STEPS.iter().enumerate() {
            assert_eq!(*step as usize, i, "step {} is out of order", step.name());
        }
        assert_eq!(STEPS.len(), N_STEPS);
    }

    #[test]
    fn gauges_table_is_dense() {
        for (i, gauge) in GAUGES.iter().enumerate() {
            assert_eq!(*gauge as usize, i, "gauge {} is out of order", gauge.name());
        }
        assert_eq!(GAUGES.len(), N_GAUGES);
    }

    #[test]
    fn step_names_are_unique() {
        let mut names: Vec<&str> = STEPS.iter().map(|s| s.name()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate step name");
    }

    #[test]
    fn emitted_row_count_matches_build() {
        let emitted = STEPS.iter().filter(|s| s.emitted()).count();
        // 26 unconditional subsystem steps on this line (25 shared with the
        // master line, plus `resend_pending_fmp_rekey_msg3`, which exists only
        // here) + the whole-tick span, plus the two conditionally-compiled
        // steps where this build has them. The count is pinned deliberately: it
        // is what caught the extra step when the master-line instrumentation
        // was merged up, rather than letting the tables silently disagree — and
        // it did so again when `purge_expired_path_mtu` arrived with the
        // path-MTU expiry work, taking the shared count from 24 to 25.
        let mut expected = 27;
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            expected += 1;
        }
        if cfg!(debug_assertions) {
            expected += 1;
        }
        assert_eq!(emitted, expected);
    }

    #[test]
    fn record_accumulates_count_max_and_total() {
        let _guard = serial();
        reset();
        record(Domain::Tick, Step::CheckRekey, Duration::from_nanos(10));
        record(Domain::Tick, Step::CheckRekey, Duration::from_nanos(30));
        let (count, max, total) = take_step(Domain::Tick, Step::CheckRekey);
        assert_eq!((count, max, total), (2, 30, 40));
        // Taking clears the slot.
        assert_eq!(take_step(Domain::Tick, Step::CheckRekey), (0, 0, 0));
    }

    #[test]
    fn starvation_is_the_measured_lateness_of_the_entry() {
        let _guard = serial();
        reset();
        // The interval hands back the deadline it was scheduled for, so the
        // delay is `now - deadline` and nothing is derived from the period, the
        // previous entry, or the previous body.
        PREV_ENTRY_NS.store(1_000_000_000, Relaxed);
        tick_entry_at(1_100_000_000, 50_000_000);
        assert_eq!(take_gauge(Gauge::TickGap), (1, 100_000_000, 100_000_000));
        assert_eq!(
            take_gauge(Gauge::ArmStarvation),
            (1, 50_000_000, 50_000_000)
        );
        assert_eq!(take_gauge(Gauge::Ticks).0, 1);
        reset();
    }

    #[test]
    fn sustained_lateness_is_reported_on_every_tick() {
        let _guard = serial();
        reset();
        // The regime the two earlier designs both hid. Three consecutive entries
        // each 50 ms past their deadline, one period apart, i.e. the arm waiting
        // a constant amount behind the other select arms every round. The gaps
        // are all exactly one period, so any formula derived from the
        // inter-entry gap reports zero here; measured lateness reports 50 ms
        // three times, which is the truth.
        PREV_ENTRY_NS.store(1_000_000_000, Relaxed);
        tick_entry_at(1_050_000_000, 50_000_000);
        tick_entry_at(1_100_000_000, 50_000_000);
        tick_entry_at(1_150_000_000, 50_000_000);
        let (count, max, total) = take_gauge(Gauge::ArmStarvation);
        assert_eq!(count, 3);
        assert_eq!(max, 50_000_000);
        assert_eq!(total, 150_000_000);
        // ...and the gap alone carries no signal about it: every gap is one
        // period, exactly as it would be on a perfectly healthy node.
        assert_eq!(take_gauge(Gauge::TickGap), (3, 50_000_000, 150_000_000));
        reset();
    }

    #[test]
    fn first_entry_of_a_capture_records_no_gap_but_still_records_lateness() {
        let _guard = serial();
        reset();
        tick_entry_at(500, 7_000_000);
        assert_eq!(take_gauge(Gauge::Ticks).0, 1);
        assert_eq!(take_gauge(Gauge::TickGap), (0, 0, 0));
        // Lateness does not depend on a previous entry, so the first tick of a
        // capture still contributes one.
        assert_eq!(take_gauge(Gauge::ArmStarvation), (1, 7_000_000, 7_000_000));
        reset();
    }

    #[test]
    fn an_on_schedule_entry_reports_no_starvation() {
        let _guard = serial();
        reset();
        PREV_ENTRY_NS.store(1_000_000_000, Relaxed);
        tick_entry_at(1_050_000_000, 0);
        assert_eq!(take_gauge(Gauge::ArmStarvation), (1, 0, 0));
        assert_eq!(take_gauge(Gauge::TickGap), (1, 50_000_000, 50_000_000));
        reset();
    }

    #[test]
    fn gate_off_records_nothing() {
        let _guard = serial();
        reset();
        let t = Instant::now();
        tick_entry(false, t, t);
        tick_gauges(false, 42);
        assert_eq!(take_gauge(Gauge::Ticks), (0, 0, 0));
        assert_eq!(take_gauge(Gauge::Peers), (0, 0, 0));
    }
}
