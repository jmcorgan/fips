// Some entry points (e.g. `stamp`, `record_since`) are only called from
// paths that aren't yet wired up in this PR (FSP-pipelined dispatch,
// per-stage worker telemetry). Keep them in tree so the follow-up wiring
// PR is a pure call-site change.
#![allow(dead_code)]

//! Runtime perf profiler for the FMP/FSP hot path and queue handoffs.
//!
//! Avoids external dependencies (`perf`, samply, etc.) by instrumenting
//! the key stages directly with `AtomicU64` ns counters, histograms,
//! and packet counts. A background task prints a per-stage breakdown
//! every `FIPS_PERF_INTERVAL_SECS` seconds when `FIPS_PERF=1` or
//! `FIPS_PIPELINE_TRACE=1` is set at runtime.
//!
//! Enabling adds `Instant::now()` plus a few relaxed atomics per
//! measured stage, so the measured numbers are slightly pessimistic vs
//! production. The relative picture is the point: it shows whether a
//! run is spending time in crypto, syscalls, or scheduler/channel
//! waits.
//!
//! Stages tracked, inbound:
//!   * `UDP_RECV` — recvmmsg syscall + per-message buffer copy
//!   * `FMP_DECRYPT` — outer AEAD open + replay window
//!   * `LINK_DISPATCH` — `dispatch_link_message` excluding FSP work
//!   * `FSP_DECRYPT` — inner AEAD open + replay window
//!   * `TUN_WRITE` — IPv6 shim decompress + tun_tx.send
//!
//! Stages tracked, outbound:
//!   * `FSP_ENCRYPT` — inner AEAD seal (`send_session_data`)
//!   * `FMP_ENCRYPT` — outer AEAD seal (`send_encrypted_link_message`)
//!   * `UDP_SEND` — sendmmsg/sendmsg/sendto flush
//!
//! Handoff waits tracked:
//!   * `TRANSPORT_QUEUE_WAIT` — UDP/transport receive loop → rx_loop
//!   * `ENDPOINT_COMMAND_WAIT` — FipsEndpoint send → node command loop
//!   * `FMP_WORKER_QUEUE_WAIT` — rx_loop FMP job dispatch → worker
//!   * `ENDPOINT_EVENT_WAIT` — rx_loop endpoint delivery → endpoint recv

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Instant;

/// Number of measurement buckets. Indices match `Stage`.
const N_STAGES: usize = 16;
const N_EVENTS: usize = 6;
const HIST_BUCKETS: usize = 48;

/// Stage identifier. `as usize` indexes into the counter arrays.
#[derive(Copy, Clone, Debug)]
#[repr(usize)]
pub enum Stage {
    UdpRecv = 0,
    FmpDecrypt = 1,
    LinkDispatch = 2,
    FspDecrypt = 3,
    TunWrite = 4,
    FspEncrypt = 5,
    FmpEncrypt = 6,
    UdpSend = 7,
    /// Whole `Node::process_packet` body. Anchor for "what fraction of
    /// the receive hot path is in the non-AEAD parts of the pipeline".
    ProcessPacket = 8,
    /// Just the `endpoint_event_tx.send()` for inbound application
    /// payloads — wakes the embedded-endpoint consumer task.
    EndpointDeliver = 9,
    /// Whole `handle_encrypted_session_msg` (FSP receive path) minus
    /// the `FspDecrypt` sub-span. Surfaces dispatch + ipv6_shim +
    /// `Vec::drain` cost on the inner session layer.
    FspHandle = 10,
    /// Whole `handle_endpoint_data_command` body — the SENDER's
    /// per-packet "do everything to push one outbound packet"
    /// dispatch. Compare against the sum of `FspEncrypt`,
    /// `FmpEncrypt`, and `UdpSend` to see how much of the sender
    /// hot path is in state-touching dispatch (sessions/peers
    /// lookups, MMP/stats updates, Vec allocs) vs the AEAD/syscall
    /// work that's a natural fit for an off-task worker.
    EndpointSend = 11,
    /// Time spent waiting after `FipsEndpoint::send`/`blocking_send`
    /// creates a node command until `rx_loop` starts handling it.
    EndpointCommandWait = 12,
    /// Time spent waiting after `rx_loop` creates an FMP encrypt/send
    /// worker job until the worker thread starts encrypting it.
    FmpWorkerQueueWait = 13,
    /// Time spent waiting after a transport receives a packet until
    /// `rx_loop` starts processing it.
    TransportQueueWait = 14,
    /// Time spent waiting after `rx_loop` delivers endpoint data until
    /// the embedded endpoint consumer receives it.
    EndpointEventWait = 15,
}

impl Stage {
    const fn name(self) -> &'static str {
        match self {
            Stage::UdpRecv => "udp_recv",
            Stage::FmpDecrypt => "fmp_decrypt",
            Stage::LinkDispatch => "link_dispatch",
            Stage::FspDecrypt => "fsp_decrypt",
            Stage::TunWrite => "tun_write",
            Stage::FspEncrypt => "fsp_encrypt",
            Stage::FmpEncrypt => "fmp_encrypt",
            Stage::UdpSend => "udp_send",
            Stage::ProcessPacket => "process_packet",
            Stage::EndpointDeliver => "endpoint_deliver",
            Stage::FspHandle => "fsp_handle",
            Stage::EndpointSend => "endpoint_send",
            Stage::EndpointCommandWait => "endpoint_command_wait",
            Stage::FmpWorkerQueueWait => "fmp_worker_queue_wait",
            Stage::TransportQueueWait => "transport_queue_wait",
            Stage::EndpointEventWait => "endpoint_event_wait",
        }
    }
}

fn stage_from_index(idx: usize) -> Stage {
    match idx {
        0 => Stage::UdpRecv,
        1 => Stage::FmpDecrypt,
        2 => Stage::LinkDispatch,
        3 => Stage::FspDecrypt,
        4 => Stage::TunWrite,
        5 => Stage::FspEncrypt,
        6 => Stage::FmpEncrypt,
        7 => Stage::UdpSend,
        8 => Stage::ProcessPacket,
        9 => Stage::EndpointDeliver,
        10 => Stage::FspHandle,
        11 => Stage::EndpointSend,
        12 => Stage::EndpointCommandWait,
        13 => Stage::FmpWorkerQueueWait,
        14 => Stage::TransportQueueWait,
        15 => Stage::EndpointEventWait,
        _ => unreachable!(),
    }
}

/// Count-only events that clarify which hot-path variant is active.
#[derive(Copy, Clone, Debug)]
#[repr(usize)]
pub enum Event {
    UdpSendConnected = 0,
    UdpSendWildcard = 1,
    UdpSendBackpressure = 2,
    ConnectedUdpInstalled = 3,
    ConnectedUdpActivationFailed = 4,
    UdpSendBackpressureSleep = 5,
}

impl Event {
    const fn name(self) -> &'static str {
        match self {
            Event::UdpSendConnected => "udp_send_connected",
            Event::UdpSendWildcard => "udp_send_wildcard",
            Event::UdpSendBackpressure => "udp_send_backpressure",
            Event::ConnectedUdpInstalled => "connected_udp_installed",
            Event::ConnectedUdpActivationFailed => "connected_udp_activation_failed",
            Event::UdpSendBackpressureSleep => "udp_send_backpressure_sleep",
        }
    }
}

fn event_from_index(idx: usize) -> Event {
    match idx {
        0 => Event::UdpSendConnected,
        1 => Event::UdpSendWildcard,
        2 => Event::UdpSendBackpressure,
        3 => Event::ConnectedUdpInstalled,
        4 => Event::ConnectedUdpActivationFailed,
        5 => Event::UdpSendBackpressureSleep,
        _ => unreachable!(),
    }
}

static TOTAL_NS: [AtomicU64; N_STAGES] = [const { AtomicU64::new(0) }; N_STAGES];
static COUNT: [AtomicU64; N_STAGES] = [const { AtomicU64::new(0) }; N_STAGES];
static MAX_NS: [AtomicU64; N_STAGES] = [const { AtomicU64::new(0) }; N_STAGES];
static HIST: [AtomicU64; N_STAGES * HIST_BUCKETS] =
    [const { AtomicU64::new(0) }; N_STAGES * HIST_BUCKETS];
static EVENTS: [AtomicU64; N_EVENTS] = [const { AtomicU64::new(0) }; N_EVENTS];

/// True iff perf/pipeline tracing is enabled. Read once at startup so
/// the per-packet check is a single cached load.
pub(crate) fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        ["FIPS_PERF", "FIPS_PIPELINE_TRACE"].into_iter().any(|key| {
            std::env::var(key)
                .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
        })
    })
}

/// Capture a timestamp for a future queue-wait measurement. Returns
/// `None` when tracing is disabled so callers can store it cheaply in
/// packet/job structs without paying `Instant::now()` in production.
#[inline]
pub(crate) fn stamp() -> Option<Instant> {
    if enabled() {
        Some(Instant::now())
    } else {
        None
    }
}

/// Record time elapsed since a previously captured stamp.
#[inline]
pub(crate) fn record_since(stage: Stage, start: Option<Instant>) {
    if let Some(start) = start {
        record(stage, start.elapsed().as_nanos() as u64);
    }
}

/// Record `elapsed_ns` for the given stage. No-op when disabled.
pub fn record(stage: Stage, elapsed_ns: u64) {
    if !enabled() {
        return;
    }
    let idx = stage as usize;
    let elapsed_ns = elapsed_ns.max(1);
    TOTAL_NS[idx].fetch_add(elapsed_ns, Relaxed);
    COUNT[idx].fetch_add(1, Relaxed);
    MAX_NS[idx].fetch_max(elapsed_ns, Relaxed);
    HIST[(idx * HIST_BUCKETS) + bucket_for_ns(elapsed_ns)].fetch_add(1, Relaxed);
}

#[inline]
pub fn record_event(event: Event) {
    record_event_count(event, 1);
}

pub fn record_event_count(event: Event, count: u64) {
    if !enabled() || count == 0 {
        return;
    }
    EVENTS[event as usize].fetch_add(count, Relaxed);
}

/// RAII timer — `drop` records the elapsed time into the stage.
/// Use:
/// ```ignore
/// let _t = profile::Timer::start(Stage::FmpDecrypt);
/// // ... AEAD work ...
/// ```
pub struct Timer {
    stage: Stage,
    start: Option<Instant>,
}

impl Timer {
    #[inline]
    pub fn start(stage: Stage) -> Self {
        let start = if enabled() {
            Some(Instant::now())
        } else {
            None
        };
        Self { stage, start }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        if let Some(t0) = self.start {
            let ns = t0.elapsed().as_nanos() as u64;
            record(self.stage, ns);
        }
    }
}

/// Spawn a background task that prints a per-stage breakdown every
/// `FIPS_PERF_INTERVAL_SECS` seconds (default 5). Idempotent — only
/// the first call spawns. No-op when profiling isn't enabled.
pub fn maybe_spawn_reporter() {
    if !enabled() {
        return;
    }
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }
    let interval = std::env::var("FIPS_PERF_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(5)
        .max(1);
    tokio::spawn(async move {
        let mut prev_total = [0u64; N_STAGES];
        let mut prev_count = [0u64; N_STAGES];
        let mut prev_hist = [0u64; N_STAGES * HIST_BUCKETS];
        let mut prev_events = [0u64; N_EVENTS];
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            let mut line = format!("[pipe {}s]", interval);
            for i in 0..N_STAGES {
                let t = TOTAL_NS[i].load(Relaxed);
                let c = COUNT[i].load(Relaxed);
                let dt = t.saturating_sub(prev_total[i]);
                let dc = c.saturating_sub(prev_count[i]);
                prev_total[i] = t;
                prev_count[i] = c;

                let base = i * HIST_BUCKETS;
                let mut hist_delta = [0u64; HIST_BUCKETS];
                for (bucket, delta) in hist_delta.iter_mut().enumerate().take(HIST_BUCKETS) {
                    let idx = base + bucket;
                    let current = HIST[idx].load(Relaxed);
                    *delta = current.saturating_sub(prev_hist[idx]);
                    prev_hist[idx] = current;
                }
                if dc == 0 {
                    continue;
                }
                let stage = stage_from_index(i);
                let avg_ns = if dc > 0 { dt / dc } else { 0 };
                let pps = if interval > 0 { dc / interval } else { 0 };
                let p50 = percentile_ns(&hist_delta, dc, 50);
                let p95 = percentile_ns(&hist_delta, dc, 95);
                let p99 = percentile_ns(&hist_delta, dc, 99);
                let approx_max = interval_max_ns(&hist_delta);
                let lifetime_max = MAX_NS[i].load(Relaxed);
                line.push_str(&format!(
                    " {}={}/s avg={} p50<={} p95<={} p99<={} max<={} allmax={}",
                    stage.name(),
                    pps,
                    fmt_ns(avg_ns),
                    fmt_ns(p50),
                    fmt_ns(p95),
                    fmt_ns(p99),
                    fmt_ns(approx_max),
                    fmt_ns(lifetime_max),
                ));
            }
            for i in 0..N_EVENTS {
                let current = EVENTS[i].load(Relaxed);
                let delta = current.saturating_sub(prev_events[i]);
                prev_events[i] = current;
                if delta == 0 {
                    continue;
                }
                let event = event_from_index(i);
                let per_sec = delta / interval;
                line.push_str(&format!(" {}={}/s", event.name(), per_sec));
            }
            // eprintln so it always lands regardless of RUST_LOG.
            eprintln!("{}", line);
        }
    });
}

fn bucket_for_ns(ns: u64) -> usize {
    if ns <= 1 {
        return 0;
    }
    ((u64::BITS - (ns - 1).leading_zeros()) as usize).min(HIST_BUCKETS - 1)
}

fn bucket_upper_ns(bucket: usize) -> u64 {
    if bucket == 0 {
        1
    } else if bucket >= 63 {
        u64::MAX
    } else {
        1u64 << bucket
    }
}

fn percentile_ns(hist_delta: &[u64; HIST_BUCKETS], total: u64, pct: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    let target = total.saturating_mul(pct).saturating_add(99) / 100;
    let mut seen = 0u64;
    for (idx, count) in hist_delta.iter().enumerate() {
        seen = seen.saturating_add(*count);
        if seen >= target {
            return bucket_upper_ns(idx);
        }
    }
    bucket_upper_ns(HIST_BUCKETS - 1)
}

fn interval_max_ns(hist_delta: &[u64; HIST_BUCKETS]) -> u64 {
    for idx in (0..HIST_BUCKETS).rev() {
        if hist_delta[idx] != 0 {
            return bucket_upper_ns(idx);
        }
    }
    0
}

fn fmt_ns(ns: u64) -> String {
    if ns >= 1_000_000_000 {
        format!("{:.1}s", ns as f64 / 1_000_000_000.0)
    } else if ns >= 1_000_000 {
        format!("{:.1}ms", ns as f64 / 1_000_000.0)
    } else if ns >= 1_000 {
        format!("{:.1}us", ns as f64 / 1_000.0)
    } else {
        format!("{ns}ns")
    }
}
