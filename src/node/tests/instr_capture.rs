//! The rx loop's tick with a profiling capture armed.
//!
//! The armed branch of `instr_step!` runs only while a capture is armed, so no
//! other test reaches it. This one arms a capture, drives a real node's rx loop
//! for several ticks, stops through `instr::shutdown` (the teardown path), and
//! reads the capture file back. Every step the tick arm runs unconditionally
//! records once per tick, so each one's count must match the whole-tick count.
//! Evaluating a step's body twice when armed, or skipping it when armed, breaks
//! that equality: under double evaluation the whole-tick body runs twice per
//! whole-tick record, so every nested step records twice; under the skip the
//! nested steps record nothing.
//!
//! Built only with the `profiling` feature.

use super::*;
use crate::instr::Step;
use std::collections::HashMap;

/// The steps the tick arm in `node::dataplane::rx_loop` runs on every tick,
/// whatever the node's state. Two are compiled only on some targets or build
/// profiles, with the same `cfg` as their call sites; at run time none of
/// these is conditional.
fn unconditional_steps() -> Vec<Step> {
    let mut steps = vec![
        Step::CheckTimeouts,
        Step::ReloadPeerAcl,
        Step::ReloadHostMap,
        Step::PollPendingConnects,
        Step::PollNostrRendezvous,
        Step::PollLanRendezvous,
        Step::DrivePeerTimers,
        Step::ResendPendingRekeys,
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
        Step::PollProbes,
        Step::PollTransportDiscovery,
        Step::SampleTransportCongestion,
    ];
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    steps.push(Step::ActivateConnectedUdpSessions);
    #[cfg(debug_assertions)]
    steps.push(Step::DebugAssertPeerMapsCoherent);
    steps
}

/// Ticks this node is driven through. Enough that a doubled count is far
/// outside [`SLACK`].
const TICKS: u64 = 6;

/// How far a step's count may run ahead of the whole-tick count.
///
/// The capture gate is process-wide, and `cargo test` runs tests as threads in
/// one process, so another test's node may tick into this capture. Its whole
/// ticks add one to every count alike. A tick of its that is part-way through
/// its body when the capture stops has recorded some nested steps but not yet
/// its whole-tick span, which puts those steps one ahead each. Two covers two
/// such ticks in flight at the stop; a doubled count runs ahead by at least
/// [`TICKS`].
const SLACK: u64 = 2;

/// Sum the duration rows' counts per step name in the tick domain.
///
/// Rows are tab-separated under the header
/// `ts_unix kind domain name count max total unit`; every drain writes one row
/// per step, so the counts across drains add up.
fn step_counts(text: &str) -> HashMap<String, u64> {
    let mut counts = HashMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() == 8 && fields[1] == "step" && fields[2] == "tick" {
            let count: u64 = fields[4].parse().expect("a numeric count");
            *counts.entry(fields[3].to_string()).or_default() += count;
        }
    }
    counts
}

/// Synchronous so the shared instrumentation lock, a `std::sync::MutexGuard`,
/// is never held across an `.await` in an async fn. The test builds its own
/// current-thread runtime on a paused clock, which auto-advances to the next
/// tick whenever the loop is idle, so the ticks cost no wall-clock time.
#[test]
fn the_rx_tick_with_a_capture_armed_records_each_unconditional_step_once_per_tick() {
    let _guard = crate::instr::test_serial();
    let dir = tempfile::tempdir().expect("tempdir");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("a runtime");

    let path = runtime.block_on(async {
        let mut config = Config::new();
        config.transports.udp =
            crate::config::TransportInstances::Single(crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            });
        config.dns.enabled = false;
        config.node.control.enabled = false;
        config.node.tick_interval_secs = 1;
        let mut node = make_node_with(config);
        node.start().await.unwrap();

        let started =
            crate::instr::capture::start_in(dir.path(), "npub1test", 1).expect("arm a capture");
        let path = std::path::PathBuf::from(started["path"].as_str().unwrap());

        // The interval fires at once and then every second, so this window
        // holds TICKS ticks; the bound ends the loop before the next one.
        let window = Duration::from_millis((TICKS - 1) * 1000 + 500);
        let drive = tokio::time::timeout(
            window,
            node.run_rx_loop_with_shutdown(std::future::pending()),
        )
        .await;
        assert!(
            drive.is_err(),
            "the rx loop must still be running: {drive:?}"
        );

        crate::instr::shutdown();
        node.stop().await.unwrap();
        path
    });

    let text = std::fs::read_to_string(&path).expect("read the capture");
    let counts = step_counts(&text);
    let whole = counts
        .get(Step::WholeTick.name())
        .copied()
        .unwrap_or_else(|| panic!("no whole_tick row in the capture:\n{text}"));
    assert!(
        whole >= TICKS,
        "the capture holds {whole} ticks, not the {TICKS} driven:\n{text}"
    );

    let mut wrong = Vec::new();
    for step in unconditional_steps() {
        let count = counts.get(step.name()).copied().unwrap_or(0);
        if count < whole || count > whole + SLACK {
            wrong.push(format!("{}: {count}", step.name()));
        }
    }
    assert!(
        wrong.is_empty(),
        "steps not recorded once per tick ({whole} ticks): {wrong:?}"
    );
}
