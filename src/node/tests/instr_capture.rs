//! The rx loop's tick with a profiling capture armed.
//!
//! The armed branch of `instr_step!` runs only while a capture is armed, so no
//! other test reaches it. This one arms a capture, drives a real node's rx loop
//! until it has run a counted number of ticks, stops through `instr::shutdown`
//! (the teardown path), and reads the capture file back. Every step the tick
//! arm runs unconditionally records once per tick, so each one's count must
//! equal the whole-tick count. Evaluating a step's body twice when armed, or
//! skipping it when armed, breaks that equality: under double evaluation the
//! whole-tick body runs twice per whole-tick record, so every nested step
//! records twice; under the skip the nested steps record nothing. A single
//! step run twice, or skipped, in any one tick breaks it too.
//!
//! The drive runs in a child process of its own. The capture is process-wide
//! and every node's teardown calls `instr::shutdown`, so under `cargo test`,
//! which runs tests as threads in one process, any other test stopping a node
//! while this one drives would stop this capture early and leave it short of
//! the ticks driven, and any other test's node ticking meanwhile would add its
//! own steps to the counts. In the child this node is the only one, and its
//! last tick ends before the capture stops, so the counts are exact.
//!
//! Built only with the `profiling` feature.

use super::*;
use crate::instr::Step;
use std::cell::Cell;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::thread::JoinHandle;

/// Environment variable naming the test a re-run test binary is to drive.
const CHILD: &str = "FIPS_TEST_INSTR_CAPTURE_CHILD";

/// This test's path, for re-running the test binary on it alone.
const TEST: &str = "node::tests::instr_capture::the_rx_tick_with_a_capture_armed_records_each_unconditional_step_once_per_tick";

/// Real time the child may take before the test fails. The ticks run on a
/// paused clock and cost no real time, so a healthy child, loaded or not,
/// finishes far inside this; reaching it means the loop is wedged.
const BOUND: Duration = Duration::from_secs(60);

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

/// Ticks this node is driven through: several, so the loop crosses more than
/// one tick deadline and a step that misbehaves on only some ticks still shows.
const TICKS: u64 = 6;

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

/// Drive a fresh node through at least [`TICKS`] ticks with a capture armed
/// in `dir`, and return the capture's text.
///
/// Builds its own current-thread runtime on a paused clock, which advances to
/// the next timer whenever the loop is idle, so the ticks cost no real time.
fn capture_ticks(dir: &Path) -> String {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("a runtime");

    runtime.block_on(async {
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

        let started = crate::instr::capture::start_in(dir, "npub1test", 1).expect("arm a capture");
        let path = std::path::PathBuf::from(started["path"].as_str().unwrap());

        // The tick arm sits before the shutdown arm in the loop's biased
        // select, so this future is polled only when no tick is due: its first
        // poll follows tick 0, and when it resolves every tick due by then has
        // run, which is at least TICKS. The interval bursts any tick the
        // paused clock moved past before this arm is polled again, so the
        // count does not depend on how far the clock moves between polls.
        let signalled = Cell::new(false);
        let after_ticks = async {
            let first = tokio::time::Instant::now();
            tokio::time::sleep_until(first + Duration::from_secs(TICKS - 1)).await;
            signalled.set(true);
        };
        node.run_rx_loop_with_shutdown(after_ticks)
            .await
            .expect("the rx loop returns cleanly");
        assert!(
            signalled.get(),
            "the rx loop ended before the shutdown signal"
        );

        let state = crate::instr::capture::status()["state"].clone();
        assert_eq!(
            state, "running",
            "the capture stopped before the drive ended"
        );
        crate::instr::shutdown();
        node.finish_shutdown().await;
        std::fs::read_to_string(&path).expect("read the capture")
    })
}

/// Read a child's pipe to its end on a thread of its own, so a child writing
/// more than the pipe holds never blocks waiting for the parent.
fn drain(mut pipe: impl Read + Send + 'static) -> JoinHandle<String> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = pipe.read_to_end(&mut bytes);
        String::from_utf8_lossy(&bytes).into_owned()
    })
}

/// Re-run this test binary on this test alone, as the child, and require it
/// to pass within [`BOUND`].
fn run_in_child() {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST, "--nocapture", "--test-threads", "1"])
        .env(CHILD, TEST)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("re-run the test binary");
    let stdout = drain(child.stdout.take().unwrap());
    let stderr = drain(child.stderr.take().unwrap());
    let deadline = std::time::Instant::now() + BOUND;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            let (stdout, stderr) = (stdout.join().unwrap(), stderr.join().unwrap());
            panic!(
                "the child did not drive {TICKS} ticks within {BOUND:?} of real time:\n{stdout}\n{stderr}"
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let (stdout, stderr) = (stdout.join().unwrap(), stderr.join().unwrap());
    assert!(
        status.success(),
        "the test failed in the child ({status}):\n{stdout}\n{stderr}"
    );
    // libtest exits 0 when the filter selects nothing, so require that the
    // child actually ran the test.
    assert!(
        stdout.contains("1 passed"),
        "the child did not run the test:\n{stdout}\n{stderr}"
    );
}

/// Synchronous so the shared instrumentation lock, a `std::sync::MutexGuard`,
/// is never held across an `.await` in an async fn.
#[test]
fn the_rx_tick_with_a_capture_armed_records_each_unconditional_step_once_per_tick() {
    if std::env::var(CHILD).as_deref() != Ok(TEST) {
        run_in_child();
        return;
    }

    let _guard = crate::instr::test_serial();
    let dir = tempfile::tempdir().expect("tempdir");
    let text = capture_ticks(dir.path());

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
        if count != whole {
            wrong.push(format!("{}: {count}", step.name()));
        }
    }
    assert!(
        wrong.is_empty(),
        "steps not recorded once per tick ({whole} ticks): {wrong:?}"
    );
}
