//! The line that shows a spawned task waiting for the runtime thread.
//!
//! Each test runs on a `current_thread` runtime, the daemon's shape, and holds
//! that thread with a blocking sleep, which is what a held thread is to a
//! spawned task.

use super::*;
use crate::node::dataplane::wait::watch;
use crate::testutil::{LogCapture, capture_logs_scoped, log_field, wait_until};
use crate::transport::packet_channel;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;

/// How long a test holds the thread, and the least the line must then read:
/// the hold, less the task's own sleep and the timer's slack.
const HOLD: Duration = Duration::from_millis(300);
const LEAST_MS: u64 = 250;

/// How long a line can take: it is written once a second.
const LINE_LIMIT: Duration = Duration::from_secs(5);

/// The largest wait the captured lines report.
fn worst_ms(logs: &LogCapture) -> u64 {
    logs.lines_with("Task wait")
        .iter()
        .filter_map(|line| log_field(line, "worst_ms")?.parse().ok())
        .max()
        .unwrap_or(0)
}

#[tokio::test(flavor = "current_thread")]
async fn a_thread_held_for_300_ms_shows_as_a_task_wait_of_at_least_250_ms() {
    let (logs, _guard) = capture_logs_scoped();
    let _watch = watch().expect("precondition: the capture takes debug lines");
    tokio::time::sleep(Duration::from_millis(30)).await;
    std::thread::sleep(HOLD);
    let seen = wait_until(|| worst_ms(&logs) >= LEAST_MS, LINE_LIMIT).await;
    assert!(
        seen,
        "the thread was held {HOLD:?} and the worst line reads {} ms: {:?}",
        worst_ms(&logs),
        logs.lines_with("Task wait")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn no_task_runs_when_the_wait_line_would_not_be_written() {
    let quiet = tracing_subscriber::registry().with(LevelFilter::INFO);
    let _guard = tracing::subscriber::set_default(quiet);
    assert!(watch().is_none(), "a watch started with debug off");
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_the_watch_ends_its_task() {
    let (_logs, _guard) = capture_logs_scoped();
    let running = watch().expect("precondition: the capture takes debug lines");
    let task = running.ended();
    tokio::task::yield_now().await;
    assert!(!task.is_finished(), "precondition: the watch is running");
    drop(running);
    let ended = wait_until(|| task.is_finished(), LINE_LIMIT).await;
    assert!(ended, "the task outlived its watch");
}

/// The daemon's own loop starts the watch.
#[tokio::test(flavor = "current_thread")]
async fn the_receive_loop_starts_the_watch() {
    let (logs, _guard) = capture_logs_scoped();
    let mut node = make_node();
    let (_packet_tx, packet_rx) = packet_channel(8);
    node.packet_rx = Some(packet_rx);
    let holds = async {
        tokio::time::sleep(Duration::from_millis(30)).await;
        std::thread::sleep(HOLD);
        wait_until(|| worst_ms(&logs) >= LEAST_MS, LINE_LIMIT).await
    };
    let seen = tokio::select! {
        biased;
        seen = holds => seen,
        result = node.run_rx_loop_with_shutdown(std::future::pending()) => {
            panic!("precondition: the receive loop ran on: {result:?}")
        }
    };
    assert!(seen, "the loop ran with no task wait line");
}
