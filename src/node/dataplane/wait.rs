//! How long a spawned task waits for the runtime thread.
//!
//! The daemon runs on one thread, so a socket's reader, a spawned task, runs
//! only when the receive loop and everything else on that thread let it. The
//! task here sleeps a short interval in a loop and writes the largest
//! overshoot of each second, so a run's log shows a held thread with no
//! special build. It sleeps through the runtime's timer as a reader waits on
//! the runtime's I/O driver, so it reads what a reader waits.
//!
//! The figure alone cannot tell a held thread from a stalled host. A stalled
//! host shows on every node at once.

use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep};
use tracing::debug;

/// The sleep whose overshoot is the wait.
const TICK: Duration = Duration::from_millis(10);

/// How often a line can be written.
const WINDOW: Duration = Duration::from_secs(1);

/// The smallest wait that writes a line. Below it the figure is the timer's
/// own resolution and the scheduler's noise.
const FLOOR: Duration = Duration::from_millis(5);

/// The running watch. Dropping it ends the task.
pub(in crate::node) struct TaskWait(JoinHandle<()>);

impl Drop for TaskWait {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
impl TaskWait {
    /// A handle that outlives the watch, to see the task end.
    pub(in crate::node) fn ended(&self) -> tokio::task::AbortHandle {
        self.0.abort_handle()
    }
}

/// Start the watch if its line would be written, so a run without it has no
/// extra task or timer.
pub(in crate::node) fn watch() -> Option<TaskWait> {
    tracing::enabled!(tracing::Level::DEBUG).then(|| TaskWait(tokio::spawn(run())))
}

/// Sleep in a loop, writing each window's largest overshoot at or over the
/// floor.
async fn run() {
    let mut worst = Duration::ZERO;
    let mut since = Instant::now();
    loop {
        let before = Instant::now();
        sleep(TICK).await;
        let now = Instant::now();
        worst = worst.max((now - before).saturating_sub(TICK));
        if now - since >= WINDOW {
            if worst >= FLOOR {
                debug!(worst_ms = worst.as_millis() as u64, "Task wait");
            }
            worst = Duration::ZERO;
            since = now;
        }
    }
}
