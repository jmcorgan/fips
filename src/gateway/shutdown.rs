//! Stopping the gateway's tasks.
//!
//! The gateway binary runs a resolver, a pool tick and a control socket as
//! tasks, all feeding pool events into one bounded channel that the main
//! loop drains. When the main loop ends, [`stop_tasks`] stops those tasks in
//! the order that lets each of them end, and gives up on any that does not
//! end in time, so the route, proxy NDP and NAT cleanup that follows it is
//! always reached.

use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::task::{JoinError, JoinHandle};
use tokio::time::Instant;
use tracing::warn;

use super::pool::PoolEvent;

/// Capacity of the pool-event channel from the resolver and the tick to the
/// main loop.
pub const EVENT_CAPACITY: usize = 64;

/// How long the gateway waits for the resolver and the tick, together, to
/// end after shutdown is signalled.
///
/// One deadline covers both. It sits well inside the OpenWrt init script's
/// kill 3 s after SIGTERM and systemd's `TimeoutStopSec=15`, leaving time for
/// the final state write and the network and NAT cleanup. A normal stop takes
/// milliseconds; a resolver waiting on a silent upstream would otherwise
/// hold the stop for the full upstream timeout.
///
/// The bound only covers a task that is waiting on something asynchronous
/// (a socket, a channel, a lock). On the gateway's current-thread runtime a
/// task stuck in synchronous code holds the thread, and the timer that
/// enforces the bound cannot fire until it lets go.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(1);

/// How one task ended, as [`stop_tasks`] saw it.
#[derive(Debug)]
pub enum TaskEnd<T> {
    /// The task returned this value.
    Finished(T),
    /// The task panicked, or was cancelled by someone else.
    Failed(JoinError),
    /// The task had not ended by the deadline and was aborted. Work it had
    /// handed to a blocking thread may still be running.
    Abandoned,
}

/// How each task ended, as [`stop_tasks`] saw it.
#[derive(Debug)]
pub struct Stopped<D, T> {
    /// How the resolver ended, or `None` when no resolver task was running
    /// (it had already ended and been awaited by the main loop).
    pub resolver: Option<TaskEnd<D>>,
    /// How the tick ended.
    pub tick: TaskEnd<T>,
}

/// Stop the gateway's tasks once the main loop has stopped receiving events.
///
/// Closes the event channel (`events`), signals shutdown on `signal`, aborts
/// and waits for the control socket task, then waits for the resolver and
/// the tick until one deadline `timeout` after the signal, aborting either
/// one still running then. Returns how those two ended.
pub async fn stop_tasks<D, T>(
    events: mpsc::Receiver<PoolEvent>,
    signal: &watch::Sender<bool>,
    control: Option<JoinHandle<()>>,
    resolver: Option<JoinHandle<D>>,
    tick: JoinHandle<T>,
    timeout: Duration,
) -> Stopped<D, T> {
    // Close the event channel first. Nothing receives from it any more, and
    // a resolver or tick blocked sending into a full channel cannot see the
    // shutdown signal; closing it makes that send fail at once.
    drop(events);

    // Signal all tasks to stop
    let _ = signal.send(true);
    let deadline = Instant::now() + timeout;

    // Wait for tasks (control task is cancelled by dropping the listener)
    if let Some(task) = control {
        task.abort();
        let _ = task.await;
    }
    let resolver = match resolver {
        Some(task) => Some(wait_until("resolver", task, deadline, timeout).await),
        None => None,
    };
    let tick = wait_until("tick", tick, deadline, timeout).await;
    Stopped { resolver, tick }
}

/// Wait for `task` until `deadline`; past it, abort the task and wait for
/// the abort to land, so the task's future, and any lock guard it holds, is
/// dropped before the caller goes on.
async fn wait_until<T>(
    name: &'static str,
    mut task: JoinHandle<T>,
    deadline: Instant,
    timeout: Duration,
) -> TaskEnd<T> {
    if let Ok(joined) = tokio::time::timeout_at(deadline, &mut task).await {
        return match joined {
            Ok(value) => TaskEnd::Finished(value),
            Err(e) => TaskEnd::Failed(e),
        };
    }
    warn!(
        task = name,
        timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
        "Gateway task did not stop in time; abandoning it"
    );
    task.abort();
    match task.await {
        // It ended between the deadline and the abort.
        Ok(value) => TaskEnd::Finished(value),
        Err(e) if e.is_cancelled() => TaskEnd::Abandoned,
        Err(e) => TaskEnd::Failed(e),
    }
}

#[cfg(test)]
#[path = "tests/shutdown.rs"]
mod tests;
