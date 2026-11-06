//! Supervision of the crypto worker pools: what a pool that started short
//! means for the node, and the tick's sweep for workers that have since
//! exited.
//!
//! The pools are a performance offload, and Windows never starts them at
//! all, so losing workers is `Degraded` at most and never fatal. An outbound
//! packet for a missing encrypt worker is sealed on the main loop. Inbound
//! packets for a session already held by a missing decrypt worker are
//! dropped until the session rekeys or the link is re-established; a session
//! that would be registered on the missing worker after the loss is decrypted
//! on the main loop instead.
//! The pools report facts (how many workers, how many live); the decisions
//! below turn them into supervisor events.

use super::supervisor::{Child, Event};
#[cfg(unix)]
use crate::node::Node;
#[cfg(unix)]
use crate::node::worker_set::WorkerLiveness;
#[cfg(unix)]
use tracing::{info, warn};

/// What a freshly started pool means for the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::node) struct PoolStart {
    /// Keep the pool. A pool with no live worker is dropped, so every packet
    /// takes the main-loop path directly instead of being refused first.
    pub keep: bool,
    /// Report the pool's child as up. Anything short of every worker live is
    /// reported as failed to start, so start-completion health resolves to
    /// `Degraded` on the first publish rather than `Full` corrected a tick
    /// later.
    pub up: bool,
}

impl PoolStart {
    /// Every worker started. Off Unix the pools are never started, and their
    /// children report up as before.
    #[cfg(not(unix))]
    pub(in crate::node) const ALL_LIVE: Self = Self {
        keep: true,
        up: true,
    };

    /// The supervisor event that reports this outcome for `child`.
    pub(in crate::node) fn event(self, child: Child) -> Event {
        if self.up {
            Event::SubstrateUp { child }
        } else {
            Event::SubstrateFailed { child }
        }
    }
}

/// Classify a pool that started `live` of `configured` workers.
#[cfg(unix)]
pub(in crate::node) fn pool_start(live: usize, configured: usize) -> PoolStart {
    PoolStart {
        keep: live > 0,
        up: live >= configured,
    }
}

/// Whether a pool now at `live` workers has lost any since it last reported
/// `reported`. Every loss is reported, the first one and each after it, so the
/// count of live workers stays visible as it falls. Nothing restarts a worker,
/// so the count never rises.
#[cfg(unix)]
pub(in crate::node) fn lost_workers(reported: usize, live: usize) -> bool {
    live < reported
}

#[cfg(unix)]
impl Node {
    /// Start the encrypt pool and install it, or the main-loop path when no
    /// worker started. Under test, a pool staged in
    /// [`StagedPools`](super::supervisor::StagedPools) is installed instead of
    /// spawning one, so a pool that starts short can be driven through
    /// start-up.
    pub(in crate::node) fn start_encrypt_workers(&mut self, n: usize) -> PoolStart {
        #[cfg(test)]
        if let Some(pool) = self.supervisor.staged_pools.encrypt.take() {
            return self.install_encrypt_workers(pool);
        }
        // The workers report each send they give up on as unreachable; the
        // event loop takes the receiver and tells the links' path machines.
        let (report, reports) = tokio::sync::mpsc::channel(64);
        self.paths.reports = Some(reports);
        let pool = crate::node::encrypt_worker::EncryptWorkerPool::spawn_reporting(n, report);
        self.install_encrypt_workers(pool)
    }

    /// Install a started encrypt pool, or the main-loop path when none of
    /// its workers started.
    fn install_encrypt_workers(
        &mut self,
        pool: crate::node::encrypt_worker::EncryptWorkerPool,
    ) -> PoolStart {
        let start = report_pool_start("encrypt", pool.liveness());
        if start.up {
            info!(
                workers = pool.liveness().worker_count(),
                "Spawned FMP-encrypt worker pool"
            );
        }
        self.supervisor.encrypt_workers = start.keep.then_some(pool);
        start
    }

    /// Start the decrypt pool and install it, or the main-loop path when no
    /// worker started. Under test, a pool staged in
    /// [`StagedPools`](super::supervisor::StagedPools) is installed instead of
    /// spawning one, so a pool that starts short can be driven through
    /// start-up.
    pub(in crate::node) fn start_decrypt_workers(&mut self, n: usize) -> PoolStart {
        #[cfg(test)]
        if let Some(pool) = self.supervisor.staged_pools.decrypt.take() {
            return self.install_decrypt_workers(pool);
        }
        self.install_decrypt_workers(crate::node::decrypt_worker::DecryptWorkerPool::spawn(n))
    }

    /// Install a started decrypt pool, or the main-loop path when none of
    /// its workers started.
    fn install_decrypt_workers(
        &mut self,
        pool: crate::node::decrypt_worker::DecryptWorkerPool,
    ) -> PoolStart {
        let start = report_pool_start("decrypt", pool.liveness());
        if start.up {
            info!(
                workers = pool.liveness().worker_count(),
                "Spawned FMP-decrypt worker pool"
            );
        }
        self.supervisor.decrypt_workers = start.keep.then_some(pool);
        start
    }

    /// The tick's worker-liveness sweep. For each pool that has lost a worker
    /// since the last sweep, log the loss with the live count and report the
    /// pool's child as exited. The FSM republishes `Degraded` the first time;
    /// a pool already out of its up-set republishes nothing, but each further
    /// loss is still logged with the new count.
    ///
    /// Steps the FSM directly rather than through the child-exit channel: that
    /// channel is drained by the same loop that runs this sweep, so a send into
    /// a full channel from here would never complete.
    pub(in crate::node) fn poll_worker_liveness(&mut self) {
        let mut exited = Vec::with_capacity(2);
        if let Some(pool) = &self.supervisor.encrypt_workers
            && report_worker_loss("encrypt", pool.liveness())
        {
            exited.push(Child::EncryptWorkers);
        }
        if let Some(pool) = &self.supervisor.decrypt_workers
            && report_worker_loss("decrypt", pool.liveness())
        {
            exited.push(Child::DecryptWorkers);
        }
        for child in exited {
            self.step_child_exited(child);
        }
    }
}

/// Classify how a pool started, logging a pool that started short.
#[cfg(unix)]
fn report_pool_start(pool: &'static str, workers: &dyn WorkerLiveness) -> PoolStart {
    let live = workers.live_workers();
    let configured = workers.worker_count();
    let start = pool_start(live, configured);
    if !start.up {
        warn!(
            pool,
            live, configured, "Crypto worker pool started with fewer workers than configured"
        );
    }
    start
}

/// Record a pool's live count, logging and returning `true` when it has lost a
/// worker since the last call.
#[cfg(unix)]
fn report_worker_loss(pool: &'static str, workers: &dyn WorkerLiveness) -> bool {
    let live = workers.live_workers();
    let reported = workers.swap_reported_live(live);
    if !lost_workers(reported, live) {
        return false;
    }
    warn!(
        pool,
        live,
        configured = workers.worker_count(),
        dead = ?workers.dead_workers(),
        "Crypto worker thread exited"
    );
    true
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn worker_spawn_outcome_maps_k_of_n() {
        assert_eq!(
            pool_start(4, 4),
            PoolStart {
                keep: true,
                up: true
            }
        );
        for live in 1..4 {
            assert_eq!(
                pool_start(live, 4),
                PoolStart {
                    keep: true,
                    up: false
                },
                "{live} of 4 live"
            );
        }
        assert_eq!(
            pool_start(0, 4),
            PoolStart {
                keep: false,
                up: false
            }
        );
        let child = Child::EncryptWorkers;
        assert_eq!(pool_start(4, 4).event(child), Event::SubstrateUp { child });
        assert_eq!(
            pool_start(3, 4).event(child),
            Event::SubstrateFailed { child }
        );
    }

    #[test]
    fn every_loss_is_reported_and_no_loss_is_not() {
        assert!(lost_workers(4, 3));
        assert!(lost_workers(3, 0));
        assert!(!lost_workers(4, 4));
        assert!(!lost_workers(0, 0));
    }
}
