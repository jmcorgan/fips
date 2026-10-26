//! The queue of packets toward the host.
//!
//! Everything the adapter hands the host (a packet a peer delivered, an
//! ICMPv6 answer, a hairpinned packet) goes through one [`TunTx`], read by
//! the TUN writer thread or, for a TUN the embedder owns, by the embedder.
//! The queue is bounded, and a send never waits for room: a reader that has
//! stopped keeping up loses packets, as a router's full output queue does,
//! rather than holding the node back or growing without limit.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver, SendError, SyncSender, TrySendError};

use portable_atomic::AtomicU64;
use tracing::warn;

/// Sender of the packets toward the host, bounded at
/// `node.buffers.host_channel` packets.
///
/// [`TunTx::send`] never blocks. When the queue is full it drops the packet
/// and counts it; only a reader that has gone is an error. Clones share the
/// queue and the count.
#[derive(Clone)]
pub struct TunTx {
    /// Where the packets go.
    queue: Queue,
    /// Packets dropped on a full queue, shared by every clone.
    dropped: Arc<AtomicU64>,
}

/// The channel behind a [`TunTx`].
#[derive(Clone)]
enum Queue {
    /// The bounded channel every node uses.
    Bounded(SyncSender<Vec<u8>>),
    /// An unbounded channel a test installed in place of a TUN writer, so
    /// that tests written against the old channel read what the node hands
    /// the host unchanged.
    #[cfg(test)]
    Unbounded(mpsc::Sender<Vec<u8>>),
}

impl TunTx {
    /// A sender bounded at `capacity` packets, and the receiver the TUN
    /// writer or the embedder reads.
    pub fn bounded(capacity: usize) -> (Self, Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::sync_channel(capacity);
        (
            Self {
                queue: Queue::Bounded(tx),
                dropped: Arc::default(),
            },
            rx,
        )
    }

    /// Queue `packet` for the host, without waiting.
    ///
    /// A full queue drops the packet, counts it and returns `Ok`: the reader
    /// is still there, only behind. The error is for a reader that has gone,
    /// as from a channel's own send.
    pub fn send(&self, packet: Vec<u8>) -> Result<(), SendError<Vec<u8>>> {
        match &self.queue {
            Queue::Bounded(tx) => match tx.try_send(packet) {
                Ok(()) => Ok(()),
                Err(TrySendError::Full(_)) => {
                    let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                    // Logged at the first drop and at each doubling, so a
                    // stall shows in the log without a line per packet.
                    if dropped.is_power_of_two() {
                        warn!(dropped, "Host not reading; dropping packets toward it");
                    }
                    Ok(())
                }
                Err(TrySendError::Disconnected(packet)) => Err(SendError(packet)),
            },
            #[cfg(test)]
            Queue::Unbounded(tx) => tx.send(packet),
        }
    }

    /// Packets dropped so far because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// The shared drop count, for the adapter's status to read when asked.
    pub(crate) fn counter(&self) -> Arc<AtomicU64> {
        self.dropped.clone()
    }
}

impl fmt::Debug for TunTx {
    /// Shows the drop count; the channel itself has nothing to show.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunTx")
            .field("dropped", &self.dropped())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl From<mpsc::Sender<Vec<u8>>> for TunTx {
    /// An unbounded sender standing in for the TUN writer's, for tests.
    fn from(tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            queue: Queue::Unbounded(tx),
            dropped: Arc::default(),
        }
    }
}

#[cfg(test)]
#[path = "tests/queue.rs"]
mod tests;
