//! USB transport statistics.

use portable_atomic::{AtomicU64, Ordering};
use serde::Serialize;

/// Counters for one USB transport instance, updated from its own tasks.
#[derive(Default)]
pub struct UsbStats {
    pub packets_sent: AtomicU64,
    pub bytes_sent: AtomicU64,
    /// Writes put on the link. Fewer than `packets_sent` when the writer
    /// coalesced several packets into one transfer.
    pub transfers_sent: AtomicU64,
    pub packets_recv: AtomicU64,
    pub bytes_recv: AtomicU64,
    pub send_errors: AtomicU64,
    pub recv_errors: AtomicU64,
    pub mtu_exceeded: AtomicU64,
    /// Links handed to the transport by a backend or the embedder.
    pub links_attached: AtomicU64,
    /// Links that completed the hello and joined the pool.
    pub links_established: AtomicU64,
    /// Links dropped because the hello failed: timeout, bad magic or
    /// version, an invalid key, or our own key echoed back.
    pub hello_failures: AtomicU64,
    /// Links that displaced an older link to the same peer.
    pub links_replaced: AtomicU64,
}

impl UsbStats {
    /// Create a new stats instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn record_send(&self, packets: u64, bytes: usize) {
        self.packets_sent.fetch_add(packets, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
        self.transfers_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_recv(&self, bytes: usize) {
        self.packets_recv.fetch_add(1, Ordering::Relaxed);
        self.bytes_recv.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(crate) fn record_send_error(&self) {
        self.send_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_recv_error(&self) {
        self.recv_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_mtu_exceeded(&self) {
        self.mtu_exceeded.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_link_attached(&self) {
        self.links_attached.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_link_established(&self) {
        self.links_established.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_hello_failure(&self) {
        self.hello_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_link_replaced(&self) {
        self.links_replaced.fetch_add(1, Ordering::Relaxed);
    }

    /// Read every counter now.
    pub fn snapshot(&self) -> UsbStatsSnapshot {
        UsbStatsSnapshot {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            transfers_sent: self.transfers_sent.load(Ordering::Relaxed),
            packets_recv: self.packets_recv.load(Ordering::Relaxed),
            bytes_recv: self.bytes_recv.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
            recv_errors: self.recv_errors.load(Ordering::Relaxed),
            mtu_exceeded: self.mtu_exceeded.load(Ordering::Relaxed),
            links_attached: self.links_attached.load(Ordering::Relaxed),
            links_established: self.links_established.load(Ordering::Relaxed),
            hello_failures: self.hello_failures.load(Ordering::Relaxed),
            links_replaced: self.links_replaced.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time copy of [`UsbStats`], as `show_transports` reports it.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct UsbStatsSnapshot {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub transfers_sent: u64,
    pub packets_recv: u64,
    pub bytes_recv: u64,
    pub send_errors: u64,
    pub recv_errors: u64,
    pub mtu_exceeded: u64,
    pub links_attached: u64,
    pub links_established: u64,
    pub hello_failures: u64,
    pub links_replaced: u64,
}
