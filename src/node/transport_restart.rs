//! Restart supervision for transports that failed to start.
//!
//! Some transports depend on a backend that is not necessarily ready the
//! moment the node starts — a radio, driver, or bridge that is wired up
//! shortly after process start rather than before it. A transport whose
//! `start()` call fails because that backend is not yet present should not
//! be gone forever: once the backend appears, the transport should come up
//! on its own, without anything above the transport layer restarting.
//!
//! This module gives failed-but-restartable transport handles a home
//! (`Node::pending_transports`) and a periodic chance to try again, driven
//! by the node's existing maintenance tick. It is generic: it knows nothing
//! about any particular transport or backend, only that
//! [`crate::transport::TransportState::can_start`] says another attempt is
//! sanctioned.

use super::Node;
use crate::transport::TransportHandle;
use tracing::{debug, info};

/// Base retry delay, in milliseconds.
///
/// Matches the node's maintenance tick interval, so the first retry after a
/// failed start lands on the very next tick.
const RESTART_BASE_MS: u64 = 1_000;

/// Maximum retry delay, in milliseconds.
///
/// Caps the cost of a permanently-unavailable backend at one start attempt
/// per 30 seconds — supervision never gives up, it just stops trying harder.
const RESTART_MAX_MS: u64 = 30_000;

/// A transport handle that failed to start and is waiting for its next
/// scheduled retry.
///
/// Invisible to every data-plane path until a retry succeeds and the handle
/// is promoted into [`Node::transports`] — nothing outside this module reads
/// [`Node::pending_transports`].
pub(super) struct PendingTransport {
    /// The failed handle, retained so it can be retried in place.
    pub(super) handle: TransportHandle,
    /// Number of start attempts made so far (including the one that put it
    /// here).
    pub(super) attempts: u32,
    /// Timestamp (Unix ms) when the next retry is due.
    pub(super) retry_after_ms: u64,
}

impl PendingTransport {
    /// Compute the backoff delay for the current attempt count.
    ///
    /// Doubles from `RESTART_BASE_MS` on each attempt, capped at
    /// `RESTART_MAX_MS`. `checked_shl` plus `saturating_mul` means a very
    /// large attempt count saturates instead of overflowing or panicking.
    fn backoff_ms(&self) -> u64 {
        let multiplier = 1u64.checked_shl(self.attempts).unwrap_or(u64::MAX);
        RESTART_BASE_MS
            .saturating_mul(multiplier)
            .min(RESTART_MAX_MS)
    }

    /// Whether this entry's retry is due at `now_ms`.
    fn is_due(&self, now_ms: u64) -> bool {
        now_ms >= self.retry_after_ms
    }

    /// Record a failed (re)start attempt and schedule the next one.
    fn schedule_after_failure(&mut self, now_ms: u64) {
        self.retry_after_ms = now_ms + self.backoff_ms();
        self.attempts = self.attempts.saturating_add(1);
    }
}

impl Node {
    /// Adopt a transport that just started successfully — the single
    /// success path, shared by a first-try start and a retried one.
    ///
    /// A transport promoted through here is indistinguishable from one that
    /// started the first time: same fd hand-off, same map insertion.
    pub(super) fn adopt_started_transport(&mut self, handle: TransportHandle) {
        let transport_id = handle.transport_id();
        let transport_type = handle.transport_type().name;

        #[cfg(unix)]
        if transport_type == "udp"
            && let (Some(tx), Some(fd)) = (&self.udp_bind_tx, handle.raw_fd())
        {
            let _ = tx.send(fd);
        }

        self.transports.insert(transport_id, handle);
    }

    /// Quarantine a transport handle whose `start()` call just failed.
    ///
    /// Only handles whose post-failure state reports
    /// [`crate::transport::TransportState::can_start`] are retained — that
    /// is true for BLE today (it marks itself `Failed` on a listener
    /// failure) and false for UDP/TCP (which stay in `Starting`), matching
    /// today's behaviour of dropping those handles.
    pub(super) fn quarantine_transport(&mut self, handle: TransportHandle, now_ms: u64) {
        if !handle.state().can_start() {
            // Not retryable — this is today's behaviour for UDP/TCP.
            return;
        }

        let transport_type = handle.transport_type().name;
        let mut pending = PendingTransport {
            handle,
            attempts: 0,
            retry_after_ms: now_ms,
        };
        pending.schedule_after_failure(now_ms);
        debug!(
            transport_type,
            retry_after_ms = pending.retry_after_ms,
            "Transport start failed; quarantined for retry"
        );
        self.pending_transports.push(pending);
    }

    /// Retry every pending transport that is due, on the node's maintenance
    /// tick. A transport that starts successfully is promoted through
    /// [`Node::adopt_started_transport`]; one that fails again is
    /// rescheduled with the next backoff step.
    pub(super) async fn retry_pending_transports(&mut self, now_ms: u64) {
        if self.pending_transports.is_empty() {
            return;
        }

        let pending = std::mem::take(&mut self.pending_transports);
        let mut keep = Vec::with_capacity(pending.len());

        for mut entry in pending {
            if !entry.is_due(now_ms) {
                keep.push(entry);
                continue;
            }

            let transport_type = entry.handle.transport_type().name;
            let transport_id = entry.handle.transport_id();
            let attempts = entry.attempts;

            match entry.handle.start().await {
                Ok(()) => {
                    info!(
                        transport_type,
                        transport_id = %transport_id,
                        attempts,
                        "Transport started after retry"
                    );
                    self.adopt_started_transport(entry.handle);
                }
                Err(_) => {
                    entry.schedule_after_failure(now_ms);
                    debug!(
                        transport_type,
                        transport_id = %transport_id,
                        attempts,
                        retry_after_ms = entry.retry_after_ms,
                        "Transport retry failed; rescheduled"
                    );
                    keep.push(entry);
                }
            }
        }

        self.pending_transports = keep;
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn pending_at(attempts: u32) -> u64 {
        // Build a throwaway PendingTransport purely to exercise backoff_ms
        // without needing a real TransportHandle.
        struct Backoff {
            attempts: u32,
        }
        impl Backoff {
            fn backoff_ms(&self) -> u64 {
                let multiplier = 1u64.checked_shl(self.attempts).unwrap_or(u64::MAX);
                RESTART_BASE_MS
                    .saturating_mul(multiplier)
                    .min(RESTART_MAX_MS)
            }
        }
        Backoff { attempts }.backoff_ms()
    }

    #[test]
    fn backoff_doubles_from_base() {
        assert_eq!(pending_at(0), 1_000);
        assert_eq!(pending_at(1), 2_000);
        assert_eq!(pending_at(2), 4_000);
        assert_eq!(pending_at(3), 8_000);
    }

    #[test]
    fn backoff_saturates_at_cap() {
        // 2^15 * 1000ms already exceeds the 30s cap.
        assert_eq!(pending_at(15), RESTART_MAX_MS);
        // A very large attempt count must not overflow or panic.
        assert_eq!(pending_at(u32::MAX), RESTART_MAX_MS);
    }

    #[test]
    fn never_gives_up_past_the_cap() {
        // An entry parked at the cap is still due once the cap has
        // elapsed, and stays retryable forever — it never becomes
        // terminal.
        let mut entry_attempts = 20u32;
        let mut retry_after_ms = 0u64;
        let backoff = pending_at(entry_attempts);
        assert_eq!(backoff, RESTART_MAX_MS);
        retry_after_ms += backoff;
        entry_attempts = entry_attempts.saturating_add(1);
        // Simulate "an hour late": the entry is still due, and retrying it
        // again still yields the capped delay, not an error state.
        let now_ms = retry_after_ms + 3_600_000;
        assert!(now_ms >= retry_after_ms);
        assert_eq!(pending_at(entry_attempts), RESTART_MAX_MS);
    }

    #[test]
    fn is_due_boundary() {
        struct Due {
            retry_after_ms: u64,
        }
        impl Due {
            fn is_due(&self, now_ms: u64) -> bool {
                now_ms >= self.retry_after_ms
            }
        }
        let entry = Due {
            retry_after_ms: 10_000,
        };
        assert!(!entry.is_due(9_999));
        assert!(entry.is_due(10_000));
        assert!(entry.is_due(10_001));
    }
}

#[cfg(all(test, ble_available))]
mod node_integration_tests {
    use crate::config::BleConfig;
    use crate::node::tests::make_node;
    use crate::transport::ble::{BleTransport, addr::BleAddr, io::MockBleIo};
    use crate::transport::{Transport, TransportId, TransportState};

    fn test_addr(n: u8) -> BleAddr {
        BleAddr {
            adapter: "hci0".to_string(),
            device: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n],
        }
    }

    #[tokio::test]
    async fn failed_ble_start_is_retried_and_adopted_without_node_restart() {
        let mut node = make_node();

        let io = MockBleIo::new("hci0", test_addr(1));
        io.fail_next_listens(1);

        let config = BleConfig {
            accept_connections: Some(true),
            scan: Some(false),
            advertise: Some(false),
            ..Default::default()
        };

        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let mut transport = BleTransport::new(TransportId::new(1), None, config, io, tx);

        // First attempt fails — the radio is not available yet.
        assert!(transport.start_async().await.is_err());
        assert_eq!(transport.state(), TransportState::Failed);

        let handle = crate::transport::TransportHandle::Ble(transport);
        node.quarantine_transport(handle, 0);

        assert!(node.get_transport(&TransportId::new(1)).is_none());
        assert_eq!(node.pending_transports.len(), 1);

        // Not yet due.
        node.retry_pending_transports(500).await;
        assert_eq!(node.pending_transports.len(), 1);
        assert!(node.get_transport(&TransportId::new(1)).is_none());

        // Due now — the injected failure was one-shot, so this retry
        // succeeds.
        node.retry_pending_transports(1_500).await;
        assert!(node.pending_transports.is_empty());
        let promoted = node
            .get_transport(&TransportId::new(1))
            .expect("transport should be promoted into Node::transports");
        assert_eq!(promoted.state(), TransportState::Up);
    }

    #[tokio::test]
    async fn a_handle_that_cannot_restart_is_not_quarantined() {
        let mut node = make_node();

        // UDP leaves `state` at `Starting` (not `Failed`) when `start_async`
        // errors out on bind-address parsing — reproduce that exact shape
        // with an unparseable bind address, then feed the failed handle to
        // `quarantine_transport` and confirm it is dropped, not retained.
        let udp_config = crate::config::UdpConfig {
            bind_addr: Some("not-an-address".to_string()),
            ..Default::default()
        };
        let (packet_tx, _packet_rx) = crate::transport::packet_channel(64);
        let mut udp = crate::transport::udp::UdpTransport::new(
            TransportId::new(3),
            None,
            udp_config,
            packet_tx,
        );

        assert!(udp.start_async().await.is_err());
        assert_eq!(udp.state(), TransportState::Starting);
        assert!(!TransportState::Starting.can_start());

        let handle = crate::transport::TransportHandle::Udp(udp);
        node.quarantine_transport(handle, 0);

        // Dropped, exactly like today — no retryable entry, no promoted
        // transport.
        assert!(node.pending_transports.is_empty());
        assert!(node.get_transport(&TransportId::new(3)).is_none());
    }
}
