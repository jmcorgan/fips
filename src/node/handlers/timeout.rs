//! Timeout management for stale handshake connections and idle sessions.

use crate::node::Node;
use crate::transport::LinkId;
use tracing::{debug, info};

impl Node {
    /// Check for timed-out handshake connections and clean them up.
    ///
    /// Called periodically by the RX event loop. Removes connections that have
    /// been idle longer than the configured handshake timeout or are in Failed state.
    pub(in crate::node) fn check_timeouts(&mut self) {
        if self.connections.is_empty() {
            return;
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let timeout_ms = self.config.node.rate_limit.handshake_timeout_secs * 1000;

        let stale: Vec<LinkId> = self.connections.iter()
            .filter(|(_, conn)| conn.is_timed_out(now_ms, timeout_ms) || conn.is_failed())
            .map(|(link_id, _)| *link_id)
            .collect();

        for link_id in stale {
            // Log and schedule retry before cleanup (need connection state)
            if let Some(conn) = self.connections.get(&link_id) {
                let direction = conn.direction();
                let idle_ms = conn.idle_time(now_ms);
                if conn.is_failed() {
                    info!(
                        link_id = %link_id,
                        direction = %direction,
                        "Failed handshake connection cleaned up"
                    );
                } else {
                    info!(
                        link_id = %link_id,
                        direction = %direction,
                        idle_secs = idle_ms / 1000,
                        "Stale handshake connection timed out"
                    );
                }

                // Schedule retry for failed outbound auto-connect peers
                if conn.is_outbound()
                    && let Some(identity) = conn.expected_identity()
                {
                    self.schedule_retry(*identity.node_addr(), now_ms);
                }
            }
            self.cleanup_stale_connection(link_id, now_ms);
        }
    }

    /// Remove a handshake connection and all associated state.
    ///
    /// Frees the session index, removes pending_outbound entry, and cleans up
    /// the link and address mapping. Does not log — callers provide context-appropriate
    /// log messages.
    fn cleanup_stale_connection(&mut self, link_id: LinkId, _now_ms: u64) {
        let conn = match self.connections.remove(&link_id) {
            Some(c) => c,
            None => return,
        };

        // Free session index and pending_outbound if allocated
        if let Some(idx) = conn.our_index() {
            if let Some(tid) = conn.transport_id() {
                self.pending_outbound.remove(&(tid, idx.as_u32()));
            }
            let _ = self.index_allocator.free(idx);
        }

        // Remove link and addr_to_link
        self.remove_link(&link_id);
    }

    /// Remove established sessions that have been idle too long.
    ///
    /// Only targets sessions in the Established state. Initiating/Responding
    /// sessions are handled by the handshake timeout.
    pub(in crate::node) fn purge_idle_sessions(&mut self, now_ms: u64) {
        let timeout_ms = self.config.node.session.idle_timeout_secs * 1000;
        if timeout_ms == 0 {
            return; // disabled
        }

        let idle: Vec<_> = self.sessions.iter()
            .filter(|(_, entry)| {
                entry.is_established()
                    && now_ms.saturating_sub(entry.last_activity()) > timeout_ms
            })
            .map(|(addr, _)| *addr)
            .collect();

        for addr in idle {
            self.sessions.remove(&addr);
            self.pending_tun_packets.remove(&addr);
            debug!(
                dest = %addr,
                idle_secs = timeout_ms / 1000,
                "Idle session removed"
            );
        }
    }
}
