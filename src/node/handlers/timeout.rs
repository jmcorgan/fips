//! Timeout management for stale handshake connections, idle sessions,
//! and handshake message resend scheduling.

use crate::node::Node;
use crate::peer::HandshakeState;
use crate::proto::fmp::{
    ConnAction, ConnSnapshot, LifecycleView, PeerSnapshot, RekeyResendSnapshot,
};
use crate::transport::LinkId;
use tracing::{debug, info};

impl LifecycleView for Node {
    fn stale_connections(&self, now_ms: u64, timeout_ms: u64) -> Vec<ConnSnapshot> {
        self.connections
            .iter()
            .filter(|(_, conn)| conn.is_timed_out(now_ms, timeout_ms) || conn.is_failed())
            .map(|(link_id, conn)| ConnSnapshot {
                link: *link_id,
                is_outbound: conn.is_outbound(),
                retry_addr: conn.expected_identity().map(|id| *id.node_addr()),
                resend_count: 0,
                msg1: Vec::new(),
            })
            .collect()
    }

    fn resend_candidates(&self, now_ms: u64, max_resends: u32) -> Vec<ConnSnapshot> {
        self.connections
            .iter()
            .filter(|(_, conn)| {
                conn.is_outbound()
                    && conn.handshake_state() == HandshakeState::SentMsg1
                    && conn.resend_count() < max_resends
                    && conn.next_resend_at_ms() > 0
                    && now_ms >= conn.next_resend_at_ms()
            })
            .filter_map(|(link_id, conn)| {
                conn.handshake_msg1().map(|msg1| ConnSnapshot {
                    link: *link_id,
                    is_outbound: true,
                    retry_addr: None,
                    resend_count: conn.resend_count(),
                    msg1: msg1.to_vec(),
                })
            })
            .collect()
    }

    fn rekey_peers(&self) -> Vec<PeerSnapshot> {
        // The snapshot builder lives in `rekey` beside its drain/dampening
        // constants; the read-seam unifies here.
        self.rekey_peer_snapshots()
    }

    fn rekey_resend_candidates(&self, now_ms: u64) -> Vec<RekeyResendSnapshot> {
        self.rekey_resend_snapshots(now_ms)
    }
}

impl Node {
    /// Check for timed-out handshake connections and clean them up.
    ///
    /// Called periodically by the RX event loop. Removes connections that have
    /// been idle longer than the configured handshake timeout or are in Failed state.
    ///
    /// The stale/failed predicate and every registry mutation stay shell-side;
    /// the retry-then-teardown choreography is the pure
    /// [`Fmp::poll_timeouts`](crate::proto::fmp::Fmp::poll_timeouts) decision.
    pub(in crate::node) fn check_timeouts(&mut self) {
        if self.connections.is_empty() {
            return;
        }

        let now_ms = Self::now_ms();
        let timeout_ms = self.config().node.rate_limit.handshake_timeout_secs * 1000;

        let stale = self.stale_connections(now_ms, timeout_ms);
        for action in self.fmp.poll_timeouts(stale) {
            match action {
                ConnAction::ScheduleRetry { peer } => self.note_handshake_timeout(peer, now_ms),
                ConnAction::Teardown { link } => {
                    // Log before cleanup (needs live connection state).
                    if let Some(conn) = self.connections.get(&link) {
                        let direction = conn.direction();
                        if conn.is_failed() {
                            debug!(
                                link_id = %link,
                                direction = %direction,
                                "Failed handshake connection cleaned up"
                            );
                        } else {
                            debug!(
                                link_id = %link,
                                direction = %direction,
                                idle_secs = conn.idle_time(now_ms) / 1000,
                                "Stale handshake connection timed out"
                            );
                        }
                    }
                    self.cleanup_stale_connection(link, now_ms);
                }
                #[allow(unreachable_patterns)]
                _ => {}
            }
        }
    }

    /// Remove a handshake connection and all associated state.
    ///
    /// Frees the session index, removes pending_outbound entry, and cleans up
    /// the link and address mapping. Does not log — callers provide context-appropriate
    /// log messages.
    pub(in crate::node) fn cleanup_stale_connection(&mut self, link_id: LinkId, _now_ms: u64) {
        let conn = match self.connections.remove(&link_id) {
            Some(c) => c,
            None => return,
        };
        // A dial-persisted outbound control machine shares the connection's
        // `link_id` and lifetime; drop it here so a reaped handshake leg leaves
        // no dangling machine. A no-op for promoted peers — `promote_connection`
        // already removed their connection, so this reaper never runs for them.
        self.remove_peer_machine(link_id);
        let transport_id = conn.transport_id();

        // Free session index and pending_outbound if allocated
        if let Some(idx) = conn.our_index() {
            if let Some(tid) = conn.transport_id() {
                self.pending_outbound.remove(&(tid, idx.as_u32()));
            }
            let _ = self.index_allocator.free(idx);
        }

        // Remove link and addr_to_link
        self.remove_link(&link_id);
        if let Some(transport_id) = transport_id {
            self.cleanup_bootstrap_transport_if_unused(transport_id);
        }
    }

    /// Resend handshake messages for pending connections.
    ///
    /// For outbound connections in SentMsg1 state, resends the stored msg1
    /// with exponential backoff. Called periodically from the RX event loop.
    pub(in crate::node) async fn resend_pending_handshakes(&mut self, now_ms: u64) {
        if self.connections.is_empty() {
            return;
        }

        let max_resends = self.config().node.rate_limit.handshake_max_resends;
        let interval_ms = self.config().node.rate_limit.handshake_resend_interval_ms;
        let backoff = self.config().node.rate_limit.handshake_resend_backoff;

        // The shell resolves the resend-candidate predicate and copies the
        // opaque msg1 bytes; the core computes the backoff schedule.
        let candidates = self.resend_candidates(now_ms, max_resends);
        for action in self
            .fmp
            .poll_resends(candidates, now_ms, interval_ms, backoff)
        {
            let ConnAction::ResendMsg1 {
                link,
                bytes,
                next_resend_at_ms,
            } = action
            else {
                continue;
            };

            // Get transport and address info from the connection
            let (transport_id, remote_addr) = match self.connections.get(&link) {
                Some(conn) => match (conn.transport_id(), conn.source_addr()) {
                    (Some(tid), Some(addr)) => (tid, addr.clone()),
                    _ => continue,
                },
                None => continue,
            };

            // Send the stored msg1
            let sent = if let Some(transport) = self.transports.get(&transport_id) {
                match transport.send(&remote_addr, &bytes).await {
                    Ok(_) => true,
                    Err(e) => {
                        debug!(
                            link_id = %link,
                            error = %e,
                            "Handshake msg1 resend failed"
                        );
                        false
                    }
                }
            } else {
                false
            };

            if sent && let Some(conn) = self.connections.get_mut(&link) {
                conn.record_resend(next_resend_at_ms);
                debug!(
                    link_id = %link,
                    resend = conn.resend_count(),
                    "Resent handshake msg1"
                );
            }
        }
    }

    /// Resend session-layer handshake messages and timeout stale handshakes.
    ///
    /// For sessions in Initiating or AwaitingMsg3 state:
    /// - If the handshake has exceeded the timeout window, remove the session.
    /// - If a resend is due and under max resends, resend the stored payload
    ///   wrapped in a fresh SessionDatagram (so routing can adapt).
    pub(in crate::node) async fn resend_pending_session_handshakes(&mut self, now_ms: u64) {
        if self.sessions.is_empty() {
            return;
        }

        let timeout_ms = self.config().node.rate_limit.handshake_timeout_secs * 1000;
        let max_resends = self.config().node.rate_limit.handshake_max_resends;
        let interval_ms = self.config().node.rate_limit.handshake_resend_interval_ms;
        let backoff = self.config().node.rate_limit.handshake_resend_backoff;
        let ttl = self.config().node.session.default_ttl;

        // First pass: find timed-out sessions to remove
        let timed_out: Vec<crate::NodeAddr> = self
            .sessions
            .iter()
            .filter(|(_, entry)| {
                !entry.is_established() && now_ms.saturating_sub(entry.last_activity()) > timeout_ms
            })
            .map(|(addr, _)| *addr)
            .collect();

        for addr in &timed_out {
            let name = self.peer_display_name(addr);
            info!(dest = %name, "Session handshake timed out, removing");
            self.sessions.remove(addr);
            self.pending_tun_packets.remove(addr);
        }

        // Second pass: collect resend candidates
        let my_addr = *self.node_addr();
        let candidates: Vec<(crate::NodeAddr, Vec<u8>)> = self
            .sessions
            .iter()
            .filter(|(_, entry)| {
                !entry.is_established()
                    && entry.handshake_payload().is_some()
                    && entry.resend_count() < max_resends
                    && entry.next_resend_at_ms() > 0
                    && now_ms >= entry.next_resend_at_ms()
            })
            .map(|(addr, entry)| (*addr, entry.handshake_payload().unwrap().to_vec()))
            .collect();

        for (dest_addr, payload) in candidates {
            use crate::proto::link::SessionDatagram;

            let mut datagram = SessionDatagram::new(my_addr, dest_addr, payload).with_ttl(ttl);
            let sent = match self.send_session_datagram(&mut datagram).await {
                Ok(_) => true,
                Err(e) => {
                    debug!(
                        dest = %self.peer_display_name(&dest_addr),
                        error = %e,
                        "Session handshake resend failed"
                    );
                    false
                }
            };

            if sent && let Some(entry) = self.sessions.get_mut(&dest_addr) {
                let count = entry.resend_count() + 1;
                let next = now_ms + (interval_ms as f64 * backoff.powi(count as i32)) as u64;
                entry.record_resend(next);
                debug!(
                    dest = %self.peer_display_name(&dest_addr),
                    resend = count,
                    "Resent session handshake"
                );
            }
        }
    }

    /// Remove established sessions that have been idle too long.
    ///
    /// Only targets sessions in the Established state. Initiating/AwaitingMsg3
    /// sessions are handled by the handshake timeout.
    pub(in crate::node) fn purge_idle_sessions(&mut self, now_ms: u64) {
        let timeout_ms = self.config().node.session.idle_timeout_secs * 1000;
        if timeout_ms == 0 {
            return; // disabled
        }

        let idle: Vec<_> = self
            .sessions
            .iter()
            .filter(|(_, entry)| {
                entry.is_established() && now_ms.saturating_sub(entry.last_activity()) > timeout_ms
            })
            .map(|(addr, _)| *addr)
            .collect();

        for addr in idle {
            // Compute display name before removing the session
            let name = self.peer_display_name(&addr);

            // Log MMP teardown metrics before removing the session
            if let Some(entry) = self.sessions.get(&addr)
                && let Some(mmp) = entry.mmp()
            {
                Self::log_session_mmp_teardown(&name, mmp);
            }
            self.sessions.remove(&addr);
            self.pending_tun_packets.remove(&addr);
            debug!(
                dest = %name,
                idle_secs = timeout_ms / 1000,
                "Idle session removed (no application data)"
            );
        }
    }
}
