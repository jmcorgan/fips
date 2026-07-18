//! Timeout management for stale handshake connections, idle sessions,
//! and handshake message resend scheduling.

use crate::node::Node;
use crate::peer::machine::TimerKind;
use crate::proto::fmp::{
    ConnAction, ConnSnapshot, LifecycleView, PeerSnapshot, RekeyResendSnapshot,
};
use crate::transport::LinkId;
use tracing::{debug, info};

impl LifecycleView for Node {
    fn stale_connections(&self, now_ms: u64, timeout_ms: u64) -> Vec<ConnSnapshot> {
        // `is_failed()` legs are always reaped here (~1s), as before. The
        // idle-timeout is reaped here ONLY for legs whose timeout is not already
        // driven by a machine `HandshakeTimeout` timer — i.e. inbound legs (IK
        // inbound arms none). Outbound legs with an armed timer are reaped by
        // `drive_handshake_timeouts`, so excluding them here avoids a double
        // reap.
        self.peer_machines
            .iter()
            .filter_map(|(link_id, machine)| machine.leg().map(|conn| (link_id, machine, conn)))
            .filter(|(link_id, machine, _conn)| {
                machine.is_failed()
                    || (machine.conn_is_timed_out(now_ms, timeout_ms)
                        && !self.peer_timers.get(*link_id).is_some_and(|timers| {
                            timers.contains_key(&TimerKind::HandshakeTimeout)
                        }))
            })
            .map(|(link_id, _machine, conn)| ConnSnapshot {
                link: *link_id,
                is_outbound: conn.is_outbound(),
                retry_addr: conn.expected_identity().map(|id| *id.node_addr()),
                resend_count: 0,
                msg1: Vec::new(),
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
        if self.connection_count() == 0 {
            return;
        }

        let now_ms = Self::now_ms();
        let timeout_ms = self.config().node.rate_limit.handshake_timeout_secs * 1000;

        let stale = self.stale_connections(now_ms, timeout_ms);
        for action in self.fmp.poll_timeouts(stale) {
            match action {
                ConnAction::ScheduleRetry { peer } => self.note_handshake_timeout(peer, now_ms),
                ConnAction::Teardown { link } => {
                    // Log before cleanup (needs live connection state). The
                    // failure signal is now read from the control machine; the
                    // leg still carries direction/idle for the log fields.
                    let is_failed = self
                        .peer_machines
                        .get(&link)
                        .is_some_and(|machine| machine.is_failed());
                    if let Some(conn) = self.leg(&link) {
                        let direction = conn.direction();
                        if is_failed {
                            debug!(
                                link_id = %link,
                                direction = %direction,
                                "Failed handshake connection cleaned up"
                            );
                        } else {
                            debug!(
                                link_id = %link,
                                direction = %direction,
                                idle_secs =
                                    now_ms.saturating_sub(self.connection_last_activity(link)) / 1000,
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
        // Take the connection off its machine BEFORE disposing the machine
        // (the machine owns it), keeping it readable for the index/link
        // cleanup below. The machine shares the connection's `link_id` and
        // lifetime; dropping it here means a reaped handshake leg leaves no
        // dangling machine. A no-op for promoted peers — `promote_connection`
        // already consumed their connection, so this reaper never runs for
        // them.
        let conn = match self
            .peer_machines
            .get_mut(&link_id)
            .and_then(|machine| machine.take_leg())
        {
            Some(c) => c,
            None => return,
        };
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

    /// Act on the per-peer machine timers this tick.
    ///
    /// The sans-IO machine arms `SetTimer`/`CancelTimer` actions into
    /// [`peer_timers`](Node::peer_timers); this is the shell driver that acts on
    /// them: timeout reaps idle-timed-out outbound legs, retransmit resends the
    /// due msg1s. Handshake-TIMEOUT is driven before handshake-RETRANSMIT so a
    /// timed-out leg is reaped rather than resent on the same tick. The
    /// rekey/liveness kinds keep their own shell drivers, so only the two
    /// handshake kinds are driven here.
    pub(in crate::node) async fn drive_peer_timers(&mut self, now_ms: u64) {
        if self.peer_timers.is_empty() {
            return;
        }
        self.drive_handshake_timeouts(now_ms);
        self.drive_handshake_retransmits(now_ms).await;
    }

    /// Reap the outbound legs whose machine `HandshakeTimeout` timer marks them
    /// as machine-timeout-owned and which have idle-timed-out this tick.
    ///
    /// The timer's PRESENCE selects the leg (only OUTBOUND legs arm one — IK
    /// inbound arms none); the reap THRESHOLD is the shell `is_timed_out(now,
    /// config)` predicate, NOT the timer's stored deadline. This matters because
    /// the machine arms the timer from a hardcoded constant at dial, which is not
    /// authoritative for an operator-tuned `handshake_timeout_secs` — reading the
    /// threshold from config each tick keeps the reap neutral for any config, and
    /// off the `last_activity` clock exactly as the old `check_timeouts` did. A
    /// timed-out leg is reaped by the old Teardown path: the outbound retry
    /// reflex, then `cleanup_stale_connection` (which drops the machine + timers).
    ///
    /// `check_timeouts` keeps reaping everything else — `is_failed()` legs and the
    /// idle-timeout of legs without a machine timer (inbound legs).
    fn drive_handshake_timeouts(&mut self, now_ms: u64) {
        let timeout_ms = self.config().node.rate_limit.handshake_timeout_secs * 1000;
        let timer_links: Vec<LinkId> = self
            .peer_timers
            .iter()
            .filter(|(_, timers)| timers.contains_key(&TimerKind::HandshakeTimeout))
            .map(|(link, _)| *link)
            .collect();
        for link in timer_links {
            // The idle-timeout threshold reads the survivor carrier's
            // last-activity (the leg no longer projects it); the leg still
            // supplies direction/identity for the retry decision below.
            let timed_out = self
                .peer_machines
                .get(&link)
                .is_some_and(|machine| machine.conn_is_timed_out(now_ms, timeout_ms));
            let (reap, retry_peer) = match self.leg(&link) {
                Some(conn) if timed_out => {
                    let retry_peer = if conn.is_outbound() {
                        conn.expected_identity().map(|id| *id.node_addr())
                    } else {
                        None
                    };
                    (true, retry_peer)
                }
                // Not yet idle-timed-out: leave the timer for a later tick.
                Some(_) => (false, None),
                None => {
                    // Orphan timer (connection already reaped elsewhere) — drop it.
                    if let Some(timers) = self.peer_timers.get_mut(&link) {
                        timers.remove(&TimerKind::HandshakeTimeout);
                    }
                    (false, None)
                }
            };
            if reap {
                if let Some(peer) = retry_peer {
                    self.note_handshake_timeout(peer, now_ms);
                }
                debug!(link_id = %link, "Handshake connection timed out");
                self.cleanup_stale_connection(link, now_ms);
            }
        }
    }

    /// Fire due handshake-retransmit timers: resend the stored msg1.
    ///
    /// The pre-fold `resend_pending_handshakes` logic, re-homed: the *due* signal
    /// is the machine-armed timer (not the connection's `next_resend_at_ms`), and
    /// the resend counter lives on the machine (the operator-visible count reads
    /// from there). The wire bytes and transport target still come from the shell
    /// connection, the pure core computes the backoff schedule, and — matching the
    /// old shell exactly — the count and reschedule advance only on a successful
    /// send; a failed send neither advances the count nor marks the connection
    /// failed, it just retries next tick.
    async fn drive_handshake_retransmits(&mut self, now_ms: u64) {
        let max_resends = self.config().node.rate_limit.handshake_max_resends;
        let interval_ms = self.config().node.rate_limit.handshake_resend_interval_ms;
        let backoff = self.config().node.rate_limit.handshake_resend_backoff;

        // Collect due retransmit timers (kind-filtered).
        let due: Vec<LinkId> = self
            .peer_timers
            .iter()
            .filter(|(_, timers)| {
                timers
                    .get(&TimerKind::HandshakeRetransmit)
                    .is_some_and(|&at_ms| now_ms >= at_ms)
            })
            .map(|(link, _)| *link)
            .collect();
        if due.is_empty() {
            return;
        }

        // Classify each due link against the machine + connection. A timer whose
        // machine has left `SentMsg1` (promoted/gone) or has hit the resend cap
        // is dropped — no more resends, exactly as the old shell stopped
        // selecting a capped/settled connection; the handshake-timeout reaper
        // takes it from there.
        let mut candidates: Vec<ConnSnapshot> = Vec::new();
        let mut drop_timers: Vec<LinkId> = Vec::new();
        for link in due {
            let armed = match self.peer_machines.get(&link) {
                Some(machine)
                    if machine.is_handshaking_sent_msg1()
                        && machine.resend_count() < max_resends =>
                {
                    machine.resend_count()
                }
                Some(_) => {
                    drop_timers.push(link);
                    continue;
                }
                None => {
                    drop_timers.push(link);
                    continue;
                }
            };
            match self.leg(&link).and_then(|c| c.handshake_msg1()) {
                // Armed but the stored wire isn't there yet — leave the timer and
                // retry next tick (matches the old candidate filter skipping it).
                None => continue,
                Some(msg1) => candidates.push(ConnSnapshot {
                    link,
                    is_outbound: true,
                    retry_addr: None,
                    resend_count: armed,
                    msg1: msg1.to_vec(),
                }),
            }
        }
        for link in drop_timers {
            if let Some(timers) = self.peer_timers.get_mut(&link) {
                timers.remove(&TimerKind::HandshakeRetransmit);
            }
        }

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

            let (transport_id, remote_addr) = match self.leg(&link) {
                Some(conn) => match (conn.transport_id(), conn.source_addr()) {
                    (Some(tid), Some(addr)) => (tid, addr.clone()),
                    _ => continue,
                },
                None => continue,
            };

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

            if sent {
                if let Some(machine) = self.peer_machines.get_mut(&link) {
                    machine.record_resend(next_resend_at_ms);
                    debug!(
                        link_id = %link,
                        resend = machine.resend_count(),
                        "Resent handshake msg1"
                    );
                }
                self.peer_timers
                    .entry(link)
                    .or_default()
                    .insert(TimerKind::HandshakeRetransmit, next_resend_at_ms);
            } else {
                // Failed send: keep retrying at the tick cadence (the old shell
                // left next_resend_at_ms unchanged so the connection stayed due).
                self.peer_timers
                    .entry(link)
                    .or_default()
                    .insert(TimerKind::HandshakeRetransmit, now_ms);
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
