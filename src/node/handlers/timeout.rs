//! Timeout management for stale handshake connections, idle sessions, link
//! handshake message resend scheduling, and held TUN packets.

use crate::NodeAddr;
use crate::node::Node;
use crate::node::handlers::path_intake::Feed;
use crate::node::session::SessionInstant;
use crate::peer::handshake::{DialOrigin, TimerKind};
use crate::proto::fmp::flow::In;
use crate::proto::settle::input::Input as CoreInput;
use crate::proto::settle::legs::LegOut;
use crate::transport::{LinkId, TransportAddr, TransportId};
use fips_core::proto::path::{Input, Source};
use fips_core::time::Instant;
use std::time::Duration;
use tracing::{debug, info};

/// A handshake the stale-connection sweep reaps.
#[derive(Debug)]
pub(in crate::node) struct Stale {
    /// Its link.
    pub(in crate::node) link: LinkId,
    /// Whether its machine marked it failed.
    failed: bool,
    /// The identity to note a handshake timeout against: the one its
    /// carrier expects, for this node's own dial.
    retry: Option<NodeAddr>,
}

impl Node {
    /// Check for timed-out handshake connections and clean them up.
    ///
    /// Called periodically by the RX event loop. Removes connections that have
    /// been idle longer than the configured handshake timeout or are in Failed state.
    ///
    /// A handshake in the settlement core's legs is reaped there, at its
    /// deadline; every registry mutation stays shell-side.
    pub(in crate::node) async fn check_timeouts(&mut self) {
        self.timeouts_body().await;
        self.audit_live("check_timeouts");
    }

    /// The work of [`Self::check_timeouts`], which audits the per-peer maps
    /// after it.
    async fn timeouts_body(&mut self) {
        // First, and not behind the connection check below: a node with no
        // handshake in progress still holds TUN packets.
        self.release_stranded_tun_packets(crate::time::mono_now());
        self.check_timeouts_at(Self::interval_ms()).await;
    }

    /// [`check_timeouts`](Self::check_timeouts) at `interval_now`, a reading
    /// of the interval clock (`Node::interval_ms`), so a test can run the
    /// reaper past the handshake timeout without waiting.
    pub(in crate::node) async fn check_timeouts_at(&mut self, interval_now: u64) {
        let swept = self.core_tick(interval_now, true);
        if self.connection_count() == 0 {
            return;
        }

        // The wall reading is for the log below, whose idle time is the
        // operator-facing one; the timeout reads the interval clock.
        let now_ms = Self::now_ms();
        let peering_now = Self::peering_now();
        let timeout_ms = self.config().node.rate_limit.handshake_timeout_secs * 1000;

        let stale = self.stale_connections(interval_now, timeout_ms);
        let now = crate::time::mono_at(interval_now);
        for Stale {
            link,
            failed,
            retry,
        } in stale
        {
            // A handshake timed out in the legs is reaped there, and its
            // lease goes back to its machine for the cleanup below. The
            // core says whom it retries: a failed leg its sweep reaped, as
            // the sweep asked; any other leg it holds, as its reap asks.
            let retry = if failed {
                match swept.get(&link) {
                    Some(asked) => *asked,
                    None => match self
                        .core_no(link)
                        .filter(|no| self.legs().get(*no).is_some())
                    {
                        Some(no) => self.core_timed(no),
                        None => retry,
                    },
                }
            } else if self.leg_on(link).is_some() {
                match self.timed_reap(link, now) {
                    Some(asked) => asked,
                    None => continue,
                }
            } else {
                retry
            };
            if let Some(peer) = retry {
                self.note_handshake_timeout(peer, peering_now);
            }
            // Log before cleanup (needs live connection state). The
            // failure signal is now read from the handshake entry; the
            // leg still carries direction/idle for the log fields.
            let is_failed = self
                .handshakes
                .get(&link)
                .is_some_and(|machine| machine.is_failed());
            if let Some(machine) = self
                .handshakes
                .get(&link)
                .filter(|machine| machine.leg().is_some())
            {
                let direction = machine.conn_direction();
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
            self.cleanup_stale_connection(link, now_ms).await;
        }
    }

    /// The handshakes the stale-connection sweep reaps at `interval_now`, a
    /// reading of the interval clock: every failed one, and each idle past
    /// `timeout_ms` whose timeout no machine `HandshakeTimeout` timer drives
    /// (an answer, or an anonymous dial; `drive_handshake_timeouts` reaps
    /// the rest, so neither reaps one twice). A handshake in the settlement
    /// core's legs is idle past its timeout once its leg's deadline has come;
    /// one a test planted past the legs is judged by its carrier.
    pub(in crate::node) fn stale_connections(
        &self,
        interval_now: u64,
        timeout_ms: u64,
    ) -> Vec<Stale> {
        let now = crate::time::mono_at(interval_now);
        self.handshakes
            .iter()
            .filter(|(_, machine)| machine.leg().is_some())
            .filter(|(link_id, machine)| {
                machine.is_failed()
                    || (!self
                        .handshakes
                        .timers()
                        .get(*link_id)
                        .is_some_and(|timers| timers.contains_key(&TimerKind::HandshakeTimeout))
                        && match self.leg_on(**link_id) {
                            Some(leg) => leg.deadline() <= now,
                            None => machine.conn_is_timed_out(interval_now, timeout_ms),
                        })
            })
            .map(|(link_id, machine)| Stale {
                link: *link_id,
                failed: machine.is_failed(),
                retry: machine
                    .conn_is_outbound()
                    .then(|| machine.conn_expected_identity().map(|id| *id.node_addr()))
                    .flatten(),
            })
            .collect()
    }

    /// The handshake leg on the node's link `link` in the settlement core's
    /// legs.
    pub(in crate::node) fn leg_on(
        &self,
        link: LinkId,
    ) -> Option<&crate::proto::settle::legs::Leg<crate::peer::PeerInstant>> {
        self.core_no(link).and_then(|no| self.legs().get(no))
    }

    /// Reap the handshake on `link` in the settlement core's legs at `now`,
    /// if its deadline has come: the core says whom the dial retries, then
    /// hands its lease back to its machine for the cleanup that disposes of
    /// both. The retry the core asked for, or `None` when nothing was
    /// reaped.
    fn timed_reap(
        &mut self,
        link: LinkId,
        now: crate::peer::PeerInstant,
    ) -> Option<Option<NodeAddr>> {
        let no = self.core_no(link)?;
        if self.legs().get(no).is_none_or(|leg| leg.deadline() > now) {
            return None;
        }
        let retry = self.core_timed(no);
        self.core_reap(no, now);
        self.legs().get(no).is_none().then_some(retry)
    }

    /// Remove a handshake connection and all associated state.
    ///
    /// Frees the session index, removes pending_outbound entry, closes the
    /// underlying transport connection, and cleans up the link and address
    /// mapping. Does not log — callers provide context-appropriate log
    /// messages.
    pub(in crate::node) async fn cleanup_stale_connection(
        &mut self,
        link_id: LinkId,
        _now_ms: u64,
    ) {
        // Take the connection off its machine BEFORE disposing the machine
        // (the machine owns it), keeping it readable for the index/link
        // cleanup below. The machine shares the connection's `link_id` and
        // lifetime; dropping it here means a reaped handshake leg leaves no
        // dangling machine. A no-op for promoted peers — `install_handshake`
        // already consumed their connection, so this reaper never runs for
        // them.
        let _detached_leg = match self
            .handshakes
            .get_mut(&link_id)
            .and_then(|machine| machine.take_leg())
        {
            Some(c) => c,
            None => return,
        };
        // Read the transport ID off the surviving carrier, and the session
        // index from the handshake's leg in the settlement core's legs or else the
        // carrier, before disposing the machine (the leg no longer projects
        // them).
        self.core_drop_leg(link_id);
        let (transport_id, our_index) = match self.handshakes.get_mut(&link_id) {
            Some(machine) => (machine.conn_transport_id(), machine.take_our_index()),
            None => (None, None),
        };
        self.remove_handshake(link_id);

        // Free session index and pending_outbound if allocated
        if let Some(lease) = our_index {
            let idx = lease.release();
            if let Some(tid) = transport_id {
                self.pending_outbound.forget(&(tid, idx));
                self.pending_inbound.forget(&(tid, idx));
            }
            let _ = self
                .index_allocator
                .free(crate::utils::index::SessionIndex::new(idx));
        }

        // Tear down the transport connection, not just the node-side state.
        // A connection-oriented transport otherwise keeps the socket, its
        // pool entry and its inbound-slot accounting alive after the node
        // has forgotten the handshake that socket belonged to, so a peer
        // that sends msg1 and then stalls holds an inbound slot forever.
        // Closing twice is harmless: every `close_connection` implementation
        // is `if let Some(conn) = pool.remove(addr)` and the connectionless
        // default is a no-op, so the handshake paths that already close and
        // then drop a link cannot be disturbed by this. A connection an active
        // peer also runs on (both legs of a BLE handshake share one) is left
        // open: it is that peer's, not the stale handshake's.
        self.close_unused(link_id).await;

        // Remove the link and its index entries
        self.remove_link(&link_id);
        if let Some(transport_id) = transport_id {
            self.cleanup_bootstrap_transport_if_unused(transport_id);
        }
    }

    /// Act on the handshake timers this tick.
    ///
    /// The sans-IO machine arms its `HandshakeTimeout` into the timer store
    /// on [`handshakes`](Node::handshakes), whose presence marks an
    /// outbound leg this driver reaps once idle-timed-out; the dial's leg in
    /// the settlement core's legs times the msg1 resends this driver sends,
    /// and is told what the driver did with each. The timeouts are driven before the
    /// resends so a timed-out leg is reaped rather than resent on the same
    /// tick. The rekey/liveness kinds keep their own shell drivers.
    ///
    /// `interval_now` is a reading of the interval clock
    /// (`Node::interval_ms`), which the timers' deadlines and the legs'
    /// activity stamps are kept on.
    pub(in crate::node) async fn drive_peer_timers(&mut self, interval_now: u64) {
        self.timers_body(interval_now).await;
        self.audit_live("drive_peer_timers");
    }

    /// The work of [`Self::drive_peer_timers`], which audits the per-peer maps
    /// after it.
    async fn timers_body(&mut self, interval_now: u64) {
        let _ = self.core_tick(interval_now, false);
        if self.handshakes.timers().is_empty() && self.legs().iter().next().is_none() {
            return;
        }
        self.drive_handshake_timeouts(interval_now).await;
        self.drive_handshake_retransmits(interval_now).await;
    }

    /// Reap the outbound legs whose machine `HandshakeTimeout` timer marks them
    /// as machine-timeout-owned and which have idle-timed-out this tick.
    ///
    /// The timer's PRESENCE selects the leg (only OUTBOUND legs arm one — IK
    /// inbound arms none); the reap THRESHOLD is NOT the timer's stored
    /// deadline. This matters because the machine arms the timer from a
    /// hardcoded constant at dial, which is not authoritative for an
    /// operator-tuned `handshake_timeout_secs`. A dial in the settlement core's
    /// legs is reaped there, at its leg's deadline, which is counted from the
    /// carrier's last activity by the configured timeout; one a test planted
    /// past the legs is judged by the shell `is_timed_out(now, config)`
    /// predicate, off the same `last_activity` clock. A timed-out leg is
    /// reaped by the old Teardown path: the outbound retry reflex, then
    /// `cleanup_stale_connection` (which drops the machine + timers).
    ///
    /// `check_timeouts` keeps reaping everything else — `is_failed()` legs and the
    /// idle-timeout of legs without a machine timer (inbound legs).
    async fn drive_handshake_timeouts(&mut self, now_ms: u64) {
        let timeout_ms = self.config().node.rate_limit.handshake_timeout_secs * 1000;
        let timer_links: Vec<LinkId> = self
            .handshakes
            .timers()
            .iter()
            .filter(|(_, timers)| timers.contains_key(&TimerKind::HandshakeTimeout))
            .map(|(link, _)| *link)
            .collect();
        for link in timer_links {
            // The idle-timeout threshold reads the survivor carrier's
            // last-activity; presence of a pending handshake is what decides
            // between reaping and dropping an orphan timer.
            // A dial in the settlement core's legs has timed out once the
            // legs reap it, which puts its lease back on its machine for
            // the cleanup below.
            // The core says whom such a dial retries, as its reap asks.
            let legged = self.has_pending_leg(&link) && self.leg_on(link).is_some();
            let timed = legged
                .then(|| self.timed_reap(link, crate::time::mono_at(now_ms)))
                .flatten();
            let timed_out = if legged {
                timed.is_some()
            } else {
                self.handshakes
                    .get(&link)
                    .is_some_and(|machine| machine.conn_is_timed_out(now_ms, timeout_ms))
            };
            let (reap, retry_peer) = match self.has_pending_leg(&link) {
                true if timed_out && legged => (true, timed.flatten()),
                true if timed_out => {
                    let retry_peer = if self
                        .handshakes
                        .get(&link)
                        .is_some_and(|machine| machine.conn_is_outbound())
                    {
                        self.handshakes
                            .get(&link)
                            .and_then(|machine| machine.conn_expected_identity())
                            .map(|id| *id.node_addr())
                    } else {
                        None
                    };
                    (true, retry_peer)
                }
                // Not yet idle-timed-out: leave the timer for a later tick.
                true => (false, None),
                false => {
                    // Orphan timer (connection already reaped elsewhere) — drop it.
                    self.handshakes.cancel(link, TimerKind::HandshakeTimeout);
                    (false, None)
                }
            };
            if reap {
                if let Some(peer) = retry_peer {
                    self.note_handshake_timeout(peer, Self::peering_now());
                }
                let candidate = retry_peer.and_then(|peer| self.dial_candidate(link, peer));
                debug!(link_id = %link, "Handshake connection timed out");
                self.cleanup_stale_connection(link, now_ms).await;
                if let Some((peer, transport, addr, source)) = candidate {
                    self.hold_lost_dial(peer, transport, addr, source).await;
                }
            }
        }
    }

    /// The address the outbound leg on `link` dialled `peer` at, with the
    /// candidate source it maps to, if it is one the path machine should
    /// hold should the dial lose. A dial a transport neighbour's key claim
    /// started is left out: the neighbour is offered again while it stays.
    fn dial_candidate(
        &self,
        link: LinkId,
        peer: NodeAddr,
    ) -> Option<(NodeAddr, TransportId, TransportAddr, Source)> {
        let machine = self.handshakes.get(&link)?;
        let source = match machine.dial_origin() {
            DialOrigin::Addressed => Source::Request,
            DialOrigin::MdnsAdvert => Source::Discovery,
            DialOrigin::NeighbourClaim => return None,
        };
        let transport = machine.conn_transport_id()?;
        let addr = machine.conn_source_addr()?.clone();
        Some((peer, transport, addr, source))
    }

    /// A dial to `peer` at `addr` timed out. If the peer came up meanwhile
    /// on another link — a dial that raced a sibling and lost, typically
    /// because the peer answered on the other first — the address is still
    /// a way to reach it: hold it as a path candidate, as a connect request
    /// for a live peer is held, so the path machine opens it. Otherwise the
    /// address goes with the dial and nothing tries it again until whatever
    /// supplied it supplies it anew, which a discovery feed reporting only
    /// changes never does.
    async fn hold_lost_dial(
        &mut self,
        peer: NodeAddr,
        transport: TransportId,
        addr: TransportAddr,
        source: Source,
    ) {
        // `active_peer_link_is_live` answers true for a peer not held.
        if !self.config().node.path.enabled
            || !self.peers.contains_key(&peer)
            || !self.active_peer_link_is_live(&peer)
        {
            return;
        }
        debug!(
            peer = %self.peer_display_name(&peer),
            transport_id = %transport,
            remote_addr = %addr,
            "Dial to a live peer timed out; holding its address as a path candidate"
        );
        // An mDNS-advert address goes through the feed's listing, as every
        // other mDNS report does, so the feed can unlist it later.
        if source == Source::Discovery {
            self.intake(&peer, Feed::Mdns, transport, addr).await;
            return;
        }
        self.step_path(
            &peer,
            Input::Candidate {
                transport,
                addr,
                source,
            },
        )
        .await;
    }

    /// Send the msg1 resends the settlement core's legs find due at `now_ms`
    /// on the interval clock.
    ///
    /// The legs time each dial's resends: the first a second after the
    /// dial's msg1, then at waits of the configured interval growing by the
    /// configured multiplier, up to the configured count or the lower cap of
    /// a leg an mDNS advert directed at a node this node is not configured
    /// to dial ([`DialOrigin::resend_limit`]). The node keeps its own word on
    /// each: a dial whose peer is already held, or whose machine has left
    /// `SentMsg1` or reached its cap, sends no more resends (the leg is
    /// quieted, and the handshake timeout takes it from there); one whose
    /// carrier holds no msg1 yet stays due; and one whose send target is not
    /// known stays due. A resend is counted, on the leg and on the machine
    /// (the operator-visible count reads the machine), and the next
    /// scheduled, only once sent; a failed send is tried again at the next
    /// tick, and neither counts nor marks the dial failed.
    async fn drive_handshake_retransmits(&mut self, now_ms: u64) {
        let max_resends = self.config().node.rate_limit.handshake_max_resends;
        let now = crate::time::mono_at(now_ms);
        for out in self.legs().resends(now) {
            let LegOut::Resend { link: no, bytes } = out else {
                continue;
            };
            let Some(link) = self.core_link(no) else {
                continue;
            };
            // Skip a resend whose target peer already promoted via the inbound
            // cross-connection path — resending msg1 would start a new handshake
            // (session mismatch).
            if let Some(machine) = self.handshakes.get(&link)
                && machine.leg().is_some()
                && machine
                    .conn_expected_identity()
                    .map(|id| self.peers.contains_key(id.node_addr()))
                    .unwrap_or(false)
            {
                self.tend(CoreInput::Flow(In::Quiet { link: no }), now);
                continue;
            }
            let Some(machine) = self.handshakes.get(&link).filter(|machine| {
                machine.is_handshaking_sent_msg1()
                    && machine.resend_count() < machine.dial_origin().resend_limit(max_resends)
            }) else {
                self.tend(CoreInput::Flow(In::Quiet { link: no }), now);
                continue;
            };
            // Armed but the stored wire isn't there yet: leave it due and
            // retry next tick.
            if machine.conn_handshake_msg1().is_none() {
                continue;
            }
            let (transport_id, remote_addr) = match (
                machine.leg().is_some(),
                machine.conn_transport_id(),
                machine.conn_source_addr(),
            ) {
                (true, Some(tid), Some(addr)) => (tid, addr.clone()),
                _ => continue,
            };

            let sent = if let Some(transport) = self.transports.get(&transport_id) {
                match self
                    .send_nowait(transport, link, &remote_addr, &bytes)
                    .await
                {
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
                self.tend(CoreInput::Sent { link: no }, now);
                if let Some(machine) = self.handshakes.get_mut(&link) {
                    machine.record_resend(now_ms);
                    debug!(
                        link_id = %link,
                        resend = machine.resend_count(),
                        "Resent handshake msg1"
                    );
                }
            } else {
                self.tend(CoreInput::SendFailed { link: no }, now);
            }
        }
    }

    /// Release TUN packets held for a destination nothing is still working
    /// to deliver, or held for longer than any legitimate wait.
    ///
    /// A destination is live while it has a session entry in any state, a
    /// pending lookup, or some peer's filter reaching it (a filter that
    /// arrived inside the routing hold keeps the destination until its next
    /// retransmit starts a lookup). Inside the hold no destination is
    /// released for being not live; the age bound applies always. Each
    /// released packet is answered with ICMPv6 no-route.
    pub(in crate::node) fn release_stranded_tun_packets(&mut self, now: std::time::Instant) {
        let in_hold = self.routing_hold_active(now);

        // Queues written without a stamp still age out; stamps left behind by
        // a removal site that does not clear them are dropped.
        for dest in self.pending_tun_packets.keys() {
            self.pending_tun_since
                .entry(*dest)
                .or_insert_with(|| super::session::HeldStamp::new(now));
        }
        let held = &self.pending_tun_packets;
        self.pending_tun_since
            .retain(|dest, _| held.contains_key(dest));

        let max_age = self.pending_tun_max_age();
        let stranded: Vec<(crate::NodeAddr, &'static str)> = self
            .pending_tun_since
            .iter()
            .filter_map(|(dest, stamp)| {
                let live = self.sessions.contains_key(dest)
                    || self.lookup.pending_lookups.contains_key(dest)
                    || self.peers.values().any(|peer| peer.may_reach(dest));
                let age = now.saturating_duration_since(stamp.since);
                is_stranded(live, in_hold, age, max_age)
                    .then_some((*dest, if age > max_age { "max-age" } else { "not-live" }))
            })
            .collect();

        for (dest, reason) in stranded {
            let packets = self.release_held_tun(&dest);
            debug!(
                dest = %self.peer_display_name(&dest),
                packets,
                reason,
                "Released held TUN packets nothing is still working to deliver"
            );
        }

        let at_bound =
            self.pending_tun_packets.len() >= self.config().node.session.pending_max_destinations;
        if let Some(refused) = self.pending_tun_bound_log.tick(at_bound, now) {
            info!(
                refused,
                "Held-packet destination table below its bound again; packets to new destinations were refused while it was full"
            );
        }
    }

    /// The longest a destination's TUN packets stay held, counted from the
    /// destination's stamp (when it was first held, or the latest lookup or
    /// session started for it; see `HeldStamp`), not from when each packet
    /// was held: the whole lookup schedule plus the handshake timeout, the
    /// longest a legitimate destination waits for its lookup and then its
    /// session, with one tick of margin per lookup rung and one for the
    /// handshake sweep, since each deadline is noticed on a tick.
    pub(in crate::node) fn pending_tun_max_age(&self) -> std::time::Duration {
        let node = &self.config().node;
        let ladder = &node.lookup.attempt_timeouts_secs;
        let rungs = u32::try_from(ladder.len()).unwrap_or(u32::MAX);
        let secs = ladder
            .iter()
            .fold(0u64, |sum, s| sum.saturating_add(*s))
            .saturating_add(node.rate_limit.handshake_timeout_secs);
        std::time::Duration::from_secs(secs)
            .saturating_add(crate::node::TICK.saturating_mul(rungs.saturating_add(1)))
    }

    /// Remove established sessions that have been idle too long.
    ///
    /// Only targets sessions in the Established state. A session whose first
    /// handshake is still open is ended by its rekey machine, when its own
    /// attempt and every candidate it held have run out.
    pub(in crate::node) fn purge_idle_sessions(&mut self, now: SessionInstant) {
        let timeout_ms = self.config().node.session.idle_timeout_secs * 1000;
        if timeout_ms == 0 {
            return; // disabled
        }

        let idle: Vec<_> = self
            .sessions
            .iter()
            .filter(|(_, entry)| {
                entry.is_established()
                    && now.saturating_duration_since(entry.last_activity())
                        > Duration::from_millis(timeout_ms)
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
            self.path_mtu_lookup_release(&addr);
            debug!(
                dest = %name,
                idle_secs = timeout_ms / 1000,
                "Idle session removed (no application data)"
            );
        }
    }

    /// Expire `path_mtu_lookup` entries that nothing else will ever release.
    ///
    /// The callers of `path_mtu_lookup_release` all fire on session or peer
    /// state, so an entry written by the discovery `LookupResponse` carrier
    /// for a destination this node neither peers with nor opens a session
    /// with has no release path at all. Keep-tighter then makes one such
    /// response permanent: a `path_mtu` of 256 pins that destination's
    /// SYN-time MSS clamp at 119 bytes until the process restarts. Only those entries carry a
    /// `learned_ms`, and only they are expired here.
    ///
    /// The deadline is the coordinate cache's own TTL, because the same
    /// `LookupResponse` writes both stores: the clamp cannot outlive the
    /// route it was learned with, and shortening the coordinate cache's
    /// lifetime (`CacheConfig::coord_ttl`) shortens this with it. A TTL of
    /// zero disables the pass, matching `purge_idle_sessions`.
    pub(in crate::node) fn purge_expired_path_mtu(&mut self, now_ms: u64) {
        use crate::node::path_mtu::PathMtuEntry;

        let ttl_ms = self.config().node.cache.coord_ttl() * 1000;
        if ttl_ms == 0 {
            return; // disabled
        }
        let stale = |e: &PathMtuEntry| {
            e.learned_ms
                .is_some_and(|at| now_ms.saturating_sub(at) >= ttl_ms)
        };

        let expired: Vec<crate::Ipv6Address> = self
            .path_mtu_lookup
            .iter()
            .filter(|(_, e)| stale(e))
            .map(|(a, _)| *a)
            .collect();
        if expired.is_empty() {
            return;
        }
        for addr in &expired {
            self.path_mtu_lookup.remove(addr);
        }

        // Restore what local configuration knows, the same way
        // `path_mtu_lookup_release` does. A tighter remote claim overwrites a
        // direct peer's link MTU under keep-tighter, so an expired entry may
        // be sitting on top of a seed, and a bare removal would drop that peer
        // to the conservative ceiling until its link re-handshakes.
        let gone: std::collections::HashSet<crate::Ipv6Address> = expired.iter().copied().collect();
        let seeds: Vec<(
            crate::NodeAddr,
            crate::ipv6tun::link::PeerKey,
            crate::transport::TransportId,
            crate::transport::TransportAddr,
        )> = self
            .peers
            .iter()
            .filter(|(addr, _)| gone.contains(&crate::Ipv6Address::from_node_addr(addr)))
            .filter_map(|(addr, p)| {
                let key = crate::ipv6tun::link::PeerKey::from_xonly(&p.pubkey());
                Some((*addr, key, p.transport_id()?, p.current_addr()?.clone()))
            })
            .collect();
        for (addr, key, tid, taddr) in seeds {
            self.seed_path_mtu_for_link_peer(&addr, key, tid, &taddr);
        }

        debug!(
            expired = expired.len(),
            "Expired remote-learned path_mtu_lookup entries"
        );
    }
}

/// Whether a held TUN destination is released: nothing is working to deliver
/// it once routing has had time to converge, or it has waited past the age
/// bound whatever else is true.
fn is_stranded(
    live: bool,
    in_hold: bool,
    age: std::time::Duration,
    max_age: std::time::Duration,
) -> bool {
    (!live && !in_hold) || age > max_age
}

#[cfg(test)]
mod stranded_tests {
    use super::is_stranded;
    use std::time::Duration;

    #[test]
    fn is_stranded_releases_a_destination_with_no_session_lookup_or_filter_only_after_the_hold_or_past_its_age()
     {
        let max = Duration::from_secs(50);
        let young = Duration::ZERO;
        let at_max = max;
        let old = max + Duration::from_millis(1);
        // (live, in_hold, age, released)
        let table = [
            (false, false, young, true),
            (false, true, young, false),
            (true, false, young, false),
            (true, true, young, false),
            (false, true, at_max, false),
            (true, false, at_max, false),
            (true, true, old, true),
            (true, false, old, true),
            (false, true, old, true),
            (false, false, old, true),
        ];
        for (live, in_hold, age, want) in table {
            assert_eq!(
                is_stranded(live, in_hold, age, max),
                want,
                "live={live}, in_hold={in_hold}, age={age:?}"
            );
        }
    }
}
