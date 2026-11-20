//! Timeout management for stale handshake connections, idle sessions, link
//! handshake message resend scheduling, and held TUN packets.

use crate::NodeAddr;
use crate::node::Node;
use crate::node::handlers::path_intake::Feed;
use crate::node::session::SessionInstant;
use crate::peer::handshake::DialOrigin;
use crate::proto::fmp::{ConnAction, ConnSnapshot, LifecycleView};
use crate::proto::settle::input::Input as Settle;
use crate::proto::settle::links::LinkNo;
use crate::proto::settle::output::Output;
use crate::transport::{LinkId, TransportAddr, TransportId};
use fips_core::proto::path::{Input, Source};
use fips_core::time::Instant;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info};

impl LifecycleView for Node {
    fn stale_connections(&self, interval_now: u64, timeout_ms: u64) -> Vec<ConnSnapshot> {
        // `is_failed()` legs are always reaped here (~1s), as before. The
        // idle-timeout is reaped here ONLY for handshakes with no leg in the
        // settlement core's legs, which the core does not time out. A
        // dial's leg is reaped by the core's poll at its deadline
        // (`drive_peer_timers`), and an answer's by the core's reap above,
        // so excluding them here avoids a double reap.
        self.handshakes
            .iter()
            .filter(|(_, entry)| entry.leg().is_some())
            .filter(|(link_id, entry)| {
                entry.is_failed()
                    || (entry.conn_is_timed_out(interval_now, timeout_ms)
                        && self.leg(**link_id).is_none())
            })
            .map(|(link_id, entry)| ConnSnapshot {
                link: *link_id,
                is_outbound: entry.conn_is_outbound(),
                retry_addr: entry.conn_expected_identity().map(|id| *id.node_addr()),
            })
            .collect()
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
        // Not behind it either: a BLE channel that never carries a msg1
        // leaves no handshake connection to count.
        self.close_unproven_ble_links().await;

        // The answers past their deadline: the settlement core reaps each,
        // as it reaps a dial at the peers' timers.
        self.reap_answers(Self::settle_now()).await;

        if self.connection_count() == 0 {
            return;
        }

        // The wall reading is for the log below, whose idle time is the
        // operator-facing one; the timeout reads the interval clock.
        let now_ms = Self::now_ms();
        let interval_now = Self::interval_ms();
        let peering_now = Self::peering_now();
        let timeout_ms = self.config().node.rate_limit.handshake_timeout_secs * 1000;

        let stale = self.stale_connections(interval_now, timeout_ms);
        for action in self.fmp.poll_timeouts(stale) {
            match action {
                ConnAction::ScheduleRetry { peer } => {
                    self.note_handshake_timeout(peer, peering_now)
                }
                ConnAction::Teardown { link } => {
                    // Log before cleanup (needs live connection state): the
                    // handshake entry carries the failure signal, the
                    // direction and the idle time for the log fields.
                    let is_failed = self
                        .handshakes
                        .get(&link)
                        .is_some_and(|entry| entry.is_failed());
                    if let Some(entry) = self
                        .handshakes
                        .get(&link)
                        .filter(|entry| entry.leg().is_some())
                    {
                        let direction = entry.conn_direction();
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
                    if let Some((peer, _)) = self.redials.iter().find(|(_, r)| r.link == link) {
                        debug!(
                            peer = %self.peer_display_name(peer),
                            link_id = %link,
                            "Pending redial expired with no frame"
                        );
                    }
                    // A failed leg, or one past its timeout with no leg in
                    // the core's legs, is given up for the core too, by the
                    // cleanup.
                    self.cleanup_stale_connection(link, now_ms).await;
                }
                #[allow(unreachable_patterns)]
                _ => {}
            }
        }
    }

    /// Close each BLE channel that is unverified, has never completed a
    /// handshake, and has gone the handshake timeout since it was admitted
    /// or since this node last held a handshake or link on it, as FRC-1301
    /// Section 6.5.4 asks.
    ///
    /// A handshake leg's own reap, above, closes the channel it ran on; this
    /// covers a channel on which no leg was ever started, and one whose leg
    /// ended without a reap, a timeout after the node last held it.
    #[cfg(ble_available)]
    async fn close_unproven_ble_links(&mut self) {
        let timeout = Duration::from_secs(self.config().node.rate_limit.handshake_timeout_secs);
        for (tid, transport) in &self.transports {
            let crate::transport::TransportHandle::Ble(ble) = transport else {
                continue;
            };
            let held = |addr: &crate::transport::TransportAddr| {
                self.links.index().contains_key(&(*tid, addr.clone()))
            };
            for addr in ble.close_unproven(timeout, held).await {
                debug!(
                    transport_id = %tid,
                    remote_addr = %addr,
                    "Closed a BLE channel that carried no handshake within the handshake timeout"
                );
            }
        }
    }

    /// Without BLE there is no channel to close.
    #[cfg(not(ble_available))]
    async fn close_unproven_ble_links(&mut self) {}

    /// Remove a handshake connection and all associated state.
    ///
    /// Gives the leg up for the settlement core first, then frees the
    /// session index, the dial's leg's or else the handshake entry's, closes the
    /// underlying transport connections the core's close rule closed as it
    /// gave the leg up, and cleans up the link and address mapping. Does not
    /// log — callers provide context-appropriate log messages.
    pub(in crate::node) async fn cleanup_stale_connection(
        &mut self,
        link_id: LinkId,
        _now_ms: u64,
    ) {
        let closes = self.give_up(link_id);
        // Take the connection off its entry BEFORE dropping the entry (the
        // entry owns it), keeping it readable for the index/link cleanup
        // below. The entry shares the connection's `link_id` and lifetime;
        // dropping it here means a reaped handshake leaves no dangling entry.
        // A no-op for promoted peers — `install_handshake` already consumed
        // their connection, so this reaper never runs for them.
        let _detached_leg = match self
            .handshakes
            .get_mut(&link_id)
            .and_then(|entry| entry.take_leg())
        {
            Some(c) => c,
            None => return,
        };
        // Read the transport ID off the entry, and the session index from
        // the dial's leg or else the entry, before dropping the entry.
        let leased = self.take_leg(link_id);
        let (transport_id, our_index) = match self.handshakes.get_mut(&link_id) {
            Some(entry) => (
                entry.conn_transport_id(),
                leased.or_else(|| entry.take_our_index()),
            ),
            None => (None, leased),
        };
        self.remove_handshake(link_id);

        // Free the session index if allocated
        if let Some(lease) = our_index {
            let _ = self
                .index_allocator
                .free(crate::utils::index::SessionIndex::new(lease.release()));
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
        if closes.is_empty() {
            debug!(
                link_id = %link_id,
                "Handshake link shares its connection with another live link; leaving it open"
            );
        }
        self.close_each(closes).await;

        // Remove the link and its index entries
        self.remove_link(&link_id);
        if let Some(transport_id) = transport_id {
            self.cleanup_bootstrap_transport_if_unused(transport_id);
        }
    }

    /// Act on the handshake legs' timers this tick: a dial's leg past its
    /// deadline is reaped, and the due msg1s resent.
    ///
    /// `interval_now` is a reading of the interval clock
    /// (`Node::interval_ms`), which the timers' deadlines and the legs'
    /// activity stamps are kept on.
    pub(in crate::node) async fn drive_peer_timers(&mut self, interval_now: u64) {
        self.timers_body(interval_now).await;
        self.audit_live("drive_peer_timers");
    }

    /// The work of [`Self::drive_peer_timers`], which audits the per-peer maps
    /// after it: the settlement core's handshake legs polled at
    /// `interval_now`, the resends it asks for sent, and the legs past their
    /// deadline reaped. A dial's resends and its deadline are the core's
    /// ([`Legs`](crate::proto::settle::legs::Legs)): its msg1 resent at one
    /// resend interval and then at intervals growing by the configured
    /// multiplier, up to the configured count or the dial's own lower cap,
    /// each counted only once sent; a failed send tried again at the next
    /// tick. A reaped dial takes the outbound retry reflex, and its link's
    /// retirement closes the connections no other live link uses.
    async fn timers_body(&mut self, interval_now: u64) {
        self.run_legs(crate::time::mono_at(interval_now)).await;
    }

    /// Poll the settlement core's handshake legs at `now`, and carry out
    /// what the poll asks: each resend sent, each leg past its deadline
    /// reaped.
    async fn run_legs(&mut self, now: crate::peer::PeerInstant) {
        // A leg's link a test planted past the writers gets its record
        // first, so the reap retires it.
        #[cfg(test)]
        self.resync();
        let dials = self.dials();
        let redials = self.redialing();
        let out = self.core_tick(now);
        self.run_legs_out(out, &dials, &redials, now).await;
    }

    /// The identity each of this node's own dials in the core's legs dialed,
    /// by the dial's link, read before a poll that may reap one: the reap's
    /// outputs name only the link.
    fn dials(&self) -> HashMap<LinkNo, NodeAddr> {
        self.legs()
            .iter()
            .filter(|leg| *leg.kind() == crate::proto::settle::legs::Kind::Dial)
            .filter_map(|leg| Some((leg.link(), leg.peer()?)))
            .collect()
    }

    /// The identity of each pending redial, by its leg's link, read before
    /// a poll or reap that may reap one: the core forgets the redial with
    /// its leg.
    fn redialing(&self) -> HashMap<LinkNo, NodeAddr> {
        self.core.redials().map(|(peer, no)| (no, *peer)).collect()
    }

    /// Carry out what a poll or reap of the core's legs at `now` asked,
    /// `out`: each resend sent, and each leg reaped, its lease (the `Free`
    /// before its link's `Retire`) back to the allocator, for a dial of
    /// `dials` with the outbound retry reflex, and for a redial of
    /// `redials` with its expiry logged.
    async fn run_legs_out(
        &mut self,
        out: Vec<Output>,
        dials: &HashMap<LinkNo, NodeAddr>,
        redials: &HashMap<LinkNo, NodeAddr>,
        now: crate::peer::PeerInstant,
    ) {
        let mut freed = None;
        for o in out {
            match o {
                Output::Resend { link, bytes } => self.resend_msg1(link, &bytes, now).await,
                Output::Free { lease } => {
                    if let Some(old) = freed.replace(lease) {
                        self.free_lease(old);
                    }
                }
                Output::Retire { link, closes } => match freed.take() {
                    Some(lease) => {
                        if let (Some(peer), Some(link_id)) =
                            (redials.get(&link), self.links.id(link))
                        {
                            debug!(
                                peer = %self.peer_display_name(peer),
                                link_id = %link_id,
                                "Pending redial expired with no frame"
                            );
                        }
                        self.reap_leg(link, dials.get(&link).copied(), closes, lease)
                            .await
                    }
                    None => debug_assert!(false, "a reaped leg's link retired with no lease"),
                },
                other => debug_assert!(false, "a poll of the legs gave {other:?}"),
            }
        }
        if let Some(lease) = freed {
            self.free_lease(lease);
        }
    }

    /// Send the msg1 resend the core asked for on the leg of the core's
    /// link `no`, `bytes`, and tell the core whether it went out: a resend
    /// is counted, and the next scheduled, only once sent, and a failed one
    /// is tried again at the next tick.
    async fn resend_msg1(
        &mut self,
        no: crate::proto::settle::links::LinkNo,
        bytes: &[u8],
        now: crate::peer::PeerInstant,
    ) {
        let Some(link) = self.links.id(no) else {
            return;
        };
        let target = self
            .links
            .get(&link)
            .filter(|_| self.has_pending_leg(&link))
            .map(|l| (l.transport_id(), l.remote_addr().clone()));
        let sent = match target {
            Some((transport_id, remote_addr)) => match self.transports.get(&transport_id) {
                Some(transport) => {
                    match self.send_nowait(transport, link, &remote_addr, bytes).await {
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
                }
                None => false,
            },
            None => false,
        };
        let told = if sent {
            Settle::Sent { link: no }
        } else {
            Settle::SendFailed { link: no }
        };
        let out = self.decide_at(told, now);
        debug_assert!(
            out.is_empty(),
            "a dial's resend sent or failed gave {out:?}"
        );
        if sent {
            debug!(
                link_id = %link,
                resend = self.legs().get(no).map_or(0, |leg| leg.sent()),
                "Resent handshake msg1"
            );
        }
    }

    /// Have the settlement core reap each answer's leg past its deadline at
    /// `now`, as the stale-connection sweep reaped an inbound handshake idle
    /// past the handshake timeout.
    async fn reap_answers(&mut self, now: crate::peer::PeerInstant) {
        // A leg's link a test planted past the writers gets its record
        // first, so the reap retires it.
        #[cfg(test)]
        self.resync();
        let redials = self.redialing();
        let answers: Vec<LinkNo> = self
            .legs()
            .iter()
            .filter(|leg| matches!(leg.kind(), crate::proto::settle::legs::Kind::Answer { .. }))
            .map(|leg| leg.link())
            .collect();
        for no in answers {
            let out = self.reap(no, now);
            self.run_legs_out(out, &HashMap::new(), &redials, now).await;
        }
    }

    /// Reap the handshake leg the core's poll found past its deadline on
    /// the core's link `no`, whose lease is `lease`: for this node's own
    /// dial of `retry`, the outbound retry reflex and the dial's address
    /// kept as a path candidate where it applies, and for an answer the
    /// stale-connection line; then the link and its
    /// handshake entry go, the lease's index returns to the allocator, and the
    /// connections its retirement left unused, `closes`, are closed.
    async fn reap_leg(
        &mut self,
        no: crate::proto::settle::links::LinkNo,
        retry: Option<NodeAddr>,
        closes: Vec<crate::proto::settle::links::Pair>,
        lease: crate::proto::rekey::IndexLease,
    ) {
        let _ = self
            .index_allocator
            .free(crate::utils::index::SessionIndex::new(lease.release()));
        let Some(link) = self.links.id(no) else {
            return;
        };
        if let Some(peer) = retry {
            self.note_handshake_timeout(peer, Self::peering_now());
        }
        let candidate = retry.and_then(|peer| self.dial_candidate(link, peer));
        match (retry, self.handshakes.get(&link)) {
            (None, Some(entry)) => debug!(
                link_id = %link,
                direction = %entry.conn_direction(),
                idle_secs =
                    Self::now_ms().saturating_sub(self.connection_last_activity(link)) / 1000,
                "Stale handshake connection timed out"
            ),
            _ => debug!(link_id = %link, "Handshake connection timed out"),
        }
        let transport_id = self
            .handshakes
            .get_mut(&link)
            .map(|entry| {
                let _detached = entry.take_leg();
                entry.conn_transport_id()
            })
            .unwrap_or(None);
        self.remove_handshake(link);
        for pair in closes {
            if let Some(transport) = self.transports.get(&pair.transport) {
                transport.close_connection(&pair.addr).await;
            }
        }
        self.remove_link(&link);
        if let Some(transport_id) = transport_id {
            self.cleanup_bootstrap_transport_if_unused(transport_id);
        }
        if let Some((peer, transport, addr, source)) = candidate {
            self.hold_lost_dial(peer, transport, addr, source).await;
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
        let entry = self.handshakes.get(&link)?;
        let source = match entry.dial_origin() {
            DialOrigin::Addressed => Source::Request,
            DialOrigin::MdnsAdvert => Source::Discovery,
            DialOrigin::NeighbourClaim => return None,
        };
        let dialled = self.links.get(&link)?;
        Some((
            peer,
            dialled.transport_id(),
            dialled.remote_addr().clone(),
            source,
        ))
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
