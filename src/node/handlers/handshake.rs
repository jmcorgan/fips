//! Handshake handlers and connection promotion.

use crate::NodeAddr;
use crate::PeerIdentity;
use crate::node::acl::PeerAclContext;
use crate::node::reject::{HandshakeReject, RejectReason};
use crate::node::{Node, NodeError};
use crate::peer::{ActivePeer, PeerConnection};
use crate::proto::fmp::wire::{Msg1Header, Msg2Header, build_msg2};
use crate::proto::fmp::{
    ConnAction, EstablishSnapshot, EstablishView, InboundDecision, InboundReject, OutboundDecision,
    OutboundSnapshot, PromotionResult, WireOutcome, cross_connection_winner,
};
use crate::transport::{Link, LinkDirection, LinkId, ReceivedPacket};
use std::time::Duration;
use tracing::{debug, info, warn};

impl EstablishView for Node {
    fn establish_snapshot(&self, peer_addr: &NodeAddr) -> EstablishSnapshot {
        let existing = self.peers.get(peer_addr);
        let max_peers = self.max_peers();
        EstablishSnapshot {
            has_existing_peer: existing.is_some(),
            existing_peer_epoch: existing.and_then(|p| p.remote_epoch()),
            existing_session_age_secs: existing
                .map(|p| p.session_established_at().elapsed().as_secs())
                .unwrap_or(0),
            has_session: existing.map(|p| p.has_session()).unwrap_or(false),
            is_healthy: existing.map(|p| p.is_healthy()).unwrap_or(false),
            pending_new_session: existing
                .map(|p| p.pending_new_session().is_some())
                .unwrap_or(false),
            rekey_in_progress: existing.map(|p| p.rekey_in_progress()).unwrap_or(false),
            existing_msg2: existing.and_then(|p| p.handshake_msg2().map(|m| m.to_vec())),
            at_max_peers: max_peers > 0 && self.peers.len() >= max_peers,
            has_pending_outbound_to_peer: self.connections.values().any(|conn| {
                conn.expected_identity()
                    .map(|id| id.node_addr() == peer_addr)
                    .unwrap_or(false)
            }),
            rekey_enabled: self.config().node.rekey.enabled,
            our_node_addr: *self.identity().node_addr(),
        }
    }

    fn outbound_snapshot(&self, peer_addr: &NodeAddr) -> OutboundSnapshot {
        OutboundSnapshot {
            has_existing_peer: self.peers.contains_key(peer_addr),
            // Tie-break for THIS outbound connection (`is_outbound = true`),
            // pre-evaluated here so the core stays free of the peer helper.
            our_outbound_wins: cross_connection_winner(
                self.identity().node_addr(),
                peer_addr,
                true,
            ),
        }
    }
}

impl Node {
    /// Returns true if an inbound msg1 should be admitted past the
    /// `accept_connections` gate.
    ///
    /// Rekey/restart msg1 from an established peer is always admitted (the
    /// gate is meant to filter fresh handshakes from strangers, not
    /// maintenance traffic on established sessions). Two predicates cover
    /// "established peer at this transport+addr":
    ///
    /// 1. `addr_to_link` has an entry for `(transport_id, remote_addr)`.
    ///    This is the fast path and matches when the peer registered with
    ///    the same `TransportAddr` form we observe on inbound packets
    ///    (e.g., both numeric when peer config uses a numeric IP).
    ///
    /// 2. An active peer's `current_addr()` matches `(transport_id,
    ///    remote_addr)`. `current_addr` is updated from inbound encrypted-
    ///    frame source addrs (always numeric `SocketAddr`-form), so this
    ///    catches established peers whose `addr_to_link` key is hostname-
    ///    form (because `initiate_connection` populated it from a
    ///    hostname-bearing peer config) while inbound rekey msg1 arrives
    ///    in numeric form. Without this second predicate, the carve-out
    ///    misses any deployment that combines a hostname-based peer config
    ///    with `udp.accept_connections: false` or `udp.outbound_only: true`
    ///    (the production trigger for the 2026-04-30 bug).
    ///
    /// Otherwise the transport's `accept_connections` config decides;
    /// absence of a registered transport admits (no gate to apply).
    pub(in crate::node) fn should_admit_msg1(
        &self,
        transport_id: crate::transport::TransportId,
        remote_addr: &crate::transport::TransportAddr,
    ) -> bool {
        if self
            .addr_to_link
            .contains_key(&(transport_id, remote_addr.clone()))
        {
            return true;
        }
        if self.peers.values().any(|p| {
            p.transport_id() == Some(transport_id) && p.current_addr() == Some(remote_addr)
        }) {
            return true;
        }
        self.transports
            .get(&transport_id)
            .is_none_or(|t| t.accept_connections())
    }

    /// Handle handshake message 1 (phase 0x1).
    ///
    /// This creates a new inbound connection. Rate limiting is applied
    /// before any expensive crypto operations.
    pub(in crate::node) async fn handle_msg1(&mut self, packet: ReceivedPacket) {
        // === RATE LIMITING (before any processing) ===
        if !self.msg1_rate_limiter.start_handshake() {
            debug!(
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                "Msg1 rate limited"
            );
            return;
        }

        // accept_connections gate. Rekey/restart msg1 on an existing link
        // is always admitted; the gate only filters truly-fresh connections
        // from strangers. Without this carve-out, the dual-init tie-breaker
        // deadlocks when the larger-NodeAddr side has accept_connections=false.
        if !self.should_admit_msg1(packet.transport_id, &packet.remote_addr) {
            self.msg1_rate_limiter.complete_handshake();
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }

        // Parse header
        let header = match Msg1Header::parse(&packet.data) {
            Some(h) => h,
            None => {
                self.msg1_rate_limiter.complete_handshake();
                debug!("Invalid msg1 header");
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
            }
        };

        // Pre-crypto duplicate short-circuit. An *inbound* link from this
        // address that is not (yet) a promoted peer means our earlier msg2 was
        // lost: resend the stored msg2 without paying the crypto cost and
        // return. An inbound link that DOES belong to an active peer (a possible
        // restart/rekey) or an *outbound* link (a cross-connection) falls
        // through to the wire step and the structured classification below —
        // the pre-refactor `possible_restart` flag is no longer needed because
        // that classification now gates on `has_existing_peer` (identity), which
        // subsumes it.
        let addr_key = (packet.transport_id, packet.remote_addr.clone());
        if let Some(&existing_link_id) = self.addr_to_link.get(&addr_key)
            && let Some(link) = self.links.get(&existing_link_id)
        {
            if link.direction() == LinkDirection::Inbound {
                let is_active_peer = self.peers.values().any(|p| p.link_id() == existing_link_id);
                if !is_active_peer {
                    // Genuinely pending handshake — resend msg2.
                    let msg2_bytes = self.find_stored_msg2(existing_link_id);
                    if let Some(msg2) = msg2_bytes {
                        if let Some(transport) = self.transports.get(&packet.transport_id) {
                            match transport.send(&packet.remote_addr, &msg2).await {
                                Ok(_) => debug!(
                                    remote_addr = %packet.remote_addr,
                                    "Resent msg2 for duplicate msg1"
                                ),
                                Err(e) => debug!(
                                    remote_addr = %packet.remote_addr,
                                    error = %e,
                                    "Failed to resend msg2"
                                ),
                            }
                        }
                    } else {
                        debug!(
                            remote_addr = %packet.remote_addr,
                            "Duplicate msg1 but no stored msg2 to resend"
                        );
                        self.stats_mut().record_reject(RejectReason::Handshake(
                            HandshakeReject::UnknownConnection,
                        ));
                    }
                    self.msg1_rate_limiter.complete_handshake();
                    return;
                }
            } else {
                // Outbound link to this address with no active peer yet: a
                // cross-connection. Just log; it is classified as a net-new
                // inbound below.
                let is_active_peer = self.peers.values().any(|p| p.link_id() == existing_link_id);
                if !is_active_peer {
                    debug!(
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        existing_link_id = %existing_link_id,
                        "Cross-connection detected: have outbound, received inbound msg1"
                    );
                }
            }
        }

        // === CRYPTO COST PAID HERE ===
        let link_id = self.allocate_link_id();
        let mut conn = PeerConnection::inbound_with_transport(
            link_id,
            packet.transport_id,
            packet.remote_addr.clone(),
            packet.timestamp_ms,
        );

        let our_keypair = self.identity().keypair();
        let noise_msg1 = &packet.data[header.noise_msg1_offset..];
        let msg2_response = match conn.receive_handshake_init(
            our_keypair,
            self.startup_epoch(),
            noise_msg1,
            packet.timestamp_ms,
        ) {
            Ok(m) => m,
            Err(e) => {
                self.msg1_rate_limiter.complete_handshake();
                debug!(
                    error = %e,
                    "Failed to process msg1"
                );
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
            }
        };

        // Learn peer identity from msg1
        let peer_identity = match conn.expected_identity() {
            Some(id) => *id,
            None => {
                self.msg1_rate_limiter.complete_handshake();
                warn!("Identity not learned from msg1");
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
            }
        };

        let peer_node_addr = *peer_identity.node_addr();

        // === PHASE B result ===
        // Bundle the Noise wire-step outputs (identity, remote epoch, sender
        // index, opaque msg2 payload). The wire step touched no `Node` registry
        // state; from here the decision reads only `wire` and the snapshot.
        let wire = WireOutcome {
            peer_identity,
            remote_epoch: conn.remote_epoch(),
            their_index: header.sender_idx,
            msg2_payload: msg2_response,
        };

        // === PHASE C input ===
        // Snapshot the registry state the inbound classification reads about
        // this peer identity (existing epoch/session/rekey state with the
        // session age resolved here, the max-peers cap, our own address for the
        // tie-break). Taken before this connection is inserted into the
        // registry, matching the pre-refactor read points.
        let est = self.establish_snapshot(&peer_node_addr);

        // === PHASE C: structured classification (pure core) ===
        // The decision reads only the snapshot + wire outcome; the shell below
        // drives the effects. `Promote`/`RestartThenPromote` fall through to the
        // shared authorize → allocate → send-msg2 → promote tail; the other
        // variants complete the rate-limiter and return here.
        match self.fmp.establish_inbound(&est, &wire) {
            InboundDecision::Reject { reason } => {
                match reason {
                    InboundReject::AtMaxPeers => debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        max = self.max_peers(),
                        "Silent-dropping Msg1 at max_peers cap (early gate; no Msg2 sent)"
                    ),
                    InboundReject::PendingSession => debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        "Rekey msg1 received but already have pending session, dropping"
                    ),
                    InboundReject::DualRekeyWon => debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        "Dual rekey initiation: we win (smaller addr), dropping their msg1"
                    ),
                }
                // `conn`/`link_id` were never inserted into the registry, so the
                // local drop suffices — no cleanup needed.
                self.msg1_rate_limiter.complete_handshake();
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
            }
            InboundDecision::ResendMsg2 { msg2 } => {
                if let Some(msg2) = msg2.as_deref()
                    && let Some(transport) = self.transports.get(&packet.transport_id)
                {
                    match transport.send(&packet.remote_addr, msg2).await {
                        Ok(_) => debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            "Resent msg2 for duplicate msg1 (same epoch)"
                        ),
                        Err(e) => debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            error = %e,
                            "Failed to resend msg2"
                        ),
                    }
                }
                self.msg1_rate_limiter.complete_handshake();
                return;
            }
            InboundDecision::RekeyRespond {
                peer,
                abandon_first,
            } => {
                if abandon_first {
                    // Dual-initiation loser: abandon our own in-flight rekey and
                    // free its index before responding as the rekey responder.
                    debug!(
                        peer = %self.peer_display_name(&peer),
                        "Dual rekey initiation: we lose (larger addr), abandoning ours"
                    );
                    if let Some(existing) = self.peers.get_mut(&peer)
                        && let Some(idx) = existing.abandon_rekey()
                    {
                        if let Some(tid) = existing.transport_id() {
                            self.peers_by_index.remove(&(tid, idx.as_u32()));
                            self.pending_outbound.remove(&(tid, idx.as_u32()));
                        }
                        let _ = self.index_allocator.free(idx);
                    }
                }

                // Rekey: process as responder, store new session as pending.
                let noise_session = conn.take_session();
                let our_new_index = match self.index_allocator.allocate() {
                    Ok(idx) => idx,
                    Err(e) => {
                        warn!(error = %e, "Failed to allocate index for rekey");
                        self.msg1_rate_limiter.complete_handshake();
                        self.stats_mut()
                            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        return;
                    }
                };

                let noise_session = match noise_session {
                    Some(s) => s,
                    None => {
                        warn!("Rekey msg1: no session from handshake");
                        let _ = self.index_allocator.free(our_new_index);
                        self.msg1_rate_limiter.complete_handshake();
                        self.stats_mut()
                            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        return;
                    }
                };

                // Send msg2 response using the new handshake.
                let wire_msg2 = build_msg2(our_new_index, wire.their_index, &wire.msg2_payload);
                if let Some(transport) = self.transports.get(&packet.transport_id) {
                    match transport.send(&packet.remote_addr, &wire_msg2).await {
                        Ok(_) => {
                            debug!(
                                peer = %self.peer_display_name(&peer),
                                new_our_index = %our_new_index,
                                "Sent rekey msg2 response"
                            );
                        }
                        Err(e) => {
                            warn!(
                                peer = %self.peer_display_name(&peer),
                                error = %e,
                                "Failed to send rekey msg2"
                            );
                            let _ = self.index_allocator.free(our_new_index);
                            self.msg1_rate_limiter.complete_handshake();
                            self.stats_mut()
                                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                            return;
                        }
                    }
                }

                // Store pending session on the existing peer.
                if let Some(existing) = self.peers.get_mut(&peer) {
                    existing.set_pending_session(noise_session, our_new_index, wire.their_index);
                    existing.record_peer_rekey();
                }

                // Register new index in peers_by_index.
                self.peers_by_index
                    .insert((packet.transport_id, our_new_index.as_u32()), peer);

                // Do NOT touch addr_to_link — the entry must keep pointing at the
                // original link so future msg1s from this address are recognized
                // as rekeys (not new connections). The temporary `conn`/`link_id`
                // were never inserted into the registry, so no cleanup is needed.
                self.msg1_rate_limiter.complete_handshake();
                return;
            }
            InboundDecision::RestartThenPromote { peer } => {
                // Epoch mismatch — peer restarted. Tear down the stale session
                // and schedule a reconnect, then fall through to promote the
                // fresh handshake as a new connection.
                debug!(
                    peer = %self.peer_display_name(&peer),
                    "Peer restart detected (epoch mismatch), removing stale session"
                );
                self.remove_active_peer(&peer);
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                self.schedule_reconnect(peer, now_ms);
            }
            InboundDecision::Promote => {}
        }

        if self
            .authorize_peer(
                &wire.peer_identity,
                PeerAclContext::InboundHandshake,
                packet.transport_id,
                &packet.remote_addr,
            )
            .is_err()
        {
            self.msg1_rate_limiter.complete_handshake();
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }

        // Note: we don't early-return if peer is already in self.peers here.
        // promote_connection handles cross-connection resolution via tie-breaker.

        // Allocate our session index
        let our_index = match self.index_allocator.allocate() {
            Ok(idx) => idx,
            Err(e) => {
                self.msg1_rate_limiter.complete_handshake();
                warn!(error = %e, "Failed to allocate session index for inbound");
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
            }
        };

        conn.set_our_index(our_index);
        conn.set_their_index(wire.their_index);

        // Create link
        let link = Link::connectionless(
            link_id,
            packet.transport_id,
            packet.remote_addr.clone(),
            LinkDirection::Inbound,
            Duration::from_millis(self.config().node.base_rtt_ms),
        );

        self.links.insert(link_id, link);
        self.addr_to_link.insert(addr_key, link_id);
        self.connections.insert(link_id, conn);

        // Build and send msg2 response, storing for potential resend
        let wire_msg2 = build_msg2(our_index, wire.their_index, &wire.msg2_payload);
        if let Some(conn) = self.connections.get_mut(&link_id) {
            conn.set_handshake_msg2(wire_msg2.clone());
        }

        if let Some(transport) = self.transports.get(&packet.transport_id) {
            match transport.send(&packet.remote_addr, &wire_msg2).await {
                Ok(bytes) => {
                    debug!(
                        link_id = %link_id,
                        our_index = %our_index,
                        their_index = %wire.their_index,
                        bytes,
                        "Sent msg2 response"
                    );
                }
                Err(e) => {
                    warn!(
                        link_id = %link_id,
                        error = %e,
                        "Failed to send msg2"
                    );
                    // Clean up on failure
                    self.connections.remove(&link_id);
                    self.links.remove(&link_id);
                    self.addr_to_link
                        .remove(&(packet.transport_id, packet.remote_addr));
                    let _ = self.index_allocator.free(our_index);
                    self.msg1_rate_limiter.complete_handshake();
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
            }
        }

        // Responder handshake is complete after receive_handshake_init (Noise IK
        // pattern: responder processes msg1 and generates msg2 in one step).
        // Promote the connection to active peer now.
        let promote = ConnAction::PromoteToActive { link: link_id };
        match self.drive_promote_to_active(promote, wire.peer_identity, packet.timestamp_ms) {
            Ok(result) => {
                match result {
                    PromotionResult::Promoted(node_addr) => {
                        // Store msg2 on peer for resend on duplicate msg1
                        if let Some(peer) = self.peers.get_mut(&node_addr) {
                            peer.set_handshake_msg2(wire_msg2.clone());
                        }
                        // Promotion is logged once by `promote_connection`
                        // ("Connection promoted to active peer"); no separate
                        // inbound-path line.
                        // Send initial tree announce to new peer
                        if let Err(e) = self.send_tree_announce_to_peer(&node_addr).await {
                            debug!(peer = %self.peer_display_name(&node_addr), error = %e, "Failed to send initial TreeAnnounce");
                        }
                        // Schedule filter announce (sent on next tick via debounce)
                        self.bloom_state.mark_update_needed(node_addr);
                        self.reset_lookup_backoff();
                    }
                    PromotionResult::CrossConnectionWon {
                        loser_link_id,
                        node_addr,
                    } => {
                        // Store msg2 on peer for resend on duplicate msg1
                        if let Some(peer) = self.peers.get_mut(&node_addr) {
                            peer.set_handshake_msg2(wire_msg2.clone());
                        }
                        // Close the losing TCP connection (no-op for connectionless)
                        if let Some(loser_link) = self.links.get(&loser_link_id) {
                            let loser_tid = loser_link.transport_id();
                            let loser_addr = loser_link.remote_addr().clone();
                            if let Some(transport) = self.transports.get(&loser_tid) {
                                transport.close_connection(&loser_addr).await;
                            }
                        }
                        // Clean up the losing connection's link
                        self.remove_link(&loser_link_id);
                        debug!(
                            peer = %self.peer_display_name(&node_addr),
                            loser_link_id = %loser_link_id,
                            "Inbound cross-connection won, loser link cleaned up"
                        );
                        // Send initial tree announce to peer (new or reconnected)
                        if let Err(e) = self.send_tree_announce_to_peer(&node_addr).await {
                            debug!(peer = %self.peer_display_name(&node_addr), error = %e, "Failed to send initial TreeAnnounce");
                        }
                        // Schedule filter announce (sent on next tick via debounce)
                        self.bloom_state.mark_update_needed(node_addr);
                        self.reset_lookup_backoff();
                    }
                    PromotionResult::CrossConnectionLost { winner_link_id } => {
                        // Close the losing TCP connection (no-op for connectionless)
                        if let Some(transport) = self.transports.get(&packet.transport_id) {
                            transport.close_connection(&packet.remote_addr).await;
                        }
                        // This connection lost — clean up its link
                        self.remove_link(&link_id);
                        // Restore addr_to_link for the winner's link
                        self.addr_to_link.insert(
                            (packet.transport_id, packet.remote_addr.clone()),
                            winner_link_id,
                        );
                        debug!(
                            winner_link_id = %winner_link_id,
                            "Inbound cross-connection lost, keeping existing"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    link_id = %link_id,
                    error = %e,
                    "Failed to promote inbound connection"
                );
                // Clean up on promotion failure
                self.remove_link(&link_id);
                let _ = self.index_allocator.free(our_index);
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            }
        }

        self.msg1_rate_limiter.complete_handshake();
    }

    /// Find stored msg2 bytes for a given link (pre- or post-promotion).
    ///
    /// Checks the PeerConnection (if still pending) and then the ActivePeer
    /// (if already promoted).
    fn find_stored_msg2(&self, link_id: LinkId) -> Option<Vec<u8>> {
        // Check pending connection first
        if let Some(conn) = self.connections.get(&link_id)
            && let Some(msg2) = conn.handshake_msg2()
        {
            return Some(msg2.to_vec());
        }
        // Check promoted peer
        for peer in self.peers.values() {
            if peer.link_id() == link_id
                && let Some(msg2) = peer.handshake_msg2()
            {
                return Some(msg2.to_vec());
            }
        }
        None
    }

    /// Handle handshake message 2 (phase 0x2).
    ///
    /// This completes an outbound handshake we initiated.
    pub(in crate::node) async fn handle_msg2(&mut self, packet: ReceivedPacket) {
        // Parse header
        let header = match Msg2Header::parse(&packet.data) {
            Some(h) => h,
            None => {
                debug!("Invalid msg2 header");
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
            }
        };

        // Look up our pending handshake by our sender_idx (receiver_idx in msg2)
        let key = (packet.transport_id, header.receiver_idx.as_u32());
        let link_id = match self.pending_outbound.get(&key) {
            Some(id) => *id,
            None => {
                debug!(
                    receiver_idx = %header.receiver_idx,
                    "No pending outbound handshake for index"
                );
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::UnknownConnection));
                return;
            }
        };

        // Check if this is a rekey msg2: the handshake state is on the
        // ActivePeer (not a PeerConnection), so self.connections won't have it.
        // Look for a peer with matching rekey_our_index.
        if !self.connections.contains_key(&link_id) {
            let noise_msg2 = &packet.data[header.noise_msg2_offset..];

            // Find peer with rekey in progress for this index
            let peer_addr = self.peers.iter().find_map(|(addr, peer)| {
                if peer.rekey_in_progress() && peer.rekey_our_index() == Some(header.receiver_idx) {
                    Some(*addr)
                } else {
                    None
                }
            });

            if let Some(peer_node_addr) = peer_addr {
                let display_name = self.peer_display_name(&peer_node_addr);

                // Complete the rekey handshake on the ActivePeer
                if let Some(peer) = self.peers.get_mut(&peer_node_addr) {
                    match peer.complete_rekey_msg2(noise_msg2) {
                        Ok((session, remote_epoch)) => {
                            let our_index = peer.rekey_our_index().unwrap_or(header.receiver_idx);
                            let remote_epoch_changed = matches!(
                                (peer.remote_epoch(), remote_epoch),
                                (Some(old), Some(new)) if old != new
                            );
                            if remote_epoch.is_some() {
                                peer.set_remote_epoch(remote_epoch);
                            }
                            peer.set_pending_session(session, our_index, header.sender_idx);

                            if let Some(transport_id) = peer.transport_id() {
                                self.peers_by_index
                                    .insert((transport_id, our_index.as_u32()), peer_node_addr);
                            }

                            if remote_epoch_changed {
                                if self.sessions.remove(&peer_node_addr).is_some() {
                                    debug!(
                                        peer = %display_name,
                                        "Cleared stale FSP session after peer restart during FMP rekey"
                                    );
                                }
                                info!(
                                    peer = %display_name,
                                    "Peer restart detected during FMP rekey, replacing stale endpoint session"
                                );
                            }

                            debug!(
                                peer = %display_name,
                                new_our_index = %our_index,
                                new_their_index = %header.sender_idx,
                                "Rekey completed (initiator), pending K-bit cutover"
                            );
                        }
                        Err(e) => {
                            warn!(
                                peer = %display_name,
                                error = %e,
                                "Rekey msg2 processing failed"
                            );
                            if let Some(idx) = peer.abandon_rekey() {
                                if let Some(tid) = peer.transport_id() {
                                    self.peers_by_index.remove(&(tid, idx.as_u32()));
                                }
                                let _ = self.index_allocator.free(idx);
                            }
                            self.stats_mut()
                                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        }
                    }
                }

                self.pending_outbound.remove(&key);
                return;
            }

            // Not a rekey — stale pending_outbound entry pointing at a
            // removed connection and no rekey-in-progress peer claims the
            // receiver_idx. State-machine inconsistency, not a fresh
            // lookup miss.
            self.pending_outbound.remove(&key);
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }

        let (peer_identity, our_index) = {
            let conn = self.connections.get_mut(&link_id).unwrap();

            let noise_msg2 = &packet.data[header.noise_msg2_offset..];
            if let Err(e) = conn.complete_handshake(noise_msg2, packet.timestamp_ms) {
                warn!(
                    link_id = %link_id,
                    error = %e,
                    "Handshake completion failed"
                );
                conn.mark_failed();
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
            }

            conn.set_their_index(header.sender_idx);
            conn.set_source_addr(packet.remote_addr.clone());

            let peer_identity = match conn.expected_identity() {
                Some(id) => *id,
                None => {
                    warn!(link_id = %link_id, "No identity after handshake");
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
            };

            (peer_identity, conn.our_index())
        };

        if self
            .authorize_peer(
                &peer_identity,
                PeerAclContext::OutboundHandshake,
                packet.transport_id,
                &packet.remote_addr,
            )
            .is_err()
        {
            self.pending_outbound.remove(&key);
            if let Some(link) = self.links.get(&link_id) {
                let tid = link.transport_id();
                let addr = link.remote_addr().clone();
                if let Some(transport) = self.transports.get(&tid) {
                    transport.close_connection(&addr).await;
                }
            }
            self.connections.remove(&link_id);
            self.remove_link(&link_id);
            if let Some(idx) = our_index {
                let _ = self.index_allocator.free(idx);
            }
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }

        let peer_node_addr = *peer_identity.node_addr();

        debug!(
            peer = %self.peer_display_name(&peer_node_addr),
            link_id = %link_id,
            their_index = %header.sender_idx,
            "Outbound handshake completed"
        );

        // Cross-connection resolution: if the peer was already promoted via
        // our inbound handshake (we processed their msg1), both nodes initially
        // use mismatched sessions. The tie-breaker determines which handshake
        // wins: smaller node_addr's outbound.
        //
        // - Winner (smaller node): swap to outbound session + outbound indices
        // - Loser (larger node): keep inbound session + original their_index
        //
        // This ensures both nodes use the same Noise handshake (the winner's
        // outbound = the loser's inbound).
        // Structured classification (pure core): cross-connection swap/keep, or
        // a net-new promote. The tie-break is pre-evaluated in the snapshot; the
        // effect bodies below are unchanged.
        let out_snap = self.outbound_snapshot(&peer_node_addr);
        let out_decision = self.fmp.establish_outbound(&out_snap);
        if out_decision != OutboundDecision::Promote {
            // Extract the outbound connection
            let mut conn = match self.connections.remove(&link_id) {
                Some(c) => c,
                None => {
                    self.pending_outbound.remove(&key);
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::UnknownConnection));
                    return;
                }
            };

            if out_decision == OutboundDecision::CrossConnectionSwap {
                // We're the smaller node. Swap to outbound session + indices.
                // The peer will keep their inbound session (complement of ours).
                let outbound_our_index = conn.our_index();
                let outbound_session = conn.take_session();

                let (outbound_session, outbound_our_index) = match (
                    outbound_session,
                    outbound_our_index,
                ) {
                    (Some(s), Some(idx)) => (s, idx),
                    _ => {
                        warn!(peer = %self.peer_display_name(&peer_node_addr), "Incomplete outbound connection");
                        self.pending_outbound.remove(&key);
                        self.stats_mut()
                            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        return;
                    }
                };

                if let Some(peer) = self.peers.get_mut(&peer_node_addr) {
                    let suppressed = peer.replay_suppressed_count();
                    let old_our_index = peer.replace_session(
                        outbound_session,
                        outbound_our_index,
                        header.sender_idx,
                    );

                    // Update peers_by_index: remove old inbound index, add outbound
                    let transport_id = peer.transport_id().unwrap();
                    if let Some(old_idx) = old_our_index {
                        self.peers_by_index
                            .remove(&(transport_id, old_idx.as_u32()));
                        let _ = self.index_allocator.free(old_idx);
                    }
                    self.peers_by_index
                        .insert((transport_id, outbound_our_index.as_u32()), peer_node_addr);

                    if suppressed > 0 {
                        debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            count = suppressed,
                            "Suppressed replay detections during link transition"
                        );
                    }

                    debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        new_our_index = %outbound_our_index,
                        new_their_index = %header.sender_idx,
                        "Cross-connection: swapped to outbound session (our outbound wins)"
                    );
                }
            } else {
                // We're the larger node. Keep our inbound session (it pairs
                // with the peer's outbound, which is the winning handshake).
                //
                // Do NOT update their_index here. Our their_index was set during
                // promote_connection() from the peer's msg1 sender_idx, which is
                // the peer's outbound our_index. After the peer (winner) swaps to
                // their outbound session, that index is exactly what they'll use.
                // The msg2 sender_idx we see here is the peer's INBOUND our_index,
                // which becomes stale after the peer swaps.
                let outbound_our_index = conn.our_index();

                if let Some(peer) = self.peers.get(&peer_node_addr) {
                    debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        kept_their_index = ?peer.their_index(),
                        "Cross-connection: keeping inbound session and original their_index (peer outbound wins)"
                    );
                }

                // Free the outbound's session index since we're not using it
                if let Some(idx) = outbound_our_index {
                    let _ = self.index_allocator.free(idx);
                }
            }

            // Clean up outbound connection state
            self.pending_outbound.remove(&key);
            // Close the losing TCP connection (no-op for connectionless)
            if let Some(link) = self.links.get(&link_id) {
                let tid = link.transport_id();
                let addr = link.remote_addr().clone();
                if let Some(transport) = self.transports.get(&tid) {
                    transport.close_connection(&addr).await;
                }
            }
            self.remove_link(&link_id);

            // Send TreeAnnounce now that sessions are aligned
            if let Err(e) = self.send_tree_announce_to_peer(&peer_node_addr).await {
                debug!(peer = %self.peer_display_name(&peer_node_addr), error = %e, "Failed to send TreeAnnounce after cross-connection resolution");
            }
            // Schedule filter announce (sent on next tick via debounce)
            self.bloom_state.mark_update_needed(peer_node_addr);
            self.reset_lookup_backoff();
            return;
        }

        // Normal path: promote to active peer
        let promote = ConnAction::PromoteToActive { link: link_id };
        match self.drive_promote_to_active(promote, peer_identity, packet.timestamp_ms) {
            Ok(result) => {
                // Clean up pending_outbound
                self.pending_outbound.remove(&key);

                match result {
                    PromotionResult::Promoted(node_addr) => {
                        info!(
                            peer = %self.peer_display_name(&node_addr),
                            "Peer promoted to active"
                        );
                        // Send initial tree announce to new peer
                        if let Err(e) = self.send_tree_announce_to_peer(&node_addr).await {
                            debug!(peer = %self.peer_display_name(&node_addr), error = %e, "Failed to send initial TreeAnnounce");
                        }
                        // Schedule filter announce (sent on next tick via debounce)
                        self.bloom_state.mark_update_needed(node_addr);
                        self.reset_lookup_backoff();
                    }
                    PromotionResult::CrossConnectionWon {
                        loser_link_id,
                        node_addr,
                    } => {
                        // Close the losing TCP connection (no-op for connectionless)
                        if let Some(loser_link) = self.links.get(&loser_link_id) {
                            let loser_tid = loser_link.transport_id();
                            let loser_addr = loser_link.remote_addr().clone();
                            if let Some(transport) = self.transports.get(&loser_tid) {
                                transport.close_connection(&loser_addr).await;
                            }
                        }
                        // Clean up the losing connection's link
                        self.remove_link(&loser_link_id);
                        // Ensure addr_to_link points to the winning link
                        self.addr_to_link
                            .insert((packet.transport_id, packet.remote_addr.clone()), link_id);
                        debug!(
                            peer = %self.peer_display_name(&node_addr),
                            loser_link_id = %loser_link_id,
                            "Outbound cross-connection won, loser link cleaned up"
                        );
                        // Send initial tree announce to peer (new or reconnected)
                        if let Err(e) = self.send_tree_announce_to_peer(&node_addr).await {
                            debug!(peer = %self.peer_display_name(&node_addr), error = %e, "Failed to send initial TreeAnnounce");
                        }
                        // Schedule filter announce (sent on next tick via debounce)
                        self.bloom_state.mark_update_needed(node_addr);
                        self.reset_lookup_backoff();
                    }
                    PromotionResult::CrossConnectionLost { winner_link_id } => {
                        // Close the losing TCP connection (no-op for connectionless)
                        if let Some(transport) = self.transports.get(&packet.transport_id) {
                            transport.close_connection(&packet.remote_addr).await;
                        }
                        // This connection lost — clean up its link
                        self.remove_link(&link_id);
                        // Ensure addr_to_link points to the winner's link
                        self.addr_to_link.insert(
                            (packet.transport_id, packet.remote_addr.clone()),
                            winner_link_id,
                        );
                        debug!(
                            winner_link_id = %winner_link_id,
                            "Outbound cross-connection lost, keeping existing"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    link_id = %link_id,
                    error = %e,
                    "Failed to promote connection"
                );
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            }
        }
    }

    /// Execute a [`ConnAction::PromoteToActive`] from the establish machine.
    ///
    /// The decision to promote is made by the establish handlers (and, from the
    /// establish-core stage on, the pure decision in `proto::fmp`); this is the
    /// executor half of the seam. It runs the promotion through
    /// [`Self::promote_connection`], resolving the verified identity and
    /// promotion timestamp from the ambient wire context, and returns the
    /// [`PromotionResult`] so the caller can drive the site-specific
    /// post-promotion tail (TreeAnnounce, bloom mark, discovery-backoff reset,
    /// loser-link cleanup).
    fn drive_promote_to_active(
        &mut self,
        action: ConnAction,
        verified_identity: PeerIdentity,
        current_time_ms: u64,
    ) -> Result<PromotionResult, NodeError> {
        match action {
            ConnAction::PromoteToActive { link } => {
                self.promote_connection(link, verified_identity, current_time_ms)
            }
            _ => unreachable!("drive_promote_to_active requires a PromoteToActive action"),
        }
    }

    /// Promote a connection to active peer after successful authentication.
    ///
    /// Handles cross-connection detection and resolution using tie-breaker rules.
    pub(in crate::node) fn promote_connection(
        &mut self,
        link_id: LinkId,
        verified_identity: PeerIdentity,
        current_time_ms: u64,
    ) -> Result<PromotionResult, NodeError> {
        // Remove the connection from pending
        let mut connection = self
            .connections
            .remove(&link_id)
            .ok_or(NodeError::ConnectionNotFound(link_id))?;

        // Verify handshake is complete and extract session
        if !connection.has_session() {
            return Err(NodeError::HandshakeIncomplete(link_id));
        }

        let noise_session = connection
            .take_session()
            .ok_or(NodeError::NoSession(link_id))?;

        let our_index = connection
            .our_index()
            .ok_or_else(|| NodeError::PromotionFailed {
                link_id,
                reason: "missing our_index".into(),
            })?;
        let their_index = connection
            .their_index()
            .ok_or_else(|| NodeError::PromotionFailed {
                link_id,
                reason: "missing their_index".into(),
            })?;
        let transport_id = connection
            .transport_id()
            .ok_or_else(|| NodeError::PromotionFailed {
                link_id,
                reason: "missing transport_id".into(),
            })?;
        let current_addr = connection
            .source_addr()
            .ok_or_else(|| NodeError::PromotionFailed {
                link_id,
                reason: "missing source_addr".into(),
            })?
            .clone();
        let link_stats = connection.link_stats().clone();
        let remote_epoch = connection.remote_epoch();

        let peer_node_addr = *verified_identity.node_addr();
        let is_outbound = connection.is_outbound();

        // Check for cross-connection
        if let Some(existing_peer) = self.peers.get(&peer_node_addr) {
            let existing_link_id = existing_peer.link_id();

            let remote_epoch_changed = matches!((existing_peer.remote_epoch(), remote_epoch), (Some(old), Some(new)) if old != new);

            // Determine which connection wins. A peer restart (different
            // startup epoch) is not a normal cross-connection: the old link
            // and FSP sessions are cryptographically stale, so the freshly
            // authenticated connection must replace them regardless of the
            // tie-breaker direction.
            let this_wins = remote_epoch_changed
                || cross_connection_winner(
                    self.identity().node_addr(),
                    &peer_node_addr,
                    is_outbound,
                );

            if this_wins {
                // This connection wins, replace the existing peer
                let old_peer = self.peers.remove(&peer_node_addr).unwrap();
                let loser_link_id = old_peer.link_id();

                // Clean up old peer's index from peers_by_index
                if let (Some(old_tid), Some(old_idx)) =
                    (old_peer.transport_id(), old_peer.our_index())
                {
                    self.peers_by_index.remove(&(old_tid, old_idx.as_u32()));
                    // Unregister the OLD cache_key from the decrypt
                    // worker pool BEFORE freeing the index for reuse.
                    // Otherwise the worker's per-shard HashMap retains a
                    // stale entry pointing at the removed peer's session;
                    // if the index allocator later recycles old_idx to a
                    // different peer, the new register call overwrites
                    // the stale entry — but until that point, decrypt
                    // jobs that land at the recycled cache_key resolve
                    // to the wrong session and AEAD silently fails.
                    #[cfg(unix)]
                    self.unregister_decrypt_worker_session((old_tid, old_idx.as_u32()));
                    let _ = self.index_allocator.free(old_idx);
                }

                if remote_epoch_changed {
                    if self.sessions.remove(&peer_node_addr).is_some() {
                        debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            "Cleared stale FSP session after peer restart during promotion"
                        );
                    }
                    info!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        winner_link = %link_id,
                        loser_link = %loser_link_id,
                        "Peer restart detected during promotion, replacing stale active peer"
                    );
                }

                self.seed_path_mtu_for_link_peer(&peer_node_addr, transport_id, &current_addr);

                let mut new_peer = ActivePeer::with_session(
                    verified_identity,
                    link_id,
                    current_time_ms,
                    noise_session,
                    our_index,
                    their_index,
                    transport_id,
                    current_addr,
                    link_stats,
                    is_outbound,
                    &self.config().node.mmp,
                    remote_epoch,
                );
                new_peer.set_tree_announce_min_interval_ms(
                    self.config().node.tree.announce_min_interval_ms,
                );

                self.peers.insert(peer_node_addr, new_peer);
                self.peers_by_index
                    .insert((transport_id, our_index.as_u32()), peer_node_addr);
                self.peering
                    .reconciler
                    .retry_pending
                    .remove(&peer_node_addr);
                self.register_identity(peer_node_addr, verified_identity.pubkey_full());

                debug!(
                    peer = %self.peer_display_name(&peer_node_addr),
                    winner_link = %link_id,
                    loser_link = %loser_link_id,
                    "Cross-connection resolved: this connection won"
                );

                // Hand the FMP recv cipher + replay window to the
                // decrypt shard worker. (Same as normal-promotion tail
                // below.)
                #[cfg(unix)]
                self.register_decrypt_worker_session(&peer_node_addr);

                Ok(PromotionResult::CrossConnectionWon {
                    loser_link_id,
                    node_addr: peer_node_addr,
                })
            } else {
                // This connection loses, keep existing
                // Free the index we allocated
                let _ = self.index_allocator.free(our_index);

                debug!(
                    peer = %self.peer_display_name(&peer_node_addr),
                    winner_link = %existing_link_id,
                    loser_link = %link_id,
                    "Cross-connection resolved: this connection lost"
                );

                Ok(PromotionResult::CrossConnectionLost {
                    winner_link_id: existing_link_id,
                })
            }
        } else {
            // No existing promoted peer. There may be a pending outbound
            // connection to the same peer (cross-connection in progress).
            // Do NOT clean it up yet — we need the outbound to stay alive
            // so that when the peer's msg2 arrives, we can learn the peer's
            // inbound session index and update their_index on the promoted
            // peer. The outbound will be cleaned up in handle_msg2 or by
            // the 30s handshake timeout.
            let pending_to_same_peer: Vec<LinkId> = self
                .connections
                .iter()
                .filter(|(_, conn)| {
                    conn.expected_identity()
                        .map(|id| *id.node_addr() == peer_node_addr)
                        .unwrap_or(false)
                })
                .map(|(lid, _)| *lid)
                .collect();

            for pending_link_id in &pending_to_same_peer {
                debug!(
                    peer = %self.peer_display_name(&peer_node_addr),
                    pending_link_id = %pending_link_id,
                    promoted_link_id = %link_id,
                    "Deferring cleanup of pending outbound (awaiting msg2 for index update)"
                );
            }

            // Normal promotion
            if self.max_peers() > 0 && self.peers.len() >= self.max_peers() {
                let _ = self.index_allocator.free(our_index);
                return Err(NodeError::MaxPeersExceeded {
                    max: self.max_peers(),
                });
            }

            // Preserve tree announce rate-limit state from old peer (if reconnecting).
            // Without this, reconnection resets the rate limit window to zero,
            // allowing an immediate announce that can feed an announce loop.
            let old_announce_ts = self
                .peers
                .get(&peer_node_addr)
                .map(|p| p.last_tree_announce_sent_ms());

            self.seed_path_mtu_for_link_peer(&peer_node_addr, transport_id, &current_addr);

            let mut new_peer = ActivePeer::with_session(
                verified_identity,
                link_id,
                current_time_ms,
                noise_session,
                our_index,
                their_index,
                transport_id,
                current_addr,
                link_stats,
                is_outbound,
                &self.config().node.mmp,
                remote_epoch,
            );
            new_peer.set_tree_announce_min_interval_ms(
                self.config().node.tree.announce_min_interval_ms,
            );
            if let Some(ts) = old_announce_ts {
                new_peer.set_last_tree_announce_sent_ms(ts);
            }

            self.peers.insert(peer_node_addr, new_peer);
            self.peers_by_index
                .insert((transport_id, our_index.as_u32()), peer_node_addr);
            self.peering
                .reconciler
                .retry_pending
                .remove(&peer_node_addr);
            self.register_identity(peer_node_addr, verified_identity.pubkey_full());

            debug!(
                peer = %self.peer_display_name(&peer_node_addr),
                link_id = %link_id,
                our_index = %our_index,
                their_index = %their_index,
                "Connection promoted to active peer"
            );

            // Hand the FMP recv cipher + replay window to the
            // decrypt shard worker. From this point on the worker
            // is the sole authority on FMP replay protection for
            // this session. No-op when the worker pool isn't
            // spawned (unit-test path or `FIPS_DECRYPT_WORKERS=0`).
            #[cfg(unix)]
            self.register_decrypt_worker_session(&peer_node_addr);

            Ok(PromotionResult::Promoted(peer_node_addr))
        }
    }
}
