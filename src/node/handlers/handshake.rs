//! Handshake handlers and connection promotion.

use crate::node::{Node, NodeError};
use crate::peer::{
    cross_connection_winner, ActivePeer, PeerConnection, PromotionResult,
};
use crate::transport::{Link, LinkDirection, LinkId, ReceivedPacket};
use crate::node::wire::{build_msg2, Msg1Header, Msg2Header};
use crate::PeerIdentity;
use std::time::Duration;
use tracing::{debug, info, warn};

impl Node {
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

        // Check if this transport accepts inbound connections
        if let Some(transport) = self.transports.get(&packet.transport_id)
            && !transport.accept_connections()
        {
            self.msg1_rate_limiter.complete_handshake();
            return;
        }

        // Parse header
        let header = match Msg1Header::parse(&packet.data) {
            Some(h) => h,
            None => {
                self.msg1_rate_limiter.complete_handshake();
                debug!("Invalid msg1 header");
                return;
            }
        };

        // Check for existing connection from this address.
        //
        // If we already have an *inbound* link from this address, this could be:
        // 1. A duplicate msg1 (our msg2 was lost) — resend msg2
        // 2. A restarted peer (different epoch) — tear down and reprocess
        //
        // If we have an *outbound* link to this address (we initiated to them
        // AND they initiated to us), this is a cross-connection — allow it.
        //
        // Epoch-based restart detection: if the sender already has an inbound
        // link AND is an active peer in self.peers, fall through to decrypt
        // the msg1 and check the epoch. Otherwise, treat as duplicate.
        let addr_key = (packet.transport_id, packet.remote_addr.clone());
        let mut possible_restart = false;
        if let Some(&existing_link_id) = self.addr_to_link.get(&addr_key)
            && let Some(link) = self.links.get(&existing_link_id)
        {
            if link.direction() == LinkDirection::Inbound {
                // Check if this link belongs to an already-promoted active peer
                let is_active_peer = self.peers.values()
                    .any(|p| p.link_id() == existing_link_id);

                if is_active_peer {
                    // Possible restart — fall through to decrypt and check epoch
                    possible_restart = true;
                } else {
                    // Genuinely pending handshake — resend msg2
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
                    }
                    self.msg1_rate_limiter.complete_handshake();
                    return;
                }
            } else {
                // Outbound link to this address — cross-connection, allow msg1
                debug!(
                    transport_id = %packet.transport_id,
                    remote_addr = %packet.remote_addr,
                    existing_link_id = %existing_link_id,
                    "Cross-connection detected: have outbound, received inbound msg1"
                );
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

        let our_keypair = self.identity.keypair();
        let noise_msg1 = &packet.data[header.noise_msg1_offset..];
        let msg2_response = match conn.receive_handshake_init(our_keypair, self.startup_epoch, noise_msg1, packet.timestamp_ms) {
            Ok(m) => m,
            Err(e) => {
                self.msg1_rate_limiter.complete_handshake();
                debug!(
                    error = %e,
                    "Failed to process msg1"
                );
                return;
            }
        };

        // Learn peer identity from msg1
        let peer_identity = match conn.expected_identity() {
            Some(id) => *id,
            None => {
                self.msg1_rate_limiter.complete_handshake();
                warn!("Identity not learned from msg1");
                return;
            }
        };

        let peer_node_addr = *peer_identity.node_addr();

        // Epoch-based restart detection and duplicate msg1 handling.
        //
        // If we fell through from the addr_to_link check above with
        // possible_restart=true, we now have the decrypted epoch from msg1.
        // Compare it against the stored epoch for this peer.
        if possible_restart
            && let Some(existing_peer) = self.peers.get(&peer_node_addr)
        {
            let new_epoch = conn.remote_epoch();
            let existing_epoch = existing_peer.remote_epoch();

            match (existing_epoch, new_epoch) {
                (Some(existing), Some(new)) if existing != new => {
                    // Epoch mismatch — peer restarted. Tear down stale session.
                    info!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        "Peer restart detected (epoch mismatch), removing stale session"
                    );
                    self.remove_active_peer(&peer_node_addr);
                    // Fall through to process as new connection
                }
                _ => {
                    // Same epoch (or no epoch stored) — duplicate msg1 from
                    // same session. Resend stored msg2.
                    if let Some(msg2) = existing_peer.handshake_msg2().map(|m| m.to_vec())
                        && let Some(transport) = self.transports.get(&packet.transport_id)
                    {
                        match transport.send(&packet.remote_addr, &msg2).await {
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
            }
        }
        // If possible_restart was true but peer is no longer in self.peers
        // (removed by another path), fall through to process as new connection.

        // Note: we don't early-return if peer is already in self.peers here.
        // promote_connection handles cross-connection resolution via tie-breaker.

        // Allocate our session index
        let our_index = match self.index_allocator.allocate() {
            Ok(idx) => idx,
            Err(e) => {
                self.msg1_rate_limiter.complete_handshake();
                warn!(error = %e, "Failed to allocate session index for inbound");
                return;
            }
        };

        conn.set_our_index(our_index);
        conn.set_their_index(header.sender_idx);

        // Create link
        let link = Link::connectionless(
            link_id,
            packet.transport_id,
            packet.remote_addr.clone(),
            LinkDirection::Inbound,
            Duration::from_millis(self.config.node.base_rtt_ms),
        );

        self.links.insert(link_id, link);
        self.addr_to_link.insert(addr_key, link_id);
        self.connections.insert(link_id, conn);

        // Build and send msg2 response, storing for potential resend
        let wire_msg2 = build_msg2(our_index, header.sender_idx, &msg2_response);
        if let Some(conn) = self.connections.get_mut(&link_id) {
            conn.set_handshake_msg2(wire_msg2.clone());
        }

        if let Some(transport) = self.transports.get(&packet.transport_id) {
            match transport.send(&packet.remote_addr, &wire_msg2).await {
                Ok(bytes) => {
                    debug!(
                        link_id = %link_id,
                        our_index = %our_index,
                        their_index = %header.sender_idx,
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
                    self.addr_to_link.remove(&(packet.transport_id, packet.remote_addr));
                    let _ = self.index_allocator.free(our_index);
                    self.msg1_rate_limiter.complete_handshake();
                    return;
                }
            }
        }

        // Responder handshake is complete after receive_handshake_init (Noise IK
        // pattern: responder processes msg1 and generates msg2 in one step).
        // Promote the connection to active peer now.
        match self.promote_connection(link_id, peer_identity, packet.timestamp_ms) {
            Ok(result) => {
                match result {
                    PromotionResult::Promoted(node_addr) => {
                        // Store msg2 on peer for resend on duplicate msg1
                        if let Some(peer) = self.peers.get_mut(&node_addr) {
                            peer.set_handshake_msg2(wire_msg2.clone());
                        }
                        info!(
                            peer = %self.peer_display_name(&node_addr),
                            link_id = %link_id,
                            our_index = %our_index,
                            "Inbound peer promoted to active"
                        );
                        // Send initial tree announce to new peer
                        if let Err(e) = self.send_tree_announce_to_peer(&node_addr).await {
                            debug!(peer = %self.peer_display_name(&node_addr), error = %e, "Failed to send initial TreeAnnounce");
                        }
                        // Schedule filter announce (sent on next tick via debounce)
                        self.bloom_state.mark_update_needed(node_addr);
                    }
                    PromotionResult::CrossConnectionWon { loser_link_id, node_addr } => {
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
                        info!(
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
                        info!(
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
                return;
            }
        };

        let conn = match self.connections.get_mut(&link_id) {
            Some(c) => c,
            None => {
                // Connection removed, clean up pending_outbound
                self.pending_outbound.remove(&key);
                return;
            }
        };

        // Process Noise msg2
        let noise_msg2 = &packet.data[header.noise_msg2_offset..];
        if let Err(e) = conn.complete_handshake(noise_msg2, packet.timestamp_ms) {
            warn!(
                link_id = %link_id,
                error = %e,
                "Handshake completion failed"
            );
            conn.mark_failed();
            return;
        }

        // Store their index
        conn.set_their_index(header.sender_idx);
        conn.set_source_addr(packet.remote_addr.clone());

        // Get peer identity for promotion
        let peer_identity = match conn.expected_identity() {
            Some(id) => *id,
            None => {
                warn!(link_id = %link_id, "No identity after handshake");
                return;
            }
        };

        let peer_node_addr = *peer_identity.node_addr();

        info!(
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
        if self.peers.contains_key(&peer_node_addr) {
            let our_outbound_wins = cross_connection_winner(
                self.identity.node_addr(),
                &peer_node_addr,
                true, // this IS our outbound
            );

            // Extract the outbound connection
            let mut conn = match self.connections.remove(&link_id) {
                Some(c) => c,
                None => {
                    self.pending_outbound.remove(&key);
                    return;
                }
            };

            if our_outbound_wins {
                // We're the smaller node. Swap to outbound session + indices.
                // The peer will keep their inbound session (complement of ours).
                let outbound_our_index = conn.our_index();
                let outbound_session = conn.take_session();

                let (outbound_session, outbound_our_index) =
                    match (outbound_session, outbound_our_index) {
                        (Some(s), Some(idx)) => (s, idx),
                        _ => {
                            warn!(peer = %self.peer_display_name(&peer_node_addr), "Incomplete outbound connection");
                            self.pending_outbound.remove(&key);
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
                        self.peers_by_index.remove(&(transport_id, old_idx.as_u32()));
                        let _ = self.index_allocator.free(old_idx);
                    }
                    self.peers_by_index.insert(
                        (transport_id, outbound_our_index.as_u32()),
                        peer_node_addr,
                    );

                    if suppressed > 0 {
                        debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            count = suppressed,
                            "Suppressed replay detections during link transition"
                        );
                    }

                    info!(
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
                    info!(
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
            return;
        }

        // Normal path: promote to active peer
        match self.promote_connection(link_id, peer_identity, packet.timestamp_ms) {
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
                    }
                    PromotionResult::CrossConnectionWon { loser_link_id, node_addr } => {
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
                        self.addr_to_link.insert(
                            (packet.transport_id, packet.remote_addr.clone()),
                            link_id,
                        );
                        info!(
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
                        info!(
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
            }
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

        let our_index = connection.our_index().ok_or_else(|| {
            NodeError::PromotionFailed {
                link_id,
                reason: "missing our_index".into(),
            }
        })?;
        let their_index = connection.their_index().ok_or_else(|| {
            NodeError::PromotionFailed {
                link_id,
                reason: "missing their_index".into(),
            }
        })?;
        let transport_id = connection.transport_id().ok_or_else(|| {
            NodeError::PromotionFailed {
                link_id,
                reason: "missing transport_id".into(),
            }
        })?;
        let current_addr = connection.source_addr().ok_or_else(|| {
            NodeError::PromotionFailed {
                link_id,
                reason: "missing source_addr".into(),
            }
        })?.clone();
        let link_stats = connection.link_stats().clone();
        let remote_epoch = connection.remote_epoch();

        let peer_node_addr = *verified_identity.node_addr();
        let is_outbound = connection.is_outbound();

        // Check for cross-connection
        if let Some(existing_peer) = self.peers.get(&peer_node_addr) {
            let existing_link_id = existing_peer.link_id();

            // Determine which connection wins
            let this_wins = cross_connection_winner(
                self.identity.node_addr(),
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
                    self.peers_by_index
                        .remove(&(old_tid, old_idx.as_u32()));
                    let _ = self.index_allocator.free(old_idx);
                }

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
                    &self.config.node.mmp,
                    remote_epoch,
                );
                new_peer.set_tree_announce_min_interval_ms(self.config.node.tree.announce_min_interval_ms);

                self.peers.insert(peer_node_addr, new_peer);
                self.peers_by_index
                    .insert((transport_id, our_index.as_u32()), peer_node_addr);
                self.retry_pending.remove(&peer_node_addr);
                self.register_identity(peer_node_addr, verified_identity.pubkey_full());

                info!(
                    peer = %self.peer_display_name(&peer_node_addr),
                    winner_link = %link_id,
                    loser_link = %loser_link_id,
                    "Cross-connection resolved: this connection won"
                );

                Ok(PromotionResult::CrossConnectionWon {
                    loser_link_id,
                    node_addr: peer_node_addr,
                })
            } else {
                // This connection loses, keep existing
                // Free the index we allocated
                let _ = self.index_allocator.free(our_index);

                info!(
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
            if self.max_peers > 0 && self.peers.len() >= self.max_peers {
                let _ = self.index_allocator.free(our_index);
                return Err(NodeError::MaxPeersExceeded { max: self.max_peers });
            }

            // Preserve tree announce rate-limit state from old peer (if reconnecting).
            // Without this, reconnection resets the rate limit window to zero,
            // allowing an immediate announce that can feed an announce loop.
            let old_announce_ts = self.peers.get(&peer_node_addr)
                .map(|p| p.last_tree_announce_sent_ms());

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
                &self.config.node.mmp,
                remote_epoch,
            );
            new_peer.set_tree_announce_min_interval_ms(self.config.node.tree.announce_min_interval_ms);
            if let Some(ts) = old_announce_ts {
                new_peer.set_last_tree_announce_sent_ms(ts);
            }

            self.peers.insert(peer_node_addr, new_peer);
            self.peers_by_index
                .insert((transport_id, our_index.as_u32()), peer_node_addr);
            self.retry_pending.remove(&peer_node_addr);
            self.register_identity(peer_node_addr, verified_identity.pubkey_full());

            info!(
                peer = %self.peer_display_name(&peer_node_addr),
                link_id = %link_id,
                our_index = %our_index,
                their_index = %their_index,
                "Connection promoted to active peer"
            );

            Ok(PromotionResult::Promoted(peer_node_addr))
        }
    }
}
