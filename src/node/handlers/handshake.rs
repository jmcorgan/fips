//! Handshake handlers and connection promotion.
//!
//! Implements the Noise XX 3-message handshake for FMP link establishment:
//! - msg1 (initiator → responder): ephemeral only, no identity
//! - msg2 (responder → initiator): responder identity + epoch + negotiation
//! - msg3 (initiator → responder): initiator identity + epoch + negotiation

use crate::PeerIdentity;
use crate::node::acl::PeerAclContext;
use crate::node::wire::{Msg1Header, Msg2Header, Msg3Header, build_msg2, build_msg3};
use crate::node::{Node, NodeError};
use crate::peer::{ActivePeer, PeerConnection, PromotionResult, cross_connection_winner};
use crate::protocol::{Disconnect, DisconnectReason, NegotiationPayload};
use crate::transport::{Link, LinkDirection, LinkId, ReceivedPacket};
use std::time::Duration;
use tracing::{debug, info, warn};

impl Node {
    /// Handle handshake message 1 (phase 0x1).
    ///
    /// With Noise XX, msg1 contains only the initiator's ephemeral key.
    /// No identity is learned. The responder processes msg1, sends msg2
    /// (revealing its own identity), and stores the connection in
    /// pending_inbound to await msg3.
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
        // With XX, we can't do identity-based checks in msg1 (no identity yet).
        // We can only detect duplicates by address: if we already have an inbound
        // link from this address with a pending connection, resend msg2.
        // If we have an active peer on this address, it could be a restart or
        // rekey — but we can't tell until msg3 reveals identity. For now, allow
        // the new handshake to proceed. Identity-based checks happen in handle_msg3.
        let addr_key = (packet.transport_id, packet.remote_addr.clone());
        if let Some(&existing_link_id) = self.addr_to_link.get(&addr_key)
            && let Some(link) = self.links.get(&existing_link_id)
        {
            if link.direction() == LinkDirection::Inbound {
                // Check if this link belongs to an already-promoted active peer
                let is_active_peer = self.peers.values().any(|p| p.link_id() == existing_link_id);

                if !is_active_peer {
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
                // Active peer on this address — allow the new handshake.
                // Identity checks (restart, rekey) deferred to handle_msg3.
                debug!(
                    transport_id = %packet.transport_id,
                    remote_addr = %packet.remote_addr,
                    existing_link_id = %existing_link_id,
                    "XX msg1 from address with active peer — proceeding (identity check deferred to msg3)"
                );
            } else {
                // Outbound link to this address — cross-connection.
                // Allow the inbound handshake to proceed.
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

        // Create FMP negotiation payload for msg2 (includes profile, MMP bits, bloom TLV)
        let neg_payload = NegotiationPayload::fmp(1, 1, self.node_profile).encode();

        let our_keypair = self.identity.keypair();
        let noise_msg1 = &packet.data[header.noise_msg1_offset..];
        let msg2_response = match conn.receive_handshake_init(
            our_keypair,
            self.startup_epoch,
            noise_msg1,
            Some(&neg_payload),
            packet.timestamp_ms,
        ) {
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

        // XX: identity is NOT learned from msg1 (only ephemeral exchange).
        // Identity will be learned from msg3 in handle_msg3.

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
                    self.addr_to_link
                        .remove(&(packet.transport_id, packet.remote_addr));
                    let _ = self.index_allocator.free(our_index);
                    self.msg1_rate_limiter.complete_handshake();
                    return;
                }
            }
        }

        // XX: handshake NOT complete yet — need msg3.
        // Store in pending_inbound for msg3 dispatch.
        self.pending_inbound
            .insert((packet.transport_id, our_index.as_u32()), link_id);

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
    /// With Noise XX, processing msg2 learns the responder's identity and
    /// generates msg3 which must be sent before the handshake is complete.
    /// After sending msg3, the initiator's handshake is complete and the
    /// connection is promoted.
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
                // XX: complete_rekey_msg2 processes msg2 and generates msg3
                let transport_id = self
                    .peers
                    .get(&peer_node_addr)
                    .and_then(|p| p.transport_id());
                let remote_addr = self
                    .peers
                    .get(&peer_node_addr)
                    .and_then(|p| p.current_addr().cloned());

                if let Some(peer) = self.peers.get_mut(&peer_node_addr) {
                    match peer.complete_rekey_msg2(noise_msg2) {
                        Ok((msg3_bytes, session)) => {
                            let our_index = peer.rekey_our_index().unwrap_or(header.receiver_idx);

                            // Send msg3 before setting pending session
                            let wire_msg3 = build_msg3(our_index, header.sender_idx, &msg3_bytes);
                            let msg3_sent = if let (Some(tid), Some(addr)) =
                                (transport_id, &remote_addr)
                                && let Some(transport) = self.transports.get(&tid)
                            {
                                match transport.send(addr, &wire_msg3).await {
                                    Ok(_) => {
                                        debug!(
                                            peer = %display_name,
                                            "Sent rekey msg3"
                                        );
                                        true
                                    }
                                    Err(e) => {
                                        warn!(
                                            peer = %display_name,
                                            error = %e,
                                            "Failed to send rekey msg3"
                                        );
                                        false
                                    }
                                }
                            } else {
                                false
                            };

                            if msg3_sent {
                                peer.set_pending_session(session, our_index, header.sender_idx);

                                if let Some(tid) = transport_id {
                                    self.peers_by_index
                                        .insert((tid, our_index.as_u32()), peer_node_addr);
                                }

                                debug!(
                                    peer = %display_name,
                                    new_our_index = %our_index,
                                    new_their_index = %header.sender_idx,
                                    "Rekey completed (initiator), pending K-bit cutover"
                                );
                            } else {
                                // msg3 send failed — abandon rekey
                                if let Some(idx) = peer.abandon_rekey() {
                                    if let Some(tid) = peer.transport_id() {
                                        self.peers_by_index.remove(&(tid, idx.as_u32()));
                                    }
                                    let _ = self.index_allocator.free(idx);
                                }
                            }
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
                        }
                    }
                }

                self.pending_outbound.remove(&key);
                return;
            }

            // Not a rekey — stale pending_outbound entry
            self.pending_outbound.remove(&key);
            return;
        }

        let (peer_identity, msg3_bytes, our_index) = {
            let Some(conn) = self.connections.get_mut(&link_id) else {
                warn!(link_id = %link_id, "Connection removed during msg2 processing");
                self.pending_outbound.remove(&key);
                return;
            };

            // Create FMP negotiation payload for msg3 (includes profile, MMP bits, bloom TLV)
            let neg_payload = NegotiationPayload::fmp(1, 1, self.node_profile).encode();

            // Process Noise msg2 and generate msg3
            let noise_msg2 = &packet.data[header.noise_msg2_offset..];
            let (msg3_bytes, received_negotiation) = match conn.complete_handshake(
                noise_msg2,
                Some(&neg_payload),
                packet.timestamp_ms,
            ) {
                Ok(result) => result,
                Err(e) => {
                    warn!(
                        link_id = %link_id,
                        error = %e,
                        "Handshake completion failed"
                    );
                    conn.mark_failed();
                    return;
                }
            };

            // Process peer's FMP negotiation payload from msg2
            if let Some(neg_bytes) = &received_negotiation {
                match process_fmp_negotiation(self.node_profile, conn, neg_bytes) {
                    Ok(()) => {}
                    Err(e) => {
                        warn!(link_id = %link_id, our_profile = %self.node_profile, error = %e, "FMP negotiation failed");
                        conn.mark_failed();
                        return;
                    }
                }
            }

            // Store their index
            conn.set_their_index(header.sender_idx);
            conn.set_source_addr(packet.remote_addr.clone());

            // Get peer identity for promotion (learned from msg2 in XX)
            let peer_identity = match conn.expected_identity() {
                Some(id) => *id,
                None => {
                    warn!(link_id = %link_id, "No identity after handshake");
                    return;
                }
            };

            let our_index = conn.our_index();

            (peer_identity, msg3_bytes, our_index)
        };

        let peer_node_addr = *peer_identity.node_addr();

        // ACL check: with XX, this is the first point where the initiator
        // knows the responder's identity.
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
            self.connections.remove(&link_id);
            self.remove_link(&link_id);
            return;
        }

        if peer_node_addr == *self.identity.node_addr() {
            debug!(link_id = %link_id, "Discovered self via shared-media beacon, dropping");
            self.connections.remove(&link_id);
            return;
        }

        // Build and send msg3
        let our_index = our_index.unwrap_or(header.receiver_idx);
        let wire_msg3 = build_msg3(our_index, header.sender_idx, &msg3_bytes);

        if let Some(transport) = self.transports.get(&packet.transport_id) {
            match transport.send(&packet.remote_addr, &wire_msg3).await {
                Ok(bytes) => {
                    debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        link_id = %link_id,
                        their_index = %header.sender_idx,
                        bytes,
                        "Sent msg3, outbound handshake completing"
                    );
                }
                Err(e) => {
                    warn!(
                        link_id = %link_id,
                        error = %e,
                        "Failed to send msg3"
                    );
                    if let Some(conn) = self.connections.get_mut(&link_id) {
                        conn.mark_failed();
                    }
                    return;
                }
            }
        }

        debug!(
            peer = %self.peer_display_name(&peer_node_addr),
            link_id = %link_id,
            their_index = %header.sender_idx,
            "Outbound handshake completed"
        );

        // Cross-connection resolution: if the peer was already promoted via
        // our inbound handshake (we processed their msg3), both nodes initially
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

                let (outbound_session, outbound_our_index) = match (
                    outbound_session,
                    outbound_our_index,
                ) {
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
                    let Some(transport_id) = peer.transport_id() else {
                        warn!(peer = %self.peer_display_name(&peer_node_addr), "Active peer missing transport_id during cross-connection");
                        self.pending_outbound.remove(&key);
                        return;
                    };
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
            self.reset_discovery_backoff();
            return;
        }

        // Normal path: promote to active peer
        debug!(
            peer = %self.peer_display_name(&peer_node_addr),
            link_id = %link_id,
            "handle_msg2: promoting outbound, peers_has_key={}",
            self.peers.contains_key(&peer_node_addr),
        );
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
                        self.reset_discovery_backoff();
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
                        self.reset_discovery_backoff();
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
            }
        }
    }

    /// Handle handshake message 3 (phase 0x3).
    ///
    /// Completes the XX handshake on the responder side. Processes msg3 to
    /// learn the initiator's identity and epoch, then performs identity-based
    /// checks (restart detection, rekey detection, cross-connection resolution)
    /// and promotes the connection to active peer.
    pub(in crate::node) async fn handle_msg3(&mut self, packet: ReceivedPacket) {
        // Parse header
        let header = match Msg3Header::parse(&packet.data) {
            Some(h) => h,
            None => {
                debug!("Invalid msg3 header");
                return;
            }
        };

        // Look up our pending inbound handshake by our index (receiver_idx in msg3)
        let key = (packet.transport_id, header.receiver_idx.as_u32());
        let link_id = match self.pending_inbound.remove(&key) {
            Some(id) => id,
            None => {
                // Check if this is a rekey msg3 for an active peer
                self.handle_rekey_msg3(&packet, &header).await;
                return;
            }
        };

        let (peer_identity, our_index, remote_epoch) = {
            // Get the pending connection
            let conn = match self.connections.get_mut(&link_id) {
                Some(c) => c,
                None => {
                    debug!(
                        link_id = %link_id,
                        "No pending connection for msg3"
                    );
                    return;
                }
            };

            // Process msg3 — learns initiator's identity and epoch
            let noise_msg3 = &packet.data[header.noise_msg3_offset..];
            let received_negotiation = match conn
                .complete_handshake_msg3(noise_msg3, packet.timestamp_ms)
            {
                Ok(neg) => neg,
                Err(e) => {
                    warn!(
                        link_id = %link_id,
                        error = %e,
                        "Msg3 processing failed"
                    );
                    // Clean up
                    self.connections.remove(&link_id);
                    self.remove_link(&link_id);
                    if let Some(idx) = self.connections.get(&link_id).and_then(|c| c.our_index()) {
                        let _ = self.index_allocator.free(idx);
                    }
                    return;
                }
            };

            // Process peer's FMP negotiation payload from msg3
            if let Some(neg_bytes) = &received_negotiation {
                match process_fmp_negotiation(self.node_profile, conn, neg_bytes) {
                    Ok(()) => {}
                    Err(e) => {
                        warn!(link_id = %link_id, our_profile = %self.node_profile, error = %e, "FMP negotiation failed");
                        self.connections.remove(&link_id);
                        self.remove_link(&link_id);
                        return;
                    }
                }
            }

            // Learn peer identity from msg3
            let peer_identity = match conn.expected_identity() {
                Some(id) => *id,
                None => {
                    warn!("Identity not learned from msg3");
                    self.connections.remove(&link_id);
                    self.remove_link(&link_id);
                    return;
                }
            };

            let our_index = conn.our_index();
            let remote_epoch = conn.remote_epoch();

            (peer_identity, our_index, remote_epoch)
        };

        let peer_node_addr = *peer_identity.node_addr();

        // ACL check: with XX, this is the first point where the responder
        // knows the initiator's identity.
        if self
            .authorize_peer(
                &peer_identity,
                PeerAclContext::InboundHandshake,
                packet.transport_id,
                &packet.remote_addr,
            )
            .is_err()
        {
            // Notify the initiator via encrypted Disconnect so they clean
            // up without waiting for link-dead timeout. The Noise session
            // is fully established at this point (msg3 just succeeded),
            // and the initiator has a matching session from processing
            // msg2. Reason `Other` is used instead of `SecurityViolation`
            // to avoid naming the ACL mechanism on the wire.
            let reject_info = match self.connections.get_mut(&link_id) {
                Some(conn) => match (conn.their_index(), conn.take_session()) {
                    (Some(idx), Some(session)) => Some((idx, session)),
                    _ => None,
                },
                None => None,
            };
            if let Some((their_idx, mut session)) = reject_info {
                let payload = Disconnect::new(DisconnectReason::Other).encode();
                let _ = self
                    .send_encrypted_link_message_raw(
                        peer_node_addr,
                        packet.transport_id,
                        &packet.remote_addr,
                        &mut session,
                        their_idx,
                        &payload,
                    )
                    .await;
            }
            self.connections.remove(&link_id);
            self.remove_link(&link_id);
            return;
        }

        if peer_node_addr == *self.identity.node_addr() {
            debug!(link_id = %link_id, "Received msg3 from self, dropping");
            self.connections.remove(&link_id);
            self.remove_link(&link_id);
            return;
        }

        let our_index = our_index.unwrap_or(header.receiver_idx);

        // Identity-based restart/rekey detection.
        //
        // Now that we know the initiator's identity from msg3, perform the
        // same checks that the old handle_msg1 used to do after decrypting msg1.
        if let Some(existing_peer) = self.peers.get(&peer_node_addr) {
            let new_epoch = remote_epoch;
            let existing_epoch = existing_peer.remote_epoch();

            match (existing_epoch, new_epoch) {
                (Some(existing), Some(new)) if existing != new => {
                    // Epoch mismatch — peer restarted. Tear down stale session.
                    info!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        "Peer restart detected (epoch mismatch), removing stale session"
                    );
                    self.remove_active_peer(&peer_node_addr);
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    self.schedule_reconnect(peer_node_addr, now_ms);
                    // Fall through to process as new connection
                }
                _ => {
                    // Same epoch (or no epoch stored).
                    // Check for rekey: session must be at least 30s old.
                    let session_age_secs =
                        existing_peer.session_established_at().elapsed().as_secs();
                    if self.config.node.rekey.enabled
                        && existing_peer.has_session()
                        && existing_peer.is_healthy()
                        && session_age_secs >= 30
                    {
                        // Guard: already have a pending session from a completed
                        // rekey (waiting for K-bit cutover). Don't overwrite.
                        if existing_peer.pending_new_session().is_some() {
                            debug!(
                                peer = %self.peer_display_name(&peer_node_addr),
                                "Rekey msg3 received but already have pending session, dropping"
                            );
                            self.connections.remove(&link_id);
                            self.links.remove(&link_id);
                            return;
                        }

                        // Dual-initiation detection: both sides sent msg1
                        // simultaneously. Apply tie-breaker.
                        if existing_peer.rekey_in_progress() {
                            let our_addr = self.identity.node_addr();
                            if our_addr < &peer_node_addr {
                                // We win as initiator — drop their msg3/handshake.
                                debug!(
                                    peer = %self.peer_display_name(&peer_node_addr),
                                    "Dual rekey initiation: we win (smaller addr), dropping their msg3"
                                );
                                self.connections.remove(&link_id);
                                self.links.remove(&link_id);
                                return;
                            }
                            // We lose — abandon our rekey, become responder below.
                            debug!(
                                peer = %self.peer_display_name(&peer_node_addr),
                                "Dual rekey initiation: we lose (larger addr), abandoning ours"
                            );
                            if let Some(peer) = self.peers.get_mut(&peer_node_addr)
                                && let Some(idx) = peer.abandon_rekey()
                            {
                                if let Some(tid) = peer.transport_id() {
                                    self.peers_by_index.remove(&(tid, idx.as_u32()));
                                    self.pending_outbound.remove(&(tid, idx.as_u32()));
                                }
                                let _ = self.index_allocator.free(idx);
                            }
                            // Fall through to respond as responder
                        }

                        // Rekey: process as responder, store new session as pending
                        let noise_session = {
                            let Some(conn) = self.connections.get_mut(&link_id) else {
                                warn!(link_id = %link_id, "Connection removed during rekey msg3 processing");
                                self.links.remove(&link_id);
                                return;
                            };
                            conn.take_session()
                        };
                        let our_new_index = our_index;

                        let noise_session = match noise_session {
                            Some(s) => s,
                            None => {
                                warn!("Rekey msg3: no session from handshake");
                                self.connections.remove(&link_id);
                                self.links.remove(&link_id);
                                return;
                            }
                        };

                        // Store pending session on the existing peer
                        if let Some(peer) = self.peers.get_mut(&peer_node_addr) {
                            peer.set_pending_session(
                                noise_session,
                                our_new_index,
                                header.sender_idx,
                            );
                            peer.record_peer_rekey();
                        }

                        // Register new index in peers_by_index
                        self.peers_by_index.insert(
                            (packet.transport_id, our_new_index.as_u32()),
                            peer_node_addr,
                        );

                        // Clean up: remove the temporary connection/link.
                        // Do NOT remove addr_to_link — the entry must remain pointing
                        // to the original link.
                        self.connections.remove(&link_id);
                        self.links.remove(&link_id);

                        debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            new_our_index = %our_new_index,
                            "Rekey completed (responder), pending K-bit cutover"
                        );
                        return;
                    }

                    // Not a rekey — duplicate handshake from same epoch.
                    // Resend stored msg2.
                    if let Some(msg2) = existing_peer.handshake_msg2().map(|m| m.to_vec())
                        && let Some(transport) = self.transports.get(&packet.transport_id)
                    {
                        match transport.send(&packet.remote_addr, &msg2).await {
                            Ok(_) => debug!(
                                peer = %self.peer_display_name(&peer_node_addr),
                                "Resent msg2 for duplicate handshake (same epoch)"
                            ),
                            Err(e) => debug!(
                                peer = %self.peer_display_name(&peer_node_addr),
                                error = %e,
                                "Failed to resend msg2"
                            ),
                        }
                    }
                    self.connections.remove(&link_id);
                    self.links.remove(&link_id);
                    return;
                }
            }
        }

        // Promote the connection to active peer.
        let wire_msg2 = self
            .connections
            .get(&link_id)
            .and_then(|c| c.handshake_msg2().map(|m| m.to_vec()));

        debug!(
            peer = %self.peer_display_name(&peer_node_addr),
            link_id = %link_id,
            our_index = %our_index,
            "handle_msg3: promoting inbound, peers_has_key={}",
            self.peers.contains_key(&peer_node_addr),
        );
        match self.promote_connection(link_id, peer_identity, packet.timestamp_ms) {
            Ok(result) => {
                match result {
                    PromotionResult::Promoted(node_addr) => {
                        // Store msg2 on peer for resend on duplicate msg1
                        if let (Some(peer), Some(msg2)) =
                            (self.peers.get_mut(&node_addr), wire_msg2)
                        {
                            peer.set_handshake_msg2(msg2);
                        }
                        debug!(
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
                        self.reset_discovery_backoff();
                    }
                    PromotionResult::CrossConnectionWon {
                        loser_link_id,
                        node_addr,
                    } => {
                        // Store msg2 on peer for resend on duplicate msg1
                        if let (Some(peer), Some(msg2)) =
                            (self.peers.get_mut(&node_addr), wire_msg2)
                        {
                            peer.set_handshake_msg2(msg2);
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
                        if let Err(e) = self.send_tree_announce_to_peer(&node_addr).await {
                            debug!(peer = %self.peer_display_name(&node_addr), error = %e, "Failed to send initial TreeAnnounce");
                        }
                        self.bloom_state.mark_update_needed(node_addr);
                        self.reset_discovery_backoff();
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
            }
        }
    }

    /// Handle a rekey msg3 for an already-active peer.
    ///
    /// When a rekey is in progress (responder side), the ActivePeer holds the
    /// handshake state. This processes msg3 to complete the rekey responder
    /// handshake.
    async fn handle_rekey_msg3(&mut self, packet: &ReceivedPacket, header: &Msg3Header) {
        // Look for a peer expecting a rekey msg3 as responder.
        // The responder's rekey handshake state is stored after processing
        // the initiator's rekey msg1+msg2 exchange via the existing link.
        let peer_addr = self.peers.iter().find_map(|(addr, peer)| {
            if peer.has_rekey_responder_handshake()
                && peer.rekey_responder_our_index() == Some(header.receiver_idx)
            {
                Some(*addr)
            } else {
                None
            }
        });

        let peer_node_addr = match peer_addr {
            Some(addr) => addr,
            None => {
                debug!(
                    receiver_idx = %header.receiver_idx,
                    "No pending inbound or rekey state for msg3"
                );
                return;
            }
        };

        let display_name = self.peer_display_name(&peer_node_addr);
        let noise_msg3 = &packet.data[header.noise_msg3_offset..];

        if let Some(peer) = self.peers.get_mut(&peer_node_addr) {
            match peer.complete_rekey_msg3(noise_msg3) {
                Ok(session) => {
                    let our_index = peer
                        .rekey_responder_our_index()
                        .unwrap_or(header.receiver_idx);
                    peer.set_pending_session(session, our_index, header.sender_idx);
                    peer.record_peer_rekey();

                    if let Some(transport_id) = peer.transport_id() {
                        self.peers_by_index
                            .insert((transport_id, our_index.as_u32()), peer_node_addr);
                    }

                    debug!(
                        peer = %display_name,
                        new_our_index = %our_index,
                        "Rekey msg3 completed (responder), pending K-bit cutover"
                    );
                }
                Err(e) => {
                    warn!(
                        peer = %display_name,
                        error = %e,
                        "Rekey msg3 processing failed"
                    );
                    peer.clear_rekey_responder();
                }
            }
        }
    }

    /// Promote a connection to active peer after successful authentication.
    ///
    /// Handles cross-connection detection and resolution using tie-breaker rules.
    /// Leaf nodes enforce single-peer constraint.
    pub(in crate::node) fn promote_connection(
        &mut self,
        link_id: LinkId,
        verified_identity: PeerIdentity,
        current_time_ms: u64,
    ) -> Result<PromotionResult, NodeError> {
        // Leaf nodes: reject if we already have a peer (single-peer enforcement)
        let peer_node_addr_check = *verified_identity.node_addr();
        if self.node_profile == crate::protocol::NodeProfile::Leaf
            && !self.peers.is_empty()
            && !self.peers.contains_key(&peer_node_addr_check)
        {
            info!(
                peer = %self.peer_display_name(&peer_node_addr_check),
                link_id = %link_id,
                "Leaf node rejecting additional peer (single-peer enforcement)"
            );
            // Clean up the connection
            if let Some(conn) = self.connections.remove(&link_id)
                && let Some(idx) = conn.our_index()
            {
                let _ = self.index_allocator.free(idx);
            }
            self.remove_link(&link_id);
            return Err(NodeError::MaxPeersExceeded { max: 1 });
        }

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
        let peer_profile = connection
            .peer_profile()
            .unwrap_or(crate::protocol::NodeProfile::Full);

        let peer_node_addr = *verified_identity.node_addr();
        let is_outbound = connection.is_outbound();

        // Check for cross-connection
        if let Some(existing_peer) = self.peers.get(&peer_node_addr) {
            let existing_link_id = existing_peer.link_id();

            // Determine which connection wins
            let this_wins =
                cross_connection_winner(self.identity.node_addr(), &peer_node_addr, is_outbound);

            if this_wins {
                // This connection wins, replace the existing peer
                let Some(old_peer) = self.peers.remove(&peer_node_addr) else {
                    return Err(NodeError::PeerNotFound(peer_node_addr));
                };
                let loser_link_id = old_peer.link_id();

                // Clean up old peer's index from peers_by_index
                if let (Some(old_tid), Some(old_idx)) =
                    (old_peer.transport_id(), old_peer.our_index())
                {
                    self.peers_by_index.remove(&(old_tid, old_idx.as_u32()));
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
                    self.node_profile,
                    peer_profile,
                );
                new_peer.set_tree_announce_min_interval_ms(
                    self.config.node.tree.announce_min_interval_ms,
                );

                self.peers.insert(peer_node_addr, new_peer);
                self.peers_by_index
                    .insert((transport_id, our_index.as_u32()), peer_node_addr);
                self.retry_pending.remove(&peer_node_addr);
                self.register_identity(peer_node_addr, verified_identity.pubkey_full());

                // Non-routing peers don't send filters; include them as
                // dependents so our bloom filter advertises their identity.
                if peer_profile != crate::protocol::NodeProfile::Full {
                    self.bloom_state.add_leaf_dependent(peer_node_addr);
                }

                debug!(
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
            if self.max_peers > 0 && self.peers.len() >= self.max_peers {
                let _ = self.index_allocator.free(our_index);
                return Err(NodeError::MaxPeersExceeded {
                    max: self.max_peers,
                });
            }

            // Preserve tree announce rate-limit state from old peer (if reconnecting).
            // Without this, reconnection resets the rate limit window to zero,
            // allowing an immediate announce that can feed an announce loop.
            let old_announce_ts = self
                .peers
                .get(&peer_node_addr)
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
                self.node_profile,
                peer_profile,
            );
            new_peer
                .set_tree_announce_min_interval_ms(self.config.node.tree.announce_min_interval_ms);
            if let Some(ts) = old_announce_ts {
                new_peer.set_last_tree_announce_sent_ms(ts);
            }

            self.peers.insert(peer_node_addr, new_peer);
            self.peers_by_index
                .insert((transport_id, our_index.as_u32()), peer_node_addr);
            self.retry_pending.remove(&peer_node_addr);
            self.register_identity(peer_node_addr, verified_identity.pubkey_full());

            // Non-routing peers don't send filters; include them as
            // dependents so our bloom filter advertises their identity.
            if peer_profile != crate::protocol::NodeProfile::Full {
                self.bloom_state.add_leaf_dependent(peer_node_addr);
            }

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

/// Process an FMP negotiation payload received from a peer.
///
/// Decodes the payload, validates profile pairing, and stores the
/// results on the PeerConnection.
fn process_fmp_negotiation(
    our_profile: crate::protocol::NodeProfile,
    conn: &mut PeerConnection,
    neg_bytes: &[u8],
) -> Result<(), crate::protocol::ProtocolError> {
    let their_payload = NegotiationPayload::decode(neg_bytes)?;

    // Validate profile pairing (at least one Full)
    let their_profile = their_payload.node_profile()?;
    NegotiationPayload::validate_profiles(our_profile, their_profile)?;

    conn.set_negotiation_results(their_profile);

    debug!(
        link_id = %conn.link_id(),
        our_profile = %our_profile,
        peer_profile = %their_profile,
        "FMP negotiation complete"
    );

    Ok(())
}
