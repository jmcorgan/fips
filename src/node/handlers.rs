//! RX event loop and message handlers.

use super::*;

impl Node {
    // === RX Event Loop ===

    /// Run the receive event loop.
    ///
    /// Processes packets from all transports, dispatching based on
    /// the discriminator byte in the wire protocol:
    /// - 0x00: Encrypted frame (session data)
    /// - 0x01: Handshake message 1 (initiator -> responder)
    /// - 0x02: Handshake message 2 (responder -> initiator)
    ///
    /// This method takes ownership of the packet_rx channel and runs
    /// until the channel is closed (typically when stop() is called).
    pub async fn run_rx_loop(&mut self) -> Result<(), NodeError> {
        let mut packet_rx = self.packet_rx.take()
            .ok_or(NodeError::NotStarted)?;

        info!("RX event loop started");

        while let Some(packet) = packet_rx.recv().await {
            self.process_packet(packet).await;
        }

        info!("RX event loop stopped (channel closed)");
        Ok(())
    }

    /// Process a single received packet.
    ///
    /// Dispatches based on the discriminator byte.
    async fn process_packet(&mut self, packet: ReceivedPacket) {
        if packet.data.is_empty() {
            return; // Drop empty packets
        }

        let discriminator = packet.data[0];
        match discriminator {
            DISCRIMINATOR_ENCRYPTED => {
                self.handle_encrypted_frame(packet).await;
            }
            DISCRIMINATOR_MSG1 => {
                self.handle_msg1(packet).await;
            }
            DISCRIMINATOR_MSG2 => {
                self.handle_msg2(packet).await;
            }
            _ => {
                // Unknown discriminator, drop silently
                debug!(
                    discriminator = discriminator,
                    transport_id = %packet.transport_id,
                    "Unknown packet discriminator, dropping"
                );
            }
        }
    }

    /// Handle an encrypted frame (discriminator 0x00).
    ///
    /// This is the hot path for established sessions. We use O(1)
    /// index-based lookup to find the session, then decrypt.
    pub(super) async fn handle_encrypted_frame(&mut self, packet: ReceivedPacket) {
        // Parse header (fail fast)
        let header = match EncryptedHeader::parse(&packet.data) {
            Some(h) => h,
            None => return, // Malformed, drop silently
        };

        // O(1) session lookup by our receiver index
        let key = (packet.transport_id, header.receiver_idx.as_u32());
        let node_addr = match self.peers_by_index.get(&key) {
            Some(id) => *id,
            None => {
                // Unknown index - could be stale session or attack
                debug!(
                    receiver_idx = %header.receiver_idx,
                    transport_id = %packet.transport_id,
                    "Unknown session index, dropping"
                );
                return;
            }
        };

        let peer = match self.peers.get_mut(&node_addr) {
            Some(p) => p,
            None => {
                // Peer removed but index not cleaned up - fix it
                self.peers_by_index.remove(&key);
                return;
            }
        };

        // Get the session (peer must have one for index-based lookup)
        let session = match peer.noise_session_mut() {
            Some(s) => s,
            None => {
                warn!(
                    node_addr = %node_addr,
                    "Peer in index map has no session"
                );
                return;
            }
        };

        // Decrypt with replay check (this is the expensive part)
        let ciphertext = &packet.data[header.ciphertext_offset..];
        let plaintext = match session.decrypt_with_replay_check(ciphertext, header.counter) {
            Ok(p) => p,
            Err(e) => {
                debug!(
                    node_addr = %node_addr,
                    counter = header.counter,
                    error = %e,
                    "Decryption failed"
                );
                return;
            }
        };

        // === PACKET IS AUTHENTIC ===

        // Update address for roaming support
        peer.set_current_addr(packet.transport_id, packet.remote_addr.clone());

        // Update statistics
        peer.link_stats_mut().record_recv(packet.data.len(), packet.timestamp_ms);
        peer.touch(packet.timestamp_ms);

        // Dispatch to link message handler
        self.dispatch_link_message(&node_addr, &plaintext).await;
    }

    /// Handle handshake message 1 (discriminator 0x01).
    ///
    /// This creates a new inbound connection. Rate limiting is applied
    /// before any expensive crypto operations.
    pub(super) async fn handle_msg1(&mut self, packet: ReceivedPacket) {
        // === RATE LIMITING (before any processing) ===
        if !self.msg1_rate_limiter.start_handshake() {
            debug!(
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                "Msg1 rate limited"
            );
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

        // Check for existing connection from this address
        let addr_key = (packet.transport_id, packet.remote_addr.clone());
        if self.addr_to_link.contains_key(&addr_key) {
            self.msg1_rate_limiter.complete_handshake();
            debug!(
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                "Already have connection from this address"
            );
            return;
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
        let msg2_response = match conn.receive_handshake_init(our_keypair, noise_msg1, packet.timestamp_ms) {
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
            Some(id) => id.clone(),
            None => {
                self.msg1_rate_limiter.complete_handshake();
                warn!("Identity not learned from msg1");
                return;
            }
        };

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
            Duration::from_millis(100),
        );

        self.links.insert(link_id, link);
        self.addr_to_link.insert(addr_key, link_id);
        self.connections.insert(link_id, conn);

        // Build and send msg2 response
        let wire_msg2 = build_msg2(our_index, header.sender_idx, &msg2_response);

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
                        info!(
                            node_addr = %node_addr,
                            link_id = %link_id,
                            our_index = %our_index,
                            "Inbound peer promoted to active"
                        );
                    }
                    PromotionResult::CrossConnectionWon { loser_link_id, node_addr } => {
                        info!(
                            node_addr = %node_addr,
                            loser_link_id = %loser_link_id,
                            "Inbound cross-connection won"
                        );
                    }
                    PromotionResult::CrossConnectionLost { winner_link_id } => {
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
                self.links.remove(&link_id);
                self.addr_to_link
                    .remove(&(packet.transport_id, packet.remote_addr));
                let _ = self.index_allocator.free(our_index);
            }
        }

        self.msg1_rate_limiter.complete_handshake();
    }

    /// Handle handshake message 2 (discriminator 0x02).
    ///
    /// This completes an outbound handshake we initiated.
    pub(super) async fn handle_msg2(&mut self, packet: ReceivedPacket) {
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
            Some(id) => id.clone(),
            None => {
                warn!(link_id = %link_id, "No identity after handshake");
                return;
            }
        };

        info!(
            node_addr = %peer_identity.node_addr(),
            link_id = %link_id,
            their_index = %header.sender_idx,
            "Outbound handshake completed"
        );

        // Promote to active peer (TODO: implement with session transfer)
        // For now, just use the existing promote_connection
        match self.promote_connection(link_id, peer_identity.clone(), packet.timestamp_ms) {
            Ok(result) => {
                // Clean up pending_outbound
                self.pending_outbound.remove(&key);

                match result {
                    PromotionResult::Promoted(node_addr) => {
                        info!(
                            node_addr = %node_addr,
                            "Peer promoted to active"
                        );
                    }
                    PromotionResult::CrossConnectionWon { loser_link_id, node_addr } => {
                        info!(
                            node_addr = %node_addr,
                            loser_link_id = %loser_link_id,
                            "Cross-connection won"
                        );
                    }
                    PromotionResult::CrossConnectionLost { winner_link_id } => {
                        info!(
                            winner_link_id = %winner_link_id,
                            "Cross-connection lost"
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
    pub(super) fn promote_connection(
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

                let new_peer = ActivePeer::with_session(
                    verified_identity,
                    link_id,
                    current_time_ms,
                    noise_session,
                    our_index,
                    their_index,
                    transport_id,
                    current_addr,
                    link_stats,
                );

                self.peers.insert(peer_node_addr, new_peer);
                self.peers_by_index
                    .insert((transport_id, our_index.as_u32()), peer_node_addr);

                info!(
                    node_addr = %peer_node_addr,
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
                    node_addr = %peer_node_addr,
                    winner_link = %existing_link_id,
                    loser_link = %link_id,
                    "Cross-connection resolved: this connection lost"
                );

                Ok(PromotionResult::CrossConnectionLost {
                    winner_link_id: existing_link_id,
                })
            }
        } else {
            // No cross-connection, normal promotion
            if self.max_peers > 0 && self.peers.len() >= self.max_peers {
                let _ = self.index_allocator.free(our_index);
                return Err(NodeError::MaxPeersExceeded { max: self.max_peers });
            }

            let new_peer = ActivePeer::with_session(
                verified_identity,
                link_id,
                current_time_ms,
                noise_session,
                our_index,
                their_index,
                transport_id,
                current_addr,
                link_stats,
            );

            self.peers.insert(peer_node_addr, new_peer);
            self.peers_by_index
                .insert((transport_id, our_index.as_u32()), peer_node_addr);

            info!(
                node_addr = %peer_node_addr,
                link_id = %link_id,
                our_index = %our_index,
                their_index = %their_index,
                "Connection promoted to active peer"
            );

            Ok(PromotionResult::Promoted(peer_node_addr))
        }
    }

    /// Dispatch a decrypted link message to the appropriate handler.
    ///
    /// Link messages are protocol messages exchanged between authenticated peers.
    async fn dispatch_link_message(&mut self, _from: &NodeAddr, plaintext: &[u8]) {
        if plaintext.is_empty() {
            return;
        }

        let msg_type = plaintext[0];
        let _payload = &plaintext[1..];

        // TODO: Implement link message handlers
        match msg_type {
            0x10 => {
                // TreeAnnounce
                debug!("Received TreeAnnounce (not yet implemented)");
            }
            0x20 => {
                // FilterAnnounce
                debug!("Received FilterAnnounce (not yet implemented)");
            }
            0x30 => {
                // LookupRequest
                debug!("Received LookupRequest (not yet implemented)");
            }
            0x31 => {
                // LookupResponse
                debug!("Received LookupResponse (not yet implemented)");
            }
            0x40 => {
                // SessionDatagram
                debug!("Received SessionDatagram (not yet implemented)");
            }
            _ => {
                debug!(msg_type = msg_type, "Unknown link message type");
            }
        }
    }
}
