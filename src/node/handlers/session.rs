//! End-to-end session message handlers.
//!
//! Handles locally-delivered session payloads from SessionDatagram envelopes.
//! Dispatches based on session message type to specific handlers for
//! SessionSetup (Noise IK msg1), SessionAck (msg2), DataPacket, and
//! error signals (CoordsRequired, PathBroken).

use crate::node::session::{EndToEndState, SessionEntry};
use crate::node::{Node, NodeError};
use crate::noise::{HandshakeState, HANDSHAKE_MSG1_SIZE, HANDSHAKE_MSG2_SIZE};
use crate::protocol::{
    CoordsRequired, DataPacket, PathBroken, SessionAck, SessionDatagram, SessionMessageType,
    SessionSetup,
};
use crate::NodeAddr;
use secp256k1::PublicKey;
use tracing::debug;

impl Node {
    /// Handle a locally-delivered session datagram payload.
    ///
    /// Called from `handle_session_datagram()` when `dest_addr == self.node_addr()`.
    /// Dispatches to the appropriate handler based on the session message type byte.
    pub(in crate::node) async fn handle_session_payload(
        &mut self,
        src_addr: &NodeAddr,
        payload: &[u8],
    ) {
        if payload.is_empty() {
            debug!("Empty session payload");
            return;
        }

        let msg_type = payload[0];
        let inner = &payload[1..];

        match SessionMessageType::from_byte(msg_type) {
            Some(SessionMessageType::SessionSetup) => {
                self.handle_session_setup(src_addr, inner).await;
            }
            Some(SessionMessageType::SessionAck) => {
                self.handle_session_ack(src_addr, inner).await;
            }
            Some(SessionMessageType::DataPacket) => {
                self.handle_data_packet(src_addr, inner).await;
            }
            Some(SessionMessageType::CoordsRequired) => {
                self.handle_coords_required(inner).await;
            }
            Some(SessionMessageType::PathBroken) => {
                self.handle_path_broken(inner);
            }
            None => {
                debug!(msg_type, "Unknown session message type");
            }
        }
    }

    /// Handle an incoming SessionSetup (Noise IK msg1).
    ///
    /// The remote node wants to establish an end-to-end session with us.
    /// We create a responder handshake, process msg1, send SessionAck with msg2.
    async fn handle_session_setup(&mut self, src_addr: &NodeAddr, inner: &[u8]) {
        let setup = match SessionSetup::decode(inner) {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "Malformed SessionSetup");
                return;
            }
        };

        if setup.handshake_payload.len() != HANDSHAKE_MSG1_SIZE {
            debug!(
                len = setup.handshake_payload.len(),
                expected = HANDSHAKE_MSG1_SIZE,
                "Invalid handshake payload size in SessionSetup"
            );
            return;
        }

        // Check for existing session with this remote
        if let Some(existing) = self.sessions.get(src_addr) {
            match existing.state() {
                EndToEndState::Initiating(_) => {
                    // Simultaneous initiation: smaller NodeAddr wins as initiator
                    if self.identity.node_addr() < src_addr {
                        // We win — drop their setup, they'll process ours
                        debug!(
                            src = %src_addr,
                            "Simultaneous session initiation: we win (smaller addr), dropping their setup"
                        );
                        return;
                    }
                    // We lose — discard our pending handshake, become responder below
                    debug!(
                        src = %src_addr,
                        "Simultaneous session initiation: we lose, becoming responder"
                    );
                }
                EndToEndState::Responding(_) => {
                    // Duplicate setup while we already responded — drop
                    debug!(src = %src_addr, "Duplicate SessionSetup, already responding");
                    return;
                }
                EndToEndState::Established(_) => {
                    // Re-establishment: replace existing session below
                    debug!(src = %src_addr, "Session re-establishment from peer");
                }
            }
        }

        // Create responder handshake and process msg1
        let our_keypair = self.identity.keypair();
        let mut handshake = HandshakeState::new_responder(our_keypair);

        if let Err(e) = handshake.read_message_1(&setup.handshake_payload) {
            debug!(error = %e, "Failed to process Noise IK msg1 in SessionSetup");
            return;
        }

        // Extract the initiator's static public key (learned from msg1)
        let remote_pubkey = match handshake.remote_static() {
            Some(pk) => *pk,
            None => {
                debug!("No remote static key after processing msg1");
                return;
            }
        };

        // Register the initiator's identity for future TUN → session routing
        self.register_identity(*src_addr, remote_pubkey);

        // Generate msg2
        let msg2 = match handshake.write_message_2() {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Failed to generate Noise IK msg2 for SessionAck");
                return;
            }
        };

        // Build and send SessionAck
        let our_coords = self.tree_state.my_coords().clone();
        let ack = SessionAck::new(our_coords).with_handshake(msg2);
        let my_addr = *self.node_addr();
        let datagram = SessionDatagram::new(my_addr, *src_addr, ack.encode())
            .with_hop_limit(self.config.node.session.default_hop_limit);

        // Route the ack back to the initiator
        if let Err(e) = self.send_session_datagram(&datagram).await {
            debug!(error = %e, dest = %src_addr, "Failed to send SessionAck");
            return;
        }

        // Store session entry in Responding state
        let now_ms = Self::now_ms();
        let entry = SessionEntry::new(*src_addr, remote_pubkey, EndToEndState::Responding(handshake), now_ms);
        self.sessions.insert(*src_addr, entry);

        debug!(src = %src_addr, "SessionSetup processed, SessionAck sent");
    }

    /// Handle an incoming SessionAck (Noise IK msg2).
    ///
    /// Completes our initiated handshake, transitions to Established.
    async fn handle_session_ack(&mut self, src_addr: &NodeAddr, inner: &[u8]) {
        let ack = match SessionAck::decode(inner) {
            Ok(a) => a,
            Err(e) => {
                debug!(error = %e, "Malformed SessionAck");
                return;
            }
        };

        if ack.handshake_payload.len() != HANDSHAKE_MSG2_SIZE {
            debug!(
                len = ack.handshake_payload.len(),
                expected = HANDSHAKE_MSG2_SIZE,
                "Invalid handshake payload size in SessionAck"
            );
            return;
        }

        // Remove the entry to take ownership of the handshake state
        let mut entry = match self.sessions.remove(src_addr) {
            Some(e) => e,
            None => {
                debug!(src = %src_addr, "SessionAck for unknown session");
                return;
            }
        };

        // Must be in Initiating state
        let handshake = match entry.take_state() {
            Some(EndToEndState::Initiating(hs)) => hs,
            _ => {
                debug!(src = %src_addr, "SessionAck but session not in Initiating state");
                // Put it back
                self.sessions.insert(*src_addr, entry);
                return;
            }
        };

        // Complete the handshake
        let session = match Self::complete_initiator_handshake(handshake, &ack.handshake_payload) {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "Failed to complete session handshake");
                return; // Entry was already removed, don't put back a broken session
            }
        };

        entry.set_state(EndToEndState::Established(session));
        entry.touch(Self::now_ms());
        self.sessions.insert(*src_addr, entry);

        // Cache the responder's coordinates
        let now_ms = Self::now_ms();
        self.coord_cache.insert(*src_addr, ack.src_coords, now_ms);

        // Flush any queued outbound packets for this destination
        self.flush_pending_packets(src_addr).await;

        debug!(src = %src_addr, "Session established (initiator)");
    }

    /// Complete an initiator-side Noise IK handshake given msg2.
    fn complete_initiator_handshake(
        mut handshake: HandshakeState,
        msg2: &[u8],
    ) -> Result<crate::noise::NoiseSession, String> {
        handshake
            .read_message_2(msg2)
            .map_err(|e| format!("read_message_2 failed: {}", e))?;
        handshake
            .into_session()
            .map_err(|e| format!("into_session failed: {}", e))
    }

    /// Handle an incoming DataPacket.
    ///
    /// Decrypts the payload using the established session key and delivers
    /// to the TUN interface.
    async fn handle_data_packet(&mut self, src_addr: &NodeAddr, inner: &[u8]) {
        let packet = match DataPacket::decode(inner) {
            Ok(p) => p,
            Err(e) => {
                debug!(error = %e, "Malformed DataPacket");
                return;
            }
        };

        // Remove entry to take ownership for potential state transition
        let mut entry = match self.sessions.remove(src_addr) {
            Some(e) => e,
            None => {
                debug!(src = %src_addr, "DataPacket for unknown session");
                return;
            }
        };

        // If in Responding state, transition to Established first
        // (responder wrote msg2, handshake is complete from our side)
        if entry.state().is_responding() {
            let old_state = entry.take_state();
            let handshake = match old_state {
                Some(EndToEndState::Responding(hs)) => hs,
                _ => {
                    debug!(src = %src_addr, "Unexpected state in DataPacket handler");
                    return;
                }
            };
            let noise_session = match handshake.into_session() {
                Ok(s) => s,
                Err(e) => {
                    debug!(error = %e, "Failed to create session from responding handshake");
                    return;
                }
            };
            entry.set_state(EndToEndState::Established(noise_session));
            debug!(src = %src_addr, "Session established (responder, on first data)");
        }

        // Decrypt
        let session = match entry.state_mut() {
            EndToEndState::Established(s) => s,
            _ => {
                debug!(src = %src_addr, "DataPacket but session not established");
                self.sessions.insert(*src_addr, entry);
                return;
            }
        };

        let plaintext = match session.decrypt(&packet.payload) {
            Ok(pt) => pt,
            Err(e) => {
                debug!(error = %e, src = %src_addr, "Session decryption failed");
                self.sessions.insert(*src_addr, entry);
                return;
            }
        };

        entry.touch(Self::now_ms());
        self.sessions.insert(*src_addr, entry);

        // Deliver to TUN
        if let Some(tun_tx) = &self.tun_tx {
            if let Err(e) = tun_tx.send(plaintext) {
                debug!(error = %e, "Failed to deliver decrypted packet to TUN");
            }
        } else {
            debug!(
                src = %src_addr,
                "DataPacket decrypted (no TUN interface, plaintext dropped)"
            );
        }

        // Flush any pending outbound packets (e.g., simultaneous initiation
        // where responder also had queued outbound packets)
        self.flush_pending_packets(src_addr).await;
    }

    /// Handle a CoordsRequired error signal from a transit router.
    ///
    /// The router couldn't route our packet because it lacks cached
    /// coordinates for the destination. Trigger discovery to populate
    /// the route cache so subsequent routing attempts succeed.
    async fn handle_coords_required(&mut self, inner: &[u8]) {
        let msg = match CoordsRequired::decode(inner) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Malformed CoordsRequired");
                return;
            }
        };

        debug!(
            dest = %msg.dest_addr,
            reporter = %msg.reporter,
            "CoordsRequired: transit router needs coordinates, initiating discovery"
        );

        self.maybe_initiate_lookup(&msg.dest_addr).await;
    }

    /// Handle a PathBroken error signal from a transit router.
    ///
    /// The router has coordinates but still can't route to the destination.
    /// Invalidate cached coordinates and consider re-discovery.
    fn handle_path_broken(&mut self, inner: &[u8]) {
        let msg = match PathBroken::decode(inner) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Malformed PathBroken");
                return;
            }
        };

        debug!(
            dest = %msg.dest_addr,
            reporter = %msg.reporter,
            "PathBroken: transit router reports routing failure"
        );

        // Invalidate stale cached coordinates
        self.coord_cache.remove(&msg.dest_addr);
    }

    // === Session Initiation (Send Path) ===

    /// Initiate an end-to-end session with a remote node.
    ///
    /// Creates a Noise IK handshake as initiator, wraps msg1 in a
    /// SessionSetup, encapsulates in a SessionDatagram, and routes
    /// toward the destination.
    pub(in crate::node) async fn initiate_session(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: PublicKey,
    ) -> Result<(), NodeError> {
        // Check for existing session
        if let Some(existing) = self.sessions.get(&dest_addr)
            && (existing.state().is_established() || existing.state().is_initiating())
        {
            return Ok(());
        }

        // Create Noise IK initiator handshake
        let our_keypair = self.identity.keypair();
        let mut handshake = HandshakeState::new_initiator(our_keypair, dest_pubkey);
        let msg1 = handshake.write_message_1().map_err(|e| NodeError::SendFailed {
            node_addr: dest_addr,
            reason: format!("Noise msg1 generation failed: {}", e),
        })?;

        // Build SessionSetup with coordinates
        let our_coords = self.tree_state.my_coords().clone();
        let dest_coords = self.get_dest_coords(&dest_addr);
        let setup = SessionSetup::new(our_coords, dest_coords)
            .with_handshake(msg1);

        // Wrap in SessionDatagram
        let my_addr = *self.node_addr();
        let datagram = SessionDatagram::new(my_addr, dest_addr, setup.encode())
            .with_hop_limit(self.config.node.session.default_hop_limit);

        // Route toward destination
        self.send_session_datagram(&datagram).await?;

        // Register destination identity for TUN → session routing
        self.register_identity(dest_addr, dest_pubkey);

        // Store session entry
        let now_ms = Self::now_ms();
        let entry = SessionEntry::new(dest_addr, dest_pubkey, EndToEndState::Initiating(handshake), now_ms);
        self.sessions.insert(dest_addr, entry);

        debug!(dest = %dest_addr, "Session initiation started");
        Ok(())
    }

    /// Send application data over an established session.
    ///
    /// Encrypts the payload with the session key, wraps in DataPacket
    /// and SessionDatagram, routes toward destination.
    pub(in crate::node) async fn send_session_data(
        &mut self,
        dest_addr: &NodeAddr,
        plaintext: &[u8],
    ) -> Result<(), NodeError> {
        let entry = self.sessions.get_mut(dest_addr).ok_or_else(|| NodeError::SendFailed {
            node_addr: *dest_addr,
            reason: "no session".into(),
        })?;

        let session = match entry.state_mut() {
            EndToEndState::Established(s) => s,
            _ => {
                return Err(NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "session not established".into(),
                });
            }
        };

        // Encrypt with session key
        let ciphertext = session.encrypt(plaintext).map_err(|e| NodeError::SendFailed {
            node_addr: *dest_addr,
            reason: format!("session encrypt failed: {}", e),
        })?;

        // Build DataPacket and wrap in SessionDatagram
        let data_packet = DataPacket::new(ciphertext);
        let my_addr = *self.node_addr();
        let datagram = SessionDatagram::new(my_addr, *dest_addr, data_packet.encode())
            .with_hop_limit(self.config.node.session.default_hop_limit);

        self.send_session_datagram(&datagram).await?;

        // Re-borrow after send (which borrowed &mut self)
        if let Some(entry) = self.sessions.get_mut(dest_addr) {
            entry.touch(Self::now_ms());
        }

        Ok(())
    }

    /// Route and send a SessionDatagram through the mesh.
    ///
    /// Finds the next hop for the destination and sends the datagram
    /// as an encrypted link message.
    async fn send_session_datagram(
        &mut self,
        datagram: &SessionDatagram,
    ) -> Result<(), NodeError> {
        let next_hop_addr = match self.find_next_hop(&datagram.dest_addr) {
            Some(peer) => *peer.node_addr(),
            None => {
                return Err(NodeError::SendFailed {
                    node_addr: datagram.dest_addr,
                    reason: "no route to destination".into(),
                });
            }
        };

        let encoded = datagram.encode();
        self.send_encrypted_link_message(&next_hop_addr, &encoded).await
    }

    /// Look up destination coordinates from available caches.
    ///
    /// Returns our own coordinates as a fallback (the SessionSetup will
    /// carry src_coords for return path routing; empty dest_coords
    /// would fail wire encoding since TreeCoordinate requires ≥1 entry).
    fn get_dest_coords(&self, dest: &NodeAddr) -> crate::tree::TreeCoordinate {
        let now_ms = Self::now_ms();
        if let Some(coords) = self.coord_cache.get(dest, now_ms) {
            return coords.clone();
        }
        if let Some(cached) = self.route_cache.get(dest) {
            return cached.coords().clone();
        }
        // Fallback: use our own coordinates. The SessionSetup dest_coords
        // field cannot be empty (wire format requires ≥1 entry). Using our
        // own coords is safe — transit routers will still cache them, and
        // the destination will return its actual coords in the SessionAck.
        self.tree_state.my_coords().clone()
    }

    /// Current Unix time in milliseconds.
    pub(in crate::node) fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    // === TUN Outbound (Data Plane) ===

    /// Handle an outbound IPv6 packet from the TUN reader.
    ///
    /// Extracts the destination FipsAddress, looks up the NodeAddr and PublicKey
    /// from the identity cache, and either sends through an established session
    /// or initiates a new one (queuing the packet until established).
    pub(in crate::node) async fn handle_tun_outbound(&mut self, ipv6_packet: Vec<u8>) {
        // Validate IPv6 header
        if ipv6_packet.len() < 40 || ipv6_packet[0] >> 4 != 6 {
            return;
        }

        // Extract destination FipsAddress prefix (IPv6 dest bytes 1-15)
        // IPv6 header: bytes 24-39 are dest addr, so prefix = bytes 25-39
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&ipv6_packet[25..40]);

        // Look up in identity cache
        let (dest_addr, dest_pubkey) = match self.lookup_by_fips_prefix(&prefix) {
            Some((addr, pk)) => (addr, pk),
            None => {
                self.send_icmpv6_dest_unreachable(&ipv6_packet);
                return;
            }
        };

        // Check for established session
        if let Some(entry) = self.sessions.get(&dest_addr) {
            if entry.is_established() {
                if let Err(e) = self.send_session_data(&dest_addr, &ipv6_packet).await {
                    debug!(dest = %dest_addr, error = %e, "Failed to send TUN packet via session");
                }
                return;
            }
            // Session exists but not yet established — queue the packet
            self.queue_pending_packet(dest_addr, ipv6_packet);
            return;
        }

        // No session: initiate one and queue the packet.
        // If session initiation fails (no route), trigger discovery and
        // queue the packet for retry when discovery completes.
        if let Err(e) = self.initiate_session(dest_addr, dest_pubkey).await {
            debug!(dest = %dest_addr, error = %e, "Failed to initiate session, trying discovery");
            self.maybe_initiate_lookup(&dest_addr).await;
            self.queue_pending_packet(dest_addr, ipv6_packet);
            return;
        }
        self.queue_pending_packet(dest_addr, ipv6_packet);
    }

    /// Send ICMPv6 Destination Unreachable back through TUN.
    pub(in crate::node) fn send_icmpv6_dest_unreachable(&self, original_packet: &[u8]) {
        use crate::upper::icmp::{build_dest_unreachable, should_send_icmp_error, DestUnreachableCode};
        use crate::FipsAddress;

        if !should_send_icmp_error(original_packet) {
            return;
        }

        let our_ipv6 = FipsAddress::from_node_addr(self.node_addr()).to_ipv6();
        if let Some(response) = build_dest_unreachable(
            original_packet,
            DestUnreachableCode::NoRoute,
            our_ipv6,
        ) && let Some(tun_tx) = &self.tun_tx {
            let _ = tun_tx.send(response);
        }
    }

    /// Queue a packet while waiting for session establishment.
    fn queue_pending_packet(&mut self, dest_addr: NodeAddr, packet: Vec<u8>) {
        // Reject if we already have too many pending destinations
        let max_dests = self.config.node.session.pending_max_destinations;
        if !self.pending_tun_packets.contains_key(&dest_addr)
            && self.pending_tun_packets.len() >= max_dests
        {
            return;
        }

        let queue = self
            .pending_tun_packets
            .entry(dest_addr)
            .or_default();
        if queue.len() >= self.config.node.session.pending_packets_per_dest {
            queue.pop_front(); // Drop oldest
        }
        queue.push_back(packet);
    }

    /// Flush pending packets for a destination whose session just reached Established.
    async fn flush_pending_packets(&mut self, dest_addr: &NodeAddr) {
        let packets = match self.pending_tun_packets.remove(dest_addr) {
            Some(q) => q,
            None => return,
        };
        for packet in packets {
            if let Err(e) = self.send_session_data(dest_addr, &packet).await {
                debug!(dest = %dest_addr, error = %e, "Failed to send queued TUN packet");
                break;
            }
        }
    }

    /// Retry session initiation after discovery provided coordinates.
    ///
    /// Called when a LookupResponse arrives and we have pending TUN packets
    /// for the discovered target. The route_cache now has coords, so
    /// `find_next_hop()` should succeed and the SessionSetup can be sent.
    pub(in crate::node) async fn retry_session_after_discovery(&mut self, dest_addr: NodeAddr) {
        // Look up the destination's public key from the identity cache
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&dest_addr.as_bytes()[0..15]);
        let dest_pubkey = match self.lookup_by_fips_prefix(&prefix) {
            Some((_, pk)) => pk,
            None => {
                debug!(dest = %dest_addr, "Discovery complete but no identity for session retry");
                return;
            }
        };

        // Skip if a session already exists
        if let Some(existing) = self.sessions.get(&dest_addr)
            && (existing.state().is_established() || existing.state().is_initiating())
        {
            return;
        }

        match self.initiate_session(dest_addr, dest_pubkey).await {
            Ok(()) => {
                debug!(dest = %dest_addr, "Session initiated after discovery");
            }
            Err(e) => {
                debug!(dest = %dest_addr, error = %e, "Session retry after discovery failed");
            }
        }
    }
}
