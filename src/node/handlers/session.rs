//! End-to-end session message handlers.
//!
//! Handles locally-delivered session payloads from SessionDatagram envelopes.
//! Dispatches based on FSP common prefix phase to specific handlers for
//! SessionSetup (Noise IK msg1), SessionAck (msg2), encrypted data,
//! and error signals (CoordsRequired, PathBroken).

use crate::node::session::{EndToEndState, SessionEntry};
use crate::node::session_wire::{
    build_fsp_header, fsp_prepend_inner_header, fsp_strip_inner_header,
    parse_encrypted_coords, FspCommonPrefix, FspEncryptedHeader, FSP_COMMON_PREFIX_SIZE,
    FSP_FLAG_CP, FSP_HEADER_SIZE, FSP_PHASE_ESTABLISHED, FSP_PHASE_MSG1, FSP_PHASE_MSG2,
};
use crate::protocol::{coords_wire_size, encode_coords};
use crate::upper::icmp::FIPS_OVERHEAD;
use crate::node::{Node, NodeError};
use crate::noise::{HandshakeState, HANDSHAKE_MSG1_SIZE, HANDSHAKE_MSG2_SIZE};
use crate::mmp::report::ReceiverReport;
use crate::mmp::{MAX_SESSION_REPORT_INTERVAL_MS, MIN_SESSION_REPORT_INTERVAL_MS};
use crate::protocol::{
    CoordsRequired, FspInnerFlags, PathBroken, PathMtuNotification, SessionAck, SessionDatagram,
    SessionMessageType, SessionReceiverReport, SessionSenderReport, SessionSetup,
};
use crate::NodeAddr;
use secp256k1::PublicKey;
use tracing::{debug, info, trace};

impl Node {
    /// Handle a locally-delivered session datagram payload.
    ///
    /// Called from `handle_session_datagram()` when `dest_addr == self.node_addr()`.
    /// Dispatches based on the 4-byte FSP common prefix:
    ///
    /// - Phase 0x1 → SessionSetup (handshake msg1)
    /// - Phase 0x2 → SessionAck (handshake msg2)
    /// - Phase 0x0 + U flag → plaintext error signal (CoordsRequired/PathBroken)
    /// - Phase 0x0 + !U → encrypted session message (data, reports, etc.)
    pub(in crate::node) async fn handle_session_payload(
        &mut self,
        src_addr: &NodeAddr,
        payload: &[u8],
        path_mtu: u16,
    ) {
        let prefix = match FspCommonPrefix::parse(payload) {
            Some(p) => p,
            None => {
                debug!(len = payload.len(), "Session payload too short for FSP prefix");
                return;
            }
        };

        let inner = &payload[FSP_COMMON_PREFIX_SIZE..];

        match prefix.phase {
            FSP_PHASE_MSG1 => {
                self.handle_session_setup(src_addr, inner).await;
            }
            FSP_PHASE_MSG2 => {
                self.handle_session_ack(src_addr, inner).await;
            }
            FSP_PHASE_ESTABLISHED if prefix.is_unencrypted() => {
                // Plaintext error signals: read msg_type from first byte after prefix
                if inner.is_empty() {
                    debug!("Empty plaintext error signal");
                    return;
                }
                let error_type = inner[0];
                let error_body = &inner[1..];
                match SessionMessageType::from_byte(error_type) {
                    Some(SessionMessageType::CoordsRequired) => {
                        self.handle_coords_required(error_body).await;
                    }
                    Some(SessionMessageType::PathBroken) => {
                        self.handle_path_broken(error_body).await;
                    }
                    _ => {
                        debug!(error_type, "Unknown plaintext error signal type");
                    }
                }
            }
            FSP_PHASE_ESTABLISHED => {
                self.handle_encrypted_session_msg(src_addr, payload, path_mtu).await;
            }
            _ => {
                debug!(phase = prefix.phase, "Unknown FSP phase");
            }
        }
    }

    /// Handle an encrypted session message (phase 0x0, U flag clear).
    ///
    /// Full FSP receive pipeline:
    /// 1. Parse FspEncryptedHeader (12 bytes) → counter, flags, header_bytes
    /// 2. If CP flag: parse cleartext coords, cache them
    /// 3. Session lookup with Responding→Established transition
    /// 4. AEAD decrypt with AAD = header_bytes
    /// 5. Strip FSP inner header → timestamp, msg_type, inner_flags
    /// 6. Dispatch by msg_type
    async fn handle_encrypted_session_msg(&mut self, src_addr: &NodeAddr, payload: &[u8], path_mtu: u16) {
        // Parse the 12-byte encrypted header (includes the 4-byte prefix)
        let header = match FspEncryptedHeader::parse(payload) {
            Some(h) => h,
            None => {
                debug!(len = payload.len(), "Encrypted session message too short for FSP header");
                return;
            }
        };

        // Determine where ciphertext starts (after header, optionally after coords)
        let mut ciphertext_offset = FSP_HEADER_SIZE;

        // If CP flag set, parse cleartext coords between header and ciphertext
        if header.has_coords() {
            let coord_data = &payload[FSP_HEADER_SIZE..];
            match parse_encrypted_coords(coord_data) {
                Ok((src_coords, dest_coords, bytes_consumed)) => {
                    let now_ms = Self::now_ms();
                    if let Some(coords) = src_coords {
                        self.coord_cache.insert(*src_addr, coords, now_ms);
                    }
                    if let Some(coords) = dest_coords {
                        self.coord_cache.insert(*self.node_addr(), coords, now_ms);
                    }
                    ciphertext_offset += bytes_consumed;
                }
                Err(e) => {
                    debug!(error = %e, "Failed to parse coords from encrypted session message");
                    return;
                }
            }
        }

        let ciphertext = &payload[ciphertext_offset..];

        // Look up session entry, handle Responding→Established transition
        let mut entry = match self.sessions.remove(src_addr) {
            Some(e) => e,
            None => {
                debug!(src = %self.peer_display_name(src_addr), "Encrypted session message for unknown session");
                return;
            }
        };

        if entry.state().is_responding() {
            let old_state = entry.take_state();
            let handshake = match old_state {
                Some(EndToEndState::Responding(hs)) => hs,
                _ => {
                    debug!(src = %self.peer_display_name(src_addr), "Unexpected state during Responding transition");
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
            entry.set_coords_warmup_remaining(self.config.node.session.coords_warmup_packets);
            entry.mark_established(Self::now_ms());
            entry.init_mmp(&self.config.node.session_mmp);
            entry.clear_handshake_payload();
            info!(src = %self.peer_display_name(src_addr), "Session established (responder, on first encrypted message)");
        }

        // Decrypt with AAD = the 12-byte header
        let session = match entry.state_mut() {
            EndToEndState::Established(s) => s,
            _ => {
                debug!(src = %self.peer_display_name(src_addr), "Encrypted message but session not established");
                self.sessions.insert(*src_addr, entry);
                return;
            }
        };

        let plaintext = match session.decrypt_with_replay_check_and_aad(
            ciphertext,
            header.counter,
            &header.header_bytes,
        ) {
            Ok(pt) => pt,
            Err(e) => {
                debug!(
                    error = %e, src = %self.peer_display_name(src_addr), counter = header.counter,
                    "Session AEAD decryption failed"
                );
                self.sessions.insert(*src_addr, entry);
                return;
            }
        };

        self.sessions.insert(*src_addr, entry);

        // Strip FSP inner header (6 bytes)
        let (timestamp, msg_type, inner_flags_byte, rest) = match fsp_strip_inner_header(&plaintext) {
            Some(parts) => parts,
            None => {
                debug!(src = %self.peer_display_name(src_addr), "Decrypted payload too short for FSP inner header");
                return;
            }
        };

        // MMP per-message recording on RX path
        if let Some(entry) = self.sessions.get_mut(src_addr)
            && let Some(mmp) = entry.mmp_mut()
        {
            let now = std::time::Instant::now();
            mmp.receiver.record_recv(
                header.counter, timestamp, plaintext.len(), false, now,
            );
            // Spin bit: advance state machine for correct TX reflection.
            // RTT samples not fed into SRTT — timestamp-echo provides
            // accurate RTT; spin bit includes variable inter-frame delays.
            let inner_flags = FspInnerFlags::from_byte(inner_flags_byte);
            let _spin_rtt = mmp.spin_bit.rx_observe(
                inner_flags.spin_bit, header.counter, now,
            );
        }

        // Feed path_mtu from datagram envelope to MMP path MTU tracking.
        // Done for ALL session messages, not just DataPackets, so the
        // destination learns the path MTU even when only reports flow.
        if let Some(entry) = self.sessions.get_mut(src_addr)
            && let Some(mmp) = entry.mmp_mut()
        {
            mmp.path_mtu.observe_incoming_mtu(path_mtu);
        }

        // Dispatch by msg_type
        match SessionMessageType::from_byte(msg_type) {
            Some(SessionMessageType::DataPacket) => {
                // msg_type 0x10: deliver rest (IPv6 payload) to TUN
                if let Some(tun_tx) = &self.tun_tx {
                    if let Err(e) = tun_tx.send(rest.to_vec()) {
                        debug!(error = %e, "Failed to deliver decrypted packet to TUN");
                    }
                } else {
                    trace!(
                        src = %self.peer_display_name(src_addr),
                        "DataPacket decrypted (no TUN interface, plaintext dropped)"
                    );
                }
            }
            Some(SessionMessageType::SenderReport) => {
                self.handle_session_sender_report(src_addr, rest);
            }
            Some(SessionMessageType::ReceiverReport) => {
                self.handle_session_receiver_report(src_addr, rest);
            }
            Some(SessionMessageType::PathMtuNotification) => {
                self.handle_session_path_mtu_notification(src_addr, rest);
            }
            Some(SessionMessageType::CoordsWarmup) => {
                // Standalone coordinate warming — coords already extracted
                // from CP flag by transit nodes. No action needed at endpoint.
                trace!(src = %self.peer_display_name(src_addr), "CoordsWarmup received");
            }
            _ => {
                debug!(src = %self.peer_display_name(src_addr), msg_type, "Unknown session message type, dropping");
            }
        }

        // Only application data resets the idle timer — MMP reports
        // (SenderReport, ReceiverReport, PathMtuNotification) do not.
        if msg_type == SessionMessageType::DataPacket.to_byte()
            && let Some(entry) = self.sessions.get_mut(src_addr)
        {
            entry.touch(Self::now_ms());
        }

        // Flush any pending outbound packets (e.g., simultaneous initiation
        // where responder also had queued outbound packets)
        self.flush_pending_packets(src_addr).await;
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
                            src = %self.peer_display_name(src_addr),
                            "Simultaneous session initiation: we win (smaller addr), dropping their setup"
                        );
                        return;
                    }
                    // We lose — discard our pending handshake, become responder below
                    debug!(
                        src = %self.peer_display_name(src_addr),
                        "Simultaneous session initiation: we lose, becoming responder"
                    );
                }
                EndToEndState::Responding(_) => {
                    // Duplicate setup while we already responded — resend stored ack
                    if let Some(payload) = existing.handshake_payload() {
                        debug!(src = %self.peer_display_name(src_addr), "Duplicate SessionSetup, resending SessionAck");
                        let my_addr = *self.node_addr();
                        let mut datagram = SessionDatagram::new(my_addr, *src_addr, payload.to_vec())
                            .with_ttl(self.config.node.session.default_ttl);
                        if let Err(e) = self.send_session_datagram(&mut datagram).await {
                            debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to resend SessionAck");
                        }
                    } else {
                        debug!(src = %self.peer_display_name(src_addr), "Duplicate SessionSetup, no stored ack to resend");
                    }
                    return;
                }
                EndToEndState::Established(_) => {
                    // Re-establishment: replace existing session below
                    debug!(src = %self.peer_display_name(src_addr), "Session re-establishment from peer");
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
        let ack_payload = ack.encode();
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *src_addr, ack_payload.clone())
            .with_ttl(self.config.node.session.default_ttl);

        // Route the ack back to the initiator
        if let Err(e) = self.send_session_datagram(&mut datagram).await {
            debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to send SessionAck");
            return;
        }

        // Store session entry in Responding state with ack payload for potential resend
        let now_ms = Self::now_ms();
        let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
        let mut entry = SessionEntry::new(*src_addr, remote_pubkey, EndToEndState::Responding(handshake), now_ms, false);
        entry.set_handshake_payload(ack_payload, now_ms + resend_interval);
        self.sessions.insert(*src_addr, entry);

        debug!(src = %self.peer_display_name(src_addr), "SessionSetup processed, SessionAck sent");
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
                debug!(src = %self.peer_display_name(src_addr), "SessionAck for unknown session");
                return;
            }
        };

        // Must be in Initiating state
        let handshake = match entry.take_state() {
            Some(EndToEndState::Initiating(hs)) => hs,
            _ => {
                debug!(src = %self.peer_display_name(src_addr), "SessionAck but session not in Initiating state");
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

        let now_ms = Self::now_ms();
        entry.set_state(EndToEndState::Established(session));
        entry.set_coords_warmup_remaining(self.config.node.session.coords_warmup_packets);
        entry.mark_established(now_ms);
        entry.init_mmp(&self.config.node.session_mmp);
        entry.clear_handshake_payload();
        entry.touch(now_ms);
        self.sessions.insert(*src_addr, entry);
        self.coord_cache.insert(*src_addr, ack.src_coords, now_ms);

        // Flush any queued outbound packets for this destination
        self.flush_pending_packets(src_addr).await;

        info!(src = %self.peer_display_name(src_addr), "Session established (initiator)");
    }

    // === Session-layer MMP report handlers ===

    /// Handle an incoming session-layer SenderReport (msg_type 0x11).
    ///
    /// Informational only — the peer is telling us about what they sent.
    /// Logged but not used for metrics (same pattern as link-layer).
    fn handle_session_sender_report(&mut self, src_addr: &NodeAddr, body: &[u8]) {
        let sr = match SessionSenderReport::decode(body) {
            Ok(sr) => sr,
            Err(e) => {
                debug!(src = %self.peer_display_name(src_addr), error = %e, "Malformed SessionSenderReport");
                return;
            }
        };

        trace!(
            src = %self.peer_display_name(src_addr),
            cum_pkts = sr.cumulative_packets_sent,
            interval_bytes = sr.interval_bytes_sent,
            "Received SessionSenderReport"
        );
    }

    /// Handle an incoming session-layer ReceiverReport (msg_type 0x12).
    ///
    /// The peer is telling us about what they received from us. We feed
    /// this to our metrics to compute RTT, loss rate, and trend indicators.
    fn handle_session_receiver_report(&mut self, src_addr: &NodeAddr, body: &[u8]) {
        let session_rr = match SessionReceiverReport::decode(body) {
            Ok(rr) => rr,
            Err(e) => {
                debug!(src = %self.peer_display_name(src_addr), error = %e, "Malformed SessionReceiverReport");
                return;
            }
        };

        // Convert to link-layer ReceiverReport for MmpMetrics processing
        let rr: ReceiverReport = ReceiverReport::from(&session_rr);

        let now_ms = Self::now_ms();
        let peer_name = self.peer_display_name(src_addr);
        let entry = match self.sessions.get_mut(src_addr) {
            Some(e) => e,
            None => {
                debug!(src = %peer_name, "SessionReceiverReport for unknown session");
                return;
            }
        };

        let our_timestamp_ms = entry.session_timestamp(now_ms);

        let Some(mmp) = entry.mmp_mut() else {
            return;
        };

        let now = std::time::Instant::now();
        mmp.metrics.process_receiver_report(&rr, our_timestamp_ms, now);

        // Feed SRTT back to sender/receiver report interval tuning (session-layer bounds)
        if let Some(srtt_ms) = mmp.metrics.srtt_ms() {
            let srtt_us = (srtt_ms * 1000.0) as i64;
            mmp.sender.update_report_interval_with_bounds(
                srtt_us,
                MIN_SESSION_REPORT_INTERVAL_MS,
                MAX_SESSION_REPORT_INTERVAL_MS,
            );
            mmp.receiver.update_report_interval_with_bounds(
                srtt_us,
                MIN_SESSION_REPORT_INTERVAL_MS,
                MAX_SESSION_REPORT_INTERVAL_MS,
            );
            // Also update PathMtu notification interval from SRTT
            mmp.path_mtu.update_interval_from_srtt(srtt_ms);
        }

        // Update reverse delivery ratio from our own receiver state
        let our_recv_packets = mmp.receiver.cumulative_packets_recv();
        let peer_highest = mmp.receiver.highest_counter();
        if peer_highest > 0 {
            let reverse_ratio = (our_recv_packets as f64) / (peer_highest as f64);
            mmp.metrics.set_delivery_ratio_reverse(reverse_ratio);
        }

        trace!(
            src = %peer_name,
            rtt_ms = ?mmp.metrics.srtt_ms(),
            loss = format_args!("{:.1}%", mmp.metrics.loss_rate() * 100.0),
            "Processed SessionReceiverReport"
        );
    }

    /// Handle an incoming PathMtuNotification (msg_type 0x13).
    ///
    /// The destination is telling us the path MTU has changed.
    /// Apply source-side rules (decrease immediate, increase validated).
    fn handle_session_path_mtu_notification(&mut self, src_addr: &NodeAddr, body: &[u8]) {
        let notif = match PathMtuNotification::decode(body) {
            Ok(n) => n,
            Err(e) => {
                debug!(src = %self.peer_display_name(src_addr), error = %e, "Malformed PathMtuNotification");
                return;
            }
        };

        let peer_name = self.peer_display_name(src_addr);
        let entry = match self.sessions.get_mut(src_addr) {
            Some(e) => e,
            None => {
                debug!(src = %peer_name, "PathMtuNotification for unknown session");
                return;
            }
        };

        let Some(mmp) = entry.mmp_mut() else {
            return;
        };

        let old_mtu = mmp.path_mtu.current_mtu();
        let now = std::time::Instant::now();
        mmp.path_mtu.apply_notification(notif.path_mtu, now);
        let new_mtu = mmp.path_mtu.current_mtu();

        if new_mtu != old_mtu {
            debug!(
                src = %peer_name,
                old_mtu,
                new_mtu,
                "Path MTU changed via notification"
            );
        }
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

    /// Handle a CoordsRequired error signal from a transit router.
    ///
    /// The router couldn't route our packet because it lacks cached
    /// coordinates for the destination. Send a standalone CoordsWarmup
    /// immediately (rate-limited), trigger discovery, and reset the
    /// warmup counter for subsequent data packets.
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
            "CoordsRequired: transit router needs coordinates"
        );

        // Send standalone CoordsWarmup immediately (rate-limited)
        if self.coords_response_rate_limiter.should_send(&msg.dest_addr) {
            if let Some(entry) = self.sessions.get(&msg.dest_addr)
                && entry.is_established()
                && let Err(e) = self.send_coords_warmup(&msg.dest_addr).await
            {
                debug!(dest = %msg.dest_addr, error = %e,
                    "Failed to send CoordsWarmup in response to CoordsRequired");
            }
        } else {
            trace!(dest = %msg.dest_addr,
                "CoordsRequired response rate-limited, skipping standalone CoordsWarmup");
        }

        self.maybe_initiate_lookup(&msg.dest_addr).await;

        // Reset coords warmup counter so the next N packets also include
        // COORDS_PRESENT, re-warming transit caches along the path.
        if let Some(entry) = self.sessions.get_mut(&msg.dest_addr) {
            let n = self.config.node.session.coords_warmup_packets;
            entry.set_coords_warmup_remaining(n);
            debug!(
                dest = %msg.dest_addr,
                warmup_packets = n,
                "Reset coords warmup counter after CoordsRequired"
            );
        }
    }

    /// Handle a PathBroken error signal from a transit router.
    ///
    /// The router has coordinates but still can't route to the destination.
    /// Send a standalone CoordsWarmup immediately (rate-limited), invalidate
    /// cached coordinates, trigger re-discovery, and reset the warmup counter.
    async fn handle_path_broken(&mut self, inner: &[u8]) {
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

        // Send standalone CoordsWarmup immediately (rate-limited)
        if self.coords_response_rate_limiter.should_send(&msg.dest_addr) {
            if let Some(entry) = self.sessions.get(&msg.dest_addr)
                && entry.is_established()
                && let Err(e) = self.send_coords_warmup(&msg.dest_addr).await
            {
                debug!(dest = %msg.dest_addr, error = %e,
                    "Failed to send CoordsWarmup in response to PathBroken");
            }
        } else {
            trace!(dest = %msg.dest_addr,
                "PathBroken response rate-limited, skipping standalone CoordsWarmup");
        }

        // Invalidate stale cached coordinates
        self.coord_cache.remove(&msg.dest_addr);

        // Trigger re-discovery to get fresh coordinates
        self.maybe_initiate_lookup(&msg.dest_addr).await;

        // Reset coords warmup counter so the next N packets include
        // COORDS_PRESENT, re-warming transit caches along the new path.
        if let Some(entry) = self.sessions.get_mut(&msg.dest_addr) {
            let n = self.config.node.session.coords_warmup_packets;
            entry.set_coords_warmup_remaining(n);
            debug!(
                dest = %msg.dest_addr,
                warmup_packets = n,
                "Reset coords warmup counter after PathBroken"
            );
        }
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
        let setup_payload = setup.encode();

        // Wrap in SessionDatagram
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, dest_addr, setup_payload.clone())
            .with_ttl(self.config.node.session.default_ttl);

        // Route toward destination
        self.send_session_datagram(&mut datagram).await?;

        // Register destination identity for TUN → session routing
        self.register_identity(dest_addr, dest_pubkey);

        // Store session entry with handshake payload for potential resend
        let now_ms = Self::now_ms();
        let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
        let mut entry = SessionEntry::new(dest_addr, dest_pubkey, EndToEndState::Initiating(handshake), now_ms, true);
        entry.set_handshake_payload(setup_payload, now_ms + resend_interval);
        self.sessions.insert(dest_addr, entry);

        info!(dest = %self.peer_display_name(&dest_addr), "Session initiation started");
        Ok(())
    }

    /// Send application data over an established session.
    ///
    /// Uses the FSP pipeline: builds a 12-byte cleartext header (used as AAD),
    /// prepends the 6-byte inner header to the plaintext, encrypts with AAD,
    /// optionally inserts cleartext coords, and wraps in a SessionDatagram.
    pub(in crate::node) async fn send_session_data(
        &mut self,
        dest_addr: &NodeAddr,
        plaintext: &[u8],
    ) -> Result<(), NodeError> {
        let now_ms = Self::now_ms();

        // First borrow: read session metadata (NLL releases before coord decision)
        let entry = self.sessions.get(dest_addr).ok_or_else(|| NodeError::SendFailed {
            node_addr: *dest_addr,
            reason: "no session".into(),
        })?;
        let wants_coords = entry.coords_warmup_remaining() > 0;
        let timestamp = entry.session_timestamp(now_ms);
        let spin_bit = entry.mmp().is_some_and(|m| m.spin_bit.tx_bit());
        if !entry.is_established() {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "session not established".into(),
            });
        }

        // Build inner plaintext (doesn't depend on counter)
        let msg_type = SessionMessageType::DataPacket.to_byte(); // 0x10
        let inner_flags = FspInnerFlags { spin_bit }.to_byte();
        let inner_plaintext = fsp_prepend_inner_header(timestamp, msg_type, inner_flags, plaintext);

        // Determine whether coords fit within transport MTU.
        // If not, send standalone CoordsWarmup before the data packet.
        let (include_coords, my_coords, dest_coords) = if wants_coords {
            let src = self.tree_state.my_coords().clone();
            let dst = self.get_dest_coords(dest_addr);
            let coords_size = coords_wire_size(&src) + coords_wire_size(&dst);
            let total_wire = FIPS_OVERHEAD as usize + coords_size + plaintext.len();
            if total_wire <= self.transport_mtu() as usize {
                (true, Some(src), Some(dst))
            } else {
                // Coords don't fit piggybacked — send standalone CoordsWarmup first
                if let Err(e) = self.send_coords_warmup(dest_addr).await {
                    debug!(dest = %self.peer_display_name(dest_addr), error = %e,
                        "Failed to send standalone CoordsWarmup before data packet");
                }
                (false, None, None)
            }
        } else {
            (false, None, None)
        };

        // Decrement warmup counter if we sent coords (piggybacked or standalone)
        if wants_coords
            && let Some(entry) = self.sessions.get_mut(dest_addr)
        {
            entry.set_coords_warmup_remaining(entry.coords_warmup_remaining() - 1);
        }

        // Build FSP flags (CP flag only if coords will be piggybacked)
        let flags = if include_coords { FSP_FLAG_CP } else { 0 };

        // Borrow session for counter + encryption (after potential standalone send)
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
        let counter = session.current_send_counter();

        // Build 12-byte FSP header (used as AAD for AEAD)
        let payload_len = inner_plaintext.len() as u16;
        let header = build_fsp_header(counter, flags, payload_len);

        // Encrypt with AAD binding to the FSP header
        let ciphertext = session.encrypt_with_aad(&inner_plaintext, &header).map_err(|e| {
            NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("session encrypt failed: {}", e),
            }
        })?;

        // Assemble: header(12) + [coords] + ciphertext
        let mut fsp_payload = Vec::with_capacity(FSP_HEADER_SIZE + ciphertext.len() + 200);
        fsp_payload.extend_from_slice(&header);
        if let (Some(src), Some(dst)) = (&my_coords, &dest_coords) {
            encode_coords(src, &mut fsp_payload);
            encode_coords(dst, &mut fsp_payload);
        }
        fsp_payload.extend_from_slice(&ciphertext);

        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *dest_addr, fsp_payload)
            .with_ttl(self.config.node.session.default_ttl);

        self.send_session_datagram(&mut datagram).await?;

        // Re-borrow after send (which borrowed &mut self)
        if let Some(entry) = self.sessions.get_mut(dest_addr) {
            if let Some(mmp) = entry.mmp_mut() {
                mmp.sender.record_sent(counter, timestamp, ciphertext.len());
            }
            entry.touch(now_ms);
        }

        Ok(())
    }

    /// Send a non-data session message (reports, notifications) over an established session.
    ///
    /// Similar to `send_session_data()` but:
    /// - Takes an explicit `msg_type` byte (0x11, 0x12, 0x13, etc.)
    /// - Never includes COORDS_PRESENT (reports are lightweight)
    /// - Reads spin bit from MMP state for the inner header
    /// - Records the send in MMP sender state
    pub(in crate::node) async fn send_session_msg(
        &mut self,
        dest_addr: &NodeAddr,
        msg_type: u8,
        payload: &[u8],
    ) -> Result<(), NodeError> {
        let now_ms = Self::now_ms();

        // Read spin bit and session timestamp from entry
        let entry = self.sessions.get(dest_addr).ok_or_else(|| NodeError::SendFailed {
            node_addr: *dest_addr,
            reason: "no session".into(),
        })?;
        let timestamp = entry.session_timestamp(now_ms);
        let spin_bit = entry.mmp().is_some_and(|m| m.spin_bit.tx_bit());

        // Build inner flags with spin bit
        let inner_flags = FspInnerFlags { spin_bit }.to_byte();

        // Get mutable access for encryption
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

        let counter = session.current_send_counter();

        // FSP inner header + plaintext
        let inner_plaintext = fsp_prepend_inner_header(timestamp, msg_type, inner_flags, payload);

        // Build 12-byte FSP header (no flags — no CP for reports)
        let payload_len = inner_plaintext.len() as u16;
        let header = build_fsp_header(counter, 0, payload_len);

        // Encrypt with AAD
        let ciphertext = session.encrypt_with_aad(&inner_plaintext, &header).map_err(|e| {
            NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("session encrypt failed: {}", e),
            }
        })?;

        // Assemble: header(12) + ciphertext (no coords)
        let mut fsp_payload = Vec::with_capacity(FSP_HEADER_SIZE + ciphertext.len());
        fsp_payload.extend_from_slice(&header);
        fsp_payload.extend_from_slice(&ciphertext);

        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *dest_addr, fsp_payload)
            .with_ttl(self.config.node.session.default_ttl);

        self.send_session_datagram(&mut datagram).await?;

        // Record in MMP sender state (no touch — MMP reports don't reset idle timer)
        if let Some(entry) = self.sessions.get_mut(dest_addr)
            && let Some(mmp) = entry.mmp_mut()
        {
            mmp.sender.record_sent(counter, timestamp, ciphertext.len());
        }

        Ok(())
    }

    /// Send a standalone CoordsWarmup message to warm transit node caches.
    ///
    /// Constructs an encrypted FSP message with CP flag set and
    /// msg_type=CoordsWarmup. Transit nodes extract the cleartext
    /// coordinates via `try_warm_coord_cache()` (same as CP-flagged data
    /// packets). The encrypted inner payload is the 6-byte inner header
    /// with no application data.
    async fn send_coords_warmup(
        &mut self,
        dest_addr: &NodeAddr,
    ) -> Result<(), NodeError> {
        let now_ms = Self::now_ms();

        let my_coords = self.tree_state.my_coords().clone();
        let dest_coords = self.get_dest_coords(dest_addr);

        // Read session metadata
        let entry = self.sessions.get(dest_addr).ok_or_else(|| NodeError::SendFailed {
            node_addr: *dest_addr,
            reason: "no session".into(),
        })?;
        let timestamp = entry.session_timestamp(now_ms);
        let spin_bit = entry.mmp().is_some_and(|m| m.spin_bit.tx_bit());

        // Get mutable access for encryption
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

        let counter = session.current_send_counter();

        // FSP inner header only, no body payload
        let msg_type = SessionMessageType::CoordsWarmup.to_byte();
        let inner_flags = FspInnerFlags { spin_bit }.to_byte();
        let inner_plaintext = fsp_prepend_inner_header(timestamp, msg_type, inner_flags, &[]);

        // Build FSP header with CP flag
        let payload_len = inner_plaintext.len() as u16;
        let header = build_fsp_header(counter, FSP_FLAG_CP, payload_len);

        // Encrypt with AAD
        let ciphertext = session.encrypt_with_aad(&inner_plaintext, &header).map_err(|e| {
            NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("session encrypt failed: {}", e),
            }
        })?;

        // Assemble: header(12) + coords + ciphertext
        let coords_size = coords_wire_size(&my_coords) + coords_wire_size(&dest_coords);
        let mut fsp_payload = Vec::with_capacity(FSP_HEADER_SIZE + coords_size + ciphertext.len());
        fsp_payload.extend_from_slice(&header);
        encode_coords(&my_coords, &mut fsp_payload);
        encode_coords(&dest_coords, &mut fsp_payload);
        fsp_payload.extend_from_slice(&ciphertext);

        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *dest_addr, fsp_payload)
            .with_ttl(self.config.node.session.default_ttl);

        self.send_session_datagram(&mut datagram).await?;

        // Record in MMP (infrastructure traffic — no idle timer touch)
        if let Some(entry) = self.sessions.get_mut(dest_addr)
            && let Some(mmp) = entry.mmp_mut()
        {
            mmp.sender.record_sent(counter, timestamp, ciphertext.len());
        }

        debug!(dest = %self.peer_display_name(dest_addr), "Sent standalone CoordsWarmup");
        Ok(())
    }

    /// Route and send a SessionDatagram through the mesh.
    ///
    /// Finds the next hop for the destination, seeds path_mtu from the
    /// first-hop transport MTU, and sends as an encrypted link message.
    pub(in crate::node) async fn send_session_datagram(
        &mut self,
        datagram: &mut SessionDatagram,
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

        // Seed path_mtu from the first-hop transport MTU (same as forwarding path)
        if let Some(peer) = self.peers.get(&next_hop_addr)
            && let Some(tid) = peer.transport_id()
            && let Some(transport) = self.transports.get(&tid)
        {
            datagram.path_mtu = datagram.path_mtu.min(transport.mtu());
        }

        // Source-side: seed our PathMtuState.current_mtu from the outbound
        // transport MTU so it doesn't stay at u16::MAX until the destination
        // sends a PathMtuNotification back.
        if let Some(entry) = self.sessions.get_mut(&datagram.dest_addr)
            && let Some(mmp) = entry.mmp_mut()
        {
            mmp.path_mtu.seed_source_mtu(datagram.path_mtu);
        }

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
    ///
    /// Also performs MTU checking: if the packet (plus FIPS overhead) exceeds
    /// the transport MTU, an ICMP Packet Too Big message is sent back to the
    /// source and the packet is dropped.
    pub(in crate::node) async fn handle_tun_outbound(&mut self, ipv6_packet: Vec<u8>) {
        // Validate IPv6 header
        if ipv6_packet.len() < 40 || ipv6_packet[0] >> 4 != 6 {
            return;
        }

        // Check if packet will fit after FIPS encapsulation
        let effective_mtu = self.effective_ipv6_mtu() as usize;
        if ipv6_packet.len() > effective_mtu {
            self.send_icmpv6_packet_too_big(&ipv6_packet, effective_mtu as u16);
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
                    debug!(dest = %self.peer_display_name(&dest_addr), error = %e, "Failed to send TUN packet via session");
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
            debug!(dest = %self.peer_display_name(&dest_addr), error = %e, "Failed to initiate session, trying discovery");
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

    /// Send ICMPv6 Packet Too Big back through TUN.
    ///
    /// Rate-limited per source address to prevent ICMP floods from
    /// misconfigured applications sending repeated oversized packets.
    pub(in crate::node) fn send_icmpv6_packet_too_big(&mut self, original_packet: &[u8], mtu: u16) {
        use crate::upper::icmp::build_packet_too_big;
        use crate::FipsAddress;
        use std::net::Ipv6Addr;

        // Extract source address for rate limiting
        if original_packet.len() < 40 {
            return;
        }
        let src_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&original_packet[8..24]).unwrap());

        // Rate limit ICMP PTB messages per source
        if !self.icmp_rate_limiter.should_send(src_addr) {
            debug!(
                src = %src_addr,
                "Rate limiting ICMP Packet Too Big"
            );
            return;
        }

        let our_ipv6 = FipsAddress::from_node_addr(self.node_addr()).to_ipv6();
        if let Some(response) = build_packet_too_big(original_packet, mtu, our_ipv6)
            && let Some(tun_tx) = &self.tun_tx
        {
            debug!(
                src = %src_addr,
                dst = %our_ipv6,
                packet_size = original_packet.len(),
                reported_mtu = mtu,
                "Sending ICMP Packet Too Big (ICMP src={}, dst={})",
                our_ipv6,
                src_addr
            );
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
                debug!(dest = %self.peer_display_name(dest_addr), error = %e, "Failed to send queued TUN packet");
                break;
            }
        }
    }

    /// Retry session initiation after discovery provided coordinates.
    ///
    /// Called when a LookupResponse arrives and we have pending TUN packets
    /// for the discovered target. The coord_cache now has coords, so
    /// `find_next_hop()` should succeed and the SessionSetup can be sent.
    pub(in crate::node) async fn retry_session_after_discovery(&mut self, dest_addr: NodeAddr) {
        // Look up the destination's public key from the identity cache
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&dest_addr.as_bytes()[0..15]);
        let dest_pubkey = match self.lookup_by_fips_prefix(&prefix) {
            Some((_, pk)) => pk,
            None => {
                debug!(dest = %self.peer_display_name(&dest_addr), "Discovery complete but no identity for session retry");
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
                debug!(dest = %self.peer_display_name(&dest_addr), "Session initiated after discovery");
            }
            Err(e) => {
                debug!(dest = %self.peer_display_name(&dest_addr), error = %e, "Session retry after discovery failed");
            }
        }
    }
}
