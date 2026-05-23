//! End-to-end session message handlers.
//!
//! Handles locally-delivered session payloads from SessionDatagram envelopes.
//! Dispatches based on FSP common prefix phase to specific handlers for
//! SessionSetup (Noise XX msg1), SessionAck (msg2), SessionMsg3 (msg3),
//! encrypted data, and error signals (CoordsRequired, PathBroken).

use crate::NodeAddr;
use crate::mmp::report::ReceiverReport;
use crate::mmp::{MAX_SESSION_REPORT_INTERVAL_MS, MIN_SESSION_REPORT_INTERVAL_MS};
use crate::node::session::{EndToEndState, EpochSlot, SessionEntry};
use crate::node::session_wire::{
    FSP_COMMON_PREFIX_SIZE, FSP_FLAG_CP, FSP_FLAG_K, FSP_HEADER_SIZE, FSP_PHASE_ESTABLISHED,
    FSP_PHASE_MSG1, FSP_PHASE_MSG2, FSP_PHASE_MSG3, FSP_PORT_HEADER_SIZE, FSP_PORT_IPV6_SHIM,
    FspCommonPrefix, FspEncryptedHeader, build_fsp_header, fsp_prepend_inner_header,
    fsp_strip_inner_header, parse_encrypted_coords,
};
#[cfg(unix)]
use crate::node::wire::{ESTABLISHED_HEADER_SIZE, FLAG_KEY_EPOCH, build_established_header};
use crate::node::{Node, NodeError};
use crate::noise::{HANDSHAKE_MSG1_SIZE, HANDSHAKE_MSG2_SIZE, HANDSHAKE_MSG3_SIZE, HandshakeState};
#[cfg(unix)]
use crate::protocol::LinkMessageType;
use crate::protocol::NegotiationPayload;
#[cfg(unix)]
use crate::protocol::SESSION_DATAGRAM_HEADER_SIZE;
use crate::protocol::{
    CoordsRequired, FspInnerFlags, MtuExceeded, PathBroken, PathMtuNotification, SessionAck,
    SessionDatagram, SessionMessageType, SessionMsg3, SessionReceiverReport, SessionSenderReport,
    SessionSetup,
};
use crate::protocol::{coords_wire_size, encode_coords};
#[cfg(unix)]
use crate::transport::TransportHandle;
use crate::upper::icmp::FIPS_OVERHEAD;
use secp256k1::PublicKey;
use tracing::{debug, info, trace, warn};

/// Inputs to `try_send_session_data_pipelined` — the FSP+FMP pipelined
/// fast path that hands both AEAD operations to the encrypt worker
/// in a single dispatch.
#[cfg(unix)]
struct PipelinedSend<'a> {
    dest_addr: &'a NodeAddr,
    payload: &'a [u8],
    now_ms: u64,
    timestamp: u32,
    fsp_flags: u8,
    inner_plaintext: &'a [u8],
    my_coords: Option<&'a crate::tree::TreeCoordinate>,
    dest_coords: Option<&'a crate::tree::TreeCoordinate>,
}

impl Node {
    /// Handle a locally-delivered session datagram payload.
    ///
    /// Called from `handle_session_datagram()` when `dest_addr == self.node_addr()`.
    /// Dispatches based on the 4-byte FSP common prefix:
    ///
    /// - Phase 0x1 → SessionSetup (handshake msg1)
    /// - Phase 0x2 → SessionAck (handshake msg2)
    /// - Phase 0x3 → SessionMsg3 (XX handshake msg3)
    /// - Phase 0x0 + U flag → plaintext error signal (CoordsRequired/PathBroken)
    /// - Phase 0x0 + !U → encrypted session message (data, reports, etc.)
    pub(in crate::node) async fn handle_session_payload(
        &mut self,
        src_addr: &NodeAddr,
        payload: &[u8],
        path_mtu: u16,
        ce_flag: bool,
    ) {
        let prefix = match FspCommonPrefix::parse(payload) {
            Some(p) => p,
            None => {
                debug!(
                    len = payload.len(),
                    "Session payload too short for FSP prefix"
                );
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
            FSP_PHASE_MSG3 => {
                self.handle_session_msg3(src_addr, inner).await;
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
                    Some(SessionMessageType::MtuExceeded) => {
                        self.handle_mtu_exceeded(error_body).await;
                    }
                    _ => {
                        debug!(error_type, "Unknown plaintext error signal type");
                    }
                }
            }
            FSP_PHASE_ESTABLISHED => {
                self.handle_encrypted_session_msg(src_addr, payload, path_mtu, ce_flag)
                    .await;
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
    /// 3. Session lookup (must be Established)
    /// 4. AEAD decrypt with AAD = header_bytes
    /// 5. Strip FSP inner header → timestamp, msg_type, inner_flags
    /// 6. Dispatch by msg_type
    async fn handle_encrypted_session_msg(
        &mut self,
        src_addr: &NodeAddr,
        payload: &[u8],
        path_mtu: u16,
        ce_flag: bool,
    ) {
        // Parse the 12-byte encrypted header (includes the 4-byte prefix)
        let header = match FspEncryptedHeader::parse(payload) {
            Some(h) => h,
            None => {
                debug!(
                    len = payload.len(),
                    "Encrypted session message too short for FSP header"
                );
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

        // Look up session entry — must be Established to decrypt
        {
            let entry = match self.sessions.get(src_addr) {
                Some(e) => e,
                None => {
                    debug!(src = %self.peer_display_name(src_addr), "Encrypted session message for unknown session");
                    return;
                }
            };
            // Drop encrypted data if session is not yet established.
            // With XX, the responder must wait for msg3 before it can decrypt.
            if !entry.is_established() {
                debug!(
                    src = %self.peer_display_name(src_addr),
                    "Encrypted message but session not established (awaiting handshake completion)"
                );
                return;
            }
        }

        // The received K-bit is only an ordering hint for the
        // trial-decrypt cascade — it picks which key epoch to try first.
        // Correctness never depends on it; promotion is driven by which
        // slot actually authenticates the frame, not by the header bit.
        let received_k_bit = header.flags & FSP_FLAG_K != 0;

        let mut entry = match self.sessions.remove(src_addr) {
            Some(e) => e,
            None => return,
        };

        let now_ms = Self::now_ms();

        // Overlapping-epoch trial-decrypt: try current, pending and
        // previous so any epoch the peer might have sealed this frame in
        // can be decrypted. This makes rekey correctness independent of
        // cutover timing — no ordering and no reordering can cause a
        // decrypt failure. A successful `previous`-slot decrypt also
        // refreshes the drain deadline so the old epoch is retained as
        // long as the peer keeps using it.
        let (plaintext, slot) = match entry.fsp_trial_decrypt(
            ciphertext,
            header.counter,
            &header.header_bytes,
            received_k_bit,
            now_ms,
        ) {
            Some(result) => result,
            None => {
                // Every live slot failed — a genuine drop. The upper
                // layer retransmits.
                debug!(
                    src = %self.peer_display_name(src_addr),
                    counter = header.counter,
                    "Session AEAD decryption failed (all epochs)"
                );
                self.sessions.insert(*src_addr, entry);
                return;
            }
        };

        // React to the epoch the frame decrypted against.
        match slot {
            EpochSlot::Pending => {
                // A frame that authenticates against `pending` is itself
                // the cutover signal — proof the peer derived the new
                // session and moved to it. Promote now: current →
                // previous, pending → current, flip the K-bit. The
                // header K-bit is no longer the gating event; the
                // authenticated decrypt is.
                info!(
                    peer = %self.peer_display_name(src_addr),
                    "Peer FSP new-epoch frame authenticated, FSP rekey cutover complete, promoting new session"
                );
                // The peer derived the new session, so it received msg3:
                // confirm it on the new epoch and stop retransmitting.
                // `handle_peer_kbit_flip` consumes the pending session,
                // so confirm first.
                if entry.rekey_msg3_payload().is_some() {
                    entry.confirm_peer_new_epoch();
                }
                entry.handle_peer_kbit_flip(now_ms);
            }
            EpochSlot::Current => {
                // If we still retain a msg3 retransmission payload but no
                // longer hold a `pending` session, we are the rekey
                // initiator that already cut over on its own timer:
                // `current` is now the new epoch, so a frame decrypting
                // against it confirms the responder reached the new
                // epoch. Stop retransmitting msg3.
                if entry.rekey_msg3_payload().is_some() && entry.pending_new_session().is_none() {
                    entry.confirm_peer_new_epoch();
                }
            }
            EpochSlot::Previous => {
                // The peer is still on the old epoch. `fsp_trial_decrypt`
                // already refreshed the drain deadline so the `previous`
                // slot is not retired while the peer keeps using it —
                // no further state change here, just deliver.
            }
        }

        self.sessions.insert(*src_addr, entry);

        // Strip FSP inner header (6 bytes)
        let (timestamp, msg_type, inner_flags_byte, rest) = match fsp_strip_inner_header(&plaintext)
        {
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
            mmp.receiver
                .record_recv(header.counter, timestamp, plaintext.len(), ce_flag, now);
            let _inner_flags = FspInnerFlags::from_byte(inner_flags_byte);
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
                // msg_type 0x10: port-multiplexed service dispatch
                if rest.len() < FSP_PORT_HEADER_SIZE {
                    debug!(len = rest.len(), "DataPacket too short for port header");
                    return;
                }
                let dst_port = u16::from_le_bytes([rest[2], rest[3]]);
                let service_payload = &rest[FSP_PORT_HEADER_SIZE..];

                match dst_port {
                    FSP_PORT_IPV6_SHIM => {
                        use crate::FipsAddress;
                        let src_ipv6 = FipsAddress::from_node_addr(src_addr).to_ipv6().octets();
                        let dst_ipv6 = FipsAddress::from_node_addr(self.node_addr())
                            .to_ipv6()
                            .octets();

                        match crate::upper::ipv6_shim::decompress_ipv6(
                            service_payload,
                            src_ipv6,
                            dst_ipv6,
                        ) {
                            Some(mut packet) => {
                                if ce_flag {
                                    mark_ipv6_ecn_ce(&mut packet);
                                    self.stats_mut().congestion.record_ce_received();
                                }
                                if let Some(tun_tx) = &self.tun_tx {
                                    if let Err(e) = tun_tx.send(packet) {
                                        debug!(error = %e, "Failed to deliver decompressed IPv6 packet to TUN");
                                    }
                                } else {
                                    trace!(
                                        src = %self.peer_display_name(src_addr),
                                        "IPv6 shim packet decompressed (no TUN interface)"
                                    );
                                }
                            }
                            None => {
                                debug!(
                                    src = %self.peer_display_name(src_addr),
                                    len = service_payload.len(),
                                    "IPv6 shim decompression failed"
                                );
                            }
                        }
                    }
                    _ => {
                        debug!(
                            src = %self.peer_display_name(src_addr),
                            dst_port,
                            "Unknown FSP service port, dropping DataPacket"
                        );
                    }
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

        // Only application data resets the idle timer and traffic counters —
        // MMP reports (SenderReport, ReceiverReport, PathMtuNotification) do not.
        if msg_type == SessionMessageType::DataPacket.to_byte()
            && let Some(entry) = self.sessions.get_mut(src_addr)
        {
            entry.record_recv(rest.len());
            entry.touch(Self::now_ms());
        }

        // Flush any pending outbound packets (e.g., simultaneous initiation
        // where responder also had queued outbound packets)
        self.flush_pending_packets(src_addr).await;
    }

    /// Handle an incoming SessionSetup (Noise XX msg1).
    ///
    /// The remote node wants to establish an end-to-end session with us.
    /// We create an XX responder handshake, process msg1, send SessionAck with msg2,
    /// and transition to AwaitingMsg3.
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
            if existing.is_initiating() {
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
            } else if existing.is_awaiting_msg3() {
                // Duplicate setup while we already sent msg2 — resend stored ack
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
            } else if existing.is_established() {
                // Rekey: if rekey enabled, treat as rekey for key rotation.
                // The existing established session remains active for traffic.
                if self.config.node.rekey.enabled {
                    let rekey_in_progress = existing.has_rekey_in_progress();
                    let has_pending = existing.pending_new_session().is_some();

                    // Dual-initiation detection: both sides initiated rekey
                    // simultaneously. Two states can reach this point:
                    //   - rekey_in_progress=true: both sides still mid-handshake
                    //   - pending_new_session=Some && !rekey_in_progress: we've
                    //     already completed our initiator path
                    //     (set_pending_session cleared rekey_in_progress) and
                    //     the peer's msg1 arrives now. Symmetric of the FMP
                    //     msg3 case at handle_msg3.
                    // Apply the smaller-NodeAddr tie-breaker uniformly so
                    // both sides converge on a single Noise session.
                    if rekey_in_progress || has_pending {
                        if self.identity.node_addr() < src_addr {
                            // We win — keep our session, drop their msg1.
                            info!(
                                src = %self.peer_display_name(src_addr),
                                our_addr = %self.identity.node_addr(),
                                their_addr = %src_addr,
                                rekey_in_progress = rekey_in_progress,
                                pending_new_session = has_pending,
                                "FSP rekey-msg1 tie-break: we win (smaller addr), drop their msg1"
                            );
                            return;
                        }
                        // We lose — abandon our rekey/pending, fall through as responder.
                        info!(
                            src = %self.peer_display_name(src_addr),
                            our_addr = %self.identity.node_addr(),
                            their_addr = %src_addr,
                            rekey_in_progress = rekey_in_progress,
                            pending_new_session = has_pending,
                            "FSP rekey-msg1 tie-break: we lose (larger addr), abandon ours"
                        );
                        if let Some(entry) = self.sessions.get_mut(src_addr) {
                            entry.abandon_rekey();
                        }
                    }
                    let our_keypair = self.identity.keypair();
                    let mut handshake = HandshakeState::new_responder(our_keypair);
                    handshake.set_local_epoch(self.startup_epoch);

                    if let Err(e) = handshake.read_message_1(&setup.handshake_payload) {
                        debug!(error = %e, "Failed to process rekey XX msg1");
                        return;
                    }

                    // Generate msg2
                    let msg2 = match handshake.write_message_2() {
                        Ok(m) => m,
                        Err(e) => {
                            debug!(error = %e, "Failed to generate rekey XX msg2");
                            return;
                        }
                    };

                    // Build and send SessionAck
                    let our_coords = self.tree_state.my_coords().clone();
                    let ack = SessionAck::new(our_coords, setup.src_coords).with_handshake(msg2);
                    let ack_payload = ack.encode();
                    let my_addr = *self.node_addr();
                    let mut datagram = SessionDatagram::new(my_addr, *src_addr, ack_payload)
                        .with_ttl(self.config.node.session.default_ttl);

                    if let Err(e) = self.send_session_datagram(&mut datagram).await {
                        debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to send rekey SessionAck");
                        return;
                    }

                    // Store rekey state on the existing entry
                    let now_ms = Self::now_ms();
                    if let Some(entry) = self.sessions.get_mut(src_addr) {
                        entry.set_rekey_state(handshake, false);
                        entry.record_peer_rekey(now_ms);
                    }

                    debug!(
                        src = %self.peer_display_name(src_addr),
                        "FSP rekey: processed peer's msg1, sent msg2, awaiting msg3"
                    );
                    return;
                }

                // Re-establishment: replace existing session below
                debug!(src = %self.peer_display_name(src_addr), "Session re-establishment from peer");
            }
        }

        // Create XX responder handshake and process msg1
        let our_keypair = self.identity.keypair();
        let mut handshake = HandshakeState::new_responder(our_keypair);
        handshake.set_local_epoch(self.startup_epoch);

        if let Err(e) = handshake.read_message_1(&setup.handshake_payload) {
            debug!(error = %e, "Failed to process Noise XX msg1 in SessionSetup");
            return;
        }

        // XX: responder does NOT learn initiator's identity until msg3
        // Use a placeholder pubkey from src_addr for the session entry.
        // The real pubkey will be registered when msg3 arrives.

        // Generate msg2 with negotiation payload
        let mut msg2 = match handshake.write_message_2() {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Failed to generate Noise XX msg2 for SessionAck");
                return;
            }
        };

        // Encrypt FSP negotiation payload (version [0,0], features=0)
        let neg_payload = NegotiationPayload::new(0, 0, 0).encode();
        match handshake.encrypt_payload(&neg_payload) {
            Ok(encrypted) => msg2.extend_from_slice(&encrypted),
            Err(e) => {
                debug!(error = %e, "Failed to encrypt negotiation payload for SessionAck");
                return;
            }
        }

        // Build and send SessionAck (include initiator's coords for return-path warming)
        let our_coords = self.tree_state.my_coords().clone();
        let ack = SessionAck::new(our_coords, setup.src_coords).with_handshake(msg2);
        let ack_payload = ack.encode();
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *src_addr, ack_payload.clone())
            .with_ttl(self.config.node.session.default_ttl);

        // Route the ack back to the initiator
        if let Err(e) = self.send_session_datagram(&mut datagram).await {
            debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to send SessionAck");
            return;
        }

        // Store session entry in AwaitingMsg3 state with ack payload for potential resend.
        // Use a dummy pubkey since we don't know the initiator's identity yet.
        // We use our own pubkey as placeholder; it will be replaced in handle_session_msg3.
        let placeholder_pubkey = self.identity.keypair().public_key();
        let now_ms = Self::now_ms();
        let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
        let mut entry = SessionEntry::new(
            *src_addr,
            placeholder_pubkey,
            EndToEndState::AwaitingMsg3(handshake),
            now_ms,
            false,
        );
        entry.set_handshake_payload(ack_payload, now_ms + resend_interval);
        self.sessions.insert(*src_addr, entry);

        debug!(src = %self.peer_display_name(src_addr), "SessionSetup processed (XX), SessionAck sent, awaiting msg3");
    }

    /// Handle an incoming SessionAck (Noise XX msg2).
    ///
    /// Processes msg2, generates and sends msg3, then transitions to Established.
    async fn handle_session_ack(&mut self, src_addr: &NodeAddr, inner: &[u8]) {
        let ack = match SessionAck::decode(inner) {
            Ok(a) => a,
            Err(e) => {
                debug!(error = %e, "Malformed SessionAck");
                return;
            }
        };

        if ack.handshake_payload.len() < HANDSHAKE_MSG2_SIZE {
            debug!(
                len = ack.handshake_payload.len(),
                min = HANDSHAKE_MSG2_SIZE,
                "Handshake payload too short in SessionAck"
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

        // Rekey path: entry is Established with rekey_state
        if entry.is_established() && entry.has_rekey_in_progress() && entry.is_rekey_initiator() {
            let mut handshake = match entry.take_rekey_state() {
                Some(hs) => hs,
                None => {
                    self.sessions.insert(*src_addr, entry);
                    return;
                }
            };

            // Process XX msg2
            if let Err(e) = handshake.read_message_2(&ack.handshake_payload) {
                debug!(error = %e, "Failed to process rekey XX msg2");
                entry.abandon_rekey();
                self.sessions.insert(*src_addr, entry);
                return;
            }

            // Generate XX msg3
            let msg3 = match handshake.write_message_3() {
                Ok(m) => m,
                Err(e) => {
                    debug!(error = %e, "Failed to generate rekey XX msg3");
                    entry.abandon_rekey();
                    self.sessions.insert(*src_addr, entry);
                    return;
                }
            };

            // Send SessionMsg3
            let msg3_wire = SessionMsg3::new(msg3);
            let msg3_payload = msg3_wire.encode();
            let my_addr = *self.node_addr();
            let mut datagram = SessionDatagram::new(my_addr, *src_addr, msg3_payload.clone())
                .with_ttl(self.config.node.session.default_ttl);

            if let Err(e) = self.send_session_datagram(&mut datagram).await {
                debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to send rekey SessionMsg3");
                entry.abandon_rekey();
                self.sessions.insert(*src_addr, entry);
                return;
            }

            // Complete handshake → store as pending new session
            let session = match handshake.into_session() {
                Ok(s) => s,
                Err(e) => {
                    debug!(error = %e, "Failed to create session from rekey XX");
                    entry.abandon_rekey();
                    self.sessions.insert(*src_addr, entry);
                    return;
                }
            };

            // Retain msg3 for retransmission (liveness): a single msg3
            // loss must not leave the responder without the new session.
            // Retransmission runs until the responder is confirmed on the
            // new epoch — an authenticated peer frame against `pending` or
            // post-cutover `current` — decoupled from this initiator's own
            // cutover. The initiator may cut over on its liveness timer
            // before the responder receives msg3; overlapping-epoch
            // decrypt keeps both directions safe meanwhile.
            let now_ms = Self::now_ms();
            let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
            entry.set_pending_session(session);
            entry.set_rekey_completed_ms(now_ms);
            entry.set_rekey_msg3_payload(msg3_payload, now_ms + resend_interval);
            self.sessions.insert(*src_addr, entry);

            debug!(
                src = %self.peer_display_name(src_addr),
                our_addr = %self.identity.node_addr(),
                their_addr = %src_addr,
                "FSP rekey: completed XX as initiator, msg3 sent, pending cutover"
            );
            return;
        }

        // Must be in Initiating state — check before take to avoid poisoning
        if !entry.is_initiating() {
            debug!(src = %self.peer_display_name(src_addr), "SessionAck but session not in Initiating state");
            self.sessions.insert(*src_addr, entry);
            return;
        }
        let mut handshake = match entry.take_state() {
            Some(EndToEndState::Initiating(hs)) => hs,
            _ => unreachable!("checked is_initiating above"),
        };

        // Split msg2 into base XX part and optional negotiation payload
        let (base_msg2, neg_bytes) = if ack.handshake_payload.len() > HANDSHAKE_MSG2_SIZE {
            (
                &ack.handshake_payload[..HANDSHAKE_MSG2_SIZE],
                Some(&ack.handshake_payload[HANDSHAKE_MSG2_SIZE..]),
            )
        } else {
            (ack.handshake_payload.as_slice(), None)
        };

        // Process XX msg2 (learns responder's identity and epoch)
        if let Err(e) = handshake.read_message_2(base_msg2) {
            debug!(error = %e, "Failed to process Noise XX msg2 in SessionAck");
            return;
        }

        // Decrypt negotiation payload from msg2 if present
        if let Some(encrypted_neg) = neg_bytes {
            match handshake.decrypt_payload(encrypted_neg) {
                Ok(_negotiation) => {
                    // FSP negotiation payload received — currently unused (version [0,0])
                }
                Err(e) => {
                    debug!(error = %e, "Failed to decrypt negotiation payload from SessionAck");
                    return;
                }
            }
        }

        // XX: verify responder's identity matches the target we intended to reach.
        // Compare x-only keys to avoid parity mismatch: npub-derived keys always
        // have even parity (0x02), but the Noise handshake reveals the real parity.
        let expected_xonly = entry.remote_pubkey().x_only_public_key().0;
        if let Some(remote_pk) = handshake.remote_static()
            && remote_pk.x_only_public_key().0 != expected_xonly
        {
            debug!(
                src = %self.peer_display_name(src_addr),
                "Responder identity mismatch in SessionAck — disconnecting"
            );
            return;
        }

        // Generate XX msg3 with negotiation payload
        let mut msg3 = match handshake.write_message_3() {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Failed to generate Noise XX msg3");
                return;
            }
        };

        // Encrypt FSP negotiation payload for msg3
        let neg_payload = NegotiationPayload::new(0, 0, 0).encode();
        match handshake.encrypt_payload(&neg_payload) {
            Ok(encrypted) => msg3.extend_from_slice(&encrypted),
            Err(e) => {
                debug!(error = %e, "Failed to encrypt negotiation payload for SessionMsg3");
                return;
            }
        }

        // Send SessionMsg3 (phase 0x3)
        let msg3_wire = SessionMsg3::new(msg3);
        let msg3_payload = msg3_wire.encode();
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *src_addr, msg3_payload)
            .with_ttl(self.config.node.session.default_ttl);

        if let Err(e) = self.send_session_datagram(&mut datagram).await {
            debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to send SessionMsg3");
            return;
        }

        // Complete the handshake: into_session()
        let session = match handshake.into_session() {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "Failed to create session after XX msg3");
                return;
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

        info!(src = %self.peer_display_name(src_addr), "Session established (initiator, XX)");
    }

    /// Handle an incoming SessionMsg3 (Noise XX msg3).
    ///
    /// The initiator reveals their encrypted static key. The responder
    /// processes msg3, learns the initiator's identity, and transitions
    /// to Established.
    async fn handle_session_msg3(&mut self, src_addr: &NodeAddr, inner: &[u8]) {
        let msg3 = match SessionMsg3::decode(inner) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Malformed SessionMsg3");
                return;
            }
        };

        if msg3.handshake_payload.len() < HANDSHAKE_MSG3_SIZE {
            debug!(
                len = msg3.handshake_payload.len(),
                min = HANDSHAKE_MSG3_SIZE,
                "Handshake payload too short in SessionMsg3"
            );
            return;
        }

        // Remove the entry to take ownership of the handshake state
        let mut entry = match self.sessions.remove(src_addr) {
            Some(e) => e,
            None => {
                debug!(src = %self.peer_display_name(src_addr), "SessionMsg3 for unknown session");
                return;
            }
        };

        // Rekey path: entry is Established with rekey_state (responder side)
        if entry.is_established() && entry.has_rekey_in_progress() && !entry.is_rekey_initiator() {
            let mut handshake = match entry.take_rekey_state() {
                Some(hs) => hs,
                None => {
                    self.sessions.insert(*src_addr, entry);
                    return;
                }
            };

            // Process XX msg3
            if let Err(e) = handshake.read_message_3(&msg3.handshake_payload) {
                debug!(error = %e, "Failed to process rekey XX msg3");
                entry.abandon_rekey();
                self.sessions.insert(*src_addr, entry);
                return;
            }

            // Complete the handshake → store as pending new session
            let session = match handshake.into_session() {
                Ok(s) => s,
                Err(e) => {
                    debug!(error = %e, "Failed to create session from rekey XX msg3");
                    entry.abandon_rekey();
                    self.sessions.insert(*src_addr, entry);
                    return;
                }
            };

            entry.set_pending_session(session);
            self.sessions.insert(*src_addr, entry);

            debug!(
                src = %self.peer_display_name(src_addr),
                our_addr = %self.identity.node_addr(),
                their_addr = %src_addr,
                "FSP rekey: completed XX as responder, pending cutover"
            );
            return;
        }

        // Must be in AwaitingMsg3 state
        if !entry.is_awaiting_msg3() {
            debug!(src = %self.peer_display_name(src_addr), "SessionMsg3 but session not in AwaitingMsg3 state");
            self.sessions.insert(*src_addr, entry);
            return;
        }
        let mut handshake = match entry.take_state() {
            Some(EndToEndState::AwaitingMsg3(hs)) => hs,
            _ => unreachable!("checked is_awaiting_msg3 above"),
        };

        // Split msg3 into base XX part and optional negotiation payload
        let (base_msg3, neg_bytes) = if msg3.handshake_payload.len() > HANDSHAKE_MSG3_SIZE {
            (
                &msg3.handshake_payload[..HANDSHAKE_MSG3_SIZE],
                Some(&msg3.handshake_payload[HANDSHAKE_MSG3_SIZE..]),
            )
        } else {
            (msg3.handshake_payload.as_slice(), None)
        };

        // Process XX msg3 (learns initiator's identity and epoch)
        if let Err(e) = handshake.read_message_3(base_msg3) {
            debug!(error = %e, "Failed to process Noise XX msg3");
            return;
        }

        // Decrypt negotiation payload from msg3 if present
        if let Some(encrypted_neg) = neg_bytes {
            match handshake.decrypt_payload(encrypted_neg) {
                Ok(_negotiation) => {
                    // FSP negotiation payload received — currently unused (version [0,0])
                }
                Err(e) => {
                    debug!(error = %e, "Failed to decrypt negotiation payload from SessionMsg3");
                    return;
                }
            }
        }

        // Extract the initiator's static public key (now available after msg3)
        let remote_pubkey = match handshake.remote_static() {
            Some(pk) => *pk,
            None => {
                debug!("No remote static key after processing XX msg3");
                return;
            }
        };

        // Register the initiator's identity for future TUN → session routing
        self.register_identity(*src_addr, remote_pubkey);

        // Complete the handshake
        let session = match handshake.into_session() {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "Failed to create session from XX handshake");
                return;
            }
        };

        let now_ms = Self::now_ms();
        // Replace the placeholder pubkey with the real one
        let mut new_entry = SessionEntry::new(
            *src_addr,
            remote_pubkey,
            EndToEndState::Established(session),
            now_ms,
            false,
        );
        new_entry.set_coords_warmup_remaining(self.config.node.session.coords_warmup_packets);
        new_entry.mark_established(now_ms);
        new_entry.init_mmp(&self.config.node.session_mmp);
        new_entry.touch(now_ms);
        self.sessions.insert(*src_addr, new_entry);

        // Flush any pending packets
        self.flush_pending_packets(src_addr).await;

        info!(src = %self.peer_display_name(src_addr), "Session established (responder, XX)");
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
            interval_pkts = sr.interval_packets_sent,
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
        mmp.metrics
            .process_receiver_report(&rr, our_timestamp_ms, now);

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

        // Update reverse delivery ratio from our own receiver state, using per-interval deltas.
        let our_recv_packets = mmp.receiver.cumulative_packets_recv();
        let peer_highest = mmp.receiver.highest_counter();
        mmp.metrics
            .update_reverse_delivery(our_recv_packets, peer_highest);

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
    pub(in crate::node) fn handle_session_path_mtu_notification(
        &mut self,
        src_addr: &NodeAddr,
        body: &[u8],
    ) {
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
        let changed = mmp.path_mtu.apply_notification(notif.path_mtu, now);
        let new_mtu = mmp.path_mtu.current_mtu();

        if !changed {
            return;
        }

        debug!(
            src = %peer_name,
            old_mtu,
            new_mtu,
            "Path MTU changed via notification"
        );

        // Mirror the new effective MTU into the FipsAddress-keyed lookup used
        // by the TUN reader/writer at TCP MSS clamp time. Without this, new
        // TCP flows opened on a path the proactive end-to-end echo has
        // already tightened keep getting clamped by the staler discovery-
        // time value until a reactive MtuExceeded happens to fire. Keep the
        // tighter of existing-or-new — never loosen the clamp.
        let fips_addr = crate::FipsAddress::from_node_addr(src_addr);
        match self.path_mtu_lookup.write() {
            Ok(mut map) => match map.get(&fips_addr).copied() {
                Some(existing) if existing <= new_mtu => {
                    debug!(
                        dest = %peer_name,
                        fips_addr = %fips_addr,
                        new_mtu,
                        existing,
                        "PathMtuNotification: keeping tighter existing path_mtu_lookup value"
                    );
                }
                other => {
                    map.insert(fips_addr, new_mtu);
                    debug!(
                        dest = %peer_name,
                        fips_addr = %fips_addr,
                        new_mtu,
                        prior = ?other,
                        map_len = map.len(),
                        "PathMtuNotification: tightened path_mtu_lookup"
                    );
                }
            },
            Err(e) => {
                warn!(
                    dest = %peer_name,
                    fips_addr = %fips_addr,
                    new_mtu,
                    error = %e,
                    "path_mtu_lookup write lock poisoned; PathMtuNotification not reflected"
                );
            }
        }
    }

    /// Handle a CoordsRequired error signal from a transit router.
    ///
    /// The router couldn't route our packet because it lacks cached
    /// coordinates for the destination. Send a standalone CoordsWarmup
    /// immediately (rate-limited), trigger discovery, and reset the
    /// warmup counter for subsequent data packets.
    async fn handle_coords_required(&mut self, inner: &[u8]) {
        self.stats_mut().errors.coords_required += 1;

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
        if self
            .coords_response_rate_limiter
            .should_send(&msg.dest_addr)
        {
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

        // Only trigger discovery if we have the target's identity cached —
        // otherwise we can't verify the LookupResponse proof.
        if self.has_cached_identity(&msg.dest_addr) {
            self.maybe_initiate_lookup(&msg.dest_addr).await;
        } else {
            debug!(dest = %msg.dest_addr,
                "Skipping discovery after CoordsRequired: no cached identity for target");
        }

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
        self.stats_mut().errors.path_broken += 1;

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
        if self
            .coords_response_rate_limiter
            .should_send(&msg.dest_addr)
        {
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

        // Trigger re-discovery to get fresh coordinates, but only if we have
        // the target's identity cached — otherwise we can't verify the
        // LookupResponse proof. This avoids a race when the XX responder
        // receives PathBroken before msg3 completes (identity unknown).
        if self.has_cached_identity(&msg.dest_addr) {
            self.maybe_initiate_lookup(&msg.dest_addr).await;
        } else {
            debug!(dest = %msg.dest_addr,
                "Skipping discovery after PathBroken: no cached identity for target");
        }

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

    /// Handle an MtuExceeded error signal from a transit router.
    ///
    /// A transit router couldn't forward our packet because it exceeded the
    /// next-hop transport MTU. Apply the reported bottleneck MTU to our
    /// PathMtuState for the affected session, causing an immediate decrease.
    pub(in crate::node) async fn handle_mtu_exceeded(&mut self, inner: &[u8]) {
        self.stats_mut().errors.mtu_exceeded += 1;

        let msg = match MtuExceeded::decode(inner) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Malformed MtuExceeded");
                return;
            }
        };

        let peer_name = self.peer_display_name(&msg.dest_addr);
        debug!(
            dest = %peer_name,
            reporter = %msg.reporter,
            bottleneck_mtu = msg.mtu,
            "MtuExceeded: transit router reports oversized packet"
        );

        // Apply to PathMtuState: immediate decrease via apply_notification()
        if let Some(entry) = self.sessions.get_mut(&msg.dest_addr)
            && let Some(mmp) = entry.mmp_mut()
        {
            let old_mtu = mmp.path_mtu.current_mtu();
            let now = std::time::Instant::now();
            if mmp.path_mtu.apply_notification(msg.mtu, now) {
                let new_mtu = mmp.path_mtu.current_mtu();
                info!(
                    dest = %peer_name,
                    old_mtu,
                    new_mtu,
                    reporter = %msg.reporter,
                    "Path MTU decreased via reactive MtuExceeded signal"
                );
            }
        }

        // Mirror the bottleneck into the FipsAddress-keyed lookup used by
        // the TUN reader/writer at TCP MSS clamp time. Discovery's reverse-
        // path response can carry a value too generous for the actual
        // forward path; the reactive signal from a forwarder that actually
        // dropped a packet is authoritative for "what fits". Keep the
        // tighter of existing-or-new — never loosen the clamp.
        let fips_addr = crate::FipsAddress::from_node_addr(&msg.dest_addr);
        match self.path_mtu_lookup.write() {
            Ok(mut map) => match map.get(&fips_addr).copied() {
                Some(existing) if existing <= msg.mtu => {
                    debug!(
                        dest = %peer_name,
                        fips_addr = %fips_addr,
                        bottleneck_mtu = msg.mtu,
                        existing,
                        "Reactive MtuExceeded: keeping tighter existing path_mtu_lookup value"
                    );
                }
                other => {
                    map.insert(fips_addr, msg.mtu);
                    debug!(
                        dest = %peer_name,
                        fips_addr = %fips_addr,
                        bottleneck_mtu = msg.mtu,
                        prior = ?other,
                        map_len = map.len(),
                        "Reactive MtuExceeded: tightened path_mtu_lookup"
                    );
                }
            },
            Err(e) => {
                warn!(
                    dest = %peer_name,
                    fips_addr = %fips_addr,
                    bottleneck_mtu = msg.mtu,
                    error = %e,
                    "path_mtu_lookup write lock poisoned; reactive MtuExceeded not reflected"
                );
            }
        }
    }

    // === Session Initiation (Send Path) ===

    /// Initiate an end-to-end session with a remote node.
    ///
    /// Creates a Noise XX handshake as initiator, wraps msg1 in a
    /// SessionSetup, encapsulates in a SessionDatagram, and routes
    /// toward the destination.
    pub(in crate::node) async fn initiate_session(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: PublicKey,
    ) -> Result<(), NodeError> {
        // Check for existing session
        if let Some(existing) = self.sessions.get(&dest_addr)
            && (existing.is_established() || existing.is_initiating())
        {
            return Ok(());
        }

        // Create Noise XX initiator handshake
        let our_keypair = self.identity.keypair();
        let mut handshake = HandshakeState::new_initiator(our_keypair);
        handshake.set_local_epoch(self.startup_epoch);
        let msg1 = handshake
            .write_message_1()
            .map_err(|e| NodeError::SendFailed {
                node_addr: dest_addr,
                reason: format!("Noise XX msg1 generation failed: {}", e),
            })?;

        // Build SessionSetup with coordinates
        let our_coords = self.tree_state.my_coords().clone();
        let dest_coords = self.get_dest_coords(&dest_addr);
        let setup = SessionSetup::new(our_coords, dest_coords).with_handshake(msg1);
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
        let mut entry = SessionEntry::new(
            dest_addr,
            dest_pubkey,
            EndToEndState::Initiating(handshake),
            now_ms,
            true,
        );
        entry.set_handshake_payload(setup_payload, now_ms + resend_interval);
        self.sessions.insert(dest_addr, entry);

        debug!(dest = %self.peer_display_name(&dest_addr), "Session initiation started");
        Ok(())
    }

    /// Send application data over an established session.
    ///
    /// Uses the FSP pipeline: builds a 12-byte cleartext header (used as AAD),
    /// prepends the 6-byte inner header to the plaintext, encrypts with AAD,
    /// optionally inserts cleartext coords, and wraps in a SessionDatagram.
    ///
    /// The `src_port` and `dst_port` identify the service. A 4-byte port header
    /// `[src_port:2 LE][dst_port:2 LE]` is prepended to `payload` inside the
    /// AEAD envelope. The receiver dispatches by `dst_port`.
    pub(in crate::node) async fn send_session_data(
        &mut self,
        dest_addr: &NodeAddr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<(), NodeError> {
        let now_ms = Self::now_ms();

        // First borrow: read session metadata (NLL releases before coord decision)
        let entry = self
            .sessions
            .get(dest_addr)
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "no session".into(),
            })?;
        let wants_coords = entry.coords_warmup_remaining() > 0;
        let timestamp = entry.session_timestamp(now_ms);
        if !entry.is_established() {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "session not established".into(),
            });
        }

        // Build port-prefixed plaintext: [src_port:2 LE][dst_port:2 LE][payload...]
        let mut port_payload = Vec::with_capacity(FSP_PORT_HEADER_SIZE + payload.len());
        port_payload.extend_from_slice(&src_port.to_le_bytes());
        port_payload.extend_from_slice(&dst_port.to_le_bytes());
        port_payload.extend_from_slice(payload);

        // Build inner plaintext (doesn't depend on counter)
        let msg_type = SessionMessageType::DataPacket.to_byte(); // 0x10
        let inner_flags = FspInnerFlags::new().to_byte();
        let inner_plaintext =
            fsp_prepend_inner_header(timestamp, msg_type, inner_flags, &port_payload);

        // Determine whether coords fit within transport MTU.
        // If not, send standalone CoordsWarmup before the data packet.
        let (include_coords, my_coords, dest_coords) = if wants_coords {
            let src = self.tree_state.my_coords().clone();
            let dst = self.get_dest_coords(dest_addr);
            let coords_size = coords_wire_size(&src) + coords_wire_size(&dst);
            let total_wire =
                FIPS_OVERHEAD as usize + FSP_PORT_HEADER_SIZE + coords_size + payload.len();
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
        if wants_coords && let Some(entry) = self.sessions.get_mut(dest_addr) {
            entry.set_coords_warmup_remaining(entry.coords_warmup_remaining() - 1);
        }

        // Build FSP flags (CP flag if coords, K-bit for key epoch)
        let mut flags = if include_coords { FSP_FLAG_CP } else { 0 };
        if let Some(entry) = self.sessions.get(dest_addr)
            && entry.current_k_bit()
        {
            flags |= FSP_FLAG_K;
        }

        // ── Pipelined FSP+FMP fast path (unix + UDP) ──
        // Both AEAD layers + the sendmmsg syscall run on the encrypt
        // worker. The rx_loop only builds the wire buffer + reserves
        // counters on both sessions. Falls through to the legacy
        // sync FSP encrypt + send_session_datagram path on any
        // prereq miss (non-UDP, no worker, no cipher, …).
        #[cfg(unix)]
        if self
            .try_send_session_data_pipelined(PipelinedSend {
                dest_addr,
                payload,
                now_ms,
                timestamp,
                fsp_flags: flags,
                inner_plaintext: &inner_plaintext,
                my_coords: my_coords.as_ref(),
                dest_coords: dest_coords.as_ref(),
            })
            .await?
        {
            return Ok(());
        }

        // Borrow session for counter + encryption (after potential standalone send)
        let entry = self
            .sessions
            .get_mut(dest_addr)
            .ok_or_else(|| NodeError::SendFailed {
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
        let ciphertext = session
            .encrypt_with_aad(&inner_plaintext, &header)
            .map_err(|e| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("session encrypt failed: {}", e),
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
            entry.record_sent(payload.len());
            if let Some(mmp) = entry.mmp_mut() {
                mmp.sender.record_sent(counter, timestamp, ciphertext.len());
            }
            entry.touch(now_ms);
        }

        Ok(())
    }

    /// Pipelined send: FSP+FMP AEAD + sendmsg on the encrypt worker.
    ///
    /// Returns `Ok(true)` when the worker accepted the job (caller is
    /// done), `Ok(false)` on prereq miss (non-UDP, no worker, no
    /// cipher) so the caller falls back to the legacy synchronous
    /// path. `Err` on routing / state errors that prevent any send.
    ///
    /// Wire layout built directly (no intermediate `inner_plaintext`
    /// or `fsp_payload` Vecs):
    /// ```text
    ///   [16 FMP header][8 link-ts][1 SessionDatagram][1 ttl][2 mtu]
    ///   [16 src_addr][16 dest_addr][12 FSP header][coords?]
    ///   [FSP plaintext]    <- worker seals here, appends FSP tag,
    ///                         then seals the full FMP plaintext and
    ///                         appends the FMP tag.
    /// ```
    #[cfg(unix)]
    async fn try_send_session_data_pipelined(
        &mut self,
        send: PipelinedSend<'_>,
    ) -> Result<bool, NodeError> {
        let dest_addr = send.dest_addr;
        let Some(workers) = self.encrypt_workers.as_ref().cloned() else {
            return Ok(false);
        };

        let Some(next_hop_addr) = self.find_next_hop(dest_addr).map(|peer| *peer.node_addr())
        else {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "no route to destination".into(),
            });
        };

        // Read the next hop's transport / link MTU for the
        // SessionDatagram's path_mtu field. Saves a path_mtu round-
        // trip vs the legacy path where we'd seed in
        // send_session_datagram.
        let mut path_mtu = u16::MAX;
        if let Some(peer) = self.peers.get(&next_hop_addr)
            && let Some(tid) = peer.transport_id()
            && let Some(transport) = self.transports.get(&tid)
        {
            if let Some(addr) = peer.current_addr() {
                path_mtu = path_mtu.min(transport.link_mtu(addr));
            } else {
                path_mtu = path_mtu.min(transport.mtu());
            }
        }

        // Extract next-hop info + FMP cipher in one peers/sessions borrow scope.
        let (their_index, transport_id, remote_addr, timestamp_ms, fmp_flags, fmp_cipher) = {
            let peer = self
                .peers
                .get_mut(&next_hop_addr)
                .ok_or(NodeError::PeerNotFound(next_hop_addr))?;
            let their_index = peer.their_index().ok_or_else(|| NodeError::SendFailed {
                node_addr: next_hop_addr,
                reason: "no their_index".into(),
            })?;
            let transport_id = peer.transport_id().ok_or_else(|| NodeError::SendFailed {
                node_addr: next_hop_addr,
                reason: "no transport_id".into(),
            })?;
            let remote_addr =
                peer.current_addr()
                    .cloned()
                    .ok_or_else(|| NodeError::SendFailed {
                        node_addr: next_hop_addr,
                        reason: "no current_addr".into(),
                    })?;
            let timestamp_ms = peer.session_elapsed_ms();
            let mut fmp_flags = 0u8;
            if peer.current_k_bit() {
                fmp_flags |= FLAG_KEY_EPOCH;
            }
            let session = peer
                .noise_session_mut()
                .ok_or_else(|| NodeError::SendFailed {
                    node_addr: next_hop_addr,
                    reason: "no noise session".into(),
                })?;
            let Some(fmp_cipher) = session.send_cipher_clone() else {
                return Ok(false);
            };
            (
                their_index,
                transport_id,
                remote_addr,
                timestamp_ms,
                fmp_flags,
                fmp_cipher,
            )
        };
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let connected_socket = self
            .peers
            .get(&next_hop_addr)
            .and_then(|peer| peer.connected_udp());

        // Need a UDP transport (this whole path is sendmsg-on-raw-fd).
        let transport = self
            .transports
            .get(&transport_id)
            .ok_or(NodeError::TransportNotFound(transport_id))?;
        let TransportHandle::Udp(udp) = transport else {
            return Ok(false);
        };
        let socket_addr_opt = {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                match connected_socket.as_ref() {
                    Some(s) => Some(s.peer_addr()),
                    None => udp.resolve_for_off_task(&remote_addr).await.ok(),
                }
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                udp.resolve_for_off_task(&remote_addr).await.ok()
            }
        };
        let Some(socket_addr) = socket_addr_opt else {
            return Ok(false);
        };
        let Some(socket) = udp.async_socket() else {
            return Ok(false);
        };

        // FSP cipher + counter — separate session from next-hop FMP session.
        let (fsp_counter, fsp_cipher) = {
            let entry = self
                .sessions
                .get_mut(dest_addr)
                .ok_or_else(|| NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "no session".into(),
                })?;
            if let Some(mmp) = entry.mmp_mut() {
                mmp.path_mtu.seed_source_mtu(path_mtu);
            }
            let session = match entry.state_mut() {
                EndToEndState::Established(s) => s,
                _ => {
                    return Err(NodeError::SendFailed {
                        node_addr: *dest_addr,
                        reason: "session not established".into(),
                    });
                }
            };
            let Some(fsp_cipher) = session.send_cipher_clone() else {
                return Ok(false);
            };
            let counter = session
                .take_send_counter()
                .map_err(|e| NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: format!("session counter reservation failed: {}", e),
                })?;
            (counter, fsp_cipher)
        };

        // FSP header (the AAD for the inner AEAD seal).
        let fsp_header = build_fsp_header(
            fsp_counter,
            send.fsp_flags,
            send.inner_plaintext.len() as u16,
        );

        let coords_size = match (send.my_coords, send.dest_coords) {
            (Some(src), Some(dst)) => coords_wire_size(src) + coords_wire_size(dst),
            _ => 0,
        };
        // FMP inner = [link-ts u64][SessionDatagram-encoded after msg_type] + [FSP-encrypted blob]
        // SessionDatagram-encoded includes: [0x00 type][ttl][mtu][src][dest][fsp_payload]
        // fsp_payload = [fsp_header][coords][fsp_plaintext][16-byte FSP tag]
        let link_plaintext_len = SESSION_DATAGRAM_HEADER_SIZE
            + FSP_HEADER_SIZE
            + coords_size
            + send.inner_plaintext.len();
        let fmp_inner_len = 4 + link_plaintext_len + crate::noise::TAG_SIZE;

        // FMP counter + header (the AAD for the outer AEAD seal).
        let fmp_counter = {
            let peer = self
                .peers
                .get_mut(&next_hop_addr)
                .ok_or(NodeError::PeerNotFound(next_hop_addr))?;
            let session = peer
                .noise_session_mut()
                .ok_or_else(|| NodeError::SendFailed {
                    node_addr: next_hop_addr,
                    reason: "no noise session".into(),
                })?;
            session
                .take_send_counter()
                .map_err(|e| NodeError::SendFailed {
                    node_addr: next_hop_addr,
                    reason: format!("counter reservation failed: {}", e),
                })?
        };
        let fmp_header =
            build_established_header(their_index, fmp_counter, fmp_flags, fmp_inner_len as u16);

        // Build the wire buffer once, in place. The two FSP/FMP tags
        // are appended by the worker after the seals — reserve their
        // capacity here so the worker doesn't have to re-grow.
        let wire_capacity = ESTABLISHED_HEADER_SIZE + fmp_inner_len + crate::noise::TAG_SIZE;
        let mut wire_buf = Vec::with_capacity(wire_capacity);
        wire_buf.extend_from_slice(&fmp_header);
        wire_buf.extend_from_slice(&timestamp_ms.to_le_bytes());
        // SessionDatagram-encoded layout (matches `SessionDatagram::encode`):
        wire_buf.push(LinkMessageType::SessionDatagram.to_byte());
        wire_buf.push(self.config.node.session.default_ttl);
        wire_buf.extend_from_slice(&path_mtu.to_le_bytes());
        wire_buf.extend_from_slice(self.node_addr().as_bytes());
        wire_buf.extend_from_slice(dest_addr.as_bytes());
        // FSP layer (worker seals on `inner_plaintext` portion):
        let fsp_aad_offset = wire_buf.len();
        wire_buf.extend_from_slice(&fsp_header);
        if let (Some(src), Some(dst)) = (send.my_coords, send.dest_coords) {
            encode_coords(src, &mut wire_buf);
            encode_coords(dst, &mut wire_buf);
        }
        let fsp_plaintext_offset = wire_buf.len();
        wire_buf.extend_from_slice(send.inner_plaintext);

        // Stats update — predict size exactly (ChaCha20-Poly1305 tag
        // is constant 16 bytes).
        let predicted_bytes = wire_capacity;
        if let Some(peer) = self.peers.get_mut(&next_hop_addr) {
            peer.link_stats_mut().record_sent(predicted_bytes);
            if let Some(mmp) = peer.mmp_mut() {
                mmp.sender
                    .record_sent(fmp_counter, timestamp_ms, predicted_bytes);
            }
        }
        self.stats_mut()
            .forwarding
            .record_originated(link_plaintext_len + crate::noise::TAG_SIZE);

        if let Some(entry) = self.sessions.get_mut(dest_addr) {
            entry.record_sent(send.payload.len());
            if let Some(mmp) = entry.mmp_mut() {
                mmp.sender.record_sent(
                    fsp_counter,
                    send.timestamp,
                    send.inner_plaintext.len() + crate::noise::TAG_SIZE,
                );
            }
            entry.touch(send.now_ms);
        }

        workers.dispatch(crate::node::encrypt_worker::FmpSendJob {
            cipher: fmp_cipher,
            counter: fmp_counter,
            wire_buf,
            fsp_seal: Some(crate::node::encrypt_worker::FspSealJob {
                cipher: fsp_cipher,
                counter: fsp_counter,
                aad_offset: fsp_aad_offset,
                plaintext_offset: fsp_plaintext_offset,
            }),
            socket,
            dest_addr: socket_addr,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket,
            // Bulk endpoint data: drop on UDP backpressure so the
            // worker queue keeps moving instead of stranding under
            // sustained congestion.
            drop_on_backpressure: true,
            queued_at: None,
        });
        Ok(true)
    }

    /// Send an IPv6 packet through the IPv6 shim (port 256) with header compression.
    ///
    /// Compresses the IPv6 header (format 0x00), then sends via `send_session_data`
    /// with `src_port=256, dst_port=256`.
    pub(in crate::node) async fn send_ipv6_packet(
        &mut self,
        dest_addr: &NodeAddr,
        ipv6_packet: &[u8],
    ) -> Result<(), NodeError> {
        let compressed = crate::upper::ipv6_shim::compress_ipv6(ipv6_packet).ok_or_else(|| {
            NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "IPv6 header compression failed".into(),
            }
        })?;
        self.send_session_data(
            dest_addr,
            FSP_PORT_IPV6_SHIM,
            FSP_PORT_IPV6_SHIM,
            &compressed,
        )
        .await
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
        let entry = self
            .sessions
            .get(dest_addr)
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "no session".into(),
            })?;
        let timestamp = entry.session_timestamp(now_ms);

        let inner_flags = FspInnerFlags::new().to_byte();

        // Get mutable access for encryption
        let entry = self
            .sessions
            .get_mut(dest_addr)
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "no session".into(),
            })?;

        // Read K-bit before mutable borrow of session state
        let k_flags = if entry.current_k_bit() { FSP_FLAG_K } else { 0 };

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

        // Build 12-byte FSP header (K-bit for key epoch, no CP for reports)
        let payload_len = inner_plaintext.len() as u16;
        let header = build_fsp_header(counter, k_flags, payload_len);

        // Encrypt with AAD
        let ciphertext = session
            .encrypt_with_aad(&inner_plaintext, &header)
            .map_err(|e| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("session encrypt failed: {}", e),
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
    async fn send_coords_warmup(&mut self, dest_addr: &NodeAddr) -> Result<(), NodeError> {
        let now_ms = Self::now_ms();

        let my_coords = self.tree_state.my_coords().clone();
        let dest_coords = self.get_dest_coords(dest_addr);

        // Read session metadata
        let entry = self
            .sessions
            .get(dest_addr)
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "no session".into(),
            })?;
        let timestamp = entry.session_timestamp(now_ms);

        // Get mutable access for encryption
        let entry = self
            .sessions
            .get_mut(dest_addr)
            .ok_or_else(|| NodeError::SendFailed {
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
        let inner_flags = FspInnerFlags::new().to_byte();
        let inner_plaintext = fsp_prepend_inner_header(timestamp, msg_type, inner_flags, &[]);

        // Build FSP header with CP flag
        let payload_len = inner_plaintext.len() as u16;
        let header = build_fsp_header(counter, FSP_FLAG_CP, payload_len);

        // Encrypt with AAD
        let ciphertext = session
            .encrypt_with_aad(&inner_plaintext, &header)
            .map_err(|e| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: format!("session encrypt failed: {}", e),
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
            if let Some(addr) = peer.current_addr() {
                datagram.path_mtu = datagram.path_mtu.min(transport.link_mtu(addr));
            } else {
                datagram.path_mtu = datagram.path_mtu.min(transport.mtu());
            }
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
        self.send_encrypted_link_message(&next_hop_addr, &encoded)
            .await?;
        self.stats_mut().forwarding.record_originated(encoded.len());
        Ok(())
    }

    /// Look up destination coordinates from available caches.
    ///
    /// Returns our own coordinates as a fallback (the SessionSetup will
    /// carry src_coords for return path routing; empty dest_coords
    /// would fail wire encoding since TreeCoordinate requires ≥1 entry).
    pub(in crate::node) fn get_dest_coords(&self, dest: &NodeAddr) -> crate::tree::TreeCoordinate {
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
            self.send_icmpv6_packet_too_big(&ipv6_packet, effective_mtu as u32);
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
                // Check per-destination path MTU learned from MtuExceeded signals.
                // The first oversized packet is forwarded normally and triggers
                // the MtuExceeded signal; subsequent packets are caught here and
                // generate ICMPv6 Packet Too Big back to the application.
                if let Some(mmp) = entry.mmp() {
                    let path_mtu = mmp.path_mtu.current_mtu();
                    let path_ipv6_mtu = crate::upper::icmp::effective_ipv6_mtu(path_mtu) as usize;
                    if path_ipv6_mtu < effective_mtu && ipv6_packet.len() > path_ipv6_mtu {
                        self.send_icmpv6_packet_too_big(&ipv6_packet, path_ipv6_mtu as u32);
                        return;
                    }
                }
                if let Err(e) = self.send_ipv6_packet(&dest_addr, &ipv6_packet).await {
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
        use crate::FipsAddress;
        use crate::upper::icmp::{
            DestUnreachableCode, build_dest_unreachable, should_send_icmp_error,
        };

        if !should_send_icmp_error(original_packet) {
            return;
        }

        let our_ipv6 = FipsAddress::from_node_addr(self.node_addr()).to_ipv6();
        if let Some(response) =
            build_dest_unreachable(original_packet, DestUnreachableCode::NoRoute, our_ipv6)
            && let Some(tun_tx) = &self.tun_tx
        {
            let _ = tun_tx.send(response);
        }
    }

    /// Send ICMPv6 Packet Too Big back through TUN.
    ///
    /// Rate-limited per source address to prevent ICMP floods from
    /// misconfigured applications sending repeated oversized packets.
    pub(in crate::node) fn send_icmpv6_packet_too_big(&mut self, original_packet: &[u8], mtu: u32) {
        use crate::upper::icmp::build_packet_too_big;
        use std::net::Ipv6Addr;

        // Extract source address for rate limiting
        if original_packet.len() < 40 {
            return;
        }
        // SAFETY: slice is exactly 16 bytes; length validated above (>= 40)
        let src_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&original_packet[8..24]).unwrap());

        // Rate limit ICMP PTB messages per source
        if !self.icmp_rate_limiter.should_send(src_addr) {
            debug!(
                src = %src_addr,
                "Rate limiting ICMP Packet Too Big"
            );
            return;
        }

        // Use the original packet's *destination* as the ICMP source so the
        // kernel sees the PTB coming from a remote router, not from itself.
        // Linux ignores PTBs whose source matches a local address, which
        // causes a PMTUD blackhole when both src and ICMP-src are local.
        // SAFETY: slice is exactly 16 bytes; length validated above (>= 40)
        let dest_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&original_packet[24..40]).unwrap());
        if let Some(response) = build_packet_too_big(original_packet, mtu, dest_addr)
            && let Some(tun_tx) = &self.tun_tx
        {
            debug!(
                original_src = %src_addr,
                original_dst = %dest_addr,
                packet_size = original_packet.len(),
                reported_mtu = mtu,
                "Sending ICMP Packet Too Big"
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

        let queue = self.pending_tun_packets.entry(dest_addr).or_default();
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
            if let Err(e) = self.send_ipv6_packet(dest_addr, &packet).await {
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
            && (existing.is_established() || existing.is_initiating())
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

/// Mark ECN-CE in an IPv6 packet's Traffic Class field.
///
/// IPv6 Traffic Class occupies bits across bytes 0 and 1:
///   byte[0] bits[3:0] = TC[7:4]
///   byte[1] bits[7:4] = TC[3:0]
/// ECN is TC[1:0]. Only marks CE (0b11) if the packet is ECN-capable
/// (ECT(0) or ECT(1)). Packets with ECN=0b00 (Not-ECT) are never marked
/// per RFC 3168.
///
/// No checksum update needed: IPv6 has no header checksum, and the Traffic
/// Class field is not part of the TCP/UDP pseudo-header.
pub(in crate::node) fn mark_ipv6_ecn_ce(packet: &mut [u8]) {
    if packet.len() < 2 {
        return;
    }
    // Extract 8-bit Traffic Class from IPv6 header bytes 0-1
    let tc = ((packet[0] & 0x0F) << 4) | (packet[1] >> 4);
    let ecn = tc & 0x03;
    // Only mark CE on ECN-capable packets (ECT(0)=0b10 or ECT(1)=0b01)
    if ecn == 0 {
        return;
    }
    // Set both ECN bits to 1 (CE = 0b11)
    let new_tc = tc | 0x03;
    packet[0] = (packet[0] & 0xF0) | (new_tc >> 4);
    packet[1] = (new_tc << 4) | (packet[1] & 0x0F);
}
