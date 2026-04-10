//! Encrypted frame handling (hot path).

use crate::node::Node;
use crate::node::wire::{EncryptedHeader, FLAG_CE, FLAG_KEY_EPOCH, FLAG_SP, strip_inner_header};
use crate::noise::NoiseError;
use crate::transport::ReceivedPacket;
use std::time::Instant;
use tracing::{debug, info, trace, warn};

/// Force-remove a peer after this many consecutive decryption failures.
const DECRYPT_FAILURE_THRESHOLD: u32 = 20;

impl Node {
    /// Handle an encrypted frame (phase 0x0).
    ///
    /// This is the hot path for established sessions. We use O(1)
    /// index-based lookup to find the session, then decrypt.
    ///
    /// K-bit handling: when the peer flips the K-bit after a rekey,
    /// we promote the pending new session to current and demote the old
    /// session to previous for a drain window. During drain, we try the
    /// current session first, then fall back to the previous session.
    pub(in crate::node) async fn handle_encrypted_frame(&mut self, packet: ReceivedPacket) {
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
                trace!(
                    receiver_idx = %header.receiver_idx,
                    transport_id = %packet.transport_id,
                    "Unknown session index, dropping"
                );
                return;
            }
        };

        if !self.peers.contains_key(&node_addr) {
            self.peers_by_index.remove(&key);
            return;
        }

        // Extract K-bit from flags
        let received_k_bit = header.flags & FLAG_KEY_EPOCH != 0;

        // K-bit flip detection: peer has cut over to the new session.
        // Check and perform cutover in a scoped borrow.
        {
            let peer = self.peers.get(&node_addr).unwrap();
            let k_bit_flipped =
                received_k_bit != peer.current_k_bit() && peer.pending_new_session().is_some();

            if k_bit_flipped {
                let display_name = self.peer_display_name(&node_addr);
                info!(
                    peer = %display_name,
                    "Peer K-bit flip detected, promoting new session"
                );

                let peer = self.peers.get_mut(&node_addr).unwrap();
                if let Some(_old_our_index) = peer.handle_peer_kbit_flip() {
                    // New index was pre-registered in peers_by_index during
                    // msg1 handling (handshake.rs). Verify, don't duplicate.
                    debug_assert!(
                        peer.transport_id().is_some()
                            && peer.our_index().is_some()
                            && self.peers_by_index.contains_key(&(
                                peer.transport_id().unwrap(),
                                peer.our_index().unwrap().as_u32()
                            )),
                        "peers_by_index should contain pre-registered new index after K-bit flip"
                    );
                }
            }
        }

        // Decrypt: try current session first, then previous (drain fallback)
        let ciphertext = &packet.data[header.ciphertext_offset()..];
        let plaintext = {
            let peer = self.peers.get_mut(&node_addr).unwrap();
            let session = match peer.noise_session_mut() {
                Some(s) => s,
                None => {
                    warn!(
                        peer = %self.peer_display_name(&node_addr),
                        "Peer in index map has no session"
                    );
                    return;
                }
            };

            match session.decrypt_with_replay_check_and_aad(
                ciphertext,
                header.counter,
                &header.header_bytes,
            ) {
                Ok(p) => {
                    peer.reset_decrypt_failures();
                    p
                }
                Err(e) => {
                    // Current session failed — try previous session (drain window)
                    if let Some(prev_session) = peer.previous_session_mut() {
                        match prev_session.decrypt_with_replay_check_and_aad(
                            ciphertext,
                            header.counter,
                            &header.header_bytes,
                        ) {
                            Ok(p) => {
                                peer.reset_decrypt_failures();
                                p
                            }
                            Err(_) => {
                                self.log_decrypt_failure(&node_addr, &header, &e);
                                self.handle_decrypt_failure(&node_addr);
                                return;
                            }
                        }
                    } else {
                        self.log_decrypt_failure(&node_addr, &header, &e);
                        self.handle_decrypt_failure(&node_addr);
                        return;
                    }
                }
            }
        };

        // === PACKET IS AUTHENTIC ===

        // Strip inner header (4-byte timestamp + msg_type)
        let (timestamp, link_message) = match strip_inner_header(&plaintext) {
            Some(parts) => parts,
            None => {
                debug!(
                    peer = %self.peer_display_name(&node_addr),
                    len = plaintext.len(),
                    "Decrypted payload too short for inner header"
                );
                return;
            }
        };

        // MMP per-frame processing and statistics
        let now = Instant::now();
        let ce_flag = header.flags & FLAG_CE != 0;
        let sp_flag = header.flags & FLAG_SP != 0;

        if let Some(peer) = self.peers.get_mut(&node_addr) {
            if let Some(mmp) = peer.mmp_mut() {
                mmp.receiver.record_recv(
                    header.counter,
                    timestamp,
                    packet.data.len(),
                    ce_flag,
                    now,
                );
                let _spin_rtt = mmp.spin_bit.rx_observe(sp_flag, header.counter, now);
            }
            peer.set_current_addr(packet.transport_id, packet.remote_addr.clone());
            peer.link_stats_mut()
                .record_recv(packet.data.len(), packet.timestamp_ms);
            peer.touch(packet.timestamp_ms);
        }

        // Dispatch to link message handler
        self.dispatch_link_message(&node_addr, link_message, ce_flag)
            .await;
    }

    /// Log a decryption failure with replay suppression.
    fn log_decrypt_failure(
        &mut self,
        node_addr: &crate::NodeAddr,
        header: &EncryptedHeader,
        error: &NoiseError,
    ) {
        if matches!(error, NoiseError::ReplayDetected(_)) {
            if let Some(peer) = self.peers.get_mut(node_addr) {
                let count = peer.increment_replay_suppressed();
                if count <= 3 {
                    debug!(
                        peer = %self.peer_display_name(node_addr),
                        counter = header.counter,
                        error = %error,
                        "Decryption failed"
                    );
                } else if count == 4 {
                    debug!(
                        peer = %self.peer_display_name(node_addr),
                        "Suppressing further replay detection messages"
                    );
                }
            } else {
                debug!(
                    peer = %self.peer_display_name(node_addr),
                    counter = header.counter,
                    error = %error,
                    "Decryption failed"
                );
            }
        } else {
            debug!(
                peer = %self.peer_display_name(node_addr),
                counter = header.counter,
                error = %error,
                "Decryption failed"
            );
        }
    }

    /// Increment decrypt failure counter and force-remove peer if threshold exceeded.
    fn handle_decrypt_failure(&mut self, node_addr: &crate::NodeAddr) {
        if let Some(peer) = self.peers.get_mut(node_addr) {
            let count = peer.increment_decrypt_failures();
            if count >= DECRYPT_FAILURE_THRESHOLD {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    consecutive_failures = count,
                    "Excessive decryption failures, removing peer"
                );
                let addr = *node_addr;
                self.remove_active_peer(node_addr);
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                self.schedule_reconnect(addr, now_ms);
            }
        }
    }
}
