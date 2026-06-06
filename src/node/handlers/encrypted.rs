//! Encrypted frame handling (hot path).

use crate::node::Node;
use crate::node::wire::{EncryptedHeader, FLAG_CE, FLAG_KEY_EPOCH, strip_inner_header};
use crate::noise::NoiseError;
use crate::transport::ReceivedPacket;
use std::time::Instant;
use tracing::{debug, trace, warn};

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
        //
        // The header K-bit is NOT a sufficient gating event on its own.
        // Under jitter the FMP rekey interval shrinks and the two
        // directions' rekeys interleave, so a node can hold a `pending`
        // session from rekey N while the peer's observed K-bit flip
        // actually belongs to rekey N+1. Promoting on the bare bit then
        // installs the WRONG Noise session as current — the two endpoints
        // diverge, every subsequent frame fails AEAD on the far side, the
        // receiver starves, and the link is declared dead at the 30s
        // heartbeat timeout (Phase-5 routing failure, green crypto). This
        // mirrors the FSP fix (node/session.rs): the authenticated decrypt,
        // not the header bit, is the cutover signal. Trial-decrypt the
        // frame against `pending` first; only promote if it authenticates.
        {
            let Some(peer) = self.peers.get(&node_addr) else {
                return;
            };
            let k_bit_flipped =
                received_k_bit != peer.current_k_bit() && peer.pending_new_session().is_some();

            if k_bit_flipped {
                let ciphertext = &packet.data[header.ciphertext_offset()..];
                let display_name = self.peer_display_name(&node_addr);
                let our_addr = *self.identity().node_addr();
                let Some(peer) = self.peers.get_mut(&node_addr) else {
                    return;
                };
                // Authenticate the frame against the pending session.
                let pending_plaintext = peer.pending_new_session_mut().and_then(|pending| {
                    pending
                        .decrypt_with_replay_check_and_aad(
                            ciphertext,
                            header.counter,
                            &header.header_bytes,
                        )
                        .ok()
                });

                if let Some(plaintext) = pending_plaintext {
                    let pending_our = peer.pending_our_index();
                    let pending_their = peer.pending_their_index();
                    debug!(
                        peer = %display_name,
                        our_addr = %our_addr,
                        their_addr = %node_addr,
                        pending_our_index = ?pending_our,
                        pending_their_index = ?pending_their,
                        "Peer new-epoch frame authenticated, K-bit flip promoting new session"
                    );
                    // The peer authenticated a frame on the new epoch, so it
                    // derived the new session (it received our rekey msg3).
                    // If we are the rekey initiator still retransmitting msg3,
                    // stop — the responder is confirmed. (No-op for the
                    // responder side, which never retained a msg3 payload.)
                    peer.clear_rekey_msg3_payload();
                    // The trial-decrypt already advanced the pending
                    // session's replay window; handle_peer_kbit_flip moves
                    // that same session object to current, so no re-decrypt.
                    let did_flip = peer.handle_peer_kbit_flip().is_some();
                    if did_flip {
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
                    // Re-register the promoted session with the decrypt
                    // worker (cache_key changed at the flip).
                    #[cfg(unix)]
                    if did_flip {
                        self.register_decrypt_worker_session(&node_addr);
                    }

                    // Deliver the frame we just authenticated via the
                    // canonical post-decrypt path, then return — it must
                    // not fall through to a second decrypt attempt.
                    let ce_flag = header.flags & FLAG_CE != 0;
                    self.process_authentic_fmp_plaintext(
                        &node_addr,
                        packet.transport_id,
                        &packet.remote_addr,
                        packet.timestamp_ms,
                        packet.data.len(),
                        header.counter,
                        ce_flag,
                        &plaintext,
                    )
                    .await;
                    return;
                }
                // Pending did NOT authenticate this frame: the flip belongs
                // to a different rekey epoch (stale pending). Do not
                // promote. Fall through to the normal current/previous
                // decrypt; the genuine cutover is recognized when a frame
                // that authenticates against `pending` arrives.
            }
        }

        // ── Decrypt-worker fast path (unix) ─────────────────────────
        // Once the session has been registered with a decrypt shard
        // (at FMP-establishment in `promote_connection`), the worker
        // owns the FMP recv cipher + replay window. Dispatch the
        // packet and return; the worker will run AEAD off-task and
        // bounce the plaintext back via `decrypt_fallback_tx` for
        // rx_loop to do the post-decrypt side-effects.
        //
        // The in-line decrypt below is the **synchronous test-mode
        // path** for unit tests that construct `Node` without
        // `lifecycle::start_async`; in production every established
        // session is dispatched to the worker.
        #[cfg(unix)]
        {
            let cache_key = (packet.transport_id, header.receiver_idx.as_u32());
            if let Some(workers) = self.decrypt_workers.as_ref().cloned()
                && self.decrypt_registered_sessions.contains(&cache_key)
            {
                let job = crate::node::decrypt_worker::DecryptJob {
                    packet_data: packet.data,
                    cache_key,
                    _transport_id: packet.transport_id,
                    _remote_addr: packet.remote_addr,
                    timestamp_ms: packet.timestamp_ms,
                    source_node_addr: node_addr,
                    fmp_counter: header.counter,
                    fmp_flags: header.flags,
                    fmp_header: header.header_bytes,
                    fmp_ciphertext_offset: header.ciphertext_offset(),
                    fallback_tx: self.decrypt_fallback_tx.clone(),
                };
                workers.dispatch_job(job);
                return;
            }
        }

        // Decrypt: try current session first, then previous (drain fallback)
        let ciphertext = &packet.data[header.ciphertext_offset()..];
        let plaintext = {
            let Some(peer) = self.peers.get_mut(&node_addr) else {
                return;
            };
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

        if let Some(peer) = self.peers.get_mut(&node_addr) {
            // Initiator-side msg3 confirm (see process_authentic_fmp_plaintext):
            // a frame authenticated against post-cutover `current` (no pending)
            // proves the responder reached the new epoch. Inline-decrypt path
            // mirror of the worker-bounce confirm.
            if peer.rekey_msg3_payload().is_some() && peer.pending_new_session().is_none() {
                peer.clear_rekey_msg3_payload();
            }
            if let Some(mmp) = peer.mmp_mut() {
                mmp.receiver.record_recv(
                    header.counter,
                    timestamp,
                    packet.data.len(),
                    ce_flag,
                    now,
                );
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

    /// Canonical post-FMP-decrypt side-effect site. Used by both the
    /// inline rx_loop decrypt path and the decrypt-worker bounce path
    /// so the per-peer bookkeeping (stats, MMP, spin-bit RTT, ECN
    /// propagation, address-rotation handling, link-message dispatch)
    /// happens in exactly one place.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::node) async fn process_authentic_fmp_plaintext(
        &mut self,
        node_addr: &crate::NodeAddr,
        transport_id: crate::transport::TransportId,
        remote_addr: &crate::transport::TransportAddr,
        packet_timestamp_ms: u64,
        packet_len: usize,
        fmp_counter: u64,
        ce_flag: bool,
        fmp_plaintext: &[u8],
    ) {
        const INNER_TIMESTAMP_LEN: usize = 4;
        let inner_ts = if fmp_plaintext.len() >= INNER_TIMESTAMP_LEN {
            u32::from_le_bytes([
                fmp_plaintext[0],
                fmp_plaintext[1],
                fmp_plaintext[2],
                fmp_plaintext[3],
            ])
        } else {
            return;
        };
        let now = Instant::now();
        let mut address_changed = false;
        if let Some(peer) = self.peers.get_mut(node_addr) {
            peer.reset_decrypt_failures();
            // If we are the rekey initiator that already cut over on its
            // own timer (no `pending`, `current` is the new session) but
            // still retain a msg3 retransmission payload, an authenticated
            // peer frame here decrypts against the post-cutover `current`
            // session — proof the responder reached the new epoch. Stop
            // retransmitting. Mirrors the FSP Current-slot confirm in
            // handle_encrypted_session_msg. Works in both the inline and
            // worker-bounce paths since both funnel through here, and the
            // only session registered for the new index is the new one.
            if peer.rekey_msg3_payload().is_some() && peer.pending_new_session().is_none() {
                peer.clear_rekey_msg3_payload();
            }
            address_changed = peer.set_current_addr(transport_id, remote_addr.clone());
            peer.link_stats_mut()
                .record_recv(packet_len, packet_timestamp_ms);
            peer.touch(packet_timestamp_ms);
            if let Some(mmp) = peer.mmp_mut() {
                mmp.receiver
                    .record_recv(fmp_counter, inner_ts, packet_len, ce_flag, now);
            }
        }
        // Address rotation invalidates the per-peer connect()-ed UDP
        // socket. Drop the connected socket + drain so the wildcard
        // listen socket takes over until the new 5-tuple settles.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if address_changed {
            self.clear_connected_udp_for_peer(node_addr);
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = address_changed;
        }
        let link_message = &fmp_plaintext[INNER_TIMESTAMP_LEN..];
        self.dispatch_link_message(node_addr, link_message, ce_flag)
            .await;
    }

    /// Process a decrypt-worker bounce (FMP plaintext only — the
    /// worker has already done the AEAD + replay check).
    #[cfg(unix)]
    pub(in crate::node) async fn process_decrypt_fallback(
        &mut self,
        fallback: crate::node::decrypt_worker::DecryptFallback,
    ) {
        let ce_flag = fallback.fmp_flags & FLAG_CE != 0;
        let plaintext = &fallback.packet_data[fallback.fmp_plaintext_offset
            ..fallback.fmp_plaintext_offset + fallback.fmp_plaintext_len];
        self.process_authentic_fmp_plaintext(
            &fallback.source_node_addr,
            fallback.transport_id,
            &fallback.remote_addr,
            fallback.timestamp_ms,
            fallback.packet_len,
            fallback.fmp_counter,
            ce_flag,
            plaintext,
        )
        .await;
    }

    /// Process a decrypt-worker failure event.
    #[cfg(unix)]
    pub(in crate::node) async fn process_decrypt_failure_report(
        &mut self,
        report: crate::node::decrypt_worker::DecryptFailureReport,
    ) {
        debug!(
            peer = %self.peer_display_name(&report.source_node_addr),
            counter = report.fmp_counter,
            replay_highest = report.fmp_replay_highest,
            "Worker FMP AEAD decryption failed"
        );
        self.handle_decrypt_failure(&report.source_node_addr);
    }

    /// Dispatch a decrypt-worker event (plaintext bounce or failure
    /// report) to the appropriate handler.
    #[cfg(unix)]
    pub(in crate::node) async fn process_decrypt_worker_event(
        &mut self,
        event: crate::node::decrypt_worker::DecryptWorkerEvent,
    ) {
        match event {
            crate::node::decrypt_worker::DecryptWorkerEvent::Plaintext(fallback) => {
                self.process_decrypt_fallback(fallback).await;
            }
            crate::node::decrypt_worker::DecryptWorkerEvent::DecryptFailure(report) => {
                self.process_decrypt_failure_report(report).await;
            }
        }
    }

    /// Hand a session's FMP recv cipher + replay window off to a shard
    /// of the decrypt worker pool. Idempotent on rekey: re-registering
    /// the same cache_key overwrites the worker's entry. Gates the
    /// `decrypt_registered_sessions` insert on actual worker acceptance
    /// so a `TrySendError::Full` on the per-worker channel doesn't
    /// black-hole the session.
    #[cfg(unix)]
    pub(in crate::node) fn register_decrypt_worker_session(&mut self, node_addr: &crate::NodeAddr) {
        let Some(workers) = self.decrypt_workers.as_ref().cloned() else {
            return;
        };
        let (cache_key, state) = {
            let Some(peer) = self.peers.get(node_addr) else {
                return;
            };
            let Some(transport_id) = peer.transport_id() else {
                return;
            };
            let Some(our_index) = peer.our_index() else {
                return;
            };
            let cache_key = (transport_id, our_index.as_u32());
            let Some(state) = self.build_owned_session_state(node_addr) else {
                return;
            };
            (cache_key, state)
        };
        if workers.register_session(cache_key, state) {
            self.decrypt_registered_sessions.insert(cache_key);
        }
    }

    /// Drop a session from the decrypt worker pool. Mirror of
    /// `register_decrypt_worker_session`. Idempotent: safe to call on a
    /// `cache_key` that isn't registered, and safe to call when the
    /// worker pool is disabled (`FIPS_DECRYPT_WORKERS=0`).
    ///
    /// Called from two sites that already iterate `peers_by_index`:
    /// the rekey drain-completion block (after the drain window has
    /// expired, the old `our_index` is unreachable to any in-flight
    /// OLD-K packet) and `remove_active_peer` (terminal peer cleanup).
    /// Without these callers, the per-worker `sessions` HashMap and
    /// the Node's `decrypt_registered_sessions` set would grow
    /// monotonically per rekey on long-lived peers.
    #[cfg(unix)]
    pub(in crate::node) fn unregister_decrypt_worker_session(
        &mut self,
        cache_key: (crate::transport::TransportId, u32),
    ) {
        if let Some(workers) = self.decrypt_workers.as_ref() {
            workers.unregister_session(cache_key);
        }
        self.decrypt_registered_sessions.remove(&cache_key);
    }

    /// Snapshot the per-peer FMP recv cipher + replay window for the
    /// decrypt worker. Returns `None` if the peer / session isn't
    /// ready. After hand-off the worker is the sole FMP replay-window
    /// authority for this session.
    #[cfg(unix)]
    fn build_owned_session_state(
        &self,
        node_addr: &crate::NodeAddr,
    ) -> Option<crate::node::decrypt_worker::OwnedSessionState> {
        let peer = self.peers.get(node_addr)?;
        let fmp_session = peer.noise_session()?;
        let fmp_cipher = fmp_session.recv_cipher_clone()?;
        let fmp_replay = fmp_session.recv_replay_snapshot_owned();
        Some(crate::node::decrypt_worker::OwnedSessionState {
            fmp_cipher,
            fmp_replay,
            source_npub: None,
        })
    }

    /// Increment decrypt failure counter and force-remove peer if threshold exceeded.
    pub(in crate::node) fn handle_decrypt_failure(&mut self, node_addr: &crate::NodeAddr) {
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
