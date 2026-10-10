//! Encrypted frame handling (hot path).

use crate::node::Node;
use crate::noise::NoiseError;
use crate::proto::fmp::wire::{
    EncryptedHeader, FLAG_CE, FLAG_KEY_EPOCH, FLAG_SP, strip_inner_header,
};
use crate::proto::link::LinkMessageType;
use crate::transport::ReceivedPacket;
use tracing::{debug, trace, warn};

/// Consecutive decryption failures at which a peer's warning is logged. The
/// peer is kept; a broken session ends at the link-dead timeout.
const DECRYPT_FAILURE_THRESHOLD: u32 = 20;

/// Which of a peer's link sessions authenticated an inbound frame.
///
/// After a rekey cutover the previous session still decrypts during the
/// drain, so frames the peer sealed before it moved are delivered. They
/// describe the session the cutover retired, though, and the new session's
/// MMP state was reset at the cutover: a previous-session frame is not
/// counted by the MMP receiver or the spin bit, and a ReceiverReport it
/// carries is not processed. A frame authenticated by a pending session is
/// promoted to current before it is processed, so it is `Current`.
///
/// The link-dead check reads the MMP receiver's last-received time, which the
/// cutover clears, so previous-session frames no longer hold the link alive:
/// after a cutover the link-dead timer runs from the cutover until a frame on
/// the new session arrives. Peer `touch` and link statistics still see them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::node) enum LinkSlot {
    Current,
    Previous,
}

impl Node {
    /// Handle an encrypted frame (phase 0x0).
    ///
    /// This is the hot path for established sessions. We use O(1)
    /// index-based lookup to find the session, then decrypt.
    ///
    /// Rekey cutover: when a frame that names the pending new session's
    /// index, or carries a flipped K-bit, authenticates against that
    /// session, we promote it to current, take the frame's K-bit, and demote
    /// the old session to previous for a drain window. During drain, we try
    /// the current session first, then fall back to the previous session.
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

        // Pending-session trial: the peer may have cut over to the new
        // session.
        //
        // A frame naming the pending session's receiver index was sealed for
        // that session, so it is always tried there. The K-bit alone is not
        // enough to select the trial: the two ends' bits can fall out of
        // step (a peer restart revealed by our rekey, or a second-path dial
        // the peer completes as a cross-connection swap), and then the
        // peer's frames on the new session carry a K-bit equal to ours. A
        // frame with a flipped K-bit is still tried too, as before.
        //
        // Neither signal is a reason to promote; only the trial is.
        // Under jitter the FMP rekey interval shrinks and the two
        // directions' rekeys interleave, so a node can hold a `pending`
        // session from rekey N while the peer's observed K-bit flip
        // actually belongs to rekey N+1. Promoting on the bare bit then
        // installs the WRONG Noise session as current — the two endpoints
        // diverge, every subsequent frame fails AEAD on the far side, the
        // receiver starves, and the link is declared dead at the heartbeat
        // timeout (routing failure, green crypto). This mirrors the FSP fix
        // (node/session.rs / node/handlers/session.rs): the authenticated
        // decrypt, not the header bit, is the cutover signal. Trial-decrypt
        // the frame against `pending` first; only promote if it
        // authenticates. On success the same frame is delivered via
        // `process_authentic_fmp_plaintext` and we return — it must not
        // fall through to a second decrypt, which would be rejected as a
        // replay (the trial-decrypt already advanced `pending`'s window).
        {
            let Some(peer) = self.peers.get(&node_addr) else {
                return;
            };
            let try_pending = peer.pending_new_session().is_some()
                && (received_k_bit != peer.current_k_bit()
                    || peer.pending_our_index() == Some(header.receiver_idx));
            // Test-only: model a peer that tries the pending session only on
            // a flipped K-bit.
            #[cfg(test)]
            let try_pending =
                try_pending && (!peer.old_gate() || received_k_bit != peer.current_k_bit());

            if try_pending {
                let ciphertext = &packet.data[header.ciphertext_offset()..];
                let display_name = self.peer_display_name(&node_addr);
                let Some(peer) = self.peers.get_mut(&node_addr) else {
                    return;
                };
                // Authenticate the frame against the pending session.
                // Trial-decrypt mutates `pending`'s replay window only on
                // success, so a failed trial leaves it untouched.
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
                    debug!(
                        peer = %display_name,
                        "Peer new-epoch frame authenticated, K-bit flip promoting new session"
                    );
                    // The trial-decrypt already advanced the pending
                    // session's replay window; `adopt_pending` moves that
                    // same session object to `current`, so no re-decrypt,
                    // and takes the K-bit from this authenticated frame.
                    let did_flip = peer.adopt_pending(received_k_bit).is_some();
                    if did_flip {
                        // New index was pre-registered in peers_by_index
                        // during msg1 handling (handshake.rs). Verify,
                        // don't duplicate.
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
                    // Re-register the (now-promoted) session with the
                    // decrypt worker: cache_key = (transport_id, our_index)
                    // changed at the flip, so the old worker entry is
                    // stranded and every packet on the new session would
                    // miss the worker's HashMap lookup. Without this,
                    // throughput drops back to the inline-decrypt path
                    // after each rekey.
                    #[cfg(unix)]
                    if did_flip {
                        self.register_decrypt_worker_session(&node_addr);
                    }

                    // Deliver the frame we just authenticated via the
                    // canonical post-decrypt path, then return — it must
                    // not fall through to a second decrypt attempt.
                    let ce_flag = header.flags & FLAG_CE != 0;
                    let sp_flag = header.flags & FLAG_SP != 0;
                    self.process_authentic_fmp_plaintext(
                        &node_addr,
                        LinkSlot::Current,
                        packet.transport_id,
                        &packet.remote_addr,
                        packet.timestamp_ms,
                        packet.data.len(),
                        header.counter,
                        ce_flag,
                        sp_flag,
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
            if let Some(workers) = self.supervisor.decrypt_workers.as_ref().cloned()
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
        let (plaintext, slot) = {
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
                    (p, LinkSlot::Current)
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
                                (p, LinkSlot::Previous)
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
        let now_ms = crate::time::mono_ms();
        let ce_flag = header.flags & FLAG_CE != 0;
        let sp_flag = header.flags & FLAG_SP != 0;

        let mut address_changed = false;
        let mut present = false;
        let mut prior = None;
        if let Some(peer) = self.peers.get_mut(&node_addr) {
            present = true;
            if peer.transport_id() != Some(packet.transport_id)
                || peer.current_addr() != Some(&packet.remote_addr)
            {
                prior = peer.transport_id().zip(peer.current_addr().cloned());
            }
            if slot == LinkSlot::Current
                && let Some(mmp) = peer.mmp_mut()
            {
                mmp.receiver.record_recv(
                    header.counter,
                    timestamp,
                    packet.data.len(),
                    ce_flag,
                    now_ms,
                );
                let _spin_rtt = mmp.spin_bit.rx_observe(sp_flag, header.counter, now_ms);
            }
            address_changed =
                peer.set_current_addr(packet.transport_id, packet.remote_addr.clone());
            peer.link_stats_mut()
                .record_recv(packet.data.len(), packet.timestamp_ms);
            peer.touch(packet.timestamp_ms);
        }

        // Address rotation invalidates the per-peer connect()-ed UDP
        // socket. Drop the connected socket + drain so the wildcard
        // listen socket takes over until the new 5-tuple settles. The
        // decrypt-worker completion path in
        // `process_authentic_fmp_plaintext` does the same thing with
        // the same flag; this is the in-line decrypt twin of it.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if address_changed {
            self.clear_connected_udp_for_peer(&node_addr);
        }

        // Tell the transports which link carries the peer: on a roam the old
        // link loses it, and over BLE every frame marks the link it arrived
        // on, so a link re-established at the same address is recognised.
        if present && (address_changed || self.tracks_peers(packet.transport_id)) {
            let link = (packet.transport_id, packet.remote_addr.clone());
            self.relink(&node_addr, prior, Some(link)).await;
        }

        // Dispatch to link message handler
        self.dispatch_authentic(&node_addr, slot, link_message, ce_flag)
            .await;
    }

    /// Dispatch the link message of an authenticated frame. A ReceiverReport
    /// on the previous session reports on this node's traffic in the session
    /// a cutover retired, and is dropped rather than judged against the new
    /// session's metrics; every other message is dispatched whichever session
    /// carried it.
    async fn dispatch_authentic(
        &mut self,
        node_addr: &crate::NodeAddr,
        slot: LinkSlot,
        link_message: &[u8],
        ce_flag: bool,
    ) {
        if slot == LinkSlot::Previous
            && link_message.first() == Some(&(LinkMessageType::ReceiverReport as u8))
        {
            trace!(
                peer = %self.peer_display_name(node_addr),
                "Dropping a ReceiverReport carried on the previous link session"
            );
            return;
        }
        self.dispatch_link_message(node_addr, link_message, ce_flag)
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
        slot: LinkSlot,
        transport_id: crate::transport::TransportId,
        remote_addr: &crate::transport::TransportAddr,
        packet_timestamp_ms: u64,
        packet_len: usize,
        fmp_counter: u64,
        ce_flag: bool,
        sp_flag: bool,
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
        let now_ms = crate::time::mono_ms();
        let mut address_changed = false;
        let mut present = false;
        let mut prior = None;
        if let Some(peer) = self.peers.get_mut(node_addr) {
            present = true;
            peer.reset_decrypt_failures();
            if peer.transport_id() != Some(transport_id) || peer.current_addr() != Some(remote_addr)
            {
                prior = peer.transport_id().zip(peer.current_addr().cloned());
            }
            address_changed = peer.set_current_addr(transport_id, remote_addr.clone());
            peer.link_stats_mut()
                .record_recv(packet_len, packet_timestamp_ms);
            peer.touch(packet_timestamp_ms);
            if slot == LinkSlot::Current
                && let Some(mmp) = peer.mmp_mut()
            {
                mmp.receiver
                    .record_recv(fmp_counter, inner_ts, packet_len, ce_flag, now_ms);
                let _spin_rtt = mmp.spin_bit.rx_observe(sp_flag, fmp_counter, now_ms);
            }
        }
        // Address rotation invalidates the per-peer connect()-ed UDP
        // socket. Drop the connected socket + drain so the wildcard
        // listen socket takes over until the new 5-tuple settles.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if address_changed {
            self.clear_connected_udp_for_peer(node_addr);
        }
        // As on the inline path. A bounce for a peer already removed (the
        // decrypt worker can finish after a Disconnect) marks nothing: no
        // later removal would withdraw it.
        if present && (address_changed || self.tracks_peers(transport_id)) {
            let link = (transport_id, remote_addr.clone());
            self.relink(node_addr, prior, Some(link)).await;
        }
        let link_message = &fmp_plaintext[INNER_TIMESTAMP_LEN..];
        self.dispatch_authentic(node_addr, slot, link_message, ce_flag)
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
        let sp_flag = fallback.fmp_flags & FLAG_SP != 0;
        let plaintext = &fallback.packet_data[fallback.fmp_plaintext_offset
            ..fallback.fmp_plaintext_offset + fallback.fmp_plaintext_len];
        // The worker decrypted with the session registered under the
        // frame's receiver index. Only the current session's index is
        // current; any other is the previous session draining, or one
        // already gone by the time the bounce is processed.
        let current = self
            .peers
            .get(&fallback.source_node_addr)
            .and_then(|p| p.our_index())
            .is_some_and(|idx| idx.as_u32() == fallback.receiver_idx);
        let slot = if current {
            LinkSlot::Current
        } else {
            LinkSlot::Previous
        };
        self.process_authentic_fmp_plaintext(
            &fallback.source_node_addr,
            slot,
            fallback.transport_id,
            &fallback.remote_addr,
            fallback.timestamp_ms,
            fallback.packet_len,
            fallback.fmp_counter,
            ce_flag,
            sp_flag,
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
        let Some(workers) = self.supervisor.decrypt_workers.as_ref().cloned() else {
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
        if let Some(workers) = self.supervisor.decrypt_workers.as_ref() {
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

    /// Count a decryption failure and warn once when the count reaches the
    /// threshold. The peer is kept: a frame that does not authenticate names
    /// its peer only by a receiver index sent in clear, so anyone who has
    /// seen the index can cause the failures. A genuinely broken session ends
    /// at the link-dead timeout, which only authenticated frames hold off.
    pub(in crate::node) fn handle_decrypt_failure(&mut self, node_addr: &crate::NodeAddr) {
        if let Some(peer) = self.peers.get_mut(node_addr) {
            let count = peer.increment_decrypt_failures();
            // Only an authenticated frame resets the count, so this fires
            // once per run of failures.
            if count == DECRYPT_FAILURE_THRESHOLD {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    consecutive_failures = count,
                    "Excessive decryption failures, peer kept"
                );
            }
        }
    }
}
