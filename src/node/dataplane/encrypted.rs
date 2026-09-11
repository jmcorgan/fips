//! Encrypted frame handling (hot path).

use crate::node::Node;
use crate::node::diag::{KeyView, OrNone, Trial};
use crate::node::reject::DataplaneReject;
use crate::noise::{NoiseError, TAG_SIZE};
use crate::proto::fmp::wire::{
    EncryptedHeader, FLAG_CE, FLAG_KEY_EPOCH, FLAG_SP, strip_inner_header,
};
use crate::proto::link::LinkMessageType;
use crate::transport::{ReceivedPacket, TransportAddr, TransportId};
use fips_core::proto::rekey::{FrameHint, Input, Reason, Slot};
use std::time::Instant;
use tracing::{debug, trace, warn};

/// The error the deployed inline decrypt reported for a frame the link's
/// rekey machine refused with `rejects`, for the decryption-failure line: a
/// refused counter, a body too short for its tag, or a tag that did not
/// verify.
fn open_failure(rejects: &[Reason], header: &EncryptedHeader, frame: &[u8]) -> NoiseError {
    if rejects.contains(&Reason::Replay) {
        return NoiseError::ReplayDetected(header.counter);
    }
    let body = frame.len().saturating_sub(header.ciphertext_offset());
    if body < TAG_SIZE {
        NoiseError::MessageTooShort {
            expected: TAG_SIZE,
            got: body,
        }
    } else {
        NoiseError::DecryptionFailed
    }
}

/// What a link session's open needs from a frame's parsed header.
fn frame_hint(header: &EncryptedHeader, k: bool) -> FrameHint {
    FrameHint {
        counter: header.counter,
        k,
        index: header.receiver_idx.as_u32(),
        body: header.ciphertext_offset(),
    }
}

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
/// Previous-session frames still hold the link alive: the link-dead check
/// reads the link machine's last frame under any session it holds as well as
/// the MMP receiver's last-received time, which the cutover clears. Peer
/// `touch` and link statistics see them too.
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
    /// A frame is opened under the one session its receiver index names:
    /// by a decrypt worker when one holds that session, else by the link's
    /// rekey machine. A frame that authenticates under the pending session
    /// cuts over to it, and one under the previous session is delivered
    /// while the drain holds it.
    pub(in crate::node) async fn handle_encrypted_frame(&mut self, packet: ReceivedPacket) {
        // Parse header (fail fast)
        let header = match EncryptedHeader::parse(&packet.data) {
            Some(h) => h,
            None => return, // Malformed, drop silently
        };

        // O(1) session lookup by our receiver index
        let key = header.receiver_idx.as_u32();
        let node_addr = match self.peers_by_index.get(&key) {
            Some(id) => *id,
            None => {
                // The sender's address is not authenticated, so the line is
                // limited by one node-wide budget rather than per source.
                if tracing::enabled!(tracing::Level::DEBUG)
                    && let Some(suppressed) = self.index_budget.admit(Instant::now())
                {
                    debug!(
                        receiver_idx = %header.receiver_idx,
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        suppressed,
                        "Unknown session index, dropping"
                    );
                }
                self.metrics()
                    .dataplane
                    .record_reject(DataplaneReject::UnknownIndex);
                return;
            }
        };

        if !self.peers.contains_key(&node_addr) {
            self.peers_by_index.remove(&key);
            self.metrics()
                .dataplane
                .record_reject(DataplaneReject::OrphanedIndex);
            return;
        }

        // Extract K-bit from flags
        let received_k_bit = header.flags & FLAG_KEY_EPOCH != 0;

        // ── Decrypt-worker fast path (unix) ─────────────────────────
        // Once a session has been registered with a decrypt shard (at
        // FMP-establishment in `promote_connection`, or at a cutover), the
        // worker owns its FMP recv cipher + replay window. Dispatch the
        // packet and return; the worker will run AEAD off-task and bounce
        // the plaintext back via `decrypt_fallback_tx` for rx_loop to do the
        // post-decrypt side-effects. A pending session is never registered,
        // so a frame naming one is opened by the link's rekey machine below.
        #[cfg(unix)]
        {
            let cache_key = header.receiver_idx.as_u32();
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

        // The link's rekey machine opens the frame under the session its
        // receiver index names, and runs that session's row: a frame under
        // the pending session cuts over to it, taking the frame's K-bit when
        // the peer made it, and is delivered as the new current session's.
        // The plaintext is written into the frame's own buffer.
        if !self
            .peers
            .get(&node_addr)
            .is_some_and(|peer| peer.has_session())
        {
            warn!(
                peer = %self.peer_display_name(&node_addr),
                "Peer in index map has no session"
            );
            return;
        }
        let mut packet = packet;
        // Carried to a failure line: whether the frame named the pending.
        let trial = Trial::of(
            self.peers
                .get(&node_addr)
                .and_then(|peer| peer.pending_our_index()),
            header.receiver_idx,
        );
        let hint = frame_hint(&header, received_k_bit);
        let input = Input::Frame {
            buf: &mut packet.data,
            hint,
        };
        let Some(out) = self.step_link(&node_addr, input) else {
            return;
        };
        let report = self.run_link_step(&node_addr, out).await;
        if report.removed {
            return;
        }
        let Some((slot, range)) = report.delivered else {
            let short = report.rejects.contains(&Reason::ShortPlaintext);
            if short {
                if let Some(peer) = self.peers.get_mut(&node_addr) {
                    peer.reset_decrypt_failures();
                }
                debug!(
                    peer = %self.peer_display_name(&node_addr),
                    "Decrypted payload too short for inner header"
                );
                return;
            }
            let e = open_failure(&report.rejects, &header, &packet.data);
            self.log_decrypt_failure(
                &node_addr,
                &header,
                &e,
                packet.transport_id,
                &packet.remote_addr,
                trial,
            );
            self.charge_decrypt_failure(&node_addr, packet.transport_id);
            return;
        };
        if let Some(peer) = self.peers.get_mut(&node_addr) {
            peer.reset_decrypt_failures();
        }
        let slot = match slot {
            Slot::Current | Slot::Pending => LinkSlot::Current,
            Slot::Previous => LinkSlot::Previous,
        };
        let plaintext = packet
            .data
            .get(range)
            .map(<[u8]>::to_vec)
            .unwrap_or_default();

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
        let mut first_frame = false;
        let mut present = false;
        let mut first_heard = false;
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
            peer.note_path_rx(packet.transport_id, now_ms);
            peer.link_stats_mut()
                .record_recv(packet.data.len(), packet.timestamp_ms);
            first_frame = !peer.heard();
            first_heard = !peer.is_heard();
            peer.touch(packet.timestamp_ms);
            if slot == LinkSlot::Previous {
                peer.count_previous();
            }
        }
        if first_frame {
            self.note_peer_heard(&node_addr);
        }

        // Address rotation invalidates the per-peer connect()-ed UDP socket,
        // which is still pinned to the old 5-tuple. The decrypt-worker
        // completion path already does this; this one discarded the flag, so a
        // peer that roamed kept sending from a socket aimed where it used to
        // be. `netmon`'s first-sight rule now rests on this too: it compares
        // that socket's pinned source against a probe to the peer's *current*
        // address, and a socket left behind makes those two disagree for as
        // long as it survives.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if address_changed {
            self.clear_connected_udp_for_peer(&node_addr);
        }

        // The first authenticated frame proves the peering live, so the
        // memory of msg1s that promoted it unheard has nothing left to bound.
        if first_heard {
            self.replayed_msg1s.forget(&node_addr);
        }

        // Tell the transports which link carries the peer: on a roam the old
        // link loses it, and over BLE every frame marks the link it arrived
        // on, so a link re-established at the same address is recognised.
        if present && (address_changed || self.tracks_peers(packet.transport_id)) {
            let link = (packet.transport_id, packet.remote_addr.clone());
            self.relink(&node_addr, prior, Some(link)).await;
        }

        // Dispatch to link message handler
        self.dispatch_authentic(
            &node_addr,
            slot,
            link_message,
            ce_flag,
            (packet.transport_id, &packet.remote_addr),
        )
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
        arrival: (TransportId, &TransportAddr),
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
        self.dispatch_link_message(node_addr, link_message, ce_flag, arrival)
            .await;
    }

    /// Log a decryption failure with replay suppression, with the frame's
    /// index, where it arrived, and the peer's key state for that index.
    /// Records the failing index on the peer for the excessive-failures
    /// warning. A run of failures that has reached the warning's threshold
    /// logs nothing more until a frame authenticates (`past_threshold`).
    fn log_decrypt_failure(
        &mut self,
        node_addr: &crate::NodeAddr,
        header: &EncryptedHeader,
        error: &NoiseError,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
        trial: Trial,
    ) {
        let replay = matches!(error, NoiseError::ReplayDetected(_));
        let replays = self.peers.get_mut(node_addr).map(|peer| {
            peer.record_failed(header.receiver_idx);
            if replay {
                peer.increment_replay_suppressed()
            } else {
                0
            }
        });
        if !replay && self.past_threshold(node_addr) {
            return;
        }
        if replay && let Some(count) = replays {
            if count == 4 {
                debug!(
                    peer = %self.peer_display_name(node_addr),
                    "Suppressing further replay detection messages"
                );
            }
            if count > 3 {
                return;
            }
        }
        let keys = KeyView::of(self.peers.get(node_addr), Some(header.receiver_idx));
        debug!(
            peer = %self.peer_display_name(node_addr),
            counter = header.counter,
            error = %error,
            receiver_idx = %header.receiver_idx,
            transport_id = %transport_id,
            remote_addr = %remote_addr,
            kbit_frame = header.flags & FLAG_KEY_EPOCH != 0,
            trial = %trial,
            slot = %keys.slot,
            kbit_ours = %keys.kbit_ours,
            epoch = %keys.epoch,
            prev_epoch = %keys.prev_epoch,
            pending_epoch = %keys.pending_epoch,
            "Decryption failed"
        );
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
        let mut first_frame = false;
        let mut present = false;
        let mut first_heard = false;
        let mut prior = None;
        if let Some(peer) = self.peers.get_mut(node_addr) {
            present = true;
            peer.reset_decrypt_failures();
            if peer.transport_id() != Some(transport_id) || peer.current_addr() != Some(remote_addr)
            {
                prior = peer.transport_id().zip(peer.current_addr().cloned());
            }
            address_changed = peer.set_current_addr(transport_id, remote_addr.clone());
            peer.note_path_rx(transport_id, now_ms);
            peer.link_stats_mut()
                .record_recv(packet_len, packet_timestamp_ms);
            first_frame = !peer.heard();
            first_heard = !peer.is_heard();
            peer.touch(packet_timestamp_ms);
            if slot == LinkSlot::Previous {
                peer.count_previous();
            }
            if slot == LinkSlot::Current
                && let Some(mmp) = peer.mmp_mut()
            {
                mmp.receiver
                    .record_recv(fmp_counter, inner_ts, packet_len, ce_flag, now_ms);
                let _spin_rtt = mmp.spin_bit.rx_observe(sp_flag, fmp_counter, now_ms);
            }
        }
        // A session's first authenticated frame clears its identity's
        // silent-session record: one identity has one peer entry, and a
        // record grows only when an unheard session ends.
        if first_frame {
            self.note_peer_heard(node_addr);
        }
        // Address rotation invalidates the per-peer connect()-ed UDP
        // socket. Drop the connected socket + drain so the wildcard
        // listen socket takes over until the new 5-tuple settles.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if address_changed {
            self.clear_connected_udp_for_peer(node_addr);
        }
        // The first authenticated frame proves the peering live, so the
        // memory of msg1s that promoted it unheard has nothing left to bound.
        if first_heard {
            self.replayed_msg1s.forget(node_addr);
        }
        // As on the inline path. A bounce for a peer already removed (the
        // decrypt worker can finish after a Disconnect) marks nothing: no
        // later removal would withdraw it.
        if present && (address_changed || self.tracks_peers(transport_id)) {
            let link = (transport_id, remote_addr.clone());
            self.relink(node_addr, prior, Some(link)).await;
        }
        let link_message = &fmp_plaintext[INNER_TIMESTAMP_LEN..];
        self.dispatch_authentic(
            node_addr,
            slot,
            link_message,
            ce_flag,
            (transport_id, remote_addr),
        )
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
        // frame's receiver index: the peering's current session, its
        // previous one draining, or one already gone by the time the bounce
        // is processed. A session that is gone authenticates nothing about
        // the peering now holding the address: a replayed msg1 may have
        // replaced it, and counting the frame would mark that phantom heard
        // and move it to the genuine peer's address. The inline path cannot
        // decrypt such a frame at all, so it is dropped here too.
        let (current, previous) = self
            .peers
            .get(&fallback.source_node_addr)
            .map(|p| {
                let receiver = Some(fallback.receiver_idx);
                (
                    p.our_index().map(|i| i.as_u32()) == receiver,
                    p.previous_our_index().map(|i| i.as_u32()) == receiver,
                )
            })
            .unwrap_or((false, false));
        if !current && !previous {
            debug!(
                peer = %self.peer_display_name(&fallback.source_node_addr),
                remote_addr = %fallback.remote_addr,
                receiver_idx = fallback.receiver_idx,
                reason = "session-gone",
                "Decrypted frame's session no longer belongs to the peering, dropping"
            );
            return;
        }
        // The link's rekey machine hears of the frame too: its key-epoch
        // bit is the one the peer was last seen sending, and a frame under
        // the current session shows the peer moved to it.
        let held = if current {
            Slot::Current
        } else {
            Slot::Previous
        };
        let tag = self
            .peers
            .get(&fallback.source_node_addr)
            .and_then(|p| p.epoch_tag(held));
        if let Some(tag) = tag {
            let input = Input::WorkerFrame {
                tag,
                k: fallback.fmp_flags & FLAG_KEY_EPOCH != 0,
                counter: fallback.fmp_counter,
                only: (),
            };
            if let Some(out) = self.step_link(&fallback.source_node_addr, input)
                && self
                    .run_link_step(&fallback.source_node_addr, out)
                    .await
                    .removed
            {
                return;
            }
        }
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
        let idx = crate::utils::index::SessionIndex::new(report.receiver_idx);
        if let Some(peer) = self.peers.get_mut(&report.source_node_addr) {
            peer.record_failed(idx);
        }
        if self.past_threshold(&report.source_node_addr) {
            self.charge_decrypt_failure(&report.source_node_addr, report.transport_id);
            return;
        }
        let keys = KeyView::of(self.peers.get(&report.source_node_addr), Some(idx));
        debug!(
            peer = %self.peer_display_name(&report.source_node_addr),
            counter = report.fmp_counter,
            replay_highest = report.fmp_replay_highest,
            receiver_idx = %idx,
            transport_id = %report.transport_id,
            remote_addr = %report.remote_addr,
            kbit_frame = report.fmp_flags & FLAG_KEY_EPOCH != 0,
            slot = %keys.slot,
            kbit_ours = %keys.kbit_ours,
            epoch = %keys.epoch,
            prev_epoch = %keys.prev_epoch,
            pending_epoch = %keys.pending_epoch,
            "Worker FMP AEAD decryption failed"
        );
        self.charge_decrypt_failure(&report.source_node_addr, report.transport_id);
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

    /// Drop a session from the decrypt worker pool. Mirror of the
    /// registration a link machine's `Delegate` output makes. Idempotent:
    /// safe to call on a `cache_key` that isn't registered, and safe to call
    /// when the worker pool is disabled (`FIPS_DECRYPT_WORKERS=0`).
    ///
    /// Called for every `Revoke` a link machine emits, which it does for a
    /// delegated session whenever it retires one: at the end of a drain
    /// (after the drain window has expired, the old `our_index` is
    /// unreachable to any in-flight OLD-K packet), at a cutover over a drain
    /// still open, on a cross-connection replacement, and when the peer is
    /// removed. Without these, the per-worker `sessions` HashMap and the
    /// Node's `decrypt_registered_sessions` set would grow monotonically
    /// per rekey on long-lived peers.
    #[cfg(unix)]
    pub(in crate::node) fn unregister_decrypt_worker_session(&mut self, cache_key: u32) {
        if let Some(workers) = self.supervisor.decrypt_workers.as_ref() {
            workers.unregister_session(cache_key);
        }
        self.decrypt_registered_sessions.remove(&cache_key);
    }

    /// Whether `node_addr`'s current run of decryption failures has already
    /// reached the warning's threshold. A peer is kept through such a run, so
    /// without this bound every failing frame would log a line: the per-frame
    /// failure lines stop at the threshold, as they did when the peer was
    /// removed there, and resume after a frame authenticates.
    fn past_threshold(&self, node_addr: &crate::NodeAddr) -> bool {
        self.peers
            .get(node_addr)
            .is_some_and(|p| p.consecutive_decrypt_failures() >= DECRYPT_FAILURE_THRESHOLD)
    }

    /// Count a decryption failure against the peer, but only if it arrived on
    /// a transport the peer is actually on.
    ///
    /// The demux is by index alone, so a frame naming a known `receiver_idx`
    /// reaches this peer's session from *any* bound transport. Counting
    /// those would let garbage frames carrying a sniffed index, from any
    /// transport, run up the failure count `fipsctl` reports and trip the
    /// warning. The same rule covers a stale in-flight frame landing on an
    /// index the allocator has already handed to a new owner: index reuse is
    /// immediate, with no quarantine.
    ///
    /// A peer with no transport bound yet is counted unconditionally.
    pub(in crate::node) fn charge_decrypt_failure(
        &mut self,
        node_addr: &crate::NodeAddr,
        transport_id: crate::transport::TransportId,
    ) {
        let on_path = self
            .peers
            .get(node_addr)
            .is_some_and(|peer| peer.paths().is_empty() || peer.path_on(transport_id).is_some());
        if !on_path {
            trace!(
                peer = %self.peer_display_name(node_addr),
                transport_id = %transport_id,
                "Decrypt failure on a transport the peer is not on, not counted"
            );
            return;
        }
        self.handle_decrypt_failure(node_addr);
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
                let keys = KeyView::of(Some(peer), peer.last_failed());
                let pending_age_s = OrNone(peer.pending_age().map(|d| d.as_secs()));
                let since_cutover_ms = OrNone(peer.since_cutover().map(|d| d.as_millis()));
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    consecutive_failures = count,
                    slot = %keys.slot,
                    kbit_ours = %keys.kbit_ours,
                    epoch = %keys.epoch,
                    prev_epoch = %keys.prev_epoch,
                    pending_epoch = %keys.pending_epoch,
                    pending_age_s = %pending_age_s,
                    since_cutover_ms = %since_cutover_ms,
                    "Excessive decryption failures, peer kept"
                );
            }
        }
    }
}
