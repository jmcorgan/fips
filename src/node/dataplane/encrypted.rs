//! Encrypted frame handling (hot path).

use crate::node::Node;
use crate::node::diag::{KeyView, OrNone, Trial};
use crate::node::handlers::path_intake::Feed;
use crate::node::reject::DataplaneReject;
use crate::noise::{NoiseError, TAG_SIZE};
use crate::peer::{ActivePeer, PeerBundle, Roam};
use crate::proto::fmp::wire::{
    EncryptedHeader, FLAG_CE, FLAG_KEY_EPOCH, INNER_HEADER_SIZE, strip_inner_header,
};
use crate::proto::link::LinkMessageType;
use crate::transport::{ReceivedPacket, TransportAddr, TransportId};
use fips_core::proto::path::{Charge, Input as PathInput};
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
pub(in crate::node) const DECRYPT_FAILURE_THRESHOLD: u32 = 20;

/// One authenticated frame, as the post-decrypt bookkeeping takes it from
/// either receive path: the link session that opened it, where it arrived,
/// when it was read (Unix milliseconds), its length on the wire, its FMP
/// counter, the timestamp from its inner header, and its CE bit.
struct Authentic<'a> {
    slot: LinkSlot,
    transport_id: TransportId,
    remote_addr: &'a TransportAddr,
    received_ms: u64,
    len: usize,
    counter: u64,
    inner_ts: u32,
    ce: bool,
}

/// Which of a peer's link sessions authenticated an inbound frame.
///
/// After a rekey cutover the previous session still decrypts during the
/// drain, so frames the peer sealed before it moved are delivered. They
/// describe the session the cutover retired, though, and the new session's
/// MMP state was reset at the cutover: a previous-session frame is not
/// counted by the MMP receiver, and a ReceiverReport it carries is not
/// processed. A frame authenticated by a pending session is promoted to
/// current before it is processed, so it is `Current`.
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

        // O(1) session lookup by our receiver index alone: indices come from
        // one allocator, so the transport that delivered the frame plays no
        // part in finding its session.
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
                    peer.authentic(packet.transport_id, &packet.remote_addr);
                }
                debug!(
                    peer = %self.peer_display_name(&node_addr),
                    "Decrypted payload too short for inner header"
                );
                return;
            }
            // A frame the anti-replay window refused is logged and counted
            // on no path: it neither adds to nor resets the count of
            // authentication failures (multipath draft Section 5.3).
            let replay = report.rejects.contains(&Reason::Replay);
            let e = open_failure(&report.rejects, &header, &packet.data);
            self.log_decrypt_failure(
                &node_addr,
                &header,
                &e,
                packet.transport_id,
                &packet.remote_addr,
                trial,
            );
            if !replay && self.charge_failure(&node_addr, packet.transport_id, &packet.remote_addr)
            {
                self.step_path(&node_addr, PathInput::Poll).await;
            }
            return;
        };
        if let Some(peer) = self.peers.get_mut(&node_addr) {
            peer.authentic(packet.transport_id, &packet.remote_addr);
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

        let frame = Authentic {
            slot,
            transport_id: packet.transport_id,
            remote_addr: &packet.remote_addr,
            received_ms: packet.timestamp_ms,
            len: packet.data.len(),
            counter: header.counter,
            inner_ts: timestamp,
            ce: header.flags & FLAG_CE != 0,
        };
        self.account_authentic(&node_addr, frame, link_message)
            .await;
    }

    /// Dispatch the link message of an authenticated frame. A ReceiverReport
    /// on the previous session reports on this node's traffic in the session
    /// a cutover retired, and is dropped rather than judged against the new
    /// session's metrics; every other message is dispatched whichever session
    /// carried it, with the frame's arrival (the transport it came in on and
    /// its source address) and its length on the wire.
    async fn dispatch_authentic(
        &mut self,
        node_addr: &crate::NodeAddr,
        slot: LinkSlot,
        link_message: &[u8],
        ce_flag: bool,
        arrival: (TransportId, &TransportAddr),
        len: usize,
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
        self.dispatch_link_message(node_addr, link_message, ce_flag, arrival, len)
            .await;
    }

    /// Log a decryption failure with replay suppression, with the frame's
    /// index, where it arrived, and the peer's key state for that index.
    /// Records the failing index on the peer for the excessive-failures
    /// warning. A run of failures on the frame's path that has reached the
    /// warning's threshold logs nothing more until a frame authenticates
    /// there (`past_threshold`).
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
        if !replay && self.past_threshold(node_addr, transport_id, remote_addr) {
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

    /// The decrypt-worker path's way into the post-decrypt bookkeeping, for
    /// a frame the worker has authenticated and bounced back with its
    /// plaintext. Starts the run of decryption failures on the frame's path
    /// again first, as the inline path does when a frame authenticates,
    /// whatever its length (multipath draft Section 5.3). A plaintext
    /// shorter than the inner header is then dropped, as on the inline
    /// path. Otherwise reads the inner timestamp and hands the frame to
    /// [`account_authentic`](Self::account_authentic).
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
        fmp_plaintext: &[u8],
    ) {
        const INNER_TIMESTAMP_LEN: usize = 4;
        if let Some(peer) = self.peers.get_mut(node_addr) {
            peer.authentic(transport_id, remote_addr);
        }
        if fmp_plaintext.len() < INNER_HEADER_SIZE {
            debug!(
                peer = %self.peer_display_name(node_addr),
                len = fmp_plaintext.len(),
                "Decrypted payload too short for inner header"
            );
            return;
        }
        let inner_ts = u32::from_le_bytes([
            fmp_plaintext[0],
            fmp_plaintext[1],
            fmp_plaintext[2],
            fmp_plaintext[3],
        ]);
        let frame = Authentic {
            slot,
            transport_id,
            remote_addr,
            received_ms: packet_timestamp_ms,
            len: packet_len,
            counter: fmp_counter,
            inner_ts,
            ce: ce_flag,
        };
        let link_message = &fmp_plaintext[INNER_TIMESTAMP_LEN..];
        self.account_authentic(node_addr, frame, link_message).await;
    }

    /// The bookkeeping for one authenticated frame, shared by the inline
    /// path and the decrypt-worker path, then the dispatch of its link
    /// message.
    ///
    /// In order: the link's path machine accounts the frame to its path,
    /// and while the link holds one path the roaming rule follows the
    /// frame's source ([`account`](crate::peer::ActivePeer::account)),
    /// the link counters and the last-seen time are updated, a frame on the
    /// previous session is counted as one, and a frame on the current
    /// session feeds the MMP receiver. Then the identity's silent-session
    /// record is cleared on the session's first frame, a connected UDP
    /// socket aimed at an address the peer left is dropped, and the
    /// transports are told which link carries the peer.
    async fn account_authentic(
        &mut self,
        node_addr: &crate::NodeAddr,
        frame: Authentic<'_>,
        link_message: &[u8],
    ) {
        let now = crate::peer::peer_now();
        let now_ms = crate::time::mono_ms_at(now);
        let mut address_changed = false;
        let mut first_frame = false;
        let mut present = false;
        let mut prior = None;
        let mut wake = None;
        let mut heard_from = false;
        let intake = self.config().node.path.enabled;
        if let Some(peer) = self.peers.get_mut(node_addr) {
            present = true;
            let msg_type = link_message.first().copied().unwrap_or(0);
            let account = peer.account(
                now,
                frame.transport_id,
                frame.remote_addr,
                frame.len,
                msg_type,
            );
            let roam = account.roam;
            // An authentic frame from a pair the link holds no path at, that
            // the one-path roam did not follow, makes the pair a candidate,
            // not a path (multipath v1 draft, Section 5.3). A path message
            // is left out: a probe from such a pair creates a path only
            // where the probe's own rules allow (Sections 5.1 and 5.5), and
            // reporting it here would admit the pair around them.
            heard_from = intake
                && account.path.is_none()
                && roam == Roam::Unmoved
                && !matches!(
                    LinkMessageType::from_byte(msg_type),
                    Some(
                        LinkMessageType::PathProbe
                            | LinkMessageType::PathAck
                            | LinkMessageType::PathClose
                    )
                );
            address_changed = roam.changed();
            // A roam that moved an address may leave the path machine work
            // to do, which the path tick must not sleep through.
            if roam != Roam::Unmoved {
                wake = peer.bundle().and_then(PeerBundle::next_wake);
            }
            // Only a link the peer actually left loses its verification. A
            // frame the roaming rule refuses to follow (another transport, or
            // a peer holding several paths) leaves the peer on its link.
            prior = roam.left();
            peer.link_stats_mut()
                .record_recv(frame.len, frame.received_ms);
            first_frame = !peer.heard();
            peer.touch(frame.received_ms);
            if frame.slot == LinkSlot::Previous {
                peer.count_previous();
            }
            if frame.slot == LinkSlot::Current
                && let Some(mmp) = peer.mmp_mut()
            {
                // Jitter and the timestamp echo come only from frames on
                // the peer's active path (multipath draft Section 5.12):
                // a sample across two paths measures their difference, and
                // an echo of a standby frame would give the peer that
                // path's round trip. On a link of one path every frame is
                // sampled. Every frame is still counted for loss.
                mmp.receiver.record_frame(
                    frame.counter,
                    frame.inner_ts,
                    frame.len,
                    frame.ce,
                    now_ms,
                    account.sample,
                );
            }
        }
        self.paths.fold(wake);
        // A session's first authenticated frame clears its identity's
        // silent-session record: one identity has one peer entry, and a
        // record grows only when an unheard session ends.
        if first_frame {
            self.note_peer_heard(node_addr);
        }
        // Address rotation invalidates the per-peer connect()-ed UDP socket,
        // which is still pinned to the old 5-tuple. Drop the socket and its
        // drain so the wildcard listen socket takes over until the new
        // 5-tuple settles. `netmon`'s first-sight rule rests on this too: it
        // compares that socket's pinned source against a probe to the peer's
        // *current* address, and a socket left behind makes those two
        // disagree for as long as it survives.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if address_changed {
            self.clear_connected_udp_for_peer(node_addr);
        }
        // Tell the transports which link carries the peer: on a roam the old
        // link loses it, and over BLE every frame marks the link it arrived
        // on, so a link re-established at the same address is recognised. A
        // frame for a peer already removed (the decrypt worker can finish
        // after a Disconnect) marks nothing: no later removal would withdraw
        // it.
        if present && (address_changed || self.tracks_peers(frame.transport_id)) {
            let link = (frame.transport_id, frame.remote_addr.clone());
            self.relink(node_addr, prior, Some(link)).await;
        }
        if heard_from {
            let addr = frame.remote_addr.clone();
            self.intake(node_addr, Feed::Heard, frame.transport_id, addr)
                .await;
        }
        let arrival = (frame.transport_id, frame.remote_addr);
        self.dispatch_authentic(
            node_addr,
            frame.slot,
            link_message,
            frame.ce,
            arrival,
            frame.len,
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
        let plaintext = &fallback.packet_data[fallback.fmp_plaintext_offset
            ..fallback.fmp_plaintext_offset + fallback.fmp_plaintext_len];
        // The worker decrypted with the session registered under the
        // frame's receiver index: the peering's current session, its
        // previous one draining, or one already gone by the time the bounce
        // is processed. A session that is gone authenticates nothing about
        // the peering now holding the address, and the link's rekey machine
        // holds no epoch to hear the frame under, so it is dropped, as the
        // inline path, which cannot decrypt such a frame at all, drops it.
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
        let (from, transport_id) = (&report.source_node_addr, report.transport_id);
        if self.past_threshold(from, transport_id, &report.remote_addr) {
            if self.charge_failure(from, transport_id, &report.remote_addr) {
                self.step_path(from, PathInput::Poll).await;
            }
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
        if self.charge_failure(from, transport_id, &report.remote_addr) {
            self.step_path(from, PathInput::Poll).await;
        }
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

    /// Whether the current run of decryption failures on `node_addr`'s path
    /// of (`transport_id`, `addr`) has already reached the warning's
    /// threshold. A peer is kept through such a run, so without this bound
    /// every failing frame would log a line: the per-frame failure lines
    /// from that path stop at the threshold, as they did when the peer was
    /// removed there, and resume after a frame authenticates on it. A frame
    /// from a pair no path holds is never past it.
    fn past_threshold(
        &self,
        node_addr: &crate::NodeAddr,
        transport_id: TransportId,
        addr: &TransportAddr,
    ) -> bool {
        self.peers
            .get(node_addr)
            .is_some_and(|p| fails_at(p, transport_id, addr) >= DECRYPT_FAILURE_THRESHOLD)
    }

    /// Count a decryption failure from (`transport_id`, `addr`) against the
    /// path of `node_addr`'s link it arrived on, and return whether the
    /// path's machine is owed a step at once.
    ///
    /// The demux is by index alone, so a frame naming a known `receiver_idx`
    /// reaches this peer's session from *any* bound transport and address.
    /// Only a failure on the link's original path, or on a path proven by a
    /// probe exchange, counts (multipath v1 draft, Section 5.3): counting
    /// the others would let garbage frames carrying a sniffed index, from
    /// anywhere, run up the failure count `fipsctl` reports and trip the
    /// warning. The same rule covers a stale in-flight frame landing on an
    /// index the allocator has already handed to a new owner: index reuse is
    /// immediate, with no quarantine.
    ///
    /// When the path's count reaches the threshold the warning is logged
    /// once, and the peer is kept: a frame that does not authenticate names
    /// its peer only by a receiver index sent in clear, so anyone who has
    /// seen the index can cause the failures. A genuinely broken session
    /// ends at the link-dead timeout, which only authenticated frames hold
    /// off. When the path has a working alternative the machine marks it
    /// Dead at its next step, which the caller makes at once.
    pub(in crate::node) fn charge_failure(
        &mut self,
        node_addr: &crate::NodeAddr,
        transport_id: TransportId,
        addr: &TransportAddr,
    ) -> bool {
        let Some(peer) = self.peers.get_mut(node_addr) else {
            return false;
        };
        match peer.charge(crate::peer::peer_now(), transport_id, addr) {
            Charge::Nothing => {
                trace!(
                    peer = %self.peer_display_name(node_addr),
                    transport_id = %transport_id,
                    remote_addr = %addr,
                    "Decrypt failure from no proven path of the peer, not counted"
                );
                false
            }
            Charge::Counted => false,
            Charge::Warn => {
                let count = fails_at(peer, transport_id, addr);
                let keys = KeyView::of(Some(peer), peer.last_failed());
                let since_cutover_ms = OrNone(peer.since_cutover().map(|d| d.as_millis()));
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    consecutive_failures = count,
                    slot = %keys.slot,
                    kbit_ours = %keys.kbit_ours,
                    epoch = %keys.epoch,
                    prev_epoch = %keys.prev_epoch,
                    pending_epoch = %keys.pending_epoch,
                    since_cutover_ms = %since_cutover_ms,
                    "Excessive decryption failures, peer kept"
                );
                false
            }
            Charge::Tripped => true,
        }
    }
}

/// The count of consecutive failures on `peer`'s path of (`transport_id`,
/// `addr`), or 0 when no path holds that pair.
fn fails_at(peer: &ActivePeer, transport_id: TransportId, addr: &TransportAddr) -> u32 {
    let Some(paths) = peer.bundle().map(|b| b.paths()) else {
        return 0;
    };
    paths
        .find(transport_id, addr)
        .and_then(|i| paths.get(i))
        .map_or(0, |p| p.live().fails())
}
