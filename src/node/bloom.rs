//! Bloom filter announce send/receive logic.
//!
//! Handles building, sending, and receiving FilterAnnounce messages,
//! including debounced propagation to peers.

use crate::NodeAddr;
use crate::proto::bloom::FilterAnnounce;
use crate::proto::bloom::{ACCEPT_FPR_CAP, BloomFilter};
use crate::proto::mmp::delivery::{LinkEvidence, RrCounters};

use super::reject::BloomReject;
use super::{Node, NodeError, diag};
use std::collections::BTreeMap;
use tracing::{debug, warn};

/// What a rejected child announce is logged with.
struct ChildEcho {
    /// Share of the filter we sent that the announce contains.
    overlap: f64,
    /// The overlap above which the announce was rejected.
    bound: f64,
    /// Digest of the filter we sent, to match against our send log.
    sent_digest: diag::Tag<8>,
}

/// Draw the origin of this node's FilterAnnounce sequence floor: a random
/// offset in `[1, 2^62)` and the instant it was drawn.
///
/// The offset hides the node's uptime, which a peer's first sequence would
/// otherwise reveal.
pub(super) fn new_seq_origin() -> (u64, std::time::Instant) {
    use rand::RngExt;
    (
        rand::rng().random_range(1..1u64 << 62),
        std::time::Instant::now(),
    )
}

impl Node {
    /// The sequence a peer with no sequence entry starts from: the origin's
    /// offset plus 256 per microsecond since the origin.
    ///
    /// One peer's sequence grows by one per announce, and announces to a
    /// peer go out at most once per tick, so a peer that is removed and
    /// re-established (which takes a full handshake) is seeded above every
    /// value it was sent before. 2^62 plus a century of microseconds times
    /// 256 stays below 2^63.
    pub(super) fn seq_floor(&self) -> u64 {
        let (offset, start) = self.seq_origin;
        let micros = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        offset.saturating_add(micros.saturating_mul(256))
    }

    /// Collect inbound filters from all peers for outgoing filter computation.
    ///
    /// Returns a map of (peer_node_addr -> filter) for peers that
    /// have sent us a FilterAnnounce.
    pub(super) fn peer_inbound_filters(&self) -> BTreeMap<NodeAddr, BloomFilter> {
        let mut filters = BTreeMap::new();
        for (addr, peer) in &self.peers {
            if self.is_tree_peer(addr)
                && let Some(filter) = peer.inbound_filter()
            {
                filters.insert(*addr, filter.clone());
            }
        }
        filters
    }

    /// Send a FilterAnnounce to a specific peer, respecting debounce.
    ///
    /// `filter` is the outgoing filter for this peer, already computed
    /// with the destination peer's own contribution excluded to prevent
    /// routing loops (don't tell a peer about destinations reachable
    /// only through them).
    ///
    /// If the peer is rate-limited, the update stays pending for
    /// delivery on the next tick cycle. A filter whose FPR is above the v1
    /// acceptance cap is held the same way: a v1 receiver would reject it,
    /// so nothing is sent, no sequence is taken, and the update stays
    /// pending until the debounce allows another attempt.
    pub(super) async fn send_filter_announce_to_peer(
        &mut self,
        peer_addr: &NodeAddr,
        filter: BloomFilter,
    ) -> Result<(), NodeError> {
        // Monotonic: the debounce compares two reads, and a wall-clock step
        // back would hold announces for the size of the step.
        let now_ms = crate::time::mono_ms();

        // Check debounce
        if !self.bloom_state.should_send_update(peer_addr, now_ms) {
            self.metrics().bloom.debounce_suppressed.inc();
            // Either not pending or rate-limited; will retry on tick
            return Ok(());
        }

        // Hold a filter a v1 receiver would reject. The threshold is the v1
        // cap, not this node's own inbound cap, so the hold is the same on
        // every sender. The peer keeps the last filter it accepted, and the
        // last-sent record keeps matching it.
        if filter.fpr() > ACCEPT_FPR_CAP {
            self.metrics().bloom.held_over_cap.inc();
            self.warn_held(peer_addr, &filter);
            self.bloom_state.defer_update(*peer_addr, now_ms);
            return Ok(());
        }

        // Build and encode
        let floor = self.seq_floor();
        let seq = self.bloom_state.next_sequence(peer_addr, floor);
        let announce = FilterAnnounce::new(filter, seq);
        let sent_filter = announce.filter.clone();
        let encoded = announce.encode().map_err(|e| NodeError::SendFailed {
            node_addr: *peer_addr,
            reason: format!("FilterAnnounce encode failed: {}", e),
        })?;

        // Send
        if let Err(e) = self.send_encrypted_link_message(peer_addr, &encoded).await {
            self.metrics().bloom.send_failed.inc();
            return Err(e);
        }

        self.metrics().bloom.sent.inc();

        // Read after the send: anything else taking a counter in between only
        // makes the recorded counter higher, which delays confirmation rather
        // than confirming a frame that was never covered.
        if let Some(link) = self.link_evidence(peer_addr) {
            let counter = link.next_counter.saturating_sub(1);
            self.bloom_state.record_announce(
                *peer_addr,
                &sent_filter,
                counter,
                &link,
                crate::time::mono_ms(),
            );
        }

        // Record send and store the filter for change detection
        debug!(
            peer = %self.peer_display_name(peer_addr),
            seq = announce.sequence,
            est_entries = match sent_filter.estimated_count(self.config().node.bloom.max_inbound_fpr) {
                Some(n) => format!("{:.0}", n),
                None => "—".to_string(),
            },
            set_bits = sent_filter.count_ones(),
            fill = format_args!("{:.1}%", sent_filter.fill_ratio() * 100.0),
            tree_peer = self.is_tree_peer(peer_addr),
            digest = %diag::filter_tag(&sent_filter),
            "Sent FilterAnnounce"
        );
        self.bloom_state.record_update_sent(*peer_addr, now_ms);
        self.bloom_state.record_sent_filter(*peer_addr, sent_filter);
        if let Some(peer) = self.peers.get_mut(peer_addr) {
            peer.clear_filter_update_needed();
        }

        Ok(())
    }

    /// Mark every peer whose outgoing filter changed because of inbound
    /// filters accepted since the last pass.
    ///
    /// Inbound announces only note the change, so a burst from one peer costs
    /// one recompute here rather than one per announce. Several peers may have
    /// announced, so every peer is a target; a peer is still marked only when
    /// its outgoing filter differs from what was last sent to it.
    pub(super) fn flush_inbound_changes(&mut self) {
        if !self.bloom_state.take_inbound_change() {
            return;
        }
        let peer_addrs: Vec<NodeAddr> = self.peers.keys().copied().collect();
        let peer_filters = self.peer_inbound_filters();
        self.bloom_state.mark_changed(&peer_addrs, &peer_filters);
    }

    /// WARN that an outgoing filter to `peer_addr` is held above the v1 cap.
    ///
    /// Rate-limited to once per 60s globally: a held update is retried at
    /// the debounce pace, and the operator needs one clear message, not one
    /// per attempt.
    fn warn_held(&mut self, peer_addr: &NodeAddr, filter: &BloomFilter) {
        let now = std::time::Instant::now();
        let should_warn = self
            .last_self_warn
            .is_none_or(|t| now.duration_since(t) >= std::time::Duration::from_secs(60));
        if !should_warn {
            return;
        }
        self.last_self_warn = Some(now);
        warn!(
            to = %self.peer_display_name(peer_addr),
            fill = format_args!("{:.3}", filter.fill_ratio()),
            fpr = format_args!("{:.4}", filter.fpr()),
            cap = format_args!("{:.4}", ACCEPT_FPR_CAP),
            "Outgoing filter above the v1 FPR cap — held, not sent"
        );
    }

    /// Send pending rate-limited filter announces whose debounce has expired.
    ///
    /// A peer that has not sent an authenticated frame since it was promoted
    /// is skipped, and its update stays pending for the first tick after that
    /// frame. A peer that completes a handshake and then sends nothing would
    /// otherwise draw an announce, and its resends, on every promotion. A
    /// working peer sends its TreeAnnounce as soon as it promotes, so its
    /// filter waits about one round trip.
    pub(super) async fn send_pending_filter_announces(&mut self) {
        self.flush_inbound_changes();

        // Monotonic: the debounce compares two reads, and a wall-clock step
        // back would hold announces for the size of the step.
        let now_ms = crate::time::mono_ms();

        let ready: Vec<NodeAddr> = self
            .peers
            .iter()
            .filter(|(addr, peer)| {
                peer.heard() && self.bloom_state.should_send_update(addr, now_ms)
            })
            .map(|(addr, _)| *addr)
            .collect();

        if ready.is_empty() {
            return;
        }

        // One snapshot and one union pass for the whole ready set. The
        // send path never mutates peer inbound filters or the tree state,
        // and the rx loop holds `&mut self` across the awaits, so the
        // snapshot cannot go stale mid-loop.
        let peer_filters = self.peer_inbound_filters();
        let mut outgoing = self
            .bloom_state
            .compute_outgoing_filters(&ready, &peer_filters);

        for peer_addr in ready {
            let Some(filter) = outgoing.remove(&peer_addr) else {
                continue;
            };
            if let Err(e) = self.send_filter_announce_to_peer(&peer_addr, filter).await {
                debug!(
                    peer = %self.peer_display_name(&peer_addr),
                    error = %e,
                    "Failed to send pending FilterAnnounce"
                );
            }
        }
    }

    /// Handle an inbound FilterAnnounce from an authenticated peer.
    ///
    /// 1. Decode and validate the message
    /// 2. Check sequence freshness (reject stale/replay)
    /// 3. Store the filter on the peer
    /// 4. Note the change; the next send pass marks the peers whose outgoing
    ///    filter it changed
    pub(super) async fn handle_filter_announce(&mut self, from: &NodeAddr, payload: &[u8]) {
        self.metrics().bloom.received.inc();

        let announce = match FilterAnnounce::decode(payload) {
            Ok(a) => a,
            Err(e) => {
                self.metrics().bloom.record_reject(BloomReject::DecodeError);
                debug!(from = %self.peer_display_name(from), error = %e, "Malformed FilterAnnounce");
                return;
            }
        };

        // Validate
        if !announce.is_valid() {
            self.metrics().bloom.record_reject(BloomReject::Invalid);
            debug!(from = %self.peer_display_name(from), "FilterAnnounce filter/size_class mismatch");
            return;
        }
        if !announce.is_v1_compliant() {
            self.metrics().bloom.record_reject(BloomReject::NonV1);
            debug!(
                from = %self.peer_display_name(from),
                size_class = announce.size_class,
                hash_count = announce.hash_count,
                "Non-v1 FilterAnnounce rejected"
            );
            return;
        }

        // Check peer exists
        let current_seq = match self.peers.get(from) {
            Some(peer) => peer.filter_sequence(),
            None => {
                self.metrics().bloom.record_reject(BloomReject::UnknownPeer);
                debug!(from = %self.peer_display_name(from), "FilterAnnounce from unknown peer");
                return;
            }
        };

        // Reject stale/replay
        if announce.sequence <= current_seq {
            self.metrics().bloom.record_reject(BloomReject::Stale);
            debug!(
                from = %self.peer_display_name(from),
                received_seq = announce.sequence,
                current_seq = current_seq,
                "Stale FilterAnnounce rejected"
            );
            return;
        }

        // Antipoison FPR cap. Reject announces whose FPR exceeds
        // node.bloom.max_inbound_fpr. Silent on the wire (no NACK) —
        // the peer's prior accepted filter and filter_sequence stay
        // untouched so the peer is not permanently silenced and an
        // on-path attacker cannot weaponize a single corrupted frame
        // to wipe a victim's contribution to aggregation.
        let max_fpr = self.config().node.bloom.max_inbound_fpr;
        let fill = announce.filter.fill_ratio();
        let fpr = announce.filter.fpr();
        if fpr > max_fpr {
            self.metrics()
                .bloom
                .record_reject(BloomReject::FillExceeded);
            warn!(
                from = %self.peer_display_name(from),
                seq = announce.sequence,
                fill = format_args!("{:.3}", fill),
                fpr = format_args!("{:.4}", fpr),
                cap = format_args!("{:.4}", max_fpr),
                "FilterAnnounce above FPR cap — rejected"
            );
            return;
        }

        // Child echo guard. A tree child's filter is merged into the one we
        // send our parent, so a child that returns what we sent it would make
        // that filter claim everything we already know. Like the FPR cap,
        // the rejection leaves the stored filter and filter_sequence as they
        // were. It applies only when there is a stored filter to keep: with
        // none, a false rejection would drop the child's subtree outright.
        if let Some(echo) = self.child_echo(from, &announce.filter) {
            self.metrics().bloom.record_reject(BloomReject::ChildRole);
            warn!(
                from = %self.peer_display_name(from),
                seq = announce.sequence,
                fill = format_args!("{:.3}", fill),
                overlap = format_args!("{:.3}", echo.overlap),
                bound = format_args!("{:.3}", echo.bound),
                digest = %diag::filter_tag(&announce.filter),
                sent_digest = %echo.sent_digest,
                "FilterAnnounce from a tree child returns the filter we sent it, kept its previous filter"
            );
            return;
        }

        self.metrics().bloom.accepted.inc();

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        debug!(
            from = %self.peer_display_name(from),
            seq = announce.sequence,
            est_entries = match announce.filter.estimated_count(max_fpr) {
                Some(n) => format!("{:.0}", n),
                None => "—".to_string(),
            },
            set_bits = announce.filter.count_ones(),
            fill = format_args!("{:.1}%", announce.filter.fill_ratio() * 100.0),
            tree_peer = self.is_tree_peer(from),
            digest = %diag::filter_tag(&announce.filter),
            tree_role = %self.tree_role(from),
            overlap = %self.overlap_with_sent(from, &announce.filter),
            "Received FilterAnnounce"
        );

        // Store on peer
        if let Some(peer) = self.peers.get_mut(from) {
            peer.update_filter(announce.filter, announce.sequence, now_ms);
        }

        // Which peers' outgoing filters changed is decided once per send
        // pass (`flush_inbound_changes`), not per announce, so a peer cannot
        // force a full recompute with every announce it sends.
        self.bloom_state.note_inbound_change();
    }

    /// The readings behind rejecting `got` from `from` as a return of the
    /// filter we last sent it, or `None` to accept it.
    ///
    /// Applies only when `from` is our tree child, already has a stored
    /// filter (the one a rejection keeps), and we have sent it a filter;
    /// the test itself is [`BloomFilter::echoes`] at
    /// `node.bloom.child_echo_threshold`.
    fn child_echo(&self, from: &NodeAddr, got: &BloomFilter) -> Option<ChildEcho> {
        if self.tree_role(from) != diag::TreeRole::Child {
            return None;
        }
        self.peers.get(from)?.inbound_filter()?;
        let sent = self.bloom_state.last_sent_filter(from)?;
        let threshold = self.config().node.bloom.child_echo_threshold;
        if !got.echoes(sent, threshold) {
            return None;
        }
        Some(ChildEcho {
            overlap: got.overlap(sent)?,
            bound: got.echo_bound(threshold),
            sent_digest: diag::filter_tag(sent),
        })
    }

    /// How much of the filter last sent to `from` the filter it announced
    /// contains, for a tree peer; `none` for a non-tree peer, or before
    /// anything was sent to it.
    fn overlap_with_sent(&self, from: &NodeAddr, got: &BloomFilter) -> diag::OrNone<diag::Ratio> {
        if self.tree_role(from) == diag::TreeRole::None {
            return diag::OrNone(None);
        }
        let sent = self.bloom_state.last_sent_filter(from);
        diag::OrNone(sent.and_then(|s| got.overlap(s)).map(diag::Ratio))
    }

    /// Read what `peer_addr`'s link shows about delivery of our frames: the
    /// session's identity and next send counter, and the last ReceiverReport
    /// accepted on it. `None` when the peer has no session. Both the filter
    /// and the tree announce resends read it.
    pub(super) fn link_evidence(&self, peer_addr: &NodeAddr) -> Option<LinkEvidence> {
        let peer = self.peers.get(peer_addr)?;
        let session = peer.noise_session()?;
        let mut epoch = [0u8; 8];
        epoch.copy_from_slice(&session.handshake_hash()[..8]);
        let rr = peer.mmp().and_then(|mmp| mmp.metrics.rr_counters()).map(
            |(highest, received, reordered)| RrCounters {
                highest,
                received,
                reordered,
            },
        );
        Some(LinkEvidence {
            epoch: u64::from_le_bytes(epoch),
            next_counter: session.current_send_counter(),
            rr,
        })
    }

    /// Mark for resend every peer whose outstanding announce the receiver
    /// reports show was lost, or could not confirm in time.
    fn check_announces(&mut self) {
        let now_ms = crate::time::mono_ms();
        let waiting: Vec<NodeAddr> = self
            .peers
            .keys()
            .filter(|addr| self.bloom_state.announce_outstanding(addr))
            .copied()
            .collect();
        for addr in waiting {
            let Some(link) = self.link_evidence(&addr) else {
                continue;
            };
            let counter = self.bloom_state.outstanding_counter(&addr);
            if let Some(reason) = self.bloom_state.check_announce(&addr, &link, now_ms) {
                debug!(
                    peer = %self.peer_display_name(&addr),
                    reason = ?reason,
                    counter = ?counter,
                    "Resending unconfirmed FilterAnnounce"
                );
            }
        }
    }

    /// Check bloom filter state on tick (called from event loop).
    ///
    /// Marks peers whose last announce was not confirmed delivered, then sends
    /// any pending debounced filter announces, so a resend goes out in the
    /// same tick through the ordinary send path.
    pub(super) async fn check_bloom_state(&mut self) {
        self.check_announces();
        self.send_pending_filter_announces().await;
    }
}
