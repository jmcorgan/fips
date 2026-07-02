//! Spanning Tree Announce send/receive logic.
//!
//! Handles building, sending, and receiving TreeAnnounce messages,
//! including periodic root refresh and rate-limited propagation.

use std::collections::HashMap;

use crate::NodeAddr;
use crate::protocol::TreeAnnounce;

use super::reject::TreeReject;
use super::{Node, NodeError};
use tracing::{debug, info, trace, warn};

impl Node {
    /// Build a TreeAnnounce from our current tree state.
    fn build_tree_announce(&self) -> Result<TreeAnnounce, NodeError> {
        let decl = self.tree_state.my_declaration().clone();
        let ancestry = self.tree_state.my_coords().clone();

        if !decl.is_signed() {
            return Err(NodeError::SendFailed {
                node_addr: *self.identity().node_addr(),
                reason: "declaration not signed".into(),
            });
        }

        Ok(TreeAnnounce::new(decl, ancestry))
    }

    /// Send a TreeAnnounce to a specific peer, respecting rate limits.
    ///
    /// If the peer is rate-limited, the announce is marked pending for
    /// delivery on the next tick cycle. Leaf nodes do not send tree
    /// announces (they don't participate in the spanning tree).
    pub(super) async fn send_tree_announce_to_peer(
        &mut self,
        peer_addr: &NodeAddr,
    ) -> Result<(), NodeError> {
        if self.node_profile() == crate::protocol::NodeProfile::Leaf {
            return Ok(());
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Check rate limit
        let peer = match self.peers.get_mut(peer_addr) {
            Some(p) => p,
            None => return Err(NodeError::PeerNotFound(*peer_addr)),
        };

        if !peer.can_send_tree_announce(now_ms) {
            peer.mark_tree_announce_pending();
            self.metrics().tree.rate_limited.inc();
            debug!(
                peer = %self.peer_display_name(peer_addr),
                "TreeAnnounce rate-limited, marking pending"
            );
            return Ok(());
        }

        // Build and encode
        let announce = self.build_tree_announce()?;
        let encoded = announce.encode().map_err(|e| NodeError::SendFailed {
            node_addr: *peer_addr,
            reason: format!("encode failed: {}", e),
        })?;

        // Send
        if let Err(e) = self.send_encrypted_link_message(peer_addr, &encoded).await {
            self.metrics().tree.send_failed.inc();
            return Err(e);
        }

        self.metrics().tree.sent.inc();

        // Record send time
        if let Some(peer) = self.peers.get_mut(peer_addr) {
            peer.record_tree_announce_sent(now_ms);
        }

        trace!(peer = %self.peer_display_name(peer_addr), "Sent TreeAnnounce");
        Ok(())
    }

    /// Send a TreeAnnounce to all active peers.
    pub(super) async fn send_tree_announce_to_all(&mut self) {
        let peer_addrs: Vec<NodeAddr> = self.peers.keys().copied().collect();

        for peer_addr in peer_addrs {
            if let Err(e) = self.send_tree_announce_to_peer(&peer_addr).await {
                debug!(
                    peer = %self.peer_display_name(&peer_addr),
                    error = %e,
                    "Failed to send TreeAnnounce"
                );
            }
        }
    }

    /// Send pending rate-limited tree announces whose cooldown has expired.
    pub(super) async fn send_pending_tree_announces(&mut self) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let ready: Vec<NodeAddr> = self
            .peers
            .iter()
            .filter(|(_, peer)| {
                peer.has_pending_tree_announce() && peer.can_send_tree_announce(now_ms)
            })
            .map(|(addr, _)| *addr)
            .collect();

        for peer_addr in ready {
            if let Err(e) = self.send_tree_announce_to_peer(&peer_addr).await {
                debug!(
                    peer = %self.peer_display_name(&peer_addr),
                    error = %e,
                    "Failed to send pending TreeAnnounce"
                );
            }
        }
    }

    /// Handle an inbound TreeAnnounce from an authenticated peer.
    ///
    /// 1. Decode the message
    /// 2. Verify the sender's declaration signature (pubkey from handshake)
    /// 3. Update the peer's tree state
    /// 4. Re-evaluate parent selection
    /// 5. If parent changed: increment seq, sign, recompute coords, announce to all
    pub(super) async fn handle_tree_announce(&mut self, from: &NodeAddr, payload: &[u8]) {
        self.metrics().tree.received.inc();

        let announce = match TreeAnnounce::decode(payload) {
            Ok(a) => a,
            Err(e) => {
                self.metrics().tree.decode_error.inc();
                debug!(from = %self.peer_display_name(from), error = %e, "Malformed TreeAnnounce");
                return;
            }
        };

        // Verify sender's declaration signature using their known pubkey
        let pubkey = match self.peers.get(from) {
            Some(peer) => peer.pubkey(),
            None => {
                self.metrics().tree.unknown_peer.inc();
                debug!(from = %self.peer_display_name(from), "TreeAnnounce from unknown peer");
                return;
            }
        };

        // The declaring node_addr in the announce should match the sender
        if announce.declaration.node_addr() != from {
            self.metrics().tree.addr_mismatch.inc();
            debug!(
                from = %self.peer_display_name(from),
                declared = %announce.declaration.node_addr(),
                "TreeAnnounce node_addr mismatch"
            );
            return;
        }

        if let Err(e) = announce.declaration.verify(&pubkey) {
            self.metrics().tree.sig_failed.inc();
            warn!(
                from = %self.peer_display_name(from),
                error = %e,
                "TreeAnnounce signature verification failed"
            );
            return;
        }

        if let Err(e) = announce.validate_semantics() {
            self.metrics()
                .tree
                .record_reject(TreeReject::AncestryInvalid);
            warn!(
                from = %self.peer_display_name(from),
                error = %e,
                "Rejected TreeAnnounce with invalid ancestry"
            );
            return;
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Update peer's tree state in ActivePeer
        if let Some(peer) = self.peers.get_mut(from) {
            peer.update_tree_position(
                announce.declaration.clone(),
                announce.ancestry.clone(),
                now_ms,
            );
        }

        // Update in TreeState
        let updated = self
            .tree_state
            .update_peer(announce.declaration.clone(), announce.ancestry.clone());

        if !updated {
            self.metrics().tree.stale.inc();
            debug!(from = %self.peer_display_name(from), "TreeAnnounce not fresher than existing, ignored");
            return;
        }

        self.metrics().tree.accepted.inc();

        debug!(
            from = %self.peer_display_name(from),
            seq = announce.declaration.sequence(),
            depth = announce.ancestry.depth(),
            root = %announce.ancestry.root_id(),
            "Processed TreeAnnounce"
        );

        // Re-push our current position when the announcing peer advertises a
        // strictly worse (higher NodeAddr) root than ours. Root election is
        // smallest-NodeAddr-wins, so a peer on a higher root has a stale or
        // pre-attachment view and can attach to (or re-attach through) us;
        // reply with our current declaration so it does so without waiting
        // for the next periodic re-broadcast cadence.
        //
        // Only the better-rooted side echoes. If the peer's root is lower
        // (better) than ours, WE are the stale side: the peer would ignore
        // our worse root anyway, and we converge via the parent re-evaluation
        // below, so echoing back is pure waste — and during a root change or
        // partition merge it would double announce traffic in the learning
        // direction. Equal roots are already converged. Restricting to `>`
        // keeps the echo to the one direction that helps.
        //
        // This closes a convergence wedge on a single-uplink node: its only
        // peer pushes the attaching announce once at promotion time, and if
        // that datagram is lost the single-uplink node cannot self-correct
        // (its own periodic parent re-evaluation is disabled below two peers)
        // and is stranded as a self-root until the parent's next periodic
        // re-broadcast (~reeval_interval_secs later). Echoing on root
        // disagreement makes tree-position exchange self-healing on the
        // receive path and is naturally bounded by the per-peer 500 ms
        // tree-announce rate limiter, so it does not storm during normal
        // convergence (it stops as soon as the peer adopts our root).
        if *announce.ancestry.root_id() > *self.tree_state.root()
            && let Err(e) = self.send_tree_announce_to_peer(from).await
        {
            debug!(
                peer = %self.peer_display_name(from),
                error = %e,
                "Failed to re-push TreeAnnounce on root disagreement"
            );
        }

        // Bloom filter exchange initiation is handled at handshake completion
        // ([handshake.rs] mark_update_needed on the new peer) and on actual
        // content changes via [bloom.rs::handle_filter_announce]'s
        // `mark_changed_peers`. Marking the peer on every received TreeAnnounce
        // is redundant — and under high TreeAnnounce churn (rapid mid-chain
        // swap propagation) it amplifies bloom traffic proportionally with
        // the tree announce rate, even when the local outgoing filter
        // content has not changed.

        // Re-evaluate parent selection with current link costs.
        // Exclude peers without MMP RTT data — they are not yet eligible
        // as parent candidates (prevents oscillation from optimistic defaults).
        let peer_costs: HashMap<NodeAddr, f64> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.has_srtt())
            .map(|(addr, peer)| (*addr, peer.link_cost()))
            .collect();
        let skip = self.non_full_peers();
        if let Some(new_parent) = self.tree_state.evaluate_parent(&peer_costs, &skip) {
            let new_seq = self.tree_state.my_declaration().sequence() + 1;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            // Clone identity up front to avoid a split borrow against the
            // &mut self.tree_state / &mut self.coord_cache calls below (cold path).
            let our_identity = self.identity().clone();
            let flap_dampened = self.tree_state.set_parent(new_parent, new_seq, timestamp);
            // recompute_coords may demote to self_root if the new path would be
            // invalid; sign AFTER recompute so the signature covers the final
            // declaration.
            self.tree_state.recompute_coords();
            if let Err(e) = self.tree_state.sign_declaration(&our_identity) {
                warn!(error = %e, "Failed to sign declaration after parent switch");
                self.metrics()
                    .tree
                    .record_reject(TreeReject::OutboundSignFailed);
                return;
            }
            // Surgical invalidation — see CoordCache::invalidate_via_node doc.
            self.coord_cache
                .invalidate_via_node(our_identity.node_addr());
            self.reset_discovery_backoff();

            self.metrics().tree.parent_switched.inc();
            self.metrics().tree.parent_switches.inc();

            info!(
                new_parent = %self.peer_display_name(&new_parent),
                new_seq = new_seq,
                new_root = %self.tree_state.root(),
                depth = self.tree_state.my_coords().depth(),
                "Parent switched, invalidated downstream coord cache entries, announcing to all peers"
            );
            if flap_dampened {
                self.metrics().tree.flap_dampened.inc();
                warn!("Flap dampening engaged: excessive parent switches detected");
            }

            self.send_tree_announce_to_all().await;

            // Tree structure changed — trigger bloom filter exchange with all peers
            let all_peers: Vec<NodeAddr> = self.peers.keys().copied().collect();
            self.bloom_state.mark_all_updates_needed(all_peers);
        } else if !self.tree_state.is_root() && self.tree_state.should_be_root() {
            // Self is the smallest visible NodeAddr — promote to root rather
            // than continuing to advertise a stale ancestry rooted elsewhere.
            // Clone identity up front to avoid a split borrow against the
            // &mut self.tree_state / &mut self.coord_cache calls below (cold path).
            let our_identity = self.identity().clone();
            self.tree_state.become_root();
            if let Err(e) = self.tree_state.sign_declaration(&our_identity) {
                warn!(error = %e, "Failed to sign self-root declaration");
                self.metrics()
                    .tree
                    .record_reject(TreeReject::OutboundSignFailed);
                return;
            }
            // Surgical invalidation — see CoordCache::invalidate_other_roots doc.
            self.coord_cache
                .invalidate_other_roots(our_identity.node_addr());
            self.reset_discovery_backoff();
            self.metrics().tree.parent_switched.inc();
            self.metrics().tree.parent_switches.inc();
            info!(
                new_root = %self.tree_state.root(),
                "Self-promoted to root: smallest visible NodeAddr"
            );
            self.send_tree_announce_to_all().await;
            let all_peers: Vec<NodeAddr> = self.peers.keys().copied().collect();
            self.bloom_state.mark_all_updates_needed(all_peers);
        } else if !self.tree_state.is_root()
            && *self.tree_state.my_declaration().parent_id() == *from
        {
            // Check for loop: if parent's ancestry now contains us, drop parent
            if let Some(parent_coords) = self.tree_state.peer_coords(from)
                && parent_coords.contains(self.identity().node_addr())
            {
                self.metrics().tree.loop_detected.inc();
                warn!(
                    parent = %self.peer_display_name(from),
                    "Parent ancestry contains us — loop detected, dropping parent"
                );
                let peer_costs: HashMap<NodeAddr, f64> = self
                    .peers
                    .iter()
                    .filter(|(_, peer)| peer.has_srtt())
                    .map(|(addr, peer)| (*addr, peer.link_cost()))
                    .collect();
                if self.tree_state.handle_parent_lost(&peer_costs) {
                    // Clone identity up front to avoid a split borrow against the
                    // &mut self.tree_state / &mut self.coord_cache calls below (cold path).
                    let our_identity = self.identity().clone();
                    if let Err(e) = self.tree_state.sign_declaration(&our_identity) {
                        warn!(error = %e, "Failed to sign declaration after loop detection");
                        self.metrics()
                            .tree
                            .record_reject(TreeReject::OutboundSignFailed);
                        return;
                    }
                    // handle_parent_lost may promote to root OR find new parent;
                    // cover both invalidation classes.
                    self.coord_cache
                        .invalidate_via_node(our_identity.node_addr());
                    self.coord_cache
                        .invalidate_other_roots(self.tree_state.root());
                    self.reset_discovery_backoff();
                    self.send_tree_announce_to_all().await;
                }
                return;
            }

            // Our parent's ancestry changed but we're keeping the same parent.
            // Recompute our own coordinates (which derive from parent's ancestry)
            // and re-announce so downstream nodes stay current.
            //
            // Compare the full address path (not just root + depth) so that a
            // mid-chain ancestor swap also triggers re-announce. A reroute that
            // replaces an interior ancestor without changing the root or the
            // path length leaves both `root` and `depth` unchanged but still
            // alters our coords; downstream peers must learn the new path or
            // they will route into a phantom intermediate that no longer
            // exists on our parent's tree.
            let old_root = *self.tree_state.root();
            let old_depth = self.tree_state.my_coords().depth();
            let old_addrs: Vec<NodeAddr> =
                self.tree_state.my_coords().node_addrs().copied().collect();

            let new_seq = self.tree_state.my_declaration().sequence() + 1;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            // Clone identity up front to avoid a split borrow against the
            // &mut self.tree_state / &mut self.coord_cache calls below (cold path).
            let our_identity = self.identity().clone();
            self.tree_state.set_parent(*from, new_seq, timestamp);
            self.tree_state.recompute_coords();
            if let Err(e) = self.tree_state.sign_declaration(&our_identity) {
                warn!(error = %e, "Failed to sign declaration after parent update");
                self.metrics()
                    .tree
                    .record_reject(TreeReject::OutboundSignFailed);
                return;
            }
            // Surgical invalidation — see CoordCache::invalidate_via_node doc.
            self.coord_cache
                .invalidate_via_node(our_identity.node_addr());
            self.reset_discovery_backoff();

            let new_addrs: Vec<NodeAddr> =
                self.tree_state.my_coords().node_addrs().copied().collect();

            if old_addrs != new_addrs {
                self.metrics().tree.ancestry_changed.inc();
                info!(
                    parent = %self.peer_display_name(from),
                    old_root = %old_root,
                    new_root = %self.tree_state.root(),
                    old_depth = old_depth,
                    new_depth = self.tree_state.my_coords().depth(),
                    "Parent ancestry changed, re-announcing"
                );
                self.send_tree_announce_to_all().await;

                // Bloom contents do not depend on path structure, only on
                // identity sets. Our parent_id is unchanged in this branch,
                // so our tree-peer set is unchanged and our outgoing filter
                // content is unchanged. Use mark_changed_peers, which
                // checks for actual content delta against last_sent_filters,
                // instead of mark_all_updates_needed, which marks
                // unconditionally regardless of whether content changed.
                let peer_addrs: Vec<NodeAddr> = self.peers.keys().copied().collect();
                let peer_filters = self.peer_inbound_filters();
                self.bloom_state
                    .mark_changed_peers(from, &peer_addrs, &peer_filters);
            }
        }
    }

    /// Periodic tree maintenance, called from the tick handler.
    ///
    /// Sends pending rate-limited announces and checks for periodic
    /// parent re-evaluation based on current MMP link costs.
    pub(super) async fn check_tree_state(&mut self) {
        self.send_pending_tree_announces().await;
        self.check_periodic_parent_reeval().await;
    }

    /// Periodic parent re-evaluation based on current MMP link costs.
    ///
    /// Self-paces using `last_parent_reeval` and the configured
    /// `reeval_interval_secs`. When a better parent is found, follows
    /// the same switch flow as TreeAnnounce-triggered switches.
    async fn check_periodic_parent_reeval(&mut self) {
        let interval_secs = self.config().node.tree.reeval_interval_secs;
        if interval_secs == 0 {
            return;
        }

        // Need at least 2 peers for a meaningful comparison
        if self.peers.len() < 2 {
            return;
        }

        let now = std::time::Instant::now();
        let interval = std::time::Duration::from_secs(interval_secs);

        if let Some(last) = self.last_parent_reeval
            && now.duration_since(last) < interval
        {
            return;
        }

        self.last_parent_reeval = Some(now);

        let peer_costs: HashMap<NodeAddr, f64> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.has_srtt())
            .map(|(addr, peer)| (*addr, peer.link_cost()))
            .collect();

        let skip = self.non_full_peers();
        if let Some(new_parent) = self.tree_state.evaluate_parent(&peer_costs, &skip) {
            let new_seq = self.tree_state.my_declaration().sequence() + 1;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            // Clone identity up front to avoid a split borrow against the
            // &mut self.tree_state / &mut self.coord_cache calls below (cold path).
            let our_identity = self.identity().clone();
            let flap_dampened = self.tree_state.set_parent(new_parent, new_seq, timestamp);
            self.tree_state.recompute_coords();
            if let Err(e) = self.tree_state.sign_declaration(&our_identity) {
                warn!(error = %e, "Failed to sign declaration after periodic parent re-eval");
                self.metrics()
                    .tree
                    .record_reject(TreeReject::OutboundSignFailed);
                return;
            }
            // Surgical invalidation — see CoordCache::invalidate_via_node doc.
            self.coord_cache
                .invalidate_via_node(our_identity.node_addr());
            self.reset_discovery_backoff();

            self.metrics().tree.parent_switched.inc();
            self.metrics().tree.parent_switches.inc();

            info!(
                new_parent = %self.peer_display_name(&new_parent),
                new_seq = new_seq,
                new_root = %self.tree_state.root(),
                depth = self.tree_state.my_coords().depth(),
                trigger = "periodic",
                "Parent switched via periodic cost re-evaluation"
            );
            if flap_dampened {
                self.metrics().tree.flap_dampened.inc();
                warn!("Flap dampening engaged: excessive parent switches detected");
            }

            self.send_tree_announce_to_all().await;

            let all_peers: Vec<NodeAddr> = self.peers.keys().copied().collect();
            self.bloom_state.mark_all_updates_needed(all_peers);
        } else if !self.tree_state.is_root() && self.tree_state.should_be_root() {
            // Clone identity up front to avoid a split borrow against the
            // &mut self.tree_state / &mut self.coord_cache calls below (cold path).
            let our_identity = self.identity().clone();
            self.tree_state.become_root();
            if let Err(e) = self.tree_state.sign_declaration(&our_identity) {
                warn!(error = %e, "Failed to sign self-root declaration in periodic reeval");
                self.metrics()
                    .tree
                    .record_reject(TreeReject::OutboundSignFailed);
                return;
            }
            // Surgical invalidation — see CoordCache::invalidate_other_roots doc.
            self.coord_cache
                .invalidate_other_roots(our_identity.node_addr());
            self.reset_discovery_backoff();
            self.metrics().tree.parent_switched.inc();
            self.metrics().tree.parent_switches.inc();
            info!(
                new_root = %self.tree_state.root(),
                trigger = "periodic",
                "Self-promoted to root in periodic reeval: smallest visible NodeAddr"
            );
            self.send_tree_announce_to_all().await;
            let all_peers: Vec<NodeAddr> = self.peers.keys().copied().collect();
            self.bloom_state.mark_all_updates_needed(all_peers);
        } else {
            // Periodic re-broadcast on no-change: makes TreeAnnounce
            // distribution eventually-consistent. Receivers coalesce
            // by sequence via ParentDeclaration::is_fresher_than and
            // short-circuit at the `if !updated` gate in
            // handle_tree_announce; the per-peer 500 ms rate-limiter
            // never blocks at this 60 s cadence. Closes the cross-init
            // in-flight loss recovery gap where the swap window can
            // strand one side's announce on a session-index the other
            // side cannot decrypt.
            trace!(
                seq = self.tree_state.my_declaration().sequence(),
                root = %self.tree_state.root(),
                "Periodic TreeAnnounce re-broadcast (no state change)"
            );
            self.send_tree_announce_to_all().await;
        }
    }

    /// Handle tree state cleanup when a peer is removed.
    ///
    /// Called from `remove_active_peer`. If the removed peer was our parent,
    /// attempts to find an alternative or becomes root.
    ///
    /// Returns `true` if our tree state changed (caller should announce).
    pub(super) fn handle_peer_removal_tree_cleanup(&mut self, node_addr: &NodeAddr) -> bool {
        let was_parent =
            !self.tree_state.is_root() && self.tree_state.my_declaration().parent_id() == node_addr;

        self.tree_state.remove_peer(node_addr);

        if was_parent {
            self.metrics().tree.parent_losses.inc();
            let peer_costs: HashMap<NodeAddr, f64> = self
                .peers
                .iter()
                .filter(|(_, peer)| peer.has_srtt())
                .map(|(addr, peer)| (*addr, peer.link_cost()))
                .collect();
            let changed = self.tree_state.handle_parent_lost(&peer_costs);
            if changed {
                // Re-sign the new declaration. Clone identity to avoid a split
                // borrow against the &mut self.tree_state receiver (cold path).
                let our_identity = self.identity().clone();
                if let Err(e) = self.tree_state.sign_declaration(&our_identity) {
                    warn!(error = %e, "Failed to sign declaration after parent loss");
                    self.metrics()
                        .tree
                        .record_reject(TreeReject::OutboundSignFailed);
                }
                // handle_parent_lost may promote to root OR find new parent;
                // cover both invalidation classes (same as the loop-detection
                // branch above). Without this, cached downstream entries keep
                // our now-stale coordinate prefix until TTL — and get_and_touch
                // refreshes the TTL on every routing access, so an actively
                // routed stale entry never self-expires.
                self.coord_cache
                    .invalidate_via_node(our_identity.node_addr());
                self.coord_cache
                    .invalidate_other_roots(self.tree_state.root());
                info!(
                    new_root = %self.tree_state.root(),
                    is_root = self.tree_state.is_root(),
                    "Tree state updated after parent loss"
                );
            }
            changed
        } else {
            false
        }
    }
}
