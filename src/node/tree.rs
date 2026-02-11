//! Spanning Tree Announce send/receive logic.
//!
//! Handles building, sending, and receiving TreeAnnounce messages,
//! including periodic root refresh and rate-limited propagation.

use crate::protocol::TreeAnnounce;
use crate::NodeAddr;

use super::{Node, NodeError};
use tracing::{debug, info, warn};

/// Root nodes re-announce every 30 minutes to keep the tree alive.
const ROOT_REFRESH_INTERVAL_SECS: u64 = 30 * 60;

impl Node {
    /// Build a TreeAnnounce from our current tree state.
    fn build_tree_announce(&self) -> Result<TreeAnnounce, NodeError> {
        let decl = self.tree_state.my_declaration().clone();
        let ancestry = self.tree_state.my_coords().clone();

        if !decl.is_signed() {
            return Err(NodeError::SendFailed {
                node_addr: *self.identity.node_addr(),
                reason: "declaration not signed".into(),
            });
        }

        Ok(TreeAnnounce::new(decl, ancestry))
    }

    /// Send a TreeAnnounce to a specific peer, respecting rate limits.
    ///
    /// If the peer is rate-limited, the announce is marked pending for
    /// delivery on the next tick cycle.
    pub(super) async fn send_tree_announce_to_peer(
        &mut self,
        peer_addr: &NodeAddr,
    ) -> Result<(), NodeError> {
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
            debug!(
                peer = %peer_addr,
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
        self.send_encrypted_link_message(peer_addr, &encoded).await?;

        // Record send time
        if let Some(peer) = self.peers.get_mut(peer_addr) {
            peer.record_tree_announce_sent(now_ms);
        }

        debug!(peer = %peer_addr, "Sent TreeAnnounce");
        Ok(())
    }

    /// Send a TreeAnnounce to all active peers.
    pub(super) async fn send_tree_announce_to_all(&mut self) {
        let peer_addrs: Vec<NodeAddr> = self.peers.keys().copied().collect();

        for peer_addr in peer_addrs {
            if let Err(e) = self.send_tree_announce_to_peer(&peer_addr).await {
                debug!(
                    peer = %peer_addr,
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
            .filter(|(_, peer)| peer.has_pending_tree_announce() && peer.can_send_tree_announce(now_ms))
            .map(|(addr, _)| *addr)
            .collect();

        for peer_addr in ready {
            if let Err(e) = self.send_tree_announce_to_peer(&peer_addr).await {
                debug!(
                    peer = %peer_addr,
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
        let announce = match TreeAnnounce::decode(payload) {
            Ok(a) => a,
            Err(e) => {
                debug!(from = %from, error = %e, "Malformed TreeAnnounce");
                return;
            }
        };

        // Verify sender's declaration signature using their known pubkey
        let pubkey = match self.peers.get(from) {
            Some(peer) => peer.pubkey(),
            None => {
                debug!(from = %from, "TreeAnnounce from unknown peer");
                return;
            }
        };

        // The declaring node_addr in the announce should match the sender
        if announce.declaration.node_addr() != from {
            debug!(
                from = %from,
                declared = %announce.declaration.node_addr(),
                "TreeAnnounce node_addr mismatch"
            );
            return;
        }

        if let Err(e) = announce.declaration.verify(&pubkey) {
            warn!(
                from = %from,
                error = %e,
                "TreeAnnounce signature verification failed"
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
        let updated = self.tree_state.update_peer(
            announce.declaration.clone(),
            announce.ancestry.clone(),
        );

        if !updated {
            debug!(from = %from, "TreeAnnounce not fresher than existing, ignored");
            return;
        }

        info!(
            from = %from,
            seq = announce.declaration.sequence(),
            depth = announce.ancestry.depth(),
            root = %announce.ancestry.root_id(),
            "Processed TreeAnnounce"
        );

        // Re-evaluate parent selection
        if let Some(new_parent) = self.tree_state.evaluate_parent() {
            let new_seq = self.tree_state.my_declaration().sequence() + 1;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            self.tree_state.set_parent(new_parent, new_seq, timestamp);
            if let Err(e) = self.tree_state.sign_declaration(&self.identity) {
                warn!(error = %e, "Failed to sign declaration after parent switch");
                return;
            }
            self.tree_state.recompute_coords();

            info!(
                new_parent = %new_parent,
                new_seq = new_seq,
                new_root = %self.tree_state.root(),
                depth = self.tree_state.my_coords().depth(),
                "Parent switched, announcing to all peers"
            );

            self.send_tree_announce_to_all().await;
        } else if !self.tree_state.is_root()
            && *self.tree_state.my_declaration().parent_id() == *from
        {
            // Our parent's ancestry changed but we're keeping the same parent.
            // Recompute our own coordinates (which derive from parent's ancestry)
            // and re-announce so downstream nodes stay current.
            let old_root = *self.tree_state.root();
            let old_depth = self.tree_state.my_coords().depth();

            let new_seq = self.tree_state.my_declaration().sequence() + 1;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            self.tree_state.set_parent(*from, new_seq, timestamp);
            if let Err(e) = self.tree_state.sign_declaration(&self.identity) {
                warn!(error = %e, "Failed to sign declaration after parent update");
                return;
            }
            self.tree_state.recompute_coords();

            let new_root = *self.tree_state.root();
            let new_depth = self.tree_state.my_coords().depth();

            if new_root != old_root || new_depth != old_depth {
                info!(
                    parent = %from,
                    old_root = %old_root,
                    new_root = %new_root,
                    new_depth = new_depth,
                    "Parent ancestry changed, re-announcing"
                );
                self.send_tree_announce_to_all().await;
            }
        }
    }

    /// Periodic tree maintenance, called from the tick handler.
    ///
    /// - Sends pending rate-limited announces
    /// - Refreshes root announcement every ROOT_REFRESH_INTERVAL_SECS (if root)
    pub(super) async fn check_tree_state(&mut self) {
        // Send any pending rate-limited announces
        self.send_pending_tree_announces().await;

        // Root refresh
        if self.tree_state.is_root() && !self.peers.is_empty() {
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            if now_secs.saturating_sub(self.last_root_refresh_secs) >= ROOT_REFRESH_INTERVAL_SECS {
                let new_seq = self.tree_state.my_declaration().sequence() + 1;
                self.tree_state
                    .set_parent(*self.identity.node_addr(), new_seq, now_secs);
                if let Err(e) = self.tree_state.sign_declaration(&self.identity) {
                    warn!(error = %e, "Failed to sign root refresh declaration");
                    return;
                }
                self.tree_state.recompute_coords();
                self.last_root_refresh_secs = now_secs;

                debug!(seq = new_seq, "Root refresh: announcing to all peers");
                self.send_tree_announce_to_all().await;
            }
        }
    }

    /// Handle tree state cleanup when a peer is removed.
    ///
    /// Called from `remove_active_peer`. If the removed peer was our parent,
    /// attempts to find an alternative or becomes root.
    ///
    /// Returns `true` if our tree state changed (caller should announce).
    pub(super) fn handle_peer_removal_tree_cleanup(&mut self, node_addr: &NodeAddr) -> bool {
        let was_parent = !self.tree_state.is_root()
            && self.tree_state.my_declaration().parent_id() == node_addr;

        self.tree_state.remove_peer(node_addr);

        if was_parent {
            let changed = self.tree_state.handle_parent_lost();
            if changed {
                // Re-sign the new declaration
                if let Err(e) = self.tree_state.sign_declaration(&self.identity) {
                    warn!(error = %e, "Failed to sign declaration after parent loss");
                }
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
