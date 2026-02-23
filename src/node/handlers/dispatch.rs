//! Link message dispatch and peer removal.

use crate::node::Node;
use crate::NodeAddr;
use tracing::{debug, info, trace};

impl Node {
    /// Dispatch a decrypted link message to the appropriate handler.
    ///
    /// Link messages are protocol messages exchanged between authenticated peers.
    pub(in crate::node) async fn dispatch_link_message(&mut self, from: &NodeAddr, plaintext: &[u8]) {
        if plaintext.is_empty() {
            return;
        }

        let msg_type = plaintext[0];
        let payload = &plaintext[1..];

        match msg_type {
            0x00 => {
                // SessionDatagram
                self.handle_session_datagram(from, payload).await;
            }
            0x01 => {
                // SenderReport
                self.handle_sender_report(from, payload);
            }
            0x02 => {
                // ReceiverReport
                self.handle_receiver_report(from, payload);
            }
            0x10 => {
                // TreeAnnounce
                self.handle_tree_announce(from, payload).await;
            }
            0x20 => {
                // FilterAnnounce
                self.handle_filter_announce(from, payload).await;
            }
            0x30 => {
                // LookupRequest
                self.handle_lookup_request(from, payload).await;
            }
            0x31 => {
                // LookupResponse
                self.handle_lookup_response(from, payload).await;
            }
            0x50 => {
                // Disconnect
                self.handle_disconnect(from, payload);
            }
            0x51 => {
                // Heartbeat — no-op, last_recv_time already updated by record_recv()
                trace!(peer = %self.peer_display_name(from), "Received heartbeat");
            }
            _ => {
                debug!(msg_type = msg_type, "Unknown link message type");
            }
        }
    }

    /// Handle a Disconnect notification from a peer.
    ///
    /// The peer is signaling an orderly departure. We immediately remove
    /// them from all state rather than waiting for timeout detection.
    fn handle_disconnect(&mut self, from: &NodeAddr, payload: &[u8]) {
        let disconnect = match crate::protocol::Disconnect::decode(payload) {
            Ok(msg) => msg,
            Err(e) => {
                debug!(from = %self.peer_display_name(from), error = %e, "Malformed disconnect message");
                return;
            }
        };

        info!(
            peer = %self.peer_display_name(from),
            reason = %disconnect.reason,
            "Peer sent disconnect notification"
        );

        self.remove_active_peer(from);
    }

    /// Remove an active peer and clean up all associated state.
    ///
    /// Frees session index, removes link and address mappings. Used for
    /// both graceful disconnect and timeout-based eviction.
    ///
    /// Also handles tree state cleanup: if the removed peer was our parent,
    /// selects an alternative or becomes root, and marks remaining peers
    /// for pending tree announce (delivered on next tick).
    pub(in crate::node) fn remove_active_peer(&mut self, node_addr: &NodeAddr) {
        let peer = match self.peers.remove(node_addr) {
            Some(p) => p,
            None => {
                debug!(peer = %self.peer_display_name(node_addr), "Peer already removed");
                return;
            }
        };

        // MMP teardown log (before we drop the peer)
        if let Some(mmp) = peer.mmp() {
            let name = self.peer_aliases.get(node_addr)
                .cloned()
                .unwrap_or_else(|| peer.identity().short_npub());
            Self::log_mmp_teardown(&name, mmp);
        }

        let link_id = peer.link_id();

        // Free session index
        if let (Some(tid), Some(idx)) = (peer.transport_id(), peer.our_index()) {
            self.peers_by_index.remove(&(tid, idx.as_u32()));
            let _ = self.index_allocator.free(idx);
        }

        // Remove link and address mapping
        self.remove_link(&link_id);

        // Tree state cleanup
        let tree_changed = self.handle_peer_removal_tree_cleanup(node_addr);
        if tree_changed {
            // Mark all remaining peers for pending tree announce.
            // These will be sent on the next tick via check_tree_state().
            for peer in self.peers.values_mut() {
                peer.mark_tree_announce_pending();
            }
        }

        // Bloom filter cleanup: clear state for removed peer, mark all remaining peers
        self.bloom_state.remove_peer_state(node_addr);
        let remaining_peers: Vec<NodeAddr> = self.peers.keys().copied().collect();
        self.bloom_state.mark_all_updates_needed(remaining_peers);

        info!(
            peer = %self.peer_display_name(node_addr),
            link_id = %link_id,
            tree_changed = tree_changed,
            "Peer removed and state cleaned up"
        );
    }
}
