//! Encrypted frame handling (hot path).

use crate::node::Node;
use crate::transport::ReceivedPacket;
use crate::node::wire::EncryptedHeader;
use tracing::{debug, warn};

impl Node {
    /// Handle an encrypted frame (discriminator 0x00).
    ///
    /// This is the hot path for established sessions. We use O(1)
    /// index-based lookup to find the session, then decrypt.
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
                // Unknown index - could be stale session or attack
                debug!(
                    receiver_idx = %header.receiver_idx,
                    transport_id = %packet.transport_id,
                    "Unknown session index, dropping"
                );
                return;
            }
        };

        let peer = match self.peers.get_mut(&node_addr) {
            Some(p) => p,
            None => {
                // Peer removed but index not cleaned up - fix it
                self.peers_by_index.remove(&key);
                return;
            }
        };

        // Get the session (peer must have one for index-based lookup)
        let session = match peer.noise_session_mut() {
            Some(s) => s,
            None => {
                warn!(
                    node_addr = %node_addr,
                    "Peer in index map has no session"
                );
                return;
            }
        };

        // Decrypt with replay check (this is the expensive part)
        let ciphertext = &packet.data[header.ciphertext_offset..];
        let plaintext = match session.decrypt_with_replay_check(ciphertext, header.counter) {
            Ok(p) => p,
            Err(e) => {
                debug!(
                    node_addr = %node_addr,
                    counter = header.counter,
                    error = %e,
                    "Decryption failed"
                );
                return;
            }
        };

        // === PACKET IS AUTHENTIC ===

        // Update address for roaming support
        peer.set_current_addr(packet.transport_id, packet.remote_addr.clone());

        // Update statistics
        peer.link_stats_mut().record_recv(packet.data.len(), packet.timestamp_ms);
        peer.touch(packet.timestamp_ms);

        // Dispatch to link message handler
        self.dispatch_link_message(&node_addr, &plaintext).await;
    }
}
