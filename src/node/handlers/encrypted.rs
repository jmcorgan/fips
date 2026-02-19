//! Encrypted frame handling (hot path).

use crate::node::Node;
use crate::node::wire::{EncryptedHeader, strip_inner_header, FLAG_CE, FLAG_SP};
use crate::transport::ReceivedPacket;
use std::time::Instant;
use tracing::{debug, warn};

impl Node {
    /// Handle an encrypted frame (phase 0x0).
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
                    peer = %self.peer_display_name(&node_addr),
                    "Peer in index map has no session"
                );
                return;
            }
        };

        // Decrypt with replay check and AAD (this is the expensive part)
        let ciphertext = &packet.data[header.ciphertext_offset()..];
        let plaintext = match session.decrypt_with_replay_check_and_aad(
            ciphertext,
            header.counter,
            &header.header_bytes,
        ) {
            Ok(p) => p,
            Err(e) => {
                debug!(
                    peer = %self.peer_display_name(&node_addr),
                    counter = header.counter,
                    error = %e,
                    "Decryption failed"
                );
                return;
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

        // MMP per-frame processing: feed counter, timestamp, flags to receiver state
        let now = Instant::now();
        let ce_flag = header.flags & FLAG_CE != 0;
        let sp_flag = header.flags & FLAG_SP != 0;
        if let Some(mmp) = peer.mmp_mut() {
            mmp.receiver.record_recv(
                header.counter,
                timestamp,
                packet.data.len(),
                ce_flag,
                now,
            );
            // Spin bit: advance state machine for correct TX reflection.
            // RTT samples from spin bit are not used for SRTT because
            // inter-frame timing in the mesh is irregular, inflating
            // spin-bit RTT by variable processing delays on both sides.
            // Timestamp-echo in ReceiverReport provides accurate RTT.
            let _spin_rtt = mmp.spin_bit.rx_observe(sp_flag, header.counter, now);
        }

        // Update address for roaming support
        peer.set_current_addr(packet.transport_id, packet.remote_addr.clone());

        // Update statistics
        peer.link_stats_mut().record_recv(packet.data.len(), packet.timestamp_ms);
        peer.touch(packet.timestamp_ms);

        // Dispatch to link message handler (msg_type + payload, inner header stripped)
        self.dispatch_link_message(&node_addr, link_message).await;
    }
}
