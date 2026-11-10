//! Link message dispatch, and the Disconnect a peer sends.

use crate::NodeAddr;
use crate::node::Node;
use crate::node::settle::exec::Removed;
use crate::proto::settle::output::Why;
use crate::transport::{TransportAddr, TransportId};
use std::time::Instant;
use tracing::{debug, info, trace};

impl Node {
    /// Dispatch a decrypted link message to the appropriate handler.
    ///
    /// Link messages are protocol messages exchanged between authenticated peers.
    /// `arrival` is the transport the frame came in on and its source address,
    /// which the path messages (0x52 to 0x54) are stepped with into the link's
    /// path machine, and `len` the frame's length on the wire, which no
    /// handler reads yet.
    pub(in crate::node) async fn dispatch_link_message(
        &mut self,
        from: &NodeAddr,
        plaintext: &[u8],
        ce_flag: bool,
        arrival: (TransportId, &TransportAddr),
        _len: usize,
    ) {
        if plaintext.is_empty() {
            return;
        }

        let msg_type = plaintext[0];
        let payload = &plaintext[1..];

        match msg_type {
            0x00 => {
                // SessionDatagram
                self.handle_session_datagram(from, payload, ce_flag).await;
            }
            0x01 => {
                // SenderReport
                self.handle_sender_report(from, payload);
            }
            0x02 => {
                // ReceiverReport
                self.handle_receiver_report(from, payload).await;
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
                // Disconnect. A malformed one keeps the peer, and with it
                // the peer's claim to its link.
                if let Some(removed) = self.handle_disconnect(from, payload) {
                    self.removed(from, removed).await;
                }
            }
            0x51 => {
                // Heartbeat — no-op, last_recv_time already updated by record_recv()
                trace!(peer = %self.peer_display_name(from), "Received heartbeat");
            }
            0x52..=0x54 => {
                // PathProbe, PathAck, PathClose: the link's path machine.
                self.path_message(from, plaintext, arrival).await;
            }
            _ => {
                if tracing::enabled!(tracing::Level::DEBUG)
                    && let Some(suppressed) = self.msgtype_budget.admit(Instant::now())
                {
                    debug!(
                        peer = %self.peer_display_name(from),
                        msg_type = msg_type,
                        suppressed,
                        "Unknown link message type"
                    );
                }
            }
        }
    }

    /// Handle a Disconnect notification from a peer.
    ///
    /// The peer is signaling an orderly departure. We immediately remove
    /// them from all state rather than waiting for timeout detection, and
    /// schedule a reconnect if the peer is configured as auto-connect.
    /// Without this, a graceful upstream shutdown orphans auto-connect
    /// entries — other removal paths (link-dead, decrypt failure, peer
    /// restart) all schedule reconnect.
    ///
    /// Returns the removal, for its caller to run what follows it, which
    /// here is the transport's mark cleared at the peer's pair; the
    /// reconnect is noted here, so that a caller that cannot await still
    /// schedules it. `None` when the message is malformed or no peer is held.
    pub(in crate::node) fn handle_disconnect(
        &mut self,
        from: &NodeAddr,
        payload: &[u8],
    ) -> Option<Removed> {
        let disconnect = match crate::proto::fmp::Disconnect::decode(payload) {
            Ok(msg) => msg,
            Err(e) => {
                debug!(from = %self.peer_display_name(from), error = %e, "Malformed disconnect message");
                return None;
            }
        };

        info!(
            peer = %self.peer_display_name(from),
            reason = %disconnect.reason,
            "Peer sent disconnect notification"
        );

        let addr = *from;
        let removed = self.remove(from, Why::Disconnect);
        self.note_link_dead(addr, Self::peering_now());
        removed.map(|r| Removed { noted: true, ..r })
    }
}
