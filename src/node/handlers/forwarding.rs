//! SessionDatagram forwarding handler.
//!
//! Handles incoming SessionDatagram (0x00) link messages: decodes the
//! envelope, enforces hop limits, performs coordinate cache warming from
//! plaintext session-layer headers, routes to the next hop or delivers
//! locally, and generates error signals on routing failure.

use crate::node::Node;
use crate::protocol::{
    CoordsRequired, DataPacket, PathBroken, SessionAck, SessionDatagram, SessionMessageType,
    SessionSetup,
};
use crate::NodeAddr;
use tracing::debug;

impl Node {
    /// Handle an incoming SessionDatagram from a peer.
    ///
    /// Called by `dispatch_link_message` for msg_type 0x00. The payload
    /// has already had its msg_type byte stripped by dispatch.
    pub(in crate::node) async fn handle_session_datagram(&mut self, _from: &NodeAddr, payload: &[u8]) {
        let mut datagram = match SessionDatagram::decode(payload) {
            Ok(dg) => dg,
            Err(e) => {
                debug!(error = %e, "Malformed SessionDatagram");
                return;
            }
        };

        // TTL enforcement: decrement and drop if exhausted
        if !datagram.decrement_ttl() {
            debug!(
                src = %datagram.src_addr,
                dest = %datagram.dest_addr,
                "SessionDatagram TTL exhausted, dropping"
            );
            return;
        }

        // Coordinate cache warming from plaintext session-layer headers
        self.try_warm_coord_cache(&datagram);

        // Local delivery: dispatch to session layer handlers
        if datagram.dest_addr == *self.node_addr() {
            self.handle_session_payload(&datagram.src_addr, &datagram.payload)
                .await;
            return;
        }

        // Find next hop toward destination
        let next_hop_addr = match self.find_next_hop(&datagram.dest_addr) {
            Some(peer) => *peer.node_addr(),
            None => {
                self.send_routing_error(&datagram).await;
                return;
            }
        };

        // Apply path_mtu min() from the outgoing link's transport MTU
        if let Some(peer) = self.peers.get(&next_hop_addr)
            && let Some(tid) = peer.transport_id()
            && let Some(transport) = self.transports.get(&tid)
        {
            datagram.path_mtu = datagram.path_mtu.min(transport.mtu());
        }

        // Forward: re-encode (includes 0x00 type byte) and send
        let encoded = datagram.encode();
        if let Err(e) = self
            .send_encrypted_link_message(&next_hop_addr, &encoded)
            .await
        {
            debug!(
                next_hop = %next_hop_addr,
                dest = %datagram.dest_addr,
                error = %e,
                "Failed to forward SessionDatagram"
            );
        }
    }

    /// Attempt to warm the coordinate cache from session-layer payload headers.
    ///
    /// Transit routers can read the session message type byte and, for
    /// SessionSetup and SessionAck, extract plaintext coordinate fields.
    /// DataPacket with COORDS_PRESENT has plaintext coords before the
    /// encrypted payload. Other types are ignored.
    ///
    /// Decode failures are logged and silently ignored — they don't block
    /// forwarding.
    fn try_warm_coord_cache(&mut self, datagram: &SessionDatagram) {
        if datagram.payload.is_empty() {
            return;
        }

        let msg_type = datagram.payload[0];
        let inner = &datagram.payload[1..];

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        match SessionMessageType::from_byte(msg_type) {
            Some(SessionMessageType::SessionSetup) => {
                match SessionSetup::decode(inner) {
                    Ok(setup) => {
                        self.coord_cache_mut().insert(
                            datagram.src_addr,
                            setup.src_coords,
                            now_ms,
                        );
                        self.coord_cache_mut().insert(
                            datagram.dest_addr,
                            setup.dest_coords,
                            now_ms,
                        );
                        debug!(
                            src = %datagram.src_addr,
                            dest = %datagram.dest_addr,
                            "Cached coords from SessionSetup"
                        );
                    }
                    Err(e) => {
                        debug!(error = %e, "Failed to decode SessionSetup for cache warming");
                    }
                }
            }
            Some(SessionMessageType::SessionAck) => {
                match SessionAck::decode(inner) {
                    Ok(ack) => {
                        self.coord_cache_mut().insert(
                            datagram.src_addr,
                            ack.src_coords,
                            now_ms,
                        );
                        debug!(
                            src = %datagram.src_addr,
                            "Cached coords from SessionAck"
                        );
                    }
                    Err(e) => {
                        debug!(error = %e, "Failed to decode SessionAck for cache warming");
                    }
                }
            }
            Some(SessionMessageType::DataPacket) => {
                match DataPacket::decode(inner) {
                    Ok(data) => {
                        if data.flags.coords_present {
                            if let Some(src_coords) = data.src_coords {
                                self.coord_cache_mut().insert(
                                    datagram.src_addr,
                                    src_coords,
                                    now_ms,
                                );
                            }
                            if let Some(dest_coords) = data.dest_coords {
                                self.coord_cache_mut().insert(
                                    datagram.dest_addr,
                                    dest_coords,
                                    now_ms,
                                );
                            }
                            debug!(
                                src = %datagram.src_addr,
                                dest = %datagram.dest_addr,
                                "Cached coords from DataPacket"
                            );
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, "Failed to decode DataPacket for cache warming");
                    }
                }
            }
            _ => {
                // CoordsRequired, PathBroken, unknown: no coords to cache
            }
        }
    }

    /// Generate and send a routing error signal back to the datagram's source.
    ///
    /// If we have cached coords for the destination, send PathBroken (we know
    /// where it is but can't reach it). Otherwise send CoordsRequired (we
    /// don't know where it is).
    ///
    /// If we can't route the error back to the source either, drop silently.
    /// No cascading errors.
    async fn send_routing_error(&mut self, original: &SessionDatagram) {
        // Rate limit: one error signal per destination per 100ms
        if !self.routing_error_rate_limiter.should_send(&original.dest_addr) {
            return;
        }

        let my_addr = *self.node_addr();

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let error_payload =
            if let Some(coords) = self.coord_cache().get(&original.dest_addr, now_ms) {
                let coords = coords.clone();
                PathBroken::new(original.dest_addr, my_addr)
                    .with_last_coords(coords)
                    .encode()
            } else {
                CoordsRequired::new(original.dest_addr, my_addr).encode()
            };

        let error_dg = SessionDatagram::new(my_addr, original.src_addr, error_payload)
            .with_ttl(self.config.node.session.default_ttl);

        let next_hop_addr = match self.find_next_hop(&original.src_addr) {
            Some(peer) => *peer.node_addr(),
            None => {
                debug!(
                    src = %original.src_addr,
                    dest = %original.dest_addr,
                    "Cannot route error signal back to source, dropping"
                );
                return;
            }
        };

        let encoded = error_dg.encode();
        if let Err(e) = self
            .send_encrypted_link_message(&next_hop_addr, &encoded)
            .await
        {
            debug!(
                next_hop = %next_hop_addr,
                error = %e,
                "Failed to send routing error signal"
            );
        } else {
            debug!(
                original_dest = %original.dest_addr,
                error_dest = %original.src_addr,
                "Sent routing error signal"
            );
        }
    }
}
