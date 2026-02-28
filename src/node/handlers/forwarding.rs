//! SessionDatagram forwarding handler.
//!
//! Handles incoming SessionDatagram (0x00) link messages: decodes the
//! envelope, enforces hop limits, performs coordinate cache warming from
//! plaintext session-layer headers, routes to the next hop or delivers
//! locally, and generates error signals on routing failure.

use crate::node::{Node, NodeError};
use crate::node::session_wire::{
    parse_encrypted_coords, FspCommonPrefix, FSP_COMMON_PREFIX_SIZE, FSP_HEADER_SIZE,
    FSP_PHASE_ESTABLISHED, FSP_PHASE_MSG1, FSP_PHASE_MSG2,
};
use crate::protocol::{
    CoordsRequired, MtuExceeded, PathBroken, SessionAck, SessionDatagram, SessionSetup,
};
use crate::NodeAddr;
use tracing::debug;

impl Node {
    /// Handle an incoming SessionDatagram from a peer.
    ///
    /// Called by `dispatch_link_message` for msg_type 0x00. The payload
    /// has already had its msg_type byte stripped by dispatch.
    pub(in crate::node) async fn handle_session_datagram(&mut self, _from: &NodeAddr, payload: &[u8]) {
        self.stats_mut().forwarding.record_received(payload.len());

        let mut datagram = match SessionDatagram::decode(payload) {
            Ok(dg) => dg,
            Err(e) => {
                self.stats_mut().forwarding.record_decode_error(payload.len());
                debug!(error = %e, "Malformed SessionDatagram");
                return;
            }
        };

        // TTL enforcement: decrement and drop if exhausted
        if !datagram.decrement_ttl() {
            self.stats_mut().forwarding.record_ttl_exhausted(payload.len());
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
            self.stats_mut().forwarding.record_delivered(payload.len());
            self.handle_session_payload(&datagram.src_addr, &datagram.payload, datagram.path_mtu)
                .await;
            return;
        }

        // Find next hop toward destination
        let next_hop_addr = match self.find_next_hop(&datagram.dest_addr) {
            Some(peer) => *peer.node_addr(),
            None => {
                self.stats_mut().forwarding.record_drop_no_route(payload.len());
                self.send_routing_error(&datagram).await;
                return;
            }
        };

        // Apply path_mtu min() from the outgoing link's transport MTU
        if let Some(peer) = self.peers.get(&next_hop_addr)
            && let Some(tid) = peer.transport_id()
            && let Some(transport) = self.transports.get(&tid)
        {
            if let Some(addr) = peer.current_addr() {
                datagram.path_mtu = datagram.path_mtu.min(transport.link_mtu(addr));
            } else {
                datagram.path_mtu = datagram.path_mtu.min(transport.mtu());
            }
        }

        // Forward: re-encode (includes 0x00 type byte) and send
        let encoded = datagram.encode();
        if let Err(e) = self
            .send_encrypted_link_message(&next_hop_addr, &encoded)
            .await
        {
            match e {
                NodeError::MtuExceeded { mtu, .. } => {
                    self.stats_mut().forwarding.record_drop_mtu_exceeded(payload.len());
                    self.send_mtu_exceeded_error(&datagram, mtu).await;
                }
                _ => {
                    self.stats_mut().forwarding.record_drop_send_error(payload.len());
                    debug!(
                        next_hop = %next_hop_addr,
                        dest = %datagram.dest_addr,
                        error = %e,
                        "Failed to forward SessionDatagram"
                    );
                }
            }
        } else {
            self.stats_mut().forwarding.record_forwarded(encoded.len());
        }
    }

    /// Attempt to warm the coordinate cache from session-layer payload headers.
    ///
    /// Transit routers parse the 4-byte FSP common prefix to identify message
    /// type, then extract plaintext coordinate fields from:
    /// - SessionSetup (phase 0x1): src_coords + dest_coords
    /// - SessionAck (phase 0x2): src_coords
    /// - Encrypted with CP flag (phase 0x0): cleartext coords between header and ciphertext
    ///
    /// Decode failures are logged and silently ignored — they don't block
    /// forwarding.
    fn try_warm_coord_cache(&mut self, datagram: &SessionDatagram) {
        let prefix = match FspCommonPrefix::parse(&datagram.payload) {
            Some(p) => p,
            None => return,
        };

        let inner = &datagram.payload[FSP_COMMON_PREFIX_SIZE..];

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        match prefix.phase {
            FSP_PHASE_MSG1 => {
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
            FSP_PHASE_MSG2 => {
                match SessionAck::decode(inner) {
                    Ok(ack) => {
                        self.coord_cache_mut().insert(
                            datagram.src_addr,
                            ack.src_coords,
                            now_ms,
                        );
                        self.coord_cache_mut().insert(
                            datagram.dest_addr,
                            ack.dest_coords,
                            now_ms,
                        );
                        debug!(
                            src = %datagram.src_addr,
                            dest = %datagram.dest_addr,
                            "Cached coords from SessionAck"
                        );
                    }
                    Err(e) => {
                        debug!(error = %e, "Failed to decode SessionAck for cache warming");
                    }
                }
            }
            FSP_PHASE_ESTABLISHED if prefix.has_coords() => {
                // CP flag set: coords in cleartext between header and ciphertext.
                // Parse coords from the cleartext section after the 12-byte header.
                // inner starts after the 4-byte prefix, so we need 8 more bytes
                // for the counter (header is 12 total = 4 prefix + 8 counter).
                let coord_data = &datagram.payload[FSP_HEADER_SIZE..];
                match parse_encrypted_coords(coord_data) {
                    Ok((src_coords, dest_coords, _bytes_consumed)) => {
                        if let Some(coords) = src_coords {
                            self.coord_cache_mut().insert(
                                datagram.src_addr,
                                coords,
                                now_ms,
                            );
                        }
                        if let Some(coords) = dest_coords {
                            self.coord_cache_mut().insert(
                                datagram.dest_addr,
                                coords,
                                now_ms,
                            );
                        }
                        debug!(
                            src = %datagram.src_addr,
                            dest = %datagram.dest_addr,
                            "Cached coords from encrypted message"
                        );
                    }
                    Err(e) => {
                        debug!(error = %e, "Failed to parse coords for cache warming");
                    }
                }
            }
            _ => {
                // Phase 0x0 without CP, error signals, unknown: no coords to cache
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

    /// Generate and send an MtuExceeded error signal back to the datagram's source.
    ///
    /// Called when `send_encrypted_link_message()` fails with
    /// `NodeError::MtuExceeded` during forwarding. The signal tells the
    /// source the bottleneck MTU so it can immediately reduce its path MTU.
    async fn send_mtu_exceeded_error(
        &mut self,
        original: &SessionDatagram,
        bottleneck_mtu: u16,
    ) {
        // Rate limit: reuse routing_error_rate_limiter keyed on dest_addr
        if !self.routing_error_rate_limiter.should_send(&original.dest_addr) {
            return;
        }

        let my_addr = *self.node_addr();

        let error_payload = MtuExceeded::new(
            original.dest_addr,
            my_addr,
            bottleneck_mtu,
        ).encode();

        let error_dg = SessionDatagram::new(my_addr, original.src_addr, error_payload)
            .with_ttl(self.config.node.session.default_ttl);

        let next_hop_addr = match self.find_next_hop(&original.src_addr) {
            Some(peer) => *peer.node_addr(),
            None => {
                debug!(
                    src = %original.src_addr,
                    dest = %original.dest_addr,
                    "Cannot route MtuExceeded signal back to source, dropping"
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
                "Failed to send MtuExceeded error signal"
            );
        } else {
            debug!(
                original_dest = %original.dest_addr,
                error_dest = %original.src_addr,
                bottleneck_mtu,
                "Sent MtuExceeded error signal"
            );
        }
    }
}
