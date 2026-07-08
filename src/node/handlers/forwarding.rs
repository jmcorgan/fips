//! SessionDatagram forwarding handler.
//!
//! Handles incoming SessionDatagram (0x00) link messages: decodes the
//! envelope, enforces hop limits, performs coordinate cache warming from
//! plaintext session-layer headers, routes to the next hop or delivers
//! locally, and generates error signals on routing failure.

use crate::NodeAddr;
use crate::node::reject::ForwardingReject;
use crate::node::{Node, NodeError, NodeRoutingView};
use crate::proto::fsp::wire::{
    FSP_COMMON_PREFIX_SIZE, FSP_HEADER_SIZE, FSP_PHASE_ESTABLISHED, FSP_PHASE_MSG1, FSP_PHASE_MSG2,
    FspCommonPrefix, parse_encrypted_coords,
};
use crate::proto::fsp::{SessionAck, SessionSetup};
use crate::proto::link::{SessionDatagram, SessionDatagramRef};
use crate::proto::routing::{DropReason, NextHop, RouteAction, RouteOutcome};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

impl Node {
    /// Handle an incoming SessionDatagram from a peer.
    ///
    /// Called by `dispatch_link_message` for msg_type 0x00. The payload
    /// has already had its msg_type byte stripped by dispatch.
    pub(in crate::node) async fn handle_session_datagram(
        &mut self,
        _from: &NodeAddr,
        payload: &[u8],
        incoming_ce: bool,
    ) {
        self.metrics().forwarding.record_received(payload.len());

        let datagram_ref = match SessionDatagramRef::decode(payload) {
            Ok(dg) => dg,
            Err(e) => {
                self.metrics()
                    .forwarding
                    .record_reject_bytes(ForwardingReject::DecodeError, payload.len());
                debug!(error = %e, "Malformed SessionDatagram");
                return;
            }
        };

        let my_addr = *self.node_addr();

        // Coordinate cache warming from plaintext session-layer headers. Gated
        // on a non-exhausted TTL so a datagram the core will drop as
        // TTL-exhausted does not warm the cache, matching the pre-refactor
        // ordering (warming ran only after the TTL early-return).
        if datagram_ref.ttl != 0 {
            self.try_warm_coord_cache_ref(&datagram_ref);
        }

        // Pre-resolve the next hop only for genuine transit packets (TTL > 0
        // and not locally destined) so `find_next_hop`'s coord-cache LRU-touch
        // side effect keeps the same scope it had inline. Warming above has
        // already run, so the resolution observes freshly cached coords.
        let next_hop = if datagram_ref.ttl != 0 && datagram_ref.dest_addr != my_addr {
            self.resolve_next_hop(&datagram_ref.dest_addr)
        } else {
            None
        };

        // Read local congestion once and reuse it for both the CE decision
        // (via the view) and the congestion metric/log below, keeping
        // `detect_congestion` the single source of truth.
        let congested = next_hop
            .as_ref()
            .map(|nh| self.detect_congestion(&nh.addr))
            .unwrap_or(false);

        // Borrow the routing tables disjointly from `&mut self.routing` for
        // the pure decision, then release both before driving the outcome.
        let outcome = {
            let view = NodeRoutingView {
                coord_cache: &self.coord_cache,
                peers: &self.peers,
                tree_state: &self.tree_state,
                congested,
            };
            self.routing
                .route(&datagram_ref, &my_addr, incoming_ce, next_hop, &view)
        };

        match outcome {
            RouteOutcome::Drop {
                reason: DropReason::TtlExhausted,
            } => {
                self.metrics()
                    .forwarding
                    .record_reject_bytes(ForwardingReject::TtlExhausted, payload.len());
                debug!(
                    src = %datagram_ref.src_addr,
                    dest = %datagram_ref.dest_addr,
                    "SessionDatagram TTL exhausted, dropping"
                );
            }
            RouteOutcome::DeliverLocal => {
                // Local delivery: dispatch to session layer handlers without
                // materializing an owned SessionDatagram payload Vec.
                self.metrics().forwarding.record_delivered(payload.len());
                self.handle_session_payload(
                    &datagram_ref.src_addr,
                    datagram_ref.payload,
                    datagram_ref.path_mtu,
                    incoming_ce,
                )
                .await;
            }
            RouteOutcome::NoRoute => {
                self.metrics()
                    .forwarding
                    .record_reject_bytes(ForwardingReject::NoRoute, payload.len());
                let original = datagram_ref.into_owned();
                debug!(
                    src = %self.peer_display_name(&original.src_addr),
                    dest = %self.peer_display_name(&original.dest_addr),
                    bytes = payload.len(),
                    "Dropping transit SessionDatagram: no route to destination"
                );
                self.send_routing_error(&original).await;
            }
            RouteOutcome::Forward {
                next_hop,
                bytes,
                outgoing_ce,
            } => {
                let dest = datagram_ref.dest_addr;

                // ECN CE relay: congestion was detected locally above; emit the
                // metric and rate-limited log at the transit chokepoint.
                if congested {
                    self.metrics().congestion.congestion_detected.inc();
                    let now = Instant::now();
                    let should_log = self
                        .last_congestion_log
                        .map(|t| now.duration_since(t) >= Duration::from_secs(5))
                        .unwrap_or(true);
                    if should_log {
                        self.last_congestion_log = Some(now);
                        debug!(next_hop = %next_hop, "Congestion detected, CE flag set on forwarded packet");
                    }
                }

                match self
                    .send_encrypted_link_message_with_ce(&next_hop, &bytes, outgoing_ce)
                    .await
                {
                    Err(NodeError::MtuExceeded { mtu, .. }) => {
                        self.metrics()
                            .forwarding
                            .record_reject_bytes(ForwardingReject::MtuExceeded, payload.len());
                        self.send_mtu_exceeded_error(dest, datagram_ref.src_addr, mtu)
                            .await;
                    }
                    Err(e) => {
                        self.metrics()
                            .forwarding
                            .record_reject_bytes(ForwardingReject::SendError, payload.len());
                        debug!(
                            next_hop = %next_hop,
                            dest = %dest,
                            error = %e,
                            "Failed to forward SessionDatagram"
                        );
                    }
                    Ok(()) => {
                        self.metrics().forwarding.record_forwarded(bytes.len());
                        // Classify this transit forward by route class (partition
                        // of forwarded_packets). Done here, at the data-plane
                        // chokepoint, so the error-signal routing callers of
                        // find_next_hop are excluded.
                        let class = self.classify_forward(&dest, &next_hop);
                        self.metrics().forwarding.record_route_class(class);
                        if outgoing_ce {
                            self.metrics().congestion.ce_forwarded.inc();
                        }
                    }
                }
            }
        }
    }

    /// Resolve the next hop toward `dest` into its address plus the outgoing
    /// link's transport MTU. Returns `None` when there is no route.
    ///
    /// The MTU defaults to `u16::MAX` (a no-op min-fold) when the peer's
    /// transport is not resolvable, matching the pre-refactor inline behavior
    /// where the MTU `if let` chain simply did not fire.
    fn resolve_next_hop(&mut self, dest: &NodeAddr) -> Option<NextHop> {
        let addr = *self.find_next_hop(dest)?.node_addr();
        let link_mtu = if let Some(peer) = self.peers.get(&addr)
            && let Some(tid) = peer.transport_id()
            && let Some(transport) = self.transports.get(&tid)
        {
            match peer.current_addr() {
                Some(link_addr) => transport.link_mtu(link_addr),
                None => transport.mtu(),
            }
        } else {
            u16::MAX
        };
        Some(NextHop { addr, link_mtu })
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
    fn try_warm_coord_cache_ref(&mut self, datagram: &SessionDatagramRef<'_>) {
        let prefix = match FspCommonPrefix::parse(datagram.payload) {
            Some(p) => p,
            None => return,
        };

        let inner = &datagram.payload[FSP_COMMON_PREFIX_SIZE..];

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        match prefix.phase {
            FSP_PHASE_MSG1 => match SessionSetup::decode(inner) {
                Ok(setup) => {
                    self.coord_cache_mut()
                        .insert(datagram.src_addr, setup.src_coords, now_ms);
                    self.coord_cache_mut()
                        .insert(datagram.dest_addr, setup.dest_coords, now_ms);
                    debug!(
                        src = %datagram.src_addr,
                        dest = %datagram.dest_addr,
                        "Cached coords from SessionSetup"
                    );
                }
                Err(e) => {
                    debug!(error = %e, "Failed to decode SessionSetup for cache warming");
                }
            },
            FSP_PHASE_MSG2 => match SessionAck::decode(inner) {
                Ok(ack) => {
                    self.coord_cache_mut()
                        .insert(datagram.src_addr, ack.src_coords, now_ms);
                    self.coord_cache_mut()
                        .insert(datagram.dest_addr, ack.dest_coords, now_ms);
                    debug!(
                        src = %datagram.src_addr,
                        dest = %datagram.dest_addr,
                        "Cached coords from SessionAck"
                    );
                }
                Err(e) => {
                    debug!(error = %e, "Failed to decode SessionAck for cache warming");
                }
            },
            FSP_PHASE_ESTABLISHED if prefix.has_coords() => {
                // CP flag set: coords in cleartext between header and ciphertext.
                // Parse coords from the cleartext section after the 12-byte header.
                // inner starts after the 4-byte prefix, so we need 8 more bytes
                // for the counter (header is 12 total = 4 prefix + 8 counter).
                let coord_data = &datagram.payload[FSP_HEADER_SIZE..];
                match parse_encrypted_coords(coord_data) {
                    Ok((src_coords, dest_coords, _bytes_consumed)) => {
                        if let Some(coords) = src_coords {
                            self.coord_cache_mut()
                                .insert(datagram.src_addr, coords, now_ms);
                        }
                        if let Some(coords) = dest_coords {
                            self.coord_cache_mut()
                                .insert(datagram.dest_addr, coords, now_ms);
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
        let my_addr = *self.node_addr();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let default_ttl = self.config().node.session.default_ttl;

        // Pure decision: rate-limit gate + PathBroken/CoordsRequired choice +
        // error-PDU encode. Borrow the routing tables disjointly from
        // `&mut self.routing`, then release them before the reverse-hop lookup.
        let action = {
            let view = NodeRoutingView {
                coord_cache: &self.coord_cache,
                peers: &self.peers,
                tree_state: &self.tree_state,
                congested: false,
            };
            self.routing.synth_routing_error(
                &original.dest_addr,
                &original.src_addr,
                &my_addr,
                &view,
                now_ms,
                default_ttl,
            )
        };
        let RouteAction::SendError { toward, bytes } = match action {
            Some(action) => action,
            // Rate limited: drop silently. No cascading errors.
            None => return,
        };

        // Resolve the reverse link hop only now, after the gate passed, so
        // `find_next_hop`'s coord-cache touch keeps its pre-refactor scope.
        let next_hop_addr = match self.find_next_hop(&toward) {
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

        if let Err(e) = self
            .send_encrypted_link_message(&next_hop_addr, &bytes)
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
    ///
    /// `dest` is the failed datagram's destination (rate-limit key); `toward`
    /// is its source, where the signal is routed back.
    async fn send_mtu_exceeded_error(
        &mut self,
        dest: NodeAddr,
        toward: NodeAddr,
        bottleneck_mtu: u16,
    ) {
        let my_addr = *self.node_addr();
        let now_ms = Self::now_ms();
        let default_ttl = self.config().node.session.default_ttl;

        // Pure decision: rate-limit gate + MtuExceeded PDU + encode.
        let action = self.routing.synth_mtu_exceeded(
            &dest,
            &toward,
            &my_addr,
            bottleneck_mtu,
            now_ms,
            default_ttl,
        );
        let RouteAction::SendError { toward, bytes } = match action {
            Some(action) => action,
            // Rate limited: drop silently. No cascading errors.
            None => return,
        };

        // Resolve the reverse link hop only now, after the gate passed, so
        // `find_next_hop`'s coord-cache touch keeps its pre-refactor scope.
        let next_hop_addr = match self.find_next_hop(&toward) {
            Some(peer) => *peer.node_addr(),
            None => {
                debug!(
                    src = %toward,
                    dest = %dest,
                    "Cannot route MtuExceeded signal back to source, dropping"
                );
                return;
            }
        };

        if let Err(e) = self
            .send_encrypted_link_message(&next_hop_addr, &bytes)
            .await
        {
            debug!(
                next_hop = %next_hop_addr,
                error = %e,
                "Failed to send MtuExceeded error signal"
            );
        } else {
            debug!(
                original_dest = %dest,
                error_dest = %toward,
                bottleneck_mtu,
                "Sent MtuExceeded error signal"
            );
        }
    }

    /// Detect congestion for CE marking on forwarded datagrams.
    ///
    /// Checks two signal sources:
    /// 1. Outgoing link MMP metrics (loss rate, ETX) against configured thresholds
    /// 2. Local transport congestion (kernel drops on any transport)
    ///
    /// Returns `true` if any signal indicates congestion.
    pub(in crate::node) fn detect_congestion(&self, next_hop: &NodeAddr) -> bool {
        if !self.config().node.ecn.enabled {
            return false;
        }
        // Outgoing link MMP metrics
        if let Some(peer) = self.peers.get(next_hop)
            && let Some(mmp) = peer.mmp()
        {
            let metrics = &mmp.metrics;
            if metrics.loss_rate() >= self.config().node.ecn.loss_threshold
                || metrics.etx >= self.config().node.ecn.etx_threshold
            {
                return true;
            }
        }
        // Local transport congestion (kernel drops)
        self.transport_drops.values().any(|s| s.dropping)
    }

    /// Sample transport congestion indicators.
    ///
    /// Called from the tick handler (1s interval). For each transport,
    /// queries the cumulative kernel drop counter and sets the `dropping`
    /// flag if new drops occurred since the previous sample.
    pub(in crate::node) fn sample_transport_congestion(&mut self) {
        let mut new_drop_events = Vec::new();
        for (&tid, transport) in &self.transports {
            let congestion = transport.congestion();
            let state = self.transport_drops.entry(tid).or_default();
            if let Some(current) = congestion.recv_drops {
                let new_drops = current > state.prev_drops;
                if new_drops && !state.dropping {
                    new_drop_events.push(tid);
                }
                state.dropping = new_drops;
                state.prev_drops = current;
            }
        }
        for tid in new_drop_events {
            self.metrics().congestion.kernel_drop_events.inc();
            warn!(
                transport_id = tid.as_u32(),
                "Kernel recv drops first observed on transport"
            );
        }
    }
}
