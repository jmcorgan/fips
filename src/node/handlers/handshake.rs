//! Handshake handlers and connection promotion.
//!
//! Implements the Noise XX 3-message handshake for FMP link establishment:
//! - msg1 (initiator → responder): ephemeral only, no identity
//! - msg2 (responder → initiator): responder identity + epoch + negotiation
//! - msg3 (initiator → responder): initiator identity + epoch + negotiation

use crate::NodeAddr;
use crate::PeerIdentity;
use crate::node::acl::PeerAclContext;
use crate::node::dataplane::PeerActionCtx;
use crate::node::reject::{HandshakeReject, RejectReason};
use crate::node::{Node, NodeError};
use crate::peer::machine::{CrossConnOutcome, PeerAction, PeerEvent, PeerMachine, TimerKind};
use crate::peer::{ActivePeer, PeerConnection};
use crate::proto::fmp::wire::{Msg1Header, Msg2Header, Msg3Header, build_msg2, build_msg3};
use crate::proto::fmp::{
    Disconnect, DisconnectReason, EstablishSnapshot, InboundDecision, InboundReject,
    NegotiationPayload, OutboundSnapshot, PromotionResult, WireOutcome, cross_connection_winner,
    decide_fmp_negotiation,
};
use crate::transport::{Link, LinkDirection, LinkId, ReceivedPacket};
use crate::utils::index::SessionIndex;
use std::time::Duration;
use tracing::{debug, info, warn};

impl Node {
    /// Snapshot the registry state the outbound establish decision reads about
    /// `peer_addr`: whether the identity is already an active peer, and the
    /// pre-evaluated cross-connection tie-break for THIS outbound connection
    /// (`is_outbound = true`), resolved into a plain `bool` here so the core
    /// stays free of the peer helper.
    fn outbound_snapshot(&self, peer_addr: &NodeAddr) -> OutboundSnapshot {
        OutboundSnapshot {
            has_existing_peer: self.peers.contains_key(peer_addr),
            our_outbound_wins: cross_connection_winner(
                self.identity().node_addr(),
                peer_addr,
                true,
            ),
        }
    }

    /// Feed the peer's control machine the completed-rekey observation after the
    /// inline `complete_rekey_msg2`. The obs records the peer's new session index
    /// and advances the rekey phase; it emits no action, so a bare `step` keeps
    /// the machine coherent without an executor pass.
    fn observe_rekey_msg2(&mut self, node_addr: &NodeAddr, their_index: SessionIndex) {
        let link = match self.peers.get(node_addr) {
            Some(peer) => peer.link_id(),
            None => return,
        };
        if let Some(machine) = self.peer_machines.get_mut(&link) {
            let acts = machine.step(
                PeerEvent::RekeyMsg2 { their_index },
                Self::now_ms(),
                &mut self.index_allocator,
            );
            debug_assert!(acts.is_empty(), "completed-rekey is a pure observation");
        } else {
            debug_assert!(
                false,
                "peer machine present for every established rekey peer"
            );
        }
    }

    /// Feed the promoted peer's control machine the cross-connection resolution
    /// after the inline session surgery. The obs reconciles the machine's shadow
    /// session indices (updated on a swap, unchanged on a keep); it emits no
    /// action, so a bare `step` keeps the machine coherent without an executor
    /// pass.
    fn observe_cross_conn_resolved(&mut self, node_addr: &NodeAddr, outcome: CrossConnOutcome) {
        let link = match self.peers.get(node_addr) {
            Some(peer) => peer.link_id(),
            None => return,
        };
        if let Some(machine) = self.peer_machines.get_mut(&link) {
            let acts = machine.step(
                PeerEvent::CrossConnResolved { outcome },
                Self::now_ms(),
                &mut self.index_allocator,
            );
            debug_assert!(
                acts.is_empty(),
                "cross-connection resolution is a pure observation"
            );
        } else {
            debug_assert!(
                false,
                "peer machine present for the promoted cross-connection peer"
            );
        }
    }

    /// Returns true if an inbound msg1 should be admitted past the
    /// `accept_connections` gate.
    ///
    /// Rekey/restart msg1 from an established peer is always admitted (the
    /// gate is meant to filter fresh handshakes from strangers, not
    /// maintenance traffic on established sessions). Two predicates cover
    /// "established peer at this transport+addr":
    ///
    /// 1. `addr_to_link` has an entry for `(transport_id, remote_addr)`.
    ///    This is the fast path and matches when the peer registered with
    ///    the same `TransportAddr` form we observe on inbound packets
    ///    (e.g., both numeric when peer config uses a numeric IP).
    ///
    /// 2. An active peer's `current_addr()` matches `(transport_id,
    ///    remote_addr)`. `current_addr` is updated from inbound encrypted-
    ///    frame source addrs (always numeric `SocketAddr`-form), so this
    ///    catches established peers whose `addr_to_link` key is hostname-
    ///    form (because `initiate_connection` populated it from a
    ///    hostname-bearing peer config) while inbound rekey msg1 arrives
    ///    in numeric form. Without this second predicate, the carve-out
    ///    misses any deployment that combines a hostname-based peer config
    ///    with `udp.accept_connections: false` or `udp.outbound_only: true`
    ///    (the production trigger for the 2026-04-30 bug).
    ///
    /// Otherwise the transport's `accept_connections` config decides;
    /// absence of a registered transport admits (no gate to apply).
    pub(in crate::node) fn should_admit_msg1(
        &self,
        transport_id: crate::transport::TransportId,
        remote_addr: &crate::transport::TransportAddr,
    ) -> bool {
        if self
            .addr_to_link
            .contains_key(&(transport_id, remote_addr.clone()))
        {
            return true;
        }
        if self.peers.values().any(|p| {
            p.transport_id() == Some(transport_id) && p.current_addr() == Some(remote_addr)
        }) {
            return true;
        }
        self.transports
            .get(&transport_id)
            .is_none_or(|t| t.accept_connections())
    }

    /// Handle handshake message 1 (phase 0x1).
    ///
    /// With Noise XX, msg1 contains only the initiator's ephemeral key.
    /// No identity is learned. The responder processes msg1, sends msg2
    /// (revealing its own identity), and stores the connection in
    /// pending_inbound to await msg3.
    pub(in crate::node) async fn handle_msg1(&mut self, packet: ReceivedPacket) {
        // === RATE LIMITING (before any processing) ===
        if !self.msg1_rate_limiter.start_handshake() {
            debug!(
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                "Msg1 rate limited"
            );
            return;
        }

        // accept_connections gate. Rekey/restart msg1 on an existing link
        // is always admitted; the gate only filters truly-fresh connections
        // from strangers. Without this carve-out, the dual-init tie-breaker
        // deadlocks when the larger-NodeAddr side has accept_connections=false.
        if !self.should_admit_msg1(packet.transport_id, &packet.remote_addr) {
            self.msg1_rate_limiter.complete_handshake();
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }

        // Parse header
        let header = match Msg1Header::parse(&packet.data) {
            Some(h) => h,
            None => {
                self.msg1_rate_limiter.complete_handshake();
                debug!("Invalid msg1 header");
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
            }
        };

        // Check for existing connection from this address.
        //
        // With XX, we can't do identity-based checks in msg1 (no identity yet).
        // We can only detect duplicates by address: if we already have an inbound
        // link from this address with a pending connection, resend msg2.
        // If we have an active peer on this address, it could be a restart or
        // rekey — but we can't tell until msg3 reveals identity. For now, allow
        // the new handshake to proceed. Identity-based checks happen in handle_msg3.
        let addr_key = (packet.transport_id, packet.remote_addr.clone());
        if let Some(&existing_link_id) = self.addr_to_link.get(&addr_key)
            && let Some(link) = self.links.get(&existing_link_id)
        {
            if link.direction() == LinkDirection::Inbound {
                // Check if this link belongs to an already-promoted active peer
                let is_active_peer = self.peers.values().any(|p| p.link_id() == existing_link_id);

                if !is_active_peer {
                    // Genuinely pending handshake — resend msg2
                    let msg2_bytes = self.find_stored_msg2(existing_link_id);
                    if let Some(msg2) = msg2_bytes {
                        if let Some(transport) = self.transports.get(&packet.transport_id) {
                            match transport.send(&packet.remote_addr, &msg2).await {
                                Ok(_) => debug!(
                                    remote_addr = %packet.remote_addr,
                                    "Resent msg2 for duplicate msg1"
                                ),
                                Err(e) => debug!(
                                    remote_addr = %packet.remote_addr,
                                    error = %e,
                                    "Failed to resend msg2"
                                ),
                            }
                        }
                    } else {
                        debug!(
                            remote_addr = %packet.remote_addr,
                            "Duplicate msg1 but no stored msg2 to resend"
                        );
                        self.stats_mut().record_reject(RejectReason::Handshake(
                            HandshakeReject::UnknownConnection,
                        ));
                    }
                    self.msg1_rate_limiter.complete_handshake();
                    return;
                }
                // Active peer on this address — allow the new handshake.
                // Identity checks (restart, rekey) deferred to handle_msg3.
                debug!(
                    transport_id = %packet.transport_id,
                    remote_addr = %packet.remote_addr,
                    existing_link_id = %existing_link_id,
                    "XX msg1 from address with active peer — proceeding (identity check deferred to msg3)"
                );
            } else {
                // Outbound link to this address — cross-connection.
                // Allow the inbound handshake to proceed.
                debug!(
                    transport_id = %packet.transport_id,
                    remote_addr = %packet.remote_addr,
                    existing_link_id = %existing_link_id,
                    "Cross-connection detected: have outbound, received inbound msg1"
                );
            }
        }

        // === CRYPTO COST PAID HERE ===
        let link_id = self.allocate_link_id();
        let mut conn = PeerConnection::inbound_with_transport(
            link_id,
            packet.transport_id,
            packet.remote_addr.clone(),
            packet.timestamp_ms,
        );

        // Create FMP negotiation payload for msg2 (includes profile, MMP bits, bloom TLV)
        let neg_payload = NegotiationPayload::fmp(1, 1, self.node_profile()).encode();

        let our_keypair = self.identity().keypair();
        let noise_msg1 = &packet.data[header.noise_msg1_offset..];
        let msg2_response = match conn.receive_handshake_init(
            our_keypair,
            self.startup_epoch(),
            noise_msg1,
            Some(&neg_payload),
            packet.timestamp_ms,
        ) {
            Ok(m) => m,
            Err(e) => {
                self.msg1_rate_limiter.complete_handshake();
                debug!(
                    error = %e,
                    "Failed to process msg1"
                );
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
            }
        };

        // XX: identity is NOT learned from msg1 (only ephemeral exchange).
        // Identity will be learned from msg3 in handle_msg3. The IK-protocol
        // version of this branch (on the maint+master lineage) carries the
        // post-identity restart-detection, rekey dual-init handling, ACL
        // check, and max_peers cap check here — none of which have an
        // equivalent placement at XX msg1 because peer identity is still
        // unknown at this point. The XX-equivalent admission gate is placed
        // in handle_msg3 after the peer's static key + signature have been
        // verified, before promote_connection is called.

        // Allocate our session index
        let our_index = match self.index_allocator.allocate() {
            Ok(idx) => idx,
            Err(e) => {
                self.msg1_rate_limiter.complete_handshake();
                warn!(error = %e, "Failed to allocate session index for inbound");
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
            }
        };

        conn.set_our_index(our_index);
        conn.set_their_index(header.sender_idx);

        // Create link
        let link = Link::connectionless(
            link_id,
            packet.transport_id,
            packet.remote_addr.clone(),
            LinkDirection::Inbound,
            Duration::from_millis(self.config().node.base_rtt_ms),
        );

        self.links.insert(link_id, link);
        self.addr_to_link.insert(addr_key, link_id);

        // Build the msg2 response, storing it on the connection for potential
        // resend before the connection is embedded on the machine below.
        let wire_msg2 = build_msg2(our_index, header.sender_idx, &msg2_response);
        conn.set_handshake_msg2(wire_msg2.clone());

        // The leg's persistent control machine is born carrying its pending
        // connection, parked at `SentMsg2` awaiting msg3 (identity is unknown
        // until then). Inserted before the msg2 send below so no suspension
        // point observes a leg in flight without a machine. `handle_msg3`
        // steps this same machine; every teardown path disposes it with the
        // embedded leg.
        let mut machine = PeerMachine::inbound_msg2_sent(link_id, our_index, packet.timestamp_ms);
        machine.set_leg(conn);
        self.peer_machines.insert(link_id, machine);

        if let Some(transport) = self.transports.get(&packet.transport_id) {
            match transport.send(&packet.remote_addr, &wire_msg2).await {
                Ok(bytes) => {
                    debug!(
                        link_id = %link_id,
                        our_index = %our_index,
                        their_index = %header.sender_idx,
                        bytes,
                        "Sent msg2 response"
                    );
                }
                Err(e) => {
                    warn!(
                        link_id = %link_id,
                        error = %e,
                        "Failed to send msg2"
                    );
                    // Clean up on failure (the machine disposal drops the
                    // embedded connection with it)
                    self.links.remove(&link_id);
                    self.addr_to_link
                        .remove(&(packet.transport_id, packet.remote_addr));
                    let _ = self.index_allocator.free(our_index);
                    self.remove_peer_machine(link_id);
                    self.msg1_rate_limiter.complete_handshake();
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
            }
        }

        // XX: handshake NOT complete yet — need msg3.
        // Store in pending_inbound for msg3 dispatch.
        self.pending_inbound
            .insert((packet.transport_id, our_index.as_u32()), link_id);

        self.msg1_rate_limiter.complete_handshake();
    }

    /// Find stored msg2 bytes for a given link (pre- or post-promotion).
    ///
    /// Checks the PeerConnection (if still pending) and then the ActivePeer
    /// (if already promoted).
    fn find_stored_msg2(&self, link_id: LinkId) -> Option<Vec<u8>> {
        // Check pending connection first
        if let Some(conn) = self.leg(&link_id)
            && let Some(msg2) = conn.handshake_msg2()
        {
            return Some(msg2.to_vec());
        }
        // Check promoted peer
        for peer in self.peers.values() {
            if peer.link_id() == link_id
                && let Some(msg2) = peer.handshake_msg2()
            {
                return Some(msg2.to_vec());
            }
        }
        None
    }

    /// Handle handshake message 2 (phase 0x2).
    ///
    /// With Noise XX, processing msg2 learns the responder's identity and
    /// generates msg3 which must be sent before the handshake is complete.
    /// After sending msg3, the initiator's handshake is complete and the
    /// connection is promoted.
    pub(in crate::node) async fn handle_msg2(&mut self, packet: ReceivedPacket) {
        // Parse header
        let header = match Msg2Header::parse(&packet.data) {
            Some(h) => h,
            None => {
                debug!("Invalid msg2 header");
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
            }
        };

        // Look up our pending handshake by our sender_idx (receiver_idx in msg2)
        let key = (packet.transport_id, header.receiver_idx.as_u32());
        let link_id = match self.pending_outbound.get(&key) {
            Some(id) => *id,
            None => {
                debug!(
                    receiver_idx = %header.receiver_idx,
                    "No pending outbound handshake for index"
                );
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::UnknownConnection));
                return;
            }
        };

        // Check if this is a rekey msg2: the handshake state is on the
        // ActivePeer (not a PeerConnection), so the link's machine — if one
        // survives at all — carries no pending connection. A bare machine
        // lookup would NOT discriminate here: an established peer's machine
        // stays keyed by this link, so the pending connection's presence is
        // what marks a fresh establish. Look for a peer with matching
        // rekey_our_index.
        if self
            .peer_machines
            .get(&link_id)
            .is_none_or(|machine| machine.leg().is_none())
        {
            let noise_msg2 = &packet.data[header.noise_msg2_offset..];

            // Find peer with rekey in progress for this index
            let peer_addr = self.peers.iter().find_map(|(addr, peer)| {
                if peer.rekey_in_progress() && peer.rekey_our_index() == Some(header.receiver_idx) {
                    Some(*addr)
                } else {
                    None
                }
            });

            if let Some(peer_node_addr) = peer_addr {
                let display_name = self.peer_display_name(&peer_node_addr);

                // Complete the rekey handshake on the ActivePeer
                // XX: complete_rekey_msg2 processes msg2 and generates msg3
                let transport_id = self
                    .peers
                    .get(&peer_node_addr)
                    .and_then(|p| p.transport_id());
                let remote_addr = self
                    .peers
                    .get(&peer_node_addr)
                    .and_then(|p| p.current_addr().cloned());
                let msg3_resend_interval =
                    self.config().node.rate_limit.handshake_resend_interval_ms;
                let msg3_now_ms = Self::now_ms();

                let mut rekey_completed = false;
                if let Some(peer) = self.peers.get_mut(&peer_node_addr) {
                    match peer.complete_rekey_msg2(noise_msg2) {
                        Ok((msg3_bytes, session, remote_epoch)) => {
                            let our_index = peer.rekey_our_index().unwrap_or(header.receiver_idx);
                            // Detect a peer restart: the epoch carried in this
                            // rekey msg2 differs from the one recorded at the
                            // last handshake. Compute before updating the field.
                            let remote_epoch_changed = matches!(
                                (peer.remote_epoch(), remote_epoch),
                                (Some(old), Some(new)) if old != new
                            );
                            if remote_epoch.is_some() {
                                peer.set_remote_epoch(remote_epoch);
                            }

                            // Send msg3 before setting pending session
                            let wire_msg3 = build_msg3(our_index, header.sender_idx, &msg3_bytes);
                            let msg3_sent = if let (Some(tid), Some(addr)) =
                                (transport_id, &remote_addr)
                                && let Some(transport) = self.transports.get(&tid)
                            {
                                match transport.send(addr, &wire_msg3).await {
                                    Ok(_) => {
                                        debug!(
                                            peer = %display_name,
                                            "Sent rekey msg3"
                                        );
                                        true
                                    }
                                    Err(e) => {
                                        warn!(
                                            peer = %display_name,
                                            error = %e,
                                            "Failed to send rekey msg3"
                                        );
                                        false
                                    }
                                }
                            } else {
                                false
                            };

                            if msg3_sent {
                                peer.set_pending_session(session, our_index, header.sender_idx);

                                // Retain msg3 for retransmission until the
                                // responder is confirmed on the new epoch.
                                // FMP sends msg3 exactly once otherwise; a
                                // lost datagram leaves the responder without
                                // the new session, so when the initiator cuts
                                // over its new-epoch frames silently miss at
                                // the peer → 30s link-dead. Mirrors FSP's
                                // resend_pending_session_msg3 liveness path.
                                peer.set_rekey_msg3_payload(
                                    wire_msg3.clone(),
                                    msg3_now_ms + msg3_resend_interval,
                                );

                                if let Some(tid) = transport_id {
                                    self.peers_by_index
                                        .insert((tid, our_index.as_u32()), peer_node_addr);
                                }

                                // Peer restart detected during this rekey:
                                // drop the stale FSP session-layer entry so the
                                // session map does not linger out of sync with
                                // the freshly rekeyed FMP link. Only after a
                                // successful msg3 send (the rekey actually
                                // completed); on a send failure the rekey is
                                // abandoned above and no teardown is warranted.
                                if remote_epoch_changed {
                                    if self.sessions.remove(&peer_node_addr).is_some() {
                                        debug!(
                                            peer = %display_name,
                                            "Cleared stale FSP session after peer restart during FMP rekey"
                                        );
                                    }
                                    debug!(
                                        peer = %display_name,
                                        "Peer restart detected during FMP rekey, replacing stale endpoint session"
                                    );
                                }

                                debug!(
                                    peer = %display_name,
                                    our_addr = %self.identity().node_addr(),
                                    new_our_index = %our_index,
                                    new_their_index = %header.sender_idx,
                                    "rekey-msg2 initiator: pending session set, awaiting K-bit cutover"
                                );

                                rekey_completed = true;
                            } else {
                                // msg3 send failed — abandon rekey
                                if let Some(idx) = peer.abandon_rekey() {
                                    if let Some(tid) = peer.transport_id() {
                                        self.peers_by_index.remove(&(tid, idx.as_u32()));
                                    }
                                    let _ = self.index_allocator.free(idx);
                                }
                                self.stats_mut().record_reject(RejectReason::Handshake(
                                    HandshakeReject::BadState,
                                ));
                            }
                        }
                        Err(e) => {
                            warn!(
                                peer = %display_name,
                                error = %e,
                                "Rekey msg2 processing failed"
                            );
                            if let Some(idx) = peer.abandon_rekey() {
                                if let Some(tid) = peer.transport_id() {
                                    self.peers_by_index.remove(&(tid, idx.as_u32()));
                                }
                                let _ = self.index_allocator.free(idx);
                            }
                            self.stats_mut()
                                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        }
                    }
                }

                // Feed the control machine the completed-rekey observation so its
                // shadow index and rekey phase stay coherent. Only on success —
                // the failure path above reverts the rekey and leaves the machine
                // untouched. The crypto effect already ran inline; this emits no
                // action.
                if rekey_completed {
                    self.observe_rekey_msg2(&peer_node_addr, header.sender_idx);
                }

                self.pending_outbound.remove(&key);
                return;
            }

            // Not a rekey — stale pending_outbound entry pointing at a
            // removed connection and no rekey-in-progress peer claims the
            // receiver_idx. State-machine inconsistency, not a fresh
            // lookup miss.
            self.pending_outbound.remove(&key);
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }

        let our_profile = self.node_profile();
        let (peer_identity, msg3_bytes, our_index) = {
            let Some(conn) = self.leg_mut(&link_id) else {
                warn!(link_id = %link_id, "Connection removed during msg2 processing");
                self.pending_outbound.remove(&key);
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::UnknownConnection));
                return;
            };

            // Create FMP negotiation payload for msg3 (includes profile, MMP bits, bloom TLV)
            let neg_payload = NegotiationPayload::fmp(1, 1, our_profile).encode();

            // Process Noise msg2 and generate msg3
            let noise_msg2 = &packet.data[header.noise_msg2_offset..];
            let (msg3_bytes, received_negotiation) = match conn.complete_handshake(
                noise_msg2,
                Some(&neg_payload),
                packet.timestamp_ms,
            ) {
                Ok(result) => result,
                Err(e) => {
                    warn!(
                        link_id = %link_id,
                        error = %e,
                        "Handshake completion failed"
                    );
                    conn.mark_failed();
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
            };

            // Process peer's FMP negotiation payload from msg2
            if let Some(neg_bytes) = &received_negotiation {
                match process_fmp_negotiation(our_profile, conn, neg_bytes) {
                    Ok(()) => {}
                    Err(e) => {
                        warn!(link_id = %link_id, our_profile = %our_profile, error = %e, "FMP negotiation failed");
                        conn.mark_failed();
                        self.stats_mut()
                            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        return;
                    }
                }
            }

            // Store their index
            conn.set_their_index(header.sender_idx);
            conn.set_source_addr(packet.remote_addr.clone());

            // Get peer identity for promotion (learned from msg2 in XX)
            let peer_identity = match conn.expected_identity() {
                Some(id) => *id,
                None => {
                    warn!(link_id = %link_id, "No identity after handshake");
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
            };

            let our_index = conn.our_index();

            (peer_identity, msg3_bytes, our_index)
        };

        let peer_node_addr = *peer_identity.node_addr();

        // ACL check: with XX, this is the first point where the initiator
        // knows the responder's identity.
        if self
            .authorize_peer(
                &peer_identity,
                PeerAclContext::OutboundHandshake,
                packet.transport_id,
                &packet.remote_addr,
            )
            .is_err()
        {
            self.pending_outbound.remove(&key);
            // Drop the machine persisted at dial — this leg never promotes,
            // and its pending connection is dropped with it.
            self.remove_peer_machine(link_id);
            self.remove_link(&link_id);
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }

        if peer_node_addr == *self.identity().node_addr() {
            // Reachable by any outbound leg whose msg2 static key turns out to
            // be our own — usually an anonymous shared-media beacon, but an
            // identified dial misdirected at ourselves lands here too (the
            // learned identity overwrites the dial-time expectation and is
            // never compared against it). This leg never promotes; its machine
            // goes with it (dropping the embedded pending connection). The
            // index, link, and `pending_outbound` entry are deliberately NOT
            // freed here (pre-existing shape).
            debug!(link_id = %link_id, "Discovered self via shared-media beacon, dropping");
            self.remove_peer_machine(link_id);
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }

        // Build and send msg3
        let our_index = our_index.unwrap_or(header.receiver_idx);
        let wire_msg3 = build_msg3(our_index, header.sender_idx, &msg3_bytes);

        if let Some(transport) = self.transports.get(&packet.transport_id) {
            match transport.send(&packet.remote_addr, &wire_msg3).await {
                Ok(bytes) => {
                    debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        link_id = %link_id,
                        their_index = %header.sender_idx,
                        bytes,
                        "Sent msg3, outbound handshake completing"
                    );
                }
                Err(e) => {
                    warn!(
                        link_id = %link_id,
                        error = %e,
                        "Failed to send msg3"
                    );
                    if let Some(conn) = self.leg_mut(&link_id) {
                        conn.mark_failed();
                    }
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
            }
        }

        debug!(
            peer = %self.peer_display_name(&peer_node_addr),
            link_id = %link_id,
            their_index = %header.sender_idx,
            "Outbound handshake completed"
        );

        // Cross-connection resolution: if the peer was already promoted via
        // our inbound handshake (we processed their msg3), both nodes initially
        // use mismatched sessions. The tie-breaker determines which handshake
        // wins: smaller node_addr's outbound.
        //
        // - Winner (smaller node): swap to outbound session + outbound indices
        // - Loser (larger node): keep inbound session + original their_index
        //
        // This ensures both nodes use the same Noise handshake (the winner's
        // outbound = the loser's inbound).
        // The machine is the sole computation site of the establish decision:
        // the shell builds the outbound snapshot, steps the machine once here,
        // and routes on the returned decision — a cross-connection resolves as
        // a single `ResolveCrossConnection { swap }` action, a net-new
        // establish as the promote action sequence. The Swap/Keep resolution
        // bodies stay inline in the shell because they mutate the already
        // promoted peer via `replace_session`, for which no `PeerAction`
        // exists.
        //
        // Every outbound leg carries a persistent machine by now — identified
        // dials persist one at dial, anonymous-discovery legs at leg birth in
        // `start_handshake` — so the lookup is expected to hit, and the
        // executor's `PromoteToActive` arm can feed `PromotionResolved` back
        // via the same lookup. For an anonymous machine this is where its
        // identity crystallizes: msg2 revealed who answered, and the learned
        // identity lands on the machine before the step (a no-op for
        // identified machines), so the Promote arm reads a crystallized
        // address. The `pending_outbound` lifecycle stays shell-side — the
        // machine never touches it.
        let out_snap = self.outbound_snapshot(&peer_node_addr);
        let actions = match self.peer_machines.get_mut(&link_id) {
            Some(machine) => {
                machine.crystallize_identity(peer_identity);
                machine.step(
                    PeerEvent::OutboundMsg2 {
                        their_index: header.sender_idx,
                        out: out_snap,
                    },
                    packet.timestamp_ms,
                    &mut self.index_allocator,
                )
            }
            None => {
                // A miss is a state-machine inconsistency (e.g. a test seeding
                // a connection/`pending_outbound` entry directly): rebuild the
                // machine defensively and persist it, so the promotion feedback
                // below still finds it and the promoted peer keeps a machine.
                debug_assert!(
                    false,
                    "outbound leg {link_id} reached msg2 without a control machine"
                );
                let mut machine =
                    PeerMachine::new_outbound(link_id, Some(peer_identity), packet.timestamp_ms);
                let actions = machine.step(
                    PeerEvent::OutboundMsg2 {
                        their_index: header.sender_idx,
                        out: out_snap,
                    },
                    packet.timestamp_ms,
                    &mut self.index_allocator,
                );
                self.peer_machines.insert(link_id, machine);
                actions
            }
        };

        let cross_swap = actions.iter().find_map(|action| match action {
            PeerAction::ResolveCrossConnection { swap } => Some(*swap),
            _ => None,
        });
        if let Some(swap) = cross_swap {
            // The cross-connection arms are decision-only: the resolution
            // action is the whole vector.
            debug_assert_eq!(actions, vec![PeerAction::ResolveCrossConnection { swap }]);
            // Extract the outbound connection from its machine FIRST — the
            // machine owns it, so disposing the machine before the take would
            // destroy the connection. The machine has delivered its decision
            // and the inline resolution below needs no machine, so drop it
            // right after the take — unconditionally, whether or not a
            // connection was carried — so none of this block's exits leave a
            // dangling machine.
            let taken_conn = self
                .peer_machines
                .get_mut(&link_id)
                .and_then(|machine| machine.take_leg());
            self.remove_peer_machine(link_id);

            let mut conn = match taken_conn {
                Some(c) => c,
                None => {
                    self.pending_outbound.remove(&key);
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::UnknownConnection));
                    return;
                }
            };

            let mut cross_conn_outcome: Option<CrossConnOutcome> = None;
            if swap {
                // We're the smaller node. Swap to outbound session + indices.
                // The peer will keep their inbound session (complement of ours).
                let outbound_our_index = conn.our_index();
                let outbound_session = conn.take_session();

                let (outbound_session, outbound_our_index) = match (
                    outbound_session,
                    outbound_our_index,
                ) {
                    (Some(s), Some(idx)) => (s, idx),
                    _ => {
                        warn!(peer = %self.peer_display_name(&peer_node_addr), "Incomplete outbound connection");
                        self.pending_outbound.remove(&key);
                        self.stats_mut()
                            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        return;
                    }
                };

                if let Some(peer) = self.peers.get_mut(&peer_node_addr) {
                    let suppressed = peer.replay_suppressed_count();
                    let old_our_index = peer.replace_session(
                        outbound_session,
                        outbound_our_index,
                        header.sender_idx,
                    );

                    // Update peers_by_index: remove old inbound index, add outbound
                    let Some(transport_id) = peer.transport_id() else {
                        warn!(peer = %self.peer_display_name(&peer_node_addr), "Active peer missing transport_id during cross-connection");
                        self.pending_outbound.remove(&key);
                        return;
                    };
                    if let Some(old_idx) = old_our_index {
                        self.peers_by_index
                            .remove(&(transport_id, old_idx.as_u32()));
                        let _ = self.index_allocator.free(old_idx);
                    }
                    self.peers_by_index
                        .insert((transport_id, outbound_our_index.as_u32()), peer_node_addr);

                    if suppressed > 0 {
                        debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            count = suppressed,
                            "Suppressed replay detections during link transition"
                        );
                    }

                    debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        new_our_index = %outbound_our_index,
                        new_their_index = %header.sender_idx,
                        "Cross-connection: swapped to outbound session (our outbound wins)"
                    );

                    cross_conn_outcome = Some(CrossConnOutcome::Swap {
                        our_index: outbound_our_index,
                        their_index: header.sender_idx,
                    });
                }
            } else {
                // We're the larger node. Keep our inbound session (it pairs
                // with the peer's outbound, which is the winning handshake).
                //
                // Do NOT update their_index here. Our their_index was set during
                // promote_connection() from the peer's msg1 sender_idx, which is
                // the peer's outbound our_index. After the peer (winner) swaps to
                // their outbound session, that index is exactly what they'll use.
                // The msg2 sender_idx we see here is the peer's INBOUND our_index,
                // which becomes stale after the peer swaps.
                let outbound_our_index = conn.our_index();

                if let Some(peer) = self.peers.get(&peer_node_addr) {
                    debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        kept_their_index = ?peer.their_index(),
                        "Cross-connection: keeping inbound session and original their_index (peer outbound wins)"
                    );
                }

                // Free the outbound's session index since we're not using it
                if let Some(idx) = outbound_our_index {
                    let _ = self.index_allocator.free(idx);
                }

                cross_conn_outcome = Some(CrossConnOutcome::Keep);
            }

            // Feed the promoted peer's control machine the cross-connection
            // resolution so its shadow session indices track the inline session
            // surgery above (updated on a swap, unchanged on a keep). The
            // outbound leg's machine was removed on entry, so this targets the
            // still-live promoted peer's machine. The crypto effect already ran
            // inline; this emits no action.
            if let Some(outcome) = cross_conn_outcome {
                self.observe_cross_conn_resolved(&peer_node_addr, outcome);
            }

            // Clean up outbound connection state
            self.pending_outbound.remove(&key);
            // Close the losing TCP connection (no-op for connectionless)
            if let Some(link) = self.links.get(&link_id) {
                let tid = link.transport_id();
                let addr = link.remote_addr().clone();
                if let Some(transport) = self.transports.get(&tid) {
                    transport.close_connection(&addr).await;
                }
            }
            self.remove_link(&link_id);

            // Send TreeAnnounce now that sessions are aligned
            if let Err(e) = self.send_tree_announce_to_peer(&peer_node_addr).await {
                debug!(peer = %self.peer_display_name(&peer_node_addr), error = %e, "Failed to send TreeAnnounce after cross-connection resolution");
            }
            // Schedule filter announce (sent on next tick via debounce)
            self.bloom_state.mark_update_needed(peer_node_addr);
            self.reset_lookup_backoff();
            return;
        }

        // === Net-new outbound establish, driven by the machine. ===
        // The machine's decision was `Promote` (`has_existing_peer == false` —
        // the cross-connection block above returns otherwise), so
        // `promote_connection` hits its normal-promotion branch and returns
        // `Promoted`. The machine survives the promotion and the executor
        // crystallizes its state via the `PromotionResolved` feedback. The
        // promote tail (info log, tree/bloom/backoff, `pending_outbound`
        // removal) lives in the executor's `PromoteToActive` arm.
        //
        // The outbound Msg2 Promote step cancels the two dial-armed handshake
        // timers (the machine survives promotion, so they would otherwise linger
        // in `peer_timers` until `drive_peer_timers` lazily discards them — the
        // promoted leg's pending connection is consumed and the machine has left
        // `SentMsg1`, so they can no longer fire) and then promotes.
        // `PromoteToActive` is what performs the promotion.
        debug_assert_eq!(
            actions,
            vec![
                PeerAction::CancelTimer {
                    kind: TimerKind::HandshakeRetransmit
                },
                PeerAction::CancelTimer {
                    kind: TimerKind::HandshakeTimeout
                },
                PeerAction::PromoteToActive { link: link_id },
            ]
        );

        let ambient = PeerActionCtx {
            verified_identity: peer_identity,
            transport_id: packet.transport_id,
            remote_addr: packet.remote_addr.clone(),
            our_index: Some(our_index),
            their_index: Some(header.sender_idx),
            now_ms: packet.timestamp_ms,
            is_outbound: true,
            pending_outbound_key: Some(key),
        };
        self.execute_peer_actions(link_id, &ambient, actions).await;
    }

    /// Handle handshake message 3 (phase 0x3).
    ///
    /// Completes the XX handshake on the responder side. Processes msg3 to
    /// learn the initiator's identity and epoch, then performs identity-based
    /// checks (restart detection, rekey detection, cross-connection resolution)
    /// and promotes the connection to active peer.
    pub(in crate::node) async fn handle_msg3(&mut self, packet: ReceivedPacket) {
        // Parse header
        let header = match Msg3Header::parse(&packet.data) {
            Some(h) => h,
            None => {
                debug!("Invalid msg3 header");
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
            }
        };

        // Look up our pending inbound handshake by our index (receiver_idx in msg3)
        let key = (packet.transport_id, header.receiver_idx.as_u32());
        let link_id = match self.pending_inbound.remove(&key) {
            Some(id) => id,
            None => {
                // No pending inbound handshake matches this msg3. The live
                // rekey-responder path completes via pending_inbound above, so
                // a miss here is an unknown connection.
                debug!(
                    receiver_idx = %header.receiver_idx,
                    "No pending inbound or rekey state for msg3"
                );
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::UnknownConnection));
                return;
            }
        };

        let our_profile = self.node_profile();
        let (peer_identity, our_index, remote_epoch) = {
            // Get the pending connection
            let conn = match self.leg_mut(&link_id) {
                Some(c) => c,
                None => {
                    debug!(
                        link_id = %link_id,
                        "No pending connection for msg3"
                    );
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::UnknownConnection));
                    return;
                }
            };

            // Process msg3 — learns initiator's identity and epoch
            let noise_msg3 = &packet.data[header.noise_msg3_offset..];
            let received_negotiation =
                match conn.complete_handshake_msg3(noise_msg3, packet.timestamp_ms) {
                    Ok(neg) => neg,
                    Err(e) => {
                        warn!(
                            link_id = %link_id,
                            error = %e,
                            "Msg3 processing failed"
                        );
                        // Clean up. Capture the index before disposing the
                        // machine (and the connection embedded on it); reading
                        // it after the disposal would always return None and
                        // leak the allocated index.
                        let our_idx_to_free = self.leg(&link_id).and_then(|c| c.our_index());
                        self.remove_link(&link_id);
                        self.remove_peer_machine(link_id);
                        if let Some(idx) = our_idx_to_free {
                            let _ = self.index_allocator.free(idx);
                        }
                        self.stats_mut()
                            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        return;
                    }
                };

            // Process peer's FMP negotiation payload from msg3
            if let Some(neg_bytes) = &received_negotiation {
                match process_fmp_negotiation(our_profile, conn, neg_bytes) {
                    Ok(()) => {}
                    Err(e) => {
                        warn!(link_id = %link_id, our_profile = %our_profile, error = %e, "FMP negotiation failed");
                        self.remove_link(&link_id);
                        self.remove_peer_machine(link_id);
                        self.stats_mut()
                            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        return;
                    }
                }
            }

            // Learn peer identity from msg3
            let peer_identity = match conn.expected_identity() {
                Some(id) => *id,
                None => {
                    warn!("Identity not learned from msg3");
                    self.remove_link(&link_id);
                    self.remove_peer_machine(link_id);
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
            };

            let our_index = conn.our_index();
            let remote_epoch = conn.remote_epoch();

            (peer_identity, our_index, remote_epoch)
        };

        let peer_node_addr = *peer_identity.node_addr();

        // ACL check: with XX, this is the first point where the responder
        // knows the initiator's identity.
        if self
            .authorize_peer(
                &peer_identity,
                PeerAclContext::InboundHandshake,
                packet.transport_id,
                &packet.remote_addr,
            )
            .is_err()
        {
            // Notify the initiator via encrypted Disconnect so they clean
            // up without waiting for link-dead timeout. The Noise session
            // is fully established at this point (msg3 just succeeded),
            // and the initiator has a matching session from processing
            // msg2. Reason `Other` is used instead of `SecurityViolation`
            // to avoid naming the ACL mechanism on the wire.
            let reject_info = match self.leg_mut(&link_id) {
                Some(conn) => match (conn.their_index(), conn.take_session()) {
                    (Some(idx), Some(session)) => Some((idx, session)),
                    _ => None,
                },
                None => None,
            };
            if let Some((their_idx, mut session)) = reject_info {
                let payload = Disconnect::new(DisconnectReason::Other).encode();
                let _ = self
                    .send_encrypted_link_message_raw(
                        peer_node_addr,
                        packet.transport_id,
                        &packet.remote_addr,
                        &mut session,
                        their_idx,
                        &payload,
                    )
                    .await;
            }
            self.remove_link(&link_id);
            self.remove_peer_machine(link_id);
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }

        if peer_node_addr == *self.identity().node_addr() {
            debug!(link_id = %link_id, "Received msg3 from self, dropping");
            self.remove_link(&link_id);
            self.remove_peer_machine(link_id);
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }

        // The inbound max_peers cap is enforced solely by the late check
        // inside promote_connection() (the "Normal promotion" branch). On
        // XX, identity isn't known until msg3 has been received, by which
        // point Msg1+Msg2+Msg3 have all crossed the wire, so an early gate
        // here would save no wire bytes; and the late check already governs
        // exactly the same peer set (net-new, not-known, not-pending-
        // outbound — known/pending-outbound peers return earlier via the
        // cross-connection paths). Over-cap inbound rejections surface as
        // NodeError::MaxPeersExceeded in the Err arm below and are logged at
        // debug rather than warn (expected policy rejection, not a fault).
        let our_index = our_index.unwrap_or(header.receiver_idx);

        // Identity-based restart/rekey/cross-connection classification.
        //
        // Now that we know the initiator's identity from msg3, classify this
        // inbound handshake against any existing active peer. The leg's machine
        // evaluates the pure `establish_inbound` decision once and returns it with
        // the arm's action stream; the driver routes on the decision below,
        // running the actions through the executor and owning only the residual
        // shell bookkeeping (link/map removal, reject records, the duplicate-msg2
        // resend). The snapshot resolves the one clock read (session age) and the
        // config-derived rekey floor up front.
        //
        // The rekey age floor sits BELOW the minimum possible rekey interval, or
        // jittered rekeys are wrongly rejected. It bounds both the
        // cross-connection branch (`< floor` -> initial cross-connection) and the
        // rekey-responder branch (`>= floor` -> rekey), so the two partition
        // cleanly; see the pre-refactor commentary retained on the decision.
        let our_node_addr = *self.identity().node_addr();
        let rekey_enabled = self.config().node.rekey.enabled;
        let rekey_age_floor_secs = {
            let min_interval = self
                .config()
                .node
                .rekey
                .after_secs
                .saturating_sub(crate::node::REKEY_JITTER_SECS.unsigned_abs());
            min_interval.saturating_sub(5).max(5)
        };
        let wire = WireOutcome {
            peer_node_addr,
            remote_epoch,
        };
        let snap = match self.peers.get(&peer_node_addr) {
            Some(existing_peer) => EstablishSnapshot {
                has_existing_peer: true,
                existing_peer_epoch: existing_peer.remote_epoch(),
                existing_session_age_secs: existing_peer
                    .session_established_at()
                    .elapsed()
                    .as_secs(),
                has_session: existing_peer.has_session(),
                is_healthy: existing_peer.is_healthy(),
                pending_new_session: existing_peer.pending_new_session().is_some(),
                rekey_in_progress: existing_peer.rekey_in_progress(),
                existing_msg2: existing_peer.handshake_msg2().map(|m| m.to_vec()),
                different_link: existing_peer.link_id() != link_id,
                rekey_enabled,
                rekey_age_floor_secs,
                our_node_addr,
            },
            None => EstablishSnapshot {
                has_existing_peer: false,
                existing_peer_epoch: None,
                existing_session_age_secs: 0,
                has_session: false,
                is_healthy: false,
                pending_new_session: false,
                rekey_in_progress: false,
                existing_msg2: None,
                different_link: false,
                rekey_enabled,
                rekey_age_floor_secs,
                our_node_addr,
            },
        };

        // Capture the snapshot fields the tie-break breadcrumb reads before the
        // snapshot moves into the single classification call below.
        let rekey_in_progress = snap.rekey_in_progress;
        let pending_new_session = snap.pending_new_session;

        // Single inbound classification site. The leg's PERSISTENT machine — born
        // at msg1, parked `SentMsg2` — evaluates `establish_inbound` once and
        // returns both the decision (for the driver to route on) and the arm's
        // action stream. The terminal tie-break/duplicate arms carry their
        // `FreeIndex` (returning the msg1-allocated inbound index) as a machine
        // action; the driver owns only the link/map removal and the reject
        // bookkeeping, since the machine cannot remove itself from the map.
        let (decision, actions) = match self.peer_machines.get_mut(&link_id) {
            // Disjoint field borrow: `self.peer_machines` (the map entry) and
            // `self.index_allocator` (the capability) are separate fields.
            Some(machine) => machine.inbound_msg3(
                wire,
                snap,
                our_index,
                packet.timestamp_ms,
                &mut self.index_allocator,
            ),
            None => {
                // Every inbound leg's machine is born at msg1, so a miss here
                // means a teardown path dropped the machine but left the leg
                // behind. Recover with a fresh machine seeded the way msg1 would
                // have left it, so the classification below behaves identically.
                debug_assert!(false, "peer machine present for every pending inbound leg");
                let mut machine =
                    PeerMachine::inbound_msg2_sent(link_id, our_index, packet.timestamp_ms);
                let result = machine.inbound_msg3(
                    wire,
                    snap,
                    our_index,
                    packet.timestamp_ms,
                    &mut self.index_allocator,
                );
                self.peer_machines.insert(link_id, machine);
                result
            }
        };

        let ambient = PeerActionCtx {
            verified_identity: peer_identity,
            transport_id: packet.transport_id,
            remote_addr: packet.remote_addr.clone(),
            our_index: Some(our_index),
            their_index: Some(header.sender_idx),
            now_ms: packet.timestamp_ms,
            is_outbound: false,
            pending_outbound_key: None,
        };

        match decision {
            InboundDecision::Reject {
                reason: InboundReject::DualRekeyWon,
            } => {
                // Dual-init rekey tie-break: we win (smaller addr), drop their msg3.
                info!(
                    peer = %self.peer_display_name(&peer_node_addr),
                    our_addr = %our_node_addr,
                    their_addr = %peer_node_addr,
                    rekey_in_progress = rekey_in_progress,
                    pending_new_session = pending_new_session,
                    "rekey-msg3 tie-break: we win (smaller addr), drop their msg3"
                );
                // We keep our in-progress rekey and drop their msg3. The machine's
                // returned `FreeIndex` returns the msg1-allocated inbound index
                // rather than orphaning it; the driver owns only the link/map
                // removal and the reject record.
                self.execute_peer_actions(link_id, &ambient, actions).await;
                debug_assert!(
                    !self.index_allocator.is_allocated(our_index),
                    "inbound index freed exactly once via the machine action"
                );
                self.links.remove(&link_id);
                self.remove_peer_machine(link_id);
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            }
            InboundDecision::ResendMsg2 { msg2 } => {
                // Not a rekey — duplicate handshake from same epoch. Resend the
                // stored msg2 bytes as-is (a driver mechanism: replaying the
                // stored frame, not rebuilding it), leaving the active peer
                // untouched.
                if let Some(msg2) = msg2
                    && let Some(transport) = self.transports.get(&packet.transport_id)
                {
                    match transport.send(&packet.remote_addr, &msg2).await {
                        Ok(_) => debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            "Resent msg2 for duplicate handshake (same epoch)"
                        ),
                        Err(e) => debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            error = %e,
                            "Failed to resend msg2"
                        ),
                    }
                }
                // The active peer is untouched. The machine's returned `FreeIndex`
                // returns the msg1-allocated inbound index rather than orphaning
                // it; the driver owns only the link/map removal.
                self.execute_peer_actions(link_id, &ambient, actions).await;
                debug_assert!(
                    !self.index_allocator.is_allocated(our_index),
                    "inbound index freed exactly once via the machine action"
                );
                self.links.remove(&link_id);
                self.remove_peer_machine(link_id);
            }
            decision @ (InboundDecision::RestartThenPromote { .. }
            | InboundDecision::Promote
            | InboundDecision::CrossConnect { .. }
            | InboundDecision::RekeyRespond { .. }) => {
                // Preserve the epoch-mismatch restart breadcrumb — it fires before
                // the machine's teardown actions run, matching the pre-refactor
                // order (breadcrumb → remove_active_peer → note_link_dead → promote).
                if let InboundDecision::RestartThenPromote { peer } = &decision {
                    debug!(
                        peer = %self.peer_display_name(peer),
                        "Peer restart detected (epoch mismatch), removing stale session"
                    );
                }
                // Machine-driven inbound establish/rekey resolution. The leg's
                // PERSISTENT machine emitted the action stream alongside the
                // decision:
                //   `[PromoteToActive]` for `Promote`;
                //   `[InvalidateSendState, ReportLost, PromoteToActive]` for
                //     `RestartThenPromote` (the two teardown actions map to
                //     `remove_active_peer` / `note_link_dead`, in that order);
                //   `[SwapToInboundSession]` for a simultaneous-init cross-connection;
                //   `[RekeyRespondTrigger]` for a rekey-responder tie-break.
                // On a promote the machine survives and crystallizes in place via
                // the executor's `PromotionResolved` feedback; on the other arms the
                // executor's teardown disposes it with the leg. The relocated
                // session-swap / promote / teardown bodies live in the executor's
                // `SwapToInboundSession` / `RekeyRespondTrigger` / `PromoteToActive`
                // / `InvalidateSendState` / `ReportLost` arms.
                self.execute_peer_actions(link_id, &ambient, actions).await;
            }
        }
    }

    /// Promote a connection to active peer after successful authentication.
    ///
    /// Handles cross-connection detection and resolution using tie-breaker rules.
    /// Leaf nodes enforce single-peer constraint.
    pub(in crate::node) fn promote_connection(
        &mut self,
        link_id: LinkId,
        verified_identity: PeerIdentity,
        current_time_ms: u64,
    ) -> Result<PromotionResult, NodeError> {
        // Leaf nodes: reject if we already have a peer (single-peer enforcement)
        let peer_node_addr_check = *verified_identity.node_addr();
        if self.node_profile() == crate::proto::fmp::NodeProfile::Leaf
            && !self.peers.is_empty()
            && !self.peers.contains_key(&peer_node_addr_check)
        {
            info!(
                peer = %self.peer_display_name(&peer_node_addr_check),
                link_id = %link_id,
                "Leaf node rejecting additional peer (single-peer enforcement)"
            );
            // Clean up the connection (taken off its machine first) and its
            // control machine
            if let Some(conn) = self
                .peer_machines
                .get_mut(&link_id)
                .and_then(|machine| machine.take_leg())
                && let Some(idx) = conn.our_index()
            {
                let _ = self.index_allocator.free(idx);
            }
            self.remove_link(&link_id);
            self.remove_peer_machine(link_id);
            return Err(NodeError::MaxPeersExceeded { max: 1 });
        }

        // Take the pending connection off its control machine. The machine
        // survives the promotion (it becomes the active peer's control
        // machine), left with no pending connection.
        let mut connection = self
            .peer_machines
            .get_mut(&link_id)
            .and_then(|machine| machine.take_leg())
            .ok_or(NodeError::ConnectionNotFound(link_id))?;

        // Verify handshake is complete and extract session
        if !connection.has_session() {
            return Err(NodeError::HandshakeIncomplete(link_id));
        }

        let noise_session = connection
            .take_session()
            .ok_or(NodeError::NoSession(link_id))?;

        let our_index = connection
            .our_index()
            .ok_or_else(|| NodeError::PromotionFailed {
                link_id,
                reason: "missing our_index".into(),
            })?;
        let their_index = connection
            .their_index()
            .ok_or_else(|| NodeError::PromotionFailed {
                link_id,
                reason: "missing their_index".into(),
            })?;
        let transport_id = connection
            .transport_id()
            .ok_or_else(|| NodeError::PromotionFailed {
                link_id,
                reason: "missing transport_id".into(),
            })?;
        let current_addr = connection
            .source_addr()
            .ok_or_else(|| NodeError::PromotionFailed {
                link_id,
                reason: "missing source_addr".into(),
            })?
            .clone();
        let link_stats = connection.link_stats().clone();
        let remote_epoch = connection.remote_epoch();
        let peer_profile = connection
            .peer_profile()
            .unwrap_or(crate::proto::fmp::NodeProfile::Full);

        let peer_node_addr = *verified_identity.node_addr();
        let is_outbound = connection.is_outbound();

        // Check for cross-connection
        if let Some(existing_peer) = self.peers.get(&peer_node_addr) {
            let existing_link_id = existing_peer.link_id();

            let remote_epoch_changed = matches!((existing_peer.remote_epoch(), remote_epoch), (Some(old), Some(new)) if old != new);

            // Determine which connection wins. A peer restart (different
            // startup epoch) is not a normal cross-connection: the old link
            // and FSP sessions are cryptographically stale, so the freshly
            // authenticated connection must replace them regardless of the
            // tie-breaker direction.
            let this_wins = remote_epoch_changed
                || cross_connection_winner(
                    self.identity().node_addr(),
                    &peer_node_addr,
                    is_outbound,
                );

            if this_wins {
                // This connection wins, replace the existing peer
                let Some(old_peer) = self.peers.remove(&peer_node_addr) else {
                    return Err(NodeError::PeerNotFound(peer_node_addr));
                };
                let loser_link_id = old_peer.link_id();

                // The replaced (losing) peer was established and so
                // carried a machine keyed by its OWN link_id (loser_link_id);
                // drop it so no machine orphans when its ActivePeer is removed.
                // The winning connection's machine is inserted below keyed by
                // the winner link_id. NEUTRAL: nothing reads peer_machines yet.
                self.remove_peer_machine(loser_link_id);

                // Clean up old peer's index from peers_by_index
                if let (Some(old_tid), Some(old_idx)) =
                    (old_peer.transport_id(), old_peer.our_index())
                {
                    self.peers_by_index.remove(&(old_tid, old_idx.as_u32()));
                    // Unregister the OLD cache_key from the decrypt
                    // worker pool BEFORE freeing the index for reuse.
                    // Otherwise the worker's per-shard HashMap retains a
                    // stale entry pointing at the removed peer's session;
                    // if the index allocator later recycles old_idx to a
                    // different peer, the new register call overwrites
                    // the stale entry — but until that point, decrypt
                    // jobs that land at the recycled cache_key resolve
                    // to the wrong session and AEAD silently fails.
                    #[cfg(unix)]
                    self.unregister_decrypt_worker_session((old_tid, old_idx.as_u32()));
                    let _ = self.index_allocator.free(old_idx);
                }

                if remote_epoch_changed {
                    if self.sessions.remove(&peer_node_addr).is_some() {
                        debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            "Cleared stale FSP session after peer restart during promotion"
                        );
                    }
                    debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        winner_link = %link_id,
                        loser_link = %loser_link_id,
                        "Peer restart detected during promotion, replacing stale active peer"
                    );
                }

                self.seed_path_mtu_for_link_peer(&peer_node_addr, transport_id, &current_addr);

                let mut new_peer = ActivePeer::with_session(
                    verified_identity,
                    link_id,
                    current_time_ms,
                    noise_session,
                    our_index,
                    their_index,
                    transport_id,
                    current_addr,
                    link_stats,
                    is_outbound,
                    &self.config().node.mmp,
                    remote_epoch,
                    self.node_profile(),
                    peer_profile,
                );
                new_peer.set_tree_announce_min_interval_ms(
                    self.config().node.tree.announce_min_interval_ms,
                );

                self.peers.insert(peer_node_addr, new_peer);
                // The winning leg's machine (keyed by the winner link) survives
                // the promotion; the executor crystallizes it in place via the
                // `PromotionResolved` feedback after this returns.
                self.peers_by_index
                    .insert((transport_id, our_index.as_u32()), peer_node_addr);
                self.peering
                    .reconciler
                    .retry_pending
                    .remove(&peer_node_addr);
                self.register_identity(peer_node_addr, verified_identity.pubkey_full());

                // Non-routing peers don't send filters; include them as
                // dependents so our bloom filter advertises their identity.
                if peer_profile != crate::proto::fmp::NodeProfile::Full {
                    self.bloom_state.add_leaf_dependent(peer_node_addr);
                }

                debug!(
                    peer = %self.peer_display_name(&peer_node_addr),
                    winner_link = %link_id,
                    loser_link = %loser_link_id,
                    "Cross-connection resolved: this connection won"
                );

                // Hand the FMP recv cipher + replay window to the
                // decrypt shard worker. (Same as normal-promotion tail
                // below.)
                #[cfg(unix)]
                self.register_decrypt_worker_session(&peer_node_addr);

                Ok(PromotionResult::CrossConnectionWon {
                    loser_link_id,
                    node_addr: peer_node_addr,
                })
            } else {
                // This connection loses, keep existing
                // Free the index we allocated
                let _ = self.index_allocator.free(our_index);

                // Dispose the losing leg's machine here, with the leg. The
                // executor's post-promote `PromotionResolved` dispatch then
                // misses on this link, so the machine-side `FreeIndex` for the
                // lost leg never fires — the inline free above stays the only
                // one.
                self.remove_peer_machine(link_id);

                debug!(
                    peer = %self.peer_display_name(&peer_node_addr),
                    winner_link = %existing_link_id,
                    loser_link = %link_id,
                    "Cross-connection resolved: this connection lost"
                );

                Ok(PromotionResult::CrossConnectionLost {
                    winner_link_id: existing_link_id,
                })
            }
        } else {
            // No existing promoted peer. There may be a pending outbound
            // connection to the same peer (cross-connection in progress).
            // Do NOT clean it up yet — we need the outbound to stay alive
            // so that when the peer's msg2 arrives, we can learn the peer's
            // inbound session index and update their_index on the promoted
            // peer. The outbound will be cleaned up in handle_msg2 or by
            // the 30s handshake timeout.
            let pending_to_same_peer: Vec<LinkId> = self
                .connections()
                .filter(|conn| {
                    conn.expected_identity()
                        .map(|id| *id.node_addr() == peer_node_addr)
                        .unwrap_or(false)
                })
                .map(|conn| conn.link_id())
                .collect();

            for pending_link_id in &pending_to_same_peer {
                debug!(
                    peer = %self.peer_display_name(&peer_node_addr),
                    pending_link_id = %pending_link_id,
                    promoted_link_id = %link_id,
                    "Deferring cleanup of pending outbound (awaiting msg2 for index update)"
                );
            }

            // Normal promotion
            if self.max_peers() > 0 && self.peers.len() >= self.max_peers() {
                let _ = self.index_allocator.free(our_index);
                return Err(NodeError::MaxPeersExceeded {
                    max: self.max_peers(),
                });
            }

            // Preserve tree announce rate-limit state from old peer (if reconnecting).
            // Without this, reconnection resets the rate limit window to zero,
            // allowing an immediate announce that can feed an announce loop.
            let old_announce_ts = self
                .peers
                .get(&peer_node_addr)
                .map(|p| p.last_tree_announce_sent_ms());

            self.seed_path_mtu_for_link_peer(&peer_node_addr, transport_id, &current_addr);

            let mut new_peer = ActivePeer::with_session(
                verified_identity,
                link_id,
                current_time_ms,
                noise_session,
                our_index,
                their_index,
                transport_id,
                current_addr,
                link_stats,
                is_outbound,
                &self.config().node.mmp,
                remote_epoch,
                self.node_profile(),
                peer_profile,
            );
            new_peer.set_tree_announce_min_interval_ms(
                self.config().node.tree.announce_min_interval_ms,
            );
            if let Some(ts) = old_announce_ts {
                new_peer.set_last_tree_announce_sent_ms(ts);
            }

            self.peers.insert(peer_node_addr, new_peer);
            // The promoted leg's machine (born at msg1 for inbound, at dial for
            // outbound) survives the promotion; the executor crystallizes it in
            // place via the `PromotionResolved` feedback after this returns.
            self.peers_by_index
                .insert((transport_id, our_index.as_u32()), peer_node_addr);
            self.peering
                .reconciler
                .retry_pending
                .remove(&peer_node_addr);
            self.register_identity(peer_node_addr, verified_identity.pubkey_full());

            // Non-routing peers don't send filters; include them as
            // dependents so our bloom filter advertises their identity.
            if peer_profile != crate::proto::fmp::NodeProfile::Full {
                self.bloom_state.add_leaf_dependent(peer_node_addr);
            }

            debug!(
                peer = %self.peer_display_name(&peer_node_addr),
                link_id = %link_id,
                our_index = %our_index,
                their_index = %their_index,
                "Connection promoted to active peer"
            );

            // Hand the FMP recv cipher + replay window to the
            // decrypt shard worker. From this point on the worker
            // is the sole authority on FMP replay protection for
            // this session. No-op when the worker pool isn't
            // spawned (unit-test path or `FIPS_DECRYPT_WORKERS=0`).
            #[cfg(unix)]
            self.register_decrypt_worker_session(&peer_node_addr);

            Ok(PromotionResult::Promoted(peer_node_addr))
        }
    }
}

/// Process an FMP negotiation payload received from a peer.
///
/// Decodes the payload, validates profile pairing, and stores the
/// results on the PeerConnection.
fn process_fmp_negotiation(
    our_profile: crate::proto::fmp::NodeProfile,
    conn: &mut PeerConnection,
    neg_bytes: &[u8],
) -> Result<(), crate::proto::Error> {
    // The decode -> validate -> profile decision is the pure core split; the
    // shell records the result on the connection and logs.
    let their_profile = decide_fmp_negotiation(our_profile, neg_bytes)?;

    conn.set_negotiation_results(their_profile);

    debug!(
        link_id = %conn.link_id(),
        our_profile = %our_profile,
        peer_profile = %their_profile,
        "FMP negotiation complete"
    );

    Ok(())
}
