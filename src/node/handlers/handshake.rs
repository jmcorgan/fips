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
use crate::node::diag::{self, HsLine, OrNone, Shown, Withheld};
use crate::node::rate_limit::Msg1Class;
use crate::node::reject::{HandshakeReject, RejectReason};
use crate::node::{Node, NodeError};
use crate::peer::machine::{
    CrossConnOutcome, DialMsg2Step, HandshakeCrypto, LinkFinal, Msg3Error, PeerAction, PeerEvent,
    PeerMachine, TimerKind,
};
use crate::peer::{ActivePeer, LinkCaps, LinkOutputs};
use crate::proto::fmp::wire::{Msg1Header, Msg2Header, Msg3Header, build_msg2, build_msg3};
use crate::proto::fmp::{
    DialMsg2Reject, DialMsg2Snapshot, Disconnect, DisconnectReason,
    EPOCH_RESTART_MIN_INTERVAL_SECS, EstablishSnapshot, InboundDecision, InboundReject, Msg1Digest,
    NegotiationPayload, NodeProfile, OutboundSnapshot, PromotionResult, RekeyClaim, WireOutcome,
    cross_connection_winner, decide_fmp_negotiation,
};
use crate::time::HostClock;
use crate::transport::{Link, LinkDirection, LinkId, ReceivedPacket, TransportError, TransportId};
use crate::utils::index::SessionIndex;
use fips_core::proto::rekey::{IndexLease, Input, Intent, Reason, Record, allocate};
use fips_core::time::Clock as _;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

impl Node {
    /// Snapshot the registry state the outbound establish decision reads about
    /// `peer_addr`: whether the identity is already an active peer, and the
    /// pre-evaluated cross-connection tie-break for THIS outbound connection
    /// (`is_outbound = true`), resolved into a plain `bool` here so the core
    /// stays free of the peer helper.
    fn outbound_snapshot(&self, peer_addr: &NodeAddr) -> OutboundSnapshot {
        let existing = self.peers.get(peer_addr);
        OutboundSnapshot {
            has_existing_peer: existing.is_some(),
            existing_peer_epoch: existing.and_then(|p| p.remote_epoch()),
            our_outbound_wins: cross_connection_winner(
                self.identity().node_addr(),
                peer_addr,
                true,
            ),
        }
    }

    /// Count a line of `kind` for `peer` and say whether to log it. On the
    /// first counted line after a session change, logs what earlier sessions
    /// withheld. A handshake with no peer entry is always logged.
    fn shown(&mut self, peer: &NodeAddr, kind: HsLine) -> bool {
        let Some(entry) = self.peers.get_mut(peer) else {
            return true;
        };
        let counts = entry.hs_lines_mut();
        let carried = counts.take_carried();
        let count = counts.count(kind);
        if let Some(withheld) = carried {
            self.log_withheld(peer, &withheld);
        }
        self.show(peer, kind, count)
    }

    /// Whether to log the `count`th line of `kind` for `peer`, logging the
    /// notice that replaces the first one suppressed.
    fn show(&self, peer: &NodeAddr, kind: HsLine, count: u32) -> bool {
        match Shown::of(count) {
            Shown::Line => true,
            Shown::Notice => {
                debug!(
                    peer = %self.peer_display_name(peer),
                    kind = %kind,
                    "Suppressing repeated handshake lines for this peer"
                );
                false
            }
            Shown::Nothing => false,
        }
    }

    /// Log how many of `peer`'s repeated handshake lines were not logged,
    /// by kind.
    pub(in crate::node) fn log_withheld(&self, peer: &NodeAddr, withheld: &Withheld) {
        debug!(
            peer = %self.peer_display_name(peer),
            resend = withheld.of(HsLine::Resend),
            resend_failed = withheld.of(HsLine::ResendFailed),
            restart = withheld.of(HsLine::Restart),
            "Suppressed repeated handshake lines"
        );
    }

    /// A session of `peer` carried its first authenticated frame: drop the
    /// identity's silent-session record, and log how many of its refusal
    /// lines were not logged.
    pub(in crate::node) fn note_peer_heard(&mut self, peer: &NodeAddr) {
        let refused = diag::withheld(self.silent_sessions.heard(peer));
        if refused > 0 {
            debug!(
                peer = %self.peer_display_name(peer),
                refused,
                "Suppressed repeated handshake lines"
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

    /// Returns true if an inbound msg1's source matches a link belonging to a
    /// **promoted** peer, i.e. it is rekey/restart maintenance traffic rather
    /// than a stranger's fresh handshake.
    ///
    /// Deliberately *not* expressed in terms of `should_admit_msg1`, and
    /// deliberately not its building block, which is how the `master` lineage
    /// arranges the same pair. On XX, `handle_msg1` inserts into
    /// `addr_to_link` for a still-pending inbound connection before any
    /// identity is known, and `initiate_connection` inserts for an outbound
    /// dial in flight. A bare `addr_to_link` hit therefore does not mean
    /// "established" here, and the two predicates answer different questions:
    /// `should_admit_msg1` asks whether the `accept_connections` gate applies
    /// (a pending outbound dial must bypass it, or the dual-init tie-breaker
    /// deadlocks), while this asks whether the source is already a promoted
    /// peer, which is the only safe basis for exempting traffic from
    /// stranger-class metering.
    ///
    /// Two ways to be a promoted peer at this `(transport_id, addr)`:
    ///
    /// 1. `addr_to_link` maps the tuple to a link that some entry in `peers`
    ///    owns. Catches the peer whose registered `TransportAddr` form matches
    ///    the form inbound packets carry.
    /// 2. A peer's `current_addr()` matches the tuple. `current_addr` is
    ///    seeded at promotion from the handshake's source address and updated
    ///    from inbound encrypted frames, so it is always numeric
    ///    `SocketAddr`-form; this catches the peer whose `addr_to_link` key is
    ///    hostname-form because `initiate_connection` populated it from a
    ///    hostname-bearing peer config.
    ///
    /// Cost: one O(1) map lookup plus one O(peers) scan covering both limbs,
    /// run on every inbound msg1 including those about to be refused. The scan
    /// exists only because `addr_to_link` is keyed on the *unresolved* dial
    /// address; correcting that keying reduces this to O(1).
    pub(in crate::node) fn is_established_link_msg1(
        &self,
        transport_id: crate::transport::TransportId,
        remote_addr: &crate::transport::TransportAddr,
    ) -> bool {
        let link_at_addr = self
            .addr_to_link
            .get(&(transport_id, remote_addr.clone()))
            .copied();
        self.peers.values().any(|p| {
            Some(p.link_id()) == link_at_addr
                || (p.transport_id() == Some(transport_id) && p.current_addr() == Some(remote_addr))
        })
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
    ///
    /// Intentionally independent of `is_established_link_msg1` on this
    /// branch, and not built from it. The two are deliberately allowed to
    /// drift because they answer different questions: predicate 1 above
    /// admits on a bare `addr_to_link` hit, which at XX also covers a
    /// *pending* inbound connection and an outbound dial still in flight.
    /// That breadth is required here — it is what admits the peer's inbound
    /// msg1 when the larger-`NodeAddr` side has `accept_connections: false`,
    /// without which the dual-init tie-breaker deadlocks — and is exactly
    /// what disqualifies it as a metering classifier, since an unpromoted
    /// stranger would then draw on the established-link bucket. Do not
    /// collapse the two into one predicate.
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
        // === CLASSIFY, THEN RATE LIMIT (both before any crypto) ===
        // Classification is one map lookup plus an O(peers) scan, and now runs
        // on every inbound msg1 including refused ones. See
        // `is_established_link_msg1` for why the scan is still needed.
        //
        // `_slot` is an RAII guard: it releases the limiter's pending slot on
        // drop, which is every return path below and the end of the function.
        // The binding name matters. Renaming it to a bare `_` drops the guard
        // right here instead, releasing the slot at acquire time — silently,
        // with no test and no clippy lint catching the difference. Do not
        // "tidy" this binding.
        //
        // Known coverage gap: `handle_msg1`'s slot is held across its `.await`
        // points by binding alone, and an early drop is unobserved by any
        // test. It is structurally unobservable at node level — `handle_msg1`
        // takes `&mut self`, so no second msg1 can be in flight to notice the
        // slot missing while this one awaits, and the pending count at return
        // is identical either way. The `#[must_use]` on `PendingHandshake` and
        // this comment are the only defences.
        let class = if self.is_established_link_msg1(packet.transport_id, &packet.remote_addr) {
            Msg1Class::EstablishedLink
        } else {
            Msg1Class::Stranger
        };
        // The binding name matters. `_slot` holds the guard until this
        // function returns, and that is what releases the pending slot on
        // every exit path. Renaming it to a bare `_` drops the guard right
        // here instead, releasing the slot at acquire time — silently, with
        // no clippy lint catching the difference. Do not "tidy" this
        // binding; the assertion below is what reds if it is tidied.
        let _slot = match self
            .msg1_rate_limiter
            .start_handshake(class, HostClock.now())
        {
            Ok(slot) => slot,
            Err(reason) => {
                debug!(
                    transport_id = %packet.transport_id,
                    remote_addr = %packet.remote_addr,
                    refused_by = %reason,
                    "Msg1 rate limited"
                );
                return;
            }
        };

        // Test-build witness for the paragraph above, and the only thing that
        // observes it. A guard released at acquire time leaves this msg1
        // in flight with its slot already back in the pool, which no counter,
        // log line or lint reports: by the time any test can look, the count
        // has returned to its baseline either way. Sampling it here, on the
        // handler's own stack, is what tells the two apart — see
        // `msg1_handler_holds_its_pending_slot_while_the_handler_runs`.
        #[cfg(test)]
        assert!(
            self.msg1_rate_limiter.pending_count() > 0,
            "the msg1 pending slot was released before the handler ran"
        );

        // accept_connections gate. Rekey/restart msg1 on an existing link
        // is always admitted; the gate only filters truly-fresh connections
        // from strangers. Without this carve-out, the dual-init tie-breaker
        // deadlocks when the larger-NodeAddr side has accept_connections=false.
        if !self.should_admit_msg1(packet.transport_id, &packet.remote_addr) {
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }

        // Parse header
        let header = match Msg1Header::parse(&packet.data) {
            Some(h) => h,
            None => {
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
        // link from this address with a pending connection that answered this
        // same msg1, resend its msg2. A different msg1 is a new attempt (a
        // rekey, a fresh dial after a restart, or a stale leg left by a replay
        // or an abandoned attempt) and gets its own leg: XX msg2 is bound to
        // the initiator's ephemeral in msg1, so the pending leg's msg2 cannot
        // answer it. The pending leg is not replaced, so a msg1 from this
        // address cannot discard a genuine leg awaiting its msg3.
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

                if is_active_peer {
                    // Active peer on this address — allow the new handshake.
                    // Identity checks (restart, rekey) deferred to handle_msg3.
                    debug!(
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        existing_link_id = %existing_link_id,
                        "XX msg1 from address with active peer — proceeding (identity check deferred to msg3)"
                    );
                } else if self.is_new_msg1_attempt(existing_link_id, &packet.data) {
                    // A pending handshake answered a different msg1 — give
                    // this one its own leg and leave that one for its msg3.
                    debug!(
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        existing_link_id = %existing_link_id,
                        "Msg1 differs from the one the pending handshake at this address answered; starting a new handshake"
                    );
                } else {
                    // Genuinely pending handshake — resend msg2. Like every
                    // reply on the rx loop it never dials: with the msg1's
                    // connection gone, a dial to its address (an inbound
                    // connection's ephemeral port) would hold the loop for up
                    // to the connect timeout.
                    let msg2_bytes = self.find_stored_msg2(existing_link_id);
                    if let Some(msg2) = msg2_bytes {
                        if let Some(transport) = self.transports.get(&packet.transport_id) {
                            match transport.send_existing(&packet.remote_addr, &msg2).await {
                                Ok(_) => debug!(
                                    remote_addr = %packet.remote_addr,
                                    transport_id = %packet.transport_id,
                                    link_id = %existing_link_id,
                                    "Resent msg2 for duplicate msg1"
                                ),
                                Err(e) => debug!(
                                    remote_addr = %packet.remote_addr,
                                    error = %e,
                                    transport_id = %packet.transport_id,
                                    link_id = %existing_link_id,
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
                    return;
                }
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

        // The control machine drives the handshake, so it is built here, above
        // the crypto. It stays a local: it enters `peer_machines` only at the
        // promote tails, so a rejected msg1 still leaves no registry trace and
        // allocates no index.
        let mut machine = PeerMachine::new_inbound(link_id, packet.timestamp_ms);
        // Seed the carrier with the transport and address msg1 arrived on, so
        // the promotion hand-off reads them from it.
        machine.set_conn_transport_id(packet.transport_id);
        machine.set_conn_source_addr(packet.remote_addr.clone());
        machine.set_leg(HandshakeCrypto::new());

        // Create FMP negotiation payload for msg2 (includes profile, MMP bits, bloom TLV)
        let neg_payload = NegotiationPayload::fmp(1, 1, self.node_profile()).encode();

        // This frame's own copy of the node's long-term private key; the
        // handshake state keeps its own and clears that on drop.
        let mut our_keypair = self.identity().keypair();
        let noise_msg1 = &packet.data[header.noise_msg1_offset..];
        let init_result = machine.receive_handshake_init(
            our_keypair,
            self.startup_epoch(),
            noise_msg1,
            Some(&neg_payload),
            packet.timestamp_ms,
        );
        our_keypair.non_secure_erase();
        let msg2_response = match init_result {
            Ok(m) => m,
            Err(e) => {
                debug!(
                    error = %e,
                    transport_id = %packet.transport_id,
                    remote_addr = %packet.remote_addr,
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

        // Allocate our session index. The leg's machine holds the lease on it
        // from here, and every exit of the leg hands the lease on or releases
        // it.
        let Some(our_lease) = allocate(&mut self.index_allocator) else {
            warn!(
                error = %crate::utils::index::IndexError::Exhausted,
                "Failed to allocate session index for inbound"
            );
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        };
        let our_index = SessionIndex::new(our_lease.index());

        machine.set_conn_their_index(header.sender_idx);

        // Create link
        let link = Link::connectionless(
            link_id,
            packet.transport_id,
            packet.remote_addr.clone(),
            LinkDirection::Inbound,
            Duration::from_millis(self.config().node.base_rtt_ms),
        );

        self.links.insert(link_id, link);
        // The key may already name a live link: an established peer's (a rekey
        // or restart msg1) or our own outbound dial (a crossing msg1). Record it
        // so `remove_link` hands the key back if this leg is disposed.
        if let Some(prior) = self.addr_to_link.insert(addr_key.clone(), link_id) {
            self.displaced_links.insert(link_id, (addr_key, prior));
        }

        // Build the msg2 response, storing it on the surviving carrier for
        // potential resend before the machine enters the registry below.
        let wire_msg2 = build_msg2(our_index, header.sender_idx, &msg2_response);

        // The machine built above the crypto now parks at `SentMsg2` awaiting
        // msg3 (identity is unknown until then), recording the index it owns.
        // It enters the registry before the msg2 send below so no suspension
        // point observes a handshake in flight without a machine. `handle_msg3`
        // steps this same machine; every teardown path disposes it along with
        // the Noise handles it carries.
        machine.park_inbound_msg2_sent(our_lease);
        // Store the framed msg2 on the surviving carrier for duplicate-msg1
        // resend while the handshake is still pending, and the msg1 it answers,
        // which tells that resend apart from a new attempt. An inbound leg
        // never resends msg1, so the resend deadline is moot.
        machine.set_conn_handshake_msg2(wire_msg2.clone());
        machine.set_conn_handshake_msg1(packet.data.clone(), 0);
        self.peer_machines.insert(link_id, machine);

        // The msg2 goes back on the msg1's connection and never dials: if that
        // connection has closed, a dial to its address (for an inbound
        // connection, the initiator's ephemeral port) would hold the rx loop
        // for up to the connect timeout. The failure tears the leg down below.
        if let Some(transport) = self.transports.get(&packet.transport_id) {
            match transport
                .send_existing(&packet.remote_addr, &wire_msg2)
                .await
            {
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
                    if !self.msg2_failed(link_id, &e) {
                        return;
                    }
                }
            }
        }

        // XX: handshake NOT complete yet — need msg3. A leg whose msg2 send
        // was deferred waits here too, for the initiator's msg1 resend.
        // Store in pending_inbound for msg3 dispatch.
        self.pending_inbound
            .insert((packet.transport_id, our_index.as_u32()), link_id);
    }

    /// Apply the msg2-send-failure rule to the inbound leg on `link`. Returns
    /// whether the leg was kept.
    ///
    /// A transient refusal is not a failed handshake. The interface under the
    /// transport is absent or mid-rebind and the binder is already working to
    /// bring it back, so the leg is left exactly as it is for the initiator's
    /// msg1 resend to land on, rather than being torn down and rebuilt.
    /// Tearing down charged a local interface flap to the remote: the reject
    /// counter it recorded means "the peer sent something invalid", which an
    /// operator reads as the peer's fault. Nothing leaks by staying: a leg
    /// nobody resends to is reaped at `handshake_timeout_secs` like every
    /// other abandoned handshake.
    ///
    /// A terminal error disposes the leg (handing its address back to any
    /// link it displaced), releases the lease on its index, removes the
    /// machine and records the reject.
    pub(in crate::node) fn msg2_failed(&mut self, link: LinkId, error: &TransportError) -> bool {
        if error.is_transient() {
            debug!(
                link_id = %link,
                error = %error,
                "Deferred msg2: the transport is between interfaces"
            );
            return true;
        }
        warn!(link_id = %link, error = %error, "Failed to send msg2");
        // Disposing the machine drops the Noise handles it carries.
        self.drop_leg(link);
        self.stats_mut()
            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
        false
    }

    /// Dispose the handshake leg on `link`: its link (handing its address
    /// back to any link it displaced), and its machine with the Noise handles
    /// it carries and the lease on the index the leg drew, which goes back to
    /// the allocator.
    pub(in crate::node) fn drop_leg(&mut self, link: LinkId) {
        self.remove_link(&link);
        self.remove_peer_machine(link);
    }

    /// Whether `msg1` is a different attempt from the one the pending inbound
    /// leg on `link` answered. A leg with no machine or no recorded msg1 is
    /// treated as answering it, which keeps the duplicate path's behaviour for
    /// it.
    fn is_new_msg1_attempt(&self, link: LinkId, msg1: &[u8]) -> bool {
        self.peer_machines
            .get(&link)
            .and_then(|machine| machine.conn_handshake_msg1())
            .is_some_and(|answered| answered != msg1)
    }

    /// Hand `packet`'s msg2, which names `peer`'s index, to that peer's link
    /// rekey machine: it completes the own rekey whose attempt the index
    /// names, or changes nothing, each counted and logged.
    async fn msg2_to_link(&mut self, peer: &NodeAddr, packet: &ReceivedPacket) {
        let Some((out, mismatch)) = self.step_link_reply(peer, &packet.data) else {
            return;
        };
        let report = self.run_link_step(peer, out).await;
        if report.pending {
            let p = self.peers.get(peer);
            debug!(
                peer = %self.peer_display_name(peer),
                new_our_index = %OrNone(p.and_then(|p| p.pending_our_index())),
                new_their_index = %OrNone(p.and_then(|p| p.pending_their_index())),
                epoch = %OrNone(p.and_then(|p| p.pending_new_session()).map(diag::epoch_tag)),
                kbit_ours = %OrNone(p.map(|p| p.current_k_bit())),
                "rekey-msg2 initiator: pending session set, awaiting K-bit cutover"
            );
        }
        for reason in report.rejects {
            match reason {
                // The msg2 read under a static other than the peer's: under
                // XX any keyed node that saw the cleartext rekey msg1 can
                // answer it. The machine keeps the attempt for the peer's own
                // msg2, and the current session is untouched. Counted apart
                // from routine noise: a sustained rate means an on-path party
                // is forging rekey msg2.
                Reason::ReplyUnauthenticated if mismatch => {
                    warn!(
                        peer = %self.peer_display_name(peer),
                        "rekey-msg2 initiator: learned static is not the established peer, keeping current session"
                    );
                    self.stats_mut().record_reject(RejectReason::Handshake(
                        HandshakeReject::RekeyStaticMismatch,
                    ));
                }
                // Nothing authenticated this msg2 before the read, and the
                // index it names travels in cleartext in our msg1, so it may
                // be a forgery: the machine keeps the attempt, its resends
                // and its deadline, so the genuine msg2 can still complete it.
                Reason::ReplyUnauthenticated => {
                    debug!(
                        peer = %self.peer_display_name(peer),
                        "Rekey msg2 did not authenticate, keeping the rekey cycle"
                    );
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                }
                // A duplicate or late copy of a msg2 that already completed,
                // or one for an attempt already given up.
                Reason::LateReply | Reason::UnknownAttempt | Reason::UnknownIndex => {
                    debug!(
                        peer = %self.peer_display_name(peer),
                        receiver_idx = ?Msg2Header::parse(&packet.data).map(|h| h.receiver_idx),
                        reason = ?reason,
                        "Rekey msg2 for no attempt in flight, dropping"
                    );
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::UnknownConnection));
                }
                other => {
                    warn!(
                        peer = %self.peer_display_name(peer),
                        reason = ?other,
                        "Rekey msg2 processing failed"
                    );
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                }
            }
        }
    }

    /// Hand the peer's rekey that an inbound leg completed, `fin`, to
    /// `peer`'s link rekey machine as a rekey of its session. The machine
    /// decides: it holds the new session as pending under the leg's index,
    /// or refuses it (a rekey of its own that wins the tie-break, a key other
    /// than the peer's) and releases the index. Each outcome is logged and
    /// counted.
    async fn peer_rekey_to_link(&mut self, peer: &NodeAddr, fin: LinkFinal) {
        if !self.peers.get(peer).is_some_and(ActivePeer::has_session) {
            if let Some(lease) = fin.into_lease() {
                let _ = self
                    .index_allocator
                    .free(SessionIndex::new(lease.release()));
            }
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::UnknownConnection));
            return;
        }
        let their_index = fin.theirs();
        let input = Input::PeerDone {
            tok: fin.into_rekey(),
            intent: Intent::Rekey,
        };
        let Some(out) = self.step_link(peer, input) else {
            return;
        };
        let report = self.run_link_step(peer, out).await;
        if report.pending {
            let held = self.peers.get(peer);
            debug!(
                peer = %self.peer_display_name(peer),
                our_addr = %self.identity().node_addr(),
                new_our_index = %OrNone(held.and_then(|p| p.pending_our_index())),
                new_their_index = %their_index,
                epoch = %OrNone(held.and_then(|p| p.pending_new_session()).map(diag::epoch_tag)),
                kbit_ours = %OrNone(held.map(|p| p.current_k_bit())),
                "rekey-msg3 responder: pending session set, awaiting K-bit cutover"
            );
        }
        for reason in report.rejects {
            match reason {
                // Both ends started a rekey and this node's wins the
                // tie-break: the peer's completion is released, and the
                // peer takes ours.
                Reason::TieBreakKept => debug!(
                    peer = %self.peer_display_name(peer),
                    "Dual rekey initiation: we win (smaller addr), keeping ours and releasing the peer's"
                ),
                Reason::KeyMismatch => {
                    warn!(
                        peer = %self.peer_display_name(peer),
                        "Link rekey msg3 authenticated a key other than the peer's, releasing it"
                    );
                    self.stats_mut().record_reject(RejectReason::Handshake(
                        HandshakeReject::RekeyStaticMismatch,
                    ));
                }
                other => {
                    debug!(
                        peer = %self.peer_display_name(peer),
                        reason = ?other,
                        "Link rekey msg3 refused by the link's rekey machine"
                    );
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                }
            }
        }
    }

    /// Find stored msg2 bytes for a given link (pre- or post-promotion).
    ///
    /// Checks the control machine's carrier (if still pending) and then the
    /// ActivePeer (if already promoted).
    fn find_stored_msg2(&self, link_id: LinkId) -> Option<Vec<u8>> {
        // Check pending connection first (its stored msg2 lives on the control
        // machine's carrier).
        if let Some(msg2) = self
            .peer_machines
            .get(&link_id)
            .and_then(|machine| machine.conn_handshake_msg2())
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

        // Look up our pending handshake by our sender_idx (receiver_idx in
        // msg2). A link-setup dial's index maps to its connection in
        // `pending_outbound`, whose control machine still carries the
        // handshake; a link rekey's attempt index is bound to its peer in
        // `peers_by_index`, and its peer's link machine reads the msg2.
        let key = (packet.transport_id, header.receiver_idx.as_u32());
        let setup = self.pending_outbound.get(&key).copied();
        let link_id = match setup {
            Some(id)
                if self
                    .peer_machines
                    .get(&id)
                    .is_some_and(|machine| machine.leg().is_some()) =>
            {
                id
            }
            _ => {
                if let Some(&peer) = self.peers_by_index.get(&key)
                    && self.peers.contains_key(&peer)
                {
                    self.msg2_to_link(&peer, &packet).await;
                    return;
                }
                debug!(
                    receiver_idx = %header.receiver_idx,
                    transport_id = %packet.transport_id,
                    remote_addr = %packet.remote_addr,
                    "No pending outbound handshake for index"
                );
                // A `pending_outbound` entry whose connection no longer
                // carries a handshake is stale: a state-machine
                // inconsistency, not a fresh lookup miss.
                let reject = if setup.is_some() {
                    self.pending_outbound.remove(&key);
                    HandshakeReject::BadState
                } else {
                    HandshakeReject::UnknownConnection
                };
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(reject));
                return;
            }
        };

        let our_profile = self.node_profile();
        let (peer_identity, dialed_peer, msg3_bytes, our_index) = {
            let Some(machine) = self.peer_machines.get_mut(&link_id) else {
                warn!(link_id = %link_id, "Connection removed during msg2 processing");
                self.pending_outbound.remove(&key);
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::UnknownConnection));
                return;
            };

            // Create FMP negotiation payload for msg3 (includes profile, MMP bits, bloom TLV)
            let neg_payload = NegotiationPayload::fmp(1, 1, our_profile).encode();

            // The dial intent, read off the carrier before the completion
            // below can write the learned identity onto it. `None` on an
            // anonymous shared-media leg.
            let dialed_peer = machine.conn_dialed_identity().map(|id| *id.node_addr());

            // Dial-identity gate. Under XX the responder's static arrives in
            // msg2 rather than being pinned at dial (as IK pinned it), so any
            // party that observes our msg1 can answer it with a msg2 that reads
            // correctly under its own static. Crypto success therefore proves
            // only that someone answered; the core decides whether that someone
            // is who we dialed. The machine runs the decision after the read and
            // before anything is consumed, so a substituted responder never gets
            // a msg3 and its identity never reaches the carrier.
            let fmp = &self.fmp;
            let decide = |learned_peer| {
                fmp.dial_outbound(&DialMsg2Snapshot {
                    dialed_peer,
                    learned_peer,
                })
            };

            // Process Noise msg2 and generate msg3
            let noise_msg2 = &packet.data[header.noise_msg2_offset..];
            let (msg3_bytes, received_negotiation) = match machine.complete_handshake(
                noise_msg2,
                Some(&neg_payload),
                packet.timestamp_ms,
                decide,
            ) {
                Ok(DialMsg2Step::Completed(msg3, negotiation)) => (msg3, negotiation),
                Ok(DialMsg2Step::Unreadable(e)) => {
                    // The index this msg2 names travels in cleartext in our
                    // msg1, so the msg2 may be a forgery rather than the peer's
                    // corrupt reply. The machine restored the handshake and left
                    // the carrier untouched, so keep the attempt with its
                    // dispatch entry, resend schedule and deadline for the
                    // genuine msg2. If none arrives, the handshake timeout ends
                    // the attempt as it would for a lost one. Logged at debug: a
                    // forger can send one of these per datagram.
                    debug!(
                        link_id = %link_id,
                        error = %e,
                        "msg2 did not authenticate, keeping the handshake attempt"
                    );
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
                Ok(DialMsg2Step::Rejected {
                    reason: DialMsg2Reject::StaticMismatch,
                    learned_peer,
                }) => {
                    // A msg2 that reads under a static other than the one
                    // dialed: an on-path party raced the peer's answer, or the
                    // address we dialed is no longer the peer we recorded there.
                    // Either way this msg2 never completes the leg. The machine
                    // restored the handshake and left the carrier's expected
                    // identity at the dialed peer, so the attempt is kept as it
                    // was for the dialed peer's own msg2; if none arrives, the
                    // handshake timeout ends it and reschedules the dial against
                    // the dialed peer. Logged at debug: any keyed node that sees
                    // the msg1 can produce one of these per datagram.
                    debug!(
                        link_id = %link_id,
                        dialed = ?dialed_peer,
                        learned = %learned_peer,
                        "msg2 answered by a different static than the one dialed, keeping the handshake attempt"
                    );
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
                Err(e) => {
                    warn!(
                        link_id = %link_id,
                        error = %e,
                        "Handshake completion failed"
                    );
                    // The leg had no handshake to read with, or completing an
                    // accepted msg2 failed after the handshake was taken: the
                    // leg cannot continue. Drop the Noise handle and record the
                    // failure on the control machine as `send_failed` — the
                    // failure state's home. The machine PHASE stays exactly
                    // where the old failure left it (`Handshaking{SentMsg1}`):
                    // the stale-connection sweep reclaims the handshake via the
                    // machine `is_failed()` at the next tick, before any
                    // projection or resend.
                    machine.mark_failed();
                    machine.mark_send_failed();
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
            };

            // Process peer's FMP negotiation payload from msg2
            if let Some(neg_bytes) = &received_negotiation {
                match process_fmp_negotiation(our_profile, machine, neg_bytes) {
                    Ok(()) => {}
                    Err(e) => {
                        warn!(link_id = %link_id, our_profile = %our_profile, error = %e, "FMP negotiation failed");
                        // Failure moves to the machine (`send_failed`); the phase
                        // stays `Handshaking{SentMsg1}` so the sweep reclaims the
                        // handshake exactly as the pre-collapse mark did.
                        machine.mark_failed();
                        machine.mark_send_failed();
                        self.stats_mut()
                            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        return;
                    }
                }
            }

            // Store their index
            machine.set_conn_their_index(header.sender_idx);
            machine.set_conn_source_addr(packet.remote_addr.clone());

            // Get peer identity for promotion (learned from msg2 in XX)
            let peer_identity = match machine.conn_expected_identity() {
                Some(id) => *id,
                None => {
                    warn!(link_id = %link_id, "No identity after handshake");
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
            };

            let our_index = machine.our_index();

            (peer_identity, dialed_peer, msg3_bytes, our_index)
        };

        let peer_node_addr = *peer_identity.node_addr();

        // The completion `touch` and the negotiated peer profile are written
        // directly onto the surviving carrier by `complete_handshake` and
        // `process_fmp_negotiation` above, so last-activity advances at msg2
        // completion and the promotion hand-off reads the profile from it.

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
            // and its pending connection and the lease on the index it drew
            // at msg1 preparation go with it, never the `receiver_idx` the
            // msg2 header supplied.
            self.remove_peer_machine(link_id);
            self.remove_link(&link_id);
            // Put the dial back on the retry schedule. The disposal above takes
            // this leg out of both reapers, so the stuck-leg sweep that normally
            // reaches `note_handshake_timeout` never runs for it, and that
            // reflex is the only thing that seeds `retry_pending` for a
            // configured peer.
            //
            // Targets `dialed_peer`, the dial-time expectation, NOT
            // `peer_identity` — the completion above already overwrote the
            // machine's expected identity with the answering static, so reading
            // that here would reschedule against whoever answered.
            if let Some(peer) = dialed_peer {
                self.note_handshake_timeout(peer, Self::peering_now());
            }
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }

        if peer_node_addr == *self.identity().node_addr() {
            // Reachable by any outbound leg whose msg2 static key turns out to
            // be our own: an anonymous shared-media beacon that echoed us back
            // at ourselves, or a dial that named our own identity and reached
            // it. An identified dial that reached someone ELSE no longer
            // arrives here — the dial-identity gate above catches it first,
            // and only a dialed == learned == us leg gets this far. This leg
            // never promotes; its machine goes with it (dropping the embedded
            // pending connection), and everything else the leg holds — the
            // index, the link, and the `pending_outbound` entry — goes with it.
            //
            // Link disposal goes through `remove_link`, never a bare
            // `links.remove` plus `addr_to_link.remove`. We have answered our own
            // msg1, so `handle_msg1` has already overwritten
            // `addr_to_link[(tid, self_addr)]` with the INBOUND leg's link;
            // `remove_link` clears the reverse entry only when it still points at
            // the link being removed, so it correctly leaves the live inbound
            // leg's mapping alone. A hand-rolled removal would destroy it.
            debug!(link_id = %link_id, "Discovered self via shared-media beacon, dropping");
            self.pending_outbound.remove(&key);
            self.remove_peer_machine(link_id);
            self.remove_link(&link_id);
            // Put the dial back on the retry schedule. The disposal above takes
            // this leg out of the stuck-leg sweep — `has_pending_leg` reads false
            // for it from here on, so the reap that normally reaches
            // `note_handshake_timeout` never runs — and that reflex is the only
            // thing that seeds `retry_pending` for a configured peer.
            // `close_connection` only drops the transport's pool entry; it
            // schedules nothing.
            //
            // `peer_identity` is safe to reschedule against here because this is
            // an IK dial: the initiator's expected identity is fixed at
            // `start_handshake` and `complete_handshake` never overwrites it, so
            // it is still the peer we meant to dial and not whoever answered.
            self.note_handshake_timeout(*peer_identity.node_addr(), Self::peering_now());
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }

        // Build and send msg3, on the msg2's connection. A reply on the rx
        // loop, so it never dials: with that connection gone the send fails
        // at once and the sweep reclaims the handshake, as on any send failure.
        let our_index = our_index.unwrap_or(header.receiver_idx);
        let wire_msg3 = build_msg3(our_index, header.sender_idx, &msg3_bytes);

        if let Some(transport) = self.transports.get(&packet.transport_id) {
            match transport
                .send_existing(&packet.remote_addr, &wire_msg3)
                .await
            {
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
                    // Failure moves to the machine (`send_failed`); the phase
                    // stays `Handshaking{SentMsg1}` (promote has not run yet) so
                    // the sweep reclaims the handshake exactly as the
                    // pre-collapse mark did.
                    if let Some(machine) = self.peer_machines.get_mut(&link_id) {
                        machine.mark_failed();
                        machine.mark_send_failed();
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
        //
        // The same holds when the peer was promoted via an earlier dial of
        // ours: the peer answers this later dial on a fresh leg and resolves
        // its msg3 by the same address order.
        // The machine is the sole computation site of the establish decision:
        // the shell builds the outbound snapshot, steps the machine once here,
        // and routes on the returned decision — a cross-connection resolves as
        // a single `ResolveCrossConnection { swap }` action, a net-new
        // establish as the promote action sequence. The Swap/Keep resolution
        // bodies stay inline in the shell because they mutate the already
        // promoted peer via `move_session`, for which no `PeerAction`
        // exists. The machine was persisted at DIAL, so the executor's
        // `PromoteToActive` arm can feed `PromotionResolved` back via the same
        // lookup; the `pending_outbound` lifecycle stays shell-side — the
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
            let (taken_conn, carrier_our_index, sent_msg1_digest) =
                match self.peer_machines.get_mut(&link_id) {
                    Some(machine) => (
                        machine.take_leg(),
                        machine.take_our_index(),
                        machine.conn_handshake_msg1().map(Msg1Digest::of),
                    ),
                    None => (None, None, None),
                };
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
                // We're the smaller node, or the peer's answer to this dial
                // supersedes our earlier dial's. Swap to outbound session +
                // indices. The peer keeps the session it answered this dial
                // with (complement of ours).
                let outbound_our_index = carrier_our_index;
                let outbound_session = conn.noise_session.take();

                let (outbound_session, outbound_lease) = match (
                    outbound_session,
                    outbound_our_index,
                ) {
                    (Some(s), Some(lease)) => (s, lease),
                    _ => {
                        warn!(peer = %self.peer_display_name(&peer_node_addr), "Incomplete outbound connection");
                        self.pending_outbound.remove(&key);
                        self.stats_mut()
                            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        return;
                    }
                };
                let outbound_our_index = SessionIndex::new(outbound_lease.index());
                let local = self.session_node_keys();
                let me = *self.identity().node_addr();
                let params = crate::node::handlers::rekey::link_params(&self.config().node);
                let workers = self.link_workers();
                let profile = self.node_profile();

                if let Some(peer) = self.peers.get_mut(&peer_node_addr) {
                    let suppressed = peer.replay_suppressed_count();
                    let epoch = diag::epoch_tag(&outbound_session);
                    // The peer's link machine is closed and rebuilt on the
                    // outbound session: what it held is unbound and freed,
                    // the outbound index bound on the peer's transport.
                    let mut caps = LinkCaps {
                        indices: &mut self.index_allocator,
                        local: &local,
                        me,
                        params,
                        record: Record::new(),
                        workers,
                        profile,
                    };
                    let out = peer.move_session(
                        outbound_session,
                        outbound_lease,
                        header.sender_idx,
                        &mut caps,
                    );
                    self.run_link_outputs(&peer_node_addr, out);

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
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        msg1_sidx = %outbound_our_index,
                        msg1_dg = %OrNone(sent_msg1_digest.as_ref().map(diag::msg1_tag)),
                        epoch = %epoch,
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
                let outbound_our_index = carrier_our_index;

                if let Some(peer) = self.peers.get(&peer_node_addr) {
                    debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        kept_their_index = ?peer.their_index(),
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        epoch = %OrNone(peer.noise_session().map(diag::epoch_tag)),
                        "Cross-connection: keeping inbound session and original their_index (peer outbound wins)"
                    );
                }

                // Free the outbound's session index since we're not using it
                if let Some(lease) = outbound_our_index {
                    let _ = self
                        .index_allocator
                        .free(SessionIndex::new(lease.release()));
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
            // Close the losing leg's connection: a separate socket on TCP, a
            // no-op when connectionless, and left open when it is the very
            // connection the promoted peer runs on (BLE), where closing would
            // take the msg3 just queued, and the link, with it.
            self.close_handshake_link_connection(link_id).await;
            self.remove_link(&link_id);

            // Send TreeAnnounce now that sessions are aligned
            if let Err(e) = self.send_tree_announce_to_peer(&peer_node_addr).await {
                debug!(peer = %self.peer_display_name(&peer_node_addr), error = %e, "Failed to send TreeAnnounce after cross-connection resolution");
            }
            // Schedule filter announce (sent on a tick once the peer has sent a frame)
            self.bloom_state.mark_update_needed(peer_node_addr);
            self.reset_lookup_backoff();
            return;
        }

        // === Net-new outbound establish, driven by the machine. ===
        // This arm is reached with no existing peer, or with one the msg2
        // shows has restarted, which the machine's leading
        // `[InvalidateSendState, ReportLost]` removes before the promotion
        // (FRC-1201 Section 5.5: no tie-break). Either way
        // `promote_connection` finds no existing peer and returns
        // `Promoted`; the defensive `CrossConnectionWon/Lost` follow-ups
        // are UNREACHABLE here.
        //
        // The outbound Msg2 Promote step cancels the two dial-armed handshake
        // timers (the machine survives promotion, so they would otherwise linger
        // in `peer_timers` until `drive_peer_timers` lazily discards them — the
        // promoted leg's pending connection is consumed and the machine has left
        // `SentMsg1`, so they can no longer fire) and then promotes.
        // `PromoteToActive` is what performs the promotion.
        let promote = [
            PeerAction::CancelTimer {
                kind: TimerKind::HandshakeRetransmit,
            },
            PeerAction::CancelTimer {
                kind: TimerKind::HandshakeTimeout,
            },
            PeerAction::PromoteToActive { link: link_id },
        ];
        let restarted = actions.first() == Some(&PeerAction::InvalidateSendState);
        debug_assert!(actions.ends_with(&promote));
        debug_assert_eq!(actions.len(), if restarted { 5 } else { 3 });
        if restarted {
            info!(
                peer = %self.peer_display_name(&peer_node_addr),
                link_id = %link_id,
                "Peer restart detected on our dial (epoch mismatch), replacing the stale peer"
            );
        }

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
                // A link rekey's initiator resends its msg3 until it hears the
                // peer under the new session, so copies keep arriving after
                // the leg handed the first to the peer's link rekey machine,
                // which binds the leg's index for the peer. Such a copy changes
                // nothing and is not counted against the peer.
                if let Some(peer) = self.peers_by_index.get(&key).copied() {
                    debug!(
                        peer = %self.peer_display_name(&peer),
                        receiver_idx = %header.receiver_idx,
                        "Rekey msg3 copy for a rekey the link's machine already holds, dropping"
                    );
                    return;
                }
                // No pending inbound handshake matches this msg3.
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
        let (peer_identity, our_index, remote_epoch, declared_rekey_of) = {
            // Get the pending connection
            let machine = match self.peer_machines.get_mut(&link_id) {
                Some(m) => m,
                None => {
                    // The pending-inbound entry outlived its machine. No path
                    // to this arm has been found. The lease on the leg's index
                    // lived on the machine, so it went with it, and nothing
                    // here owns an index to release: the receiver index is a
                    // wire field the sender chooses, and freeing it could tear
                    // down an unrelated session that holds it now.
                    //
                    // The link goes: it has no machine, its pending-inbound
                    // key is already gone, and `LinkId`s come from a monotonic
                    // counter (`allocate_link_id`) so a stale value can never
                    // name a different live connection. `remove_link` drops the
                    // `addr_to_link` reverse entry only if it still points
                    // here, so a newer leg on the same address is untouched,
                    // and hands it back to the link this leg displaced at msg1
                    // if that link is still live.
                    debug!(
                        link_id = %link_id,
                        receiver_idx = %header.receiver_idx,
                        "No pending connection for msg3"
                    );
                    self.remove_link(&link_id);
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::UnknownConnection));
                    return;
                }
            };

            // Read msg3 on a fork of the leg's handshake: it learns the
            // initiator's identity, epoch and negotiation payload.
            match machine.read_final(&packet.data, packet.timestamp_ms) {
                Ok(()) => {}
                Err(Msg3Error::Unreadable) => {
                    // The leg and its lease are untouched; put its
                    // pending-inbound entry back so the genuine msg3, or the
                    // initiator's resend, still finds it. Debug, not warn:
                    // anyone who saw msg2's cleartext header can send these.
                    debug!(link_id = %link_id, "Unreadable msg3, keeping the pending leg");
                    self.pending_inbound.insert(key, link_id);
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
                Err(e @ Msg3Error::Failed(_)) => {
                    warn!(
                        link_id = %link_id,
                        error = %e,
                        "Msg3 processing failed"
                    );
                    self.drop_leg(link_id);
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
            }
            let Some(read) = machine.final_read() else {
                debug_assert!(false, "a msg3 that read leaves its read on the leg");
                self.drop_leg(link_id);
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
            };
            let peer_identity = PeerIdentity::from_pubkey_full(*read.remote());
            let remote_epoch = Some(read.epoch());
            let negotiated = read.negotiate(our_profile);
            // The sender's rekey declaration. A present-but-malformed marker
            // is a hard failure: reading it as "not a rekey" would be exactly
            // the silent fall-through this field exists to remove.
            let declared = read.declared();

            // Process peer's FMP negotiation payload from msg3
            match negotiated {
                Ok(Some(their_profile)) => {
                    machine.set_conn_peer_profile(their_profile);
                    debug!(
                        link_id = %link_id,
                        our_profile = %our_profile,
                        peer_profile = %their_profile,
                        "FMP negotiation complete"
                    );
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(link_id = %link_id, our_profile = %our_profile, error = %e, "FMP negotiation failed");
                    // This arm sits ahead of the inbound ACL gate, so any
                    // peer able to complete a Noise msg3 reaches it without
                    // being authorized; the leg's lease goes back with it.
                    self.drop_leg(link_id);
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
            }

            let declared_rekey_of = match declared {
                Ok(claim) => claim,
                Err(e) => {
                    warn!(link_id = %link_id, error = %e, "Malformed rekey marker in msg3");
                    // This arm is reachable before the ACL gate, so leaking
                    // the leg's index would let any peer that can complete a
                    // msg3 grow the allocator set one entry per malformed
                    // marker; the lease goes back with the leg.
                    self.drop_leg(link_id);
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
            };

            // `pending_inbound` is keyed by the index the leg drew at msg1, so
            // the msg3's receiver index is the leg's own.
            let our_index = header.receiver_idx;

            (peer_identity, our_index, remote_epoch, declared_rekey_of)
        };

        let peer_node_addr = *peer_identity.node_addr();

        // The negotiated peer profile is written straight onto the surviving
        // carrier by `process_fmp_negotiation` above, so the promotion hand-off
        // reads it from there.

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
            let reject_info = match self.peer_machines.get_mut(&link_id) {
                Some(machine) => {
                    machine.settle_setup();
                    match (machine.conn_their_index(), machine.take_session()) {
                        (Some(idx), Some(session)) => Some((idx, session)),
                        _ => None,
                    }
                }
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
            // The leg's lease is released after the send: the reject signal is
            // built from state on the machine and is this arm's user-visible
            // behaviour.
            self.drop_leg(link_id);
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }

        if peer_node_addr == *self.identity().node_addr() {
            debug!(link_id = %link_id, "Received msg3 from self, dropping");
            self.drop_leg(link_id);
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
        // Identity-based restart/rekey/cross-connection classification.
        //
        // Now that we know the initiator's identity from msg3, classify this
        // inbound handshake against any existing active peer. The leg's machine
        // evaluates the pure `establish_inbound` decision once and returns it with
        // the arm's action stream; the driver routes on the decision below,
        // running the actions through the executor and owning only the residual
        // shell bookkeeping (link/map removal, reject records, the duplicate-msg2
        // resend). The snapshot resolves the one clock read (session age) and the
        // sender's rekey declaration up front.
        //
        // The declaration replaces a session-age floor that used to partition
        // "too young to be a rekey" from "old enough to be one". That floor was
        // never sound: a message-count-triggered rekey fires on a young session,
        // so a real rekey could land below it and be resolved as a
        // cross-connection, leaving the two ends on different session indices.
        let our_node_addr = *self.identity().node_addr();

        // Resolve the sender's declaration against the sessions we hold.
        // Matched ONLY against the peer this handshake authenticated as, never
        // through a global index map — otherwise one peer could name another's
        // index and steer a decision about that peer's session.
        let rekey_claim = match declared_rekey_of {
            None => RekeyClaim::None,
            Some(declared) => match self.peers.get(&peer_node_addr) {
                Some(peer) if peer.declares_own_session(declared) => RekeyClaim::Matches,
                _ => RekeyClaim::Mismatch,
            },
        };

        let wire = WireOutcome {
            peer_node_addr,
            remote_epoch,
        };
        let silent_backoff = self
            .silent_sessions
            .refusing(&peer_node_addr, crate::time::mono_ms());
        let snap = match self.peers.get(&peer_node_addr) {
            Some(existing_peer) => EstablishSnapshot {
                has_existing_peer: true,
                existing_peer_epoch: existing_peer.remote_epoch(),
                has_session: existing_peer.has_session(),
                stored_msg2: existing_peer.handshake_msg2().map(|m| m.to_vec()),
                different_link: existing_peer.link_id() != link_id,
                rekey_claim,
                our_node_addr,
                peering_idle_ms: existing_peer.idle_time(Self::now_ms()),
                epoch_restart_dampened: self
                    .restart_dampener
                    .get(&peer_node_addr)
                    .is_some_and(|t| t.elapsed().as_secs() < EPOCH_RESTART_MIN_INTERVAL_SECS),
                silent_backoff,
            },
            None => EstablishSnapshot {
                has_existing_peer: false,
                existing_peer_epoch: None,
                has_session: false,
                stored_msg2: None,
                different_link: false,
                rekey_claim,
                our_node_addr,
                // No existing peering, so neither gate applies.
                peering_idle_ms: u64::MAX,
                epoch_restart_dampened: false,
                silent_backoff,
            },
        };

        // Single inbound classification site. The leg's PERSISTENT machine — born
        // at msg1, parked `SentMsg2` — evaluates `establish_inbound` once and
        // returns both the decision (for the driver to route on) and the arm's
        // action stream. The terminal reject/duplicate arms carry their
        // `FreeIndex` (releasing the lease the leg drew at msg1) as a machine
        // action; a declared rekey leaves the leg's read, with the lease, for
        // the peer's link rekey machine. The driver owns only the link/map
        // removal and the reject bookkeeping, since the machine cannot remove
        // itself from the map.
        let (decision, actions) = match self.peer_machines.get_mut(&link_id) {
            // Disjoint field borrow: `self.peer_machines` (the map entry) and
            // `self.index_allocator` (the capability) are separate fields.
            Some(machine) => {
                machine.inbound_msg3(wire, snap, packet.timestamp_ms, &mut self.index_allocator)
            }
            None => {
                // The machine was read a few lines above and nothing between
                // removes it. Were it gone, the lease on the leg's index went
                // with it, and an index named by the wire is never freed.
                debug_assert!(false, "peer machine present for every pending inbound leg");
                self.remove_link(&link_id);
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
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
                reason: InboundReject::EpochRestartDampened,
            } => {
                // The msg1 is authentic but would destroy a peering that is
                // still carrying authenticated traffic, or it is a second epoch
                // change inside the dampening interval. No msg2 goes back: the
                // stored msg2 is bound to the original msg1's ephemeral, and
                // answering an address the sender chose is free amplification.
                if self.shown(&peer_node_addr, HsLine::Restart) {
                    debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        "Epoch mismatch dampened, dropping msg1"
                    );
                }
                self.execute_peer_actions(link_id, &ambient, actions).await;
                self.remove_link(&link_id);
                self.remove_peer_machine(link_id);
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            }
            InboundDecision::Reject {
                reason: InboundReject::SilentBackoff,
            } => {
                // The identity's last sessions at this epoch carried no frame
                // and its back-off is running. On XX the identity is first
                // known here, after our msg2 has gone, so the refusal is to
                // promote: no msg2 resend, no peer entry, no TreeAnnounce. The
                // machine's `FreeIndex` returns the msg1-allocated index.
                // Counted on the identity's record, since a refused handshake
                // has no peer entry to count on.
                let shown = self
                    .silent_sessions
                    .note_refused(&peer_node_addr)
                    .is_none_or(|n| self.show(&peer_node_addr, HsLine::Refused, n));
                if shown {
                    debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        silent = %OrNone(silent_backoff.map(|b| b.silent)),
                        remaining_s = %OrNone(silent_backoff.map(|b| b.remaining_ms.div_ceil(1000))),
                        "Msg3 from a peer whose recent sessions carried no frame, refusing during its back-off"
                    );
                }
                self.execute_peer_actions(link_id, &ambient, actions).await;
                debug_assert!(
                    !self.index_allocator.is_allocated(our_index),
                    "inbound index freed exactly once via the machine action"
                );
                self.remove_link(&link_id);
                self.remove_peer_machine(link_id);
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::SilentBackoff));
            }
            InboundDecision::PeerRekey { peer } => {
                // The peer's msg3 declares a rekey of the link we hold with it:
                // the leg's read, with the lease on its index, goes to the
                // peer's link rekey machine, which decides whether it takes
                // it. The leg itself is done; its link goes without closing a
                // transport connection, handing the peer's address back to the
                // peer's link.
                let fin = self
                    .peer_machines
                    .get_mut(&link_id)
                    .and_then(PeerMachine::take_final);
                self.execute_peer_actions(link_id, &ambient, actions).await;
                self.remove_link(&link_id);
                self.remove_peer_machine(link_id);
                match fin {
                    Some(fin) => self.peer_rekey_to_link(&peer, fin).await,
                    None => {
                        debug_assert!(false, "a declared rekey leaves its read on the leg");
                        self.stats_mut()
                            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    }
                }
            }
            InboundDecision::RepeatMsg2 { msg2 } => {
                // Not a rekey — duplicate handshake from same epoch. Resend the
                // stored msg2 bytes as-is (a driver mechanism: replaying the
                // stored frame, not rebuilding it), leaving the active peer
                // untouched. On the msg3's connection, never dialing.
                if let Some(msg2) = msg2
                    && let Some(transport) = self.transports.get(&packet.transport_id)
                {
                    let sent = transport.send_existing(&packet.remote_addr, &msg2).await;
                    // Each guard counts the line its arm logs; a suppressed
                    // line falls through to the empty arm.
                    match sent {
                        Ok(_) if self.shown(&peer_node_addr, HsLine::Resend) => debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            "Resent msg2 for duplicate handshake (same epoch)"
                        ),
                        Err(e) if self.shown(&peer_node_addr, HsLine::ResendFailed) => debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            error = %e,
                            "Failed to resend msg2"
                        ),
                        _ => {}
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
                self.remove_link(&link_id);
                self.remove_peer_machine(link_id);
            }
            decision @ (InboundDecision::RestartThenPromote { .. }
            | InboundDecision::Promote
            | InboundDecision::CrossConnect { .. }) => {
                // Preserve the epoch-mismatch restart breadcrumb — it fires before
                // the machine's teardown actions run, matching the pre-refactor
                // order (breadcrumb → remove_active_peer → note_link_dead → promote).
                if let InboundDecision::RestartThenPromote { peer } = &decision {
                    debug!(
                        peer = %self.peer_display_name(peer),
                        "Peer restart detected (epoch mismatch), removing stale session"
                    );
                    // Stamped on acceptance only. A refusal that slid the window
                    // would let a sustained replay starve a genuinely restarting
                    // peer for as long as it kept sending.
                    let cutoff = Duration::from_secs(EPOCH_RESTART_MIN_INTERVAL_SECS);
                    self.restart_dampener.retain(|_, t| t.elapsed() < cutoff);
                    self.restart_dampener.insert(*peer, Instant::now());
                }
                // Machine-driven inbound establish/rekey resolution. The leg's
                // PERSISTENT machine emitted the action stream alongside the
                // decision:
                //   `[PromoteToActive]` for `Promote`;
                //   `[InvalidateSendState, ReportLost, PromoteToActive]` for
                //     `RestartThenPromote` (the two teardown actions map to
                //     `remove_active_peer` / `note_link_dead`, in that order);
                //   `[ResolveInboundCrossConnection]` for a simultaneous-init cross-connection.
                // On a promote the machine survives and crystallizes in place via
                // the executor's `PromotionResolved` feedback; on the other arm the
                // executor's teardown disposes it with the leg. The relocated
                // session-swap / promote / teardown bodies live in the executor's
                // `ResolveInboundCrossConnection` / `PromoteToActive` /
                // `InvalidateSendState` / `ReportLost` arms.
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
            // Dispose of the machine with the Noise handles it carries and the
            // lease on the index the handshake allocated.
            self.remove_link(&link_id);
            self.remove_peer_machine(link_id);
            return Err(NodeError::MaxPeersExceeded { max: 1 });
        }

        // Take the pending connection off its control machine, and read the
        // carrier fields the promotion needs in the same borrow. The machine
        // survives the promotion (it becomes the active peer's control
        // machine), left with no pending connection.
        //
        // The connection is detached before anything is validated, so every
        // error return below leaves the machine leg-less — the caller disposes
        // of it. Gathering the carrier reads up front is only a borrow shape:
        // they are infallible, so the order in which the missing-field errors
        // are reported below is unchanged.
        let machine = self
            .peer_machines
            .get_mut(&link_id)
            .ok_or(NodeError::ConnectionNotFound(link_id))?;
        let mut connection = machine
            .take_leg()
            .ok_or(NodeError::ConnectionNotFound(link_id))?;
        let carrier_our_index = machine.our_index();
        let carrier_their_index = machine.conn_their_index();
        let carrier_transport_id = machine.conn_transport_id();
        let carrier_source_addr = machine.conn_source_addr().cloned();
        let carrier_is_outbound = machine.conn_is_outbound();
        let carrier_remote_epoch = machine.conn_remote_epoch();
        let link_stats = machine.conn_link_stats().clone();
        // The negotiated peer profile, read from the same carrier borrow.
        let peer_profile = machine
            .conn_peer_profile()
            .unwrap_or(crate::proto::fmp::NodeProfile::Full);
        let direction = machine.conn_direction();
        // The msg1 this link was set up by: the one this node sent, or the
        // one it answered. Both are kept on the carrier.
        let msg1_digest = machine.conn_handshake_msg1().map(Msg1Digest::of);

        // Verify handshake is complete and extract session
        if connection.noise_session.is_none() {
            return Err(NodeError::HandshakeIncomplete(link_id));
        }

        let noise_session = connection
            .noise_session
            .take()
            .ok_or(NodeError::NoSession(link_id))?;

        let our_index = carrier_our_index.ok_or_else(|| NodeError::PromotionFailed {
            link_id,
            reason: "missing our_index".into(),
        })?;
        let their_index = carrier_their_index.ok_or_else(|| NodeError::PromotionFailed {
            link_id,
            reason: "missing their_index".into(),
        })?;
        let transport_id = carrier_transport_id.ok_or_else(|| NodeError::PromotionFailed {
            link_id,
            reason: "missing transport_id".into(),
        })?;
        let current_addr = carrier_source_addr.ok_or_else(|| NodeError::PromotionFailed {
            link_id,
            reason: "missing source_addr".into(),
        })?;
        let remote_epoch = carrier_remote_epoch;
        // The lease that holds `our_index` moves from the carrier to the
        // promoted peer's link rekey machine, or back to the allocator.
        let our_lease = self
            .peer_machines
            .get_mut(&link_id)
            .and_then(PeerMachine::take_our_index)
            .ok_or_else(|| NodeError::PromotionFailed {
                link_id,
                reason: "missing our_index".into(),
            })?;

        let peer_node_addr = *verified_identity.node_addr();
        let is_outbound = carrier_is_outbound;

        // The key both promotion paths seed the path MTU map under.
        let peer_key = crate::ipv6tun::link::PeerKey::from_xonly(&verified_identity.pubkey());

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
                let Some(mut old_peer) = self.peers.remove(&peer_node_addr) else {
                    return Err(NodeError::PeerNotFound(peer_node_addr));
                };
                let loser_link_id = old_peer.link_id();

                // The replaced (losing) peer was established and so
                // carried a machine keyed by its OWN link_id (loser_link_id);
                // drop it so no machine orphans when its ActivePeer is removed.
                // The winning connection's machine is inserted below keyed by
                // the winner link_id. NEUTRAL: nothing reads peer_machines yet.
                self.remove_peer_machine(loser_link_id);

                // Clean up the old peer's indices from peers_by_index,
                // unregistering each from the decrypt worker pool BEFORE
                // freeing it for reuse. Otherwise the worker's per-shard
                // HashMap retains a stale entry pointing at the removed
                // peer's session; if the index allocator later recycles the
                // index to a different peer, the new register call
                // overwrites the stale entry — but until that point, decrypt
                // jobs that land at the recycled cache_key resolve to the
                // wrong session and AEAD silently fails.
                self.release_peer_indices(&peer_node_addr, &mut old_peer);

                if remote_epoch_changed {
                    if self.close_session(&peer_node_addr) {
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

                self.seed_path_mtu_for_link_peer(
                    &peer_node_addr,
                    peer_key,
                    transport_id,
                    &current_addr,
                );

                let (mut new_peer, out) = self.keyed_peer(
                    link_id,
                    verified_identity,
                    current_time_ms,
                    noise_session,
                    our_lease,
                    their_index,
                    transport_id,
                    current_addr,
                    link_stats,
                    is_outbound,
                    remote_epoch,
                    self.node_profile(),
                    peer_profile,
                )?;
                new_peer.set_tree_announce_min_interval_ms(
                    self.config().node.tree.announce_min_interval_ms,
                );

                self.peers.insert(peer_node_addr, new_peer);
                // The winning leg's machine (keyed by the winner link) survives
                // the promotion; the executor crystallizes it in place via the
                // `PromotionResolved` feedback after this returns.
                self.run_link_outputs(&peer_node_addr, out);
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

                Ok(PromotionResult::CrossConnectionWon {
                    loser_link_id,
                    node_addr: peer_node_addr,
                })
            } else {
                // This connection loses, keep existing
                // Free the index we allocated
                let _ = self
                    .index_allocator
                    .free(SessionIndex::new(our_lease.release()));

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
                .filter(|(_, machine)| {
                    machine
                        .conn_expected_identity()
                        .map(|id| *id.node_addr() == peer_node_addr)
                        .unwrap_or(false)
                })
                .map(|(_, machine)| machine.link_id())
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
                let _ = self
                    .index_allocator
                    .free(SessionIndex::new(our_lease.release()));
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

            self.seed_path_mtu_for_link_peer(
                &peer_node_addr,
                peer_key,
                transport_id,
                &current_addr,
            );

            let remote_addr = current_addr.clone();
            let epoch = diag::epoch_tag(&noise_session);
            // The msg1's sender index is the initiator's, so both ends log
            // the same one.
            let msg1_sidx = if is_outbound { our_index } else { their_index };
            let (mut new_peer, out) = self.keyed_peer(
                link_id,
                verified_identity,
                current_time_ms,
                noise_session,
                our_lease,
                their_index,
                transport_id,
                current_addr,
                link_stats,
                is_outbound,
                remote_epoch,
                self.node_profile(),
                peer_profile,
            )?;
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
            self.run_link_outputs(&peer_node_addr, out);
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
                transport_id = %transport_id,
                remote_addr = %remote_addr,
                direction = %direction,
                msg1_sidx = %msg1_sidx,
                msg1_dg = %OrNone(msg1_digest.as_ref().map(diag::msg1_tag)),
                epoch = %epoch,
                "Connection promoted to active peer"
            );

            Ok(PromotionResult::Promoted(peer_node_addr))
        }
    }

    /// Build the active peer of a link whose setup completed with
    /// `noise_session`: its link rekey machine takes the session as its first
    /// epoch, under `our_index` (the lease link setup took) and the peer's
    /// `their_index`, bound on `transport_id`, and is offered to the decrypt
    /// workers when a pool runs. `our_profile` and `peer_profile` are the two
    /// ends' negotiated node profiles. Returns the peer and the machine's
    /// outputs (the binding of `our_index` and any offer), to execute once
    /// the peer is in the table. A session that authenticated another key
    /// than `verified_identity`'s, which a completed handshake never has,
    /// frees the index and fails the promotion.
    #[allow(clippy::too_many_arguments)]
    fn keyed_peer(
        &mut self,
        link_id: LinkId,
        verified_identity: PeerIdentity,
        current_time_ms: u64,
        noise_session: crate::noise::NoiseSession,
        our_index: IndexLease,
        their_index: SessionIndex,
        transport_id: TransportId,
        current_addr: crate::transport::TransportAddr,
        link_stats: crate::transport::LinkStats,
        is_outbound: bool,
        remote_epoch: Option<[u8; 8]>,
        our_profile: NodeProfile,
        peer_profile: NodeProfile,
    ) -> Result<(ActivePeer, LinkOutputs), NodeError> {
        let local = self.session_node_keys();
        let me = *self.identity().node_addr();
        let mmp = self.config().node.mmp.clone();
        let params = crate::node::handlers::rekey::link_params(&self.config().node);
        let workers = self.link_workers();
        let mut caps = LinkCaps {
            indices: &mut self.index_allocator,
            local: &local,
            me,
            params,
            record: Record::new(),
            workers,
            profile: our_profile,
        };
        ActivePeer::with_session(
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
            &mmp,
            remote_epoch,
            our_profile,
            peer_profile,
            &mut caps,
        )
        .map_err(|lease| {
            let _ = self
                .index_allocator
                .free(SessionIndex::new(lease.release()));
            NodeError::PromotionFailed {
                link_id,
                reason: "session authenticated another key".into(),
            }
        })
    }
}

/// Process an FMP negotiation payload received from a peer.
///
/// Decodes the payload, validates profile pairing, and stores the
/// results on the peer's control machine.
fn process_fmp_negotiation(
    our_profile: crate::proto::fmp::NodeProfile,
    machine: &mut PeerMachine,
    neg_bytes: &[u8],
) -> Result<(), crate::proto::Error> {
    // The decode -> validate -> profile decision is the pure core split; the
    // shell records the result on the connection and logs.
    let their_profile = decide_fmp_negotiation(our_profile, neg_bytes)?;

    machine.set_conn_peer_profile(their_profile);

    debug!(
        link_id = %machine.link_id(),
        our_profile = %our_profile,
        peer_profile = %their_profile,
        "FMP negotiation complete"
    );

    Ok(())
}
