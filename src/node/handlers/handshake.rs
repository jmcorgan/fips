//! Handshake handlers and connection promotion.

use crate::NodeAddr;
use crate::PeerIdentity;
use crate::node::acl::PeerAclContext;
use crate::node::dataplane::PeerActionCtx;
use crate::node::rate_limit::Msg1Class;
use crate::node::reject::{HandshakeReject, RejectReason};
use crate::node::{Node, NodeError};
use crate::peer::ActivePeer;
use crate::peer::machine::{
    CrossConnOutcome, FailReason, HandshakeCrypto, HandshakePhase, PeerAction, PeerEvent,
    PeerMachine, PeerState, TimerKind,
};
use crate::proto::fmp::wire::{Msg1Header, Msg2Header, build_msg2};
use crate::proto::fmp::{
    EstablishSnapshot, EstablishView, InboundDecision, InboundReject, OutboundSnapshot,
    PromotionResult, WireOutcome, cross_connection_winner,
};
use crate::transport::{Link, LinkDirection, LinkId, ReceivedPacket};
use crate::utils::index::SessionIndex;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Minimum interval between accepted epoch changes for one peer identity,
/// and the recency threshold at which the peering an epoch change would
/// destroy still counts as live.
///
/// An epoch-mismatch msg1 is authentic but replayable: a captured one stays
/// valid indefinitely, and accepting it tears down a working peering. Both
/// conditions are receiver-local. The liveness half is the one that closes
/// the replay, since a peering under attack is by construction still
/// heartbeating; the interval half bounds the churn a peer can drive on its
/// own.
///
/// Sized against the peer's own recovery rather than against a round number:
/// a genuinely restarting peer's msg1 resends fire at roughly t+1, t+3, t+7
/// and t+15 seconds and its attempt is reaped at `handshake_timeout_secs`
/// (30), so 15 is the largest value at which a real restart still re-peers
/// inside its first handshake window with no reconnect backoff. It also sits
/// below `link_dead_timeout_secs` (30), so the liveness gate can never
/// outlive the reaper that would have removed the peering anyway.
///
/// Raising it lengthens the outage an attacker's accepted replay causes,
/// because the genuine peer's recovery msg1 hits the same arm. Lowering it
/// weakens both halves and, below the resend ladder, buys nothing.
const EPOCH_RESTART_MIN_INTERVAL_SECS: u64 = 15;

/// Why an inbound msg1 got past the `accept_connections` gate, and against
/// what identity the post-DH confirmation must check it.
///
/// Three outcomes, not two: an `Option` would conflate "no waiver was needed"
/// with "the waiver was used and nobody owns the matched address", and the
/// second of those is the case that must reject.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::node) enum Msg1Waiver {
    /// The transport accepts fresh inbound handshakes (or no transport is
    /// registered), so the address carve-out did not admit this msg1 and
    /// there is nothing to confirm.
    NotNeeded,
    /// The carve-out is what admitted this msg1, and the matched address
    /// belongs to this identity: either a promoted peer, or a handshake
    /// already in flight on the matched link whose identity is expected
    /// (outbound dial) or already learned (inbound msg1).
    Expect(NodeAddr),
    /// The carve-out is what admitted this msg1, and no identity can be
    /// attributed to the matched address. Fail closed: reject after the DH.
    Unattributed,
}

impl EstablishView for Node {
    fn establish_snapshot(&self, peer_addr: &NodeAddr) -> EstablishSnapshot {
        let existing = self.peers.get(peer_addr);
        let max_peers = self.max_peers();
        EstablishSnapshot {
            has_existing_peer: existing.is_some(),
            existing_peer_epoch: existing.and_then(|p| p.remote_epoch()),
            existing_session_age_secs: existing
                .map(|p| p.session_established_at().elapsed().as_secs())
                .unwrap_or(0),
            has_session: existing.map(|p| p.has_session()).unwrap_or(false),
            pending_new_session: existing
                .map(|p| p.pending_new_session().is_some())
                .unwrap_or(false),
            rekey_in_progress: existing.map(|p| p.rekey_in_progress()).unwrap_or(false),
            existing_msg2: existing.and_then(|p| p.handshake_msg2().map(|m| m.to_vec())),
            at_max_peers: max_peers > 0 && self.peers.len() >= max_peers,
            has_pending_outbound_to_peer: self.connections().any(|(_, machine)| {
                machine
                    .conn_expected_identity()
                    .map(|id| id.node_addr() == peer_addr)
                    .unwrap_or(false)
            }),
            rekey_enabled: self.config().node.rekey.enabled,
            our_node_addr: *self.identity().node_addr(),
        }
    }

    fn outbound_snapshot(&self, peer_addr: &NodeAddr) -> OutboundSnapshot {
        OutboundSnapshot {
            has_existing_peer: self.peers.contains_key(peer_addr),
            // Tie-break for THIS outbound connection (`is_outbound = true`),
            // pre-evaluated here so the core stays free of the peer helper.
            our_outbound_wins: cross_connection_winner(
                self.identity().node_addr(),
                peer_addr,
                true,
            ),
        }
    }
}

impl Node {
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

    /// Returns true if an inbound msg1's source matches an established
    /// link, i.e. it is rekey/restart maintenance traffic rather than a
    /// stranger's fresh handshake.
    ///
    /// This is deliberately separate from the `accept_connections` gate:
    /// it is the only half of `should_admit_msg1` that is a safe basis
    /// for exempting traffic from stranger-class treatment. Two
    /// predicates cover "established peer at this transport+addr":
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
    /// Cost: predicate 1 is O(1), predicate 2 is O(peers). Because
    /// `handle_msg1` classifies before rate limiting, predicate 2 runs on
    /// every inbound msg1 including those about to be refused, so a msg1
    /// flood costs O(peers) per dropped packet rather than O(1). Predicate 2
    /// exists only because `addr_to_link` is keyed on the *unresolved* dial
    /// address; if that keying is corrected, this becomes a single O(1)
    /// lookup and the flood cost returns to O(1).
    pub(in crate::node) fn is_established_link_msg1(
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
        // Any path, not only the one we send on: a rekey msg1 arrives on the
        // path the *peer* sends on.
        if self
            .peers
            .values()
            .any(|p| p.is_reachable_at(transport_id, remote_addr))
        {
            return true;
        }
        false
    }

    /// Classify the msg1 waiver for a source that `should_admit_msg1`
    /// admitted, so the post-DH confirmation knows whether it has an
    /// identity to check against and what to do when it has none.
    ///
    /// `established` is the caller's already-computed
    /// `is_established_link_msg1(...)`, so the O(peers) scan is not repeated
    /// on the refusal path.
    ///
    /// The two attribution limbs are composed the same way
    /// `is_established_link_msg1` composes its own: as an OR, not as an
    /// if/else. An `addr_to_link` entry that yields no identity must not
    /// short-circuit the address scan, because the two keys can be different
    /// forms of the same peer's address (the hostname-vs-numeric case that
    /// predicate 2 exists for) and the entry can outlive the link it named.
    pub(in crate::node) fn msg1_waiver(
        &self,
        established: bool,
        transport_id: crate::transport::TransportId,
        remote_addr: &crate::transport::TransportAddr,
    ) -> Msg1Waiver {
        // The carve-out only admits anything when the gate would otherwise
        // refuse, so an accepting transport has nothing to confirm.
        if self
            .transports
            .get(&transport_id)
            .is_none_or(|t| t.accept_connections())
        {
            return Msg1Waiver::NotNeeded;
        }
        if !established {
            // `should_admit_msg1` refused this msg1 and the caller returned,
            // so this arm is unreachable from the one call site. Fail closed
            // rather than skipping the check, so a second caller cannot
            // reintroduce the hole this classifier exists to close.
            return Msg1Waiver::Unattributed;
        }

        // Predicate 1: the reverse-address lookup.
        if let Some(&link_id) = self.addr_to_link.get(&(transport_id, remote_addr.clone())) {
            if let Some(peer) = self.peers.values().find(|p| p.link_id() == link_id) {
                return Msg1Waiver::Expect(*peer.node_addr());
            }
            // A link with no promoted peer: a dial in progress or an inbound
            // handshake in flight. Both register a connection carrying the
            // expected (outbound) or learned (inbound) identity.
            if let Some(id) = self
                .connections()
                .find(|(id, _)| **id == link_id)
                .and_then(|(_, machine)| machine.conn_expected_identity())
            {
                return Msg1Waiver::Expect(*id.node_addr());
            }
            // Deliberately fall through instead of returning. The entry can
            // name a link that no longer exists — `remove_link` clears the
            // reverse lookup only under the key it rebuilds from the link's
            // own remote address, so an entry inserted under a second
            // address form for that link survives its removal. Rejecting
            // here would refuse a peer predicate 2 can still attribute, and
            // would refuse it permanently: this classifier's caller returns
            // above the insert that overwrites the stale entry, so nothing
            // downstream would ever repair the map.
        }

        // Predicate 2: the address scan over promoted peers, which always
        // yields an identity when it matches.
        self.peers
            .values()
            .find(|p| p.is_reachable_at(transport_id, remote_addr))
            .map(|p| Msg1Waiver::Expect(*p.node_addr()))
            .unwrap_or(Msg1Waiver::Unattributed)
    }

    /// Returns true if an inbound msg1 should be admitted past the
    /// `accept_connections` gate.
    ///
    /// Rekey/restart msg1 from an established peer is always admitted (the
    /// gate is meant to filter fresh handshakes from strangers, not
    /// maintenance traffic on established sessions).
    ///
    /// Otherwise the transport's `accept_connections` config decides;
    /// absence of a registered transport admits (no gate to apply).
    pub(in crate::node) fn should_admit_msg1(
        &self,
        transport_id: crate::transport::TransportId,
        remote_addr: &crate::transport::TransportAddr,
    ) -> bool {
        if self.is_established_link_msg1(transport_id, remote_addr) {
            return true;
        }
        self.transports
            .get(&transport_id)
            .is_none_or(|t| t.accept_connections())
    }

    /// Handle handshake message 1 (phase 0x1).
    ///
    /// This creates a new inbound connection. Rate limiting is applied
    /// before any expensive crypto operations.
    ///
    /// Classifying the source costs no crypto (two map/scan lookups), so it
    /// happens first and selects which bucket the msg1 draws on: rekey and
    /// restart traffic from an established link stops competing with
    /// stranger admission, while still being metered.
    pub(in crate::node) async fn handle_msg1(&mut self, packet: ReceivedPacket) {
        // === CLASSIFY, THEN RATE LIMIT (both before any crypto) ===
        // Classification is two map lookups; the second is O(peers) and now
        // runs on every inbound msg1, including refused ones. See the
        // `is_established_link_msg1` doc comment for why the scan is still
        // needed and what would retire it.
        //
        // `_slot` is an RAII guard: it releases the limiter's pending slot on
        // drop, which is every return path below and the end of the function.
        let established = self.is_established_link_msg1(packet.transport_id, &packet.remote_addr);
        let class = if established {
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
        let _slot = match self.msg1_rate_limiter.start_handshake(class) {
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
        //
        // `!established &&` is not a behaviour change: `should_admit_msg1`
        // is `is_established_link_msg1() || accept_connections()`, so the
        // short-circuit only skips a second evaluation of the `peers` scan
        // on the hot path. The call is left in place so the two predicates
        // cannot drift apart.
        if !established && !self.should_admit_msg1(packet.transport_id, &packet.remote_addr) {
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }

        // Snapshot which identity, if any, the address carve-out attributed
        // this source to. Taken here rather than after the DH so the answer
        // is the one the gate acted on. On an accepting transport this is one
        // map lookup and a return.
        let waiver = self.msg1_waiver(established, packet.transport_id, &packet.remote_addr);

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

        // Pre-crypto duplicate short-circuit. An *inbound* link from this
        // address that is not (yet) a promoted peer means our earlier msg2 was
        // lost: resend the stored msg2 without paying the crypto cost and
        // return. An inbound link that DOES belong to an active peer (a possible
        // restart/rekey) or an *outbound* link (a cross-connection) falls
        // through to the wire step and the structured classification below —
        // the pre-refactor `possible_restart` flag is no longer needed because
        // that classification now gates on `has_existing_peer` (identity), which
        // subsumes it.
        let addr_key = (packet.transport_id, packet.remote_addr.clone());
        if let Some(&existing_link_id) = self.addr_to_link.get(&addr_key)
            && let Some(link) = self.links.get(&existing_link_id)
        {
            if link.direction() == LinkDirection::Inbound {
                let is_active_peer = self.peers.values().any(|p| p.link_id() == existing_link_id);
                if !is_active_peer {
                    // Genuinely pending handshake — resend msg2.
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
                    return;
                }
            } else {
                // Outbound link to this address with no active peer yet: a
                // cross-connection. Just log; it is classified as a net-new
                // inbound below.
                let is_active_peer = self.peers.values().any(|p| p.link_id() == existing_link_id);
                if !is_active_peer {
                    debug!(
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        existing_link_id = %existing_link_id,
                        "Cross-connection detected: have outbound, received inbound msg1"
                    );
                }
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

        // This frame's own copy of the node's long-term private key; the
        // handshake state keeps its own and clears that on drop.
        let mut our_keypair = self.identity().keypair();
        let noise_msg1 = &packet.data[header.noise_msg1_offset..];
        let init_result = machine.receive_handshake_init(
            our_keypair,
            self.startup_epoch(),
            noise_msg1,
            packet.timestamp_ms,
        );
        our_keypair.non_secure_erase();
        let msg2_response = match init_result {
            Ok(m) => m,
            Err(e) => {
                debug!(
                    error = %e,
                    "Failed to process msg1"
                );
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
            }
        };

        // Learn peer identity from msg1
        assert!(machine.leg().is_some(), "pending connection attached above");
        let peer_identity = match machine.conn_expected_identity() {
            Some(id) => *id,
            None => {
                warn!("Identity not learned from msg1");
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
            }
        };

        let peer_node_addr = *peer_identity.node_addr();

        // The address carve-out admitted this msg1 past a refusing gate on
        // the strength of the source address alone. Now that the DH has
        // revealed the initiator's static, confirm it belongs to the party
        // that address is attributed to; an off-path party sourcing from an
        // established peer's address gets no further than here. Cheap
        // rejection is unchanged: a stranger under accept_connections=false
        // is still refused above, having paid nothing.
        match waiver {
            Msg1Waiver::NotNeeded => {}
            Msg1Waiver::Expect(expected) if expected == peer_node_addr => {}
            Msg1Waiver::Expect(expected) => {
                warn!(
                    expected = %self.peer_display_name(&expected),
                    actual = %self.peer_display_name(&peer_node_addr),
                    transport_id = %packet.transport_id,
                    "Msg1 admitted by the established-address waiver carries a different identity, dropping"
                );
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
            }
            Msg1Waiver::Unattributed => {
                warn!(
                    actual = %self.peer_display_name(&peer_node_addr),
                    transport_id = %packet.transport_id,
                    "Msg1 admitted by the established-address waiver, but no identity owns that address, dropping"
                );
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
            }
        }

        // === PHASE B result ===
        // Bundle the Noise wire-step outputs (identity, remote epoch, sender
        // index, opaque msg2 payload). The wire step touched no `Node` registry
        // state; from here the decision reads only `wire` and the snapshot.
        let wire = WireOutcome {
            peer_identity,
            remote_epoch: machine.conn_remote_epoch(),
            their_index: header.sender_idx,
            msg2_payload: msg2_response,
        };

        // === PHASE C input ===
        // Snapshot the registry state the inbound classification reads about
        // this peer identity (existing epoch/session/rekey state with the
        // session age resolved here, the max-peers cap, our own address for the
        // tie-break). Taken before this connection is inserted into the
        // registry, matching the pre-refactor read points.
        let est = self.establish_snapshot(&peer_node_addr);

        // === PHASE C: structured classification ===
        // Evaluate the inbound decision once on a local establish leg and route
        // on it. The single `establish_inbound` evaluation lives in
        // `inbound_msg1`, which also returns the machine-phase actions the
        // Promote/Restart arms drive; the effect-bearing arm bodies stay inline
        // in the shell below. `Promote`/`RestartThenPromote` fall through to the
        // shared authorize → allocate → send-msg2 → promote tail; the other
        // variants complete the rate-limiter and return here. The local machine
        // enters `peer_machines` only at the promote tails.
        let (decision, actions) = machine.inbound_msg1(link_id, &wire, est, packet.timestamp_ms);
        match decision {
            InboundDecision::Reject {
                reason: InboundReject::AtMaxPeers,
            } => {
                // Net-new arm at the max-peers cap: the classification already
                // drove the local establish leg to `Failed{Rejected}` with the
                // index allocator untouched (no allocate before the reject).
                // That local machine is discarded (never inserted into
                // `peer_machines`); `conn`/`link_id` were never inserted into
                // the registry either.
                let _ = actions;
                debug!(
                    peer = %self.peer_display_name(&peer_node_addr),
                    max = self.max_peers(),
                    "Silent-dropping Msg1 at max_peers cap (early gate; no Msg2 sent)"
                );
                debug_assert!(matches!(
                    machine.state(),
                    PeerState::Failed {
                        reason: FailReason::Rejected
                    }
                ));
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            }
            InboundDecision::Reject {
                reason: reason @ (InboundReject::PendingSession | InboundReject::DualRekeyWon),
            } => {
                // Existing-peer rekey rejects: the classification took the
                // fresh-context fail path (no actions) and the local machine is
                // dropped; the reject bookkeeping below is the whole effect.
                debug_assert!(actions.is_empty());
                match reason {
                    InboundReject::PendingSession => debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        "Rekey msg1 received but already have pending session, dropping"
                    ),
                    InboundReject::DualRekeyWon => debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        "Dual rekey initiation: we win (smaller addr), dropping their msg1"
                    ),
                    InboundReject::AtMaxPeers => unreachable!(),
                }
                // `conn`/`link_id` were never inserted into the registry, so the
                // local drop suffices — no cleanup needed.
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            }
            InboundDecision::ResendMsg2 { msg2 } => {
                // Duplicate msg1 at the same epoch: the decision carries the
                // stored msg2 bytes and the inline resend below owns the send;
                // the classification touched no state.
                debug_assert!(actions.is_empty());
                if let Some(msg2) = msg2.as_deref()
                    && let Some(transport) = self.transports.get(&packet.transport_id)
                {
                    match transport.send(&packet.remote_addr, msg2).await {
                        Ok(_) => debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            "Resent msg2 for duplicate msg1 (same epoch)"
                        ),
                        Err(e) => debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            error = %e,
                            "Failed to resend msg2"
                        ),
                    }
                }
            }
            InboundDecision::RekeyRespond {
                peer,
                abandon_first,
            } => {
                // Rekey responder: the decision carries the routing; the inline
                // body below owns the abandon, index allocation, framed msg2
                // send, pending-session store, and dampening stamp. The
                // classification machine mutates nothing.
                debug_assert!(actions.is_empty());
                if abandon_first {
                    // Dual-initiation loser: abandon our own in-flight rekey and
                    // free its index before responding as the rekey responder.
                    debug!(
                        peer = %self.peer_display_name(&peer),
                        "Dual rekey initiation: we lose (larger addr), abandoning ours"
                    );
                    if let Some(existing) = self.peers.get_mut(&peer)
                        && let Some(idx) = existing.abandon_rekey()
                    {
                        self.peers_by_index.remove(&idx.as_u32());
                        self.pending_outbound.remove(&idx.as_u32());
                        let _ = self.index_allocator.free(idx);
                    }
                }

                // Rekey: process as responder, store new session as pending.
                let noise_session = machine.take_session();
                let our_new_index = match self.index_allocator.allocate() {
                    Ok(idx) => idx,
                    Err(e) => {
                        warn!(error = %e, "Failed to allocate index for rekey");
                        self.stats_mut()
                            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        return;
                    }
                };

                let noise_session = match noise_session {
                    Some(s) => s,
                    None => {
                        warn!("Rekey msg1: no session from handshake");
                        let _ = self.index_allocator.free(our_new_index);
                        self.stats_mut()
                            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        return;
                    }
                };

                // Send msg2 response using the new handshake.
                let wire_msg2 = build_msg2(our_new_index, wire.their_index, &wire.msg2_payload);
                if let Some(transport) = self.transports.get(&packet.transport_id) {
                    match transport.send(&packet.remote_addr, &wire_msg2).await {
                        Ok(_) => {
                            debug!(
                                peer = %self.peer_display_name(&peer),
                                new_our_index = %our_new_index,
                                "Sent rekey msg2 response"
                            );
                        }
                        Err(e) => {
                            warn!(
                                peer = %self.peer_display_name(&peer),
                                error = %e,
                                "Failed to send rekey msg2"
                            );
                            let _ = self.index_allocator.free(our_new_index);
                            self.stats_mut()
                                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                            return;
                        }
                    }
                }

                // Store the new session as the responder's pending session. It
                // is promoted by the initiator's first new-epoch frame, not by
                // our own tick.
                if let Some(existing) = self.peers.get_mut(&peer) {
                    existing.answer_rekey(noise_session, our_new_index, wire.their_index);
                    existing.record_peer_rekey();
                }

                // Register new index in peers_by_index.
                self.peers_by_index.insert(our_new_index.as_u32(), peer);

                // Do NOT touch addr_to_link — the entry must keep pointing at the
                // original link so future msg1s from this address are recognized
                // as rekeys (not new connections). The temporary `conn`/`link_id`
                // were never inserted into the registry, so no cleanup is needed.
            }
            InboundDecision::RestartThenPromote { peer } => {
                // === Restart inbound establish, driven by the machine. ===
                // Epoch mismatch — the peer restarted. The fresh leg is promoted
                // exactly like a net-new inbound (two-phase authorize); the OLD
                // peer's teardown is the machine's Phase-1
                // `[InvalidateSendState, ReportLost{peer}]`:
                //   InvalidateSendState → remove_active_peer(old): frees the four
                //     index slots + `peers_by_index` + decrypt unregister + FSP
                //     `sessions` + `pending_tun_packets`. The fresh leg's
                //     `our_index` is None, so the machine emits NO
                //     UnregisterDecryptSession.
                //   ReportLost{peer} → note_link_dead(old): reconnect backoff.
                // These execute BEFORE authorize/allocate, preserving the
                // pre-refactor order exactly (remove_active_peer → note_link_dead →
                // authorize → allocate → send msg2 → promote). `peer` here equals
                // `peer_identity.node_addr()` (see `establish_inbound`), so the
                // executor's `InvalidateSendState`
                // (`ambient.verified_identity.node_addr()`) targets the same addr
                // as the pre-refactor `remove_active_peer(&peer)`.
                // The epoch travels inside the AEAD, so this msg1 is
                // authentic — but it stays authentic after capture, and
                // replaying one destroys a working peering and the FSP session
                // state it carries, from off the path. Two receiver-local
                // conditions gate the teardown. The peering's last
                // authenticated inbound frame is the evidence it is still
                // alive, and nothing an unauthenticated sender emits can
                // refresh it, so a peer that genuinely restarted clears this by
                // having stopped sending. The interval half bounds the churn
                // one peer can drive on its own.
                let now_ms = Self::now_ms();
                let peering_idle_ms = self
                    .peers
                    .get(&peer)
                    .map(|p| p.idle_time(now_ms))
                    .unwrap_or(u64::MAX);
                let dampened = self
                    .restart_dampener
                    .get(&peer)
                    .is_some_and(|t| t.elapsed().as_secs() < EPOCH_RESTART_MIN_INTERVAL_SECS);
                if peering_idle_ms < EPOCH_RESTART_MIN_INTERVAL_SECS * 1000 || dampened {
                    debug!(
                        peer = %self.peer_display_name(&peer),
                        idle_ms = peering_idle_ms,
                        dampened,
                        "Epoch mismatch dampened, dropping msg1"
                    );
                    // Silent drop: the stored msg2 is bound to the original
                    // msg1's ephemeral, and answering an address the sender
                    // chose is free amplification.
                    //
                    // No registry cleanup is needed here. On the pre-refactor
                    // layout this arm removed the pending connection and its
                    // link, because both were inserted before msg1 was
                    // classified. The classification now runs against a local
                    // `machine` that enters `peer_machines` only at the promote
                    // tails below, and `link_id` is a bare allocation until
                    // then, so dropping out of the arm is the whole cleanup.
                    // The fresh leg holds no session index either (it is parked
                    // at `Handshaking{ReceivedMsg1}` with `our_index == None`),
                    // so nothing is leaked by returning.
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
                // Stamped on acceptance only. A refusal that slid the window
                // would let a sustained replay starve a genuinely restarting
                // peer for as long as it kept sending.
                let cutoff = Duration::from_secs(EPOCH_RESTART_MIN_INTERVAL_SECS);
                self.restart_dampener.retain(|_, t| t.elapsed() < cutoff);
                self.restart_dampener.insert(peer, Instant::now());

                debug!(
                    peer = %self.peer_display_name(&peer),
                    "Peer restart detected (epoch mismatch), removing stale session"
                );

                // Snapshot the msg2 framing inputs (`their_index` and the opaque
                // payload) for the `build_msg2` call at the promote tail below.
                // The classification borrows `wire`, so these locals carry the
                // two fields the later framing needs.
                let msg2_payload = wire.msg2_payload.clone();
                let their_index = wire.their_index;

                // The classification parked the machine at
                // `Handshaking{ReceivedMsg1}` (no allocation) and returned the
                // old-peer teardown as `actions`. For a restart the fresh leg
                // has `our_index == None`, so that sequence is exactly
                // [InvalidateSendState, ReportLost{peer}].
                debug_assert!(matches!(
                    machine.state(),
                    PeerState::Handshaking {
                        phase: HandshakePhase::ReceivedMsg1,
                        ..
                    }
                ));

                // Execute the Phase-1 teardown, in emitted order
                // (InvalidateSendState before ReportLost, both before
                // authorize/alloc). CLOCK NOTE — INTENTIONAL DIVERGENCE: the
                // pre-refactor arm timestamped `note_link_dead` with
                // `SystemTime::now()` wall-clock; routing `ReportLost` through the
                // executor uses `ambient.now_ms == packet.timestamp_ms`. This is an
                // accepted sub-millisecond reconnect-backoff timing shift — NOT
                // on-wire, NOT index/metrics. The machine is not yet in
                // `peer_machines`, but these two
                // actions do not touch the map, so executing them here is safe.
                let teardown_ctx = PeerActionCtx {
                    verified_identity: peer_identity,
                    transport_id: packet.transport_id,
                    remote_addr: packet.remote_addr.clone(),
                    our_index: None,
                    their_index: Some(their_index),
                    now_ms: packet.timestamp_ms,
                    is_outbound: false,
                };
                self.execute_peer_actions(link_id, &teardown_ctx, actions)
                    .await;

                // Shell interposition: late-ACL authorize BEFORE any allocation.
                if self
                    .authorize_peer(
                        &peer_identity,
                        PeerAclContext::InboundHandshake,
                        packet.transport_id,
                        &packet.remote_addr,
                    )
                    .is_err()
                {
                    let _ = machine.step(
                        PeerEvent::Rejected,
                        packet.timestamp_ms,
                        &mut self.index_allocator,
                    );
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }

                // Phase 2: allocate our index + emit [SendHandshake, PromoteToActive].
                let promote_actions = machine.step(
                    PeerEvent::Authorized,
                    packet.timestamp_ms,
                    &mut self.index_allocator,
                );
                let our_index = match machine.our_index() {
                    Some(idx) => idx,
                    None => {
                        // Allocation exhausted in Phase 2 (mirrors the pre-refactor
                        // allocate-failure path): no msg2, no promote. The old peer
                        // has already been torn down above — identical to the
                        // pre-refactor arm, which also removed the stale peer before
                        // hitting the shared allocate-failure return.
                        warn!("Failed to allocate session index for inbound");
                        self.stats_mut()
                            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        return;
                    }
                };

                // Shell registry surgery, in the pre-refactor order:
                // set indices on the shell connection, insert link / reverse map /
                // connection, then build + store the framed msg2. The old index was
                // already freed by `remove_active_peer` above, BEFORE this fresh
                // allocation — matching the pre-refactor allocation sequence.
                let link = Link::connectionless(
                    link_id,
                    packet.transport_id,
                    packet.remote_addr.clone(),
                    LinkDirection::Inbound,
                    Duration::from_millis(self.config().node.base_rtt_ms),
                );
                self.links.insert(link_id, link);
                self.addr_to_link.insert(addr_key, link_id);
                let wire_msg2 = build_msg2(our_index, their_index, &msg2_payload);
                // Store the framed msg2 on the surviving carrier for duplicate-
                // msg1 resend while the connection is still pending.
                machine.set_conn_handshake_msg2(wire_msg2.clone());

                // Register the machine, which already carries the connection
                // (Promote/Restart tail only).
                self.peer_machines.insert(link_id, machine);

                // Execute [SendHandshake, PromoteToActive]. Because the old peer was
                // removed in Phase 1, `promote_connection`'s cross-connection branch
                // (`peers.get(addr)`) cannot fire, so it always returns `Promoted`;
                // the defensive `PromotionResolved{CrossConnectionWon/Lost}`
                // follow-ups are unreachable here (see the post-tail note).
                let ambient = PeerActionCtx {
                    verified_identity: peer_identity,
                    transport_id: packet.transport_id,
                    remote_addr: packet.remote_addr.clone(),
                    our_index: Some(our_index),
                    their_index: Some(their_index),
                    now_ms: packet.timestamp_ms,
                    is_outbound: false,
                };
                self.execute_peer_actions(link_id, &ambient, promote_actions)
                    .await;

                // Post-`Promoted` shell tail (byte-identical to the pre-refactor
                // Promoted arm), reached only when promotion succeeded (machine now
                // Established). Three outcomes reach this line: a terminal send
                // failure or a promote failure removed the machine, leaving it
                // absent; a TRANSIENT msg2 send failure aborted the queue before
                // `PromoteToActive` ran and deliberately left the half-built leg in
                // place, so the machine is still registered at
                // `Handshaking{ReceivedMsg1}` (`peer_actions.rs`, the
                // `is_transient` branch); or promotion succeeded. The tail below is
                // gated on `Established`, so only the third runs it.
                //
                // DEFENSIVE CROSS-CONNECTION: the machine's
                // `PromotionResolved{CrossConnectionWon/Lost}` follow-ups run the
                // index-level cleanup generically in the executor, but the loser-
                // link surgery (close_connection → remove_link → addr_to_link) is
                // NOT reproduced here — it is UNREACHABLE on the driven restart
                // path: Phase-1 `remove_active_peer` removed `peers[addr]`, so
                // `promote_connection` returns `Promoted`. The full cross-connection
                // link surgery is wired later; the
                // debug_assert below catches any regression that reaches a state
                // other than those three.
                debug_assert!(matches!(
                    self.peer_machines.get(&link_id).map(|m| m.state()),
                    Some(PeerState::Established { .. })
                        | Some(PeerState::Handshaking {
                            phase: HandshakePhase::ReceivedMsg1,
                            ..
                        })
                        | None
                ));
                if matches!(
                    self.peer_machines.get(&link_id).map(|m| m.state()),
                    Some(PeerState::Established { .. })
                ) {
                    // Store msg2 on peer for resend on duplicate msg1
                    if let Some(peer) = self.peers.get_mut(&peer_node_addr) {
                        peer.set_handshake_msg2(wire_msg2.clone());
                    }
                    // Send initial tree announce to new peer
                    if let Err(e) = self.send_tree_announce_to_peer(&peer_node_addr).await {
                        debug!(peer = %self.peer_display_name(&peer_node_addr), error = %e, "Failed to send initial TreeAnnounce");
                    }
                    // Schedule filter announce (sent on next tick via debounce)
                    self.bloom_state.mark_update_needed(peer_node_addr);
                    self.reset_lookup_backoff();
                }
            }
            InboundDecision::Promote => {
                // === Net-new inbound establish, driven by the machine. ===
                // Two-phase authorize: Phase 1 classifies with no allocation; the
                // shell interposes the late-ACL gate here; Phase 2 allocates the
                // single index and emits [SendHandshake, PromoteToActive]. A
                // rejected/unauthorized msg1 therefore allocates NO index —
                // matching the pre-refactor authorize-before-allocate ordering
                // exactly.

                // Snapshot the msg2 framing inputs (`their_index` and the opaque
                // payload) for the `build_msg2` call at the promote tail below.
                // The classification borrows `wire`, so these locals carry the
                // two fields the later framing needs.
                let msg2_payload = wire.msg2_payload.clone();
                let their_index = wire.their_index;

                // Phase 1: a net-new leg classifies with no allocation and emits
                // no actions; the classification parked the machine at
                // `Handshaking{ReceivedMsg1}` awaiting the late-ACL gate.
                debug_assert!(actions.is_empty());
                debug_assert!(matches!(
                    machine.state(),
                    PeerState::Handshaking {
                        phase: HandshakePhase::ReceivedMsg1,
                        ..
                    }
                ));

                // Shell interposition: late-ACL authorize BEFORE any allocation.
                if self
                    .authorize_peer(
                        &peer_identity,
                        PeerAclContext::InboundHandshake,
                        packet.transport_id,
                        &packet.remote_addr,
                    )
                    .is_err()
                {
                    let _ = machine.step(
                        PeerEvent::Rejected,
                        packet.timestamp_ms,
                        &mut self.index_allocator,
                    );
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }

                // Phase 2: allocate our index + emit [SendHandshake, PromoteToActive].
                let promote_actions = machine.step(
                    PeerEvent::Authorized,
                    packet.timestamp_ms,
                    &mut self.index_allocator,
                );
                let our_index = match machine.our_index() {
                    Some(idx) => idx,
                    None => {
                        // Allocation exhausted in Phase 2 (mirrors the pre-refactor
                        // allocate-failure path): no msg2, no promote. The concrete
                        // allocator error is consumed inside `on_authorized`, so the
                        // restored warn! carries the pre-refactor message text only.
                        warn!("Failed to allocate session index for inbound");
                        self.stats_mut()
                            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        return;
                    }
                };

                // Shell registry surgery, in the pre-refactor order:
                // set indices on the shell connection, insert link / reverse map /
                // connection, then build + store the framed msg2.
                let link = Link::connectionless(
                    link_id,
                    packet.transport_id,
                    packet.remote_addr.clone(),
                    LinkDirection::Inbound,
                    Duration::from_millis(self.config().node.base_rtt_ms),
                );
                self.links.insert(link_id, link);
                self.addr_to_link.insert(addr_key, link_id);
                let wire_msg2 = build_msg2(our_index, their_index, &msg2_payload);
                // Store the framed msg2 on the surviving carrier for duplicate-
                // msg1 resend while the connection is still pending.
                machine.set_conn_handshake_msg2(wire_msg2.clone());

                // Register the machine, which already carries the connection
                // (Promote tail only — discarded on every reject/resend/rekey
                // arm per the insertion discipline).
                self.peer_machines.insert(link_id, machine);

                // Execute [SendHandshake, PromoteToActive]. The executor frames +
                // sends msg2 (bytes identical to `wire_msg2`), promotes via
                // `promote_connection`, feeds PromotionResolved back, and runs the
                // inert RegisterDecryptSession (register stays in
                // `promote_connection`). Its TERMINAL send-failure and its
                // promote-failure arms run the pre-refactor cleanup and remove the
                // machine, leaving it absent (not Established); its TRANSIENT
                // send-failure arm aborts the queue before `PromoteToActive` and
                // leaves the machine registered at `Handshaking{ReceivedMsg1}` for
                // the initiator's msg1 resend to land on. The `Established` gate
                // below covers all three.
                let ambient = PeerActionCtx {
                    verified_identity: peer_identity,
                    transport_id: packet.transport_id,
                    remote_addr: packet.remote_addr.clone(),
                    our_index: Some(our_index),
                    their_index: Some(their_index),
                    now_ms: packet.timestamp_ms,
                    is_outbound: false,
                };
                self.execute_peer_actions(link_id, &ambient, promote_actions)
                    .await;

                // Post-`Promoted` shell tail (byte-identical to the pre-refactor
                // Promoted arm), reached only when promotion succeeded (the machine
                // is now Established); a terminal send failure or a promote failure
                // removed the machine and already cleaned up, and a transient send
                // failure left it registered at `Handshaking{ReceivedMsg1}` — which
                // is what the gate below is for.
                if matches!(
                    self.peer_machines.get(&link_id).map(|m| m.state()),
                    Some(PeerState::Established { .. })
                ) {
                    // Store msg2 on peer for resend on duplicate msg1
                    if let Some(peer) = self.peers.get_mut(&peer_node_addr) {
                        peer.set_handshake_msg2(wire_msg2.clone());
                    }
                    // Send initial tree announce to new peer
                    if let Err(e) = self.send_tree_announce_to_peer(&peer_node_addr).await {
                        debug!(peer = %self.peer_display_name(&peer_node_addr), error = %e, "Failed to send initial TreeAnnounce");
                    }
                    // Schedule filter announce (sent on next tick via debounce)
                    self.bloom_state.mark_update_needed(peer_node_addr);
                    self.reset_lookup_backoff();
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
    /// This completes an outbound handshake we initiated.
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
        let key = header.receiver_idx.as_u32();
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
        // ActivePeer, not in a handshake carrier, so the link's machine — if
        // one survives at all — carries no pending handshake. A bare machine
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
                let mut rekey_completed = false;
                let mut cycle_kept = false;
                if let Some(peer) = self.peers.get_mut(&peer_node_addr) {
                    match peer.complete_rekey_msg2(noise_msg2) {
                        Ok((session, remote_epoch)) => {
                            let our_index = peer.rekey_our_index().unwrap_or(header.receiver_idx);
                            let remote_epoch_changed = matches!(
                                (peer.remote_epoch(), remote_epoch),
                                (Some(old), Some(new)) if old != new
                            );
                            if remote_epoch.is_some() {
                                peer.set_remote_epoch(remote_epoch);
                            }
                            peer.set_pending_session(session, our_index, header.sender_idx);

                            self.peers_by_index
                                .insert(our_index.as_u32(), peer_node_addr);

                            if remote_epoch_changed {
                                if self.sessions.remove(&peer_node_addr).is_some() {
                                    debug!(
                                        peer = %display_name,
                                        "Cleared stale FSP session after peer restart during FMP rekey"
                                    );
                                }
                                info!(
                                    peer = %display_name,
                                    "Peer restart detected during FMP rekey, replacing stale endpoint session"
                                );
                            }

                            debug!(
                                peer = %display_name,
                                new_our_index = %our_index,
                                new_their_index = %header.sender_idx,
                                "Rekey completed (initiator), pending K-bit cutover"
                            );
                            rekey_completed = true;
                        }
                        // Nothing authenticated this msg2 before the read, and the
                        // index it names travels in cleartext in our msg1, so it
                        // may be a forgery. The responder holds the session it
                        // answered with until our first new-epoch frame reaches
                        // it, so giving up the cycle here would throw away a
                        // cycle the genuine msg2 can still complete, and the
                        // responder would then hold that session until its
                        // retirement hold passes. The read rolled the handshake
                        // back: keep the cycle and its dispatch entry so the
                        // genuine msg2 can still complete it. If no readable msg2
                        // ever arrives, the msg1 resend budget abandons the cycle
                        // as it would for a lost one.
                        Err(e) if peer.awaits_msg2() => {
                            debug!(
                                peer = %display_name,
                                error = %e,
                                "Rekey msg2 did not authenticate, keeping the rekey cycle"
                            );
                            cycle_kept = true;
                            self.stats_mut()
                                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        }
                        Err(e) => {
                            warn!(
                                peer = %display_name,
                                error = %e,
                                "Rekey msg2 processing failed"
                            );
                            if let Some(idx) = peer.abandon_rekey() {
                                self.peers_by_index.remove(&idx.as_u32());
                                let _ = self.index_allocator.free(idx);
                            }
                            self.stats_mut()
                                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        }
                    }
                }

                // Feed the control machine the completed-rekey observation so its
                // shadow index and rekey phase stay coherent. Only on success —
                // the failure paths above either keep the cycle as it was or
                // revert it, and leave the machine untouched. The crypto effect
                // already ran inline; this emits no action.
                if rekey_completed {
                    self.observe_rekey_msg2(&peer_node_addr, header.sender_idx);
                }

                if !cycle_kept {
                    self.pending_outbound.remove(&key);
                }
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

        let (peer_identity, our_index) = {
            let machine = self.peer_machines.get_mut(&link_id).unwrap();

            let noise_msg2 = &packet.data[header.noise_msg2_offset..];
            if let Err(e) = machine.complete_handshake(noise_msg2, packet.timestamp_ms) {
                warn!(
                    link_id = %link_id,
                    error = %e,
                    "Handshake completion failed"
                );
                // Drop the Noise handle (byte-identical point) and record the
                // failure on the control machine as `send_failed` — the
                // failure state's home. The machine PHASE stays exactly where
                // the old failure left it (`SentMsg1`): the stale-connection
                // sweep reclaims the connection unconditionally via the
                // machine `is_failed()` at the next tick, before any
                // projection or resend.
                machine.mark_failed();
                machine.mark_send_failed();
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
            }

            machine.set_conn_source_addr(packet.remote_addr.clone());
            assert!(
                machine.leg().is_some(),
                "pending connection present for msg2 completion"
            );

            let peer_identity = match machine.conn_expected_identity() {
                Some(id) => *id,
                None => {
                    warn!(link_id = %link_id, "No identity after handshake");
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
            };

            (peer_identity, machine.our_index())
        };

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
            if let Some(link) = self.links.get(&link_id) {
                let tid = link.transport_id();
                let addr = link.remote_addr().clone();
                if let Some(transport) = self.transports.get(&tid) {
                    transport.close_connection(&addr).await;
                }
            }
            // Drop the machine persisted at dial — this leg never promotes,
            // and its pending connection is dropped with it.
            self.remove_peer_machine(link_id);
            self.remove_link(&link_id);
            if let Some(idx) = our_index {
                let _ = self.index_allocator.free(idx);
            }
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
            self.note_handshake_timeout(*peer_identity.node_addr(), packet.timestamp_ms);
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }

        let peer_node_addr = *peer_identity.node_addr();

        debug!(
            peer = %self.peer_display_name(&peer_node_addr),
            link_id = %link_id,
            their_index = %header.sender_idx,
            "Outbound handshake completed"
        );

        // Cross-connection resolution: if the peer was already promoted via
        // our inbound handshake (we processed their msg1), both nodes initially
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
        // exists. The machine was persisted at DIAL, so the executor's
        // `PromoteToActive` arm can feed `PromotionResolved` back via the same
        // lookup; the `pending_outbound` lifecycle stays shell-side — the
        // machine never touches it.
        let out_snap = self.outbound_snapshot(&peer_node_addr);
        let actions = match self.peer_machines.get_mut(&link_id) {
            Some(machine) => machine.step(
                PeerEvent::Msg2 {
                    their_index: header.sender_idx,
                    out: out_snap,
                },
                packet.timestamp_ms,
                &mut self.index_allocator,
            ),
            None => {
                // No machine persisted at dial (e.g. a test that seeds
                // `connections`/`pending_outbound` directly, or any path that
                // reaches msg2 without `start_handshake`): reproduce the
                // pre-persistence transient exactly.
                let mut machine =
                    PeerMachine::new_outbound(link_id, peer_identity, packet.timestamp_ms);
                let actions = machine.step(
                    PeerEvent::Msg2 {
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
            let (taken_conn, carrier_our_index) = match self.peer_machines.get_mut(&link_id) {
                Some(machine) => (machine.take_leg(), machine.our_index()),
                None => (None, None),
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
                // We're the smaller node. Swap to outbound session + indices.
                // The peer will keep their inbound session (complement of ours).
                let outbound_our_index = carrier_our_index;
                let outbound_session = conn.noise_session.take();

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
                    if let Some(old_idx) = old_our_index {
                        self.peers_by_index.remove(&old_idx.as_u32());
                        let _ = self.index_allocator.free(old_idx);
                    }
                    self.peers_by_index
                        .insert(outbound_our_index.as_u32(), peer_node_addr);

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
                let outbound_our_index = carrier_our_index;

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
        // This arm is `has_existing_peer == false` only, so `promote_connection`
        // always hits its else branch and returns `Promoted`; the defensive
        // `CrossConnectionWon/Lost` follow-ups are UNREACHABLE here.
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

        // Execute `[PromoteToActive]`. The executor calls `promote_connection`,
        // feeds `PromotionResolved{Promoted}` back, registers the decrypt-worker
        // session (the register was relocated into the executor's
        // `PromoteToActive` Ok arm, gated on the result), and runs the now-inert
        // `RegisterDecryptSession` follow-up. A promote failure (e.g.
        // `MaxPeersExceeded` if peers filled between dial and msg2) runs the
        // executor's Err cleanup and removes the machine, leaving it absent (not
        // Established).
        let ambient = PeerActionCtx {
            verified_identity: peer_identity,
            transport_id: packet.transport_id,
            remote_addr: packet.remote_addr.clone(),
            our_index,
            their_index: Some(header.sender_idx),
            now_ms: packet.timestamp_ms,
            is_outbound: true,
        };
        self.execute_peer_actions(link_id, &ambient, actions).await;

        // Post-`Promoted` shell tail (byte-identical to the pre-refactor Promoted
        // arm), reached only when promotion succeeded (machine now Established).
        // `pending_outbound.remove` runs here — exactly where the pre-refactor Ok
        // arm removed it, before the TreeAnnounce/bloom/backoff tail. A promote
        // failure removed the machine and skips the whole tail (the pre-refactor
        // Err arm likewise left `pending_outbound` in place and only recorded the
        // reject, which the executor's Err arm already did).
        debug_assert!(matches!(
            self.peer_machines.get(&link_id).map(|m| m.state()),
            Some(PeerState::Established { .. }) | None
        ));
        if matches!(
            self.peer_machines.get(&link_id).map(|m| m.state()),
            Some(PeerState::Established { .. })
        ) {
            self.pending_outbound.remove(&key);
            info!(
                peer = %self.peer_display_name(&peer_node_addr),
                "Peer promoted to active"
            );
            // Send initial tree announce to new peer
            if let Err(e) = self.send_tree_announce_to_peer(&peer_node_addr).await {
                debug!(peer = %self.peer_display_name(&peer_node_addr), error = %e, "Failed to send initial TreeAnnounce");
            }
            // Schedule filter announce (sent on next tick via debounce)
            self.bloom_state.mark_update_needed(peer_node_addr);
            self.reset_lookup_backoff();
        }
    }

    /// Promote a connection to active peer after successful authentication.
    ///
    /// Handles cross-connection detection and resolution using tie-breaker rules.
    pub(in crate::node) fn promote_connection(
        &mut self,
        link_id: LinkId,
        verified_identity: PeerIdentity,
        current_time_ms: u64,
    ) -> Result<PromotionResult, NodeError> {
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

        let peer_node_addr = *verified_identity.node_addr();
        let is_outbound = carrier_is_outbound;

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
                let old_peer = self.peers.remove(&peer_node_addr).unwrap();
                let loser_link_id = old_peer.link_id();

                // Clean up old peer's index from peers_by_index
                if let Some(old_idx) = old_peer.our_index() {
                    self.peers_by_index.remove(&old_idx.as_u32());
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
                    self.unregister_decrypt_worker_session(old_idx.as_u32());
                    let _ = self.index_allocator.free(old_idx);
                }

                if remote_epoch_changed {
                    if self.sessions.remove(&peer_node_addr).is_some() {
                        debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            "Cleared stale FSP session after peer restart during promotion"
                        );
                    }
                    info!(
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
                );
                new_peer.set_tree_announce_min_interval_ms(
                    self.config().node.tree.announce_min_interval_ms,
                );

                new_peer.set_path_role(
                    transport_id,
                    self.transports
                        .get(&transport_id)
                        .map(|t| t.role())
                        .unwrap_or_default(),
                );
                self.peers.insert(peer_node_addr, new_peer);
                self.peers_by_index
                    .insert(our_index.as_u32(), peer_node_addr);
                self.peering
                    .reconciler
                    .retry_pending
                    .remove(&peer_node_addr);
                self.register_identity(peer_node_addr, verified_identity.pubkey_full());

                debug!(
                    peer = %self.peer_display_name(&peer_node_addr),
                    winner_link = %link_id,
                    loser_link = %loser_link_id,
                    "Cross-connection resolved: this connection won"
                );

                // The decrypt-worker registration is no longer done
                // here — it relocated OUT of `promote_connection` into the single
                // executor `PromoteToActive` Ok arm (`peer_actions.rs`), gated on
                // the returned `PromotionResult` (`Promoted | CrossConnectionWon`).
                // The executor runs it synchronously right after this call returns,
                // before any await, so the live establish behaviour is unchanged.

                Ok(PromotionResult::CrossConnectionWon {
                    loser_link_id,
                    node_addr: peer_node_addr,
                })
            } else {
                // This connection loses, keep existing
                // Free the index we allocated
                let _ = self.index_allocator.free(our_index);

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
            );
            new_peer.set_tree_announce_min_interval_ms(
                self.config().node.tree.announce_min_interval_ms,
            );
            if let Some(ts) = old_announce_ts {
                new_peer.set_last_tree_announce_sent_ms(ts);
            }

            new_peer.set_path_role(
                transport_id,
                self.transports
                    .get(&transport_id)
                    .map(|t| t.role())
                    .unwrap_or_default(),
            );
            self.peers.insert(peer_node_addr, new_peer);
            self.peers_by_index
                .insert(our_index.as_u32(), peer_node_addr);
            self.peering
                .reconciler
                .retry_pending
                .remove(&peer_node_addr);
            self.register_identity(peer_node_addr, verified_identity.pubkey_full());

            debug!(
                peer = %self.peer_display_name(&peer_node_addr),
                link_id = %link_id,
                our_index = %our_index,
                their_index = %their_index,
                "Connection promoted to active peer"
            );

            // The decrypt-worker registration relocated OUT of
            // `promote_connection` into the single executor `PromoteToActive` Ok
            // arm (`peer_actions.rs`), gated on the returned `PromotionResult`
            // (`Promoted | CrossConnectionWon`, never `CrossConnectionLost`). The
            // executor runs it synchronously right after this call returns, before
            // any await — same point, same effect as the pre-refactor in-place call
            // (no-op when the worker pool isn't spawned; unit-test path or
            // `FIPS_DECRYPT_WORKERS=0`).

            Ok(PromotionResult::Promoted(peer_node_addr))
        }
    }
}
