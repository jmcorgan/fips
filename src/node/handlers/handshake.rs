//! Handshake handlers and connection promotion.

use crate::NodeAddr;
use crate::PeerIdentity;
use crate::identity::OsEntropy;
use crate::node::acl::PeerAclContext;
use crate::node::dataplane::PeerActionCtx;
use crate::node::diag::{self, HsLine, Msg1Path, OrNone, Shown, Withheld};
use crate::node::handlers::path::NodeFacts;
use crate::node::rate_limit::Msg1Class;
use crate::node::reject::{HandshakeReject, RejectReason};
use crate::node::settle::params::settle_params;
use crate::node::{Node, NodeError};
use crate::peer::PeerInstant;
use crate::peer::machine::{
    CrossConnOutcome, FailReason, HandshakeCrypto, HandshakePhase, PeerAction, PeerEvent,
    PeerMachine, PeerState,
};
use crate::peer::{LinkCaps, Match, PathCaps};
use crate::proto::fmp::ActiveBackoff;
use crate::proto::fmp::rekey::ik::{Arrived, read_msg1};
use crate::proto::fmp::wire::{Msg1Header, Msg2Header, build_msg2};
use crate::proto::fmp::{
    EphemeralDigest, EstablishSnapshot, EstablishView, InboundDecision, InboundReject, LegStamp,
    Msg1Digest, OutboundSnapshot, PromotionResult, WireOutcome, cross_connection_winner,
};
use crate::proto::settle::gates::{Ask, Liveness, Refusal, Source};
use crate::proto::settle::output::Why;
use crate::proto::settle::params::Params;
use crate::time::HostClock;
use crate::transport::{Link, LinkDirection, LinkId, ReceivedPacket, TransportError, TransportId};
use crate::utils::index::{IndexError, SessionIndex};
use fips_core::proto::rekey::{Arrival, Input, Reason, Route, allocate};
use fips_core::time::{Clock as _, Instant as _};
use std::time::Duration;
use tracing::{debug, info, warn};

/// The age an unheard peering must reach before a msg1 may replace it, in
/// milliseconds: the restart gates' `Params::unheard`, for the tests that
/// wait it out.
#[cfg(test)]
pub(in crate::node) const UNHEARD_PEERING_MIN_AGE_MS: u64 = 1_000;

/// Where a same-epoch msg1 from a held peer goes after that peer's link
/// rekey machine has judged it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::node) enum LinkVerdict {
    /// The machine answered, resent or refused it: nothing more.
    Done,
    /// The restart gates, as a replacement of the peering.
    Replace,
    /// A pending redial, with the msg1's ephemeral the machine has not
    /// recorded.
    Redial(fips_core::proto::rekey::Digest),
}

/// A msg1 classified as a redial, with what arming it needs: the leg's
/// control machine (parked at `Handshaking{ReceivedMsg1}`), the link
/// allocated for it, the held peer and the authenticated identity, the
/// msg1's ephemeral as the link machine and the node key it, and the
/// leg's stamp.
pub(in crate::node) struct Armed {
    pub(in crate::node) machine: PeerMachine,
    pub(in crate::node) link: LinkId,
    pub(in crate::node) peer: NodeAddr,
    pub(in crate::node) identity: PeerIdentity,
    pub(in crate::node) digest: Option<fips_core::proto::rekey::Digest>,
    pub(in crate::node) ephemeral: Option<EphemeralDigest>,
    pub(in crate::node) leg_at: LegStamp,
}

/// The handshake reject a msg1 refusal records.
///
/// Each refusal the classification decides keeps its own counter, so a
/// rekey copy, a crossing and an admission refusal are told apart in
/// `show_metrics` rather than summed into `bad_state`. The match has no
/// wildcard: a new refusal does not compile until it is given a counter.
pub(in crate::node) fn msg1_reject(reason: &InboundReject) -> HandshakeReject {
    match reason {
        InboundReject::AtMaxPeers => HandshakeReject::AtMaxPeers,
        InboundReject::SilentBackoff => HandshakeReject::SilentBackoff,
    }
}

/// The handshake reject a link rekey machine's refusal of a msg1 records.
///
/// The machine's refusals keep the counters the deployed classification
/// gave them, so a rekey copy, a crossing and a pending held are still told
/// apart in `show_metrics`; a refusal no well-routed msg1 meets counts as a
/// state-machine rejection.
pub(in crate::node) fn msg1_refusal(reason: Reason) -> HandshakeReject {
    match reason {
        Reason::PendingHeld => HandshakeReject::RekeyPending,
        Reason::DualInitWon => HandshakeReject::RekeyTiebreak,
        Reason::AnsweredBefore => HandshakeReject::AnsweredBefore,
        Reason::OffLink => HandshakeReject::OffLink,
        _ => HandshakeReject::BadState,
    }
}

/// The instant `ms` milliseconds before now on the peer clock, or an hour
/// before it when the clock does not reach back that far: a wall-clock
/// interval carried onto the peer clock, for the mutation lane's wall-clock
/// breaks of the restart gates.
fn ago(ms: u64) -> PeerInstant {
    let now = crate::peer::peer_now();
    now.checked_sub(Duration::from_millis(ms))
        .or_else(|| now.checked_sub(Duration::from_secs(3_600)))
        .unwrap_or(now)
}

/// The instant on the peer clock whose reading, in milliseconds, is `ms`:
/// a stamp taken on another clock read as if it were the peer clock's.
fn mono_instant(ms: u64) -> PeerInstant {
    let now = crate::peer::peer_now();
    let at = crate::time::mono_ms();
    if ms >= at {
        now.checked_add(Duration::from_millis(ms - at))
    } else {
        now.checked_sub(Duration::from_millis(at - ms))
    }
    .unwrap_or(now)
}

/// Now on the wall clock, as an instant on the peer clock: the peer clock's
/// reading when the wall clock was first read here, moved by the wall
/// clock's time since, so a step of the wall clock moves it and a step of
/// the peer clock does not. Only the mutation lane's wall-clock breaks of
/// the replay memory read it.
fn wall_now() -> PeerInstant {
    static FIRST: std::sync::OnceLock<(PeerInstant, u64)> = std::sync::OnceLock::new();
    let (at, wall) = *FIRST.get_or_init(|| (crate::peer::peer_now(), Node::now_ms()));
    let now = Node::now_ms();
    if now >= wall {
        at.checked_add(Duration::from_millis(now - wall))
    } else {
        at.checked_sub(Duration::from_millis(wall - now))
    }
    .unwrap_or(at)
}

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
            replace: false,
            redial: false,
            at_max_peers: max_peers > 0 && self.peers.len() >= max_peers,
            silent_backoff: self
                .gates
                .refusing(peer_addr, crate::peer::peer_now())
                .map(|b| ActiveBackoff {
                    epoch: b.epoch,
                    silent: b.silent,
                    remaining_ms: b.remaining.as_millis() as u64,
                }),
        }
    }

    fn outbound_snapshot(&self, peer_addr: &NodeAddr) -> OutboundSnapshot {
        let existing = self.peers.get(peer_addr);
        OutboundSnapshot {
            has_existing_peer: existing.is_some(),
            existing_peer_epoch: existing.and_then(|p| p.remote_epoch()),
            // Tie-break for THIS outbound connection (`is_outbound = true`),
            // pre-evaluated here so the core stays free of the peer helper.
            our_outbound_wins: cross_connection_winner(
                self.identity().node_addr(),
                peer_addr,
                true,
            ),
            own_dial: existing
                .and_then(|p| self.links.get(&p.link_id()))
                .is_some_and(|link| link.direction() == LinkDirection::Outbound),
        }
    }
}

/// Repeated handshake lines: a peer that keeps sending msg1s with one outcome
/// logs that outcome a bounded number of times per session, and the number
/// not logged is reported later.
impl Node {
    /// Count a line of `kind` for `peer` and say whether to log it. On the
    /// first counted line after a session change, logs what earlier sessions
    /// withheld. A msg1 with no peer entry is always logged.
    pub(in crate::node) fn shown(&mut self, peer: &NodeAddr, kind: HsLine) -> bool {
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
            rekey_resend = withheld.of(HsLine::RekeyResend),
            rekey_resend_failed = withheld.of(HsLine::RekeyResendFailed),
            pending = withheld.of(HsLine::Pending),
            answered = withheld.of(HsLine::Answered),
            off_link = withheld.of(HsLine::OffLink),
            replace = withheld.of(HsLine::Replace),
            restart = withheld.of(HsLine::Restart),
            redial = withheld.of(HsLine::Redial),
            "Suppressed repeated handshake lines"
        );
    }

    /// A session of `peer` carried its first authenticated frame: drop the
    /// identity's silent-session record, and log how many of its refusal
    /// lines were not logged.
    pub(in crate::node) fn note_peer_heard(&mut self, peer: &NodeAddr) {
        let refused = self.gates.take_refused(peer);
        self.gates.framed(peer);
        let refused = diag::withheld(refused);
        if refused > 0 {
            debug!(
                peer = %self.peer_display_name(peer),
                refused,
                "Suppressed repeated handshake lines"
            );
        }
    }
}

impl Node {
    /// Feed the promoted peer's control machine the cross-connection resolution
    /// after the inline session surgery. The obs reconciles the machine's shadow
    /// session indices (updated on a swap, unchanged on a keep); it emits no
    /// action, so a bare `step` keeps the machine coherent without an executor
    /// pass.
    pub(in crate::node) fn observe_cross_conn_resolved(
        &mut self,
        node_addr: &NodeAddr,
        outcome: CrossConnOutcome,
    ) {
        let link = match self.peers.get(node_addr) {
            Some(peer) => peer.link_id(),
            None => return,
        };
        if let Some(machine) = self.peer_machines.get_mut(&link) {
            let acts = machine.step(
                PeerEvent::CrossConnResolved { outcome },
                Self::interval_ms(),
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
    /// for exempting traffic from stranger-class treatment. The settlement
    /// core's records of the node's links answer it
    /// ([`Placement::established`](crate::proto::settle::links::Placement::established)):
    /// the link index names a link at `(transport_id, remote_addr)`, or a
    /// held peer holds a path there that is Live or acked in the link,
    /// whatever its state now (multipath v1 draft, Section 5.10). A path
    /// still being probed is not. The index names each link at the address
    /// it was set up at, which for a dial is the configured form, perhaps a
    /// hostname, and the peer's paths are at the numeric addresses inbound
    /// packets carry, so a rekey msg1 from either form of an established
    /// peer's address is matched. Without the paths, the carve-out misses
    /// any deployment that combines a hostname-based peer config with
    /// `udp.accept_connections: false` or `udp.outbound_only: true` (the
    /// production trigger for the 2026-04-30 bug).
    ///
    /// Cost: one walk over the link records. Because `handle_msg1`
    /// classifies before rate limiting, it runs on every inbound msg1
    /// including those about to be refused, so a msg1 flood costs O(links)
    /// per dropped packet.
    pub(in crate::node) fn is_established_link_msg1(
        &self,
        transport_id: crate::transport::TransportId,
        remote_addr: &crate::transport::TransportAddr,
    ) -> bool {
        self.placement(&(transport_id, remote_addr.clone()))
            .established()
    }

    /// Classify the msg1 waiver for a source that `should_admit_msg1`
    /// admitted, so the post-DH confirmation knows whether it has an
    /// identity to check against and what to do when it has none.
    ///
    /// `established` is the caller's already-computed
    /// `is_established_link_msg1(...)`, so the walk is not repeated on the
    /// refusal path.
    ///
    /// The identity is the settlement core's records' answer
    /// ([`Placement::expected`](crate::proto::settle::links::Placement::expected)):
    /// the peer holding the link the index names at the pair, or the
    /// identity the handshake on that link expects; failing both, a held
    /// peer whose path there is Live or acked. A named link that yields no
    /// identity does not stop the search, because the index and the paths
    /// can hold different forms of the same peer's address (the
    /// hostname-vs-numeric case `is_established_link_msg1` describes).
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
        self.placement(&(transport_id, remote_addr.clone()))
            .expected()
            .map_or(Msg1Waiver::Unattributed, Msg1Waiver::Expect)
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

    /// Where a msg1 from `key` stands among the settlement core's records
    /// of the node's links, the identity a handshake leg expects read from
    /// its machine.
    pub(in crate::node) fn placement(
        &self,
        key: &crate::node::AddrKey,
    ) -> crate::proto::settle::links::Placement {
        self.links.placement(key, |id| {
            self.connections()
                .find(|(link, _)| **link == id)
                .and_then(|(_, machine)| machine.conn_expected_identity())
                .map(|identity| *identity.node_addr())
        })
    }

    /// The transport and address of `peer`'s established link, where a reply
    /// to the peer's msg1 goes first, whatever address the msg1 arrived from.
    fn established_link(
        &self,
        peer: &NodeAddr,
    ) -> Option<(
        crate::transport::TransportId,
        crate::transport::TransportAddr,
    )> {
        let p = self.peers.get(peer)?;
        Some((p.transport_id()?, p.current_addr()?.clone()))
    }

    /// Whether `peer`'s established link can carry a reply now: its transport
    /// is connectionless, or the transport still pools a connection to the
    /// link's address. False when the peer, its link or its transport is
    /// missing.
    ///
    /// Reads only, through `has_connection`: a finished background connect
    /// is not promoted and the pool lock is awaited, so the answer does not
    /// depend on lock contention.
    async fn link_reachable(&self, peer: &NodeAddr) -> bool {
        let Some((tid, addr)) = self.established_link(peer) else {
            return false;
        };
        match self.transports.get(&tid) {
            Some(transport) => transport.has_connection(&addr).await,
            None => false,
        }
    }

    /// Send `reply`, an answer to `packet`'s msg1 from `peer`, on `route`.
    /// Returns the transport the reply went out on.
    ///
    /// [`Route::Arrival`] sends on the msg1's own transport and source
    /// address, with the link up or not. A connectionless source address is
    /// whatever the sender wrote, so this route trusts it; the machine picks
    /// it only with multipath enabled (`node.path.enabled`), for a msg1 that
    /// arrived on the established link, and the caller sends on it only when
    /// the msg1 came on one of the link's proven paths. A msg1 on the link
    /// from any other pair is answered on the established route with its
    /// fallback instead.
    ///
    /// [`Route::Established`] sends on the peer's established link, or, with
    /// `fallback` set, on the connection the msg1 arrived on when the
    /// established link's connection has gone.
    ///
    /// Neither send dials. The established route's fallback uses the arrival
    /// connection only on a connection-oriented transport: the remote opened
    /// it, so a reply on it reaches only the remote. That is how a peer that
    /// redialed after its old connection closed has its msg1 answered before
    /// the old link is reaped. On that route a msg1 that came over a
    /// connectionless transport is answered on the established link only.
    ///
    /// The arrival connection must also be on the established link's
    /// transport. The fallback stands in for the established link's own
    /// connection, which the far end has replaced on that transport, so it
    /// answers only there; sending an answer on another path is a choice for
    /// the answer's route to make, not for this fallback.
    ///
    /// The fallback needs the established connection to be gone from the
    /// pool. A half-open one, whose path broke without a FIN or reset
    /// reaching this node, still accepts writes, so the reply is lost there
    /// until the link-dead reaper removes the peer.
    pub(in crate::node) async fn answer_msg1(
        &self,
        peer: &NodeAddr,
        packet: &ReceivedPacket,
        reply: &[u8],
        route: Route,
    ) -> Result<TransportId, String> {
        let fallback = match route {
            Route::Arrival => {
                let transport = self
                    .transports
                    .get(&packet.transport_id)
                    .ok_or_else(|| "no transport for the msg1's arrival".to_string())?;
                transport
                    .send_existing(&packet.remote_addr, reply)
                    .await
                    .map_err(|e| e.to_string())?;
                return Ok(packet.transport_id);
            }
            Route::Established { fallback } => fallback,
        };
        let (tid, addr) = self
            .established_link(peer)
            .ok_or_else(|| "the peer has no established link".to_string())?;
        let transport = self
            .transports
            .get(&tid)
            .ok_or_else(|| "no transport for the peer's link".to_string())?;
        match transport.send_existing(&addr, reply).await {
            Ok(_) => return Ok(tid),
            Err(TransportError::NotConnected) => {}
            Err(e) => return Err(e.to_string()),
        }
        if !fallback
            || packet.transport_id != tid
            || packet.remote_addr == addr
            || !transport.transport_type().connection_oriented
        {
            return Err(TransportError::NotConnected.to_string());
        }
        transport
            .send_existing(&packet.remote_addr, reply)
            .await
            .map_err(|e| format!("established link not connected; msg1's connection: {e}"))?;
        debug!(
            peer = %self.peer_display_name(peer),
            remote_addr = %packet.remote_addr,
            transport_id = %packet.transport_id,
            link_tid = %tid,
            link_addr = %addr,
            "Established link not connected, answered on the msg1's connection"
        );
        Ok(tid)
    }

    /// Handle handshake message 1 (phase 0x1).
    ///
    /// This creates a new inbound connection. Rate limiting is applied
    /// before any expensive crypto operations.
    ///
    /// Classifying the source costs no crypto (one walk over the link
    /// records), so it happens first and selects which bucket the msg1 draws
    /// on: rekey and restart traffic from an established link stops
    /// competing with stranger admission, while still being metered.
    pub(in crate::node) async fn handle_msg1(&mut self, packet: ReceivedPacket) {
        #[cfg(test)]
        self.resync();
        self.msg1_body(packet).await;
        self.audit_live("handle_msg1");
    }

    /// The work of [`Self::handle_msg1`], which audits the per-peer maps
    /// after it.
    async fn msg1_body(&mut self, packet: ReceivedPacket) {
        // === CLASSIFY, THEN RATE LIMIT (both before any crypto) ===
        // Classification is one walk over the settlement core's link
        // records, O(links), and runs on every inbound msg1, including
        // refused ones. See the `is_established_link_msg1` doc comment for
        // why it reads the paths as well as the index.
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

        // The shadow core takes every msg1 the rate limiter admits, before
        // any Diffie-Hellman. The limiter is the node's resource admission,
        // not a settlement decision: a msg1 it refuses never reaches the
        // core, and its refusal is not one the core is compared on.
        #[cfg(test)]
        self.decide(crate::proto::settle::input::Input::Arrived {
            from: crate::proto::settle::links::Pair {
                transport: packet.transport_id,
                addr: packet.remote_addr.clone(),
            },
            bytes: packet.data.clone(),
        });

        // accept_connections gate. Rekey/restart msg1 on an existing link
        // is always admitted; the gate only filters truly-fresh connections
        // from strangers. Without this carve-out, the dual-init tie-breaker
        // deadlocks when the larger-NodeAddr side has accept_connections=false.
        //
        // `!established &&` is not a behaviour change: `should_admit_msg1`
        // is `is_established_link_msg1() || accept_connections()`, so the
        // short-circuit only skips a second walk over the settlement core's
        // link records on the hot path. The call is left in place so the two
        // predicates cannot drift apart.
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
        // lost or never sent: resend the stored msg2 without paying the crypto
        // cost and return. A leg whose first send failed transiently was never
        // promoted, so a successful resend promotes it here. An inbound link
        // that DOES belong to an active peer (a possible restart/rekey) or an
        // *outbound* link (a cross-connection) falls through to the wire step
        // and the structured classification below — the pre-refactor
        // `possible_restart` flag is no longer needed because that
        // classification now gates on `has_existing_peer` (identity), which
        // subsumes it.
        let addr_key = (packet.transport_id, packet.remote_addr.clone());
        #[cfg(all(test, debug_assertions))]
        crate::node::settle::audit::placed(
            self,
            "duplicate",
            &addr_key,
            crate::node::settle::audit::Asked::Unanswered(
                self.links.index().get(&addr_key).copied().filter(|id| {
                    self.links
                        .get(id)
                        .is_some_and(|l| l.direction() == LinkDirection::Inbound)
                        && !self.peers.values().any(|p| p.link_id() == *id)
                }),
            ),
        );
        if let Some(&existing_link_id) = self.links.index().get(&addr_key)
            && let Some(link) = self.links.get(&existing_link_id)
        {
            // Once sent, a stored msg2 answers only the msg1 it was written
            // for. Any other msg1 from this address, such as a fresh dial of
            // the same peer or a capture spoofed from it, is read and
            // classified below rather than answered with keys it does not
            // hold.
            let own_msg1 = self.peer_machines.get(&existing_link_id).is_none_or(|m| {
                !m.msg2_sent()
                    || node_fault!(StoredAnswersAny)
                    || m.conn_msg1_digest() == Some(Msg1Digest::of(&packet.data))
            });
            if link.direction() == LinkDirection::Inbound && !own_msg1 {
                debug!(
                    remote_addr = %packet.remote_addr,
                    transport_id = %packet.transport_id,
                    link_id = %existing_link_id,
                    "Msg1 from the address of a pending inbound link is not the msg1 its sent msg2 answers, classifying it"
                );
            } else if link.direction() == LinkDirection::Inbound {
                let is_active_peer = self.peers.values().any(|p| p.link_id() == existing_link_id);
                if !is_active_peer {
                    // Genuinely pending handshake — resend the msg2 its
                    // answer's leg stored.
                    let msg2_bytes = self
                        .links
                        .no(&existing_link_id)
                        .and_then(|no| self.legs.msg2(no))
                        .map(<[u8]>::to_vec);
                    if let Some(msg2) = msg2_bytes {
                        if let Some(transport) = self.transports.get(&packet.transport_id) {
                            // The answer is decided here; whether its send
                            // went out is told after, as for a first answer.
                            #[cfg(test)]
                            self.did(crate::node::settle::exec::Did::Answer { stored: true });
                            match transport.send_existing(&packet.remote_addr, &msg2).await {
                                Ok(_) => {
                                    if let Some(m) = self.peer_machines.get_mut(&existing_link_id) {
                                        m.note_msg2_sent();
                                    }
                                    debug!(
                                        remote_addr = %packet.remote_addr,
                                        transport_id = %packet.transport_id,
                                        link_id = %existing_link_id,
                                        "Resent msg2 for duplicate msg1"
                                    );
                                    #[cfg(test)]
                                    self.shadow_sent(existing_link_id, true);
                                    self.promote_resent(existing_link_id, &packet).await;
                                }
                                Err(e) => {
                                    debug!(
                                        remote_addr = %packet.remote_addr,
                                        error = %e,
                                        transport_id = %packet.transport_id,
                                        link_id = %existing_link_id,
                                        "Failed to resend msg2"
                                    );
                                    #[cfg(test)]
                                    self.shadow_sent(existing_link_id, false);
                                }
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
        // The packet's wall stamp for what operators are shown, and the
        // interval clock, read once here, for the handshake's timers and
        // timeout.
        let interval_ms = Self::interval_ms();
        let leg_at = LegStamp {
            wall_ms: packet.timestamp_ms,
            interval_ms,
        };

        // The control machine drives the handshake, so it is built here, above
        // the crypto. It stays a local: it enters `peer_machines` only at the
        // promote tails, so a rejected msg1 still leaves no registry trace and
        // allocates no index.
        let mut machine = PeerMachine::new_inbound(link_id, leg_at);
        // Seed the carrier with the transport and address msg1 arrived on, so
        // the promotion hand-off reads them from it.
        machine.set_conn_transport_id(packet.transport_id);
        machine.set_conn_source_addr(packet.remote_addr.clone());
        machine.set_leg(HandshakeCrypto::new());

        // This frame's own copy of the node's long-term private key; the
        // handshake state keeps its own and clears that on drop.
        let mut our_keypair = self.identity().keypair();
        let noise_msg1 = &packet.data[header.noise_msg1_offset..];
        let ephemeral = EphemeralDigest::of_noise_msg1(noise_msg1);
        let init_result =
            machine.receive_handshake_init(our_keypair, self.startup_epoch(), noise_msg1, leg_at);
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
            msg1_digest: Msg1Digest::of(&packet.data),
        };
        // The shadow core reads the msg1 as the node has: what an admitted
        // msg1 opens is numbered as this msg1's link.
        // The Noise read took the ephemeral, so the msg1 carries one.
        #[cfg(test)]
        let shadow_read = ephemeral.map(|ephemeral| crate::proto::settle::input::Read {
            peer: peer_node_addr,
            from: crate::proto::settle::links::Pair {
                transport: packet.transport_id,
                addr: packet.remote_addr.clone(),
            },
            bytes: packet.data.clone(),
            ephemeral,
            epoch: wire.remote_epoch.unwrap_or_default(),
        });
        #[cfg(test)]
        if let Some(read) = shadow_read.clone() {
            let reachable = !self.peers.contains_key(&peer_node_addr)
                || self.link_reachable(&peer_node_addr).await;
            let input = crate::proto::settle::input::Input::Msg1 { read, reachable };
            self.decide_at(Some(link_id), input);
        }
        // The promotion line reads the msg1's digest from the carrier.
        machine.set_conn_msg1_digest(wire.msg1_digest);
        // The work that follows a promotion records the msg1 on the peer, and
        // runs where the packet is no longer at hand.
        machine.hold_msg1(packet.data.clone());

        // === PHASE C input ===
        // Snapshot the registry state the inbound classification reads about
        // this peer identity (its existing epoch, the max-peers cap, a pending
        // outbound dial, its silent-session refusal). Taken before this
        // connection is inserted into the registry.
        let est = self.establish_snapshot(&peer_node_addr);
        let silent_backoff = est.silent_backoff;
        let msg1_dg = diag::msg1_tag(&wire.msg1_digest);

        // === PHASE C: structured classification ===
        // Evaluate the inbound decision on a local establish leg and route on
        // it. A same-epoch msg1 from a held peer goes to that peer's link
        // rekey machine, which owns FRC-1201 rules 3 and 4; only when that
        // machine asks for the restart gates (a fresh dial on a link too young
        // to rekey) is the msg1 classified again as a replacement. `Promote`,
        // `RestartThenPromote` and `ReplaceThenPromote` fall through to the
        // shared authorize → allocate → send-msg2 → promote tail; the other
        // variants complete the rate-limiter and return here. The local machine
        // enters `peer_machines` only at the promote tails.
        let (mut decision, mut actions) =
            machine.inbound_msg1(link_id, &wire, est, packet.timestamp_ms);
        let mut redial_ephemeral = None;
        if let InboundDecision::Rekey { peer } = decision {
            debug_assert!(actions.is_empty());
            let mut est = self.establish_snapshot(&peer_node_addr);
            match self.msg1_to_link(&peer, &packet, &wire).await {
                LinkVerdict::Done => return,
                LinkVerdict::Replace => {
                    // The rekey machine asked for the restart gates: the
                    // shadow core is told of the replacement it asked for.
                    #[cfg(test)]
                    if let Some(read) = shadow_read.clone() {
                        self.decide_at(
                            Some(link_id),
                            crate::proto::settle::input::Input::Replace(read),
                        );
                    }
                    est.replace = true;
                }
                LinkVerdict::Redial(e) => {
                    // The shadow core is not told of a redial yet: the
                    // comparison stops at one.
                    #[cfg(test)]
                    self.shadow.diverge();
                    est.redial = true;
                    redial_ephemeral = Some(e);
                }
            }
            (decision, actions) = machine.inbound_msg1(link_id, &wire, est, packet.timestamp_ms);
        }
        let replacing = matches!(decision, InboundDecision::ReplaceThenPromote { .. });
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
                #[cfg(test)]
                self.did(crate::node::settle::exec::Did::Reject {
                    peer: Some(peer_node_addr),
                });
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(msg1_reject(
                        &InboundReject::AtMaxPeers,
                    )));
            }
            InboundDecision::Reject {
                reason: InboundReject::SilentBackoff,
            } => {
                // The identity's last sessions at this epoch carried no
                // frame and its back-off is running. The classification
                // failed the fresh leg with no actions, and `conn`/`link_id`
                // were never registered, so dropping the msg1 unanswered is
                // the whole effect.
                debug_assert!(actions.is_empty());
                // Counted on the identity's record, since a refused msg1
                // may have no peer entry to count on.
                let shown = self
                    .gates
                    .count_refused(&peer_node_addr)
                    .is_none_or(|n| self.show(&peer_node_addr, HsLine::Refused, n));
                if shown {
                    debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        msg1_dg = %msg1_dg,
                        silent = %OrNone(silent_backoff.map(|b| b.silent)),
                        remaining_s = %OrNone(silent_backoff.map(|b| b.remaining_ms.div_ceil(1000))),
                        "Msg1 from a peer whose recent sessions carried no frame, refusing during its back-off"
                    );
                }
                #[cfg(test)]
                self.did(crate::node::settle::exec::Did::Reject {
                    peer: Some(peer_node_addr),
                });
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(msg1_reject(
                        &InboundReject::SilentBackoff,
                    )));
            }
            InboundDecision::Rekey { .. } => {
                // Classified again with the replacement requested, a held
                // peer's msg1 is a replacement or a refusal, never a rekey.
                debug_assert!(false, "a replacement was classified as a rekey");
            }
            InboundDecision::Redial { peer } => {
                debug_assert!(actions.is_empty());
                let armed = Armed {
                    machine,
                    link: link_id,
                    peer,
                    identity: peer_identity,
                    digest: redial_ephemeral,
                    ephemeral,
                    leg_at,
                };
                // Boxed: the redial's arming adds its own state to the msg1
                // handler's future, which a test's thread runs on its stack.
                Box::pin(self.arm_redial(armed, &packet, &wire)).await;
            }
            InboundDecision::RestartThenPromote { peer }
            | InboundDecision::ReplaceThenPromote { peer } => {
                // === Restart inbound establish, driven by the machine. ===
                // Epoch mismatch — the peer restarted. The fresh leg is promoted
                // exactly like a net-new inbound (two-phase authorize); the OLD
                // peer's teardown is the machine's Phase-1
                // `[InvalidateSendState, ReportLost{peer}]`:
                //   InvalidateSendState → the removal of old: frees the four
                //     index slots + `peers_by_index` + decrypt unregister + FSP
                //     `sessions`, keeping the packets held for the peer. The fresh leg's
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
                //
                // A same-epoch replacement is the same teardown and just as
                // replayable: the link's record recognises a captured msg1 of
                // an earlier peering at the same epoch only while the node's
                // store still holds that peering's record, and never one this
                // node did not see. So it is gated by the same two conditions
                // and the same per-peer dampener.
                //
                // The peering's own promotion is not evidence that it is
                // alive: a responder promotion came from a msg1, which may be
                // a capture. Until its first authenticated frame it counts as
                // idle once `UNHEARD_PEERING_MIN_AGE_MS` old (on the peer
                // clock, from its promotion), so the genuine peer's msg1 can
                // replace it, while the second msg1 of a dialer opening two
                // paths at once cannot replace the first. What bounds
                // that churn instead is the replay memory: an ephemeral that
                // already promoted an unheard peering of this peer inside the
                // interval is not answered again (a header-changed copy of a
                // capture the link's record does not hold lands here), and
                // once the peer has spent the memory's bound of them a
                // further replacement waits for the oldest to age out.
                // The settlement core's restart gates judge it, in that order:
                // the replay memory, the two floors, then the dampener, which
                // an acceptance tearing down a heard peering stamps.
                let now_ms = Self::now_ms();
                // The logs report the idle time from the wall-clock stamps
                // operators are shown, as they always have; the gates measure
                // on the peer clock, which a step of the system clock does not
                // move. For an unheard peering it is its age since promotion,
                // not time since the peer was heard.
                let shown_idle_ms = self.peers.get(&peer).map_or(u64::MAX, |p| {
                    if p.is_heard() {
                        p.idle_time(now_ms)
                    } else {
                        packet.timestamp_ms.saturating_sub(p.authenticated_at())
                    }
                });
                let params = self.gate_params();
                let now = crate::peer::peer_now();
                let dampened = self
                    .gates
                    .stamp(&peer)
                    .is_some_and(|t| now.saturating_duration_since(t) < params.interval);
                let ask = Ask {
                    source: if replacing {
                        Source::Replacement
                    } else {
                        Source::Restart
                    },
                    held: self.liveness(&peer, packet.timestamp_ms),
                    ephemeral,
                    epoch: wire.remote_epoch,
                    memory: Self::memory_instant(&packet),
                };
                match self.gates.gate(peer, ask, now, &params) {
                    None => {}
                    Some(refusal @ (Refusal::Replayed | Refusal::ReplayFull)) => {
                        debug!(
                            peer = %self.peer_display_name(&peer),
                            remote_addr = %packet.remote_addr,
                            reason = match refusal {
                                Refusal::Replayed => "replayed-ephemeral",
                                _ => "replay-memory-full",
                            },
                            "Msg1 replacing an unheard peering was already used or over the per-peer bound, dropping"
                        );
                        #[cfg(test)]
                        self.did(crate::node::settle::exec::Did::Reject { peer: Some(peer) });
                        self.stats_mut()
                            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        return;
                    }
                    Some(refusal) => {
                        let reason = match refusal {
                            Refusal::Heard => "heard-within-interval",
                            Refusal::Unheard => "unheard-peering-young",
                            Refusal::Silent => "silent-backoff",
                            // A redial's refusal is not one a restart or a
                            // replacement is given.
                            Refusal::Dampened
                            | Refusal::Replayed
                            | Refusal::ReplayFull
                            | Refusal::Redialed => "dampened",
                        };
                        if replacing {
                            if self.shown(&peer, HsLine::Replace) {
                                debug!(
                                    peer = %self.peer_display_name(&peer),
                                    remote_addr = %packet.remote_addr,
                                    idle_ms = shown_idle_ms,
                                    dampened,
                                    reason,
                                    "Same-epoch msg1 inside the peering's replacement interval, dropping"
                                );
                            }
                        } else if self.shown(&peer, HsLine::Restart) {
                            debug!(
                                peer = %self.peer_display_name(&peer),
                                remote_addr = %packet.remote_addr,
                                idle_ms = shown_idle_ms,
                                dampened,
                                reason,
                                "Epoch mismatch inside the peering's restart interval, dropping msg1"
                            );
                        }
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
                        #[cfg(test)]
                        self.did(crate::node::settle::exec::Did::Reject { peer: Some(peer) });
                        self.stats_mut()
                            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        return;
                    }
                }
                // Stamped on acceptance only, by the gates. A refusal that
                // slid the window would let a sustained replay starve a
                // genuinely restarting peer for as long as it kept sending.
                // Stamped only when the peering torn down had been heard from:
                // the dampener bounds churn a peer drives on its own, and a
                // peering that never carried a frame is not that. Stamping it
                // would let two captured msg1s refuse the genuine peer for the
                // interval.

                if replacing {
                    debug!(
                        peer = %self.peer_display_name(&peer),
                        "Same-epoch msg1 from a silent peer, replacing its session"
                    );
                } else {
                    debug!(
                        peer = %self.peer_display_name(&peer),
                        "Peer restart detected (epoch mismatch), removing stale session"
                    );
                }

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
                // authorize/alloc). `ReportLost` schedules the reconnect on the
                // peering clock (`note_link_dead` at `Self::peering_now()`), a
                // monotonic one, and reads neither of the ambient's stamps. The
                // machine is not yet in
                // `peer_machines`, but these two
                // actions do not touch the map, so executing them here is safe.
                // The removal runs the first part of the replacement's plan,
                // and the promotion below, told the same cause, the rest.
                let why = if replacing {
                    Why::Replacement
                } else {
                    Why::Restart
                };
                let teardown_ctx = PeerActionCtx {
                    verified_identity: peer_identity,
                    transport_id: packet.transport_id,
                    remote_addr: packet.remote_addr.clone(),
                    our_index: None,
                    their_index: Some(their_index),
                    now_ms: packet.timestamp_ms,
                    interval_ms,
                    is_outbound: false,
                    why: Some(why),
                };
                let carried_announce = if node_fault!(TreeCarryAcrossRestart) {
                    self.peers
                        .get(&peer)
                        .map(|p| p.last_tree_announce_sent_ms())
                } else {
                    None
                };
                self.execute_peer_actions(link_id, &teardown_ctx, actions)
                    .await;

                // Admitted: the answer is asked for, and authorized next.
                #[cfg(test)]
                self.did(crate::node::settle::exec::Did::Ask {
                    peer: peer_node_addr,
                });
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
                    let _ = machine.step(PeerEvent::Rejected, interval_ms);
                    #[cfg(test)]
                    self.shadow_unasked(link_id);
                    // The refused msg1's connection closes now, unless a
                    // live link uses it, rather than at the transport's
                    // idle deadline.
                    self.close_pair(packet.transport_id, &packet.remote_addr, link_id)
                        .await;
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }

                // Phase 2: allocate our index, which the answer's leg holds
                // until the promotion takes it, then emit [SendHandshake,
                // PromoteToActive].
                let our_lease = match allocate(&mut self.index_allocator) {
                    Some(lease) => lease,
                    None => {
                        // Allocation exhausted in Phase 2 (mirrors the pre-refactor
                        // allocate-failure path): no msg2, no promote. The old peer
                        // has already been torn down above — identical to the
                        // pre-refactor arm, which also removed the stale peer before
                        // hitting the shared allocate-failure return.
                        warn!("Failed to allocate session index for inbound");
                        #[cfg(test)]
                        self.shadow_unasked(link_id);
                        self.close_pair(packet.transport_id, &packet.remote_addr, link_id)
                            .await;
                        self.stats_mut()
                            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        return;
                    }
                };
                let our_index = SessionIndex::new(our_lease.index());
                let promote_actions = machine.step(PeerEvent::Authorized, interval_ms);

                // Shell registry surgery, in the pre-refactor order:
                // set indices on the shell connection, insert link / reverse map /
                // connection, then build + store the framed msg2. The old index was
                // already freed by the removal above, BEFORE this fresh
                // allocation — matching the pre-refactor allocation sequence.
                let link = Link::connectionless(
                    link_id,
                    packet.transport_id,
                    packet.remote_addr.clone(),
                    LinkDirection::Inbound,
                    Duration::from_millis(self.config().node.base_rtt_ms),
                );
                self.links.open(link);
                let wire_msg2 = build_msg2(our_index, their_index, &msg2_payload);
                #[cfg(test)]
                self.did(crate::node::settle::exec::Did::Answer { stored: false });
                #[cfg(test)]
                self.shadow_hello(link_id, our_index.as_u32(), &wire_msg2, interval_ms);
                // The answer's leg, the settlement core's: the msg1 answered,
                // the framed msg2 a resend of that msg1 draws while the
                // connection is still pending, and the lease, reaped at the
                // handshake deadline counted from the msg1's arrival. The
                // surviving carrier keeps the msg2 for the promotion's tail.
                self.answer_leg(
                    link_id,
                    *peer_identity.node_addr(),
                    &packet.data,
                    wire_msg2.clone(),
                    our_lease,
                    interval_ms,
                );
                machine.set_conn_handshake_msg2(wire_msg2);

                // Register the machine, which already carries the connection
                // (Promote/Restart tail only).
                self.peer_machines.add(link_id, machine);

                // Execute [SendHandshake, PromoteToActive]. The old peer was
                // removed in Phase 1, so `promote_connection` finds no peer held
                // for the identity and returns `Promoted`; a held one would be
                // refused (`NodeError::IdentityHeld`), which the executor asserts
                // never happens.
                let ambient = PeerActionCtx {
                    verified_identity: peer_identity,
                    transport_id: packet.transport_id,
                    remote_addr: packet.remote_addr.clone(),
                    our_index: Some(our_index),
                    their_index: Some(their_index),
                    now_ms: packet.timestamp_ms,
                    interval_ms,
                    is_outbound: false,
                    why: Some(why),
                };
                self.execute_peer_actions(link_id, &ambient, promote_actions)
                    .await;
                if let (Some(sent), Some(p)) = (carried_announce, self.peers.get_mut(&peer)) {
                    p.set_last_tree_announce_sent_ms(sent);
                }

                // Three outcomes reach this line: a terminal send failure or a
                // promote failure removed the machine, leaving it absent; a
                // TRANSIENT msg2 send failure aborted the queue before
                // `PromoteToActive` ran and deliberately left the half-built leg in
                // place, so the machine is still registered at
                // `Handshaking{ReceivedMsg1}` (`peer_actions.rs`, the
                // `is_transient` branch) until a resend of the stored msg2
                // promotes it (`promote_resent`); or promotion succeeded, and the
                // executor's promotion arm ran the promotion's tail, leaving the
                // machine Established. The debug_assert below catches any
                // regression that reaches a state other than those three.
                debug_assert!(matches!(
                    self.peer_machines.get(&link_id).map(|m| m.state()),
                    Some(PeerState::Established { .. })
                        | Some(PeerState::Handshaking {
                            phase: HandshakePhase::ReceivedMsg1,
                            ..
                        })
                        | None
                ));
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

                // Admitted: the answer is asked for, and authorized next.
                #[cfg(test)]
                self.did(crate::node::settle::exec::Did::Ask {
                    peer: peer_node_addr,
                });
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
                    let _ = machine.step(PeerEvent::Rejected, interval_ms);
                    #[cfg(test)]
                    self.shadow_unasked(link_id);
                    // The refused msg1's connection closes now, unless a
                    // live link uses it, rather than at the transport's
                    // idle deadline.
                    self.close_pair(packet.transport_id, &packet.remote_addr, link_id)
                        .await;
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }

                // Phase 2: allocate our index, which the answer's leg holds
                // until the promotion takes it, then emit [SendHandshake,
                // PromoteToActive].
                let our_lease = match allocate(&mut self.index_allocator) {
                    Some(lease) => lease,
                    None => {
                        // Allocation exhausted in Phase 2 (mirrors the pre-refactor
                        // allocate-failure path): no msg2, no promote. The restored
                        // warn! carries the pre-refactor message text only.
                        warn!("Failed to allocate session index for inbound");
                        #[cfg(test)]
                        self.shadow_unasked(link_id);
                        self.close_pair(packet.transport_id, &packet.remote_addr, link_id)
                            .await;
                        self.stats_mut()
                            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        return;
                    }
                };
                let our_index = SessionIndex::new(our_lease.index());
                let promote_actions = machine.step(PeerEvent::Authorized, interval_ms);

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
                self.links.open(link);
                let wire_msg2 = build_msg2(our_index, their_index, &msg2_payload);
                #[cfg(test)]
                self.did(crate::node::settle::exec::Did::Answer { stored: false });
                #[cfg(test)]
                self.shadow_hello(link_id, our_index.as_u32(), &wire_msg2, interval_ms);
                // The answer's leg, the settlement core's: the msg1 answered,
                // the framed msg2 a resend of that msg1 draws while the
                // connection is still pending, and the lease, reaped at the
                // handshake deadline counted from the msg1's arrival. The
                // surviving carrier keeps the msg2 for the promotion's tail.
                self.answer_leg(
                    link_id,
                    *peer_identity.node_addr(),
                    &packet.data,
                    wire_msg2.clone(),
                    our_lease,
                    interval_ms,
                );
                machine.set_conn_handshake_msg2(wire_msg2);

                // Register the machine, which already carries the connection
                // (Promote tail only — discarded on every reject/resend/rekey
                // arm per the insertion discipline).
                self.peer_machines.add(link_id, machine);

                // Execute [SendHandshake, PromoteToActive]. The executor frames +
                // sends msg2 (bytes identical to `wire_msg2`), promotes via
                // `promote_connection`, feeds PromotionResolved back, and runs the
                // inert RegisterDecryptSession (register stays in
                // `promote_connection`), and once the promotion succeeded runs
                // the promotion's tail: the msg2 and msg1 stored on the peer, an
                // unheard peering's ephemeral remembered, the initial tree
                // announce and the filter announce scheduled. Its TERMINAL
                // send-failure and its promote-failure arms run the pre-refactor
                // cleanup and remove the machine, leaving it absent (not
                // Established); its TRANSIENT send-failure arm aborts the queue
                // before `PromoteToActive` and leaves the machine registered at
                // `Handshaking{ReceivedMsg1}` for the initiator's msg1 resend to
                // land on, which promotes it once the stored msg2 is sent
                // (`promote_resent`). Neither runs the tail.
                let ambient = PeerActionCtx {
                    verified_identity: peer_identity,
                    transport_id: packet.transport_id,
                    remote_addr: packet.remote_addr.clone(),
                    our_index: Some(our_index),
                    their_index: Some(their_index),
                    now_ms: packet.timestamp_ms,
                    interval_ms,
                    is_outbound: false,
                    why: None,
                };
                self.execute_peer_actions(link_id, &ambient, promote_actions)
                    .await;
            }
        }
    }

    /// Promote the pending inbound leg on `link` after its stored msg2 was
    /// sent in answer to `packet`, and finish the promotion as a first
    /// successful send would. A leg that has learned no identity or holds no
    /// indices is left alone.
    async fn promote_resent(&mut self, link: LinkId, packet: &ReceivedPacket) {
        let ours = self.leg(link).map(|leg| SessionIndex::new(leg.index()));
        let Some((identity, ours, theirs)) = self
            .peer_machines
            .get(&link)
            .and_then(|m| Some((*m.conn_expected_identity()?, ours?, m.conn_their_index()?)))
        else {
            return;
        };
        let peer = *identity.node_addr();
        let peer_held = self.peers.contains_key(&peer);
        let interval_ms = Self::interval_ms();
        let ambient = PeerActionCtx {
            verified_identity: identity,
            transport_id: packet.transport_id,
            remote_addr: packet.remote_addr.clone(),
            our_index: Some(ours),
            their_index: Some(theirs),
            now_ms: packet.timestamp_ms,
            interval_ms,
            is_outbound: false,
            why: None,
        };
        self.advance_peer_machine(
            link,
            PeerEvent::Msg2Resent { peer_held },
            interval_ms,
            &ambient,
        )
        .await;
        // The executor's promotion arm finished the promotion, leaving the
        // machine Established, when it promoted.
        if matches!(
            self.peer_machines.get(&link).map(|m| m.state()),
            Some(PeerState::Established { .. })
        ) {
            debug!(
                link_id = %link,
                peer = %self.peer_display_name(&peer),
                "Promoted a pending inbound link after resending its msg2"
            );
        } else if peer_held {
            debug!(
                link_id = %link,
                peer = %self.peer_display_name(&peer),
                "Resent msg2 for a pending link whose peer is held on another link, not promoting"
            );
        }
    }

    /// Remember the ephemeral of a msg1 that promoted `peer` here, if the
    /// peering it left is unheard (a cross-connection may have kept a peering
    /// this node initiated instead).
    pub(in crate::node) fn note_unheard_promotion(
        &mut self,
        peer: &NodeAddr,
        ephemeral: Option<EphemeralDigest>,
    ) {
        let unheard = self.peers.get(peer).is_some_and(|p| !p.is_heard());
        if unheard && let Some(ephemeral) = ephemeral {
            let params = self.gate_params();
            self.gates.promoted(
                *peer,
                ephemeral,
                crate::peer::peer_now(),
                Self::memory_now(),
                &params,
            );
        }
    }

    /// The restart gates' parameters: the core's own, which no
    /// configuration moves.
    pub(in crate::node) fn gate_params(&self) -> Params {
        settle_params(&self.config().node)
    }

    /// What the restart gates know of the peering held for `peer`, as a
    /// restart source stamped `stamp_ms` on the wall clock would tear it
    /// down: whether it is heard, when it was promoted, and when its last
    /// frame authenticated (its promotion before the first). `None` when no
    /// peering is held.
    pub(in crate::node) fn liveness(
        &self,
        peer: &NodeAddr,
        stamp_ms: u64,
    ) -> Option<Liveness<PeerInstant>> {
        let p = self.peers.get(peer)?;
        let mut live = Liveness {
            heard: p.is_heard(),
            installed: p.promoted_at(),
            last: Some(p.heard_at()),
        };
        // The mutation lane's breaks: the heard floor read from the wall
        // clock's idle time, and the unheard peering's age from the source's
        // wall stamp.
        if node_fault!(GateOnWall) {
            live.last = Some(ago(p.idle_time(Self::now_ms())));
        }
        if node_fault!(UnheardAgeOnWall) {
            live.installed = ago(stamp_ms.saturating_sub(p.authenticated_at()));
        }
        Some(live)
    }

    /// The instant the restart gates read the replay memory at for a msg1
    /// in `packet`: the peer clock's now (`None`), or, under the mutation
    /// lane's breaks, the wall clock, or the msg1's wall stamp taken as a
    /// reading of the peer clock.
    pub(in crate::node) fn memory_instant(packet: &ReceivedPacket) -> Option<PeerInstant> {
        match (
            node_fault!(MemoryOnWall),
            node_fault!(MemoryVerdictOnPacketStamp),
        ) {
            (true, _) => Some(wall_now()),
            (false, true) => Some(mono_instant(packet.timestamp_ms)),
            (false, false) => None,
        }
    }

    /// The instant the restart gates read and store the replay memory at
    /// for a writer other than a msg1's gate: the peer clock's now
    /// (`None`), or the wall clock under the mutation lane's break that
    /// measures the replay memory there, so the memory stays on one clock.
    pub(in crate::node) fn memory_now() -> Option<PeerInstant> {
        node_fault!(MemoryOnWall).then(wall_now)
    }

    /// Ask the restart gates about a new epoch `epoch` that a msg2 stamped
    /// `stamp_ms` on the wall clock found for the peer held as `peer`: the
    /// msg2 of a link rekey when `rekey`, else the answer to this node's own
    /// dial. The gates pass both msg2 sources, since a msg2 is the reply to
    /// this node's own handshake; the refusal, if any, is returned.
    pub(in crate::node) fn gate_msg2(
        &mut self,
        peer: NodeAddr,
        rekey: bool,
        epoch: Option<[u8; 8]>,
        stamp_ms: u64,
    ) -> Option<Refusal> {
        let ask = Ask {
            source: Source::msg2(rekey),
            held: self.liveness(&peer, stamp_ms),
            ephemeral: None,
            epoch,
            memory: Self::memory_now(),
        };
        let params = self.gate_params();
        self.gates.gate(peer, ask, crate::peer::peer_now(), &params)
    }

    /// Hand `packet`'s msg1, read as `wire`, a same-epoch msg1 from the held
    /// peer `peer`, to that peer's link rekey machine, and carry out what it
    /// asks for: answer it into a new pending session, resend a stored
    /// answer, or refuse it, each counted and logged. Returns where the
    /// msg1 goes next: nowhere, to the restart gates as a replacement (the
    /// machine asked for them, for a fresh dial on the link while it is too
    /// young to rekey, or the peer has no machine to ask), or to a pending
    /// redial (the machine asked for one, for a fresh dial off the link).
    async fn msg1_to_link(
        &mut self,
        peer: &NodeAddr,
        packet: &ReceivedPacket,
        wire: &WireOutcome,
    ) -> LinkVerdict {
        if !self.peers.get(peer).is_some_and(|p| p.has_session()) {
            return LinkVerdict::Replace;
        }
        let local = self.session_node_keys();
        let Some(tok) = read_msg1::<OsEntropy>(&local, &packet.data) else {
            // The control machine's read authenticated this msg1, so only one
            // that carries no startup epoch fails the machine's.
            debug!(
                peer = %self.peer_display_name(peer),
                remote_addr = %packet.remote_addr,
                "Same-epoch msg1 carries no startup epoch, dropping"
            );
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return LinkVerdict::Done;
        };
        // A held path still Probing is treated as no path, even where a
        // link index entry maps its pair to the link: the machine then
        // refuses the msg1 while the established link is reachable and
        // accepts it once the link is down. `proven` keeps whether the pair
        // is a proven path, for the answer's route below; the link step
        // does not change the peer's paths.
        let (on_link, proven) = self.link_arrival(peer, packet);
        // Only a heard peering is redialed (operator decision, 2026-11-17):
        // a fresh msg1 off the link of an unheard one keeps the replacement
        // at the msg1 and its floors.
        let arrival = Arrival {
            on_link,
            reachable: self.link_reachable(peer).await,
            heard: self.peers.get(peer).is_some_and(|p| p.is_heard()),
        };
        let path = Msg1Path::new(
            packet.transport_id,
            &packet.remote_addr,
            self.established_link(peer),
        );
        let held = self.peers.get(peer).and_then(|p| p.rekey_answer());
        let held_dg = OrNone(held.as_ref().map(|(msg1, _)| diag::msg1_tag(msg1)));
        let pending_age_s = OrNone(
            self.peers
                .get(peer)
                .and_then(|p| p.pending_age())
                .map(|d| d.as_secs()),
        );
        let age_s = OrNone(
            self.peers
                .get(peer)
                .and_then(|p| p.session_established_at())
                .map(|t| crate::peer::since(t).as_secs()),
        );
        let msg1_dg = diag::msg1_tag(&wire.msg1_digest);
        let msg1_sidx = wire.their_index;
        // The receiver index of the stored msg2 a resent setup msg1 is
        // answered with is the sender index of the msg1 it answers.
        let stored_ridx = self
            .peers
            .get(peer)
            .and_then(|p| p.handshake_msg2())
            .and_then(Msg2Header::parse)
            .map(|h| h.receiver_idx);
        let answers_it = OrNone(stored_ridx.map(|r| r == wire.their_index));
        let stored_ridx = OrNone(stored_ridx);
        let Some(out) = self.step_link(peer, Input::PeerMsg1 { tok, arrival }) else {
            return LinkVerdict::Done;
        };
        let report = self.run_link_step(peer, out).await;
        for reason in &report.rejects {
            let shown = match reason {
                Reason::PendingHeld => self.shown(peer, HsLine::Pending),
                Reason::AnsweredBefore => self.shown(peer, HsLine::Answered),
                Reason::OffLink => self.shown(peer, HsLine::OffLink),
                // Never suppressed: an integration check counts the
                // tie-break line to detect a dual-initiation loop, which
                // holds one session and so would never restart a
                // per-session count.
                _ => true,
            };
            if shown {
                match reason {
                    Reason::PendingHeld => debug!(
                        peer = %self.peer_display_name(peer),
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        same_path = path.same_path(),
                        msg1_dg = %msg1_dg,
                        held_dg = %held_dg,
                        pending_age_s = %pending_age_s,
                        "Rekey msg1 received but already have pending session, dropping"
                    ),
                    Reason::DualInitWon => debug!(
                        peer = %self.peer_display_name(peer),
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        same_path = path.same_path(),
                        msg1_dg = %msg1_dg,
                        "Dual rekey initiation: we win (smaller addr), dropping their msg1"
                    ),
                    Reason::AnsweredBefore => debug!(
                        peer = %self.peer_display_name(peer),
                        remote_addr = %packet.remote_addr,
                        transport_id = %packet.transport_id,
                        same_path = path.same_path(),
                        msg1_dg = %msg1_dg,
                        "Rekey msg1 answered in an ended cycle, dropping the copy"
                    ),
                    Reason::OffLink => debug!(
                        peer = %self.peer_display_name(peer),
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        same_path = path.same_path(),
                        msg1_dg = %msg1_dg,
                        "Same-epoch msg1 off the established link while that link is up, dropping"
                    ),
                    Reason::IndexExhausted => warn!(
                        peer = %self.peer_display_name(peer),
                        error = %IndexError::Exhausted,
                        "Failed to allocate index for rekey"
                    ),
                    other => debug!(
                        peer = %self.peer_display_name(peer),
                        remote_addr = %packet.remote_addr,
                        reason = ?other,
                        "Rekey msg1 refused"
                    ),
                }
            }
            self.stats_mut()
                .record_reject(RejectReason::Handshake(msg1_refusal(*reason)));
        }
        for (msg2, route) in &report.replies {
            // An answer on the arrival goes there only when the msg1 came on
            // one of the link's proven paths. A msg1 on the link from any
            // other pair, such as the setup address of a link whose peer is
            // not capable, is answered on the established link at the
            // peer's current address (FRC-1201 Section 5.7).
            let route = match route {
                Route::Arrival if !proven => Route::Established { fallback: true },
                other => *other,
            };
            let sent = self.answer_msg1(peer, packet, msg2, route).await;
            if report.pending {
                match sent {
                    Ok(_) => debug!(
                        peer = %self.peer_display_name(peer),
                        new_our_index = %OrNone(
                            self.peers.get(peer).and_then(|p| p.pending_our_index())
                        ),
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        link_tid = %path.link_tid(),
                        link_addr = %path.link_addr(),
                        same_path = path.same_path(),
                        age_s = %age_s,
                        msg1_sidx = %msg1_sidx,
                        msg1_dg = %msg1_dg,
                        epoch = %OrNone(
                            self.peers
                                .get(peer)
                                .and_then(|p| p.pending_new_session())
                                .map(diag::epoch_tag)
                        ),
                        kbit_ours = %OrNone(self.peers.get(peer).map(|p| p.current_k_bit())),
                        "Sent rekey msg2 response"
                    ),
                    // The pending stays held: a msg2 the transport refused is
                    // lost, and the peer's resend of its msg1 draws it again.
                    Err(e) => {
                        warn!(
                            peer = %self.peer_display_name(peer),
                            error = %e,
                            transport_id = %packet.transport_id,
                            remote_addr = %packet.remote_addr,
                            link_tid = %path.link_tid(),
                            link_addr = %path.link_addr(),
                            same_path = path.same_path(),
                            msg1_sidx = %msg1_sidx,
                            msg1_dg = %msg1_dg,
                            "Failed to send rekey msg2"
                        );
                        self.stats_mut()
                            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    }
                }
            } else if held.as_ref().is_some_and(|(_, answer)| answer == msg2) {
                // A resend of the msg1 that armed the pending we hold: our
                // msg2 was lost, so the same answer goes again.
                match sent {
                    Ok(_) if self.shown(peer, HsLine::RekeyResend) => debug!(
                        peer = %self.peer_display_name(peer),
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        same_path = path.same_path(),
                        "Resent rekey msg2 for a resent msg1"
                    ),
                    Err(e) if self.shown(peer, HsLine::RekeyResendFailed) => debug!(
                        peer = %self.peer_display_name(peer),
                        error = %e,
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        same_path = path.same_path(),
                        "Failed to resend rekey msg2"
                    ),
                    _ => {}
                }
            } else {
                // A resend of the msg1 the peering was promoted from, on a
                // link too young to rekey: the stored msg2 goes again.
                match sent {
                    Ok(_) if self.shown(peer, HsLine::Resend) => debug!(
                        peer = %self.peer_display_name(peer),
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        link_tid = %path.link_tid(),
                        link_addr = %path.link_addr(),
                        same_path = path.same_path(),
                        msg1_sidx = %msg1_sidx,
                        msg1_dg = %msg1_dg,
                        age_s = %age_s,
                        stored_ridx = %stored_ridx,
                        answers_it = %answers_it,
                        "Resent msg2 for duplicate msg1 (same epoch)"
                    ),
                    Err(e) if self.shown(peer, HsLine::ResendFailed) => debug!(
                        peer = %self.peer_display_name(peer),
                        error = %e,
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        link_tid = %path.link_tid(),
                        link_addr = %path.link_addr(),
                        same_path = path.same_path(),
                        msg1_sidx = %msg1_sidx,
                        msg1_dg = %msg1_dg,
                        age_s = %age_s,
                        stored_ridx = %stored_ridx,
                        answers_it = %answers_it,
                        "Failed to resend msg2"
                    ),
                    _ => {}
                }
            }
        }
        match report.redial {
            Some(ephemeral) => LinkVerdict::Redial(ephemeral),
            None if report.replace => LinkVerdict::Replace,
            None => LinkVerdict::Done,
        }
    }

    /// Whether `packet` arrived on `peer`'s link, and whether its pair is a
    /// path of the peer's proven at this end. On the link, as the
    /// settlement core's records of the node's links place it
    /// ([`Placement::on_link`](crate::proto::settle::links::Placement::on_link)):
    /// from a path the peer's link holds that is proven at this end (Live
    /// or acked; the original path is both), or, on a link whose peer is
    /// not capable, from a pair the link holds no path at that the link
    /// index names the link at. That is FRC-1201 Section 5.7's setup
    /// address, such as the address the link was set up at after its one
    /// path followed the peer elsewhere, or a hostname-keyed dial address
    /// beside a numeric current address. On a link whose peer is capable
    /// such a pair is off the link (multipath draft Section 5.10). A
    /// same-epoch msg1 and a rekey msg2 are placed by this one rule.
    fn link_arrival(&self, peer: &NodeAddr, packet: &ReceivedPacket) -> (bool, bool) {
        let Some(p) = self.peers.get(peer) else {
            return (false, false);
        };
        let key = (packet.transport_id, packet.remote_addr.clone());
        let on_link = self
            .links
            .no(&p.link_id())
            .is_some_and(|no| self.placement(&key).on_link(no));
        let proven = matches!(
            p.path_match(packet.transport_id, &packet.remote_addr),
            Match::Proven { .. }
        );
        (on_link, proven)
    }

    /// Hand `packet`'s msg2, which names `peer`'s index, to that peer's link
    /// rekey machine: it completes the own rekey whose attempt the index
    /// names, or changes nothing, each counted and logged. Where it arrived
    /// goes with it: once the attempt has read and refused its budget of
    /// msg2s, the machine reads only one that arrived on the link.
    async fn msg2_to_link(&mut self, peer: &NodeAddr, packet: &ReceivedPacket) {
        let (on_link, _) = self.link_arrival(peer, packet);
        let Some(out) = self.step_link(
            peer,
            Input::Reply {
                bytes: &packet.data,
                route: Arrived { on_link },
            },
        ) else {
            return;
        };
        let report = self.run_link_step(peer, out).await;
        if report.pending {
            let p = self.peers.get(peer);
            debug!(
                peer = %self.peer_display_name(peer),
                new_our_index = %OrNone(p.and_then(|p| p.pending_our_index())),
                epoch = %OrNone(p.and_then(|p| p.pending_new_session()).map(diag::epoch_tag)),
                kbit_ours = %OrNone(p.map(|p| p.current_k_bit())),
                "Rekey completed (initiator), pending K-bit cutover"
            );
        }
        for reason in report.rejects {
            match reason {
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
                // The attempt has read and refused its budget of msg2s, and
                // this one came from off the peer's link, so it was dropped
                // unread. The peer's msg2 from its link is still read, and a
                // msg1 resend draws a lost one again.
                Reason::ReplyUnread => {
                    debug!(
                        peer = %self.peer_display_name(peer),
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        "Rekey msg2 from off the link after the refused-read budget, dropping unread"
                    );
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::OffLink));
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

    /// Handle handshake message 2 (phase 0x2).
    ///
    /// This completes an outbound handshake we initiated.
    pub(in crate::node) async fn handle_msg2(&mut self, packet: ReceivedPacket) {
        #[cfg(test)]
        self.resync();
        self.msg2_body(packet).await;
        self.audit_live("handle_msg2");
    }

    /// The work of [`Self::handle_msg2`], which audits the per-peer maps
    /// after it.
    async fn msg2_body(&mut self, packet: ReceivedPacket) {
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
        // msg2). A link-setup dial's index is the one its leg's lease holds
        // (`Node::dial_at`), and its control machine still carries the
        // handshake; a link rekey's attempt index is bound to its peer in
        // `peers_by_index`, and its peer's link machine reads the msg2.
        //
        // A fresh handshake is bound to the transport its msg1 went out on:
        // a dial is found by its link's transport and its index, so a msg2 from
        // any other transport misses and, unless it names a rekey, is
        // discarded before any state changes. A relayed copy of the genuine
        // msg2 therefore cannot complete the dial at a foreign address. A
        // forgery carrying the sniffed index cannot spoil the dial on any
        // transport, for another reason: a msg2 that does not authenticate
        // leaves the attempt in place. A rekey msg2 is accepted from any
        // transport: the link is established, and `peers_by_index` is keyed
        // by the index alone; past its budget of refused reads, the rekey
        // reads only one that arrived on the link.
        let key = (packet.transport_id, header.receiver_idx.as_u32());
        let setup = self.dial_at(key.0, key.1);
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
                if let Some(&peer) = self.peers_by_index.get(&key.1)
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
                // A dial's leg whose connection no longer carries a
                // handshake is stale: a state-machine inconsistency, not a
                // fresh lookup miss.
                let reject = if let Some(stale) = setup {
                    self.drop_leg(stale);
                    HandshakeReject::BadState
                } else {
                    HandshakeReject::UnknownConnection
                };
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(reject));
                return;
            }
        };

        // The leg is stamped on the interval clock from here, beside the
        // wall stamp it keeps.
        let interval_ms = Self::interval_ms();
        let peer_identity = {
            let machine = self.peer_machines.get_mut(&link_id).unwrap();

            let noise_msg2 = &packet.data[header.noise_msg2_offset..];
            if let Err(e) = machine.complete_handshake(
                noise_msg2,
                LegStamp {
                    wall_ms: packet.timestamp_ms,
                    interval_ms,
                },
            ) {
                // Nothing authenticated this msg2 before the read, and the
                // index it names travels in cleartext in our msg1, so it may
                // be a forgery. Ending the attempt here would let anyone who
                // saw the msg1 end every dial with one datagram. When the
                // handle is back in the leg, the read was rolled back: keep
                // the attempt, its dispatch entry, its resend schedule and its
                // deadline, so the genuine msg2 can still complete it. If no
                // readable msg2 ever arrives, the handshake timeout ends the
                // attempt as it would for a lost one. Logged at debug because
                // a forger can send one per datagram.
                if machine
                    .leg()
                    .is_some_and(|leg| leg.noise_handshake.is_some())
                {
                    debug!(
                        link_id = %link_id,
                        error = %e,
                        "msg2 did not authenticate, keeping the handshake attempt"
                    );
                    if node_fault!(ForgetDialOnRefusedMsg2) {
                        self.drop_leg(link_id);
                    }
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
                warn!(
                    link_id = %link_id,
                    error = %e,
                    "Handshake completion failed"
                );
                // The handle is gone, so the leg cannot continue: record the
                // failure on the control machine as `send_failed`, the failure
                // state's home. The machine PHASE stays where it is
                // (`SentMsg1`): the stale-connection sweep reclaims the
                // connection unconditionally via the machine `is_failed()` at
                // the next tick, before any projection or resend.
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

            match machine.conn_expected_identity() {
                Some(id) => *id,
                None => {
                    warn!(link_id = %link_id, "No identity after handshake");
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
            }
        };

        // The msg2 completed the dial: its leg leaves the legs, and the
        // machine takes the lease the shell drew for it, and its msg1, for
        // the promotion or the crossing that follows.
        if let Some(leg) = self.take_leg(link_id) {
            let machine = self
                .peer_machines
                .get_mut(&link_id)
                .expect("the completed dial's machine");
            machine.set_conn_handshake_msg1(leg.msg1().to_vec());
            if let Some(old) = machine.set_conn_our_index(leg.lease()) {
                let _ = self.index_allocator.free(SessionIndex::new(old.release()));
            }
        }
        let our_index = self
            .peer_machines
            .get(&link_id)
            .and_then(|machine| machine.our_index());

        if self
            .authorize_peer(
                &peer_identity,
                PeerAclContext::OutboundHandshake,
                packet.transport_id,
                &packet.remote_addr,
            )
            .is_err()
        {
            #[cfg(test)]
            self.shadow_abandon(link_id);
            if let Some(link) = self.links.get(&link_id) {
                let tid = link.transport_id();
                let addr = link.remote_addr().clone();
                #[cfg(test)]
                self.closed(tid, &addr);
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
            self.note_handshake_timeout(*peer_identity.node_addr(), Self::peering_now());
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

        // The shadow core completes the dial on its link.
        #[cfg(test)]
        if let Some(link) = self.shadow_link(link_id) {
            let epoch = self
                .peer_machines
                .get(&link_id)
                .and_then(|m| m.conn_remote_epoch())
                .unwrap_or_default();
            let input = crate::proto::settle::input::Input::Msg2 {
                link,
                epoch,
                from: crate::proto::settle::links::Pair {
                    transport: packet.transport_id,
                    addr: packet.remote_addr.clone(),
                },
            };
            self.decide(input);
        }

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
        //
        // If the peer was promoted via an earlier dial of ours instead, the
        // peer's answer to this later dial supersedes the earlier one (a
        // replacement on a link too young to rekey, a rekey on an older one),
        // so this node swaps at either address.
        // The machine is the sole computation site of the establish decision:
        // the shell builds the outbound snapshot, steps the machine once here,
        // and routes on the returned decision — a cross-connection resolves as
        // a single `ResolveCrossConnection { swap }` action, a net-new
        // establish as the promote action sequence. A swap moves the already
        // promoted peer here, via `move_session`, for which no `PeerAction`
        // exists, and the rest of a swap or a keep runs through the
        // settlement executor. The machine was persisted at DIAL, so the
        // executor's `PromoteToActive` arm can feed `PromotionResolved` back
        // via the same lookup; the dial's leg left the legs when this msg2
        // completed it, and the machine never touches the legs.
        let out_snap = self.outbound_snapshot(&peer_node_addr);
        let own_dial = out_snap.has_existing_peer && out_snap.own_dial;
        // A dial made while the peer was held, answered while it is still
        // held on that link, is a later dial to a held peer even where the
        // peer dialled the link: the record is taken at the dial, because a
        // leg promoted after the dial started can hold an older link.
        let held_now = self.peers.get(&peer_node_addr).map(|p| p.link_id());
        let later_dial = held_now.is_some()
            && self.peer_machines.get(&link_id).and_then(|m| m.held_link()) == held_now;
        // A new epoch in the answer to this node's own dial is a restart,
        // which the restart gates are asked about as every restart source
        // is. They pass it: the msg2 is the reply to this node's own msg1.
        let msg2_epoch = self
            .peer_machines
            .get(&link_id)
            .and_then(|m| m.conn_remote_epoch());
        if out_snap.has_existing_peer
            && matches!(
                (out_snap.existing_peer_epoch, msg2_epoch),
                (Some(held), Some(new)) if held != new
            )
            && let Some(refusal) =
                self.gate_msg2(peer_node_addr, false, msg2_epoch, packet.timestamp_ms)
        {
            debug!(
                peer = %self.peer_display_name(&peer_node_addr),
                link_id = %link_id,
                reason = ?refusal,
                "Restart on our dial refused by the restart gates, dropping the dial"
            );
            // The dial's connection closes by the close rule, as the
            // settlement core decides it: not while the held link, or any
            // other live link, uses it.
            if let Some((tid, addr)) = self
                .links
                .get(&link_id)
                .map(|link| (link.transport_id(), link.remote_addr().clone()))
            {
                self.close_pair(tid, &addr, link_id).await;
            }
            self.remove_peer_machine(link_id);
            self.remove_link(&link_id);
            if let Some(idx) = our_index {
                let _ = self.index_allocator.free(idx);
            }
            #[cfg(test)]
            self.did(crate::node::settle::exec::Did::Reject {
                peer: Some(peer_node_addr),
            });
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }
        let actions = match self.peer_machines.get_mut(&link_id) {
            Some(machine) => machine.step(
                PeerEvent::Msg2 {
                    their_index: header.sender_idx,
                    out: out_snap,
                },
                interval_ms,
            ),
            None => {
                // No machine persisted at dial (e.g. a test that seeds a dial
                // directly, or any path that
                // reaches msg2 without `start_handshake`): reproduce the
                // pre-persistence transient exactly.
                let mut machine = PeerMachine::new_outbound(
                    link_id,
                    peer_identity,
                    LegStamp {
                        wall_ms: packet.timestamp_ms,
                        interval_ms,
                    },
                );
                let actions = machine.step(
                    PeerEvent::Msg2 {
                        their_index: header.sender_idx,
                        out: out_snap,
                    },
                    interval_ms,
                );
                self.peer_machines.add(link_id, machine);
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
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::UnknownConnection));
                    return;
                }
            };

            if crate::node::settle::exec::Run::swaps(swap, !own_dial && !later_dial) {
                #[cfg(test)]
                self.did(crate::node::settle::exec::Did::Swapped {
                    peer: peer_node_addr,
                    own: own_dial,
                    unpin: own_dial || later_dial,
                });
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
                        self.stats_mut()
                            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        return;
                    }
                };
                let outbound_our_index = SessionIndex::new(outbound_lease.index());
                let local = self.session_node_keys();
                let me = *self.identity().node_addr();
                let params = crate::node::handlers::rekey::link_params(&self.config().node);
                let path_params = crate::node::handlers::path::path_params(&self.config().node);
                let workers = self.link_workers();
                let prior = self.peer_link(&peer_node_addr);
                let own = own_dial || later_dial;

                // The mutation lane's break: the tree announce goes out on
                // the session the move is about to leave.
                if node_fault!(MoveAnnouncesFirst) && self.peers.contains_key(&peer_node_addr) {
                    let _ = self.send_tree_announce_to_peer(&peer_node_addr).await;
                }

                if let Some(peer) = self.peers.get_mut(&peer_node_addr) {
                    let suppressed = peer.replay_suppressed_count();
                    // Read before the move, which may make the peering heard.
                    let unheard = !peer.is_heard();
                    let epoch = diag::epoch_tag(&outbound_session);
                    // The peer's link machine is closed and rebuilt on the
                    // outbound session: what it held is unbound and freed.
                    // The peer is taken at the msg2's transport and source
                    // address (FRC-1201, Section 5.6), and the rebuilt
                    // machine records the outbound index's binding on the
                    // transport the msg2 came on. The path machine starts
                    // again with that pair as the new link's original path
                    // (multipath v1 draft, Section 5.4), for a peer whose
                    // handshake the ACL has passed; no probe is stepped here.
                    let facts = NodeFacts {
                        transports: &self.transports,
                        denied: false,
                    };
                    let mut caps = LinkCaps {
                        indices: &mut self.index_allocator,
                        local: &local,
                        me,
                        params,
                        record: fips_core::proto::rekey::Record::new(),
                        workers,
                        path: PathCaps {
                            params: path_params,
                            facts: &facts,
                        },
                    };
                    let (out, paths) = peer.move_session(
                        outbound_session,
                        outbound_lease,
                        header.sender_idx,
                        (packet.transport_id, packet.remote_addr.clone()),
                        link_id,
                        own,
                        &mut caps,
                    );
                    // The machine was rebuilt exactly when the peer is on
                    // the dial's index: every refused or failed move leaves
                    // the old machine, or none, and hands the index back in
                    // its outputs.
                    let built = peer.our_index() == Some(outbound_our_index);
                    let first_heard = unheard && peer.is_heard();
                    // A rebuilt move holds the peer on the dial's link, and
                    // the link it left is the one torn down.
                    let left =
                        held_now.filter(|held| *held != link_id && peer.link_id() == link_id);

                    // The rest of the move, in its order: the machines'
                    // outputs, the path feeds, the peer held on the dial's
                    // link, what follows a move to another pair, the pin,
                    // the notes, the control machine, and the losing link.
                    let mut run = crate::node::settle::exec::Run::new(
                        peer_node_addr,
                        crate::node::settle::table::Transition::Move {
                            dial: link_id,
                            own,
                            built,
                        },
                    );
                    run.prior = prior;
                    run.dial = Some(link_id);
                    let facts = run.crossing();
                    facts.out = out;
                    facts.paths = paths;
                    facts.ours = Some(outbound_our_index);
                    facts.theirs = Some(header.sender_idx);
                    facts.to = Some((packet.transport_id, packet.remote_addr.clone()));
                    facts.own_dial = own_dial;
                    facts.loser = Some(left.unwrap_or(link_id));
                    facts.key = Some(crate::ipv6tun::link::PeerKey::from_xonly(
                        &peer_identity.pubkey(),
                    ));
                    facts.suppressed = suppressed;
                    facts.epoch = Some(epoch);
                    facts.msg1 = sent_msg1_digest;
                    facts.outcome = Some(CrossConnOutcome::Swap {
                        our_index: outbound_our_index,
                        their_index: header.sender_idx,
                    });
                    facts.first_heard = first_heard;
                    self.run(&mut run).await;
                    return;
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
                let mut run = crate::node::settle::exec::Run::new(
                    peer_node_addr,
                    crate::node::settle::table::Transition::Keep { dial: link_id },
                );
                run.dial = Some(link_id);
                let facts = run.crossing();
                facts.to = Some((packet.transport_id, packet.remote_addr.clone()));
                facts.lease = carrier_our_index;
                facts.loser = Some(link_id);
                facts.outcome = Some(CrossConnOutcome::Keep);
                self.run(&mut run).await;
                return;
            }

            // A won crossing whose peer is no longer held moves nothing, and
            // the dial's leg still ends as at any crossing. The decision was
            // made on a snapshot that held the peer, with nothing awaited
            // since, so this is not reached.
            // Close the losing leg's connection: a separate socket on TCP, a
            // no-op when connectionless, and left open when it is the very
            // connection the promoted peer runs on (BLE).
            self.close_unused(link_id).await;
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
        // `Promoted`; a held one would be refused, which the executor
        // asserts never happens.
        //
        // The outbound Msg2 Promote step promotes; the dial's leg, with its
        // resends and deadline, left the legs when this msg2 completed it.
        // `PromoteToActive` is what performs the promotion.
        let promote = [PeerAction::PromoteToActive { link: link_id }];
        let restarted = actions.first() == Some(&PeerAction::InvalidateSendState);
        debug_assert!(actions.ends_with(&promote));
        debug_assert_eq!(actions.len(), if restarted { 3 } else { 1 });
        if restarted {
            info!(
                peer = %self.peer_display_name(&peer_node_addr),
                link_id = %link_id,
                "Peer restart detected on our dial (epoch mismatch), replacing the stale peer"
            );
        }

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
            interval_ms,
            is_outbound: true,
            why: restarted.then_some(Why::OwnRestart),
        };
        self.execute_peer_actions(link_id, &ambient, actions).await;

        // A promotion that succeeded left the machine Established, and the
        // executor's promotion arm ran its tail: the promotion logged, the
        // initial tree announce and the filter announce scheduled. A promote
        // failure removed the machine and runs no tail (the pre-refactor Err
        // arm likewise only recorded the reject, which the executor's Err
        // arm does).
        debug_assert!(matches!(
            self.peer_machines.get(&link_id).map(|m| m.state()),
            Some(PeerState::Established { .. }) | None
        ));
    }

    /// Promote a connection to active peer after successful authentication.
    ///
    /// A crossing is resolved before the promotion is asked for, so this
    /// installs a new peer only: an identity already held is refused with
    /// [`NodeError::IdentityHeld`] and the connection's index is freed. The
    /// result is always [`PromotionResult::Promoted`].
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
        // An answer's leg leaves the legs here: the machine takes the lease
        // the shell drew for it, for the promotion.
        if self.peer_machines.contains_key(&link_id)
            && let Some(lease) = self.take_leg(link_id).map(|leg| leg.lease())
            && let Some(old) = self
                .peer_machines
                .get_mut(&link_id)
                .and_then(|machine| machine.set_conn_our_index(lease))
        {
            let _ = self.index_allocator.free(SessionIndex::new(old.release()));
        }
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
        let direction = machine.conn_direction();
        // The msg1 this link was set up by: the one this node sent, or the
        // one it answered.
        let msg1_digest = match direction {
            LinkDirection::Outbound => machine.conn_handshake_msg1().map(Msg1Digest::of),
            LinkDirection::Inbound => machine.conn_msg1_digest(),
        };

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

        // Every producer of `PromoteToActive` runs with no peer held for
        // this identity: the machine decides `Promote` only with none, a
        // restart or a replace removes the old peer before the promotion,
        // and a resent msg2 promotes only while none is held. Installing
        // over a held peer would overwrite it and leak its indices, so a
        // promotion that finds one is refused rather than resolved.
        if self.peers.contains_key(&peer_node_addr) {
            let _ = self
                .index_allocator
                .free(SessionIndex::new(our_lease.release()));
            return Err(NodeError::IdentityHeld(link_id));
        }

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
            #[cfg(test)]
            self.did(crate::node::settle::exec::Did::Reject {
                peer: Some(peer_node_addr),
            });
            let _ = self
                .index_allocator
                .free(SessionIndex::new(our_lease.release()));
            return Err(NodeError::MaxPeersExceeded {
                max: self.max_peers(),
            });
        }

        let remote_addr = current_addr.clone();
        let epoch = diag::epoch_tag(&noise_session);
        // The msg1's sender index is the initiator's, so both ends log
        // the same one.
        let msg1_sidx = if is_outbound { our_index } else { their_index };
        self.install(
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
        )?;

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
