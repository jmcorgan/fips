//! Handshake handlers and connection promotion.

use crate::NodeAddr;
use crate::PeerIdentity;
use crate::identity::OsEntropy;
use crate::node::acl::PeerAclContext;
use crate::node::diag::{self, HsLine, Msg1Path, OrNone, Shown, Withheld};
use crate::node::handlers::path::NodeFacts;
use crate::node::rate_limit::Msg1Class;
use crate::node::reject::{HandshakeReject, RejectReason};
use crate::node::settle::exec::{Ambient, By, Removed, Run};
use crate::node::settle::params::settle_params;
use crate::node::{Node, NodeError};
use crate::peer::handshake::{Handshake, HandshakeCrypto};
use crate::peer::{LinkCaps, Match, PathCaps};
use crate::proto::fmp::ActiveBackoff;
use crate::proto::fmp::rekey::ik::{Arrived, read_msg1};
use crate::proto::fmp::wire::{Msg1Header, Msg2Header, build_msg2};
use crate::proto::fmp::{
    EphemeralDigest, InboundReject, LegStamp, Msg1Digest, PromotionResult, WireOutcome,
};
use crate::proto::settle::gates::{Refusal, Source};
use crate::proto::settle::input::{Hello, Input as SettleInput, Read};
use crate::proto::settle::links::{LinkNo, Pair};
use crate::proto::settle::output::{Denial, Output, Transition, Why};
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

/// What a msg1's refusal logs read about the identity before the core
/// steps.
struct Msg1Seen {
    /// The identity's silent-session refusal in force.
    silent: Option<ActiveBackoff>,
    /// The identity's silent-session count.
    silent_count: Option<u32>,
    /// Whether the restart dampener holds the identity.
    dampened: bool,
    /// The held peering's idle time as operators are shown it.
    idle_ms: u64,
}

/// What the core decided when an answer's msg2 went out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::node) enum Installed {
    /// It installs the leg, whose session index is this one.
    Yes(SessionIndex),
    /// It installs nothing: the peer is held through another link.
    No,
    /// It refused the install at the max-peers cap, retiring the leg's
    /// link: the connections that retirement leaves unused, to close.
    Refused(Vec<Pair>),
}

/// A msg1 classified as a redial, with what arming it needs: the leg's
/// handshake entry (its msg1 read and answered), the link allocated for it,
/// the held peer and the authenticated identity, the msg1's ephemeral as
/// the link machine keys it, and the leg's stamp.
pub(in crate::node) struct Armed {
    pub(in crate::node) entry: Handshake,
    pub(in crate::node) link: LinkId,
    pub(in crate::node) peer: NodeAddr,
    pub(in crate::node) identity: PeerIdentity,
    pub(in crate::node) digest: Option<fips_core::proto::rekey::Digest>,
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
        let refused = self.core.take_refused(peer);
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
    /// its handshake entry.
    pub(in crate::node) fn placement(
        &self,
        key: &crate::node::AddrKey,
    ) -> crate::proto::settle::links::Placement {
        self.links.placement(self.core.links(), key, |id| {
            self.connections()
                .find(|(link, _)| **link == id)
                .and_then(|(_, entry)| entry.conn_expected_identity())
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
    ///
    /// Returns, beside the transport, whether the reply went out on the
    /// msg1's connection in place of the established link's, which had gone.
    pub(in crate::node) async fn answer_msg1(
        &self,
        peer: &NodeAddr,
        packet: &ReceivedPacket,
        reply: &[u8],
        route: Route,
    ) -> Result<(TransportId, bool), String> {
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
                return Ok((packet.transport_id, false));
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
            Ok(_) => return Ok((tid, false)),
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
        Ok((tid, true))
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

        // The settlement core takes every msg1 the rate limiter admits,
        // before any Diffie-Hellman. The limiter is the node's resource
        // admission, not a settlement decision: a msg1 it refuses never
        // reaches the core.

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

        // Pre-crypto: the settlement core answers a resend of the msg1 a
        // stored msg2 was written for from that answer's leg, without the
        // crypto cost, and refuses a msg1 past the admission cap on answers
        // in flight. A stored msg2 not yet sent answers any msg1 from its
        // address; once sent it answers only the msg1 it was written for, so
        // any other msg1 from this address, such as a fresh dial of the same
        // peer or a capture spoofed from it, is read and classified below
        // rather than answered with keys it does not hold. A leg whose first
        // send failed transiently was never promoted, so a successful resend
        // promotes it here.
        let arrived = self.decide(SettleInput::Arrived {
            from: Pair {
                transport: packet.transport_id,
                addr: packet.remote_addr.clone(),
            },
            bytes: packet.data.clone(),
        });
        for o in arrived {
            match o {
                Output::Answer { link, msg2, .. } => {
                    self.resend_answer(link, &msg2, &packet).await;
                    return;
                }
                Output::Reject { why, .. } => {
                    debug!(
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        reason = ?why,
                        "Msg1 refused by the settlement core before any crypto"
                    );
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
                other => debug_assert!(false, "a msg1's arrival gave {other:?}"),
            }
        }
        let addr_key = (packet.transport_id, packet.remote_addr.clone());
        if let Some(&existing_link_id) = self.links.index().get(&addr_key)
            && let Some(link) = self.links.get(&existing_link_id)
            && !self.peers.values().any(|p| p.link_id() == existing_link_id)
        {
            if link.direction() == LinkDirection::Inbound && self.leg(existing_link_id).is_none() {
                // A pending inbound link with no answer's leg has no stored
                // msg2 to resend.
                debug!(
                    remote_addr = %packet.remote_addr,
                    "Duplicate msg1 but no stored msg2 to resend"
                );
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::UnknownConnection));
                return;
            } else if link.direction() == LinkDirection::Inbound {
                debug!(
                    remote_addr = %packet.remote_addr,
                    transport_id = %packet.transport_id,
                    link_id = %existing_link_id,
                    "Msg1 from the address of a pending inbound link is not the msg1 its sent msg2 answers, classifying it"
                );
            } else {
                // Outbound link to this address with no active peer yet: a
                // cross-connection. Just log; it is classified as a net-new
                // inbound below.
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
        // The packet's wall stamp for what operators are shown, and the
        // interval clock, read once here, for the handshake's timers and
        // timeout.
        let interval_ms = Self::interval_ms();
        let leg_at = LegStamp {
            wall_ms: packet.timestamp_ms,
            interval_ms,
        };

        // The handshake's entry holds its crypto, so it is built here, above
        // the crypto. It stays a local: it enters the handshake map only once
        // the msg1 is answered, so a rejected msg1 still leaves no registry
        // trace and allocates no index.
        let mut entry = Handshake::new_inbound(link_id, leg_at);
        // Seed the entry with the transport and address msg1 arrived on, so
        // the promotion hand-off reads them from it.
        entry.set_conn_transport_id(packet.transport_id);
        entry.set_conn_source_addr(packet.remote_addr.clone());
        entry.set_leg(HandshakeCrypto::new());

        // This frame's own copy of the node's long-term private key; the
        // handshake state keeps its own and clears that on drop.
        let mut our_keypair = self.identity().keypair();
        let noise_msg1 = &packet.data[header.noise_msg1_offset..];
        let ephemeral = EphemeralDigest::of_noise_msg1(noise_msg1);
        let init_result =
            entry.receive_handshake_init(our_keypair, self.startup_epoch(), noise_msg1, leg_at);
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
        assert!(entry.leg().is_some(), "pending connection attached above");
        let peer_identity = match entry.conn_expected_identity() {
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
            remote_epoch: entry.conn_remote_epoch(),
            their_index: header.sender_idx,
            msg2_payload: msg2_response,
            msg1_digest: Msg1Digest::of(&packet.data),
        };
        // The Noise read took the ephemeral, so the msg1 carries one.
        // The promotion line reads the msg1's digest from the entry.
        entry.set_conn_msg1_digest(wire.msg1_digest);
        // The work that follows a promotion records the msg1 on the peer, and
        // runs where the packet is no longer at hand.
        entry.hold_msg1(packet.data.clone());

        // === CLASSIFICATION, BY THE SETTLEMENT CORE ===
        // The core reads the msg1 as the node has. It refuses one past the
        // max-peers cap or under the identity's silent-session back-off,
        // hands a same-epoch msg1 from a held identity to that peer's link
        // rekey machine, which owns FRC-1201 rules 3 and 4 and asks for the
        // restart gates only for a fresh dial on a link too young to rekey,
        // and puts a restart or a replacement through the restart gates.
        // An admitted msg1 tears down any held peer first and is asked for
        // its answer, which the late ACL and the index draw below give or
        // refuse.
        let msg1_dg = diag::msg1_tag(&wire.msg1_digest);
        let Some(ephemeral_read) = ephemeral else {
            debug!(
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                "Msg1 carries no ephemeral, dropping"
            );
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        };
        let read = Read {
            peer: peer_node_addr,
            from: Pair {
                transport: packet.transport_id,
                addr: packet.remote_addr.clone(),
            },
            bytes: packet.data.clone(),
            ephemeral: ephemeral_read,
            epoch: wire.remote_epoch.unwrap_or_default(),
        };
        let reachable =
            !self.peers.contains_key(&peer_node_addr) || self.link_reachable(&peer_node_addr).await;
        let mut seen = self.msg1_seen(&peer_node_addr, &packet);
        let mut out = self.decide(SettleInput::Msg1 {
            read: read.clone(),
            reachable,
        });
        if let Some(peer) = out.iter().find_map(|o| match o {
            Output::Rekey { peer, .. } => Some(*peer),
            _ => None,
        }) {
            match self.msg1_to_link(&peer, &packet, &wire).await {
                LinkVerdict::Done => return,
                LinkVerdict::Replace => {
                    seen = self.msg1_seen(&peer_node_addr, &packet);
                    out = self.decide(SettleInput::Replace(read));
                }
                LinkVerdict::Redial(e) => {
                    // The core judges the redial: the silent-session
                    // back-off, the slot rule, the redial memory and the
                    // dampener, and asks for its answer beside the held
                    // peering. An identity the core no longer holds is a
                    // msg1 from an identity not held, and is run below.
                    let held = self.core.held(&peer).is_some();
                    let decided = self.decide(SettleInput::Redial(read));
                    if !held {
                        out = decided;
                    } else {
                        entry.set_conn_their_index(wire.their_index);
                        let armed = Armed {
                            entry,
                            link: link_id,
                            peer,
                            identity: peer_identity,
                            digest: Some(e),
                            leg_at,
                        };
                        // Boxed: the redial's arming adds its own state to
                        // the msg1 handler's future, which a test's thread
                        // runs on its stack.
                        Box::pin(self.arm_redial(armed, decided, &packet, &wire, seen.silent))
                            .await;
                        return;
                    }
                }
            }
        }

        // The removal of a held peer the msg1 restarts or replaces, and the
        // answer asked for, in the core's order.
        let mut asked = None;
        let mut why = None;
        let teardown_ctx = |why| Ambient {
            verified_identity: peer_identity,
            transport_id: packet.transport_id,
            remote_addr: packet.remote_addr.clone(),
            our_index: None,
            now_ms: packet.timestamp_ms,
            is_outbound: false,
            why: Some(why),
        };
        let mut out = out;
        let mut retired = Self::retired(&mut out);
        for o in out {
            match o {
                Output::Answer { link, msg2, .. } => {
                    self.resend_answer(link, &msg2, &packet).await;
                    return;
                }
                Output::Reject {
                    why: Denial::Cap, ..
                } => {
                    // Net-new msg1 at the max-peers cap: dropped before any
                    // msg2, with no index drawn and nothing registered.
                    debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        max = self.max_peers(),
                        "Silent-dropping Msg1 at max_peers cap (early gate; no Msg2 sent)"
                    );
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(msg1_reject(
                            &InboundReject::AtMaxPeers,
                        )));
                    return;
                }
                Output::Reject {
                    why: Denial::Gate(Refusal::Silent),
                    ..
                } => {
                    self.refuse_silent(&peer_node_addr, &packet, &msg1_dg, seen.silent);
                    return;
                }
                Output::Reject {
                    why: Denial::Gate(refusal),
                    source,
                    ..
                } => {
                    let replacing = source == Some(Source::Replacement);
                    self.refuse_restart(&peer_node_addr, &packet, &seen, replacing, refusal);
                    return;
                }
                Output::Reject { why: denial, .. } => {
                    debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        reason = ?denial,
                        "Msg1 refused by the settlement core"
                    );
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
                Output::Remove { peer, why: removal } => {
                    if removal == Why::Replacement {
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
                    // The mutation lane's break: the new peer is installed
                    // as if sent the old peer's last tree announce.
                    if node_fault!(TreeCarryAcrossRestart) {
                        self.tree_carry = self
                            .peers
                            .get(&peer)
                            .map(|p| (peer, p.last_tree_announce_sent_ms()));
                    }
                    why = Some(removal);
                    // The removal runs the first part of the replacement's
                    // plan, and the promotion below, told the same cause,
                    // the rest. The core asks for the reconnect itself.
                    if let Some(removed) = self.remove(
                        &peer,
                        removal,
                        By::Core {
                            silent: seen.silent_count,
                        },
                    ) {
                        let mut removed = Removed {
                            noted: true,
                            ..removed
                        };
                        let closes = Self::closes_of(&mut retired, &peer);
                        self.retire_closes(peer, &mut removed, closes);
                        let mut run = Run::replacement(link_id, removed, &teardown_ctx(removal));
                        self.run_removal(&mut run).await;
                    }
                }
                Output::Retry { peer } => self.note_link_dead(peer, Self::peering_now()),
                Output::Free { lease } => self.free_lease(lease),
                // Any other link the msg1 retired closes what the core's
                // close rule closes.
                Output::Retire { closes, .. } => self.close_each(closes).await,
                Output::Ask { link, .. } => asked = Some(link),
                other => debug_assert!(false, "a msg1 gave {other:?}"),
            }
        }
        let Some(no) = asked else {
            return;
        };

        // Admitted: the leg waits on the late ACL, which runs BEFORE any
        // allocation, so a refused msg1 draws no index.
        entry.set_conn_their_index(wire.their_index);
        if self
            .authorize_peer(
                &peer_identity,
                PeerAclContext::InboundHandshake,
                packet.transport_id,
                &packet.remote_addr,
            )
            .is_err()
        {
            // The refused msg1's connection closes now, unless a live link
            // uses it, rather than at the transport's idle deadline.
            self.unasked(no, false).await;
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }

        // Allocate our index, which the answer's leg holds until the
        // promotion takes it.
        let Some(our_lease) = allocate(&mut self.index_allocator) else {
            // No msg2, no promote; a held peer the msg1 restarts or replaces
            // is already torn down.
            warn!("Failed to allocate session index for inbound");
            self.unasked(no, true).await;
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        };
        let our_index = SessionIndex::new(our_lease.index());
        let their_index = wire.their_index;
        let link = Link::connectionless(
            link_id,
            packet.transport_id,
            packet.remote_addr.clone(),
            LinkDirection::Inbound,
            Duration::from_millis(self.config().node.base_rtt_ms),
        );
        self.links.bind(&mut self.core, link, no);
        let wire_msg2 = build_msg2(our_index, their_index, &wire.msg2_payload);
        // The answer's leg, the settlement core's: the msg1 answered, the
        // framed msg2 a resend of that msg1 draws while the connection is
        // still pending, and the lease, reaped at the handshake deadline
        // counted from the msg1's arrival. The msg2 is sent below.
        let hello = Hello {
            link: no,
            msg2: wire_msg2.clone(),
            lease: our_lease,
        };
        for o in self.decide_at(SettleInput::Hello(hello), crate::time::mono_at(interval_ms)) {
            match o {
                Output::Free { lease } => self.free_lease(lease),
                Output::Answer { .. } => {}
                other => debug_assert!(false, "an answer gave {other:?}"),
            }
        }
        entry.set_conn_handshake_msg2(wire_msg2.clone());
        self.handshakes.add(link_id, entry);

        // Send the msg2, tell the core it went out, and promote the leg the
        // core installs; a transient send failure leaves the leg for the
        // initiator's resend, which promotes it once its stored msg2 is sent
        // (`promote_resent`).
        let ambient = Ambient {
            verified_identity: peer_identity,
            transport_id: packet.transport_id,
            remote_addr: packet.remote_addr.clone(),
            our_index: Some(our_index),
            now_ms: packet.timestamp_ms,
            is_outbound: false,
            why,
        };
        if self.send_answer(link_id, &ambient, &wire_msg2).await {
            self.promote(link_id, &ambient).await;
        }
    }

    /// What the logs of a msg1's refusal read about `peer` before the core
    /// steps: its silent-session refusal in force, the identity's silent
    /// count, whether the dampener holds it, and the idle time shown.
    fn msg1_seen(&self, peer: &NodeAddr, packet: &ReceivedPacket) -> Msg1Seen {
        let now = crate::peer::peer_now();
        let params = self.gate_params();
        let now_ms = Self::now_ms();
        Msg1Seen {
            silent: self.gates().refusing(peer, now).map(|b| ActiveBackoff {
                epoch: b.epoch,
                silent: b.silent,
                remaining_ms: b.remaining.as_millis() as u64,
            }),
            silent_count: self.gates().silent(peer),
            dampened: self
                .gates()
                .stamp(peer)
                .is_some_and(|t| now.saturating_duration_since(t) < params.interval),
            // The logs report the idle time from the wall-clock stamps
            // operators are shown; for an unheard peering it is its age since
            // promotion, not time since the peer was heard.
            idle_ms: self.peers.get(peer).map_or(u64::MAX, |p| {
                if p.is_heard() {
                    p.idle_time(now_ms)
                } else {
                    packet.timestamp_ms.saturating_sub(p.authenticated_at())
                }
            }),
        }
    }

    /// Refuse `packet`'s msg1 from `peer` during its identity's
    /// silent-session back-off: its last sessions at this epoch carried no
    /// frame. Counted on the identity's record, since a refused msg1 may
    /// have no peer entry to count on.
    pub(in crate::node) fn refuse_silent(
        &mut self,
        peer: &NodeAddr,
        packet: &ReceivedPacket,
        msg1_dg: &impl std::fmt::Display,
        silent_backoff: Option<ActiveBackoff>,
    ) {
        let shown = self
            .core
            .count_refused(peer)
            .is_none_or(|n| self.show(peer, HsLine::Refused, n));
        if shown {
            debug!(
                peer = %self.peer_display_name(peer),
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                msg1_dg = %msg1_dg,
                silent = %OrNone(silent_backoff.map(|b| b.silent)),
                remaining_s = %OrNone(silent_backoff.map(|b| b.remaining_ms.div_ceil(1000))),
                "Msg1 from a peer whose recent sessions carried no frame, refusing during its back-off"
            );
        }
        self.stats_mut()
            .record_reject(RejectReason::Handshake(msg1_reject(
                &InboundReject::SilentBackoff,
            )));
    }

    /// Refuse `packet`'s msg1, a restart of the held `peer` or, when
    /// `replacing`, a same-epoch replacement, which the restart gates
    /// refused for `refusal`. Silent drop: the stored msg2 is bound to the
    /// original msg1's ephemeral, and answering an address the sender chose
    /// is free amplification.
    fn refuse_restart(
        &mut self,
        peer: &NodeAddr,
        packet: &ReceivedPacket,
        seen: &Msg1Seen,
        replacing: bool,
        refusal: Refusal,
    ) {
        if let Refusal::Replayed | Refusal::ReplayFull = refusal {
            debug!(
                peer = %self.peer_display_name(peer),
                remote_addr = %packet.remote_addr,
                reason = match refusal {
                    Refusal::Replayed => "replayed-ephemeral",
                    _ => "replay-memory-full",
                },
                "Msg1 replacing an unheard peering was already used or over the per-peer bound, dropping"
            );
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }
        let reason = match refusal {
            Refusal::Heard => "heard-within-interval",
            Refusal::Unheard => "unheard-peering-young",
            Refusal::Silent => "silent-backoff",
            // A redial's refusal is not one a restart or a replacement is
            // given.
            Refusal::Dampened | Refusal::Replayed | Refusal::ReplayFull | Refusal::Redialed => {
                "dampened"
            }
        };
        if replacing {
            if self.shown(peer, HsLine::Replace) {
                debug!(
                    peer = %self.peer_display_name(peer),
                    remote_addr = %packet.remote_addr,
                    idle_ms = seen.idle_ms,
                    dampened = seen.dampened,
                    reason,
                    "Same-epoch msg1 inside the peering's replacement interval, dropping"
                );
            }
        } else if self.shown(peer, HsLine::Restart) {
            debug!(
                peer = %self.peer_display_name(peer),
                remote_addr = %packet.remote_addr,
                idle_ms = seen.idle_ms,
                dampened = seen.dampened,
                reason,
                "Epoch mismatch inside the peering's restart interval, dropping msg1"
            );
        }
        self.stats_mut()
            .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
    }

    /// Resend the stored msg2 `msg2` of the answer's leg on the core's link
    /// `no` in answer to `packet`'s msg1, and tell the core whether it went
    /// out: a sent one promotes the leg if the core installs it.
    async fn resend_answer(&mut self, no: LinkNo, msg2: &[u8], packet: &ReceivedPacket) {
        let Some(link) = self.links.id(no) else {
            return;
        };
        let Some(transport) = self.transports.get(&packet.transport_id) else {
            return;
        };
        match transport.send_existing(&packet.remote_addr, msg2).await {
            Ok(_) => {
                debug!(
                    remote_addr = %packet.remote_addr,
                    transport_id = %packet.transport_id,
                    link_id = %link,
                    "Resent msg2 for duplicate msg1"
                );
                self.promote_resent(link, no, packet).await;
            }
            Err(e) => {
                debug!(
                    remote_addr = %packet.remote_addr,
                    error = %e,
                    transport_id = %packet.transport_id,
                    link_id = %link,
                    "Failed to resend msg2"
                );
                let _ = self.decide(SettleInput::SendFailed { link: no });
            }
        }
    }

    /// Tell the core the stored msg2 of the pending inbound leg on `link`
    /// (the core's `no`) was sent in answer to `packet`, and promote the leg
    /// if the core installs it, as a first successful send would. A leg that
    /// has learned no identity is left alone.
    async fn promote_resent(&mut self, link: LinkId, no: LinkNo, packet: &ReceivedPacket) {
        let Some(identity) = self
            .handshakes
            .get(&link)
            .filter(|e| e.conn_their_index().is_some())
            .and_then(|e| e.conn_expected_identity().copied())
        else {
            return;
        };
        let peer = *identity.node_addr();
        let out = self.decide(SettleInput::Sent { link: no });
        let mut ambient = Ambient {
            verified_identity: identity,
            transport_id: packet.transport_id,
            remote_addr: packet.remote_addr.clone(),
            our_index: None,
            now_ms: packet.timestamp_ms,
            is_outbound: false,
            why: None,
        };
        match self.installed(link, out) {
            Installed::Yes(ours) => {
                ambient.our_index = Some(ours);
                self.promote(link, &ambient).await;
                debug!(
                    link_id = %link,
                    peer = %self.peer_display_name(&peer),
                    "Promoted a pending inbound link after resending its msg2"
                );
            }
            Installed::No if self.peers.contains_key(&peer) => debug!(
                link_id = %link,
                peer = %self.peer_display_name(&peer),
                "Resent msg2 for a pending link whose peer is held on another link, not promoting"
            ),
            Installed::No => {}
            Installed::Refused(closes) => self.close_each(closes).await,
        }
    }

    /// Run what the core decided when the msg2 of the answer's leg on
    /// `link` went out, `out`: the lease of a leg it installs moves to the
    /// leg's handshake entry for the promotion, and a leg it refuses at the
    /// max-peers cap is dropped as a refused promotion is.
    pub(in crate::node) fn installed(&mut self, link: LinkId, out: Vec<Output>) -> Installed {
        let mut installed = Installed::No;
        let no = self.links.no(&link);
        let mut refused = false;
        let mut closes = Vec::new();
        for o in out {
            match o {
                Output::Install(i) => {
                    let ours = SessionIndex::new(i.lease.index());
                    if let Some(old) = self
                        .handshakes
                        .get_mut(&link)
                        .and_then(|e| e.set_conn_our_index(i.lease))
                    {
                        let _ = self.index_allocator.free(SessionIndex::new(old.release()));
                    }
                    installed = Installed::Yes(ours);
                }
                Output::Reject {
                    why: Denial::Cap, ..
                } => {
                    // The promotion refused at the max-peers cap: the link
                    // and the entry go, and the core hands the lease back.
                    // The link's connection closes by the close rule, when
                    // no other live link uses it, as one the ACL refuses.
                    warn!(
                        target: "fips::node::handlers::handshake",
                        link_id = %link,
                        error = %NodeError::MaxPeersExceeded {
                            max: self.max_peers(),
                        },
                        "Failed to promote inbound connection"
                    );
                    self.remove_link(&link);
                    self.remove_handshake(link);
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    refused = true;
                }
                Output::Free { lease } => self.free_lease(lease),
                Output::Retire { link: l, closes: c } if Some(l) == no => closes = c,
                Output::Reset { .. } | Output::Retire { .. } => {}
                other => debug_assert!(false, "a sent answer gave {other:?}"),
            }
        }
        if refused {
            installed = Installed::Refused(closes);
        }
        installed
    }

    /// Send `msg2`, the framed answer of the handshake on `link` whose step
    /// facts are `ambient`, and tell the settlement core how the send went.
    /// Returns whether the leg may be promoted: the core installed it, or
    /// it never numbered the link.
    ///
    /// A transient send failure leaves the leg for the initiator's resend,
    /// which promotes it once its stored msg2 is sent (`promote_resent`);
    /// any other failure gives the answer up. A sent answer, or one with no
    /// transport to send it on, is told to the core, which installs the leg,
    /// refuses it at the max-peers cap, or leaves it for a peer held through
    /// another link.
    pub(in crate::node) async fn send_answer(
        &mut self,
        link: LinkId,
        ambient: &Ambient,
        msg2: &[u8],
    ) -> bool {
        // A missing transport skips the send and goes on. The send never
        // dials: if the msg1's connection has closed, a dial to its address
        // (for an inbound connection, the initiator's ephemeral port) would
        // hold the rx loop for up to the connect timeout.
        let sent = match self.transports.get(&ambient.transport_id) {
            Some(transport) => Some(transport.send_existing(&ambient.remote_addr, msg2).await),
            None => None,
        };
        if let Some(e) = sent.and_then(Result::err) {
            // A transient refusal is not a failed handshake. The interface
            // under this transport is absent or mid-rebind, and the binder is
            // already working to bring it back — so the half-built link is
            // left exactly as it is for the initiator's msg1 resend to land
            // on, rather than being torn down and rebuilt.
            //
            // Tearing down here charged a *local* interface flap to the
            // remote: the reject counter it recorded means "the peer sent
            // something invalid", which is a different thing entirely and
            // one an operator reads as the peer's fault.
            //
            // The initiator's resend draws the stored msg2, and the leg is
            // promoted once that send succeeds. Nothing leaks by staying: an
            // initiator that never resends leaves a stale connection, which
            // the core reaps at the handshake deadline exactly as it reaps
            // every other abandoned answer.
            if e.is_transient() {
                debug!(
                    link_id = %link,
                    error = %e,
                    "Deferred msg2: the transport is between interfaces"
                );
                if let Some(no) = self.links.no(&link) {
                    let _ = self.decide(SettleInput::SendFailed { link: no });
                }
                return false;
            }
            warn!(link_id = %link, error = %e, "Failed to send msg2");
            // The core gives the answer up: its leg goes and its lease comes
            // back, and its close rule closes nothing for it.
            if let Some(no) = self.links.no(&link) {
                for o in self.decide(SettleInput::Unsendable { link: no }) {
                    match o {
                        Output::Free { lease } => self.free_lease(lease),
                        Output::Retire { closes, .. } => {
                            self.close_each(closes).await;
                        }
                        other => {
                            debug_assert!(false, "an unsendable answer gave {other:?}")
                        }
                    }
                }
            }
            self.links.forget(
                &mut self.core,
                &link,
                &(ambient.transport_id, ambient.remote_addr.clone()),
            );
            self.remove_handshake(link);
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return false;
        }
        let Some(no) = self.links.no(&link) else {
            return true;
        };
        let out = self.decide(SettleInput::Sent { link: no });
        match self.installed(link, out) {
            Installed::Yes(_) => true,
            Installed::No => false,
            Installed::Refused(closes) => {
                self.close_each(closes).await;
                false
            }
        }
    }

    /// Promote the handshake on `link`, whose step facts are `ambient`:
    /// install its peer, run the promotion's plan, and drop its entry once
    /// the plan has read it. Returns whether the peer was installed.
    ///
    /// A refused promotion cleans up as its direction did before: for this
    /// node's dial only the reject is recorded and the entry dropped, the
    /// link left for the stale-connection reaper; for an answered msg1 the
    /// link and the index go too.
    pub(in crate::node) async fn promote(&mut self, link: LinkId, ambient: &Ambient) -> bool {
        match self.install_handshake(link, ambient.verified_identity, ambient.now_ms) {
            Ok(result) => {
                // A promotion that created a peer has already offered its
                // session to the decrypt workers: the link's rekey machine is
                // built knowing whether a pool runs, and its offer is carried
                // out with its index binding. For a replacement this is the
                // part of its plan after the removal, which ran at its site.
                let mut run = Run::promotion(link, result, ambient);
                self.run_promotion(&mut run).await;
                self.remove_handshake(link);
                true
            }
            Err(e) => {
                // Every promotion runs with no peer held for the identity, so
                // a refusal for a held one means a new path reached here
                // without resolving its crossing first.
                debug_assert!(
                    !matches!(e, NodeError::IdentityHeld(_)),
                    "a promotion reached the executor for an identity already held"
                );
                if ambient.is_outbound {
                    // A dial's refused promotion records the reject only: the
                    // dead link and its index entry are left for the
                    // stale-connection reaper (`install_handshake` already
                    // handled the entry's index on error).
                    warn!(
                        target: "fips::node::handlers::handshake",
                        link_id = %link,
                        error = %e,
                        "Failed to promote connection"
                    );
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    self.remove_handshake(link);
                } else {
                    // An answered msg1's refused promotion drops the link and
                    // its index entry, frees our index, drops the entry and
                    // records the reject.
                    warn!(
                        target: "fips::node::handlers::handshake",
                        link_id = %link,
                        error = %e,
                        "Failed to promote inbound connection"
                    );
                    self.remove_link(&link);
                    if let Some(idx) = ambient.our_index {
                        let _ = self.index_allocator.free(idx);
                    }
                    self.remove_handshake(link);
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                }
                false
            }
        }
    }

    /// Retire the link the core asked about for a msg1 the node refused
    /// after the core asked for its answer, the core's `no`, and close the
    /// connections no live link uses. `authorized` says the ACL passed it,
    /// and the refusal came at the session index's draw.
    pub(in crate::node) async fn unasked(&mut self, no: LinkNo, authorized: bool) {
        for o in self.decide(SettleInput::Abandon {
            link: no,
            authorized,
        }) {
            match o {
                Output::Retire { closes, .. } => self.close_each(closes).await,
                other => debug_assert!(false, "an abandoned ask gave {other:?}"),
            }
        }
    }

    /// The restart gates' parameters: the core's own, which no
    /// configuration moves.
    pub(in crate::node) fn gate_params(&self) -> Params {
        settle_params(&self.config().node)
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
            // The handshake entry's Noise read authenticated this msg1, so only one
            // that carries no startup epoch fails the link machine's.
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
                // The pending session's adoption then tells the core the
                // peer set the link up, on the connection it opened.
                if matches!(sent, Ok((_, true)))
                    && let Some(p) = self.peers.get_mut(peer)
                {
                    p.mark_answered_off();
                }
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
        // (`Node::dial_at`), and its handshake entry still carries the
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
                    .handshakes
                    .get(&id)
                    .is_some_and(|entry| entry.leg().is_some()) =>
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
            let entry = self.handshakes.get_mut(&link_id).unwrap();

            let noise_msg2 = &packet.data[header.noise_msg2_offset..];
            if let Err(e) = entry.complete_handshake(
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
                if entry.leg().is_some_and(|leg| leg.noise_handshake.is_some()) {
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
                // failure on its entry. The stale-connection sweep reclaims
                // the connection unconditionally via the entry's
                // `is_failed()` at the next tick, before any projection or
                // resend.
                entry.fail();
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
            }

            entry.set_conn_source_addr(packet.remote_addr.clone());
            assert!(
                entry.leg().is_some(),
                "pending connection present for msg2 completion"
            );

            match entry.conn_expected_identity() {
                Some(id) => *id,
                None => {
                    warn!(link_id = %link_id, "No identity after handshake");
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                }
            }
        };

        // The msg1 this dial sent, which the promotion and the move's line
        // read. The dial's leg stays the settlement core's: the core takes
        // it, and its lease, when it decides on the msg2 below.
        let sent_msg1 = self.leg(link_id).map(|leg| leg.msg1().to_vec());
        if let (Some(msg1), Some(entry)) = (&sent_msg1, self.handshakes.get_mut(&link_id)) {
            entry.set_conn_handshake_msg1(msg1.clone());
        }

        if self
            .authorize_peer(
                &peer_identity,
                PeerAclContext::OutboundHandshake,
                packet.transport_id,
                &packet.remote_addr,
            )
            .is_err()
        {
            if let Some(link) = self.links.get(&link_id) {
                let tid = link.transport_id();
                let addr = link.remote_addr().clone();
                if let Some(transport) = self.transports.get(&tid) {
                    transport.close_connection(&addr).await;
                }
            }
            // The dial's leg ends with its lease back to the allocator, and
            // the entry made at dial goes with it: this leg never promotes.
            // Its connection is closed above, whatever else uses it.
            let _ = self.give_up(link_id);
            self.remove_handshake(link_id);
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

        let peer_node_addr = *peer_identity.node_addr();

        debug!(
            peer = %self.peer_display_name(&peer_node_addr),
            link_id = %link_id,
            their_index = %header.sender_idx,
            "Outbound handshake completed"
        );

        // === THE SETTLEMENT CORE DECIDES ===
        // The core completes the dial on its link. With no peer held it
        // installs one. A new epoch from a held peer is a restart, which the
        // restart gates are asked about as every restart source is; they
        // pass it, the msg2 being the reply to this node's own msg1, and the
        // stale peer goes before the dial installs. Otherwise the dial
        // crossed a held peering: the core moves the peer onto this node's
        // dial when the link it holds is this node's own dial, or when this
        // node is the smaller and wins the tie-break, and keeps it on its
        // link otherwise (FRC-1201 Section 5.5).
        let Some(no) = self.links.no(&link_id) else {
            debug_assert!(false, "a dial's leg is on a link the core numbered");
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        };
        let msg2_epoch = self
            .handshakes
            .get(&link_id)
            .and_then(|e| e.conn_remote_epoch());
        // Read before the core decides: the silent count a restart's
        // removal logs against, the link the peer is held on, and the pair
        // it is at.
        let silent = self.gates().silent(&peer_node_addr);
        let held_now = self.peers.get(&peer_node_addr).map(|p| p.link_id());
        let prior = self.peer_link(&peer_node_addr);
        let decided = self.decide(SettleInput::Msg2 {
            link: no,
            epoch: msg2_epoch.unwrap_or_default(),
            from: Pair {
                transport: packet.transport_id,
                addr: packet.remote_addr.clone(),
            },
        });
        let teardown_ctx = |why| Ambient {
            verified_identity: peer_identity,
            transport_id: packet.transport_id,
            remote_addr: packet.remote_addr.clone(),
            our_index: None,
            now_ms: packet.timestamp_ms,
            is_outbound: true,
            why: Some(why),
        };
        let mut install = None;
        let mut reset = None;
        let mut swapped = None;
        let mut refusal = None;
        let mut capped = false;
        let mut restarted = false;
        let mut closes = Vec::new();
        let mut decided = decided;
        let mut retired = Self::retired(&mut decided);
        for o in decided {
            match o {
                Output::Remove { peer, why } => {
                    info!(
                        peer = %self.peer_display_name(&peer),
                        link_id = %link_id,
                        "Peer restart detected on our dial (epoch mismatch), replacing the stale peer"
                    );
                    restarted = true;
                    // The removal runs the first part of the replacement's
                    // plan, and the promotion below, told the same cause,
                    // the rest. The core asks for the reconnect itself.
                    if let Some(removed) = self.remove(&peer, why, By::Core { silent }) {
                        let mut removed = Removed {
                            noted: true,
                            ..removed
                        };
                        let closes = Self::closes_of(&mut retired, &peer);
                        self.retire_closes(peer, &mut removed, closes);
                        let mut run = Run::replacement(link_id, removed, &teardown_ctx(why));
                        self.run_removal(&mut run).await;
                    }
                }
                Output::Retry { peer } => self.note_link_dead(peer, Self::peering_now()),
                Output::Install(i) => install = Some(i),
                Output::Reset { transition, .. } => reset = Some(transition),
                Output::Swapped { own, unpin, .. } => swapped = Some((own, unpin)),
                Output::Reject {
                    why: Denial::Gate(r),
                    ..
                } => refusal = Some(r),
                Output::Reject {
                    why: Denial::Cap, ..
                } => capped = true,
                Output::Free { lease } => self.free_lease(lease),
                // A removal's connections are closed by its plan, from the
                // `Retire` taken above; a crossing's are closed by the
                // crossing's own run, and the refused restart's below.
                Output::Retire { closes: c, .. } => closes = c,
                other => debug_assert!(false, "a msg2 gave {other:?}"),
            }
        }

        if let Some(refusal) = refusal {
            debug!(
                peer = %self.peer_display_name(&peer_node_addr),
                link_id = %link_id,
                reason = ?refusal,
                "Restart on our dial refused by the restart gates, dropping the dial"
            );
            // The dial's connection closes by the close rule: not while the
            // held link, or any other live link, uses it.
            self.close_each(closes).await;
            self.remove_handshake(link_id);
            self.remove_link(&link_id);
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }
        if capped {
            // The install refused at the max-peers cap (peers filled between
            // the dial and its msg2). The core hands the lease back and
            // retires the dial's link, which goes with its entry; its
            // connection closes by the close rule, when no other live link
            // uses it, as one the ACL refuses.
            warn!(
                target: "fips::node::handlers::handshake",
                link_id = %link_id,
                error = %NodeError::MaxPeersExceeded {
                    max: self.max_peers(),
                },
                "Failed to promote connection"
            );
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            self.close_each(closes).await;
            self.remove_handshake(link_id);
            self.remove_link(&link_id);
            return;
        }

        let crossing = swapped.is_some() || reset == Some(Transition::Keep);
        if crossing {
            // Extract the outbound connection from its entry FIRST — the
            // entry owns it, so dropping the entry before the take would
            // destroy the connection. The core has decided and the inline
            // resolution below needs no entry, so drop it right after the
            // take, whether or not a connection was carried, so none of this
            // block's exits leave a dangling entry.
            let taken_conn = self
                .handshakes
                .get_mut(&link_id)
                .and_then(|entry| entry.take_leg());
            let sent_msg1_digest = sent_msg1.as_deref().map(Msg1Digest::of);
            self.remove_handshake(link_id);
            let mut conn = match taken_conn {
                Some(c) => c,
                None => {
                    if let Some(i) = install {
                        self.free_lease(i.lease);
                    }
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::UnknownConnection));
                    return;
                }
            };

            if let (Some((own_dial, own)), Some(install)) = (swapped, install) {
                // The core moved the peer onto this dial: this node is the
                // smaller, or the link the peer held was its own dial, or the
                // dial was made while the peer was held on it. Swap to the
                // outbound session and the dial's index. The peer keeps the
                // session it answered this dial with (complement of ours).
                let outbound_lease = install.lease;
                let Some(outbound_session) = conn.noise_session.take() else {
                    warn!(peer = %self.peer_display_name(&peer_node_addr), "Incomplete outbound connection");
                    self.free_lease(outbound_lease);
                    self.stats_mut()
                        .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                    return;
                };
                let outbound_our_index = SessionIndex::new(outbound_lease.index());
                let local = self.session_node_keys();
                let me = *self.identity().node_addr();
                let params = crate::node::handlers::rekey::link_params(&self.config().node);
                let path_params = crate::node::handlers::path::path_params(&self.config().node);
                let workers = self.link_workers();

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
                    let (out, paths) = peer.adopt_dial(
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
                    // the notes, and the losing link.
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
                    facts.closes = std::mem::take(&mut closes);
                    facts.key = Some(crate::ipv6tun::link::PeerKey::from_xonly(
                        &peer_identity.pubkey(),
                    ));
                    facts.suppressed = suppressed;
                    facts.epoch = Some(epoch);
                    facts.msg1 = sent_msg1_digest;
                    facts.first_heard = first_heard;
                    self.run(&mut run).await;
                    return;
                }
                self.free_lease(outbound_lease);
            } else {
                // The core kept the peer on its inbound session (it pairs
                // with the peer's outbound, which is the winning handshake),
                // and handed the dial's index back.
                //
                // Do NOT update their_index here. Our their_index was set during
                // install_handshake() from the peer's msg1 sender_idx, which is
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
                facts.loser = Some(link_id);
                facts.closes = closes;
                self.run(&mut run).await;
                return;
            }

            // A won crossing whose peer is no longer held moves nothing, and
            // the dial's leg still ends as at any crossing. The core decided
            // on the node's own record of the peer, with nothing awaited
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

        // === Net-new outbound establish ===
        // The core installs the dial as a new peer, with no peer held or
        // after a restart's removal above (FRC-1201 Section 5.5: no
        // tie-break). The lease the dial's leg held moves to the dial's entry
        // for the promotion, which installs the peer.
        let Some(install) = install else {
            debug_assert!(
                false,
                "a completed dial the core neither refused nor settled"
            );
            self.remove_handshake(link_id);
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        };
        let our_index = SessionIndex::new(install.lease.index());
        let Some(entry) = self.handshakes.get_mut(&link_id) else {
            self.free_lease(install.lease);
            return;
        };
        if let Some(old) = entry.set_conn_our_index(install.lease) {
            let _ = self.index_allocator.free(SessionIndex::new(old.release()));
        }
        if let Some(entry) = self.handshakes.get_mut(&link_id) {
            entry.set_conn_their_index(header.sender_idx);
        }

        // The promotion installs the peer and runs its tail: the promotion
        // logged, the initial tree announce and the filter announce
        // scheduled. A refused promotion drops the entry and runs no tail.
        let ambient = Ambient {
            verified_identity: peer_identity,
            transport_id: packet.transport_id,
            remote_addr: packet.remote_addr.clone(),
            our_index: Some(our_index),
            now_ms: packet.timestamp_ms,
            is_outbound: true,
            why: restarted.then_some(Why::OwnRestart),
        };
        self.promote(link_id, &ambient).await;
    }

    /// Promote a connection to active peer after successful authentication.
    ///
    /// A crossing is resolved before the promotion is asked for, so this
    /// installs a new peer only: an identity already held is refused with
    /// [`NodeError::IdentityHeld`] and the connection's index is freed. The
    /// result is always [`PromotionResult::Promoted`].
    pub(in crate::node) fn install_handshake(
        &mut self,
        link_id: LinkId,
        verified_identity: PeerIdentity,
        current_time_ms: u64,
    ) -> Result<PromotionResult, NodeError> {
        // Take the pending connection off its handshake entry, and read the
        // fields the promotion needs in the same borrow. The entry outlives
        // the promotion, left with no pending connection, until the
        // promotion's work has read it.
        //
        // The connection is detached before anything is validated, so every
        // error return below leaves the entry leg-less — the caller disposes
        // of it. Gathering the reads up front is only a borrow shape: they
        // are infallible, so the order in which the missing-field errors are
        // reported below is unchanged.
        // An answer's leg leaves the legs here: the entry takes the lease the
        // shell drew for it, for the promotion.
        if self.handshakes.contains_key(&link_id)
            && let Some(lease) = self.take_leg(link_id)
            && let Some(old) = self
                .handshakes
                .get_mut(&link_id)
                .and_then(|entry| entry.set_conn_our_index(lease))
        {
            let _ = self.index_allocator.free(SessionIndex::new(old.release()));
        }
        let entry = self
            .handshakes
            .get_mut(&link_id)
            .ok_or(NodeError::ConnectionNotFound(link_id))?;
        let mut connection = entry
            .take_leg()
            .ok_or(NodeError::ConnectionNotFound(link_id))?;
        let carrier_our_index = entry.our_index();
        let carrier_their_index = entry.conn_their_index();
        let carrier_transport_id = entry.conn_transport_id();
        let carrier_source_addr = entry.conn_source_addr().cloned();
        let carrier_is_outbound = entry.conn_is_outbound();
        let carrier_remote_epoch = entry.conn_remote_epoch();
        let link_stats = entry.conn_link_stats().clone();
        let direction = entry.conn_direction();
        // The msg1 this link was set up by: the one this node sent, or the
        // one it answered.
        let msg1_digest = match direction {
            LinkDirection::Outbound => entry.conn_handshake_msg1().map(Msg1Digest::of),
            LinkDirection::Inbound => entry.conn_msg1_digest(),
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
        // The lease that holds `our_index` moves from the entry to the
        // promoted peer's link rekey machine, or back to the allocator.
        let our_lease = self
            .handshakes
            .get_mut(&link_id)
            .and_then(Handshake::take_our_index)
            .ok_or_else(|| NodeError::PromotionFailed {
                link_id,
                reason: "missing our_index".into(),
            })?;

        let peer_node_addr = *verified_identity.node_addr();
        let is_outbound = carrier_is_outbound;

        // Every promotion runs with no peer held for this identity: the
        // settlement core installs a leg only with none, a restart or a
        // replace removes the old peer before the promotion, and a resent
        // msg2 promotes only while none is held. Installing
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
            .filter(|(_, entry)| {
                entry
                    .conn_expected_identity()
                    .map(|id| *id.node_addr() == peer_node_addr)
                    .unwrap_or(false)
            })
            .map(|(link, _)| *link)
            .collect();

        for pending_link_id in &pending_to_same_peer {
            debug!(
                peer = %self.peer_display_name(&peer_node_addr),
                pending_link_id = %pending_link_id,
                promoted_link_id = %link_id,
                "Deferring cleanup of pending outbound (awaiting msg2 for index update)"
            );
        }

        // Normal promotion. The settlement core refuses an install at the
        // max-peers cap before it hands one to the executor, so only a
        // test's direct call of the promotion reaches this refusal.
        if self.max_peers() > 0 && self.peers.len() >= self.max_peers() {
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
