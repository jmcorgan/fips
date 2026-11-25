//! The traversal half of the rendezvous machine: the initiator's connect,
//! the responder's answer to an offer, the signals between them, and the
//! node's failure records.
//!
//! Every check keeps the order FRC-1601 and the code before this one gave
//! it. The initiator: capacity, the peer's advert (cache, else the relays),
//! its `udp:nat` endpoint, the peer's inbox relays, the socket, the local
//! candidates and the STUN observation, the offer, the wait for the answer
//! (the skew noted before the answer is checked), the on-link prefixes,
//! the plan and the punch. The responder: the signal gate (before any
//! decryption), the offer admission, the offer's bounds, capacity,
//! freshness, the dual-initiation election, the replay check, then the
//! same inbox, socket and observation steps, the answer, and the punch.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::SocketAddr;
use core::time::Duration;

use fips_core::entropy::EntropySource;
use fips_core::identity::PeerIdentity;
use fips_core::time::{Instant, deadline};
use fips_core::utils::onlink::OnLinkPrefixes;
use nostr::event::{Event, Kind};
use nostr::nips::nip19::ToBech32;
use nostr::types::{RelayUrl, Timestamp};

use super::super::error::Error;
use super::super::event::signal::{open_signal, rumor, seal_and_wrap};
use super::super::params::TRAVERSAL_STUN_TIMEOUT;
use super::super::punch::attempt::{Attempt, PunchOut};
use super::super::punch::plan::planned_remote_endpoints;
use super::super::signal::{
    FreshnessOutcome, check_offer, create_traversal_answer, create_traversal_offer,
    estimate_clock_skew, validate_traversal_answer_for_offer,
};
use super::super::stun::candidates::{local_candidates, offerable};
use super::super::stun::client::{Observation, Out};
use super::super::traversal::admission::AdmissionReject;
use super::super::traversal::election::{OfferDisposition, SeenDecision};
use super::super::traversal::rules::{
    self, INBOX_FETCH_TIMEOUT, RejectReason, canonical_npub, check_offer_bounds, short_id,
    short_npub,
};
use super::super::traversal::sessions::{EARLY_DATAGRAMS, Key, Resend, Role, Session, Stage};
use super::super::types::{
    FailureReply, NostrFailureDecision, OverlayAdvert, SIGNAL_KIND, TraversalAddress,
    TraversalAnswer, TraversalOffer,
};
use super::io::{Action, ConnectId, Interfaces, PeerKey, Read, Reply, ReplyId, ReqId, SocketId};
use super::log::{Log, Source};
use super::{Now, Rendezvous};

/// An address as the traversal lines print it: `ip:port`, or `-`.
fn addr_text(address: Option<&TraversalAddress>) -> String {
    address.map_or_else(|| "-".to_string(), |a| format!("{}:{}", a.ip, a.port))
}

/// A traversal address for `addr`.
fn udp(addr: SocketAddr) -> TraversalAddress {
    TraversalAddress {
        protocol: "udp".to_string(),
        ip: addr.ip().to_string(),
        port: addr.port(),
    }
}

/// How a session ends when it fails.
pub(super) struct Failure {
    error: Error,
    /// For a refused offer: whether relay lag cannot explain it.
    adversarial: bool,
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self {
            error,
            adversarial: false,
        }
    }
}

impl From<RejectReason> for Failure {
    fn from(reason: RejectReason) -> Self {
        Self {
            adversarial: reason.adversarial(),
            error: reason.into(),
        }
    }
}

/// A re-send of an initiator's offer in flight: the session, and what its
/// line names.
pub(super) struct Resending {
    session: Key,
    peer: String,
    short_session: String,
    event: String,
    session_id: String,
}

impl<I: Instant, E: EntropySource> Rendezvous<I, E> {
    // --- the node's calls ------------------------------------------------

    /// Traverse to the peer the node configured as `npub`.
    pub(super) fn connect(&mut self, npub: String, connect: ConnectId, now: Now<I>) {
        // The configuration may name the peer by any spelling of its key.
        // The traversal runs under the canonical npub, so the initiator set
        // dedupes spellings and the offer names the recipient as it names
        // itself; the failure event hands back the configuration as given.
        let canonical = canonical_npub(&npub);
        if !self.election.begin_initiator(&canonical) {
            self.actions.push_back(Action::Release { connect });
            return;
        }
        let peer = short_npub(&canonical);
        if !self.capacity {
            self.log(Log::InitiatorSuppressed { peer });
            return self.connect_failed(connect, &canonical, Error::Disabled);
        }
        self.log(Log::InitiatorStarting { peer });
        let (pubkey, key_npub) = match rules::peer_key(&canonical) {
            Ok(key) => key,
            Err(error) => return self.connect_failed(connect, &canonical, error),
        };
        let key = PeerKey {
            pubkey,
            npub: key_npub,
        };
        self.prune(now.unix_ms);
        let session = Session::new(
            Role::Initiator { connect },
            key.clone(),
            String::new(),
            Stage::Binding,
        );
        let session = self.sessions.insert(session);
        if let Some(advert) = self.cache.cached_advert(&key.npub, now.unix_ms) {
            self.log(Log::Resolved {
                peer: key.npub.clone(),
                source: Source::Cache,
                endpoints: advert.endpoints.clone(),
            });
            return self.advert_resolved(session, Ok(advert), now);
        }
        let req = ReqId(self.id());
        let filter = Self::advert_filter(&key);
        if let Some(s) = self.sessions.get(session) {
            s.stage = Stage::ResolvingAdvert(req);
        }
        self.actions.push_back(Action::Fetch {
            req,
            relays: self.params.advert_relays.clone(),
            filter,
            timeout: super::super::params::ADVERT_FETCH_TIMEOUT,
        });
    }

    /// A connect ended before it had a session.
    fn connect_failed(&mut self, connect: ConnectId, npub: &str, error: Error) {
        self.election.end_initiator(npub);
        self.actions.push_back(Action::Failed {
            connect,
            reason: error.to_string(),
        });
    }

    /// Whether the node has room for another peer.
    pub(super) fn set_capacity(&mut self, capacity: bool) {
        #[cfg(test)]
        {
            self.capacity_taken += 1;
        }
        self.capacity = capacity;
    }

    /// Record a failed traversal to `npub` and answer with the decision.
    pub(super) fn record_failure(&mut self, npub: &str, reply: ReplyId, now: Now<I>) {
        let d = self
            .failures
            .record_failure(&canonical_npub(npub), now.unix_ms);
        self.status_changed = true;
        let decision = NostrFailureDecision {
            consecutive_failures: d.consecutive_failures,
            should_warn: d.should_warn,
            cooldown_until_ms: d.cooldown_until_ms,
            crossed_threshold: d.crossed_threshold,
        };
        self.reply(
            reply,
            Reply::Failure(FailureReply {
                decision,
                at_ms: now.unix_ms,
            }),
        );
    }

    /// A datagram from a traversed peer's address carried another FMP
    /// version: hold the peer off for the long mismatch cooldown, and warn
    /// once for a fresh observation.
    pub(super) fn version_mismatch(
        &mut self,
        npub: String,
        transport_id: String,
        remote_addr: String,
        peer_version: u8,
        our_version: u8,
        now: Now<I>,
    ) {
        let cooldown_secs = self.params.protocol_mismatch_cooldown_secs;
        let fresh = self.failures.record_protocol_mismatch(
            &canonical_npub(&npub),
            now.unix_ms,
            cooldown_secs.saturating_mul(1000),
        );
        self.status_changed = true;
        if fresh {
            self.log(Log::VersionMismatch {
                npub,
                transport_id,
                remote_addr,
                peer_version,
                our_version,
                cooldown_secs,
            });
        }
    }

    // --- signals ---------------------------------------------------------

    /// A traversal signal a relay delivered: shed it before decryption if
    /// the gate says so, open it, and hand an answer to the traversal
    /// waiting for it or take an offer in.
    pub(super) fn signal(&mut self, event: Box<Event>, now: Now<I>) {
        // Ahead of the open, which is two NIP-44 decrypts and a signature
        // verify. Nothing about the sender is known yet (the outer event is
        // signed by a key made per event), so the allowance is shared and
        // indiscriminate; the reserve is what keeps a flood from also
        // shedding the answers to traversals this node started.
        if let Err(reason) = self.gate.admit(self.awaiting_answers(), now.mono) {
            self.shed += 1;
            let total = self.shed;
            // Debug per signal: whoever trips this sends faster than the
            // node wants, so a line each would turn the flood into log
            // volume. The doubling summary is the operator's signal.
            self.log(Log::SignalShed { reason, total });
            if total.is_power_of_two() {
                self.log(Log::SignalsShed { shed: total });
            }
            return;
        }
        let opened = match open_signal(&self.signer, &event) {
            Ok(opened) => opened,
            Err(error) => {
                return self.log(Log::UnwrapFailed {
                    error: error.to_string(),
                });
            }
        };
        let sender_npub = match opened.sender.to_bech32() {
            Ok(npub) => npub,
            Err(error) => {
                return self.log(Log::SenderNpubFailed {
                    error: error.to_string(),
                });
            }
        };
        let content = &opened.rumor.content;
        if let Ok(answer) = serde_json::from_str::<TraversalAnswer>(content)
            && answer.message_type == "answer"
            && answer.recipient_npub == self.npub
        {
            return self.route_answer(answer, sender_npub, now);
        }
        if let Ok(offer) = serde_json::from_str::<TraversalOffer>(content)
            && offer.message_type == "offer"
            && offer.recipient_npub == self.npub
        {
            self.offer(offer, opened.sender, sender_npub, now);
        }
    }

    /// Whether any traversal of ours waits on an answer.
    fn awaiting_answers(&self) -> bool {
        #[cfg(test)]
        if !self.answer_waits.is_empty() {
            return true;
        }
        self.sessions.awaiting_answers()
    }

    /// Hand `answer` to the initiator whose offer it answers, if one waits.
    fn route_answer(&mut self, answer: TraversalAnswer, sender_npub: String, now: Now<I>) {
        #[cfg(test)]
        if let Some(reply) = self.answer_waits.remove(&answer.in_reply_to) {
            return self.reply(reply, Reply::AnswerRouted);
        }
        let Some(key) = self.sessions.by_nonce(&answer.in_reply_to) else {
            return;
        };
        let Some(session) = self.sessions.get(key) else {
            return;
        };
        if session.stage == Stage::AwaitingAnswer {
            self.answer_received(key, answer, sender_npub, now);
        } else {
            // The offer is still being published: hold the answer for when
            // the wait starts.
            session.held_answer = Some((answer, sender_npub));
        }
    }

    /// An offer from `sender`: take an admission slot, then check it.
    fn offer(
        &mut self,
        offer: TraversalOffer,
        sender: nostr::key::PublicKey,
        sender_npub: String,
        now: Now<I>,
    ) {
        let slot = match self.admission.try_admit(&sender_npub) {
            Ok(slot) => slot,
            Err(AdmissionReject::GlobalFull) => {
                return self.log(Log::OfferRateLimited {
                    sender_npub,
                    limit: self.params.max_concurrent_incoming_offers,
                });
            }
            // Debug, not warn: whoever trips this sends faster than the
            // node wants. The global arm above stays at warn as the
            // operator's sign the node is saturated.
            Err(AdmissionReject::SenderFull) => {
                return self.log(Log::OfferSenderFull {
                    sender_npub,
                    limit: self.params.max_concurrent_offers_per_npub,
                });
            }
        };
        let peer = short_npub(&sender_npub);
        let session = short_id(&offer.session_id);
        let refuse = |this: &mut Self, failure: Failure| {
            this.admission.release(slot);
            this.offer_failed(&peer, &session, failure);
        };
        // Before anything logs, records or copies the session id or nonce.
        if let Err(reason) = check_offer_bounds(&offer) {
            return refuse(self, reason.into());
        }
        if !self.capacity {
            self.admission.release(slot);
            return self.log(Log::OfferDroppedAtCapacity { peer, session });
        }
        let received_at = now.unix_ms;
        self.log(Log::OfferReceived {
            peer: peer.clone(),
            session: session.clone(),
            reflexive: addr_text(offer.reflexive_address.as_ref()),
            local: offer.local_addresses.len(),
        });
        let outcome = match check_offer(
            &offer,
            received_at,
            self.params.signal_ttl_secs * 1000,
            &sender_npub,
            &self.npub,
        ) {
            Ok(outcome) => outcome,
            Err(reason) => return refuse(self, reason.into()),
        };
        if outcome == FreshnessOutcome::FreshWithinSkewTolerance {
            self.log(Log::OfferWithinTolerance {
                peer: peer.clone(),
                session: session.clone(),
                offer_issued_at: offer.issued_at,
                offer_expires_at: offer.expires_at,
                offer_received_at: received_at,
            });
        }
        // When both nodes start a traversal to each other at once, both keep
        // the one the smaller node address started: if ours is the one,
        // this offer is not answered, and the peer's initiator times out. A
        // one-sided connect is never suppressed.
        match (
            PeerIdentity::from_npub(&self.npub),
            PeerIdentity::from_npub(&sender_npub),
        ) {
            (Ok(ours), Ok(theirs)) => {
                let disposition = self.election.classify_incoming_offer(
                    &sender_npub,
                    ours.node_addr(),
                    theirs.node_addr(),
                );
                if disposition == OfferDisposition::Suppress {
                    self.admission.release(slot);
                    self.log(Log::ResponderSuppressed {
                        peer: peer.clone(),
                        session,
                    });
                    return self.resend(&sender_npub, now);
                }
            }
            // No node address for one side: answer rather than risk
            // suppressing the only session.
            _ => self.log(Log::NoNodeAddr { peer: peer.clone() }),
        }
        match self
            .election
            .note_session_seen(&offer.session_id, now.unix_ms)
        {
            SeenDecision::Replay => {
                return refuse(self, RejectReason::Replay(offer.session_id.clone()).into());
            }
            SeenDecision::Full => return refuse(self, RejectReason::SeenFull.into()),
            SeenDecision::Fresh => {}
        }
        let key = PeerKey {
            pubkey: sender,
            npub: sender_npub,
        };
        let session_id = offer.session_id.clone();
        let session = Session::new(
            Role::Responder {
                slot,
                offer: Box::new(offer),
                received_at_ms: received_at,
            },
            key,
            session_id,
            Stage::Binding,
        );
        let session = self.sessions.insert(session);
        // The answer's relays are resolved before a socket is bound and
        // STUN run: nothing in the relay choice depends on what STUN
        // observes, and an offer from a peer we share no relay with cannot
        // be answered at all.
        self.lookup_inbox(session, now);
    }

    /// Log a refused offer: at warn when relay lag cannot explain it.
    fn offer_failed(&mut self, peer: &str, session: &str, failure: Failure) {
        self.log(Log::OfferFailed {
            peer: peer.to_string(),
            session: session.to_string(),
            error: failure.error.to_string(),
            adversarial: failure.adversarial,
        });
    }

    /// Send our offer to `peer_npub` once more, when the dual-initiation
    /// election suppresses the peer's. If the peer got ours it answers that
    /// one and drops this copy as a replay; if ours was lost, this copy
    /// lets the peer answer now rather than after the signal lifetime. At
    /// most one successful re-send per offer: it is marked done only once a
    /// publish succeeds, and while one is publishing no other is sent.
    fn resend(&mut self, peer_npub: &str, now: Now<I>) {
        let Some(key) = self.sessions.awaiting_from(peer_npub) else {
            return;
        };
        let Some(session) = self.sessions.get(key) else {
            return;
        };
        if session.resend != Resend::Available {
            return;
        }
        let (Some(offer), receiver) = (session.offer.clone(), session.peer.pubkey) else {
            return;
        };
        session.resend = Resend::Sending;
        let relays = session.relays.clone();
        let peer = short_npub(&session.peer.npub);
        let short_session = short_id(&offer.session_id);
        match self.signal_event(receiver, &offer, now) {
            Ok(event) => {
                let req = ReqId(self.id());
                self.resends.insert(
                    req,
                    Resending {
                        session: key,
                        peer,
                        short_session,
                        event: short_id(&event.id.to_string()),
                        session_id: offer.session_id,
                    },
                );
                self.publish_signal(req, relays, event);
            }
            Err(error) => {
                if let Some(session) = self.sessions.get(key) {
                    session.resend = Resend::Available;
                }
                self.log(Log::OfferResendFailed {
                    peer,
                    session: short_session,
                    error: error.to_string(),
                });
            }
        }
    }

    /// The re-send `req` ended.
    pub(super) fn resent(&mut self, req: ReqId, ok: Result<(), String>) -> bool {
        let Some(resending) = self.resends.remove(&req) else {
            return false;
        };
        // The session may have ended (answered or timed out) while the
        // publish ran; only this offer's session is updated.
        if let Some(session) = self
            .sessions
            .get(resending.session)
            .filter(|s| s.session_id == resending.session_id)
        {
            session.resend = if ok.is_ok() {
                Resend::Done
            } else {
                Resend::Available
            };
        }
        match ok {
            Ok(()) => self.log(Log::OfferResent {
                peer: resending.peer,
                session: resending.short_session,
                event: resending.event,
            }),
            Err(error) => self.log(Log::OfferResendFailed {
                peer: resending.peer,
                session: resending.short_session,
                error: Error::Nostr(error).to_string(),
            }),
        }
        true
    }

    /// A traversal signal carrying `payload` from us to `receiver`, at the
    /// step's time.
    fn signal_event<T: serde::Serialize>(
        &self,
        receiver: nostr::key::PublicKey,
        payload: &T,
        now: Now<I>,
    ) -> Result<Event, Error> {
        let body = serde_json::to_string(payload).map_err(|e| Error::Nostr(e.to_string()))?;
        let rumor = rumor(self.signer.public_key(), receiver, body, now.unix_ms);
        seal_and_wrap::<E>(
            &self.signer,
            receiver,
            rumor,
            now.unix_ms,
            Timestamp::from((now.unix_ms + self.params.signal_ttl_secs * 1000) / 1000),
        )
    }

    /// Publish a traversal signal. A signal has no deadline of its own: the
    /// client's send ends it.
    fn publish_signal(&mut self, req: ReqId, relays: Vec<String>, event: Event) {
        self.sent.insert(req, (SIGNAL_KIND, event.id, relays.len()));
        self.actions.push_back(Action::Publish {
            req,
            relays,
            event,
            timeout: None,
        });
    }

    // --- the session steps -------------------------------------------------

    /// End the session under `key` with `failure`: the initiator's connect
    /// fails, and the responder logs why.
    pub(super) fn fail(&mut self, key: Key, failure: Failure) {
        let Some(session) = self.end(key, true) else {
            return;
        };
        match session.role {
            Role::Initiator { connect } => self.actions.push_back(Action::Failed {
                connect,
                reason: failure.error.to_string(),
            }),
            Role::Responder { .. } => {
                let peer = short_npub(&session.peer.npub);
                let short = short_id(&session.session_id);
                self.offer_failed(&peer, &short, failure);
            }
        }
    }

    /// Take the session under `key` out: close its socket when `close`,
    /// give its admission slot back, and end the peer's initiator.
    fn end(&mut self, key: Key, close: bool) -> Option<Session<I, E>> {
        let session = self.sessions.remove(key)?;
        if close && let Some(socket) = session.socket {
            self.actions.push_back(Action::Close { socket });
        }
        match &session.role {
            Role::Initiator { .. } => self.election.end_initiator(&session.peer.npub),
            Role::Responder { slot, .. } => self.admission.release(*slot),
        }
        Some(session)
    }

    /// The initiator's advert for its peer arrived.
    pub(super) fn advert_resolved(
        &mut self,
        key: Key,
        advert: Result<OverlayAdvert, Error>,
        now: Now<I>,
    ) {
        let advert = match advert {
            Ok(advert) => advert,
            Err(error) => return self.fail(key, error.into()),
        };
        let Some(session) = self.sessions.get(key) else {
            return;
        };
        if !advert.has_udp_nat_endpoint() {
            let npub = session.peer.npub.clone();
            return self.fail(key, Error::MissingNatEndpoint(npub).into());
        }
        session.advert_signal = advert.signal_relays;
        self.lookup_inbox(key, now);
    }

    /// Look up the peer's inbox relay list.
    fn lookup_inbox(&mut self, key: Key, now: Now<I>) {
        let req = ReqId(self.id());
        let Some(session) = self.sessions.get(key) else {
            return;
        };
        session.stage = Stage::InboxLookup(req);
        let (relays, filter) = rules::inbox_lookup(
            session.peer.pubkey,
            &self.params.dm_relays,
            &self.params.advert_relays,
            now.unix_ms,
        );
        self.actions.push_back(Action::Fetch {
            req,
            relays,
            filter,
            timeout: INBOX_FETCH_TIMEOUT,
        });
    }

    /// A fetch a session waited on ended.
    pub(super) fn session_fetched(
        &mut self,
        req: ReqId,
        outcome: Result<Vec<Event>, String>,
        now: Now<I>,
    ) {
        let Some(key) = self.sessions.by_req(req) else {
            return;
        };
        let Some(session) = self.sessions.get(key) else {
            return;
        };
        match session.stage {
            Stage::ResolvingAdvert(_) => {
                let peer = session.peer.clone();
                let advert = self.fetched_advert(&peer, outcome, now);
                self.advert_resolved(key, advert, now);
            }
            Stage::InboxLookup(_) => self.inbox_fetched(key, outcome),
            _ => {}
        }
    }

    /// The peer's inbox relay list was looked up: choose the relays its
    /// signals go to, from those the relay pool holds, then bind. A list
    /// whose id or signature does not verify is counted and dropped, as if
    /// no relay had sent it, so a forged newer list cannot redirect the
    /// signals.
    fn inbox_fetched(&mut self, key: Key, outcome: Result<Vec<Event>, String>) {
        if let Err(error) = &outcome {
            self.log(Log::InboxFetchFailed {
                error: error.clone(),
            });
        }
        let outcome = outcome.map(|events| self.authentic_only(events));
        let Some(session) = self.sessions.get(key) else {
            return;
        };
        let inbox = rules::inbox_or_fallback(
            outcome.as_deref(),
            session.peer.pubkey,
            &self.params.dm_relays,
        );
        let usable = rules::signal_relays(
            &inbox,
            session.advert_signal.as_deref(),
            &self.params.dm_relays,
            &self.pool,
        );
        let peer = session
            .peer
            .pubkey
            .to_bech32()
            .map(|npub| short_npub(&npub))
            .unwrap_or_default();
        let (inbox, count) = (inbox.len(), usable.len());
        session.relays = usable;
        let missing = match &session.role {
            Role::Initiator { .. } => session.peer.npub.clone(),
            Role::Responder { offer, .. } => offer.sender_npub.clone(),
        };
        self.log(Log::SignalRelaysResolved {
            peer,
            inbox,
            usable: count,
        });
        if count == 0 {
            return self.fail(key, Error::MissingRelays(missing).into());
        }
        let socket = SocketId(self.id());
        if let Some(session) = self.sessions.get(key) {
            session.socket = Some(socket);
            session.stage = Stage::Binding;
        }
        self.actions.push_back(Action::Bind { socket });
    }

    /// A session's socket is bound at `local`: read the local candidates
    /// first when they are shared, then observe.
    pub(super) fn session_bound(&mut self, key: Key, local: SocketAddr, now: Now<I>) {
        let share = self.params.share_local_candidates;
        let req = share.then(|| ReqId(self.id()));
        let Some(session) = self.sessions.get(key) else {
            return;
        };
        session.local = Some(local);
        if let Some(req) = req {
            session.stage = Stage::Candidates(req);
            self.actions.push_back(Action::ReadInterfaces {
                req,
                read: Read::Candidates { port: local.port() },
            });
        } else {
            self.observe(key, now);
        }
    }

    /// What the read `req` found.
    pub(super) fn interfaces(&mut self, req: ReqId, read: Interfaces, now: Now<I>) {
        let Some(key) = self.sessions.by_req(req) else {
            return;
        };
        let Some(session) = self.sessions.get(key) else {
            return;
        };
        match (session.stage, read) {
            (Stage::Candidates(_), Interfaces::Candidates { entries, observed }) => {
                let Some(local) = session.local else {
                    return;
                };
                session.local_addresses =
                    offerable(local_candidates(&entries, &observed), local.is_ipv4())
                        .into_iter()
                        .map(|ip| TraversalAddress {
                            protocol: "udp".to_string(),
                            ip,
                            port: local.port(),
                        })
                        .collect();
                self.observe(key, now);
            }
            (Stage::OnLink(_), Interfaces::OnLink(on_link)) => self.plan(key, &on_link, now),
            _ => {}
        }
    }

    /// Observe the socket's reflexive address over the configured STUN
    /// servers. It drains every datagram on the socket until it ends, so it
    /// completes before any punch can be in flight.
    fn observe(&mut self, key: Key, now: Now<I>) {
        let servers = self.params.stun_servers.clone();
        let Some(session) = self.sessions.get(key) else {
            return;
        };
        let want_v4 = session.local.is_none_or(|local| local.is_ipv4());
        let mut client = Observation::new(servers, TRAVERSAL_STUN_TIMEOUT, want_v4);
        let out = client.begin(now.mono);
        session.stun = Some(client);
        session.stage = Stage::Observing;
        self.session_stun(key, out, now);
    }

    /// Carry out what a session's STUN client asked for.
    pub(super) fn session_stun(&mut self, key: Key, out: Vec<Out>, now: Now<I>) {
        for step in out {
            let Some(session) = self.sessions.get(key) else {
                return;
            };
            let Some(socket) = session.socket else {
                return;
            };
            match step {
                Out::Resolve { host, port } => {
                    let req = ReqId(self.next_id);
                    self.next_id += 1;
                    if let Some(session) = self.sessions.get(key) {
                        session.resolving = Some(req);
                    }
                    self.actions.push_back(Action::Resolve { req, host, port });
                }
                Out::Send { dst, bytes } => {
                    self.actions.push_back(Action::Send { socket, dst, bytes });
                }
                Out::Discarded {
                    server,
                    expected,
                    rejected,
                    last_unexpected,
                } => self.log(Log::StunDiscarded {
                    server,
                    expected,
                    rejected,
                    last_unexpected,
                }),
                Out::Succeeded { server, mapped } => {
                    self.log(Log::StunSucceeded {
                        server: server.clone(),
                        mapped,
                    });
                    if let Some(session) = self.sessions.get(key) {
                        session.reflexive = Some(udp(mapped));
                        session.stun_server = Some(server);
                    }
                    return self.observed(key, now);
                }
                Out::Failed { error } => {
                    if let Some(error) = error {
                        self.log(Log::StunFailed { error });
                    }
                    return self.observed(key, now);
                }
            }
        }
    }

    /// The observation ended: the initiator sends its offer, the responder
    /// its answer.
    fn observed(&mut self, key: Key, now: Now<I>) {
        let npub = self.npub.clone();
        let ttl_ms = self.params.signal_ttl_secs * 1000;
        let hint = rules::punch_hint(
            now.unix_ms,
            self.params.punch_start_delay_ms,
            self.params.punch_interval_ms,
            self.params.punch_duration_ms,
        );
        let session_id = self.draw_nonce(now);
        let Some(session) = self.sessions.get(key) else {
            return;
        };
        session.stun = None;
        session.resolving = None;
        let peer = short_npub(&session.peer.npub);
        let receiver = session.peer.pubkey;
        let reflexive = addr_text(session.reflexive.as_ref());
        let local = session.local_addresses.len();
        let body = match &session.role {
            Role::Initiator { .. } => {
                let offer = create_traversal_offer(
                    session_id.clone(),
                    now.unix_ms,
                    ttl_ms,
                    session_id.clone(),
                    npub,
                    session.peer.npub.clone(),
                    session.reflexive.clone(),
                    session.local_addresses.clone(),
                    session.stun_server.clone(),
                );
                let stun = session
                    .stun_server
                    .clone()
                    .unwrap_or_else(|| "-".to_string());
                session.session_id = session_id;
                session.offer = Some(offer.clone());
                self.log(Log::InitiatorStunObserved {
                    peer,
                    reflexive,
                    local,
                    stun,
                });
                self.signal_event(receiver, &offer, now)
            }
            Role::Responder {
                offer,
                received_at_ms,
                ..
            } => {
                let accepted = session.reflexive.is_some() || !session.local_addresses.is_empty();
                let answer = create_traversal_answer(
                    offer.session_id.clone(),
                    now.unix_ms,
                    ttl_ms,
                    session_id,
                    npub,
                    offer.sender_npub.clone(),
                    offer.nonce.clone(),
                    accepted,
                    session.reflexive.clone(),
                    session.local_addresses.clone(),
                    session.stun_server.clone(),
                    accepted.then_some(hint),
                    (!accepted).then(|| "no-usable-addresses".to_string()),
                    Some(*received_at_ms),
                );
                session.answer = Some(answer.clone());
                let short = short_id(&session.session_id);
                self.log(Log::ResponderStunObserved {
                    peer,
                    session: short,
                    accepted,
                    reflexive,
                    local,
                });
                self.signal_event(receiver, &answer, now)
            }
        };
        let event = match body {
            Ok(event) => event,
            Err(error) => return self.fail(key, error.into()),
        };
        let req = ReqId(self.id());
        let Some(session) = self.sessions.get(key) else {
            return;
        };
        session.stage = Stage::Sending(req);
        let relays = session.relays.clone();
        self.publish_signal(req, relays, event);
    }

    /// A nonce: the step's Unix time and 64 bits from `E`.
    fn draw_nonce(&self, now: Now<I>) -> String {
        let mut bytes = [0u8; 8];
        E::fill(&mut bytes);
        format!("{}-{:016x}", now.unix_ms, u64::from_le_bytes(bytes))
    }

    /// A session's offer or answer publish ended.
    pub(super) fn session_sent(
        &mut self,
        req: ReqId,
        ok: Result<(), String>,
        event: String,
        now: Now<I>,
    ) {
        let Some(key) = self.sessions.by_req(req) else {
            return;
        };
        let Some(session) = self.sessions.get(key) else {
            return;
        };
        if let Err(error) = ok {
            return self.fail(key, Error::Nostr(error).into());
        }
        let peer = short_npub(&session.peer.npub);
        let short = short_id(&session.session_id);
        let relays = session.relays.len();
        match &session.role {
            Role::Initiator { .. } => {
                session.stage = Stage::AwaitingAnswer;
                session.resend = Resend::Available;
                session.answer_deadline = Some(deadline(
                    now.mono,
                    Duration::from_secs(self.params.signal_ttl_secs),
                ));
                let held = session.held_answer.take();
                self.log(Log::OfferSent {
                    peer,
                    session: short,
                    relays,
                    event,
                });
                if let Some((answer, sender_npub)) = held {
                    self.answer_received(key, answer, sender_npub, now);
                }
            }
            Role::Responder { .. } => {
                let accepted = session.answer.as_ref().is_some_and(|a| a.accepted);
                self.log(Log::AnswerSent {
                    peer,
                    session: short,
                    accepted,
                    relays,
                    event,
                });
                if !accepted {
                    self.end(key, true);
                    return;
                }
                self.read_on_link(key);
            }
        }
    }

    /// Read the on-link prefixes, to plan the punch.
    fn read_on_link(&mut self, key: Key) {
        let req = ReqId(self.id());
        if let Some(session) = self.sessions.get(key) {
            session.stage = Stage::OnLink(req);
            self.actions.push_back(Action::ReadInterfaces {
                req,
                read: Read::OnLink,
            });
        }
    }

    /// The initiator's answer arrived: note the skew, check it, and go on
    /// to the punch if it was accepted.
    fn answer_received(&mut self, key: Key, answer: TraversalAnswer, sender: String, now: Now<I>) {
        let ttl_ms = self.params.signal_ttl_secs * 1000;
        let Some(session) = self.sessions.get(key) else {
            return;
        };
        let Some(offer) = session.offer.clone() else {
            return;
        };
        session.answer_deadline = None;
        let peer_npub = session.peer.npub.clone();
        let peer = short_npub(&peer_npub);
        let short = short_id(&offer.session_id);
        let at = now.unix_ms;
        self.log(Log::AnswerReceived {
            peer: peer.clone(),
            session: short.clone(),
            accepted: answer.accepted,
            reflexive: addr_text(answer.reflexive_address.as_ref()),
            local: answer.local_addresses.len(),
        });
        // Noted before the answer is checked, as it always was.
        if let Some(skew_ms) = estimate_clock_skew(&offer, &answer, at) {
            self.failures.note_observed_skew(&peer_npub, skew_ms, at);
            self.status_changed = true;
            if rules::skew_is_significant(skew_ms) {
                self.log(Log::SkewSignificant {
                    peer: peer.clone(),
                    session: short.clone(),
                    skew_ms,
                });
            } else {
                self.log(Log::SkewNominal {
                    peer: peer.clone(),
                    skew_ms,
                });
            }
        }
        let outcome = match validate_traversal_answer_for_offer(
            &offer, &answer, at, ttl_ms, &sender, &self.npub,
        ) {
            Ok(outcome) => outcome,
            Err(error) => return self.fail(key, error.into()),
        };
        if outcome == FreshnessOutcome::FreshWithinSkewTolerance {
            self.log(Log::AnswerWithinTolerance {
                peer,
                session: short,
                answer_issued_at: answer.issued_at,
                answer_expires_at: answer.expires_at,
            });
        }
        if !answer.accepted {
            let reason = answer
                .reason
                .clone()
                .unwrap_or_else(|| "remote rejected traversal".to_string());
            return self.fail(key, Error::Protocol(reason).into());
        }
        if let Some(session) = self.sessions.get(key) {
            session.answer = Some(answer);
        }
        self.read_on_link(key);
    }

    /// Plan the punch from both sides' addresses and start the attempt.
    fn plan(&mut self, key: Key, on_link: &OnLinkPrefixes, now: Now<I>) {
        let own_hint = rules::punch_hint(
            now.unix_ms,
            self.params.punch_start_delay_ms,
            self.params.punch_interval_ms,
            self.params.punch_duration_ms,
        );
        let timeout = Duration::from_secs(self.params.attempt_timeout_secs);
        let Some(session) = self.sessions.get(key) else {
            return;
        };
        let (offer, answer) = match (&session.role, &session.offer, &session.answer) {
            (Role::Initiator { .. }, Some(offer), Some(answer)) => (offer.clone(), answer.clone()),
            (Role::Responder { offer, .. }, _, Some(answer)) => ((**offer).clone(), answer.clone()),
            _ => return,
        };
        let initiator = session.initiator();
        // Ours first, then the peer's.
        let planned = if initiator {
            planned_remote_endpoints(
                &offer.local_addresses,
                offer.reflexive_address.as_ref(),
                &answer.local_addresses,
                answer.reflexive_address.as_ref(),
                on_link,
            )
        } else {
            planned_remote_endpoints(
                &answer.local_addresses,
                answer.reflexive_address.as_ref(),
                &offer.local_addresses,
                offer.reflexive_address.as_ref(),
                on_link,
            )
        };
        let peer = short_npub(&session.peer.npub);
        let short = short_id(&session.session_id);
        let (remotes, tally) = match planned {
            Ok(planned) => planned,
            Err(error) => return self.fail(key, error.into()),
        };
        if tally.has_refusals() {
            // One aggregated line per plan, at warn only for the shapes no
            // honest peer produces, and then at most once a minute.
            let suppressed = self.refusal.decide(&tally, now.mono);
            self.log(Log::PunchCandidatesRefused {
                suppressed,
                peer,
                session: short,
                tally,
            });
        }
        let Some(session) = self.sessions.get(key) else {
            return;
        };
        let hint = if initiator {
            own_hint
        } else {
            match answer.punch.clone() {
                Some(hint) => hint,
                None => return,
            }
        };
        let attempt = Attempt::new(
            &session.session_id,
            remotes,
            &hint,
            timeout,
            now.mono,
            now.unix_ms,
        );
        let mut attempt = match attempt {
            Ok(attempt) => attempt,
            Err(error) => return self.punch_failed(key, error),
        };
        let mut out = attempt.timeout(now.mono);
        for (src, bytes) in core::mem::take(&mut session.early) {
            out.extend(attempt.datagram(src, &bytes, now.mono));
        }
        session.attempt = Some(attempt);
        session.stage = Stage::Punching;
        self.session_punch(key, out, now);
    }

    /// Carry out what a session's punch attempt asked for.
    pub(super) fn session_punch(&mut self, key: Key, out: Vec<PunchOut>, now: Now<I>) {
        for step in out {
            let Some(session) = self.sessions.get(key) else {
                return;
            };
            let Some(socket) = session.socket else {
                return;
            };
            match step {
                PunchOut::Send { dst, bytes } => {
                    self.actions.push_back(Action::Send { socket, dst, bytes });
                }
                PunchOut::Adopt(remote) => return self.punched(key, remote, now),
                PunchOut::TimedOut => {
                    let peer = session.peer.npub.clone();
                    let session_id = session.session_id.clone();
                    self.attempt_tally(key);
                    let error = if self.sessions.get(key).is_some_and(|s| s.initiator()) {
                        Error::PunchTimeout(peer)
                    } else {
                        Error::PunchTimeout(session_id)
                    };
                    return self.punch_failed(key, error);
                }
            }
        }
    }

    /// The lines an attempt logs when it ends: what it refused and the
    /// receives that failed.
    fn attempt_tally(&mut self, key: Key) {
        let Some(session) = self.sessions.get(key) else {
            return;
        };
        let Some(tally) = session.attempt.as_ref().map(|a| a.tally().clone()) else {
            return;
        };
        let short = short_id(&session.session_id);
        if tally.unplanned > 0 || tally.superseded > 0 {
            self.log(Log::PunchSourcesRefused {
                session: short.clone(),
                unplanned: tally.unplanned,
                superseded: tally.superseded,
            });
        }
        if tally.recv_errors > 0 {
            self.log(Log::PunchRecvErrors {
                session: short,
                recv_errors: tally.recv_errors,
                last_error: tally.last_error,
            });
        }
    }

    /// The punch adopted nothing: the initiator's connect fails with a
    /// punch timeout whatever the cause, and the responder logs the cause.
    fn punch_failed(&mut self, key: Key, error: Error) {
        let Some(session) = self.sessions.get(key) else {
            return;
        };
        if session.initiator() {
            let npub = session.peer.npub.clone();
            return self.fail(key, Error::PunchTimeout(npub).into());
        }
        let peer = short_npub(&session.peer.npub);
        let short = short_id(&session.session_id);
        self.end(key, true);
        self.log(Log::ResponderPunchFailed {
            peer,
            session: short,
            error: error.to_string(),
        });
    }

    /// The punch reached the peer at `remote`: hand the socket over.
    fn punched(&mut self, key: Key, remote: SocketAddr, now: Now<I>) {
        self.attempt_tally(key);
        let Some(session) = self.end(key, false) else {
            return;
        };
        let Some(socket) = session.socket else {
            return;
        };
        let peer = short_npub(&session.peer.npub);
        let short = short_id(&session.session_id);
        let connect = match session.role {
            Role::Initiator { connect } => {
                self.log(Log::InitiatorPunchSucceeded {
                    peer,
                    session: short,
                    remote,
                });
                self.failures
                    .record_success(&session.peer.npub, now.unix_ms);
                self.status_changed = true;
                Some(connect)
            }
            Role::Responder { .. } => {
                self.log(Log::ResponderPunchSucceeded {
                    peer,
                    session: short,
                    remote,
                });
                None
            }
        };
        self.actions.push_back(Action::Adopt {
            socket,
            session: session.session_id,
            peer_npub: session.peer.npub,
            remote,
            connect,
        });
    }

    /// A datagram arrived on a session's socket: the STUN client's while it
    /// observes, the attempt's while it punches, and held for the attempt
    /// in between.
    pub(super) fn session_datagram(
        &mut self,
        key: Key,
        src: SocketAddr,
        bytes: Vec<u8>,
        now: Now<I>,
    ) {
        let Some(session) = self.sessions.get(key) else {
            return;
        };
        match session.stage {
            Stage::Observing => {
                if let Some(client) = session.stun.as_mut() {
                    let out = client.datagram(src, &bytes, now.mono);
                    self.session_stun(key, out, now);
                }
            }
            Stage::Punching => {
                if let Some(attempt) = session.attempt.as_mut() {
                    let out = attempt.datagram(src, &bytes, now.mono);
                    self.session_punch(key, out, now);
                }
            }
            Stage::Sending(_) | Stage::AwaitingAnswer | Stage::OnLink(_) => {
                if session.early.len() < EARLY_DATAGRAMS {
                    session.early.push((src, bytes));
                }
            }
            _ => {}
        }
    }

    /// Receiving on a session's socket failed.
    pub(super) fn session_recv_error(&mut self, key: Key, error: String, now: Now<I>) {
        let Some(session) = self.sessions.get(key) else {
            return;
        };
        match session.stage {
            Stage::Observing => {
                if let Some(client) = session.stun.as_mut() {
                    let out = client.recv_error(now.mono);
                    self.session_stun(key, out, now);
                }
            }
            Stage::Punching => {
                if let Some(attempt) = session.attempt.as_mut() {
                    attempt.recv_error(error);
                }
            }
            _ => {}
        }
    }

    /// Run each session's deadline that is due at `now`.
    pub(super) fn session_timeouts(&mut self, now: Now<I>) {
        for key in self.sessions.due(now.mono) {
            let Some(session) = self.sessions.get(key) else {
                continue;
            };
            if session.answer_deadline.is_some_and(|at| at <= now.mono) {
                let npub = session.peer.npub.clone();
                self.fail(key, Error::SignalTimeout(npub).into());
                continue;
            }
            if let Some(client) = session.stun.as_mut()
                && client.deadline().is_some_and(|at| at <= now.mono)
            {
                let out = client.timeout(now.mono);
                self.session_stun(key, out, now);
                continue;
            }
            if let Some(attempt) = session.attempt.as_mut()
                && attempt.deadline().is_some_and(|at| at <= now.mono)
            {
                let out = attempt.timeout(now.mono);
                self.session_punch(key, out, now);
            }
        }
    }

    /// The pool set: the configured advert and DM relays, normalised as
    /// the relay client keys its pool.
    pub(super) fn pool_of(
        advert_relays: &[String],
        dm_relays: &[String],
    ) -> alloc::collections::BTreeSet<RelayUrl> {
        advert_relays
            .iter()
            .chain(dm_relays)
            .filter_map(|url| RelayUrl::parse(url).ok())
            .collect()
    }

    /// Whether `event` is a traversal signal.
    pub(super) fn is_signal(event: &Event) -> bool {
        event.kind == Kind::Custom(SIGNAL_KIND)
    }
}
