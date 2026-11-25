//! The rendezvous machine: the one owner of FRC-1601's state, stepped by
//! the shell's pump.
//!
//! [`Rendezvous`] holds the peer advert cache, this node's own advert with
//! its publish schedule and the transports it is assembled from, the relay
//! subscriptions and the inbox relay list's schedule, and the traversal
//! half (`traversal.rs`): the sessions in hand, the dual-initiation
//! election and the seen sessions, the signal gate, the offer admission and
//! the per-peer failure state. The shell feeds it [`Input`]s and timeouts,
//! each with the step's two clock readings ([`Now`]), and carries out the
//! [`Action`]s it queues: relay operations, sockets, host reads, replies to
//! the node, hand-offs, and log lines. It holds no lock and does no I/O;
//! every relay call is the shell's, which posts the result back as an
//! input. The only copy of the node key it signs with is its own.

pub mod io;
pub mod log;
pub mod status;
mod traversal;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::time::Duration;

use fips_core::entropy::EntropySource;
use fips_core::time::Instant;
use fips_core::utils::hash::KeyedHasher;
use nostr::event::{Event, Kind};
use nostr::filter::Filter;
use nostr::types::RelayUrl;

use super::NodeSigner;
use super::adverts::cache::{AdvertAdmission, Cache};
use super::adverts::effective_created_at_secs;
use super::adverts::ingest::{self, MAX_ADVERT_CONTENT_BYTES, MAX_ADVERT_LIST_ENTRIES};
use super::adverts::publisher::{LocalTransports, PublishPlan, PublishSchedule, Publisher};
use super::error::Error;
use super::event::advert::advert_event;
use super::event::auth::auth_event;
use super::event::inbox::inbox_list;
use super::inbox::{Lists, Purpose};
use super::params::{ADVERT_FETCH_TIMEOUT, ADVERT_PUBLISH_TIMEOUT, Params, STARTUP_OP_TIMEOUT};
use super::punch::refusal::RefusalWarnGate;
use super::relays::Book;
use super::stun::client::{Observation, Out};
use super::traversal::admission::Admission;
use super::traversal::election::Election;
use super::traversal::failures::FailureState;
use super::traversal::gate::SignalGate;
use super::traversal::rules::short_id;
use super::traversal::sessions::{Key as SessionKey, Sessions};
use super::types::{
    ADVERT_IDENTIFIER, ADVERT_KIND, CachedOverlayAdvert, NostrRefetchOutcome, OverlayAdvert,
    OverlayEndpointAdvert, SIGNAL_KIND,
};
pub use io::{
    Action, BindStage, ConnectId, Input, Interfaces, Outcome, PeerKey, Read, Reply, ReplyId, ReqId,
    SocketId, SubId,
};
use log::{IngestPath, Log, Source};
use status::Status;

/// A step's two clock readings: the monotonic one, for every deadline and
/// schedule, and Unix time in milliseconds, for what FRC-1601 writes in
/// Unix time (an advert's `created_at`, `expiration` and horizon).
#[derive(Debug, Clone, Copy)]
pub struct Now<I> {
    pub mono: I,
    pub unix_ms: u64,
}

/// The advert cache for `params`: the configured cache cap, and one
/// republish interval of lapse grace after an entry's horizon, so an honest
/// author that misses one republish keeps its slot during a flood. Its map
/// is keyed from `E`.
pub fn advert_cache<I: Instant, E: EntropySource>(npub: String, params: &Params) -> Cache<I> {
    Cache::new(
        npub,
        params.advert_cache_max_entries,
        KeyedHasher::new::<E>(),
    )
    .with_lapse_grace(params.advert_refresh_secs.saturating_mul(1000))
}

/// A fetch the machine is waiting on for the node, and what it is for.
/// A traversal's fetches are its session's.
#[derive(Debug)]
enum Fetching {
    /// A peer's advert endpoints for the node.
    Resolve { key: PeerKey, reply: ReplyId },
    /// The stale-advert refetch, with the cached `created_at` when it was
    /// asked for.
    Refetch {
        key: PeerKey,
        reply: ReplyId,
        cached_created_at: Option<u64>,
    },
}

/// How long each STUN server has to answer the public-address observation,
/// from its first send. Longer than a traversal's, because the observation
/// is rare (its result is kept) and the advert would rather wait a few
/// seconds than go out without its UDP endpoint.
const PUBLIC_ADDR_STUN_TIMEOUT: Duration = Duration::from_secs(5);

/// The public-address observation in flight: its socket, the port the
/// advert names, the STUN client once the socket is bound, and the lookup
/// it is waiting on.
struct PublicObservation<I, E> {
    socket: SocketId,
    port: u16,
    client: Option<Observation<I, E>>,
    resolving: Option<ReqId>,
}

/// The advert publish in flight: its event and the endpoints it carries,
/// for the line logged when it ends.
#[derive(Debug)]
struct Publishing {
    req: ReqId,
    event: nostr::event::EventId,
    endpoints: Vec<OverlayEndpointAdvert>,
}

/// The rendezvous machine. Single owner, no lock.
pub struct Rendezvous<I: Instant, E: EntropySource> {
    params: Params,
    signer: NodeSigner,
    npub: String,
    cache: Cache<I>,
    local: Publisher,
    schedule: PublishSchedule<I>,
    transports: LocalTransports<I, ReplyId, SocketId>,
    observation: Option<PublicObservation<I, E>>,
    publishing: Option<Publishing>,
    relays: Option<Book<I>>,
    inbox: Lists<I>,
    fetches: BTreeMap<ReqId, Fetching>,
    /// Each publish in flight: the event's kind, its id, and how many relays
    /// it was sent to, for the line logged if it reaches none.
    sent: BTreeMap<ReqId, (u16, nostr::event::EventId, usize)>,
    actions: VecDeque<Action>,
    next_id: u64,
    stopped: bool,
    /// The last step's clock readings, from which the cache's earliest
    /// expiry, in Unix time, is turned into a monotonic deadline.
    last_step: Option<Now<I>>,
    /// The initiators running, by peer, and the offers seen.
    election: Election,
    /// Each peer's traversal failures and cooldowns.
    failures: FailureState,
    /// Whether `failures` changed since the shell last took the status.
    status_changed: bool,
    /// The allowance for inbound signals ahead of any decryption.
    gate: SignalGate<I>,
    /// Inbound signals shed since start.
    shed: u64,
    /// Inbound offers in hand, per sender and in all.
    admission: Admission,
    /// One suspicious-offer warning a minute.
    refusal: RefusalWarnGate<I>,
    /// Whether the node has room for another peer.
    capacity: bool,
    /// The relays the client holds: the configured advert and DM relays.
    pool: BTreeSet<nostr::types::RelayUrl>,
    sessions: Sessions<I, E>,
    /// The re-sends of initiators' offers in flight.
    resends: BTreeMap<ReqId, traversal::Resending>,
    /// Test requests waiting for an answer to a nonce.
    #[cfg(test)]
    answer_waits: BTreeMap<String, ReplyId>,
    #[cfg(test)]
    transports_taken: u64,
    #[cfg(test)]
    capacity_taken: u64,
    _entropy: PhantomData<fn() -> E>,
}

impl<I: Instant, E: EntropySource> Rendezvous<I, E> {
    /// A machine for the node whose key `signer` holds and whose npub is
    /// `npub`, configured by `params`. Nothing happens until
    /// [`Input::Start`], but the node's requests are answered at once.
    pub fn new(params: Params, signer: NodeSigner, npub: String, now: Now<I>) -> Self {
        let cache = advert_cache::<I, E>(npub.clone(), &params);
        let refresh = Duration::from_secs(params.advert_refresh_secs.max(1));
        let success_ttl = Duration::from_secs(params.advert_refresh_secs.max(60));
        Self {
            election: Election::new(
                params.replay_window_secs * 1000,
                params.seen_sessions_max_entries,
                KeyedHasher::new::<E>(),
            ),
            failures: FailureState::new(
                params.failure_streak_threshold,
                params.extended_cooldown_secs,
                params.warn_log_interval_secs,
                params.failure_state_max_entries,
                KeyedHasher::new::<E>(),
            ),
            status_changed: false,
            gate: SignalGate::new(now.mono),
            shed: 0,
            admission: Admission::new(
                params.max_concurrent_incoming_offers,
                params.max_concurrent_offers_per_npub,
                KeyedHasher::new::<E>(),
            ),
            refusal: RefusalWarnGate::default(),
            capacity: true,
            pool: Self::pool_of(&params.advert_relays, &params.dm_relays),
            sessions: Sessions::new(),
            resends: BTreeMap::new(),
            #[cfg(test)]
            answer_waits: BTreeMap::new(),
            #[cfg(test)]
            capacity_taken: 0,
            local: Publisher::new(params.advertise),
            schedule: PublishSchedule::new(refresh),
            transports: LocalTransports::new(success_ttl),
            observation: None,
            params,
            signer,
            npub,
            cache,
            publishing: None,
            relays: None,
            inbox: Lists::new(),
            fetches: BTreeMap::new(),
            sent: BTreeMap::new(),
            actions: VecDeque::new(),
            next_id: 1,
            stopped: false,
            last_step: None,
            #[cfg(test)]
            transports_taken: 0,
            _entropy: PhantomData,
        }
    }

    /// Take one input at `now`.
    pub fn handle(&mut self, input: Input, now: Now<I>) {
        if self.stopped {
            return;
        }
        match input {
            Input::Start => self.start(now),
            Input::Shutdown => {
                self.stopped = true;
                return;
            }
            Input::RelayEvent { event, .. } if Self::is_signal(&event) => self.signal(event, now),
            Input::RelayEvent { relay, event } => self.relay_event(relay, event, now),
            Input::SubscribeDone { req, outcome } => self.subscribe_done(req, outcome, now),
            Input::PublishDone { req, outcome } => self.publish_done(req, outcome, now),
            Input::FetchDone { req, outcome } => self.fetch_done(req, outcome, now),
            Input::AuthChallenge {
                relay,
                challenge,
                reply,
            } => {
                let event = auth_event(&self.signer, &relay, &challenge, now.unix_ms, aux::<E>());
                self.reply(reply, Reply::Auth(event));
            }
            Input::SocketBound { socket, local } => {
                if let Some(key) = self.sessions.by_socket(socket) {
                    self.session_bound(key, local, now);
                } else {
                    self.socket_bound(socket, local, now);
                }
            }
            Input::BindFailed {
                socket,
                stage,
                error,
            } => {
                if let Some(key) = self.sessions.by_socket(socket) {
                    if let Some(session) = self.sessions.get(key) {
                        session.socket = None;
                    }
                    self.fail(key, Error::Io(error).into());
                } else {
                    self.bind_failed(socket, stage, error, now);
                }
            }
            Input::Resolved { req, addrs } => {
                if let Some(client) = self.resolving(req) {
                    let out = client.resolved(addrs, now.mono);
                    self.stun_out(out, now);
                } else if let Some((key, client)) = self.session_resolving(req) {
                    let out = client.resolved(addrs, now.mono);
                    self.session_stun(key, out, now);
                }
            }
            Input::ResolveFailed { req, error } => {
                if let Some(client) = self.resolving(req) {
                    let out = client.resolve_failed(error, now.mono);
                    self.stun_out(out, now);
                } else if let Some((key, client)) = self.session_resolving(req) {
                    let out = client.resolve_failed(error, now.mono);
                    self.session_stun(key, out, now);
                }
            }
            Input::Datagram { socket, src, bytes } => {
                if let Some(client) = self.observing(socket) {
                    let out = client.datagram(src, &bytes, now.mono);
                    self.stun_out(out, now);
                } else if let Some(key) = self.sessions.by_socket(socket) {
                    self.session_datagram(key, src, bytes, now);
                }
            }
            Input::RecvError { socket, error } => {
                if let Some(client) = self.observing(socket) {
                    let out = client.recv_error(now.mono);
                    self.stun_out(out, now);
                } else if let Some(key) = self.sessions.by_socket(socket) {
                    self.session_recv_error(key, error, now);
                }
            }
            Input::SendFailed { socket, dst, error } => {
                if let Some(client) = self.observing(socket) {
                    let out = client.send_failed(dst, error, now.mono);
                    self.stun_out(out, now);
                } else if let Some(key) = self.sessions.by_socket(socket)
                    && let Some(client) = self.sessions.get(key).and_then(|s| s.stun.as_mut())
                {
                    // A failed probe or ack is ignored, as the next round
                    // sends again; only the STUN client judges a send.
                    let out = client.send_failed(dst, error, now.mono);
                    self.session_stun(key, out, now);
                }
            }
            Input::Transports { snapshot, reply } => {
                #[cfg(test)]
                {
                    self.transports_taken += 1;
                }
                self.transports.set(snapshot, reply);
                self.advance_transports(now);
            }
            Input::Protection(npubs) => {
                self.cache.set_protected(npubs);
                self.prune(now.unix_ms);
            }
            Input::Endpoints { key, reply } => self.resolve(key, reply, now),
            Input::CachedEndpoints { npub, reply } => {
                let endpoints = self
                    .cache
                    .cached_advert(&npub, now.unix_ms)
                    .map(|advert| advert.endpoints);
                self.reply(reply, Reply::CachedEndpoints(endpoints));
            }
            Input::OpenDiscovery { max, skip, reply } => {
                self.prune(now.unix_ms);
                let candidates =
                    self.cache
                        .open_discovery_candidates::<E>(max, now.unix_ms, |npub| {
                            skip.contains(npub)
                        });
                self.reply(reply, Reply::OpenDiscovery(candidates));
            }
            Input::Refetch { key, reply } => self.refetch(key, reply),
            Input::Connect { npub, connect } => self.connect(npub, connect, now),
            Input::Capacity(capacity) => self.set_capacity(capacity),
            Input::RecordFailure { npub, reply } => self.record_failure(&npub, reply, now),
            Input::VersionMismatch {
                npub,
                transport_id,
                remote_addr,
                peer_version,
                our_version,
            } => self.version_mismatch(
                npub,
                transport_id,
                remote_addr,
                peer_version,
                our_version,
                now,
            ),
            Input::Interfaces { req, read } => self.interfaces(req, read, now),
            #[cfg(test)]
            Input::AwaitAnswer { nonce, reply } => {
                self.answer_waits.insert(nonce, reply);
            }
            #[cfg(test)]
            Input::Settle { reply } => self.reply(reply, Reply::Settled),
            #[cfg(test)]
            Input::Inspect { npub, reply } => {
                let inspection = io::Inspection {
                    created_at: self.cache.cached_created_at(&npub),
                    protected: self.cache.protected().clone(),
                    transports: self.transports_taken,
                    capacity: self.capacity_taken,
                };
                self.reply(reply, Reply::Inspected(inspection));
            }
            #[cfg(test)]
            Input::InsertAdvert {
                npub,
                advert,
                reply,
            } => {
                let _ = self.cache.insert_fetched(&npub, advert, now.unix_ms);
                self.reply(reply, Reply::Settled);
            }
            #[cfg(test)]
            Input::SetAdvertRelays(relays) => self.params.advert_relays = relays,
        }
        self.after_step(now);
    }

    /// Run whatever is due at `now`.
    pub fn handle_timeout(&mut self, now: Now<I>) {
        if self.stopped {
            return;
        }
        if self
            .relays
            .as_mut()
            .is_some_and(|relays| relays.retry_due(now.mono))
        {
            self.subscribe();
        }
        if self.inbox.due(now.mono) {
            self.publish_inbox(Purpose::Republish, now);
        }
        if self.schedule.due(now.mono) {
            self.request_publish(now);
        }
        if self.transports.refresh_due(now.mono) {
            self.advance_transports(now);
        }
        let stun_due = self
            .observation
            .as_ref()
            .and_then(|o| o.client.as_ref())
            .and_then(Observation::deadline)
            .is_some_and(|at| at <= now.mono);
        if stun_due && let Some(client) = self.observation.as_mut().and_then(|o| o.client.as_mut())
        {
            let out = client.timeout(now.mono);
            self.stun_out(out, now);
        }
        self.session_timeouts(now);
        self.after_step(now);
    }

    /// The next deadline the machine has, if any.
    pub fn poll_timeout(&self) -> Option<I> {
        [
            self.relays.as_ref().and_then(Book::deadline),
            self.inbox.deadline(),
            self.schedule.deadline(),
            self.cache.bound_release_at(),
            self.expiry_deadline(),
            self.transports.expiry(),
            self.observation
                .as_ref()
                .and_then(|o| o.client.as_ref())
                .and_then(Observation::deadline),
            self.sessions.deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// The status the node reads, when it changed since the last call.
    pub fn take_status(&mut self) -> Option<Status> {
        if !core::mem::take(&mut self.status_changed) {
            return None;
        }
        Some(Status::of(&self.failures))
    }

    /// When the cache's earliest entry is due to go, on the monotonic clock,
    /// measured from the last step. A step at that instant prunes it, so an
    /// idle node drops expired adverts, and starts the cache-full latch's
    /// hold, without waiting for an input.
    fn expiry_deadline(&self) -> Option<I> {
        let last = self.last_step?;
        let at = self.cache.earliest_expiry_ms()?;
        Some(fips_core::time::deadline(
            last.mono,
            Duration::from_millis(at.saturating_sub(last.unix_ms)),
        ))
    }

    /// The next action for the shell, in the order the machine queued them.
    pub fn poll_action(&mut self) -> Option<Action> {
        self.actions.pop_front()
    }

    /// Whether the machine has been shut down.
    pub fn stopped(&self) -> bool {
        self.stopped
    }

    fn id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn log(&mut self, line: Log) {
        self.actions.push_back(Action::Log(line));
    }

    fn reply(&mut self, reply: ReplyId, payload: Reply) {
        self.actions.push_back(Action::Reply { reply, payload });
    }

    /// What every step ends with: a prune once the earliest entry is due to
    /// go, and the release of the cache-full warning's latch.
    fn after_step(&mut self, now: Now<I>) {
        self.last_step = Some(now);
        if self
            .cache
            .earliest_expiry_ms()
            .is_some_and(|at| now.unix_ms >= at)
        {
            self.prune(now.unix_ms);
        }
        if let Some(refused) = self.cache.bound_tick(now.mono) {
            self.log(Log::CacheBelowCap { refused });
        }
    }

    fn prune(&mut self, now_ms: u64) {
        let report = self.cache.prune(now_ms);
        if report.evicted > 0 {
            self.log(Log::CacheEvicted {
                evicted: report.evicted,
                retained: report.retained,
                cap: self.params.advert_cache_max_entries,
            });
        }
    }

    /// The lines for an advert a full cache refused on `path`.
    fn refused(&mut self, peer: &str, first_at_bound: bool, path: IngestPath) {
        if first_at_bound {
            self.log(Log::CacheFull {
                bound: self.params.advert_cache_max_entries,
            });
        }
        self.log(Log::NotCached {
            peer: peer.to_string(),
            path,
        });
    }

    // --- start-up: subscribe, inbox relay list, advert ------------------

    fn start(&mut self, now: Now<I>) {
        if self.relays.is_some() {
            return;
        }
        let signals = SubId(self.id());
        let adverts = SubId(self.id());
        let req = ReqId(self.id());
        self.relays = Some(Book::new(signals, adverts, req));
        self.push_subscribe(req, signals, adverts);
        self.schedule.start(now.mono);
    }

    /// A retry of the subscribe, under the same subscriptions.
    fn subscribe(&mut self) {
        let req = ReqId(self.id());
        let Some(relays) = self.relays.as_mut() else {
            return;
        };
        relays.retrying(req);
        let (signals, adverts) = (relays.signals, relays.adverts);
        self.push_subscribe(req, signals, adverts);
    }

    fn push_subscribe(&mut self, req: ReqId, signals: SubId, adverts: SubId) {
        let subs = alloc::vec![
            (
                signals,
                self.params.dm_relays.clone(),
                Filter::new()
                    .kind(Kind::Custom(SIGNAL_KIND))
                    .pubkey(self.signer.public_key())
                    .limit(0),
            ),
            (
                adverts,
                self.params.advert_relays.clone(),
                Filter::new()
                    .kind(Kind::Custom(ADVERT_KIND))
                    .identifier(ADVERT_IDENTIFIER),
            ),
        ];
        self.actions.push_back(Action::Subscribe {
            req,
            subs,
            timeout: STARTUP_OP_TIMEOUT,
        });
    }

    fn subscribe_done(&mut self, req: ReqId, outcome: Outcome, now: Now<I>) {
        let accepted = matches!(outcome, Outcome::Ok { .. });
        if !self
            .relays
            .as_mut()
            .is_some_and(|relays| relays.subscribed(req, accepted))
        {
            return;
        }
        match outcome {
            Outcome::Ok { .. } => {}
            Outcome::Err(error) => self.log(Log::SubscribeFailed {
                error: Error::Nostr(error).to_string(),
            }),
            Outcome::TimedOut => self.log(Log::SubscribeTimedOut {
                timeout_ms: STARTUP_OP_TIMEOUT.as_millis() as u64,
            }),
        }
        self.publish_inbox(Purpose::Startup, now);
    }

    fn publish_inbox(&mut self, purpose: Purpose, now: Now<I>) {
        match inbox_list(
            &self.signer,
            &self.params.dm_relays,
            now.unix_ms,
            aux::<E>(),
        ) {
            Ok(event) => {
                let req = ReqId(self.id());
                self.inbox.sending(req, purpose);
                self.sent.insert(
                    req,
                    (
                        Kind::InboxRelays.as_u16(),
                        event.id,
                        self.params.dm_relays.len(),
                    ),
                );
                self.actions.push_back(Action::Publish {
                    req,
                    relays: self.params.dm_relays.clone(),
                    event,
                    timeout: Some(STARTUP_OP_TIMEOUT),
                });
            }
            Err(error) => {
                self.log(Log::InboxFailed {
                    error: error.to_string(),
                });
                self.inbox_sent(purpose, now);
            }
        }
    }

    /// The inbox relay list publish for `purpose` ended.
    fn inbox_sent(&mut self, purpose: Purpose, now: Now<I>) {
        if purpose != Purpose::Startup {
            return;
        }
        self.request_publish(now);
        if self
            .relays
            .as_mut()
            .is_some_and(|relays| relays.published(now.mono))
        {
            self.inbox.schedule(now.mono);
        }
    }

    fn publish_done(&mut self, req: ReqId, outcome: Outcome, now: Now<I>) {
        if let (Outcome::Ok { reached: 0 }, Some((kind, event, relays))) =
            (&outcome, self.sent.get(&req))
        {
            self.log(Log::PublishReachedNone {
                kind: *kind,
                event: *event,
                relays: *relays,
            });
        }
        let sent = self.sent.remove(&req);
        // A signal publish fails only on the client's error, as the send
        // it replaces did; reaching no relay is treated as sent.
        let signal_outcome = || match &outcome {
            Outcome::Ok { .. } => Ok(()),
            Outcome::Err(error) => Err(error.clone()),
            Outcome::TimedOut => Err("timed out".to_string()),
        };
        if self.resent(req, signal_outcome()) {
            return;
        }
        if let Some(key) = self.sessions.by_req(req)
            && self
                .sessions
                .get(key)
                .is_some_and(|s| s.waits_on() == Some(req))
        {
            let event = sent
                .map(|(_, id, _)| short_id(&id.to_string()))
                .unwrap_or_default();
            return self.session_sent(req, signal_outcome(), event, now);
        }
        if let Some(purpose) = self.inbox.sent(req) {
            match outcome {
                Outcome::Ok { .. } => {}
                Outcome::Err(error) => self.log(Log::InboxFailed {
                    error: Error::Nostr(error).to_string(),
                }),
                Outcome::TimedOut => self.log(Log::InboxTimedOut {
                    timeout_ms: STARTUP_OP_TIMEOUT.as_millis() as u64,
                }),
            }
            self.inbox_sent(purpose, now);
            return;
        }
        let Some(publishing) = self.publishing.take_if(|p| p.req == req) else {
            return;
        };
        match outcome {
            Outcome::Ok { .. } => self.log(Log::AdvertPublished {
                event: publishing.event,
                relays: self.params.advert_relays.len(),
                endpoints: publishing.endpoints,
                ttl_secs: self.params.advert_ttl_secs,
            }),
            Outcome::Err(error) => self.log(Log::AdvertFailed {
                error: Error::Nostr(error).to_string(),
            }),
            Outcome::TimedOut => self.log(Log::AdvertTimedOut {
                timeout_ms: ADVERT_PUBLISH_TIMEOUT.as_millis() as u64,
            }),
        }
        self.publish_finished(now);
    }

    // --- the advert publish ----------------------------------------------

    fn request_publish(&mut self, now: Now<I>) {
        if self.schedule.request() {
            self.start_publish(now);
        }
    }

    fn publish_finished(&mut self, now: Now<I>) {
        if self.schedule.finished() {
            self.start_publish(now);
        }
    }

    /// Plan, clamp, sign and send our advert, or log why not.
    fn start_publish(&mut self, now: Now<I>) {
        let mut advert = match self.local.plan_publish() {
            Ok(PublishPlan::Publish(advert)) => advert,
            Ok(PublishPlan::Nothing) => return self.publish_finished(now),
            Err(error) => {
                self.log(Log::AdvertFailed {
                    error: error.to_string(),
                });
                return self.publish_finished(now);
            }
        };
        for cut in ingest::clamp_own(&mut advert) {
            self.log(Log::ListCut {
                list: cut.list,
                configured: cut.configured,
                published: MAX_ADVERT_LIST_ENTRIES,
            });
        }
        let signed = serde_json::to_string(&advert)
            .map_err(|e| format!("serde error: {e}"))
            .and_then(|content| {
                advert_event(
                    &self.signer,
                    content,
                    ADVERT_IDENTIFIER,
                    &self.params.app,
                    self.params.advert_ttl_secs,
                    now.unix_ms,
                    aux::<E>(),
                )
                .map_err(|e| e.to_string())
            });
        let event = match signed {
            Ok(event) => event,
            Err(error) => {
                self.log(Log::AdvertFailed { error });
                return self.publish_finished(now);
            }
        };
        if event.content.len() > MAX_ADVERT_CONTENT_BYTES {
            self.log(Log::AdvertTooLarge {
                bytes: event.content.len(),
                bound: MAX_ADVERT_CONTENT_BYTES,
            });
        }
        let req = ReqId(self.id());
        self.sent.insert(
            req,
            (ADVERT_KIND, event.id, self.params.advert_relays.len()),
        );
        self.publishing = Some(Publishing {
            req,
            event: event.id,
            endpoints: advert.endpoints,
        });
        self.actions.push_back(Action::Publish {
            req,
            relays: self.params.advert_relays.clone(),
            event,
            timeout: Some(ADVERT_PUBLISH_TIMEOUT),
        });
    }

    /// Observe the next wanted public address, or assemble the advert once
    /// none is missing. With no STUN servers an address is unknown at once:
    /// no socket is bound, and the failure is kept for its time to live.
    fn advance_transports(&mut self, now: Now<I>) {
        while let Some((key, port)) = self.transports.next_observation(now.mono) {
            if self.params.stun_servers.is_empty() {
                self.transports.unlearned(key, now.mono);
                continue;
            }
            let socket = SocketId(self.id());
            self.transports.observe(socket, key);
            self.observation = Some(PublicObservation {
                socket,
                port,
                client: None,
                resolving: None,
            });
            self.actions.push_back(Action::Bind { socket });
            return;
        }
        if !self.transports.ready(now.mono) {
            return;
        }
        let (assembly, waiting) = self
            .transports
            .assemble(&self.params.dm_relays, &self.params.stun_servers);
        for note in assembly.notes {
            self.log(match note {
                super::adverts::assemble::AssemblyNote::UdpUnlearned {
                    transport_id,
                    bind_addr,
                } => Log::UdpUnlearned {
                    transport_id,
                    bind_addr,
                },
                super::adverts::assemble::AssemblyNote::TcpWildcard { bind_addr } => {
                    Log::TcpWildcard { bind_addr }
                }
            });
        }
        if self.local.set_local_advert(assembly.advert) {
            self.request_publish(now);
        }
        for reply in waiting {
            self.reply(reply, Reply::Assembled);
        }
    }

    // --- the public-address observation ----------------------------------

    /// The STUN client observing on `socket`, if that is the observation in
    /// flight.
    fn observing(&mut self, socket: SocketId) -> Option<&mut Observation<I, E>> {
        self.observation
            .as_mut()
            .filter(|o| o.socket == socket)
            .and_then(|o| o.client.as_mut())
    }

    /// The STUN client waiting on the lookup `req`, if any; the lookup is
    /// then no longer awaited.
    fn resolving(&mut self, req: ReqId) -> Option<&mut Observation<I, E>> {
        let observation = self
            .observation
            .as_mut()
            .filter(|o| o.resolving == Some(req))?;
        observation.resolving = None;
        observation.client.as_mut()
    }

    fn socket_bound(&mut self, socket: SocketId, local: core::net::SocketAddr, now: Now<I>) {
        let Some(observation) = self
            .observation
            .as_mut()
            .filter(|o| o.socket == socket && o.client.is_none())
        else {
            return;
        };
        let mut client = Observation::new(
            self.params.stun_servers.clone(),
            PUBLIC_ADDR_STUN_TIMEOUT,
            local.is_ipv4(),
        );
        let out = client.begin(now.mono);
        observation.client = Some(client);
        self.stun_out(out, now);
    }

    fn bind_failed(&mut self, socket: SocketId, stage: BindStage, error: String, now: Now<I>) {
        if self.observation.as_ref().is_none_or(|o| o.socket != socket) {
            return;
        }
        self.log(match stage {
            BindStage::Bind => Log::PublicAddrBindFailed { error },
            BindStage::NonBlocking => Log::PublicAddrNonBlockingFailed { error },
            BindStage::LocalAddr => Log::PublicAddrFailed {
                error: format!("io error: {error}"),
            },
        });
        self.finish_observation(None, false, now);
    }

    /// Carry out what the STUN client asked for.
    fn stun_out(&mut self, out: Vec<Out>, now: Now<I>) {
        for step in out {
            let Some(observation) = self.observation.as_mut() else {
                return;
            };
            let (socket, port) = (observation.socket, observation.port);
            match step {
                Out::Resolve { host, port } => {
                    let req = ReqId(self.next_id);
                    self.next_id += 1;
                    if let Some(observation) = self.observation.as_mut() {
                        observation.resolving = Some(req);
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
                    self.log(Log::PublicAddrObserved {
                        stun: Some(server),
                        reflexive: Some(mapped),
                    });
                    let public = core::net::SocketAddr::new(mapped.ip(), port);
                    return self.finish_observation(Some(public), true, now);
                }
                Out::Failed { error } => {
                    if let Some(error) = error {
                        self.log(Log::StunFailed { error });
                    }
                    self.log(Log::PublicAddrObserved {
                        stun: None,
                        reflexive: None,
                    });
                    return self.finish_observation(None, true, now);
                }
            }
        }
    }

    /// The observation in flight ended with `addr`: close its socket if it
    /// was bound, keep the result, and go on with the transports.
    fn finish_observation(
        &mut self,
        addr: Option<core::net::SocketAddr>,
        bound: bool,
        now: Now<I>,
    ) {
        let Some(observation) = self.observation.take() else {
            return;
        };
        if bound {
            self.actions.push_back(Action::Close {
                socket: observation.socket,
            });
        }
        if self
            .transports
            .observed(&observation.socket, addr, now.mono)
        {
            self.advance_transports(now);
        }
    }

    // --- peers' adverts --------------------------------------------------

    fn max_age_ms(&self) -> u64 {
        ingest::max_age_ms(self.params.advert_ttl_secs)
    }

    /// Cache an advert a relay delivered, if it passes the ingest checks,
    /// then prune.
    fn relay_event(&mut self, _relay: RelayUrl, event: Box<Event>, now: Now<I>) {
        if event.kind != Kind::Custom(ADVERT_KIND) {
            return;
        }
        if let Some(checked) =
            ingest::check(&event, &self.params.app, self.max_age_ms(), now.unix_ms)
        {
            let endpoints = checked.advert.endpoints.clone();
            let admission = self.cache.observe_advert(
                &checked.author_npub,
                checked.advert,
                checked.created_at,
                checked.valid_until_ms,
                now.unix_ms,
            );
            match admission {
                AdvertAdmission::Admitted | AdvertAdmission::Updated
                    if checked.author_npub != self.npub =>
                {
                    self.log(Log::PeerCached {
                        peer: checked.author_npub,
                        endpoints,
                        event: event.id,
                    });
                }
                AdvertAdmission::Refused { first_at_bound } => {
                    self.refused(&checked.author_npub, first_at_bound, IngestPath::Stream);
                }
                _ => {}
            }
        }
        self.prune(now.unix_ms);
    }

    fn advert_filter(key: &PeerKey) -> Filter {
        Filter::new()
            .author(key.pubkey)
            .kind(Kind::Custom(ADVERT_KIND))
            .identifier(ADVERT_IDENTIFIER)
    }

    /// Answer with `key`'s advert endpoints from the cache, or fetch them.
    fn resolve(&mut self, key: PeerKey, reply: ReplyId, now: Now<I>) {
        self.prune(now.unix_ms);
        if let Some(advert) = self.cache.cached_advert(&key.npub, now.unix_ms) {
            self.log(Log::Resolved {
                peer: key.npub.clone(),
                source: Source::Cache,
                endpoints: advert.endpoints.clone(),
            });
            return self.reply(reply, Reply::Endpoints(Ok(advert.endpoints)));
        }
        let req = ReqId(self.id());
        let filter = Self::advert_filter(&key);
        self.fetches.insert(req, Fetching::Resolve { key, reply });
        self.actions.push_back(Action::Fetch {
            req,
            relays: self.params.advert_relays.clone(),
            filter,
            timeout: ADVERT_FETCH_TIMEOUT,
        });
    }

    fn refetch(&mut self, key: PeerKey, reply: ReplyId) {
        if self.params.advert_relays.is_empty() {
            return self.reply(reply, Reply::Refetch(NostrRefetchOutcome::Skipped));
        }
        let cached_created_at = self.cache.cached_created_at(&key.npub);
        let req = ReqId(self.id());
        let filter = Self::advert_filter(&key);
        self.fetches.insert(
            req,
            Fetching::Refetch {
                key,
                reply,
                cached_created_at,
            },
        );
        self.actions.push_back(Action::Fetch {
            req,
            relays: self.params.advert_relays.clone(),
            filter,
            timeout: ADVERT_FETCH_TIMEOUT,
        });
    }

    fn fetch_done(&mut self, req: ReqId, outcome: Result<Vec<Event>, String>, now: Now<I>) {
        match self.fetches.remove(&req) {
            Some(Fetching::Resolve { key, reply }) => {
                let advert = self.fetched_advert(&key, outcome, now);
                self.reply(reply, Reply::Endpoints(advert.map(|a| a.endpoints)));
            }
            Some(Fetching::Refetch {
                key,
                reply,
                cached_created_at,
            }) => {
                let result = self.refetched(&key, cached_created_at, outcome, now);
                self.reply(reply, Reply::Refetch(result));
            }
            None => self.session_fetched(req, outcome, now),
        }
    }

    /// The fetched advert for a dial or a traversal: the newest valid one
    /// by the peer, cached if there is room, and used either way.
    fn fetched_advert(
        &mut self,
        key: &PeerKey,
        outcome: Result<Vec<Event>, String>,
        now: Now<I>,
    ) -> Result<OverlayAdvert, Error> {
        let events = outcome.map_err(Error::Nostr)?;
        let max_age_ms = self.max_age_ms();
        let mut best: Option<ingest::Checked> = None;
        for event in &events {
            let Some(checked) = ingest::check(event, &self.params.app, max_age_ms, now.unix_ms)
            else {
                continue;
            };
            if checked.author_npub != key.npub {
                continue;
            }
            if best
                .as_ref()
                .is_none_or(|current| checked.created_at >= current.created_at)
            {
                best = Some(checked);
            }
        }
        let Some(best) = best else {
            return Err(Error::MissingAdvert(key.npub.clone()));
        };
        self.log(Log::Resolved {
            peer: key.npub.clone(),
            source: Source::RelayFetch,
            endpoints: best.advert.endpoints.clone(),
        });
        let admission = self.cache.insert_fetched(
            &key.npub,
            CachedOverlayAdvert {
                author_npub: best.author_npub,
                advert: best.advert.clone(),
                created_at: best.created_at,
                valid_until_ms: best.valid_until_ms,
            },
            now.unix_ms,
        );
        if let AdvertAdmission::Refused { first_at_bound } = admission {
            self.refused(&key.npub, first_at_bound, IngestPath::Fetch);
        }
        self.prune(now.unix_ms);
        Ok(best.advert)
    }

    /// The stale-advert refetch's outcome: absent on the relays evicts,
    /// older or equal is the same advert, newer and valid refreshes when
    /// the cache keeps it. Foreign-only answers and errors change nothing.
    fn refetched(
        &mut self,
        key: &PeerKey,
        cached_created_at: Option<u64>,
        outcome: Result<Vec<Event>, String>,
        now: Now<I>,
    ) -> NostrRefetchOutcome {
        let Ok(events) = outcome else {
            return NostrRefetchOutcome::Skipped;
        };
        let Some(newest) = ingest::newest_by_author(events.iter(), key.pubkey) else {
            if !events.is_empty() {
                // The relays answered, but nothing they returned was signed
                // by this peer. That is no evidence of absence.
                return NostrRefetchOutcome::Skipped;
            }
            self.cache.remove(&key.npub);
            self.reset_streak(&key.npub);
            return NostrRefetchOutcome::Evicted;
        };
        let relay_created_at = effective_created_at_secs(newest.created_at.as_secs(), now.unix_ms);
        if cached_created_at.is_some_and(|cached| relay_created_at <= cached) {
            return NostrRefetchOutcome::SameAdvert;
        }
        let Some(checked) = ingest::check(newest, &self.params.app, self.max_age_ms(), now.unix_ms)
        else {
            return NostrRefetchOutcome::Skipped;
        };
        let admission = self.cache.insert_fetched(
            &key.npub,
            CachedOverlayAdvert {
                author_npub: key.npub.clone(),
                advert: checked.advert,
                created_at: checked.created_at,
                valid_until_ms: checked.valid_until_ms,
            },
            now.unix_ms,
        );
        if let AdvertAdmission::Refused { first_at_bound } = admission {
            // The cache does not hold this advert, so the streak is not
            // reset on the strength of it.
            self.refused(&key.npub, first_at_bound, IngestPath::Refetch);
            return NostrRefetchOutcome::Skipped;
        }
        self.reset_streak(&key.npub);
        NostrRefetchOutcome::Refreshed
    }

    /// Reset `npub`'s failure streak, as a refreshed or evicted advert
    /// warrants.
    fn reset_streak(&mut self, npub: &str) {
        self.failures.reset_streak_after_refresh(npub);
        self.status_changed = true;
    }

    /// The session whose STUN client waits on the lookup `req`, which is
    /// then no longer awaited.
    fn session_resolving(&mut self, req: ReqId) -> Option<(SessionKey, &mut Observation<I, E>)> {
        let key = self.sessions.by_req(req)?;
        let session = self.sessions.get(key)?;
        if session.resolving != Some(req) {
            return None;
        }
        session.resolving = None;
        session.stun.as_mut().map(|client| (key, client))
    }
}

/// Fresh auxiliary randomness for a signature, from `E`.
fn aux<E: EntropySource>() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    E::fill(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests;
