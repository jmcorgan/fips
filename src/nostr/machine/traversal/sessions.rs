//! The traversal sessions in hand: one table for the initiator's and the
//! responder's, each session a state, found by the nonce an answer names,
//! by its peer, by its socket or by the operation it waits on.
//!
//! A session never outlives what it holds: ending one is what closes its
//! socket, gives its admission slot back and ends the peer's initiator, so
//! there is one place each of those happens.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::SocketAddr;

use fips_core::time::Instant;

use super::super::punch::attempt::Attempt;
use super::super::rendezvous::io::{ConnectId, PeerKey, ReqId, SocketId};
use super::super::stun::client::Observation;
use super::super::types::{TraversalAddress, TraversalAnswer, TraversalOffer};
use super::admission::SlotId;

/// The most datagrams a session keeps that arrive on its socket after its
/// observation and before its punch attempt starts, to hand the attempt as
/// a kernel buffer would have held them.
pub const EARLY_DATAGRAMS: usize = 64;

/// A session's key in the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key(u64);

/// Which side of the traversal a session is.
#[derive(Debug)]
pub enum Role {
    /// We started it, for the node's connect `connect`.
    Initiator { connect: ConnectId },
    /// We answer the peer's offer, received at `received_at_ms`, holding
    /// `slot` of the offer admission until the session ends.
    Responder {
        slot: SlotId,
        offer: Box<TraversalOffer>,
        received_at_ms: u64,
    },
}

/// Where a session stands, and the operation it waits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// The initiator fetches the peer's advert.
    ResolvingAdvert(ReqId),
    /// The peer's inbox relay list is looked up.
    InboxLookup(ReqId),
    /// The traversal socket is being bound.
    Binding,
    /// This host's own addresses are read, for local candidates.
    Candidates(ReqId),
    /// The STUN client observes the socket's reflexive address.
    Observing,
    /// The offer or the answer is being published.
    Sending(ReqId),
    /// The initiator waits for the answer.
    AwaitingAnswer,
    /// The on-link prefixes are read, to plan the punch.
    OnLink(ReqId),
    /// The punch attempt runs.
    Punching,
}

/// Where the one re-send an initiator's offer is allowed stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resend {
    /// Not published yet; the next suppression may try.
    Available,
    /// A suppression is publishing it now, so a concurrent one must not.
    Sending,
    /// Published; the offer gets no further re-send.
    Done,
}

/// One traversal.
#[derive(Debug)]
pub struct Session<I, E> {
    pub role: Role,
    /// The peer, by its canonical npub.
    pub peer: PeerKey,
    /// The session id: the initiator's own nonce, or the offer's.
    pub session_id: String,
    pub stage: Stage,
    pub socket: Option<SocketId>,
    /// The socket's local address, once bound.
    pub local: Option<SocketAddr>,
    /// The relays the initiator's advert names for signals.
    pub advert_signal: Option<Vec<String>>,
    /// The relays this session's signals go to.
    pub relays: Vec<String>,
    pub stun: Option<Observation<I, E>>,
    /// The STUN client's lookup in flight.
    pub resolving: Option<ReqId>,
    pub local_addresses: Vec<TraversalAddress>,
    pub reflexive: Option<TraversalAddress>,
    pub stun_server: Option<String>,
    /// The initiator's own offer.
    pub offer: Option<TraversalOffer>,
    /// The answer: the responder's own, or the one the initiator received.
    pub answer: Option<TraversalAnswer>,
    /// An answer that arrived while the offer was still being published,
    /// with its sender's npub.
    pub held_answer: Option<(TraversalAnswer, String)>,
    /// When the initiator stops waiting for the answer.
    pub answer_deadline: Option<I>,
    pub resend: Resend,
    pub attempt: Option<Attempt<I>>,
    /// Datagrams that arrived after the observation, before the attempt.
    pub early: Vec<(SocketAddr, Vec<u8>)>,
}

impl<I: Instant, E> Session<I, E> {
    /// A session for `role` with `peer`, under `session_id`, at `stage`.
    pub fn new(role: Role, peer: PeerKey, session_id: String, stage: Stage) -> Self {
        Self {
            role,
            peer,
            session_id,
            stage,
            socket: None,
            local: None,
            advert_signal: None,
            relays: Vec::new(),
            stun: None,
            resolving: None,
            local_addresses: Vec::new(),
            reflexive: None,
            stun_server: None,
            offer: None,
            answer: None,
            held_answer: None,
            answer_deadline: None,
            resend: Resend::Available,
            attempt: None,
            early: Vec::new(),
        }
    }

    /// Whether this is the initiator's session.
    pub fn initiator(&self) -> bool {
        matches!(self.role, Role::Initiator { .. })
    }

    /// The operation this session waits on, if any.
    pub fn waits_on(&self) -> Option<ReqId> {
        match self.stage {
            Stage::ResolvingAdvert(req)
            | Stage::InboxLookup(req)
            | Stage::Candidates(req)
            | Stage::Sending(req)
            | Stage::OnLink(req) => Some(req),
            _ => None,
        }
    }

    /// Whether this initiator is waiting on an answer: its offer is being
    /// published or is out.
    pub fn awaits_answer(&self) -> bool {
        self.initiator() && matches!(self.stage, Stage::Sending(_) | Stage::AwaitingAnswer)
    }
}

impl<I: Instant, E: fips_core::entropy::EntropySource> Session<I, E> {
    /// The session's next deadline: its STUN client's, its attempt's, or
    /// the end of its wait for the answer.
    pub fn deadline(&self) -> Option<I> {
        [
            self.stun.as_ref().and_then(Observation::deadline),
            self.attempt.as_ref().and_then(Attempt::deadline),
            self.answer_deadline,
        ]
        .into_iter()
        .flatten()
        .min()
    }
}

/// Every session in hand.
#[derive(Debug)]
pub struct Sessions<I, E> {
    table: BTreeMap<Key, Session<I, E>>,
    next: u64,
}

impl<I: Instant, E: fips_core::entropy::EntropySource> Sessions<I, E> {
    /// No sessions.
    pub fn new() -> Self {
        Self {
            table: BTreeMap::new(),
            next: 0,
        }
    }

    /// Hold `session`, and return its key.
    pub fn insert(&mut self, session: Session<I, E>) -> Key {
        let key = Key(self.next);
        self.next += 1;
        self.table.insert(key, session);
        key
    }

    /// The session under `key`.
    pub fn get(&mut self, key: Key) -> Option<&mut Session<I, E>> {
        self.table.get_mut(&key)
    }

    /// Take the session under `key` out of the table.
    pub fn remove(&mut self, key: Key) -> Option<Session<I, E>> {
        self.table.remove(&key)
    }

    /// The first session `pick` accepts.
    fn find(&self, pick: impl Fn(&Session<I, E>) -> bool) -> Option<Key> {
        self.table
            .iter()
            .find(|(_, session)| pick(session))
            .map(|(key, _)| *key)
    }

    /// The session waiting on the operation `req`, or whose STUN client
    /// waits on the lookup `req`.
    pub fn by_req(&self, req: ReqId) -> Option<Key> {
        self.find(|s| s.waits_on() == Some(req) || s.resolving == Some(req))
    }

    /// The session on `socket`.
    pub fn by_socket(&self, socket: SocketId) -> Option<Key> {
        self.find(|s| s.socket == Some(socket))
    }

    /// The initiator waiting on the answer whose `inReplyTo` is `nonce`.
    pub fn by_nonce(&self, nonce: &str) -> Option<Key> {
        self.find(|s| s.awaits_answer() && s.offer.as_ref().is_some_and(|o| o.nonce == nonce))
    }

    /// The initiator to `npub` whose offer is out, waiting on the answer.
    pub fn awaiting_from(&self, npub: &str) -> Option<Key> {
        self.find(|s| s.initiator() && s.stage == Stage::AwaitingAnswer && s.peer.npub == npub)
    }

    /// Whether any initiator is waiting on an answer.
    pub fn awaiting_answers(&self) -> bool {
        self.table.values().any(Session::awaits_answer)
    }

    /// The keys of the sessions with a deadline at or before `now`.
    pub fn due(&self, now: I) -> Vec<Key> {
        self.table
            .iter()
            .filter(|(_, s)| s.deadline().is_some_and(|at| at <= now))
            .map(|(key, _)| *key)
            .collect()
    }

    /// The earliest deadline of any session.
    pub fn deadline(&self) -> Option<I> {
        self.table.values().filter_map(Session::deadline).min()
    }
}
