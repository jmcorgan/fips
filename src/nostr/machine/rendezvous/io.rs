//! What passes between the rendezvous machine and its shell: the inputs it
//! takes, the actions it asks for, the answers to the node's requests, and
//! the ids that tie a result to the action that asked for it.
//!
//! Every id is an opaque counter the machine or the shell assigns and never
//! reuses: a `oneshot` sender, a socket or a relay subscription in the
//! machine's types would break its fence, so the shell keeps the map from
//! each id to the thing it names.

use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::SocketAddr;
use core::time::Duration;

use nostr::event::Event;
use nostr::filter::Filter;
use nostr::key::PublicKey;
use nostr::types::RelayUrl;

use super::super::adverts::assemble::AdvertTransportSnapshot;
use super::super::error::Error;
#[cfg(test)]
use super::super::types::CachedOverlayAdvert;
use super::super::types::{NostrRefetchOutcome, OverlayAdvert, OverlayEndpointAdvert};
use super::log::Log;

/// A relay operation, or a public-address observation, the machine started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReqId(pub u64);

/// A request from the node (or the relay client's authenticator) whose
/// answer someone is awaiting. The shell assigns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReplyId(pub u64);

/// A long-lived relay subscription. A retried subscribe names the same one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubId(pub u64);

/// A UDP socket the machine asked the shell to bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SocketId(pub u64);

/// Which step of making a socket failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindStage {
    /// Binding `0.0.0.0:0`.
    Bind,
    /// Making it non-blocking.
    NonBlocking,
    /// Reading its local address.
    LocalAddr,
}

/// A peer's key and its canonical npub, the text the advert cache and the
/// failure state key it by. The shell derives both from the npub the node
/// gave, refusing a spelling that is not a NIP-19 npub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerKey {
    pub pubkey: PublicKey,
    pub npub: String,
}

/// How a relay operation with a deadline ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The client accepted it; `reached` relays took it, possibly none.
    Ok { reached: usize },
    /// The client refused it as a whole; the text is the client's error.
    Err(String),
    /// The deadline passed first.
    TimedOut,
}

/// What the shell hands the machine.
#[derive(Debug)]
pub enum Input {
    /// Begin: subscribe, publish the inbox relay list, then the advert.
    Start,
    /// Stop. The machine asks for nothing more.
    Shutdown,
    /// An advert a relay delivered on the subscription's stream.
    RelayEvent { relay: RelayUrl, event: Box<Event> },
    /// The subscribe `req` ended.
    SubscribeDone { req: ReqId, outcome: Outcome },
    /// The publish `req` ended.
    PublishDone { req: ReqId, outcome: Outcome },
    /// The fetch `req` ended: the events the relays returned, or the
    /// client's error.
    FetchDone {
        req: ReqId,
        outcome: Result<Vec<Event>, String>,
    },
    /// A relay asked for NIP-42 authentication.
    AuthChallenge {
        relay: RelayUrl,
        challenge: String,
        reply: ReplyId,
    },
    /// `socket` is bound at `local`, and its datagrams are being read.
    SocketBound { socket: SocketId, local: SocketAddr },
    /// Making `socket` failed at `stage`; the text is the I/O error's.
    BindFailed {
        socket: SocketId,
        stage: BindStage,
        error: String,
    },
    /// The lookup `req` gave `addrs`.
    Resolved { req: ReqId, addrs: Vec<SocketAddr> },
    /// The lookup `req` failed; the text is the I/O error's.
    ResolveFailed { req: ReqId, error: String },
    /// A datagram from `src` arrived on `socket`.
    Datagram {
        socket: SocketId,
        src: SocketAddr,
        bytes: Vec<u8>,
    },
    /// Receiving on `socket` failed.
    RecvError { socket: SocketId },
    /// A send on `socket` to `dst` failed; the text is the I/O error's.
    SendFailed {
        socket: SocketId,
        dst: SocketAddr,
        error: String,
    },
    /// The node's advertisable transports. With a reply, the shell is
    /// waiting for the advert to be assembled from them.
    Transports {
        snapshot: Vec<AdvertTransportSnapshot>,
        reply: Option<ReplyId>,
    },
    /// The authors whose cached adverts survive a full cache.
    Protection(BTreeSet<String>),
    /// A peer's advert endpoints, from the cache or else the relays.
    Endpoints { key: PeerKey, reply: ReplyId },
    /// A peer's advert endpoints from the cache alone. `npub` is canonical.
    CachedEndpoints { npub: String, reply: ReplyId },
    /// The cached adverts open discovery should consider.
    OpenDiscovery {
        max: usize,
        skip: BTreeSet<String>,
        reply: ReplyId,
    },
    /// Check a peer's advert on the relays again.
    Refetch { key: PeerKey, reply: ReplyId },
    /// A peer's whole advert, from the cache or else the relays, for the
    /// traversal flows still served outside the machine.
    ResolveAdvert { key: PeerKey, reply: ReplyId },
    /// Answer once every earlier input has been handled.
    #[cfg(test)]
    Settle { reply: ReplyId },
    /// What the cache holds for `npub`, and the protected authors.
    #[cfg(test)]
    Inspect { npub: String, reply: ReplyId },
    /// Cache `advert` under `npub` as a fetched advert.
    #[cfg(test)]
    InsertAdvert {
        npub: String,
        advert: CachedOverlayAdvert,
        reply: ReplyId,
    },
    /// Use `relays` as the advert relays from now on.
    #[cfg(test)]
    SetAdvertRelays(Vec<String>),
}

/// What the machine asks the shell to do.
#[derive(Debug)]
pub enum Action {
    /// Open each subscription in order, under one deadline, and report one
    /// `SubscribeDone`: the first whole-call error, or `Ok`.
    Subscribe {
        req: ReqId,
        subs: Vec<(SubId, Vec<String>, Filter)>,
        timeout: Duration,
    },
    /// Send `event` to `relays` within `timeout`, and report `PublishDone`.
    Publish {
        req: ReqId,
        relays: Vec<String>,
        event: Event,
        timeout: Duration,
    },
    /// Fetch what `relays` hold that matches `filter`, waiting at most
    /// `timeout`, and report `FetchDone`.
    Fetch {
        req: ReqId,
        relays: Vec<String>,
        filter: Filter,
        timeout: Duration,
    },
    /// Bind a UDP socket on `0.0.0.0:0`, non-blocking, read its datagrams,
    /// and report `SocketBound` or `BindFailed`.
    Bind { socket: SocketId },
    /// Look `host` up, and report `Resolved` or `ResolveFailed`.
    Resolve { req: ReqId, host: String, port: u16 },
    /// Send `bytes` to `dst` on `socket`; report a failure as `SendFailed`.
    Send {
        socket: SocketId,
        dst: SocketAddr,
        bytes: Vec<u8>,
    },
    /// Stop reading `socket` and drop it.
    Close { socket: SocketId },
    /// Complete a request.
    Reply { reply: ReplyId, payload: Reply },
    /// Reset `npub`'s failure streak, as a refreshed or evicted advert
    /// warrants. Run before any reply queued after it.
    ResetStreak { npub: String },
    /// Log a line.
    Log(Log),
}

/// What the cache holds for one author, and the protected authors.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(test)]
pub struct Inspection {
    pub created_at: Option<u64>,
    pub protected: BTreeSet<String>,
    /// How many `Transports` inputs the machine has taken.
    pub transports: u64,
}

/// The answer to a request.
#[derive(Debug)]
pub enum Reply {
    /// The NIP-42 authentication event, or why none was made.
    Auth(Result<Event, Error>),
    /// The advert has been assembled from the snapshot that asked.
    Assembled,
    /// A peer's advert endpoints.
    Endpoints(Result<Vec<OverlayEndpointAdvert>, Error>),
    /// A peer's cached advert endpoints, if any.
    CachedEndpoints(Option<Vec<OverlayEndpointAdvert>>),
    /// Open discovery's candidates: author, endpoints, `created_at`.
    OpenDiscovery(Vec<(String, Vec<OverlayEndpointAdvert>, u64)>),
    /// The refetch's outcome.
    Refetch(NostrRefetchOutcome),
    /// A peer's whole advert.
    Advert(Result<OverlayAdvert, Error>),
    /// Every earlier input has been handled.
    #[cfg(test)]
    Settled,
    /// See [`Inspection`].
    #[cfg(test)]
    Inspected(Inspection),
}
