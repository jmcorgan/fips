//! The lines the rendezvous machine asks the shell to log. Each variant is
//! one line, carrying that line's fields; the shell's `log.rs` renders it
//! with the level, text, field names and target it has always had, so an
//! operator's filters and the scripts that read the log see no difference.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::SocketAddr;

use nostr::event::EventId;

use super::super::punch::plan::PunchTargetTally;
use super::super::traversal::gate::SignalShed;
use super::super::types::OverlayEndpointAdvert;

/// How a peer's advert reached the cache, for the line that says it could
/// not be cached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestPath {
    /// Delivered on the subscription's stream.
    Stream,
    /// Fetched for a dial, which uses it even though it is not cached.
    Fetch,
    /// Fetched by the stale-advert refetch.
    Refetch,
}

/// Where a resolved advert came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The advert cache.
    Cache,
    /// A fetch from the advert relays.
    RelayFetch,
}

/// One line the machine logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Log {
    /// A peer's advert was cached or replaced (debug).
    PeerCached {
        peer: String,
        endpoints: Vec<OverlayEndpointAdvert>,
        event: EventId,
    },
    /// The cache refused its first advert since it was last below its cap
    /// (warn).
    CacheFull { bound: usize },
    /// A full cache refused an advert (debug).
    NotCached { peer: String, path: IngestPath },
    /// A prune removed unprotected entries to bring the cache to its cap
    /// (debug).
    CacheEvicted {
        evicted: usize,
        retained: usize,
        cap: usize,
    },
    /// The cache has been below its cap for a minute (info).
    CacheBelowCap { refused: u64 },
    /// A peer's advert was resolved (debug).
    Resolved {
        peer: String,
        source: Source,
        endpoints: Vec<OverlayEndpointAdvert>,
    },
    /// The subscribe failed (warn).
    SubscribeFailed { error: String },
    /// The subscribe timed out (warn).
    SubscribeTimedOut { timeout_ms: u64 },
    /// The inbox relay list was not published (warn).
    InboxFailed { error: String },
    /// The inbox relay list publish timed out (warn).
    InboxTimedOut { timeout_ms: u64 },
    /// The advert was not published (warn).
    AdvertFailed { error: String },
    /// The advert publish timed out (warn).
    AdvertTimedOut { timeout_ms: u64 },
    /// The advert was published (debug).
    AdvertPublished {
        event: EventId,
        relays: usize,
        endpoints: Vec<OverlayEndpointAdvert>,
        ttl_secs: u64,
    },
    /// One of our advert's lists was cut to the bound peers accept (warn).
    ListCut {
        list: &'static str,
        configured: usize,
        published: usize,
    },
    /// Our advert's content is over the bound peers parse (warn).
    AdvertTooLarge { bytes: usize, bound: usize },
    /// A wildcard public UDP transport was left out of the advert because
    /// its public address was not learned (warn).
    UdpUnlearned {
        transport_id: u32,
        bind_addr: SocketAddr,
    },
    /// A wildcard TCP transport was left out of the advert (warn).
    TcpWildcard { bind_addr: SocketAddr },
    /// A STUN server answered (debug).
    StunSucceeded { server: String, mapped: SocketAddr },
    /// A STUN server's wait ended with datagrams from other sources
    /// discarded (debug).
    StunDiscarded {
        server: String,
        expected: SocketAddr,
        rejected: u64,
        last_unexpected: Option<SocketAddr>,
    },
    /// Every STUN server failed; `error` is the last one's (debug).
    StunFailed { error: String },
    /// The public-address observation's socket could not be bound (debug).
    PublicAddrBindFailed { error: String },
    /// The public-address observation's socket could not be made
    /// non-blocking (debug).
    PublicAddrNonBlockingFailed { error: String },
    /// The public-address observation ended: the server that answered and
    /// the reflexive address, or neither (debug).
    PublicAddrObserved {
        stun: Option<String>,
        reflexive: Option<SocketAddr>,
    },
    /// The public-address observation could not run (debug).
    PublicAddrFailed { error: String },
    /// A publish of an event of `kind` to `relays` relays was accepted by
    /// the client but reached none of them (debug).
    PublishReachedNone {
        kind: u16,
        event: EventId,
        relays: usize,
    },

    // --- traversal: the `peer` and `session` fields are already short ----
    /// An inbound signal was shed before decryption (debug), and the count
    /// since start.
    SignalShed { reason: SignalShed, total: u64 },
    /// The count of signals shed reached a power of two (warn).
    SignalsShed { shed: u64 },
    /// An inbound signal could not be opened (trace).
    UnwrapFailed { error: String },
    /// An inbound signal's sender key has no npub (debug).
    SenderNpubFailed { error: String },
    /// An offer was dropped at the global offer bound (warn).
    OfferRateLimited { sender_npub: String, limit: usize },
    /// An offer was dropped at its sender's allowance (debug).
    OfferSenderFull { sender_npub: String, limit: usize },
    /// An offer was refused: at warn when relay lag cannot explain it,
    /// else at debug.
    OfferFailed {
        peer: String,
        session: String,
        error: String,
        adversarial: bool,
    },
    /// The node is at capacity, so no initiator starts (debug).
    InitiatorSuppressed { peer: String },
    /// An initiator starts (debug).
    InitiatorStarting { peer: String },
    /// The initiator's addresses are observed (debug).
    InitiatorStunObserved {
        peer: String,
        reflexive: String,
        local: usize,
        stun: String,
    },
    /// The offer was published (debug).
    OfferSent {
        peer: String,
        session: String,
        relays: usize,
        event: String,
    },
    /// The answer arrived (debug).
    AnswerReceived {
        peer: String,
        session: String,
        accepted: bool,
        reflexive: String,
        local: usize,
    },
    /// A clock skew of 30 s or more was observed (debug).
    SkewSignificant {
        peer: String,
        session: String,
        skew_ms: i64,
    },
    /// A smaller clock skew was observed (trace).
    SkewNominal { peer: String, skew_ms: i64 },
    /// The answer was fresh only within the skew tolerance (debug).
    AnswerWithinTolerance {
        peer: String,
        session: String,
        answer_issued_at: u64,
        answer_expires_at: u64,
    },
    /// The initiator's punch reached the peer (debug).
    InitiatorPunchSucceeded {
        peer: String,
        session: String,
        remote: SocketAddr,
    },
    /// Our offer was sent again after the peer's was suppressed (debug).
    OfferResent {
        peer: String,
        session: String,
        event: String,
    },
    /// Sending our offer again failed (debug).
    OfferResendFailed {
        peer: String,
        session: String,
        error: String,
    },
    /// The node is at capacity, so an offer is dropped (debug).
    OfferDroppedAtCapacity { peer: String, session: String },
    /// An offer arrived (debug).
    OfferReceived {
        peer: String,
        session: String,
        reflexive: String,
        local: usize,
    },
    /// The offer was fresh only within the skew tolerance (debug).
    OfferWithinTolerance {
        peer: String,
        session: String,
        offer_issued_at: u64,
        offer_expires_at: u64,
        offer_received_at: u64,
    },
    /// Our own initiator wins the dual initiation, so the peer's offer is
    /// not answered (debug).
    ResponderSuppressed { peer: String, session: String },
    /// A node address could not be derived, so the offer is answered
    /// (trace).
    NoNodeAddr { peer: String },
    /// The responder's addresses are observed (debug).
    ResponderStunObserved {
        peer: String,
        session: String,
        accepted: bool,
        reflexive: String,
        local: usize,
    },
    /// The answer was published (debug).
    AnswerSent {
        peer: String,
        session: String,
        accepted: bool,
        relays: usize,
        event: String,
    },
    /// The responder's punch reached the peer (debug).
    ResponderPunchSucceeded {
        peer: String,
        session: String,
        remote: SocketAddr,
    },
    /// The responder's punch adopted nothing (debug).
    ResponderPunchFailed {
        peer: String,
        session: String,
        error: String,
    },
    /// The relays a signal goes to (debug).
    SignalRelaysResolved {
        peer: String,
        inbox: usize,
        usable: usize,
    },
    /// The peer's inbox relay list could not be fetched (debug).
    InboxFetchFailed { error: String },
    /// Punch candidates the peer named were refused: at warn with the
    /// count of warnings held back when `suppressed` is set, else at debug.
    PunchCandidatesRefused {
        suppressed: Option<u64>,
        peer: String,
        session: String,
        tally: PunchTargetTally,
    },
    /// Punch packets from unplanned sources, and remapped holds a later
    /// one replaced, in one attempt (debug).
    PunchSourcesRefused {
        session: String,
        unplanned: usize,
        superseded: usize,
    },
    /// Receives that failed on the punch socket in one attempt (debug).
    PunchRecvErrors {
        session: String,
        recv_errors: usize,
        last_error: Option<String>,
    },
    /// A datagram from a traversed peer's address carried another FMP
    /// version, so the peer is not traversed again for a while (warn, with
    /// the receive loop's target).
    VersionMismatch {
        npub: String,
        transport_id: String,
        remote_addr: String,
        peer_version: u8,
        our_version: u8,
        cooldown_secs: u64,
    },
}
