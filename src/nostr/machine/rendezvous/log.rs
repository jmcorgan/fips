//! The lines the rendezvous machine asks the shell to log. Each variant is
//! one line, carrying that line's fields; the shell's `log.rs` renders it
//! with the level, text, field names and target it has always had, so an
//! operator's filters and the scripts that read the log see no difference.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::SocketAddr;

use nostr::event::EventId;

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
}
