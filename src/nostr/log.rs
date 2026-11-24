//! The shell's rendering of the rendezvous machine's log lines, and of the
//! lines the pump and the signal task log themselves.
//!
//! Each line keeps the level, text, field names and target it had before
//! the code that logs it moved: every line that `runtime.rs` used to log
//! keeps `fips::nostr::runtime`, and the two advert assembly warnings keep
//! `fips::nostr::driver`. Operators filter on the target and scripts match
//! the text, so both are set explicitly here rather than taken from this
//! file's path.

use std::time::Instant;

use tracing::{debug, info, warn};

use super::machine::rendezvous::log::{IngestPath, Log, Source};
use super::runtime::{Feed, endpoint_summary, short_id, short_npub};

/// Log `line` as the shell always has.
pub(super) fn render(line: &Log) {
    match line {
        Log::PeerCached {
            peer,
            endpoints,
            event,
        } => debug!(
            target: "fips::nostr::runtime",
            peer = %short_npub(peer),
            endpoints = %endpoint_summary(endpoints),
            event = %short_id(&event.to_string()),
            "advert: peer cached"
        ),
        Log::CacheFull { bound } => warn!(
            target: "fips::nostr::runtime",
            bound = *bound,
            "advert cache full; refusing adverts from new unconfigured authors"
        ),
        Log::NotCached { peer, path } => match path {
            IngestPath::Stream => debug!(
                target: "fips::nostr::runtime",
                peer = %short_npub(peer),
                reason = "cache-full",
                "advert cache full; advert not cached"
            ),
            IngestPath::Fetch => debug!(
                target: "fips::nostr::runtime",
                peer = %short_npub(peer),
                reason = "cache-full",
                "advert cache full; fetched advert used for this dial only"
            ),
            IngestPath::Refetch => debug!(
                target: "fips::nostr::runtime",
                peer = %short_npub(peer),
                reason = "cache-full",
                "advert cache full; refetched advert not cached"
            ),
        },
        Log::CacheEvicted {
            evicted,
            retained,
            cap,
        } => debug!(
            target: "fips::nostr::runtime",
            evicted = *evicted,
            retained = *retained,
            cap = *cap,
            "advert cache over cap; evicted unprotected entries"
        ),
        Log::CacheBelowCap { refused } => info!(
            target: "fips::nostr::runtime",
            refused = *refused,
            "advert cache below cap again"
        ),
        Log::Resolved {
            peer,
            source,
            endpoints,
        } => debug!(
            target: "fips::nostr::runtime",
            peer = %short_npub(peer),
            source = match source {
                Source::Cache => "cache",
                Source::RelayFetch => "relay-fetch",
            },
            endpoints = %endpoint_summary(endpoints),
            "advert: resolved"
        ),
        Log::SubscribeFailed { error } => warn!(
            target: "fips::nostr::runtime",
            error = %error,
            "failed to subscribe to Nostr discovery relays"
        ),
        Log::SubscribeTimedOut { timeout_ms } => warn!(
            target: "fips::nostr::runtime",
            timeout_ms = *timeout_ms,
            "Nostr discovery relay subscribe timed out"
        ),
        Log::InboxFailed { error } => warn!(
            target: "fips::nostr::runtime",
            error = %error,
            "failed to publish Nostr inbox relay list"
        ),
        Log::InboxTimedOut { timeout_ms } => warn!(
            target: "fips::nostr::runtime",
            timeout_ms = *timeout_ms,
            "Nostr inbox relay publish timed out"
        ),
        Log::AdvertFailed { error } => warn!(
            target: "fips::nostr::runtime",
            error = %error,
            "failed to publish traversal advert"
        ),
        Log::AdvertTimedOut { timeout_ms } => warn!(
            target: "fips::nostr::runtime",
            timeout_ms = *timeout_ms,
            "Nostr traversal advert publish timed out"
        ),
        Log::AdvertPublished {
            event,
            relays,
            endpoints,
            ttl_secs,
        } => debug!(
            target: "fips::nostr::runtime",
            event = %short_id(&event.to_string()),
            relays = *relays,
            endpoints = %endpoint_summary(endpoints),
            ttl_secs = *ttl_secs,
            "advert: published"
        ),
        Log::ListCut {
            list,
            configured,
            published,
        } => warn!(
            target: "fips::nostr::runtime",
            list = *list,
            configured = *configured,
            published = *published,
            "advert: list longer than peers accept; publishing only its first entries"
        ),
        Log::AdvertTooLarge { bytes, bound } => warn!(
            target: "fips::nostr::runtime",
            bytes = *bytes,
            bound = *bound,
            "advert: larger than peers accept; peers will refuse it"
        ),
        Log::UdpUnlearned {
            transport_id,
            bind_addr,
        } => warn!(
            target: "fips::nostr::driver",
            transport_id = *transport_id,
            bind_addr = %bind_addr,
            "advert: udp public=true bound to wildcard but \
            STUN observation failed; advertising no UDP \
            endpoint. Either set transports.udp.external_addr, \
            bind to a specific public IP, or ensure \
            node.rendezvous.nostr.stun_servers is reachable"
        ),
        Log::TcpWildcard { bind_addr } => warn!(
            target: "fips::nostr::driver",
            bind_addr = %bind_addr,
            "advert: tcp advertise_on_nostr=true bound to wildcard \
            and no transports.tcp.external_addr set; advertising no \
            TCP endpoint. Either set external_addr to the public \
            IP (recommended for cloud 1:1-NAT setups) or bind \
            explicitly to the public IP"
        ),
        Log::StunSucceeded { server, mapped } => debug!(
            target: "fips::nostr::stun",
            stun_server = %server,
            reflexive = ?Some(mapped),
            "STUN observation succeeded"
        ),
        Log::StunDiscarded {
            server,
            expected,
            rejected,
            last_unexpected,
        } => debug!(
            target: "fips::nostr::stun",
            stun_server = %server,
            expected = %expected,
            rejected = *rejected,
            last_unexpected = ?last_unexpected,
            "discarded STUN datagrams from unexpected sources"
        ),
        Log::StunFailed { error } => debug!(
            target: "fips::nostr::stun",
            error = %error,
            "stun observation failed, falling back to LAN-only addresses"
        ),
        Log::PublicAddrBindFailed { error } => debug!(
            target: "fips::nostr::runtime",
            error = %error,
            "public-udp-addr: ephemeral bind failed"
        ),
        Log::PublicAddrNonBlockingFailed { error } => debug!(
            target: "fips::nostr::runtime",
            error = %error,
            "public-udp-addr: set_nonblocking failed"
        ),
        Log::PublicAddrObserved { stun, reflexive } => debug!(
            target: "fips::nostr::runtime",
            stun = %stun.as_deref().unwrap_or("-"),
            reflexive = %reflexive
                .map(|a| format!("{}:{}", a.ip(), a.port()))
                .unwrap_or_else(|| "-".into()),
            "public-udp-addr: STUN observation"
        ),
        Log::PublishReachedNone {
            kind,
            event,
            relays,
        } => debug!(
            target: "fips::nostr::runtime",
            kind = *kind,
            event = %short_id(&event.to_string()),
            relays = *relays,
            "publish reached no relay"
        ),
        Log::PublicAddrFailed { error } => debug!(
            target: "fips::nostr::runtime",
            error = %error,
            "public-udp-addr: STUN failed"
        ),
    }
}

/// The pump has started reading the relay client's stream.
pub(super) fn notify_loop_entered() {
    info!(target: "fips::nostr::runtime", "nostr notify loop entered");
}

/// The first notification of any kind arrived, from either feed,
/// `elapsed_ms` after the pump started.
pub(super) fn first_event(elapsed_ms: u64) {
    info!(
        target: "fips::nostr::runtime",
        elapsed_ms,
        "nostr notify loop received first event"
    );
}

/// `channel` has closed, so the task reading it ends.
pub(super) fn channel_closed(channel: Feed) {
    warn!(
        target: "fips::nostr::runtime",
        channel = ?channel,
        "nostr notification channel closed; notify loop exiting"
    );
}

/// A datagram from the address a traversal adopted for `npub` carried
/// another FMP version, and the peer's re-traversal is suppressed for
/// `cooldown_secs`. Logged with the receive loop's target, where the line
/// was first written.
pub(super) fn version_mismatch(
    npub: &str,
    transport_id: &str,
    remote_addr: &str,
    peer_version: u8,
    our_version: u8,
    cooldown_secs: u64,
) {
    warn!(
        target: "fips::node::dataplane::rx_loop",
        peer_npub = %npub,
        transport_id = %transport_id,
        remote_addr = %remote_addr,
        peer_version,
        our_version,
        cooldown_secs,
        "Datagram from the traversed peer's address carried another FMP version; suppressing re-traversal"
    );
}

/// Whether the first notification has been logged, shared by the pump and
/// the signal task, and when the pump started.
#[derive(Debug)]
pub(super) struct FirstEvent {
    started: Instant,
    seen: std::sync::atomic::AtomicBool,
}

impl FirstEvent {
    /// Not yet seen, counting from now.
    pub(super) fn new() -> Self {
        Self {
            started: Instant::now(),
            seen: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// A notification arrived: log the first one, once.
    pub(super) fn note(&self) {
        if !self.seen.swap(true, std::sync::atomic::Ordering::Relaxed) {
            first_event(self.started.elapsed().as_millis() as u64);
        }
    }
}

#[cfg(test)]
#[path = "tests/log.rs"]
mod tests;
