//! The golden list of the lines the rendezvous machine and the pump log:
//! each one's level, text, fields and target, as `runtime.rs` and
//! `driver.rs` logged them before the code moved. Operators filter on the
//! target and scripts match the text.

use std::net::SocketAddr;

use nostr::event::EventId;

use super::super::machine::rendezvous::log::{IngestPath, Log, Source};
use super::super::types::{OverlayEndpointAdvert, OverlayTransportKind};
use super::*;
use crate::testutil::capture_logs;

const PEER: &str = "npub1lycg5qvjtrp3qjf5f7zl382j9x6nrjz9sdhenvyxq8c3808qxmus6gq266";

fn endpoints() -> Vec<OverlayEndpointAdvert> {
    vec![
        OverlayEndpointAdvert {
            transport: OverlayTransportKind::Udp,
            addr: "nat".to_string(),
        },
        OverlayEndpointAdvert {
            transport: OverlayTransportKind::Tcp,
            addr: "8.8.8.8:443".to_string(),
        },
    ]
}

fn event_id() -> EventId {
    EventId::from_hex("8f7476a38d5f5ea8c139b8cef70a215f9733a5ee36dd2fab0f164e7123c9436e").unwrap()
}

fn bind() -> SocketAddr {
    "0.0.0.0:2121".parse().unwrap()
}

/// What `emit` logs: its one line, and the target of each line with the
/// message `message`.
fn logged(emit: impl FnOnce(), message: &str) -> (Vec<String>, Vec<&'static str>) {
    let ((), capture) = capture_logs(emit);
    (capture.lines(), capture.targets(message))
}

/// The message of a captured `line`: the text between ` message=` and the
/// first field the line goes on to.
fn message_of<'a>(line: &'a str, fields: &str) -> &'a str {
    let rest = line.split_once(" message=").map_or("", |(_, rest)| rest);
    if fields.is_empty() {
        rest
    } else {
        rest.strip_suffix(fields).map_or(rest, str::trim_end)
    }
}

/// A line the shell logs itself: how to emit it, its level, its message
/// and its fields.
type ShellLine = (fn(), &'static str, &'static str, &'static str);

const RUNTIME: &str = "fips::nostr::runtime";
const DRIVER: &str = "fips::nostr::driver";
const STUN: &str = "fips::nostr::stun";

/// Each machine line: the event, its target, its message and its fields as
/// the capture writes them, after the level.
fn machine_cases() -> Vec<(Log, &'static str, &'static str, &'static str, &'static str)> {
    vec![
        (
            Log::PeerCached {
                peer: PEER.to_string(),
                endpoints: endpoints(),
                event: event_id(),
            },
            RUNTIME,
            "DEBUG",
            "advert: peer cached",
            "peer=npub1lycg..q266 endpoints=udp:nat,tcp:8.8.8.8:443 event=8f7476a3",
        ),
        (
            Log::CacheFull { bound: 2048 },
            RUNTIME,
            "WARN",
            "advert cache full; refusing adverts from new unconfigured authors",
            "bound=2048",
        ),
        (
            Log::NotCached {
                peer: PEER.to_string(),
                path: IngestPath::Stream,
            },
            RUNTIME,
            "DEBUG",
            "advert cache full; advert not cached",
            "peer=npub1lycg..q266 reason=\"cache-full\"",
        ),
        (
            Log::NotCached {
                peer: PEER.to_string(),
                path: IngestPath::Fetch,
            },
            RUNTIME,
            "DEBUG",
            "advert cache full; fetched advert used for this dial only",
            "peer=npub1lycg..q266 reason=\"cache-full\"",
        ),
        (
            Log::NotCached {
                peer: PEER.to_string(),
                path: IngestPath::Refetch,
            },
            RUNTIME,
            "DEBUG",
            "advert cache full; refetched advert not cached",
            "peer=npub1lycg..q266 reason=\"cache-full\"",
        ),
        (
            Log::CacheEvicted {
                evicted: 3,
                retained: 2048,
                cap: 2048,
            },
            RUNTIME,
            "DEBUG",
            "advert cache over cap; evicted unprotected entries",
            "evicted=3 retained=2048 cap=2048",
        ),
        (
            Log::CacheBelowCap { refused: 17 },
            RUNTIME,
            "INFO",
            "advert cache below cap again",
            "refused=17",
        ),
        (
            Log::Resolved {
                peer: PEER.to_string(),
                source: Source::Cache,
                endpoints: endpoints(),
            },
            RUNTIME,
            "DEBUG",
            "advert: resolved",
            "peer=npub1lycg..q266 source=\"cache\" endpoints=udp:nat,tcp:8.8.8.8:443",
        ),
        (
            Log::Resolved {
                peer: PEER.to_string(),
                source: Source::RelayFetch,
                endpoints: endpoints(),
            },
            RUNTIME,
            "DEBUG",
            "advert: resolved",
            "peer=npub1lycg..q266 source=\"relay-fetch\" endpoints=udp:nat,tcp:8.8.8.8:443",
        ),
        (
            Log::SubscribeFailed {
                error: "nostr error: relay not found".to_string(),
            },
            RUNTIME,
            "WARN",
            "failed to subscribe to Nostr discovery relays",
            "error=nostr error: relay not found",
        ),
        (
            Log::SubscribeTimedOut { timeout_ms: 5000 },
            RUNTIME,
            "WARN",
            "Nostr discovery relay subscribe timed out",
            "timeout_ms=5000",
        ),
        (
            Log::InboxFailed {
                error: "nostr error: relay not found".to_string(),
            },
            RUNTIME,
            "WARN",
            "failed to publish Nostr inbox relay list",
            "error=nostr error: relay not found",
        ),
        (
            Log::InboxTimedOut { timeout_ms: 5000 },
            RUNTIME,
            "WARN",
            "Nostr inbox relay publish timed out",
            "timeout_ms=5000",
        ),
        (
            Log::AdvertFailed {
                error: "nostr error: relay not found".to_string(),
            },
            RUNTIME,
            "WARN",
            "failed to publish traversal advert",
            "error=nostr error: relay not found",
        ),
        (
            Log::AdvertTimedOut { timeout_ms: 10000 },
            RUNTIME,
            "WARN",
            "Nostr traversal advert publish timed out",
            "timeout_ms=10000",
        ),
        (
            Log::AdvertPublished {
                event: event_id(),
                relays: 2,
                endpoints: endpoints(),
                ttl_secs: 3600,
            },
            RUNTIME,
            "DEBUG",
            "advert: published",
            "event=8f7476a3 relays=2 endpoints=udp:nat,tcp:8.8.8.8:443 ttl_secs=3600",
        ),
        (
            Log::ListCut {
                list: "signalRelays",
                configured: 40,
                published: 32,
            },
            RUNTIME,
            "WARN",
            "advert: list longer than peers accept; publishing only its first entries",
            "list=\"signalRelays\" configured=40 published=32",
        ),
        (
            Log::AdvertTooLarge {
                bytes: 9000,
                bound: 8192,
            },
            RUNTIME,
            "WARN",
            "advert: larger than peers accept; peers will refuse it",
            "bytes=9000 bound=8192",
        ),
        (
            Log::UdpUnlearned {
                transport_id: 7,
                bind_addr: bind(),
            },
            DRIVER,
            "WARN",
            "advert: udp public=true bound to wildcard but STUN observation failed; \
             advertising no UDP endpoint. Either set transports.udp.external_addr, bind to \
             a specific public IP, or ensure node.rendezvous.nostr.stun_servers is reachable",
            "transport_id=7 bind_addr=0.0.0.0:2121",
        ),
        (
            Log::TcpWildcard { bind_addr: bind() },
            DRIVER,
            "WARN",
            "advert: tcp advertise_on_nostr=true bound to wildcard and no \
             transports.tcp.external_addr set; advertising no TCP endpoint. Either set \
             external_addr to the public IP (recommended for cloud 1:1-NAT setups) or bind \
             explicitly to the public IP",
            "bind_addr=0.0.0.0:2121",
        ),
        (
            Log::StunSucceeded {
                server: "stun:198.51.100.1:3478".to_string(),
                mapped: "8.8.4.4:50000".parse().unwrap(),
            },
            STUN,
            "DEBUG",
            "STUN observation succeeded",
            "stun_server=stun:198.51.100.1:3478 reflexive=Some(8.8.4.4:50000)",
        ),
        (
            Log::StunDiscarded {
                server: "stun:198.51.100.1:3478".to_string(),
                expected: "198.51.100.1:3478".parse().unwrap(),
                rejected: 2,
                last_unexpected: Some("198.51.100.66:3478".parse().unwrap()),
            },
            STUN,
            "DEBUG",
            "discarded STUN datagrams from unexpected sources",
            "stun_server=stun:198.51.100.1:3478 expected=198.51.100.1:3478 rejected=2 \
             last_unexpected=Some(198.51.100.66:3478)",
        ),
        (
            Log::StunFailed {
                error: "stun failed: timed out waiting for stun:198.51.100.1:3478".to_string(),
            },
            STUN,
            "DEBUG",
            "stun observation failed, falling back to LAN-only addresses",
            "error=stun failed: timed out waiting for stun:198.51.100.1:3478",
        ),
        (
            Log::PublicAddrBindFailed {
                error: "Address in use".to_string(),
            },
            RUNTIME,
            "DEBUG",
            "public-udp-addr: ephemeral bind failed",
            "error=Address in use",
        ),
        (
            Log::PublicAddrNonBlockingFailed {
                error: "Bad file descriptor".to_string(),
            },
            RUNTIME,
            "DEBUG",
            "public-udp-addr: set_nonblocking failed",
            "error=Bad file descriptor",
        ),
        (
            Log::PublicAddrObserved {
                stun: Some("stun:198.51.100.1:3478".to_string()),
                reflexive: Some("8.8.4.4:50000".parse().unwrap()),
            },
            RUNTIME,
            "DEBUG",
            "public-udp-addr: STUN observation",
            "stun=stun:198.51.100.1:3478 reflexive=8.8.4.4:50000",
        ),
        (
            Log::PublicAddrObserved {
                stun: None,
                reflexive: None,
            },
            RUNTIME,
            "DEBUG",
            "public-udp-addr: STUN observation",
            "stun=- reflexive=-",
        ),
        (
            Log::PublicAddrFailed {
                error: "io error: Bad file descriptor".to_string(),
            },
            RUNTIME,
            "DEBUG",
            "public-udp-addr: STUN failed",
            "error=io error: Bad file descriptor",
        ),
        (
            Log::PublishReachedNone {
                kind: 37195,
                event: event_id(),
                relays: 2,
            },
            RUNTIME,
            "DEBUG",
            "publish reached no relay",
            "kind=37195 event=8f7476a3 relays=2",
        ),
    ]
}

#[test]
fn every_machine_log_event_renders_with_todays_target_level_text_and_fields() {
    for (event, target, level, message, fields) in machine_cases() {
        let (lines, targets) = logged(|| render(&event), message);
        let expected = if fields.is_empty() {
            format!("{level} message={message}")
        } else {
            format!("{level} message={message} {fields}")
        };
        assert_eq!(lines, vec![expected], "{event:?}");
        assert_eq!(targets, vec![target], "{event:?}");
        assert_eq!(message_of(&lines[0], fields), message);
    }

    let shell: [ShellLine; 4] = [
        (notify_loop_entered, "INFO", "nostr notify loop entered", ""),
        (
            || first_event(42),
            "INFO",
            "nostr notify loop received first event",
            "elapsed_ms=42",
        ),
        (
            || channel_closed(Feed::Pool),
            "WARN",
            "nostr notification channel closed; notify loop exiting",
            "channel=Pool",
        ),
        (
            || channel_closed(Feed::Signals),
            "WARN",
            "nostr notification channel closed; notify loop exiting",
            "channel=Signals",
        ),
    ];
    for (emit, level, message, fields) in shell {
        let (lines, targets) = logged(emit, message);
        let expected = if fields.is_empty() {
            format!("{level} message={message}")
        } else {
            format!("{level} message={message} {fields}")
        };
        assert_eq!(lines, vec![expected], "{message}");
        assert_eq!(targets, vec![RUNTIME], "{message}");
    }
}

/// The mismatch warning moved from the receive loop into the engine's
/// handle keeps the receive loop's target, level, text and fields, and a
/// repeat inside the cooldown logs nothing.
#[tokio::test]
async fn the_mismatch_warning_keeps_the_receive_loops_target_text_and_fields() {
    const MESSAGE: &str = "Datagram from the traversed peer's address carried another FMP version; suppressing re-traversal";
    let runtime = super::super::runtime::NostrRendezvous::new_for_test();
    let (capture, _guard) = crate::testutil::capture_logs_scoped();
    for _ in 0..2 {
        runtime.note_version_mismatch(PEER, "udp1", "192.0.2.7:2121", 1, 0);
    }
    runtime.settled_for_test().await;
    assert_eq!(
        capture.lines_with(MESSAGE),
        vec![format!(
            "WARN message={MESSAGE} peer_npub={PEER} transport_id=udp1 \
             remote_addr=192.0.2.7:2121 peer_version=1 our_version=0 cooldown_secs=86400"
        )]
    );
    assert_eq!(
        capture.targets(MESSAGE),
        vec!["fips::node::dataplane::rx_loop"]
    );
}
