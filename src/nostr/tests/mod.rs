// These tests build events with nostr's own keys, clock and signing helpers.
// The ban in the root clippy.toml is on non-test code using them.
#![allow(clippy::disallowed_types, clippy::disallowed_methods)]

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use nostr::event::FinalizeEvent;
use nostr::prelude::{EventBuilder, Kind, RelayUrl, Tag, Timestamp};

use super::machine::NodeSigner;
use super::machine::adverts::{is_reserved_ip, is_unroutable_direct_advert_ip};
use super::machine::error::Error as MachineError;
use super::machine::params::Params;
use super::machine::punch::parse_punch_packet;
use super::machine::punch::plan::{
    PunchStrategy, is_doc_ip, is_never_punchable_ip, is_private_ip, plan_punch_targets,
};
use super::machine::tests::TestInstant;
use super::machine::traversal::election::suppress_responder_for_own_initiator;
use super::runtime::{
    NostrRendezvous, adversarial_offer_reject, inbox_relays, short_id, signal_relays,
};
use super::signal::{
    FreshnessOutcome, build_signal_event, create_traversal_answer, create_traversal_offer,
    estimate_clock_skew, rumor, unwrap_signal_event, validate_offer_freshness,
    validate_traversal_answer_for_offer,
};
use super::stun::{parse_stun_binding_success, parse_stun_url};
use super::traversal::{
    RefusalWarnGate, SourceRank, build_punch_packet, now_ms, planned_remote_endpoints,
    rank_punch_source, session_hash,
};
use super::types::BootstrapError;
use super::{
    ADVERT_IDENTIFIER, ADVERT_KIND, ADVERT_VERSION, OverlayAdvert, OverlayEndpointAdvert,
    OverlayTransportKind, PunchHint, PunchPacketKind, TraversalAddress,
};
use crate::NodeAddr;
use crate::utils::onlink::OnLinkPrefixes;

#[derive(Clone, Copy, PartialEq, Eq)]
enum NatType {
    RestrictedCone,
    PortRestricted,
    Symmetric,
}

fn addr(ip: &str, port: u16) -> TraversalAddress {
    TraversalAddress {
        protocol: "udp".to_string(),
        ip: ip.to_string(),
        port,
    }
}

fn can_reach(local_nat: NatType, remote_nat: NatType) -> bool {
    if local_nat == NatType::Symmetric || remote_nat == NatType::Symmetric {
        return false;
    }
    !(local_nat == NatType::PortRestricted && remote_nat == NatType::PortRestricted)
}

fn signed_overlay_advert_event(
    created_at_secs: u64,
    expiration_secs: Option<u64>,
) -> nostr::event::Event {
    signed_overlay_advert_event_from(
        &nostr::key::Keys::generate(),
        created_at_secs,
        expiration_secs,
    )
}

fn signed_overlay_advert_event_from(
    keys: &nostr::key::Keys,
    created_at_secs: u64,
    expiration_secs: Option<u64>,
) -> nostr::event::Event {
    let content = r#"{"identifier":"fips-overlay-v1","version":1,"endpoints":[{"transport":"tcp","addr":"8.8.8.8:443"}]}"#;
    let mut builder = EventBuilder::new(Kind::Custom(ADVERT_KIND), content)
        .custom_created_at(Timestamp::from(created_at_secs));
    if let Some(expiration_secs) = expiration_secs {
        builder = builder.tags([Tag::expiration(Timestamp::from(expiration_secs))]);
    }
    builder.finalize(keys).unwrap()
}

fn signed_inbox_relay_event(
    keys: &nostr::key::Keys,
    created_at_secs: u64,
    relay: &str,
) -> nostr::event::Event {
    EventBuilder::new(Kind::InboxRelays, "")
        .tags([Tag::custom(
            "relay",
            [RelayUrl::parse(relay).unwrap().to_string()],
        )])
        .custom_created_at(Timestamp::from(created_at_secs))
        .finalize(keys)
        .unwrap()
}

#[test]
fn serializes_direct_overlay_advert_without_nat_metadata() {
    let advert = OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: ADVERT_VERSION,
        endpoints: vec![
            OverlayEndpointAdvert {
                transport: OverlayTransportKind::Tcp,
                addr: "203.0.113.10:443".to_string(),
            },
            OverlayEndpointAdvert {
                transport: OverlayTransportKind::Tor,
                addr: "exampleonion.onion:1234".to_string(),
            },
        ],
        signal_relays: None,
        stun_servers: None,
    };

    let json = serde_json::to_string(&advert).unwrap();
    assert!(json.contains("\"endpoints\""));
    assert!(!json.contains("\"signalRelays\""));
    assert!(!json.contains("\"stunServers\""));
}

#[test]
fn serializes_nat_overlay_advert_with_metadata() {
    let advert = OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: ADVERT_VERSION,
        endpoints: vec![OverlayEndpointAdvert {
            transport: OverlayTransportKind::Udp,
            addr: "nat".to_string(),
        }],
        signal_relays: Some(vec!["wss://relay.example".to_string()]),
        stun_servers: Some(vec!["stun:stun.example.org:3478".to_string()]),
    };

    let json = serde_json::to_string(&advert).unwrap();
    assert!(json.contains("\"signalRelays\""));
    assert!(json.contains("\"stunServers\""));
}

#[test]
fn rejects_invalid_overlay_adverts() {
    let missing_nat_metadata = OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: ADVERT_VERSION,
        endpoints: vec![OverlayEndpointAdvert {
            transport: OverlayTransportKind::Udp,
            addr: "nat".to_string(),
        }],
        signal_relays: None,
        stun_servers: None,
    };
    assert!(NostrRendezvous::validate_overlay_advert(missing_nat_metadata).is_err());

    let wrong_identifier = OverlayAdvert {
        identifier: "not-fips-overlay".to_string(),
        version: ADVERT_VERSION,
        endpoints: vec![OverlayEndpointAdvert {
            transport: OverlayTransportKind::Tcp,
            addr: "203.0.113.10:443".to_string(),
        }],
        signal_relays: None,
        stun_servers: None,
    };
    assert!(NostrRendezvous::validate_overlay_advert(wrong_identifier).is_err());
}

#[test]
fn validate_overlay_advert_filters_unroutable_direct_endpoints() {
    let advert = OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: ADVERT_VERSION,
        endpoints: vec![
            OverlayEndpointAdvert {
                transport: OverlayTransportKind::Tcp,
                addr: "192.168.1.10:443".to_string(),
            },
            OverlayEndpointAdvert {
                transport: OverlayTransportKind::Udp,
                addr: "100.64.1.2:2121".to_string(),
            },
            OverlayEndpointAdvert {
                transport: OverlayTransportKind::Tcp,
                addr: "8.8.8.8:443".to_string(),
            },
        ],
        signal_relays: None,
        stun_servers: None,
    };

    let validated = NostrRendezvous::validate_overlay_advert(advert).unwrap();
    assert_eq!(validated.endpoints.len(), 1);
    assert_eq!(validated.endpoints[0].addr, "8.8.8.8:443");
}

#[test]
fn validate_overlay_advert_rejects_only_unroutable_direct_endpoints() {
    let advert = OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: ADVERT_VERSION,
        endpoints: vec![
            OverlayEndpointAdvert {
                transport: OverlayTransportKind::Tcp,
                addr: "127.0.0.1:443".to_string(),
            },
            OverlayEndpointAdvert {
                transport: OverlayTransportKind::Udp,
                addr: "10.0.0.2:2121".to_string(),
            },
        ],
        signal_relays: None,
        stun_servers: None,
    };

    let err = NostrRendezvous::validate_overlay_advert(advert).unwrap_err();
    assert!(err.to_string().contains("missing publicly routable"));
}

#[test]
fn advert_freshness_rejects_expired_events() {
    let now_secs = Timestamp::now().as_secs();
    let event = signed_overlay_advert_event(now_secs, Some(now_secs.saturating_sub(1)));
    let valid_until =
        NostrRendezvous::compute_advert_valid_until_ms(&event, 600_000, now_secs * 1000);
    assert!(valid_until.is_none());
}

#[test]
fn advert_freshness_rejects_stale_created_at_without_expiration() {
    let now_secs = Timestamp::now().as_secs();
    let stale_created = now_secs.saturating_sub(10_000);
    let event = signed_overlay_advert_event(stale_created, None);
    let valid_until =
        NostrRendezvous::compute_advert_valid_until_ms(&event, 600_000, now_secs * 1000);
    assert!(valid_until.is_none());
}

/// A hostile advert relay may answer an author-filtered request with an event
/// it signed itself. Selection has to drop those before the newest-`created_at`
/// contest, or a future-dated foreign advert suppresses the genuine one.
#[test]
fn advert_selection_ignores_events_not_signed_by_the_target_peer() {
    let now_secs = Timestamp::now().as_secs();
    let peer_keys = nostr::key::Keys::generate();
    let hostile_keys = nostr::key::Keys::generate();

    let hostile = signed_overlay_advert_event_from(&hostile_keys, now_secs + 3_600, None);
    let genuine = signed_overlay_advert_event_from(&peer_keys, now_secs.saturating_sub(10), None);
    let events = [hostile, genuine];

    let selected = NostrRendezvous::newest_event_by_author(events.iter(), peer_keys.public_key())
        .expect("the peer's own advert should be selected");
    assert_eq!(selected.pubkey, peer_keys.public_key());
}

/// Nothing signed by the peer means nothing to select, even though the relays
/// did answer. The caller reads this as "no evidence", not "withdrawn".
#[test]
fn advert_selection_returns_nothing_when_every_event_is_foreign() {
    let now_secs = Timestamp::now().as_secs();
    let peer_keys = nostr::key::Keys::generate();
    let hostile_keys = nostr::key::Keys::generate();

    let events = [signed_overlay_advert_event_from(
        &hostile_keys,
        now_secs + 3_600,
        None,
    )];

    assert!(
        NostrRendezvous::newest_event_by_author(events.iter(), peer_keys.public_key()).is_none()
    );
}

/// The same omission on the inbox-relay lookup steers this node's DM and
/// signal traffic onto relays an attacker chose, so it gets the same filter.
#[test]
fn inbox_relay_selection_ignores_relay_lists_not_signed_by_the_target() {
    let now_secs = Timestamp::now().as_secs();
    let peer_keys = nostr::key::Keys::generate();
    let hostile_keys = nostr::key::Keys::generate();

    let events = [
        signed_inbox_relay_event(&hostile_keys, now_secs + 3_600, "wss://hostile.example/"),
        signed_inbox_relay_event(
            &peer_keys,
            now_secs.saturating_sub(10),
            "wss://genuine.example/",
        ),
    ];

    let selected = NostrRendezvous::newest_event_by_author(events.iter(), peer_keys.public_key())
        .expect("the peer's own relay list should be selected");
    let relays = inbox_relays(selected);
    assert_eq!(relays, vec!["wss://genuine.example/".to_string()]);
}

/// A far-future `created_at` must not buy a proportionally distant validity
/// horizon. The window is computed from the clamped timestamp instead, so the
/// entry expires on our clock rather than the publisher's.
#[test]
fn advert_freshness_clamps_created_at_beyond_the_forward_skew_tolerance() {
    let now_secs = Timestamp::now().as_secs();
    let event = signed_overlay_advert_event(now_secs + 3_600, None);
    let valid_until =
        NostrRendezvous::compute_advert_valid_until_ms(&event, 600_000, now_secs * 1000)
            .expect("a future-dated advert is still usable, just not for as long");
    assert_eq!(valid_until, (now_secs + 60) * 1000 + 600_000);
}

/// Pins the forward bound to `FRESHNESS_SKEW_TOLERANCE_MS` exactly, mirroring
/// the signal path: 60s ahead is taken as published, 61s ahead is clamped.
/// This is the healthy-path half; an ordinary clock difference must not cost a
/// legitimate peer anything.
#[test]
fn advert_freshness_at_the_forward_skew_limit_is_untouched_and_one_second_beyond_is_clamped() {
    let now_secs = Timestamp::now().as_secs();

    let at_limit = signed_overlay_advert_event(now_secs + 60, None);
    let valid_until =
        NostrRendezvous::compute_advert_valid_until_ms(&at_limit, 600_000, now_secs * 1000)
            .expect("an advert exactly at the forward tolerance should be accepted as published");
    assert_eq!(valid_until, (now_secs + 60) * 1000 + 600_000);

    let past_limit = signed_overlay_advert_event(now_secs + 61, None);
    let clamped =
        NostrRendezvous::compute_advert_valid_until_ms(&past_limit, 600_000, now_secs * 1000)
            .expect("an advert one second past the tolerance is clamped, not refused");
    assert_eq!(clamped, (now_secs + 60) * 1000 + 600_000);
}

#[test]
fn advert_freshness_uses_earliest_expiration_bound() {
    let now_secs = Timestamp::now().as_secs();
    let event = signed_overlay_advert_event(now_secs.saturating_sub(10), Some(now_secs + 30));
    let valid_until =
        NostrRendezvous::compute_advert_valid_until_ms(&event, 3_600_000, now_secs * 1000)
            .expect("event should be fresh");
    assert_eq!(valid_until, (now_secs + 30) * 1000);
}

#[test]
fn parses_stun_urls() {
    let parsed = parse_stun_url("stun:stun.l.google.com:19302").unwrap();
    assert_eq!(parsed.host, "stun.l.google.com");
    assert_eq!(parsed.port, 19302);
}

#[test]
fn parses_ipv6_stun_urls() {
    let parsed = parse_stun_url("stun:[2001:db8::10]:3478").unwrap();
    assert_eq!(parsed.host, "[2001:db8::10]");
    assert_eq!(parsed.port, 3478);
}

#[test]
fn parses_ipv6_xor_mapped_address() {
    let txn_id = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76,
    ];
    let addr = std::net::SocketAddr::new("2001:db8::1234".parse().unwrap(), 3478);
    let port = addr.port() ^ 0x2112;

    let mut attr = Vec::with_capacity(24);
    attr.extend_from_slice(&0x0020u16.to_be_bytes());
    attr.extend_from_slice(&20u16.to_be_bytes());
    attr.push(0);
    attr.push(0x02);
    attr.extend_from_slice(&port.to_be_bytes());

    let ipv6 = match addr.ip() {
        std::net::IpAddr::V6(ip) => ip.octets(),
        std::net::IpAddr::V4(_) => panic!("expected IPv6 test address"),
    };
    let cookie = 0x2112_a442u32.to_be_bytes();
    for index in 0..16 {
        let mask = if index < 4 {
            cookie[index]
        } else {
            txn_id[index - 4]
        };
        attr.push(ipv6[index] ^ mask);
    }

    let mut packet = Vec::with_capacity(44);
    packet.extend_from_slice(&0x0101u16.to_be_bytes());
    packet.extend_from_slice(&(attr.len() as u16).to_be_bytes());
    packet.extend_from_slice(&0x2112_a442u32.to_be_bytes());
    packet.extend_from_slice(&txn_id);
    packet.extend_from_slice(&attr);

    assert_eq!(parse_stun_binding_success(&packet, &txn_id), Some(addr));
}

#[test]
fn builds_and_parses_probe_packets() {
    let packet = build_punch_packet(PunchPacketKind::Probe, 7, "sess-1");
    let parsed = parse_punch_packet(&packet).unwrap();
    assert_eq!(parsed.kind, PunchPacketKind::Probe);
    assert_eq!(parsed.sequence, 7);
    assert_eq!(parsed.session_hash, session_hash("sess-1"));
}

#[test]
fn validates_offer_answer_pair() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        1_700_000_000_000,
        60_000,
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        Some(addr("203.0.113.10", 62000)),
        vec![addr("192.168.1.10", 62000)],
        Some("stun:example.org:3478".to_string()),
    );
    let answer = create_traversal_answer(
        "sess-1".to_string(),
        1_700_000_000_500,
        60_000,
        "answer-1".to_string(),
        "npub1server".to_string(),
        "npub1client".to_string(),
        "offer-1".to_string(),
        true,
        Some(addr("198.51.100.20", 63000)),
        vec![addr("192.168.1.20", 63000)],
        Some("stun:example.org:3478".to_string()),
        Some(PunchHint {
            start_at_ms: 1_700_000_002_000,
            interval_ms: 200,
            duration_ms: 10_000,
        }),
        None,
        Some(1_700_000_000_400),
    );

    assert!(
        validate_traversal_answer_for_offer(
            &offer,
            &answer,
            1_700_000_000_900,
            60_000,
            "npub1server",
            "npub1client",
        )
        .is_ok()
    );
}

/// An answer's `inReplyTo` names the offer's `nonce`, not the offer's event
/// id. `validates_offer_answer_pair` is the control: the same pair with the
/// nonce is accepted.
#[test]
fn an_answer_whose_in_reply_to_is_the_offer_event_id_rather_than_its_nonce_is_refused_as_a_session_mismatch()
 {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        1_700_000_000_000,
        60_000,
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        Some(addr("203.0.113.10", 62000)),
        vec![addr("192.168.1.10", 62000)],
        Some("stun:example.org:3478".to_string()),
    );
    let offer_event_id = "ab".repeat(32);
    let answer = create_traversal_answer(
        "sess-1".to_string(),
        1_700_000_000_500,
        60_000,
        "answer-1".to_string(),
        "npub1server".to_string(),
        "npub1client".to_string(),
        offer_event_id,
        true,
        Some(addr("198.51.100.20", 63000)),
        vec![addr("192.168.1.20", 63000)],
        Some("stun:example.org:3478".to_string()),
        Some(PunchHint {
            start_at_ms: 1_700_000_002_000,
            interval_ms: 200,
            duration_ms: 10_000,
        }),
        None,
        Some(1_700_000_000_400),
    );

    match validate_traversal_answer_for_offer(
        &offer,
        &answer,
        1_700_000_000_900,
        60_000,
        "npub1server",
        "npub1client",
    ) {
        Err(MachineError::Protocol(reason)) => assert_eq!(reason, "session-mismatch"),
        other => panic!("expected a session-mismatch refusal, got {other:?}"),
    }
}

/// The kind 21059 wrap is signed by a one-time key, so relays do not see the
/// sender; the seal inside it is signed by the sender's identity key, which
/// the receiver recovers on unwrapping.
#[tokio::test]
async fn the_signal_wrap_is_signed_by_a_one_time_key_and_the_seal_by_the_identity_key() {
    let identity = NodeSigner::new(nostr::key::SecretKey::generate());
    let receiver = NodeSigner::new(nostr::key::SecretKey::generate());
    let rumor = rumor(
        identity.public_key(),
        receiver.public_key(),
        "hello".to_string(),
        now_ms(),
    );

    let event = build_signal_event(
        &identity,
        receiver.public_key(),
        rumor,
        Timestamp::from(Timestamp::now().as_secs() + 30),
    )
    .expect("signal event should build");

    assert_ne!(
        event.pubkey,
        identity.public_key(),
        "the wrap must not be signed by the identity key"
    );
    assert_ne!(event.pubkey, receiver.public_key());
    event.verify().expect("the wrap carries a valid signature");

    let unwrapped = unwrap_signal_event(&receiver, &event)
        .await
        .expect("the receiver can unwrap the signal");
    assert_eq!(
        unwrapped.sender,
        identity.public_key(),
        "the seal must be signed by the identity key"
    );
}

#[test]
fn rejects_offer_with_mismatched_actual_sender() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        1_700_000_000_000,
        60_000,
        "offer-1".to_string(),
        "npub1claimed".to_string(),
        "npub1server".to_string(),
        None,
        vec![addr("192.168.1.10", 62000)],
        None,
    );

    let result = validate_offer_freshness(
        &offer,
        1_700_000_000_100,
        60_000,
        "npub1actual",
        "npub1server",
    );

    assert!(result.is_err());
}

#[test]
fn rejects_answer_with_mismatched_actual_sender() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        1_700_000_000_000,
        60_000,
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        Some(addr("203.0.113.10", 62000)),
        vec![addr("192.168.1.10", 62000)],
        Some("stun:example.org:3478".to_string()),
    );
    let answer = create_traversal_answer(
        "sess-1".to_string(),
        1_700_000_000_500,
        60_000,
        "answer-1".to_string(),
        "npub1server".to_string(),
        "npub1client".to_string(),
        "offer-1".to_string(),
        true,
        Some(addr("198.51.100.20", 63000)),
        vec![addr("192.168.1.20", 63000)],
        Some("stun:example.org:3478".to_string()),
        Some(PunchHint {
            start_at_ms: 1_700_000_002_000,
            interval_ms: 200,
            duration_ms: 10_000,
        }),
        None,
        Some(1_700_000_000_400),
    );

    let result = validate_traversal_answer_for_offer(
        &offer,
        &answer,
        1_700_000_000_900,
        60_000,
        "npub1spoofed",
        "npub1client",
    );

    assert!(result.is_err());
}

#[test]
fn plans_reflexive_targets_before_lan() {
    let (planned, _tally) = plan_punch_targets(
        &[addr("192.168.1.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("192.168.1.20", 63000)],
        Some(&addr("198.51.100.20", 63000)),
        &prefixes(&[("192.168.1.0", 24)]),
    );

    assert_eq!(planned[0].strategy, PunchStrategy::Reflexive);
    assert_eq!(planned[1].strategy, PunchStrategy::Lan);
}

#[test]
fn simulated_lan_scenario_includes_lan_target_and_succeeds() {
    let (planned, _tally) = plan_punch_targets(
        &[addr("192.168.1.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("192.168.1.20", 63000)],
        Some(&addr("198.51.100.20", 63000)),
        &prefixes(&[("192.168.1.0", 24)]),
    );

    assert!(
        planned
            .iter()
            .any(|target| target.strategy == PunchStrategy::Lan)
    );
    assert!(can_reach(NatType::RestrictedCone, NatType::RestrictedCone));
}

#[test]
fn simulated_symmetric_nat_scenario_requires_fallback() {
    let (planned, _tally) = plan_punch_targets(
        &[addr("10.0.0.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("10.0.1.10", 63000)],
        Some(&addr("198.51.100.20", 63000)),
        &prefixes(&[("10.0.0.0", 24)]),
    );

    assert!(
        planned
            .iter()
            .any(|target| target.strategy == PunchStrategy::Reflexive)
    );
    assert!(!can_reach(NatType::Symmetric, NatType::RestrictedCone));
}

#[test]
fn planned_remote_endpoints_include_private_and_reflexive_paths() {
    let (endpoints, _tally) = planned_remote_endpoints(
        &[addr("192.168.1.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("192.168.1.20", 63000)],
        Some(&addr("198.51.100.20", 63000)),
        &prefixes(&[("192.168.1.0", 24)]),
    )
    .expect("endpoint planning should succeed");

    assert!(endpoints.contains(&"192.168.1.20:63000".parse().unwrap()));
    assert!(endpoints.contains(&"198.51.100.20:63000".parse().unwrap()));
}

#[test]
fn planned_remote_endpoints_reject_never_punchable_remote_candidates() {
    // An empty local list is the shipped `share_local_candidates=false`
    // shape, where every non-reflexive target comes from the ungated
    // reflexive-to-remote-candidate pairing.
    let (endpoints, _tally) = planned_remote_endpoints(
        &[],
        Some(&addr("203.0.113.10", 62000)),
        &[
            addr("127.0.0.1", 63000),
            addr("224.0.0.1", 63000),
            addr("169.254.1.1", 63000),
            addr("255.255.255.255", 63000),
            addr("0.0.0.0", 63000),
            addr("100.64.1.2", 63000),
            addr("8.8.8.8", 0),
        ],
        Some(&addr("198.51.100.20", 63000)),
        &OnLinkPrefixes::default(),
    )
    .expect("endpoint planning should succeed");

    assert_eq!(
        endpoints,
        vec!["198.51.100.20:63000".parse::<SocketAddr>().unwrap()]
    );
}

#[test]
fn planned_remote_endpoints_drop_private_candidate_outside_our_subnet() {
    let (endpoints, _tally) = planned_remote_endpoints(
        &[addr("192.168.1.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("10.9.9.9", 63000)],
        Some(&addr("198.51.100.20", 63000)),
        &prefixes(&[("192.168.1.0", 24)]),
    )
    .expect("endpoint planning should succeed");

    assert!(!endpoints.contains(&"10.9.9.9:63000".parse().unwrap()));
    assert!(endpoints.contains(&"198.51.100.20:63000".parse().unwrap()));
}

#[test]
fn planned_remote_endpoints_reject_ipv4_mapped_private_candidate() {
    let (endpoints, _tally) = planned_remote_endpoints(
        &[],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("::ffff:10.0.0.1", 63000)],
        Some(&addr("198.51.100.20", 63000)),
        &OnLinkPrefixes::default(),
    )
    .expect("endpoint planning should succeed");

    assert_eq!(
        endpoints,
        vec!["198.51.100.20:63000".parse::<SocketAddr>().unwrap()]
    );
}

#[test]
fn planned_remote_endpoints_cap_targets_from_an_oversized_candidate_list() {
    // Public candidates throughout, so the cap and not the address filter is
    // what bounds the result.
    let mut remotes = Vec::new();
    for host in 1..=150u8 {
        remotes.push(addr(&format!("203.0.113.{host}"), 63000));
        remotes.push(addr(&format!("198.51.100.{host}"), 63000));
    }

    let (endpoints, tally) = planned_remote_endpoints(
        &[],
        Some(&addr("203.0.113.10", 62000)),
        &remotes,
        Some(&addr("198.51.100.20", 63000)),
        &OnLinkPrefixes::default(),
    )
    .expect("endpoint planning should succeed");

    // The exact figures are determined by the inputs: the plan is one
    // reflexive-to-reflexive pair plus 300 reflexive-to-candidate pairs, all
    // distinct, so the cap lands on exactly MAX_PUNCH_TARGETS. An inequality
    // here could not tell the cap from a collapse to a single target.
    assert!(tally.capped > 0, "the cap should have discarded targets");
    assert!(tally.suspicious());
    assert_eq!(tally.admitted, 8);
    assert_eq!(endpoints.len(), 8);
}

/// The IPv6 arm of `is_never_punchable_ip` is exercised as a pure predicate
/// elsewhere; this drives it end to end through the planner, which is the
/// path the reflector attack actually uses.
///
/// The local address is a ULA, so our own addresses are not empty, and
/// `fd00::1` is still refused off-subnet rather than admitted: the traversal
/// socket is IPv4, so no unique-local candidate is ever punched.
#[test]
fn planned_remote_endpoints_reject_never_punchable_ipv6_candidates() {
    let (endpoints, _tally) = planned_remote_endpoints(
        &[addr("fd00::2", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[
            addr("::1", 63000),
            addr("::", 63000),
            addr("ff02::1", 63000),
            addr("fe80::1", 63000),
            addr("fd00::1", 63000),
        ],
        Some(&addr("198.51.100.20", 63000)),
        &OnLinkPrefixes::default(),
    )
    .expect("endpoint planning should succeed");

    assert_eq!(
        endpoints,
        vec!["198.51.100.20:63000".parse::<SocketAddr>().unwrap()]
    );
}

/// The cap test above uses public candidates so the cap and not the filter is
/// what bounds the output. The attack shape is the opposite: several hundred
/// attacker-chosen unroutable addresses. This is the only test that pins the
/// filter and the cap acting together on that input, and its failure would
/// mean the reflector is back.
#[test]
fn planned_remote_endpoints_bound_an_oversized_list_of_unroutable_candidates() {
    let mut remotes = Vec::new();
    for host in 1..=150u8 {
        remotes.push(addr(&format!("127.0.0.{host}"), 63000));
        remotes.push(addr(&format!("224.0.0.{host}"), 63000));
    }

    let (endpoints, tally) = planned_remote_endpoints(
        &[],
        Some(&addr("203.0.113.10", 62000)),
        &remotes,
        Some(&addr("198.51.100.20", 63000)),
        &OnLinkPrefixes::default(),
    )
    .expect("endpoint planning should succeed");

    assert_eq!(
        endpoints,
        vec!["198.51.100.20:63000".parse::<SocketAddr>().unwrap()]
    );
    // Only the first MAX_OFFERED_CANDIDATES are vetted at all now, so the
    // unroutable count is the bound rather than the whole list; the rest are
    // recorded as never having been looked at.
    assert_eq!(tally.unroutable, 32);
    assert_eq!(tally.over_offered, 268);
    assert_eq!(tally.admitted, 1);
    assert!(tally.suspicious());
}

/// Guards the deployment whose STUN server sits inside the private network,
/// so the observed reflexive address is itself private. A peer's private
/// reflexive address on the same LAN is kept because one of our interface
/// prefixes holds both it and our own reflexive address; dropping it would
/// remove the only branch that works across arbitrary NATs.
#[test]
fn planned_remote_endpoints_keep_private_reflexive_when_stun_is_on_the_lan() {
    let (endpoints, _tally) = planned_remote_endpoints(
        &[],
        Some(&addr("192.168.1.10", 62000)),
        &[],
        Some(&addr("192.168.1.20", 63000)),
        &prefixes(&[("192.168.1.0", 24)]),
    )
    .expect("endpoint planning should succeed");

    assert!(endpoints.contains(&"192.168.1.20:63000".parse().unwrap()));
}

/// A node whose own STUN result is public, and which shares no local
/// candidate, holds no address of its own on any LAN, so a peer's private
/// reflexive address is only ever an address of the peer's choosing, even
/// when our interface prefix holds it. Admitting it would have this node
/// punch inside its own private network.
#[test]
fn a_peers_private_reflexive_address_is_refused_when_our_own_stun_result_is_public() {
    let (endpoints, tally) = planned_remote_endpoints(
        &[],
        Some(&addr("203.0.113.10", 62000)),
        &[],
        Some(&addr("192.168.1.20", 63000)),
        &prefixes(&[("192.168.1.0", 24)]),
    )
    .expect("endpoint planning should succeed");

    assert!(endpoints.is_empty());
    assert_eq!(tally.reflexive, Some("off-subnet"));
}

/// A node with no reflexive address at all keeps same-LAN peering through
/// its shared local candidate: one of its interface prefixes holds both that
/// address and the peer's private reflexive address.
#[test]
fn a_peers_private_reflexive_address_is_kept_when_we_have_no_stun_result_at_all() {
    let (endpoints, tally) = planned_remote_endpoints(
        &[addr("192.168.1.10", 62000)],
        None,
        &[],
        Some(&addr("192.168.1.20", 63000)),
        &prefixes(&[("192.168.1.0", 24)]),
    )
    .expect("endpoint planning should succeed");

    assert!(endpoints.contains(&"192.168.1.20:63000".parse().unwrap()));
    assert_eq!(tally.reflexive, None);
}

/// Refusing a peer's private reflexive address is now something an honest
/// asymmetric-STUN deployment produces, so it must not warn on its own. The
/// never-routable case above still does.
#[test]
fn an_off_subnet_reflexive_refusal_alone_is_not_suspicious() {
    let (_planned, tally) = plan_punch_targets(
        &[],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("203.0.113.5", 63000)],
        Some(&addr("192.168.1.20", 63000)),
        &OnLinkPrefixes::default(),
    );

    assert_eq!(tally.reflexive, Some("off-subnet"));
    assert!(
        tally.admitted > 0,
        "the host-candidate path should still plan"
    );
    assert!(!tally.suspicious());
}

/// The eight-target cap runs after both planning loops, so it bounds the
/// output and not the work. The discriminating assertion is `unroutable`:
/// vetting every candidate would count all thousand, so a count of exactly
/// `MAX_OFFERED_CANDIDATES` is what proves the excess was never walked.
#[test]
fn an_oversized_candidate_list_is_bounded_before_vetting() {
    let mut remotes = Vec::new();
    for index in 0..1000u32 {
        remotes.push(addr(
            &format!("127.0.0.{}", 1 + (index % 254)),
            63000 + (index % 1000) as u16,
        ));
    }

    let (_planned, tally) = plan_punch_targets(
        &[],
        Some(&addr("203.0.113.10", 62000)),
        &remotes,
        Some(&addr("198.51.100.20", 63000)),
        &OnLinkPrefixes::default(),
    );

    assert_eq!(tally.offered, 1001);
    assert_eq!(tally.unroutable, 32);
    assert_eq!(tally.over_offered, 968);
    assert!(tally.suspicious());
}

/// The four refusal classes tell four different operational stories, so a
/// change that collapses them into one counter, or that makes the warning
/// fire on the benign dual-homed shape, has to red here.
#[test]
fn refused_punch_candidates_are_counted_by_class_and_sampled() {
    let (_planned, tally) = plan_punch_targets(
        &[addr("192.168.1.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[
            addr("127.0.0.1", 63000),
            addr("203.0.113.5", 0),
            addr("10.9.9.9", 63000),
            addr("not-an-ip", 63000),
        ],
        Some(&addr("198.51.100.20", 63000)),
        &prefixes(&[("192.168.1.0", 24)]),
    );

    assert_eq!(tally.offered, 5);
    assert_eq!(tally.unroutable, 1);
    assert_eq!(tally.zeroport, 1);
    assert_eq!(tally.offsubnet, 1);
    assert_eq!(tally.unparsable, 1);
    assert_eq!(tally.sample.as_deref(), Some("127.0.0.1:63000"));
    assert_eq!(tally.reflexive, None);
    assert!(tally.admitted > 0, "the reflexive path should still plan");
    assert!(tally.suspicious());
}

#[test]
fn a_clean_plan_and_an_off_subnet_only_plan_are_not_suspicious() {
    let (_planned, clean) = plan_punch_targets(
        &[addr("192.168.1.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("192.168.1.20", 63000)],
        Some(&addr("198.51.100.20", 63000)),
        &prefixes(&[("192.168.1.0", 24)]),
    );
    assert_eq!(clean.offsubnet, 0);
    assert!(!clean.suspicious());

    let (_planned, off_subnet) = plan_punch_targets(
        &[addr("192.168.1.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("10.9.9.9", 63000)],
        Some(&addr("198.51.100.20", 63000)),
        &prefixes(&[("192.168.1.0", 24)]),
    );
    assert_eq!(off_subnet.offsubnet, 1);
    assert!(off_subnet.admitted > 0);
    assert!(!off_subnet.suspicious());
}

#[test]
fn an_offer_whose_every_candidate_is_refused_is_suspicious() {
    let (planned, tally) = plan_punch_targets(
        &[],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("127.0.0.1", 63000), addr("224.0.0.1", 63000)],
        None,
        &OnLinkPrefixes::default(),
    );

    assert!(planned.is_empty());
    assert_eq!(tally.admitted, 0);
    assert_eq!(tally.unroutable, 2);
    assert!(tally.suspicious());
}

/// A suspicious offer whose refusals are hidden behind its planned pairings
/// logs nothing, so it must not spend the one warning a minute that a later
/// suspicious offer, which does log, is owed.
#[test]
fn a_suspicious_offer_that_logs_nothing_does_not_use_up_the_next_ones_warning() {
    let (_planned, quiet) = plan_punch_targets(
        &[addr("203.0.113.5", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("127.0.0.1", 4000), addr("198.51.100.30", 4000)],
        Some(&addr("198.51.100.20", 4000)),
        &OnLinkPrefixes::default(),
    );
    assert!(quiet.suspicious());
    assert!(!quiet.has_refusals(), "the shape logs nothing: {quiet:?}");
    let (_planned, loud) = plan_punch_targets(
        &[],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("127.0.0.1", 63000)],
        None,
        &OnLinkPrefixes::default(),
    );
    assert!(loud.suspicious());

    let mut gate = RefusalWarnGate::default();
    let t = TestInstant(0);
    assert_eq!(gate.decide(&quiet, t), None);
    assert_eq!(
        gate.decide(&loud, TestInstant(1)),
        Some(0),
        "the warning went to an offer that logged nothing"
    );
}

/// A peer's reflexive address is refused on its own terms: losing it removes
/// the only branch that works across arbitrary NATs, so it is recorded apart
/// from the host-candidate counts.
#[test]
fn a_refused_reflexive_address_is_recorded_apart_from_the_candidates() {
    let (_planned, tally) = plan_punch_targets(
        &[addr("192.168.1.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("192.168.1.20", 63000)],
        Some(&addr("127.0.0.1", 63000)),
        &prefixes(&[("192.168.1.0", 24)]),
    );

    assert_eq!(tally.reflexive, Some("never-routable"));
    assert_eq!(tally.unroutable, 0);
    assert_eq!(tally.sample.as_deref(), Some("127.0.0.1:63000"));
    assert!(tally.suspicious());
}

/// Interface prefixes for a planning test, as `(address, prefix length)`.
fn prefixes(pairs: &[(&str, u8)]) -> OnLinkPrefixes {
    OnLinkPrefixes::from_pairs(
        pairs
            .iter()
            .map(|(ip, len)| (ip.parse::<IpAddr>().expect("test prefix"), *len)),
    )
}

fn endpoint(text: &str) -> SocketAddr {
    text.parse().expect("test endpoint")
}

/// A STUN server inside our LAN gives us a private reflexive address. A
/// stranger's private reflexive address on another subnet must not be
/// punched on the strength of that alone.
#[test]
fn a_strangers_private_reflexive_address_is_refused_when_our_lan_stun_address_shares_no_prefix_with_it()
 {
    let (endpoints, tally) = planned_remote_endpoints(
        &[],
        Some(&addr("192.168.1.5", 62000)),
        &[addr("198.51.100.30", 4000)],
        Some(&addr("10.9.8.7", 4000)),
        &prefixes(&[("192.168.1.0", 24)]),
    )
    .expect("endpoint planning should succeed");

    assert!(
        endpoints
            .iter()
            .all(|e| e.ip() != endpoint("10.9.8.7:1").ip()),
        "planned {endpoints:?}"
    );
    assert_eq!(tally.reflexive, Some("off-subnet"));
    assert!(endpoints.contains(&endpoint("198.51.100.30:4000")));
}

/// With no STUN result of our own, a stranger's private reflexive address
/// is refused unless one of our prefixes holds it and one of our addresses.
#[test]
fn a_strangers_private_reflexive_address_is_refused_when_we_have_no_stun_result() {
    let (planned, tally) = plan_punch_targets(
        &[addr("192.168.1.10", 62000)],
        None,
        &[addr("192.168.1.20", 4000)],
        Some(&addr("10.9.8.7", 4000)),
        &prefixes(&[("192.168.1.0", 24)]),
    );

    assert!(
        planned.iter().all(|t| t.remote.ip != "10.9.8.7"),
        "planned {planned:?}"
    );
    assert_eq!(tally.reflexive, Some("off-subnet"));
    assert!(
        planned
            .iter()
            .any(|t| t.strategy == PunchStrategy::Lan && t.remote.ip == "192.168.1.20")
    );
}

/// A /24 text match is not a link: on a /25, `.200` is another network.
#[test]
fn a_private_candidate_outside_our_interface_prefix_is_refused_even_inside_the_same_slash_24() {
    let (endpoints, tally) = planned_remote_endpoints(
        &[addr("192.168.1.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("192.168.1.200", 4000), addr("192.168.1.20", 4000)],
        None,
        &prefixes(&[("192.168.1.0", 25)]),
    )
    .expect("endpoint planning should succeed");

    assert!(!endpoints.contains(&endpoint("192.168.1.200:4000")));
    assert_eq!(tally.offsubnet, 1);
    assert!(endpoints.contains(&endpoint("192.168.1.20:4000")));
}

/// At the default settings (public STUN, no shared local candidates) we hold
/// no address of our own on the LAN to vouch for a private candidate, so an
/// offer cannot aim probes at hosts on our LAN even though our prefix holds
/// them.
#[test]
fn at_default_settings_an_offer_cannot_aim_probes_at_hosts_on_our_lan() {
    let (endpoints, tally) = planned_remote_endpoints(
        &[],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("192.168.1.77", 4000)],
        Some(&addr("198.51.100.20", 4000)),
        &prefixes(&[("192.168.1.0", 24)]),
    )
    .expect("endpoint planning should succeed");

    assert!(!endpoints.contains(&endpoint("192.168.1.77:4000")));
    assert_eq!(tally.offsubnet, 1);
    assert_eq!(endpoints, vec![endpoint("198.51.100.20:4000")]);
}

#[test]
fn a_private_reflexive_address_on_our_lan_stun_prefix_is_punched() {
    let (endpoints, tally) = planned_remote_endpoints(
        &[],
        Some(&addr("192.168.1.5", 62000)),
        &[],
        Some(&addr("192.168.1.50", 4000)),
        &prefixes(&[("192.168.1.0", 24)]),
    )
    .expect("endpoint planning should succeed");

    assert_eq!(endpoints, vec![endpoint("192.168.1.50:4000")]);
    assert_eq!(tally.reflexive, None);
}

#[test]
fn a_public_reflexive_address_is_punched_whatever_the_prefixes() {
    let (endpoints, _tally) = planned_remote_endpoints(
        &[],
        Some(&addr("203.0.113.10", 62000)),
        &[],
        Some(&addr("198.51.100.20", 4000)),
        &OnLinkPrefixes::default(),
    )
    .expect("endpoint planning should succeed");

    assert_eq!(endpoints, vec![endpoint("198.51.100.20:4000")]);
}

#[test]
fn a_peer_in_a_slash_16_lan_is_punched_where_the_slash_24_test_refused_it() {
    let (planned, tally) = plan_punch_targets(
        &[addr("10.20.1.1", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("10.20.7.8", 4000)],
        None,
        &prefixes(&[("10.20.0.0", 16)]),
    );

    assert_eq!(tally.offsubnet, 0);
    assert!(
        planned
            .iter()
            .any(|t| t.strategy == PunchStrategy::Lan && t.remote.ip == "10.20.7.8"),
        "planned {planned:?}"
    );
}

/// Two peers whose STUN servers sit inside their own, different LANs see
/// each other's private reflexive address refused on every attempt. That is
/// accepted, and must not warn every time.
#[test]
fn a_cross_subnet_lan_stun_offer_refused_as_off_subnet_is_not_suspicious() {
    let (planned, tally) = plan_punch_targets(
        &[],
        Some(&addr("192.168.1.5", 62000)),
        &[],
        Some(&addr("10.9.8.7", 4000)),
        &prefixes(&[("192.168.1.0", 24)]),
    );
    assert!(planned.is_empty());
    assert_eq!(tally.reflexive, Some("off-subnet"));
    assert!(!tally.suspicious());

    let (_planned, loopback) = plan_punch_targets(
        &[],
        Some(&addr("192.168.1.5", 62000)),
        &[],
        Some(&addr("127.0.0.1", 4000)),
        &prefixes(&[("192.168.1.0", 24)]),
    );
    assert!(loopback.suspicious());
}

#[test]
fn a_unique_local_candidate_is_refused_while_the_traversal_socket_is_ipv4_only() {
    let (planned, tally) = plan_punch_targets(
        &[addr("fd00::2", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("fd00::1", 4000)],
        None,
        &prefixes(&[("fd00::", 64)]),
    );

    assert_eq!(tally.offsubnet, 1);
    assert!(planned.iter().all(|t| t.strategy != PunchStrategy::Lan));
    assert!(planned.iter().all(|t| t.remote.ip != "fd00::1"));
}

/// An honest dual-stack peer offers a private IPv4 address, two unique-local
/// addresses and a global IPv6 address, as we do. The plan must fit the
/// eight-target cap so nothing is discarded and nothing warns.
#[test]
fn an_honest_dual_stack_offer_fills_no_more_than_the_target_cap() {
    let (planned, tally) = plan_punch_targets(
        &[
            addr("192.168.1.10", 62000),
            addr("fd00::10", 62000),
            addr("fd01::10", 62000),
            addr("2001:db8::1", 62000),
        ],
        Some(&addr("203.0.113.10", 62000)),
        &[
            addr("192.168.1.20", 4000),
            addr("fd00::20", 4000),
            addr("fd01::20", 4000),
            addr("2001:db8::2", 4000),
        ],
        Some(&addr("198.51.100.20", 4000)),
        &prefixes(&[
            ("192.168.1.0", 24),
            ("fd00::", 64),
            ("fd01::", 64),
            ("2001:db8::", 64),
        ]),
    );

    assert_eq!(tally.capped, 0, "planned {planned:?}");
    assert_eq!(planned.len(), 8);
    assert!(!tally.suspicious());
}

/// A driver holding one adopted bootstrap transport (id 7) that reached
/// `peer` at 198.51.100.7:4000.
fn driver_with_bootstrap(peer: &crate::PeerIdentity) -> super::RendezvousDriver {
    let mut driver = super::RendezvousDriver::default();
    driver.insert_bootstrap_transport(
        crate::transport::TransportId::new(7),
        peer.npub(),
        *peer.node_addr(),
        "198.51.100.7:4000".parse().unwrap(),
    );
    driver
}

#[test]
fn mismatch_evidence_names_the_traversed_peer_only_for_its_own_address_before_a_link() {
    use super::MismatchEvidence;
    let peer = crate::PeerIdentity::from_pubkey(crate::Identity::generate().pubkey());
    let driver = driver_with_bootstrap(&peer);
    let t7 = crate::transport::TransportId::new(7);
    let unlinked = |_: &NodeAddr| false;
    let npub = peer.npub();

    assert_eq!(
        driver.mismatch_evidence(
            &crate::transport::TransportId::new(8),
            Some(endpoint("198.51.100.7:4000")),
            unlinked
        ),
        MismatchEvidence::NotBootstrap
    );
    assert_eq!(
        driver.mismatch_evidence(&t7, Some(endpoint("203.0.113.99:5000")), unlinked),
        MismatchEvidence::ForeignSource
    );
    assert_eq!(
        driver.mismatch_evidence(&t7, None, unlinked),
        MismatchEvidence::ForeignSource
    );
    assert_eq!(
        driver.mismatch_evidence(&t7, Some(endpoint("198.51.100.7:4001")), unlinked),
        MismatchEvidence::ForeignSource
    );
    assert_eq!(
        driver.mismatch_evidence(&t7, Some(endpoint("198.51.100.7:4000")), unlinked),
        MismatchEvidence::Traversed(&npub)
    );
    // A dual-stack socket reports an IPv4 source in its mapped form.
    assert_eq!(
        driver.mismatch_evidence(&t7, Some(endpoint("[::ffff:198.51.100.7]:4000")), unlinked),
        MismatchEvidence::Traversed(&npub)
    );
    let linked = |addr: &NodeAddr| addr == peer.node_addr();
    assert_eq!(
        driver.mismatch_evidence(&t7, Some(endpoint("198.51.100.7:4000")), linked),
        MismatchEvidence::AfterLink
    );
}

#[test]
fn note_linked_bootstraps_keeps_refusing_after_the_link_drops() {
    use super::MismatchEvidence;
    let peer = crate::PeerIdentity::from_pubkey(crate::Identity::generate().pubkey());
    let other = crate::PeerIdentity::from_pubkey(crate::Identity::generate().pubkey());
    let mut driver = driver_with_bootstrap(&peer);
    let t7 = crate::transport::TransportId::new(7);

    // A link to some other node latches nothing.
    driver.note_linked_bootstraps(|addr| addr == other.node_addr());
    assert!(matches!(
        driver.mismatch_evidence(&t7, Some(endpoint("198.51.100.7:4000")), |_| false),
        MismatchEvidence::Traversed(_)
    ));

    driver.note_linked_bootstraps(|addr| addr == peer.node_addr());
    assert_eq!(
        driver.mismatch_evidence(&t7, Some(endpoint("198.51.100.7:4000")), |_| false),
        MismatchEvidence::AfterLink,
        "the link has gone, but it was seen"
    );
}

/// The advert predicate is the three punch predicates plus the advert's own
/// reserved term. Each row gives the three punch predicates' verdict, taken
/// from the single disjunction the advert filter used before the split, and
/// the reserved term's.
#[test]
fn split_address_predicates_and_the_reserved_term_make_the_advert_predicate() {
    let cases = [
        ("127.0.0.1", true, false),
        ("::1", true, false),
        ("0.0.0.0", true, true),
        ("::", true, false),
        ("224.0.0.1", true, false),
        ("ff02::1", true, false),
        ("255.255.255.255", true, true),
        ("169.254.1.1", true, false),
        ("fe80::1", true, false),
        ("192.0.2.1", true, false),
        ("198.51.100.1", true, false),
        ("203.0.113.1", true, false),
        ("100.64.0.1", true, false),
        ("100.127.255.255", true, false),
        ("100.128.0.1", false, false),
        ("10.0.0.1", true, false),
        ("192.168.1.1", true, false),
        ("172.16.0.1", true, false),
        ("fd00::1", true, false),
        ("8.8.8.8", false, false),
        ("2001:4860:4860::8888", false, false),
        ("0.1.2.3", false, true),
        ("240.0.0.1", false, true),
        ("2001:db8::1", false, true),
        ("198.18.0.1", false, false),
    ];

    for (text, punch, reserved) in cases {
        let ip = text.parse::<IpAddr>().unwrap();
        assert_eq!(
            is_never_punchable_ip(ip) || is_private_ip(ip) || is_doc_ip(ip),
            punch,
            "the split predicates disagree with the old advert filter for {text}"
        );
        assert_eq!(is_reserved_ip(ip), reserved, "reserved term for {text}");
        assert_eq!(
            is_unroutable_direct_advert_ip(ip),
            punch || reserved,
            "unexpected advert verdict for {text}"
        );
    }
}

/// The documentation ranges are held out of the punch filter deliberately, so
/// that the reflexive addresses these tests and lab topologies use as public
/// stand-ins keep working. An advert must still not name one.
#[test]
fn documentation_addresses_are_punchable_but_not_advertisable() {
    let ip = "198.51.100.20".parse::<IpAddr>().unwrap();

    assert!(!is_never_punchable_ip(ip));
    assert!(!is_private_ip(ip));
    assert!(is_unroutable_direct_advert_ip(ip));
}

/// B4: strict-fresh path returns Fresh; the offer is well within TTL and
/// not expired.
#[test]
fn freshness_strict_returns_fresh_outcome() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        1_700_000_000_000,
        60_000,
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        Some(addr("203.0.113.10", 62000)),
        vec![addr("192.168.1.10", 62000)],
        Some("stun:example.org:3478".to_string()),
    );

    let result = validate_offer_freshness(
        &offer,
        1_700_000_000_500,
        60_000,
        "npub1client",
        "npub1server",
    )
    .expect("strict-fresh offer should validate");
    assert_eq!(result, FreshnessOutcome::Fresh);
}

/// B4: an offer whose `expires_at` has already passed by < SKEW_TOL is
/// accepted but flagged FreshWithinSkewTolerance — emulates the case where
/// the responder's clock is ahead of the initiator's.
#[test]
fn freshness_responder_clock_ahead_within_tolerance_is_tolerated() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        1_700_000_000_000,
        60_000, // expires_at = 1_700_000_060_000
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        Some(addr("203.0.113.10", 62000)),
        vec![addr("192.168.1.10", 62000)],
        None,
    );

    // now 90s past issued_at — 30s past strict expiry, but inside the 60s
    // SKEW_TOL grace.
    let result = validate_offer_freshness(
        &offer,
        1_700_000_090_000,
        60_000,
        "npub1client",
        "npub1server",
    )
    .expect("offer just past strict expiry should be tolerated");
    assert_eq!(result, FreshnessOutcome::FreshWithinSkewTolerance);
}

/// B4: an offer beyond TTL + SKEW_TOL is rejected as expired.
#[test]
fn freshness_responder_clock_far_ahead_is_rejected() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        1_700_000_000_000,
        60_000,
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        Some(addr("203.0.113.10", 62000)),
        vec![addr("192.168.1.10", 62000)],
        None,
    );

    // 130s past issued_at: 70s past strict expiry, 10s past tolerated expiry.
    let err = validate_offer_freshness(
        &offer,
        1_700_000_130_000,
        60_000,
        "npub1client",
        "npub1server",
    )
    .expect_err("offer past tolerated expiry should be rejected");
    assert!(err.to_string().contains("expired-offer"), "{}", err);
}

/// An offer dated far ahead of the local clock is rejected. The age term
/// saturates to zero for any future stamp, so nothing but the forward bound
/// can catch this.
#[test]
fn freshness_offer_dated_far_in_the_future_is_rejected() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        1_700_000_600_000,
        60_000,
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        Some(addr("203.0.113.10", 62000)),
        vec![addr("192.168.1.10", 62000)],
        None,
    );

    // Issued ten minutes ahead of the validating clock.
    let err = validate_offer_freshness(
        &offer,
        1_700_000_000_000,
        60_000,
        "npub1client",
        "npub1server",
    )
    .expect_err("offer dated far in the future should be rejected");
    assert!(err.to_string().contains("future-dated-offer"), "{}", err);
}

/// An offer dated slightly ahead of the local clock is accepted, but reports
/// the skew outcome so the operator-facing clock-skew log fires. It must not
/// report strict freshness.
#[test]
fn freshness_offer_dated_slightly_in_the_future_reports_skew_tolerance() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        1_700_000_010_000,
        60_000,
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        Some(addr("203.0.113.10", 62000)),
        vec![addr("192.168.1.10", 62000)],
        None,
    );

    // Issued 10s ahead, inside the 60s tolerance.
    let result = validate_offer_freshness(
        &offer,
        1_700_000_000_000,
        60_000,
        "npub1client",
        "npub1server",
    )
    .expect("offer inside the forward tolerance should be accepted");
    assert_eq!(result, FreshnessOutcome::FreshWithinSkewTolerance);
}

/// The wire `expires_at` cannot widen the window past the issuer's own stamp
/// plus our configured TTL. A sender declaring a 600s expiry gets the same
/// treatment at our 60s TTL boundary as one declaring 60s.
#[test]
fn freshness_ignores_an_expires_at_inflated_beyond_issued_at_plus_ttl() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        1_700_000_000_000,
        600_000, // expires_at = 1_700_000_600_000, ten times our TTL
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        Some(addr("203.0.113.10", 62000)),
        vec![addr("192.168.1.10", 62000)],
        None,
    );

    // Age exactly our TTL: the clamped expiry equals now, so strict freshness
    // cannot fire and the tolerated branch accepts.
    let result = validate_offer_freshness(
        &offer,
        1_700_000_060_000,
        60_000,
        "npub1client",
        "npub1server",
    )
    .expect("offer at the clamped expiry should still be tolerated");
    assert_eq!(result, FreshnessOutcome::FreshWithinSkewTolerance);
}

/// Pins the forward bound to `FRESHNESS_SKEW_TOLERANCE_MS` exactly: 60_000ms
/// ahead is accepted, 60_001ms ahead is not.
#[test]
fn freshness_offer_at_the_forward_skew_limit_is_accepted_and_one_ms_beyond_is_rejected() {
    let now = 1_700_000_000_000;
    let build = |issued: u64| {
        create_traversal_offer(
            "sess-1".to_string(),
            issued,
            60_000,
            "offer-1".to_string(),
            "npub1client".to_string(),
            "npub1server".to_string(),
            Some(addr("203.0.113.10", 62000)),
            vec![addr("192.168.1.10", 62000)],
            None,
        )
    };

    let at_limit = build(now + 60_000);
    let result = validate_offer_freshness(&at_limit, now, 60_000, "npub1client", "npub1server")
        .expect("offer exactly at the forward tolerance should be accepted");
    assert_eq!(result, FreshnessOutcome::FreshWithinSkewTolerance);

    let past_limit = build(now + 60_001);
    let err = validate_offer_freshness(&past_limit, now, 60_000, "npub1client", "npub1server")
        .expect_err("offer one millisecond past the forward tolerance should be rejected");
    assert!(err.to_string().contains("future-dated-offer"), "{}", err);
}

/// The forward bound covers the answer path too. The initiator is the side
/// that binds a socket and punches on an accepted answer, so a future-dated
/// answer is the more consequential half.
#[test]
fn freshness_answer_dated_far_in_the_future_is_rejected() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        1_700_000_000_000,
        60_000,
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        Some(addr("203.0.113.10", 62000)),
        vec![addr("192.168.1.10", 62000)],
        Some("stun:example.org:3478".to_string()),
    );
    let answer = create_traversal_answer(
        "sess-1".to_string(),
        1_700_000_600_000, // ten minutes ahead of the validating clock
        60_000,
        "answer-1".to_string(),
        "npub1server".to_string(),
        "npub1client".to_string(),
        "offer-1".to_string(),
        true,
        Some(addr("198.51.100.20", 63000)),
        vec![addr("192.168.1.20", 63000)],
        Some("stun:example.org:3478".to_string()),
        Some(PunchHint {
            start_at_ms: 1_700_000_002_000,
            interval_ms: 200,
            duration_ms: 10_000,
        }),
        None,
        Some(1_700_000_000_400),
    );

    let err = validate_traversal_answer_for_offer(
        &offer,
        &answer,
        1_700_000_000_900,
        60_000,
        "npub1server",
        "npub1client",
    )
    .expect_err("answer dated far in the future should be rejected");
    assert!(err.to_string().contains("future-dated-answer"), "{}", err);
}

/// The answer path re-checks our own offer, and a failure there must be
/// reported as the offer's, not the answer's, so the operator can tell a
/// backwards local clock step from a bad reply.
#[test]
fn answer_validation_reports_a_stale_offer_as_the_offers_own_failure() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        1_700_000_000_000,
        60_000,
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        Some(addr("203.0.113.10", 62000)),
        vec![addr("192.168.1.10", 62000)],
        None,
    );
    // The answer is issued now; only the offer is beyond TTL + tolerance.
    let now = 1_700_000_130_000;
    let answer = create_traversal_answer(
        "sess-1".to_string(),
        now,
        60_000,
        "answer-1".to_string(),
        "npub1server".to_string(),
        "npub1client".to_string(),
        "offer-1".to_string(),
        true,
        Some(addr("198.51.100.20", 63000)),
        vec![addr("192.168.1.20", 63000)],
        None,
        None,
        None,
        None,
    );

    let err = validate_traversal_answer_for_offer(
        &offer,
        &answer,
        now,
        60_000,
        "npub1server",
        "npub1client",
    )
    .expect_err("an offer past tolerated expiry should reject the round trip");
    assert!(
        err.to_string().contains("expired-offer-in-answer"),
        "{}",
        err
    );
}

/// Only the inbound-offer rejection classes that cannot be produced by relay
/// delivery lag escalate to a warning; a stale offer stays quiet.
#[test]
fn only_the_non_lag_offer_rejections_escalate_to_a_warning() {
    let protocol = |reason: &str| BootstrapError::Protocol(reason.to_string());

    assert!(adversarial_offer_reject(&protocol("future-dated-offer")));
    assert!(adversarial_offer_reject(&protocol("identity-mismatch")));
    assert!(adversarial_offer_reject(&protocol("invalid-offer")));

    assert!(!adversarial_offer_reject(&protocol("expired-offer")));
    assert!(!adversarial_offer_reject(&BootstrapError::Nostr(
        "relay unreachable".to_string()
    )));
}

/// B5a: the NTP-style skew estimator returns the responder's apparent
/// clock offset relative to the initiator. Symmetric one-way delays of
/// 50ms each plus a +500ms responder skew should yield ≈+500ms.
#[test]
fn estimate_clock_skew_matches_responder_offset() {
    // T1 (initiator sent)
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        1_700_000_000_000,
        60_000,
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        None,
        vec![addr("192.168.1.10", 62000)],
        None,
    );
    // Wire takes 50ms, responder clock is +500ms ahead, so:
    //   T2 = 1_700_000_000_000 + 50 + 500 = 1_700_000_000_550
    //   T3 = 1_700_000_000_550 (no processing time for this synthetic case)
    //   T4 = T1 + 50 + (T3 - T2 + 500_skew_corrected) + 50 wire return
    //      For simplicity: T4 = T1 + 100ms wire + 0 responder processing
    //                       = 1_700_000_000_100 (initiator wall clock)
    let answer = create_traversal_answer(
        "sess-1".to_string(),
        1_700_000_000_550, // T3
        60_000,
        "answer-1".to_string(),
        "npub1server".to_string(),
        "npub1client".to_string(),
        "offer-1".to_string(),
        true,
        Some(addr("198.51.100.20", 63000)),
        vec![],
        None,
        None,
        None,
        Some(1_700_000_000_550), // T2
    );
    let answer_received_at = 1_700_000_000_100; // T4

    let skew = estimate_clock_skew(&offer, &answer, answer_received_at)
        .expect("offer_received_at populated -> Some");
    // ((550 - 0) + (550 - 100)) / 2 = (550 + 450) / 2 = 500
    assert_eq!(skew, 500);
}

/// B5a: backward-compat — when the responder did not populate
/// `offer_received_at` (older daemon), skew estimation returns None
/// and callers should silently skip logging it.
#[test]
fn estimate_clock_skew_returns_none_without_responder_timestamp() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        1_700_000_000_000,
        60_000,
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        None,
        vec![],
        None,
    );
    let answer = create_traversal_answer(
        "sess-1".to_string(),
        1_700_000_000_500,
        60_000,
        "answer-1".to_string(),
        "npub1server".to_string(),
        "npub1client".to_string(),
        "offer-1".to_string(),
        true,
        Some(addr("198.51.100.20", 63000)),
        vec![],
        None,
        None,
        None,
        None, // older responder
    );
    assert!(estimate_clock_skew(&offer, &answer, 1_700_000_000_900).is_none());
}

#[tokio::test]
async fn signal_events_use_current_timestamps() {
    let sender = NodeSigner::new(nostr::key::SecretKey::generate());
    let receiver = NodeSigner::new(nostr::key::SecretKey::generate());
    let rumor = rumor(
        sender.public_key(),
        receiver.public_key(),
        "hello".to_string(),
        now_ms(),
    );
    let before = Timestamp::now().as_secs();

    let event = build_signal_event(
        &sender,
        receiver.public_key(),
        rumor,
        Timestamp::from(before + 30),
    )
    .expect("signal event should build");

    let after = Timestamp::now().as_secs();
    let created_at = event.created_at.as_secs();

    assert!(created_at >= before);
    assert!(created_at <= after);
}

#[test]
fn rank_punch_source_accepts_a_planned_target() {
    let target: SocketAddr = "198.51.100.20:63000".parse().unwrap();
    assert_eq!(rank_punch_source(target, &[target]), SourceRank::Planned);
}

#[test]
fn rank_punch_source_reports_a_planned_targets_other_port_as_remapped() {
    let target: SocketAddr = "198.51.100.20:63000".parse().unwrap();
    let remapped: SocketAddr = "198.51.100.20:41234".parse().unwrap();
    assert_eq!(
        rank_punch_source(remapped, &[target]),
        SourceRank::RemappedPort
    );
}

#[test]
fn rank_punch_source_rejects_an_address_we_never_planned_to_probe() {
    let target: SocketAddr = "198.51.100.20:63000".parse().unwrap();
    let stranger: SocketAddr = "203.0.113.9:63000".parse().unwrap();
    assert_eq!(
        rank_punch_source(stranger, &[target]),
        SourceRank::Unplanned
    );
}

fn node_addr(first_byte: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = first_byte;
    NodeAddr::from_bytes(bytes)
}

#[test]
fn responder_suppression_election() {
    let smaller = node_addr(0x01);
    let larger = node_addr(0x02);

    // Symmetric dual-auto_connect (co-active initiator on both sides):
    // both nodes must keep the session initiated by the smaller NodeAddr.

    // Smaller-addr node handling the larger node's offer: our own outbound
    // initiator (smaller) is preferred, so suppress this responder session.
    assert!(suppress_responder_for_own_initiator(
        &smaller, &larger, true
    ));

    // Larger-addr node handling the smaller node's offer: the smaller node's
    // session is preferred, so do NOT suppress — answer it.
    assert!(!suppress_responder_for_own_initiator(
        &larger, &smaller, true
    ));

    // Asymmetric / one-sided auto_connect: no co-active initiator means only
    // one session exists; never suppress, regardless of address ordering.
    assert!(!suppress_responder_for_own_initiator(
        &smaller, &larger, false
    ));
    assert!(!suppress_responder_for_own_initiator(
        &larger, &smaller, false
    ));

    // Self / loopback (equal addresses): never suppress.
    assert!(!suppress_responder_for_own_initiator(
        &smaller, &smaller, true
    ));
}

#[test]
fn now_ms_tracks_the_wall_clock() {
    use std::time::{SystemTime, UNIX_EPOCH};

    fn wall_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_millis() as u64
    }

    // Bracket a sample between two independent wall-clock reads taken either
    // side of it. This is the property the traversal clock has to hold for the
    // NIP-40 expiration tags it computes to be in the future when published.
    //
    // Read this for what it is: it pins the contract (Unix epoch, milliseconds,
    // tracking real time) and it fires on a host that has actually suspended,
    // where the sample falls below `before` by the suspend duration. It is NOT a
    // regression guard for the anchored-clock defect. Nothing reachable from a
    // unit test can simulate a suspend, so on a machine that has not slept, an
    // anchored implementation passes this -- deterministically when this is the
    // first caller of `now_ms()` in the binary, and otherwise with a probability
    // set by the fractional millisecond the anchor happened to capture.
    let before = wall_ms();
    let sampled = now_ms();
    let after = wall_ms();

    assert!(
        sampled >= before,
        "now_ms() is behind the wall clock: {sampled} < {before}"
    );
    assert!(
        sampled <= after,
        "now_ms() is ahead of the wall clock: {sampled} > {after}"
    );
}

fn pool(urls: &[&str]) -> HashSet<RelayUrl> {
    urls.iter()
        .map(|url| RelayUrl::parse(url).expect("test pool url parses"))
        .collect()
}

fn candidates(urls: &[&str]) -> Vec<String> {
    urls.iter().map(|url| url.to_string()).collect()
}

#[test]
fn out_of_pool_relay_does_not_suppress_the_shared_ones() {
    let usable = signal_relays(
        &candidates(&[
            "wss://relay.damus.io",
            "wss://temp.iris.to",
            "wss://nos.lol",
        ]),
        None,
        &[],
        &pool(&[
            "wss://relay.damus.io",
            "wss://nos.lol",
            "wss://offchain.pub",
        ]),
    );
    assert_eq!(
        usable,
        vec![
            "wss://relay.damus.io".to_string(),
            "wss://nos.lol".to_string()
        ],
        "the unknown relay must be dropped without taking the shared ones with it"
    );
}

#[test]
fn trailing_slash_and_host_case_variants_are_retained() {
    let usable = signal_relays(
        &candidates(&["wss://Relay.Damus.io/", "wss://nos.lol"]),
        None,
        &[],
        &pool(&["wss://relay.damus.io", "wss://nos.lol"]),
    );
    assert_eq!(
        usable.len(),
        2,
        "normalized spellings of a configured relay are the same relay: {usable:?}"
    );
}

#[test]
fn duplicates_that_normalize_alike_are_collapsed() {
    let usable = signal_relays(
        &candidates(&["wss://nos.lol", "wss://nos.lol/", "wss://NOS.LOL"]),
        None,
        &[],
        &pool(&["wss://nos.lol"]),
    );
    assert_eq!(usable, vec!["wss://nos.lol".to_string()]);
}

#[test]
fn unparseable_candidates_are_dropped_rather_than_failing_the_set() {
    let usable = signal_relays(
        &candidates(&["not a url", "wss://nos.lol"]),
        None,
        &[],
        &pool(&["wss://nos.lol"]),
    );
    assert_eq!(usable, vec!["wss://nos.lol".to_string()]);
}

#[test]
fn no_shared_relay_yields_an_empty_set_for_the_caller_to_reject() {
    let usable = signal_relays(
        &candidates(&["wss://temp.iris.to"]),
        None,
        &[],
        &pool(&["wss://nos.lol"]),
    );
    assert!(
        usable.is_empty(),
        "with no overlap the caller must see nothing to send to, not a doomed send"
    );
}

#[test]
fn signal_relays_merges_all_three_sources_then_filters() {
    let usable = signal_relays(
        &candidates(&["wss://temp.iris.to", "wss://nos.lol"]),
        Some(&candidates(&[
            "wss://relay.damus.io",
            "wss://unknown.example",
        ])),
        &candidates(&["wss://offchain.pub"]),
        &pool(&[
            "wss://nos.lol",
            "wss://relay.damus.io",
            "wss://offchain.pub",
        ]),
    );
    assert_eq!(
        usable,
        vec![
            "wss://nos.lol".to_string(),
            "wss://relay.damus.io".to_string(),
            "wss://offchain.pub".to_string(),
        ],
        "every source must contribute, and only the out-of-pool entries drop out"
    );
}

#[test]
fn signal_relays_keeps_our_dm_relays_when_the_peer_shares_nothing() {
    let usable = signal_relays(
        &candidates(&["wss://temp.iris.to"]),
        Some(&candidates(&["wss://also.unknown"])),
        &candidates(&["wss://nos.lol"]),
        &pool(&["wss://nos.lol"]),
    );
    assert_eq!(
        usable,
        vec!["wss://nos.lol".to_string()],
        "our own DM relays are always in the pool, so the result is never empty \
         while any are configured"
    );
}

#[test]
fn signal_relays_without_an_advert_still_resolves() {
    let usable = signal_relays(
        &candidates(&["wss://nos.lol", "wss://temp.iris.to"]),
        None,
        &candidates(&["wss://offchain.pub"]),
        &pool(&["wss://nos.lol", "wss://offchain.pub"]),
    );
    assert_eq!(
        usable,
        vec![
            "wss://nos.lol".to_string(),
            "wss://offchain.pub".to_string()
        ],
        "the responder path passes no advert and must still produce a target set"
    );
}

/// A `JoinHandle` for a task that has definitely completed. Yields until the
/// runtime has polled the no-op task to completion, so `is_finished()` is
/// deterministically `true` on return.
async fn finished_handle() -> tokio::task::JoinHandle<()> {
    let handle = tokio::spawn(async {});
    while !handle.is_finished() {
        tokio::task::yield_now().await;
    }
    handle
}

/// A `JoinHandle` for a task that never completes.
fn live_handle() -> tokio::task::JoinHandle<()> {
    tokio::spawn(std::future::pending::<()>())
}

#[tokio::test]
async fn nostr_liveness_fires_when_the_pump_dies() {
    let runtime = NostrRendezvous::new_for_test();
    runtime
        .install_task_handle_for_test(finished_handle().await)
        .await;
    assert!(
        runtime.is_finished(),
        "a dead pump means no advert or traversal signal is ever handled again"
    );
}

/// `shutdown` takes the handle, leaving `None`. That must read as finished so
/// the 2s liveness poll monitor terminates instead of spinning after a stop.
#[tokio::test]
async fn nostr_liveness_reports_finished_once_the_handles_are_taken() {
    let runtime = NostrRendezvous::new_for_test();
    runtime.install_task_handle_for_test(live_handle()).await;
    assert!(!runtime.is_finished(), "control: a live pump reads as live");
    runtime.take_task_handle_for_test().await;
    assert!(
        runtime.is_finished(),
        "no installed handles (post-shutdown) reads as finished"
    );
}

#[test]
fn short_id_truncates_a_multibyte_session_id_on_a_character_boundary_without_panicking() {
    // The session id arrives as an unvalidated string in a remote party's JSON,
    // so a byte-index slice can land inside a multi-byte character. Byte 8 of
    // this input is the middle of the euro sign.
    assert_eq!(short_id("aaaaaaa\u{20AC}zzzz"), "aaaaaaa\u{20AC}");
    // Ascii behaviour is unchanged: long truncates to eight, short passes through.
    assert_eq!(short_id("abcdefghij"), "abcdefgh");
    assert_eq!(short_id("abc"), "abc");
    assert_eq!(short_id(""), "");
}

/// A stale-advert refetch that finds a newer, valid advert by the peer on
/// the advert relays caches it in place of the older one: the only refetch
/// outcome that runs the full ingest check.
#[tokio::test(flavor = "multi_thread")]
async fn a_refetch_that_finds_a_newer_advert_refreshes_the_cached_entry() {
    use nostr::key::SecretKey;
    use nostr::nips::nip19::ToBech32;
    use nostr_sdk::local_relay::LocalRelay;

    let relay = LocalRelay::builder().build();
    relay.run().await.expect("the in-process relay starts");
    let url = relay.url().await.to_string();

    let peer = NodeSigner::new(
        SecretKey::from_hex("b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef")
            .unwrap(),
    );
    let peer_npub = peer.public_key().to_bech32().unwrap();
    let now_secs = now_ms() / 1_000;
    let runtime = NostrRendezvous::new_for_test();
    let config = crate::config::NostrRendezvousConfig::default();
    let body = OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: ADVERT_VERSION,
        endpoints: vec![OverlayEndpointAdvert {
            transport: OverlayTransportKind::Tcp,
            addr: "8.8.8.8:443".to_string(),
        }],
        signal_relays: None,
        stun_servers: None,
    };
    let newer = super::machine::event::advert::advert_event(
        &peer,
        serde_json::to_string(&body).unwrap(),
        ADVERT_IDENTIFIER,
        &config.app,
        config.advert_ttl_secs,
        now_secs * 1_000,
        [0u8; 32],
    )
    .unwrap();
    let publisher = nostr_sdk::client::ClientBuilder::new().build();
    publisher.add_relay(url.as_str()).await.unwrap();
    publisher.connect().await;
    publisher
        .send_event(&newer)
        .await
        .expect("the relay stores the advert");

    runtime.set_advert_relays_for_test(vec![url]).await;
    let older = NostrRendezvous::cached_advert_for_test(
        peer_npub.clone(),
        OverlayEndpointAdvert {
            transport: OverlayTransportKind::Tcp,
            addr: "203.0.113.11:443".to_string(),
        },
        now_secs - 100,
    );
    runtime
        .insert_advert_for_test(peer_npub.clone(), older)
        .await;

    let outcome = runtime.refetch_advert_for_stale_check(&peer_npub).await;
    assert_eq!(outcome, crate::nostr::NostrRefetchOutcome::Refreshed);
    assert_eq!(
        runtime.cached_created_at_for_test(&peer_npub).await,
        Some(now_secs),
        "the newer advert did not replace the cached one"
    );
}

/// The cache read path intake uses parses a peer's npub as it always has,
/// which differs from every other advert entry point: it finds an advert
/// from the lower-case npub and from the key in hex, and not from the npub
/// in upper case, where the dial path finds it from either case and refuses
/// hex as not a NIP-19 npub.
#[tokio::test]
async fn cached_endpoints_parses_the_npub_as_the_cache_read_did() {
    use nostr::nips::nip19::ToBech32;
    let runtime = NostrRendezvous::new_for_test();
    let keys = nostr::key::Keys::generate();
    let npub = keys.public_key().to_bech32().unwrap();
    let hex = keys.public_key().to_hex();
    let endpoint = OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: "203.0.113.7:2121".to_string(),
    };
    let advert =
        NostrRendezvous::cached_advert_for_test(npub.clone(), endpoint.clone(), now_ms() / 1_000);
    runtime.insert_advert_for_test(npub.clone(), advert).await;

    assert_eq!(
        runtime.cached_endpoints(&npub).await,
        Some(vec![endpoint.clone()])
    );
    assert_eq!(
        runtime.cached_endpoints(&hex).await,
        Some(vec![endpoint.clone()]),
        "the cache read takes the key in hex"
    );
    assert_eq!(
        runtime.cached_endpoints(&npub.to_uppercase()).await,
        None,
        "the cache read does not take an upper-case npub"
    );

    assert!(matches!(
        runtime.advert_endpoints_for_peer(&npub).await,
        Ok(found) if found == vec![endpoint.clone()]
    ));
    assert!(matches!(
        runtime.advert_endpoints_for_peer(&npub.to_uppercase()).await,
        Ok(found) if found == vec![endpoint.clone()]
    ));
    assert!(matches!(
        runtime.advert_endpoints_for_peer(&hex).await,
        Err(BootstrapError::InvalidPeerNpub { .. })
    ));
}

/// The advert cache holds adverts under the canonical lower-case npub, and
/// a configured npub may be written in upper case. Resolving that peer's
/// advert finds the cached entry instead of missing it and going to the
/// relays.
#[tokio::test]
async fn an_upper_case_configured_npub_resolves_its_cached_advert() {
    let runtime = NostrRendezvous::new_for_test();
    let npub = crate::encode_npub(&crate::Identity::generate().pubkey());
    let endpoint = OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: "203.0.113.7:2121".to_string(),
    };
    let now_secs = now_ms() / 1_000;
    let advert = NostrRendezvous::cached_advert_for_test(npub.clone(), endpoint.clone(), now_secs);
    runtime.insert_advert_for_test(npub.clone(), advert).await;

    // Control: the canonical form resolves from the cache.
    let endpoints = runtime
        .advert_endpoints_for_peer(&npub)
        .await
        .expect("canonical npub resolved");
    assert_eq!(endpoints, vec![endpoint.clone()]);

    let endpoints = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        runtime.advert_endpoints_for_peer(&npub.to_uppercase()),
    )
    .await
    .expect("resolution finished")
    .expect("cached advert resolved");
    assert_eq!(endpoints, vec![endpoint]);
}

fn offer_between(session: &str, from: &str, to: &str) -> super::TraversalOffer {
    create_traversal_offer(
        session.to_string(),
        now_ms(),
        30_000,
        session.to_string(),
        from.to_string(),
        to.to_string(),
        Some(addr("203.0.113.7", 40000)),
        Vec::new(),
        None,
    )
}

/// A NIP-42 authenticator that answers a relay's challenge with an
/// authentication event signed directly by `signer`, created now, with fresh
/// randomness for its signature: the node's answer, without the pump.
#[derive(Debug)]
pub(super) struct SignerAuthenticator {
    pub(super) signer: std::sync::Arc<NodeSigner>,
}

impl nostr_sdk::authenticator::Authenticator for SignerAuthenticator {
    fn make_auth_event<'a>(
        &'a self,
        relay_url: &'a nostr::types::RelayUrl,
        challenge: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<nostr::event::Event, nostr_sdk::error::Error>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            super::machine::event::auth::auth_event(
                &self.signer,
                relay_url,
                challenge,
                now_ms(),
                super::relay::aux(),
            )
            .map_err(|e| nostr_sdk::error::Error::other(e.to_string()))
        })
    }
}

// --- advert cache: an entry past its horizon keeps its slot for a grace ---

mod advert_lapse {
    use fips_core::utils::hash::KeyedHasher;

    use super::super::machine::adverts::cache::{AdvertAdmission, Cache};
    use super::super::machine::params::Params;
    use super::super::machine::tests::{SeededEntropy, TestInstant, ZeroEntropy};
    use super::{ADVERT_IDENTIFIER, ADVERT_VERSION, OverlayAdvert, OverlayEndpointAdvert};
    use super::{OverlayTransportKind, nostr_config_with_refresh};

    const T0: u64 = 1_000_000_000;
    /// The advert horizon an honest author's event gives (`advert_ttl_secs`).
    const HORIZON: u64 = 3_600_000;
    /// One republish interval (`advert_refresh_secs`), the grace.
    const REFRESH: u64 = 1_800_000;

    fn advert() -> OverlayAdvert {
        OverlayAdvert {
            identifier: ADVERT_IDENTIFIER.to_string(),
            version: ADVERT_VERSION,
            endpoints: vec![OverlayEndpointAdvert {
                transport: OverlayTransportKind::Udp,
                addr: "203.0.113.7:9000".to_string(),
            }],
            signal_relays: None,
            stun_servers: None,
        }
    }

    /// A cache of `cap` entries with one republish interval of grace, as the
    /// runtime builds it.
    fn cache(cap: usize) -> Cache<TestInstant> {
        Cache::new(
            "npub1self".to_string(),
            cap,
            KeyedHasher::new::<ZeroEntropy>(),
        )
        .with_lapse_grace(REFRESH)
    }

    fn offer(
        m: &mut Cache<TestInstant>,
        npub: &str,
        created_at: u64,
        valid_until_ms: u64,
        now_ms: u64,
    ) -> AdvertAdmission {
        m.observe_advert(npub, advert(), created_at, valid_until_ms, now_ms)
    }

    /// A cache held full by a flood, with the honest author admitted first.
    /// Flood adverts omit the expiration tag, so they carry twice the horizon.
    fn flooded(cap: usize) -> Cache<TestInstant> {
        let mut m = cache(cap);
        assert_eq!(
            offer(&mut m, "npub1honest", 1, T0 + HORIZON, T0),
            AdvertAdmission::Admitted
        );
        for i in 1..cap {
            let key = format!("npub1flood{i}");
            assert_eq!(
                offer(&mut m, &key, 1, T0 + 2 * HORIZON, T0),
                AdvertAdmission::Admitted
            );
        }
        m
    }

    /// The honest author misses one republish, so its entry passes its
    /// horizon while a flood keeps the cache full. Its next advert must take
    /// its slot back rather than be refused as a newcomer's.
    #[test]
    fn an_honest_author_that_misses_one_republish_during_a_flood_keeps_its_slot() {
        let mut m = flooded(4);
        let lapsed = T0 + HORIZON + 1;
        let _ = m.prune(lapsed);
        let late = offer(&mut m, "npub1flood-late", 1, lapsed + 2 * HORIZON, lapsed);

        let republished = T0 + HORIZON + REFRESH / 2;
        let _ = m.prune(republished);
        assert_eq!(
            offer(&mut m, "npub1honest", 2, republished + HORIZON, republished),
            AdvertAdmission::Updated,
            "the honest author's next advert takes its slot back"
        );
        assert!(m.cached_advert("npub1honest", republished).is_some());
        assert!(
            matches!(late, AdvertAdmission::Refused { .. }),
            "a flood key took the lapsed slot: {late:?}"
        );
    }

    /// The slot an honest author takes back keeps its admission order, so a
    /// protected author arriving later still displaces the newest flood key
    /// rather than the returning author.
    #[test]
    fn a_returning_author_keeps_its_admission_order() {
        let mut m = flooded(4);
        let republished = T0 + HORIZON + 1;
        let _ = m.prune(republished);
        assert_eq!(
            offer(&mut m, "npub1honest", 2, republished + HORIZON, republished),
            AdvertAdmission::Updated
        );
        m.set_protected(["npub1configured".to_string()]);
        assert_eq!(
            offer(
                &mut m,
                "npub1configured",
                1,
                republished + HORIZON,
                republished
            ),
            AdvertAdmission::Admitted
        );
        assert!(m.cached_created_at("npub1honest").is_some());
        assert!(
            m.cached_created_at("npub1flood3").is_none(),
            "the most recently admitted flood key makes room"
        );
    }

    /// An entry in its grace holds its slot but serves nothing: neither the
    /// dial path's cache lookup nor open discovery sees it.
    #[test]
    fn a_lapsed_advert_is_served_to_neither_the_dial_path_nor_open_discovery() {
        let mut m = flooded(4);
        let lapsed = T0 + HORIZON + 1;
        let _ = m.prune(lapsed);

        assert!(m.cached_created_at("npub1honest").is_some(), "slot kept");
        assert!(m.cached_advert("npub1honest", lapsed).is_none());
        SeededEntropy::seed(3);
        let window = m.open_discovery_candidates::<SeededEntropy>(64, lapsed, |_| false);
        assert!(
            window.iter().all(|(npub, _, _)| npub != "npub1honest"),
            "a lapsed entry was offered to open discovery"
        );
        assert_eq!(window.len(), 3, "the live entries are still offered");

        // A protected author's lapsed entry is not served either.
        m.set_protected(["npub1honest".to_string()]);
        SeededEntropy::seed(3);
        let window = m.open_discovery_candidates::<SeededEntropy>(64, lapsed, |_| false);
        assert!(window.iter().all(|(npub, _, _)| npub != "npub1honest"));
    }

    /// Once the grace has passed without a republish, the slot frees as it
    /// did before, and a newcomer is admitted.
    #[test]
    fn a_lapsed_slot_frees_once_one_republish_interval_has_passed() {
        let mut m = flooded(4);
        let still_lapsed = T0 + HORIZON + REFRESH - 1;
        let report = m.prune(still_lapsed);
        assert_eq!(report.expired, 0);
        assert!(m.cached_created_at("npub1honest").is_some());

        let gone = T0 + HORIZON + REFRESH;
        let report = m.prune(gone);
        assert_eq!(report.expired, 1);
        assert!(m.cached_created_at("npub1honest").is_none());
        assert_eq!(
            offer(&mut m, "npub1newcomer", 1, gone + HORIZON, gone),
            AdvertAdmission::Admitted
        );
    }

    /// A protected author arriving at a cache full of live and lapsed entries
    /// is admitted as before, taking the newest unprotected entry's slot.
    #[test]
    fn a_protected_author_still_makes_room_while_an_entry_is_lapsed() {
        let mut m = flooded(4);
        let lapsed = T0 + HORIZON + 1;
        let _ = m.prune(lapsed);
        m.set_protected(["npub1configured".to_string()]);
        assert_eq!(
            offer(&mut m, "npub1configured", 1, lapsed + HORIZON, lapsed),
            AdvertAdmission::Admitted
        );
        assert!(m.cached_created_at("npub1configured").is_some());
        assert!(m.cached_created_at("npub1flood3").is_none());
        assert!(
            m.cached_created_at("npub1honest").is_some(),
            "the lapsed honest entry keeps its slot"
        );
    }

    /// The runtime gives the cache one republish interval of grace, taken
    /// from this node's own `advert_refresh_secs`.
    #[test]
    fn the_runtime_takes_the_grace_from_the_advert_refresh_interval() {
        let m = super::super::machine::rendezvous::advert_cache::<
            crate::time::HostInstant,
            crate::identity::OsEntropy,
        >(
            "npub1self".to_string(),
            &Params::from(&nostr_config_with_refresh(1_200)),
        );
        assert_eq!(m.lapse_grace_ms(), 1_200_000);
    }
}

/// The default Nostr discovery configuration with `advert_refresh_secs` set.
fn nostr_config_with_refresh(secs: u64) -> crate::config::NostrRendezvousConfig {
    crate::config::NostrRendezvousConfig {
        advert_refresh_secs: secs,
        ..Default::default()
    }
}

/// A kind 10050 inbox relay list carrying `tags`, signed by a fresh key.
fn inbox_list_with_tags(tags: Vec<Tag>) -> nostr::event::Event {
    EventBuilder::new(Kind::InboxRelays, "")
        .tags(tags)
        .finalize(&nostr::key::Keys::generate())
        .unwrap()
}

/// `url` as the relay pool normalizes it.
fn normalized(url: &str) -> String {
    RelayUrl::parse(url).unwrap().to_string()
}

/// The NIP-17 `relay` tag form is read.
#[test]
fn an_inbox_relay_list_in_the_nip17_relay_form_is_still_read() {
    let event = signed_inbox_relay_event(
        &nostr::key::Keys::generate(),
        Timestamp::now().as_secs(),
        "wss://relay.example",
    );
    assert_eq!(
        inbox_relays(&event),
        vec![normalized("wss://relay.example")]
    );
}

/// A relay named in both tag forms is listed once.
#[test]
fn an_inbox_relay_list_naming_one_relay_in_both_tag_forms_lists_it_once() {
    let url = "wss://relay.example";
    let event = inbox_list_with_tags(vec![
        Tag::custom("relay", [RelayUrl::parse(url).unwrap().to_string()]),
        Tag::parse(["r", url]).unwrap(),
    ]);
    assert_eq!(inbox_relays(&event), vec![normalized(url)]);
}

/// An `r` tag with a read or write marker is a NIP-65 relay entry, not an
/// inbox relay, and is not read.
#[test]
fn an_r_tag_carrying_a_marker_is_not_read_as_an_inbox_relay() {
    let event = inbox_list_with_tags(vec![
        Tag::parse(["r", "wss://relay.example", "write"]).unwrap(),
    ]);
    assert!(inbox_relays(&event).is_empty());
}

/// Only a kind 10050 event is read as an inbox relay list. A relay can answer
/// the lookup with another event the target signed, such as its NIP-65 relay
/// list (kind 10002), whose bare `r` tags would otherwise read as inbox relays.
#[test]
fn an_event_of_another_kind_is_not_read_as_an_inbox_relay_list() {
    let event = EventBuilder::new(Kind::RelayList, "")
        .tags(vec![Tag::parse(["r", "wss://relay.example"]).unwrap()])
        .finalize(&nostr::key::Keys::generate())
        .unwrap();
    assert!(inbox_relays(&event).is_empty());
}

/// Each machine setting is copied from its own configuration key: every key
/// gets a distinct value, so two fields swapped in the conversion cannot both
/// read right.
#[test]
fn the_machine_params_copy_each_value_from_its_own_config_key() {
    let config = crate::config::NostrRendezvousConfig {
        failure_streak_threshold: 7,
        extended_cooldown_secs: 11,
        warn_log_interval_secs: 13,
        failure_state_max_entries: 17,
        replay_window_secs: 19,
        seen_sessions_max_entries: 23,
        advertise: false,
        advert_cache_max_entries: 29,
        advert_refresh_secs: 31,
        app: "app-37".to_string(),
        advert_relays: vec!["wss://adverts-41.example".to_string()],
        dm_relays: vec!["wss://dm-43.example".to_string()],
        stun_servers: vec!["stun:stun-47.example:3478".to_string()],
        advert_ttl_secs: 53,
        signal_ttl_secs: 59,
        attempt_timeout_secs: 61,
        punch_start_delay_ms: 67,
        punch_interval_ms: 71,
        punch_duration_ms: 73,
        share_local_candidates: true,
        protocol_mismatch_cooldown_secs: 79,
        max_concurrent_incoming_offers: 83,
        max_concurrent_offers_per_npub: 89,
        ..Default::default()
    };
    let params = Params::from(&config);
    assert_eq!(params.failure_streak_threshold, 7);
    assert_eq!(params.extended_cooldown_secs, 11);
    assert_eq!(params.warn_log_interval_secs, 13);
    assert_eq!(params.failure_state_max_entries, 17);
    assert_eq!(params.replay_window_secs, 19);
    assert_eq!(params.seen_sessions_max_entries, 23);
    assert!(!params.advertise);
    assert_eq!(params.advert_cache_max_entries, 29);
    assert_eq!(params.advert_refresh_secs, 31);
    assert_eq!(params.app, "app-37");
    assert_eq!(params.advert_relays, vec!["wss://adverts-41.example"]);
    assert_eq!(params.dm_relays, vec!["wss://dm-43.example"]);
    assert_eq!(params.stun_servers, vec!["stun:stun-47.example:3478"]);
    assert_eq!(params.advert_ttl_secs, 53);
    assert_eq!(params.signal_ttl_secs, 59);
    assert_eq!(params.attempt_timeout_secs, 61);
    assert_eq!(params.punch_start_delay_ms, 67);
    assert_eq!(params.punch_interval_ms, 71);
    assert_eq!(params.punch_duration_ms, 73);
    assert!(params.share_local_candidates);
    assert_eq!(params.protocol_mismatch_cooldown_secs, 79);
    assert_eq!(params.max_concurrent_incoming_offers, 83);
    assert_eq!(params.max_concurrent_offers_per_npub, 89);
    // The flags' other values too, so a conversion that ignores one fails.
    let config = crate::config::NostrRendezvousConfig {
        advertise: true,
        share_local_candidates: false,
        ..config
    };
    assert!(Params::from(&config).advertise);
    assert!(!Params::from(&config).share_local_candidates);
}

mod clock_skew;
mod fixtures;
mod inbox_read;
mod notify_channels;
mod npub_spelling;
mod punch_recv_error;
mod seen_session_cap;
mod seen_session_floor;
mod signal_bounds;
mod signal_lag;
mod unknown_transport;

/// The failure reply carries the Unix time the decision was computed at,
/// and its cooldown is measured from that time, so the node's reported
/// cooldown and retry schedule start where the cooldown does.
#[tokio::test]
async fn the_failure_reply_carries_the_time_it_was_computed_at() {
    let config = crate::config::NostrRendezvousConfig {
        failure_streak_threshold: 1,
        extended_cooldown_secs: 600,
        ..Default::default()
    };
    let runtime = NostrRendezvous::new_for_test_with_config(config);
    let peer_npub = crate::Identity::generate().npub();
    let before = now_ms();
    let reply = runtime.record_traversal_failure(&peer_npub).await;
    let after = now_ms();
    assert!(
        (before..=after).contains(&reply.at_ms),
        "the reply's time {} is not when it was computed ({before}..={after})",
        reply.at_ms
    );
    assert_eq!(reply.decision.consecutive_failures, 1);
    assert_eq!(
        reply.decision.cooldown_until_ms,
        Some(reply.at_ms + 600_000),
        "the cooldown is not measured from the reply's time"
    );
    assert_eq!(
        runtime.cooldown_until(&peer_npub, reply.at_ms),
        Some(reply.at_ms + 600_000),
        "the status the node reads does not hold the cooldown"
    );
}
