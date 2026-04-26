use nostr::prelude::{EventBuilder, Kind, Tag, Timestamp};

use super::runtime::NostrDiscovery;
use super::signal::{
    build_signal_event, create_traversal_answer, create_traversal_offer, validate_offer_freshness,
    validate_traversal_answer_for_offer,
};
use super::stun::{parse_stun_binding_success, parse_stun_url};
use super::traversal::{
    PunchStrategy, build_punch_packet, parse_punch_packet, plan_punch_targets,
    planned_remote_endpoints, session_hash,
};
use super::{
    ADVERT_IDENTIFIER, ADVERT_KIND, ADVERT_VERSION, OverlayAdvert, OverlayEndpointAdvert,
    OverlayTransportKind, PunchHint, PunchPacketKind, TraversalAddress,
};

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

fn signed_overlay_advert_event(created_at_secs: u64, expiration_secs: Option<u64>) -> nostr::Event {
    let keys = nostr::Keys::generate();
    let content = r#"{"identifier":"fips-overlay-v1","version":1,"endpoints":[{"transport":"tcp","addr":"203.0.113.10:443"}]}"#;
    let mut builder = EventBuilder::new(Kind::Custom(ADVERT_KIND), content)
        .custom_created_at(Timestamp::from(created_at_secs));
    if let Some(expiration_secs) = expiration_secs {
        builder = builder.tags([Tag::expiration(Timestamp::from(expiration_secs))]);
    }
    builder.sign_with_keys(&keys).unwrap()
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
    assert!(NostrDiscovery::validate_overlay_advert(missing_nat_metadata).is_err());

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
    assert!(NostrDiscovery::validate_overlay_advert(wrong_identifier).is_err());
}

#[test]
fn advert_freshness_rejects_expired_events() {
    let now_secs = Timestamp::now().as_secs();
    let event = signed_overlay_advert_event(now_secs, Some(now_secs.saturating_sub(1)));
    let valid_until =
        NostrDiscovery::compute_advert_valid_until_ms(&event, 600_000, now_secs * 1000);
    assert!(valid_until.is_none());
}

#[test]
fn advert_freshness_rejects_stale_created_at_without_expiration() {
    let now_secs = Timestamp::now().as_secs();
    let stale_created = now_secs.saturating_sub(10_000);
    let event = signed_overlay_advert_event(stale_created, None);
    let valid_until =
        NostrDiscovery::compute_advert_valid_until_ms(&event, 600_000, now_secs * 1000);
    assert!(valid_until.is_none());
}

#[test]
fn advert_freshness_uses_earliest_expiration_bound() {
    let now_secs = Timestamp::now().as_secs();
    let event = signed_overlay_advert_event(now_secs.saturating_sub(10), Some(now_secs + 30));
    let valid_until =
        NostrDiscovery::compute_advert_valid_until_ms(&event, 3_600_000, now_secs * 1000)
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
    let planned = plan_punch_targets(
        &[addr("192.168.1.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("192.168.1.20", 63000)],
        Some(&addr("198.51.100.20", 63000)),
    );

    assert_eq!(planned[0].strategy, PunchStrategy::Reflexive);
    assert_eq!(planned[1].strategy, PunchStrategy::Lan);
}

#[test]
fn simulated_lan_scenario_includes_lan_target_and_succeeds() {
    let planned = plan_punch_targets(
        &[addr("192.168.1.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("192.168.1.20", 63000)],
        Some(&addr("198.51.100.20", 63000)),
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
    let planned = plan_punch_targets(
        &[addr("10.0.0.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("10.0.1.10", 63000)],
        Some(&addr("198.51.100.20", 63000)),
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
    let endpoints = planned_remote_endpoints(
        &[addr("192.168.1.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("192.168.1.20", 63000)],
        Some(&addr("198.51.100.20", 63000)),
    )
    .expect("endpoint planning should succeed");

    assert!(endpoints.contains(&"192.168.1.20:63000".parse().unwrap()));
    assert!(endpoints.contains(&"198.51.100.20:63000".parse().unwrap()));
}

#[tokio::test]
async fn signal_events_use_current_timestamps() {
    let sender = nostr::Keys::generate();
    let receiver = nostr::Keys::generate();
    let rumor = EventBuilder::private_msg_rumor(receiver.public_key(), "hello".to_string())
        .build(sender.public_key());
    let before = Timestamp::now().as_secs();

    let event = build_signal_event(
        &sender,
        receiver.public_key(),
        rumor,
        Timestamp::from(before + 30),
    )
    .await
    .expect("signal event should build");

    let after = Timestamp::now().as_secs();
    let created_at = event.created_at.as_secs();

    assert!(created_at >= before);
    assert!(created_at <= after);
}
