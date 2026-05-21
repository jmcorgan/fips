use nostr::prelude::{EventBuilder, Kind, Tag, Timestamp};

use super::runtime::NostrDiscovery;
use super::signal::{
    FreshnessOutcome, build_signal_event, create_traversal_answer, create_traversal_offer,
    estimate_clock_skew, validate_offer_freshness, validate_traversal_answer_for_offer,
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
    let content = r#"{"identifier":"fips-overlay-v1-next","version":1,"endpoints":[{"transport":"tcp","addr":"203.0.113.10:443"}]}"#;
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

    let validated = NostrDiscovery::validate_overlay_advert(advert).unwrap();
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

    let err = NostrDiscovery::validate_overlay_advert(advert).unwrap_err();
    assert!(err.to_string().contains("missing publicly routable"));
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
