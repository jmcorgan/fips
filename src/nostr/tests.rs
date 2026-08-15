use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use nostr::prelude::{EventBuilder, Kind, RelayUrl, Tag, Timestamp};

use super::runtime::{
    NostrRendezvous, adversarial_offer_reject, is_unroutable_direct_advert_ip, short_id,
    signal_relays,
};
use super::signal::{
    FreshnessOutcome, build_signal_event, create_traversal_answer, create_traversal_offer,
    estimate_clock_skew, validate_offer_freshness, validate_traversal_answer_for_offer,
};
use super::stun::{parse_stun_binding_success, parse_stun_url};
use super::traversal::{
    PunchStrategy, build_punch_packet, is_doc_ip, is_never_punchable_ip, is_private_ip, now_ms,
    parse_punch_packet, plan_punch_targets, planned_remote_endpoints, session_hash,
};
use super::traversal_machine::suppress_responder_for_own_initiator;
use super::types::BootstrapError;
use super::{
    ADVERT_IDENTIFIER, ADVERT_KIND, ADVERT_VERSION, OverlayAdvert, OverlayEndpointAdvert,
    OverlayTransportKind, PunchHint, PunchPacketKind, TraversalAddress,
};
use crate::NodeAddr;

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
/// The local address is a ULA so `lan_refs` is non-empty and `same_subnet_24`
/// is genuinely called with two IPv6 strings. It splits on `.` and requires
/// four parts, so no IPv6 candidate can ever satisfy the /24 gate and
/// `fd00::1` is refused off-subnet rather than admitted.
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
    )
    .expect("endpoint planning should succeed");

    assert_eq!(
        endpoints,
        vec!["198.51.100.20:63000".parse::<SocketAddr>().unwrap()]
    );
    assert_eq!(tally.unroutable, 300);
    assert_eq!(tally.admitted, 1);
    assert!(tally.suspicious());
}

/// Guards the deployment whose STUN server sits inside the private network,
/// so the observed reflexive address is itself private. Applying the /24 gate
/// to a peer's reflexive address would drop it and remove the only branch
/// that works across arbitrary NATs; this test reds if anyone does that.
#[test]
fn planned_remote_endpoints_keep_private_reflexive_when_stun_is_on_the_lan() {
    let (endpoints, _tally) = planned_remote_endpoints(
        &[],
        Some(&addr("192.168.1.10", 62000)),
        &[],
        Some(&addr("192.168.1.20", 63000)),
    )
    .expect("endpoint planning should succeed");

    assert!(endpoints.contains(&"192.168.1.20:63000".parse().unwrap()));
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
    );
    assert_eq!(clean.offsubnet, 0);
    assert!(!clean.suspicious());

    let (_planned, off_subnet) = plan_punch_targets(
        &[addr("192.168.1.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("10.9.9.9", 63000)],
        Some(&addr("198.51.100.20", 63000)),
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
    );

    assert!(planned.is_empty());
    assert_eq!(tally.admitted, 0);
    assert_eq!(tally.unroutable, 2);
    assert!(tally.suspicious());
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
    );

    assert_eq!(tally.reflexive, Some("never-routable"));
    assert_eq!(tally.unroutable, 0);
    assert_eq!(tally.sample.as_deref(), Some("127.0.0.1:63000"));
    assert!(tally.suspicious());
}

#[test]
fn split_address_predicates_match_the_old_advert_predicate() {
    // Expected values are hand-derived from the single disjunction the advert
    // filter used before the split, which is the spec for this refactor.
    let cases = [
        ("127.0.0.1", true),
        ("::1", true),
        ("0.0.0.0", true),
        ("::", true),
        ("224.0.0.1", true),
        ("ff02::1", true),
        ("255.255.255.255", true),
        ("169.254.1.1", true),
        ("fe80::1", true),
        ("192.0.2.1", true),
        ("198.51.100.1", true),
        ("203.0.113.1", true),
        ("100.64.0.1", true),
        ("100.127.255.255", true),
        ("100.128.0.1", false),
        ("10.0.0.1", true),
        ("192.168.1.1", true),
        ("172.16.0.1", true),
        ("fd00::1", true),
        ("8.8.8.8", false),
        ("2001:4860:4860::8888", false),
    ];

    for (text, expected) in cases {
        let ip = text.parse::<IpAddr>().unwrap();
        assert_eq!(
            is_unroutable_direct_advert_ip(ip),
            expected,
            "unexpected advert verdict for {text}"
        );
        assert_eq!(
            is_never_punchable_ip(ip) || is_private_ip(ip) || is_doc_ip(ip),
            expected,
            "the split predicates disagree with the advert filter for {text}"
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

/// The regression case: `connect_task` and `relay_startup_task` both return by
/// design (`Client::connect()` only kicks off per-relay connection tasks;
/// the startup loop breaks on the first successful subscribe), so a healthy
/// node has two finished handles and must still report live.
#[tokio::test]
async fn nostr_liveness_ignores_the_tasks_that_return_by_design() {
    let runtime = NostrRendezvous::new_for_test();
    runtime
        .install_tasks_for_test(
            finished_handle().await,
            finished_handle().await,
            live_handle(),
            live_handle(),
            live_handle(),
        )
        .await;
    assert!(
        !runtime.is_finished(),
        "a node whose connect/relay-startup tasks have returned normally is healthy"
    );
}

#[tokio::test]
async fn nostr_liveness_fires_when_the_notify_loop_dies() {
    let runtime = NostrRendezvous::new_for_test();
    runtime
        .install_tasks_for_test(
            live_handle(),
            live_handle(),
            finished_handle().await,
            live_handle(),
            live_handle(),
        )
        .await;
    assert!(
        runtime.is_finished(),
        "a dead inbound notify loop means no advert or signal is ever received again"
    );
}

#[tokio::test]
async fn nostr_liveness_fires_when_the_publish_loop_dies() {
    let runtime = NostrRendezvous::new_for_test();
    runtime
        .install_tasks_for_test(
            live_handle(),
            live_handle(),
            live_handle(),
            finished_handle().await,
            live_handle(),
        )
        .await;
    assert!(
        runtime.is_finished(),
        "a dead publish loop means this node stops being discoverable"
    );
}

#[tokio::test]
async fn nostr_liveness_fires_when_the_advertise_loop_dies() {
    let runtime = NostrRendezvous::new_for_test();
    runtime
        .install_tasks_for_test(
            live_handle(),
            live_handle(),
            live_handle(),
            live_handle(),
            finished_handle().await,
        )
        .await;
    assert!(
        runtime.is_finished(),
        "a dead advertise ticker means the advert is never refreshed"
    );
}

/// `shutdown` takes every handle, leaving `None`. That must read as finished so
/// the 2s liveness poll monitor terminates instead of spinning after a stop.
#[tokio::test]
async fn nostr_liveness_reports_finished_once_the_handles_are_taken() {
    let runtime = NostrRendezvous::new_for_test();
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
