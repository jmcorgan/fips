use std::cell::Cell;

use nostr::event::Tag;

use nostr::key::SecretKey;

use super::super::super::event::{NodeSigner, SignedKind};
use super::super::super::types::{OverlayEndpointAdvert, OverlayTransportKind};
use super::super::endpoint_advert_is_publicly_usable;
use super::*;

/// This branch's identifier and default app. `next` uses
/// `fips-overlay-v1-next` where FRC-1601 writes `fips-overlay-v1`, so the
/// adverts built here carry it and only the C.2 vector keeps the FRC's.
const APP: &str = "fips-overlay-v1-next";

/// Node A's secret key, FRC-1601 C.1.
const NODE_A_SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000003";
/// Node B's secret key, FRC-1601 C.1.
const NODE_B_SECRET: &str = "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef";
/// The time of publication of FRC-1601 C.1, in seconds.
const C1_SECS: u64 = 1_830_297_600;

/// A signer for the secret key written as `hex`.
fn signer(hex: &str) -> NodeSigner {
    NodeSigner::new(SecretKey::from_hex(hex).expect("a secret key"))
}

/// FRC-1601 Section 4.2's advert content, as the FRC writes it.
const FRC_SECTION_4_2: &str = r#"{"identifier":"fips-overlay-v1","version":1,"endpoints":[{"transport":"udp","addr":"nat"},{"transport":"tcp","addr":"fips.example.com:8443"}],"signalRelays":["wss://relay.damus.io","wss://nos.lol"],"stunServers":["stun:stun.l.google.com:19302"]}"#;

/// FRC-1601 Section 4.2's advert content with this branch's identifier.
const SECTION_4_2: &str = r#"{"identifier":"fips-overlay-v1-next","version":1,"endpoints":[{"transport":"udp","addr":"nat"},{"transport":"tcp","addr":"fips.example.com:8443"}],"signalRelays":["wss://relay.damus.io","wss://nos.lol"],"stunServers":["stun:stun.l.google.com:19302"]}"#;

/// The time FRC-1601 C.3 judges each row at, in ms.
const C3_NOW_MS: u64 = 1_830_297_660_000;

/// An advert event signed by the secret key written as `secret`, created at
/// `created_at` seconds, carrying `tags` after the protocol tag for `app`,
/// and `content`.
fn advert_with(
    secret: &str,
    created_at: u64,
    app: &str,
    extra: Vec<Vec<&str>>,
    content: &str,
) -> Event {
    let mut tags = vec![
        Tag::identifier(APP.to_string()),
        Tag::custom("protocol", [app.to_string()]),
    ];
    tags.extend(extra.into_iter().map(|t| Tag::parse(t).expect("a tag")));
    signer(secret)
        .sign(
            SignedKind::Advert,
            Timestamp::from(created_at),
            tags,
            content.to_string(),
            [0u8; 32],
        )
        .expect("an advert")
}

/// Node A's advert created at C.1's time, expiring at `expiration`.
fn advert_a(expiration: u64) -> Event {
    advert_with(
        NODE_A_SECRET,
        C1_SECS,
        APP,
        vec![vec!["expiration", &expiration.to_string()]],
        SECTION_4_2,
    )
}

/// `event` with its content replaced by `content` after signing, so its id
/// no longer verifies.
fn tampered(mut event: Event, content: &str) -> Event {
    event.content = content.to_string();
    event
}

/// Node B's advert carrying `content`, created at C.1's time, with the
/// signature of node A's advert of the same content: its id is right for
/// what it carries, and its signature is not B's over that id.
fn signed_by_another_key(content: &str) -> Event {
    let b = advert_with(NODE_B_SECRET, C1_SECS, APP, Vec::new(), content);
    let a = advert_with(NODE_A_SECRET, C1_SECS, APP, Vec::new(), content);
    Event::new(
        b.id,
        b.pubkey,
        b.created_at,
        b.kind,
        b.tags.clone(),
        b.content.clone(),
        a.sig,
    )
}

/// A body naming one TCP endpoint other than Section 4.2's.
const ELSEWHERE: &str = r#"{"identifier":"fips-overlay-v1-next","version":1,"endpoints":[{"transport":"tcp","addr":"8.8.8.8:443"}]}"#;

#[test]
fn an_expired_advert_is_refused_before_it_is_parsed() {
    let parses = Cell::new(0);
    let counting = |event: &Event| {
        parses.set(parses.get() + 1);
        decode(event)
    };
    // Malformed content: were it parsed, the parse would fail too, so only
    // the count tells the two orders apart.
    let expired = advert_with(
        NODE_A_SECRET,
        C1_SECS,
        APP,
        vec![vec!["expiration", &(C1_SECS + 10).to_string()]],
        "not json",
    );
    let now_ms = (C1_SECS + 20) * 1000;
    assert_eq!(
        check_with(&expired, APP, 7_200_000, now_ms, counting),
        Err(Refusal::Expired)
    );
    assert_eq!(parses.get(), 0, "an expired advert was parsed");

    // Control: a current advert with the same content is parsed, once.
    let current = advert_with(NODE_A_SECRET, C1_SECS, APP, Vec::new(), "not json");
    assert_eq!(
        check_with(&current, APP, 7_200_000, now_ms, counting),
        Err(Refusal::Invalid)
    );
    assert_eq!(parses.get(), 1);
}

#[test]
fn a_forged_advert_is_refused_before_it_is_decoded() {
    let decodes = Cell::new(0);
    let counting = |event: &Event| {
        decodes.set(decodes.get() + 1);
        decode(event)
    };
    let now_ms = C1_SECS * 1000;
    let genuine = advert_with(NODE_B_SECRET, C1_SECS, APP, Vec::new(), SECTION_4_2);
    let forged = [
        tampered(genuine.clone(), ELSEWHERE),
        signed_by_another_key(SECTION_4_2),
    ];
    for event in &forged {
        assert_eq!(
            check_with(event, APP, 7_200_000, now_ms, counting),
            Err(Refusal::Forged)
        );
        assert!(!authentic(event));
    }
    assert_eq!(decodes.get(), 0, "a forged advert was decoded");

    // Control: the genuine advert is decoded, once, and admitted.
    assert!(check_with(&genuine, APP, 7_200_000, now_ms, counting).is_ok());
    assert_eq!(decodes.get(), 1);
}

#[test]
fn an_advert_signed_by_another_key_than_its_pubkey_is_forged() {
    let event = signed_by_another_key(SECTION_4_2);
    assert_eq!(
        event.id,
        advert_with(NODE_B_SECRET, C1_SECS, APP, Vec::new(), SECTION_4_2).id,
        "the id is right for what the event carries"
    );
    assert!(!authentic(&event));
    assert_eq!(
        check(&event, APP, 7_200_000, C1_SECS * 1000),
        Err(Refusal::Forged)
    );
}

#[test]
fn a_genuine_advert_passes_the_signature_check() {
    // FRC-1601 C.2's advert of Section 4.2, by node A.
    let c2 = super::super::super::event::advert::advert_event(
        &signer(NODE_A_SECRET),
        FRC_SECTION_4_2.to_string(),
        "fips-overlay-v1",
        "fips-overlay-v1",
        3_600,
        C1_SECS * 1000,
        [0u8; 32],
    )
    .expect("an advert");
    assert_eq!(
        c2.id.to_hex(),
        "8f7476a38d5f5ea8c139b8cef70a215f9733a5ee36dd2fab0f164e7123c9436e",
        "C.2's id"
    );
    assert!(authentic(&c2));
    // C.2 carries FRC-1601's identifier, which `next` does not take: it is
    // refused as another app's, before its signature is checked. The same
    // advert built with this branch's identifier is admitted.
    assert_eq!(
        check(&c2, APP, 7_200_000, C1_SECS * 1000),
        Err(Refusal::Invalid),
        "C.2's advert is another branch's"
    );
    let ours = advert_a(C1_SECS + 3_600);
    assert!(authentic(&ours));
    let checked = check(&ours, APP, 7_200_000, C1_SECS * 1000)
        .expect("C.2's advert with this branch's identifier is admitted");
    assert_eq!(checked.advert.endpoints.len(), 2);

    // The advert a node running the nostr 0.44 code sent, captured then.
    let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/nostr/fixtures/v044/advert.json"
    )))
    .expect("the fixture");
    let captured_ms = fixture["captureUnixMs"].as_u64().expect("its time");
    let event = Event::from_json(fixture["event"].to_string()).expect("its event");
    assert!(authentic(&event));
    let checked = check(&event, APP, 7_200_000, captured_ms).expect("the 0.44 advert is admitted");
    assert_eq!(checked.advert.endpoints.len(), 2);
}

#[test]
fn an_advert_without_our_protocol_tag_is_refused_before_its_signature_is_checked() {
    let now_ms = C1_SECS * 1000;
    let untagged = signer(NODE_B_SECRET)
        .sign(
            SignedKind::Advert,
            Timestamp::from(C1_SECS),
            vec![Tag::identifier(APP.to_string())],
            SECTION_4_2.to_string(),
            [0u8; 32],
        )
        .expect("an event");
    let theirs = advert_with(NODE_B_SECRET, C1_SECS, "other-app", Vec::new(), SECTION_4_2);
    let oversized = advert_with(NODE_B_SECRET, C1_SECS, APP, Vec::new(), SECTION_4_2);
    let refused_unchecked = [
        tampered(untagged, ELSEWHERE),
        tampered(theirs, ELSEWHERE),
        tampered(oversized, &"x".repeat(MAX_ADVERT_CONTENT_BYTES + 1)),
    ];
    for event in &refused_unchecked {
        assert!(!authentic(event), "control: the event is forged");
        assert_eq!(
            check(event, APP, 7_200_000, now_ms),
            Err(Refusal::Invalid),
            "the screen refuses it before the signature check"
        );
    }
}

#[test]
fn an_advert_for_another_app_is_refused() {
    let theirs = advert_with(NODE_A_SECRET, C1_SECS, "other-app", Vec::new(), SECTION_4_2);
    let refused = parse(&theirs, APP);
    assert!(
        matches!(&refused, Err(ParseError::Invalid(Error::InvalidAdvert(text)))
            if text == "unsupported protocol 'other-app'"),
        "{refused:?}"
    );
    let now_ms = C1_SECS * 1000;
    assert_eq!(
        check(&theirs, APP, 7_200_000, now_ms),
        Err(Refusal::Invalid)
    );
    let ours = advert_with(NODE_A_SECRET, C1_SECS, APP, Vec::new(), SECTION_4_2);
    assert!(check(&ours, APP, 7_200_000, now_ms).is_ok(), "control");
}

#[test]
fn an_oversized_advert_is_refused_before_it_is_decoded() {
    // Not JSON at all: a decode would give a JSON error, so the content
    // bound's refusal shows the content was never decoded.
    let content = "x".repeat(MAX_ADVERT_CONTENT_BYTES + 1);
    let event = advert_with(NODE_A_SECRET, C1_SECS, APP, Vec::new(), &content);
    let refused = parse(&event, APP);
    assert!(
        matches!(&refused, Err(ParseError::Invalid(Error::InvalidAdvert(text)))
            if text == "content of 8193 bytes, over the bound of 8192"),
        "{refused:?}"
    );
    let at_bound = advert_with(
        NODE_A_SECRET,
        C1_SECS,
        APP,
        Vec::new(),
        &"x".repeat(MAX_ADVERT_CONTENT_BYTES),
    );
    assert!(
        matches!(parse(&at_bound, APP), Err(ParseError::Json(_))),
        "control: content at the bound is decoded"
    );
}

#[test]
fn a_future_created_at_is_clamped_before_admission() {
    let now_ms = C1_SECS * 1000;
    let future = advert_with(NODE_A_SECRET, C1_SECS + 3_600, APP, Vec::new(), SECTION_4_2);
    let checked = check(&future, APP, 7_200_000, now_ms).expect("admitted");
    assert_eq!(
        checked.created_at,
        C1_SECS + 60,
        "clamped to the skew tolerance"
    );
    assert_eq!(
        checked.valid_until_ms,
        (C1_SECS + 60) * 1000 + 7_200_000,
        "the horizon runs from the clamped time"
    );
    let near = advert_with(NODE_A_SECRET, C1_SECS + 30, APP, Vec::new(), SECTION_4_2);
    assert_eq!(
        check(&near, APP, 7_200_000, now_ms)
            .expect("admitted")
            .created_at,
        C1_SECS + 30,
        "control: a created_at inside the tolerance is kept"
    );
}

#[test]
fn the_newest_event_is_chosen_only_among_the_authors_events() {
    let a = signer(NODE_A_SECRET).public_key();
    let older = advert_with(NODE_A_SECRET, C1_SECS, APP, Vec::new(), SECTION_4_2);
    let newer = advert_with(NODE_A_SECRET, C1_SECS + 10, APP, Vec::new(), SECTION_4_2);
    let foreign = advert_with(NODE_B_SECRET, C1_SECS + 1_000, APP, Vec::new(), SECTION_4_2);
    let events = [older.clone(), foreign.clone(), newer.clone()];
    assert_eq!(newest_by_author(events.iter(), a), Some(&newer));
    assert_eq!(newest_by_author([foreign].iter(), a), None);
    assert_eq!(
        author_npub(&older),
        "npub1lycg5qvjtrp3qjf5f7zl382j9x6nrjz9sdhenvyxq8c3808qxmus6gq266"
    );
}

#[test]
fn clamping_our_own_advert_cuts_each_long_list_to_its_first_entries_and_names_it() {
    let endpoint = |i: usize| OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: format!("198.51.100.{i}:2121"),
    };
    let mut advert = OverlayAdvert {
        identifier: APP.to_string(),
        version: 1,
        endpoints: (0..40).map(endpoint).collect(),
        signal_relays: Some((0..33).map(|i| format!("wss://r{i}.example")).collect()),
        stun_servers: Some(vec!["stun:s.example:3478".to_string()]),
    };
    let cuts = clamp_own(&mut advert);
    assert_eq!(
        cuts,
        vec![
            ListCut {
                list: "endpoints",
                configured: 40,
            },
            ListCut {
                list: "signalRelays",
                configured: 33,
            },
        ]
    );
    assert_eq!(
        advert.endpoints,
        (0..32).map(endpoint).collect::<Vec<_>>(),
        "the first entries are kept, in order"
    );
    assert_eq!(advert.signal_relays.as_ref().unwrap().len(), 32);
    assert_eq!(advert.stun_servers.as_ref().unwrap().len(), 1);
    assert!(
        clamp_own(&mut advert).is_empty(),
        "a clamped advert is not cut again"
    );
}

#[test]
fn the_frc_c3_validity_horizon_holds() {
    let rows: [(Event, u64, Option<u64>); 4] = [
        (advert_a(1_830_301_200), 7_200_000, Some(1_830_301_200_000)),
        (advert_a(1_830_301_200), 1_800_000, Some(1_830_299_400_000)),
        (
            advert_with(
                NODE_A_SECRET,
                1_830_301_200,
                APP,
                vec![vec!["expiration", "1830304800"]],
                SECTION_4_2,
            ),
            3_600_000,
            Some(1_830_301_320_000),
        ),
        (
            advert_with(
                NODE_A_SECRET,
                C1_SECS,
                APP,
                vec![vec!["expiration", "abc"], vec!["expiration", "1830298200"]],
                SECTION_4_2,
            ),
            7_200_000,
            Some(1_830_304_800_000),
        ),
    ];
    for (i, (event, max_age_ms, horizon)) in rows.iter().enumerate() {
        assert_eq!(
            valid_until_ms(event, *max_age_ms, C3_NOW_MS),
            *horizon,
            "C.3 row {}",
            i + 1
        );
        let checked = check(event, APP, *max_age_ms, C3_NOW_MS).expect("admitted");
        assert_eq!(Some(checked.valid_until_ms), *horizon, "C.3 row {}", i + 1);
    }
    let clamped = check(&rows[2].0, APP, 3_600_000, C3_NOW_MS).expect("admitted");
    assert_eq!(
        clamped.created_at, 1_830_297_720,
        "C.3 row 3's clamped created"
    );
}

/// Whether the endpoint rule keeps `addr` over `transport`, read from JSON
/// as a peer's advert carries it.
fn usable(transport: &str, addr: &str) -> bool {
    let endpoint: OverlayEndpointAdvert = serde_json::from_str(&format!(
        r#"{{"transport":"{transport}","addr":"{}"}}"#,
        addr.replace('\t', "\\t")
    ))
    .expect("an endpoint");
    endpoint_advert_is_publicly_usable(&endpoint)
}

#[test]
fn the_frc_c8_endpoint_rule_holds_where_the_node_follows_it() {
    let rows: &[(&str, &str, bool)] = &[
        ("udp", "nat", true),
        ("udp", "NAT", true),
        ("tcp", "nat", false),
        ("tor", "nat", false),
        ("tcp", "fips.example.com:8443", true),
        ("udp", "192.0.2.1:2121", false),
        ("udp", "10.0.0.1:2121", false),
        ("udp", "100.64.0.1:2121", false),
        ("udp", "[fd00::1]:2121", false),
        ("udp", "198.18.0.1:2121", true),
        ("tcp", "localhost:80", false),
        ("tcp", "[localhost]:80", false),
        ("tcp", "[]:80", false),
        ("tcp", "example.com:0", false),
        ("udp", "example.com", false),
        ("udp", " nat ", true),
        ("udp", "[fe80::1%4294967295]:2121", false),
        ("udp", "example.com:+080", true),
        ("tor", "", false),
        ("tor", "  \t", false),
        ("tor", "nat", false),
        ("tor", " NaT ", false),
    ];
    for (transport, addr, passes) in rows {
        assert_eq!(
            usable(transport, addr),
            *passes,
            "C.8: {transport} {addr:?}"
        );
    }
    // A NAT endpoint with white space around it passes the rule, but is not
    // a NAT endpoint.
    let spaced = OverlayAdvert {
        identifier: APP.to_string(),
        version: 1,
        endpoints: vec![OverlayEndpointAdvert {
            transport: OverlayTransportKind::Udp,
            addr: " nat ".to_string(),
        }],
        signal_relays: None,
        stun_servers: None,
    };
    assert!(!spaced.has_udp_nat_endpoint());
}

/// The rows of FRC-1601 Appendix C.8 whose verdict the node does not
/// follow: each is a form Section 8.1 of that document lists as admitted by
/// its endpoint rule though meant to be excluded. The node refuses them; the
/// document's endpoint rule and C.8 are to be brought in line. Each row is
/// its transport, its address, C.8's verdict and the node's.
#[test]
fn the_endpoint_rule_is_stricter_than_frc_c8_for_these_forms() {
    let rows: &[(&str, &str, bool, bool)] = &[
        ("udp", "[::ffff:10.0.0.1]:2121", true, false),
        ("udp", "127.1:2121", true, false),
        ("udp", "[ 10.0.0.1]:2121", true, false),
        ("udp", "[fe80::1%eth0]:2121", true, false),
        ("udp", "[fe80::1%4294967296]:2121", true, false),
        ("udp", "[2001:db8::1]:2121", true, false),
        ("tor", "abc.onion:443", true, false),
        ("tor", "anything else", true, false),
    ];
    for (transport, addr, c8, node) in rows {
        assert_ne!(c8, node, "{transport} {addr:?} differs from C.8");
        assert_eq!(usable(transport, addr), *node, "{transport} {addr:?}");
    }
}

#[test]
fn the_endpoint_rule_refuses_an_excluded_address_in_ipv4_mapped_form() {
    for transport in ["udp", "tcp"] {
        for addr in [
            "[::ffff:127.0.0.1]:2121",
            "[::ffff:10.0.0.1]:2121",
            "[::ffff:192.168.1.1]:2121",
            "[::ffff:100.64.0.1]:2121",
            "[::ffff:192.0.2.1]:2121",
        ] {
            assert!(!usable(transport, addr), "{transport} {addr}");
        }
        assert!(
            usable(transport, "[::ffff:8.8.8.8]:2121"),
            "a public address in mapped form is kept"
        );
    }
}

#[test]
fn the_endpoint_rule_refuses_a_zoned_address() {
    assert!(!usable("udp", "[2600::1%7]:2121"), "a zoned global address");
    assert!(usable("udp", "[2600::1]:2121"), "the same address unzoned");
    assert!(
        !usable("udp", "[fe80::1%3]:2121"),
        "a zoned link-local address"
    );
}

/// A host name of `len` bytes, of labels of 63 bytes but the last.
fn name_of_len(len: usize) -> String {
    let name = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "b".repeat(len - 192));
    assert_eq!(name.len(), len);
    name
}

#[test]
fn the_endpoint_rule_refuses_numeric_and_malformed_host_spellings() {
    let long_label = format!("{}.example", "a".repeat(64));
    let long_name = name_of_len(254);
    let rows = [
        // A host whose last label is a number: an IPv4 address in another
        // spelling, or not an address at all.
        "127.1:2121",
        "10.1:2121",
        "2130706433:2121",
        "0x7f000001:2121",
        "0X7F000001:2121",
        "0x7F000001:2121",
        "0x7f.1:2121",
        "0177.0.0.1:2121",
        "010.0.0.1:2121",
        "127.000000000000000001:2121",
        "10.0.0.1.:2121",
        "1.2.3.4.5:2121",
        // A canonical excluded address with a port the rule tolerates.
        "10.0.0.1:+2121",
        // Malformed brackets, zones and unbracketed IPv6.
        "[ 10.0.0.1]:2121",
        "[fe80::1%eth0]:2121",
        "[fe80::1%4294967296]:2121",
        "[example.com]:443",
        "2600::1:2121",
        // White space, names under localhost, non-ASCII, and lengths.
        "exa mple.com:80",
        "foo.localhost:80",
        "localhost.:80",
        "bücher.de:443",
        &format!("{long_label}:443"),
        &format!("{long_name}:443"),
    ];
    for transport in ["udp", "tcp"] {
        for addr in rows {
            assert!(!usable(transport, addr), "{transport} {addr:?}");
        }
    }
}

#[test]
fn the_endpoint_rule_still_accepts_the_host_names_the_tree_dials() {
    let label = format!("{}.example", "a".repeat(63));
    let name = name_of_len(253);
    let rows = [
        "fips.example.com:8443",
        "fips-nat-relay:7777",
        "my_container:2121",
        "example.com.:443",
        "example.com:+080",
        "1e100.net:443",
        "123.example:80",
        "0xdeadbeef.example:443",
        "8.8.8.8:+2121",
        &format!("{label}:443"),
        &format!("{name}:443"),
    ];
    for transport in ["udp", "tcp"] {
        for addr in rows {
            assert!(usable(transport, addr), "{transport} {addr:?}");
        }
    }
}

#[test]
fn the_endpoint_rule_refuses_the_reserved_ranges() {
    for addr in ["0.1.2.3:2121", "240.0.0.1:2121", "[2001:db8::1]:2121"] {
        assert!(!usable("udp", addr), "{addr}");
    }
    assert!(
        usable("udp", "198.18.0.1:2121"),
        "the benchmarking range is kept"
    );
}

#[test]
fn the_endpoint_rule_accepts_a_version_3_onion_and_nothing_else_for_tor() {
    // The public test node's onion, and the open-discovery scenario's seed
    // name, which has no valid checksum.
    let real = "7c5mtyo5mk477t7l4mg56xs4wcnt4zrsqtjampijy532ggxgdg42gcyd.onion";
    let seed = "fipsopendiscoveryseedxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion";
    for addr in [
        format!("{real}:443"),
        format!("{}:443", real.to_ascii_uppercase()),
        format!("{seed}:443"),
    ] {
        assert!(usable("tor", &addr), "{addr}");
    }
    let one = format!("{}1.onion:443", "a".repeat(55));
    for addr in [
        "abc.onion:443".to_string(),
        "abcdefghij234567.onion:443".to_string(),
        real.to_string(),
        format!("{real}:0"),
        format!("www.{real}:443"),
        "example.com:443".to_string(),
        "10.0.0.1:443".to_string(),
        "anything else".to_string(),
        one,
    ] {
        assert!(!usable("tor", &addr), "{addr}");
    }
}
