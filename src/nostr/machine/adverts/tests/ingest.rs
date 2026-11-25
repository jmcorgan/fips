use std::cell::Cell;

use nostr::event::Tag;

use nostr::key::SecretKey;

use super::super::super::event::{NodeSigner, SignedKind};
use super::super::super::types::{OverlayEndpointAdvert, OverlayTransportKind};
use super::super::endpoint_advert_is_publicly_usable;
use super::*;

const APP: &str = "fips-overlay-v1";

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

/// FRC-1601 Section 4.2's advert content.
const SECTION_4_2: &str = r#"{"identifier":"fips-overlay-v1","version":1,"endpoints":[{"transport":"udp","addr":"nat"},{"transport":"tcp","addr":"fips.example.com:8443"}],"signalRelays":["wss://relay.damus.io","wss://nos.lol"],"stunServers":["stun:stun.l.google.com:19302"]}"#;

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
        Tag::identifier("fips-overlay-v1".to_string()),
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
const ELSEWHERE: &str = r#"{"identifier":"fips-overlay-v1","version":1,"endpoints":[{"transport":"tcp","addr":"8.8.8.8:443"}]}"#;

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
        SECTION_4_2.to_string(),
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
    let checked = check(&c2, APP, 7_200_000, C1_SECS * 1000).expect("C.2's advert is admitted");
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
            vec![Tag::identifier("fips-overlay-v1".to_string())],
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

#[test]
fn the_frc_c8_endpoint_rule_holds() {
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
        ("udp", "[2001:db8::1]:2121", true),
        ("udp", "[::ffff:10.0.0.1]:2121", true),
        ("udp", "198.18.0.1:2121", true),
        ("tcp", "localhost:80", false),
        ("tcp", "[localhost]:80", false),
        ("tcp", "[]:80", false),
        ("tcp", "example.com:0", false),
        ("udp", "example.com", false),
        ("udp", " nat ", true),
        ("udp", "127.1:2121", true),
        ("udp", "[ 10.0.0.1]:2121", true),
        ("udp", "[fe80::1%eth0]:2121", true),
        ("udp", "[fe80::1%4294967295]:2121", false),
        ("udp", "[fe80::1%4294967296]:2121", true),
        ("udp", "example.com:+080", true),
        ("tor", "", false),
        ("tor", "  \t", false),
        ("tor", "nat", false),
        ("tor", " NaT ", false),
        ("tor", "abc.onion:443", true),
        ("tor", "anything else", true),
    ];
    for (transport, addr, passes) in rows {
        let endpoint: OverlayEndpointAdvert = serde_json::from_str(&format!(
            r#"{{"transport":"{transport}","addr":"{}"}}"#,
            addr.replace('\t', "\\t")
        ))
        .expect("an endpoint");
        assert_eq!(
            endpoint_advert_is_publicly_usable(&endpoint),
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
