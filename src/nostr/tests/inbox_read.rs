//! Golden tables for how the shell reads two things a peer controls: the
//! relays a kind 10050 inbox relay list names, and the `expiration` tag of an
//! overlay advert. Each row's expected value is what nostr 0.44, the version
//! deployed nodes run, reads from that shape, so a change in how a later
//! nostr version reads a tag shows here as a changed row. The four
//! expiration rows marked below are the exception: there the relay client
//! itself reads the tag as nostr 0.45 does, before the shell sees the event,
//! and the shell reads it the same way.

use nostr::event::FinalizeEvent;
use nostr::prelude::{EventBuilder, Keys, Kind, Tag, Timestamp};

use super::super::ADVERT_KIND;
use super::super::runtime::{NostrRendezvous, inbox_relays};

/// Each inbox-list tag shape, and the relay nostr 0.44 reads from it, if any.
/// The shapes cover the NIP-17 `relay` form and the bare `r` form; extra,
/// empty and marker values; `ALL_RELAYS`; http and https schemes; leading
/// and trailing spaces; an upper-case scheme and host; IPv6, onion and
/// fragment URLs; and a relay named twice.
const INBOX_SHAPES: [(&[&str], Option<&str>); 32] = [
    (&["relay", "wss://a1.example"], Some("wss://a1.example")),
    (&["relay", "ALL_RELAYS"], None),
    (&["r", "wss://a1.example"], Some("wss://a1.example")),
    (&["relay", "wss://a2.example/"], Some("wss://a2.example/")),
    (&["relay", "wss://A3.EXAMPLE"], Some("wss://a3.example")),
    (&["relay", "not a url"], None),
    (&["relay"], None),
    (&["relay", "wss://b1.example", "extra"], None),
    (&["relay", "wss://b2.example", ""], None),
    (&["r", "wss://c1.example"], Some("wss://c1.example")),
    (&["r", "wss://c2.example", "read"], None),
    (&["r", "wss://c3.example", "write"], None),
    (&["r", "wss://c4.example", ""], None),
    (&["r", "wss://c5.example", "bogus"], None),
    (&["r", "wss://c6.example", "read", "x"], None),
    (&["r", "http://d1.example"], None),
    (&["r", "https://d2.example"], None),
    (&["relay", "http://d3.example"], None),
    (&["r", "wss://e1.example:443"], Some("wss://e1.example")),
    (
        &["r", "wss://f1.example/path?x=1"],
        Some("wss://f1.example/path?x=1"),
    ),
    (&["R", "wss://g1.example"], None),
    (&["r"], None),
    (&["r", ""], None),
    (&["relay", ""], None),
    (&["p", "wss://h1.example"], None),
    (
        &["relay", "ws://127.0.0.1:7777"],
        Some("ws://127.0.0.1:7777"),
    ),
    (&["r", "ws://[::1]:7777"], Some("ws://[::1]:7777")),
    (
        &["relay", "wss://onion1234567890abcdef.onion"],
        Some("wss://onion1234567890abcdef.onion"),
    ),
    (
        &["r", "wss://i1.example#frag"],
        Some("wss://i1.example/#frag"),
    ),
    (&["r", " wss://j1.example"], None),
    (&["relay", "wss://k1.example "], Some("wss://k1.example")),
    (&["relay", "WSS://l1.example"], Some("wss://l1.example")),
];

/// All of [`INBOX_SHAPES`] in one list, as nostr 0.44 reads it: in tag order,
/// each relay once.
const INBOX_ALL: [&str; 12] = [
    "wss://a1.example",
    "wss://a2.example/",
    "wss://a3.example",
    "wss://c1.example",
    "wss://e1.example",
    "wss://f1.example/path?x=1",
    "ws://127.0.0.1:7777",
    "ws://[::1]:7777",
    "wss://onion1234567890abcdef.onion",
    "wss://i1.example/#frag",
    "wss://k1.example",
    "wss://l1.example",
];

/// A tag from its elements, which may be any shape a peer sends.
fn tag(shape: &[&str]) -> Tag {
    Tag::parse(shape.iter().copied()).expect("a tag of at least one element")
}

/// An event of `kind` carrying `tags`, created at `created_at_secs`, signed
/// by a fresh key.
fn event_with(
    kind: Kind,
    content: &str,
    created_at_secs: u64,
    tags: Vec<Tag>,
) -> nostr::event::Event {
    EventBuilder::new(kind, content)
        .tags(tags)
        .custom_created_at(Timestamp::from(created_at_secs))
        .finalize(&Keys::generate())
        .expect("sign event")
}

/// A peer's inbox relay list is read by nostr 0.44's rules: a tag of exactly
/// two elements, a `relay` value other than `ALL_RELAYS` or an `r` value
/// starting `ws://` or `wss://`, that parses as a relay URL, listed once.
#[test]
fn each_inbox_list_tag_shape_reads_as_nostr_044_reads_it() {
    let now = Timestamp::now().as_secs();
    for (shape, expected) in INBOX_SHAPES {
        let event = event_with(Kind::InboxRelays, "", now, vec![tag(shape)]);
        let expected: Vec<String> = expected.iter().map(|url| url.to_string()).collect();
        assert_eq!(inbox_relays(&event), expected, "the tag {shape:?}");
    }
    let all = event_with(
        Kind::InboxRelays,
        "",
        now,
        INBOX_SHAPES.iter().map(|(shape, _)| tag(shape)).collect(),
    );
    assert_eq!(inbox_relays(&all), INBOX_ALL, "every shape in one list");
}

/// An advert naming two protocols is read by the first `protocol` tag alone.
#[test]
fn an_adverts_first_protocol_tag_is_the_one_read() {
    let app = crate::config::NostrRendezvousConfig::default().app;
    // `next`'s identifier, which the advert body must carry here.
    let content = r#"{"identifier":"fips-overlay-v1-next","version":1,"endpoints":[{"transport":"tcp","addr":"8.8.8.8:443"}]}"#;
    let now = Timestamp::now().as_secs();
    let ours_first = event_with(
        Kind::Custom(ADVERT_KIND),
        content,
        now,
        vec![tag(&["protocol", &app]), tag(&["protocol", "other"])],
    );
    let theirs_first = event_with(
        Kind::Custom(ADVERT_KIND),
        content,
        now,
        vec![tag(&["protocol", "other"]), tag(&["protocol", &app])],
    );
    assert!(
        NostrRendezvous::parse_overlay_advert_event(&ours_first, &app).is_ok(),
        "an advert whose first protocol tag is ours was refused"
    );
    let refused = NostrRendezvous::parse_overlay_advert_event(&theirs_first, &app)
        .expect_err("an advert whose first protocol tag is another app's was accepted");
    assert_eq!(
        refused.to_string(),
        "invalid overlay advert: unsupported protocol 'other'"
    );
}

/// What an advert's validity is pinned to: its `expiration` tag's time, or
/// the window its `created_at` and the maximum age give.
#[derive(Debug, Clone, Copy)]
enum Validity {
    /// The time the first `expiration` tag gives, in seconds.
    Expiration(u64),
    /// No expiration is read, so the `created_at` window decides.
    Window,
}

/// How long after its `created_at` an advert stays valid in the tests below.
const MAX_AGE_MS: u64 = 3_600_000;

/// Each `expiration` tag shape is read as the relay client reads it: the
/// first `expiration` tag, whose second element parses as an unsigned
/// integer. nostr 0.44 also required the tag to have exactly two elements;
/// nostr 0.45 reads one with elements after the time too, and drops such an
/// event inside the relay client once that time has passed, so the four rows
/// marked are pinned to the time where 0.44 gave the window. The expiration
/// times are in the future and inside the `created_at` window, so a reading
/// shows in the result.
#[test]
fn each_advert_expiration_tag_shape_gives_its_pinned_validity() {
    let now = Timestamp::now().as_secs();
    let t = (now + 100).to_string();
    let t2 = (now + 200).to_string();
    let plus_t = format!("+{t}");
    let space_t = format!(" {t}");
    let t_space = format!("{t} ");
    let t_frac = format!("{t}.5");
    let max = u64::MAX.to_string();
    let over_max = "18446744073709551616";
    let at_t = Validity::Expiration(now + 100);
    let at_t2 = Validity::Expiration(now + 200);
    let shapes: [(Vec<Vec<&str>>, Validity); 18] = [
        (vec![vec!["expiration", &t]], at_t),
        // Read by nostr 0.45, not by 0.44, which gave the window.
        (vec![vec!["expiration", &t, "x"]], at_t),
        // Read by nostr 0.45, not by 0.44, which gave the window.
        (vec![vec!["expiration", &t, ""]], at_t),
        // Read by nostr 0.45, not by 0.44, which gave the window.
        (vec![vec!["expiration", &t, "x", "y"]], at_t),
        (vec![vec!["expiration", &space_t]], Validity::Window),
        (vec![vec!["expiration", &t_space]], Validity::Window),
        (vec![vec!["expiration", "abc"]], Validity::Window),
        (vec![vec!["expiration", ""]], Validity::Window),
        (vec![vec!["expiration"]], Validity::Window),
        (vec![vec!["expiration", "-5"]], Validity::Window),
        (vec![vec!["expiration", &t_frac]], Validity::Window),
        (vec![vec!["expiration", &plus_t]], at_t),
        (vec![vec!["expiration", &max]], Validity::Window),
        (vec![vec!["expiration", over_max]], Validity::Window),
        (
            vec![vec!["expiration", "abc"], vec!["expiration", &t2]],
            Validity::Window,
        ),
        // Read by nostr 0.45, not by 0.44, which gave the window.
        (
            vec![vec!["expiration", &t, "x"], vec!["expiration", &t2]],
            at_t,
        ),
        (vec![vec!["expiration", &t2], vec!["expiration", &t]], at_t2),
        (vec![vec!["EXPIRATION", &t]], Validity::Window),
    ];
    for (tags, validity) in shapes {
        let event = event_with(
            Kind::Custom(ADVERT_KIND),
            "{}",
            now,
            tags.iter().map(|shape| tag(shape)).collect(),
        );
        let expected = match validity {
            Validity::Expiration(secs) => secs * 1000,
            Validity::Window => now * 1000 + MAX_AGE_MS,
        };
        assert_eq!(
            NostrRendezvous::compute_advert_valid_until_ms(&event, MAX_AGE_MS, now * 1000),
            Some(expected),
            "the tags {tags:?}, pinned to {validity:?}"
        );
    }
}
