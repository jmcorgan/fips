//! Tests of the overlay advert codec against FRC-1601 Appendix C.2.

use nostr::event::Kind;

use super::super::tests::{C1_SECS, NODE_A_SECRET, signer};
use super::*;

/// The content of FRC-1601 Section 4.2: a NAT endpoint with its signal
/// relays and STUN server, and a TCP endpoint at a host name.
const SECTION_4_2: &str = r#"{"identifier":"fips-overlay-v1","version":1,"endpoints":[{"transport":"udp","addr":"nat"},{"transport":"tcp","addr":"fips.example.com:8443"}],"signalRelays":["wss://relay.damus.io","wss://nos.lol"],"stunServers":["stun:stun.l.google.com:19302"]}"#;

/// The same advert with only its TCP endpoint.
const TCP_ONLY: &str = r#"{"identifier":"fips-overlay-v1","version":1,"endpoints":[{"transport":"tcp","addr":"fips.example.com:8443"}]}"#;

/// Node A's adverts of C.2, published at C.1's time with a 3600 s lifetime,
/// have the ids C.2 gives, so the codec writes C.2's tags in C.2's order.
/// The identifier and protocol are written out rather than taken from this
/// branch's constants, since the vectors are fixed.
#[test]
fn the_advert_codec_gives_the_frc_1601_c2_ids() {
    let a = signer(NODE_A_SECRET);
    for (content, id) in [
        (
            SECTION_4_2,
            "8f7476a38d5f5ea8c139b8cef70a215f9733a5ee36dd2fab0f164e7123c9436e",
        ),
        (
            TCP_ONLY,
            "2125115451bf9f6ea8b4b77005d0581d48a10c9519f027e55f5ce37f79fd8348",
        ),
    ] {
        let event = advert_event(
            &a,
            content.to_string(),
            "fips-overlay-v1",
            "fips-overlay-v1",
            3_600,
            C1_SECS * 1000,
            [0u8; 32],
        )
        .expect("advert");
        assert_eq!(event.kind, Kind::Custom(37195));
        assert_eq!(event.id.to_hex(), id, "the advert carrying {content}");
        assert_eq!(protocol(&event), Some("fips-overlay-v1"));
    }
}
