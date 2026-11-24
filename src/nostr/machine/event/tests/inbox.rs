//! Tests of the inbox relay list codec against FRC-1601 Appendix C.4.

use nostr::event::Kind;

use super::super::tests::{C1_SECS, NODE_B_SECRET, signer};
use super::*;

/// Node B's list of C.4, published at C.1's time, has the id C.4 gives, and
/// reads back as the relays it names.
#[test]
fn the_inbox_codec_gives_the_frc_1601_c4_id() {
    let b = signer(NODE_B_SECRET);
    let relays = ["wss://relay.damus.io", "wss://nos.lol"];
    let event = inbox_list(&b, &relays, C1_SECS * 1000, [0u8; 32]).expect("inbox list");
    assert_eq!(event.kind, Kind::InboxRelays);
    assert_eq!(
        event.id.to_hex(),
        "22f5a40a97c6afa71c2f93119f0dedaaf11e58cf6207bbd6b04f6fd6da7c0f1b"
    );
    assert_eq!(inbox_relays(&event), relays);
}
