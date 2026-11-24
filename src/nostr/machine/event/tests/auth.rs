//! Tests of the NIP-42 authentication codec.

use nostr::event::Kind;
use nostr::nips::nip42;

use super::super::tests::{C1_SECS, NODE_A_SECRET, signer};
use super::*;

/// The event answers the relay's challenge as nostr's own check reads it,
/// which nostr-sdk applies before it sends an authentication.
#[test]
fn the_auth_event_passes_nip42_validation() {
    let a = signer(NODE_A_SECRET);
    let relay = RelayUrl::parse("wss://relay.example").expect("relay url");
    let event = auth_event(&a, &relay, "a-challenge", C1_SECS * 1000, [0u8; 32]).expect("auth");
    assert_eq!(event.kind, Kind::Authentication);
    assert!(nip42::is_valid_auth_event(&event, &relay, "a-challenge"));
    let other = RelayUrl::parse("wss://other.example").expect("relay url");
    assert!(
        !nip42::is_valid_auth_event(&event, &other, "a-challenge"),
        "control: the check accepted another relay"
    );
    assert!(
        !nip42::is_valid_auth_event(&event, &relay, "another-challenge"),
        "control: the check accepted another challenge"
    );
}
