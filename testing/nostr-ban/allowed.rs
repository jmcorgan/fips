//! The same uses as `banned.rs` under a file-level allow, the shape the
//! test files that use these items take: the allow must silence every one.
#![allow(clippy::disallowed_types, clippy::disallowed_methods)]

use nostr::prelude::*;

/// An unsigned event to sign, built without any banned item.
fn unsigned(keys: &Keys) -> UnsignedEvent {
    UnsignedEvent::new(keys.public_key(), Timestamp::from(1u64), Kind::TextNote, Tags::new(), "x")
}

/// The synchronous forms.
pub fn synchronous(keys: &Keys, event: &Event, relay: RelayUrl) {
    let _ = EventBuilder::new(Kind::TextNote, "x");
    let _ = Timestamp::now();
    let _ = Keys::generate();
    let _ = Keys::parse("0000000000000000000000000000000000000000000000000000000000000003");
    let _ = keys.sign_schnorr(b"x");
    let _ = nip44::encrypt(keys.secret_key(), &keys.public_key(), "x", nip44::Version::V2);
    let _ = event.verify();
    let _ = event.is_expired();
    let _ = SecretKey::generate();
    let _ = SubscriptionId::generate();
    let _ = keys.sign_event(unsigned(keys));
    let _ = unsigned(keys).finalize(keys);
    let _ = ClientAuthentication::new("c", relay).finalize_unsigned(keys.public_key());
    let _ = keys.nip44_encrypt(&keys.public_key(), "x");
}

/// The asynchronous forms.
pub async fn asynchronous(keys: &Keys) {
    let _ = keys.sign_event_async(unsigned(keys)).await;
    let _ = unsigned(keys).finalize_async(keys).await;
    let _ = keys.nip44_encrypt_async(&keys.public_key(), "x").await;
}
