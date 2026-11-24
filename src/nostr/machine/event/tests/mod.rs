//! Tests of the node's signer, and helpers the event codecs' tests share.

use std::cell::RefCell;
use std::collections::VecDeque;

use fips_core::entropy::EntropySource;
use nostr::event::Event;
use nostr::key::SecretKey;
use nostr::nips::nip44;
use nostr::types::{RelayUrl, Timestamp};
use rand::SeedableRng;
use rand::rngs::StdRng;

use super::advert::advert_event;
use super::auth::auth_event;
use super::inbox::inbox_list;
use super::signal::{rumor, seal_and_wrap};
use super::{NodeSigner, SignedKind};

/// Node A's secret key, FRC-1601 C.1 (test vector 0 of BIP-340).
pub(crate) const NODE_A_SECRET: &str =
    "0000000000000000000000000000000000000000000000000000000000000003";
/// Node B's secret key, FRC-1601 C.1 (test vector 1 of BIP-340).
pub(crate) const NODE_B_SECRET: &str =
    "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef";
/// The time of publication of FRC-1601 C.1, in seconds.
pub(crate) const C1_SECS: u64 = 1_830_297_600;

/// The secret key written as `hex`.
pub(crate) fn secret(hex: &str) -> SecretKey {
    SecretKey::from_hex(hex).expect("a secret key")
}

/// A signer for the secret key written as `hex`.
pub(crate) fn signer(hex: &str) -> NodeSigner {
    NodeSigner::new(secret(hex))
}

/// The seal inside `wrap`, decrypted with `recipient`'s secret key, without
/// the checks the codec makes.
pub(crate) fn seal_in(wrap: &Event, recipient: &SecretKey) -> Event {
    let json = nip44::decrypt(recipient, &wrap.pubkey, &wrap.content).expect("the wrap decrypts");
    Event::from_json(json).expect("the seal parses")
}

std::thread_local! {
    /// The draws [`ScriptedEntropy`] gives next, and the generator behind
    /// any draw not scripted, one per test thread.
    static SCRIPT: RefCell<(VecDeque<Option<Vec<u8>>>, StdRng)> =
        RefCell::new((VecDeque::new(), StdRng::seed_from_u64(0)));
}

/// An entropy source whose draws a test scripts in order: a `Some` draw is
/// given as written, and a `None` draw, or any draw after the script runs
/// out, comes from a generator seeded with 0.
pub(crate) struct ScriptedEntropy;

impl ScriptedEntropy {
    /// Script this thread's next draws, and restart its generator.
    pub(crate) fn script(draws: Vec<Option<Vec<u8>>>) {
        SCRIPT.with(|script| {
            *script.borrow_mut() = (draws.into(), StdRng::seed_from_u64(0));
        });
    }
}

impl EntropySource for ScriptedEntropy {
    fn fill(dest: &mut [u8]) {
        SCRIPT.with(|script| {
            let (draws, rng) = &mut *script.borrow_mut();
            match draws.pop_front().flatten() {
                Some(draw) => {
                    assert_eq!(draw.len(), dest.len(), "a scripted draw of the wrong size");
                    dest.copy_from_slice(&draw);
                }
                None => rand::Rng::fill_bytes(rng, dest),
            }
        });
    }
}

/// The time an event is built at is the caller's, for every kind the node
/// key signs: none of the codecs reads a clock. The seal's backdating is
/// scripted to zero, so its `created_at` is the time passed in.
#[test]
fn every_kind_the_node_key_signs_carries_the_injected_created_at() {
    let a = signer(NODE_A_SECRET);
    let b = signer(NODE_B_SECRET);
    let unix_ms = C1_SECS * 1000;
    let aux = [1u8; 32];
    let advert = advert_event(
        &a,
        "{}".to_string(),
        "fips-overlay-v1",
        "fips-overlay-v1",
        3_600,
        unix_ms,
        aux,
    )
    .expect("advert");
    let inbox = inbox_list(&a, &["wss://relay.damus.io"], unix_ms, aux).expect("inbox list");
    let relay = RelayUrl::parse("wss://relay.example").expect("relay url");
    let auth = auth_event(&a, &relay, "challenge", unix_ms, aux).expect("auth");
    ScriptedEntropy::script(vec![None, Some(0u64.to_le_bytes().to_vec())]);
    let wrap = seal_and_wrap::<ScriptedEntropy>(
        &a,
        b.public_key(),
        rumor(a.public_key(), b.public_key(), "{}".to_string(), unix_ms),
        unix_ms,
        Timestamp::from(C1_SECS + 120),
    )
    .expect("wrap");
    let seal = seal_in(&wrap, &secret(NODE_B_SECRET));

    for (name, event, kind) in [
        ("advert", &advert, SignedKind::Advert),
        ("inbox list", &inbox, SignedKind::InboxRelays),
        ("auth", &auth, SignedKind::Auth),
        ("seal", &seal, SignedKind::Seal),
    ] {
        assert_eq!(event.kind, kind.kind(), "{name}: kind");
        assert_eq!(event.pubkey, a.public_key(), "{name}: author");
        assert_eq!(
            event.created_at,
            Timestamp::from(C1_SECS),
            "{name}: created_at"
        );
    }
}

/// A signature is a function of the key, the event and the aux bytes alone:
/// the same inputs give the same event, byte for byte, and other aux bytes
/// give another signature over the same id. An event id does not depend on
/// the aux bytes, so this is the test that sees where they come from.
#[test]
fn signing_the_same_inputs_twice_gives_the_same_event_and_a_new_aux_a_new_signature() {
    let a = signer(NODE_A_SECRET);
    let unix_ms = C1_SECS * 1000;
    let relay = RelayUrl::parse("wss://relay.example").expect("relay url");
    let build = |aux: [u8; 32]| -> [Event; 4] {
        [
            advert_event(
                &a,
                "{}".to_string(),
                "fips-overlay-v1",
                "fips-overlay-v1",
                3_600,
                unix_ms,
                aux,
            )
            .expect("advert"),
            inbox_list(&a, &["wss://relay.damus.io"], unix_ms, aux).expect("inbox list"),
            a.sign(
                SignedKind::Seal,
                Timestamp::from(C1_SECS),
                Vec::new(),
                "sealed".to_string(),
                aux,
            )
            .expect("seal"),
            auth_event(&a, &relay, "challenge", unix_ms, aux).expect("auth"),
        ]
    };
    let first = build([7u8; 32]);
    let again = build([7u8; 32]);
    let other = build([8u8; 32]);
    for ((first, again), other) in first.iter().zip(&again).zip(&other) {
        assert_eq!(
            first.as_json(),
            again.as_json(),
            "kind {}: the same inputs gave another event",
            first.kind
        );
        assert_eq!(
            first.id, other.id,
            "kind {}: the aux changed the id",
            first.kind
        );
        assert_ne!(
            first.sig, other.sig,
            "kind {}: other aux bytes gave the same signature",
            first.kind
        );
    }
}
