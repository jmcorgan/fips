//! Tests of the traversal signal codec: FRC-1601 Appendix C.9 opened, the
//! wrap's signature check, the seal's backdating, and who can open a wrap.

use nostr::event::Kind;

use super::super::super::tests::SeededEntropy;
use super::super::tests::{
    C1_SECS, NODE_A_SECRET, NODE_B_SECRET, ScriptedEntropy, seal_in, secret, signer,
};
use super::*;

/// The sample wrap of FRC-1601 C.9, from node A to node B.
const C9: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/nostr/fixtures/frc1601/c9.json"
));

/// A wrap from node A to node B carrying `body`, built at C.1's time with
/// draws from a generator seeded with `seed`.
fn wrap_from_a_to_b(body: &str, seed: u64) -> Event {
    let a = signer(NODE_A_SECRET);
    let b = signer(NODE_B_SECRET);
    SeededEntropy::seed(seed);
    seal_and_wrap::<SeededEntropy>(
        &a,
        b.public_key(),
        rumor(
            a.public_key(),
            b.public_key(),
            body.to_string(),
            C1_SECS * 1000,
        ),
        C1_SECS * 1000,
        Timestamp::from(C1_SECS + 120),
    )
    .expect("wrap")
}

/// Node B opens C.9's sample: the seal is the one C.9 step 2 gives, signed
/// by node A, and the rumor inside is C.6's.
#[test]
fn opening_the_frc_1601_c9_sample_gives_its_seal_and_the_c6_rumor() {
    let wrap = Event::from_json(C9).expect("the sample parses");
    let a = signer(NODE_A_SECRET);
    let b = signer(NODE_B_SECRET);
    let seal = seal_in(&wrap, &secret(NODE_B_SECRET));
    assert_eq!(seal.kind, Kind::Seal);
    assert_eq!(
        seal.id.to_hex(),
        "2679ed7d8ba6b376a80c5e039021d2d69aae276b7682bb8f58de23445cee11a9"
    );
    assert_eq!(seal.created_at, Timestamp::from(1_791_352_629));
    assert_eq!(seal.pubkey, a.public_key());
    assert!(seal.tags.is_empty());

    let opened = open_signal(&b, &wrap).expect("node B opens the sample");
    assert_eq!(opened.sender, a.public_key());
    let mut rumor = opened.rumor;
    assert_eq!(
        rumor.id().to_hex(),
        "e9ebb384ff7b36f0ea8503e3cfded1b14c7b3d3a8e04d5f5074f0050981d6bd3"
    );
}

/// A wrap whose signature does not verify is refused by the signature
/// check, not by a later step: one nibble of its `sig` is changed, so the
/// rest would still decrypt.
#[test]
fn a_wrap_whose_signature_fails_is_refused_before_it_is_decrypted() {
    let wrap = wrap_from_a_to_b("{}", 1);
    let b = signer(NODE_B_SECRET);
    assert!(open_signal(&b, &wrap).is_ok(), "control: the wrap opens");

    let sig = wrap.sig.to_string();
    let flipped = if sig.starts_with('0') { "1" } else { "0" };
    let json = wrap
        .as_json()
        .replace(&sig, &format!("{flipped}{}", &sig[1..]));
    let forged = Event::from_json(json).expect("the forged wrap parses");
    assert_ne!(forged.sig, wrap.sig, "setup: the signature was not changed");
    match open_signal(&b, &forged) {
        Err(Error::Nostr(reason)) => assert!(
            reason.to_lowercase().contains("signature"),
            "refused, but not by the signature check: {reason}"
        ),
        other => panic!("a wrap with a bad signature was not refused: {other:?}"),
    }
}

/// A seal is backdated by 0 to 172,799 seconds, as nostr 0.44's seal builder
/// did: the draw is reduced modulo two days.
#[test]
fn the_seal_backdate_spans_zero_to_172799_seconds() {
    for (draw, backdate) in [(0, 0), (172_799, 172_799), (172_800, 0), (345_599, 172_799)] {
        assert_eq!(seal_backdate(draw), backdate, "the draw {draw}");
    }

    let wrap = wrap_from_a_to_b("{}", 7);
    let seal = seal_in(&wrap, &secret(NODE_B_SECRET));
    let created = seal.created_at.as_secs();
    assert!(
        (C1_SECS - 172_799..=C1_SECS).contains(&created),
        "the seal's created_at {created} is outside the two days before {C1_SECS}"
    );

    ScriptedEntropy::script(vec![None, Some(172_799u64.to_le_bytes().to_vec())]);
    let a = signer(NODE_A_SECRET);
    let b = signer(NODE_B_SECRET);
    let wrap = seal_and_wrap::<ScriptedEntropy>(
        &a,
        b.public_key(),
        rumor(
            a.public_key(),
            b.public_key(),
            "{}".to_string(),
            C1_SECS * 1000,
        ),
        C1_SECS * 1000,
        Timestamp::from(C1_SECS + 120),
    )
    .expect("wrap");
    assert_eq!(
        seal_in(&wrap, &secret(NODE_B_SECRET)).created_at,
        Timestamp::from(C1_SECS - 172_799),
        "the largest backdate the scripted draw gives"
    );
}

/// Only the recipient's key opens a wrap: the sender's own key and a third
/// key do not.
#[test]
fn a_wrap_built_here_opens_with_the_recipients_key_only() {
    let wrap = wrap_from_a_to_b(r#"{"sessionId":"x"}"#, 3);
    let a = signer(NODE_A_SECRET);
    let b = signer(NODE_B_SECRET);
    assert_eq!(wrap.kind, Kind::Custom(SIGNAL_KIND));
    assert_ne!(
        wrap.pubkey,
        a.public_key(),
        "the wrap is signed by a one-time key"
    );

    let opened = open_signal(&b, &wrap).expect("the recipient opens the wrap");
    assert_eq!(opened.sender, a.public_key());
    assert_eq!(opened.rumor.pubkey, a.public_key());
    assert_eq!(opened.rumor.kind, Kind::PrivateDirectMessage);
    assert_eq!(opened.rumor.content, r#"{"sessionId":"x"}"#);

    let third = signer("0000000000000000000000000000000000000000000000000000000000000007");
    for (name, key) in [("the sender", &a), ("a third key", &third)] {
        assert!(
            open_signal(key, &wrap).is_err(),
            "{name} opened a wrap sealed to node B"
        );
    }
}
