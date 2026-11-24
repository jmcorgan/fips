use super::*;
use crate::nostr::machine::tests::ZeroEntropy;

fn node_addr(first_byte: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = first_byte;
    NodeAddr::from_bytes(bytes)
}

fn machine() -> Election {
    Election::new(1_000_000, 3, KeyedHasher::new::<ZeroEntropy>())
}

// --- election ordering (classify_incoming_offer) -------------------

#[test]
fn election_vectors() {
    let smaller = node_addr(0x01);
    let larger = node_addr(0x02);
    let peer = "npub1peer";

    // V1: co-active initiator, our addr smaller -> Suppress.
    let mut m = machine();
    assert!(m.begin_initiator(peer));
    assert_eq!(
        m.classify_incoming_offer(peer, &smaller, &larger),
        OfferDisposition::Suppress
    );

    // V2: co-active initiator, our addr larger -> Proceed.
    let mut m = machine();
    assert!(m.begin_initiator(peer));
    assert_eq!(
        m.classify_incoming_offer(peer, &larger, &smaller),
        OfferDisposition::Proceed
    );

    // V3: no co-active initiator, our addr smaller -> Proceed
    // (asymmetric one-sided auto_connect).
    let m = machine();
    assert_eq!(
        m.classify_incoming_offer(peer, &smaller, &larger),
        OfferDisposition::Proceed
    );

    // V4: co-active initiator, equal addresses -> Proceed (self/loopback).
    let mut m = machine();
    assert!(m.begin_initiator(peer));
    assert_eq!(
        m.classify_incoming_offer(peer, &smaller, &smaller),
        OfferDisposition::Proceed
    );

    // V5: classify BEFORE begin_initiator -> Proceed (offer-first race).
    let m = machine();
    assert_eq!(
        m.classify_incoming_offer(peer, &smaller, &larger),
        OfferDisposition::Proceed
    );

    // V6: begin then end then classify -> Proceed (initiator finished).
    let mut m = machine();
    assert!(m.begin_initiator(peer));
    m.end_initiator(peer);
    assert_eq!(
        m.classify_incoming_offer(peer, &smaller, &larger),
        OfferDisposition::Proceed
    );
}

// --- initiator dedup ------------------------------------------------

#[test]
fn initiator_dedup() {
    let mut m = machine();
    assert!(m.begin_initiator("npub1p"), "first is a fresh initiator");
    assert!(
        !m.begin_initiator("npub1p"),
        "second for same npub is a dup"
    );
    m.end_initiator("npub1p");
    assert!(
        m.begin_initiator("npub1p"),
        "fresh again after end_initiator"
    );
}

// --- replay (note_session_seen) ------------------------------------

#[test]
fn replay_first_then_repeat() {
    // First id Fresh; same id within window Replay.
    let mut m = machine();
    assert_eq!(m.note_session_seen("s1", 1000), SeenDecision::Fresh);
    assert_eq!(m.note_session_seen("s1", 1500), SeenDecision::Replay);
}

#[test]
fn replay_prunes_expired() {
    // An entry past its expiry is pruned, so re-seeing it is Fresh.
    let mut m = machine(); // replay_window_ms = 1_000_000
    assert_eq!(m.note_session_seen("s1", 1000), SeenDecision::Fresh);
    // now well past s1's expiry (1000 + 1_000_000): s1 pruned by retain,
    // so s1 is Fresh again rather than Replay.
    assert_eq!(m.note_session_seen("s1", 5_000_000), SeenDecision::Fresh);
}

#[test]
fn replay_cap_refuses_a_new_session_while_full_of_live_entries() {
    // A full cache refuses a new id rather than forgetting a live one.
    let mut m = machine(); // cap = 3, window huge so nothing expires here
    assert_eq!(m.note_session_seen("s1", 1), SeenDecision::Fresh);
    assert_eq!(m.note_session_seen("s2", 2), SeenDecision::Fresh);
    assert_eq!(m.note_session_seen("s3", 3), SeenDecision::Fresh);
    assert_eq!(m.note_session_seen("s4", 4), SeenDecision::Full);
    // Nothing was evicted, so s1 is still a replay.
    assert_eq!(m.note_session_seen("s1", 5), SeenDecision::Replay);
}
