//! Tests that the seen-sessions memory (`TraversalMachine::note_session_seen`
//! in `traversal_machine.rs`) never forgets a session id whose offer can still
//! be fresh: a full memory refuses a new session instead, both in the machine
//! and through the incoming-offer handler in `runtime.rs`, and its default
//! size holds every session the signal gate (`signal_gate.rs`) admits in one
//! replay window.

use super::super::runtime::NostrRendezvous;
use super::super::signal_gate::{
    ANSWER_RESERVE_BURST, ANSWER_RESERVE_RATE_PER_SEC, SIGNAL_BURST, SIGNAL_RATE_PER_SEC,
};
use super::super::traversal_machine::{SeenDecision, TraversalMachine};
use super::super::types::BootstrapError;
use super::offer_between;
use crate::config::NostrRendezvousConfig;

/// An explicit cap below the default, so the refusal tests turn on the
/// memory's behaviour when full rather than on the default's size.
const EXPLICIT_CAP: usize = 2048;

/// A memory with an explicit cap of 2048 records a captured session, then
/// 2048 others at 10 a second, all inside the 300 s replay window. The last
/// of them finds the memory full of live entries and is refused, and the
/// captured session is still a replay.
#[test]
fn a_full_cache_refuses_a_new_session_rather_than_forgetting_a_live_one() {
    let window_ms = NostrRendezvousConfig::default().replay_window_secs * 1000;
    let machine = TraversalMachine::new(window_ms, EXPLICIT_CAP);
    let t0 = 1_900_000_000_000u64;
    assert_eq!(
        machine.note_session_seen("captured", t0),
        SeenDecision::Fresh,
        "precondition: the captured session is recorded"
    );
    let mut last = SeenDecision::Fresh;
    let mut now = t0;
    for i in 0..EXPLICIT_CAP {
        now = t0 + (i as u64 + 1) * 100;
        last = machine.note_session_seen(&format!("filler-{i}"), now);
    }
    assert!(
        now - t0 < window_ms,
        "precondition: the fill ends inside the replay window"
    );

    assert_eq!(
        machine.note_session_seen("captured", now + 1),
        SeenDecision::Replay,
        "defect: a full memory forgot a session recorded {} ms earlier, inside its {window_ms} ms \
         replay window",
        now + 1 - t0
    );
    assert_eq!(
        last,
        SeenDecision::Full,
        "defect: the session past the cap was admitted rather than refused"
    );
    assert_eq!(
        machine.note_session_seen(&format!("filler-{}", EXPLICIT_CAP - 1), now + 2),
        SeenDecision::Full,
        "defect: the refused session was recorded"
    );
}

/// A full memory takes new sessions again once its entries pass their
/// replay window, and a session whose entry expired is new again.
#[test]
fn a_full_cache_admits_again_once_its_entries_expire() {
    let window_ms = 1_000;
    let machine = TraversalMachine::new(window_ms, 4);
    for i in 0..4u64 {
        assert_eq!(
            machine.note_session_seen(&format!("s{i}"), i),
            SeenDecision::Fresh,
            "precondition: s{i} is recorded while there is room"
        );
    }
    let after = 3 + window_ms + 1;
    assert_eq!(
        machine.note_session_seen("late", after),
        SeenDecision::Fresh,
        "defect: a new session is refused after every entry has expired"
    );
    assert_eq!(
        machine.note_session_seen("s0", after),
        SeenDecision::Fresh,
        "defect: a session whose entry expired is not new again"
    );
}

/// The default cap holds every session id the signal gate can admit in one
/// replay window: both allowances' sustained rates over
/// `replay_window_secs`, plus both bursts. Below that, a node at the defaults
/// can be driven to refuse offers through the gate alone.
#[test]
fn the_default_cap_holds_every_session_the_signal_gate_admits_in_one_replay_window() {
    let defaults = NostrRendezvousConfig::default();
    let admitted = (SIGNAL_RATE_PER_SEC + ANSWER_RESERVE_RATE_PER_SEC)
        * defaults.replay_window_secs as f64
        + SIGNAL_BURST
        + ANSWER_RESERVE_BURST;
    assert!(
        defaults.seen_sessions_max_entries as f64 >= admitted,
        "defect: the default seen_sessions_max_entries ({}) is below the {admitted} session ids \
         the signal gate admits in {} s",
        defaults.seen_sessions_max_entries,
        defaults.replay_window_secs
    );
}

/// The handler refuses a new offer with the `seen-sessions-full` reason when
/// the memory is full of live entries.
#[tokio::test]
async fn a_new_offer_is_refused_as_seen_sessions_full_by_the_handler_when_the_memory_is_full() {
    use nostr::ToBech32;
    let runtime = std::sync::Arc::new(NostrRendezvous::new_for_test_with_config(
        NostrRendezvousConfig {
            seen_sessions_max_entries: 2,
            ..Default::default()
        },
    ));
    let our_npub = runtime.npub_for_test().to_string();
    let peer = nostr::Keys::generate();
    let peer_npub = peer.public_key().to_bech32().unwrap();
    for i in 0..2 {
        let r = runtime
            .clone()
            .handle_incoming_offer_for_test(
                offer_between(&format!("filler-{i}"), &peer_npub, &our_npub),
                peer.public_key(),
                peer_npub.clone(),
            )
            .await;
        assert!(
            matches!(r, Err(BootstrapError::MissingRelays(_))),
            "precondition: offer {i} passes the replay check: {r:?}"
        );
    }
    let r = runtime
        .clone()
        .handle_incoming_offer_for_test(
            offer_between("past-the-cap", &peer_npub, &our_npub),
            peer.public_key(),
            peer_npub.clone(),
        )
        .await;
    assert!(
        matches!(&r, Err(BootstrapError::Protocol(reason)) if reason == "seen-sessions-full"),
        "defect: an offer past the cap was not refused as seen-sessions-full: {r:?}"
    );
}

/// An explicit cap, small enough that the handler fills it quickly. The
/// default is not used, so the test turns on the memory's behaviour when
/// full rather than on its size.
const HANDLER_CAP: usize = 64;

/// A responder records a captured offer, then receives as many other offers
/// as its seen-sessions memory holds, all inside one replay window. A copy of
/// the captured offer, still fresh, must still be refused as a replay.
#[tokio::test]
async fn a_captured_offer_is_still_refused_as_a_replay_after_the_seen_session_cap_fills() {
    use nostr::ToBech32;
    let runtime = std::sync::Arc::new(NostrRendezvous::new_for_test_with_config(
        NostrRendezvousConfig {
            seen_sessions_max_entries: HANDLER_CAP,
            ..Default::default()
        },
    ));
    let our_npub = runtime.npub_for_test().to_string();
    let peer = nostr::Keys::generate();
    let peer_npub = peer.public_key().to_bech32().unwrap();
    let handle = |offer: super::super::TraversalOffer| {
        let runtime = runtime.clone();
        let (sender, sender_npub) = (peer.public_key(), peer_npub.clone());
        async move {
            runtime
                .handle_incoming_offer_for_test(offer, sender, sender_npub)
                .await
        }
    };

    let captured = offer_between("captured", &peer_npub, &our_npub);
    // The test runtime shares no signal relay with the peer, so an offer that
    // passes the replay check fails afterwards with MissingRelays.
    let r = handle(captured.clone()).await;
    assert!(
        matches!(r, Err(BootstrapError::MissingRelays(_))),
        "precondition: the first copy passes the replay check: {r:?}"
    );
    let r = handle(captured.clone()).await;
    assert!(
        matches!(r, Err(BootstrapError::Replay(_))),
        "precondition: an immediate copy is refused as a replay: {r:?}"
    );
    // Expiry is kept in whole milliseconds. Without this pause the first
    // fillers can share the captured session's expiry, and an eviction by
    // expiry order then picks among the tied entries in hash order, so the
    // test would pass with the defect present on some runs.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;

    let started = std::time::Instant::now();
    for i in 0..HANDLER_CAP {
        let r = handle(offer_between(&format!("filler-{i}"), &peer_npub, &our_npub)).await;
        assert!(
            !matches!(r, Err(BootstrapError::Replay(_))),
            "precondition: a new session is not taken for a replay: {r:?}"
        );
    }
    let r = handle(captured.clone()).await;
    assert!(
        matches!(r, Err(BootstrapError::Replay(_))),
        "defect: the captured offer, still fresh ({} ms after the first copy), passed the \
         replay check: {r:?}",
        started.elapsed().as_millis()
    );
}
