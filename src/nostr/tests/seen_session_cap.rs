//! Tests that the seen-sessions memory (`Election::note_session_seen` in
//! `machine/traversal/election.rs`) never forgets a session id whose offer can
//! still be fresh: a full memory refuses a new session instead, and its
//! default size holds every session the signal gate
//! (`machine/traversal/gate.rs`) admits in one replay window. The same
//! refusals through the responder's handling of an offer are tested in
//! `machine/rendezvous/tests/traversal.rs`.

use super::super::machine::tests::ZeroEntropy;
use super::super::machine::traversal::election::{Election, SeenDecision};
use super::super::machine::traversal::gate::{
    ANSWER_RESERVE_BURST, ANSWER_RESERVE_RATE_PER_SEC, SIGNAL_BURST, SIGNAL_RATE_PER_SEC,
};
use crate::config::NostrRendezvousConfig;
use fips_core::utils::hash::KeyedHasher;

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
    let mut machine = Election::new(window_ms, EXPLICIT_CAP, KeyedHasher::new::<ZeroEntropy>());
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
    let mut machine = Election::new(window_ms, 4, KeyedHasher::new::<ZeroEntropy>());
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
