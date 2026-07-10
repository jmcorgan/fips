//! Synchronous decision core for the Nostr NAT-traversal control state.
//!
//! `TraversalMachine` owns the engine-scoped, cross-session state that
//! previously lived directly on `NostrRendezvous` — the set of in-flight
//! outbound initiators, and the replay/seen-sessions cache — and hosts the
//! *decisions* over that state: initiator dedup, the dual-`auto_connect`
//! responder election, and replay rejection.
//!
//! Following the sans-IO shape used by `advert` / `failure_state`, every
//! method here is synchronous, performs no network I/O and no `.await`,
//! holds its state behind `std::sync::Mutex`, and takes the current time as
//! an explicit `now_ms: u64` input rather than reading a clock. The async
//! driver on `NostrRendezvous` reads the clock at the call site, derives the
//! `NodeAddr`s from npubs, and performs the actual socket/STUN/relay I/O.
//!
//! The inherently-async concurrency primitives stay driver-side: the
//! `pending_answers` oneshot routing and the `offer_slots` semaphore
//! admission are not modeled here, and neither is the punch send-cadence.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use crate::NodeAddr;

/// Decide whether an incoming-offer responder session should be suppressed
/// in favour of our own already-running outbound initiator session.
///
/// Two peers that each have the other as `auto_connect` simultaneously run an
/// initiator traversal *and* a responder traversal for the same peer, binding a
/// separate UDP socket per session. Each node then emits two
/// `BootstrapEvent::Established` events and `adopt_established_traversal` keeps
/// only the first on a non-deterministic race; when the two nodes' independent
/// races resolve to mismatched sessions, each side's Noise msg1 lands on a peer
/// port the peer already stopped draining and both handshakes stall.
///
/// To collapse the four-socket dance to a single, guaranteed-matching socket
/// pair, both nodes deterministically keep the session **initiated by the
/// smaller `NodeAddr`** — reusing the project's existing NodeAddr tie-breaker
/// convention (`cross_connection_winner`, the rekey dual-init resolution, and
/// the dual-cross-init adopt path in `lifecycle.rs`).
///
/// This is evaluated on the responder path, where the session being handled is
/// *peer-initiated*. It returns `true` (suppress this responder session) only
/// when genuine duplication exists — i.e. we also have an in-flight outbound
/// initiator for this same peer (`have_active_initiator`) — and our own
/// initiator session is the preferred one (`our_addr < peer_addr`). When there
/// is no co-active initiator (the asymmetric / one-sided `auto_connect` case,
/// where only one session exists at all) it never suppresses, so connectivity
/// is preserved. The `our_addr == peer_addr` case (self / loopback) and any
/// caller that cannot derive a peer `NodeAddr` likewise fall through to "do not
/// suppress".
pub(super) fn suppress_responder_for_own_initiator(
    our_addr: &NodeAddr,
    peer_addr: &NodeAddr,
    have_active_initiator: bool,
) -> bool {
    have_active_initiator && our_addr < peer_addr
}

/// Result of the dual-init responder election. Returned by
/// [`TraversalMachine::classify_incoming_offer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OfferDisposition {
    /// Answer this offer normally.
    Proceed,
    /// Decline this responder session; our own outbound initiator wins.
    Suppress,
}

/// Result of the replay / seen-sessions check. Returned by
/// [`TraversalMachine::note_session_seen`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SeenDecision {
    /// First time we've seen this session id within the replay window. If a
    /// cap eviction occurred, `evicted` carries `(evicted, retained)` for the
    /// driver's overflow debug line.
    Fresh { evicted: Option<(usize, usize)> },
    /// The session id is already present within the replay window.
    Replay,
}

pub(super) struct TraversalMachine {
    /// Replay window length in ms (`replay_window_secs * 1000`).
    replay_window_ms: u64,
    /// Size cap for the seen-sessions cache.
    seen_max_entries: usize,
    /// npubs of peers we currently have an in-flight outbound initiator for.
    active_initiators: Mutex<HashSet<String>>,
    /// Replay cache: session id -> expiry (ms).
    seen_sessions: Mutex<HashMap<String, u64>>,
}

impl TraversalMachine {
    pub(super) fn new(replay_window_ms: u64, seen_max_entries: usize) -> Self {
        Self {
            replay_window_ms,
            seen_max_entries,
            active_initiators: Mutex::new(HashSet::new()),
            seen_sessions: Mutex::new(HashMap::new()),
        }
    }

    // --- initiator lifecycle -------------------------------------------

    /// Register an in-flight outbound initiator for `npub`. Returns `false`
    /// when one is already active (dedup — the driver should not start a
    /// second).
    pub(super) fn begin_initiator(&self, npub: &str) -> bool {
        self.lock_initiators().insert(npub.to_string())
    }

    /// Clear the in-flight initiator for `npub` on task completion.
    pub(super) fn end_initiator(&self, npub: &str) {
        self.lock_initiators().remove(npub);
    }

    // --- responder dual-init election ----------------------------------

    /// Decide whether an incoming offer from `sender_npub` should be answered
    /// or suppressed in favour of our own outbound initiator. The driver
    /// derives both `NodeAddr`s (keeping today's derivation-failure "answer
    /// anyway" fallthrough) and passes them in; the machine reads its own
    /// active-initiator membership under its lock.
    pub(super) fn classify_incoming_offer(
        &self,
        sender_npub: &str,
        our_addr: &NodeAddr,
        peer_addr: &NodeAddr,
    ) -> OfferDisposition {
        let have_active = self.lock_initiators().contains(sender_npub);
        if suppress_responder_for_own_initiator(our_addr, peer_addr, have_active) {
            OfferDisposition::Suppress
        } else {
            OfferDisposition::Proceed
        }
    }

    // --- replay / seen-sessions ----------------------------------------

    /// Record that `session_id` was seen at `now_ms`. Prunes expired entries,
    /// rejects a replay, inserts the fresh id, then applies the size cap.
    ///
    /// Returns [`SeenDecision::Replay`] in place of the old
    /// `Err(BootstrapError::Replay)`, or [`SeenDecision::Fresh`] carrying the
    /// `(evicted, retained)` pair when a cap eviction occurred.
    pub(super) fn note_session_seen(&self, session_id: &str, now_ms: u64) -> SeenDecision {
        let expiry = now_ms + self.replay_window_ms;
        let mut seen = self.lock_seen();
        seen.retain(|_, expires_at| *expires_at > now_ms);
        if seen.contains_key(session_id) {
            return SeenDecision::Replay;
        }
        seen.insert(session_id.to_string(), expiry);
        if seen.len() > self.seen_max_entries {
            let mut oldest = seen
                .iter()
                .map(|(session, expires_at)| (session.clone(), *expires_at))
                .collect::<Vec<_>>();
            oldest.sort_by_key(|(_, expires_at)| *expires_at);
            let overflow = seen.len().saturating_sub(self.seen_max_entries);
            for (session, _) in oldest.into_iter().take(overflow) {
                seen.remove(&session);
            }
            return SeenDecision::Fresh {
                evicted: Some((overflow, seen.len())),
            };
        }
        SeenDecision::Fresh { evicted: None }
    }

    // --- lock helpers ---------------------------------------------------

    fn lock_initiators(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.active_initiators
            .lock()
            .expect("traversal-machine active-initiators mutex poisoned")
    }

    fn lock_seen(&self) -> std::sync::MutexGuard<'_, HashMap<String, u64>> {
        self.seen_sessions
            .lock()
            .expect("traversal-machine seen-sessions mutex poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_addr(first_byte: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = first_byte;
        NodeAddr::from_bytes(bytes)
    }

    fn machine() -> TraversalMachine {
        TraversalMachine::new(1_000_000, 3)
    }

    // --- election ordering (classify_incoming_offer) -------------------

    #[test]
    fn election_vectors() {
        let smaller = node_addr(0x01);
        let larger = node_addr(0x02);
        let peer = "npub1peer";

        // V1: co-active initiator, our addr smaller -> Suppress.
        let m = machine();
        assert!(m.begin_initiator(peer));
        assert_eq!(
            m.classify_incoming_offer(peer, &smaller, &larger),
            OfferDisposition::Suppress
        );

        // V2: co-active initiator, our addr larger -> Proceed.
        let m = machine();
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
        let m = machine();
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
        let m = machine();
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
        let m = machine();
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
        // R1: first id Fresh; same id within window Replay.
        let m = machine();
        assert_eq!(
            m.note_session_seen("s1", 1000),
            SeenDecision::Fresh { evicted: None }
        );
        assert_eq!(m.note_session_seen("s1", 1500), SeenDecision::Replay);
    }

    #[test]
    fn replay_prunes_expired() {
        // R2: an entry past its expiry is pruned, so re-seeing it is Fresh.
        let m = machine(); // replay_window_ms = 1_000_000
        assert_eq!(
            m.note_session_seen("s1", 1000),
            SeenDecision::Fresh { evicted: None }
        );
        // now well past s1's expiry (1000 + 1_000_000): s1 pruned by retain,
        // so s1 is Fresh again rather than Replay.
        assert_eq!(
            m.note_session_seen("s1", 5_000_000),
            SeenDecision::Fresh { evicted: None }
        );
    }

    #[test]
    fn replay_cap_evicts_oldest_by_expiry() {
        // R3: cap overflow evicts oldest-by-expiry, returns (evicted, retained).
        let m = machine(); // cap = 3, window huge so nothing expires here
        assert_eq!(
            m.note_session_seen("s1", 1),
            SeenDecision::Fresh { evicted: None }
        );
        assert_eq!(
            m.note_session_seen("s2", 2),
            SeenDecision::Fresh { evicted: None }
        );
        assert_eq!(
            m.note_session_seen("s3", 3),
            SeenDecision::Fresh { evicted: None }
        );
        assert_eq!(
            m.note_session_seen("s4", 4),
            SeenDecision::Fresh {
                evicted: Some((1, 3))
            }
        );
        // Oldest expiry (s1) was evicted, so re-seeing it is Fresh.
        assert_eq!(
            m.note_session_seen("s1", 5),
            SeenDecision::Fresh {
                evicted: Some((1, 3))
            }
        );
    }
}
