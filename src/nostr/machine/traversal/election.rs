//! Synchronous decision core for the Nostr NAT-traversal control state.
//!
//! `Election` owns the engine-scoped, cross-session state that
//! previously lived directly on `NostrRendezvous` — the set of in-flight
//! outbound initiators, and the replay/seen-sessions cache — and hosts the
//! *decisions* over that state: initiator dedup, the dual-`auto_connect`
//! responder election, and replay rejection.
//!
//! Like the rest of the machine, every method here is synchronous, performs
//! no I/O and no `.await`, and takes the current time as an explicit
//! `now_ms: u64` input rather than reading a clock. It holds no lock: the
//! runtime keeps the `Election` behind one `std::sync::Mutex`. The async
//! driver on `NostrRendezvous` reads the clock at the call site, derives the
//! `NodeAddr`s from npubs, and performs the actual socket/STUN/relay I/O.
//!
//! The inherently-async concurrency primitives stay driver-side: the
//! `pending_answers` oneshot routing and the `offer_slots` semaphore
//! admission are not modeled here, and neither is the punch send-cadence.

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};

use fips_core::identity::NodeAddr;
use fips_core::utils::hash::{HashMap, KeyedHasher};

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
pub fn suppress_responder_for_own_initiator(
    our_addr: &NodeAddr,
    peer_addr: &NodeAddr,
    have_active_initiator: bool,
) -> bool {
    have_active_initiator && our_addr < peer_addr
}

/// Result of the dual-init responder election. Returned by
/// [`Election::classify_incoming_offer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferDisposition {
    /// Answer this offer normally.
    Proceed,
    /// Decline this responder session; our own outbound initiator wins.
    Suppress,
}

/// Result of the replay / seen-sessions check. Returned by
/// [`Election::note_session_seen`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeenDecision {
    /// First time we've seen this session id within the replay window; it is
    /// now recorded.
    Fresh,
    /// The session id is already present within the replay window.
    Replay,
    /// The cache holds `seen_max_entries` ids that are all still inside the
    /// replay window. The new id is refused and not recorded, because making
    /// room would forget a session whose offer can still be fresh, and a copy
    /// of that offer would then pass the replay check.
    Full,
}

/// The initiator set and the seen-sessions cache, and the decisions over
/// them.
pub struct Election {
    /// Replay window length in ms (`replay_window_secs * 1000`).
    replay_window_ms: u64,
    /// Size cap for the seen-sessions cache.
    seen_max_entries: usize,
    /// npubs of peers we currently have an in-flight outbound initiator for.
    /// Only ever tested for membership.
    active_initiators: BTreeSet<String>,
    /// Replay cache: session id -> expiry (ms). Keyed by an id the peer
    /// chooses, so the map's hasher is keyed from the host's entropy.
    seen_sessions: HashMap<String, u64>,
}

impl Election {
    /// An election with no initiators and no seen sessions, its seen-sessions
    /// map keyed with `hasher`.
    pub fn new(replay_window_ms: u64, seen_max_entries: usize, hasher: KeyedHasher) -> Self {
        Self {
            replay_window_ms,
            seen_max_entries,
            active_initiators: BTreeSet::new(),
            seen_sessions: HashMap::with_hasher(hasher),
        }
    }

    // --- initiator lifecycle -------------------------------------------

    /// Register an in-flight outbound initiator for `npub`. Returns `false`
    /// when one is already active (dedup — the driver should not start a
    /// second).
    pub fn begin_initiator(&mut self, npub: &str) -> bool {
        self.active_initiators.insert(npub.to_string())
    }

    /// Clear the in-flight initiator for `npub` on task completion.
    pub fn end_initiator(&mut self, npub: &str) {
        self.active_initiators.remove(npub);
    }

    // --- responder dual-init election ----------------------------------

    /// Decide whether an incoming offer from `sender_npub` should be answered
    /// or suppressed in favour of our own outbound initiator. The driver
    /// derives both `NodeAddr`s (keeping today's derivation-failure "answer
    /// anyway" fallthrough) and passes them in; the machine reads its own
    /// active-initiator membership.
    pub fn classify_incoming_offer(
        &self,
        sender_npub: &str,
        our_addr: &NodeAddr,
        peer_addr: &NodeAddr,
    ) -> OfferDisposition {
        let have_active = self.active_initiators.contains(sender_npub);
        if suppress_responder_for_own_initiator(our_addr, peer_addr, have_active) {
            OfferDisposition::Suppress
        } else {
            OfferDisposition::Proceed
        }
    }

    // --- replay / seen-sessions ----------------------------------------

    /// Record that `session_id` was seen at `now_ms`. Prunes expired entries,
    /// rejects a replay, then records the fresh id if there is room.
    ///
    /// Returns [`SeenDecision::Replay`] for an id still inside the replay
    /// window, [`SeenDecision::Full`] when the cache holds `seen_max_entries`
    /// live ids (the new id is not recorded), and [`SeenDecision::Fresh`]
    /// otherwise. A live id is never removed to make room.
    pub fn note_session_seen(&mut self, session_id: &str, now_ms: u64) -> SeenDecision {
        let expiry = now_ms + self.replay_window_ms;
        let seen = &mut self.seen_sessions;
        seen.retain(|_, expires_at| *expires_at > now_ms);
        if seen.contains_key(session_id) {
            return SeenDecision::Replay;
        }
        if seen.len() >= self.seen_max_entries {
            return SeenDecision::Full;
        }
        seen.insert(session_id.to_string(), expiry);
        SeenDecision::Fresh
    }
}

#[cfg(test)]
#[path = "tests/election.rs"]
mod tests;
