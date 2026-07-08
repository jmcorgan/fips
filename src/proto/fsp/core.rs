//! Sans-IO FSP session-rekey + epoch-reaction decision core.
//!
//! Pure, runtime-agnostic decisions for the FSP end-to-end session lifecycle:
//! the per-tick rekey choreography (initiator cutover, drain completion, rekey
//! trigger), msg3 retransmission classification, and the post-decrypt epoch
//! reaction. The async I/O adapters in `node::handlers::{rekey,session}` build
//! the plain-data snapshots (pre-computing every clock read into `u64`/`bool`),
//! call these decisions, and drive the returned effects — the sends, the
//! `SessionEntry` mutations, metrics, and logging. No I/O, no clock, no crypto,
//! no metrics, no logging here.
//!
//! The crypto-owning `SessionEntry` stays shell-side (`node::session`), so this
//! core carries no `proto -> noise` and no `proto -> node` dependency: the
//! trial-decrypt AEAD open runs shell-side and the resulting epoch is mapped to
//! the plain-data [`DecryptSlot`] mirror before it reaches [`Fsp::classify_epoch`].

use super::limits::FSP_CUTOVER_DELAY_MS;
use crate::proto::stp::TreeCoordinate;
use crate::{FipsAddress, NodeAddr};

/// FSP session-lifecycle subsystem anchor owned by [`Node`](crate::node::Node).
///
/// Like [`Fmp`](crate::proto::fmp::Fmp), the FSP core owns **no** mutable state:
/// every `SessionEntry`/coord-cache/path-MTU mutation stays shell-side, driven
/// by the [`FspAction`]s (and outcome enums) the pure decisions emit. `Fsp` is a
/// stateless namespace anchor so the decisions can hang off a `Node` field
/// (`self.fsp`) in the same shape the other migrated subsystems use.
pub(crate) struct Fsp;

impl Fsp {
    /// Create the (stateless) FSP lifecycle anchor.
    pub(crate) fn new() -> Self {
        Self
    }
}

/// A registry/session effect the async shell performs on the core's behalf.
///
/// Only the variants the stage-2 rekey/epoch decisions actually emit are
/// defined; the send/decrypt-path effects are added when their emitting arms
/// migrate (an unconstructed variant would trip `clippy::dead_code`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FspAction {
    /// Perform the initiator-side K-bit cutover to `addr`'s pending session
    /// (`SessionEntry::cutover_to_new_session`).
    CutOver { addr: NodeAddr },
    /// Complete `addr`'s drain window (`SessionEntry::complete_drain`): erase
    /// the previous session.
    CompleteDrain { addr: NodeAddr },
    /// Initiate a fresh outbound rekey to `addr` (`initiate_session_rekey`).
    /// The XK msg1 construction is the shell-side establish leaf; the action
    /// carries only the target.
    InitiateRekey { addr: NodeAddr },
    /// Abandon `addr`'s in-flight rekey cycle (`SessionEntry::abandon_rekey`):
    /// its msg3 went unconfirmed past the retransmission budget.
    AbandonRekey { addr: NodeAddr },
    /// Retransmit `addr`'s retained rekey msg3 (the shell re-reads the payload
    /// from the entry, sends it, then records the retransmission on success).
    ResendSessionMsg3 { addr: NodeAddr },
    /// Cache `coords` for `addr` in the shared coordinate cache
    /// (`coord_cache.insert`).
    CacheCoords {
        addr: NodeAddr,
        coords: TreeCoordinate,
    },
    /// Invalidate the shared cached coordinates for `addr`
    /// (`coord_cache.remove`).
    InvalidateCoords { addr: NodeAddr },
    /// Write `mtu` into the shared `FipsAddress`-keyed path-MTU lookup, keeping
    /// the tighter of existing-or-new (the shell applies the write under the
    /// `path_mtu_lookup` guard).
    TightenPathMtuLookup { fips_addr: FipsAddress, mtu: u16 },
    /// Trigger discovery toward `dest` (`maybe_initiate_lookup`); emitted only
    /// when the target's identity is cached.
    InitiateLookup { dest: NodeAddr },
}

/// The rekey trigger thresholds, read shell-side from node config.
pub(crate) struct RekeyCfg {
    /// Rekey after this many seconds of session age (before jitter).
    pub after_secs: u64,
    /// Rekey after this many sent messages.
    pub after_messages: u64,
}

/// A snapshot of one established session's rekey-relevant state, taken by the
/// shell so the core decides without touching the live `SessionEntry` or reading
/// a clock.
///
/// Every clock read is resolved shell-side into a plain `u64`/`bool`:
/// `cutover_timer_elapsed`, `drain_expired`, and `is_dampened` are the
/// pre-evaluated timer predicates; `elapsed_secs` is the monotonic session age.
/// The core applies the rekey thresholds and jitter with **no** clock read.
pub(crate) struct SessionSnapshot {
    /// The session's remote node address (cutover/drain/rekey target).
    pub addr: NodeAddr,
    /// A completed rekey session is pending, awaiting the K-bit cutover.
    pub has_pending: bool,
    /// A rekey handshake is currently in flight.
    pub rekey_in_progress: bool,
    /// We initiated the current rekey (only the initiator cuts over on the
    /// liveness timer).
    pub is_rekey_initiator: bool,
    /// The initiator liveness-cutover delay has elapsed (pre-evaluated:
    /// `now - rekey_completed_ms >= FSP_CUTOVER_DELAY_MS`).
    pub cutover_timer_elapsed: bool,
    /// The session is in its post-cutover drain window.
    pub is_draining: bool,
    /// The drain window has expired (pre-evaluated against the drain timer).
    pub drain_expired: bool,
    /// The initiator still retains a msg3 retransmission payload (a rekey cycle
    /// is mid-flight; do not start another).
    pub has_rekey_msg3_payload: bool,
    /// Local rekey initiation is dampened after a recently received peer rekey
    /// msg1 (pre-evaluated against the dampening timer).
    pub is_dampened: bool,
    /// Monotonic session age in seconds (`(now - session_start_ms) / 1000`).
    pub elapsed_secs: u64,
    /// Current Noise send counter.
    pub counter: u64,
    /// Per-session symmetric rekey jitter, added to the time threshold.
    pub jitter_secs: i64,
}

/// A snapshot of one session with a retained rekey-msg3 payload, taken by the
/// shell for the msg3 retransmission decision.
pub(crate) struct RekeyMsg3ResendSnapshot {
    /// The session's remote node address (abandon/resend target).
    pub addr: NodeAddr,
    /// How many msg3 retransmissions have already happened. Drives the
    /// abandon-vs-resend classification.
    pub resend_count: u32,
    /// The retained msg3 is due for retransmission as of the shell's `now_ms`
    /// (pre-evaluated: `next_resend_ms != 0 && now_ms >= next_resend_ms`).
    pub resend_due: bool,
}

/// Which key epoch a just-decrypted frame authenticated against — the shell-side
/// [`EpochSlot`](crate::node::session::EpochSlot) mapped to a proto-local
/// plain-data mirror so the core carries no `node` dependency.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DecryptSlot {
    /// Decrypted against the current (active) session — steady state.
    Current,
    /// Decrypted against the pending (new) session — the peer cut over first.
    Pending,
    /// Decrypted against the previous (draining) session — old-epoch straggler.
    Previous,
}

/// The reaction the shell drives after a frame authenticates against a given
/// epoch. Post-decrypt classification (§3): the shell opens the frame, the core
/// classifies, the shell applies the `SessionEntry` mutation + observability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EpochReaction {
    /// A `pending` hit while a msg3 retransmission is retained: confirm the peer
    /// on the new epoch (stop retransmitting), then promote (cutover).
    PromoteConfirming,
    /// A `pending` hit with no retained msg3: promote (cutover).
    Promote,
    /// A `current` hit as the already-cut-over initiator (msg3 retained, no
    /// pending): confirm the responder reached the new epoch.
    ConfirmResponder,
    /// No state change (a steady-state `current` hit, or an old-epoch
    /// `previous` straggler — the drain refresh already happened shell-side).
    None,
}

impl Fsp {
    /// Decide the per-tick rekey choreography for the established sessions the
    /// shell snapshotted. Reproduces `check_session_rekey`'s priority and phase
    /// grouping exactly:
    ///
    /// - **Cutover** takes precedence: an initiator with a pending session, no
    ///   in-flight rekey, and an elapsed liveness timer cuts over and is
    ///   considered for nothing else.
    /// - Otherwise an expired drain window is completed, and — independently —
    ///   the rekey trigger fires when the session is neither mid-rekey, holding
    ///   a pending session, retaining a msg3 payload, nor dampened, and its
    ///   jittered time threshold or send counter is reached.
    ///
    /// Actions are returned phase-grouped (all cutovers, then all drains, then
    /// all rekey initiations) to preserve the pre-refactor execution order.
    pub(crate) fn poll_rekey(
        &self,
        sessions: Vec<SessionSnapshot>,
        cfg: &RekeyCfg,
    ) -> Vec<FspAction> {
        let mut cutovers = Vec::new();
        let mut drains = Vec::new();
        let mut rekeys = Vec::new();
        for s in sessions {
            // 1. Initiator-side cutover (unconditional liveness timer).
            if s.has_pending
                && !s.rekey_in_progress
                && s.is_rekey_initiator
                && s.cutover_timer_elapsed
            {
                cutovers.push(FspAction::CutOver { addr: s.addr });
                continue;
            }
            // 2. Drain window expiry (does not preclude a trigger below).
            if s.is_draining && s.drain_expired {
                drains.push(FspAction::CompleteDrain { addr: s.addr });
            }
            // 3. Rekey trigger.
            if s.rekey_in_progress || s.has_pending || s.has_rekey_msg3_payload || s.is_dampened {
                continue;
            }
            let effective_after = cfg.after_secs.saturating_add_signed(s.jitter_secs);
            if s.elapsed_secs >= effective_after || s.counter >= cfg.after_messages {
                rekeys.push(FspAction::InitiateRekey { addr: s.addr });
            }
        }
        cutovers.extend(drains);
        cutovers.extend(rekeys);
        cutovers
    }

    /// Decide the msg3 retransmission choreography for the sessions the shell
    /// snapshotted as retaining a msg3 payload. A due candidate past
    /// `max_resends` has its cycle abandoned; an in-budget due candidate is
    /// retransmitted. Candidates not yet due are neither abandoned nor resent
    /// this tick (matching the pre-refactor due-gate ordering).
    ///
    /// Actions are returned abandons-first (matching the pre-refactor two-pass
    /// order); the shell commits a retransmission's count++ and reschedule only
    /// on a successful send.
    pub(crate) fn poll_rekey_msg3_resends(
        &self,
        candidates: Vec<RekeyMsg3ResendSnapshot>,
        max_resends: u32,
    ) -> Vec<FspAction> {
        let mut abandons = Vec::new();
        let mut resends = Vec::new();
        for c in candidates {
            if !c.resend_due {
                continue;
            }
            if c.resend_count >= max_resends {
                abandons.push(FspAction::AbandonRekey { addr: c.addr });
                continue;
            }
            resends.push(FspAction::ResendSessionMsg3 { addr: c.addr });
        }
        abandons.extend(resends);
        abandons
    }

    /// Classify the reaction to a frame that authenticated against `slot`. Pure
    /// over the slot and the two plain-data session flags; the shell applies the
    /// resulting `SessionEntry` mutation and observability.
    ///
    /// Mirrors the pre-refactor `handle_encrypted_session_msg` epoch reaction
    /// exactly: a `pending` hit always promotes (confirming first when a msg3
    /// payload is retained); a `current` hit confirms the responder only when
    /// the initiator already cut over (msg3 retained, no pending); a `previous`
    /// hit is a no-op (the drain refresh happened during the shell-side open).
    pub(crate) fn classify_epoch(
        &self,
        slot: DecryptSlot,
        has_rekey_msg3_payload: bool,
        has_pending: bool,
    ) -> EpochReaction {
        match slot {
            DecryptSlot::Pending => {
                if has_rekey_msg3_payload {
                    EpochReaction::PromoteConfirming
                } else {
                    EpochReaction::Promote
                }
            }
            DecryptSlot::Current => {
                if has_rekey_msg3_payload && !has_pending {
                    EpochReaction::ConfirmResponder
                } else {
                    EpochReaction::None
                }
            }
            DecryptSlot::Previous => EpochReaction::None,
        }
    }

    /// Decide which cleartext-coords (CP flag) present on an inbound encrypted
    /// frame to cache. Emits an ordered `CacheCoords` per present coordinate:
    /// the source's coords keyed by `src_addr`, then the destination's coords
    /// keyed by `my_addr` (our own address). Mirrors the pre-refactor
    /// `handle_encrypted_session_msg` CP-coords caching order.
    pub(crate) fn plan_cache_coords(
        &self,
        src_addr: NodeAddr,
        my_addr: NodeAddr,
        src_coords: Option<TreeCoordinate>,
        dest_coords: Option<TreeCoordinate>,
    ) -> Vec<FspAction> {
        let mut actions = Vec::new();
        if let Some(coords) = src_coords {
            actions.push(FspAction::CacheCoords {
                addr: src_addr,
                coords,
            });
        }
        if let Some(coords) = dest_coords {
            actions.push(FspAction::CacheCoords {
                addr: my_addr,
                coords,
            });
        }
        actions
    }

    /// Decide the discovery reaction to a `CoordsRequired` signal: trigger a
    /// lookup toward `dest` only when the target's identity is cached (else the
    /// `LookupResponse` proof cannot be verified). The rate-limited warmup send
    /// and warmup-counter reset stay shell-side.
    pub(crate) fn plan_coords_required_lookup(
        &self,
        dest: NodeAddr,
        has_cached_identity: bool,
    ) -> Vec<FspAction> {
        if has_cached_identity {
            vec![FspAction::InitiateLookup { dest }]
        } else {
            Vec::new()
        }
    }

    /// Decide the reaction to a `PathBroken` signal: unconditionally invalidate
    /// the stale cached coordinates for `dest`, then (only when the identity is
    /// cached) trigger re-discovery. Order is invalidate-then-lookup, matching
    /// the pre-refactor handler. The warmup send and counter reset stay shell.
    pub(crate) fn plan_path_broken(
        &self,
        dest: NodeAddr,
        has_cached_identity: bool,
    ) -> Vec<FspAction> {
        let mut actions = vec![FspAction::InvalidateCoords { addr: dest }];
        if has_cached_identity {
            actions.push(FspAction::InitiateLookup { dest });
        }
        actions
    }

    /// Decide whether a path-MTU update should tighten the shared lookup: emit
    /// `TightenPathMtuLookup` only when `candidate` is at least as tight as the
    /// `existing` value (keep-tighter, never loosen). The `existing` read and
    /// the applied write are performed shell-side under one `path_mtu_lookup`
    /// write guard, so the decision stays atomic.
    pub(crate) fn plan_path_mtu_tighten(
        &self,
        fips_addr: FipsAddress,
        existing: Option<u16>,
        candidate: u16,
    ) -> Vec<FspAction> {
        if should_apply_path_mtu(existing, candidate) {
            vec![FspAction::TightenPathMtuLookup {
                fips_addr,
                mtu: candidate,
            }]
        } else {
            Vec::new()
        }
    }
}

/// Pre-evaluate the initiator liveness-cutover timer for a session: whether the
/// `FSP_CUTOVER_DELAY_MS` bound has elapsed since the rekey handshake completed.
/// Resolved shell-side into [`SessionSnapshot::cutover_timer_elapsed`].
pub(crate) fn cutover_timer_elapsed(now_ms: u64, rekey_completed_ms: u64) -> bool {
    now_ms.saturating_sub(rekey_completed_ms) >= FSP_CUTOVER_DELAY_MS
}

/// Determine the winner of an FSP session-initiation tie-break: the node with
/// the smaller `NodeAddr` wins as initiator. Deterministic and symmetric — both
/// endpoints reach the same conclusion. Used for both simultaneous session
/// setup and dual rekey initiation.
///
/// Returns `true` if *we* win (keep initiating, drop the peer's message).
pub(crate) fn initiation_winner(our_node_addr: &NodeAddr, their_node_addr: &NodeAddr) -> bool {
    our_node_addr < their_node_addr
}

/// Decide whether a path-MTU update should be applied to the shared
/// `FipsAddress`-keyed lookup: keep the tighter of existing-or-candidate, never
/// loosen. Returns `true` when `candidate` should be written (there is no
/// existing value, or the candidate is at least as tight).
pub(crate) fn should_apply_path_mtu(existing: Option<u16>, candidate: u16) -> bool {
    !matches!(existing, Some(existing) if existing <= candidate)
}

/// Push `packet` onto a bounded per-destination pending queue, dropping the
/// oldest entry first when the queue is at `per_dest` capacity. Pure transform
/// over a passed-in queue (the max-destinations cap is a shell-side map-level
/// check).
pub(crate) fn push_bounded_pending(
    queue: &mut alloc::collections::VecDeque<Vec<u8>>,
    packet: Vec<u8>,
    per_dest: usize,
) {
    if queue.len() >= per_dest {
        queue.pop_front(); // Drop oldest
    }
    queue.push_back(packet);
}

/// Mark ECN-CE in an IPv6 packet's Traffic Class field.
///
/// IPv6 Traffic Class occupies bits across bytes 0 and 1:
///   byte[0] bits[3:0] = TC[7:4]
///   byte[1] bits[7:4] = TC[3:0]
/// ECN is TC[1:0]. Only marks CE (0b11) if the packet is ECN-capable (ECT(0) or
/// ECT(1)). Packets with ECN=0b00 (Not-ECT) are never marked per RFC 3168.
///
/// No checksum update needed: IPv6 has no header checksum, and the Traffic Class
/// field is not part of the TCP/UDP pseudo-header.
pub(crate) fn mark_ipv6_ecn_ce(packet: &mut [u8]) {
    if packet.len() < 2 {
        return;
    }
    // Extract 8-bit Traffic Class from IPv6 header bytes 0-1
    let tc = ((packet[0] & 0x0F) << 4) | (packet[1] >> 4);
    let ecn = tc & 0x03;
    // Only mark CE on ECN-capable packets (ECT(0)=0b10 or ECT(1)=0b01)
    if ecn == 0 {
        return;
    }
    // Set both ECN bits to 1 (CE = 0b11)
    let new_tc = tc | 0x03;
    packet[0] = (packet[0] & 0xF0) | (new_tc >> 4);
    packet[1] = (new_tc << 4) | (packet[1] & 0x0F);
}
