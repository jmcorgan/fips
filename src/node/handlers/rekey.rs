//! Periodic rekey (key rotation) for FMP link sessions, and the executor of
//! the end-to-end session rekey machines.
//!
//! Checks all active peers on each tick for:
//! 1. Rekey trigger (time elapsed or send counter exceeded)
//! 2. Drain window expiry (clean up previous session after cutover)
//! 3. Initiator-side cutover (first send after handshake completion)
//! 4. Retirement of a responder's pending session the initiator never adopted
//!
//! Each session's rekey machine runs its first handshake and decides its own
//! rekeys: it is polled on the tick, and the outputs it returns there or
//! from a session handshake message or frame are carried out here.

use crate::NodeAddr;
use crate::node::Node;
use crate::node::dataplane::PeerActionCtx;
use crate::node::diag::{self, OrNone};
use crate::node::reject::{RejectReason, SessionReject};
use crate::node::session::{SessionInstant, SessionOutput, SessionOutputs};
use crate::noise::HandshakeState;
use crate::peer::machine::PeerEvent;
use crate::proto::fmp::wire::build_msg1;
use crate::proto::fmp::{ConnAction, LifecycleView, PeerSnapshot, RekeyCfg, RekeyResendSnapshot};
use crate::proto::fsp::{SessionAck, SessionMsg3, SessionSetup};
use crate::proto::link::SessionDatagram;
use crate::proto::stp::{TreeCoordinate, coords_wire_size, encode_coords};
use crate::transport::{TransportAddr, TransportId};
use fips_core::proto::rekey::{EpochTag, MsgKind, NodeKeys};
use tracing::{debug, info, trace, warn};

/// Keep previous session alive for this long after cutover.
///
/// FMP-scoped copy for `check_rekey`; the FSP session-rekey timing bounds live
/// in `crate::proto::fsp::limits`.
const DRAIN_WINDOW_SECS: u64 = 10;

// A rekey msg1 is answered only once this drain window has passed since the
// last cutover; a shorter floor would let the responder arm complete a drain
// early.
const _: () = assert!(DRAIN_WINDOW_SECS <= crate::proto::fmp::REKEY_MIN_CUTOVER_AGE_SECS);

/// Suppress local rekey initiation for this long after receiving
/// a peer's rekey msg1. FMP-scoped copy for `check_rekey`.
const REKEY_DAMPENING_SECS: u64 = 30;

/// Floor on the absolute ceiling for `previous`-slot retention after a
/// cutover, in seconds.
///
/// The drain deadline is peer-progress-aware: it slides forward on every
/// inbound frame that authenticates against the old epoch, so a peer that
/// keeps sealing in that epoch holds the retired key for as long as it
/// likes. This bounds that. It has to stay longer than the worst-case
/// recovery of a legitimate peer that lost msg3, which at stock defaults
/// is the msg3 resend ladder (about 31 s) plus `handshake_timeout_secs`
/// (30 s) before the responder abandons plus `REKEY_DAMPENING_SECS`
/// (30 s) before it may re-initiate, so about 90 s. 120 s clears that
/// with margin and still bounds retention to roughly one
/// `node.rekey.after_secs` period. `drain_max_retention_ms` takes the
/// larger of this floor and the budget the running configuration
/// actually implies, so a shortened handshake timer cannot push the
/// ceiling under the recovery it has to clear.
///
/// Lowering it below that budget cuts off legitimate slow peers: their
/// frames go silently undecryptable until their own rekey retry
/// re-converges the epochs, because nothing tears an established session
/// down on repeated decrypt failure. Raising it lengthens the window in
/// which a retired key stays resident.
const DRAIN_MAX_RETENTION_SECS: u64 = crate::proto::fsp::limits::DRAIN_WINDOW_SECS * 12;

/// Effective ceiling on total `previous`-slot retention, in milliseconds.
///
/// The larger of `DRAIN_MAX_RETENTION_SECS` and the msg3 recovery budget
/// the configured handshake timers imply, so the ceiling always clears
/// the recovery it is supposed to leave room for.
pub(in crate::node) fn drain_max_retention_ms(rate_limit: &crate::config::RateLimitConfig) -> u64 {
    let recovery_budget_ms = ladder_ms(rate_limit)
        .saturating_add(rate_limit.handshake_timeout_secs.saturating_mul(1000))
        .saturating_add(crate::proto::fsp::limits::REKEY_DAMPENING_SECS * 1000);
    (DRAIN_MAX_RETENTION_SECS * 1000).max(recovery_budget_ms)
}

/// Sum of the handshake resend intervals, in milliseconds: the initial
/// interval, multiplied by the backoff factor after each resend, over the
/// configured number of resends.
fn ladder_ms(rate_limit: &crate::config::RateLimitConfig) -> u64 {
    let mut total: u64 = 0;
    let mut interval = rate_limit.handshake_resend_interval_ms as f64;
    for _ in 0..rate_limit.handshake_max_resends {
        total = total.saturating_add(interval as u64);
        interval *= rate_limit.handshake_resend_backoff;
    }
    total
}

/// The longest silence, in milliseconds, the node tolerates on a link it
/// keeps.
///
/// A peer's handshake resend ladder, three ticks of scheduling slack, and
/// the longer of one heartbeat interval and the link-dead timeout. The
/// link-dead reap is suppressed while a rekey still has msg1 resends left,
/// which is what the ladder term covers. 64 s at stock settings.
pub(in crate::node) fn link_silence_ms(node: &crate::config::NodeConfig) -> u64 {
    let after_ms = node
        .heartbeat_interval_secs
        .max(node.link_dead_timeout_secs)
        .saturating_mul(1000);
    ladder_ms(&node.rate_limit)
        .saturating_add(node.tick_interval_secs.saturating_mul(3000))
        .saturating_add(after_ms)
}

/// The inbound idle deadline for stream transports: how long an accepted
/// connection may go without delivering a complete frame once it has
/// delivered one.
///
/// Set to `link_silence_ms`, so a connection carrying a link the node would
/// keep is never dropped by it, whatever the heartbeat, link-dead, tick and
/// resend settings are; a connection carrying no live link is reclaimed.
pub(in crate::node) fn inbound_idle_timeout(
    node: &crate::config::NodeConfig,
) -> std::time::Duration {
    std::time::Duration::from_millis(link_silence_ms(node))
}

/// How long a rekey responder holds a pending session its initiator has
/// not adopted before retiring it.
///
/// The initiator reads a msg2 only while it holds its handshake, so the
/// msg1 resend ladder, one tick to the abandon and one tick to the
/// cutover bound the in-flight age of a msg2 it can still adopt. That
/// assumes its sends succeed: a resend that fails to send does not
/// advance the ladder. After the cutover the hold must also outlast the
/// longer of the two ways the cutover reaches this node, or fails to:
/// the first frame on the new epoch on an idle link, up to one heartbeat
/// interval later, and the link-dead reap if every frame from the
/// initiator is lost. Both are allowed one more tick. Retiring before
/// either turns a late but legitimate adoption into a split. That floor
/// is `link_silence_ms`, 64 s at stock settings; the drain ceiling, which
/// bounds residence for the same recovering-peer reason, is 120 s and is
/// used unless the configured timers push the floor above it.
pub(in crate::node) fn pending_hold(node: &crate::config::NodeConfig) -> std::time::Duration {
    std::time::Duration::from_millis(
        drain_max_retention_ms(&node.rate_limit).max(link_silence_ms(node)),
    )
}

impl Node {
    /// Periodic rekey check. Called from the tick loop.
    ///
    /// For each active peer with a session:
    /// - If the initiator has a pending session, perform K-bit cutover
    /// - If the drain window has expired, clean up the previous session
    /// - If a responder's pending session was never adopted by the initiator
    ///   within the hold, retire it
    /// - If the rekey timer/counter fires, initiate a new handshake
    pub(in crate::node) async fn check_rekey(&mut self) {
        let cfg = RekeyCfg {
            after_secs: self.config().node.rekey.after_secs,
            after_messages: self.config().node.rekey.after_messages,
        };

        // The shell snapshots each peer's rekey ages/flags (every clock
        // read resolved here); the core decides cutover, drain, retirement and
        // trigger with no clock and returns the actions phase-grouped: all
        // Cutover, then all Drain, then all RetirePending, then all
        // InitiateRekey. That grouping fixes the shared `index_allocator`
        // free-then-allocate sequence that appears on the wire, so the batch
        // `poll_rekey` call stays here in the shell. The machine must NOT
        // re-poll; it CONSUMES each decided `ConnAction` in the order the batch
        // returned.
        let snapshots = self.rekey_peers();
        for action in self.fmp.poll_rekey(snapshots, &cfg) {
            match action {
                // Initiator cutover: route the decided action through the peer
                // machine + executor. The executor's `SwapSendState` arm
                // reproduces the pre-refactor cutover body EXACTLY.
                ConnAction::Cutover { peer: node_addr } => {
                    self.route_rekey_cadence(node_addr, ConnAction::Cutover { peer: node_addr })
                        .await;
                }
                // Drain completion: route through the machine + executor. The
                // executor's `CompleteDrain` arm reads the REAL previous index
                // from `complete_drain()` and frees it at the same point the old
                // inline body did (index-order preserving).
                ConnAction::Drain { peer: node_addr } => {
                    self.route_rekey_cadence(node_addr, ConnAction::Drain { peer: node_addr })
                        .await;
                }
                // Initiate a new rekey: STAYS INLINE (the Noise msg1 build +
                // index allocation are a shell-side leaf, byte-unchanged). Feed
                // the machine a `RekeyInitiated` observation afterward so its
                // control state stays coherent for the next tick's Cutover/Drain.
                ConnAction::InitiateRekey { peer: node_addr } => {
                    self.initiate_rekey(&node_addr).await;
                    self.observe_rekey_initiated(&node_addr);
                }
                // Retire a responder pending the initiator never adopted. Stays
                // inline: the peer machine models only the initiator's pending
                // (`on_rekey_msg2`), so there is nothing for it to consume.
                ConnAction::RetirePending { peer: node_addr } => {
                    self.retire_unadopted(&node_addr);
                }
                #[allow(unreachable_patterns)]
                _ => {}
            }
        }
    }

    /// Route a cadence-decided `Cutover`/`Drain` `ConnAction` through the peer
    /// machine + executor. The shell already decided (batch `poll_rekey`);
    /// the machine consumes via [`PeerEvent::RekeyConsume`] WITHOUT re-polling,
    /// preserving the phase order. The `SwapSendState`/`CompleteDrain` executor
    /// arms reproduce the pre-refactor inline effect bodies exactly.
    ///
    /// An established peer always has a `peer_machine`. If the peer vanished
    /// between snapshot and effect, the old inline body was a no-op, so we do
    /// nothing; if the machine is absent (which should be impossible) we fall
    /// back to the byte-identical inline body under a `debug_assert`.
    pub(in crate::node) async fn route_rekey_cadence(
        &mut self,
        node_addr: NodeAddr,
        action: ConnAction,
    ) {
        let link = match self.peers.get(&node_addr) {
            Some(peer) => peer.link_id(),
            None => return,
        };
        if !self.peer_machines.contains_key(&link) {
            debug_assert!(
                false,
                "peer machine present for every established rekey peer"
            );
            match action {
                ConnAction::Cutover { peer } => self.cutover_peer_inline(&peer),
                ConnAction::Drain { peer } => self.drain_peer_inline(&peer),
                _ => {}
            }
            return;
        }
        let ambient = self.rekey_cadence_ctx(&node_addr);
        self.advance_peer_machine(
            link,
            PeerEvent::RekeyConsume { action },
            ambient.now_ms,
            &ambient,
        )
        .await;
    }

    /// Feed the machine the `RekeyInitiated` observation after the inline
    /// `initiate_rekey`. The obs emits no action, so there is no executor
    /// pass — a bare `step` keeps the machine's control state coherent.
    fn observe_rekey_initiated(&mut self, node_addr: &NodeAddr) {
        let link = match self.peers.get(node_addr) {
            Some(peer) => peer.link_id(),
            None => return,
        };
        if let Some(machine) = self.peer_machines.get_mut(&link) {
            let acts = machine.step(
                PeerEvent::RekeyInitiated,
                Self::now_ms(),
                &mut self.index_allocator,
            );
            debug_assert!(acts.is_empty(), "RekeyInitiated is a pure observation");
        } else {
            debug_assert!(
                false,
                "peer machine present for every established rekey peer"
            );
        }
    }

    /// Ambient shell facts for the routed cadence Cutover/Drain step. Only
    /// `verified_identity` is read by the `SwapSendState`/`CompleteDrain`
    /// executor arms — `SwapSendState` resolves its `NodeAddr` from it (so it must
    /// equal `node_addr`), and `CompleteDrain` carries its peer in the action
    /// payload. The transport/index/direction fields are unused by these two arms
    /// (they matter only to `PromoteToActive`, never emitted on this path) and are
    /// populated best-effort for coherence.
    fn rekey_cadence_ctx(&self, node_addr: &NodeAddr) -> PeerActionCtx {
        let peer = &self.peers[node_addr];
        PeerActionCtx {
            verified_identity: *peer.identity(),
            transport_id: peer.transport_id().unwrap_or_else(|| TransportId::new(0)),
            remote_addr: peer
                .current_addr()
                .cloned()
                .unwrap_or_else(|| TransportAddr::new(Vec::new())),
            our_index: peer.our_index(),
            their_index: peer.their_index(),
            now_ms: Self::now_ms(),
            is_outbound: false,
        }
    }

    /// Pre-refactor initiator cutover body, retained as the release fallback for
    /// the (should-be-impossible) missing-machine case. Byte-identical to the old
    /// inline `ConnAction::Cutover` arm and to the executor's `SwapSendState` arm.
    fn cutover_peer_inline(&mut self, node_addr: &NodeAddr) {
        let did_cutover = if let Some(peer) = self.peers.get_mut(node_addr) {
            if let Some(_old_our_index) = peer.cutover_to_new_session() {
                let epoch = OrNone(peer.noise_session().map(diag::epoch_tag));
                let kbit_ours = peer.current_k_bit();
                // New index was pre-registered in peers_by_index during msg2
                // handling (handshake.rs).
                debug_assert!(
                    peer.transport_id().is_some()
                        && peer.our_index().is_some()
                        && self.peers_by_index.contains_key(&(
                            peer.transport_id().unwrap(),
                            peer.our_index().unwrap().as_u32()
                        )),
                    "peers_by_index should contain pre-registered new index after cutover"
                );
                debug!(
                    peer = %self.peer_display_name(node_addr),
                    epoch = %epoch,
                    kbit_ours,
                    "Rekey cutover complete (initiator), K-bit flipped"
                );
                true
            } else {
                false
            }
        } else {
            false
        };
        // Re-register the new session with the decrypt worker — the cache_key
        // (transport_id, our_index) just changed, so the old worker entry is
        // stale and every packet on the new session would miss the lookup.
        #[cfg(unix)]
        if did_cutover {
            self.register_decrypt_worker_session(node_addr);
        }
        #[cfg(not(unix))]
        let _ = did_cutover;
    }

    /// Retire `node_addr`'s responder-held pending session: unregister its
    /// index and free it. The index was registered in `peers_by_index` when
    /// the msg2 was sent and was never given to the decrypt worker, which
    /// sees a session only once it is current.
    fn retire_unadopted(&mut self, node_addr: &NodeAddr) {
        let retired = self
            .peers
            .get_mut(node_addr)
            .and_then(|peer| peer.retire_pending().map(|idx| (idx, peer.transport_id())));
        if let Some((idx, transport_id)) = retired {
            if let Some(tid) = transport_id {
                self.peers_by_index.remove(&(tid, idx.as_u32()));
            }
            let _ = self.index_allocator.free(idx);
            debug!(
                peer = %self.peer_display_name(node_addr),
                index = %idx,
                "Rekey pending session retired: the initiator never adopted it"
            );
        }
    }

    /// Pre-refactor drain-completion body, retained as the release fallback for
    /// the (should-be-impossible) missing-machine case. Byte-identical to the old
    /// inline `ConnAction::Drain` arm and to the executor's `CompleteDrain` arm.
    fn drain_peer_inline(&mut self, node_addr: &NodeAddr) {
        // Extract the old index and transport_id under the peer borrow, then drop
        // the borrow so the cache_key cleanup below can take &mut self for
        // unregister_decrypt_worker_session.
        let drained = self
            .peers
            .get_mut(node_addr)
            .and_then(|peer| peer.complete_drain().map(|idx| (idx, peer.transport_id())));
        if let Some((old_our_index, transport_id)) = drained {
            if let Some(tid) = transport_id {
                let cache_key = (tid, old_our_index.as_u32());
                self.peers_by_index.remove(&cache_key);
                #[cfg(unix)]
                self.unregister_decrypt_worker_session(cache_key);
            }
            let _ = self.index_allocator.free(old_our_index);
            trace!(
                peer = %self.peer_display_name(node_addr),
                old_index = %old_our_index,
                "Drain complete, previous session erased"
            );
        }
    }

    /// Snapshot every peer with a session for the rekey decision,
    /// pre-computing its monotonic ages and timer predicates so the pure core
    /// applies the thresholds without reading a clock (see [`PeerSnapshot`]).
    ///
    /// Lives here, beside the drain/dampening constants and the FSP analog, so
    /// the forward-merge onto `next` reconciles rekey timing in one place.
    pub(in crate::node) fn rekey_peer_snapshots(&self) -> Vec<PeerSnapshot> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.has_session())
            .map(|(node_addr, peer)| PeerSnapshot {
                addr: *node_addr,
                has_pending: peer.pending_new_session().is_some(),
                rekey_in_progress: peer.rekey_in_progress(),
                is_draining: peer.is_draining(),
                drain_expired: peer.drain_expired(DRAIN_WINDOW_SECS),
                is_dampened: peer.is_rekey_dampened(REKEY_DAMPENING_SECS),
                elapsed_secs: crate::peer::since(peer.session_established_at()).as_secs(),
                counter: peer
                    .noise_session()
                    .map(|s| s.current_send_counter())
                    .unwrap_or(0),
                jitter_secs: peer.rekey_jitter_secs(),
                pending_role: peer.pending_role(),
                pending_expired: peer.pending_expired(pending_hold(&self.config().node)),
            })
            .collect()
    }

    /// Initiate an outbound rekey to a peer.
    ///
    /// Creates a new IK handshake as initiator, sends msg1 over the existing
    /// link (same transport, same remote address), and stores the handshake
    /// state on the ActivePeer. No new Link or PeerConnection is created.
    async fn initiate_rekey(&mut self, node_addr: &NodeAddr) {
        let peer = match self.peers.get(node_addr) {
            Some(p) => p,
            None => return,
        };

        let transport_id = match peer.transport_id() {
            Some(t) => t,
            None => return,
        };
        let remote_addr = match peer.current_addr() {
            Some(a) => a.clone(),
            None => return,
        };
        let link_id = peer.link_id();
        let peer_pubkey = peer.identity().pubkey_full();

        // Allocate a new session index for the rekey
        let our_index = match self.index_allocator.allocate() {
            Ok(idx) => idx,
            Err(e) => {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    error = %e,
                    "Failed to allocate index for rekey"
                );
                return;
            }
        };

        // Create IK initiator handshake directly (no PeerConnection)
        // This frame's own copy of the node's long-term private key; the
        // handshake state keeps its own and clears that on drop.
        let mut our_keypair = self.identity().keypair();
        let mut hs = HandshakeState::new_initiator(our_keypair, peer_pubkey);
        our_keypair.non_secure_erase();
        hs.set_local_epoch(self.startup_epoch());

        let noise_msg1 = match hs.write_message_1() {
            Ok(msg) => msg,
            Err(e) => {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    error = %e,
                    "Failed to generate rekey msg1"
                );
                let _ = self.index_allocator.free(our_index);
                return;
            }
        };

        let wire_msg1 = build_msg1(our_index, &noise_msg1);

        // Send msg1 on the existing link (same transport + address). This
        // runs on the tick, so it never dials: with the connection gone it
        // fails at once, the index is freed, and the next tick's trigger
        // tries again, by then over any connection the failed send started.
        if let Some(transport) = self.transports.get(&transport_id) {
            match self
                .send_nowait(transport, link_id, &remote_addr, &wire_msg1)
                .await
            {
                Ok(_) => {
                    debug!(
                        peer = %self.peer_display_name(node_addr),
                        our_index = %our_index,
                        "Rekey initiated, sent msg1 on existing link"
                    );
                }
                Err(e) => {
                    // The teardown here is already benign — this returns before
                    // `set_rekey_state`, so the cycle simply does not start and
                    // is retried when rekey next comes due, with nothing torn
                    // down and nothing charged to the peer. Only the severity
                    // is wrong for a transport between interfaces, which is a
                    // local and self-clearing condition the presence machine
                    // has already reported.
                    if e.is_transient() {
                        debug!(
                            peer = %self.peer_display_name(node_addr),
                            error = %e,
                            "Deferred rekey msg1: the transport is between interfaces"
                        );
                    } else {
                        warn!(
                            peer = %self.peer_display_name(node_addr),
                            error = %e,
                            "Failed to send rekey msg1"
                        );
                    }
                    let _ = self.index_allocator.free(our_index);
                    return;
                }
            }
        }

        // Store handshake state on the ActivePeer (not a separate PeerConnection)
        let resend_interval = self.config().node.rate_limit.handshake_resend_interval_ms;
        let now_ms = crate::time::mono_ms();
        if let Some(peer) = self.peers.get_mut(node_addr) {
            peer.set_rekey_state(hs, our_index, wire_msg1, now_ms + resend_interval);
        }

        // Register in pending_outbound for msg2 dispatch (maps to existing link)
        self.pending_outbound
            .insert((transport_id, our_index.as_u32()), link_id);
    }

    /// Resend pending rekey msg1s and abandon timed-out rekeys, now.
    ///
    /// Called from the tick loop. The schedule is read on the monotonic clock,
    /// as it was stamped when the msg1 went out, so a step of the system clock
    /// neither sends a resend early nor holds one back.
    pub(in crate::node) async fn resend_pending_rekeys(&mut self) {
        self.resend_rekeys_at(crate::time::mono_ms()).await;
    }

    /// Resend pending rekey msg1s and abandon timed-out rekeys as of `now_ms`,
    /// in milliseconds of [`crate::time::mono_ms`].
    ///
    /// Uses the same resend interval and max resend count as initial
    /// handshakes.
    pub(in crate::node) async fn resend_rekeys_at(&mut self, now_ms: u64) {
        let interval_ms = self.config().node.rate_limit.handshake_resend_interval_ms;
        let backoff = self.config().node.rate_limit.handshake_resend_backoff;
        let max_resends = self.config().node.rate_limit.handshake_max_resends;

        // The shell snapshots each in-flight rekey (resend-due predicate
        // resolved here); the core classifies abandon-vs-resend and computes
        // the backoff, abandons first.
        let candidates = self.rekey_resend_candidates(now_ms);
        for action in
            self.fmp
                .poll_rekey_resends(candidates, now_ms, interval_ms, backoff, max_resends)
        {
            match action {
                // Abandon rekey cycles that exhausted their retransmission budget.
                ConnAction::AbandonRekey { peer: node_addr } => {
                    // `abandon_rekey` hands back whichever index the abandoned
                    // cycle owned; dropping the return value orphans it, and the
                    // `pending_outbound` entry seeded at rekey msg1 with it. Same
                    // shape as the dual-initiation loser and the rekey-msg2
                    // failure arm in `handshake.rs`.
                    //
                    // The `peers_by_index` removal is parity with those two arms
                    // and is a no-op at THIS call site: `AbandonRekey` is emitted
                    // only from the msg1-resend-budget classification, so no rekey
                    // msg2 ever arrived and nothing was inserted.
                    //
                    // Known exposure, kept for parity rather than closed here:
                    // `transport_id()` is RE-READ, while the `pending_outbound`
                    // entry was keyed by whatever it was when rekey msg1 went out.
                    // A roam in between (`set_current_addr` overwrites
                    // `send.transport_id`) makes the removal miss, so the index is
                    // freed with a stale entry still pointing at the peer's live
                    // link. Walked to its end: a later msg2 naming that index on
                    // the old transport resolves the stale link, finds the
                    // promoted peer's machine leg-less, finds no peer with a
                    // matching `rekey_our_index` (this arm cleared it), and takes
                    // the "not a rekey" arm, which removes the stale entry and
                    // records a reject. No teardown, no wrong-peer effect.
                    // Removing by index VALUE would close it outright.
                    if let Some(peer) = self.peers.get_mut(&node_addr)
                        && let Some(idx) = peer.abandon_rekey()
                    {
                        if let Some(tid) = peer.transport_id() {
                            self.peers_by_index.remove(&(tid, idx.as_u32()));
                            self.pending_outbound.remove(&(tid, idx.as_u32()));
                        }
                        let _ = self.index_allocator.free(idx);
                    }
                    debug!(
                        peer = %self.peer_display_name(&node_addr),
                        "FMP rekey aborted: msg1 unconfirmed after max retransmissions, abandoning cycle"
                    );
                }
                ConnAction::ResendRekeyMsg1 {
                    peer: node_addr,
                    bytes,
                    next_resend_at_ms,
                } => {
                    let (link_id, transport_id, remote_addr) = match self.peers.get(&node_addr) {
                        Some(p) => match (p.transport_id(), p.current_addr()) {
                            (Some(tid), Some(addr)) => (p.link_id(), tid, addr.clone()),
                            _ => continue,
                        },
                        None => continue,
                    };

                    // A failed send records no resend, so the msg1 stays due
                    // and is retried next tick, over any connection the
                    // failed send started.
                    let sent = if let Some(transport) = self.transports.get(&transport_id) {
                        self.send_nowait(transport, link_id, &remote_addr, &bytes)
                            .await
                            .is_ok()
                    } else {
                        false
                    };

                    if sent && let Some(peer) = self.peers.get_mut(&node_addr) {
                        peer.record_rekey_msg1_resend(next_resend_at_ms);
                        let count = peer.rekey_msg1_resend_count();
                        trace!(
                            peer = %self.peer_display_name(&node_addr),
                            resend = count,
                            "Resent rekey msg1"
                        );
                    }
                }
                #[allow(unreachable_patterns)]
                _ => {}
            }
        }
    }

    /// Snapshot every peer with a rekey handshake in flight (and a stored
    /// msg1) for the retransmission decision, pre-evaluating the resend-due
    /// predicate against `now_ms`, in milliseconds of
    /// [`crate::time::mono_ms`], so the core reads no clock.
    pub(in crate::node) fn rekey_resend_snapshots(&self, now_ms: u64) -> Vec<RekeyResendSnapshot> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.rekey_in_progress() && peer.rekey_msg1().is_some())
            .map(|(node_addr, peer)| RekeyResendSnapshot {
                peer: *node_addr,
                resend_count: peer.rekey_msg1_resend_count(),
                needs_resend: peer.needs_msg1_resend(now_ms),
                msg1: peer.rekey_msg1().unwrap().to_vec(),
            })
            .collect()
    }

    /// Poll every session's rekey machine at `now`, and carry out what each
    /// asks for: its first setup's resends and its retained msg3's, the
    /// end of an unanswered first attempt or of a session whose candidates
    /// all expired, its rekey msg3 resends with their probes, its keepalives
    /// and prompt repeats, and the cutover, revert and drain end it reports.
    pub(in crate::node) async fn poll_session_rekeys(&mut self, now: SessionInstant) {
        if self.sessions.is_empty() {
            return;
        }
        let local = self.session_node_keys();
        let addrs: Vec<NodeAddr> = self.sessions.keys().copied().collect();
        for addr in addrs {
            self.poll_session(&addr, now, &local).await;
        }
    }

    /// Poll `addr`'s session rekey machine at `now` if one of its deadlines
    /// or start instants has already come, before a SessionSetup is admitted
    /// and stepped into it. The 1 s tick can process a deadline up to a
    /// second late, and a setup judged in that second meets a state the
    /// deadline has ended: the smaller node, its completed rekey past its
    /// confirmation deadline or its final msg3 rung, would refuse the setup
    /// to keep a completed handshake the deadline gives up. A deployed peer
    /// sends its rekey setup once, so the refusal costs the rotation it
    /// starts. A start instant that has come starts this node's own rekey
    /// before the setup is judged, as a shell polling at the machine's next
    /// wake would have done before the setup arrived; the poll is all of the
    /// machine's due work or none of it, so it cannot take the deadlines
    /// alone.
    pub(in crate::node) async fn poll_overdue(&mut self, addr: &NodeAddr, now: SessionInstant) {
        if self.sessions.get(addr).is_some_and(|e| e.wake_due(now)) {
            let local = self.session_node_keys();
            self.poll_session(addr, now, &local).await;
        }
    }

    /// Poll `addr`'s session rekey machine at `now` and carry out what it
    /// asks for, telling it first whether a next hop toward the peer exists.
    async fn poll_session(&mut self, addr: &NodeAddr, now: SessionInstant, local: &NodeKeys) {
        let reachable = self.find_next_hop(addr).is_some();
        let Some(entry) = self.sessions.get_mut(addr) else {
            return;
        };
        let opening = !entry.is_established();
        let out = entry.poll_rekey(now, reachable, local);
        self.run_session_outputs(addr, out, opening).await;
    }

    /// Carry out the outputs of `addr`'s session rekey machine, front to
    /// back; `opening` says the session's first handshake was still open
    /// when the call that produced them began. A send the transport refuses
    /// is loss: the machine is never told, and its deadlines bound what the
    /// loss costs.
    pub(in crate::node) async fn run_session_outputs(
        &mut self,
        addr: &NodeAddr,
        out: SessionOutputs,
        opening: bool,
    ) {
        self.run_session_outputs_answering(addr, out, opening, None)
            .await;
    }

    /// Carry out the outputs of `addr`'s session rekey machine as
    /// [`Node::run_session_outputs`] does, where a SessionAck answers a
    /// setup that carried the initiator's coordinates `answering`.
    pub(in crate::node) async fn run_session_outputs_answering(
        &mut self,
        addr: &NodeAddr,
        out: SessionOutputs,
        opening: bool,
        answering: Option<&TreeCoordinate>,
    ) {
        for output in out {
            self.run_session_output(addr, output, opening, answering)
                .await;
        }
    }

    /// Carry out one output of `addr`'s session rekey machine, from a call
    /// that began with the first handshake open when `opening`; a
    /// SessionAck carries `answering` as the initiator's coordinates.
    async fn run_session_output(
        &mut self,
        addr: &NodeAddr,
        output: SessionOutput,
        opening: bool,
        answering: Option<&TreeCoordinate>,
    ) {
        use fips_core::proto::rekey::{Abandon, EvidenceKind, Output, Reason, Role};
        match output {
            Output::Send { msg, kind, .. } => {
                if opening
                    && kind == MsgKind::Setup
                    && let Some(entry) = self.sessions.get_mut(addr)
                {
                    entry.note_setup_sent();
                }
                // A send the transport refuses is loss, which the
                // machine's resends and deadlines recover.
                let _ = self.send_rekey_message(addr, msg, kind, answering).await;
            }
            Output::Prompt { tag } => self.send_session_prompt(addr, tag).await,
            // The handler that completed the first handshake logs the
            // session's establishment, after the packets held for it go.
            Output::Installed {
                evidence: EvidenceKind::First,
                ..
            } => {}
            Output::Installed {
                tag,
                role,
                evidence,
            } => {
                // The wording is the one operators' log searches and the
                // rekey and interop suites count cutovers by.
                let peer = self.peer_display_name(addr);
                match role {
                    Role::Initiator => debug!(
                        %peer,
                        epoch = tag.get(),
                        ?evidence,
                        "FSP rekey cutover complete (initiator), new session keys current"
                    ),
                    Role::Responder => debug!(
                        %peer,
                        epoch = tag.get(),
                        ?evidence,
                        "FSP rekey cutover complete (responder), new session keys current"
                    ),
                }
            }
            Output::Retired { tag } => {
                trace!(
                    peer = %self.peer_display_name(addr),
                    epoch = tag.get(),
                    "FSP session keys erased"
                );
            }
            Output::Reverted { tag } => {
                info!(
                    peer = %self.peer_display_name(addr),
                    epoch = tag.get(),
                    "FSP peer heard under the previous keys after an assumed cutover, new keys back to waiting"
                );
            }
            Output::Abandoned(Abandon::Unanswered) if opening => {
                debug!(
                    peer = %self.peer_display_name(addr),
                    "Session setup got no answer within the handshake timeout"
                );
            }
            Output::Abandoned(Abandon::Yielded) if opening => {
                debug!(
                    peer = %self.peer_display_name(addr),
                    "Simultaneous session initiation: our attempt gave way to the peer's completed one"
                );
            }
            Output::Abandoned(Abandon::Unanswered) => {
                self.stats_mut().session.rekey_unanswered += 1;
                info!(
                    peer = %self.peer_display_name(addr),
                    "FSP rekey we initiated got no answer within the handshake timeout, session retained"
                );
            }
            Output::Abandoned(Abandon::Yielded) => {
                self.stats_mut()
                    .record_reject(RejectReason::Session(SessionReject::RekeyYielded));
                debug!(
                    peer = %self.peer_display_name(addr),
                    "FSP rekey we initiated yielded to the peer's completed rekey"
                );
            }
            Output::Abandoned(why) => {
                debug!(
                    peer = %self.peer_display_name(addr),
                    ?why,
                    "FSP rekey given up"
                );
            }
            Output::Reject(Reason::CandidateExpired) if opening => {
                debug!(
                    peer = %self.peer_display_name(addr),
                    "Session setup answered for the peer expired without msg3"
                );
            }
            Output::Reject(Reason::KeyMismatch) if opening => {
                // A session the peer's setups opened is bonded to the address
                // they claimed: a msg3 authenticating a key that address is
                // not derived from proves only that its candidate was forged,
                // and only it goes. A forger reaches this once per candidate,
                // so it logs at debug.
                self.stats_mut()
                    .record_reject(RejectReason::Session(SessionReject::AddrMismatch));
                debug!(
                    src = %self.peer_display_name(addr),
                    reason = "addr-mismatch",
                    "SessionMsg3 source address does not match the authenticated static key, dropping its candidate"
                );
            }
            Output::Reject(Reason::CandidateExpired) => {
                self.stats_mut().session.rekey_expired += 1;
                info!(
                    peer = %self.peer_display_name(addr),
                    "FSP rekey setup answered for the peer expired without msg3, session retained"
                );
            }
            Output::Reject(reason) => {
                if let Some(counted) = session_reject(reason, opening) {
                    self.stats_mut()
                        .record_reject(RejectReason::Session(counted));
                }
                if reason == Reason::KeyMismatch {
                    warn!(
                        peer = %self.peer_display_name(addr),
                        "FSP rekey: initiator static key differs from the established peer key"
                    );
                }
                trace!(
                    peer = %self.peer_display_name(addr),
                    ?reason,
                    "FSP rekey input changed nothing"
                );
            }
            // The rekey that reported the restart has already repaired the
            // session: the old keys are retired and the session MMP is
            // per epoch, so only the count and the log are left to do.
            Output::PeerRestarted { epoch, .. } => {
                self.stats_mut().session.peer_restarted += 1;
                info!(
                    peer = %self.peer_display_name(addr),
                    epoch = %hex::encode(epoch),
                    "FSP peer restarted, session rekeyed under its new startup epoch"
                );
            }
            Output::Teardown(why) => {
                let name = self.peer_display_name(addr);
                if let Some(entry) = self.sessions.get(addr)
                    && let Some(mmp) = entry.mmp()
                {
                    Self::log_session_mmp_teardown(&name, mmp);
                }
                self.sessions.remove(addr);
                self.pending_tun_packets.remove(addr);
                self.path_mtu_lookup_release(addr);
                if opening {
                    info!(dest = %name, ?why, "Session handshake timed out, removing");
                } else {
                    info!(dest = %name, ?why, "FSP session closed by its rekey machine");
                }
            }
            // A session cutover carries nothing other layers resend, a
            // frame's delivery is the receive path's, and a session machine
            // holds no index, worker copy or link-setup msg1.
            Output::Rekeyed { .. }
            | Output::Deliver { .. }
            | Output::Bind { .. }
            | Output::Unbind { .. }
            | Output::Delegate { .. }
            | Output::Revoke { .. }
            | Output::Release(_)
            | Output::ReplaceRequested { .. } => {}
        }
    }

    /// Send the session handshake message `msg` the rekey machine of `addr`
    /// asked for, wrapped in its session message with the coordinates of
    /// now: a SessionSetup toward the coordinates cached for `addr` (a direct
    /// peer's announced ones on a miss, as the dial does), a SessionAck
    /// toward the setup's own coordinates `answering`, a SessionMsg3 bare.
    /// Returns whether it left, for the one caller that keeps a session
    /// only if its first setup did.
    pub(in crate::node) async fn send_rekey_message(
        &mut self,
        addr: &NodeAddr,
        msg: Vec<u8>,
        kind: MsgKind,
        answering: Option<&TreeCoordinate>,
    ) -> Result<(), crate::node::NodeError> {
        let our_coords = self.tree_state.my_coords().clone();
        let payload = match kind {
            MsgKind::Msg3 => SessionMsg3::new(msg).encode(),
            MsgKind::Setup => {
                // The wire needs non-empty destination coordinates, and on a
                // cache miss our own would be filed under the destination's
                // address by every node on the path. Routing never refreshes
                // a direct peer's cache entry, so fall back to the
                // coordinates a direct peer announced. Only a destination
                // that is neither cached nor an announced direct peer gets
                // ours, as a first setup always has; the destination answers
                // with its own.
                let dest_coords = self
                    .cached_dest_coords(addr)
                    .or_else(|| self.tree_state.peer_coords(addr).cloned())
                    .unwrap_or_else(|| our_coords.clone());
                SessionSetup::new(our_coords, dest_coords)
                    .with_handshake(msg)
                    .encode()
            }
            MsgKind::Ack => {
                let Some(dest_coords) = answering.cloned() else {
                    debug!(
                        peer = %self.peer_display_name(addr),
                        "FSP SessionAck with no setup to answer, dropping"
                    );
                    return Ok(());
                };
                SessionAck::new(our_coords, dest_coords)
                    .with_handshake(msg)
                    .encode()
            }
            MsgKind::Msg1 | MsgKind::Msg2 => {
                debug!(
                    peer = %self.peer_display_name(addr),
                    ?kind,
                    "FSP session machine asked for a link handshake message, dropping"
                );
                return Ok(());
            }
        };
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *addr, payload)
            .with_ttl(self.config().node.session.default_ttl);
        let sent = self.send_session_datagram(&mut datagram).await;
        match &sent {
            Ok(()) => {
                trace!(peer = %self.peer_display_name(addr), ?kind, "Sent FSP handshake message")
            }
            Err(e) => debug!(
                peer = %self.peer_display_name(addr),
                ?kind,
                error = %e,
                "FSP handshake message not sent, counted as lost"
            ),
        }
        sent
    }

    /// Seal and send the prompt the rekey machine of `addr` asked for under
    /// the epoch `tag`: a CoordsWarmup, carrying the destination's cached
    /// coordinates, or else the ones the peer's own handshake message
    /// carried, or else the ones a direct peer announced.
    async fn send_session_prompt(&mut self, addr: &NodeAddr, tag: EpochTag) {
        let now = Self::session_now();
        let Some(entry) = self.sessions.get_mut(addr) else {
            return;
        };
        let prompt = match entry.seal_prompt(now, tag) {
            Ok(prompt) => prompt,
            Err(e) => {
                debug!(
                    peer = %self.peer_display_name(addr),
                    error = ?e,
                    "FSP rekey prompt not sealed"
                );
                return;
            }
        };
        let dest_coords = self
            .cached_dest_coords(addr)
            .or_else(|| prompt.route.clone())
            .or_else(|| self.tree_state.peer_coords(addr).cloned());
        let Some(dest_coords) = dest_coords else {
            debug!(
                peer = %self.peer_display_name(addr),
                "FSP rekey prompt has no destination coordinates, counted as lost"
            );
            return;
        };
        let my_coords = self.tree_state.my_coords().clone();
        let coords_size = coords_wire_size(&my_coords) + coords_wire_size(&dest_coords);
        let mut fsp_payload =
            Vec::with_capacity(prompt.header.len() + coords_size + prompt.ciphertext.len());
        fsp_payload.extend_from_slice(&prompt.header);
        encode_coords(&my_coords, &mut fsp_payload);
        encode_coords(&dest_coords, &mut fsp_payload);
        fsp_payload.extend_from_slice(&prompt.ciphertext);
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *addr, fsp_payload)
            .with_ttl(self.config().node.session.default_ttl);
        if let Err(e) = self.send_session_datagram(&mut datagram).await {
            debug!(
                peer = %self.peer_display_name(addr),
                error = %e,
                "FSP rekey prompt not sent, counted as lost"
            );
            return;
        }
        if prompt.measured
            && let Some(entry) = self.sessions.get_mut(addr)
            && let Some(mmp) = entry.mmp_mut()
        {
            mmp.sender
                .record_sent(prompt.counter, prompt.timestamp, prompt.ciphertext.len());
        }
        trace!(peer = %self.peer_display_name(addr), "Sent FSP rekey prompt");
    }
}

/// The session reject counter a machine refusal is counted under, for the
/// refusals one input alone can produce, from a call that began with the
/// first handshake open when `opening`. A tie-break refusal is counted by
/// the handler that knows which message met it, and the first handshake's
/// refusals of setups count nothing, as its candidates' expiries do not.
fn session_reject(reason: fips_core::proto::rekey::Reason, opening: bool) -> Option<SessionReject> {
    use fips_core::proto::rekey::Reason;
    match reason {
        Reason::CandidatesFull if !opening => Some(SessionReject::RekeyHeld),
        Reason::ReplyUnauthenticated => Some(SessionReject::AckHandshakeFailed),
        Reason::UnknownAttempt | Reason::LateReply => Some(SessionReject::BadState),
        Reason::KeyMismatch if !opening => Some(SessionReject::RekeyKeyMismatch),
        _ => None,
    }
}
