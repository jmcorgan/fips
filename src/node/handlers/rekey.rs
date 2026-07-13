//! Periodic rekey (key rotation) for FMP link sessions.
//!
//! Checks all active peers on each tick for:
//! 1. Rekey trigger (time elapsed or send counter exceeded)
//! 2. Drain window expiry (clean up previous session after cutover)
//! 3. Initiator-side cutover (first send after handshake completion)

use crate::NodeAddr;
use crate::node::Node;
use crate::node::dataplane::PeerActionCtx;
use crate::noise::HandshakeState;
use crate::peer::machine::PeerEvent;
use crate::proto::fmp::wire::build_msg1;
use crate::proto::fmp::{ConnAction, LifecycleView, PeerSnapshot, RekeyCfg, RekeyResendSnapshot};
use crate::proto::fsp::{
    FspAction, RekeyMsg3ResendSnapshot, SessionSetup, SessionSnapshot, cutover_timer_elapsed,
};
use crate::proto::link::SessionDatagram;
use crate::transport::{TransportAddr, TransportId};
use tracing::{debug, trace, warn};

/// Keep previous session alive for this long after cutover.
///
/// FMP-scoped copy for `check_rekey`; the FSP session-rekey timing bounds live
/// in `crate::proto::fsp::limits`.
const DRAIN_WINDOW_SECS: u64 = 10;

/// Suppress local rekey initiation for this long after receiving
/// a peer's rekey msg1. FMP-scoped copy for `check_rekey`.
const REKEY_DAMPENING_SECS: u64 = 30;

impl Node {
    /// Periodic rekey check. Called from the tick loop.
    ///
    /// For each active peer with a session:
    /// - If the initiator has a pending session, perform K-bit cutover
    /// - If the drain window has expired, clean up the previous session
    /// - If the rekey timer/counter fires, initiate a new handshake
    pub(in crate::node) async fn check_rekey(&mut self) {
        if !self.config().node.rekey.enabled {
            return;
        }

        let cfg = RekeyCfg {
            after_secs: self.config().node.rekey.after_secs,
            after_messages: self.config().node.rekey.after_messages,
        };

        // The shell snapshots each healthy peer's rekey ages/flags (every clock
        // read resolved here); the core decides cutover/drain/trigger with no
        // clock, phase-grouped to preserve the pre-refactor execution order.
        // The batch `poll_rekey` + snapshots STAY SHELL-SIDE and BYTE-UNCHANGED
        // (Finding B): the cross-peer phase-grouping (all Cutover → all Drain →
        // all InitiateRekey) governs the shared `index_allocator` free-then-alloc
        // SEQUENCE that appears on the wire. The machine must NOT re-poll; it
        // CONSUMES each decided `ConnAction` in the same order the batch returned.
        let snapshots = self.rekey_peers();
        for action in self.fmp.poll_rekey(snapshots, &cfg) {
            match action {
                // Initiator cutover: route the decided action through the peer
                // machine + executor (C4-1). The executor's `SwapSendState` arm
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
                #[allow(unreachable_patterns)]
                _ => {}
            }
        }
    }

    /// Route a cadence-decided `Cutover`/`Drain` `ConnAction` through the peer
    /// machine + executor (C4-1). The shell already decided (batch `poll_rekey`);
    /// the machine consumes via [`PeerEvent::RekeyConsume`] WITHOUT re-polling,
    /// preserving the phase order. The `SwapSendState`/`CompleteDrain` executor
    /// arms reproduce the pre-refactor inline effect bodies exactly.
    ///
    /// Finding A: an established peer always has a `peer_machine`. If the peer
    /// vanished between snapshot and effect, the old inline body was a no-op, so
    /// we do nothing; if the machine is absent (impossible per Finding A) we fall
    /// back to the byte-identical inline body under a `debug_assert`.
    async fn route_rekey_cadence(&mut self, node_addr: NodeAddr, action: ConnAction) {
        let link = match self.peers.get(&node_addr) {
            Some(peer) => peer.link_id(),
            None => return,
        };
        if !self.peer_machines.contains_key(&link) {
            debug_assert!(
                false,
                "peer machine present for every established rekey peer (Finding A)"
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
            Self::now_ms(),
            &ambient,
        )
        .await;
    }

    /// Feed the machine the `RekeyInitiated` observation after the inline
    /// `initiate_rekey` (C4-1). The obs emits no action, so there is no executor
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
                "peer machine present for every established rekey peer (Finding A)"
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
    /// the (Finding-A-impossible) missing-machine case. Byte-identical to the old
    /// inline `ConnAction::Cutover` arm and to the executor's `SwapSendState` arm.
    fn cutover_peer_inline(&mut self, node_addr: &NodeAddr) {
        let did_cutover = if let Some(peer) = self.peers.get_mut(node_addr) {
            if let Some(_old_our_index) = peer.cutover_to_new_session() {
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

    /// Pre-refactor drain-completion body, retained as the release fallback for
    /// the (Finding-A-impossible) missing-machine case. Byte-identical to the old
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

    /// Snapshot every healthy peer with a session for the rekey decision,
    /// pre-computing its monotonic ages and timer predicates so the pure core
    /// applies the thresholds without reading a clock (see [`PeerSnapshot`]).
    ///
    /// Lives here, beside the drain/dampening constants and the FSP analog, so
    /// the forward-merge onto `next` reconciles rekey timing in one place.
    pub(in crate::node) fn rekey_peer_snapshots(&self) -> Vec<PeerSnapshot> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.has_session() && peer.is_healthy())
            .map(|(node_addr, peer)| PeerSnapshot {
                addr: *node_addr,
                has_pending: peer.pending_new_session().is_some(),
                rekey_in_progress: peer.rekey_in_progress(),
                is_draining: peer.is_draining(),
                drain_expired: peer.drain_expired(DRAIN_WINDOW_SECS),
                is_dampened: peer.is_rekey_dampened(REKEY_DAMPENING_SECS),
                elapsed_secs: peer.session_established_at().elapsed().as_secs(),
                counter: peer
                    .noise_session()
                    .map(|s| s.current_send_counter())
                    .unwrap_or(0),
                jitter_secs: peer.rekey_jitter_secs(),
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
        let our_keypair = self.identity().keypair();
        let mut hs = HandshakeState::new_initiator(our_keypair, peer_pubkey);
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

        // Send msg1 on the existing link (same transport + address)
        if let Some(transport) = self.transports.get(&transport_id) {
            match transport.send(&remote_addr, &wire_msg1).await {
                Ok(_) => {
                    debug!(
                        peer = %self.peer_display_name(node_addr),
                        our_index = %our_index,
                        "Rekey initiated, sent msg1 on existing link"
                    );
                }
                Err(e) => {
                    warn!(
                        peer = %self.peer_display_name(node_addr),
                        error = %e,
                        "Failed to send rekey msg1"
                    );
                    let _ = self.index_allocator.free(our_index);
                    return;
                }
            }
        }

        // Store handshake state on the ActivePeer (not a separate PeerConnection)
        let resend_interval = self.config().node.rate_limit.handshake_resend_interval_ms;
        let now_ms = Self::now_ms();
        if let Some(peer) = self.peers.get_mut(node_addr) {
            peer.set_rekey_state(hs, our_index, wire_msg1, now_ms + resend_interval);
        }

        // Register in pending_outbound for msg2 dispatch (maps to existing link)
        self.pending_outbound
            .insert((transport_id, our_index.as_u32()), link_id);
    }

    /// Resend pending rekey msg1s and abandon timed-out rekeys.
    ///
    /// Called from the tick loop. Uses the same resend interval and max
    /// resend count as initial handshakes.
    pub(in crate::node) async fn resend_pending_rekeys(&mut self, now_ms: u64) {
        if !self.config().node.rekey.enabled {
            return;
        }

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
                    if let Some(peer) = self.peers.get_mut(&node_addr) {
                        peer.abandon_rekey();
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
                    let (transport_id, remote_addr) = match self.peers.get(&node_addr) {
                        Some(p) => match (p.transport_id(), p.current_addr()) {
                            (Some(tid), Some(addr)) => (tid, addr.clone()),
                            _ => continue,
                        },
                        None => continue,
                    };

                    let sent = if let Some(transport) = self.transports.get(&transport_id) {
                        transport.send(&remote_addr, &bytes).await.is_ok()
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
    /// predicate against `now_ms` so the core reads no clock.
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

    /// Retransmit FSP rekey msg3 until the responder is confirmed on the
    /// new epoch.
    ///
    /// Called from the tick loop. The rekey initiator retains its msg3
    /// wire payload after the first send (`handle_session_ack`); this
    /// driver resends it on the handshake resend interval (with backoff)
    /// while the payload is still retained.
    ///
    /// This is a **liveness-only** mechanism. Overlapping-epoch
    /// trial-decrypt makes the rekey transition safe regardless of
    /// cutover skew; retransmission only guarantees the responder
    /// eventually derives the new session. Its lifetime is tied to the
    /// responder *receiving* msg3 — the retained payload is cleared when
    /// an inbound peer frame authenticates against `pending` or
    /// post-cutover `current` — decoupled from the initiator's own
    /// cutover. The initiator may cut over on its liveness timer while
    /// the responder still lacks the new session; retransmission
    /// continues, and overlapping-epoch decrypt keeps both directions
    /// working meanwhile.
    ///
    /// After `handshake_max_resends` attempts with no confirmed progress,
    /// the rekey cycle is abandoned cleanly (`abandon_rekey`): the
    /// pending session is dropped and the next cycle retries fresh. This
    /// is safe — an abandoned cycle never leaves a divergent unsafe
    /// state.
    pub(in crate::node) async fn resend_pending_session_msg3(&mut self, now_ms: u64) {
        if !self.config().node.rekey.enabled || self.sessions.is_empty() {
            return;
        }

        let interval_ms = self.config().node.rate_limit.handshake_resend_interval_ms;
        let backoff = self.config().node.rate_limit.handshake_resend_backoff;
        let max_resends = self.config().node.rate_limit.handshake_max_resends;
        let ttl = self.config().node.session.default_ttl;
        let my_addr = *self.node_addr();

        // The shell snapshots each session retaining a msg3 payload (resend-due
        // predicate resolved here); the core classifies abandon-vs-resend,
        // abandons first.
        let candidates = self.rekey_msg3_resend_snapshots(now_ms);
        for action in self.fsp.poll_rekey_msg3_resends(candidates, max_resends) {
            match action {
                FspAction::AbandonRekey { addr } => {
                    if let Some(entry) = self.sessions.get_mut(&addr) {
                        entry.abandon_rekey();
                    }
                    debug!(
                        peer = %self.peer_display_name(&addr),
                        "FSP rekey aborted: msg3 unconfirmed after max retransmissions, abandoning cycle"
                    );
                }
                FspAction::ResendSessionMsg3 { addr } => {
                    let payload = match self
                        .sessions
                        .get(&addr)
                        .and_then(|e| e.rekey_msg3_payload())
                    {
                        Some(p) => p.to_vec(),
                        None => continue,
                    };
                    let mut datagram = SessionDatagram::new(my_addr, addr, payload).with_ttl(ttl);
                    let sent = match self.send_session_datagram(&mut datagram).await {
                        Ok(_) => true,
                        Err(e) => {
                            debug!(
                                peer = %self.peer_display_name(&addr),
                                error = %e,
                                "FSP rekey msg3 retransmission failed"
                            );
                            false
                        }
                    };

                    if sent && let Some(entry) = self.sessions.get_mut(&addr) {
                        let count = entry.rekey_msg3_resend_count() + 1;
                        let next =
                            now_ms + (interval_ms as f64 * backoff.powi(count as i32)) as u64;
                        entry.record_rekey_msg3_resend(next);
                        trace!(
                            peer = %self.peer_display_name(&addr),
                            resend = count,
                            "Resent FSP rekey msg3"
                        );
                    }
                }
                #[allow(unreachable_patterns)]
                _ => {}
            }
        }
    }

    /// Snapshot every session retaining a rekey-msg3 payload for the
    /// retransmission decision, pre-evaluating the resend-due predicate against
    /// `now_ms` so the core reads no clock.
    fn rekey_msg3_resend_snapshots(&self, now_ms: u64) -> Vec<RekeyMsg3ResendSnapshot> {
        self.sessions
            .iter()
            .filter(|(_, entry)| entry.rekey_msg3_payload().is_some())
            .map(|(node_addr, entry)| RekeyMsg3ResendSnapshot {
                addr: *node_addr,
                resend_count: entry.rekey_msg3_resend_count(),
                resend_due: entry.rekey_msg3_next_resend_ms() != 0
                    && now_ms >= entry.rekey_msg3_next_resend_ms(),
            })
            .collect()
    }

    /// Periodic session (FSP) rekey check. Called from the tick loop.
    ///
    /// For each established session:
    /// - If the initiator holds a pending session past the liveness
    ///   timer, perform the K-bit cutover (overlapping-epoch decrypt
    ///   makes this safe on any schedule — see `FSP_CUTOVER_DELAY_MS`)
    /// - If the drain window has expired, clean up the previous session
    /// - If the rekey timer/counter fires, initiate a new XK handshake
    ///
    /// msg3 retransmission is handled separately by
    /// `resend_pending_session_msg3`; its lifetime is tied to the
    /// responder receiving msg3, not to this initiator's cutover.
    pub(in crate::node) async fn check_session_rekey(&mut self) {
        if !self.config().node.rekey.enabled {
            return;
        }

        let cfg = crate::proto::fsp::RekeyCfg {
            after_secs: self.config().node.rekey.after_secs,
            after_messages: self.config().node.rekey.after_messages,
        };
        let now_ms = Self::now_ms();

        // The shell snapshots each established session's rekey ages/flags
        // (every clock read resolved here); the core decides
        // cutover/drain/trigger with no clock, phase-grouped to preserve the
        // pre-refactor execution order.
        let snapshots = self.session_rekey_snapshots(now_ms);
        for action in self.fsp.poll_rekey(snapshots, &cfg) {
            match action {
                FspAction::CutOver { addr } => {
                    if let Some(entry) = self.sessions.get_mut(&addr)
                        && entry.cutover_to_new_session(now_ms)
                    {
                        debug!(
                            peer = %self.peer_display_name(&addr),
                            "FSP rekey cutover complete (initiator), K-bit flipped"
                        );
                    }
                }
                FspAction::CompleteDrain { addr } => {
                    if let Some(entry) = self.sessions.get_mut(&addr) {
                        entry.complete_drain();
                        trace!(
                            peer = %self.peer_display_name(&addr),
                            "FSP drain complete, previous session erased"
                        );
                    }
                }
                FspAction::InitiateRekey { addr } => {
                    self.initiate_session_rekey(&addr).await;
                }
                #[allow(unreachable_patterns)]
                _ => {}
            }
        }
    }

    /// Snapshot every established session for the FSP rekey decision,
    /// pre-computing its monotonic age and timer predicates so the pure core
    /// applies the thresholds without reading a clock (see [`SessionSnapshot`]).
    fn session_rekey_snapshots(&self, now_ms: u64) -> Vec<SessionSnapshot> {
        let drain_ms = crate::proto::fsp::limits::DRAIN_WINDOW_SECS * 1000;
        let dampening_ms = crate::proto::fsp::limits::REKEY_DAMPENING_SECS * 1000;
        self.sessions
            .iter()
            .filter(|(_, entry)| entry.is_established())
            .map(|(node_addr, entry)| SessionSnapshot {
                addr: *node_addr,
                has_pending: entry.pending_new_session().is_some(),
                rekey_in_progress: entry.has_rekey_in_progress(),
                is_rekey_initiator: entry.is_rekey_initiator(),
                cutover_timer_elapsed: cutover_timer_elapsed(now_ms, entry.rekey_completed_ms()),
                is_draining: entry.is_draining(),
                drain_expired: entry.drain_expired(now_ms, drain_ms),
                has_rekey_msg3_payload: entry.rekey_msg3_payload().is_some(),
                is_dampened: entry.is_rekey_dampened(now_ms, dampening_ms),
                elapsed_secs: now_ms.saturating_sub(entry.session_start_ms()) / 1000,
                counter: entry.send_counter(),
                jitter_secs: entry.rekey_jitter_secs(),
            })
            .collect()
    }

    /// Initiate an FSP session rekey.
    ///
    /// Creates a new XK handshake as initiator, sends SessionSetup msg1
    /// through the mesh, and stores the handshake state on the existing entry.
    async fn initiate_session_rekey(&mut self, dest_addr: &NodeAddr) {
        // Check route availability before paying crypto cost
        if self.find_next_hop(dest_addr).is_none() {
            trace!(
                peer = %self.peer_display_name(dest_addr),
                "FSP rekey skipped: no route to destination"
            );
            return;
        }

        let entry = match self.sessions.get(dest_addr) {
            Some(e) => e,
            None => return,
        };
        let dest_pubkey = *entry.remote_pubkey();

        // Create Noise XK initiator handshake
        let our_keypair = self.identity().keypair();
        let mut handshake = HandshakeState::new_xk_initiator(our_keypair, dest_pubkey);
        handshake.set_local_epoch(self.startup_epoch());

        let msg1 = match handshake.write_xk_message_1() {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    peer = %self.peer_display_name(dest_addr),
                    error = %e,
                    "Failed to generate FSP rekey XK msg1"
                );
                return;
            }
        };

        // Build SessionSetup with coordinates
        let our_coords = self.tree_state.my_coords().clone();
        let dest_coords = self.get_dest_coords(dest_addr);
        let setup = SessionSetup::new(our_coords, dest_coords).with_handshake(msg1);
        let setup_payload = setup.encode();

        // Send through the mesh
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *dest_addr, setup_payload)
            .with_ttl(self.config().node.session.default_ttl);

        if let Err(e) = self.send_session_datagram(&mut datagram).await {
            debug!(
                peer = %self.peer_display_name(dest_addr),
                error = %e,
                "Failed to send FSP rekey SessionSetup"
            );
            return;
        }

        // Store rekey state on the existing session entry
        if let Some(entry) = self.sessions.get_mut(dest_addr) {
            entry.set_rekey_state(handshake, true);
        }

        debug!(
            peer = %self.peer_display_name(dest_addr),
            "FSP rekey initiated, sent SessionSetup"
        );
    }
}
