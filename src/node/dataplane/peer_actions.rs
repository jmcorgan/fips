//! Executor for the per-peer control machine's [`PeerAction`]s.
//!
//! The per-peer FSM in [`crate::peer::machine`] is a sans-IO reducer: it decides
//! *what* must happen and returns a `Vec<PeerAction>`; this module is the *doing*
//! half — the thin driver that maps each action onto the exact shell call it
//! stands for (`build_msg2` + `transport.send`, `promote_connection`,
//! `remove_active_peer`, `index_allocator.free`, `note_link_dead`, …).
//!
//! ## Shadow-only skeleton
//!
//! The machine home (`Node.peer_machines`), the
//! executor, and the disjoint-borrow advance helper. It is **unwired** — the live
//! `handle_msg1`/`handle_msg2` path does not drive it yet, so every method here is
//! `#[allow(dead_code)]`. The inbound cutover (`handle_msg1` → `step(InboundMsg1)`)
//! and the outbound cutover (`handle_msg2` / dial) are wired later.
//!
//! Arms not yet exercised are inert stubs (outbound dial, rekey/crypto installs,
//! link-control frames, timers, and the connected-UDP plane are inert stubs
//! realized as those planes are wired).
//! `RegisterDecryptSession` is a deliberate no-op — see its arm for the note.

use crate::PeerIdentity;
use crate::node::Node;
use crate::node::reject::{HandshakeReject, RejectReason};
use crate::peer::machine::{LostKind, PeerAction, PeerEvent};
use crate::proto::fmp::PromotionResult;
use crate::proto::fmp::wire::build_msg2;
use crate::transport::{LinkId, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use std::collections::VecDeque;
use tracing::{debug, trace, warn};

/// Ambient shell facts a [`PeerAction`] executor needs that the machine's
/// runtime-agnostic action payloads deliberately omit (verified identity,
/// transport target, the msg2 framing indices, the promotion timestamp).
///
/// Unlike a machine event/action payload this is **executor-side**, so it may
/// hold real values resolved from the wire context (cf. `handle_msg1`'s
/// `wire`/`packet` locals and `promote_connection`'s ambient args). It is
/// built fresh per driven step by the caller at cutover time.
#[allow(dead_code)]
pub(in crate::node) struct PeerActionCtx {
    /// The authenticated peer identity: `PromoteToActive` /
    /// `InvalidateSendState` resolve their `NodeAddr` from this.
    pub(in crate::node) verified_identity: PeerIdentity,
    /// The transport the exchange is happening over (msg2 send target, decrypt
    /// cache-key transport half).
    pub(in crate::node) transport_id: TransportId,
    /// The peer's wire address (msg2 send target).
    pub(in crate::node) remote_addr: TransportAddr,
    /// Our session index for this exchange (msg2 framing sender_idx).
    pub(in crate::node) our_index: Option<SessionIndex>,
    /// The peer's session index for this exchange (msg2 framing
    /// receiver_idx).
    pub(in crate::node) their_index: Option<SessionIndex>,
    /// The wire timestamp driving this step (promotion ts / loss-report clock).
    pub(in crate::node) now_ms: u64,
    /// Establish direction for this exchange. Discriminates the
    /// `PromoteToActive` failure cleanup: the pre-refactor inbound
    /// (`handle_msg1`) and outbound (`handle_msg2`) promote-Err arms were NOT
    /// byte-identical, so the executor must reproduce each. `false` = inbound
    /// (drop link + reverse map + free index), `true` = outbound (record the
    /// reject only; leave the dead link/`addr_to_link` for the stale-connection
    /// reaper, matching old `handle_msg2`).
    pub(in crate::node) is_outbound: bool,
}

impl Node {
    /// Advance the machine for `link` by one event and execute the resulting
    /// actions.
    ///
    /// The borrow structure the whole seam turns on: the machine
    /// needs `&mut IndexAllocator` as a synchronous capability *while it is
    /// itself borrowed mutably out of `peer_machines`*. `peer_machines` and
    /// `index_allocator` are **distinct `Node` fields**, so the collect below is
    /// a disjoint two-field borrow the checker accepts; once the actions are
    /// collected both borrows drop and the executor runs against `&mut self`.
    pub(in crate::node) async fn advance_peer_machine(
        &mut self,
        link: LinkId,
        event: PeerEvent,
        now: u64,
        ambient: &PeerActionCtx,
    ) {
        let actions = match self.peer_machines.get_mut(&link) {
            // Disjoint field borrow: `self.peer_machines` (the map entry) and
            // `self.index_allocator` (the capability) are separate fields.
            Some(machine) => machine.step(event, now, &mut self.index_allocator),
            None => return,
        };
        self.execute_peer_actions(link, ambient, actions).await;
    }

    /// Map each [`PeerAction`] onto its shell call.
    ///
    /// `PromoteToActive` feeds its [`PromotionResult`](crate::proto::fmp::PromotionResult)
    /// back into the machine and appends the follow-up actions to the same
    /// worklist — a queue rather than self-recursion so the async executor stays a
    /// single flat future (no boxing) and the emitted order is preserved (the
    /// establish sequences always end in `PromoteToActive`, so its follow-ups run
    /// after any siblings).
    pub(in crate::node) async fn execute_peer_actions(
        &mut self,
        link: LinkId,
        ambient: &PeerActionCtx,
        actions: Vec<PeerAction>,
    ) {
        let mut queue: VecDeque<PeerAction> = actions.into();
        while let Some(action) = queue.pop_front() {
            match action {
                PeerAction::OpenTransport { .. } => {
                    // Outbound dial (`initiate_connection`,
                    // `lifecycle/mod.rs:470`). Outbound establish is not cut over
                    // yet; inert in the shadow-only skeleton.
                }
                PeerAction::SendHandshake { bytes } => {
                    // The machine payload is the UNFRAMED Noise msg2 payload;
                    // frame it with our/their index (mirrors `handshake.rs:472`'s
                    // `build_msg2(our_index, their_index, &payload)`) before the
                    // wire send. A fresh-outbound msg1 (empty payload → build msg1
                    // from indices) is framed differently and is wired later.
                    if let (Some(sender_idx), Some(receiver_idx)) =
                        (ambient.our_index, ambient.their_index)
                    {
                        let frame = build_msg2(sender_idx, receiver_idx, &bytes);
                        // Surface the send Result. A missing transport skips
                        // the send and continues (mirrors `handle_msg1`'s
                        // `if let Some(transport)` guard); a send *error* runs the
                        // pre-refactor msg2-send-failure cleanup (`handle_msg1`
                        // L494-503) and ABORTS the remaining queue so the queued
                        // `PromoteToActive` never runs.
                        let send_err = match self.transports.get(&ambient.transport_id) {
                            Some(transport) => {
                                transport.send(&ambient.remote_addr, &frame).await.err()
                            }
                            None => None,
                        };
                        if let Some(e) = send_err {
                            // Restored pre-refactor msg2-send-failure warn!
                            // (`handle_msg1` L665): the send error text is surfaced
                            // at the executor point where the failure is now handled.
                            warn!(link_id = %link, error = %e, "Failed to send msg2");
                            self.connections.remove(&link);
                            self.links.remove(&link);
                            self.addr_to_link
                                .remove(&(ambient.transport_id, ambient.remote_addr.clone()));
                            if let Some(idx) = ambient.our_index {
                                let _ = self.index_allocator.free(idx);
                            }
                            self.peer_machines.remove(&link);
                            self.stats_mut()
                                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                            return;
                        }
                    }
                }
                PeerAction::SendRekey { .. } => {
                    // Rekey msg2 framing (`build_msg2(our_new_index, …)`,
                    // `handshake.rs:365`) + send. Rekey fold is not yet wired.
                }
                PeerAction::SendLinkMessage { .. } => {
                    // Encrypt + send a link-control frame (heartbeat / filter
                    // / tree / disconnect). Data-plane-owned; not yet wired.
                }
                PeerAction::PromoteToActive { link: promote_link } => {
                    // Ambient supplies the verified identity + promotion ts
                    // that `promote_connection` needs (resolved from the wire ctx).
                    match self.promote_connection(
                        promote_link,
                        ambient.verified_identity,
                        ambient.now_ms,
                    ) {
                        Ok(result) => {
                            // The decrypt-worker registration relocated
                            // OUT of `promote_connection` into THIS single executor
                            // arm — the one live caller of `promote_connection` (both
                            // the inbound `handle_msg1` and outbound `handle_msg2`
                            // net-new establish paths reach it here). Register iff the
                            // promotion actually created or replaced a peer
                            // (`Promoted | CrossConnectionWon`), NEVER on
                            // `CrossConnectionLost`. Run synchronously right after
                            // `promote_connection` returns, before feeding
                            // `PromotionResolved` and before any await — the exact
                            // synchronous point (and Promoted/Won gating) of the
                            // pre-refactor in-`promote_connection` call. No-op when
                            // the worker pool isn't spawned (`register_...` early-
                            // returns), so the direct `promote_connection` test
                            // callers (which bypass this executor) are unaffected.
                            #[cfg(unix)]
                            match result {
                                PromotionResult::Promoted(node_addr)
                                | PromotionResult::CrossConnectionWon { node_addr, .. } => {
                                    self.register_decrypt_worker_session(&node_addr);
                                }
                                PromotionResult::CrossConnectionLost { .. } => {}
                            }

                            // Feed the outcome back into the machine and fold the
                            // follow-up actions (RegisterDecryptSession — now a
                            // redundant no-op, see its arm — and the cross-conn index
                            // frees) into the worklist. Disjoint field borrow again.
                            let follow = match self.peer_machines.get_mut(&promote_link) {
                                Some(machine) => machine.step(
                                    PeerEvent::PromotionResolved { result },
                                    ambient.now_ms,
                                    &mut self.index_allocator,
                                ),
                                None => Vec::new(),
                            };
                            queue.extend(follow);

                            // Defensive cross-connection loser-link surgery.
                            // LINK-ONLY: close the losing transport connection, drop
                            // its link, and re-point `addr_to_link`, reproducing the
                            // pre-refactor inline `handle_msg2`/`handle_msg1` per-arm
                            // order EXACTLY. The index-plane frees/unregisters are
                            // owned by the machine's `PromotionResolved{Won/Lost}`
                            // follow-up (queued just above), so NOTHING here touches
                            // an index — no double-free.
                            //
                            // UNREACHABLE on every current driven path: the inbound
                            // and outbound net-new establish arms only route to the
                            // machine when no promoted peer exists for the node_addr
                            // (and `RestartThenPromote` removes the old peer first),
                            // so `promote_connection` always returns `Promoted`. The
                            // `debug_assert!(false, ..)` catches any future path that
                            // drives a cross-connection through the executor without
                            // the matching send-state handling.
                            match result {
                                PromotionResult::CrossConnectionWon { loser_link_id, .. } => {
                                    debug_assert!(
                                        false,
                                        "executor CrossConnectionWon is unreachable on \
                                         driven net-new establish paths"
                                    );
                                    // Close the losing transport connection (no-op for
                                    // connectionless) via the LOSER link's own
                                    // transport/addr, then drop the losing link.
                                    if let Some(loser_link) = self.links.get(&loser_link_id) {
                                        let loser_tid = loser_link.transport_id();
                                        let loser_addr = loser_link.remote_addr().clone();
                                        if let Some(transport) = self.transports.get(&loser_tid) {
                                            transport.close_connection(&loser_addr).await;
                                        }
                                    }
                                    self.remove_link(&loser_link_id);
                                    // Point `addr_to_link` at the winning (current)
                                    // link.
                                    self.addr_to_link.insert(
                                        (ambient.transport_id, ambient.remote_addr.clone()),
                                        promote_link,
                                    );
                                }
                                PromotionResult::CrossConnectionLost { winner_link_id } => {
                                    debug_assert!(
                                        false,
                                        "executor CrossConnectionLost is unreachable on \
                                         driven net-new establish paths"
                                    );
                                    // Close this (losing) connection, drop its link,
                                    // and restore `addr_to_link` to the winner.
                                    if let Some(transport) =
                                        self.transports.get(&ambient.transport_id)
                                    {
                                        transport.close_connection(&ambient.remote_addr).await;
                                    }
                                    self.remove_link(&promote_link);
                                    self.addr_to_link.insert(
                                        (ambient.transport_id, ambient.remote_addr.clone()),
                                        winner_link_id,
                                    );
                                }
                                PromotionResult::Promoted(_) => {}
                            }
                        }
                        Err(e) => {
                            // Promotion failed. `promote_connection` already
                            // removed `connections[link]` and (on error) handled its
                            // own index internally. The pre-refactor inbound and
                            // outbound promote-Err arms were NOT byte-identical, so
                            // discriminate on `ambient.is_outbound`. The queue is
                            // drained (PromoteToActive is the last establish action),
                            // so no explicit abort.
                            if ambient.is_outbound {
                                // OLD outbound (`handle_msg2` promote-Err): warn +
                                // record_reject ONLY. NO `remove_link`, NO
                                // `index_allocator.free`, NO `addr_to_link` removal —
                                // the dead link/addr_to_link/pending_outbound were
                                // left for the 30s stale-connection reaper
                                // (`promote_connection` already handled
                                // `connections[link]`/its index on error). Restored
                                // pre-refactor outbound warn! ("Failed to promote
                                // connection").
                                //
                                // The transient outbound machine was inserted BEFORE
                                // execute; it is additive state that
                                // did not exist pre-refactor, so removing the just-
                                // inserted machine on failure is neutral vs old and
                                // prevents a leak.
                                warn!(
                                    target: "fips::node::handlers::handshake",
                                    link_id = %promote_link,
                                    error = %e,
                                    "Failed to promote connection"
                                );
                                self.stats_mut().record_reject(RejectReason::Handshake(
                                    HandshakeReject::BadState,
                                ));
                                self.peer_machines.remove(&promote_link);
                            } else {
                                // OLD inbound (`handle_msg1` L587-591): drop the link
                                // + reverse map, free our index, discard the machine,
                                // and record the reject. Restored pre-refactor inbound
                                // promote-failure warn! (`handle_msg1` L757).
                                warn!(
                                    target: "fips::node::handlers::handshake",
                                    link_id = %promote_link,
                                    error = %e,
                                    "Failed to promote inbound connection"
                                );
                                self.remove_link(&promote_link);
                                if let Some(idx) = ambient.our_index {
                                    let _ = self.index_allocator.free(idx);
                                }
                                self.peer_machines.remove(&promote_link);
                                self.stats_mut().record_reject(RejectReason::Handshake(
                                    HandshakeReject::BadState,
                                ));
                            }
                        }
                    }
                }
                PeerAction::SwapSendState { .. } => {
                    // Initiator cutover. Reproduces the `ConnAction::Cutover`
                    // body in `handlers/rekey.rs:53-88` EXACTLY. `addr` is resolved
                    // from the ambient verified identity (as `InvalidateSendState`
                    // does). The decrypt re-register folds HERE, gated on
                    // `did_cutover` — the generic `RegisterDecryptSession` arm stays a
                    // no-op so a promote never double-registers. Shadow-only until the
                    // cadence fold routes here.
                    let node_addr = *ambient.verified_identity.node_addr();
                    let did_cutover = if let Some(peer) = self.peers.get_mut(&node_addr) {
                        if let Some(_old_our_index) = peer.cutover_to_new_session() {
                            // New index was pre-registered in peers_by_index
                            // during msg2 handling (handshake.rs).
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
                                // Pin the target to the pre-refactor module: this
                                // cutover log relocated from handlers/rekey.rs into
                                // the executor, but operators (and the test harness)
                                // filter it under fips::node::handlers::rekey. Keeping
                                // the target preserves the observable log contract.
                                target: "fips::node::handlers::rekey",
                                peer = %self.peer_display_name(&node_addr),
                                "Rekey cutover complete (initiator), K-bit flipped"
                            );
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    // Re-register the new session with the decrypt worker — the
                    // cache_key (transport_id, our_index) just changed, so the
                    // old worker entry is stale and every packet on the new
                    // session would miss the worker's HashMap lookup.
                    #[cfg(unix)]
                    if did_cutover {
                        self.register_decrypt_worker_session(&node_addr);
                    }
                    #[cfg(not(unix))]
                    let _ = did_cutover;
                }
                PeerAction::CompleteDrain { peer: node_addr } => {
                    // Initiator drain completion. Reproduces the
                    // `ConnAction::Drain` body in `handlers/rekey.rs:90-111` EXACTLY.
                    // Extract the real previous index + transport_id under the peer
                    // borrow, drop the borrow, then run the cache_key cleanup (which
                    // takes &mut self for unregister_decrypt_worker_session).
                    // Shadow-only until the cadence fold routes here.
                    let drained = self.peers.get_mut(&node_addr).and_then(|peer| {
                        peer.complete_drain().map(|idx| (idx, peer.transport_id()))
                    });
                    if let Some((old_our_index, transport_id)) = drained {
                        if let Some(tid) = transport_id {
                            let cache_key = (tid, old_our_index.as_u32());
                            self.peers_by_index.remove(&cache_key);
                            #[cfg(unix)]
                            self.unregister_decrypt_worker_session(cache_key);
                        }
                        let _ = self.index_allocator.free(old_our_index);
                        trace!(
                            // Pin to the pre-refactor module (see the cutover log
                            // above) so the relocated drain log stays visible under
                            // the operator's fips::node::handlers::rekey filter.
                            target: "fips::node::handlers::rekey",
                            peer = %self.peer_display_name(&node_addr),
                            old_index = %old_our_index,
                            "Drain complete, previous session erased"
                        );
                    }
                }
                PeerAction::InvalidateSendState => {
                    // The FULL teardown. `remove_active_peer`
                    // (`dispatch.rs:107`) frees the four index slots
                    // (current/rekey/pending/previous), drops `peers_by_index`,
                    // unregisters the decrypt worker, removes the FSP `sessions`
                    // entry and `pending_tun_packets`. The machine emits NO
                    // `FreeIndex` for those slots, so there is no double-free.
                    self.remove_active_peer(ambient.verified_identity.node_addr());
                }
                PeerAction::RegisterDecryptSession { index } => {
                    let _ = index;
                    // No-op by design. The decrypt-worker
                    // registration relocated into the `PromoteToActive` Ok arm above, gated on
                    // the returned `PromotionResult`, so it runs once per live
                    // promote (Promoted/Won) at the pre-refactor synchronous point.
                    // This machine-emitted action is now redundant with that arm;
                    // kept as an inert no-op (rather than removing the emission) so
                    // the machine's action sequence and its unit tests stay
                    // unchanged. The keyed-by-NodeAddr register does not need the
                    // machine's `index` payload.
                }
                PeerAction::UnregisterDecryptSession { index } => {
                    // Executor supplies `transport_id` from ambient; keyed by
                    // (tid, index) like `remove_active_peer` / the rekey drain path.
                    #[cfg(unix)]
                    self.unregister_decrypt_worker_session((ambient.transport_id, index.as_u32()));
                    #[cfg(not(unix))]
                    let _ = index;
                }
                PeerAction::FreeIndex { index } => {
                    let _ = self.index_allocator.free(index);
                }
                PeerAction::ActivateConnectedUdp | PeerAction::TeardownConnectedUdp => {
                    // Connected-UDP plane ownership (`connected_udp.rs`).
                }
                PeerAction::SetTimer { .. } | PeerAction::CancelTimer { .. } => {
                    // Timers become actions on the existing quantized tick.
                    // INERT — the legacy tick timers still run, so driving
                    // these would double-schedule.
                }
                PeerAction::ReportLost { peer, kind } => {
                    // The single loss token, routed to the reconciler reflex the
                    // `kind` names: an un-promoted handshake attempt takes the
                    // connected-guarded `note_handshake_timeout` (`driver.rs:28`),
                    // an established peer's link-death takes the unconditional
                    // `note_link_dead` (`driver.rs:48`).
                    match kind {
                        LostKind::HandshakeTimeout => {
                            self.note_handshake_timeout(peer, ambient.now_ms);
                        }
                        LostKind::LinkDead => {
                            self.note_link_dead(peer, ambient.now_ms);
                        }
                    }
                }
            }
        }
    }
}
