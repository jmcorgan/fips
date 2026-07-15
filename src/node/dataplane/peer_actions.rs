//! Executor for the per-peer control machine's [`PeerAction`]s.
//!
//! The per-peer FSM in [`crate::peer::machine`] is a sans-IO reducer: it decides
//! *what* must happen and returns a `Vec<PeerAction>`; this module is the *doing*
//! half — the thin driver that maps each action onto the exact shell call it
//! stands for (`build_msg2` + `transport.send`, `promote_connection`,
//! `remove_active_peer`, `index_allocator.free`, `note_link_dead`, …).
//!
//! ## Progressive cutover
//!
//! The executor is wired incrementally. Live today: the outbound msg2 promote
//! (`handle_msg2` looks up the dial-persisted machine), the connectionless
//! outbound msg1 send (`SendHandshake` with `their_index == None` →
//! `send_stored_msg1`, driven from `initiate_connection`), and the
//! connection-oriented dial (`OpenTransport` performs the non-blocking
//! `transport.connect`; `TransportConnected` drives the connect-resolution msg1
//! send from `poll_pending_connects`).
//!
//! Inbound establish is not machine-driven here: `handle_msg1` builds and sends
//! msg2 inline, so `PeerEvent::InboundMsg1` is never dispatched and the
//! `SendHandshake` `their_index == Some` (msg2) branch stays dormant.
//!
//! Not yet driven, so their arms stay inert stubs: rekey/crypto installs,
//! link-control frames, the timers (`SetTimer`/`CancelTimer` — the legacy tick
//! still runs them), and the connected-UDP plane. `RegisterDecryptSession` is a
//! deliberate no-op — see its arm for the note.

use crate::PeerIdentity;
use crate::node::reject::{HandshakeReject, RejectReason};
use crate::node::{Node, NodeError};
use crate::peer::machine::{LostKind, PeerAction, PeerEvent};
use crate::proto::fmp::PromotionResult;
use crate::proto::fmp::wire::build_msg2;
use crate::transport::{LinkId, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use std::collections::VecDeque;
use tracing::{debug, info, trace, warn};

/// Ambient shell facts a [`PeerAction`] executor needs that the machine's
/// runtime-agnostic action payloads deliberately omit (verified identity,
/// transport target, the msg2 framing indices, the promotion timestamp).
///
/// Unlike a machine event/action payload this is **executor-side**, so it may
/// hold real values resolved from the wire context (cf. `handle_msg3`'s
/// `wire`/`packet` locals and `promote_connection`'s ambient args). It is built
/// fresh per driven step by the caller at cutover time.
#[allow(dead_code)]
pub(in crate::node) struct PeerActionCtx {
    /// The authenticated peer identity (`PromoteToActive` / `InvalidateSendState`
    /// / `SwapSendState` resolve their `NodeAddr` from this).
    pub(in crate::node) verified_identity: PeerIdentity,
    /// The transport the exchange is happening over (msg2 send target, decrypt
    /// cache-key transport half).
    pub(in crate::node) transport_id: TransportId,
    /// The peer's wire address (msg2 send target).
    pub(in crate::node) remote_addr: TransportAddr,
    /// Our session index for this exchange (msg2 framing sender_idx).
    pub(in crate::node) our_index: Option<SessionIndex>,
    /// The peer's session index for this exchange (msg2 framing receiver_idx).
    pub(in crate::node) their_index: Option<SessionIndex>,
    /// The wire timestamp driving this step (promotion ts / loss-report clock).
    pub(in crate::node) now_ms: u64,
    /// Establish direction for this exchange. `false` = inbound, `true` =
    /// outbound. `PromoteToActive` reads this to pick the direction-specific
    /// promote tail: the outbound branch logs a `Peer promoted to active` line
    /// and clears `pending_outbound`, and its promote-Err cleanup is warn-only
    /// (no link/index teardown), unlike the inbound branch.
    pub(in crate::node) is_outbound: bool,
    /// The `pending_outbound` key for an outbound promote, cleared on success.
    /// `Some` only on the outbound driven step (the map entry keyed by the wire
    /// `receiver_idx`); `None` on the inbound and maintenance paths, which have
    /// no `pending_outbound` entry to clear.
    pub(in crate::node) pending_outbound_key: Option<(TransportId, u32)>,
}

impl Node {
    /// Advance the machine for `link` by one event and execute the resulting
    /// actions.
    ///
    /// The borrow structure the whole seam turns on: the machine needs
    /// `&mut IndexAllocator` as a synchronous capability *while it is itself
    /// borrowed mutably out of `peer_machines`*. `peer_machines` and
    /// `index_allocator` are **distinct `Node` fields**, so the collect below is a
    /// disjoint two-field borrow the checker accepts; once the actions are
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
    /// The worklist is a `VecDeque` rather than self-recursion so the async
    /// executor stays a single flat future (no boxing) and the emitted order is
    /// preserved. `PromoteToActive` (deferred) will feed its resolution back into
    /// the machine and fold follow-up actions onto this same queue.
    pub(in crate::node) async fn execute_peer_actions(
        &mut self,
        link: LinkId,
        ambient: &PeerActionCtx,
        actions: Vec<PeerAction>,
    ) {
        let _ = link;
        let mut queue: VecDeque<PeerAction> = actions.into();
        while let Some(action) = queue.pop_front() {
            match action {
                PeerAction::OpenTransport {
                    transport_id,
                    remote_addr,
                } => {
                    // Outbound connection-oriented dial. `initiate_connection`'s
                    // oriented branch drove the machine to `Connecting`, which
                    // emitted this action. Perform the non-blocking
                    // `transport.connect` and, on success, push the
                    // `PendingConnect` for `poll_pending_connects` to resolve. On
                    // connect error, tear down the dial-window state (link,
                    // reverse map, control machine) and abort the queue — the
                    // executor-local mirror of the old inline
                    // `initiate_connection` connect+push.
                    if let Some(transport) = self.transports.get(&transport_id) {
                        match transport.connect(&remote_addr).await {
                            Ok(()) => {
                                debug!(
                                    transport_id = %transport_id,
                                    remote_addr = %remote_addr,
                                    link_id = %link,
                                    "Transport connect initiated (non-blocking)"
                                );
                                self.peering
                                    .pending_connects
                                    .push(crate::node::PendingConnect {
                                        link_id: link,
                                        transport_id,
                                        remote_addr,
                                        peer_identity: Some(ambient.verified_identity),
                                    });
                            }
                            Err(_e) => {
                                self.links.remove(&link);
                                self.addr_to_link.remove(&(transport_id, remote_addr));
                                self.peer_machines.remove(&link);
                                return;
                            }
                        }
                    }
                }
                PeerAction::SendHandshake { bytes } => {
                    // Two outbound directions share this action, discriminated by
                    // `their_index`:
                    //   msg2 (`their_index == Some`): the machine payload is the
                    //   UNFRAMED Noise msg2; frame it with our/their index
                    //   (`build_msg2`) and send.
                    //   msg1 (`their_index == None`): a fresh outbound handshake;
                    //   the machine's empty payload is ignored — the shell already
                    //   allocated the index, ran the Noise leaf, and armed the
                    //   wire at dial (`prepare_outbound_msg1`); this just sends the
                    //   stored wire (see `send_stored_msg1`).
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
                    } else {
                        // msg1: the shell already allocated the index, ran the
                        // Noise leaf, and armed the wire on the connection at dial
                        // (`prepare_outbound_msg1`); send the stored wire. The
                        // machine's empty payload is ignored.
                        let _ = bytes;
                        self.send_stored_msg1(link, ambient.transport_id, &ambient.remote_addr)
                            .await;
                    }
                }
                PeerAction::SendRekey { .. } => {
                    // Rekey msg framing (`build_msg2(our_new_index, …)`) + send.
                    // Rekey fold is out of scope here.
                }
                PeerAction::SendLinkMessage { .. } => {
                    // Encrypt + send a link-control frame (heartbeat / filter /
                    // tree / disconnect). Data-plane-owned; out of scope here.
                }
                PeerAction::PromoteToActive { link: promote_link } => {
                    // Establish promote, driven through the machine. Transcribes
                    // `handle_msg3`'s shared inbound promote block verbatim, adapted
                    // to the executor's ambient context. Two XX-specific choices vs
                    // the IK-lineage executor: (1) the decrypt-worker register stays
                    // INSIDE `promote_connection` (NOT relocated here) — re-
                    // registering would double-register; (2) NO `PromotionResolved`
                    // is fed back — the persistent machine is born `established()` by
                    // `promote_connection`, so feeding it would perturb that ctor
                    // state that the rekey/reap folds read.

                    // Capture msg2 BEFORE `promote_connection` removes the pending
                    // connection, so a duplicate msg1 can be answered with it. Only
                    // the inbound promote answers a duplicate inbound msg1; the
                    // outbound side has no stored msg2 to resend.
                    let wire_msg2 = if ambient.is_outbound {
                        None
                    } else {
                        self.connections
                            .get(&promote_link)
                            .and_then(|c| c.handshake_msg2().map(|m| m.to_vec()))
                    };

                    if ambient.is_outbound {
                        debug!(
                            // Relocated from `handlers/handshake.rs`: pin the target
                            // so it stays visible under the harness's
                            // `fips::node::handlers::handshake=debug` filter.
                            target: "fips::node::handlers::handshake",
                            peer = %self.peer_display_name(ambient.verified_identity.node_addr()),
                            link_id = %promote_link,
                            "handle_msg2: promoting outbound, peers_has_key={}",
                            self.peers.contains_key(ambient.verified_identity.node_addr()),
                        );
                    } else {
                        debug!(
                            // Relocated from `handlers/handshake.rs`: pin the target
                            // so it stays visible under the harness's
                            // `fips::node::handlers::handshake=debug` filter.
                            target: "fips::node::handlers::handshake",
                            peer = %self.peer_display_name(ambient.verified_identity.node_addr()),
                            link_id = %promote_link,
                            our_index = ?ambient.our_index,
                            "handle_msg3: promoting inbound, peers_has_key={}",
                            self.peers.contains_key(ambient.verified_identity.node_addr()),
                        );
                    }
                    match self.promote_connection(
                        promote_link,
                        ambient.verified_identity,
                        ambient.now_ms,
                    ) {
                        Ok(PromotionResult::Promoted(node_addr)) => {
                            if ambient.is_outbound {
                                // The outbound promote logs a second line here in
                                // addition to `promote_connection`'s "Connection
                                // promoted to active peer". Pin the target so the
                                // relocated line keeps the module it filtered under.
                                info!(
                                    target: "fips::node::handlers::handshake",
                                    peer = %self.peer_display_name(&node_addr),
                                    "Peer promoted to active"
                                );
                            } else {
                                // Store msg2 on peer for resend on duplicate msg1
                                if let (Some(peer), Some(msg2)) =
                                    (self.peers.get_mut(&node_addr), wire_msg2)
                                {
                                    peer.set_handshake_msg2(msg2);
                                }
                                // Promotion is logged once by `promote_connection`
                                // ("Connection promoted to active peer"); no separate
                                // inbound-path line.
                            }
                            // Send initial tree announce to new peer
                            if let Err(e) = self.send_tree_announce_to_peer(&node_addr).await {
                                debug!(peer = %self.peer_display_name(&node_addr), error = %e, "Failed to send initial TreeAnnounce");
                            }
                            // Schedule filter announce (sent on next tick via debounce)
                            self.bloom_state.mark_update_needed(node_addr);
                            self.reset_lookup_backoff();
                            // Clear the pending outbound entry on promote success
                            // only; a failed promote leaves it for the stale-
                            // connection reaper.
                            if let Some(k) = ambient.pending_outbound_key {
                                self.pending_outbound.remove(&k);
                            }
                        }
                        Ok(PromotionResult::CrossConnectionWon {
                            loser_link_id,
                            node_addr,
                        }) => {
                            // UNREACHABLE on driven XX establish paths: `Promote`
                            // and `RestartThenPromote` (which removes the old peer
                            // first) both imply no existing peer at promote time, so
                            // `promote_connection` returns `Promoted`. Body kept
                            // byte-equivalent to next so a future path that drives a
                            // cross-connection through the executor trips the assert.
                            debug_assert!(
                                false,
                                "executor CrossConnectionWon is unreachable on driven \
                                 XX inbound establish paths"
                            );
                            // Store msg2 on peer for resend on duplicate msg1
                            if let (Some(peer), Some(msg2)) =
                                (self.peers.get_mut(&node_addr), wire_msg2)
                            {
                                peer.set_handshake_msg2(msg2);
                            }
                            // Close the losing TCP connection (no-op for connectionless)
                            if let Some(loser_link) = self.links.get(&loser_link_id) {
                                let loser_tid = loser_link.transport_id();
                                let loser_addr = loser_link.remote_addr().clone();
                                if let Some(transport) = self.transports.get(&loser_tid) {
                                    transport.close_connection(&loser_addr).await;
                                }
                            }
                            // Clean up the losing connection's link
                            self.remove_link(&loser_link_id);
                            debug!(
                                peer = %self.peer_display_name(&node_addr),
                                loser_link_id = %loser_link_id,
                                "Inbound cross-connection won, loser link cleaned up"
                            );
                            if let Err(e) = self.send_tree_announce_to_peer(&node_addr).await {
                                debug!(peer = %self.peer_display_name(&node_addr), error = %e, "Failed to send initial TreeAnnounce");
                            }
                            self.bloom_state.mark_update_needed(node_addr);
                            self.reset_lookup_backoff();
                        }
                        Ok(PromotionResult::CrossConnectionLost { winner_link_id }) => {
                            // UNREACHABLE on driven XX establish paths (see the Won
                            // arm). Body kept byte-equivalent to next; uses the
                            // ambient transport/addr in place of next's `packet.*`.
                            debug_assert!(
                                false,
                                "executor CrossConnectionLost is unreachable on driven \
                                 XX inbound establish paths"
                            );
                            // Close the losing TCP connection (no-op for connectionless)
                            if let Some(transport) = self.transports.get(&ambient.transport_id) {
                                transport.close_connection(&ambient.remote_addr).await;
                            }
                            // This connection lost — clean up its link
                            self.remove_link(&promote_link);
                            // Restore addr_to_link for the winner's link
                            self.addr_to_link.insert(
                                (ambient.transport_id, ambient.remote_addr.clone()),
                                winner_link_id,
                            );
                            debug!(
                                winner_link_id = %winner_link_id,
                                "Inbound cross-connection lost, keeping existing"
                            );
                        }
                        Err(e) if ambient.is_outbound => {
                            // The outbound promote-failure path is warn-only: it
                            // records the reject but performs no link/index teardown
                            // and leaves the `pending_outbound` entry for the stale-
                            // connection reaper.
                            warn!(
                                target: "fips::node::handlers::handshake",
                                link_id = %promote_link,
                                error = %e,
                                "Failed to promote connection"
                            );
                            self.stats_mut()
                                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        }
                        Err(e) => {
                            // A max_peers rejection is expected policy, not a fault —
                            // log it at debug to avoid WARN spam when a cap'd node is
                            // under sustained inbound pressure. Other promotion
                            // failures remain at warn.
                            if matches!(e, NodeError::MaxPeersExceeded { .. }) {
                                debug!(
                                    // Emit under the handshake target (same as the
                                    // "promoting inbound" line above) so this stays
                                    // visible wherever inbound handshake events are
                                    // logged at debug, independent of this module's
                                    // own log level.
                                    target: "fips::node::handlers::handshake",
                                    peer = %self.peer_display_name(ambient.verified_identity.node_addr()),
                                    max = self.max_peers(),
                                    "Rejecting inbound connection at max_peers cap (no promotion)"
                                );
                            } else {
                                warn!(
                                    target: "fips::node::handlers::handshake",
                                    link_id = %promote_link,
                                    error = %e,
                                    "Failed to promote inbound connection"
                                );
                            }
                            // Clean up on promotion failure. promote_connection
                            // already freed our_index in its MaxPeersExceeded path;
                            // freeing again here is benign (IndexAllocator::free is a
                            // HashSet::remove, the second call returns Err(NotFound)
                            // and is ignored).
                            self.remove_link(&promote_link);
                            if let Some(idx) = ambient.our_index {
                                let _ = self.index_allocator.free(idx);
                            }
                            self.stats_mut()
                                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        }
                    }
                }
                PeerAction::SwapSendState { .. } => {
                    // Initiator cutover. Reproduces the `ConnAction::Cutover` body
                    // in `handlers/rekey.rs`'s `check_rekey` EXACTLY. `addr` is
                    // resolved from the ambient verified identity. The decrypt
                    // re-register folds HERE, gated on `did_cutover` — the generic
                    // `RegisterDecryptSession` arm stays a no-op so a promote never
                    // double-registers. Shadow-only until the cadence fold routes
                    // here.
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
                            let our_index = peer.our_index();
                            let their_index = peer.their_index();
                            info!(
                                // Pin the target to the pre-refactor module: this
                                // cutover log relocated from handlers/rekey.rs into
                                // the executor, but operators (and the test harness)
                                // filter it under fips::node::handlers::rekey.
                                // Keeping the target preserves the observable log
                                // contract (level + fields match next's rekey.rs).
                                target: "fips::node::handlers::rekey",
                                peer = %self.peer_display_name(&node_addr),
                                our_addr = %self.identity().node_addr(),
                                their_addr = %node_addr,
                                our_index = ?our_index,
                                their_index = ?their_index,
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
                    // cache_key (transport_id, our_index) just changed, so the old
                    // worker entry is stale and every packet on the new session
                    // would miss the worker's HashMap lookup.
                    #[cfg(unix)]
                    if did_cutover {
                        self.register_decrypt_worker_session(&node_addr);
                    }
                    #[cfg(not(unix))]
                    let _ = did_cutover;
                }
                PeerAction::CompleteDrain { peer: node_addr } => {
                    // Initiator drain completion. Reproduces the `ConnAction::Drain`
                    // body in `handlers/rekey.rs`'s `check_rekey` EXACTLY. Extract
                    // the real previous index + transport_id under the peer borrow,
                    // drop the borrow, then run the cache_key cleanup (which takes
                    // &mut self for unregister_decrypt_worker_session). Shadow-only
                    // until the cadence fold routes here.
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
                    // The FULL teardown. `remove_active_peer` frees the four index
                    // slots (current/rekey/pending/previous), drops
                    // `peers_by_index`, unregisters the decrypt worker, removes the
                    // FSP `sessions` entry and `pending_tun_packets`. The machine
                    // emits NO `FreeIndex` for those slots, so there is no
                    // double-free.
                    self.remove_active_peer(ambient.verified_identity.node_addr());
                }
                PeerAction::SwapToInboundSession { .. } => {
                    // DEFERRED: XX inbound cross-connection resolved at msg3. The
                    // session swap (`take_session`/`replace_session`,
                    // `peers_by_index` surgery, free the peer's OLD index — or free
                    // `our_index` on the losing side) is written, wired, and
                    // ci-local-validated when the inbound establish path is wired.
                    // Unreachable now (nothing drives the machine).
                    debug_assert!(
                        false,
                        "SwapToInboundSession executor body lands when inbound establish is wired"
                    );
                }
                PeerAction::RekeyRespondTrigger { .. } => {
                    // DEFERRED: XX rekey-responder resolved at msg3. The session
                    // move (`abandon_rekey` + index/`peers_by_index`/
                    // `pending_outbound` cleanup, then `take_session` +
                    // `set_pending_session` + `record_peer_rekey` +
                    // `peers_by_index.insert`) is written, wired, and
                    // ci-local-validated when the inbound establish path is wired.
                    // Unreachable now (nothing drives the machine).
                    debug_assert!(
                        false,
                        "RekeyRespondTrigger executor body lands when inbound establish is wired"
                    );
                }
                PeerAction::RegisterDecryptSession { index } => {
                    let _ = index;
                    // No-op by design. The rekey-cutover decrypt-worker register
                    // relocates into the driven `SwapSendState` site above (gated
                    // on `did_cutover`); the establish-promote register stays INSIDE
                    // `promote_connection`, so `PromoteToActive` does not re-register
                    // either. This machine-emitted action is redundant with both;
                    // kept as an inert no-op (rather than removing the emission) so
                    // the machine's action sequence and unit tests stay unchanged.
                    // The keyed-by-NodeAddr register does not need the machine's
                    // `index` payload.
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
                    // Connected-UDP plane ownership (`connected_udp.rs`). Out of
                    // scope for now.
                }
                PeerAction::SetTimer { .. } | PeerAction::CancelTimer { .. } => {
                    // Timers become actions on the existing quantized tick. INERT:
                    // the legacy tick timers still run, so driving these would
                    // double-schedule.
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
