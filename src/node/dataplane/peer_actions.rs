//! Executor for the per-peer control machine's [`PeerAction`]s (Step 2 / M2).
//!
//! The per-peer FSM in [`crate::peer::machine`] is a sans-IO reducer: it decides
//! *what* must happen and returns a `Vec<PeerAction>`; this module is the *doing*
//! half — the thin driver that maps each action onto the exact shell call it
//! stands for (`build_msg2` + `transport.send`, `promote_connection`,
//! `remove_active_peer`, `index_allocator.free`, `note_link_dead`, …).
//!
//! ## M2 skeleton (SHADOW-ONLY)
//!
//! This is the **M2** increment: the machine home (`Node.peer_machines`), the
//! executor, and the disjoint-borrow advance helper. It is **unwired** — no live
//! handler path drives the machine and nothing inserts into `peer_machines`, so
//! every method here is `#[allow(dead_code)]` and behaviorally inert.
//!
//! The arm bodies that a later reap/rekey/timer step will drive for real are
//! ported 1:1 from the IK-lineage executor and adapted to next's Node API — they
//! reproduce next's inline shell bodies exactly:
//!
//! - `SwapSendState` / `CompleteDrain` mirror `handlers/rekey.rs`'s `check_rekey`
//!   `Cutover` / `Drain` bodies (`peer.cutover_to_new_session()` +
//!   `register_decrypt_worker_session` gated on `did_cutover`;
//!   `peer.complete_drain()` → `peers_by_index.remove` +
//!   `unregister_decrypt_worker_session` + `index_allocator.free`).
//! - `InvalidateSendState` → `remove_active_peer` (the full teardown).
//! - `ReportLost` → `note_link_dead` (the reconciler loss reflex).
//! - `UnregisterDecryptSession` / `FreeIndex` index-plane cleanups.
//! - `RegisterDecryptSession` is a deliberate no-op — the decrypt-worker register
//!   relocates into the driven register sites (`SwapSendState` here for the rekey
//!   cutover; `PromoteToActive`'s deferred body for the establish promote).
//!
//! Actions the M2 skeleton does not yet exercise are inert stubs carrying the
//! step that realizes them: the establish send-path (`SendHandshake` framing) and
//! the establish promote (`PromoteToActive`) both land when the inbound establish
//! path is wired; `SendRekey`/`SendLinkMessage`, the timers
//! (`SetTimer`/`CancelTimer`), the outbound dial (`OpenTransport`), and the
//! connected-UDP plane are inert here.
//!
//! Three XX-semantic arms are explicit **deferred stubs** whose real bodies land
//! when the inbound establish path is wired: `PromoteToActive`,
//! `SwapToInboundSession`, and `RekeyRespondTrigger`. Each carries a
//! `debug_assert!(false, …)` guard + a benign no-op — they are unreachable now
//! (nothing drives the machine), so this is safe shadow.

use crate::node::Node;
use crate::peer::machine::{PeerAction, PeerEvent};
use crate::transport::{LinkId, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use crate::{NodeAddr, PeerIdentity};
use std::collections::VecDeque;
use tracing::{info, trace};

/// Ambient shell facts a [`PeerAction`] executor needs that the machine's
/// runtime-agnostic action payloads deliberately omit (verified identity,
/// transport target, the msg2 framing indices, the promotion timestamp).
///
/// Unlike a machine event/action payload this is **executor-side**, so it may
/// hold real values resolved from the wire context (cf. `handle_msg3`'s
/// `wire`/`packet` locals and `promote_connection`'s ambient args). It is built
/// fresh per driven step by the caller at cutover time (a later establish step).
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
    /// Establish direction for this exchange. Discriminates the `PromoteToActive`
    /// failure cleanup (the inbound and outbound promote-Err arms differ). `false`
    /// = inbound, `true` = outbound. Consumed by the deferred `PromoteToActive`
    /// body.
    pub(in crate::node) is_outbound: bool,
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
    #[allow(dead_code)]
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

    /// Map each [`PeerAction`] onto its shell call (the executor table).
    ///
    /// The worklist is a `VecDeque` rather than self-recursion so the async
    /// executor stays a single flat future (no boxing) and the emitted order is
    /// preserved. `PromoteToActive` (deferred) will feed its resolution back into
    /// the machine and fold follow-up actions onto this same queue.
    #[allow(dead_code)]
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
                PeerAction::OpenTransport { .. } => {
                    // Outbound dial (`initiate_connection`). Outbound establish is
                    // not cut over yet; inert in the M2 skeleton.
                }
                PeerAction::SendHandshake { .. } => {
                    // Inbound establish send-path: frame the unframed Noise msg2
                    // payload with our/their index (`build_msg2(our_index,
                    // their_index, &payload)`) and send, with the msg2-send-failure
                    // cleanup + queue abort. Lands with `PromoteToActive` when the
                    // inbound establish path is wired; inert in the M2 skeleton.
                }
                PeerAction::SendRekey { .. } => {
                    // Rekey msg framing (`build_msg2(our_new_index, …)`) + send.
                    // Rekey fold is out of M2 scope.
                }
                PeerAction::SendLinkMessage { .. } => {
                    // Encrypt + send a link-control frame (heartbeat / filter /
                    // tree / disconnect). Data-plane-owned; out of M2 scope.
                }
                PeerAction::PromoteToActive { .. } => {
                    // DEFERRED: crystallize identity + `promote_connection` +
                    // relocated decrypt-worker register + `PromotionResolved`
                    // feedback + cross-connection loser-link surgery. This is
                    // XX-semantic (identity at msg3) and is written, wired, and
                    // ci-local-validated when the inbound establish path is wired.
                    // Unreachable now (nothing drives the machine).
                    debug_assert!(
                        false,
                        "PromoteToActive executor body lands when inbound establish is wired"
                    );
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
                    // No-op by design. The decrypt-worker registration relocates
                    // into the driven register sites: `SwapSendState` above (gated
                    // on `did_cutover`) for the rekey cutover, and the deferred
                    // `PromoteToActive` body for the establish promote. This
                    // machine-emitted action is redundant with those; kept as an
                    // inert no-op (rather than removing the emission) so the
                    // machine's action sequence and unit tests stay unchanged. The
                    // keyed-by-NodeAddr register does not need the machine's `index`
                    // payload.
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
                    // Connected-UDP plane ownership (`connected_udp.rs`). Out of M2
                    // scope.
                }
                PeerAction::SetTimer { .. } | PeerAction::CancelTimer { .. } => {
                    // Timers become actions on the existing quantized tick. INERT in
                    // M2 — the legacy tick timers still run, so driving these would
                    // double-schedule.
                }
                PeerAction::ReportLost { peer } => {
                    // The single loss token → the reconciler reflex.
                    self.report_peer_lost(peer, ambient.now_ms);
                }
            }
        }
    }

    /// `ReportLost` → `note_link_dead` (kept as a named seam so the ambient clock
    /// source is explicit and a later step can thread the reconciler-computed
    /// backoff).
    #[allow(dead_code)]
    fn report_peer_lost(&mut self, peer: NodeAddr, now_ms: u64) {
        self.note_link_dead(peer, now_ms);
    }
}
