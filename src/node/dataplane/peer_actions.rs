//! Executor for the per-peer control machine's [`PeerAction`]s (Step 2 / C3).
//!
//! The per-peer FSM in [`crate::peer::machine`] is a sans-IO reducer: it decides
//! *what* must happen and returns a `Vec<PeerAction>`; this module is the *doing*
//! half — the thin driver that maps each action onto the exact shell call it
//! stands for (`build_msg2` + `transport.send`, `promote_connection`,
//! `remove_active_peer`, `index_allocator.free`, `note_link_dead`, …).
//!
//! ## C3-1 skeleton (SHADOW-ONLY)
//!
//! This is the **C3-1** increment: the machine home (`Node.peer_machines`), the
//! executor, and the disjoint-borrow advance helper. It is **unwired** — the live
//! `handle_msg1`/`handle_msg2` path does not drive it yet, so every method here is
//! `#[allow(dead_code)]`. The inbound cutover (`handle_msg1` → `step(InboundMsg1)`)
//! lands in **C3-2**, the outbound cutover (`handle_msg2` / dial) in **C3-3**.
//!
//! Arms the C3 ladder does not yet exercise are inert stubs carrying the sub-commit
//! that realizes them (`OpenTransport`→C3-3, `SendRekey`/`SwapSendState`→C4,
//! `SendLinkMessage`→C4/C5, `SetTimer`/`CancelTimer`→C5 inert, connected-UDP→C6).
//! `RegisterDecryptSession` is a deliberate no-op — see its arm for the C3-2 note.

use crate::node::Node;
use crate::node::reject::{HandshakeReject, RejectReason};
use crate::peer::machine::{PeerAction, PeerEvent};
use crate::proto::fmp::wire::build_msg2;
use crate::transport::{LinkId, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use crate::{NodeAddr, PeerIdentity};
use std::collections::VecDeque;
use tracing::warn;

/// Ambient shell facts a [`PeerAction`] executor needs that the machine's
/// runtime-agnostic action payloads deliberately omit (verified identity,
/// transport target, the msg2 framing indices, the promotion timestamp).
///
/// Unlike a machine event/action payload this is **executor-side**, so it may
/// hold real values resolved from the wire context (cf. `handle_msg1`'s
/// `wire`/`packet` locals and `drive_promote_to_active`'s ambient args). It is
/// built fresh per driven step by the caller at cutover time (C3-2/C3-3).
#[allow(dead_code)]
pub(in crate::node) struct PeerActionCtx {
    /// The authenticated peer identity (GAP-1: `PromoteToActive` /
    /// `InvalidateSendState` resolve their `NodeAddr` from this).
    pub(in crate::node) verified_identity: PeerIdentity,
    /// The transport the exchange is happening over (msg2 send target, decrypt
    /// cache-key transport half).
    pub(in crate::node) transport_id: TransportId,
    /// The peer's wire address (msg2 send target).
    pub(in crate::node) remote_addr: TransportAddr,
    /// Our session index for this exchange (GAP-2: msg2 framing sender_idx).
    pub(in crate::node) our_index: Option<SessionIndex>,
    /// The peer's session index for this exchange (GAP-2: msg2 framing
    /// receiver_idx).
    pub(in crate::node) their_index: Option<SessionIndex>,
    /// The wire timestamp driving this step (promotion ts / loss-report clock).
    pub(in crate::node) now_ms: u64,
}

impl Node {
    /// Advance the machine for `link` by one event and execute the resulting
    /// actions.
    ///
    /// The borrow structure the whole seam turns on (spec risk #8): the machine
    /// needs `&mut IndexAllocator` as a synchronous capability *while it is
    /// itself borrowed mutably out of `peer_machines`*. `peer_machines` and
    /// `index_allocator` are **distinct `Node` fields**, so the collect below is
    /// a disjoint two-field borrow the checker accepts; once the actions are
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

    /// Map each [`PeerAction`] onto its shell call (spec's executor table).
    ///
    /// `PromoteToActive` feeds its [`PromotionResult`](crate::proto::fmp::PromotionResult)
    /// back into the machine (GAP-1) and appends the follow-up actions to the same
    /// worklist — a queue rather than self-recursion so the async executor stays a
    /// single flat future (no boxing) and the emitted order is preserved (the
    /// establish sequences always end in `PromoteToActive`, so its follow-ups run
    /// after any siblings).
    #[allow(dead_code)]
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
                    // C3-3: outbound dial (`initiate_connection`,
                    // `lifecycle/mod.rs:470`). Outbound establish is not cut over
                    // until C3-3; inert in the C3-1 skeleton.
                }
                PeerAction::SendHandshake { bytes } => {
                    // GAP-2: the machine payload is the UNFRAMED Noise msg2 payload;
                    // frame it with our/their index (mirrors `handshake.rs:472`'s
                    // `build_msg2(our_index, their_index, &payload)`) before the
                    // wire send. A fresh-outbound msg1 (empty payload → build msg1
                    // from indices) is framed differently and lands in C3-3.
                    if let (Some(sender_idx), Some(receiver_idx)) =
                        (ambient.our_index, ambient.their_index)
                    {
                        let frame = build_msg2(sender_idx, receiver_idx, &bytes);
                        // GAP-5: surface the send Result. A missing transport skips
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
                    // C4: rekey msg2 framing (`build_msg2(our_new_index, …)`,
                    // `handshake.rs:365`) + send. Rekey fold is out of C3 scope.
                }
                PeerAction::SendLinkMessage { .. } => {
                    // C4/C5: encrypt + send a link-control frame (heartbeat / filter
                    // / tree / disconnect). Data-plane-owned; out of C3 scope.
                }
                PeerAction::PromoteToActive { link: promote_link } => {
                    // GAP-1: ambient supplies the verified identity + promotion ts
                    // that `promote_connection` needs (cf. `drive_promote_to_active`).
                    match self.promote_connection(
                        promote_link,
                        ambient.verified_identity,
                        ambient.now_ms,
                    ) {
                        Ok(result) => {
                            // Feed the outcome back into the machine and fold the
                            // follow-up actions (RegisterDecryptSession, cross-conn
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
                        }
                        Err(e) => {
                            // GAP-4: promotion failed. `promote_connection` already
                            // removed `connections[link]`; mirror the pre-refactor
                            // cleanup (`handle_msg1` L587-591): drop the link +
                            // reverse map, free our index, discard the machine, and
                            // record the reject. The queue is drained (PromoteToActive
                            // is the last establish action), so no explicit abort.
                            //
                            // Restored pre-refactor promote-failure warn!
                            // (`handle_msg1` L757).
                            warn!(link_id = %promote_link, error = %e, "Failed to promote inbound connection");
                            self.remove_link(&promote_link);
                            if let Some(idx) = ambient.our_index {
                                let _ = self.index_allocator.free(idx);
                            }
                            self.peer_machines.remove(&promote_link);
                            self.stats_mut()
                                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                        }
                    }
                }
                PeerAction::SwapSendState { .. } => {
                    // C4: initiator cutover (`active.rs:1033`
                    // `cutover_to_new_session`).
                }
                PeerAction::InvalidateSendState => {
                    // GAP-4 (biggest): the FULL teardown. `remove_active_peer`
                    // (`dispatch.rs:107`) frees the four index slots
                    // (current/rekey/pending/previous), drops `peers_by_index`,
                    // unregisters the decrypt worker, removes the FSP `sessions`
                    // entry and `pending_tun_packets`. The machine emits NO
                    // `FreeIndex` for those slots, so there is no double-free.
                    self.remove_active_peer(ambient.verified_identity.node_addr());
                }
                PeerAction::RegisterDecryptSession { index } => {
                    let _ = index;
                    // C3-2 (HALT-reported): the decrypt-worker registration still
                    // runs INSIDE `promote_connection` (`handshake.rs:1193/1305`),
                    // which is the single source of truth for its ~40 direct
                    // `promote_connection` callers (unit/integration tests) and the
                    // two live handlers. Relocating it out (GAP-3) would perturb the
                    // live promote path, so C3-1 keeps it there and drives this
                    // action as a no-op; the relocation lands with the inbound
                    // cutover in C3-2.
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
                    // C6: connected-UDP plane ownership (`connected_udp.rs`).
                }
                PeerAction::SetTimer { .. } | PeerAction::CancelTimer { .. } => {
                    // C5: timers become actions on the existing quantized tick.
                    // INERT in C3 — the legacy tick timers still run, so driving
                    // these would double-schedule (spec risk #7).
                }
                PeerAction::ReportLost { peer } => {
                    // The single loss token → the reconciler reflex (`driver.rs:48`).
                    self.report_peer_lost(peer, ambient.now_ms);
                }
            }
        }
    }

    /// `ReportLost` → `note_link_dead` (kept as a named seam so the ambient clock
    /// source is explicit and C5 can thread the reconciler-computed backoff).
    #[allow(dead_code)]
    fn report_peer_lost(&mut self, peer: NodeAddr, now_ms: u64) {
        self.note_link_dead(peer, now_ms);
    }
}
