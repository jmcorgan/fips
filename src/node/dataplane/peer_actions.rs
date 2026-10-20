//! Executor for the per-peer control machine's [`PeerAction`]s.
//!
//! The per-peer FSM in [`crate::peer::machine`] is a sans-IO reducer: it decides
//! *what* must happen and returns a `Vec<PeerAction>`; this module is the *doing*
//! half — the thin driver that maps each action onto the exact shell call it
//! stands for (`build_msg2` + `send_existing`, `send_stored_msg1`,
//! `promote_connection`, `remove_active_peer`, `index_allocator.free`,
//! `note_link_dead`, …).
//!
//! ## Progressive cutover
//!
//! The executor is wired incrementally. Live today: the outbound msg2 promote
//! (`handle_msg2` looks up the dial-persisted machine), the connectionless
//! outbound msg1 send (`SendHandshake` with `their_index == None` →
//! `send_stored_msg1`, driven from `initiate_connection`), the
//! connection-oriented dial (`OpenTransport` performs the non-blocking
//! `transport.connect`; `TransportConnected` drives the connect-resolution msg1
//! send from `poll_pending_connects`), and the liveness reap (`route_link_dead`
//! → `LinkDeadSuspected`, driving `InvalidateSendState` → `remove_active_peer`).
//! A link's rekeys do not pass through here: the active peer's link rekey
//! machine holds them, and its outputs run through `run_link_outputs`.
//!
//! Inbound msg1 is not machine-driven here: `handle_msg1` builds and sends
//! msg2 inline (persisting the leg's machine parked at `SentMsg2` alongside),
//! so `PeerEvent::InboundMsg1` is never dispatched and the `SendHandshake`
//! `their_index == Some` (msg2) branch stays dormant. Inbound msg3 IS
//! machine-driven: `handle_msg3` steps the leg's persistent machine and this
//! executor performs its verdict (`PromoteToActive`, `ResolveInboundCrossConnection`),
//! disposing the machine on every path that consumes the leg without
//! promoting it.
//!
//! The genuine inert stubs remaining are `SendRekey`, `SendLinkMessage`, and
//! the connected-UDP arms. `RegisterDecryptSession` is a deliberate no-op —
//! see its arm for the note.
//!
//! The timer arms (`SetTimer`/`CancelTimer`) populate/clear the per-peer timer
//! store (`peer_timers`). The `HandshakeRetransmit` and `HandshakeTimeout`
//! deadlines are read and fired by `drive_peer_timers` (the handshake resend +
//! reap home). The liveness kind is still SHADOW — driven by its own shell
//! driver — so populating it stays behavior-neutral.

use crate::PeerIdentity;
use crate::identity::NodeAddr;
use crate::node::reject::{HandshakeReject, RejectReason};
use crate::node::{Node, NodeError};
use crate::peer::machine::{LostKind, PeerAction, PeerEvent};
use crate::proto::fmp::wire::build_msg2;
use crate::proto::fmp::{PromotionResult, cross_connection_winner};
use crate::transport::{LinkId, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use std::collections::VecDeque;
use tracing::{debug, info, warn};

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
    /// The wire timestamp driving this step (promotion ts). A loss report does
    /// not use it: the retry schedule reads the peering clock.
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
                                let origin = self
                                    .peer_machines
                                    .get(&link)
                                    .map(|machine| machine.dial_origin())
                                    .unwrap_or_default();
                                self.peering
                                    .pending_connects
                                    .push(crate::node::PendingConnect {
                                        link_id: link,
                                        transport_id,
                                        remote_addr,
                                        peer_identity: Some(ambient.verified_identity),
                                        origin,
                                    });
                            }
                            Err(_e) => {
                                self.links.remove(&link);
                                self.addr_to_link.remove(&(transport_id, remote_addr));
                                self.remove_peer_machine(link);
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
                        // `if let Some(transport)` guard); a send *error* is
                        // settled by the rule `handle_msg1` uses
                        // (`Node::msg2_failed`: a transient one keeps the leg,
                        // a terminal one disposes it) and, either way, ABORTS
                        // the remaining queue so the queued `PromoteToActive`
                        // never runs. The send never dials: if the msg1's
                        // connection has closed, a dial to its address (for an
                        // inbound connection, the initiator's ephemeral port)
                        // would hold the rx loop for up to the connect timeout.
                        let send_err = match self.transports.get(&ambient.transport_id) {
                            Some(transport) => transport
                                .send_existing(&ambient.remote_addr, &frame)
                                .await
                                .err(),
                            None => None,
                        };
                        if let Some(e) = send_err {
                            self.msg2_failed(link, &e);
                            return;
                        }
                    } else {
                        // msg1: the shell already allocated the index, ran the
                        // Noise leaf, and armed the wire on the connection at dial
                        // (`prepare_outbound_msg1`); send the stored wire. The
                        // machine's empty payload is ignored.
                        let _ = bytes;
                        self.send_stored_msg1(
                            link,
                            ambient.transport_id,
                            &ambient.remote_addr,
                            ambient.now_ms,
                        )
                        .await;
                    }
                }
                PeerAction::SendLinkMessage { .. } => {
                    // Encrypt + send a link-control frame (heartbeat / filter /
                    // tree / disconnect). Data-plane-owned; out of scope here.
                }
                PeerAction::PromoteToActive { link: promote_link } => {
                    // Establish promote, driven through the machine. Transcribes
                    // `handle_msg3`'s shared inbound promote block verbatim, adapted
                    // to the executor's ambient context. One XX-specific choice vs
                    // the IK-lineage executor: the decrypt-worker register stays
                    // INSIDE `promote_connection` (NOT relocated here) — re-
                    // registering would double-register. The promoted leg's machine
                    // (msg1-born inbound, dial-born outbound) survives the promotion
                    // and is crystallized in place by the `PromotionResolved`
                    // feedback fed back after the Ok handling below.

                    // Capture msg2 BEFORE `promote_connection` removes the pending
                    // connection, so a duplicate msg1 can be answered with it. Only
                    // the inbound promote answers a duplicate inbound msg1; the
                    // outbound side has no stored msg2 to resend.
                    let wire_msg2 = if ambient.is_outbound {
                        None
                    } else {
                        self.peer_machines
                            .get(&promote_link)
                            .and_then(|m| m.conn_handshake_msg2().map(|b| b.to_vec()))
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
                    let promote_result = self.promote_connection(
                        promote_link,
                        ambient.verified_identity,
                        ambient.now_ms,
                    );
                    match &promote_result {
                        Ok(PromotionResult::Promoted(node_addr)) => {
                            let node_addr = *node_addr;
                            // Two nodes that dialled each other may share two
                            // transport connections at this address. Now that
                            // the handshake has named the peer, tell the
                            // transport which to keep: the one the smaller
                            // node dialled, the same rule that settles
                            // crossed handshakes, so both ends keep the same
                            // one. First, so the tree announce below goes on
                            // the connection that stays.
                            let keep_outbound =
                                cross_connection_winner(self.node_addr(), &node_addr, true);
                            if let Some(transport) = self.transports.get(&ambient.transport_id) {
                                transport
                                    .settle_link(&ambient.remote_addr, keep_outbound)
                                    .await;
                            }
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
                            // Schedule filter announce (sent on a tick once the peer has sent a frame)
                            self.bloom_state.mark_update_needed(node_addr);
                            self.reset_lookup_backoff();
                            // Clear the pending outbound entry on promote success
                            // only; a failed promote leaves it for the stale-
                            // connection reaper.
                            if let Some(k) = ambient.pending_outbound_key {
                                self.pending_outbound.remove(&k);
                            }

                            // Tell the transport which link the new peer uses.
                            // Only the initiator's promotion does; the
                            // responder's link is marked by the initiator's
                            // first authenticated frame, which follows its
                            // promotion at once.
                            if ambient.is_outbound {
                                let link = (ambient.transport_id, ambient.remote_addr.clone());
                                self.relink(&node_addr, None, Some(link)).await;
                            }
                        }
                        Ok(PromotionResult::CrossConnectionWon {
                            loser_link_id,
                            node_addr,
                        }) => {
                            let (loser_link_id, node_addr) = (*loser_link_id, *node_addr);
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
                            let winner_link_id = *winner_link_id;
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
                            // connection reaper. The leg's machine must go with the
                            // leg, though: `promote_connection` took the pending
                            // connection off the machine before erring, so the reaper
                            // (which sweeps the machines' embedded legs) can never
                            // reach this link's machine — dropping it here is the
                            // only disposal point.
                            warn!(
                                target: "fips::node::handlers::handshake",
                                link_id = %promote_link,
                                error = %e,
                                "Failed to promote connection"
                            );
                            self.remove_peer_machine(promote_link);
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
                            // Clean up on promotion failure. The leg's lease was
                            // released by `promote_connection` once it took it, or
                            // is still on the machine and goes with it; the index
                            // the msg3 named is never freed by value.
                            self.remove_link(&promote_link);
                            self.remove_peer_machine(promote_link);
                            let reason = if matches!(e, NodeError::MaxPeersExceeded { .. }) {
                                HandshakeReject::AtMaxPeers
                            } else {
                                HandshakeReject::BadState
                            };
                            self.stats_mut()
                                .record_reject(RejectReason::Handshake(reason));
                        }
                    }

                    // Feed the promotion outcome back into the surviving machine
                    // and fold the follow-up actions onto the worklist (the
                    // `Promoted` arm crystallizes the machine in place and emits
                    // `RegisterDecryptSession`, a redundant no-op here — see its
                    // arm). Unconditional across Ok variants; on
                    // `CrossConnectionLost` the losing leg's machine was disposed
                    // inside `promote_connection`, so the lookup misses and no
                    // machine-side index free can double the inline one. Disjoint
                    // field borrow again.
                    if let Ok(result) = promote_result {
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
                }
                PeerAction::ResolveCrossConnection { .. } => {
                    // A decision token, not an effect: the outbound msg2
                    // handler intercepts it and runs the inline swap/keep
                    // resolution itself, so it must never reach the executor.
                    debug_assert!(
                        false,
                        "ResolveCrossConnection is intercepted by the msg2 \
                         handler and must never reach the executor"
                    );
                }
                PeerAction::InvalidateSendState => {
                    // The FULL teardown. `remove_active_peer`
                    // (`dispatch.rs:107`) closes the peer's link rekey machine,
                    // whose outputs free every index its sessions hold (current,
                    // pending, previous), drop their `peers_by_index` entries
                    // and unregister their decrypt workers, frees the rekey
                    // handshake's index, and removes the FSP `sessions` entry
                    // and `pending_tun_packets`. The machine emits NO
                    // `FreeIndex` for those slots, so there is no double-free.
                    let gone = *ambient.verified_identity.node_addr();
                    let held = self.peer_link(&gone);
                    self.remove_active_peer(&gone);
                    self.relink(&gone, held, None).await;
                }
                PeerAction::ResolveInboundCrossConnection {
                    peer,
                    our_index,
                    our_inbound_wins,
                } => {
                    // Simultaneous-init cross-connection resolved at msg3 (msg2-then-
                    // msg3 ordering): apply the same tie-breaker the inverse ordering
                    // uses so both sides converge on a single Noise session pair.
                    let their_index = ambient
                        .their_index
                        .expect("cross-connection swap carries the peer session index");
                    let (session, lease) = match self.peer_machines.get_mut(&link) {
                        Some(m) => (m.take_session(), m.take_our_index()),
                        None => (None, None),
                    };
                    match (our_inbound_wins, session, lease) {
                        (true, Some(session), Some(lease)) => {
                            // Larger node side: move to the inbound session so it
                            // pairs with the peer's kept outbound session. The
                            // peer's link machine is closed and rebuilt on it,
                            // which abandons any rekey of ours in flight and
                            // releases every index the old machine held; the
                            // leg's lease is bound on the peer's transport.
                            let local = self.session_node_keys();
                            let me = *self.identity().node_addr();
                            let params =
                                crate::node::handlers::rekey::link_params(&self.config().node);
                            let workers = self.link_workers();
                            let profile = self.node_profile();
                            let out = match self.peers.get_mut(&peer) {
                                Some(peer_ref) => {
                                    let mut caps = crate::peer::LinkCaps {
                                        indices: &mut self.index_allocator,
                                        local: &local,
                                        me,
                                        params,
                                        record: fips_core::proto::rekey::Record::new(),
                                        workers,
                                        profile,
                                    };
                                    peer_ref.move_session(session, lease, their_index, &mut caps)
                                }
                                None => vec![crate::peer::LinkOutput::Release(lease)],
                            };
                            self.run_link_outputs(&peer, out);
                            debug!(
                                peer = %self.peer_display_name(&peer),
                                new_our_index = %our_index,
                                new_their_index = %their_index,
                                "Simultaneous-init (msg3): swapped to inbound session (our inbound wins)"
                            );
                        }
                        (true, _, lease) => {
                            if let Some(lease) = lease {
                                let _ = self
                                    .index_allocator
                                    .free(SessionIndex::new(lease.release()));
                            }
                            self.remove_link(&link);
                            self.remove_peer_machine(link);
                            self.stats_mut()
                                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                            return;
                        }
                        (false, _, lease) => {
                            // Smaller node side: keep the existing outbound
                            // session, release the inbound leg's index.
                            if let Some(lease) = lease {
                                let _ = self
                                    .index_allocator
                                    .free(SessionIndex::new(lease.release()));
                            }
                            debug!(
                                peer = %self.peer_display_name(&peer),
                                "Simultaneous-init (msg3): keeping outbound session (our outbound wins)"
                            );
                        }
                    }

                    // Both branches tear down the temporary inbound link via
                    // `remove_link`, which hands its `addr_to_link` key back to
                    // the link the leg displaced at msg1 if that link is still
                    // live, disposing the leg's machine (and its embedded
                    // connection) with it.
                    self.remove_link(&link);
                    self.remove_peer_machine(link);
                    return;
                }
                PeerAction::RegisterDecryptSession { index } => {
                    let _ = index;
                    // No-op by design. The decrypt-worker
                    // registration is the link rekey machine's offer, made when
                    // the promotion builds it and carried out with its index
                    // binding, so it runs once per live promote (Promoted/Won).
                    // This machine-emitted action is redundant with that offer;
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
                PeerAction::SetTimer { kind, at_ms } => {
                    // Populate the per-peer timer store (overwrite = reschedule).
                    // The `HandshakeRetransmit` and `HandshakeTimeout` deadlines
                    // are read + fired by `drive_peer_timers`. The liveness kind
                    // is still SHADOW here — it keeps its own shell driver — so
                    // populating it stays behavior-neutral.
                    self.peer_timers
                        .entry(link)
                        .or_default()
                        .insert(kind, at_ms);
                }
                PeerAction::CancelTimer { kind } => {
                    if let Some(timers) = self.peer_timers.get_mut(&link) {
                        timers.remove(&kind);
                    }
                }
                PeerAction::ReportLost { peer, kind } => {
                    // The single loss token, routed to the reconciler reflex the
                    // `kind` names: an un-promoted handshake attempt takes the
                    // connected-guarded `note_handshake_timeout` (`driver.rs:28`),
                    // an established peer's link-death takes the unconditional
                    // `note_link_dead` (`driver.rs:48`). Both schedule on the
                    // peering clock, read here; `ambient.now_ms` is wall time.
                    match kind {
                        LostKind::HandshakeTimeout => {
                            self.note_handshake_timeout(peer, Self::peering_now());
                        }
                        LostKind::LinkDead => {
                            self.note_link_dead(peer, Self::peering_now());
                        }
                    }
                }
            }
        }
    }
}

impl Node {
    /// The transport and address the active peer `node` sends over.
    pub(in crate::node) fn peer_link(
        &self,
        node: &NodeAddr,
    ) -> Option<(TransportId, TransportAddr)> {
        let peer = self.peers.get(node)?;
        Some((peer.transport_id()?, peer.current_addr()?.clone()))
    }

    /// Tell the transports that the active peer `node` moved from `old` to
    /// `new`: the old connection no longer carries it, the new one does. With
    /// no `new`, the peer was removed.
    ///
    /// BLE uses this to decide which of its connections carry an active
    /// peer's session, which it protects from eviction; every other
    /// transport ignores it.
    ///
    /// The new link is marked before the old one is cleared. Each is a
    /// separate turn of the transport's lock, and a newcomer waiting on that
    /// lock in between must not find the peer with no verified link: it
    /// could evict the link the peer is moving onto. Within one transport the
    /// mark already demotes the old link; across transports the two links
    /// are in different pools.
    pub(in crate::node) async fn relink(
        &self,
        node: &NodeAddr,
        old: Option<(TransportId, TransportAddr)>,
        new: Option<(TransportId, TransportAddr)>,
    ) {
        if let Some((tid, addr)) = &new
            && let Some(transport) = self.transports.get(tid)
        {
            transport.mark_verified(addr, node).await;
        }
        if let Some((tid, addr)) = &old
            && old != new
            && let Some(transport) = self.transports.get(tid)
        {
            transport.clear_verified(addr, node, new.is_none()).await;
        }
    }

    /// Whether `transport` needs to hear of every authenticated frame's link.
    pub(in crate::node) fn tracks_peers(&self, transport: TransportId) -> bool {
        self.transports
            .get(&transport)
            .is_some_and(|t| t.tracks_peers())
    }
}
