//! What a handshake's establish decision does in the node.
//!
//! The settlement core decides each handshake (`src/node/settle/decide.rs`);
//! the handshake handlers carry its decision out through the functions here:
//! a dial's connect ([`Node::open_dial`]) and its msg1 ([`Node::send_dial`]),
//! the promotion of a completed handshake ([`Node::promote`]), the removal
//! of a held peer a restart replaces before that promotion
//! ([`Node::replace_held`]), and a crossing settled at an answer's msg3
//! ([`Node::cross_inbound`]). The last three take the [`Ambient`] facts of
//! the handshake they carry out.

use crate::PeerIdentity;
use crate::identity::NodeAddr;
use crate::node::reject::{HandshakeReject, RejectReason};
use crate::node::settle::exec::{Removed, Run};
use crate::node::settle::table::Transition;
use crate::node::{Node, NodeError};
use crate::peer::handshake::{RETRANSMIT_MS, TIMEOUT_MS, TimerKind};
use crate::proto::settle::output::Why;
use crate::transport::{LinkId, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use tracing::{debug, warn};

/// The facts of the handshake a promotion, a replacement or a crossing
/// carries out: the verified identity, the transport and address it ran
/// on, its indices, its stamps, its direction, its dial's dispatch key, and
/// why a peer it removes is removed.
pub(in crate::node) struct Ambient {
    /// The authenticated peer identity. The promotion installs it, and the
    /// replacement removes the held peer of its address.
    pub(in crate::node) verified_identity: PeerIdentity,
    /// The transport the handshake ran over.
    pub(in crate::node) transport_id: TransportId,
    /// The peer's wire address.
    pub(in crate::node) remote_addr: TransportAddr,
    /// Our session index for this handshake.
    pub(in crate::node) our_index: Option<SessionIndex>,
    /// The peer's session index for this handshake.
    pub(in crate::node) their_index: Option<SessionIndex>,
    /// The wire timestamp of the message that completed the handshake, Unix
    /// milliseconds, which the promotion stamps the peer with.
    pub(in crate::node) now_ms: u64,
    /// Whether this node dialed the handshake. The promotion of a dial logs
    /// a `Peer promoted to active` line and clears `pending_outbound`, and
    /// its promote-Err cleanup is warn-only (no link/index teardown), unlike
    /// an answer's.
    pub(in crate::node) is_outbound: bool,
    /// The `pending_outbound` key for a dial's promotion, cleared on success.
    /// `None` for an answer, which has no `pending_outbound` entry.
    pub(in crate::node) pending_outbound_key: Option<(TransportId, u32)>,
    /// Why a peer the handshake removes is removed: a handshake that
    /// replaces the held peer says how, which the replacement's promotion
    /// reads too. `None` where no peer is removed.
    pub(in crate::node) why: Option<Why>,
}

impl Node {
    /// Start the connect of the identified, connection-oriented dial on
    /// `link` to `remote_addr` on `transport_id`, for `peer`. The dial's
    /// entry moves to connecting; on a connect started the pending connect
    /// is queued for `poll_pending_connects` to resolve, and on a connect
    /// error the dial's link and entry go.
    pub(in crate::node) async fn open_dial(
        &mut self,
        link: LinkId,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        peer: PeerIdentity,
    ) {
        match self.handshakes.get_mut(&link) {
            Some(entry) => {
                entry.set_conn_transport_id(transport_id);
                if !entry.connecting() {
                    return;
                }
            }
            None => return,
        }
        let Some(transport) = self.transports.get(&transport_id) else {
            return;
        };
        match transport.connect(&remote_addr).await {
            Ok(()) => {
                debug!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    link_id = %link,
                    "Transport connect initiated (non-blocking)"
                );
                let origin = self
                    .handshakes
                    .get(&link)
                    .map(|entry| entry.dial_origin())
                    .unwrap_or_default();
                self.peering
                    .pending_connects
                    .push(crate::node::PendingConnect {
                        link_id: link,
                        transport_id,
                        remote_addr,
                        peer_identity: Some(peer),
                        origin,
                    });
            }
            Err(_e) => {
                self.core_connect_failed(link);
                self.links
                    .forget(self.core.parts_mut().0, &link, &(transport_id, remote_addr));
                self.remove_handshake(link);
            }
        }
    }

    /// Send the identified dial's msg1 on `link`, the wire
    /// `prepare_outbound_msg1` stored, to `remote_addr` on `transport_id`,
    /// and arm the dial's timers: for a connectionless dial at once
    /// (`connected` false), and for a connection-oriented one once its
    /// connect resolves (`connected` true). The msg1 resend timer is armed
    /// only for a dial whose leg the settlement core does not hold, since
    /// the core's leg times its resends. Nothing is done for an entry not
    /// at that point of its dial.
    pub(in crate::node) async fn send_dial(
        &mut self,
        link: LinkId,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
        connected: bool,
    ) {
        let now = Self::interval_ms();
        match self.handshakes.get_mut(&link) {
            Some(entry) => {
                if !connected {
                    entry.set_conn_transport_id(transport_id);
                }
                if !entry.sending_msg1(connected) {
                    return;
                }
            }
            None => return,
        }
        self.send_stored_msg1(link, transport_id, remote_addr).await;
        if self.leg_on(link).is_none() {
            self.handshakes
                .arm(link, TimerKind::HandshakeRetransmit, now + RETRANSMIT_MS);
        }
        self.handshakes
            .arm(link, TimerKind::HandshakeTimeout, now + TIMEOUT_MS);
    }

    /// Promote the completed handshake on `link`: install its peer, then
    /// run the table's plan for the promotion. `carried_announce` is the
    /// replaced peer's tree announce stamp, which the mutation lane's
    /// `TreeCarryAcrossRestart` break carries to the new peer.
    pub(in crate::node) async fn promote(
        &mut self,
        promote_link: LinkId,
        ambient: &Ambient,
        carried_announce: Option<Option<u64>>,
    ) {
        // Capture msg2 BEFORE `install_handshake` removes the pending
        // connection, so a duplicate msg1 can be answered with it. Only
        // the inbound promote answers a duplicate inbound msg1; the
        // outbound side has no stored msg2 to resend.
        let wire_msg2 = if ambient.is_outbound {
            None
        } else {
            self.handshakes
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
        let promote_result =
            self.install_handshake(promote_link, ambient.verified_identity, ambient.now_ms);
        match promote_result {
            Ok(result) => {
                // A promotion installs a new peer only, under the verified
                // identity's address.
                let node_addr = *ambient.verified_identity.node_addr();
                // The mutation lane's break: the new peer takes
                // the replaced peer's announce stamp. Before the
                // plan, whose steps before its tree announce read
                // no stamp.
                if let Some(sent) = carried_announce
                    && let Some(p) = self.peers.get_mut(&node_addr)
                {
                    p.set_last_tree_announce_sent_ms(sent);
                }
                // The table's plan for the promotion runs here:
                // the transport told which connection to keep,
                // what the promotion of a dial or of an inbound
                // leg does, the entry marked as the peer's, and the
                // path feeds told the path machine is new. For a
                // replacement this is the part of its plan after
                // the removal, which `replace_held` ran.
                let mut run = Run::promotion(promote_link, result, ambient, wire_msg2);
                self.run_promotion(&mut run).await;
            }
            Err(e) if ambient.is_outbound => {
                // Every promotion runs with no peer held for the identity,
                // so a refusal for a held one means a new path reached here
                // without resolving its crossing first.
                debug_assert!(
                    !matches!(e, NodeError::IdentityHeld(_)),
                    "a promotion reached the executor for an identity already held"
                );
                // The outbound promote-failure path is warn-only: it
                // records the reject but performs no link/index teardown
                // and leaves the `pending_outbound` entry for the stale-
                // connection reaper. The handshake entry must go with the
                // leg, though: `install_handshake` took the crypto off the
                // entry before erring, so the reaper (which sweeps the
                // entries carrying crypto) can never reach it; dropping it
                // here is the only disposal point.
                warn!(
                    target: "fips::node::handlers::handshake",
                    link_id = %promote_link,
                    error = %e,
                    "Failed to promote connection"
                );
                self.remove_handshake(promote_link);
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            }
            Err(e) => {
                debug_assert!(
                    !matches!(e, NodeError::IdentityHeld(_)),
                    "a promotion reached the executor for an identity already held"
                );
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
                // released by `install_handshake` once it took it, or
                // is still on the entry and goes with it; the index
                // the msg3 named is never freed by value.
                self.remove_link(&promote_link);
                self.remove_handshake(promote_link);
                let reason = if matches!(e, NodeError::MaxPeersExceeded { .. }) {
                    HandshakeReject::AtMaxPeers
                } else {
                    HandshakeReject::BadState
                };
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(reason));
            }
        }
    }

    /// Remove the held peer of `ambient.verified_identity` that a restart
    /// found at `link`'s handshake replaces, before that handshake's
    /// promotion, and note the loss for a reconnect. Returns the tree
    /// announce stamp the mutation lane's `TreeCarryAcrossRestart` break
    /// carries to the new peer.
    pub(in crate::node) async fn replace_held(
        &mut self,
        link: LinkId,
        ambient: &Ambient,
    ) -> Option<Option<u64>> {
        let mut carried_announce = None;
        // The FULL teardown. The removal closes the peer's link
        // rekey machine, whose outputs free every index its
        // sessions hold (current, pending, previous), drop their
        // `peers_by_index` entries and unregister their decrypt
        // workers, frees the rekey handshake's index, and removes
        // the FSP `sessions` entry; the packets held for the peer
        // stay for its next session. Nothing else frees those
        // slots, so there is no double-free.
        //
        // Every caller says why: a context that does not is one
        // the table does not know.
        debug_assert!(
            ambient.why.is_some(),
            "a held peer was replaced with no cause"
        );
        let gone = *ambient.verified_identity.node_addr();
        if node_fault!(TreeCarryAcrossRestart) {
            carried_announce = self
                .peers
                .get(&gone)
                .map(|p| p.last_tree_announce_sent_ms());
        }
        let why = ambient.why.unwrap_or(Why::Restart);
        // The loss is noted for a reconnect below, once the removal
        // has run.
        let removed = self.remove(&gone, why).map(|removed| Removed {
            noted: true,
            ..removed
        });
        if let Some(removed) = removed {
            if matches!(why, Why::Dead | Why::Orphaned) {
                self.removed(&gone, removed).await;
            } else {
                // A replacement's first part. Its promotion runs
                // the rest once it succeeds; a refusal stops it
                // here with the old peer gone.
                let mut run = Run::replacement(link, removed, ambient);
                self.run_removal(&mut run).await;
            }
        }
        self.note_link_dead(gone, Self::peering_now());
        carried_announce
    }

    /// Carry out the crossing the settlement core settled at the answer on
    /// `link`'s msg3, from `peer`: `our_inbound_wins` moves the held peer
    /// onto the answer's session and its lease on `our_index`, and otherwise
    /// the held peer is kept and the answer ends.
    pub(in crate::node) async fn cross_inbound(
        &mut self,
        link: LinkId,
        peer: NodeAddr,
        our_index: SessionIndex,
        our_inbound_wins: bool,
        ambient: &Ambient,
    ) {
        // Simultaneous-init cross-connection resolved at msg3 (msg2-then-
        // msg3 ordering): apply the same tie-breaker the inverse ordering
        // uses so both sides converge on a single Noise session pair.
        let their_index = ambient
            .their_index
            .expect("cross-connection swap carries the peer session index");
        let (session, lease) = match self.handshakes.get_mut(&link) {
            Some(entry) => (entry.take_session(), entry.take_our_index()),
            None => (None, None),
        };
        match (our_inbound_wins, session, lease) {
            (true, Some(session), Some(lease)) => {
                // Larger node side, or either node where the peer
                // dialed the link held as well as this leg (the
                // same-side rule): move to the inbound session so it
                // pairs with the peer's outbound session. The
                // peer's link machine is closed and rebuilt on it,
                // which abandons any rekey of ours in flight and
                // releases every index the old machine held. Both
                // ends converge on the link the peer dialed (FRC-2201,
                // Section 5.7), which this msg3 came over, so the peer
                // is held on the leg's link, taken at the msg3's
                // transport and source address, and the rebuilt machine
                // records the leg's binding on that transport. The link
                // it held, its own dial's at a crossing, is torn down
                // and its connection closed unless a live link uses it.
                // The path
                // machine starts again with that pair as the new link's
                // original path (multipath v1 draft, Section 5.4).
                let prior = self.peer_link(&peer);
                let held = self.peers.get(&peer).map(|p| p.link_id());
                let local = self.session_node_keys();
                let me = *self.identity().node_addr();
                let params = crate::node::handlers::rekey::link_params(&self.config().node);
                let path_params = crate::node::handlers::path::path_params(&self.config().node);
                let workers = self.link_workers();
                let profile = self.node_profile();
                let facts = crate::node::handlers::path::NodeFacts {
                    transports: &self.transports,
                    denied: false,
                };
                let ours = SessionIndex::new(lease.index());
                let Some(peer_ref) = self.peers.get_mut(&peer) else {
                    // The decision was made on a snapshot that
                    // held the peer, with nothing awaited since,
                    // so this is not reached: the leg's index
                    // goes back and the leg ends.
                    self.run_link_outputs(&peer, vec![crate::peer::LinkOutput::Release(lease)]);
                    debug!(
                        peer = %self.peer_display_name(&peer),
                        new_our_index = %our_index,
                        new_their_index = %their_index,
                        "Simultaneous-init (msg3): swapped to inbound session (our inbound wins)"
                    );
                    self.remove_link(&link);
                    self.remove_handshake(link);
                    return;
                };
                let mut caps = crate::peer::LinkCaps {
                    indices: &mut self.index_allocator,
                    local: &local,
                    me,
                    params,
                    record: fips_core::proto::rekey::Record::new(),
                    workers,
                    profile,
                    path: crate::peer::PathCaps {
                        params: path_params,
                        facts: &facts,
                    },
                    // Not needed for safety: the peer is held
                    // here on the leg's link, which the peer
                    // dialed, so no own-dial keep reads this
                    // mark until a later dial of ours holds it.
                    mark: self.next_link_id,
                };
                let (out, paths) = peer_ref.adopt_dial(
                    session,
                    lease,
                    their_index,
                    (ambient.transport_id, ambient.remote_addr.clone()),
                    link,
                    false,
                    true,
                    &mut caps,
                );
                // The machine was rebuilt exactly when the peer is
                // on the leg's index.
                let built = peer_ref.our_index() == Some(ours);
                // A rebuilt move holds the peer on the leg's link, and the
                // link it held, its own dial's, is the one torn down.
                let left = held.filter(|held| built && peer_ref.link_id() != *held);
                // The rest of the move, in its order: the machine's
                // outputs, the waiver, the path feeds, what follows
                // a move to another pair, the note, and the leg.
                let mut run = Run::new(
                    peer,
                    Transition::Move {
                        dial: link,
                        own: false,
                        built,
                        inbound: true,
                    },
                );
                run.prior = prior;
                let facts = run.crossing();
                facts.out = out;
                facts.paths = paths;
                facts.ours = Some(our_index);
                facts.theirs = Some(their_index);
                facts.loser = left;
                facts.to = Some((ambient.transport_id, ambient.remote_addr.clone()));
                facts.key = Some(crate::ipv6tun::link::PeerKey::from_xonly(
                    &ambient.verified_identity.pubkey(),
                ));
                self.run(&mut run).await;
            }
            (true, _, lease) => {
                if let Some(lease) = lease {
                    let _ = self
                        .index_allocator
                        .free(SessionIndex::new(lease.release()));
                }
                self.remove_link(&link);
                self.remove_handshake(link);
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            }
            (false, _, lease) => {
                // Smaller node side: keep the existing outbound
                // session, release the inbound leg's index, and
                // tear down the temporary inbound link via
                // `remove_link`, which hands its link index key
                // back to the link the leg displaced at msg1 if
                // that link is still live, disposing the leg's
                // entry (and the crypto it carries) with it.
                let mut run = Run::new(
                    peer,
                    Transition::Keep {
                        dial: link,
                        inbound: true,
                    },
                );
                run.crossing().lease = lease;
                self.run(&mut run).await;
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
