//! A held peer's redial from another address: a fresh same-epoch msg1 that
//! arrived off the peer's established link.
//!
//! Such a msg1 comes from a peer that changed address while its node kept
//! running and dialed again, from a peer whose first packet from a new
//! address is its timed rekey msg1, from a dial to another address of the
//! peer, or from a replayer holding a capture. The wire tells these apart
//! only by what follows: the peer holds the keys of the handshake its msg1
//! opened and sends frames under them, and a replayer does not.
//!
//! So the msg1 is answered by a leg on its own inbound link beside the held
//! peering, which nothing touches: [`Node::arm_redial`]. The leg's msg2 goes
//! to the address the msg1 came from. When the first frame naming the leg's
//! index authenticates under the leg's session, the peering is replaced by
//! the leg: [`Node::redial_frame`], then [`Node::settle_redial`]. The swap
//! replaces the link-level state (link, paths, indices, link session) and
//! keeps the identity's tree declaration and filter, which the same process
//! at the same epoch still holds, and opens the end-to-end session again
//! when it closed a heard one. A leg no frame proves is reaped at the
//! handshake timeout like any inbound leg, changing nothing.
//!
//! A proving frame that arrived on another transport than the leg's, at a
//! pair of the held link, comes from a peer that moved onto the leg's
//! session without moving address, as a deployed release that wins the
//! tie-break between its two dials does: it frees the old session's index
//! with no drain, sends under the new session on the held link's transport
//! and closes the connection the leg runs on. The core then keeps the peer
//! on the held link and pair, and [`Node::adopt_redial`] moves that link
//! onto the leg's session and retires the leg's link. No peer is removed,
//! so the end-to-end session stays; the peer is sent a tree announce and
//! its filter again, since what was sent under the session it discarded is
//! lost.
//!
//! Only a heard peering is redialed (operator decision, 2026-11-17): the
//! link machine asks for a redial only when the held peering has been heard
//! from. A fresh msg1 off the link of an unheard peering, such as one a
//! replayed msg1 promoted or the first of a dial over two paths, keeps the
//! replacement at the msg1 and its floors (`handlers::handshake`).
//!
//! The settlement core (`Node.core`) decides the redial: it refuses one
//! under the identity's silent-session back-off, holds one back while
//! another redial of the peer is pending and under 1 s old (an older one
//! gives way), refuses one whose ephemeral armed a redial of the peer in the
//! last 15 s or when the memory of them is full, and one the dampener
//! holds; it asks for the answer of the rest, beside the held peering. The
//! node runs the ACL and draws the leg's session index; only once the ACL
//! has passed it is the msg1's ephemeral noted, by the node in the held
//! link's replay record and by the core in the redial memory, so a genuine
//! dial refused by a gate is judged again at its next resend. A redial the ACL
//! refuses, or one no session index is left for, has its connection closed
//! at once unless a live link uses it, as any msg1 refused after its answer
//! is asked for does. The core keeps the pending redials; the node's
//! [`RedialMap`](crate::node::settle::RedialMap) is a cache of them, by
//! the index each leg's msg2 named, rebuilt after every step.

use crate::NodeAddr;
use crate::node::Node;
use crate::node::acl::PeerAclContext;
use crate::node::diag::{self, HsLine};
use crate::node::handlers::handshake::Armed;
use crate::node::handlers::path::NodeFacts;
use crate::node::reject::{DataplaneReject, HandshakeReject, RejectReason};
use crate::node::settle::Redial;
use crate::node::settle::exec::plan::adopt;
use crate::node::settle::exec::{Ambient, By, Removed, Run};
use crate::peer::{LinkCaps, PathCaps};
use crate::proto::bloom::BloomFilter;
use crate::proto::fmp::wire::{EncryptedHeader, build_msg2};
use crate::proto::fmp::{ActiveBackoff, WireOutcome};
use crate::proto::settle::gates::Refusal;
use crate::proto::settle::input::{Hello, Input as SettleInput};
use crate::proto::settle::links::Pair;
use crate::proto::settle::output::{Denial, Output, Why};
use crate::proto::stp::{ParentDeclaration, TreeCoordinate};
use crate::transport::{Link, LinkDirection, LinkId, ReceivedPacket};
use crate::utils::index::SessionIndex;
use fips_core::proto::path::{PathRef, PathState};
use fips_core::proto::rekey::allocate;
use std::time::Duration;
use tracing::{debug, warn};

/// Why a redial was refused before it was armed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Held {
    /// Another redial of the peer is pending and under 1 s old.
    Slot,
    /// Its ephemeral armed a redial of the peer in the last 15 s, or the
    /// memory of them is full.
    Seen,
    /// The restart dampener holds the peer.
    Dampened,
}

impl Node {
    /// Answer the redial `armed`, the msg1 in `packet` read as `wire`, into
    /// a pending redial beside the held peering, as the core decided it,
    /// `decided`: a refusal is logged and counted, and an ask is authorized,
    /// drawn an index and answered. `silent` is the identity's
    /// silent-session refusal in force before the core stepped, for its log.
    pub(in crate::node) async fn arm_redial(
        &mut self,
        armed: Armed,
        decided: Vec<Output>,
        packet: &ReceivedPacket,
        wire: &WireOutcome,
        silent: Option<ActiveBackoff>,
    ) {
        let Armed {
            mut entry,
            link,
            peer,
            identity,
            digest,
            leg_at,
        } = armed;
        let interval_ms = leg_at.interval_ms;
        let mut asked = None;
        for o in decided {
            match o {
                Output::Ask { link: no, .. } => asked = Some(no),
                Output::Reject {
                    why: Denial::Gate(Refusal::Silent),
                    ..
                } => {
                    let dg = diag::msg1_tag(&wire.msg1_digest);
                    self.refuse_silent(&peer, packet, &dg, silent);
                    return;
                }
                Output::Reject { why, .. } => {
                    self.refuse_redial(&peer, packet, why);
                    return;
                }
                other => debug_assert!(false, "a redial gave {other:?}"),
            }
        }
        let Some(no) = asked else {
            return;
        };
        // Admitted: the answer is asked for, and authorized next.
        if !node_fault!(RedialSkipsAcl)
            && self
                .authorize_peer(
                    &identity,
                    PeerAclContext::InboundHandshake,
                    packet.transport_id,
                    &packet.remote_addr,
                )
                .is_err()
        {
            // The refused redial's connection closes now, unless a live link
            // uses it, rather than at the transport's idle deadline.
            self.unasked(no, false).await;
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }
        // Every gate passed: the msg1's ephemeral goes into the held link's
        // replay record, so its copies are copies from here on, and the core
        // notes it in the redial memory at its answer, or at its abandon if
        // no index can be drawn for it.
        if let Some(digest) = digest
            && let Some(held) = self.peers.get_mut(&peer)
        {
            held.note_redial(digest);
        }
        // Draw the leg's index, which the answer's leg holds until a
        // promotion takes it, and send its msg2; nothing is promoted.
        let Some(our_lease) = allocate(&mut self.index_allocator) else {
            warn!("Failed to allocate session index for a redial");
            self.unasked(no, true).await;
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        };
        let our_index = SessionIndex::new(our_lease.index());
        let their_index = wire.their_index;
        let opened = Link::connectionless(
            link,
            packet.transport_id,
            packet.remote_addr.clone(),
            LinkDirection::Inbound,
            Duration::from_millis(self.config().node.base_rtt_ms),
        );
        self.links.bind(&mut self.core, opened, no);
        // A pending redial older than the slot's floor gives way to this
        // one: the core abandons its leg at this answer. Its link is read
        // first, while the cache still names it.
        let older = self.redials.of(&peer).map(|r| r.link);
        let wire_msg2 = build_msg2(our_index, their_index, &wire.msg2_payload);
        // The answer's leg, the settlement core's, reaped at the handshake
        // deadline counted from the msg1's arrival.
        let hello = Hello {
            link: no,
            msg2: wire_msg2.clone(),
            lease: our_lease,
        };
        let mut answered = false;
        let mut retired = Vec::new();
        let mut swap = Vec::new();
        for o in self.decide_at(SettleInput::Hello(hello), crate::time::mono_at(interval_ms)) {
            match o {
                Output::Answer { .. } if !answered => answered = true,
                Output::Free { lease } => self.free_lease(lease),
                Output::Retire { link: l, closes } if Some(l) != self.links.no(&link) => {
                    retired.push((l, closes));
                }
                other => swap.push(other),
            }
        }
        for (l, closes) in retired {
            if let Some(old) = self.links.id(l).filter(|id| Some(*id) == older) {
                debug!(
                    peer = %self.peer_display_name(&peer),
                    link_id = %old,
                    "A later redial replaces a pending redial its frame never proved"
                );
                self.retired_leg(old, closes).await;
            }
        }
        if !answered {
            return;
        }
        entry.set_conn_handshake_msg2(wire_msg2.clone());
        self.handshakes.add(link, entry);
        self.stats_mut().handshake.redials += 1;
        debug!(
            peer = %self.peer_display_name(&peer),
            link_id = %link,
            our_index = %our_index,
            transport_id = %packet.transport_id,
            remote_addr = %packet.remote_addr,
            "Same-epoch msg1 off the established link, answered into a pending redial"
        );
        let ambient = Ambient {
            verified_identity: identity,
            transport_id: packet.transport_id,
            remote_addr: packet.remote_addr.clone(),
            our_index: Some(our_index),
            now_ms: packet.timestamp_ms,
            is_outbound: false,
            why: None,
        };
        let swapping = Swapping::of(self, &peer);
        // The msg2 goes out and the core is told; nothing is promoted here,
        // whatever it decided at the send.
        let _ = self.send_answer(link, &ambient, &wire_msg2).await;
        let from = Pair {
            transport: packet.transport_id,
            addr: packet.remote_addr.clone(),
        };
        if !swap.is_empty() {
            // The core replaced the peering at the answer (the mutation
            // lane's break, `RedialTearsDownAtMsg1`): its swap runs once the
            // msg2 is out.
            self.swap_redial(peer, link, swap, swapping, packet.timestamp_ms)
                .await;
        } else if node_fault!(RedialSwapsUnproven)
            && self.redials.of(&peer).is_some_and(|r| r.link == link)
        {
            // The mutation lane's break: the peering replaced once the msg2
            // is sent, as if a frame from the msg1's address proved it.
            self.settle_redial(peer, link, from, packet.timestamp_ms)
                .await;
        }
    }

    /// Log and count a redial of `peer` in `packet` the core refused for
    /// `why`.
    fn refuse_redial(&mut self, peer: &NodeAddr, packet: &ReceivedPacket, why: Denial) {
        let held = match why {
            Denial::Held => Held::Slot,
            Denial::Gate(Refusal::Dampened) => Held::Dampened,
            Denial::Gate(_) => Held::Seen,
            Denial::Full | Denial::Cap => {
                debug!(
                    peer = %self.peer_display_name(peer),
                    transport_id = %packet.transport_id,
                    remote_addr = %packet.remote_addr,
                    reason = ?why,
                    "Redial refused by the settlement core"
                );
                self.stats_mut()
                    .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
                return;
            }
        };
        if self.shown(peer, HsLine::Redial) {
            debug!(
                peer = %self.peer_display_name(peer),
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                held = ?held,
                "Same-epoch msg1 off the established link held back as a redial, dropping"
            );
        }
        let reject = match held {
            Held::Slot => HandshakeReject::RedialHeld,
            Held::Seen => HandshakeReject::RedialSeen,
            Held::Dampened => HandshakeReject::RedialDampened,
        };
        self.stats_mut()
            .record_reject(RejectReason::Handshake(reject));
    }

    /// The handshake leg on `link`, which the core retired with the
    /// connections `closes` its retirement leaves unused, is gone: its
    /// handshake entry and link go, and those connections are closed.
    pub(in crate::node) async fn retired_leg(&mut self, link: LinkId, closes: Vec<Pair>) {
        let transport_id = self.handshakes.get_mut(&link).and_then(|entry| {
            let _detached = entry.take_leg();
            entry.conn_transport_id()
        });
        self.remove_handshake(link);
        self.close_each(closes).await;
        self.remove_link(&link);
        if let Some(transport_id) = transport_id {
            self.cleanup_bootstrap_transport_if_unused(transport_id);
        }
    }

    /// A frame in `packet`, with `header`, names the index of `peer`'s
    /// pending redial `redial`: open it under the leg's session, leaving
    /// its replay window as it is, and on success replace the peering by
    /// the leg. Returns whether the frame opened. A frame that does not open
    /// changes nothing and is charged to no peer.
    pub(in crate::node) async fn redial_frame(
        &mut self,
        peer: NodeAddr,
        redial: Redial,
        header: &EncryptedHeader,
        packet: &ReceivedPacket,
    ) -> bool {
        let opened = self
            .handshakes
            .get(&redial.link)
            .and_then(|e| e.leg())
            .and_then(|leg| leg.noise_session.as_ref())
            .is_some_and(|session| {
                session.check_replay(header.counter).is_ok()
                    && packet
                        .data
                        .get(header.ciphertext_offset()..)
                        .is_some_and(|body| {
                            session
                                .open_unmarked(body, header.counter, &header.header_bytes)
                                .is_ok()
                        })
            });
        if !opened {
            self.metrics()
                .dataplane
                .record_reject(DataplaneReject::RedialUnopened);
            if node_fault!(RedialChargesHeld) && self.peers.contains_key(&peer) {
                self.charge_failure(&peer, packet.transport_id, &packet.remote_addr);
            }
            return false;
        }
        let from = Pair {
            transport: packet.transport_id,
            addr: packet.remote_addr.clone(),
        };
        self.settle_redial(peer, redial.link, from, packet.timestamp_ms)
            .await;
        true
    }

    /// A frame from `from` proved the pending redial of `peer` on `link`:
    /// the ACL checked again, then the core told, which replaces the held
    /// peering by the leg ([`Node::swap_redial`]). `now_ms` is that packet's
    /// wall stamp.
    pub(in crate::node) async fn settle_redial(
        &mut self,
        peer: NodeAddr,
        link: LinkId,
        from: Pair,
        now_ms: u64,
    ) {
        let Some(no) = self.links.no(&link) else {
            return;
        };
        let Some((identity, transport_id, remote_addr)) =
            self.handshakes.get(&link).and_then(|e| {
                Some((
                    *e.conn_expected_identity()?,
                    e.conn_transport_id()?,
                    e.conn_source_addr()?.clone(),
                ))
            })
        else {
            return;
        };
        if self
            .authorize_peer(
                &identity,
                PeerAclContext::InboundHandshake,
                transport_id,
                &remote_addr,
            )
            .is_err()
        {
            debug!(
                peer = %self.peer_display_name(&peer),
                link_id = %link,
                "Redial's peer no longer authorized at its first frame, dropping the redial"
            );
            let closes = self.give_up(link);
            self.retired_leg(link, closes).await;
            return;
        }
        let swapping = Swapping::of(self, &peer);
        let out = self.decide(SettleInput::LegHeard { link: no, from });
        self.swap_redial(peer, link, out, swapping, now_ms).await;
    }

    /// Run the core's swap of `peer`'s held peering for the redial's leg on
    /// `link`, `out`: the held peering torn down for a redial, keeping the
    /// identity's tree declaration and filter, the leg promoted with the
    /// lease the core installs it with, and the end-to-end session opened
    /// again if the teardown closed a heard one. `swapping` is what the
    /// node read of the held peering before the core stepped, and `now_ms`
    /// the wall stamp of the packet that proved the redial. An install on
    /// the held link's own number is the core keeping the peer there
    /// ([`Node::adopt_redial`]).
    async fn swap_redial(
        &mut self,
        peer: NodeAddr,
        link: LinkId,
        out: Vec<Output>,
        swapping: Swapping,
        now_ms: u64,
    ) {
        let held = self
            .peers
            .get(&peer)
            .and_then(|p| self.links.no(&p.link_id()));
        if let Some(held) = held
            && out
                .iter()
                .any(|o| matches!(o, Output::Install(i) if i.link == held))
        {
            self.adopt_redial(peer, link, out).await;
            return;
        }
        let Some((identity, transport_id, remote_addr)) = self
            .handshakes
            .get(&link)
            .filter(|e| e.conn_their_index().is_some())
            .and_then(|e| {
                Some((
                    *e.conn_expected_identity()?,
                    e.conn_transport_id()?,
                    e.conn_source_addr()?.clone(),
                ))
            })
        else {
            return;
        };
        let Swapping {
            held,
            had_session,
            ended,
            silent,
        } = swapping;
        let ctx = |our_index, why| Ambient {
            verified_identity: identity,
            transport_id,
            remote_addr: remote_addr.clone(),
            our_index,
            now_ms,
            is_outbound: false,
            why,
        };
        let mut ours = None;
        let mut out = out;
        let mut retired = Self::retired(&mut out);
        for o in out {
            match o {
                Output::Remove { peer: gone, why } => {
                    debug!(
                        peer = %self.peer_display_name(&gone),
                        link_id = %link,
                        "Redial proven by the peer's frame, replacing the peering"
                    );
                    self.log_paths_ended(&gone, &ended);
                    // The removal runs the first part of the replacement's
                    // plan, and the promotion below, told the same cause,
                    // the rest. The core asks for the reconnect itself.
                    if let Some(removed) = self.remove(&gone, why, By::Core { silent }) {
                        let mut removed = Removed {
                            noted: true,
                            ..removed
                        };
                        let closes = Self::closes_of(&mut retired, &gone);
                        self.retire_closes(gone, &mut removed, closes);
                        let mut run = Run::replacement(link, removed, &ctx(None, Some(why)));
                        self.run_removal(&mut run).await;
                    }
                }
                Output::Retry { peer } => self.note_link_dead(peer, Self::peering_now()),
                Output::Install(i) => {
                    ours = Some(SessionIndex::new(i.lease.index()));
                    if let Some(old) = self
                        .handshakes
                        .get_mut(&link)
                        .and_then(|e| e.set_conn_our_index(i.lease))
                    {
                        let _ = self.index_allocator.free(SessionIndex::new(old.release()));
                    }
                }
                Output::Free { lease } => self.free_lease(lease),
                // The removal's connections are closed by its plan, from the
                // `Retire` taken above.
                Output::Retire { .. } | Output::Reset { .. } => {}
                other => debug_assert!(false, "a redial's swap gave {other:?}"),
            }
        }
        let Some(ours) = ours else {
            return;
        };
        let ambient = ctx(Some(ours), held.as_ref().map(|_| Why::Redial));
        if !self.promote(link, &ambient).await {
            return;
        }
        if !ended.is_empty() {
            self.log_paths_begun(&peer);
        }
        self.stats_mut().handshake.redials_proven += 1;
        let session_closed = had_session && !self.sessions.contains_key(&peer);
        // The peer's process and epoch are unchanged, so what it declared
        // and the filter it sent still hold for the peering that replaces
        // the one they came on.
        if let Some((tree, filter)) = held
            && !node_fault!(RedialDropsIdentity)
            && let Some(p) = self.peers.get_mut(&peer)
        {
            let now = Self::now_ms();
            if let Some((declaration, ancestry)) = tree {
                p.update_tree_position(declaration, ancestry, now);
            }
            if let Some((filter, sequence)) = filter {
                p.update_filter(filter, sequence, now);
            }
        }
        if session_closed && !node_fault!(RedialNoSessionReopen) {
            let pubkey = identity.pubkey_full();
            match self.initiate_session(peer, pubkey).await {
                Ok(()) => {
                    self.stats_mut().handshake.redial_session_reopens += 1;
                    debug!(
                        peer = %self.peer_display_name(&peer),
                        "Opened the end-to-end session again after a redial's swap"
                    );
                }
                Err(e) => debug!(
                    peer = %self.peer_display_name(&peer),
                    error = %e,
                    "Failed to open the end-to-end session again after a redial's swap"
                ),
            }
        }
    }
}

impl Node {
    /// Run the core's adoption of the redial's session on `link` by the
    /// held `peer`, `out`: the proof arrived on the held link, so the peer
    /// stays on that link and pair. The leg's session, lease and the peer's
    /// index leave the handshake entry; `adopt_dial` rebuilds the peer's
    /// link machine on them, keeping the link, and settles the peer's
    /// record as a move does; the move's effects that apply to a move that
    /// stays on its link run (`plan::ADOPT`); and the leg's link is retired. The
    /// paths the bundle's renewal released are queued to close by their
    /// release, in `RunRenewed`. A session that authenticated another key,
    /// which a leg of the same identity should never hold, hands its lease
    /// back and leaves the peer as it was.
    async fn adopt_redial(&mut self, peer: NodeAddr, link: LinkId, out: Vec<Output>) {
        let mut install = None;
        let mut closes = Vec::new();
        for o in out {
            match o {
                Output::Install(i) => install = Some(i),
                Output::Retire { closes: c, .. } => closes = c,
                Output::Free { lease } => self.free_lease(lease),
                Output::Reset { .. } => {}
                other => debug_assert!(false, "a redial's adoption gave {other:?}"),
            }
        }
        let Some(install) = install else {
            self.retired_leg(link, closes).await;
            return;
        };
        // The leg's session, its lease and the peer's index leave the
        // handshake entry, so retiring the entry frees none of them.
        let Some(entry) = self.handshakes.get_mut(&link) else {
            self.free_lease(install.lease);
            self.retired_leg(link, closes).await;
            return;
        };
        if let Some(old) = entry.set_conn_our_index(install.lease) {
            let _ = self.index_allocator.free(SessionIndex::new(old.release()));
        }
        let lease = entry.take_our_index();
        let theirs = entry.conn_their_index();
        let identity = entry.conn_expected_identity().copied();
        let session = entry.take_leg().and_then(|mut c| c.noise_session.take());
        let to = self.peer_link(&peer);
        let (Some(lease), Some(theirs), Some(identity), Some(session), Some(to)) =
            (lease, theirs, identity, session, to)
        else {
            debug!(
                peer = %self.peer_display_name(&peer),
                link_id = %link,
                "Redial proven on the held link, but its leg is incomplete; dropping it"
            );
            self.retired_leg(link, closes).await;
            return;
        };
        let ours = SessionIndex::new(lease.index());
        let local = self.session_node_keys();
        let me = *self.identity().node_addr();
        let params = crate::node::handlers::rekey::link_params(&self.config().node);
        let path_params = crate::node::handlers::path::path_params(&self.config().node);
        let workers = self.link_workers();
        let facts = NodeFacts {
            transports: &self.transports,
            denied: false,
        };
        let Some(p) = self.peers.get_mut(&peer) else {
            let _ = self
                .index_allocator
                .free(SessionIndex::new(lease.release()));
            self.retired_leg(link, closes).await;
            return;
        };
        let held = p.link_id();
        let mut caps = LinkCaps {
            indices: &mut self.index_allocator,
            local: &local,
            me,
            params,
            record: fips_core::proto::rekey::Record::new(),
            workers,
            path: PathCaps {
                params: path_params,
                facts: &facts,
            },
        };
        let (lout, paths) =
            p.adopt_dial(session, lease, theirs, to.clone(), held, false, &mut caps);
        let built = p.our_index() == Some(ours);
        if !built {
            debug!(
                peer = %self.peer_display_name(&peer),
                link_id = %link,
                "Redial proven on the held link, but its session could not be adopted"
            );
            self.run_link_outputs(&peer, lout);
            self.retired_leg(link, closes).await;
            return;
        }
        let mut run = Run::new(
            peer,
            crate::node::settle::table::Transition::Move {
                dial: held,
                own: false,
                built,
            },
        );
        let f = run.crossing();
        f.out = lout;
        f.paths = paths;
        f.ours = Some(ours);
        f.theirs = Some(theirs);
        f.to = Some(to);
        f.own_dial = false;
        f.loser = None;
        f.key = Some(crate::ipv6tun::link::PeerKey::from_xonly(
            &identity.pubkey(),
        ));
        self.run_with(&mut run, adopt()).await;
        self.stats_mut().handshake.redials_adopted += 1;
        debug!(
            peer = %self.peer_display_name(&peer),
            link_id = %link,
            held_link = %held,
            new_our_index = %ours,
            new_their_index = %theirs,
            "Redial proven on the held link; moved the held link onto the redial's session"
        );
        self.retired_leg(link, closes).await;
    }
}

/// A held peering's tree declaration and its coordinates, when it has both.
type Tree = Option<(ParentDeclaration, TreeCoordinate)>;

/// What the node reads of a redialed peer's held peering before the core
/// swaps it: its tree declaration and filter, kept across the swap, whether
/// an end-to-end session was open, the paths the teardown releases unlogged,
/// and its silent-session count.
struct Swapping {
    held: Option<(Tree, Option<(BloomFilter, u64)>)>,
    had_session: bool,
    ended: Vec<(PathRef, u32, PathState)>,
    silent: Option<u32>,
}

impl Swapping {
    /// Read it of `peer` on `node`.
    fn of(node: &Node, peer: &NodeAddr) -> Self {
        Self {
            held: node.peers.get(peer).map(|p| {
                (
                    p.declaration().cloned().zip(p.coords().cloned()),
                    p.inbound_filter()
                        .cloned()
                        .map(|f| (f, p.filter_sequence())),
                )
            }),
            had_session: node.sessions.contains_key(peer),
            ended: node.path_states(peer),
            silent: node.gates().silent(peer),
        }
    }
}
