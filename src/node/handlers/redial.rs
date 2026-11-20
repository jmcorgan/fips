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
//! Only a heard peering is redialed (operator decision, 2026-11-17): the
//! link machine asks for a redial only when the held peering has been heard
//! from. A fresh msg1 off the link of an unheard peering, such as one a
//! replayed msg1 promoted or the first of a dial over two paths, keeps the
//! replacement at the msg1 and its floors (`handlers::handshake`).
//!
//! At most one redial is pending per identity. Before one is armed it must
//! pass, in order: the slot rule (a pending redial under 1 s old holds the
//! slot; an older one is replaced), the restart gates (`Node.gates`, asked
//! as a redial: the redial memory, which refuses an ephemeral that armed a
//! redial of the peer in the last 15 s or a full memory, then the
//! dampener) and the ACL. Only then is the msg1's ephemeral recorded, in
//! the held link's replay record and the gates' redial memory, so a genuine
//! dial refused by a gate is judged again at its next resend.

use crate::NodeAddr;
use crate::node::Node;
use crate::node::acl::PeerAclContext;
use crate::node::dataplane::PeerActionCtx;
use crate::node::diag::HsLine;
use crate::node::handlers::handshake::Armed;
use crate::node::reject::{DataplaneReject, HandshakeReject, RejectReason};
use crate::node::settle::Redial;
use crate::peer::machine::{PeerAction, PeerEvent, PeerState};
use crate::proto::fmp::wire::{EncryptedHeader, build_msg2};
use crate::proto::fmp::{EphemeralDigest, WireOutcome};
use crate::proto::settle::gates::{Ask, Refusal, Source};
use crate::proto::settle::output::Why;
use crate::transport::{Link, LinkDirection, LinkId, ReceivedPacket};
use crate::utils::index::SessionIndex;
use fips_core::proto::rekey::allocate;
use std::time::Duration;
use tracing::{debug, warn};

/// Why a redial was refused before it was armed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Held {
    /// Another redial of the peer is pending and under 1 s old.
    Slot,
    /// Its ephemeral armed a redial of the peer in the last 15 s, or the
    /// memory of them is full. A silent-session refusal, which the msg1's
    /// classification makes before a redial is armed, would be counted here
    /// too.
    Seen,
    /// The restart dampener holds the peer.
    Dampened,
}

impl Node {
    /// Answer the redial `armed`, the msg1 in `packet` read as `wire`, into
    /// a pending redial beside the held peering, or refuse it at the first
    /// gate that holds it.
    pub(in crate::node) async fn arm_redial(
        &mut self,
        armed: Armed,
        packet: &ReceivedPacket,
        wire: &WireOutcome,
    ) {
        let Armed {
            mut machine,
            link,
            peer,
            identity,
            digest,
            ephemeral,
            leg_at,
        } = armed;
        let interval_ms = leg_at.interval_ms;
        let pending = self.redials.of(&peer);
        if let Some(held) = self.redial_held(&peer, pending, ephemeral, wire, packet, interval_ms) {
            if self.shown(&peer, HsLine::Redial) {
                debug!(
                    peer = %self.peer_display_name(&peer),
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
            return;
        }
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
            let _ = machine.step(PeerEvent::Rejected, interval_ms);
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        }
        // Every gate passed: a pending redial older than the slot's floor
        // gives way to this one, and the msg1's ephemeral is recorded, so
        // its copies are copies from here on.
        if let Some(old) = pending {
            debug!(
                peer = %self.peer_display_name(&peer),
                link_id = %old.link,
                "A later redial replaces a pending redial its frame never proved"
            );
            self.cleanup_stale_connection(old.link, packet.timestamp_ms)
                .await;
        }
        if let Some(digest) = digest
            && let Some(held) = self.peers.get_mut(&peer)
        {
            held.note_redial(digest);
        }
        if let Some(ephemeral) = ephemeral
            && !node_fault!(RedialMemoryIgnored)
        {
            let params = self.gate_params();
            let at = Self::memory_instant(packet).unwrap_or_else(crate::peer::peer_now);
            self.gates.redialed(peer, ephemeral, at, &params);
        }

        // Draw the leg's index, which the answer's leg holds until a
        // promotion takes it, and send its msg2; nothing is promoted.
        let Some(our_lease) = allocate(&mut self.index_allocator) else {
            warn!("Failed to allocate session index for a redial");
            let _ = machine.step(PeerEvent::Rejected, interval_ms);
            self.stats_mut()
                .record_reject(RejectReason::Handshake(HandshakeReject::BadState));
            return;
        };
        let our_index = SessionIndex::new(our_lease.index());
        let actions = machine.step(PeerEvent::AuthorizedHeld, interval_ms);
        let their_index = wire.their_index;
        self.links.open(Link::connectionless(
            link,
            packet.transport_id,
            packet.remote_addr.clone(),
            LinkDirection::Inbound,
            Duration::from_millis(self.config().node.base_rtt_ms),
        ));
        let wire_msg2 = build_msg2(our_index, their_index, &wire.msg2_payload);
        // The answer's leg, the settlement core's, reaped at the handshake
        // deadline counted from the msg1's arrival.
        self.answer_leg(
            link,
            peer,
            &packet.data,
            wire_msg2.clone(),
            our_lease,
            interval_ms,
        );
        machine.set_conn_handshake_msg2(wire_msg2);
        self.peer_machines.add(link, machine);
        self.redials.note(
            peer,
            Redial {
                link,
                index: our_index,
                at: interval_ms,
            },
        );
        self.stats_mut().handshake.redials += 1;
        debug!(
            peer = %self.peer_display_name(&peer),
            link_id = %link,
            our_index = %our_index,
            transport_id = %packet.transport_id,
            remote_addr = %packet.remote_addr,
            "Same-epoch msg1 off the established link, answered into a pending redial"
        );
        let ambient = PeerActionCtx {
            verified_identity: identity,
            transport_id: packet.transport_id,
            remote_addr: packet.remote_addr.clone(),
            our_index: Some(our_index),
            their_index: Some(their_index),
            now_ms: packet.timestamp_ms,
            interval_ms,
            is_outbound: false,
            why: None,
        };
        self.execute_peer_actions(link, &ambient, actions).await;
        // The mutation lane's breaks: the peering replaced with no frame
        // from the peer, at the msg1 or once its answer is sent.
        let unproven = [
            node_fault!(RedialTearsDownAtMsg1),
            node_fault!(RedialSwapsUnproven),
        ]
        .contains(&true);
        if unproven && self.redials.of(&peer).is_some_and(|r| r.link == link) {
            self.settle_redial(peer, link, packet.timestamp_ms).await;
        }
    }

    /// The first gate that holds back a redial of `peer`, whose pending
    /// redial is `pending`, with the msg1's `ephemeral`, read as `wire` from
    /// `packet`, at `now_ms` on the interval clock; `None` when every gate
    /// passes. The slot rule is the node's; the redial memory and the
    /// dampener are the restart gates', asked as a redial, which stamps
    /// nothing.
    fn redial_held(
        &mut self,
        peer: &NodeAddr,
        pending: Option<Redial>,
        ephemeral: Option<EphemeralDigest>,
        wire: &WireOutcome,
        packet: &ReceivedPacket,
        now_ms: u64,
    ) -> Option<Held> {
        if node_fault!(RedialTearsDownAtMsg1) {
            return None;
        }
        let params = self.gate_params();
        let floor = u64::try_from(params.unheard.as_millis()).unwrap_or(u64::MAX);
        if let Some(pending) = pending
            && now_ms.saturating_sub(pending.at) < floor
            && !node_fault!(RedialSlotIgnored)
        {
            return Some(Held::Slot);
        }
        let ask = Ask {
            source: Source::Redial,
            held: self.liveness(peer, packet.timestamp_ms),
            ephemeral: ephemeral.filter(|_| !node_fault!(RedialMemoryIgnored)),
            epoch: wire.remote_epoch,
            memory: Self::memory_instant(packet),
        };
        match self
            .gates
            .gate(*peer, ask, crate::peer::peer_now(), &params)
        {
            None => None,
            Some(Refusal::Redialed) => Some(Held::Seen),
            Some(Refusal::Dampened) if node_fault!(RedialSkipsDampener) => None,
            Some(Refusal::Dampened) => Some(Held::Dampened),
            Some(other) => {
                debug_assert_eq!(
                    other,
                    Refusal::Silent,
                    "a redial's gate refused it as no redial is refused"
                );
                Some(Held::Seen)
            }
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
            .peer_machines
            .get(&redial.link)
            .and_then(|m| m.leg())
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
        self.settle_redial(peer, redial.link, packet.timestamp_ms)
            .await;
        true
    }

    /// Replace the peering with `peer` by the pending redial's leg on
    /// `link`: the ACL checked again, the held peering torn down for a
    /// redial, keeping the identity's tree declaration and filter, the leg
    /// promoted, and the end-to-end session opened again if the teardown
    /// closed a heard one. `now_ms` is the wall stamp of the packet that
    /// proved it.
    pub(in crate::node) async fn settle_redial(
        &mut self,
        peer: NodeAddr,
        link: LinkId,
        now_ms: u64,
    ) {
        // The leg's index is the shell's until the promotion takes it, so
        // it is read from the pending redial.
        let Some(ours) = self
            .redials
            .of(&peer)
            .filter(|r| r.link == link)
            .map(|r| r.index)
        else {
            return;
        };
        let Some((identity, theirs, transport_id, remote_addr)) =
            self.peer_machines.get(&link).and_then(|m| {
                Some((
                    *m.conn_expected_identity()?,
                    m.conn_their_index()?,
                    m.conn_transport_id()?,
                    m.conn_source_addr()?.clone(),
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
            self.cleanup_stale_connection(link, now_ms).await;
            return;
        }
        let interval_ms = Self::interval_ms();
        let held = self.peers.get(&peer).map(|p| {
            (
                p.is_heard(),
                p.declaration().cloned().zip(p.coords().cloned()),
                p.inbound_filter()
                    .cloned()
                    .map(|f| (f, p.filter_sequence())),
            )
        });
        let had_session = self.sessions.contains_key(&peer);
        // The held link's paths, which the teardown releases unlogged.
        let ended = self.path_states(&peer);
        let actions = match self.peer_machines.get_mut(&link) {
            Some(machine) => machine.step(
                PeerEvent::Proven {
                    peer_held: held.is_some(),
                },
                interval_ms,
            ),
            None => return,
        };
        let at = actions
            .iter()
            .position(|a| matches!(a, PeerAction::PromoteToActive { .. }))
            .unwrap_or(actions.len());
        let mut teardown = actions;
        let promote = teardown.split_off(at);
        if !teardown.is_empty() {
            debug!(
                peer = %self.peer_display_name(&peer),
                link_id = %link,
                "Redial proven by the peer's frame, replacing the peering"
            );
            self.log_paths_ended(&peer, &ended);
            let teardown_ctx = PeerActionCtx {
                verified_identity: identity,
                transport_id,
                remote_addr: remote_addr.clone(),
                our_index: None,
                their_index: Some(theirs),
                now_ms,
                interval_ms,
                is_outbound: false,
                why: Some(Why::Redial),
            };
            self.execute_peer_actions(link, &teardown_ctx, teardown)
                .await;
        }
        // Stamped as an accepted replacement of a heard peering is: it bounds
        // the churn two processes under one key could drive. A replayer
        // cannot reach here, so it cannot stamp it. The swap also forgets
        // the identity's redial memory.
        let heard = held.as_ref().is_some_and(|(heard, _, _)| *heard);
        self.gates.swapped(peer, heard, crate::peer::peer_now());
        let session_closed = had_session && !self.sessions.contains_key(&peer);
        let ambient = PeerActionCtx {
            verified_identity: identity,
            transport_id,
            remote_addr,
            our_index: Some(ours),
            their_index: Some(theirs),
            now_ms,
            interval_ms,
            is_outbound: false,
            why: held.as_ref().map(|_| Why::Redial),
        };
        self.execute_peer_actions(link, &ambient, promote).await;
        if !matches!(
            self.peer_machines.get(&link).map(|m| m.state()),
            Some(PeerState::Established { .. })
        ) {
            return;
        }
        if !ended.is_empty() {
            self.log_paths_begun(&peer);
        }
        self.stats_mut().handshake.redials_proven += 1;
        // The peer's process and epoch are unchanged, so what it declared
        // and the filter it sent still hold for the peering that replaces
        // the one they came on.
        if let Some((_, tree, filter)) = held
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

    /// Drop `peer`'s pending redial, if any, as its expiry would: the
    /// operator disconnected the peer, so a later frame under the leg must
    /// promote nothing.
    pub(in crate::node) async fn drop_redial(&mut self, peer: &NodeAddr) {
        if let Some(redial) = self.redials.of(peer) {
            debug!(
                peer = %self.peer_display_name(peer),
                link_id = %redial.link,
                "Dropping the pending redial of a peer disconnected by the operator"
            );
            self.cleanup_stale_connection(redial.link, Self::now_ms())
                .await;
        }
    }
}
