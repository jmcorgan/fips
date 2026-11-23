//! A crossing resolved on the peer held: moved onto the session of the other
//! handshake with it, or kept on the session it holds with the other
//! handshake's link closed. The other handshake is this node's own dial,
//! settled at its msg2, or an inbound leg the peer's msg3 completed, settled
//! there. A move holds the peer on the other handshake's link and closes the
//! link it left: at the msg2 the dial's link, and at the msg3 the leg's, the
//! link the smaller node dialed. A keep at the msg3 closes the leg.
//!
//! The sites, `handle_msg2`'s crossing arm and `Node::cross_inbound` at the
//! peer's msg3, make a move themselves with `adopt_dial`, which also
//! settles the peer's record, then fill the run's [`Facts`] with what the
//! move returned and what it read before it, and the executor runs the rest
//! of the crossing from here.

use super::Run;
use crate::ipv6tun::link::PeerKey;
use crate::node::Node;
use crate::node::diag::{self, OrNone, Tag4};
use crate::node::handlers::path_intake::Feed;
use crate::node::settle::table::Transition;
use crate::peer::{LinkOutputs, UdpSlot};
use crate::proto::fmp::Msg1Digest;
use crate::transport::{LinkId, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use fips_core::proto::path::Outputs;
use fips_core::proto::rekey::IndexLease;
use tracing::debug;

/// What a crossing's effects read beyond the transition, which holds the
/// other handshake's link and whether it is an inbound leg.
#[derive(Default)]
pub(in crate::node) struct Facts {
    /// The rekey machine's outputs from the move, taken when run.
    pub(in crate::node) out: LinkOutputs,
    /// The path machine's outputs from its renewal, taken when run.
    pub(in crate::node) paths: Outputs<UdpSlot>,
    /// The index of this node's session on the other handshake.
    pub(in crate::node) ours: Option<SessionIndex>,
    /// The peer's index on the other handshake: the msg2's or the msg3's
    /// sender index.
    pub(in crate::node) theirs: Option<SessionIndex>,
    /// The transport and source address of the message that settled the
    /// crossing.
    pub(in crate::node) to: Option<(TransportId, TransportAddr)>,
    /// The key the peer's path MTU is seeded under.
    pub(in crate::node) key: Option<PeerKey>,
    /// Replays suppressed on the session the move left, read before it.
    pub(in crate::node) suppressed: u32,
    /// The tag of the session the peer moved onto.
    pub(in crate::node) epoch: Option<Tag4>,
    /// The digest of the msg1 this node sent on the dial.
    pub(in crate::node) msg1: Option<Msg1Digest>,
    /// The session index of the handshake a kept crossing ends, freed when
    /// run.
    pub(in crate::node) lease: Option<IndexLease>,
    /// The link the crossing tears down: at a move that holds the peer on
    /// the other handshake's link, the link it left; unset otherwise, and
    /// the other handshake's link is the loser.
    pub(in crate::node) loser: Option<LinkId>,
}

impl Run {
    /// This run's crossing facts, set to their defaults first if the run
    /// held none.
    pub(in crate::node) fn crossing(&mut self) -> &mut Facts {
        if !matches!(self.facts, super::Facts::Cross(_)) {
            self.facts = super::Facts::Cross(Facts::default());
        }
        match &mut self.facts {
            super::Facts::Cross(facts) => facts,
            super::Facts::None
            | super::Facts::Install(_)
            | super::Facts::Paths(_)
            | super::Facts::Remove(_) => unreachable!("set to a crossing's above"),
        }
    }
}

/// The link of the other handshake `t` names, and whether it is an inbound
/// leg the peer's msg3 completed, for a crossing; `None` for any other
/// transition.
fn other(t: &Transition) -> Option<(LinkId, bool)> {
    match t {
        Transition::Move { dial, inbound, .. } | Transition::Keep { dial, inbound } => {
            Some((*dial, *inbound))
        }
        Transition::Promote { .. }
        | Transition::Replace { .. }
        | Transition::Cutover { .. }
        | Transition::Restarted
        | Transition::Roam
        | Transition::Follow
        | Transition::Switch
        | Transition::Release { .. }
        | Transition::Remove { .. } => None,
    }
}

/// Whether `t` is a crossing settled at the peer's msg3.
fn at_leg(t: &Transition) -> bool {
    other(t).is_some_and(|(_, inbound)| inbound)
}

/// Run the rekey machine's outputs from the move.
pub(super) async fn link_outputs(node: &mut Node, r: &mut Run) {
    let out = std::mem::take(&mut r.crossing().out);
    node.run_link_outputs(&r.peer, out);
}

/// The link a move left for the other handshake's, if it held the peer on
/// that handshake's link; `None` at a keep and at a move refused or kept on
/// its link.
fn left(r: &mut Run) -> Option<LinkId> {
    let dial = other(&r.t).map(|(link, _)| link);
    r.crossing().loser.filter(|loser| Some(*loser) != dial)
}

/// The link the crossing tears down: the one the move left, or the other
/// handshake's.
fn loser(r: &mut Run) -> Option<LinkId> {
    let dial = other(&r.t).map(|(link, _)| link);
    r.crossing().loser.or(dial)
}

/// Run the path machine's outputs from its renewal: the bundle renewed on
/// the peer's link, and what it released belonging to the link the move
/// left.
pub(super) async fn renewed(node: &mut Node, r: &mut Run) {
    let left = left(r);
    let paths = std::mem::take(&mut r.crossing().paths);
    node.run_renewed(&r.peer, left, paths);
}

/// Hold the peer on the other handshake's link, the dial's or the leg's, if
/// the move left another: the core's record of that link is the peer's, and
/// the peer's handshake entry, its timers and the carrier readings are keyed
/// under it, which every later read of the peer's link names. At the msg3
/// the leg's own entry is dropped first.
pub(super) async fn hold_dial(node: &mut Node, r: &mut Run) {
    let (Some(left), Some((dial, _))) = (left(r), other(&r.t)) else {
        return;
    };
    node.links.hold(node.core.parts_mut().0, &dial, r.peer);
    // The mutation lane's break: the entry stays under the link left.
    if !node_fault!(MachineLeftBehind) {
        node.handshakes.rekey(left, dial);
    }
    // The mutation lane's break: the readings stay under the link left.
    if !node_fault!(CarrierLeftBehind) {
        node.rekey_carrier(left, dial);
    }
}

/// Offer the pair the link left to the heard feed, if the move left one.
/// It carried the link's frames until now, and nothing else offers it
/// again: without it the peer's next beacon there reads as a stranger's.
/// The heard feed offers it, so it is unlisted again once the peer goes
/// unheard there for the feed's silence.
pub(super) async fn heard_left(node: &mut Node, r: &mut Run) {
    let moved = node.peer_link(&r.peer);
    if let Some((transport, addr)) = r.prior.clone()
        && moved != r.prior
    {
        node.intake(&r.peer, Feed::Heard, transport, addr).await;
    }
}

/// Read the pair the peer is on after the move into `r.moved`.
pub(super) async fn moved_read(node: &mut Node, r: &mut Run) {
    r.moved = node.peer_link(&r.peer);
}

/// Seed the path MTU from the pair the peer moved to, if it moved: the MTU
/// was seeded from the link the peer was promoted on and describes that
/// link.
pub(super) async fn seed_mtu(node: &mut Node, r: &mut Run) {
    if r.moved == r.prior {
        return;
    }
    let key = r.crossing().key;
    if let (Some((tid, addr)), Some(key)) = (&r.moved, key) {
        node.seed_path_mtu_for_link_peer(&r.peer, key, *tid, addr);
    }
}

/// Whether `link` is this node's own dial, by its record's direction.
fn own_dial(node: &Node, link: &LinkId) -> bool {
    node.links
        .get(link)
        .is_some_and(|l| l.direction() == crate::transport::LinkDirection::Outbound)
}

/// Log the move: at a dial's msg2, the replays suppressed during it too. At
/// the msg3 a crossing logs master's keeping line instead, and a move from
/// a link the peer dialed (the same-side rule) logs its own line.
pub(super) async fn move_note(node: &mut Node, r: &mut Run) {
    let peer = node.peer_display_name(&r.peer);
    let leg = at_leg(&r.t);
    let epoch = node
        .peers
        .get(&r.peer)
        .and_then(|p| p.noise_session().map(diag::epoch_tag));
    let f = r.crossing();
    if leg {
        if f.loser.is_some_and(|left| own_dial(node, &left)) {
            // A crossing, the link left this node's own dial: the larger
            // node ends on the peer's dial, as master's larger node does when
            // it keeps its inbound session, so it logs master's line, the
            // one the chaos harness's crossing clause reads.
            debug!(
                peer = %peer,
                kept_their_index = %OrNone(f.theirs),
                transport_id = %OrNone(f.to.as_ref().map(|(tid, _)| *tid)),
                remote_addr = %OrNone(f.to.as_ref().map(|(_, addr)| addr)),
                epoch = %OrNone(epoch),
                "Cross-connection: keeping inbound session and original their_index (peer outbound wins)"
            );
            return;
        }
        debug!(
            peer = %peer,
            new_our_index = %OrNone(f.ours),
            new_their_index = %OrNone(f.theirs),
            "Simultaneous-init (msg3): swapped to inbound session (our inbound wins)"
        );
        return;
    }
    if f.suppressed > 0 {
        debug!(
            peer = %peer,
            count = f.suppressed,
            "Suppressed replay detections during link transition"
        );
    }
    debug!(
        peer = %peer,
        new_our_index = %OrNone(f.ours),
        new_their_index = %OrNone(f.theirs),
        transport_id = %OrNone(f.to.as_ref().map(|(tid, _)| *tid)),
        remote_addr = %OrNone(f.to.as_ref().map(|(_, addr)| addr)),
        msg1_sidx = %OrNone(f.ours),
        msg1_dg = %OrNone(f.msg1.as_ref().map(diag::msg1_tag)),
        epoch = %OrNone(f.epoch),
        "Cross-connection: swapped to outbound session (our outbound wins)"
    );
}

/// Close the losing link's connection, the link a move left or the other
/// handshake's: a separate socket on TCP, a no-op when connectionless, and
/// left open while a live link uses it, such as the very connection the peer
/// runs on (BLE), where closing would take the msg3 just queued, and the
/// link, with it.
pub(super) async fn loser_close(node: &mut Node, r: &mut Run) {
    // The mutation lane's break: a keep at the peer's msg3 leaves the leg's
    // connection open.
    if node_fault!(Msg3KeepLeavesLegOpen) && matches!(r.t, Transition::Keep { inbound: true, .. }) {
        return;
    }
    if let Some(link) = loser(r) {
        node.close_unused(link).await;
    }
}

/// Remove the losing link: the link a move left, or the other handshake's.
/// At the msg3 the leg's pair goes back to the link the index named there
/// before the leg, if that link is still live.
pub(super) async fn loser_removed(node: &mut Node, r: &mut Run) {
    if let Some(link) = loser(r) {
        node.remove_link(&link);
    }
}

/// Drop the handshake entry of the inbound leg the peer's msg3 completed,
/// with the connection it carries.
pub(super) async fn leg_machine_removed(node: &mut Node, r: &mut Run) {
    if let Some((link, _)) = other(&r.t) {
        node.remove_handshake(link);
    }
}

/// Log the crossing kept on the session the peer holds. At the msg3 the
/// smaller node logs master's swap line, since it ends as master's smaller
/// node does.
pub(super) async fn keep_note(node: &mut Node, r: &mut Run) {
    let name = node.peer_display_name(&r.peer);
    let Some(peer) = node.peers.get(&r.peer) else {
        return;
    };
    if at_leg(&r.t) {
        // Only the address order keeps at the msg3, so this is a crossing
        // and the smaller node stays on its own dial, as master's smaller
        // node ends when it swaps to its outbound session: it logs master's
        // line, the one the chaos harness's crossing clause reads.
        let to = node.peer_link(&r.peer);
        debug!(
            peer = %name,
            new_our_index = %OrNone(peer.our_index()),
            new_their_index = %OrNone(peer.their_index()),
            transport_id = %OrNone(to.as_ref().map(|(tid, _)| *tid)),
            remote_addr = %OrNone(to.as_ref().map(|(_, addr)| addr)),
            epoch = %OrNone(peer.noise_session().map(diag::epoch_tag)),
            "Cross-connection: swapped to outbound session (our outbound wins)"
        );
        return;
    }
    let f = r.crossing();
    debug!(
        peer = %name,
        kept_their_index = ?peer.their_index(),
        transport_id = %OrNone(f.to.as_ref().map(|(tid, _)| *tid)),
        remote_addr = %OrNone(f.to.as_ref().map(|(_, addr)| addr)),
        epoch = %OrNone(peer.noise_session().map(diag::epoch_tag)),
        "Cross-connection: keeping inbound session and original their_index (peer outbound wins)"
    );
}

/// Free the session index of the handshake a kept crossing ends.
pub(super) async fn lease_freed(node: &mut Node, r: &mut Run) {
    if let Some(lease) = r.crossing().lease.take() {
        let _ = node
            .index_allocator
            .free(SessionIndex::new(lease.release()));
    }
}
