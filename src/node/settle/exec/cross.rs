//! A crossing resolved on the peer held: moved onto this node's dial, and
//! held on the dial's link with the link it left closed, or kept on the
//! peer's inbound session with the dial closed.
//!
//! The site, `handle_msg2`'s crossing arm, makes a move itself with
//! `move_session`, which also settles the peer's record, then fills the
//! run's [`Facts`] with what the move returned and what it read before it,
//! and the executor runs the rest of the crossing from here.

use super::Run;
use crate::ipv6tun::link::PeerKey;
use crate::node::Node;
use crate::node::diag::{self, OrNone, Tag4};
use crate::node::settle::table::Transition;
use crate::peer::machine::CrossConnOutcome;
use crate::peer::{LinkOutputs, UdpSlot};
use crate::proto::fmp::Msg1Digest;
use crate::transport::{LinkId, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use fips_core::proto::path::Outputs;
use fips_core::proto::rekey::IndexLease;
use tracing::debug;

/// What a crossing's effects read beyond the transition, which holds the
/// dial's link and whether a move answered this node's own or a later dial.
#[derive(Default)]
pub(in crate::node) struct Facts {
    /// The rekey machine's outputs from the move, taken when run.
    pub(in crate::node) out: LinkOutputs,
    /// The path machine's outputs from its renewal, taken when run.
    pub(in crate::node) paths: Outputs<UdpSlot>,
    /// The index of this node's session on the dial.
    pub(in crate::node) ours: Option<SessionIndex>,
    /// The peer's index on the dial, the msg2's sender index.
    pub(in crate::node) theirs: Option<SessionIndex>,
    /// The transport and source address of the msg2 that answered the dial.
    pub(in crate::node) to: Option<(TransportId, TransportAddr)>,
    /// Whether the peer was held on a link this node dialled. A later dial
    /// moves the peer as its own dial does, but logs as a crossing won.
    pub(in crate::node) own_dial: bool,
    /// The key the peer's path MTU is seeded under.
    pub(in crate::node) key: Option<PeerKey>,
    /// Replays suppressed on the session the move left, read before it.
    pub(in crate::node) suppressed: u32,
    /// The tag of the session the peer moved onto.
    pub(in crate::node) epoch: Option<Tag4>,
    /// The digest of the msg1 this node sent on the dial.
    pub(in crate::node) msg1: Option<Msg1Digest>,
    /// How the crossing resolved, for the peer's control machine.
    pub(in crate::node) outcome: Option<CrossConnOutcome>,
    /// The session index of the dial a kept crossing closes, freed when
    /// run.
    pub(in crate::node) lease: Option<IndexLease>,
    /// The move made the peering heard: it was unheard before the move and
    /// is heard after it.
    pub(in crate::node) first_heard: bool,
    /// The link the crossing tears down: at a move that holds the peer on
    /// the dial's link, the link it left; otherwise the dial's.
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

    /// Whether a resolved crossing moves the peer onto this node's dial, as
    /// the decision `swap` says. `tie` says the tie-break decided it, with
    /// neither this node's own nor a later dial in play.
    pub(in crate::node) fn swaps(swap: bool, tie: bool) -> bool {
        // The mutation lane's break: the smaller node keeps, as the larger
        // does.
        swap && !(tie && node_fault!(CrossedRunsKeep))
    }
}

/// The dial `t` names, and whether it answered this node's own or a later
/// dial, for a crossing; `None` for any other transition.
fn dial(t: &Transition) -> Option<(LinkId, bool)> {
    match t {
        Transition::Move { dial, own, .. } => Some((*dial, *own)),
        Transition::Keep { dial } => Some((*dial, false)),
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

/// Run the rekey machine's outputs from the move.
pub(super) async fn link_outputs(node: &mut Node, r: &mut Run) {
    let out = std::mem::take(&mut r.crossing().out);
    node.run_link_outputs(&r.peer, out);
}

/// The link a move left for the dial's, if it held the peer on the dial's
/// link; `None` at a keep and at a move refused or kept on its link.
fn left(r: &mut Run) -> Option<LinkId> {
    let dial = dial(&r.t).map(|(link, _)| link);
    r.crossing().loser.filter(|loser| Some(*loser) != dial)
}

/// The link the crossing tears down: the one the move left, or the dial's.
fn loser(r: &mut Run) -> Option<LinkId> {
    let dial = dial(&r.t).map(|(link, _)| link);
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

/// Hold the peer on the dial's link, if the move left another: the core's
/// record of the dial's link is the peer's, and the control machine, its
/// timers and the carrier readings are keyed under the dial's link, which
/// every later read of the peer's link names.
pub(super) async fn hold_dial(node: &mut Node, r: &mut Run) {
    let (Some(left), Some((dial, _))) = (left(r), dial(&r.t)) else {
        return;
    };
    node.links.hold(&dial, r.peer);
    // The mutation lane's break: the machine stays under the link left.
    if !node_fault!(MachineLeftBehind) {
        node.peer_machines.rekey(left, dial);
    }
    // The mutation lane's break: the readings stay under the link left.
    if !node_fault!(CarrierLeftBehind) {
        node.rekey_carrier(left, dial);
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

/// End the operator's pin if the move answered this node's own or a later
/// dial and the peer is on that dial's session. The peer may have answered
/// the dial by replacing the peering, which nothing here tells apart from a
/// rekey, and a pin ends when the peer is replaced through a new handshake;
/// a crossing won on the tie-break keeps it.
pub(super) async fn unpin_own(node: &mut Node, r: &mut Run) {
    let own = dial(&r.t).is_some_and(|(_, own)| own);
    let ours = r.crossing().ours;
    let swapped = node.peers.get(&r.peer).and_then(|p| p.our_index()) == ours;
    if own && swapped {
        node.step_path(&r.peer, fips_core::proto::path::Input::Unpin)
            .await;
    }
}

/// Log the replays suppressed during the move and the move itself.
pub(super) async fn move_note(node: &mut Node, r: &mut Run) {
    let peer = node.peer_display_name(&r.peer);
    let f = r.crossing();
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
        "{}",
        if f.own_dial {
            "Second dial answered: swapped to its session (the answer supersedes our earlier dial's)"
        } else {
            "Cross-connection: swapped to outbound session (our outbound wins)"
        }
    );
}

/// Tell the peer's control machine how the crossing resolved, so its shadow
/// session indices track the move (updated) or the keep (unchanged).
pub(super) async fn machine_crossed(node: &mut Node, r: &mut Run) {
    if let Some(outcome) = r.crossing().outcome {
        node.observe_cross_conn_resolved(&r.peer, outcome);
    }
}

/// Close the losing link's connection, the link a move left or the dial's:
/// a separate socket on TCP, a no-op when connectionless, and left open
/// while a live link uses it, such as the very connection the peer runs on
/// (BLE).
pub(super) async fn loser_close(node: &mut Node, r: &mut Run) {
    if let Some(link) = loser(r) {
        node.close_unused(link).await;
    }
}

/// Remove the losing link, the link a move left or the dial's.
pub(super) async fn loser_removed(node: &mut Node, r: &mut Run) {
    if let Some(link) = loser(r) {
        node.remove_link(&link);
    }
}

/// Log the crossing kept on the peer's inbound session.
pub(super) async fn keep_note(node: &mut Node, r: &mut Run) {
    let Some(peer) = node.peers.get(&r.peer) else {
        return;
    };
    let name = node.peer_display_name(&r.peer);
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

/// Free the session index of the dial a kept crossing closes.
pub(super) async fn lease_freed(node: &mut Node, r: &mut Run) {
    if let Some(lease) = r.crossing().lease.take() {
        let _ = node
            .index_allocator
            .free(SessionIndex::new(lease.release()));
    }
}

/// Forget the msg1s remembered against replay for a peering the move made
/// heard, as its first authenticated frame would: the memory bounds the
/// replacements of an unheard peering, and this one is heard.
pub(super) async fn replay_forget(node: &mut Node, r: &mut Run) {
    // The mutation lane's break: the memory stays until the peer's removal.
    if r.crossing().first_heard && !node_fault!(MoveKeepsReplayMemory) {
        node.replayed_msg1s.forget(&r.peer);
    }
}
