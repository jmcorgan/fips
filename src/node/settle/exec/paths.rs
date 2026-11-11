//! A change to the peer's paths: a one-path roam, a path that followed its
//! peer to another address, a switch of the active path, and a path
//! released.
//!
//! A roam's effects are shared ones and await, and the frame's accounting
//! runs them through `Node::run`. The other three are reached from code
//! that cannot await, a removal's release of every path among it, so their
//! effects are plain functions here, and [`Node::run_now`] walks such a plan
//! without awaiting. Their sites are the path machine's executor in
//! `handlers/path.rs`, which builds each run with [`Run::followed`],
//! [`Run::switched`] or [`Run::released`] and clears a moved or released
//! path's driver slot itself, before the run, as it did before. A release at
//! the peer's removal runs the same plan, and its effects leave the link's
//! lookup alone, since the removal drops the link.

use super::plan::{Effect, plan};
use super::{Facts as Of, Run};
use crate::NodeAddr;
use crate::node::settle::table::{Cell, Row, Transition, cell};
use crate::node::{AddrKey, Node};
use crate::transport::LinkId;
use fips_core::proto::path::{PathRef, Switch};
use tracing::{debug, info};

/// What a path change's effects read beyond the transition, as its site
/// read it.
#[derive(Debug, Default)]
pub(in crate::node) struct Facts {
    /// The peer's link, or `None` where the site found no peer held.
    link: Option<LinkId>,
    /// The pair a moved path left, or the path active before a switch.
    from: Option<PathRef>,
    /// The pair a moved path is at, the newly active path, or the path
    /// released.
    to: Option<PathRef>,
    /// Why the active path changed.
    why: Option<Switch>,
    /// Whether the release is part of the peer's removal.
    removed: bool,
}

impl Run {
    /// The path of the peer at `peer` at `from` moved to `to`, on its link
    /// `link` if the peer was held when the path machine's step began.
    pub(in crate::node) fn followed(
        peer: NodeAddr,
        link: Option<LinkId>,
        from: PathRef,
        to: PathRef,
    ) -> Self {
        let facts = Facts {
            link,
            from: Some(from),
            to: Some(to),
            ..Facts::default()
        };
        Self {
            facts: Of::Paths(facts),
            ..Self::new(peer, Transition::Follow)
        }
    }

    /// The link `link` to the peer at `peer` now sends on `to`, its path
    /// machine having left `from` for `why`.
    pub(in crate::node) fn switched(
        peer: NodeAddr,
        link: LinkId,
        from: Option<PathRef>,
        to: PathRef,
        why: Switch,
    ) -> Self {
        let facts = Facts {
            link: Some(link),
            from,
            to: Some(to),
            why: Some(why),
            removed: false,
        };
        Self {
            facts: Of::Paths(facts),
            ..Self::new(peer, Transition::Switch)
        }
    }

    /// The path `to` of the link `link` to the peer at `peer` was released,
    /// with `keep` if the peer may still send there, and with `removed` at
    /// the peer's removal.
    pub(in crate::node) fn released(
        peer: NodeAddr,
        link: LinkId,
        to: PathRef,
        keep: bool,
        removed: bool,
    ) -> Self {
        let facts = Facts {
            link: Some(link),
            to: Some(to),
            removed,
            ..Facts::default()
        };
        Self {
            facts: Of::Paths(facts),
            ..Self::new(peer, Transition::Release { keep })
        }
    }
}

impl Node {
    /// Run `r`'s plan where the caller cannot await: every effect in it must
    /// be one of this file's.
    pub(in crate::node) fn run_now(&mut self, r: &mut Run) {
        for effect in plan(&r.t) {
            match effect {
                Effect::LinkFollow => link_follow(self, r),
                Effect::FollowNote => follow_note(self, r),
                Effect::ClearOldUdp => clear_old(self, r),
                Effect::LinkClaim => link_claim(self, r),
                Effect::SeedMtu => seed_mtu(self, r),
                Effect::TightenSessions => tighten(self, r),
                Effect::SwitchNote => switch_note(self, r),
                Effect::LinkUnclaim => link_unclaim(self, r),
                Effect::CloseQueued => close_queued(self, r),
                Effect::CloseSession
                | Effect::SettleData
                | Effect::TreeCleanup
                | Effect::BloomForgetSent
                | Effect::BloomMarkAll
                | Effect::TreeAnnounce
                | Effect::Unpin
                | Effect::DialForget
                | Effect::BloomMark
                | Effect::BackoffReset
                | Effect::PathsRenewed
                | Effect::ClearUdpIfMoved
                | Effect::RelinkIfMoved
                | Effect::MachineResolved
                | Effect::RelinkInitiator
                | Effect::PromotedNote
                | Effect::SetupNote
                | Effect::UnheardNote
                | Effect::RunLinkOutputs
                | Effect::RunRenewed
                | Effect::MovedRead
                | Effect::SeedMtuIfMoved
                | Effect::UnpinIfOwn
                | Effect::MoveNote
                | Effect::MachineCrossed
                | Effect::DialClose
                | Effect::DialLinkRemoved
                | Effect::KeepNote
                | Effect::LeaseFreed
                | Effect::UnmarkHeld
                | Effect::CloseHeld
                | Effect::Reconnect => {
                    debug_assert!(
                        false,
                        "{effect:?} awaits, so its plan runs through Node::run"
                    );
                }
            }
        }
    }
}

/// The path change's facts in `r`, which a run built by this file's
/// constructors always carries.
fn of(r: &Run) -> Option<&Facts> {
    match &r.facts {
        Of::Paths(facts) => Some(facts),
        Of::None | Of::Install(_) | Of::Cross(_) | Of::Remove(_) => {
            debug_assert!(false, "a path change runs with its facts");
            None
        }
    }
}

/// The path's pair as the link's lookup keys it.
fn key(path: &PathRef) -> AddrKey {
    (path.transport, path.addr.clone())
}

/// Rebuild the link's lookup at the path's move; the link's record follows
/// the move when the feed applies it.
pub(super) fn link_follow(node: &mut Node, _: &mut Run) {
    node.links.follow();
}

/// Log the path's move.
pub(super) fn follow_note(node: &mut Node, r: &mut Run) {
    if let Some(f) = of(r)
        && let (Some(from), Some(to)) = (&f.from, &f.to)
    {
        debug!(
            peer = %node.peer_display_name(&r.peer),
            from = %from.addr,
            to = %to.addr,
            transport_id = %to.transport,
            "Path moved to a new address"
        );
    }
}

/// Drop the connected UDP socket of the path that was active; the new
/// path's is opened at the next tick.
pub(super) fn clear_old(node: &mut Node, r: &mut Run) {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if let Some(f) = of(r)
        && let Some(old) = f.from.as_ref()
        && let Some(peer) = node.peers.get_mut(&r.peer)
        && let Some(bundle) = peer.bundle_mut()
        && let Some(i) = bundle.paths().find(old.transport, &old.addr)
        && let Some(slot) = bundle.driver_mut(i)
    {
        slot.clear_connected_udp();
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = (node, r);
}

/// Claim the newly active pair for the link in the lookup.
pub(super) fn link_claim(node: &mut Node, r: &mut Run) {
    if let Some(f) = of(r)
        && let (Some(link), Some(to)) = (f.link, &f.to)
    {
        node.links.claim(link, key(to));
    }
}

/// Seed the peer's path MTU from the newly active pair, as a move to a new
/// link seeds it, so a tighter value learned on the old path does not carry
/// over.
pub(super) fn seed_mtu(node: &mut Node, r: &mut Run) {
    if let Some(f) = of(r)
        && let Some(to) = &f.to
        && let Some(peer) = node.peers.get(&r.peer)
    {
        let key = crate::ipv6tun::link::PeerKey::from_xonly(&peer.identity().pubkey());
        node.seed_mtu(&r.peer, key, to.transport, &to.addr, true);
    }
}

/// Tighten every session whose next hop is the peer to the new pair's MTU
/// at once.
pub(super) fn tighten(node: &mut Node, r: &mut Run) {
    let Some(to) = of(r).and_then(|f| f.to.as_ref()) else {
        return;
    };
    let Some(mtu) = node
        .transports
        .get(&to.transport)
        .map(|t| t.link_mtu(&to.addr))
    else {
        return;
    };
    let dests: Vec<NodeAddr> = node.sessions.keys().copied().collect();
    for dest in dests {
        let via_peer = node
            .find_next_hop(&dest)
            .is_some_and(|hop| hop.node_addr() == &r.peer);
        if via_peer && let Some(mmp) = node.sessions.get_mut(&dest).and_then(|s| s.mmp_mut()) {
            mmp.path_mtu.seed_source_mtu(mtu);
        }
    }
}

/// Log the switch.
pub(super) fn switch_note(node: &mut Node, r: &mut Run) {
    if let Some(f) = of(r)
        && let (Some(to), Some(why)) = (&f.to, f.why)
    {
        info!(
            peer = %node.peer_display_name(&r.peer),
            from = %f.from.as_ref().map_or_else(|| "none".to_string(), |f| f.addr.to_string()),
            to = %to.addr,
            transport_id = %to.transport,
            why = switch_name(why),
            "Path switched"
        );
    }
}

/// The name of a change of active path's reason, for the log.
fn switch_name(why: Switch) -> &'static str {
    match why {
        Switch::Mandatory => "mandatory",
        Switch::Handover => "handover",
        Switch::Discretionary => "discretionary",
        Switch::Pinned => "pinned",
    }
}

/// Unclaim the released pair from the link's lookup while the link lives;
/// a removal drops the whole link.
pub(super) fn link_unclaim(node: &mut Node, r: &mut Run) {
    if let Some(f) = of(r)
        && !f.removed
        && let (Some(link), Some(to)) = (f.link, &f.to)
    {
        node.links.unclaim(link, &key(to));
    }
}

/// Queue the released pair's connection to close where the table's cell
/// says a release closes it, the peer having no further use for it, unless
/// another peer's link uses it (draft Section 5.8).
pub(super) fn close_queued(node: &mut Node, r: &mut Run) {
    if cell(Row::Connection, &r.t) != Cell::QueuedDrained || node_fault!(ReleaseKeepsPairOpen) {
        return;
    }
    if let Some(f) = of(r)
        && let (Some(link), Some(to)) = (f.link, &f.to)
        && !node.addr_carries_other_peer(to.transport, &to.addr, link)
    {
        node.paths.close_later(to.clone(), r.peer, f.removed);
    }
}
