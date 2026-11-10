//! A promotion, and a replacement: what the node runs once a new peer is
//! installed for an identity it did not hold, and the removal of the held
//! peer a replacement starts with.
//!
//! [`Node::install`] is the part a promotion runs before its plan, which a
//! test may call alone through `promote_connection`: it builds the peer's
//! machines and puts the peer in the node's maps. The peer action executor's
//! promotion arm then runs the plan of a [`Run::promotion`], whose effects
//! here read the [`Facts`] it holds.
//!
//! A replacement is not one step. Its plan is the removal's effects, then
//! the promotion's, and between the two the old peer's control machine notes
//! the loss and the site checks the ACL and allocates the new index, either
//! of which may stop the replacement with the removal done. So the executor's
//! removal arm runs the first part, through [`Run::replacement`] and
//! [`Node::run_removal`], and the promotion arm the second, through
//! [`Node::run_promotion`]; a promotion's plan is all of the second kind.

use super::plan::{Effect, plan};
use super::{Removed, Run};
use crate::PeerIdentity;
use crate::node::dataplane::PeerActionCtx;
use crate::node::handlers::path::NodeFacts;
use crate::node::settle::table::Transition;
use crate::node::{AddrKey, Node, NodeError};
use crate::peer::machine::{PeerAction, PeerEvent};
use crate::peer::{ActivePeer, LinkCaps, LinkOutputs, PathCaps};
use crate::proto::fmp::wire::Msg1Header;
use crate::proto::fmp::{EphemeralDigest, PromotionResult};
use crate::proto::settle::input::Input;
use crate::proto::settle::output::Why;
use crate::transport::{LinkId, LinkStats, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use fips_core::proto::rekey::IndexLease;
use tracing::info;

/// What a promotion's effects read beyond the transition.
#[derive(Debug, Default)]
pub(in crate::node) struct Facts {
    /// The promotion's outcome, which the leg's control machine is told.
    result: Option<PromotionResult>,
    /// The interval clock's reading the control machine steps at.
    interval_ms: u64,
    /// The pair the promoted link runs on, which the transport marks for a
    /// dial of this node's.
    at: Option<AddrKey>,
    /// The ephemeral of the msg1 that set the link up, which the setup note
    /// reads and the unheard note remembers.
    ephemeral: Option<EphemeralDigest>,
    /// What the control machine returned for the outcome, for the worklist
    /// of the step that promoted.
    follow: Vec<PeerAction>,
    /// The removal a replacement starts with, which its removal's effects
    /// read; `None` in the run of a promotion.
    removed: Option<Removed>,
}

impl Facts {
    /// The removal a replacement's removal effects read.
    pub(super) fn removed(&self) -> Option<&Removed> {
        self.removed.as_ref()
    }
}

impl Run {
    /// The run of a promotion of `link` that `promote_connection` answered
    /// with `result`, by a step whose facts are `ambient`: of this node's
    /// dial, answered by its msg2, when the step is outbound, and of a msg1
    /// this node answered otherwise. Where `ambient` says the step replaced
    /// a held peer, the run is of that replacement, whose removal ran first.
    pub(in crate::node) fn promotion(
        link: LinkId,
        result: PromotionResult,
        ambient: &PeerActionCtx,
    ) -> Self {
        let initiator = ambient.is_outbound;
        // A dial's msg2 found it in the dial map under the transport its msg1
        // went out on and the index the dial holds, which the msg2 named.
        let dial = ambient
            .our_index
            .filter(|_| initiator)
            .map(|index| (ambient.transport_id, index.as_u32()));
        Self {
            peer: *ambient.verified_identity.node_addr(),
            t: transition(link, ambient),
            prior: None,
            moved: None,
            dial,
            facts: super::Facts::Install(Facts {
                result: Some(result),
                interval_ms: ambient.interval_ms,
                at: Some((ambient.transport_id, ambient.remote_addr.clone())),
                ephemeral: None,
                follow: Vec::new(),
                removed: None,
            }),
        }
    }

    /// The run of the replacement whose removal of the held peer, by a step
    /// whose facts are `ambient`, gave `removed`, and whose new peer is to be
    /// promoted on `link`.
    pub(in crate::node) fn replacement(
        link: LinkId,
        removed: Removed,
        ambient: &PeerActionCtx,
    ) -> Self {
        let t = transition(link, ambient);
        debug_assert!(
            matches!(t, Transition::Replace { .. }),
            "a replacement's removal ran for a step that replaces no peer"
        );
        let mut r = Self::new(*ambient.verified_identity.node_addr(), t);
        r.facts = super::Facts::Install(Facts {
            removed: Some(removed),
            ..Facts::default()
        });
        r
    }

    /// Take what the leg's control machine returned for the promotion's
    /// outcome, which the step that promoted runs after the plan.
    pub(in crate::node) fn follow(&mut self) -> Vec<PeerAction> {
        facts(self)
            .map(|f| std::mem::take(&mut f.follow))
            .unwrap_or_default()
    }
}

/// The promotion's own facts in `r`.
fn facts(r: &mut Run) -> Option<&mut Facts> {
    let super::Facts::Install(f) = &mut r.facts else {
        debug_assert!(false, "a promotion's effect ran without its facts");
        return None;
    };
    Some(f)
}

/// The transition of a step whose facts are `ambient` that installs a new
/// peer on `link`: a replacement where the step says why it removed the
/// held one, and a promotion otherwise.
fn transition(link: LinkId, ambient: &PeerActionCtx) -> Transition {
    let initiator = ambient.is_outbound;
    match ambient.why {
        Some(why @ (Why::Restart | Why::Replacement | Why::OwnRestart)) => Transition::Replace {
            link,
            initiator,
            why,
        },
        Some(
            Why::Ended | Why::Orphaned | Why::Disconnect | Why::Dead | Why::Admin | Why::Closed,
        )
        | None => Transition::Promote { link, initiator },
    }
}

/// Where `t`'s plan divides: the effects before this place are a
/// replacement's removal's, and those from it on are a promotion's, which is
/// the whole of a promotion's plan.
fn divide(t: &Transition) -> usize {
    const REMOVAL: [Effect; 3] = [Effect::UnmarkHeld, Effect::CloseHeld, Effect::Reconnect];
    plan(t)
        .iter()
        .rposition(|e| REMOVAL.contains(e))
        .map_or(0, |at| at + 1)
}

/// The link a promotion installs.
fn link(t: &Transition) -> Option<LinkId> {
    if let Transition::Promote { link, .. } | Transition::Replace { link, .. } = t {
        Some(*link)
    } else {
        None
    }
}

impl Node {
    /// Run the part of `r`'s plan a replacement's removal runs, where the
    /// held peer was removed.
    pub(in crate::node) async fn run_removal(&mut self, r: &mut Run) {
        let at = divide(&r.t);
        self.run_part(r, 0..at).await;
    }

    /// Run the part of `r`'s plan a promotion runs once the new peer is
    /// installed: a promotion's whole plan, or what follows a replacement's
    /// removal.
    pub(in crate::node) async fn run_promotion(&mut self, r: &mut Run) {
        let at = divide(&r.t);
        self.run_part(r, at..plan(&r.t).len()).await;
    }

    /// Run the effects of `r`'s plan in `part`, in their order. Boxed, as
    /// `Node::run` is, so that no effect boxes anything.
    async fn run_part(&mut self, r: &mut Run, part: std::ops::Range<usize>) {
        let effects = &plan(&r.t)[part];
        Box::pin(async move {
            for effect in effects {
                self.effect(*effect, r).await;
            }
        })
        .await;
    }

    /// Install the peer of `link_id`, whose setup completed with
    /// `noise_session` and authenticated `verified_identity`, an identity
    /// this node does not hold: seed the path MTU from the pair it runs on,
    /// build its machines, put it in the node's maps, run what its link rekey
    /// machine returned once it is there, hold the core's record of the link
    /// for the peer and record the new bundle's original path in it, drop any
    /// retry of the identity and register its key. A session that
    /// authenticated another key frees `our_index` and fails, with nothing
    /// installed but the MTU seed.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::node) fn install(
        &mut self,
        link_id: LinkId,
        verified_identity: PeerIdentity,
        current_time_ms: u64,
        noise_session: crate::noise::NoiseSession,
        our_index: IndexLease,
        their_index: SessionIndex,
        transport_id: TransportId,
        current_addr: TransportAddr,
        link_stats: LinkStats,
        is_outbound: bool,
        remote_epoch: Option<[u8; 8]>,
    ) -> Result<(), NodeError> {
        let peer_node_addr = *verified_identity.node_addr();
        // The key the promotion seeds the path MTU map under.
        let peer_key = crate::ipv6tun::link::PeerKey::from_xonly(&verified_identity.pubkey());
        self.seed_path_mtu_for_link_peer(&peer_node_addr, peer_key, transport_id, &current_addr);

        let (mut new_peer, (out, core)) = self.keyed_peer(
            link_id,
            verified_identity,
            current_time_ms,
            noise_session,
            our_index,
            their_index,
            transport_id,
            current_addr,
            link_stats,
            is_outbound,
            remote_epoch,
        )?;
        new_peer
            .set_tree_announce_min_interval_ms(self.config().node.tree.announce_min_interval_ms);
        if node_fault!(NewPeerStartsRateLimited) {
            new_peer.set_last_tree_announce_sent_ms(Some(crate::time::mono_ms()));
        }

        if node_fault!(OutputsBeforeInstall) {
            self.run_link_outputs(&peer_node_addr, out);
            self.peers.install(peer_node_addr, new_peer);
        } else {
            self.peers.install(peer_node_addr, new_peer);
            self.run_link_outputs(&peer_node_addr, out);
        }
        self.links.hold(&link_id, peer_node_addr);
        for input in &core {
            self.feed(input);
        }
        self.peering
            .reconciler
            .retry_pending
            .remove(&peer_node_addr);
        self.register_identity(peer_node_addr, verified_identity.pubkey_full());
        Ok(())
    }

    /// Build the active peer of a link whose setup completed with
    /// `noise_session`: its link rekey machine takes the session as its first
    /// epoch, under `our_index` (the lease link setup took) and the peer's
    /// `their_index`, bound on `transport_id`, and is offered to the decrypt
    /// workers when a pool runs. Returns the peer and what to carry out once
    /// the peer is in the table: the machine's outputs (the binding of
    /// `our_index` and any offer) and the core inputs for the link's record.
    /// A session that authenticated another key than `verified_identity`'s,
    /// which a completed handshake never has, frees the index and fails the
    /// promotion.
    #[allow(clippy::too_many_arguments)]
    fn keyed_peer(
        &mut self,
        link_id: LinkId,
        verified_identity: PeerIdentity,
        current_time_ms: u64,
        noise_session: crate::noise::NoiseSession,
        our_index: IndexLease,
        their_index: SessionIndex,
        transport_id: TransportId,
        current_addr: TransportAddr,
        link_stats: LinkStats,
        is_outbound: bool,
        remote_epoch: Option<[u8; 8]>,
    ) -> Result<(ActivePeer, (LinkOutputs, Vec<Input>)), NodeError> {
        let local = self.session_node_keys();
        let me = *self.identity().node_addr();
        let mmp = self.config().node.mmp.clone();
        let params = crate::node::handlers::rekey::link_params(&self.config().node);
        let path_params = crate::node::handlers::path::path_params(&self.config().node);
        let record = self.link_records.take(
            verified_identity.node_addr(),
            remote_epoch.unwrap_or_default(),
        );
        let workers = self.link_workers();
        let link = self.links.no(&link_id);
        // A machine built at promotion, for a peer whose handshake the ACL
        // has passed; no probe is stepped here.
        let facts = NodeFacts {
            transports: &self.transports,
            denied: false,
        };
        let mut caps = LinkCaps {
            indices: &mut self.index_allocator,
            local: &local,
            me,
            params,
            record,
            workers,
            path: PathCaps {
                params: path_params,
                facts: &facts,
            },
        };
        ActivePeer::with_session(
            verified_identity,
            link_id,
            current_time_ms,
            noise_session,
            our_index,
            their_index,
            transport_id,
            current_addr,
            link_stats,
            is_outbound,
            &mmp,
            remote_epoch,
            link,
            &mut caps,
        )
        .map_err(|lease| {
            let _ = self
                .index_allocator
                .free(SessionIndex::new(lease.release()));
            NodeError::PromotionFailed {
                link_id,
                reason: "session authenticated another key".into(),
            }
        })
    }
}

/// Feed the promotion's outcome to the leg's control machine, keeping what
/// it returns for the step's worklist.
pub(super) async fn machine_resolved(node: &mut Node, r: &mut Run) {
    let link = link(&r.t);
    let Some(f) = facts(r) else {
        return;
    };
    let Some(result) = f.result else {
        return;
    };
    // Disjoint field borrow: the machine's map and the index allocator.
    f.follow = match link.and_then(|link| node.peer_machines.get_mut(&link)) {
        Some(machine) => machine.step(
            PeerEvent::PromotionResolved { result },
            f.interval_ms,
            &mut node.index_allocator,
        ),
        None => Vec::new(),
    };
}

/// Tell the transport which link the new peer uses. Only the initiator's
/// promotion does: it follows msg2, which answers this node's own fresh
/// ephemeral key, whereas a responder promotes on msg1 alone, and a captured
/// msg1 replayed on another link would promote there too. The responder's
/// link is marked by the initiator's first authenticated frame. No old link
/// is cleared: a promotion installs a new peer only, so there is none.
pub(super) async fn relink_initiator(node: &mut Node, r: &mut Run) {
    let Some(f) = facts(r) else {
        return;
    };
    if let (Some(PromotionResult::Promoted(peer)), Some(at)) = (f.result, f.at.clone())
        && !node_fault!(DropInitiatorMark)
    {
        node.relink(&peer, None, Some(at)).await;
    }
}

/// Log the promotion of a dial of this node's.
pub(super) async fn promoted_note(node: &mut Node, r: &mut Run) {
    info!(
        target: "fips::node::handlers::handshake",
        peer = %node.peer_display_name(&r.peer),
        "Peer promoted to active"
    );
}

/// Store on the peer the msg2 that answered the link's setup msg1, kept on
/// the leg's control machine for resends, so a duplicate msg1 is answered
/// with it; record that msg1 itself, since a copy of it after the session
/// can rekey is not a rekey and must not arm a pending; and its ephemeral.
pub(super) async fn setup_note(node: &mut Node, r: &mut Run) {
    let Some(machine) = link(&r.t).and_then(|link| node.peer_machines.get_mut(&link)) else {
        return;
    };
    let msg1 = machine.take_msg1().unwrap_or_default();
    let msg2 = machine
        .conn_handshake_msg2()
        .map(<[u8]>::to_vec)
        .unwrap_or_default();
    let ephemeral = Msg1Header::parse(&msg1)
        .and_then(|h| EphemeralDigest::of_noise_msg1(msg1.get(h.noise_msg1_offset..)?));
    if let Some(p) = node.peers.get_mut(&r.peer) {
        p.set_handshake_msg2(msg2.clone());
        p.note_setup(&msg1, &msg2);
        p.note_setup_ephemeral(ephemeral);
    }
    if let Some(f) = facts(r) {
        f.ephemeral = ephemeral;
    }
}

/// Remember an unheard peering's setup ephemeral.
pub(super) async fn unheard_note(node: &mut Node, r: &mut Run) {
    let ephemeral = facts(r).and_then(|f| f.ephemeral);
    node.note_unheard_promotion(&r.peer, ephemeral);
}
