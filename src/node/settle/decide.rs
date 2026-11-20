//! The settlement core's decisions, taken by the node.
//!
//! Each decision site builds the core's [`Input`] after any Noise read and
//! hands it to [`Node::decide`], which steps the node's one copy of the
//! core's table (`Node.core`) at the instant every settlement input takes
//! ([`Node::settle_now`]) and returns the outputs for the site to run, front
//! to back. [`Node::core_tick`] runs the handshake legs' timers the same way. The
//! link table's index is a cache of the core's link records, so it is
//! rebuilt after every step.

use crate::NodeAddr;
use crate::node::Node;
use crate::node::settle::exec::{By, Removed};
use crate::peer::{ActivePeer, PeerInstant};
use crate::proto::settle::input::Input;
use crate::proto::settle::links::{LinkNo, Pair};
use crate::proto::settle::output::Output;
#[cfg(test)]
use crate::proto::settle::table::Held;
use crate::transport::{TransportAddr, TransportId};

/// The pair `peer` is at, as its link's transport and current address give
/// it, or an empty address on transport 0 for a peer that has neither.
pub(in crate::node) fn current(peer: &ActivePeer) -> Pair {
    Pair {
        transport: peer.transport_id().unwrap_or_else(|| TransportId::new(0)),
        addr: peer
            .current_addr()
            .cloned()
            .unwrap_or_else(|| TransportAddr::new(Vec::new())),
    }
}

/// The core's record of `peer`, held on the core's link `link`, from the
/// peer's own facts: its epoch, the pair it is at, whether it is heard, the
/// instants of its promotion and of its last frame (the instant it was
/// last heard at, once a frame came or, on a heard peering, once it
/// differs from its promotion), and the ephemeral of the msg1 it was
/// promoted from. An unheard peering has had no frame, and the core reads
/// its floor from its promotion and counts its end as silent, so a test
/// that backdates its promotion alone gives it no last frame. A test's
/// resync plants it (test builds only).
#[cfg(test)]
pub(in crate::node) fn held(peer: &ActivePeer, link: LinkNo) -> Held<PeerInstant> {
    Held {
        link,
        epoch: peer.remote_epoch().unwrap_or_default(),
        current: current(peer),
        heard: peer.is_heard(),
        installed: peer.promoted_at(),
        last: last(peer),
        setup: peer.setup_ephemeral(),
        sending: None,
    }
}

/// The instant of `peer`'s last frame, as the core holds it: the instant
/// it was last heard at, once a frame came or, on a heard peering, once it
/// differs from its promotion.
pub(in crate::node) fn last(peer: &ActivePeer) -> Option<PeerInstant> {
    let framed = peer.heard() || (peer.is_heard() && peer.heard_at() != peer.promoted_at());
    framed.then_some(peer.heard_at())
}

/// The name a test's count of the inputs goes under for `input`.
#[cfg(test)]
fn kind_of(input: &Input) -> &'static str {
    match input {
        Input::Dial(_) => "Dial",
        Input::Connecting { .. } => "Connecting",
        Input::Punched(_) => "Punched",
        Input::ConnectFailed { .. } => "ConnectFailed",
        Input::Arrived { .. } => "Arrived",
        Input::Msg1 { .. } => "Msg1",
        Input::Replace(_) => "Replace",
        Input::Redial(_) => "Redial",
        Input::LegHeard { .. } => "LegHeard",
        Input::Hello(_) => "Hello",
        Input::Abandon { .. } => "Abandon",
        Input::Msg2 { .. } => "Msg2",
        Input::Restarted { .. } => "Restarted",
        Input::PeerEpoch { .. } => "PeerEpoch",
        Input::Ended { .. } => "Ended",
        Input::Orphaned { .. } => "Orphaned",
        Input::Heard { .. } => "Heard",
        Input::Disconnect { .. } => "Disconnect",
        Input::Dead { .. } => "Dead",
        Input::Admin { .. } => "Admin",
        Input::Sent { .. } => "Sent",
        Input::SendFailed { .. } => "SendFailed",
        Input::Unsendable { .. } => "Unsendable",
        Input::Moved { .. } => "Moved",
        Input::Switched { .. } => "Switched",
        Input::Released { .. } => "Released",
        Input::Capable { .. } => "Capable",
        Input::State { .. } => "State",
    }
}

impl Node {
    /// Take out of `out` the `Retire` that follows each `Remove`, the core's
    /// retirement of the removed peer's link: the connections it closes, by the
    /// peer removed, for the removal's run to close.
    pub(in crate::node) fn retired(out: &mut Vec<Output>) -> Vec<(NodeAddr, Vec<Pair>)> {
        let mut taken = Vec::new();
        let mut i = 0;
        while i + 1 < out.len() {
            if let (Output::Remove { peer, .. }, Output::Retire { .. }) = (&out[i], &out[i + 1]) {
                let peer = *peer;
                if let Output::Retire { closes, .. } = out.remove(i + 1) {
                    taken.push((peer, closes));
                }
            }
            i += 1;
        }
        taken
    }

    /// The connections the removal of `peer` closes, taken from `retired`.
    pub(in crate::node) fn closes_of(
        retired: &mut Vec<(NodeAddr, Vec<Pair>)>,
        peer: &NodeAddr,
    ) -> Vec<Pair> {
        retired
            .iter()
            .position(|(p, _)| p == peer)
            .map(|i| retired.remove(i).1)
            .unwrap_or_default()
    }

    /// Hand the settlement core `input` now, and return what it decided,
    /// for the caller to run in order.
    pub(in crate::node) fn decide(&mut self, input: Input) -> Vec<Output> {
        self.decide_at(input, Self::settle_now())
    }

    /// [`Node::decide`] at `now`: for an input that opens a handshake leg
    /// the node stamped at `now`, so the leg counts its deadline and
    /// resends from that instant.
    pub(in crate::node) fn decide_at(&mut self, input: Input, now: PeerInstant) -> Vec<Output> {
        #[cfg(test)]
        {
            self.resync();
            *self.inputs.entry(kind_of(&input)).or_insert(0) += 1;
        }
        let out = self.core.step(input, now);
        self.stepped();
        out
    }

    /// Run the handshake legs' timers at `now`: the msg1 resends due, and
    /// the legs past their deadline reaped.
    pub(in crate::node) fn core_tick(&mut self, now: PeerInstant) -> Vec<Output> {
        let out = self.core.poll(now);
        self.stepped();
        out
    }

    /// [`Node::core_tick`]'s reap of the leg on the core's link `link` alone, if
    /// it is past its deadline at `now`, and no resend.
    pub(in crate::node) fn reap(&mut self, link: LinkNo, now: PeerInstant) -> Vec<Output> {
        let out = self.core.reap_leg(link, now);
        self.stepped();
        out
    }

    /// Rebuild the caches of the core's state after a step: the link
    /// table's index, and the pending redials by their legs' indices.
    pub(in crate::node) fn stepped(&mut self) {
        self.links.stepped(&mut self.core);
        let pending: Vec<_> = self
            .core
            .redials()
            .map(|(peer, no)| {
                (
                    *peer,
                    self.links.id(no),
                    self.core.legs().get(no).map(|leg| leg.index()),
                )
            })
            .collect();
        self.redials.rebuild(pending.into_iter());
    }

    /// Give `lease`'s index back to the allocator.
    pub(in crate::node) fn free_lease(&mut self, lease: crate::proto::rekey::IndexLease) {
        let _ = self
            .index_allocator
            .free(crate::utils::index::SessionIndex::new(lease.release()));
    }

    /// Tell the core the node gave up unfinished the dial or leg on its
    /// link `id`, for a cause the core has no timer of its own for: a
    /// connection that failed or was abandoned, a dial whose msg1 could not
    /// be built, a failed leg, a traversal's adoption. The leg's lease, if
    /// it held one, goes back to the allocator, and the connections the
    /// link's retirement leaves unused are returned for the caller to close.
    /// Nothing when the link has no record.
    pub(in crate::node) fn give_up(&mut self, id: crate::transport::LinkId) -> Vec<Pair> {
        let Some(link) = self.links.no(&id) else {
            return Vec::new();
        };
        let mut closes = Vec::new();
        for o in self.decide(Input::ConnectFailed { link }) {
            match o {
                Output::Free { lease } => self.free_lease(lease),
                Output::Retire { closes: c, .. } => closes = c,
                other => debug_assert!(false, "a dial given up gave {other:?}"),
            }
        }
        closes
    }

    /// Close the transport connection at each pair of `closes`, which the
    /// core's close rule found no live link uses.
    pub(in crate::node) async fn close_each(&mut self, closes: Vec<Pair>) {
        for pair in closes {
            if let Some(transport) = self.transports.get(&pair.transport) {
                transport.close_connection(&pair.addr).await;
            }
        }
    }

    /// The link the core opened for the input that gave `out`: a dial's
    /// `Opened`, or an admitted msg1's `Ask`.
    pub(in crate::node) fn opened(out: &[Output]) -> Option<LinkNo> {
        out.iter().find_map(|o| match o {
            Output::Opened { link } | Output::Ask { link, .. } => Some(*link),
            _ => None,
        })
    }

    /// Tell the core a frame of `peer` authenticated from `transport` and
    /// `addr`, of link message type `kind`: the peering is heard, at its
    /// last frame now, and the gates forget what a frame makes them forget.
    /// It changes no link record, so the index is not rebuilt.
    pub(in crate::node) fn hear(
        &mut self,
        peer: NodeAddr,
        transport: TransportId,
        addr: &TransportAddr,
        kind: u8,
    ) {
        let input = Input::Heard {
            peer,
            from: Pair {
                transport,
                addr: addr.clone(),
            },
            kind,
        };
        #[cfg(test)]
        {
            self.resync();
            *self.inputs.entry(kind_of(&input)).or_insert(0) += 1;
        }
        let _ = self.core.step(input, Self::settle_now());
        // The node keeps the instant of the peer's last frame as the core
        // holds it. The mutation lane's break: the node's copy goes stale.
        if !node_fault!(HeldCacheStale)
            && let Some(at) = self.core.held(&peer).and_then(|h| h.last)
            && let Some(p) = self.peers.get_mut(&peer)
        {
            p.heard_at_core(at);
        }
    }

    /// Hand the core a removal it decides, `input` (a link dead, an
    /// orphaned bundle, a `Disconnect`, an operator disconnect or a rekey
    /// teardown), and remove the peer it says to remove. Returns the
    /// removal, marked as noted for a reconnect so the removal's plan
    /// schedules none of its own, whether the core asked for a reconnect,
    /// and the core's other outputs.
    pub(in crate::node) fn decide_removal(
        &mut self,
        input: Input,
    ) -> (Option<Removed>, bool, Vec<Output>) {
        let peer = match &input {
            Input::Dead { peer }
            | Input::Orphaned { peer }
            | Input::Disconnect { peer }
            | Input::Admin { peer }
            | Input::Ended { peer } => Some(*peer),
            _ => None,
        };
        let silent = peer.and_then(|p| self.gates().silent(&p));
        let mut removed = None;
        let mut retry = false;
        let mut rest = Vec::new();
        let mut out = self.decide(input);
        let mut retired = Self::retired(&mut out);
        for o in out {
            match o {
                Output::Remove { peer, why } => {
                    removed = self
                        .remove(&peer, why, By::Core { silent })
                        .map(|r| Removed { noted: true, ..r });
                    let closes = Self::closes_of(&mut retired, &peer);
                    if let Some(r) = removed.as_mut() {
                        self.retire_closes(peer, r, closes);
                    }
                }
                Output::Retry { .. } => retry = true,
                Output::Free { lease } => self.free_lease(lease),
                other => rest.push(other),
            }
        }
        (removed, retry, rest)
    }

    /// Stop holding the peer at `peer` in the core, after a test removed it
    /// by a removal of its own (test builds only).
    #[cfg(test)]
    pub(in crate::node) fn unadopt(&mut self, peer: &NodeAddr) {
        let _ = self.core.unadopt(peer);
    }

    /// How many inputs named `kind` the node handed the core (test builds
    /// only).
    #[cfg(test)]
    pub(in crate::node) fn seen(&self, kind: &str) -> u64 {
        self.inputs.get(kind).copied().unwrap_or(0)
    }
}
