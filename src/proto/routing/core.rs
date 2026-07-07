//! Sans-IO routing decision core.
//!
//! Pure, runtime-agnostic transit-forward decision for SessionDatagrams. The
//! async I/O adapter in `node::handlers::forwarding` decodes the wire bytes,
//! pre-resolves the next hop, builds a [`RoutingView`] over live node state,
//! calls [`Router::route`], and drives the returned [`RouteOutcome`] (the
//! actual encrypted sends, metrics, and logging). No I/O, no clock, no
//! metrics, no logging here.
//!
//! This module also holds the pure candidate assembly ([`routing_candidates`])
//! and the hop-selection / route-classification helpers
//! ([`select_best_candidate`], [`classify_forward`]). The assembly enumerates
//! peers through the [`RoutingView`] seam, applies the bloom `may_reach`
//! filter, and snapshots each survivor into a [`Candidate`]; the shell hands
//! over only raw per-peer reads (enumeration plus `may_reach` / `can_send` /
//! `link_cost` / `coords`). Selection and classification then consume the
//! assembled set. All routing narrowing and decision logic lives here.

use super::state::Router;
use super::wire::{CoordsRequired, MtuExceeded, PathBroken};
use crate::protocol::{SessionDatagram, SessionDatagramRef};
use crate::{NodeAddr, TreeCoordinate};

/// Read-only view of routing state the routing core needs.
///
/// The core defines this interface; the async shell (`node`) implements it
/// over the live peer/coord/congestion state. Keeping it a trait keeps
/// `proto` free of any dependency on `node` and lets the core be unit-tested
/// with a mock.
pub(crate) trait RoutingView {
    /// Is the outgoing link toward `next_hop` congested (ECN local signal)?
    fn is_congested(&self, next_hop: &NodeAddr) -> bool;
    /// Cached destination coordinates for `dest`, if any (read-only lookup).
    ///
    /// Drives the PathBroken-vs-CoordsRequired choice in
    /// [`Router::synth_routing_error`].
    fn cached_coords(&self, dest: &NodeAddr, now_ms: u64) -> Option<TreeCoordinate>;

    /// Node addresses of every currently-active peer — the raw enumeration the
    /// candidate assembly iterates. No filtering or ordering is applied here;
    /// [`routing_candidates`] applies the bloom `may_reach` narrowing in core.
    fn peer_addrs(&self) -> Vec<NodeAddr>;
    /// Does `peer`'s bloom filter indicate it may reach `dest`? The raw
    /// per-peer predicate the core assembly filters candidates on.
    fn peer_may_reach(&self, peer: &NodeAddr, dest: &NodeAddr) -> bool;
    /// Can `peer`'s session currently carry a forward?
    fn peer_can_send(&self, peer: &NodeAddr) -> bool;
    /// `peer`'s outgoing link cost (lower is preferred).
    fn peer_link_cost(&self, peer: &NodeAddr) -> f64;
    /// `peer`'s tree coordinates, if known.
    fn peer_coords(&self, peer: &NodeAddr) -> Option<TreeCoordinate>;
}

/// A next hop the shell resolved for a transit forward: the peer address and
/// the outgoing link's transport MTU (already narrowed to the specific link).
pub(crate) struct NextHop {
    pub addr: NodeAddr,
    pub link_mtu: u16,
}

/// Why a datagram was dropped without forwarding or delivering.
pub(crate) enum DropReason {
    /// Received TTL was already exhausted (0) — cannot decrement further.
    TtlExhausted,
}

/// Outcome of routing an inbound SessionDatagram.
pub(crate) enum RouteOutcome {
    /// Drop the datagram; the shell records the reason-specific metric + log.
    Drop { reason: DropReason },
    /// Deliver to the local session layer. Carries no bytes — the shell
    /// services delivery from the borrowed datagram ref, avoiding a copy.
    DeliverLocal,
    /// Forward toward `next_hop`. `bytes` is the fully re-encoded datagram
    /// (TTL decremented, path MTU min-folded), the single copy the shell would
    /// have produced itself. `outgoing_ce` is the CE flag to set on the send.
    Forward {
        next_hop: NodeAddr,
        bytes: Vec<u8>,
        outgoing_ce: bool,
    },
    /// No route to the destination. The shell synthesizes a routing error
    /// signal back toward the source.
    NoRoute,
}

/// An I/O action the async shell performs on the core's behalf.
pub(crate) enum RouteAction {
    /// Route the encoded error datagram in `bytes` toward `toward` (the failed
    /// datagram's source). The shell resolves the outgoing link hop for
    /// `toward` and performs the encrypted send. `toward` is the routing
    /// target, not a pre-resolved link hop: the reverse hop is resolved
    /// shell-side *after* the rate-limit gate so `find_next_hop`'s cache touch
    /// keeps the same post-gate scope it had inline.
    SendError { toward: NodeAddr, bytes: Vec<u8> },
}

impl Router {
    /// Decide the fate of an inbound SessionDatagram: drop (TTL), local
    /// delivery, transit forward, or no-route. Pure over the datagram, the
    /// shell-resolved next hop, and the [`RoutingView`] reads.
    ///
    /// The shell pre-resolves `next_hop` only for genuine transit packets
    /// (TTL > 0 and dest not local), so `find_next_hop`'s LRU-touch side
    /// effect keeps the same scope it has today. `route` still re-checks TTL
    /// and local delivery authoritatively.
    pub(crate) fn route(
        &mut self,
        dg: &SessionDatagramRef<'_>,
        my_addr: &NodeAddr,
        incoming_ce: bool,
        next_hop: Option<NextHop>,
        rv: &impl RoutingView,
    ) -> RouteOutcome {
        if dg.ttl == 0 {
            return RouteOutcome::Drop {
                reason: DropReason::TtlExhausted,
            };
        }
        if dg.dest_addr == *my_addr {
            return RouteOutcome::DeliverLocal;
        }
        let nh = match next_hop {
            Some(nh) => nh,
            None => return RouteOutcome::NoRoute,
        };

        // Re-encode with decremented TTL and the path MTU min-folded against
        // the outgoing link. This is the single owned copy + encode the shell
        // performed inline today.
        let mut datagram = SessionDatagram::new(dg.src_addr, dg.dest_addr, dg.payload.to_vec());
        datagram.ttl = dg.ttl - 1;
        datagram.path_mtu = dg.path_mtu.min(nh.link_mtu);
        let outgoing_ce = incoming_ce || rv.is_congested(&nh.addr);
        let bytes = datagram.encode();
        RouteOutcome::Forward {
            next_hop: nh.addr,
            bytes,
            outgoing_ce,
        }
    }

    /// Synthesize a routing error signal for an undeliverable transit datagram.
    ///
    /// Applies the per-destination rate-limit gate, then chooses the error PDU
    /// from cached coordinate state: PathBroken (with last-known coords) when
    /// `dest` is cached — we know where it is but cannot reach it — otherwise
    /// CoordsRequired. The chosen PDU is wrapped in a fresh SessionDatagram
    /// addressed back to `toward` (the failed datagram's source) and encoded.
    ///
    /// Returns `None` when the rate-limit gate suppresses the signal (the shell
    /// drops silently). On `Some`, the shell resolves the reverse link hop for
    /// `toward` and sends — resolving the hop only after this gate preserves
    /// the pre-refactor ordering (rate-limit before `find_next_hop`'s cache
    /// touch) and lets the shell distinguish suppression from no-reverse-route
    /// for logging.
    pub(crate) fn synth_routing_error(
        &mut self,
        dest: &NodeAddr,
        toward: &NodeAddr,
        my_addr: &NodeAddr,
        rv: &impl RoutingView,
        now_ms: u64,
        default_ttl: u8,
    ) -> Option<RouteAction> {
        if !self.error_limiter.should_send(dest, now_ms) {
            return None;
        }
        let error_payload = match rv.cached_coords(dest, now_ms) {
            Some(coords) => PathBroken::new(*dest, *my_addr)
                .with_last_coords(coords)
                .encode(),
            None => CoordsRequired::new(*dest, *my_addr).encode(),
        };
        let error_dg = SessionDatagram::new(*my_addr, *toward, error_payload).with_ttl(default_ttl);
        Some(RouteAction::SendError {
            toward: *toward,
            bytes: error_dg.encode(),
        })
    }

    /// Synthesize an MtuExceeded error signal after a forward send failed with
    /// a bottleneck MTU. Applies the per-destination rate-limit gate (the same
    /// limiter as [`synth_routing_error`]), then builds the MtuExceeded PDU
    /// carrying `bottleneck_mtu`, wraps it in a fresh SessionDatagram addressed
    /// back to `toward` (the failed datagram's source), and encodes it.
    ///
    /// Returns `None` when the gate suppresses the signal. On `Some`, the shell
    /// resolves the reverse link hop for `toward` and sends — resolving the hop
    /// only after this gate preserves the pre-refactor ordering (rate-limit
    /// before `find_next_hop`'s cache touch). No coordinate read is involved;
    /// unlike routing errors, the PDU is unconditional once the gate passes.
    pub(crate) fn synth_mtu_exceeded(
        &mut self,
        dest: &NodeAddr,
        toward: &NodeAddr,
        my_addr: &NodeAddr,
        bottleneck_mtu: u16,
        now_ms: u64,
        default_ttl: u8,
    ) -> Option<RouteAction> {
        if !self.error_limiter.should_send(dest, now_ms) {
            return None;
        }
        let error_payload = MtuExceeded::new(*dest, *my_addr, bottleneck_mtu).encode();
        let error_dg = SessionDatagram::new(*my_addr, *toward, error_payload).with_ttl(default_ttl);
        Some(RouteAction::SendError {
            toward: *toward,
            bytes: error_dg.encode(),
        })
    }
}

/// Route class of a transit-forwarded packet, classified from tree
/// coordinates at the forwarding decision point. The six variants
/// partition `forwarded_packets` exactly.
///
/// Two variants are up-and-over forwards (destination not in the chosen
/// peer's subtree); they differ in whether they depend on a child
/// advertising cross-link reach *upward* to its parent:
/// - `TreeDownCross`: the chosen peer is our tree descendant, but the
///   destination is *not* in that child's subtree. The forward only fired
///   because the child advertised cross-link reach upward to us, beyond its
///   own subtree. If children advertised only their subtree upward, this
///   forward would route up instead, so its count measures how much
///   forwarding depends on the upward cross-link advertisement — the
///   dive-to-tree-child cut-through.
/// - `CrosslinkAscend`: the chosen peer is lateral (neither ancestor nor
///   descendant) and the destination is not in its subtree. This is a node
///   using its *own* cross-link, learned via the peer's split-horizon
///   advertisement to its neighbors, so it does not depend on any upward
///   advertisement. Tracked alongside `TreeDownCross` as the lateral
///   up-and-over contrast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteClass {
    /// Chosen peer is our ancestor (tree-up).
    TreeUp,
    /// Chosen peer is our descendant and dest is in its subtree (canonical
    /// tree-down).
    TreeDown,
    /// Chosen peer is our descendant but dest is *not* in its subtree: the
    /// dive-to-tree-child cut-through enabled by upward cross-link
    /// advertisement.
    TreeDownCross,
    /// Chosen peer is lateral and dest is in its subtree (subtree entry).
    CrosslinkDescend,
    /// Chosen peer is lateral and dest is not in its subtree (up-and-over).
    CrosslinkAscend,
    /// Chosen peer is the destination itself (degenerate direct hop).
    DirectPeer,
}

/// A bloom-filter routing candidate, snapshotted by [`routing_candidates`]
/// from the per-peer reads the [`RoutingView`] seam exposes.
///
/// The assembly applies the bloom `may_reach` narrowing before building each
/// snapshot, so [`select_best_candidate`] is a pure consumer of an
/// already-narrowed set and names no shell peer type.
pub(crate) struct Candidate {
    /// The candidate peer's node address.
    pub addr: NodeAddr,
    /// Whether the peer's session can currently carry a forward.
    pub can_send: bool,
    /// The outgoing link cost (lower is preferred).
    pub link_cost: f64,
    /// The candidate's tree coordinates, if known.
    pub coords: Option<TreeCoordinate>,
}

/// Assemble the bloom-filter routing candidates toward `dest`.
///
/// Enumerates every peer through the [`RoutingView`] seam, applies the bloom
/// `may_reach` filter, and snapshots each surviving peer's send-eligibility,
/// link cost, and tree coordinates into a [`Candidate`]. Pure over the seam's
/// primitive reads — the shell hands over raw per-peer data only, so all
/// narrowing and snapshotting happens here and [`select_best_candidate`]
/// consumes an already-assembled set. Candidate order follows the seam's
/// enumeration, which the selection ordering renders immaterial (it breaks
/// ties deterministically on `node_addr`).
pub(crate) fn routing_candidates(rv: &impl RoutingView, dest: &NodeAddr) -> Vec<Candidate> {
    rv.peer_addrs()
        .into_iter()
        .filter(|peer| rv.peer_may_reach(peer, dest))
        .map(|peer| Candidate {
            can_send: rv.peer_can_send(&peer),
            link_cost: rv.peer_link_cost(&peer),
            coords: rv.peer_coords(&peer),
            addr: peer,
        })
        .collect()
}

/// Select the best next hop from a set of bloom-filter candidates.
///
/// Uses each candidate's tree-coordinate distance to the destination as the
/// primary metric (after link cost). Only peers strictly closer to the
/// destination than we are (`my_coords`) are eligible — the self-distance
/// check that prevents routing loops.
///
/// Ordering: `(link_cost, distance_to_dest, node_addr)`. Returns the winning
/// peer's address, or `None` when no candidate is send-ready and strictly
/// closer to the destination than us.
pub(crate) fn select_best_candidate(
    candidates: &[Candidate],
    dest_coords: &TreeCoordinate,
    my_coords: &TreeCoordinate,
) -> Option<NodeAddr> {
    let my_distance = my_coords.distance_to(dest_coords);

    let mut best: Option<(&Candidate, f64, usize)> = None;

    for candidate in candidates {
        if !candidate.can_send {
            continue;
        }

        let cost = candidate.link_cost;

        let dist = candidate
            .coords
            .as_ref()
            .map(|pc| pc.distance_to(dest_coords))
            .unwrap_or(usize::MAX);

        // Self-distance check: only consider peers strictly closer
        // to the destination than we are (prevents routing loops)
        if dist >= my_distance {
            continue;
        }

        let dominated = match &best {
            None => true,
            Some((_, best_cost, best_dist)) => {
                cost < *best_cost
                    || (cost == *best_cost && dist < *best_dist)
                    || (cost == *best_cost
                        && dist == *best_dist
                        && candidate.addr < best.as_ref().unwrap().0.addr)
            }
        };

        if dominated {
            best = Some((candidate, cost, dist));
        }
    }

    best.map(|(candidate, _, _)| candidate.addr)
}

/// Classify a transit forward by route class from tree coordinates.
///
/// Pure re-expression of the node-shell classifier. The shell pre-resolves
/// the destination coordinates from its cache (the sole impurity — a
/// read-only cache lookup) and reads `my_coords` / `peer_coords` from tree
/// state, then calls this. Called at the transit chokepoint after
/// `find_next_hop` returns a peer, so the six classes partition
/// `forwarded_packets` exactly. The branch that `find_next_hop` took (bloom
/// vs greedy-tree) is *not* the route class: a peer can be selected by
/// either, so the cut-through splits (`TreeDownCross`, `CrosslinkAscend`) are
/// decided here from coordinates, not from which branch fired.
///
/// Both the tree-down and cross-link branches split on whether the
/// destination is in the chosen peer's subtree; when `dest_coords` is
/// unavailable that test defaults to "not in subtree", i.e. the up-and-over
/// variant (`TreeDownCross` for a descendant peer, `CrosslinkAscend` for a
/// lateral one).
pub(crate) fn classify_forward(
    dest: &NodeAddr,
    chosen_peer: &NodeAddr,
    my_addr: &NodeAddr,
    my_coords: &TreeCoordinate,
    dest_coords: Option<&TreeCoordinate>,
    peer_coords: Option<&TreeCoordinate>,
) -> RouteClass {
    // Degenerate: the next hop is the destination itself (Branch 2).
    if chosen_peer == dest {
        return RouteClass::DirectPeer;
    }

    // Tree-up: the chosen peer is our ancestor.
    if my_coords.has_ancestor(chosen_peer) {
        return RouteClass::TreeUp;
    }

    // Whether the destination is in the chosen peer's subtree. Both the
    // tree-down and cross-link splits below turn on this same test, so it
    // is computed once. On the live transit path the dest coords are
    // always present here: `find_next_hop` looks them up with an early
    // return, so a coord-cache miss yields no next hop to classify (the
    // caller signals `CoordsRequired` instead of forwarding). The miss
    // branch below is therefore defensive — reachable only by direct
    // unit-test calls — and defaults the test to "not in subtree", i.e.
    // the up-and-over variant of whichever branch fires (TreeDownCross for
    // a descendant peer, CrosslinkAscend for a lateral one), matching the
    // original cross-link default-to-ascend.
    let dest_in_peer_subtree =
        dest_coords.is_some_and(|dest_coords| dest_coords.has_ancestor(chosen_peer));

    // Tree-down: the chosen peer is our descendant (we are its ancestor).
    // Split by subtree membership: a dest genuinely below the child is the
    // canonical tree-down; a dest *not* below it means we only forwarded
    // down because the child advertised cross-link reach upward, beyond its
    // own subtree — the dive-to-tree-child cut-through (TreeDownCross).
    if let Some(peer_coords) = peer_coords
        && peer_coords.has_ancestor(my_addr)
    {
        return if dest_in_peer_subtree {
            RouteClass::TreeDown
        } else {
            RouteClass::TreeDownCross
        };
    }

    // Cross-link (lateral): split by whether the destination is in the
    // chosen peer's subtree. Descend = subtree entry; ascend = up-and-over
    // via the node's own cross-link (learned from the peer's split-horizon
    // advertisement, independent of any upward advertisement).
    if dest_in_peer_subtree {
        return RouteClass::CrosslinkDescend;
    }

    RouteClass::CrosslinkAscend
}
