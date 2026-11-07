//! The shell audit: whether a set of real nodes holds one coherent
//! settlement, checked from the node's own maps after a test has driven it.
//!
//! [`audit`] reports every breach of four properties; [`assert_coherent`]
//! fails the test on any. The properties, by name:
//!
//! - `OneSession`, two clauses, each its own [`Breach`] variant. First
//!   ([`Breach::Split`]): two nodes that hold each other are on one session,
//!   each end's local index the other's remote index, and a heartbeat sent
//!   now authenticates each way. Counters already recorded do not count, so a
//!   pair whose ends hold different sessions is seen even after frames once
//!   flowed. Second ([`Breach::Unadoptable`]): neither end holds a pending
//!   session that the other end has no handshake able to adopt. Tests call
//!   the audit once both ends are quiet, so a rekey in flight is not caught
//!   halfway.
//! - `RightLink` ([`Breach::RightLink`]): the peer's link record exists and
//!   is the link the session sits on, at the peer's transport and current
//!   address. A node does not record which side of its current session's
//!   handshake it was, so the record's direction is not checked on its own:
//!   after a crossing on master the stale record is the inbound link at
//!   another pair, which this sees. A stale inbound record at the same pair
//!   is the case it cannot see.
//! - `MapsAgree` ([`Breach::MapsAgree`]): the link map against peers and
//!   handshake legs, and the `(transport, address)` index against the link
//!   map. The session-index map, the allocator and the decrypt workers are
//!   checked by `link_index_audit::audit`, which runs first for every node
//!   and panics with its own `{step}:` message rather than reporting. A
//!   `peers_by_index` or lease clause here would be unreachable behind it.
//! - `ConnectionsInUse` ([`Breach::ConnectionsInUse`]): every open TCP
//!   connection is in use by a live link, as its setup address (on master no
//!   link has a bundle). The TCP pool exposes only its counts outside the
//!   transport, so this compares the count of open connections with the
//!   count of distinct live-link setup addresses at which the transport holds
//!   one; it cannot name the connection left over.
//!
//! Exemptions are listed in [`Exempt`], each with a plain reason and the
//! change that removes it. One applies only when the test passes it; the
//! audit never infers one from state.
//!
//! The audit's own tests run with multipath off under their plain names and
//! on as their `_with_multipath_on` siblings; each case's body is a helper
//! taking the setting.

use super::super::link_index_audit;
use super::super::spanning_tree::{TestNode, cleanup_nodes, initiate_handshake};
use super::super::*;
use super::{
    bind_index, crossed_tcp, heartbeat_reaches, loopback_node, pump, resolve_connect, tcp_dial,
    tcp_pair, with_path,
};
use crate::transport::{TransportHandle, TransportId};
use fips_core::proto::rekey::Role;
use std::collections::HashSet;
use std::fmt;

/// A waiver of one property for one node, passed by the test that makes the
/// state it waives.
///
/// Listed, not coded, because nothing on master can name it yet:
///
/// - a candidate path of multipath's bundle, whose connection is open but
///   not yet in use: added with multipath's rebase, waiving
///   `ConnectionsInUse` for the candidate's address;
/// - an accepted TCP connection awaiting its msg1, inside the handshake
///   timeout: a healthy state, but the TCP pool cannot name or age a
///   connection from outside the transport, so it is not coded until the
///   audit can tell it from a leaked one. Every audited test delivers until
///   the nodes are idle first, so none holds one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Exempt {
    /// After crossed dials the smaller node, `node`, moves to its own
    /// outbound session but keeps the inbound link it promoted `peer` on as
    /// the peer's link record, and the connection it dialed is no live
    /// link's setup address. The move renews the link's paths on the pair
    /// the winning msg2 came from, releasing the inbound link's original
    /// path, and with it that link's `(transport, address)` entry. Waives
    /// `RightLink` for `node`'s record of `peer`, `MapsAgree`'s missing
    /// entry for that record's link, and `ConnectionsInUse` for `node`'s
    /// connection at `peer`'s current address. Removed when a crossing
    /// moves the smaller node onto the link it dialed.
    CrossedInbound { node: usize, peer: usize },
    /// A node, `node`, whose own later dial to `peer` completed while it
    /// held the peer moves the session, its indices and its address onto
    /// that dial, but keeps the link the peer was promoted on as the peer's
    /// link record. On another transport or address the record is then at
    /// another pair, and the move's renewal of the link's paths on the
    /// dial's pair releases the record's original path and its
    /// `(transport, address)` entry. Waives `RightLink` for `node`'s record
    /// of `peer`, and `MapsAgree`'s missing entry for that record's link.
    /// Removed when that move re-keys the peer's link record to the dial's
    /// link.
    MovedOwnDial { node: usize, peer: usize },
    /// After `node`'s own later dial to `peer` at the address of the link
    /// it holds the peer on completes and moves the session, the dial's
    /// link is retired and takes the `(transport, address)` entry with it,
    /// so the held link is left with none. Waives `MapsAgree`'s missing
    /// entry for the link `node` holds `peer` on. Removed when retiring the
    /// dial's link leaves the held link's entry in place.
    HeldLinkEntry { node: usize, peer: usize },
}

/// One breach of a property, naming the node (by index in the test's
/// slice) whose maps show it.
#[derive(Clone, PartialEq, Eq)]
pub(super) enum Breach {
    /// `OneSession`, first clause: `node` and `peer` hold each other, but
    /// not on one session, or a heartbeat sent now does not authenticate.
    Split {
        node: usize,
        peer: usize,
        /// Each end's (local, remote) index, `node`'s first.
        indices: [(Option<SessionIndex>, Option<SessionIndex>); 2],
        /// Whether a heartbeat sent now authenticated, `node` to `peer` and
        /// back.
        fresh: [bool; 2],
    },
    /// `OneSession`, first clause: `node` holds `peer`, which does not hold
    /// it.
    OneSided { node: usize, peer: usize },
    /// `OneSession`, second clause: `node` holds a pending session for
    /// `peer`, from the `role` side of a rekey, that `peer` has no pending,
    /// current or in-flight handshake able to adopt.
    Unadoptable {
        node: usize,
        peer: usize,
        role: Role,
        /// The pending session's (local, remote) index.
        pending: (Option<SessionIndex>, Option<SessionIndex>),
    },
    /// `RightLink`: `node`'s link record for `peer` is missing, or is not at
    /// the peer's transport and current address.
    RightLink {
        node: usize,
        peer: usize,
        /// The record: direction, transport, remote address.
        record: Option<(LinkDirection, TransportId, TransportAddr)>,
        /// Where `node` holds `peer`: transport and current address.
        pair: (Option<TransportId>, Option<TransportAddr>),
    },
    /// `MapsAgree`: `node`'s link map or `(transport, address)` index
    /// disagrees with its peers and handshake legs at `link`.
    MapsAgree {
        node: usize,
        link: LinkId,
        what: &'static str,
    },
    /// `ConnectionsInUse`: `node`'s TCP transport `transport` holds `open`
    /// connections, (inbound, outbound), but only `used` distinct live-link
    /// setup addresses with a connection.
    ConnectionsInUse {
        node: usize,
        transport: TransportId,
        open: (u64, u64),
        used: u64,
    },
}

impl Breach {
    /// The node whose maps show the breach.
    pub(super) fn node(&self) -> usize {
        match self {
            Breach::Split { node, .. }
            | Breach::OneSided { node, .. }
            | Breach::Unadoptable { node, .. }
            | Breach::RightLink { node, .. }
            | Breach::MapsAgree { node, .. }
            | Breach::ConnectionsInUse { node, .. } => *node,
        }
    }
}

/// Written out rather than derived, so every field is read: a derived
/// `Debug` does not count as a read, and a field read by nothing else would
/// fail the dead-code lint.
impl fmt::Debug for Breach {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Breach::Split {
                node,
                peer,
                indices,
                fresh,
            } => f
                .debug_struct("Split")
                .field("node", node)
                .field("peer", peer)
                .field("indices", indices)
                .field("fresh", fresh)
                .finish(),
            Breach::OneSided { node, peer } => f
                .debug_struct("OneSided")
                .field("node", node)
                .field("peer", peer)
                .finish(),
            Breach::Unadoptable {
                node,
                peer,
                role,
                pending,
            } => f
                .debug_struct("Unadoptable")
                .field("node", node)
                .field("peer", peer)
                .field("role", role)
                .field("pending", pending)
                .finish(),
            Breach::RightLink {
                node,
                peer,
                record,
                pair,
            } => f
                .debug_struct("RightLink")
                .field("node", node)
                .field("peer", peer)
                .field("record", record)
                .field("pair", pair)
                .finish(),
            Breach::MapsAgree { node, link, what } => f
                .debug_struct("MapsAgree")
                .field("node", node)
                .field("link", link)
                .field("what", what)
                .finish(),
            Breach::ConnectionsInUse {
                node,
                transport,
                open,
                used,
            } => f
                .debug_struct("ConnectionsInUse")
                .field("node", node)
                .field("transport", transport)
                .field("open", open)
                .field("used", used)
                .finish(),
        }
    }
}

/// Check every node and report each breach, after running
/// `link_index_audit::audit` on each node (which panics on its own). Sends
/// one heartbeat each way between every pair that holds each other, and
/// delivers until idle, so it changes link counters but no settlement.
pub(super) async fn audit(nodes: &mut [TestNode], exempt: &[Exempt]) -> Vec<Breach> {
    for (i, tn) in nodes.iter().enumerate() {
        link_index_audit::audit(&tn.node, &format!("node {i}"));
    }
    let mut breaches = Vec::new();
    one_session(nodes, &mut breaches).await;
    for i in 0..nodes.len() {
        right_link(nodes, i, exempt, &mut breaches);
        maps_agree(nodes, i, exempt, &mut breaches);
        connections_in_use(nodes, i, exempt, &mut breaches).await;
    }
    breaches
}

/// Fail the test, marked as the defect, if [`audit`] reports any breach at
/// `step`.
pub(super) async fn assert_coherent(nodes: &mut [TestNode], exempt: &[Exempt], step: &str) {
    let breaches = audit(nodes, exempt).await;
    assert!(
        breaches.is_empty(),
        "defect: incoherent at {step}: {breaches:#?}"
    );
}

/// The index in `nodes` of the node whose address is `addr`.
fn index_of(nodes: &[TestNode], addr: &NodeAddr) -> Option<usize> {
    nodes.iter().position(|tn| tn.node.node_addr() == addr)
}

/// `OneSession`, both clauses, over every pair of nodes.
async fn one_session(nodes: &mut [TestNode], breaches: &mut Vec<Breach>) {
    for a in 0..nodes.len() {
        for b in a + 1..nodes.len() {
            let a_addr = *nodes[a].node.node_addr();
            let b_addr = *nodes[b].node.node_addr();
            let at_a = nodes[a].node.get_peer(&b_addr).is_some();
            let at_b = nodes[b].node.get_peer(&a_addr).is_some();
            match (at_a, at_b) {
                (false, false) => continue,
                (true, false) => {
                    breaches.push(Breach::OneSided { node: a, peer: b });
                    continue;
                }
                (false, true) => {
                    breaches.push(Breach::OneSided { node: b, peer: a });
                    continue;
                }
                (true, true) => {}
            }
            // The second clause first, before the audit's own heartbeats
            // can step either end's rekey.
            unadoptable(nodes, a, b, breaches);
            unadoptable(nodes, b, a, breaches);
            let indices = [indices_of(nodes, a, b), indices_of(nodes, b, a)];
            let complementary = indices[0].0.is_some()
                && indices[0].0 == indices[1].1
                && indices[0].1 == indices[1].0;
            let fresh = [
                heartbeat_reaches(nodes, a, b).await.is_ok(),
                heartbeat_reaches(nodes, b, a).await.is_ok(),
            ];
            if !complementary || !fresh[0] || !fresh[1] {
                breaches.push(Breach::Split {
                    node: a,
                    peer: b,
                    indices,
                    fresh,
                });
            }
        }
    }
}

/// `nodes[at]`'s (local, remote) index on its current session with
/// `nodes[peer]`.
fn indices_of(
    nodes: &[TestNode],
    at: usize,
    peer: usize,
) -> (Option<SessionIndex>, Option<SessionIndex>) {
    let peer_addr = *nodes[peer].node.node_addr();
    nodes[at]
        .node
        .get_peer(&peer_addr)
        .map(|p| (p.our_index(), p.their_index()))
        .unwrap_or((None, None))
}

/// `OneSession`, second clause, for `nodes[at]`'s pending session with
/// `nodes[peer]`: the peer must hold a pending session complementing it,
/// be on it already, or have a rekey in flight whose local index is the
/// pending's remote one.
fn unadoptable(nodes: &[TestNode], at: usize, peer: usize, breaches: &mut Vec<Breach>) {
    let at_addr = *nodes[at].node.node_addr();
    let peer_addr = *nodes[peer].node.node_addr();
    let Some(mine) = nodes[at].node.get_peer(&peer_addr) else {
        return;
    };
    let Some(role) = mine.pending_role() else {
        return;
    };
    let pending = (mine.pending_our_index(), mine.pending_their_index());
    let Some(theirs) = nodes[peer].node.get_peer(&at_addr) else {
        return;
    };
    let matches = |ours: Option<SessionIndex>, their: Option<SessionIndex>| {
        ours.is_some() && ours == pending.1 && their == pending.0
    };
    let adoptable = matches(theirs.pending_our_index(), theirs.pending_their_index())
        || matches(theirs.our_index(), theirs.their_index())
        || (theirs.rekey_in_progress()
            && theirs.rekey_our_index().is_some()
            && theirs.rekey_our_index() == pending.1);
    if !adoptable {
        breaches.push(Breach::Unadoptable {
            node: at,
            peer,
            role,
            pending,
        });
    }
}

/// `RightLink` for every peer `nodes[i]` holds among the test's nodes.
fn right_link(nodes: &[TestNode], i: usize, exempt: &[Exempt], breaches: &mut Vec<Breach>) {
    let node = &nodes[i].node;
    for (addr, peer) in node.peers.iter() {
        let Some(p) = index_of(nodes, addr) else {
            continue;
        };
        if exempt.contains(&Exempt::CrossedInbound { node: i, peer: p })
            || exempt.contains(&Exempt::MovedOwnDial { node: i, peer: p })
        {
            continue;
        }
        let record = node
            .links
            .get(&peer.link_id())
            .map(|k| (k.direction(), k.transport_id(), k.remote_addr().clone()));
        let pair = (peer.transport_id(), peer.current_addr().cloned());
        let at_pair = matches!(
            (&record, &pair),
            (Some((_, tid, remote)), (Some(t), Some(a))) if tid == t && remote == a
        );
        if !at_pair {
            breaches.push(Breach::RightLink {
                node: i,
                peer: p,
                record,
                pair,
            });
        }
    }
}

/// `MapsAgree` for `node`: every link is named by a peer or a handshake
/// leg; every peer's and leg's link is in the link map; and the
/// `(transport, address)` index names each live link at its own pair and
/// nothing else.
fn maps_agree(nodes: &[TestNode], i: usize, exempt: &[Exempt], breaches: &mut Vec<Breach>) {
    let node = &nodes[i].node;
    let waived: HashSet<LinkId> = exempt
        .iter()
        .filter_map(|e| match *e {
            Exempt::HeldLinkEntry { node: n, peer }
            | Exempt::CrossedInbound { node: n, peer }
            | Exempt::MovedOwnDial { node: n, peer }
                if n == i =>
            {
                node.get_peer(nodes[peer].node.node_addr())
                    .map(|p| p.link_id())
            }
            _ => None,
        })
        .collect();
    let mut named: HashSet<LinkId> = node.peers.values().map(|p| p.link_id()).collect();
    named.extend(node.peer_machines.keys().copied());
    named.extend(node.pending_outbound.values().copied());
    for link in node.links.keys() {
        if !named.contains(link) {
            breaches.push(Breach::MapsAgree {
                node: i,
                link: *link,
                what: "a link no peer or handshake leg names",
            });
        }
    }
    for link in node.pending_outbound.values() {
        if !node.links.contains_key(link) {
            breaches.push(Breach::MapsAgree {
                node: i,
                link: *link,
                what: "a pending dial whose link is not in the link map",
            });
        }
    }
    for ((tid, remote), link) in node.links.index().iter() {
        let right = node
            .links
            .get(link)
            .is_some_and(|k| k.transport_id() == *tid && k.remote_addr() == remote);
        if !right {
            breaches.push(Breach::MapsAgree {
                node: i,
                link: *link,
                what: "an index entry naming a link not at its pair",
            });
        }
    }
    for (link, k) in node.links.iter() {
        let key = (k.transport_id(), k.remote_addr().clone());
        if node.links.index().get(&key) != Some(link) && !waived.contains(link) {
            breaches.push(Breach::MapsAgree {
                node: i,
                link: *link,
                what: "a live link with no index entry at its pair",
            });
        }
    }
}

/// `ConnectionsInUse` for each TCP transport of `nodes[i]`.
async fn connections_in_use(
    nodes: &[TestNode],
    i: usize,
    exempt: &[Exempt],
    breaches: &mut Vec<Breach>,
) {
    let node = &nodes[i].node;
    for (tid, handle) in node.transports.iter() {
        let TransportHandle::Tcp(tcp) = handle else {
            continue;
        };
        let s = tcp.stats().snapshot();
        let open = (s.pool_inbound, s.pool_outbound);
        let mut addrs: HashSet<TransportAddr> = node
            .links
            .values()
            .filter(|k| k.transport_id() == *tid)
            .map(|k| k.remote_addr().clone())
            .collect();
        for e in exempt {
            let Exempt::CrossedInbound { node: n, peer } = *e else {
                continue;
            };
            if n != i {
                continue;
            }
            let peer_addr = *nodes[peer].node.node_addr();
            if let Some(p) = node.get_peer(&peer_addr)
                && p.transport_id() == Some(*tid)
                && let Some(at) = p.current_addr()
            {
                addrs.insert(at.clone());
            }
        }
        let mut used = 0;
        for addr in &addrs {
            if handle.has_connection(addr).await {
                used += 1;
            }
        }
        if open.0 + open.1 > used {
            breaches.push(Breach::ConnectionsInUse {
                node: i,
                transport: *tid,
                open,
                used,
            });
        }
    }
}

/// A single loopback dial, delivered until idle, is coherent.
async fn loopback_passes(on: bool) {
    let mut nodes = vec![loopback_node(on).await, loopback_node(on).await];
    initiate_handshake(&mut nodes, 0, 1).await;
    pump(&mut nodes).await;
    let a1 = *nodes[1].node.node_addr();
    assert!(
        nodes[0].node.get_peer(&a1).is_some(),
        "precondition: the dial promoted the peer"
    );
    assert_coherent(&mut nodes, &[], "a single loopback dial").await;
    cleanup_nodes(&mut nodes).await;
}

/// [`loopback_passes`] with multipath off.
#[tokio::test]
async fn the_audit_passes_a_single_loopback_dial() {
    loopback_passes(false).await;
}

/// [`loopback_passes`] with multipath on.
#[tokio::test]
async fn the_audit_passes_a_single_loopback_dial_with_multipath_on() {
    loopback_passes(true).await;
}

/// One TCP dial from `nodes[d]`, delivered until idle.
async fn single_tcp_dial(on: bool, zero_smaller: bool, d: usize) -> Vec<TestNode> {
    let mut nodes = tcp_pair(on, zero_smaller).await;
    tcp_dial(&mut nodes, d, 1 - d).await;
    resolve_connect(&mut nodes[d]).await;
    pump(&mut nodes).await;
    let r = *nodes[1 - d].node.node_addr();
    assert!(
        nodes[d].node.get_peer(&r).is_some(),
        "precondition: the dial promoted the peer"
    );
    nodes
}

/// A single TCP dial from the larger node is coherent.
async fn larger_passes(on: bool) {
    let mut nodes = single_tcp_dial(on, true, 1).await;
    assert_coherent(&mut nodes, &[], "a TCP dial from the larger node").await;
    cleanup_nodes(&mut nodes).await;
}

/// [`larger_passes`] with multipath off.
#[tokio::test]
async fn the_audit_passes_a_single_tcp_dial_from_the_larger_node() {
    larger_passes(false).await;
}

/// [`larger_passes`] with multipath on.
#[tokio::test]
async fn the_audit_passes_a_single_tcp_dial_from_the_larger_node_with_multipath_on() {
    larger_passes(true).await;
}

/// A single TCP dial from the smaller node is coherent.
async fn smaller_passes(on: bool) {
    let mut nodes = single_tcp_dial(on, true, 0).await;
    assert_coherent(&mut nodes, &[], "a TCP dial from the smaller node").await;
    cleanup_nodes(&mut nodes).await;
}

/// [`smaller_passes`] with multipath off.
#[tokio::test]
async fn the_audit_passes_a_single_tcp_dial_from_the_smaller_node() {
    smaller_passes(false).await;
}

/// [`smaller_passes`] with multipath on.
#[tokio::test]
async fn the_audit_passes_a_single_tcp_dial_from_the_smaller_node_with_multipath_on() {
    smaller_passes(true).await;
}

/// The breaches in `breaches` that `node`'s maps show.
fn at_node(breaches: &[Breach], node: usize) -> Vec<&Breach> {
    breaches.iter().filter(|b| b.node() == node).collect()
}

/// After crossed TCP dials, with no exemption passed, the audit flags the
/// smaller node's link record for the larger node (the inbound link it was
/// promoted on, at another pair than the one it holds the peer at), and its
/// connection to the peer, which no live link uses.
async fn exemption_needed(on: bool) {
    let (mut nodes, s, l) = crossed_tcp(on, true).await;
    let breaches = audit(&mut nodes, &[]).await;
    let at_s = at_node(&breaches, s);
    assert!(
        at_s.iter().any(|b| matches!(
            b,
            Breach::RightLink { peer, record: Some((LinkDirection::Inbound, _, _)), .. } if *peer == l
        )),
        "defect: the smaller node's inbound record for the larger is not flagged: {breaches:#?}"
    );
    assert!(
        at_s.iter().any(|b| matches!(
            b,
            Breach::ConnectionsInUse {
                open: (0, 1),
                used: 0,
                ..
            }
        )),
        "defect: the smaller node's unused connection is not flagged: {breaches:#?}"
    );
    cleanup_nodes(&mut nodes).await;
}

/// [`exemption_needed`] with multipath off.
#[tokio::test]
async fn the_audit_without_its_crossing_exemption_flags_the_smaller_nodes_inbound_link_record() {
    exemption_needed(false).await;
}

/// [`exemption_needed`] with multipath on.
#[tokio::test]
async fn the_audit_without_its_crossing_exemption_flags_the_smaller_nodes_inbound_link_record_with_multipath_on()
 {
    exemption_needed(true).await;
}

/// The crossing exemption waives the named node's record and connection
/// only: naming the smaller node clears its breaches, naming the larger
/// node leaves them.
async fn exemption_scoped(on: bool) {
    let (mut nodes, s, l) = crossed_tcp(on, true).await;
    let named = audit(&mut nodes, &[Exempt::CrossedInbound { node: s, peer: l }]).await;
    assert!(
        named.is_empty(),
        "defect: with the smaller node named the crossing is still flagged: {named:#?}"
    );
    let other = audit(&mut nodes, &[Exempt::CrossedInbound { node: l, peer: s }]).await;
    assert!(
        other
            .iter()
            .any(|b| matches!(b, Breach::RightLink { node, peer, .. } if *node == s && *peer == l)),
        "defect: naming the larger node waived the smaller node's record: {other:#?}"
    );
    cleanup_nodes(&mut nodes).await;
}

/// [`exemption_scoped`] with multipath off.
#[tokio::test]
async fn the_crossing_exemption_waives_only_the_named_nodes_record() {
    exemption_scoped(false).await;
}

/// [`exemption_scoped`] with multipath on.
#[tokio::test]
async fn the_crossing_exemption_waives_only_the_named_nodes_record_with_multipath_on() {
    exemption_scoped(true).await;
}

/// A link left in the link map with no peer or handshake leg naming it, the
/// shape of a stale link-map entry after a rekey, is flagged by the audit's
/// own clause (the index audit does not read the link map, so it does not
/// panic first).
async fn stale_flagged(on: bool) {
    let mut nodes = vec![loopback_node(on).await, loopback_node(on).await];
    initiate_handshake(&mut nodes, 0, 1).await;
    pump(&mut nodes).await;
    let stale = nodes[0].node.allocate_link_id();
    let remote = nodes[1].addr.clone();
    let tid = nodes[0].transport_id;
    nodes[0].node.links.raw().insert(
        stale,
        Link::connectionless(
            stale,
            tid,
            remote,
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    let breaches = audit(&mut nodes, &[]).await;
    assert!(
        breaches.iter().any(|b| matches!(
            b,
            Breach::MapsAgree { node: 0, link, what } if *link == stale && what.starts_with("a link no peer")
        )),
        "defect: the stale link-map entry is not flagged: {breaches:#?}"
    );
    cleanup_nodes(&mut nodes).await;
}

/// [`stale_flagged`] with multipath off.
#[tokio::test]
async fn the_audit_flags_a_link_map_entry_no_peer_or_leg_uses() {
    stale_flagged(false).await;
}

/// [`stale_flagged`] with multipath on.
#[tokio::test]
async fn the_audit_flags_a_link_map_entry_no_peer_or_leg_uses_with_multipath_on() {
    stale_flagged(true).await;
}

/// An index-map entry for an index no link machine binds panics inside the
/// audit, through the index audit it runs first.
async fn unbound_panics(on: bool) {
    let mut nodes = vec![loopback_node(on).await, loopback_node(on).await];
    initiate_handshake(&mut nodes, 0, 1).await;
    pump(&mut nodes).await;
    let peer = *nodes[1].node.node_addr();
    let tid = nodes[0].transport_id;
    bind_index(&mut nodes[0].node, tid, 0x7fff_fff0, peer);
    let _ = audit(&mut nodes, &[]).await;
}

/// [`unbound_panics`] with multipath off.
#[tokio::test]
#[should_panic(expected = "peers_by_index must map exactly")]
async fn the_index_audit_inside_the_audit_panics_on_an_unbound_index() {
    unbound_panics(false).await;
}

/// [`unbound_panics`] with multipath on.
#[tokio::test]
#[should_panic(expected = "peers_by_index must map exactly")]
async fn the_index_audit_inside_the_audit_panics_on_an_unbound_index_with_multipath_on() {
    unbound_panics(true).await;
}

/// A TCP connection opened with no handshake on it, which no link uses, is
/// flagged at the node that opened it.
async fn open_flagged(on: bool) {
    let mut nodes = tcp_pair(on, true).await;
    let at = nodes[1].addr.clone();
    let tid = nodes[0].transport_id;
    let Some(TransportHandle::Tcp(tcp)) = nodes[0].node.transports.get(&tid) else {
        panic!("precondition: node 0 has its TCP transport");
    };
    tcp.connect_async(&at)
        .await
        .expect("precondition: the connect starts");
    let mut connected = false;
    for _ in 0..200 {
        if tcp.has_connection(&at).await
            || matches!(
                tcp.connection_state_sync(&at),
                crate::transport::ConnectionState::Connected
            )
        {
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(connected, "precondition: the connection opened within 2 s");
    let breaches = audit(&mut nodes, &[]).await;
    assert!(
        breaches.iter().any(|b| matches!(
            b,
            Breach::ConnectionsInUse { node: 0, transport, open: (0, 1), used: 0 } if *transport == tid
        )),
        "defect: the unused connection is not flagged: {breaches:#?}"
    );
    cleanup_nodes(&mut nodes).await;
}

/// [`open_flagged`] with multipath off.
#[tokio::test]
async fn the_audit_flags_an_open_connection_no_link_uses() {
    open_flagged(false).await;
}

/// [`open_flagged`] with multipath on.
#[tokio::test]
async fn the_audit_flags_an_open_connection_no_link_uses_with_multipath_on() {
    open_flagged(true).await;
}

/// A rekey stopped with both ends pending, the initiator on its pending
/// and the responder on its own, is not flagged by `OneSession`'s second
/// clause: each end's pending has a complement at the other.
async fn pending_passes(on: bool) {
    use super::super::rekey_parity::{
        age_link, linked_pair, rekey_config, rekey_to_pending, trigger_age,
    };
    let config = with_path(rekey_config(60), on);
    let mut nodes = linked_pair(config.clone(), config).await;
    age_link(&mut nodes, 0, 1, trigger_age());
    rekey_to_pending(&mut nodes, 0, 1).await;
    let a1 = *nodes[1].node.node_addr();
    assert_eq!(
        nodes[0].node.get_peer(&a1).and_then(|p| p.pending_role()),
        Some(Role::Initiator),
        "precondition: node 0 holds an initiator pending"
    );
    let breaches = audit(&mut nodes, &[]).await;
    let unadoptable: Vec<_> = breaches
        .iter()
        .filter(|b| matches!(b, Breach::Unadoptable { .. }))
        .collect();
    assert!(
        unadoptable.is_empty(),
        "defect: a two-way pending is flagged as unadoptable: {unadoptable:#?}"
    );
    cleanup_nodes(&mut nodes).await;
}

/// [`pending_passes`] with multipath off.
#[tokio::test]
async fn the_audit_passes_a_rekey_left_at_both_ends_pending() {
    pending_passes(false).await;
}

/// [`pending_passes`] with multipath on.
#[tokio::test]
async fn the_audit_passes_a_rekey_left_at_both_ends_pending_with_multipath_on() {
    pending_passes(true).await;
}
