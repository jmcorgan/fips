//! Shared test helpers for the routing subsystem unit tests.

use crate::proto::link::SessionDatagramRef;
use crate::proto::routing::{NextHop, RoutingView};
use crate::testutil::make_node_addr;
use crate::{NodeAddr, TreeCoordinate};

/// A mock peer for the routing seam: the set of destinations its bloom filter
/// reaches, its send state, link cost, tree coordinates and node profile.
#[derive(Clone)]
pub(super) struct MockPeer {
    pub(super) addr: NodeAddr,
    pub(super) reach: Vec<NodeAddr>,
    pub(super) can_send: bool,
    pub(super) link_cost: f64,
    pub(super) coords: Option<TreeCoordinate>,
    pub(super) is_full: bool,
}

/// Mock routing view: a fixed congestion answer, a small coord table, and a
/// set of peers the candidate assembly enumerates through the seam.
pub(super) struct MockRoutingView {
    pub(super) congested: bool,
    pub(super) coords: Vec<(NodeAddr, TreeCoordinate)>,
    pub(super) peers: Vec<MockPeer>,
}

impl MockRoutingView {
    pub(super) fn new(congested: bool) -> Self {
        Self {
            congested,
            coords: Vec::new(),
            peers: Vec::new(),
        }
    }
}

impl RoutingView for MockRoutingView {
    type Peer<'a>
        = &'a MockPeer
    where
        Self: 'a;

    fn is_congested(&self, _next_hop: &NodeAddr) -> bool {
        self.congested
    }
    fn cached_coords(&self, dest: &NodeAddr, _now_ms: u64) -> Option<TreeCoordinate> {
        self.coords
            .iter()
            .find(|(addr, _)| addr == dest)
            .map(|(_, coords)| coords.clone())
    }
    fn for_each_peer<'a>(&'a self, mut visitor: impl FnMut(Self::Peer<'a>)) {
        for peer in &self.peers {
            visitor(peer);
        }
    }
    fn peer_addr<'a>(&'a self, peer: Self::Peer<'a>) -> NodeAddr {
        peer.addr
    }
    fn peer_may_reach<'a>(&'a self, peer: Self::Peer<'a>, dest: &NodeAddr) -> bool {
        peer.reach.contains(dest)
    }
    fn peer_can_send<'a>(&'a self, peer: Self::Peer<'a>) -> bool {
        peer.can_send
    }
    fn peer_link_cost<'a>(&'a self, peer: Self::Peer<'a>) -> f64 {
        peer.link_cost
    }
    fn peer_coords<'a>(&'a self, peer: Self::Peer<'a>) -> Option<&'a TreeCoordinate> {
        peer.coords.as_ref()
    }
    fn peer_is_full<'a>(&'a self, peer: Self::Peer<'a>) -> bool {
        peer.is_full
    }
}

/// Build a borrowed datagram with the given TTL and destination. The source is
/// a fixed address and the payload is empty (routing decisions never inspect
/// it); `path_mtu` starts at the maximum so tests can observe the min-fold.
pub(super) fn make_datagram_ref(ttl: u8, dest: NodeAddr) -> SessionDatagramRef<'static> {
    SessionDatagramRef {
        src_addr: make_node_addr(0x01),
        dest_addr: dest,
        ttl,
        path_mtu: u16::MAX,
        payload: &[],
    }
}

pub(super) fn make_next_hop(addr: NodeAddr, link_mtu: u16) -> NextHop {
    NextHop { addr, link_mtu }
}

pub(super) fn make_coords(ids: &[u8]) -> TreeCoordinate {
    TreeCoordinate::from_addrs(ids.iter().map(|&v| make_node_addr(v)).collect()).unwrap()
}
