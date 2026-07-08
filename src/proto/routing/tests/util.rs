//! Shared test helpers for the routing subsystem unit tests.

use crate::proto::link::SessionDatagramRef;
use crate::proto::routing::{NextHop, RoutingView};
use crate::testutil::make_node_addr;
use crate::{NodeAddr, TreeCoordinate};

/// A mock peer for the candidate-assembly seam: the set of destinations its
/// bloom filter reaches, its send state, link cost, and tree coordinates.
pub(super) struct MockPeer {
    pub(super) addr: NodeAddr,
    pub(super) reach: Vec<NodeAddr>,
    pub(super) can_send: bool,
    pub(super) link_cost: f64,
    pub(super) coords: Option<TreeCoordinate>,
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

    fn peer(&self, addr: &NodeAddr) -> Option<&MockPeer> {
        self.peers.iter().find(|p| p.addr == *addr)
    }
}

impl RoutingView for MockRoutingView {
    fn is_congested(&self, _next_hop: &NodeAddr) -> bool {
        self.congested
    }
    fn cached_coords(&self, dest: &NodeAddr, _now_ms: u64) -> Option<TreeCoordinate> {
        self.coords
            .iter()
            .find(|(addr, _)| addr == dest)
            .map(|(_, coords)| coords.clone())
    }
    fn peer_addrs(&self) -> Vec<NodeAddr> {
        self.peers.iter().map(|p| p.addr).collect()
    }
    fn peer_may_reach(&self, peer: &NodeAddr, dest: &NodeAddr) -> bool {
        self.peer(peer).is_some_and(|p| p.reach.contains(dest))
    }
    fn peer_can_send(&self, peer: &NodeAddr) -> bool {
        self.peer(peer).is_some_and(|p| p.can_send)
    }
    fn peer_link_cost(&self, peer: &NodeAddr) -> f64 {
        self.peer(peer).map_or(f64::INFINITY, |p| p.link_cost)
    }
    fn peer_coords(&self, peer: &NodeAddr) -> Option<TreeCoordinate> {
        self.peer(peer).and_then(|p| p.coords.clone())
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
