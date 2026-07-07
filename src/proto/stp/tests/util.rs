//! Shared test helpers for the STP primitive unit tests.

use std::collections::BTreeMap;

use crate::NodeAddr;
use crate::proto::stp::{ParentDeclaration, TreeCoordinate, TreeState};

pub(super) fn make_node_addr(val: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = val;
    NodeAddr::from_bytes(bytes)
}

pub(super) fn make_coords(ids: &[u8]) -> TreeCoordinate {
    TreeCoordinate::from_addrs(ids.iter().map(|&v| make_node_addr(v)).collect()).unwrap()
}

/// Build a TreeState with our own coordinates set.
pub(super) fn make_tree_state(my_addr: u8, coord_path: &[u8]) -> TreeState {
    let my_node = make_node_addr(my_addr);
    let mut state = TreeState::new(my_node, 1000);
    let coords = make_coords(coord_path);
    state.root = *coords.root_id();
    state.my_coords = coords;
    state
}

/// Add a peer with given coordinates to the tree state.
pub(super) fn add_peer(state: &mut TreeState, peer_addr: u8, coord_path: &[u8]) {
    let peer = make_node_addr(peer_addr);
    let parent = make_node_addr(coord_path[1]);
    state.update_peer(
        ParentDeclaration::new(peer, parent, 1, 1000),
        make_coords(coord_path),
    );
}

/// Build a peer_costs map from (addr_byte, cost) pairs.
pub(super) fn make_costs(entries: &[(u8, f64)]) -> BTreeMap<NodeAddr, f64> {
    entries
        .iter()
        .map(|&(addr, cost)| (make_node_addr(addr), cost))
        .collect()
}
