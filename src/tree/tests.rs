use super::*;

fn make_node_addr(val: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = val;
    NodeAddr::from_bytes(bytes)
}

fn make_coords(ids: &[u8]) -> TreeCoordinate {
    TreeCoordinate::from_addrs(ids.iter().map(|&v| make_node_addr(v)).collect()).unwrap()
}

// ===== TreeCoordinate Tests =====

#[test]
fn test_tree_coordinate_root() {
    let root_id = make_node_addr(1);
    let coord = TreeCoordinate::root(root_id);

    assert!(coord.is_root());
    assert_eq!(coord.depth(), 0);
    assert_eq!(coord.node_addr(), &root_id);
    assert_eq!(coord.root_id(), &root_id);
    assert_eq!(coord.parent_id(), &root_id);
}

#[test]
fn test_tree_coordinate_path() {
    let node = make_node_addr(1);
    let parent = make_node_addr(2);
    let root = make_node_addr(3);

    let coord = make_coords(&[1, 2, 3]);

    assert!(!coord.is_root());
    assert_eq!(coord.depth(), 2);
    assert_eq!(coord.node_addr(), &node);
    assert_eq!(coord.parent_id(), &parent);
    assert_eq!(coord.root_id(), &root);
}

#[test]
fn test_tree_coordinate_empty_fails() {
    let result = TreeCoordinate::from_addrs(vec![]);
    assert!(matches!(result, Err(TreeError::EmptyCoordinate)));
}

#[test]
fn test_tree_coordinate_entries_metadata() {
    let node = make_node_addr(1);
    let root = make_node_addr(0);

    let coord = TreeCoordinate::new(vec![
        CoordEntry::new(node, 5, 1000),
        CoordEntry::new(root, 1, 500),
    ])
    .unwrap();

    assert_eq!(coord.entries()[0].sequence, 5);
    assert_eq!(coord.entries()[0].timestamp, 1000);
    assert_eq!(coord.entries()[1].sequence, 1);
    assert_eq!(coord.entries()[1].timestamp, 500);
}

#[test]
fn test_tree_distance_same_node() {
    let node = make_node_addr(1);
    let coord = TreeCoordinate::root(node);

    assert_eq!(coord.distance_to(&coord), 0);
}

#[test]
fn test_tree_distance_siblings() {
    let coord_a = make_coords(&[1, 0]);
    let coord_b = make_coords(&[2, 0]);

    // a -> root -> b = 2 hops
    assert_eq!(coord_a.distance_to(&coord_b), 2);
}

#[test]
fn test_tree_distance_ancestor() {
    let coord_parent = make_coords(&[1, 0]);
    let coord_child = make_coords(&[2, 1, 0]);

    // child -> parent = 1 hop
    assert_eq!(coord_child.distance_to(&coord_parent), 1);
}

#[test]
fn test_tree_distance_cousins() {
    // Tree structure:
    //       root(0)
    //      /    \
    //     a(1)   b(2)
    //    /        \
    //   c(3)       d(4)
    let coord_c = make_coords(&[3, 1, 0]);
    let coord_d = make_coords(&[4, 2, 0]);

    // c -> a -> root -> b -> d = 4 hops
    assert_eq!(coord_c.distance_to(&coord_d), 4);
}

#[test]
fn test_tree_distance_different_roots() {
    let coord1 = TreeCoordinate::root(make_node_addr(1));
    let coord2 = TreeCoordinate::root(make_node_addr(2));

    assert_eq!(coord1.distance_to(&coord2), usize::MAX);
}

#[test]
fn test_has_ancestor() {
    let root = make_node_addr(0);
    let parent = make_node_addr(1);
    let child = make_node_addr(2);

    let coord = make_coords(&[2, 1, 0]);

    assert!(coord.has_ancestor(&parent));
    assert!(coord.has_ancestor(&root));
    assert!(!coord.has_ancestor(&child)); // self is not an ancestor
}

#[test]
fn test_contains() {
    let root = make_node_addr(0);
    let parent = make_node_addr(1);
    let child = make_node_addr(2);
    let other = make_node_addr(99);

    let coord = make_coords(&[2, 1, 0]);

    assert!(coord.contains(&child));
    assert!(coord.contains(&parent));
    assert!(coord.contains(&root));
    assert!(!coord.contains(&other));
}

#[test]
fn test_ancestor_at() {
    let root = make_node_addr(0);
    let parent = make_node_addr(1);
    let child = make_node_addr(2);

    let coord = make_coords(&[2, 1, 0]);

    assert_eq!(coord.ancestor_at(0), Some(&child));
    assert_eq!(coord.ancestor_at(1), Some(&parent));
    assert_eq!(coord.ancestor_at(2), Some(&root));
    assert_eq!(coord.ancestor_at(3), None);
}

#[test]
fn test_lca() {
    let root = make_node_addr(0);
    let a = make_node_addr(1);

    // c under a, d under b, both under root
    let coord_c = make_coords(&[3, 1, 0]);
    let coord_d = make_coords(&[4, 2, 0]);

    assert_eq!(coord_c.lca(&coord_d), Some(&root));

    // c and a share ancestry through a and root
    let coord_a = make_coords(&[1, 0]);
    assert_eq!(coord_c.lca(&coord_a), Some(&a));
}

// ===== ParentDeclaration Tests =====

#[test]
fn test_parent_declaration_new() {
    let node = make_node_addr(1);
    let parent = make_node_addr(2);

    let decl = ParentDeclaration::new(node, parent, 1, 1000);

    assert_eq!(decl.node_addr(), &node);
    assert_eq!(decl.parent_id(), &parent);
    assert_eq!(decl.sequence(), 1);
    assert_eq!(decl.timestamp(), 1000);
    assert!(!decl.is_root());
    assert!(!decl.is_signed());
}

#[test]
fn test_parent_declaration_self_root() {
    let node = make_node_addr(1);

    let decl = ParentDeclaration::self_root(node, 5, 2000);

    assert!(decl.is_root());
    assert_eq!(decl.node_addr(), decl.parent_id());
}

#[test]
fn test_parent_declaration_freshness() {
    let node = make_node_addr(1);
    let parent = make_node_addr(2);

    let old_decl = ParentDeclaration::new(node, parent, 1, 1000);
    let new_decl = ParentDeclaration::new(node, parent, 2, 2000);

    assert!(new_decl.is_fresher_than(&old_decl));
    assert!(!old_decl.is_fresher_than(&new_decl));
    assert!(!old_decl.is_fresher_than(&old_decl));
}

#[test]
fn test_parent_declaration_signing_bytes() {
    let node = make_node_addr(1);
    let parent = make_node_addr(2);

    let decl = ParentDeclaration::new(node, parent, 100, 1234567890);
    let bytes = decl.signing_bytes();

    // Should be 48 bytes: 16 + 16 + 8 + 8
    assert_eq!(bytes.len(), 48);

    // Verify structure
    assert_eq!(&bytes[0..16], node.as_bytes());
    assert_eq!(&bytes[16..32], parent.as_bytes());
    assert_eq!(&bytes[32..40], &100u64.to_le_bytes());
    assert_eq!(&bytes[40..48], &1234567890u64.to_le_bytes());
}

#[test]
fn test_parent_declaration_equality() {
    let node = make_node_addr(1);
    let parent = make_node_addr(2);

    let decl1 = ParentDeclaration::new(node, parent, 1, 1000);
    let decl2 = ParentDeclaration::new(node, parent, 1, 1000);
    let decl3 = ParentDeclaration::new(node, parent, 2, 1000);

    assert_eq!(decl1, decl2);
    assert_ne!(decl1, decl3);
}

// ===== TreeState Tests =====

#[test]
fn test_tree_state_new() {
    let node = make_node_addr(1);
    let state = TreeState::new(node);

    assert_eq!(state.my_node_addr(), &node);
    assert!(state.is_root());
    assert_eq!(state.root(), &node);
    assert_eq!(state.my_coords().depth(), 0);
    assert_eq!(state.peer_count(), 0);
}

#[test]
fn test_tree_state_update_peer() {
    let my_node = make_node_addr(0);
    let mut state = TreeState::new(my_node);

    let peer = make_node_addr(1);
    let root = make_node_addr(2);

    let decl = ParentDeclaration::new(peer, root, 1, 1000);
    let coords = make_coords(&[1, 2]);

    assert!(state.update_peer(decl.clone(), coords.clone()));
    assert_eq!(state.peer_count(), 1);
    assert!(state.peer_coords(&peer).is_some());
    assert!(state.peer_declaration(&peer).is_some());

    // Same sequence should not update
    let decl2 = ParentDeclaration::new(peer, root, 1, 1000);
    assert!(!state.update_peer(decl2, coords.clone()));

    // Higher sequence should update
    let decl3 = ParentDeclaration::new(peer, root, 2, 2000);
    assert!(state.update_peer(decl3, coords));
}

#[test]
fn test_tree_state_remove_peer() {
    let my_node = make_node_addr(0);
    let mut state = TreeState::new(my_node);

    let peer = make_node_addr(1);
    let root = make_node_addr(2);

    let decl = ParentDeclaration::new(peer, root, 1, 1000);
    let coords = make_coords(&[1, 2]);

    state.update_peer(decl, coords);
    assert_eq!(state.peer_count(), 1);

    state.remove_peer(&peer);
    assert_eq!(state.peer_count(), 0);
    assert!(state.peer_coords(&peer).is_none());
}

#[test]
fn test_tree_state_distance_to_peer() {
    let my_node = make_node_addr(0);
    let mut state = TreeState::new(my_node);

    let peer = make_node_addr(1);

    // Both are roots in their own trees initially - different roots
    let peer_coords = TreeCoordinate::root(peer);
    let decl = ParentDeclaration::self_root(peer, 1, 1000);
    state.update_peer(decl, peer_coords);

    // Different roots = MAX distance
    assert_eq!(state.distance_to_peer(&peer), Some(usize::MAX));

    // If they share a root, distance should be finite
    let shared_root = make_node_addr(99);

    // Update my state to have shared root
    state.set_parent(shared_root, 1, 1000);
    let my_new_coords = make_coords(&[0, 99]);
    // Manually set coords for test (normally done by recompute_coords)
    state.my_coords = my_new_coords;
    state.root = shared_root;

    // Update peer to have same root
    let peer_coords = make_coords(&[1, 99]);
    let decl = ParentDeclaration::new(peer, shared_root, 2, 2000);
    state.update_peer(decl, peer_coords);

    // Now distance should be 2 (me -> root -> peer)
    assert_eq!(state.distance_to_peer(&peer), Some(2));
}

#[test]
fn test_tree_state_peer_ids() {
    let my_node = make_node_addr(0);
    let mut state = TreeState::new(my_node);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);

    state.update_peer(
        ParentDeclaration::self_root(peer1, 1, 1000),
        TreeCoordinate::root(peer1),
    );
    state.update_peer(
        ParentDeclaration::self_root(peer2, 1, 1000),
        TreeCoordinate::root(peer2),
    );

    let ids: Vec<_> = state.peer_ids().collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&&peer1));
    assert!(ids.contains(&&peer2));
}

// ===== Parent Selection Tests =====

#[test]
fn test_evaluate_parent_picks_smallest_root() {
    // Node 5 starts as root. Peers 3 and 7 each claim different roots.
    // Peer 3's path: [3, 1] (root=1)
    // Peer 7's path: [7, 2] (root=2)
    // Should pick peer 3 because root 1 < root 2.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let peer3 = make_node_addr(3);
    let peer7 = make_node_addr(7);

    state.update_peer(
        ParentDeclaration::new(peer3, make_node_addr(1), 1, 1000),
        make_coords(&[3, 1]),
    );
    state.update_peer(
        ParentDeclaration::new(peer7, make_node_addr(2), 1, 1000),
        make_coords(&[7, 2]),
    );

    let result = state.evaluate_parent();
    assert_eq!(result, Some(peer3));
}

#[test]
fn test_evaluate_parent_prefers_shallowest_depth() {
    // Node 5, root=0 (shared). Peer 1 at depth 1, peer 2 at depth 3.
    // Both reach root 0. Should pick peer 1 (shallowest).
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);
    let root = make_node_addr(0);

    // Peer 1: depth 1 (path = [1, 0])
    state.update_peer(
        ParentDeclaration::new(peer1, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    // Peer 2: depth 3 (path = [2, 3, 4, 0])
    state.update_peer(
        ParentDeclaration::new(peer2, make_node_addr(3), 1, 1000),
        make_coords(&[2, 3, 4, 0]),
    );

    let result = state.evaluate_parent();
    assert_eq!(result, Some(peer1));
}

#[test]
fn test_evaluate_parent_stays_root_when_smallest() {
    // Node 0 (smallest possible) should stay root even if peers exist.
    let my_node = make_node_addr(0);
    let mut state = TreeState::new(my_node);

    let peer1 = make_node_addr(1);
    // Peer 1 has root 0 (us) — shouldn't trigger switch
    state.update_peer(
        ParentDeclaration::new(peer1, my_node, 1, 1000),
        make_coords(&[1, 0]),
    );

    assert_eq!(state.evaluate_parent(), None);
}

#[test]
fn test_evaluate_parent_no_switch_when_already_best() {
    // Node 5, already using peer 1 as parent. No better option.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let peer1 = make_node_addr(1);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer1, root, 1, 1000),
        make_coords(&[1, 0]),
    );

    // Switch to peer1 as parent first
    state.set_parent(peer1, 1, 1000);
    state.recompute_coords();

    // Now evaluate — should return None since peer1 is already our parent
    assert_eq!(state.evaluate_parent(), None);
}

#[test]
fn test_evaluate_parent_no_peers() {
    let my_node = make_node_addr(5);
    let state = TreeState::new(my_node);

    assert_eq!(state.evaluate_parent(), None);
}

#[test]
fn test_evaluate_parent_depth_threshold() {
    // Node 5, currently at depth 4 through peer 2.
    // Peer 1 offers depth 3 (improvement of 1, which equals threshold).
    // Peer 3 offers depth 1 (improvement of 3, exceeds threshold).
    // Should switch to peer 3.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let peer2 = make_node_addr(2);
    let peer3 = make_node_addr(3);
    let root = make_node_addr(0);

    // Peer 2: depth 3 (we'd be depth 4 through them)
    state.update_peer(
        ParentDeclaration::new(peer2, make_node_addr(6), 1, 1000),
        make_coords(&[2, 6, 7, 0]),
    );

    // Set peer2 as our parent, making us depth 4
    state.set_parent(peer2, 1, 1000);
    state.recompute_coords();
    assert_eq!(state.my_coords().depth(), 4);

    // Peer 3: depth 1 (we'd be depth 2 through them) — improvement of 2
    state.update_peer(
        ParentDeclaration::new(peer3, root, 1, 1000),
        make_coords(&[3, 0]),
    );

    let result = state.evaluate_parent();
    assert_eq!(result, Some(peer3));
}

#[test]
fn test_handle_parent_lost_finds_alternative() {
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer1, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer2, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Set peer1 as parent
    state.set_parent(peer1, 1, 1000);
    state.recompute_coords();

    // Remove peer1 (parent lost)
    state.remove_peer(&peer1);
    let changed = state.handle_parent_lost();

    assert!(changed);
    // Should have switched to peer2
    assert_eq!(state.my_declaration().parent_id(), &peer2);
    assert!(!state.is_root());
}

#[test]
fn test_handle_parent_lost_becomes_root() {
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let peer1 = make_node_addr(1);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer1, root, 1, 1000),
        make_coords(&[1, 0]),
    );

    // Set peer1 as parent
    state.set_parent(peer1, 1, 1000);
    state.recompute_coords();
    let seq_before = state.my_declaration().sequence();

    // Remove peer1 (only parent)
    state.remove_peer(&peer1);
    let changed = state.handle_parent_lost();

    assert!(changed);
    assert!(state.is_root());
    assert!(state.my_declaration().sequence() > seq_before);
    assert_eq!(state.root(), &my_node);
}

// === find_next_hop tests ===

/// Build a TreeState with our own coordinates set.
fn make_tree_state(my_addr: u8, coord_path: &[u8]) -> TreeState {
    let my_node = make_node_addr(my_addr);
    let mut state = TreeState::new(my_node);
    let coords = make_coords(coord_path);
    state.root = *coords.root_id();
    state.my_coords = coords;
    state
}

/// Add a peer with given coordinates to the tree state.
fn add_peer(state: &mut TreeState, peer_addr: u8, coord_path: &[u8]) {
    let peer = make_node_addr(peer_addr);
    let parent = make_node_addr(coord_path[1]);
    state.update_peer(
        ParentDeclaration::new(peer, parent, 1, 1000),
        make_coords(coord_path),
    );
}

#[test]
fn test_find_next_hop_chain() {
    // Chain: 0 (root) <- 5 (us) <- 1 <- 2
    // Both peers 1 and 2 are in our peer_ancestry. Peer 2 IS the
    // destination (distance 0), so it's the best next hop.
    let mut state = make_tree_state(5, &[5, 0]);
    add_peer(&mut state, 1, &[1, 5, 0]);
    add_peer(&mut state, 2, &[2, 1, 5, 0]);

    let dest = make_coords(&[2, 1, 5, 0]);
    assert_eq!(state.find_next_hop(&dest), Some(make_node_addr(2)));
}

#[test]
fn test_find_next_hop_chain_indirect() {
    // Chain: 0 (root) <- 5 (us) <- 1
    // Dest is node 2 at [2, 1, 5, 0] but peer 2 is NOT in our peer
    // list — only peer 1 is. So we route via peer 1 (distance 1).
    let mut state = make_tree_state(5, &[5, 0]);
    add_peer(&mut state, 1, &[1, 5, 0]);

    let dest = make_coords(&[2, 1, 5, 0]);
    assert_eq!(state.find_next_hop(&dest), Some(make_node_addr(1)));
}

#[test]
fn test_find_next_hop_toward_root() {
    // Tree: 0 (root) <- 1 <- 5 (us)
    // Routing toward root should pick node 1 (our parent).
    let mut state = make_tree_state(5, &[5, 1, 0]);
    add_peer(&mut state, 1, &[1, 0]);

    let dest = make_coords(&[0]);
    assert_eq!(state.find_next_hop(&dest), Some(make_node_addr(1)));
}

#[test]
fn test_find_next_hop_sibling() {
    // Tree: 0 (root) <- 5 (us), 0 <- 3
    // Routing to sibling 3: should go through parent 0... but 0 is
    // the root and not in our peer list. Our only peer is 3 itself.
    // But 3 is not a "closer" peer in tree distance — distance from
    // us to 3 is 2 (up to root, down to 3), and distance from 3 to
    // 3 is 0, so 3 IS closer. Should pick 3.
    let mut state = make_tree_state(5, &[5, 0]);
    add_peer(&mut state, 3, &[3, 0]);

    let dest = make_coords(&[3, 0]);
    assert_eq!(state.find_next_hop(&dest), Some(make_node_addr(3)));
}

#[test]
fn test_find_next_hop_tie_breaking() {
    // Tree: 0 (root) <- 5 (us), 0 <- 3, 0 <- 2
    // Both peers are siblings at depth 1, equidistant to a dest
    // at [4, 0]. Should pick node 2 (smaller node_addr).
    let mut state = make_tree_state(5, &[5, 0]);
    add_peer(&mut state, 3, &[3, 0]);
    add_peer(&mut state, 2, &[2, 0]);

    let dest = make_coords(&[4, 0]);
    // Our distance: 2 (up to root, down to 4)
    // Peer 3 distance: 2 (up to root, down to 4)
    // Peer 2 distance: 2 (up to root, down to 4)
    // All equal to our distance — no peer is strictly closer.
    assert_eq!(state.find_next_hop(&dest), None);
}

#[test]
fn test_find_next_hop_different_root() {
    let mut state = make_tree_state(5, &[5, 0]);
    add_peer(&mut state, 1, &[1, 0]);

    // Destination in a different tree (root = 9)
    let dest = make_coords(&[3, 9]);
    assert_eq!(state.find_next_hop(&dest), None);
}

#[test]
fn test_find_next_hop_no_peers() {
    let state = make_tree_state(5, &[5, 0]);
    let dest = make_coords(&[3, 0]);
    assert_eq!(state.find_next_hop(&dest), None);
}

#[test]
fn test_find_next_hop_local_minimum() {
    // Tree: 0 (root) <- 5 (us), 5 <- 8
    // Routing to node 3 at [3, 0]. Our distance = 2.
    // Peer 8's distance = 4 (8→5→0→3 but via coords: [8,5,0] to [3,0] = 3).
    // Actually: lca of [8,5,0] and [3,0] is root 0 at depth 0.
    // dist = (2-0) + (1-0) = 3. Our dist = (1-0) + (1-0) = 2.
    // Peer is farther, so no hop.
    let mut state = make_tree_state(5, &[5, 0]);
    add_peer(&mut state, 8, &[8, 5, 0]);

    let dest = make_coords(&[3, 0]);
    assert_eq!(state.find_next_hop(&dest), None);
}

#[test]
fn test_find_next_hop_best_of_multiple() {
    // Tree: 0 (root) <- 1 <- 5 (us), 1 <- 3 <- 7
    // Dest is node 7 at [7, 3, 1, 0].
    // Peer 1 coords [1, 0]: dist to dest = 0 + 2 = 2
    // Peer 3 coords [3, 1, 0]: dist to dest = 0 + 1 = 1
    // Our coords [5, 1, 0]: dist to dest = 1 + 2 = 3
    // Peer 3 is closest. Should pick 3.
    let mut state = make_tree_state(5, &[5, 1, 0]);
    add_peer(&mut state, 1, &[1, 0]);
    add_peer(&mut state, 3, &[3, 1, 0]);

    let dest = make_coords(&[7, 3, 1, 0]);
    assert_eq!(state.find_next_hop(&dest), Some(make_node_addr(3)));
}
