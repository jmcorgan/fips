//! ParentDeclaration, TreeState, parent-selection, and find_next_hop unit tests.

use std::collections::{BTreeMap, BTreeSet};

use super::util::{add_peer, make_coords, make_costs, make_node_addr, make_tree_state};
use crate::proto::stp::{ParentDeclaration, ParentEval, TreeCoordinate, TreeState};

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
    let state = TreeState::new(node, 1000);

    assert_eq!(state.my_node_addr(), &node);
    assert!(state.is_root());
    assert_eq!(state.root(), &node);
    assert_eq!(state.my_coords().depth(), 0);
    assert_eq!(state.peer_count(), 0);
}

#[test]
fn test_tree_state_update_peer() {
    let my_node = make_node_addr(0);
    let mut state = TreeState::new(my_node, 1000);

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
    let mut state = TreeState::new(my_node, 1000);

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
    let mut state = TreeState::new(my_node, 1000);

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
    state.set_parent(shared_root, 1, 1000, 1000);
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
    let mut state = TreeState::new(my_node, 1000);

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
    let mut state = TreeState::new(my_node, 1000);

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

    let result = state
        .evaluate_parent(&BTreeMap::new(), &BTreeSet::new())
        .switch_target();
    assert_eq!(result, Some(peer3));
}

#[test]
fn test_evaluate_parent_prefers_shallowest_depth() {
    // Node 5, root=0 (shared). Peer 1 at depth 1, peer 2 at depth 3.
    // Both reach root 0. Should pick peer 1 (shallowest).
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);

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

    let result = state
        .evaluate_parent(&BTreeMap::new(), &BTreeSet::new())
        .switch_target();
    assert_eq!(result, Some(peer1));
}

#[test]
fn test_evaluate_parent_stays_root_when_smallest() {
    // Node 0 (smallest possible) should stay root even if peers exist.
    let my_node = make_node_addr(0);
    let mut state = TreeState::new(my_node, 1000);

    let peer1 = make_node_addr(1);
    // Peer 1 has root 0 (us) — shouldn't trigger switch
    state.update_peer(
        ParentDeclaration::new(peer1, my_node, 1, 1000),
        make_coords(&[1, 0]),
    );

    assert_eq!(
        state
            .evaluate_parent(&BTreeMap::new(), &BTreeSet::new())
            .switch_target(),
        None
    );
}

#[test]
fn test_evaluate_parent_no_switch_when_already_best() {
    // Node 5, already using peer 1 as parent. No better option.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);

    let peer1 = make_node_addr(1);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer1, root, 1, 1000),
        make_coords(&[1, 0]),
    );

    // Switch to peer1 as parent first
    state.set_parent(peer1, 1, 1000, 1000);
    state.recompute_coords();

    // Now evaluate — should return None since peer1 is already our parent
    assert_eq!(
        state
            .evaluate_parent(&BTreeMap::new(), &BTreeSet::new())
            .switch_target(),
        None
    );
}

#[test]
fn test_evaluate_parent_no_peers() {
    let my_node = make_node_addr(5);
    let state = TreeState::new(my_node, 1000);

    assert_eq!(
        state
            .evaluate_parent(&BTreeMap::new(), &BTreeSet::new())
            .switch_target(),
        None
    );
}

#[test]
fn test_evaluate_parent_depth_threshold() {
    // Node 5, currently at depth 4 through peer 2.
    // Peer 1 offers depth 3 (improvement of 1, which equals threshold).
    // Peer 3 offers depth 1 (improvement of 3, exceeds threshold).
    // Should switch to peer 3.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);

    let peer2 = make_node_addr(2);
    let peer3 = make_node_addr(3);
    let root = make_node_addr(0);

    // Peer 2: depth 3 (we'd be depth 4 through them)
    state.update_peer(
        ParentDeclaration::new(peer2, make_node_addr(6), 1, 1000),
        make_coords(&[2, 6, 7, 0]),
    );

    // Set peer2 as our parent, making us depth 4
    state.set_parent(peer2, 1, 1000, 1000);
    state.recompute_coords();
    assert_eq!(state.my_coords().depth(), 4);

    // Peer 3: depth 1 (we'd be depth 2 through them) — improvement of 2
    state.update_peer(
        ParentDeclaration::new(peer3, root, 1, 1000),
        make_coords(&[3, 0]),
    );

    let result = state
        .evaluate_parent(&BTreeMap::new(), &BTreeSet::new())
        .switch_target();
    assert_eq!(result, Some(peer3));
}

#[test]
fn test_evaluate_parent_rejects_loop_candidate() {
    // Node 5 with peer 1 whose ancestry contains node 5 — selecting
    // peer 1 would create a coordinate loop. evaluate_parent must skip it.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);

    let peer1 = make_node_addr(1);
    let _root = make_node_addr(0);

    // Peer 1's ancestry: [1, 5, 0] — contains us (node 5)
    state.update_peer(
        ParentDeclaration::new(peer1, my_node, 1, 1000),
        make_coords(&[1, 5, 0]),
    );

    // Should return None — the only candidate creates a loop
    assert_eq!(
        state
            .evaluate_parent(&BTreeMap::new(), &BTreeSet::new())
            .switch_target(),
        None
    );
}

#[test]
fn test_evaluate_parent_picks_loop_free_over_loopy() {
    // Two peers reach the same root. Peer 1's ancestry contains us (loop),
    // peer 2's does not. Should pick peer 2 even though peer 1 is shallower.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);
    let _root = make_node_addr(0);

    // Peer 1: depth 2, but ancestry contains us — loop
    state.update_peer(
        ParentDeclaration::new(peer1, my_node, 1, 1000),
        make_coords(&[1, 5, 0]),
    );
    // Peer 2: depth 3, loop-free
    state.update_peer(
        ParentDeclaration::new(peer2, make_node_addr(3), 1, 1000),
        make_coords(&[2, 3, 4, 0]),
    );

    let result = state
        .evaluate_parent(&BTreeMap::new(), &BTreeSet::new())
        .switch_target();
    assert_eq!(result, Some(peer2));
}

#[test]
fn test_handle_parent_lost_finds_alternative() {
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);

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
    state.set_parent(peer1, 1, 1000, 1000);
    state.recompute_coords();

    // Remove peer1 (parent lost)
    state.remove_peer(&peer1);
    let changed = state.handle_parent_lost(&BTreeMap::new(), 1000, 1000);

    assert!(changed);
    // Should have switched to peer2
    assert_eq!(state.my_declaration().parent_id(), &peer2);
    assert!(!state.is_root());
}

#[test]
fn test_handle_parent_lost_becomes_root_when_self_smaller_than_remaining() {
    // Regression: self (NodeAddr 1) had peer 0 as parent. Peer 0 disappears,
    // leaving only peers with bigger NodeAddrs (and bigger roots). The old
    // evaluate_parent() picked one of them — recompute_coords() then
    // produced [self, peer, ..., peer_root] where last (peer_root) > min
    // (self), an ancestry that recipients reject as
    // "advertised root X is not the minimum path entry Y". This is the
    // bug seen in production where ubuntu-dev (3847a4..) advertised itself
    // as root while its path still contained mac (312c79..).
    let my_node = make_node_addr(1); // our addr is the smallest
    let mut state = TreeState::new(my_node, 1000);

    let smaller = make_node_addr(0);
    let bigger1 = make_node_addr(2);
    let bigger2 = make_node_addr(3);

    // Initially: peer 0 (smaller) is our parent.
    state.update_peer(
        ParentDeclaration::self_root(smaller, 1, 1000),
        make_coords(&[0]),
    );
    // Bigger peers exist, both rooted at themselves (no smaller node visible
    // through them).
    state.update_peer(
        ParentDeclaration::self_root(bigger1, 1, 1000),
        make_coords(&[2]),
    );
    state.update_peer(
        ParentDeclaration::self_root(bigger2, 1, 1000),
        make_coords(&[3]),
    );

    state.set_parent(smaller, 2, 2000, 2000);
    state.recompute_coords();
    assert_eq!(state.my_coords().entries().len(), 2);
    assert_eq!(state.root(), &smaller);

    // Smaller peer disconnects.
    state.remove_peer(&smaller);
    let changed = state.handle_parent_lost(&BTreeMap::new(), 1000, 1000);
    assert!(changed);

    // Must become root (we're the smallest visible), NOT pick bigger1/bigger2.
    assert!(
        state.is_root(),
        "must self-root when no smaller peer remains"
    );
    assert_eq!(state.root(), &my_node);
    assert_eq!(state.my_coords().entries().len(), 1);

    // The resulting ancestry must be valid: last == min.
    let entries = state.my_coords().entries();
    let min = entries.iter().map(|e| e.node_addr).min().unwrap();
    assert_eq!(*state.my_coords().root_id(), min);
}

#[test]
fn test_recompute_coords_demotes_when_self_smaller_than_parent_root() {
    // Defensive: even if set_parent is called with a parent whose root is
    // bigger than us (e.g., a stale evaluate_parent decision in some legacy
    // path), recompute_coords must produce a valid ancestry by demoting to
    // self-root rather than emit [self, peer, peer_root] with last > min.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);

    let bigger_peer = make_node_addr(7);
    state.update_peer(
        ParentDeclaration::self_root(bigger_peer, 1, 1000),
        make_coords(&[7]),
    );

    state.set_parent(bigger_peer, 2, 2000, 2000);
    state.recompute_coords();

    assert!(state.is_root(), "recompute_coords demoted to self-root");
    assert_eq!(state.root(), &my_node);
    assert_eq!(state.my_coords().entries().len(), 1);
    let entries = state.my_coords().entries();
    let min = entries.iter().map(|e| e.node_addr).min().unwrap();
    assert_eq!(*state.my_coords().root_id(), min);
}

#[test]
fn test_handle_parent_lost_becomes_root() {
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);

    let peer1 = make_node_addr(1);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer1, root, 1, 1000),
        make_coords(&[1, 0]),
    );

    // Set peer1 as parent
    state.set_parent(peer1, 1, 1000, 1000);
    state.recompute_coords();
    let seq_before = state.my_declaration().sequence();

    // Remove peer1 (only parent)
    state.remove_peer(&peer1);
    let changed = state.handle_parent_lost(&BTreeMap::new(), 1000, 1000);

    assert!(changed);
    assert!(state.is_root());
    assert!(state.my_declaration().sequence() > seq_before);
    assert_eq!(state.root(), &my_node);
}

// === find_next_hop tests ===

#[test]
fn test_find_next_hop_chain() {
    // Chain: 0 (root) <- 5 (us) <- 1 <- 2
    // Both peers 1 and 2 are in our peer_ancestry. Peer 2 IS the
    // destination (distance 0), so it's the best next hop.
    let mut state = make_tree_state(5, &[5, 0]);
    add_peer(&mut state, 1, &[1, 5, 0]);
    add_peer(&mut state, 2, &[2, 1, 5, 0]);

    let dest = make_coords(&[2, 1, 5, 0]);
    assert_eq!(
        state.find_next_hop(&dest, &BTreeSet::new()),
        Some(make_node_addr(2))
    );
}

#[test]
fn test_find_next_hop_chain_indirect() {
    // Chain: 0 (root) <- 5 (us) <- 1
    // Dest is node 2 at [2, 1, 5, 0] but peer 2 is NOT in our peer
    // list — only peer 1 is. So we route via peer 1 (distance 1).
    let mut state = make_tree_state(5, &[5, 0]);
    add_peer(&mut state, 1, &[1, 5, 0]);

    let dest = make_coords(&[2, 1, 5, 0]);
    assert_eq!(
        state.find_next_hop(&dest, &BTreeSet::new()),
        Some(make_node_addr(1))
    );
}

#[test]
fn test_find_next_hop_toward_root() {
    // Tree: 0 (root) <- 1 <- 5 (us)
    // Routing toward root should pick node 1 (our parent).
    let mut state = make_tree_state(5, &[5, 1, 0]);
    add_peer(&mut state, 1, &[1, 0]);

    let dest = make_coords(&[0]);
    assert_eq!(
        state.find_next_hop(&dest, &BTreeSet::new()),
        Some(make_node_addr(1))
    );
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
    assert_eq!(
        state.find_next_hop(&dest, &BTreeSet::new()),
        Some(make_node_addr(3))
    );
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
    assert_eq!(state.find_next_hop(&dest, &BTreeSet::new()), None);
}

#[test]
fn test_find_next_hop_different_root() {
    let mut state = make_tree_state(5, &[5, 0]);
    add_peer(&mut state, 1, &[1, 0]);

    // Destination in a different tree (root = 9)
    let dest = make_coords(&[3, 9]);
    assert_eq!(state.find_next_hop(&dest, &BTreeSet::new()), None);
}

#[test]
fn test_find_next_hop_no_peers() {
    let state = make_tree_state(5, &[5, 0]);
    let dest = make_coords(&[3, 0]);
    assert_eq!(state.find_next_hop(&dest, &BTreeSet::new()), None);
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
    assert_eq!(state.find_next_hop(&dest, &BTreeSet::new()), None);
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
    assert_eq!(
        state.find_next_hop(&dest, &BTreeSet::new()),
        Some(make_node_addr(3))
    );
}

// === Cost-based parent selection tests ===

#[test]
fn test_effective_depth_selects_lower_cost_deeper_peer() {
    // Peer A at depth 1 with high cost (LoRa), peer B at depth 2 with low cost (fiber).
    // effective_depth(A) = 1 + 6.0 = 7.0
    // effective_depth(B) = 2 + 1.01 = 3.01
    // Should select B despite being deeper.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    // Peer A: depth 1
    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    // Peer B: depth 2
    state.update_peer(
        ParentDeclaration::new(peer_b, make_node_addr(3), 1, 1000),
        make_coords(&[2, 3, 0]),
    );

    let costs = make_costs(&[(1, 6.0), (2, 1.01)]);
    let result = state
        .evaluate_parent(&costs, &BTreeSet::new())
        .switch_target();
    assert_eq!(result, Some(peer_b));
}

#[test]
fn test_effective_depth_equal_cost_degenerates_to_depth() {
    // Both peers at cost 1.0 (default). Should pick shallowest, same as v1.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);
    let root = make_node_addr(0);

    // Peer 1: depth 1
    state.update_peer(
        ParentDeclaration::new(peer1, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    // Peer 2: depth 3
    state.update_peer(
        ParentDeclaration::new(peer2, make_node_addr(3), 1, 1000),
        make_coords(&[2, 3, 4, 0]),
    );

    let costs = make_costs(&[(1, 1.0), (2, 1.0)]);
    let result = state
        .evaluate_parent(&costs, &BTreeSet::new())
        .switch_target();
    assert_eq!(result, Some(peer1));
}

#[test]
fn test_effective_depth_tiebreak_by_node_addr() {
    // Two peers with identical effective_depth. Smaller NodeAddr wins.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);
    let root = make_node_addr(0);

    // Both at depth 1, cost 1.0 → effective_depth 2.0
    state.update_peer(
        ParentDeclaration::new(peer1, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer2, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    let costs = make_costs(&[(1, 1.0), (2, 1.0)]);
    let result = state
        .evaluate_parent(&costs, &BTreeSet::new())
        .switch_target();
    assert_eq!(result, Some(peer1)); // smaller NodeAddr
}

#[test]
fn test_hysteresis_prevents_marginal_switch() {
    // Current parent eff_depth 3.5, candidate 3.2.
    // With 20% hysteresis, threshold = 3.5 * 0.8 = 2.8.
    // 3.2 > 2.8, so no switch.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_parent_hysteresis(0.2);

    let peer_a = make_node_addr(1); // current parent
    let peer_b = make_node_addr(2); // candidate
    let root = make_node_addr(0);

    // Peer A: depth 1, cost 2.5 → eff 3.5
    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    // Peer B: depth 1, cost 2.2 → eff 3.2
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Set peer_a as current parent
    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();

    let costs = make_costs(&[(1, 2.5), (2, 2.2)]);
    let result = state
        .evaluate_parent(&costs, &BTreeSet::new())
        .switch_target();
    assert_eq!(result, None); // marginal improvement blocked by hysteresis
}

#[test]
fn test_hysteresis_allows_significant_switch() {
    // Current parent eff_depth 7.0, candidate 3.01.
    // With 20% hysteresis, threshold = 7.0 * 0.8 = 5.6.
    // 3.01 < 5.6, so switch occurs.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_parent_hysteresis(0.2);

    let peer_a = make_node_addr(1); // current parent (LoRa)
    let peer_b = make_node_addr(2); // candidate (fiber)
    let root = make_node_addr(0);

    // Peer A: depth 1, cost 6.0 → eff 7.0
    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    // Peer B: depth 2, cost 1.01 → eff 3.01
    state.update_peer(
        ParentDeclaration::new(peer_b, make_node_addr(3), 1, 1000),
        make_coords(&[2, 3, 0]),
    );

    // Set peer_a as current parent
    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();

    let costs = make_costs(&[(1, 6.0), (2, 1.01)]);
    let result = state
        .evaluate_parent(&costs, &BTreeSet::new())
        .switch_target();
    assert_eq!(result, Some(peer_b));
}

#[test]
fn test_cold_start_default_cost() {
    // Peer with no cost entry in map gets default 1.0.
    // This degenerates to depth-only selection.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);
    let root = make_node_addr(0);

    // Peer 1: depth 1, peer 2: depth 3
    state.update_peer(
        ParentDeclaration::new(peer1, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer2, make_node_addr(3), 1, 1000),
        make_coords(&[2, 3, 4, 0]),
    );

    // Empty cost map — all peers get default 1.0
    let result = state
        .evaluate_parent(&BTreeMap::new(), &BTreeSet::new())
        .switch_target();
    assert_eq!(result, Some(peer1)); // shallowest wins
}

#[test]
fn test_hold_down_suppresses_reeval() {
    // After a parent switch, re-evaluation returns None during hold-down.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_hold_down(60); // 60s hold-down

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Switch to peer_a (sets last_parent_switch)
    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();

    // Peer_b now offers better cost, but hold-down suppresses
    let costs = make_costs(&[(1, 5.0), (2, 1.0)]);
    state.set_parent_hysteresis(0.0); // no hysteresis, only hold-down
    // The hold-down veto now lives at the shell edge, not inside evaluate_parent.
    // The clock-free core still finds peer_b as a discretionary candidate; the shell
    // suppresses it because hold-down is active — same net "no switch" as before.
    assert!(state.is_switch_suppressed(1000)); // hold-down active at the edge
    assert!(matches!(
        state.evaluate_parent(&costs, &BTreeSet::new()),
        ParentEval::Discretionary(p) if p == peer_b
    ));
}

#[test]
fn test_mandatory_switch_bypasses_hold_down() {
    // Parent loss during hold-down still triggers switch.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_hold_down(60); // 60s hold-down

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Switch to peer_a
    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();

    // Remove peer_a (parent lost) — should bypass hold-down
    state.remove_peer(&peer_a);
    // Hold-down is active at the edge, but a parent-lost switch is mandatory and
    // bypasses the veto: the core returns Mandatory and the switch is taken anyway.
    assert!(state.is_switch_suppressed(1000)); // hold-down active
    assert!(matches!(
        state.evaluate_parent(&BTreeMap::new(), &BTreeSet::new()),
        ParentEval::Mandatory(p) if p == peer_b
    ));
}

#[test]
fn test_heterogeneous_7node_avoids_bottleneck() {
    // 7-node topology simulating a mixed fiber/LoRa network:
    //
    //   0 (root)
    //   ├── 1 (fiber, cost 1.01) — depth 1
    //   │   ├── 3 (fiber, cost 1.01) — depth 2
    //   │   └── 4 (fiber, cost 1.01) — depth 2
    //   ├── 2 (LoRa, cost 6.0)  — depth 1
    //   │   └── 5 (fiber, cost 1.01) — depth 2 (inherits LoRa bottleneck!)
    //   └── 6 (wifi, cost 1.07) — depth 1
    //
    // Node 5 is connected to both node 2 (LoRa parent, depth 1) and
    // node 1 (fiber, depth 1). Without cost-awareness, node 5 could
    // pick node 2 as parent (both at depth 1, tiebreak by addr).
    // With cost-awareness, node 5 should pick node 1 (eff 2.01) over
    // node 2 (eff 7.0).

    let root = make_node_addr(0);

    // Test from node 5's perspective
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);

    let peer1 = make_node_addr(1); // fiber peer at depth 1
    let peer2 = make_node_addr(2); // LoRa peer at depth 1

    // Both peers reach root 0 at depth 1
    state.update_peer(
        ParentDeclaration::new(peer1, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer2, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Without costs (all 1.0): picks peer 1 (smaller addr) — correct by luck
    let result_no_cost = state
        .evaluate_parent(&BTreeMap::new(), &BTreeSet::new())
        .switch_target();
    assert_eq!(result_no_cost, Some(peer1));

    // With costs: fiber (1.01) vs LoRa (6.0) — fiber wins definitively
    let costs = make_costs(&[(1, 1.01), (2, 6.0)]);
    let result_with_cost = state
        .evaluate_parent(&costs, &BTreeSet::new())
        .switch_target();
    assert_eq!(result_with_cost, Some(peer1));

    // Now test the critical case: node 5 currently has LoRa parent (peer 2).
    // Even without hysteresis, it should want to switch to fiber (peer 1).
    state.set_parent(peer2, 1, 1000, 1000);
    state.recompute_coords();
    assert_eq!(state.my_coords().depth(), 2); // depth 2 through LoRa peer

    let result_switch = state
        .evaluate_parent(&costs, &BTreeSet::new())
        .switch_target();
    assert_eq!(result_switch, Some(peer1)); // switches away from LoRa bottleneck

    // With hysteresis enabled, still switches because the cost difference is large
    state.set_parent_hysteresis(0.2);
    // current_parent_eff = 1 + 6.0 = 7.0, best_eff = 1 + 1.01 = 2.01
    // threshold = 7.0 * 0.8 = 5.6, 2.01 < 5.6 → switch
    let result_hyst = state
        .evaluate_parent(&costs, &BTreeSet::new())
        .switch_target();
    assert_eq!(result_hyst, Some(peer1));
}

// =====================================================================
// Cost degradation tests (periodic re-evaluation scenarios)
// =====================================================================
//
// These test evaluate_parent() with changing cost maps, validating the
// scenarios that periodic re-evaluation is designed to catch: link
// quality changes after the tree has stabilized.

#[test]
fn test_cost_degradation_triggers_switch() {
    // Node 5 has two peers at depth 1. Initially both have similar costs
    // (both fiber). After stabilization, peer A's link degrades (becomes
    // LoRa-like). Re-evaluation with updated costs should trigger a switch.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_parent_hysteresis(0.2);

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Initial: both fiber-like costs. Node picks peer_a (smaller addr).
    let initial_costs = make_costs(&[(1, 1.05), (2, 1.08)]);
    let result = state
        .evaluate_parent(&initial_costs, &BTreeSet::new())
        .switch_target();
    assert_eq!(result, Some(peer_a));

    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();

    // Verify stable: no switch with same costs
    let result = state
        .evaluate_parent(&initial_costs, &BTreeSet::new())
        .switch_target();
    assert_eq!(result, None);

    // Peer A's link degrades significantly (LoRa-like latency + loss)
    // current_parent_eff = 1 + 6.0 = 7.0
    // best_eff = 1 + 1.08 = 2.08
    // threshold = 7.0 * 0.8 = 5.6, 2.08 < 5.6 → switch
    let degraded_costs = make_costs(&[(1, 6.0), (2, 1.08)]);
    let result = state
        .evaluate_parent(&degraded_costs, &BTreeSet::new())
        .switch_target();
    assert_eq!(result, Some(peer_b));
}

#[test]
fn test_cost_improvement_within_hysteresis_no_switch() {
    // Node 5 has parent peer_a. Peer_b's cost improves slightly but
    // stays within the hysteresis band. Re-evaluation should not switch.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_parent_hysteresis(0.2);

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();

    // Peer B slightly better: cost 1.5 vs peer A cost 2.0
    // current_parent_eff = 1 + 2.0 = 3.0
    // best_eff = 1 + 1.5 = 2.5
    // threshold = 3.0 * 0.8 = 2.4, 2.5 > 2.4 → no switch
    let costs = make_costs(&[(1, 2.0), (2, 1.5)]);
    let result = state
        .evaluate_parent(&costs, &BTreeSet::new())
        .switch_target();
    assert_eq!(result, None);
}

#[test]
fn test_single_peer_no_reeval_benefit() {
    // With only one peer, evaluate_parent should select it initially,
    // but once it's our parent, re-evaluation returns None regardless
    // of cost changes (no alternative exists).
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);

    let peer_a = make_node_addr(1);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );

    // Initial selection: picks the only peer
    let costs = make_costs(&[(1, 1.05)]);
    let result = state
        .evaluate_parent(&costs, &BTreeSet::new())
        .switch_target();
    assert_eq!(result, Some(peer_a));

    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();

    // Even with terrible cost, no switch (no alternative)
    let bad_costs = make_costs(&[(1, 50.0)]);
    let result = state
        .evaluate_parent(&bad_costs, &BTreeSet::new())
        .switch_target();
    assert_eq!(result, None);
}
