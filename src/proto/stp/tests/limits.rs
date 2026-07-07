//! Flap dampening / hold-down unit tests.

use std::collections::{BTreeMap, BTreeSet};

use super::util::{make_coords, make_costs, make_node_addr};
use crate::proto::stp::{ParentDeclaration, TreeState};

#[test]
fn test_flap_dampening_engages_after_threshold() {
    // Create TreeState with flap_threshold=3, window=60s, dampening=3600s (long)
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_flap_dampening(3, 60, 3600);
    state.set_hold_down(0); // disable hold-down for this test

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

    // Switch 1: initial parent selection (root -> peer_a)
    assert!(!state.is_flap_dampened(3000));
    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();
    assert!(!state.is_flap_dampened(3000));

    // Switch 2: peer_a -> peer_b
    state.set_parent(peer_b, 2, 2000, 2000);
    state.recompute_coords();
    assert!(!state.is_flap_dampened(3000));

    // Switch 3: peer_b -> peer_a — threshold reached, dampening engages
    let dampened = state.set_parent(peer_a, 3, 3000, 3000);
    state.recompute_coords();
    assert!(dampened);
    assert!(state.is_flap_dampened(3000));

    // evaluate_parent should return None for non-mandatory switches
    // Make peer_b much better than peer_a
    let costs = make_costs(&[(1, 10.0), (2, 1.0)]);
    let result = state.evaluate_parent(&costs, &BTreeSet::new(), 3000);
    assert_eq!(result, None); // suppressed by flap dampening
}

#[test]
fn test_flap_dampening_allows_mandatory_switches() {
    // Engage dampening, then verify mandatory switches still work
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_flap_dampening(3, 60, 3600);
    state.set_hold_down(0);

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

    // Trigger dampening with 3 switches
    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();
    state.set_parent(peer_b, 2, 2000, 2000);
    state.recompute_coords();
    state.set_parent(peer_a, 3, 3000, 3000);
    state.recompute_coords();
    assert!(state.is_flap_dampened(3000));

    // Remove current parent (peer_a) — this is a mandatory switch
    state.remove_peer(&peer_a);
    let result = state.evaluate_parent(&BTreeMap::new(), &BTreeSet::new(), 3000);
    assert_eq!(result, Some(peer_b)); // mandatory switch bypasses dampening
}

#[test]
fn test_flap_dampening_expires() {
    // Test with 0-second dampening duration to verify expiry logic
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_flap_dampening(3, 60, 0); // 0-second dampening
    state.set_hold_down(0);

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

    // Trigger dampening
    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();
    state.set_parent(peer_b, 2, 2000, 2000);
    state.recompute_coords();
    let dampened = state.set_parent(peer_a, 3, 3000, 3000);
    state.recompute_coords();
    assert!(dampened); // dampening was engaged

    // With 0-second duration, dampening should have already expired
    assert!(!state.is_flap_dampened(3000));

    // evaluate_parent should work normally now
    let costs = make_costs(&[(1, 10.0), (2, 1.0)]);
    let result = state.evaluate_parent(&costs, &BTreeSet::new(), 3000);
    assert_eq!(result, Some(peer_b)); // not suppressed
}

#[test]
fn test_flap_dampening_below_threshold() {
    // Fewer switches than threshold should NOT engage dampening
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_flap_dampening(4, 60, 3600); // threshold=4
    state.set_hold_down(0);

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

    // Only 3 switches (below threshold of 4)
    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();
    state.set_parent(peer_b, 2, 2000, 2000);
    state.recompute_coords();
    state.set_parent(peer_a, 3, 3000, 3000);
    state.recompute_coords();

    assert!(!state.is_flap_dampened(3000));

    // evaluate_parent should still work normally
    let costs = make_costs(&[(1, 10.0), (2, 1.0)]);
    let result = state.evaluate_parent(&costs, &BTreeSet::new(), 3000);
    assert_eq!(result, Some(peer_b)); // not suppressed
}

#[test]
fn test_flap_dampening_window_reset() {
    // Test that the flap window resets after expiry.
    // Use a 0-second window so it immediately expires between switch groups.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    // threshold=3, window=0s (expires immediately), dampening=3600s
    state.set_flap_dampening(3, 0, 3600);
    state.set_hold_down(0);

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

    // Each switch resets the window (0s window means every switch starts fresh).
    // So we never accumulate enough to reach threshold=3.
    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();
    // Window expired, counter resets on next switch
    state.set_parent(peer_b, 2, 2000, 2000);
    state.recompute_coords();
    // Window expired, counter resets on next switch
    state.set_parent(peer_a, 3, 3000, 3000);
    state.recompute_coords();

    // Dampening should NOT have engaged because each switch reset the window
    assert!(!state.is_flap_dampened(3000));
}

#[test]
fn test_flap_dampening_same_parent_no_count() {
    // Re-declaring the same parent should not count as a flap
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_flap_dampening(3, 60, 3600);
    state.set_hold_down(0);

    let peer_a = make_node_addr(1);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );

    // Initial parent selection
    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();

    // Re-declare same parent multiple times (e.g., parent ancestry changed)
    state.set_parent(peer_a, 2, 2000, 2000);
    state.recompute_coords();
    state.set_parent(peer_a, 3, 3000, 3000);
    state.recompute_coords();
    state.set_parent(peer_a, 4, 4000, 4000);
    state.recompute_coords();
    state.set_parent(peer_a, 5, 5000, 5000);
    state.recompute_coords();

    // Should NOT be dampened since only the first was a real switch
    assert!(!state.is_flap_dampened(3000));
}
