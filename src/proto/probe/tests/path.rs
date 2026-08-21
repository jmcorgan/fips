//! Pure LCA arithmetic. Expected values are derived from
//! `TreeCoordinate::depth()`, which is `entries - 1`, and worked out in each
//! test's comment — never read off a rendered example.

use crate::NodeAddr;
use crate::proto::probe::core::describe_path;
use crate::proto::stp::TreeCoordinate;

fn addr(v: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = v;
    NodeAddr::from_bytes(bytes)
}

/// Coordinates are stored self → root.
fn coord(path: &[u8]) -> TreeCoordinate {
    TreeCoordinate::from_addrs(path.iter().copied().map(addr).collect()).unwrap()
}

#[test]
fn path_facts_same_tree() {
    // ours   [4d, 91, 7c] : self 4d, parent 91, root 7c        depth 2
    // theirs [4a, e5, 91, 7c] : self 4a, e5, 91, root 7c       depth 3
    // common suffix is [7c, 91], so the LCA is 91 at root-relative depth 1.
    // up   = our_depth - lca_depth   = 2 - 1 = 1
    // down = their_depth - lca_depth = 3 - 1 = 2
    let facts = describe_path(
        &coord(&[0x4d, 0x91, 0x7c]),
        &coord(&[0x4a, 0xe5, 0x91, 0x7c]),
    );
    assert!(facts.same_root);
    assert_eq!(facts.our_depth, 2);
    assert_eq!(facts.their_depth, 3);
    assert_eq!(facts.lca, Some(addr(0x91)));
    assert_eq!(facts.lca_depth, Some(1));
    assert_eq!(facts.tree_hops_up, Some(1));
    assert_eq!(facts.tree_hops_down, Some(2));
    assert_eq!(facts.tree_distance, Some(3));
}

#[test]
fn path_facts_different_roots_is_disjoint_not_depth_zero() {
    // `lca_depth` alone returns 0 here through its `saturating_sub(1)`, which
    // would render as "the LCA is the root" — a wrong answer that looks
    // plausible. `lca()` returning None is the only sound discriminator.
    let facts = describe_path(&coord(&[0x11, 0x01]), &coord(&[0x22, 0x02]));
    assert!(!facts.same_root);
    assert_eq!(facts.lca, None);
    assert_eq!(facts.lca_depth, None);
    assert_eq!(facts.tree_hops_up, None);
    assert_eq!(facts.tree_hops_down, None);
    assert_eq!(facts.tree_distance, None);
}

#[test]
fn path_facts_ancestor_pair() {
    // theirs [91, 7c] is a strict ancestor of ours [4d, 91, 7c]:
    // the LCA is 91 itself, at depth 1, so nothing goes back down.
    let facts = describe_path(&coord(&[0x4d, 0x91, 0x7c]), &coord(&[0x91, 0x7c]));
    assert_eq!(facts.lca, Some(addr(0x91)));
    assert_eq!(facts.lca_depth, Some(1));
    assert_eq!(facts.tree_hops_up, Some(1));
    assert_eq!(facts.tree_hops_down, Some(0));
    assert_eq!(facts.tree_distance, Some(1));
}

#[test]
fn depth_matches_entry_count_minus_one() {
    let facts = describe_path(
        &coord(&[0x4d, 0x91, 0x7c]),
        &coord(&[0x4a, 0xe5, 0x91, 0x7c]),
    );
    assert_eq!(facts.our_depth, facts.our_coords.len() - 1);
    assert_eq!(facts.their_depth, facts.their_coords.len() - 1);
}
