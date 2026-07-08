//! TreeCoordinate unit tests.

use super::util::{make_coords, make_node_addr};
use crate::proto::stp::{CoordEntry, CoordError, TreeCoordinate};

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
    assert!(matches!(result, Err(CoordError::EmptyCoordinate)));
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
