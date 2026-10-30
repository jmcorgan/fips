//! The least lifetime of a coordinate cache entry against
//! `node.cache.coord_ttl_secs`.
//!
//! A node must not let an entry expire before `COORD_CACHE_TTL` (300 s) has
//! elapsed since it was last written or read, whatever lifetime it is
//! configured with (FRC-1404, Section 4.5.1). A node built from a file that
//! sets a shorter lifetime runs at 300 s.

use super::*;
use crate::config::Config;
use crate::proto::coord::TreeCoordinate;

/// `COORD_CACHE_TTL` in milliseconds.
const FLOOR_MS: u64 = 300_000;

/// A node built from `yaml`.
fn node_from(yaml: &str) -> Node {
    let config: Config = serde_yaml::from_str(yaml).expect("the file parses");
    Node::new(config).unwrap_or_else(|e| panic!("{yaml:?} must build: {e}"))
}

/// Write one entry at `t0` and report whether it is still live just short
/// of the floor.
fn live_just_short_of_the_floor(node: &mut Node) -> bool {
    let target = make_node_addr(0x42);
    let coords = TreeCoordinate::from_addrs(vec![target, *node.node_addr()]).unwrap();
    let t0 = 1_000_000;
    let _ = node.coord_cache_mut().insert(target, coords, t0);
    assert!(
        node.coord_cache().contains(&target, t0),
        "precondition: the entry was written"
    );
    node.coord_cache().contains(&target, t0 + FLOOR_MS - 1)
}

#[test]
fn a_coord_ttl_below_three_hundred_seconds_does_not_expire_entries_before_the_floor() {
    let mut node = node_from("node:\n  cache:\n    coord_ttl_secs: 10\n");
    assert!(
        live_just_short_of_the_floor(&mut node),
        "coord_ttl_secs: 10 was used as given and an entry expired before 300 s"
    );
}

#[test]
fn the_default_and_a_coord_ttl_of_three_hundred_seconds_build_a_node_that_keeps_entries_to_the_floor()
 {
    for yaml in ["node: {}\n", "node:\n  cache:\n    coord_ttl_secs: 300\n"] {
        let mut node = node_from(yaml);
        assert!(
            live_just_short_of_the_floor(&mut node),
            "{yaml:?}: an entry must live until the floor"
        );
    }
}
