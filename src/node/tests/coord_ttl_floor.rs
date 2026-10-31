//! The least lifetime of a coordinate cache entry against
//! `node.cache.coord_ttl_secs`.
//!
//! A node must not let an entry expire before `COORD_CACHE_TTL` (300 s) has
//! elapsed since it was last written or read, whatever lifetime it is
//! configured with (FRC-1404, Section 4.5.1). A node built from a file that
//! sets a shorter lifetime runs at 300 s.
//!
//! The test-only `node.cache.test_coord_ttl_secs` sets a shorter lifetime for
//! test harnesses, honoured only by a build with the `test-overrides`
//! feature. The tests named `test_only_coord_ttl` cover it: the
//! `cfg(not(feature = "test-overrides"))` ones run in the default test build
//! and show the key cannot lower the lifetime there, and the
//! `cfg(feature = "test-overrides")` ones run under
//! `cargo test --features test-overrides` and show it is honoured.

use super::*;
use crate::config::Config;
use crate::proto::coord::TreeCoordinate;
use crate::testutil::{LogCapture, capture_logs, log_field};

/// `COORD_CACHE_TTL` in milliseconds.
const FLOOR_MS: u64 = 300_000;

/// A file that sets only the test-only lifetime, at 10 s.
const OVERRIDE: &str = "node:\n  cache:\n    test_coord_ttl_secs: 10\n";

/// The lifetime `OVERRIDE` sets, in milliseconds.
const OVERRIDE_MS: u64 = 10_000;

/// The warning a build with `test-overrides` logs for the test-only key.
const HONOURED: &str = "test-only key honoured by this test-overrides build; coordinate cache entries expire at this lifetime, whatever the 300 s floor";

/// The warning any other build logs for the test-only key.
const IGNORED: &str =
    "test-only key, honoured only by a build with the test-overrides feature; ignored";

/// The lifetime in milliseconds a node built from `OVERRIDE` must run with
/// in this build: the override with `test-overrides`, the floor without.
fn expected_ms() -> u64 {
    if cfg!(feature = "test-overrides") {
        OVERRIDE_MS
    } else {
        FLOOR_MS
    }
}

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

/// A node built from `OVERRIDE` by `build`, and the log written while
/// building it.
fn built_from_override(
    build: impl FnOnce(Config) -> Result<Node, NodeError>,
) -> (Node, LogCapture) {
    let config: Config = serde_yaml::from_str(OVERRIDE).expect("the file parses");
    let (node, logs) = capture_logs(|| build(config));
    let node = node.unwrap_or_else(|e| panic!("{OVERRIDE:?} must build: {e}"));
    (node, logs)
}

/// Assert that `logs` holds the warning naming the test-only key, with
/// target `fips::config`, `configured` 10, and the message and value used
/// that this build logs.
fn assert_override_warning(logs: &LogCapture) {
    let message = if cfg!(feature = "test-overrides") {
        HONOURED
    } else {
        IGNORED
    };
    assert_eq!(
        logs.targets(message),
        vec!["fips::config"],
        "test_coord_ttl_secs: 10 was handled without a warning naming it: {:?}",
        logs.lines()
    );
    let line = logs.line(message).unwrap();
    assert_eq!(
        log_field(&line, "key"),
        Some("\"node.cache.test_coord_ttl_secs\""),
        "{line}"
    );
    assert_eq!(log_field(&line, "configured"), Some("10"), "{line}");
    let used = (expected_ms() / 1000).to_string();
    assert_eq!(log_field(&line, "used"), Some(used.as_str()), "{line}");
}

/// Whether a path MTU entry learned at `t0` by a node built from `OVERRIDE`
/// is still held after the expiry pass runs at `t0 + after_ms`.
fn path_mtu_held_after(after_ms: u64) -> bool {
    let (mut node, _) = built_from_override(Node::new);
    let dest = crate::Ipv6Address::from_node_addr(&make_node_addr(0x43));
    let t0 = 1_000_000;
    node.path_mtu_lookup_learn(dest, 800, t0);
    assert_eq!(
        node.path_mtu_lookup_get(&dest),
        Some(800),
        "precondition: the entry was learned"
    );
    node.purge_expired_path_mtu(t0 + after_ms);
    node.path_mtu_lookup_get(&dest) == Some(800)
}

#[cfg(not(feature = "test-overrides"))]
#[test]
fn a_test_only_coord_ttl_key_is_ignored_with_a_warning_by_a_build_without_test_overrides() {
    let (mut node, logs) = built_from_override(Node::new);
    assert_eq!(
        node.coord_cache().default_ttl_ms(),
        FLOOR_MS,
        "test_coord_ttl_secs: 10 changed the lifetime of a build without test-overrides"
    );
    assert!(
        live_just_short_of_the_floor(&mut node),
        "test_coord_ttl_secs: 10 expired an entry before 300 s in a build without test-overrides"
    );
    assert_override_warning(&logs);
}

#[cfg(not(feature = "test-overrides"))]
#[test]
fn a_test_only_coord_ttl_key_does_not_shorten_the_path_mtu_expiry_in_a_build_without_test_overrides()
 {
    assert!(
        path_mtu_held_after(FLOOR_MS - 1),
        "test_coord_ttl_secs: 10 expired a path MTU entry before 300 s in a build without test-overrides"
    );
}

#[cfg(feature = "test-overrides")]
#[test]
fn a_test_only_coord_ttl_key_sets_the_coordinate_cache_lifetime_in_a_test_overrides_build() {
    let (mut node, logs) = built_from_override(Node::new);
    assert_eq!(
        node.coord_cache().default_ttl_ms(),
        OVERRIDE_MS,
        "default_ttl_ms is not the 10000 test_coord_ttl_secs set"
    );
    let target = make_node_addr(0x42);
    let coords = TreeCoordinate::from_addrs(vec![target, *node.node_addr()]).unwrap();
    let t0 = 1_000_000;
    let _ = node.coord_cache_mut().insert(target, coords, t0);
    assert!(
        node.coord_cache().contains(&target, t0 + OVERRIDE_MS),
        "an entry expired before the 10 s test_coord_ttl_secs set"
    );
    assert!(
        !node.coord_cache().contains(&target, t0 + OVERRIDE_MS + 1),
        "an entry outlived the 10 s test_coord_ttl_secs set"
    );
    assert_override_warning(&logs);

    let (node, logs) =
        built_from_override(|config| Node::with_identity(crate::Identity::generate(), config));
    assert_eq!(
        node.coord_cache().default_ttl_ms(),
        OVERRIDE_MS,
        "Node::with_identity: default_ttl_ms is not the 10000 test_coord_ttl_secs set"
    );
    assert_override_warning(&logs);
}

#[cfg(feature = "test-overrides")]
#[test]
fn a_test_only_coord_ttl_key_sets_the_path_mtu_expiry_in_a_test_overrides_build() {
    assert!(
        path_mtu_held_after(OVERRIDE_MS - 1),
        "a path MTU entry expired before the 10 s test_coord_ttl_secs set"
    );
    assert!(
        !path_mtu_held_after(OVERRIDE_MS),
        "a path MTU entry outlived the 10 s test_coord_ttl_secs set"
    );
}
