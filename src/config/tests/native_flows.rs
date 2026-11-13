//! Tests for the native API flow ceiling in `Config::validate`
//! (`node.native_api.max_flows`).

use super::*;

#[test]
fn validate_refuses_native_api_max_flows_of_zero() {
    // Zero starts a node whose native API admits no flow: every client
    // connect is refused with EMFILE and every peer arrival is dropped.
    let mut config = Config::default();
    config.node.native_api.max_flows = 0;

    let err = config.validate().expect_err("validation should fail");
    let msg = err.to_string();
    assert!(msg.contains("node.native_api.max_flows"), "got: {msg}");
}

#[test]
fn validate_accepts_native_api_max_flows_of_one() {
    // One is the smallest working ceiling: a single flow fits, and the
    // per-peer share rounds up to one.
    let mut config = Config::default();
    config.node.native_api.max_flows = 1;

    config.validate().expect("max_flows of 1 should validate");
}
