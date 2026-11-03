//! Planted tests for the known-defect lane's self-check.
//!
//! `testing/known-defect-lane.sh` runs each of these through its classifier
//! (`testing/lib/test-verdict.sh`) before it runs any inventory entry, and
//! fails if one is not classified as its name says. Together they show the
//! lane tells a test that failed at its `defect:` assertion from one that
//! failed anywhere else. They are ignored, inventoried as `helper`, and run
//! nowhere else.

use std::hint::black_box;

/// A setup helper whose own check has a plain message, the shape of a shared
/// helper's `expect` that a settlement test cannot mark (for example
/// `spanning_tree::add_loopback_alias`).
fn planted_setup(present: bool) -> u32 {
    black_box(present)
        .then_some(1)
        .expect("the planted helper's input must be present")
}

#[test]
#[ignore = "helper: the known-defect lane's self-check expects it to fail at its precondition"]
fn a_planted_failure_at_its_precondition() {
    assert!(black_box(false), "precondition: the planted setup holds");
}

#[test]
#[ignore = "helper: the known-defect lane's self-check expects it to fail at a bare unwrap"]
fn a_planted_failure_at_a_bare_unwrap() {
    let missing: Option<u32> = black_box(None);
    let _ = missing.unwrap();
}

#[test]
#[ignore = "helper: the known-defect lane's self-check expects it to fail in a setup helper"]
fn a_planted_failure_at_a_plain_expect_in_a_setup_helper() {
    let _ = planted_setup(false);
}

#[test]
#[ignore = "helper: the known-defect lane's self-check expects it to fail at its defect assertion"]
fn a_planted_failure_at_its_defect_assertion() {
    let held = planted_setup(true);
    assert_eq!(held, 1, "precondition: the planted setup holds");
    assert_eq!(black_box(held), 2, "defect: the planted behaviour is wrong");
}

#[test]
#[ignore = "helper: the known-defect lane's self-check expects it to pass"]
fn a_planted_test_that_passes() {
    let held = planted_setup(true);
    assert_eq!(black_box(held), 1, "defect: the planted behaviour is wrong");
}
