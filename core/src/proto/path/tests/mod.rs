//! Tests of the path module as a whole: the shell that drives a `Bundle`
//! through its inputs and checks every call, the behaviour tests built on
//! it, and checks on the module's source. Tests of one file's private items
//! sit beside this file as `tests/<file>.rs`, attached from that file.

use alloc::vec::Vec;

mod account;
mod active;
mod admit;
mod capability;
mod charge;
mod choice;
mod close;
mod connect;
mod disabled;
mod exchange;
mod floor;
mod hold;
mod intake;
mod liveness;
mod pin;
mod renew;
pub(crate) mod shell;
mod sim;
mod stub;
mod view;

#[test]
fn the_wildcard_arm_fence_is_declared_at_the_path_module_root() {
    let root = include_str!("../mod.rs");
    assert!(
        root.lines()
            .any(|l| l.trim() == "#![deny(clippy::wildcard_enum_match_arm)]"),
        "every match on the module's enums stays exhaustive only while the lint is denied at \
         the module root"
    );
}

/// The `.rs` files directly under `dir`, relative to the module.
fn on_disk(dir: &str) -> usize {
    let path = std::format!("{}/src/proto/path/{dir}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_dir(path)
        .expect("the directory reads")
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".rs"))
        .count()
}

/// Every source file of the module, for the setter scan.
const SOURCES: &[(&str, &str)] = &[
    ("candidate.rs", include_str!("../candidate.rs")),
    ("capable.rs", include_str!("../capable.rs")),
    ("live.rs", include_str!("../live.rs")),
    ("machine.rs", include_str!("../machine.rs")),
    ("mod.rs", include_str!("../mod.rs")),
    ("params.rs", include_str!("../params.rs")),
    ("rules.rs", include_str!("../rules.rs")),
    ("select.rs", include_str!("../select.rs")),
    ("set.rs", include_str!("../set.rs")),
    ("wire.rs", include_str!("../wire.rs")),
];

/// The lines of `source` that define a setter, by its `set_` name.
fn setters(source: &str) -> Vec<&str> {
    source.lines().filter(|l| l.contains("fn set_")).collect()
}

#[test]
fn no_path_source_defines_a_state_setter_and_the_scan_finds_a_planted_one() {
    let planted = "#[cfg(test)]\n    pub(crate) fn set_state(&mut self, s: PathState) {}\n";
    assert_eq!(setters(planted).len(), 1, "the scan finds a planted setter");
    for (name, source) in SOURCES {
        assert!(
            setters(source).is_empty(),
            "{name} defines a setter, so a test could reach a state the machine cannot: {:?}",
            setters(source)
        );
    }
    assert_eq!(on_disk(""), SOURCES.len(), "every source file is scanned");
}

/// Every test file of the module, for the scan of who changes a path.
const TESTS: &[(&str, &str)] = &[
    ("account.rs", include_str!("account.rs")),
    ("active.rs", include_str!("active.rs")),
    ("admit.rs", include_str!("admit.rs")),
    ("candidate.rs", include_str!("candidate.rs")),
    ("capability.rs", include_str!("capability.rs")),
    ("capable.rs", include_str!("capable.rs")),
    ("charge.rs", include_str!("charge.rs")),
    ("choice.rs", include_str!("choice.rs")),
    ("close.rs", include_str!("close.rs")),
    ("connect.rs", include_str!("connect.rs")),
    ("disabled.rs", include_str!("disabled.rs")),
    ("exchange.rs", include_str!("exchange.rs")),
    ("floor.rs", include_str!("floor.rs")),
    ("hold.rs", include_str!("hold.rs")),
    ("intake.rs", include_str!("intake.rs")),
    ("live.rs", include_str!("live.rs")),
    ("liveness.rs", include_str!("liveness.rs")),
    ("mod.rs", include_str!("mod.rs")),
    ("params.rs", include_str!("params.rs")),
    ("pin.rs", include_str!("pin.rs")),
    ("renew.rs", include_str!("renew.rs")),
    ("rules.rs", include_str!("rules.rs")),
    ("select.rs", include_str!("select.rs")),
    ("set.rs", include_str!("set.rs")),
    ("shell.rs", include_str!("shell.rs")),
    ("sim.rs", include_str!("sim.rs")),
    ("stub.rs", include_str!("stub.rs")),
    ("view.rs", include_str!("view.rs")),
    ("wire.rs", include_str!("wire.rs")),
];

/// The set's methods that change a path's state, address or standing,
/// built in pieces so that this file, which is scanned, does not name them.
const CHANGES: &[&str] = &[
    concat!("transi", "tion("),
    concat!("mark", "_dead("),
    concat!("mark", "_acked("),
    concat!("learn", "_peer("),
    concat!("acti", "vate("),
    concat!("readd", "ress("),
    concat!("disc", "ard("),
];

/// The lines of `source` that call one of [`CHANGES`].
fn changes(source: &str) -> Vec<&str> {
    source
        .lines()
        .filter(|l| CHANGES.iter().any(|c| l.contains(c)))
        .collect()
}

#[test]
fn only_the_machine_and_the_sets_own_tests_call_the_transition_methods() {
    let planted = concat!("    n.b.set.transi", "tion(1, PathState::Dead, now);\n");
    assert_eq!(changes(planted).len(), 1, "the scan finds a planted call");
    for (name, source) in TESTS {
        if *name == "set.rs" {
            continue;
        }
        assert!(
            changes(source).is_empty(),
            "{name} changes a path past the machine, so it could reach a state no input \
             reaches: {:?}",
            changes(source)
        );
    }
    assert_eq!(on_disk("tests"), TESTS.len(), "every test file is scanned");
}
