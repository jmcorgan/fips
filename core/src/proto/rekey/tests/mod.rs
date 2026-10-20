//! Tests of the rekey machine that drive it through its public interface:
//! a stub profile, a test shell, and one file per group of transition
//! tables. Tests of one module's private items sit beside these as
//! `tests/<module>.rs`, attached from that module.

mod explore;
// The `slow-tests` feature (see the crate's Cargo.toml) gates the
// guard-switch meta-test.
#[cfg(feature = "slow-tests")]
mod faults;
mod fmp;
mod fsp;
mod next;
mod regress;
mod sim;
pub(crate) mod stub;
mod survivors;

#[test]
fn the_wildcard_arm_fence_is_declared_at_the_module_root() {
    let root = include_str!("../mod.rs");
    assert!(
        root.lines()
            .any(|l| l.trim() == "#![deny(clippy::wildcard_enum_match_arm)]"),
        "every transition match stays exhaustive only while the lint is denied at the module root"
    );
}

/// Every source file of the machine, for the setter scan.
const SOURCES: &[(&str, &str)] = &[
    ("mod.rs", include_str!("../mod.rs")),
    ("access.rs", include_str!("../access.rs")),
    ("candidates.rs", include_str!("../candidates.rs")),
    ("cycle.rs", include_str!("../cycle.rs")),
    ("epoch.rs", include_str!("../epoch.rs")),
    ("faults.rs", include_str!("../faults.rs")),
    ("hooks.rs", include_str!("../hooks.rs")),
    ("keys.rs", include_str!("../keys.rs")),
    ("ladder.rs", include_str!("../ladder.rs")),
    ("lease.rs", include_str!("../lease.rs")),
    ("machine.rs", include_str!("../machine.rs")),
    ("params.rs", include_str!("../params.rs")),
    ("profile.rs", include_str!("../profile.rs")),
    ("proof.rs", include_str!("../proof.rs")),
    ("reason.rs", include_str!("../reason.rs")),
    ("record.rs", include_str!("../record.rs")),
    ("resolve.rs", include_str!("../resolve.rs")),
];

/// The lines of `source` that define a setter, by its `set_` name.
fn setters(source: &str) -> alloc::vec::Vec<&str> {
    source.lines().filter(|l| l.contains("fn set_")).collect()
}

#[test]
fn no_machine_source_defines_a_state_setter_and_the_scan_finds_a_planted_one() {
    let planted = "#[cfg(test)]\n    pub(crate) fn set_cycle(&mut self, c: Cycle) {}\n";
    assert_eq!(setters(planted).len(), 1, "the scan finds a planted setter");
    for (name, source) in SOURCES {
        assert!(
            setters(source).is_empty(),
            "{name} defines a setter, so a test could reach a state production cannot: {:?}",
            setters(source)
        );
    }
    let on_disk = std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/src/proto/rekey"))
        .expect("the module directory reads")
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".rs"))
        .count();
    assert_eq!(
        on_disk,
        SOURCES.len(),
        "every source file of the machine is scanned"
    );
}
