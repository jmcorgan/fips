//! Tests of peer settlement in a deterministic world: the world and its
//! transports, the reference model as a node of it, the named starts, the
//! bounded explorer, the settlement properties, the rekey machine's
//! decisions, and a model of the current node. See this directory's
//! README.
//!
//! The scans below read the settlement sources through the rekey
//! machine's code reader, so comments and string literals never count.

#[cfg(feature = "slow-tests")]
mod candidates;
mod cmp;
mod drive;
mod explore;
mod faults;
mod legacy;
mod oracle;
mod party;
mod regress;
mod rekeyside;
mod shadow;
mod shapes;
mod sim;
mod starts;
mod stub;
mod world;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::faults::Fault;
use crate::proto::rekey::{code_idents, code_text};

/// Every source file of the settlement core, beside the model and the
/// tests.
const SOURCES: &[(&str, &str)] = &[
    ("mod.rs", include_str!("../mod.rs")),
    ("faults.rs", include_str!("../faults.rs")),
    ("gates.rs", include_str!("../gates.rs")),
    ("input.rs", include_str!("../input.rs")),
    ("legs.rs", include_str!("../legs.rs")),
    ("links.rs", include_str!("../links.rs")),
    ("output.rs", include_str!("../output.rs")),
    ("params.rs", include_str!("../params.rs")),
    ("table.rs", include_str!("../table.rs")),
];

/// Every source file of the reference model, its tests included.
const MODEL: &[(&str, &str)] = &[
    ("model/mod.rs", include_str!("../model/mod.rs")),
    ("model/history.rs", include_str!("../model/history.rs")),
    ("model/judge.rs", include_str!("../model/judge.rs")),
    ("model/tests/mod.rs", include_str!("../model/tests/mod.rs")),
    (
        "model/tests/classify.rs",
        include_str!("../model/tests/classify.rs"),
    ),
    (
        "model/tests/close.rs",
        include_str!("../model/tests/close.rs"),
    ),
    (
        "model/tests/crossing.rs",
        include_str!("../model/tests/crossing.rs"),
    ),
    (
        "model/tests/gates.rs",
        include_str!("../model/tests/gates.rs"),
    ),
];

/// The core's modules, which no model source may name.
const CORE_MODULES: &[&str] = &[
    "links", "legs", "gates", "table", "input", "output", "params",
];

/// The one line of the core that names the model: its declaration.
const MODEL_DECLARATION: &str = "pub mod model;";

/// The settlement directory on disk, or `rel` below it.
fn dir(rel: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/proto/settle")
        .join(rel)
}

/// The contents of the `.rs` files in `path`, and below it when `deep`.
fn files(path: &std::path::Path, deep: bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(path)
        .expect("the directory reads")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            if deep {
                out.extend(files(&p, true));
            }
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(std::fs::read_to_string(&p).expect("the file reads"));
        }
    }
    out
}

/// Whether `source` declares the wildcard-arm deny at its root.
fn fenced(source: &str) -> bool {
    code_text(source)
        .lines()
        .any(|l| l.trim() == "#![deny(clippy::wildcard_enum_match_arm)]")
}

#[test]
fn the_wildcard_arm_fence_is_declared_at_the_settlement_root() {
    let root = include_str!("../mod.rs");
    let unfenced = root.replace("#![deny(clippy::wildcard_enum_match_arm)]", "");
    assert!(!fenced(&unfenced), "the scan finds a root without the deny");
    assert!(
        fenced(root),
        "every match over the core's states stays exhaustive only while the lint is denied at the module root"
    );
}

/// The lines of `source` that define a setter, by its `set_` name.
fn setters(source: &str) -> Vec<usize> {
    code_idents(source)
        .windows(2)
        .filter(|w| w[0].1 == "fn" && w[1].1.starts_with("set_"))
        .map(|w| w[1].0)
        .collect()
}

#[test]
fn no_core_source_defines_a_setter_and_the_scan_finds_a_planted_one() {
    for (name, source) in SOURCES {
        assert!(
            setters(source).is_empty(),
            "{name} defines a setter at lines {:?}, so a test could reach a state the inputs cannot",
            setters(source)
        );
    }
    let planted = "impl Links {\n    pub(crate) fn set_holder(&mut self) {}\n}\n";
    assert_eq!(setters(planted), [2], "the scan finds a planted setter");
}

/// The lines of the core source `name` that name the model, other than
/// its declaration in `mod.rs`. The model's items share names with the
/// core's, so the scan looks for the module's name, which no core item
/// takes.
fn core_reaches(name: &str, source: &str) -> Vec<usize> {
    let lines: Vec<&str> = source.lines().collect();
    code_idents(source)
        .into_iter()
        .filter(|(n, w)| {
            w == "model"
                && !(name == "mod.rs"
                    && lines
                        .get(n - 1)
                        .is_some_and(|l| l.trim() == MODEL_DECLARATION))
        })
        .map(|(n, _)| n)
        .collect()
}

#[test]
fn no_core_source_reaches_into_the_model_and_the_scan_finds_a_planted_path() {
    let links = include_str!("../links.rs");
    for plant in [
        "use super::model::judge::Judge;",
        "use crate::proto::settle::{model, links};",
    ] {
        let planted = format!("{links}\n{plant}\n");
        assert!(
            !core_reaches("links.rs", &planted).is_empty(),
            "the scan finds {plant} planted in links.rs"
        );
    }
    for (name, source) in SOURCES {
        let hits = core_reaches(name, source);
        assert!(
            hits.is_empty(),
            "{name} names the model at lines {hits:?}; the core must stand without it"
        );
    }
}

/// Whether `c` can be part of an identifier.
fn ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The identifiers of the braced group that opens `group`, nested groups
/// included.
fn group_idents(group: &str) -> Vec<&str> {
    let mut depth = 0usize;
    let end = group
        .char_indices()
        .find(|&(_, c)| {
            if c == '{' {
                depth += 1;
            } else if c == '}' {
                depth -= 1;
            }
            depth == 0
        })
        .map_or(group.len(), |(i, _)| i);
    group[..end].split(|c: char| !ident(c)).collect()
}

/// The core modules a model source names by a path through `super` or
/// `settle`, alone or in a braced group.
fn model_reaches(source: &str) -> Vec<String> {
    let code: String = code_text(source)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let mut hits = Vec::new();
    for base in ["super::", "settle::"] {
        let mut from = 0;
        while let Some(at) = code[from..].find(base) {
            let start = from + at;
            from = start + base.len();
            if code[..start].chars().next_back().is_some_and(ident) {
                continue;
            }
            let rest = &code[from..];
            let named: Vec<&str> = if rest.starts_with('{') {
                group_idents(rest)
            } else {
                rest.split(|c: char| !ident(c)).take(1).collect()
            };
            for m in CORE_MODULES {
                if named.contains(m) {
                    hits.push(format!("{base}{m}"));
                }
            }
        }
    }
    hits
}

#[test]
fn no_model_source_reaches_into_the_core_and_the_scan_finds_a_planted_path() {
    let judge = include_str!("../model/judge.rs");
    for plant in [
        "use super::super::table::Table;",
        "use crate::proto::settle::{links::Links, model};",
    ] {
        let planted = format!("{judge}\n{plant}\n");
        assert!(
            !model_reaches(&planted).is_empty(),
            "the scan finds {plant} planted in model/judge.rs"
        );
    }
    for (name, source) in MODEL {
        let hits = model_reaches(source);
        assert!(
            hits.is_empty(),
            "{name} names the core through {hits:?}; the model must stand without it"
        );
    }
}

#[test]
fn every_core_and_model_source_file_is_scanned() {
    assert_eq!(
        files(&dir(""), false).len(),
        SOURCES.len(),
        "every source file of the core is in the scans' list"
    );
    assert_eq!(
        files(&dir("model"), true).len(),
        MODEL.len(),
        "every source file of the model is in the scans' list"
    );
}

/// The names of the tests `source` defines.
fn tests_in(source: &str) -> Vec<String> {
    let code = code_text(source);
    let lines: Vec<&str> = code.lines().collect();
    let mut out = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        if l.trim() != "#[test]" {
            continue;
        }
        let name = lines[i + 1..]
            .iter()
            .map(|l| l.trim())
            .find(|l| !l.starts_with("#["))
            .and_then(|l| l.split("fn ").nth(1))
            .and_then(|l| l.split('(').next())
            .expect("a test attribute is followed by its function");
        out.push(String::from(name.trim()));
    }
    out
}

#[test]
fn every_settlement_test_is_named_by_a_switch_or_listed_and_the_scan_finds_a_planted_one() {
    let tests: Vec<String> = files(&dir("tests"), true)
        .iter()
        .flat_map(|text| tests_in(text))
        .collect();
    for (name, source) in SOURCES {
        assert!(
            tests_in(source).is_empty(),
            "{name} holds a test; the core's tests go in the tests directory"
        );
    }
    let missing = faults::uncovered(
        &tests,
        faults::ROWS,
        faults::SELF_CHECKED,
        faults::CHARACTERISATION,
    );
    assert!(
        missing.is_empty(),
        "these tests are named by no switch's row, plant no break of their own and are not characterisation: {missing:?}"
    );
    let planted = [String::from("a_planted_test_no_switch_names")];
    assert_eq!(
        faults::uncovered(
            &planted,
            faults::ROWS,
            faults::SELF_CHECKED,
            faults::CHARACTERISATION
        ),
        ["a_planted_test_no_switch_names"],
        "the scan finds a planted test on no list"
    );
    let stale: Vec<&str> = faults::ROWS
        .iter()
        .flat_map(|(_, ts)| ts.iter().map(|(_, n)| *n))
        .chain(faults::SELF_CHECKED.iter().copied())
        .chain(faults::CHARACTERISATION.iter().map(|(n, _)| *n))
        .filter(|n| !tests.iter().any(|t| t == n))
        .collect();
    assert!(
        stale.is_empty(),
        "the tables name tests the scan cannot find: {stale:?}"
    );
}

#[test]
fn every_switch_has_a_row_and_the_scan_finds_a_row_removed() {
    let missing = faults::rowless(Fault::ALL, faults::ROWS);
    assert!(
        missing.is_empty(),
        "these switches have no row, so nothing shows its guard can fail: {missing:?}"
    );
    let first = faults::ROWS[0].0;
    assert_eq!(
        faults::rowless(&[first], &faults::ROWS[1..]),
        [first],
        "the scan finds a switch whose row was removed"
    );
}
