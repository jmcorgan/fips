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
mod joint;
mod legacy;
mod oracle;
mod party;
mod regress;
mod shadow;
mod shapes;
mod sim;
mod starts;
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
    ("join.rs", include_str!("../join.rs")),
    ("legs.rs", include_str!("../legs.rs")),
    ("links.rs", include_str!("../links.rs")),
    ("output.rs", include_str!("../output.rs")),
    ("params.rs", include_str!("../params.rs")),
    ("parity.rs", include_str!("../parity.rs")),
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
        faults::REKEY,
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
            faults::REKEY,
            faults::SELF_CHECKED,
            faults::CHARACTERISATION
        ),
        ["a_planted_test_no_switch_names"],
        "the scan finds a planted test on no list"
    );
    let stale: Vec<&str> = faults::ROWS
        .iter()
        .flat_map(|(_, ts)| ts.iter().map(|(_, n)| *n))
        .chain(
            faults::REKEY
                .iter()
                .flat_map(|(_, ts)| ts.iter().map(|(_, n)| *n)),
        )
        .chain(faults::SELF_CHECKED.iter().copied())
        .chain(faults::CHARACTERISATION.iter().map(|(n, _)| *n))
        .filter(|n| !tests.iter().any(|t| t == n))
        .collect();
    assert!(
        stale.is_empty(),
        "the tables name tests the scan cannot find: {stale:?}"
    );
}

/// The rekey machine's switches, read from its source.
const REKEY_FAULTS: &str = include_str!("../../rekey/faults.rs");

/// The names of `rekey` that are no switch of the rekey machine, whose
/// list in `source` names each as `Self::<name>`: a child would panic on
/// such a name, red for the wrong reason.
fn unknown(rekey: &[faults::RekeyRow], source: &str) -> Vec<&'static str> {
    let idents = code_idents(source);
    rekey
        .iter()
        .map(|(n, _)| *n)
        .filter(|n| !idents.windows(2).any(|w| w[0].1 == "Self" && w[1].1 == *n))
        .collect()
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
    let unnamed = unknown(faults::REKEY, REKEY_FAULTS);
    assert!(
        unnamed.is_empty(),
        "these rekey rows name no switch of the rekey machine: {unnamed:?}"
    );
    let planted: &[faults::RekeyRow] = &[("NoSuchSwitch", &[])];
    assert_eq!(
        unknown(planted, REKEY_FAULTS),
        ["NoSuchSwitch"],
        "the scan finds a rekey row naming no switch"
    );
}

/// The `.rs` files directly in the joint world's directory, by name.
fn joint_sources() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = std::fs::read_dir(dir("tests/joint"))
        .expect("the directory reads")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .map(|p| {
            let name = p
                .file_name()
                .and_then(|n| n.to_str())
                .map(String::from)
                .expect("a file name");
            (name, std::fs::read_to_string(&p).expect("the file reads"))
        })
        .collect();
    out.sort();
    assert!(
        out.iter().any(|(n, _)| n == "party.rs"),
        "the joint world's sources are found"
    );
    out
}

#[test]
fn no_joint_source_defines_a_setter_and_the_scan_finds_a_planted_one() {
    for (name, source) in joint_sources() {
        assert!(
            setters(&source).is_empty(),
            "joint/{name} defines a setter at lines {:?}, so a test could reach a state the world's inputs cannot",
            setters(&source)
        );
    }
    let planted = "impl Machines {\n    pub(super) fn set_active(&mut self) {}\n}\n";
    assert_eq!(setters(planted), [2], "the scan finds a planted setter");
}

/// The lines of `source` whose code names the wildcard-arm lint: under
/// the joint world the lint is only ever denied, at the settlement root.
fn wildcards(source: &str) -> Vec<usize> {
    code_text(source)
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains("wildcard_enum_match_arm"))
        .map(|(n, _)| n + 1)
        .collect()
}

#[test]
fn no_joint_source_allows_a_wildcard_arm_and_the_scan_finds_a_planted_one() {
    for (name, source) in joint_sources() {
        assert!(
            wildcards(&source).is_empty(),
            "joint/{name} names the wildcard-arm lint at lines {:?}; a match over a machine's outputs or a core output must name every arm",
            wildcards(&source)
        );
    }
    for plant in [
        "#[allow(clippy::wildcard_enum_match_arm)]",
        "#[expect(clippy::too_many_arguments, clippy::wildcard_enum_match_arm)]",
    ] {
        let planted = format!("fn route() {{}}\n{plant}\nfn moved() {{}}\n");
        assert_eq!(wildcards(&planted), [2], "the scan finds {plant} planted");
    }
}

/// The name a joint node's shell binds the core's record of a held peer
/// to, wherever it reads one.
const HELD: &str = "h";

/// The functions of a joint source allowed to read the core's record of
/// where a held peer is, `Held.current`, each with why: the node's own
/// address for the peer is the bundle's active path, and the core's
/// record is read for the oracles alone.
const READS_CURRENT: &[(&str, &str, &str)] = &[
    ("party.rs", "view", "the view's record of the peer"),
    (
        "party.rs",
        "facts",
        "the joint oracles' input, which the paths' mirror compares with the active path",
    ),
    (
        "party.rs",
        "attribute",
        "attribution's judge, naming the pinned shapes where the core's rule is wider",
    ),
    (
        "party.rs",
        "to",
        "the switch that sends by the core's record, the defect's shape",
    ),
];

/// Each read of `<HELD>.current` in `source`, with the function it is in.
fn current_reads(source: &str) -> Vec<(usize, String)> {
    let code = code_text(source);
    let needle = format!("{HELD}.current");
    let mut func = String::new();
    let mut out = Vec::new();
    for (n, line) in code.lines().enumerate() {
        let words: Vec<&str> = line.split(|c: char| !ident(c)).collect();
        if let Some(i) = words.iter().position(|w| *w == "fn")
            && let Some(name) = words[i + 1..].iter().find(|w| !w.is_empty())
        {
            func = String::from(*name);
        }
        let mut from = 0;
        while let Some(at) = line[from..].find(&needle) {
            let start = from + at;
            from = start + needle.len();
            let before = line[..start].chars().next_back();
            let after = line[from..].chars().next();
            if !before.is_some_and(ident) && !after.is_some_and(ident) {
                out.push((n + 1, func.clone()));
            }
        }
    }
    out
}

/// The reads of `Held.current` in the joint source `name` outside the
/// functions [`READS_CURRENT`] allows.
fn stray_reads(name: &str, source: &str) -> Vec<(usize, String)> {
    current_reads(source)
        .into_iter()
        .filter(|(_, f)| {
            !READS_CURRENT
                .iter()
                .any(|(file, func, _)| *file == name && func == f)
        })
        .collect()
}

#[test]
fn the_cores_record_of_where_a_peer_is_is_read_only_for_the_oracles_and_the_scan_finds_a_planted_read()
 {
    let mut seen = Vec::new();
    for (name, source) in joint_sources() {
        let stray = stray_reads(&name, &source);
        assert!(
            stray.is_empty(),
            "joint/{name} reads the core's record of where a peer is outside the view and the oracles, at (line, function) {stray:?}; the shell's address for the peer is the bundle's active path"
        );
        seen.extend(
            current_reads(&source)
                .into_iter()
                .map(|(_, f)| (name.clone(), f)),
        );
    }
    for (file, func, _) in READS_CURRENT {
        assert!(
            seen.iter().any(|(n, f)| n == file && f == func),
            "joint/{file}'s {func} no longer reads the core's record; its entry is stale"
        );
    }
    let party = std::fs::read_to_string(dir("tests/joint/party.rs")).expect("the file reads");
    let planted = format!("{party}\nfn reply(h: &Held) -> Pair {{\n    h.current.clone()\n}}\n");
    let stray = stray_reads("party.rs", &planted);
    assert_eq!(
        stray.iter().map(|(_, f)| f.as_str()).collect::<Vec<_>>(),
        ["reply"],
        "the scan finds a planted read: {stray:?}"
    );
    assert!(
        stray_reads(
            "party.rs",
            "fn reply(h: &Held) -> bool {\n    h.currently\n}\n"
        )
        .is_empty(),
        "and does not take another field for it"
    );
}

/// The names the deleted transcription of the rekey machine and the
/// stand-in core's party went by.
const RETIRED: &[&str] = &["RekeySide", "CoreParty", "TwinParty", "rekeyside"];

/// The lines of `source` whose code names one of [`RETIRED`].
fn retired(source: &str) -> Vec<usize> {
    let mut out: Vec<usize> = code_idents(source)
        .into_iter()
        .filter(|(_, w)| RETIRED.contains(&w.as_str()))
        .map(|(n, _)| n)
        .collect();
    out.dedup();
    out
}

#[test]
fn no_settlement_test_names_the_retired_rekey_transcription_and_the_scan_finds_a_planted_one() {
    for source in files(&dir("tests"), true) {
        let found = retired(&source);
        let first = source.lines().next().unwrap_or_default();
        assert!(
            found.is_empty(),
            "a settlement test names the retired rekey transcription at lines {found:?} (the file begins {first:?}); a joint node runs the real machine"
        );
    }
    let planted = "// RekeySide in a comment is not code\nuse super::rekeyside::{RekeySide};\n";
    assert_eq!(retired(planted), [2], "the scan finds a planted use");
}
