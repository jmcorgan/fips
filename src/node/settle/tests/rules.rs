//! The XX flow's incidental rules and the tests that record them.
//!
//! `core/src/proto/fmp/flow/rules.txt` names each rule of next's handshake
//! settlement whose outcome no clause of FRC-2201 and no decision fixes, and
//! `current.txt` beside it each test that asserts one; each such test says in
//! its doc comment that it records current behaviour. This check holds the
//! three together, over both crates' tests, which is why it lives in the
//! root crate: the root crate's sources can read the core's, and not the
//! other way round.
//!
//! The settlement core's own lists (`core/src/proto/settle/rules.txt` and
//! `current.txt`, rule IDs `S-NN`) mark tests of master's node, and next
//! does not check them. This check reads the XX lists alone, with rule IDs
//! `XX-NN`, and a doc line that names no XX rule is not its concern.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The incidental rules, one line each.
const RULES: &str = include_str!("../../../../core/src/proto/fmp/flow/rules.txt");

/// The tests that record them, one line per test and rule.
const CURRENT: &str = include_str!("../../../../core/src/proto/fmp/flow/current.txt");

/// How a marked test's doc line starts.
const MARK: &str = "Records current behaviour (";

/// What a marked test's doc line says of the outcome it records.
const OPEN: &str = "open to change by decision";

/// The classes a rule in `rules.txt` may have.
const CLASSES: &[&str] = &["I", "I-kept"];

/// The repository root, where both crates' sources are.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The root module file of `krate`, if it is one of the two.
fn crate_root(krate: &str) -> Option<PathBuf> {
    match krate {
        "fips-core" => Some(root().join("core/src/lib.rs")),
        "fips-mesh" => Some(root().join("src/lib.rs")),
        _ => None,
    }
}

/// The lines of `text` that are not blank and not comments.
fn entries(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(n, l)| (n + 1, l.trim()))
        .filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
}

/// Whether `id` is a rule ID of the XX lists, `XX-` and two digits.
fn rule_id(id: &str) -> bool {
    id.len() == 5 && id.starts_with("XX-") && id[3..].bytes().all(|b| b.is_ascii_digit())
}

/// The path attribute among `attrs`, if any.
fn path_attr(attrs: &[&str]) -> Option<String> {
    attrs.iter().find_map(|a| {
        let rest = a.trim().strip_prefix("#[path")?.trim_start();
        let rest = rest.strip_prefix('=')?.trim_start().strip_prefix('"')?;
        Some(rest.split('"').next()?.to_string())
    })
}

/// What is left of `line` after the attributes written at its start.
fn after_attrs(line: &str) -> (Vec<&str>, &str) {
    let mut attrs = Vec::new();
    let mut rest = line.trim_start();
    while rest.starts_with("#[") {
        let mut depth = 0usize;
        let end = rest
            .char_indices()
            .find(|&(_, c)| {
                if c == '[' {
                    depth += 1;
                } else if c == ']' {
                    depth -= 1;
                }
                depth == 0
            })
            .map_or(rest.len(), |(i, _)| i + 1);
        attrs.push(&rest[..end]);
        rest = rest[end..].trim_start();
    }
    (attrs, rest)
}

/// Whether `code` declares the file module `name`: `mod name;` with any
/// visibility.
fn declares(code: &str, name: &str) -> bool {
    let mut rest = code.trim();
    if let Some(r) = rest.strip_prefix("pub") {
        rest = r.trim_start();
        if rest.starts_with('(') {
            rest = rest.split_once(')').map_or("", |(_, r)| r).trim_start();
        }
    }
    rest.strip_prefix("mod")
        .filter(|r| r.starts_with(char::is_whitespace))
        .and_then(|r| r.trim().strip_suffix(';'))
        .is_some_and(|m| m.trim() == name)
}

/// The path attribute of the declaration of file module `name` in
/// `source`: `None` when there is no declaration, `Some(None)` when it has
/// no path attribute.
fn declaration(source: &str, name: &str) -> Option<Option<String>> {
    let lines: Vec<&str> = source.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let (mut attrs, code) = after_attrs(line);
        if !declares(code, name) {
            continue;
        }
        for above in lines[..i].iter().rev() {
            let t = above.trim();
            if t.starts_with("#[") {
                attrs.push(t);
            } else if !t.starts_with("///") {
                break;
            }
        }
        return Some(path_attr(&attrs));
    }
    None
}

/// The file module path `mods` names below the crate root `top`, resolved
/// as rustc does: through a path attribute relative to the declaring file's
/// directory, else beside a `lib.rs`, `mod.rs` or path-loaded file, else in
/// the directory named for the declaring file.
fn module_file(top: &Path, mods: &[&str]) -> Result<PathBuf, String> {
    let mut file = top.to_path_buf();
    let mut owns = true;
    for m in mods {
        let source = std::fs::read_to_string(&file)
            .map_err(|e| format!("{} does not read: {e}", file.display()))?;
        let dir = file.parent().map(Path::to_path_buf).unwrap_or_default();
        let next = match declaration(&source, m) {
            None => return Err(format!("{} declares no `mod {m};`", file.display())),
            Some(Some(p)) => {
                owns = true;
                dir.join(p)
            }
            Some(None) => {
                let base = if owns {
                    dir
                } else {
                    let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                    dir.join(stem)
                };
                let flat = base.join(format!("{m}.rs"));
                let file = if flat.exists() {
                    flat
                } else {
                    base.join(m).join("mod.rs")
                };
                owns = file.file_name().is_some_and(|n| n == "mod.rs");
                file
            }
        };
        file = next;
    }
    Ok(file)
}

/// Whether `line` defines the function `name`.
fn defines(line: &str, name: &str) -> bool {
    let words: Vec<&str> = line
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .collect();
    words.windows(2).any(|w| w[0] == "fn" && w[1] == name) && line.contains(&format!("{name}("))
}

/// One function of a source file, as the check reads it.
struct Function {
    /// Whether a test attribute is on it.
    test: bool,
    /// Its doc comment, its lines joined by spaces.
    doc: String,
}

/// The function `name` in `source`, with its doc comment and whether it is
/// a test.
fn function(source: &str, name: &str) -> Option<Function> {
    let lines: Vec<&str> = source.lines().collect();
    let at = lines.iter().position(|l| defines(l, name))?;
    let mut test = false;
    let mut doc = Vec::new();
    for above in lines[..at].iter().rev() {
        let t = above.trim();
        if t.starts_with("#[") {
            test |= t == "#[test]" || t.contains("::test");
        } else if let Some(d) = t.strip_prefix("///") {
            doc.push(d.trim());
        } else {
            break;
        }
    }
    doc.reverse();
    Some(Function {
        test,
        doc: doc.join(" "),
    })
}

/// The rule IDs the current-behaviour doc line in `doc` names, if it has
/// one that says the outcome is open to change.
fn marked(doc: &str) -> Option<BTreeSet<String>> {
    let at = doc.find(MARK)?;
    let named = &doc[at + MARK.len()..];
    let (inside, after) = named.split_once(')')?;
    if !after.contains(OPEN) {
        return None;
    }
    Some(
        inside
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .filter(|w| rule_id(w))
            .map(str::to_string)
            .collect(),
    )
}

/// The functions in every `.rs` file under `dir` whose doc comment carries
/// the current-behaviour line naming an XX rule, by file and name.
fn marks_under(dir: &Path, out: &mut BTreeSet<(PathBuf, String)>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("the directory reads")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            marks_under(&p, out);
            continue;
        }
        if p.extension().is_none_or(|x| x != "rs") {
            continue;
        }
        let source = std::fs::read_to_string(&p).expect("the file reads");
        if !source.contains(MARK) {
            continue;
        }
        let mut doc = String::new();
        for line in source.lines() {
            let t = line.trim();
            if let Some(d) = t.strip_prefix("///") {
                doc.push_str(d.trim());
                doc.push(' ');
            } else if !t.starts_with("#[") {
                let name = t
                    .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .filter(|w| !w.is_empty())
                    .skip_while(|w| *w != "fn")
                    .nth(1);
                if let Some(name) = name
                    && marked(&doc).is_some_and(|ids| !ids.is_empty())
                {
                    out.insert((p.clone(), name.to_string()));
                }
                doc.clear();
            }
        }
    }
}

/// Every function of either crate that carries the current-behaviour line
/// naming an XX rule.
fn marks() -> BTreeSet<(PathBuf, String)> {
    let mut out = BTreeSet::new();
    marks_under(&root().join("core/src"), &mut out);
    marks_under(&root().join("src"), &mut out);
    out
}

/// A listed test as found: the file that defines it and the rules its doc
/// line names; or why it cannot be found.
type Found = Result<(PathBuf, BTreeSet<String>), String>;

/// Find the test a `current.txt` line names in `krate` at `path`.
fn find(krate: &str, path: &str) -> Found {
    let top = crate_root(krate).ok_or_else(|| format!("{krate} is not a crate of this tree"))?;
    let segments: Vec<&str> = path.split("::").collect();
    let (name, mods) = segments
        .split_last()
        .ok_or_else(|| format!("{path} names no test"))?;
    let file = module_file(&top, mods)?;
    let source = std::fs::read_to_string(&file)
        .map_err(|e| format!("{} does not read: {e}", file.display()))?;
    let f = function(&source, name)
        .ok_or_else(|| format!("{} defines no function {name}", file.display()))?;
    if !f.test {
        return Err(format!("{krate} {path} is not a test"));
    }
    let rules = marked(&f.doc)
        .ok_or_else(|| format!("{krate} {path} carries no current-behaviour doc line"))?;
    Ok((file, rules))
}

/// Every way `rules` and `current` disagree with each other, with the
/// tests `find` reads, and with the functions `marks` says carry the doc
/// line. Empty when they agree.
fn problems(
    rules: &str,
    current: &str,
    find: &dyn Fn(&str, &str) -> Found,
    marks: &BTreeSet<(PathBuf, String)>,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut tested: BTreeMap<String, bool> = BTreeMap::new();
    for (n, line) in entries(rules) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [id, class, status, ..] = fields[..] else {
            out.push(format!("rules.txt:{n} is not `ID CLASS STATUS TEXT`"));
            continue;
        };
        if !rule_id(id) {
            out.push(format!("rules.txt:{n}: {id} is not a rule ID"));
        }
        if !CLASSES.contains(&class) {
            out.push(format!(
                "rules.txt:{n}: {id} is class {class}; only I and I-kept rules are listed"
            ));
        }
        let status = match status {
            "tested" => true,
            "untested" => false,
            other => {
                out.push(format!(
                    "rules.txt:{n}: {id} is {other}, not tested or untested"
                ));
                continue;
            }
        };
        if fields.len() < 4 {
            out.push(format!("rules.txt:{n}: {id} says nothing of its rule"));
        }
        if tested.insert(id.to_string(), status).is_some() {
            out.push(format!("rules.txt:{n}: {id} is listed twice"));
        }
    }
    let mut listed: BTreeMap<String, usize> = BTreeMap::new();
    let mut tests: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for (n, line) in entries(current) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [krate, path, rule] = fields[..] else {
            out.push(format!("current.txt:{n} is not `CRATE PATH RULE`"));
            continue;
        };
        if !tested.contains_key(rule) {
            out.push(format!(
                "current.txt:{n}: {rule} is no rule of rules.txt, so {path} records no incidental rule"
            ));
        }
        *listed.entry(rule.to_string()).or_default() += 1;
        let key = (krate.to_string(), path.to_string());
        if !tests.entry(key).or_default().insert(rule.to_string()) {
            out.push(format!(
                "current.txt:{n}: {path} is listed under {rule} twice"
            ));
        }
    }
    for (id, status) in &tested {
        match (status, listed.get(id).copied().unwrap_or(0)) {
            (true, 0) => out.push(format!(
                "{id} is tested in rules.txt and current.txt lists no test of it; mark it untested or list its test"
            )),
            (false, n) if n > 0 => out.push(format!(
                "{id} is untested in rules.txt and current.txt lists {n} test(s) of it"
            )),
            _ => {}
        }
    }
    let mut found = BTreeSet::new();
    for ((krate, path), rules) in &tests {
        match find(krate, path) {
            Err(why) => out.push(why),
            Ok((file, named)) => {
                if &named != rules {
                    out.push(format!(
                        "{krate} {path}: its doc line names {named:?}, current.txt lists it under {rules:?}"
                    ));
                }
                let name = path.rsplit("::").next().unwrap_or(path);
                found.insert((file, name.to_string()));
            }
        }
    }
    for (file, name) in marks.difference(&found) {
        out.push(format!(
            "{name} in {} carries the current-behaviour doc line and current.txt does not list it",
            file.display()
        ));
    }
    out
}

/// This check's own test, which carries no current-behaviour doc line.
const UNMARKED: &str = "node::settle::tests::rules::the_incidental_rules_their_marked_tests_and_the_doc_lines_agree_and_the_check_finds_each_planted_line";

/// `rules.txt`, `current.txt` and the doc lines agree: every listed test
/// exists and names in its doc line exactly the rules it is listed under,
/// every rule marked tested lists a test and none marked untested does,
/// every listed rule is in `rules.txt` and of class I or I-kept, and every
/// test with the doc line is listed. Then each of those is broken by a
/// planted line, and the check finds it.
#[test]
fn the_incidental_rules_their_marked_tests_and_the_doc_lines_agree_and_the_check_finds_each_planted_line()
 {
    let marks = marks();
    let found = problems(RULES, CURRENT, &find, &marks);
    assert!(
        found.is_empty(),
        "rules.txt, current.txt and the marked tests disagree:\n{}",
        found.join("\n")
    );
    let listed: BTreeSet<&str> = entries(CURRENT)
        .filter_map(|(_, l)| l.split_whitespace().nth(1))
        .collect();
    assert_eq!(
        marks.len(),
        listed.len(),
        "precondition: the scan for the doc line finds each listed test once"
    );
    let with = |text: &str, line: &str| format!("{text}{line}\n");
    let planted: [(&str, String, String, &str); 7] = [
        (
            "a listed test that does not exist",
            RULES.to_string(),
            with(
                CURRENT,
                "fips-core  proto::fmp::flow::tests::msg2::a_planted_test_no_file_defines  XX-05",
            ),
            "defines no function a_planted_test_no_file_defines",
        ),
        (
            "a listed test with no doc line",
            RULES.to_string(),
            with(CURRENT, &format!("fips-mesh  {UNMARKED}  XX-05")),
            "carries no current-behaviour doc line",
        ),
        (
            "a test listed under a rule its doc line does not name",
            RULES.to_string(),
            with(
                CURRENT,
                "fips-core  proto::fmp::flow::tests::msg2::a_leaf_refuses_a_second_peer_at_msg2_and_removes_the_link_at_once  XX-01",
            ),
            "its doc line names",
        ),
        (
            "a test listed under a rule rules.txt does not hold",
            RULES.to_string(),
            with(
                CURRENT,
                "fips-core  proto::fmp::flow::tests::msg2::a_leaf_refuses_a_second_peer_at_msg2_and_removes_the_link_at_once  XX-90",
            ),
            "XX-90 is no rule of rules.txt",
        ),
        (
            "an I rule that lists no test and is not marked untested",
            with(RULES, "XX-99  I       tested    a planted rule"),
            CURRENT.to_string(),
            "XX-99 is tested in rules.txt and current.txt lists no test of it",
        ),
        (
            "a rule marked untested that lists a test",
            RULES.replace("XX-05  I-kept  tested", "XX-05  I-kept  untested"),
            CURRENT.to_string(),
            "XX-05 is untested in rules.txt",
        ),
        (
            "a rule of a class other than I and I-kept",
            with(RULES, "XX-98  R       untested  a planted rule"),
            CURRENT.to_string(),
            "only I and I-kept rules are listed",
        ),
    ];
    for (what, rules, current, want) in &planted {
        let found = problems(rules, current, &find, &marks);
        assert!(
            found.iter().any(|p| p.contains(want)),
            "the check finds {what}: {found:?}"
        );
    }
    let mut stray = marks.clone();
    stray.insert((root().join("src/lib.rs"), String::from("a_planted_mark")));
    let found = problems(RULES, CURRENT, &find, &stray);
    assert!(
        found
            .iter()
            .any(|p| p.contains("a_planted_mark") && p.contains("does not list it")),
        "the check finds a doc line on a test current.txt does not list: {found:?}"
    );
}
