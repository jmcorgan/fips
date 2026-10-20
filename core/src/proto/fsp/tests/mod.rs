mod core;
mod quorum;
mod wire;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use std::path::{Path, PathBuf};

use crate::proto::rekey::{code_idents, code_text, lost_items};

/// Names of the deployed session rekey code, which kept its rules apart
/// from the rekey machine: the stateless decisions and snapshots of this
/// module, the timer cutover, the tie-break at a setup, the transitional
/// state moves and entry points the session shell drove the machine
/// through, and the deployed policy values and fault switches the migration
/// carried until each was switched off. None may name anything in the core
/// again, since each would be a second copy of a rule the machine owns.
///
/// The session's transitional moves that the link layer's deployed code
/// also has a function for (`install_pending`, `retire_pending`,
/// `complete_drain`, `backdate_pending`) are left out: the link layer's own
/// transitional moves are named for the deployed functions they replace.
const DEPLOYED: &[&str] = &[
    "SessionSnapshot",
    "RekeyMsg3ResendSnapshot",
    "InitialMsg3ResendSnapshot",
    "DecryptSlot",
    "EpochReaction",
    "PromoteConfirming",
    "ConfirmResponder",
    "ExpireInitiation",
    "classify_epoch",
    "cutover_timer_elapsed",
    "initiation_winner",
    "poll_rekey_msg3_resends",
    "poll_initial_msg3_resends",
    "FSP_CUTOVER_DELAY_MS",
    "promote_pending",
    "hold_previous",
    "refresh_previous_use",
    "drain_anchors",
    "install_initiated",
    "install_answered",
    "trial_open",
    "mark_established",
    "fsp_trigger",
    "setup_resend",
    "restart_by_epoch",
    "DeployedSetupResend",
    "DeployedEpochCompare",
    "DeployedSilenceStart",
];

/// The fields a policy value had for the session rules. A link layer's
/// `Policy` may come back for its own rules, but never with one of these:
/// `silence` cannot be banned by name, since `Params` has its own.
const SESSION_FIELDS: &[&str] = &["fsp_trigger", "silence", "setup_resend", "restart_by_epoch"];

/// Names the link layer's deployed rekey still uses, which the session
/// module's code must not: the stateless poll and its rekey effects, and
/// any policy value, since a session machine runs every row as the design
/// states it.
const SESSION_ONLY: &[&str] = &[
    "poll_rekey",
    "RekeyCfg",
    "CutOver",
    "CompleteDrain",
    "InitiateRekey",
    "AbandonRekey",
    "AbandonHandshake",
    "Policy",
    "policy",
    "DEPLOYED",
];

/// Every non-test `.rs` file under `dir`, recursively. Test files (a
/// `tests` directory, or a file named `tests.rs` or ending `_tests.rs`)
/// are left out: they may name the deployed code they model.
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("the source directory reads") {
        let path = entry.expect("the directory entry reads").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if name != "tests" {
                sources(&path, out);
            }
        } else if name.ends_with(".rs") && name != "tests.rs" && !name.ends_with("_tests.rs") {
            out.push(path);
        }
    }
}

/// Each use of a name in `banned` in the code of `source`, as
/// `file:line: name`.
fn uses(file: &str, source: &str, banned: &[&str]) -> Vec<String> {
    code_idents(source)
        .into_iter()
        .filter(|(_, w)| banned.contains(&w.as_str()))
        .map(|(n, w)| [file, ":", &n.to_string(), ": ", &w].concat())
        .collect()
}

/// Each session field a `struct Policy` in the code of `source` declares,
/// as `file: Policy.field`.
fn policy_fields(file: &str, source: &str) -> Vec<String> {
    let code = code_text(source);
    let mut out = Vec::new();
    let mut rest = code.as_str();
    while let Some(at) = rest.find("struct Policy") {
        rest = &rest[at + "struct Policy".len()..];
        if rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let body = match (rest.find('{'), rest.find([';', '('])) {
            (Some(open), stop) if stop.is_none_or(|s| open < s) => {
                &rest[open..rest[open..].find('}').map_or(rest.len(), |n| open + n)]
            }
            _ => continue,
        };
        out.extend(
            code_idents(body)
                .into_iter()
                .filter(|(_, w)| SESSION_FIELDS.contains(&w.as_str()))
                .map(|(_, w)| [file, ": Policy.", &w].concat()),
        );
    }
    out
}

/// Every deployed session rekey rule, transitional state move, policy
/// value and fault switch the migration deleted stays deleted: the code of
/// every non-test source file of the core is scanned for their names, the
/// session module's code also for the link layer's and for any policy, and
/// any `Policy` for a session field. The planted lines show each scan
/// finds what it looks for in code, not in a comment, and past a `//` in a
/// string literal.
#[test]
fn no_deployed_session_rekey_rule_survives_in_the_core_and_the_scan_finds_a_planted_one() {
    let planted = "/// `initiation_winner` once decided a crossing.\n\
                   pub fn initiation_winner(a: u8, b: u8) -> bool { a < b }\n\
                   const U: &str = \"http://x\"; fn hold_previous() {}\n\
                   pub struct Policy { /* restart_by_epoch */ pub silence: bool }\n";
    assert_eq!(
        uses("planted.rs", planted, DEPLOYED),
        [
            "planted.rs:2: initiation_winner",
            "planted.rs:3: hold_previous"
        ],
        "the scan finds a planted deployed rule in code, and not in its doc"
    );
    assert_eq!(
        policy_fields("planted.rs", planted),
        ["planted.rs: Policy.silence"],
        "the scan finds a session field of a planted policy, and not in its comment"
    );
    assert_eq!(
        lost_items(
            "const S: &str = \"\\\"\";\nfn kept() {}\nconst Q: &str = \"\n fn swallowed() {}\n\";\n"
        ),
        [4],
        "a line opening an item that the reader blanked is reported"
    );

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let session = root.join("proto").join("fsp");
    let mut files = Vec::new();
    sources(&root, &mut files);
    let mut found = Vec::new();
    for path in &files {
        let source = std::fs::read_to_string(path).expect("the source file reads");
        let file = path.strip_prefix(&root).unwrap().to_string_lossy();
        found.extend(uses(&file, &source, DEPLOYED));
        found.extend(policy_fields(&file, &source));
        found.extend(
            lost_items(&source)
                .iter()
                .map(|n| alloc::format!("{file}:{n}: unread")),
        );
        if path.starts_with(&session) {
            found.extend(uses(&file, &source, SESSION_ONLY));
        }
    }
    assert!(
        found.is_empty(),
        "deployed session rekey code is back in the core: {found:?}"
    );
    // The scan reaches the session module, its rekey profile one directory
    // down, the machine they drive, and the parameters a policy lived in.
    for want in [
        "proto/fsp/core.rs",
        "proto/fsp/rekey/xk.rs",
        "proto/rekey/machine.rs",
        "proto/rekey/params.rs",
    ] {
        assert!(files.iter().any(|p| p.ends_with(want)), "{want} is scanned");
    }
}
