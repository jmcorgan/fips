//! The scan that keeps the deployed rekey code of both layers out of the
//! core once the rekey machine replaced it.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use std::path::{Path, PathBuf};

use crate::proto::rekey::{code_idents, lost_items};

/// Names of the deployed session rekey code, which kept its rules apart
/// from the rekey machine: the stateless decisions and snapshots of the
/// session core, the timer cutover, the tie-break at a setup, the
/// transitional state moves and entry points the session shell drove the
/// machine through, and the deployed policy values and fault switches the
/// migration carried until each was switched off.
const SESSION: &[&str] = &[
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

/// Names of the deployed link rekey code: the stateless poll of the link
/// core with its snapshots and their fields, configuration, rekey effects
/// and the trait methods that listed the peers it polled, the rekey arms of
/// the inbound classification and their refusals, the record of answered
/// msg1s and its moves, the shell's rekey vocabulary, the drain and dampening
/// constants and the cutover-age floor, the transitional state moves and
/// reads the link shell drove the machine through (the cross-connection
/// replace, the restart note, the dampening and record reads, the offer at
/// promotion, the worker acceptance and the epoch record made outside
/// `step`), and the link policy that held the deployed rules until each was
/// switched off: the type, its constants, its field in `Config` and every
/// field it had. The session rules' policy is caught by the same names.
const LINK: &[&str] = &[
    "poll_rekey",
    "poll_rekey_resends",
    "rekey_peers",
    "rekey_resend_candidates",
    "RekeyCfg",
    "RekeyResendSnapshot",
    "is_dampened",
    "needs_resend",
    "msg1_answered_before",
    "msg1_on_link",
    "existing_msg2",
    "ResendRekeyMsg1",
    "ResendMsg2",
    "CutOver",
    "Cutover",
    "CompleteDrain",
    "RetirePending",
    "InitiateRekey",
    "AbandonRekey",
    "AbandonHandshake",
    "RekeyRespond",
    "ResendRekeyMsg2",
    "DualRekeyWon",
    "PendingSession",
    "Msg1Arrival",
    "AnsweredMsg1s",
    "ENDED_MSG1_RECORD",
    "end_setup",
    "push_ended",
    "RekeyRole",
    "RekeyAnswer",
    "DRAIN_WINDOW_SECS",
    "REKEY_DAMPENING_SECS",
    "REKEY_MIN_LINK_AGE_SECS",
    "REKEY_MIN_CUTOVER_AGE_SECS",
    "install_pending",
    "retire_pending",
    "complete_drain",
    "cutover_to_new_session",
    "handle_peer_kbit_flip",
    "adopt_pending",
    "abandon_rekey",
    "take_pending",
    "note_restart",
    "replace_session",
    "record_peer_rekey",
    "is_rekey_dampened",
    "answered_before",
    "open_slot",
    "resends_left",
    "drain_window",
    "offer_current",
    "delegated",
    "learn_epoch",
    "Policy",
    "policy",
    "DEPLOYED",
    "msg1_ladder",
    "msg1_record",
    "cutover_prompt",
    "k_rule",
    "drain_rule",
    "restart_cutover",
];

/// Names banned only under `proto/`: the link core's per-peer rekey
/// snapshot, whose name the node's statistics history also uses for a
/// type of its own.
const PROTO: &[&str] = &["PeerSnapshot"];

/// Names banned only under `proto/fmp/`: the link core's drain effect,
/// whose name the machine's own drain record also uses.
const FMP: &[&str] = &["Drain"];

/// The names the transitional link module had, and the deployed-rule
/// reads the machine kept while a link ran the deployed rules (the age
/// floors, the deadline of a deployed-ladder msg1 and the record of the
/// setup msg1 made outside `step`), banned in the machine's own directory
/// so they cannot come back under it.
const MACHINE: &[&str] = &["deployed", "age_floors", "msg1_end", "mark_setup"];

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

/// Every deployed rekey rule, transitional state move, policy value and
/// fault switch of either layer that the migration deleted stays deleted:
/// the code of every non-test source file of the core is scanned for their
/// names, the protocol modules also for the link core's snapshot, the link
/// core for its drain effect and the machine's directory for the
/// transitional module and reads. The planted lines show
/// the scan finds each in code, not in a comment, and past a `//` in a
/// string literal.
#[test]
fn no_deployed_rekey_rule_of_either_layer_survives_in_the_core_and_the_scan_finds_a_planted_one() {
    let planted = "/// `initiation_winner` once decided a crossing.\n\
                   pub fn initiation_winner(a: u8, b: u8) -> bool { a < b }\n\
                   const U: &str = \"http://x\"; fn hold_previous() {}\n\
                   pub struct Policy { /* k_rule */ pub drain_rule: bool }\n\
                   mod deployed; fn offer_current(s: &PeerSnapshot) {}\n\
                   enum ConnAction { Drain { peer: u8 }, ResendRekeyMsg1 }\n";
    let found = |banned| uses("planted.rs", planted, banned);
    assert_eq!(
        found(SESSION),
        [
            "planted.rs:2: initiation_winner",
            "planted.rs:3: hold_previous"
        ],
        "the scan finds a planted session rule in code, and not in its doc"
    );
    assert_eq!(
        found(LINK),
        [
            "planted.rs:4: Policy",
            "planted.rs:4: drain_rule",
            "planted.rs:5: offer_current",
            "planted.rs:6: ResendRekeyMsg1"
        ],
        "the scan finds a planted link policy, its field, a link move and a link effect, and not a comment"
    );
    assert_eq!(found(PROTO), ["planted.rs:5: PeerSnapshot"]);
    assert_eq!(found(FMP), ["planted.rs:6: Drain"]);
    assert_eq!(found(MACHINE), ["planted.rs:5: deployed"]);
    assert_eq!(
        lost_items(
            "const S: &str = \"\\\"\";\nfn kept() {}\nconst Q: &str = \"\n fn swallowed() {}\n\";\n"
        ),
        [4],
        "a line opening an item that the reader blanked is reported"
    );

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let proto = root.join("proto");
    let fmp = proto.join("fmp");
    let machine = proto.join("rekey");
    let mut files = Vec::new();
    sources(&root, &mut files);
    let mut found = Vec::new();
    for path in &files {
        let source = std::fs::read_to_string(path).expect("the source file reads");
        let file = path.strip_prefix(&root).unwrap().to_string_lossy();
        found.extend(uses(&file, &source, SESSION));
        found.extend(uses(&file, &source, LINK));
        if path.starts_with(&proto) {
            found.extend(uses(&file, &source, PROTO));
        }
        if path.starts_with(&fmp) {
            found.extend(uses(&file, &source, FMP));
        }
        if path.starts_with(&machine) {
            found.extend(uses(&file, &source, MACHINE));
        }
        found.extend(
            lost_items(&source)
                .iter()
                .map(|n| alloc::format!("{file}:{n}: unread")),
        );
    }
    assert!(
        found.is_empty(),
        "deployed rekey code is back in the core: {found:?}"
    );
    // The scan reaches both layers' modules and rekey profiles, the machine
    // they drive, its link accessors and the parameters a policy lived in.
    for want in [
        "proto/fsp/core.rs",
        "proto/fsp/rekey/xk.rs",
        "proto/fmp/core.rs",
        "proto/fmp/rekey/ik.rs",
        "proto/rekey/machine.rs",
        "proto/rekey/access.rs",
        "proto/rekey/params.rs",
    ] {
        assert!(files.iter().any(|p| p.ends_with(want)), "{want} is scanned");
    }
}
