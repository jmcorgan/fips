//! The scan that keeps the deployed rekey shell code of both layers out of
//! the root crate once each layer's rekey machine replaced it.

use std::path::{Path, PathBuf};

/// Names of the deployed session rekey code in the shell: the snapshots it
/// built for the stateless core, the sweeps that resent its handshake
/// messages, its trial decrypt, the hold, pause and tie-break of the first
/// handshake, its own rekey predicates and resend slots, the transitional
/// entry points the migration used, and the predicates, state moves and
/// constants it shared with the link layer's deployed rekey.
const SESSION: &[&str] = &[
    "SessionSnapshot",
    "RekeyMsg3ResendSnapshot",
    "InitialMsg3ResendSnapshot",
    "DecryptSlot",
    "EpochReaction",
    "CandidateAdmission",
    "CheckSessionRekey",
    "ResendPendingSessionHandshakes",
    "FSP_CUTOVER_DELAY_MS",
    "session_rekey_snapshots",
    "rekey_msg3_resend_snapshots",
    "initial_msg3_resend_snapshots",
    "check_session_rekey",
    "initiate_session_rekey",
    "resend_pending_session_msg3",
    "resend_pending_session_handshakes",
    "resend_initial_msg3",
    "poll_rekey_msg3_resends",
    "poll_initial_msg3_resends",
    "classify_epoch",
    "react_to_epoch",
    "cutover_timer_elapsed",
    "initiation_winner",
    "fsp_trial_decrypt",
    "trial_open",
    "pending_stale",
    "has_rekey_in_progress",
    "set_rekey_completed",
    "peer_new_epoch_confirmed",
    "confirm_peer_new_epoch",
    "refresh_previous_use",
    "drain_anchors",
    "responder_hold_open",
    "responder_hold_aged",
    "responder_hold_expired",
    "pause_initiator",
    "initiator_paused",
    "resume_initiator",
    "attach_initiator",
    "drop_initiator_leg",
    "has_initiator_leg",
    "keep_candidates_only",
    "candidate_admission",
    "rekey_msg3_payload",
    "set_rekey_msg3_payload",
    "clear_rekey_msg3_payload",
    "rekey_msg3_next_resend",
    "rekey_msg3_resend_count",
    "record_rekey_msg3_resend",
    "install_initiated",
    "install_answered",
    "mark_established",
    "RekeyCfg",
    "REKEY_DAMPENING_SECS",
    "DRAIN_WINDOW_SECS",
    "rekey_completed",
    "last_peer_rekey",
    "record_peer_rekey",
    "is_rekey_dampened",
    "drain_expired",
    "complete_drain",
    "cutover_to_new_session",
    "promote_pending",
    "begin_rekey",
    "abandon_rekey",
    "abandon_handshake",
    "is_rekey_initiator",
    "set_rekey_state",
    "take_rekey_state",
    "clear_rekey_state",
    "set_pending_session",
    "handle_peer_kbit_flip",
    "draw_rekey_jitter",
];

/// Names of the deployed link rekey code in the shell: the rekey check, its
/// cadence routing and inline cutover, drain and retirement, the snapshots
/// it built for the stateless link core, the peers it listed for it and the
/// effects it ran from it, the msg1 initiation and resend sweep with their
/// resend slots, the drain ceiling and hold arithmetic it kept beside the
/// machine's parameters, the active peer's rekey slots, fields and state
/// moves, the decrypt-worker registration it ran beside the machine's
/// offer and the test seam of the earlier key-epoch gate, the peer
/// machine's rekey phases, sub-phases, constant copies, timers, events and
/// actions, the rekey arms and refusals of the inbound classification, the
/// record of answered msg1s and the shell's rekey vocabulary, the
/// transitional moves of the migration (the cutover, drain and abandon
/// steps the shell ran on the machine's outputs, the index hand-off and
/// releases, the resend sweep, the cross-connection replace, the restart
/// note, the offer at promotion, the worker acceptance and the epoch record
/// outside `step`), and the fields the link policy had.
const LINK: &[&str] = &[
    "check_rekey",
    "route_rekey_cadence",
    "observe_rekey_initiated",
    "rekey_cadence_ctx",
    "cutover_peer_inline",
    "retire_unadopted",
    "drain_peer_inline",
    "rekey_peer_snapshots",
    "peer_snapshot",
    "rekey_peers",
    "rekey_resend_candidates",
    "observe_rekey_msg2",
    "initiate_rekey",
    "resend_pending_rekeys",
    "rekey_resend_snapshots",
    "RekeyResendSnapshot",
    "poll_rekey_resends",
    "drain_max_retention_ms",
    "DRAIN_MAX_RETENTION_SECS",
    "pending_hold",
    "REKEY_MIN_LINK_AGE_SECS",
    "REKEY_MIN_CUTOVER_AGE_SECS",
    "answer_rekey",
    "release_pending",
    "install_pending",
    "adopt_pending",
    "retire_pending",
    "pending_expired",
    "replace_session",
    "note_restart",
    "complete_rekey_msg2",
    "complete_rekey_msg3",
    "needs_msg1_resend",
    "rekey_msg1",
    "set_msg1_next_resend",
    "rekey_msg1_resend_count",
    "record_rekey_msg1_resend",
    "set_rekey_in_progress",
    "previous_session_mut",
    "pending_new_session_mut",
    "noise_session_mut",
    "awaits_msg2",
    "clear_handshake_msg2",
    "demote_current",
    "rekey_handshake",
    "rekey_lease",
    "rekey_msg1_next_resend",
    "pending_since",
    "pending_restart",
    "setup_msg1",
    "drain_started",
    "set_oldgate",
    "old_gate",
    "register_decrypt_worker_session",
    "build_owned_session_state",
    "RekeyPhase",
    "Msg1Sent",
    "PendingCutover",
    "REKEY_DAMPEN_MS",
    "DRAIN_WINDOW_MS",
    "REKEY_CADENCE_INTERVAL_MS",
    "REKEY_RESEND_INTERVAL_MS",
    "REKEY_MAX_RESENDS",
    "REKEY_AFTER_SECS",
    "REKEY_AFTER_MESSAGES",
    "RekeyMsg1",
    "RekeyMsg2",
    "SwapSendState",
    "RekeyCadence",
    "DrainExpiry",
    "RekeyConsume",
    "RekeyInitiated",
    "PeerKbitFlip",
    "SendRekey",
    "CompleteDrain",
    "CutOver",
    "InitiateRekey",
    "AbandonRekey",
    "RetirePending",
    "ResendRekeyMsg1",
    "ResendMsg2",
    "on_rekey_msg2",
    "on_rekey_initiated",
    "on_rekey_cadence",
    "map_rekey_action",
    "on_rekey_resend",
    "rekey_resend_count",
    "last_peer_rekey_ms",
    "draining_index",
    "RekeyRespond",
    "ResendRekeyMsg2",
    "DualRekeyWon",
    "Msg1Arrival",
    "AnsweredMsg1s",
    "RekeyRole",
    "RekeyAnswer",
    "cutover_peer",
    "drain_peer",
    "drop_rekey_attempt",
    "run_cutover_outputs",
    "take_rekey_index",
    "release_index",
    "release_retired",
    "rekey_resending",
    "resend_rekeys_at",
    "offer_current",
    "delegated",
    "learn_epoch",
    "msg1_ladder",
    "msg1_record",
    "cutover_prompt",
    "k_rule",
    "drain_rule",
    "restart_cutover",
];

/// Names banned in the link and session shells only: a policy value,
/// which the peering reconciler's own `Policy` keeps from being banned
/// crate-wide, and the link core's per-peer rekey snapshot, whose name the
/// node's statistics history also uses.
const SHELLS: &[&str] = &["Policy", "policy", "DEPLOYED", "PeerSnapshot"];

/// Each use of a name in `banned` in the code of `source` (comments and
/// literals left out, so prose may still say what the deployed code did),
/// as `file:line: name`.
fn uses(file: &str, source: &str, banned: &[&str]) -> Vec<String> {
    fips_core::proto::rekey::code_idents(source)
        .into_iter()
        .filter(|(_, w)| banned.contains(&w.as_str()))
        .map(|(n, w)| format!("{file}:{n}: {w}"))
        .collect()
}

/// Every non-test `.rs` file under `dir`, recursively, leaving out a
/// `tests` directory and a file named `tests.rs` or ending `_tests.rs`.
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

/// Every deployed rekey rule, predicate and transitional move the shells of
/// either layer held stays deleted: the code of every non-test source file
/// of the root crate is scanned for their names, and the link and session
/// shells (the active peer and its machine, the session table, their
/// handlers and the data plane) also for any policy value and the link
/// core's snapshot. The planted lines show the scan finds each in code,
/// not in a comment, and past a `//` in a string literal.
#[test]
fn no_deployed_rekey_rule_of_either_layer_survives_in_the_shells_and_the_scan_finds_a_planted_one()
{
    let planted = "    // pending_stale once retired a pending.\n\
                   \x20   if entry.pending_stale(now) { entry.abandon_rekey(); }\n\
                   \x20   let url = \"http://x\"; let p = Policy::DEPLOYED;\n\
                   \x20   peer.offer_current(); // replace_session\n\
                   \x20   node.cutover_peer(&addr); let t = REKEY_DAMPEN_MS;\n";
    let found = |banned| uses("planted.rs", planted, banned);
    assert_eq!(
        found(SESSION),
        ["planted.rs:2: pending_stale", "planted.rs:2: abandon_rekey"],
        "the scan finds a planted shell predicate and state move in code, and not in a comment"
    );
    assert_eq!(
        found(LINK),
        [
            "planted.rs:4: offer_current",
            "planted.rs:5: cutover_peer",
            "planted.rs:5: REKEY_DAMPEN_MS"
        ],
        "the scan finds planted link moves and a constant copy, and not one named in a comment"
    );
    assert_eq!(
        found(SHELLS),
        ["planted.rs:3: Policy", "planted.rs:3: DEPLOYED"],
        "the scan finds a planted policy value past a `//` in a literal"
    );

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let node = root.join("node");
    let handlers = node.join("handlers");
    let shells = [
        root.join("peer"),
        node.join("session"),
        node.join("dataplane"),
        handlers.join("session.rs"),
        handlers.join("rekey.rs"),
        handlers.join("handshake.rs"),
    ];
    let mut files = Vec::new();
    sources(&root, &mut files);
    let mut found = Vec::new();
    for path in &files {
        let source = std::fs::read_to_string(path).expect("the source file reads");
        let file = path.strip_prefix(&root).unwrap().to_string_lossy();
        found.extend(uses(&file, &source, SESSION));
        found.extend(uses(&file, &source, LINK));
        let lost = fips_core::proto::rekey::lost_items(&source);
        found.extend(lost.iter().map(|n| format!("{file}:{n}: unread")));
        if shells.iter().any(|s| path.starts_with(s)) {
            found.extend(uses(&file, &source, SHELLS));
        }
    }
    assert!(
        found.is_empty(),
        "deployed rekey code is back in the shell: {found:?}"
    );
    // The scan reaches the session table and its handlers, the active peer
    // and its machine, the link handshake handlers, the data plane and the
    // executor of both layers' outputs.
    for want in [
        "node/session/mod.rs",
        "node/handlers/session.rs",
        "node/handlers/rekey.rs",
        "node/handlers/handshake.rs",
        "node/dataplane/encrypted.rs",
        "peer/active.rs",
        "peer/machine.rs",
    ] {
        assert!(files.iter().any(|p| p.ends_with(want)), "{want} is scanned");
    }
}
