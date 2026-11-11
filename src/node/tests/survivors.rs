//! The scans that keep removed code out of the root crate: the deployed
//! rekey shell code of both layers, once each layer's rekey machine replaced
//! it, and the node's handling of the two cross-connection promotion results,
//! once a promotion for a held identity became a refusal. The second is the
//! same scan over a narrower directory, the node outside its tests, because
//! the peer machine still carries those results. A third keeps the per-peer
//! map wrappers of `node/settle/` closed: what the compiler cannot refuse
//! there is a `DerefMut` on a wrapper, or a way past the writers outside
//! `#[cfg(test)]`. A fourth keeps out what a crossed dial's fix replaced:
//! the two close helpers the close rule took over, the excuses for a link
//! with no index entry, and the dial's close and removal. The settlement
//! scans of `node/settle/tests/` walk the source with this file's `sources`
//! too, and name each file with its `label`.

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
/// outside `step`), the fields the link policy had, the MMP reset a
/// cutover and a move ran beside the transition table's cells for them, and
/// the release of a removed peer's indices beside its machine's close, which
/// the settlement core's join now makes.
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
    "reset_mmp",
    "release_peer_indices",
];

/// Names banned in the link and session shells only: a policy value,
/// which the peering reconciler's own `Policy` keeps from being banned
/// crate-wide, and the link core's per-peer rekey snapshot, whose name the
/// node's statistics history also uses.
const SHELLS: &[&str] = &["Policy", "policy", "DEPLOYED", "PeerSnapshot"];

/// Names of the code a crossed dial's fix replaced: the two helpers whose
/// work is now `close_unused` and the close rule `in_use`; the waiver that
/// excused a link with no index entry, the effect that recorded it and the
/// table's lookup of it, once the index was derived from the link records;
/// and the effects and bodies that closed and removed the dial's link at a
/// crossing, which now close and remove the losing link.
const CROSSING: &[&str] = &[
    "close_handshake_link_connection",
    "addr_carries_other_peer",
    "Waiver",
    "WaiverIfNoEntry",
    "shadowed",
    "DialClose",
    "DialLinkRemoved",
    "dial_close",
    "dial_removed",
];

/// Banned in `node/settle/` only: the effect body that recorded a waiver,
/// whose name the handshake handlers still give the established-address
/// waiver of a msg1.
const SETTLE: &[&str] = &["waiver"];

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
pub(in crate::node) fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
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

/// The name a scan gives `path`, a file under `root`: its components below
/// `root` joined with `/`, the form the scans' lists of files are written
/// in. Its display form would join them with the platform's separator,
/// which on Windows is `\`, so no written path would match it there.
pub(in crate::node) fn label(root: &Path, path: &Path) -> String {
    let below = path
        .strip_prefix(root)
        .expect("the scanned file is under the scan's root");
    below
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// A scan names a file by its components joined with `/`, whatever the
/// platform's separator: a path built from components reads as the path
/// the scans' lists are written in, and one with a `.` component reads
/// without it, where the path's display form keeps it.
#[test]
fn a_scanned_file_is_named_by_its_components_joined_with_a_forward_slash() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let path = root
        .join("node")
        .join("settle")
        .join("exec")
        .join("remove.rs");
    assert_eq!(label(&root, &path), "node/settle/exec/remove.rs");
    let dotted = root.join("node").join(".").join("mod.rs");
    assert_eq!(
        label(&root, &dotted),
        "node/mod.rs",
        "the name is built from the path's components, not its display form"
    );
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
        let file = label(&root, path);
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

/// Nothing a crossed dial's fix replaced is back in the root crate's code,
/// and no waiver body is back in the settlement code. The planted lines show
/// the scan finds each name in code, and not one named in a comment.
#[test]
fn no_name_the_crossed_dial_fix_replaced_survives_and_the_scan_finds_a_planted_one() {
    let planted = "    // close_handshake_link_connection once closed a leg.\n\
                   \x20   node.close_handshake_link_connection(id).await;\n\
                   \x20   if node.addr_carries_other_peer(t, &a, id) {}\n\
                   \x20   let w: Option<Waiver> = links.shadowed(&key);\n\
                   \x20   Effect::WaiverIfNoEntry => cross::waiver(node, r),\n\
                   \x20   Effect::DialClose => cross::dial_close(node, r).await,\n\
                   \x20   Effect::DialLinkRemoved => cross::dial_removed(node, r).await,\n";
    assert_eq!(
        uses("planted.rs", planted, CROSSING),
        [
            "planted.rs:2: close_handshake_link_connection",
            "planted.rs:3: addr_carries_other_peer",
            "planted.rs:4: Waiver",
            "planted.rs:4: shadowed",
            "planted.rs:5: WaiverIfNoEntry",
            "planted.rs:6: DialClose",
            "planted.rs:6: dial_close",
            "planted.rs:7: DialLinkRemoved",
            "planted.rs:7: dial_removed"
        ],
        "the scan finds each replaced name in code, and not one named in a comment"
    );
    assert_eq!(
        uses("planted.rs", planted, SETTLE),
        ["planted.rs:5: waiver"],
        "the scan finds a planted waiver body"
    );

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let settle = root.join("node").join("settle");
    let mut files = Vec::new();
    sources(&root, &mut files);
    let mut found = Vec::new();
    for path in &files {
        let source = std::fs::read_to_string(path).expect("the source file reads");
        let file = label(&root, path);
        found.extend(uses(&file, &source, CROSSING));
        if path.starts_with(&settle) {
            found.extend(uses(&file, &source, SETTLE));
        }
    }
    assert!(
        found.is_empty(),
        "code a crossed dial's fix replaced is back: {found:?}"
    );
    // The scan reaches the close rule's home, the crossing's executor, the
    // link table and the reaped leg's close.
    for want in [
        "node/mod.rs",
        "node/settle/exec/cross.rs",
        "node/settle/exec/plan.rs",
        "node/settle/links.rs",
        "node/handlers/timeout.rs",
    ] {
        assert!(files.iter().any(|p| p.ends_with(want)), "{want} is scanned");
    }
}

/// Each way a file of `node/settle/` would open a map wrapper to writes past
/// its writers, as `file:line: what`: a use of `DerefMut` in code, or a
/// `fn raw` or `fn raw_*` with no `#[cfg(test)]` among the attributes above
/// it.
fn wrapper_escapes(file: &str, source: &str) -> Vec<String> {
    let idents = fips_core::proto::rekey::code_idents(source);
    let lines: Vec<&str> = source.lines().collect();
    let mut found = Vec::new();
    for (i, (n, w)) in idents.iter().enumerate() {
        if w == "DerefMut" {
            found.push(format!("{file}:{n}: DerefMut"));
        }
        let raw = idents
            .get(i + 1)
            .is_some_and(|(m, next)| m == n && (next == "raw" || next.starts_with("raw_")));
        if w == "fn" && raw {
            let gated = lines[..n - 1]
                .iter()
                .rev()
                .map(|l| l.trim())
                .take_while(|l| l.starts_with("#[") || l.starts_with("//"))
                .any(|l| l == "#[cfg(test)]");
            if !gated {
                found.push(format!("{file}:{n}: {} outside cfg(test)", idents[i + 1].1));
            }
        }
    }
    found
}

/// No map wrapper of the node has a `DerefMut`, and every way past a
/// wrapper's writers is test code, so production writes each map only
/// through its named writers. A direct write to the inner map does not
/// compile, since the field is private; this scan checks the two things the
/// compiler would let through. The planted lines show it finds each, and not
/// a name in a comment.
#[test]
fn no_map_wrapper_opens_its_map_to_production_writes_and_the_scan_finds_a_planted_one() {
    let planted = "    // impl DerefMut for MachineMap, once.\n\
                   \x20   impl std::ops::DerefMut for DialMap {\n\
                   \x20   #[cfg(test)]\n\
                   \x20   /// The inner map.\n\
                   \x20   pub(in crate::node) fn raw(&mut self) -> &mut Map {\n\
                   \x20   pub(in crate::node) fn raw_timers(&mut self) -> &mut Map {\n";
    assert_eq!(
        wrapper_escapes("planted.rs", planted),
        [
            "planted.rs:2: DerefMut",
            "planted.rs:6: raw_timers outside cfg(test)"
        ],
        "the scan finds a planted DerefMut and an ungated raw_timers, and passes a gated raw"
    );

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let settle = root.join("node").join("settle");
    let mut files = Vec::new();
    sources(&settle, &mut files);
    let mut found = Vec::new();
    for path in &files {
        let source = std::fs::read_to_string(path).expect("the source file reads");
        let file = label(&root, path);
        found.extend(wrapper_escapes(&file, &source));
    }
    assert!(
        found.is_empty(),
        "a map wrapper is open to production writes: {found:?}"
    );
    // The scan reaches the wrappers and the macro their reads come from.
    for want in [
        "node/settle/mod.rs",
        "node/settle/maps.rs",
        "node/settle/links.rs",
    ] {
        assert!(files.iter().any(|p| p.ends_with(want)), "{want} is scanned");
    }
}
