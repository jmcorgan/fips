//! The meta-test of the XX flow's switches (`../faults.rs`), and the
//! tables the coverage scan in `mod.rs` reads.
//!
//! For each row, every test it names runs in a child process of this test
//! binary with the row's switch on, and must fail; every named test also
//! runs once with no switch and must pass. A child runs one test by its
//! exact path, so it never runs this meta-test again. The tables are
//! compiled in every test build so that the coverage scan runs everywhere;
//! the meta-test itself waits for the `slow-tests` feature, as the
//! settlement core's does. The coverage scan is the core's
//! (`settle::tests::faults::uncovered`): every flow test is named by a row
//! or listed below with why no switch breaks it.

use super::super::faults::Fault;

/// The test-path prefix of each test file.
const MSG1: &str = "proto::fmp::flow::tests::msg1::";
const MSG2: &str = "proto::fmp::flow::tests::msg2::";
const MSG3: &str = "proto::fmp::flow::tests::msg3::";

/// One test, by the prefix of its file and its name.
type Test = (&'static str, &'static str);

/// Each switch with the tests that must fail with it on.
pub(crate) const ROWS: &[(Fault, &[Test])] = &[
    (
        Fault::AnonLegNamed,
        &[(
            MSG1,
            "an_anonymous_answer_installs_nothing_at_its_send_and_waits_for_its_msg3_after_the_peer_at_its_source_is_gone",
        )],
    ),
    (
        Fault::PendingCountsSentAnswers,
        &[(
            MSG1,
            "the_admission_cap_counts_an_anonymous_answer_only_until_its_msg2_is_sent",
        )],
    ),
    (
        Fault::AnonDialNamed,
        &[(
            MSG2,
            "an_anonymous_dial_completes_under_the_identity_its_msg2_taught",
        )],
    ),
    (
        Fault::BesideOwnSendsFinal,
        &[(
            MSG2,
            "a_msg2_beside_this_nodes_own_dial_is_kept_at_once_with_no_msg3_and_offers_its_pair",
        )],
    ),
    (
        Fault::FinalBeforeSendOutcome,
        &[(MSG2, "a_msg2_installs_nothing_until_its_msg3_is_sent")],
    ),
    (
        Fault::LeafKeepsLink,
        &[
            (
                MSG2,
                "a_leaf_refuses_a_second_peer_at_msg2_and_removes_the_link_at_once",
            ),
            (
                MSG3,
                "a_leaf_refuses_a_second_peer_at_msg3_and_removes_the_link_at_once",
            ),
        ],
    ),
    (
        Fault::Msg3RestartUngated,
        &[
            (
                MSG3,
                "a_restart_at_msg3_is_refused_while_the_peering_was_heard_inside_the_interval_and_accepted_after",
            ),
            (
                MSG3,
                "a_restart_at_msg3_is_refused_inside_the_interval_from_the_install_when_no_frame_was_heard",
            ),
        ],
    ),
    (
        Fault::MismatchClaimTearsDown,
        &[(
            MSG3,
            "a_msg3_claiming_a_session_not_held_repeats_the_stored_msg2_and_leaves_the_peer",
        )],
    ),
    (
        Fault::MatchesReadAsCross,
        &[(
            MSG3,
            "a_msg3_claiming_the_session_held_hands_the_leg_and_its_lease_to_the_peers_rekey",
        )],
    ),
    (
        Fault::SilentRefusalAnyEpoch,
        &[(
            MSG3,
            "a_silent_identitys_msg3_is_refused_at_the_epoch_it_counted_and_promoted_at_another",
        )],
    ),
];

/// Why a test of a rule the flow takes from the table, or carries in no
/// condition of its own, is characterisation.
const RULE: &str = "it states one of next's rules where the flow has no guard of its own to switch off: the outcome is the table's shared rule or a plain consequence of the flow's state, and its break is a scratch edit run by hand and logged with the commit";

/// Why a comparison of the flow, or the table under it, with next's own
/// code is characterisation.
const CHARACTERISED: &str = "a characterisation of where the flow on the shared table meets next's code, by next's own type beside the core's or by next's rule written out beside the core's decision; a difference reds it whichever side moved, and no one guard of the flow stands behind it";

/// Why a scan of the flow's sources is characterisation.
const SCAN: &str = "a scan of the flow's sources that plants its own failing case";

/// Why a check of the transcription of next's rules against the judge is
/// characterisation.
const JUDGED: &str = "a check of the transcription of next's rules (`next.rs`) against the judge (`../model/`), neither of which runs the flow, so no switch of the flow reaches it";

/// Why a scripted run of flow nodes held to next's nodes and the judge is
/// characterisation.
const JOINT: &str = "a scripted run of flow nodes in the settlement world, held event by event to the same run of next's transcribed nodes and to the judge; a guard's break may red it, and the switch rows name the table tests built to red each guard";

/// The tests that characterise behaviour no switch breaks, each with why.
pub(crate) const CHARACTERISATION: &[(&str, &str)] = &[
    (
        "a_lone_dial_on_flow_nodes_logs_what_next_does_and_settles_as_the_judge_does",
        JOINT,
    ),
    (
        "a_simultaneous_dial_on_flow_nodes_logs_what_next_does_in_every_order",
        JOINT,
    ),
    (
        "two_dials_of_one_flow_node_answered_in_turn_log_what_next_does",
        JOINT,
    ),
    (
        "a_redial_by_either_flow_node_while_it_holds_the_peer_logs_what_next_does",
        JOINT,
    ),
    (
        "a_restart_answered_at_the_dialers_msg2_on_flow_nodes_logs_what_next_does",
        JOINT,
    ),
    (
        "a_restart_at_msg3_of_a_peering_installed_inside_the_interval_with_no_frame_on_flow_nodes_logs_what_next_does",
        JOINT,
    ),
    ("a_lone_dial_settles_both_ends_as_the_judge_does", JUDGED),
    (
        "a_simultaneous_dial_differs_from_the_judge_only_where_the_larger_node_keeps_at_its_msg2",
        JUDGED,
    ),
    (
        "two_dials_of_one_node_answered_in_turn_keep_the_first_installed_without_a_msg3_for_the_second",
        JUDGED,
    ),
    (
        "a_redial_by_the_smaller_node_while_it_holds_the_peer_agrees_with_the_judge",
        JUDGED,
    ),
    (
        "a_redial_by_the_larger_node_while_it_holds_the_peer_shows_the_pinned_same_side_rule_at_both_ends",
        JUDGED,
    ),
    (
        "a_restart_answered_at_the_dialers_msg2_inside_the_interval_shows_the_pinned_ungated_restart",
        JUDGED,
    ),
    (
        "a_restart_at_msg3_of_a_peering_installed_inside_the_interval_with_no_frame_is_refused_by_next_alone",
        JUDGED,
    ),
    (
        "every_difference_the_check_names_is_told_apart_by_its_cause",
        JUDGED,
    ),
    ("the_wildcard_arm_fence_is_declared_at_the_flows_root", SCAN),
    (
        "every_flow_test_is_named_by_a_switch_or_listed_and_the_scan_finds_a_planted_one",
        SCAN,
    ),
    (
        "every_guard_switch_of_the_flow_turns_each_test_it_names_red_and_each_passes_with_none",
        "the meta-test itself",
    ),
    (
        "the_xx_parameters_keep_one_interval_floor_and_no_unheard_floor_or_replay_memory",
        RULE,
    ),
    (
        "an_install_marks_the_dials_in_flight_then_and_not_a_later_one",
        RULE,
    ),
    (
        "a_frame_marks_the_session_heard_and_a_removal_forgets_the_peers_marks",
        RULE,
    ),
    (
        "an_anonymous_msg1_opens_an_inbound_link_and_its_answer_a_leg_that_names_no_one",
        RULE,
    ),
    ("an_answer_to_no_ask_hands_its_lease_back", RULE),
    (
        "a_dial_in_flight_at_the_install_is_settled_by_address_order_once_the_peer_was_heard",
        RULE,
    ),
    (
        "a_later_dial_of_a_held_peer_is_settled_by_address_order_once_its_msg3_is_sent",
        RULE,
    ),
    ("a_restarted_peers_msg2_replaces_it_with_no_gate", RULE),
    (
        "the_peer_cap_at_msg2_leaves_the_dials_leg_for_its_reap",
        RULE,
    ),
    (
        "a_msg2_from_a_static_other_than_the_one_dialed_keeps_the_leg",
        RULE,
    ),
    (
        "a_failed_msg3_send_installs_nothing_and_the_sweep_retries_the_identity_the_msg2_taught",
        RULE,
    ),
    (
        "a_refusal_at_msg2_ends_the_leg_at_once_closing_nothing_and_retries_whom_the_shell_names",
        RULE,
    ),
    (
        "an_anonymous_dial_on_a_connection_starts_on_its_link_and_a_failed_connection_closes_nothing",
        RULE,
    ),
    (
        "a_msg3_from_an_identity_not_held_installs_it_as_responder",
        RULE,
    ),
    (
        "a_crossing_at_msg3_moves_the_larger_node_onto_its_inbound_session_and_keeps_the_smaller_on_its_own",
        RULE,
    ),
    ("the_peer_cap_at_msg3_leaves_the_answer_for_its_reap", RULE),
    ("a_msg3_for_no_anonymous_answer_changes_nothing", RULE),
    (
        "a_resend_of_the_answered_msg1_draws_the_stored_msg2_until_its_msg3_and_no_other_msg1_does",
        CHARACTERISED,
    ),
    (
        "the_gates_count_silent_sessions_and_refuse_as_nexts_silent_sessions_record_does",
        CHARACTERISED,
    ),
    (
        "the_admission_cap_counts_asks_and_unsent_answers_and_a_sent_answer_frees_its_place",
        CHARACTERISED,
    ),
    (
        "every_answers_link_is_its_own_so_the_crossings_guards_are_always_true",
        CHARACTERISED,
    ),
    (
        "a_dial_predates_the_session_held_exactly_when_opened_before_its_install_or_move",
        CHARACTERISED,
    ),
    (
        "the_retry_after_each_failure_at_msg2_goes_to_the_identity_the_leg_expects_by_then",
        CHARACTERISED,
    ),
    (
        "an_anonymous_msg1_whose_index_could_not_be_drawn_retires_its_link_closing_nothing_and_takes_no_lease",
        CHARACTERISED,
    ),
    (
        "a_crossing_return_at_msg2_ends_the_parked_dial_closing_nothing_and_retries_no_one",
        CHARACTERISED,
    ),
    (
        "the_gate_read_as_heard_refuses_exactly_where_nexts_idle_floor_and_dampener_refuse",
        CHARACTERISED,
    ),
];

#[cfg(feature = "slow-tests")]
mod run {
    //! The meta-test itself, which runs each row in child processes.

    use alloc::format;
    use alloc::string::String;
    use alloc::vec::Vec;

    use super::super::super::faults::VAR;
    use super::ROWS;

    /// The node list's variable, which every child runs without.
    const NODE_VAR: &str = "FIPS_NODE_FAULTS";

    /// Run the test at `path` alone in a child process with `faults` set,
    /// or with no switch when it is empty; true when it passed, with what
    /// the child printed.
    fn child(path: &str, faults: &str) -> (bool, String) {
        let exe = std::env::current_exe().expect("the test binary's path");
        let mut cmd = std::process::Command::new(exe);
        cmd.args([path, "--exact", "--test-threads=1"])
            .env_remove(VAR)
            .env_remove(NODE_VAR);
        if !faults.is_empty() {
            cmd.env(VAR, faults);
        }
        let out = cmd.output().expect("the test binary runs");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    }

    #[test]
    fn every_guard_switch_of_the_flow_turns_each_test_it_names_red_and_each_passes_with_none() {
        if std::env::var_os(VAR).is_some() || std::env::var_os(NODE_VAR).is_some() {
            return;
        }
        let compiled = crate::testutil::compiled_tests();
        let mut wrong = Vec::new();
        let mut named: Vec<String> = Vec::new();
        let mut runs = 0;
        for (fault, tests) in ROWS {
            if tests.is_empty() {
                wrong.push(format!("{fault:?} names no test"));
            }
            for (prefix, test) in *tests {
                let path = format!("{prefix}{test}");
                if !compiled.contains(&path) {
                    wrong.push(format!(
                        "{fault:?} names {path}, which this build does not compile"
                    ));
                    continue;
                }
                let (passed, text) = child(&path, &format!("{fault:?}"));
                runs += 1;
                if passed || !text.contains("running 1 test") || !text.contains("1 failed") {
                    wrong.push(format!("{path} does not fail with {fault:?} on:\n{text}"));
                }
                if !named.contains(&path) {
                    named.push(path);
                }
            }
        }
        for path in &named {
            let (passed, text) = child(path, "");
            runs += 1;
            if !passed || !text.contains("running 1 test") || !text.contains("1 passed") {
                wrong.push(format!("{path} does not pass with no switch:\n{text}"));
            }
        }
        std::eprintln!(
            "{} rows, {} named tests, {runs} child runs",
            ROWS.len(),
            named.len()
        );
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }
}
