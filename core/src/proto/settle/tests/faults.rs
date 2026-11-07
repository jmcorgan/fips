//! The meta-test of the switches in `../faults.rs`, and the tables the
//! coverage scan in `mod.rs` reads.
//!
//! For each row, every test it names runs in a child process of this test
//! binary with the row's switch on, and must fail: a guard whose removal
//! turns nothing red is itself a failure. Every named test also runs once
//! with no switch and must pass, so a row cannot be met by a test that
//! fails anyway, or by one that is ignored. A child runs one test by its
//! exact path, so it never runs this meta-test again.
//!
//! The tables are compiled in every test build so that the coverage scan,
//! which is cheap, runs everywhere; only the meta-test, which runs each row
//! in a child, waits for the `slow-tests` feature. A row's tests in a file
//! only `slow-explorers` compiles (the runs against the deployed models)
//! are left out of the meta-test without that feature, and every row must
//! keep at least one test it runs.
//!
//! A row names the cheapest tests its switch was shown to red. The core
//! explorer reds most of the core's switches, at 20 to 50 s a run, so it is
//! named only where it is the closest observation of the defect a switch
//! stands for; the commit records list every test each switch reds.

use alloc::string::String;
use alloc::vec::Vec;

use super::super::faults::Fault;

/// The test-path prefix of each test file.
const LINKS: &str = "proto::settle::links::tests::";
const GATES: &str = "proto::settle::gates::tests::";
const LEGS: &str = "proto::settle::legs::tests::";
const TABLE: &str = "proto::settle::table::tests::";
const CANDIDATES: &str = "proto::settle::tests::candidates::";
const CMP: &str = "proto::settle::tests::cmp::";
const EXPLORE: &str = "proto::settle::tests::explore::";
const FINDINGS: &str = "proto::settle::tests::legacy::findings::";
const LEGACY: &str = "proto::settle::tests::legacy::explore::";
const ORACLE: &str = "proto::settle::tests::oracle::checks::";
const REGRESS: &str = "proto::settle::tests::regress::";
const REKEYSIDE: &str = "proto::settle::tests::rekeyside::checks::";
const SHADOW: &str = "proto::settle::tests::shadow::checks::";
const SHAPES: &str = "proto::settle::tests::shapes::";
const SIM: &str = "proto::settle::tests::sim::";
const STUB: &str = "proto::settle::tests::stub::";
const WORLD: &str = "proto::settle::tests::world::checks::";

/// One test, by the prefix of its file and its name.
type Test = (&'static str, &'static str);

/// The core explored in the world, at both ends and against the model.
const CORE_EXPLORED: Test = (
    STUB,
    "every_explored_interleaving_of_the_core_keeps_the_properties_and_heals",
);
/// The model explored as both ends of every start.
const MODEL_SETTLES: Test = (ORACLE, "model_parties_settle_on_every_start");
/// The model's histories through the core.
const AGREES: Test = (
    CMP,
    "the_core_agrees_with_the_model_on_every_model_table_history",
);
/// Each named difference from the model met where it should be.
const NAMED: Test = (CMP, "every_named_difference_from_the_model_still_differs");
/// The gates beside a model `Judge` on the model's gate histories.
const GATE_HISTORIES: Test = (
    GATES,
    "the_gates_agree_with_the_model_on_every_gate_history",
);
/// The seeded faulty sets, one per transport model.
const SIM_DATAGRAM: Test = (
    SIM,
    "seeded_faulty_runs_on_the_connectionless_transport_keep_the_properties_and_heal",
);
/// See [`SIM_DATAGRAM`].
const SIM_STREAM: Test = (
    SIM,
    "seeded_faulty_runs_on_the_connection_oriented_transport_keep_the_properties_and_heal",
);
/// See [`SIM_DATAGRAM`].
const SIM_BLE: Test = (
    SIM,
    "seeded_faulty_runs_on_ble_keep_the_properties_and_heal",
);
/// See [`SIM_DATAGRAM`].
const SIM_MIXED: Test = (
    SIM,
    "seeded_faulty_runs_on_two_transports_keep_the_properties_and_heal",
);
/// The single seeds that once reached a difference the comparison resyncs.
const SIM_REACHED: Test = (
    SIM,
    "seeded_runs_that_reached_a_resynced_difference_keep_the_properties_and_heal",
);
/// The in-order controls of the late-dial pins.
const IN_ORDER_LARGER: Test = (
    REGRESS,
    "after_a_late_second_dial_answered_in_order_both_ends_hold_one_session_larger_dialer",
);
/// See [`IN_ORDER_LARGER`].
const IN_ORDER_SMALLER: Test = (
    REGRESS,
    "after_a_late_second_dial_answered_in_order_both_ends_hold_one_session_smaller_dialer",
);
/// The young-link control of the aged-link pin.
const YOUNG_LINK: Test = (
    REGRESS,
    "after_a_dial_on_the_peers_young_link_the_peer_answers_the_larger_nodes_rekey",
);
/// The model of `master`'s four defects, one finding test each.
const AGED: Test = (
    FINDINGS,
    "against_a_model_of_master_a_dial_on_the_peers_aged_link_leaves_a_pending_the_peer_cannot_adopt",
);

/// One row: a switch, and the tests that must each fail with it on.
pub type Row = (Fault, &'static [Test]);

/// Every switch and the tests it must turn red.
pub const ROWS: &[Row] = &[
    (
        Fault::IndexStale,
        &[
            (
                LINKS,
                "the_index_holds_each_live_links_setup_address_and_proven_paths",
            ),
            (
                REGRESS,
                "a_removed_peers_link_leaves_no_entry_in_the_address_index",
            ),
            SIM_DATAGRAM,
            SIM_BLE,
        ],
    ),
    (
        Fault::CloseByPeerAddress,
        &[(
            LINKS,
            "retiring_a_link_closes_only_addresses_no_other_live_link_uses",
        )],
    ),
    (
        Fault::CloseBySetupAddress,
        &[(
            LINKS,
            "a_retired_links_address_that_is_another_links_live_path_stays_open",
        )],
    ),
    (
        Fault::ProbingCounts,
        &[(LINKS, "a_probing_path_keeps_no_connection_open")],
    ),
    (
        Fault::KeepIgnored,
        &[(LINKS, "a_released_path_marked_keep_closes_nothing")],
    ),
    (
        Fault::UnheardInclusive,
        &[
            (
                GATES,
                "the_unheard_floor_refuses_until_one_second_and_accepts_at_it",
            ),
            IN_ORDER_LARGER,
            IN_ORDER_SMALLER,
        ],
    ),
    (
        Fault::HeardFromInstall,
        &[
            (GATES, "the_heard_floor_counts_from_the_last_frame"),
            GATE_HISTORIES,
            YOUNG_LINK,
        ],
    ),
    (
        Fault::HeardNeedsFrame,
        &[
            (
                GATES,
                "the_heard_floor_counts_from_installation_when_no_frame_has_arrived",
            ),
            GATE_HISTORIES,
        ],
    ),
    (
        Fault::DampenerFromRefusal,
        &[
            (
                GATES,
                "the_dampener_refuses_until_its_ceiling_after_the_last_accepted_restart",
            ),
            CORE_EXPLORED,
        ],
    ),
    (
        Fault::OutboundGated,
        &[
            (
                GATES,
                "an_own_msg2_restart_goes_through_the_gate_and_is_accepted_inside_its_floors",
            ),
            GATE_HISTORIES,
            AGREES,
            (
                REGRESS,
                "an_own_dial_answered_from_a_restarted_peer_replaces_the_stale_session",
            ),
        ],
    ),
    (
        Fault::DampenerAtMsg2,
        &[
            (GATES, "an_own_msg2_restart_does_not_stamp_the_dampener"),
            GATE_HISTORIES,
        ],
    ),
    (
        Fault::ReplayUnbounded,
        &[(GATES, "the_replay_memory_holds_at_most_eight"), NAMED],
    ),
    (
        Fault::ReplaySeenIgnored,
        &[
            (
                GATES,
                "the_replay_memory_refuses_an_ephemeral_that_already_promoted_an_unheard_peering",
            ),
            NAMED,
            (
                REGRESS,
                "a_replayed_msg1_that_promoted_an_unheard_peering_stays_refused",
            ),
        ],
    ),
    (
        Fault::HeardKeepsMemory,
        &[(
            GATES,
            "a_frame_forgets_the_replay_memory_and_the_silent_sessions",
        )],
    ),
    (
        Fault::SilentEarly,
        &[
            (
                GATES,
                "silent_sessions_start_a_refusal_at_the_third_in_a_row",
            ),
            NAMED,
        ],
    ),
    (
        Fault::SilentFlat,
        &[(
            GATES,
            "each_further_silent_session_doubles_the_refusal_up_to_its_cap",
        )],
    ),
    (
        Fault::IntervalTen,
        &[
            (GATES, "the_default_intervals_are_the_frcs"),
            (
                REGRESS,
                "a_second_restart_inside_the_dampener_interval_is_refused",
            ),
        ],
    ),
    (
        Fault::LegNeverReaped,
        &[
            (
                LEGS,
                "a_dial_leg_is_reaped_at_its_deadline_and_returns_its_lease",
            ),
            (
                LEGS,
                "a_responder_leg_answers_a_resend_with_its_stored_msg2_and_is_reclaimed",
            ),
        ],
    ),
    (
        Fault::ResendFresh,
        &[(
            LEGS,
            "resends_follow_the_backoff_and_repeat_the_msg1_byte_for_byte",
        )],
    ),
    (
        Fault::AnswerFresh,
        &[(
            LEGS,
            "a_responder_leg_answers_a_resend_with_its_stored_msg2_and_is_reclaimed",
        )],
    ),
    (
        Fault::PollAhead,
        &[(LEGS, "a_poll_before_the_next_wake_does_nothing")],
    ),
    (
        Fault::DeadlineWraps,
        &[(LEGS, "a_deadline_past_the_end_of_the_clock_saturates")],
    ),
    (
        Fault::LeaseKept,
        &[(LEGS, "close_returns_every_lease_and_retires_every_link")],
    ),
    (Fault::MoveKeepsOldPair, &[AGREES]),
    (
        Fault::MoveKeepsInboundLink,
        &[
            (
                TABLE,
                "a_crossing_moves_the_smaller_node_and_retires_the_inbound_link",
            ),
            (
                TABLE,
                "a_late_second_dial_in_order_retires_the_link_moved_off",
            ),
            AGREES,
            (
                REGRESS,
                "a_crossing_over_two_transports_settles_on_one_session",
            ),
            SIM_STREAM,
            SIM_MIXED,
            (
                SIM,
                "seeded_clean_runs_on_every_transport_model_keep_the_properties_and_heal",
            ),
            CORE_EXPLORED,
        ],
    ),
    (
        Fault::MoveNoReset,
        &[
            (TABLE, "a_move_resets_peer_data"),
            AGREES,
            (
                REGRESS,
                "a_crossing_moves_the_smaller_node_with_a_reset_and_keeps_the_maps",
            ),
        ],
    ),
    (Fault::MoveSetsHeard, &[NAMED]),
    (
        Fault::IgnoreOwnDial,
        &[
            AGREES,
            IN_ORDER_LARGER,
            (
                LEGACY,
                "the_core_against_a_model_of_master_converges_on_every_start_in_both_address_orders",
            ),
            (
                LEGACY,
                "the_core_against_a_model_of_maint_converges_on_every_start_in_both_address_orders",
            ),
        ],
    ),
    (Fault::ModelFallbackInCore, &[NAMED]),
    (Fault::ReplacementUngated, &[AGREES, YOUNG_LINK]),
    (
        Fault::AttributeBySetupOnly,
        &[(TABLE, "a_msg1_from_a_proven_path_is_on_the_link"), AGREES],
    ),
    (
        Fault::PathMoveIgnored,
        &[(
            TABLE,
            "a_path_moved_rekeys_the_links_index_entry_to_the_new_pair",
        )],
    ),
    (
        Fault::SwitchIgnored,
        &[(TABLE, "a_path_switched_adds_the_new_pair_to_the_index")],
    ),
    (
        Fault::ReleaseKeepsPair,
        &[(
            TABLE,
            "a_path_released_drops_its_pair_and_closes_unless_in_use_or_kept",
        )],
    ),
    (
        Fault::StateIgnored,
        &[(
            TABLE,
            "a_path_state_change_to_probing_stops_it_counting_as_in_use",
        )],
    ),
    (
        Fault::PunchedDropped,
        &[(
            TABLE,
            "a_punched_input_opens_a_dial_leg_at_the_punched_pair",
        )],
    ),
    (
        Fault::SendFailedDropsLeg,
        &[
            (
                TABLE,
                "a_failed_msg2_send_keeps_the_stored_answer_for_the_resend",
            ),
            (
                REGRESS,
                "a_stored_answer_whose_send_failed_installs_at_the_resend",
            ),
        ],
    ),
    (
        Fault::OrphanedIgnored,
        &[(
            TABLE,
            "an_orphaned_bundle_removes_the_peer_and_retires_its_link",
        )],
    ),
    (
        Fault::CapLifted,
        &[(
            TABLE,
            "a_msg1_past_the_admission_cap_is_rejected_and_holds_no_leg",
        )],
    ),
    (
        Fault::ReachOneMore,
        &[(
            EXPLORE,
            "every_named_start_reaches_its_target_depth_over_the_model",
        )],
    ),
    (
        Fault::FlightByHash,
        &[
            (EXPLORE, "a_replayed_path_rebuilds_the_same_world"),
            (
                SIM,
                "a_seeded_run_replays_byte_identically_from_its_seed_and_from_its_schedule",
            ),
        ],
    ),
    (
        Fault::FrameOpensAny,
        &[(
            WORLD,
            "a_frame_opens_only_under_a_session_the_receiver_holds",
        )],
    ),
    (
        Fault::NoHeartbeat,
        &[(
            WORLD,
            "a_party_holding_a_session_sends_a_heartbeat_at_each_heartbeat_wake",
        )],
    ),
    (
        Fault::ReplyNewConn,
        &[(
            WORLD,
            "a_connection_oriented_reply_goes_on_the_arrival_connection",
        )],
    ),
    (Fault::EofDropped, &[(WORLD, "an_eof_reaches_the_far_end")]),
    (
        Fault::BleSecondConn,
        &[(WORLD, "a_ble_link_holds_one_connection_per_pair")],
    ),
    (
        Fault::SendAtDial,
        &[(
            WORLD,
            "a_dial_inside_the_connect_window_sends_nothing_until_it_connects",
        )],
    ),
    (
        Fault::DelayUnbounded,
        &[(
            WORLD,
            "what_is_in_flight_is_lost_when_the_clock_moves_and_when_its_receiver_restarts",
        )],
    ),
    (
        Fault::ConnectRefusedSilent,
        &[(
            WORLD,
            "a_dialer_inside_its_connect_window_is_told_when_the_acceptor_restarts",
        )],
    ),
    (
        Fault::RefusedConnKept,
        &[(
            WORLD,
            "an_inbound_connection_whose_msg1_was_refused_is_closed_at_the_handshake_timeout",
        )],
    ),
    (
        Fault::ReplacedConnKept,
        &[
            (
                ORACLE,
                "a_replacement_over_another_connection_closes_the_replaced_links_connection",
            ),
            MODEL_SETTLES,
            CORE_EXPLORED,
        ],
    ),
    (
        Fault::ShapeBlind,
        &[
            (
                SHAPES,
                "a_stale_frame_moves_a_late_dialer_back_onto_the_session_its_peer_dropped",
            ),
            (
                SHAPES,
                "observed_a_late_msg1_from_the_peers_previous_life_is_accepted_as_a_restart",
            ),
            (
                SHAPES,
                "observed_a_replayed_msg1_from_the_peers_previous_life_is_accepted_as_a_restart",
            ),
            (
                SHAPES,
                "observed_a_restarted_node_installed_from_the_peers_rekey_is_parted_by_its_late_crossing_dial",
            ),
            (
                SHAPES,
                "the_two_defects_left_for_later_show_their_shapes_in_the_current_and_deployed_node",
            ),
            MODEL_SETTLES,
        ],
    ),
    (
        Fault::ShapeLoose,
        &[(
            SHAPES,
            "each_starts_own_script_shows_only_the_shape_it_carries",
        )],
    ),
    (
        Fault::RightLinkOff,
        &[
            (
                FINDINGS,
                "against_a_model_of_master_crossed_dials_on_one_connectionless_transport_leave_the_smaller_node_on_the_wrong_link_smaller_first",
            ),
            (
                FINDINGS,
                "against_a_model_of_master_crossed_dials_on_one_connectionless_transport_leave_the_smaller_node_on_the_wrong_link_larger_first",
            ),
            (
                FINDINGS,
                "against_a_model_of_master_crossed_dials_on_a_connection_oriented_transport_leave_the_smaller_node_on_the_wrong_link_smaller_first",
            ),
            (
                FINDINGS,
                "against_a_model_of_master_crossed_dials_on_a_connection_oriented_transport_leave_the_smaller_node_on_the_wrong_link_larger_first",
            ),
            (
                FINDINGS,
                "the_model_of_master_against_itself_on_every_start_shows_the_four_defects",
            ),
        ],
    ),
    (
        Fault::RightLinkPairOnly,
        &[
            (
                FINDINGS,
                "against_a_model_of_master_crossed_dials_on_one_connectionless_transport_leave_the_smaller_node_on_the_wrong_link_smaller_first",
            ),
            (
                FINDINGS,
                "against_a_model_of_master_crossed_dials_on_one_connectionless_transport_leave_the_smaller_node_on_the_wrong_link_larger_first",
            ),
        ],
    ),
    (
        Fault::RightLinkNoDirection,
        &[(
            ORACLE,
            "right_link_fires_when_both_ends_of_a_crossing_settle_on_the_larger_nodes_dial",
        )],
    ),
    (
        Fault::OneSessionNoSplit,
        &[
            (
                FINDINGS,
                "against_a_model_of_master_a_late_second_dial_answered_in_the_other_order_splits_the_session_larger_dialer",
            ),
            (
                FINDINGS,
                "against_a_model_of_master_a_late_second_dial_answered_in_the_other_order_splits_the_session_smaller_dialer",
            ),
        ],
    ),
    (Fault::OneSessionNoPending, &[AGED]),
    (
        Fault::OneSessionNoFresh,
        &[(
            ORACLE,
            "one_session_fires_on_complementary_indices_with_no_fresh_frame",
        )],
    ),
    (
        Fault::ClassifiedNoRefusal,
        &[(
            FINDINGS,
            "against_a_model_of_master_a_forward_wall_step_lets_a_msg1_replace_a_peering_heard_just_now",
        )],
    ),
    (
        Fault::PendingAnswers,
        &[
            (
                REKEYSIDE,
                "the_rekey_side_agrees_with_the_model_on_every_rule_3_and_4_history",
            ),
            AGED,
        ],
    ),
    (
        Fault::ResyncKeepsAll,
        &[(
            SHADOW,
            "the_late_dial_resync_closes_what_the_model_closes_when_its_fallback_is_dropped",
        )],
    ),
    (Fault::ModelDropsFallback, &[MODEL_SETTLES]),
    (
        Fault::PacketStamp,
        &[
            (
                REGRESS,
                "a_restart_dial_inside_the_heard_floor_is_judged_on_one_clock",
            ),
            CORE_EXPLORED,
        ],
    ),
    (
        Fault::StoredByBytes,
        &[(
            TABLE,
            "a_msg1_from_the_address_of_an_unsent_answer_draws_that_answer_whatever_its_bytes",
        )],
    ),
    (Fault::YieldKept, &[SIM_REACHED, SIM_STREAM]),
    (Fault::RekeyOutlivesPeer, &[SIM_REACHED, SIM_STREAM]),
    (Fault::PreviousUnheard, &[SIM_REACHED]),
    (Fault::ReachablePeeks, &[SIM_REACHED, SIM_STREAM]),
    (
        Fault::NoShrink,
        &[(SIM, "a_planted_failing_run_shrinks_to_its_cause")],
    ),
    (Fault::RecordedCompared, &[SIM_DATAGRAM, SIM_BLE]),
    (Fault::FrameCutoverMissed, &[SIM_DATAGRAM, SIM_MIXED]),
    (
        Fault::CandidateHoldsNothing,
        &[(
            CANDIDATES,
            "both_late_dial_candidates_settle_a_late_second_dial_answered_in_the_other_order",
        )],
    ),
    (
        Fault::AgedTieBreak,
        &[(
            CANDIDATES,
            "the_aged_move_candidate_answers_the_rekey_after_a_dial_on_the_aged_link_once_its_frame_arrives_first",
        )],
    ),
];

/// The tests that plant their own break and show it is found, so no
/// switch is needed for them.
pub const SELF_CHECKED: &[&str] = &[
    "the_wildcard_arm_fence_is_declared_at_the_settlement_root",
    "no_core_source_defines_a_setter_and_the_scan_finds_a_planted_one",
    "no_core_source_reaches_into_the_model_and_the_scan_finds_a_planted_path",
    "no_model_source_reaches_into_the_core_and_the_scan_finds_a_planted_path",
    "every_core_and_model_source_file_is_scanned",
    "every_settlement_test_is_named_by_a_switch_or_listed_and_the_scan_finds_a_planted_one",
    "every_switch_has_a_row_and_the_scan_finds_a_row_removed",
    "every_guard_switch_turns_each_test_it_names_red_and_each_passes_with_none",
];

/// The tests that characterise behaviour no switch breaks, each with why.
pub const CHARACTERISATION: &[(&str, &str)] = &[
    (
        "after_a_late_second_dial_answered_in_the_other_order_both_ends_hold_one_session_larger_dialer",
        "a known defect, red today and ignored; the known-defect lane checks that it still fails at its defect line",
    ),
    (
        "after_a_late_second_dial_answered_in_the_other_order_both_ends_hold_one_session_smaller_dialer",
        "a known defect, red today and ignored; the known-defect lane checks that it still fails at its defect line",
    ),
    (
        "after_a_dial_on_the_peers_aged_link_the_peer_answers_the_larger_nodes_rekey",
        "a known defect, red today and ignored; the known-defect lane checks that it still fails at its defect line",
    ),
    (
        "the_dialer_settle_candidate_explored_shows_exactly_the_breaches_recorded_for_it",
        "the record of a candidate rule's explored outcome, every breach and convergence in candidates.txt, which reds at any change to it either way; no switch is a defect of the candidate, and a row would rerun some minutes of exploration per child, so the breaks a row would name are run by hand and logged with the commit",
    ),
    (
        "the_responder_hold_candidate_explored_shows_exactly_the_breaches_recorded_for_it",
        "the record of a candidate rule's explored outcome, every breach and convergence in candidates.txt, which reds at any change to it either way; no switch is a defect of the candidate, and a row would rerun some minutes of exploration per child, so the breaks a row would name are run by hand and logged with the commit",
    ),
    (
        "the_aged_move_candidate_explored_shows_exactly_the_breaches_recorded_for_it",
        "the record of a candidate rule's explored outcome, every breach and convergence in candidates.txt, which reds at any change to it either way; no switch is a defect of the candidate, and a row would rerun some minutes of exploration per child, so the breaks a row would name are run by hand and logged with the commit",
    ),
];

/// The switches in `all` that no row of `rows` names.
pub fn rowless(all: &[Fault], rows: &[Row]) -> Vec<Fault> {
    all.iter()
        .copied()
        .filter(|f| !rows.iter().any(|(r, _)| r == f))
        .collect()
}

/// The names in `tests` that no row of `rows` names and neither list
/// holds.
pub fn uncovered<'a>(
    tests: &'a [String],
    rows: &[Row],
    checked: &[&str],
    characterised: &[(&str, &str)],
) -> Vec<&'a str> {
    tests
        .iter()
        .map(String::as_str)
        .filter(|t| {
            !rows.iter().any(|(_, ts)| ts.iter().any(|(_, n)| n == t))
                && !checked.contains(t)
                && !characterised.iter().any(|(n, _)| n == t)
        })
        .collect()
}

#[cfg(feature = "slow-tests")]
mod run {
    //! The meta-test itself, which runs each row in child processes.

    use alloc::format;
    use alloc::string::String;
    use alloc::vec::Vec;

    use super::super::super::faults::VAR;
    use super::{LEGACY, ROWS};

    /// The test files only a build with `slow-explorers` compiles.
    const EXPLORERS: &[&str] = &[LEGACY];

    /// Whether this build compiles the tests of the file `prefix` names.
    fn built(prefix: &str) -> bool {
        cfg!(feature = "slow-explorers") || !EXPLORERS.contains(&prefix)
    }

    /// Run the test at `path` alone in a child process with `faults` on;
    /// true when it passed, with what the child printed. Seeded sets
    /// report a failure unshrunk, since only its being red counts here.
    fn child(path: &str, faults: &str) -> (bool, String) {
        let exe = std::env::current_exe().expect("the test binary's path");
        let out = std::process::Command::new(exe)
            .args([path, "--exact", "--test-threads=1"])
            .env(VAR, faults)
            .env("FIPS_SETTLE_SIM_NOSHRINK", "1")
            .output()
            .expect("the test binary runs");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    }

    /// Run `jobs` on a few threads.
    fn parallel<T: Send + Sync, R: Send>(jobs: Vec<T>, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
        let lanes = 6;
        let mut chunks: Vec<Vec<T>> = (0..lanes).map(|_| Vec::new()).collect();
        for (i, j) in jobs.into_iter().enumerate() {
            chunks[i % lanes].push(j);
        }
        let f = &f;
        std::thread::scope(|s| {
            let handles: Vec<_> = chunks
                .iter()
                .map(|c| s.spawn(move || c.iter().map(f).collect::<Vec<R>>()))
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().expect("a lane finishes"))
                .collect()
        })
    }

    #[test]
    fn every_guard_switch_turns_each_test_it_names_red_and_each_passes_with_none() {
        if std::env::var_os(VAR).is_some() {
            return;
        }
        let mut named: Vec<String> = Vec::new();
        let mut jobs = Vec::new();
        let mut wrong = Vec::new();
        let mut left = 0;
        for (fault, tests) in ROWS {
            if !tests.iter().any(|(prefix, _)| built(prefix)) {
                wrong.push(format!("{fault:?} names no test this build compiles"));
            }
            for (prefix, test) in *tests {
                if !built(prefix) {
                    left += 1;
                    continue;
                }
                let path = format!("{prefix}{test}");
                if !named.contains(&path) {
                    named.push(path.clone());
                }
                jobs.push((format!("{fault:?}"), path));
            }
        }
        for p in &named {
            jobs.push((String::new(), p.clone()));
        }
        let started = std::time::Instant::now();
        let results = parallel(jobs, |(fault, path)| {
            let t = std::time::Instant::now();
            let (passed, text) = child(path, fault);
            (fault.clone(), path.clone(), passed, text, t.elapsed())
        });
        for (fault, path, passed, text, took) in results {
            let ran = text.contains("running 1 test");
            let shown = if fault.is_empty() { "none" } else { &fault };
            std::eprintln!("{shown} {path}: {} ms", took.as_millis());
            if fault.is_empty() {
                if !passed || !ran || !text.contains("1 passed") {
                    wrong.push(format!("{path} does not pass with no switch:\n{text}"));
                }
            } else if passed || !ran || !text.contains("1 failed") {
                wrong.push(format!("{path} stays green with {fault} on"));
            }
        }
        std::eprintln!(
            "{} rows, {} tests, {} s; {left} row entries left to the explorers' build",
            ROWS.len(),
            named.len(),
            started.elapsed().as_secs()
        );
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }
}
