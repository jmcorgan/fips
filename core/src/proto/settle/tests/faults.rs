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
//!
//! A second table, [`REKEY`], names switches of the rekey machine
//! (`../../rekey/faults.rs`) by their variants' names, with the settlement
//! tests that must fail with each: a joint node runs a real rekey machine,
//! so a guard of the machine can be shown red in the settlement world too.
//! Its children take the rekey machine's variable, `FIPS_REKEY_FAULTS`,
//! where the first table's take `FIPS_SETTLE_FAULTS`. The rekey machine's
//! own meta-test keeps its rows; these are rows beside them.

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
const SHADOW: &str = "proto::settle::tests::shadow::checks::";
const SHAPES: &str = "proto::settle::tests::shapes::";
const SIM: &str = "proto::settle::tests::sim::";
const WORLD: &str = "proto::settle::tests::world::checks::";
const JOINT_MACHINES: &str = "proto::settle::tests::joint::machines::";
const JOINT_PARTY: &str = "proto::settle::tests::joint::party::";
const JOINT_EXPLORE: &str = "proto::settle::tests::joint::explore::";
const JOINT_FEEDS: &str = "proto::settle::tests::joint::feeds::";
const JOINT_ORACLE: &str = "proto::settle::tests::joint::oracle::";
const JOINT_PARITY: &str = "proto::settle::tests::joint::parity::";
const JOINT_RUNS: &str = "proto::settle::tests::joint::runs::";
const JOINT_STARTS: &str = "proto::settle::tests::joint::starts::";

/// One test, by the prefix of its file and its name.
type Test = (&'static str, &'static str);

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
/// The aged-link defect of the model of `master`.
const AGED: Test = (
    FINDINGS,
    "against_a_model_of_master_a_dial_on_the_peers_aged_link_leaves_a_pending_the_peer_cannot_adopt",
);

/// The table and a shell's record reading the bundle's reports one way.
const MIRROR: Test = (
    TABLE,
    "the_table_and_the_record_read_the_mirror_the_same_way",
);

/// A joint node's machines carried across a cross-connection move.
const MOVED: Test = (
    JOINT_MACHINES,
    "a_move_keeps_the_record_the_link_age_and_renews_the_bundle",
);

/// A crossing of joint nodes, settled on one session.
const JOINT_CROSSING: Test = (
    JOINT_PARTY,
    "a_crossing_settles_on_one_session_on_real_machines",
);

/// One view of a restart at a joint node, found at a rekey and at a
/// replacement.
const JOINT_RESTART: Test = (
    JOINT_ORACLE,
    "one_view_reads_a_restart_on_both_sides_of_the_core",
);

/// Each machine output a joint node's core must hear of, matched to its
/// input.
const JOINT_DELIVERED: Test = (JOINT_ORACLE, "delivered_matches_each_output_to_its_input");

/// A joint node's mirror of its bundles' paths, at a roam and at a second
/// path.
const JOINT_MIRRORED: Test = (
    JOINT_ORACLE,
    "mirrored_fires_on_a_path_the_core_did_not_take",
);

/// A joint node's key, which holds every field a successor reads.
const JOINT_KEYED: Test = (
    JOINT_EXPLORE,
    "a_state_differing_only_inside_a_machine_has_its_own_key",
);

/// A rekey answer of a joint node, on the arrival path at On and the
/// established link at Off.
const JOINT_ARRIVAL: Test = (
    JOINT_FEEDS,
    "a_rekey_answer_goes_on_the_arrival_path_at_on_and_the_established_link_at_off",
);

/// The only path's transport removed, the peer orphaned and redialled.
const JOINT_ORPHANED: Test = (
    JOINT_STARTS,
    "the_only_paths_transport_removed_orphans_the_peer_and_a_redial_settles",
);

/// The two pinned defects shown by joint nodes.
const JOINT_DEFECTS: Test = (
    JOINT_PARTY,
    "starts_6_and_7_show_their_two_defects_on_real_machines",
);

/// The shared schedules on the model of the node, against the trace.
const PARITY_MODEL: Test = (
    JOINT_PARITY,
    "every_shared_schedule_gives_its_trace_on_the_model_of_the_node",
);

/// The shared schedules on joint nodes, against the trace and its `core`
/// lines.
const PARITY_JOINT: Test = (
    JOINT_PARITY,
    "every_shared_schedule_gives_its_trace_on_joint_nodes",
);

/// Every start's script with its heal, joint nodes at Off at both ends.
const SCRIPTED_OFF: Test = (JOINT_PARTY, "every_start_settles_scripted_off_with_off");

/// Every start's script with its heal, joint nodes at On at both ends.
const SCRIPTED_ON: Test = (JOINT_RUNS, "every_start_settles_scripted_on_with_on");

/// The joint party explored on the wall step start alone, at Off with
/// Off.
const SWEPT_WALL: Test = (
    JOINT_RUNS,
    "the_sweep_of_start_14_keeps_the_properties_off_with_off",
);

/// One row: a switch, and the tests that must each fail with it on.
pub type Row = (Fault, &'static [Test]);

/// One row of the rekey machine's switches: a variant's name in
/// `../../rekey/faults.rs`, and the tests that must each fail with it on.
pub type RekeyRow = (&'static str, &'static [Test]);

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
            JOINT_CROSSING,
            SCRIPTED_OFF,
            SCRIPTED_ON,
        ],
    ),
    (
        Fault::CloseByPeerAddress,
        &[
            (
                LINKS,
                "retiring_a_link_closes_only_addresses_no_other_live_link_uses",
            ),
            (
                JOINT_STARTS,
                "a_link_retired_beside_a_dial_in_flight_keeps_the_connection_the_dial_uses",
            ),
        ],
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
            SCRIPTED_OFF,
            SCRIPTED_ON,
        ],
    ),
    (
        Fault::HeardFromInstall,
        &[
            (GATES, "the_heard_floor_counts_from_the_last_frame"),
            GATE_HISTORIES,
            YOUNG_LINK,
            SCRIPTED_OFF,
            SCRIPTED_ON,
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
            (
                JOINT_RUNS,
                "the_sweep_of_the_drain_start_keeps_the_properties_off_with_off",
            ),
        ],
    ),
    (
        Fault::DampenerFromRefusal,
        &[
            (
                GATES,
                "the_dampener_refuses_until_its_ceiling_after_the_last_accepted_restart",
            ),
            SCRIPTED_OFF,
            SCRIPTED_ON,
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
            SWEPT_WALL,
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
            SWEPT_WALL,
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
            SCRIPTED_OFF,
            SCRIPTED_ON,
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
        &[
            (
                LEGS,
                "a_responder_leg_answers_a_resend_with_its_stored_msg2_and_is_reclaimed",
            ),
            SCRIPTED_OFF,
            SCRIPTED_ON,
        ],
    ),
    (
        Fault::PollAhead,
        &[
            (LEGS, "a_poll_before_the_next_wake_does_nothing"),
            SCRIPTED_OFF,
            SCRIPTED_ON,
        ],
    ),
    (
        Fault::DeadlineWraps,
        &[(LEGS, "a_deadline_past_the_end_of_the_clock_saturates")],
    ),
    (
        Fault::LeaseKept,
        &[
            (LEGS, "close_returns_every_lease_and_retires_every_link"),
            SWEPT_WALL,
        ],
    ),
    (
        Fault::MoveKeepsOldPair,
        &[
            AGREES,
            (
                JOINT_PARTY,
                "a_crossing_on_a_connection_oriented_transport_leaves_the_smaller_node_at_its_dials_pair_on_real_machines",
            ),
            SCRIPTED_OFF,
            SCRIPTED_ON,
        ],
    ),
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
            SCRIPTED_OFF,
            SCRIPTED_ON,
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
            JOINT_CROSSING,
            SCRIPTED_OFF,
            SCRIPTED_ON,
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
                "a_joint_node_off_against_a_model_of_maint_converges_on_every_start_in_both_address_orders",
            ),
            SCRIPTED_OFF,
            SCRIPTED_ON,
        ],
    ),
    (Fault::ModelFallbackInCore, &[NAMED]),
    (
        Fault::ReplacementUngated,
        &[AGREES, YOUNG_LINK, SCRIPTED_OFF, SCRIPTED_ON],
    ),
    (
        Fault::AttributeBySetupOnly,
        &[
            (TABLE, "a_msg1_from_a_proven_path_is_on_the_link"),
            AGREES,
            (
                JOINT_ORACLE,
                "attributed_reads_a_roamed_link_as_the_node_does",
            ),
        ],
    ),
    (
        Fault::PathMoveIgnored,
        &[
            (
                TABLE,
                "a_path_moved_rekeys_the_links_index_entry_to_the_new_pair",
            ),
            MIRROR,
            (
                JOINT_STARTS,
                "a_nat_rebound_of_the_second_path_moves_it_in_the_link_record",
            ),
        ],
    ),
    (
        Fault::SwitchIgnored,
        &[
            (TABLE, "a_path_switched_adds_the_new_pair_to_the_index"),
            MIRROR,
        ],
    ),
    (
        Fault::ReleaseKeepsPair,
        &[
            (
                TABLE,
                "a_path_released_drops_its_pair_and_closes_unless_in_use_or_kept",
            ),
            MIRROR,
            (
                JOINT_STARTS,
                "a_path_removed_at_the_peer_leaves_the_link_record",
            ),
        ],
    ),
    (
        Fault::StateIgnored,
        &[
            (
                TABLE,
                "a_path_state_change_to_probing_stops_it_counting_as_in_use",
            ),
            MIRROR,
            JOINT_MIRRORED,
            (
                JOINT_RUNS,
                "the_sweep_of_start_12_keeps_the_properties_on_with_on",
            ),
            (
                JOINT_STARTS,
                "a_carrier_loss_and_a_mandatory_switch_keep_both_ends_mirrored",
            ),
        ],
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
            SCRIPTED_OFF,
            SCRIPTED_ON,
        ],
    ),
    (
        Fault::OrphanedIgnored,
        &[
            (
                TABLE,
                "an_orphaned_bundle_removes_the_peer_and_retires_its_link",
            ),
            JOINT_ORPHANED,
        ],
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
        &[
            (
                EXPLORE,
                "every_named_start_reaches_its_target_depth_over_the_model",
            ),
            (
                JOINT_RUNS,
                "the_reach_of_start_14_stays_within_its_cap_off_with_off",
            ),
            (
                JOINT_RUNS,
                "the_reach_of_start_14_stays_within_its_cap_on_with_on",
            ),
            (
                JOINT_RUNS,
                "the_reach_of_start_14_stays_within_its_cap_on_with_off",
            ),
            (
                JOINT_RUNS,
                "the_reach_of_start_14_stays_within_its_cap_off_with_on",
            ),
        ],
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
        Fault::ExemptByPath,
        &[(
            ORACLE,
            "a_split_of_another_cause_on_a_shaped_path_is_not_exempt",
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
            JOINT_DEFECTS,
        ],
    ),
    (Fault::OneSessionNoPending, &[AGED, JOINT_DEFECTS]),
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
            ORACLE,
            "classified_fires_on_a_refusal_the_model_does_not_make",
        )],
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
        &[(
            REGRESS,
            "a_restart_dial_inside_the_heard_floor_is_judged_on_one_clock",
        )],
    ),
    (
        Fault::StoredByBytes,
        &[
            (
                TABLE,
                "a_msg1_from_the_address_of_an_unsent_answer_draws_that_answer_whatever_its_bytes",
            ),
            (
                JOINT_RUNS,
                "the_sweep_of_start_10_keeps_the_properties_off_with_off",
            ),
        ],
    ),
    (Fault::YieldKept, &[SIM_REACHED, SIM_DATAGRAM]),
    (Fault::RekeyOutlivesPeer, &[SIM_REACHED, SIM_STREAM]),
    (
        Fault::PreviousUnheard,
        &[(
            SHADOW,
            "a_frame_under_the_drained_session_counts_as_heard_at_the_next_gate",
        )],
    ),
    (Fault::ReachablePeeks, &[SIM_REACHED]),
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
    (
        Fault::WireByNumber,
        &[(WORLD, "two_orders_of_commuting_sends_reach_one_key")],
    ),
    (Fault::MoveBuildsFresh, &[MOVED]),
    (
        Fault::RenewSkipped,
        &[
            MOVED,
            (
                JOINT_STARTS,
                "a_crossing_while_capability_probes_are_out_renews_the_bundle_and_keeps_both_ends_mirrored",
            ),
            PARITY_MODEL,
            PARITY_JOINT,
        ],
    ),
    (
        Fault::ModeIgnored,
        &[
            (
                JOINT_MACHINES,
                "a_disabled_bundle_takes_a_candidate_as_a_poll_and_an_enabled_one_holds_it",
            ),
            (
                JOINT_FEEDS,
                "an_on_end_against_an_off_end_stays_not_capable_within_the_probe_budget",
            ),
        ],
    ),
    (
        Fault::ReplaceDropped,
        &[
            (
                JOINT_PARTY,
                "a_fresh_msg1_on_a_young_link_reaches_the_gates",
            ),
            JOINT_DELIVERED,
        ],
    ),
    (
        Fault::PathsUnmirrored,
        &[
            (JOINT_PARTY, "a_one_path_roam_reaches_the_link_record"),
            JOINT_MIRRORED,
        ],
    ),
    (
        Fault::RestartDropped,
        &[
            (
                JOINT_PARTY,
                "a_restart_revealed_in_a_rekey_msg2_reaches_the_core",
            ),
            JOINT_RESTART,
            JOINT_DELIVERED,
        ],
    ),
    (
        Fault::SendsByHeld,
        &[(
            JOINT_PARTY,
            "after_a_frame_from_another_transport_sends_stay_on_the_active_path",
        )],
    ),
    (Fault::KeyFromView, &[JOINT_KEYED]),
    (Fault::KeyOmitsBundle, &[JOINT_KEYED]),
    (
        Fault::HeardFeedDropped,
        &[(
            JOINT_FEEDS,
            "an_on_pair_with_a_candidate_becomes_capable_and_holds_a_second_path",
        )],
    ),
    (Fault::ArrivalIgnored, &[JOINT_ARRIVAL]),
    (
        Fault::ProvenCompared,
        &[
            JOINT_ARRIVAL,
            (
                SHADOW,
                "a_msg1_on_a_proven_pair_is_compared_as_on_the_link_and_a_refusal_there_still_reds",
            ),
        ],
    ),
    (
        Fault::MoveBuildsStale,
        &[
            (JOINT_ORACLE, "one_view_reads_the_session_a_move_built_from"),
            PARITY_MODEL,
            PARITY_JOINT,
        ],
    ),
    (Fault::ReplaceKeepsMachine, &[JOINT_RESTART]),
    (
        Fault::LeaseForgotten,
        &[(JOINT_ORACLE, "leases_fire_on_a_free_the_shell_lost")],
    ),
    (
        Fault::CloseSkipped,
        &[(JOINT_ORACLE, "no_orphan_fires_on_a_machine_past_its_peer")],
    ),
    (Fault::OrphanKept, &[JOINT_DELIVERED, JOINT_ORPHANED]),
];

/// The rekey machine's switches that a joint node's tests red, each by its
/// variant's name, and the tests that must each fail with it on. A rekey
/// switch is here only where a settlement test reaches its guard; the
/// rekey machine's own table still names the tests that red it there.
pub const REKEY: &[RekeyRow] = &[
    (
        "LargerKeepsOwn",
        &[(JOINT_RUNS, "simultaneous_rekeys_settle_on_one_session")],
    ),
    (
        "RefusalUnrecorded",
        &[(
            JOINT_RUNS,
            "a_refused_rekey_msg1_stays_refused_when_it_comes_again",
        )],
    ),
    (
        "CloseSkipsRecord",
        &[(
            JOINT_RUNS,
            "a_copy_of_an_answered_rekey_msg1_after_a_move_is_refused_as_answered_before",
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
    "one_view_fires_on_a_planted_identity",
    "each_machine_predicate_fires_on_a_planted_state",
    "each_path_check_fires_on_a_planted_output",
    "no_joint_source_defines_a_setter_and_the_scan_finds_a_planted_one",
    "no_joint_source_allows_a_wildcard_arm_and_the_scan_finds_a_planted_one",
    "the_cores_record_of_where_a_peer_is_is_read_only_for_the_oracles_and_the_scan_finds_a_planted_read",
    "no_settlement_test_names_the_retired_rekey_transcription_and_the_scan_finds_a_planted_one",
    "a_trace_reads_back_as_it_was_written",
    "a_script_names_no_node_or_transport_it_does_not_hold",
    "every_script_has_its_lines_and_every_line_its_script",
    "a_core_line_names_a_listed_cause",
];

/// Why a sweep that only the slow explorers' build runs is characterisation.
const SWEPT_SLOW: &str = "a sweep of the joint party with the oracles of the sweep at On with On, whose rows show they can fail; it runs only in the slow explorers' build, and a row would rerun some minutes of exploration per child";

/// Why a whole sweep or reach test of the joint party in the default build
/// is characterisation.
const WHOLE: &str = "a whole sweep or reach of the joint party at one pairing, whose body and checks the one-start runs' rows show can fail; a row would rerun minutes of exploration per child, which takes the meta-test past nextest's limit";

/// Why the cold start's reach tests are characterisation.
const COLD: &str = "the cold start's reach at its stated depth, through the reach check whose failing `ReachOneMore`'s row shows on start 14 at each pairing; with that switch on, a child explores past the stated depth and is the meta-test's longest, so the break is run by hand and logged with the commit";

/// Why a test whose guard needs no switch of its own is characterisation.
const HAND: &str =
    "its break is a scratch edit with no switch of its own, run by hand and logged with the commit";

/// Why a test of the join function, whose break no switch makes, is
/// characterisation; its doc comment names its break.
const JOIN_HAND: &str = "its break is a scratch edit of the join function where no switch sits; run by hand and logged with the commit";

/// Why a run of a joint node against a model of a deployed node beside the
/// one on `IgnoreOwnDial`'s row is characterisation.
const LEGACY_RUN: &str = "the same oracles and list as the run on `IgnoreOwnDial`'s row, a whole set of sweeps past a row's cost; the list's own check is run by hand and logged";

/// The tests that characterise behaviour no switch breaks, each with why.
pub const CHARACTERISATION: &[(&str, &str)] = &[
    (
        "each_rekey_output_routes_to_the_core_or_the_shell",
        JOIN_HAND,
    ),
    ("each_bundle_output_mirrors_to_its_input", JOIN_HAND),
    ("a_bundle_output_at_a_removal_reaches_no_link", JOIN_HAND),
    ("a_released_path_goes_to_the_link_moved_off", JOIN_HAND),
    ("a_roam_is_moved_and_a_bind_is_a_live_path", JOIN_HAND),
    ("a_steps_outputs_come_back_in_order", JOIN_HAND),
    ("a_rekey_step_through_join_allocates_nothing", JOIN_HAND),
    ("a_start_mirrors_the_original_path_as_live", JOIN_HAND),
    (
        "a_move_refused_for_another_key_leaves_both_machines_as_they_were",
        JOIN_HAND,
    ),
    ("a_stop_files_what_the_rekey_machine_carried", JOIN_HAND),
    (
        "every_explored_interleaving_of_the_core_keeps_the_properties_and_heals",
        "a whole sweep of joint nodes at multipath off and against the model on every start, minutes a child on two cores and past the meta-test's limit; each of its switches reds a cheaper test of its row",
    ),
    (
        "against_a_model_of_master_a_forward_wall_step_does_not_let_a_msg1_replace_a_peering_heard_just_now",
        HAND,
    ),
    ("the_cold_start_reaches_its_stated_depth_off_with_off", COLD),
    ("the_cold_start_reaches_its_stated_depth_on_with_on", COLD),
    (
        "the_cold_start_is_explored_as_deep_as_the_reach_budget_allows_at_off_and_at_on",
        "a measurement run by hand and ignored, which asserts nothing: it prints how deep the cold start is explored within a time limit, and the depth it gives is asserted by the cold start's reach tests",
    ),
    (
        "the_model_of_master_against_itself_on_every_start_shows_the_three_defects",
        "a whole sweep of the model on machines at each setting, past a row's cost; the crossing tests carry `RightLinkOff`",
    ),
    (
        "the_model_of_master_with_multipath_on_against_itself_on_a_crossing_of_two_transports",
        "the rest of that sweep at multipath on, in the slow explorers' lane, one start each; the crossing tests carry `RightLinkOff`",
    ),
    (
        "the_model_of_master_with_multipath_on_shows_the_wrong_link_on_a_connection_oriented_crossing",
        "the rest of that sweep at multipath on, in the slow explorers' lane, one start each; the crossing tests carry `RightLinkOff`",
    ),
    (
        "the_model_of_master_with_multipath_on_against_itself_on_a_crossing_during_a_rekey",
        "the rest of that sweep at multipath on, in the slow explorers' lane, one start each; the crossing tests carry `RightLinkOff`",
    ),
    (
        "an_abstract_far_ends_frame_opens_at_the_machine_holding_its_session",
        HAND,
    ),
    (
        "the_split_a_shape_left_is_exempt_after_both_ends_rekey",
        HAND,
    ),
    (
        "a_path_message_reaches_the_model_as_a_frame_and_draws_no_answer",
        HAND,
    ),
    (
        "a_joint_node_holds_the_model_on_the_models_frames_alone",
        HAND,
    ),
    (
        "a_copy_of_the_models_msg2_to_a_dial_is_no_reply_to_an_own_rekey",
        HAND,
    ),
    (
        "a_joint_node_on_against_a_model_of_maint_converges_on_every_start_in_both_address_orders",
        LEGACY_RUN,
    ),
    (
        "a_joint_node_off_against_a_model_of_master_off_converges_on_every_start_in_both_address_orders",
        LEGACY_RUN,
    ),
    (
        "a_joint_node_off_against_a_model_of_master_on_converges_on_every_start_in_both_address_orders",
        LEGACY_RUN,
    ),
    (
        "a_joint_node_on_against_a_model_of_master_off_converges_on_every_start_in_both_address_orders",
        LEGACY_RUN,
    ),
    (
        "a_joint_node_on_against_a_model_of_master_on_converges_on_the_quicker_starts",
        LEGACY_RUN,
    ),
    (
        "a_joint_node_on_against_a_model_of_master_on_converges_on_a_crossing_of_two_transports",
        LEGACY_RUN,
    ),
    (
        "a_joint_node_on_against_a_model_of_master_on_converges_on_a_connection_oriented_crossing",
        LEGACY_RUN,
    ),
    (
        "a_joint_node_on_against_a_model_of_master_on_converges_on_a_crossing_during_a_rekey",
        LEGACY_RUN,
    ),
    (
        "a_joint_node_on_against_a_model_of_master_on_converges_on_the_starts_on_real_bundles",
        LEGACY_RUN,
    ),
    (
        "a_held_peers_reachability_reads_the_bundles_active_path_not_the_cores_record",
        HAND,
    ),
    (
        "the_stub_keys_keep_the_worlds_address_order_in_both_flips",
        HAND,
    ),
    (
        "an_abstract_msg1_reads_as_the_ik_msg1_of_its_handshake",
        HAND,
    ),
    (
        "an_abstract_msg2_reads_as_the_ik_msg2_of_its_handshake",
        HAND,
    ),
    ("an_abstract_frame_opens_only_under_its_handshake", HAND),
    (
        "the_stub_profile_selects_the_rows_the_link_profile_does",
        HAND,
    ),
    (
        "two_peers_machines_rekey_and_both_cut_over_on_one_session",
        HAND,
    ),
    (
        "a_rekey_cuts_over_at_both_ends_and_the_old_session_drains",
        HAND,
    ),
    ("two_worlds_on_one_path_have_one_digest", HAND),
    (
        "every_named_start_reaches_its_target_depth_with_the_machines_off",
        WHOLE,
    ),
    (
        "every_named_start_reaches_its_target_depth_with_the_machines_on",
        WHOLE,
    ),
    (
        "every_named_start_reaches_its_target_depth_with_the_machines_on_against_off",
        WHOLE,
    ),
    (
        "every_named_start_reaches_its_target_depth_with_the_machines_off_against_on",
        WHOLE,
    ),
    (
        "every_explored_interleaving_of_the_joint_party_keeps_the_properties_off",
        WHOLE,
    ),
    (
        "every_explored_interleaving_of_the_joint_party_keeps_the_properties_on",
        WHOLE,
    ),
    (
        "the_sweep_of_start_2_keeps_the_properties_on_with_on",
        SWEPT_SLOW,
    ),
    (
        "the_sweep_of_start_3_keeps_the_properties_on_with_on",
        SWEPT_SLOW,
    ),
    (
        "the_sweep_of_start_9_keeps_the_properties_on_with_on",
        SWEPT_SLOW,
    ),
    (
        "the_sweeps_of_the_two_path_starts_keep_the_properties_on_with_on",
        SWEPT_SLOW,
    ),
    (
        "every_explored_interleaving_of_the_joint_party_keeps_the_properties_on_against_off",
        SWEPT_SLOW,
    ),
    (
        "every_explored_interleaving_of_the_joint_party_keeps_the_properties_off_against_on",
        SWEPT_SLOW,
    ),
    (
        "a_capable_live_peer_is_not_dialled_and_a_stale_or_not_capable_one_is",
        HAND,
    ),
    (
        "a_closed_connection_on_a_link_of_two_paths_fails_that_path_and_keeps_the_link",
        HAND,
    ),
    (
        "a_path_message_roams_a_one_path_link_at_off_and_not_at_on",
        HAND,
    ),
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
        "a_crossing_moved_onto_the_pair_of_the_peers_dial_keeps_that_connection_open",
        "a known defect, red today and ignored; the known-defect lane checks that it still fails at its defect line",
    ),
    (
        "a_proven_path_whose_connection_failed_is_not_counted_in_use_without_a_connection",
        "a known defect, red today and ignored; the known-defect lane checks that it still fails at its defect line",
    ),
    (
        "a_peer_silent_for_the_link_dead_timeout_is_removed_then_and_redialled",
        HAND,
    ),
    (
        "a_peer_silent_past_the_link_dead_timeout_on_a_link_of_several_paths_is_removed_and_the_pair_heals",
        HAND,
    ),
    (
        "each_breach_the_pins_hold_is_exempted_by_its_own_cause_and_a_settled_pair_by_none",
        HAND,
    ),
    (
        "a_frame_from_another_transport_leaves_the_cores_record_of_the_peer_at_the_active_path",
        "a known defect, red today and ignored; the known-defect lane checks that it still fails at its defect line",
    ),
    (
        "a_switch_moves_the_cores_record_of_the_peer_to_the_new_active_path",
        "a known defect, red today and ignored; the known-defect lane checks that it still fails at its defect line",
    ),
    (
        "a_msg1_from_a_capable_peers_setup_pair_with_no_path_is_off_the_link",
        "a known defect, red today and ignored; the known-defect lane checks that it still fails at its defect line",
    ),
    (
        "a_switch_to_a_path_that_is_not_live_leaves_it_acknowledged_in_the_core",
        "a known defect, red today and ignored; the known-defect lane checks that it still fails at its defect line",
    ),
    (
        "a_msg1_from_the_pair_a_frame_from_another_transport_came_from_is_off_the_link",
        "a known defect, red today and ignored; the known-defect lane checks that it still fails at its defect line",
    ),
    (
        "a_msg1_from_the_pair_a_frame_moved_the_cores_record_to_whose_path_is_probing_is_off_the_link",
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

/// The names in `tests` that no row of `rows` or of `rekey` names and
/// neither list holds.
pub fn uncovered<'a>(
    tests: &'a [String],
    rows: &[Row],
    rekey: &[RekeyRow],
    checked: &[&str],
    characterised: &[(&str, &str)],
) -> Vec<&'a str> {
    let named = |t: &str| {
        rows.iter().any(|(_, ts)| ts.iter().any(|(_, n)| *n == t))
            || rekey.iter().any(|(_, ts)| ts.iter().any(|(_, n)| *n == t))
    };
    tests
        .iter()
        .map(String::as_str)
        .filter(|t| !named(t) && !checked.contains(t) && !characterised.iter().any(|(n, _)| n == t))
        .collect()
}

#[cfg(feature = "slow-tests")]
mod run {
    //! The meta-test itself, which runs each row in child processes.

    use alloc::format;
    use alloc::string::String;
    use alloc::vec::Vec;

    use super::super::super::faults::VAR;
    use super::{LEGACY, REKEY, ROWS, Test};

    /// The rekey machine's variable, which a child of a [`REKEY`] row takes
    /// (`../../rekey/faults.rs`).
    const REKEY_VAR: &str = "FIPS_REKEY_FAULTS";

    /// The test files only a build with `slow-explorers` compiles.
    const EXPLORERS: &[&str] = &[LEGACY];

    /// Whether this build compiles the tests of the file `prefix` names.
    fn built(prefix: &str) -> bool {
        cfg!(feature = "slow-explorers") || !EXPLORERS.contains(&prefix)
    }

    /// Run the test at `path` alone in a child process with the variable
    /// `var` set to `faults`, or with no switch when `var` is empty; true
    /// when it passed, with what the child printed. Seeded sets report a
    /// failure unshrunk, since only its being red counts here.
    fn child(path: &str, var: &str, faults: &str) -> (bool, String) {
        let exe = std::env::current_exe().expect("the test binary's path");
        let mut cmd = std::process::Command::new(exe);
        cmd.args([path, "--exact", "--test-threads=1"])
            .env_remove(VAR)
            .env_remove(REKEY_VAR)
            .env("FIPS_SETTLE_SIM_NOSHRINK", "1");
        if !var.is_empty() {
            cmd.env(var, faults);
        }
        let out = cmd.output().expect("the test binary runs");
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
        if std::env::var_os(VAR).is_some() || std::env::var_os(REKEY_VAR).is_some() {
            return;
        }
        let tables: Vec<(&str, String, &[Test])> = ROWS
            .iter()
            .map(|(f, ts)| (VAR, format!("{f:?}"), *ts))
            .chain(
                REKEY
                    .iter()
                    .map(|(f, ts)| (REKEY_VAR, String::from(*f), *ts)),
            )
            .collect();
        let mut named: Vec<String> = Vec::new();
        let mut jobs = Vec::new();
        let mut wrong = Vec::new();
        let mut left = 0;
        for (var, fault, tests) in &tables {
            if !tests.iter().any(|(prefix, _)| built(prefix)) {
                wrong.push(format!("{fault} names no test this build compiles"));
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
                jobs.push((*var, fault.clone(), path));
            }
        }
        for p in &named {
            jobs.push(("", String::new(), p.clone()));
        }
        let started = std::time::Instant::now();
        let results = parallel(jobs, |(var, fault, path)| {
            let t = std::time::Instant::now();
            let (passed, text) = child(path, var, fault);
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
            "{} rows and {} rekey rows, {} tests, {} s; {left} row entries left to the explorers' build",
            ROWS.len(),
            REKEY.len(),
            named.len(),
            started.elapsed().as_secs()
        );
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }
}
