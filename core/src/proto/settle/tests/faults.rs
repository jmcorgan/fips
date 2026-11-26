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
//! in a child, waits for the `slow-tests` feature. Every test a row names
//! must be compiled by that build, so a misspelled or renamed name fails
//! it. Which tests this build compiles is read from the binary's own list
//! (`crate::testutil::compiled_tests`).
//!
//! A row names the cheapest tests its switch was shown to red; the commit
//! records list every test each switch reds. A row whose switch the joint
//! world reaches names a joint test or scripted start it reds there, and a
//! row whose switch no joint test or scripted start reds says why in a
//! comment above it.
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
const JOIN: &str = "proto::settle::join::tests::";
const CANDIDATES: &str = "proto::settle::tests::candidates::";
const CMP: &str = "proto::settle::tests::cmp::";
const EXPLORE: &str = "proto::settle::tests::explore::";
const FINDINGS: &str = "proto::settle::tests::legacy::findings::";
const ORACLE: &str = "proto::settle::tests::oracle::checks::";
const REGRESS: &str = "proto::settle::tests::regress::";
const SHADOW: &str = "proto::settle::tests::shadow::checks::";
const SHAPES: &str = "proto::settle::tests::shapes::";
const SIM: &str = "proto::settle::tests::sim::";
const WORLD: &str = "proto::settle::tests::world::checks::";
const JOINT_MACHINES: &str = "proto::settle::tests::joint::machines::";
const JOINT_PARTY: &str = "proto::settle::tests::joint::party::";
const JOINT_PINS: &str = "proto::settle::tests::joint::pins::";
const JOINT_EXPLORE: &str = "proto::settle::tests::joint::explore::";
const JOINT_FEEDS: &str = "proto::settle::tests::joint::feeds::";
const JOINT_ORACLE: &str = "proto::settle::tests::joint::oracle::";
const JOINT_PARITY: &str = "proto::settle::tests::joint::parity::";
const JOINT_RUNS: &str = "proto::settle::tests::joint::runs::";
const JOINT_STARTS: &str = "proto::settle::tests::joint::starts::";

/// One test, by the prefix of its file and its name.
type Test = (&'static str, &'static str);

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

/// The right-link property on a crossing both ends settled on the larger
/// node's dial, which leaves the smaller node inbound.
const RIGHT_LINK: Test = (
    ORACLE,
    "right_link_fires_when_both_ends_of_a_crossing_settle_on_the_larger_nodes_dial",
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
        Fault::ReleasedSetupIndexed,
        &[(
            LINKS,
            "a_released_setup_address_leaves_the_index_and_a_roamed_one_stays",
        )],
    ),
    // Not in the joint world alone. Its one shape there, a capable peer's
    // msg1 from a setup pair whose path its transport's removal took, never
    // asks this guard: the removal released the path and took the pair out of
    // the index. The joint pin of that shape needs `SwitchLeavesPeer` with
    // `AttributeByCurrent` (`CHARACTERISATION`), and no joint test, scripted
    // start or sweep reds this switch alone.
    (
        Fault::CapableIgnored,
        &[(
            TABLE,
            "a_capable_peers_bare_setup_pair_is_off_the_link_in_the_table",
        )],
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
            (
                JOINT_PARTY,
                "an_on_link_replacement_in_a_rekeys_drain_is_held_by_the_heard_floor_off_with_off_and_on_with_on",
            ),
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
    // Not in the joint world: no joint test, scripted start or sweep of the
    // default build reds with it on. The memory it drops is read again only
    // once that heard peering is gone and a later one is unheard.
    (
        Fault::FrameForgetsReplays,
        &[(
            TABLE,
            "a_frame_on_a_peering_heard_from_its_install_keeps_the_replay_memory_and_forgets_the_silent_sessions",
        )],
    ),
    // Not in the joint world: no joint test, scripted start or sweep of the
    // default build reds with it on. The count it leaves out is read only by
    // a later msg1 of the same identity at the same epoch, and only once
    // three such sessions have ended.
    (
        Fault::SilentReadsHeard,
        &[(
            TABLE,
            "an_own_dials_session_that_ends_before_the_peers_first_frame_counts_as_a_silent_session",
        )],
    ),
    // Not in the joint world: no joint test, scripted start or sweep of the
    // default build reaches a standby path's roam.
    (
        Fault::StandbyRoamResets,
        &[(JOIN, "a_standby_paths_roam_is_moved_and_not_marked_a_roam")],
    ),
    // Not in the joint world: what the switch keeps is an identity whose
    // stamp, replays and silence have all lapsed, and each gate reads those
    // against its own interval or horizon, so no verdict changes. Only the
    // memory's size shows the defect, which the gates tests read.
    (
        Fault::MemoryNeverDropped,
        &[
            (
                GATES,
                "gate_memory_holds_no_entry_once_an_identitys_state_has_lapsed",
            ),
            (
                GATES,
                "the_refused_count_goes_with_its_silent_session_record",
            ),
        ],
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
            (
                TABLE,
                "a_reap_of_one_leg_reaps_only_that_leg_and_only_from_its_deadline",
            ),
            (
                LEGS,
                "a_quieted_dial_resends_nothing_more_and_is_still_reaped_at_its_deadline",
            ),
            SCRIPTED_OFF,
            SCRIPTED_ON,
        ],
    ),
    (
        Fault::ResendFresh,
        &[
            (
                LEGS,
                "resends_follow_the_backoff_and_repeat_the_msg1_byte_for_byte",
            ),
            (
                LEGS,
                "the_resends_alone_ask_for_each_due_resend_byte_for_byte_and_reap_no_leg_past_its_deadline",
            ),
        ],
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
            (
                LEGS,
                "the_resends_alone_ask_for_each_due_resend_byte_for_byte_and_reap_no_leg_past_its_deadline",
            ),
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
        &[(LEGS, "close_returns_every_lease_and_retires_every_link")],
    ),
    // Not in the joint world, nor the two switches below: a world's send is
    // never refused, so the joint party reports every msg1 resend as sent
    // (`In::Sent` at its poll) and no dial resend fails to send.
    (
        Fault::UnsentStaysDue,
        &[
            (
                TABLE,
                "an_unsent_dial_resend_is_tried_again_at_the_next_tick_and_not_before",
            ),
            (
                TABLE,
                "a_failed_dial_resend_is_due_at_the_next_poll_whatever_its_instant",
            ),
        ],
    ),
    (
        Fault::UnsentDueAtWake,
        &[(
            TABLE,
            "a_failed_dial_resend_is_due_at_the_next_poll_whatever_its_instant",
        )],
    ),
    (
        Fault::UnsentPastCap,
        &[(
            TABLE,
            "a_send_failure_after_a_dials_last_resend_asks_for_no_more",
        )],
    ),
    (
        Fault::MoveKeepsOldPair,
        // The seeded clean runs and the scripted run at Off with Off see this
        // switch only because a move never closes the connection its msg2
        // came over: closed, it takes the stale pair away and the redial
        // heals the run with no oracle firing.
        &[
            AGREES,
            (
                JOINT_PARTY,
                "a_crossing_on_a_connection_oriented_transport_leaves_the_smaller_node_at_its_dials_pair_on_real_machines",
            ),
            (
                SIM,
                "seeded_clean_runs_on_every_transport_model_keep_the_properties_and_heal",
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
            // Not here: the crossing over two transports, the seeded clean
            // runs, and the connection-oriented and two-transport seeded
            // sets. Under this switch the kept inbound link's setup path is
            // released at the renewal, so its address leaves the derived
            // index and `ConnectionsInUse` no longer finds it in use on the
            // closed connection. Each still reds with `ReleasedSetupIndexed`
            // on as well, and a row holds one switch; the first two are on
            // `MoveKeepsOldPair`'s row, the seeded sets on others.
            SCRIPTED_OFF,
            SCRIPTED_ON,
            (
                FINDINGS,
                "against_a_model_of_the_node_crossed_dials_on_one_connectionless_transport_leave_the_smaller_node_on_the_link_it_dialed_smaller_first",
            ),
            (
                FINDINGS,
                "against_a_model_of_the_node_crossed_dials_on_one_connectionless_transport_leave_the_smaller_node_on_the_link_it_dialed_larger_first",
            ),
            (
                FINDINGS,
                "against_a_model_of_the_node_crossed_dials_on_a_connection_oriented_transport_leave_the_smaller_node_on_the_link_it_dialed_smaller_first",
            ),
            (
                FINDINGS,
                "against_a_model_of_the_node_crossed_dials_on_a_connection_oriented_transport_leave_the_smaller_node_on_the_link_it_dialed_larger_first",
            ),
            PARITY_MODEL,
        ],
    ),
    (
        Fault::MoveClosesNewPair,
        &[
            (
                TABLE,
                "a_move_onto_a_dial_answered_from_the_peers_other_pair_keeps_that_pair_open",
            ),
            (
                JOINT_PINS,
                "a_crossing_moved_onto_the_pair_of_the_peers_dial_keeps_that_connection_open",
            ),
        ],
    ),
    // No joint test, scripted start or sweep reds `AdoptedKeepsDir`: the
    // joint party reports no adoption of a rekey answer.
    (
        Fault::AdoptedKeepsDir,
        &[(
            TABLE,
            "an_adopted_answer_on_the_msg1s_connection_turns_a_dialed_link_inbound",
        )],
    ),
    (
        Fault::MoveLeavesDialOpen,
        &[
            (
                TABLE,
                "a_move_onto_a_dial_answered_from_the_peers_other_pair_closes_the_dials_own_connection",
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
    (
        Fault::MoveLeavesUnheard,
        &[
            (
                TABLE,
                "a_move_onto_this_nodes_own_dial_makes_the_peering_heard",
            ),
            SIM_REACHED,
            PARITY_MODEL,
            PARITY_JOINT,
        ],
    ),
    // Not in the joint world: no joint test, scripted start or sweep of the
    // default build reds with it on. A move makes a peering heard only where
    // a crossing promoted it unheard first, and the memory it keeps is read
    // again only once that heard peering is gone.
    (
        Fault::MoveKeepsReplayMemory,
        &[(
            TABLE,
            "a_move_that_makes_the_peering_heard_forgets_its_replay_memory_and_keeps_its_silent_sessions",
        )],
    ),
    (
        Fault::CrossedRunsKeep,
        &[(
            TABLE,
            "a_crossing_decided_by_the_tie_break_alone_moves_the_smaller_node_onto_its_dial",
        )],
    ),
    (
        Fault::TouchKeepsHeardInstant,
        &[(
            TABLE,
            "a_frame_moves_the_instant_of_the_peerings_last_frame",
        )],
    ),
    (
        Fault::EpochAtCutover,
        &[(
            TABLE,
            "a_restarted_peers_epoch_its_rekey_took_makes_its_msg1_at_that_epoch_a_rekey",
        )],
    ),
    (
        Fault::MovedLeavesEntry,
        &[(
            TABLE,
            "a_path_moved_rekeys_the_links_index_entry_to_the_new_pair",
        )],
    ),
    (
        Fault::IgnoreOwnDial,
        &[
            (
                TABLE,
                "a_second_dial_to_a_peer_held_on_this_nodes_own_dial_moves_the_peer_onto_it",
            ),
            AGREES,
            IN_ORDER_LARGER,
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
        Fault::RedialInstallsAtSent,
        &[
            (TABLE, "a_redial_opens_a_leg_and_leaves_the_held_peer"),
            (
                REGRESS,
                "a_deployed_releases_late_second_dial_on_another_transport_leaves_one_session_larger_dialer",
            ),
        ],
    ),
    (
        Fault::LegHeardIgnored,
        &[
            (
                TABLE,
                "a_frame_under_a_sent_redial_leg_replaces_the_held_peer_for_redial",
            ),
            (
                TABLE,
                "a_redial_proven_at_the_legs_own_pair_replaces_the_peering",
            ),
            (
                TABLE,
                "a_redial_proven_at_a_third_transports_pair_not_of_the_held_link_replaces_the_peering",
            ),
        ],
    ),
    (
        Fault::RedialUngated,
        &[
            (
                GATES,
                "the_redial_memory_refuses_a_seen_ephemeral_and_a_full_memory_until_it_ages_out",
            ),
            (TABLE, "the_redial_memory_refuses_a_seen_ephemeral"),
            (
                GATES,
                "the_swap_stamps_the_dampener_only_for_a_heard_peering_and_clears_the_redial_memory",
            ),
        ],
    ),
    (
        Fault::RedialHeardFloored,
        &[(GATES, "a_redial_is_not_held_by_the_heard_floor")],
    ),
    (
        Fault::RedialSlotIgnored,
        &[
            (TABLE, "one_redial_leg_per_identity"),
            (
                TABLE,
                "a_second_redial_within_the_unheard_floor_of_the_first_is_held_back",
            ),
        ],
    ),
    (
        Fault::RedialEntryKeptAtPromote,
        &[(
            TABLE,
            "a_redials_leg_installed_at_its_send_is_no_longer_a_pending_redial",
        )],
    ),
    (
        Fault::RedialMemoryIgnored,
        &[(TABLE, "the_redial_memory_refuses_a_seen_ephemeral")],
    ),
    (
        Fault::RedialSkipsDampener,
        &[
            (TABLE, "a_redial_within_the_dampener_of_a_swap_is_refused"),
            (
                TABLE,
                "a_redial_within_the_dampener_of_an_adoption_is_refused",
            ),
            (
                TABLE,
                "a_redial_msg1_sent_again_after_an_adoption_is_refused_and_opens_no_redial",
            ),
        ],
    ),
    (
        Fault::RedialTearsDownAtMsg1,
        &[(
            TABLE,
            "a_redials_answer_leaves_the_held_peer_until_a_frame_proves_it",
        )],
    ),
    (
        Fault::RedialNeverExpires,
        &[(TABLE, "a_pending_redials_leg_is_reaped_at_its_deadline")],
    ),
    (
        Fault::AuthorizedRedialUnnoted,
        &[(
            TABLE,
            "a_redial_abandoned_after_its_acl_passed_is_noted_in_the_redial_memory",
        )],
    ),
    (
        Fault::RedialLegKept,
        &[
            (
                TABLE,
                "a_redial_leg_reaped_at_its_deadline_leaves_the_held_peer",
            ),
            (
                TABLE,
                "a_redial_leg_whose_peer_is_gone_installs_at_its_send_and_is_no_longer_a_redial",
            ),
        ],
    ),
    (
        Fault::RedialMemoryLapses,
        &[
            (
                GATES,
                "the_redial_memory_outlives_a_frame_and_the_lapse_of_the_rest_of_the_identitys_memory",
            ),
            (
                GATES,
                "the_redial_memory_outlives_the_first_frame_of_a_heard_session_and_a_move",
            ),
        ],
    ),
    (
        Fault::RedialCompared,
        &[(
            SHADOW,
            "a_deployed_releases_refusal_of_a_redial_is_named_and_a_redialing_nodes_is_a_difference",
        )],
    ),
    (
        Fault::ReopenedCompared,
        &[
            (
                SHADOW,
                "a_redial_over_a_connection_opened_again_is_compared_with_the_address_open",
            ),
            SIM_STREAM,
        ],
    ),
    (
        Fault::RedialUnnoted,
        &[(
            JOINT_RUNS,
            "a_rekey_msg1_answered_as_a_redial_off_the_link_is_refused_as_a_copy_when_it_comes_on_the_link",
        )],
    ),
    (
        Fault::AttributeBySetupOnly,
        &[
            (LINKS, "each_attribution_question_answers_as_the_node_does"),
            (TABLE, "a_msg1_from_a_proven_path_is_on_the_link"),
            AGREES,
            (
                JOINT_ORACLE,
                "attributed_reads_a_roamed_link_as_the_node_does",
            ),
        ],
    ),
    // Not in the joint world alone: the core's record of the peer follows the
    // bundle there, and each of the three joint pins of a msg1 counted by
    // that record needs a second break that moves it off the active path
    // (`HeardMovesPeer` or `SwitchLeavesPeer`; `CHARACTERISATION`). No joint
    // test, scripted start or sweep reds this switch alone.
    (
        Fault::AttributeByCurrent,
        &[
            (
                TABLE,
                "a_msg1_from_the_pair_the_core_holds_the_peer_at_with_no_path_there_is_off_the_link",
            ),
            (
                TABLE,
                "a_msg1_from_a_pair_whose_path_is_probing_is_off_the_link",
            ),
            (
                TABLE,
                "a_msg1_from_a_setup_pair_the_index_names_another_link_at_is_off_the_link",
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
            (
                TABLE,
                "a_one_path_roam_moves_the_cores_record_and_resets_once",
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
        Fault::SwitchLeavesPeer,
        &[
            (
                TABLE,
                "a_switch_moves_the_held_record_to_the_new_active_path_in_the_table",
            ),
            (
                JOINT_PINS,
                "a_switch_moves_the_cores_record_of_the_peer_to_the_new_active_path",
            ),
        ],
    ),
    (
        Fault::HeardMovesPeer,
        &[
            (
                TABLE,
                "a_frame_from_another_transport_moves_nothing_in_the_core",
            ),
            (
                JOINT_PINS,
                "a_frame_from_another_transport_leaves_the_cores_record_of_the_peer_at_the_active_path",
            ),
            SCRIPTED_ON,
        ],
    ),
    (
        Fault::FollowResets,
        &[
            (
                TABLE,
                "a_path_the_bundle_followed_moves_the_cores_record_and_resets_nothing",
            ),
            (
                JOINT_STARTS,
                "a_nat_rebound_of_the_active_path_moves_the_peer_with_it",
            ),
        ],
    ),
    (
        Fault::SwitchWritesLive,
        &[
            (
                TABLE,
                "a_switch_to_an_acknowledged_path_leaves_it_acknowledged",
            ),
            (
                JOINT_PINS,
                "a_switch_to_a_path_that_is_not_live_leaves_it_acknowledged_in_the_core",
            ),
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
    // Not in the joint world, nor the next switch: the joint party redials a
    // configured peer at every removal (`Output::Remove` in `joint/party.rs`),
    // so a removal with no `Retry` changes nothing the world does.
    (
        Fault::OrphanedNoRetry,
        &[(TABLE, "an_orphaned_bundles_peer_is_retried")],
    ),
    (
        Fault::RestartNoRetry,
        &[(
            TABLE,
            "a_restarted_or_replaced_peer_is_retried_in_each_of_the_three_ways",
        )],
    ),
    (
        Fault::RedialNoRetry,
        &[(TABLE, "a_peer_a_redials_swap_replaces_is_retried")],
    ),
    (
        Fault::UnsendableKeepsRedial,
        &[(
            TABLE,
            "a_redials_answer_given_up_as_unsendable_is_no_longer_a_pending_redial",
        )],
    ),
    (
        Fault::RedialKeptAtDisconnect,
        &[(
            TABLE,
            "an_operator_disconnect_abandons_the_peers_pending_redial",
        )],
    ),
    (
        Fault::RedialSwapHeard,
        &[(
            TABLE,
            "a_redials_swap_installs_the_peer_unheard_and_its_frames_heard_hears_it",
        )],
    ),
    (
        Fault::CrossedLegSwaps,
        &[
            (
                TABLE,
                "crossed_redials_settle_both_nodes_on_the_smaller_nodes_dial_at_the_legs_first_frames",
            ),
            (
                TABLE,
                "a_late_frame_under_a_crossed_leg_the_tie_break_retired_changes_nothing",
            ),
            (
                TABLE,
                "a_redial_answered_after_the_smaller_node_moved_onto_its_dial_leaves_the_pair_on_one_dial",
            ),
            (
                TABLE,
                "a_redial_answered_inside_the_crossing_window_is_retired_at_its_first_frame",
            ),
        ],
    ),
    (
        Fault::CrossingWindowOutlivesFrame,
        &[(
            TABLE,
            "a_redial_answered_after_a_frame_on_the_moved_onto_dial_is_swapped_in_at_its_first_frame",
        )],
    ),
    (
        Fault::CrossingWindowOutlivesTimeout,
        &[(
            TABLE,
            "a_redial_answered_a_handshake_timeout_after_the_move_is_swapped_in_at_its_first_frame",
        )],
    ),
    (
        Fault::AdoptedRedialCountsOwn,
        &[
            (
                TABLE,
                "crossed_redials_where_the_larger_adopts_its_leg_before_its_msg2_end_on_one_dial",
            ),
            (
                TABLE,
                "a_redial_answered_after_the_smaller_moved_where_the_larger_adopts_its_leg_before_its_msg2_ends_on_one_dial",
            ),
        ],
    ),
    (
        Fault::LateLegUncrossed,
        &[
            (
                TABLE,
                "a_redial_answered_after_the_smaller_node_moved_onto_its_dial_leaves_the_pair_on_one_dial",
            ),
            (
                TABLE,
                "a_redial_answered_inside_the_crossing_window_is_retired_at_its_first_frame",
            ),
        ],
    ),
    // In the joint world only against the model of the deployed release:
    // a joint node of this tree moves onto its own second dial at its msg2,
    // so its first frame under the redial's session reaches the responder
    // on the redial's transport.
    (
        Fault::RedialProofLeavesHeldLink,
        &[
            (
                TABLE,
                "a_redial_proven_at_the_held_pair_from_another_transport_moves_the_held_link_onto_its_session",
            ),
            (
                TABLE,
                "a_redial_proven_at_the_held_pair_from_another_transport_rebuilds_from_the_carry_with_the_legs_lease",
            ),
            (
                REGRESS,
                "a_deployed_releases_late_second_dial_on_another_transport_leaves_one_session_smaller_dialer",
            ),
        ],
    ),
    // Not in the joint world: no joint test, scripted start or sweep has a
    // peer prove a redial from a path the held link holds on the redial's
    // transport, and whether one can is not established.
    (
        Fault::RedialProofAnyTransport,
        &[(
            TABLE,
            "a_redial_proven_at_a_counting_path_of_the_held_link_on_the_legs_transport_replaces_the_peering",
        )],
    ),
    // Not in the joint world: no joint node is told of an operator
    // disconnect, and at the one orphaning, the start whose only path's
    // transport is removed, the one more pair this switch closes changes
    // nothing an oracle reads; no joint test, scripted start or sweep reds it.
    (
        Fault::RemovalClosesEveryPair,
        &[
            (
                TABLE,
                "an_orphaned_peer_closes_its_bundles_paths_and_not_a_setup_pair_released_to_keep",
            ),
            (
                TABLE,
                "an_operator_disconnect_closes_the_peers_pair_though_a_dial_uses_it",
            ),
        ],
    ),
    (
        Fault::CapLifted,
        &[(
            TABLE,
            "a_msg1_past_the_admission_cap_is_rejected_and_holds_no_leg",
        )],
    ),
    // Not in the joint world: every joint node's table takes
    // `Params::default`, whose max-peers cap is 128, and a joint world has at
    // most three nodes.
    (
        Fault::CapNotCounted,
        &[
            (
                TABLE,
                "a_msg1_from_a_new_identity_at_the_peer_cap_is_refused_before_any_answer",
            ),
            (
                TABLE,
                "a_replacement_for_an_identity_not_held_at_the_peer_cap_is_refused_before_any_answer",
            ),
            (
                TABLE,
                "an_answer_sent_to_a_new_identity_once_the_peer_cap_filled_is_not_installed",
            ),
            (
                TABLE,
                "a_dial_completing_to_a_new_identity_at_the_peer_cap_is_not_installed",
            ),
        ],
    ),
    (
        Fault::AnswerBeforeAdmit,
        &[
            (TABLE, "a_refused_msg1_asks_for_no_answer"),
            (TABLE, "a_rekey_msg1_asks_for_no_answer"),
            (
                TABLE,
                "a_restarts_teardown_comes_before_its_answer_is_asked_for",
            ),
            SCRIPTED_OFF,
            SCRIPTED_ON,
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
        &[
            (
                WORLD,
                "a_connection_oriented_reply_goes_on_the_arrival_connection",
            ),
            (
                ORACLE,
                "a_crossing_on_the_connection_oriented_transport_with_its_frames_lost_leaves_every_connection_in_use",
            ),
        ],
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
        &[(
            WORLD,
            "a_replacement_of_an_unheard_peering_over_another_connection_closes_the_replaced_links_connection",
        )],
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
    (Fault::RightLinkOff, &[RIGHT_LINK]),
    (Fault::RightLinkPairOnly, &[RIGHT_LINK]),
    (Fault::RightLinkNoDirection, &[RIGHT_LINK]),
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
    (
        Fault::PacketStamp,
        &[(
            REGRESS,
            "a_restart_dial_inside_the_heard_floor_is_judged_on_one_clock",
        )],
    ),
    (
        Fault::StoredByBytes,
        &[(
            TABLE,
            "a_msg1_from_the_address_of_an_unsent_answer_draws_that_answer_whatever_its_bytes",
        )],
    ),
    (
        Fault::StoredAnswersAny,
        &[(
            TABLE,
            "a_msg1_from_the_address_of_a_sent_answer_is_read_unless_it_is_the_msg1_answered",
        )],
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
    // Not in the joint world: every joint node's table takes
    // `Params::default`, whose multiplier is 2, so a wait doubled from the
    // first interval is the configured one. Only another multiplier shows the
    // defect, which the legs test sets.
    (
        Fault::BackoffDoubles,
        &[(
            LEGS,
            "a_configured_multiplier_spaces_the_resends_as_the_node_truncates_them",
        )],
    ),
    // Not in the joint world: every joint node's table takes
    // `Params::default`, whose resend interval is the node's fixed first
    // wait, a second. Only another interval shows the defect, which the legs
    // test sets.
    (
        Fault::FirstResendAtInterval,
        &[(
            LEGS,
            "a_dials_first_resend_comes_a_second_after_its_msg1_whatever_the_configured_interval",
        )],
    ),
    // Not in the joint world: no joint dial carries a resend cap of its own
    // (the joint party's `Dialed` has `resends: None`), as an mDNS-directed
    // dial does.
    (
        Fault::OriginIgnored,
        &[(LEGS, "an_mdns_directed_dial_stops_at_its_resend_cap")],
    ),
    // Not in the joint world: the joint party opens a dial's connection and
    // hands the core its dial in one step, and tells it of no `Connecting`, so
    // no dial waits on a connection still to be opened.
    (
        Fault::ConnectingUnlinked,
        &[
            (
                TABLE,
                "a_connecting_dials_pair_is_in_use_before_its_msg1_and_a_failed_connect_retires_it_with_no_lease",
            ),
            (
                TABLE,
                "a_dial_after_its_connect_starts_its_leg_on_the_link_the_connect_opened",
            ),
        ],
    ),
    // Not in the joint world: the joint party hands the core its dial in one
    // step and tells it of no `Connecting`, so no dial is given up while it
    // connects.
    (
        Fault::ConnectingCloses,
        &[(TABLE, "a_dial_given_up_while_connecting_closes_nothing")],
    ),
    // Not in the joint world: the joint party's sends do not fail.
    (
        Fault::UnsendableCloses,
        &[(
            TABLE,
            "an_answer_whose_msg2_cannot_be_sent_is_given_up_and_closes_nothing",
        )],
    ),
    // Not in the joint world by this row: the joint party's closes are
    // checked by its own oracles.
    (
        Fault::TeardownIgnoresKeep,
        &[
            (
                TABLE,
                "a_teardown_of_a_capable_link_closes_each_path_but_the_one_the_peer_sends_on",
            ),
            (
                TABLE,
                "a_link_not_known_capable_keeps_its_other_paths_at_an_operator_disconnect",
            ),
            (
                TABLE,
                "a_link_not_known_capable_keeps_its_other_paths_at_a_move",
            ),
        ],
    ),
    // Not in the joint world: the joint party keeps no operator pin of a
    // path (it carries out `Output::Swapped` as nothing).
    (
        Fault::UnpinOwnOnly,
        &[(
            TABLE,
            "a_move_onto_a_later_dial_to_a_peer_held_on_the_link_it_dialled_ends_the_pin",
        )],
    ),
    // The late second dial answered in the other order: the accepted
    // recovery, one end's link-dead timer ending the split and the redial
    // settling one session within a heal. The timer's own tests: a silent
    // peer removed at the timeout, on a link of one path and of several.
    // And the exemption of the model's missing timer, which reds at its
    // precondition: with no timer the joint node never removes the model,
    // so the stale peering that the exemption is for is never left.
    (
        Fault::TimerNever,
        &[
            (
                REGRESS,
                "after_a_late_second_dial_answered_in_the_other_order_the_link_dead_timer_and_the_redial_settle_one_session_within_a_heal_larger_dialer",
            ),
            (
                REGRESS,
                "after_a_late_second_dial_answered_in_the_other_order_the_link_dead_timer_and_the_redial_settle_one_session_within_a_heal_smaller_dialer",
            ),
            (
                JOINT_PARTY,
                "a_peer_silent_for_the_link_dead_timeout_is_removed_then_and_redialled",
            ),
            (
                JOINT_PARTY,
                "a_peer_silent_past_the_link_dead_timeout_on_a_link_of_several_paths_is_removed_and_the_pair_heals",
            ),
            (
                JOINT_EXPLORE,
                "each_breach_the_pins_hold_is_exempted_by_its_own_cause_and_a_settled_pair_by_none",
            ),
        ],
    ),
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

/// Why a test whose guard needs no switch of its own is characterisation.
const HAND: &str =
    "its break is a scratch edit with no switch of its own, run by hand and logged with the commit";

/// Why the capable peer's attribution pin, whose shape needs the core to
/// keep the peer at a path its bundle switched away from, is
/// characterisation.
const SWITCH_BREAKS: &str = "its shape needs two breaks at once: the core keeping the peer at the path switched away from (SwitchLeavesPeer) and attribution reading where the core holds the peer (AttributeByCurrent); either alone leaves the msg1 off the link, so no one switch reds it, and both together red it, run by hand and logged with the commit";

/// Why an attribution pin whose shape needs the core to follow a frame
/// is characterisation.
const TWO_BREAKS: &str = "its shape needs two breaks at once: the core following a frame to its source (HeardMovesPeer) and attribution reading where the core holds the peer (AttributeByCurrent); either alone leaves the msg1 off the link, so no one switch reds it, and both together red it, run by hand and logged with the commit";

/// Why a test whose break showed only while the core followed every
/// frame is characterisation.
const FRAME_BREAKS: &str = "its break shows only together with HeardMovesPeer, the core following a frame to its source: with the core's record of where the peer is following the bundle, the other break alone changes nothing the test sees, so no one switch reds it, and the two together red it, run by hand and logged with the commit";

/// Why a test of the join function, whose break no switch makes, is
/// characterisation; its doc comment names its break.
const JOIN_HAND: &str = "its break is a scratch edit of the join function where no switch sits; run by hand and logged with the commit";

/// Why a guard of the unpin a move reports is characterisation.
const UNPIN_HAND: &str = "a guard of the pin a move ends where `UnpinOwnOnly` changes nothing, the link left being this node's dial or the dial made before the peer was held; its breaks, `unpin` true at every move and `unpin` without the link left being this node's dial, are scratch edits run by hand and logged with the commit";

/// Why a test of the hold a flow outside settle makes, which no IK rule
/// calls and no switch sits in, is characterisation.
const HOLD_HAND: &str = "a test of `Ops::hold_answer`, which only a flow outside settle calls; its breaks, the peer installed on the answer's link and the answer's link left unretired, are scratch edits run by hand and logged with the commit";

/// Why a test of the move a flow outside settle makes, which no IK rule
/// calls and no switch sits in, is characterisation.
const MOVE_HAND: &str = "a test of `Ops::move_answer`, which only a flow outside settle calls; its breaks, the peer left on the link it held and that link left unretired, are scratch edits run by hand and logged with the commit";

/// Why the test that a move keeps the peering's liveness is
/// characterisation.
const MOVE_LIVE_HAND: &str = "a test of `Ops::move_answer`, which only a flow outside settle calls; its break, the peer seated as a fresh install with no liveness carried, is the scratch revert of the carry, run by hand and logged with the commit";

/// The tests that characterise behaviour no switch breaks, each with why.
pub const CHARACTERISATION: &[(&str, &str)] = &[
    (
        "moving_a_peer_onto_an_answers_link_keeps_whether_it_was_heard_its_install_instant_and_its_last_frame",
        MOVE_LIVE_HAND,
    ),
    (
        "moving_a_peer_onto_an_answers_link_installs_the_answers_lease_there_and_retires_the_link_it_held",
        MOVE_HAND,
    ),
    (
        "moving_a_peer_not_held_frees_the_answers_lease_and_retires_its_link",
        MOVE_HAND,
    ),
    (
        "holding_a_peer_on_its_link_with_an_answers_session_installs_the_answers_lease_there_and_retires_the_answers_link",
        HOLD_HAND,
    ),
    (
        "holding_a_peer_on_its_link_with_an_answers_session_rebuilds_from_the_carry_as_responder",
        HOLD_HAND,
    ),
    (
        "holding_a_peer_not_held_frees_the_answers_lease_and_retires_its_link",
        HOLD_HAND,
    ),
    (
        "holding_a_peer_on_a_link_known_capable_leaves_its_record_not_capable_as_the_renewed_bundle_is",
        HOLD_HAND,
    ),
    (
        "an_adopted_answer_on_a_link_the_peer_set_up_or_for_no_held_peer_changes_nothing",
        HAND,
    ),
    (
        "a_msg1_from_a_capable_peers_setup_pair_with_no_path_is_off_the_link",
        SWITCH_BREAKS,
    ),
    (
        "a_msg1_from_the_pair_a_frame_from_another_transport_came_from_is_off_the_link",
        TWO_BREAKS,
    ),
    (
        "a_msg1_from_the_pair_a_frame_moved_the_cores_record_to_whose_path_is_probing_is_off_the_link",
        TWO_BREAKS,
    ),
    (
        "a_crossing_over_two_transports_settles_on_one_session",
        FRAME_BREAKS,
    ),
    (
        "after_a_frame_from_another_transport_sends_stay_on_the_active_path",
        FRAME_BREAKS,
    ),
    (
        "a_move_onto_a_dial_made_before_the_peer_was_held_keeps_the_pin",
        UNPIN_HAND,
    ),
    (
        "a_second_dial_made_before_the_peer_was_held_and_answered_after_a_crossing_ends_the_pin",
        UNPIN_HAND,
    ),
    (
        "an_abandoned_answer_frees_its_link_and_takes_no_lease",
        HAND,
    ),
    ("a_held_identity_at_the_peer_cap_restarts_as_before", HAND),
    ("a_zero_peer_cap_admits_any_number", HAND),
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
        "against_a_model_of_master_a_forward_wall_step_does_not_let_a_msg1_replace_a_peering_heard_just_now",
        HAND,
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
        "the_stub_profile_selects_the_rows_the_link_profile_does_but_those_of_a_third_message",
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
        "after_a_dial_on_the_peers_aged_link_the_peer_answers_the_larger_nodes_rekey",
        "a known defect, red today and ignored; the known-defect lane checks that it still fails at its defect line",
    ),
    (
        "a_proven_path_whose_connection_failed_is_not_counted_in_use_without_a_connection",
        "a known defect, red today and ignored; the known-defect lane checks that it still fails at its defect line",
    ),
    (
        "the_named_start_numbers_are_the_settlement_tests_starts",
        "a list held equal to the starts the settlement tests define, which no switch of the node or the core changes; its break, a number added to the list, is a scratch edit run by hand and logged with the commit",
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
/// neither list holds. A row's switch may be of any list's type: only its
/// tests are read.
pub fn uncovered<'a, F>(
    tests: &'a [String],
    rows: &[(F, &'static [Test])],
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
    use super::{REKEY, ROWS, Test};

    /// The rekey machine's variable, which a child of a [`REKEY`] row takes
    /// (`../../rekey/faults.rs`).
    const REKEY_VAR: &str = "FIPS_REKEY_FAULTS";

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
        let compiled = crate::testutil::compiled_tests();
        let built = |prefix: &str, test: &str| compiled.contains(&format!("{prefix}{test}"));
        let mut named: Vec<String> = Vec::new();
        let mut jobs = Vec::new();
        let mut wrong = Vec::new();
        for (var, fault, tests) in &tables {
            if tests.is_empty() {
                wrong.push(format!("{fault} names no test"));
            }
            for (prefix, test) in *tests {
                let path = format!("{prefix}{test}");
                if !built(prefix, test) {
                    wrong.push(format!(
                        "{fault} names {path}, which this build does not compile"
                    ));
                    continue;
                }
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
            "{} rows and {} rekey rows, {} tests, {} s",
            ROWS.len(),
            REKEY.len(),
            named.len(),
            started.elapsed().as_secs()
        );
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }
}
