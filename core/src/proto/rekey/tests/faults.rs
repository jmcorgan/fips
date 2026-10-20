//! The meta-test of the guard switches in `faults.rs`.
//!
//! For each row, every test it names runs in a child process of this test
//! binary with the row's switches on, and must fail: a guard whose removal
//! turns nothing red is itself a failure. Every named test also runs once
//! with no switch and must pass, so a row cannot be satisfied by a test
//! that fails anyway. A child runs one test by its exact path, so it never
//! runs this meta-test again.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::super::faults::{Fault, VAR};

/// The test-path prefix of each test file.
const FSP: &str = "proto::rekey::tests::fsp::";
const FMP: &str = "proto::rekey::tests::fmp::";
const NEXT: &str = "proto::rekey::tests::next::";
const SIM: &str = "proto::rekey::tests::sim::";
const EXPLORE: &str = "proto::rekey::tests::explore::";
const REGRESS: &str = "proto::rekey::tests::regress::";
const LINK: &str = "proto::rekey::tests::legacy::fmp::";
const SESSION: &str = "proto::rekey::tests::legacy::fsp::";

/// The interop traces against the deployed releases' models.
const LINK_TRACES: (&str, &str) = (LINK, "link_traces_hold_against_every_deployed_release");
/// See [`LINK_TRACES`].
const REKEY_TRACES: (&str, &str) = (
    SESSION,
    "session_rekey_traces_hold_against_every_deployed_release",
);
/// See [`LINK_TRACES`].
const FIRST_TRACES: (&str, &str) = (
    SESSION,
    "session_first_handshake_traces_hold_against_every_deployed_release",
);
/// The seeded lossy runs against the deployed releases and between new
/// nodes on the production profiles.
const LOSSY_LINKS: (&str, &str) = (
    LINK,
    "lossy_link_runs_converge_against_every_deployed_release",
);
/// See [`LOSSY_LINKS`].
const LOSSY_SESSIONS: (&str, &str) = (
    SESSION,
    "lossy_session_runs_converge_against_every_deployed_release",
);

/// The bounded explorer against the deployed releases' models and between
/// new nodes on the production profiles.
const LEGACY_EXPLORE: (&str, &str) = (
    "proto::rekey::tests::legacy::explore::",
    "every_explored_interleaving_against_each_deployed_release_heals",
);

/// One row: the switches turned on together, and the tests (prefix, name)
/// that must each fail with them on.
type Row = (&'static [Fault], &'static [(&'static str, &'static str)]);

/// Every switch and the tests it must turn red.
const ROWS: &[Row] = &[
    (
        &[Fault::GarbageAdopts],
        &[(
            EXPLORE,
            "every_explored_interleaving_keeps_the_invariants_and_heals",
        )],
    ),
    (
        &[Fault::BondAlways],
        &[
            (FSP, "completion_with_another_static_installs_nothing"),
            (NEXT, "impostor_reply_never_reports_a_restart"),
        ],
    ),
    (
        &[Fault::BondAfterEpoch],
        &[(NEXT, "impostor_reply_never_reports_a_restart")],
    ),
    (
        &[Fault::EvidencePrevious],
        &[(
            FSP,
            "drained_epoch_frame_during_a_confirming_repair_marks_the_peer_as_staying",
        )],
    ),
    (
        &[Fault::StayedFromPrevious],
        &[
            (
                FSP,
                "current_epoch_frame_after_the_last_probe_marks_the_peer_as_staying",
            ),
            (
                REGRESS,
                "scripted_schedules_lose_no_frame_beyond_their_bounds_and_converge",
            ),
            REKEY_TRACES,
        ],
    ),
    (
        &[Fault::SealPending],
        &[
            (
                FSP,
                "no_seal_call_produces_a_ciphertext_under_a_pending_epoch",
            ),
            (
                REGRESS,
                "scripted_schedules_lose_no_frame_beyond_their_bounds_and_converge",
            ),
            LEGACY_EXPLORE,
        ],
    ),
    (
        &[Fault::ProbeMoves],
        &[
            (FSP, "responders_only_prompt_lost_loses_no_initiator_frame"),
            (
                REGRESS,
                "scripted_schedules_lose_no_frame_beyond_their_bounds_and_converge",
            ),
        ],
    ),
    (
        &[Fault::NoProbeAnswer],
        &[(FSP, "responders_only_prompt_lost_loses_no_initiator_frame")],
    ),
    (
        &[Fault::RevertRetires],
        &[
            (
                FSP,
                "a_previous_epoch_frame_after_an_assumed_cutover_returns_the_epoch_to_pending",
            ),
            (
                REGRESS,
                "scripted_schedules_lose_no_frame_beyond_their_bounds_and_converge",
            ),
        ],
    ),
    (
        &[Fault::NoOpeningTeardown],
        &[(FSP, "inbound_opening_with_no_candidate_left_is_torn_down")],
    ),
    (
        &[Fault::RefusalUnrecorded],
        &[
            (FMP, "refused_msg1_copy_never_arms_a_pending"),
            (
                SIM,
                "faulty_runs_hold_every_oracle_and_converge_once_healed",
            ),
        ],
    ),
    (
        &[Fault::LargerKeepsOwn],
        &[
            (
                FMP,
                "larger_node_with_an_attempt_abandons_it_and_answers_a_fresh_eligible_msg1",
            ),
            LINK_TRACES,
            LOSSY_LINKS,
        ],
    ),
    (
        &[Fault::KeepCandidatesAtCutover],
        &[(
            FSP,
            "stale_candidate_never_completes_after_a_cutover_on_evidence",
        )],
    ),
    (
        &[Fault::AcceptDropsNewer],
        &[(
            FSP,
            "late_msg3_after_a_newer_setup_keeps_the_newer_candidate",
        )],
    ),
    (
        &[Fault::LargerDropsAtAssumed],
        &[
            (
                FSP,
                "assumed_cutover_at_the_larger_node_keeps_an_acknowledged_setup",
            ),
            REKEY_TRACES,
        ],
    ),
    (
        &[Fault::StartWhileFin],
        &[(
            FSP,
            "fsp_ack_from_a_restarted_peer_cuts_over_at_msg3_and_retains_it",
        )],
    ),
    (
        &[Fault::RevertWithoutAbandon],
        &[(
            FSP,
            "assumed_epoch_frame_during_a_repair_reverts_and_abandons_the_repair",
        )],
    ),
    (
        &[Fault::F6bPendIReverts],
        &[(
            FSP,
            "drained_epoch_frame_during_a_confirming_repair_marks_the_peer_as_staying",
        )],
    ),
    (
        &[Fault::F6bPendINotStaying],
        &[(
            FSP,
            "drained_epoch_frame_during_a_confirming_repair_marks_the_peer_as_staying",
        )],
    ),
    (
        &[Fault::RespondRetiresDrain],
        &[(
            FMP,
            "residual_msg1_during_an_unevidenced_drain_retires_nothing",
        )],
    ),
    (
        &[Fault::CloseSkipsRecord],
        &[(
            FMP,
            "cross_connection_move_keeps_the_link_and_session_anchors",
        )],
    ),
    (
        &[Fault::F4KeepsCandidates],
        &[(
            FSP,
            "first_handshake_candidate_is_dropped_once_the_peer_is_heard_under_cur",
        )],
    ),
    (
        &[Fault::F4DropsAll],
        &[
            (
                FSP,
                "deployed_rekey_acknowledged_before_the_first_handshake_is_confirmed_completes_at_the_larger_node",
            ),
            FIRST_TRACES,
        ],
    ),
    (
        &[Fault::F4KeepsAtBoth, Fault::S10Fin],
        &[(
            FSP,
            "late_first_handshake_setup_copy_never_moves_the_smaller_node_off_its_confirmed_epoch",
        )],
    ),
    (
        &[Fault::S10Fin],
        &[
            (
                FSP,
                "fsp_ack_from_a_restarted_peer_cuts_over_at_msg3_and_retains_it",
            ),
            FIRST_TRACES,
        ],
    ),
    (
        &[Fault::S10PendI],
        &[
            (FSP, "every_xk_setup_cell_takes_its_rows_action"),
            REKEY_TRACES,
        ],
    ),
    (
        &[Fault::RestartDropsCandidates],
        &[(
            FSP,
            "restart_crossing_with_a_smaller_restarted_peer_converges_on_its_epoch",
        )],
    ),
    (
        &[Fault::SkipStaleIncarnation],
        &[(
            FSP,
            "restart_crossing_with_a_smaller_restarted_peer_converges_on_its_epoch",
        )],
    ),
    (
        &[Fault::KarnOff],
        &[(FSP, "hs_rtt_ignores_a_reply_to_a_resent_message")],
    ),
    (
        &[Fault::NoGraceCap],
        &[(FSP, "probe_grace_never_outlasts_the_confirmation_deadline")],
    ),
    (
        &[Fault::NoKeptBackoff],
        &[
            (FSP, "hs_rtt_ignores_a_reply_to_a_resent_message"),
            REKEY_TRACES,
        ],
    ),
    (
        &[Fault::LateProbe],
        &[(
            FSP,
            "late_poll_never_sends_a_probe_it_cannot_judge_before_the_confirmation_deadline",
        )],
    ),
    (
        &[Fault::ShortenedUnevidenced],
        &[
            (
                FMP,
                "ik_rekey_completes_through_the_attempt_the_reply_the_poll_and_the_adoption",
            ),
            (
                SIM,
                "clean_runs_rotate_on_cadence_with_no_reject_abandon_revert_or_assumed_cutover",
            ),
        ],
    ),
    (
        &[Fault::FinOutlivesLadder],
        &[(NEXT, "retained_msg3_never_outlives_its_ladder")],
    ),
    (
        &[Fault::NoKeepalive],
        &[(
            FSP,
            "xk_rekey_completes_with_probes_and_the_responders_prompt",
        )],
    ),
    (
        &[Fault::KeepaliveLate],
        &[
            (
                "proto::rekey::ladder::tests::",
                "probe_ladder_fills_every_gap_longer_than_the_keepalive_gap_before_its_deadline",
            ),
            REKEY_TRACES,
        ],
    ),
    (
        &[Fault::NoHoldBack],
        &[
            (
                FSP,
                "the_smaller_node_refuses_a_crossing_setup_while_its_attempt_is_young_and_the_larger_holds_back_early_resends",
            ),
            FIRST_TRACES,
        ],
    ),
    (
        &[Fault::RefusalEndsTrial],
        &[(
            FSP,
            "previous_epoch_frame_with_a_counter_inside_the_current_window_is_delivered",
        )],
    ),
    (
        &[Fault::ConfirmWithoutCheck],
        &[
            (
                "proto::rekey::params::tests::",
                "derived_values_match_their_derivations_at_the_defaults",
            ),
            REKEY_TRACES,
        ],
    ),
    (
        &[Fault::BaseAtCreation],
        &[(
            FMP,
            "ik_rekey_completes_through_the_attempt_the_reply_the_poll_and_the_adoption",
        )],
    ),
    (
        &[Fault::NoLinkFloorCheck],
        &[(
            "proto::rekey::params::tests::",
            "params_reject_after_secs_below_jitter_plus_min_link_age",
        )],
    ),
    (
        &[Fault::EvictEstablished],
        &[
            (FSP, "every_xk_setup_cell_takes_its_rows_action"),
            REKEY_TRACES,
        ],
    ),
    (
        &[Fault::CandidateVeto],
        &[
            (FSP, "forged_setups_never_defer_or_cancel_own_rotation"),
            (
                SIM,
                "lossless_runs_under_forgery_hold_every_oracle_and_keep_rotating",
            ),
        ],
    ),
    (
        &[Fault::ResolveSwapped],
        &[
            (
                "proto::rekey::resolve::tests::",
                "both_ends_name_the_same_survivor_for_every_pair",
            ),
            (FSP, "every_xk_final_cell_takes_its_rows_action"),
            (
                NEXT,
                "completed_own_attempts_meet_a_completion_by_the_tie_break",
            ),
            (
                SIM,
                "crossing_runs_converge_with_only_the_tie_break_outcomes",
            ),
        ],
    ),
    (
        &[Fault::RetireSkipsRevoke],
        &[
            (FMP, "leases_outstanding_equal_leases_held"),
            (
                SIM,
                "faulty_runs_hold_every_oracle_and_converge_once_healed",
            ),
        ],
    ),
    (
        &[Fault::DelegatedAtOffer],
        &[
            (
                FMP,
                "reoffered_receive_copy_refuses_counters_the_lost_worker_saw",
            ),
            (
                SIM,
                "faulty_runs_hold_every_oracle_and_converge_once_healed",
            ),
        ],
    ),
    (
        &[Fault::ReofferNoFloor],
        &[(
            FMP,
            "reoffered_receive_copy_refuses_counters_the_lost_worker_saw",
        )],
    ),
    (
        &[Fault::DrainExtends],
        &[(FMP, "peer_on_previous_epoch_is_not_reaped_while_drain_held")],
    ),
    (
        &[Fault::CutoverKeepsDrain],
        &[
            (FMP, "cutover_over_an_open_drain_releases_its_index"),
            (
                REGRESS,
                "scripted_schedules_lose_no_frame_beyond_their_bounds_and_converge",
            ),
        ],
    ),
    (
        &[Fault::RestartAtCompletion],
        &[(
            FMP,
            "rekey_msg2_from_a_restarted_peer_retires_the_old_epoch_and_reports_the_restart_after_the_install",
        )],
    ),
    (
        &[Fault::CutoverAtProof],
        &[
            (
                FSP,
                "xk_rekey_completes_with_probes_and_the_responders_prompt",
            ),
            (
                REGRESS,
                "scripted_schedules_lose_no_frame_beyond_their_bounds_and_converge",
            ),
            REKEY_TRACES,
            LEGACY_EXPLORE,
        ],
    ),
    (
        &[Fault::KFromOwn],
        &[
            (
                FMP,
                "initiator_epoch_takes_the_inverse_of_the_peers_observed_k_not_of_its_own",
            ),
            LINK_TRACES,
        ],
    ),
    (
        &[Fault::DeadlinePerRung],
        &[
            (
                FMP,
                "unanswered_attempt_is_abandoned_and_retried_after_backoff",
            ),
            (
                SIM,
                "faulty_runs_hold_every_oracle_and_converge_once_healed",
            ),
            LOSSY_SESSIONS,
        ],
    ),
    (
        &[Fault::NoZeroMessagesCheck],
        &[(
            "proto::rekey::params::tests::",
            "params_reject_zero_after_messages",
        )],
    ),
    (
        &[Fault::DueByKind],
        &[(FSP, "late_poll_processes_stored_deadlines_in_order")],
    ),
    (
        &[Fault::AnchorAtDeadline],
        &[(FSP, "late_poll_processes_stored_deadlines_in_order")],
    ),
    (
        &[Fault::Rebox],
        &[(
            FSP,
            "session_address_is_stable_across_cutover_demotion_and_revert",
        )],
    ),
    (
        &[Fault::LinkAgeReset],
        &[(FMP, "link_age_anchor_survives_cutover")],
    ),
    (
        &[Fault::ResponderTimerCutover],
        &[
            (FMP, "responder_never_cuts_over_on_a_timer"),
            (
                REGRESS,
                "scripted_schedules_lose_no_frame_beyond_their_bounds_and_converge",
            ),
            LINK_TRACES,
        ],
    ),
    (
        &[Fault::FreshAck],
        &[(FSP, "every_xk_setup_cell_takes_its_rows_action")],
    ),
    (
        &[Fault::UnbindTransportNow],
        &[(
            FMP,
            "unbind_uses_the_transport_recorded_at_bind_across_a_rebind",
        )],
    ),
    (
        &[Fault::ForgedTeardown],
        &[(FSP, "forged_frames_change_nothing")],
    ),
    (
        &[Fault::ReplayAsUnauthenticated],
        &[
            (FMP, "every_ik_frame_cell_takes_its_rows_action"),
            (
                FSP,
                "previous_epoch_frame_with_a_counter_inside_the_current_window_is_delivered",
            ),
        ],
    ),
    (
        &[Fault::ReplyOnArrival],
        &[(FMP, "every_ik_msg1_cell_takes_its_rows_action")],
    ),
    (
        &[Fault::RespondRefreshes],
        &[
            (
                FMP,
                "residual_msg1_during_an_unevidenced_drain_retires_nothing",
            ),
            (
                SIM,
                "faulty_runs_hold_every_oracle_and_converge_once_healed",
            ),
        ],
    ),
    (
        &[Fault::FailedFinalRetires],
        &[(FSP, "completion_with_another_static_installs_nothing")],
    ),
    (
        &[Fault::AbandonClearsTrigger],
        &[(
            FMP,
            "unanswered_attempt_is_abandoned_and_retried_after_backoff",
        )],
    ),
    (
        &[Fault::DrainReapedAtWindow],
        &[(FMP, "peer_on_previous_epoch_is_not_reaped_while_drain_held")],
    ),
    (
        &[Fault::RecordUnbounded],
        &[(
            "proto::rekey::record::tests::",
            "replay_record_never_exceeds_its_bound",
        )],
    ),
    (
        &[Fault::GlobalJitter],
        &[(SIM, "simulator_replay_from_a_seed_is_byte_identical")],
    ),
];

/// Run the test at `path` alone in a child process with `faults` on; true
/// when it passed, with what the child printed.
fn child(path: &str, faults: &str) -> (bool, String) {
    let exe = std::env::current_exe().expect("the test binary's path");
    let out = std::process::Command::new(exe)
        .args([path, "--exact", "--test-threads=1"])
        .env(VAR, faults)
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
    let chunks: Vec<Vec<T>> = {
        let mut c: Vec<Vec<T>> = (0..lanes).map(|_| Vec::new()).collect();
        for (i, j) in jobs.into_iter().enumerate() {
            c[i % lanes].push(j);
        }
        c
    };
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
    let mut named = Vec::new();
    for f in Fault::ALL {
        assert!(
            ROWS.iter().any(|(fs, _)| fs.contains(f)),
            "the switch {f:?} has no row, so nothing shows its guard can fail"
        );
    }
    let mut jobs = Vec::new();
    for (faults, tests) in ROWS {
        let names: Vec<String> = faults.iter().map(|f| format!("{f:?}")).collect();
        for (prefix, test) in *tests {
            let path = format!("{prefix}{test}");
            if !named.contains(&path) {
                named.push(path.clone());
            }
            jobs.push((names.join(","), path));
        }
    }
    for p in &named {
        jobs.push((String::new(), p.clone()));
    }
    let results = parallel(jobs, |(faults, path)| {
        let (passed, text) = child(path, faults);
        (faults.clone(), path.clone(), passed, text)
    });
    let mut wrong = Vec::new();
    for (faults, path, passed, text) in results {
        let ran = text.contains("running 1 test");
        if faults.is_empty() {
            if !passed || !ran {
                wrong.push(format!("{path} does not pass with no switch:\n{text}"));
            }
        } else if passed || !ran || !text.contains("1 failed") {
            wrong.push(format!("{path} stays green with {faults} on"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
