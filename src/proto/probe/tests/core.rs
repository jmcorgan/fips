//! Stage-machine tests. Each drives `Probe::step` with synthetic `now_ms` and
//! hand-built `Observation`s and asserts on the returned action list.

use crate::NodeAddr;
use crate::proto::probe::core::{Budgets, Observation, Probe, ProbeAction};
use crate::proto::probe::state::{
    FailKind, LeftIntact, LookupOutcomeKind, NextHopFacts, Overall, PathFacts, Preflight,
    ResolveSource, RttCounters, StageVerdict,
};
use crate::proto::routing::RouteClass;

const T0: u64 = 1_000_000;

fn budgets() -> Budgets {
    // The default ladder [1,2,4,8] at a 1s tick.
    Budgets::derive(1_000, &[1, 2, 4, 8])
}

fn addr(v: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = v;
    NodeAddr::from_bytes(bytes)
}

/// A path that resolves cleanly, so the path stage never fails and never
/// masks what a test is actually asserting on.
fn good_path() -> PathFacts {
    PathFacts {
        our_coords: vec![addr(2), addr(1)],
        their_coords: vec![addr(3), addr(1)],
        our_depth: 1,
        their_depth: 1,
        same_root: true,
        lca: Some(addr(1)),
        lca_depth: Some(0),
        tree_hops_up: Some(1),
        tree_hops_down: Some(1),
        tree_distance: Some(2),
    }
}

fn good_hop() -> NextHopFacts {
    NextHopFacts {
        node_addr: addr(3),
        class: RouteClass::DirectPeer,
        direct_peer: true,
        leaves_tree_walk: false,
    }
}

/// An observation with everything healthy and nothing happening.
fn obs(now_ms: u64) -> Observation {
    Observation {
        now_ms,
        coords_cached: true,
        lookup_pending: false,
        lookup_outcome: None,
        lookup_fanout: None,
        path: Some(good_path()),
        next_hop: Some(good_hop()),
        no_hop_reason: None,
        session_present: false,
        session_established: false,
        session_is_ours: false,
        session_error: None,
        target_is_direct_peer: false,
        counters: RttCounters::default(),
        last_rtt_ms: None,
        srtt_ms: None,
        path_mtu: None,
    }
}

fn preflight() -> Preflight {
    Preflight {
        session_present: false,
        coords_cached: true,
        identity_cached: true,
        target_claimed: false,
    }
}

/// Drive a probe from a fresh start to an established, owned session, and
/// return it sitting at the top of the rtt stage.
fn probe_at_rtt() -> (Probe, u64) {
    let mut probe = Probe::new(T0, budgets(), preflight());
    // Resolve (skipped, cached) then path, then session opens.
    let actions = probe.step(&obs(T0));
    assert_eq!(actions, vec![ProbeAction::OpenSession]);
    let mut o = obs(T0 + 1_000);
    o.session_present = true;
    o.session_established = true;
    o.session_is_ours = true;
    let actions = probe.step(&o);
    assert_eq!(actions, vec![ProbeAction::SendWarmup]);
    (probe, T0 + 1_000)
}

// ---- bloom and discovery ------------------------------------------------------------

#[test]
fn both_lookup_stages_are_skipped_when_coords_are_cached() {
    let mut probe = Probe::new(T0, budgets(), preflight());
    let actions = probe.step(&obs(T0));
    assert!(!actions.contains(&ProbeAction::InitiateLookup));
    let snap = probe.snapshot();
    // Neither stage ran, and both name the same reason: the second must not
    // invent a reason of its own for work the first already declined.
    assert_eq!(snap.bloom.verdict, StageVerdict::Skipped);
    assert_eq!(snap.bloom.reason, Some(FailKind::Cached));
    assert_eq!(snap.discovery.verdict, StageVerdict::Skipped);
    assert_eq!(snap.discovery.reason, Some(FailKind::Cached));
    assert_eq!(snap.resolve_source, Some(ResolveSource::Cache));
}

#[test]
fn both_lookup_stages_are_skipped_for_a_direct_peer() {
    let mut pre = preflight();
    pre.coords_cached = false;
    let mut probe = Probe::new(T0, budgets(), pre);
    let mut o = obs(T0);
    o.coords_cached = false;
    o.target_is_direct_peer = true;
    let actions = probe.step(&o);
    assert!(!actions.contains(&ProbeAction::InitiateLookup));
    let snap = probe.snapshot();
    assert_eq!(snap.bloom.verdict, StageVerdict::Skipped);
    assert_eq!(snap.bloom.reason, Some(FailKind::DirectPeer));
    assert_eq!(snap.discovery.reason, Some(FailKind::DirectPeer));
    // The probe proceeds rather than declaring a neighbour unreachable.
    assert_eq!(actions, vec![ProbeAction::OpenSession]);
}

#[test]
fn discovery_times_out_at_its_own_budget_measured_from_the_request() {
    let b = budgets();
    let mut pre = preflight();
    pre.coords_cached = false;
    let mut probe = Probe::new(T0, b, pre);

    let mut o = obs(T0);
    o.coords_cached = false;
    assert_eq!(probe.step(&o), vec![ProbeAction::InitiateLookup]);

    // The gate's answer arrives on the next observation and closes the bloom
    // stage; the discovery budget runs from there, not from the probe's start.
    let sent_ms = T0 + 1_000;
    let mut o = obs(sent_ms);
    o.coords_cached = false;
    o.lookup_pending = true;
    o.lookup_outcome = Some(LookupOutcomeKind::Sent);
    assert!(probe.step(&o).is_empty());
    assert_eq!(probe.snapshot().bloom.verdict, StageVerdict::Ok);
    assert_eq!(probe.snapshot().discovery.verdict, StageVerdict::Running);

    // One millisecond short of the budget the machine must still be running.
    let mut o = obs(sent_ms + b.discovery_ms - 1);
    o.coords_cached = false;
    o.lookup_pending = true;
    assert!(probe.step(&o).is_empty());
    assert_eq!(probe.snapshot().discovery.verdict, StageVerdict::Running);

    let mut o = obs(sent_ms + b.discovery_ms);
    o.coords_cached = false;
    o.lookup_pending = true;
    assert_eq!(probe.step(&o), vec![ProbeAction::Finish]);
    let snap = probe.snapshot();
    assert_eq!(snap.discovery.verdict, StageVerdict::Failed);
    assert_eq!(snap.discovery.reason, Some(FailKind::BloomUnconfirmed));
    assert_eq!(
        snap.bloom.verdict,
        StageVerdict::Ok,
        "the request did go out"
    );
}

#[test]
fn discovery_fails_early_when_the_pending_entry_clears() {
    let b = budgets();
    let mut pre = preflight();
    pre.coords_cached = false;
    let mut probe = Probe::new(T0, b, pre);

    let mut o = obs(T0);
    o.coords_cached = false;
    probe.step(&o);

    let mut o = obs(T0 + 1_000);
    o.coords_cached = false;
    o.lookup_pending = true;
    o.lookup_outcome = Some(LookupOutcomeKind::Sent);
    assert!(probe.step(&o).is_empty());

    // The ladder gave up well inside the budget; the answer is already known.
    let mut o = obs(T0 + 2_000);
    o.coords_cached = false;
    o.lookup_pending = false;
    assert_eq!(probe.step(&o), vec![ProbeAction::Finish]);
    assert_eq!(
        probe.snapshot().discovery.reason,
        Some(FailKind::BloomUnconfirmed)
    );
    assert!(T0 + 2_000 < T0 + b.discovery_ms);
}

#[test]
fn each_gate_decision_lands_on_the_stage_that_owns_it() {
    let cases = [
        (LookupOutcomeKind::BloomMiss, FailKind::BloomMiss),
        (LookupOutcomeKind::Suppressed, FailKind::BackoffSuppressed),
        (LookupOutcomeKind::ZeroFanout, FailKind::NoTreePeers),
        (LookupOutcomeKind::Deduplicated, FailKind::AlreadyPending),
    ];
    for (kind, expected) in cases {
        let mut pre = preflight();
        pre.coords_cached = false;
        let mut probe = Probe::new(T0, budgets(), pre);
        let mut o = obs(T0);
        o.coords_cached = false;
        probe.step(&o);

        let mut o = obs(T0 + 1_000);
        o.coords_cached = false;
        o.lookup_outcome = Some(kind);
        o.lookup_pending = kind == LookupOutcomeKind::Deduplicated;
        probe.step(&o);

        if kind == LookupOutcomeKind::Deduplicated {
            // Joined an in-flight lookup; it has to fail before the reason is
            // known, so clear the pending entry.
            let mut o = obs(T0 + 2_000);
            o.coords_cached = false;
            o.lookup_pending = false;
            probe.step(&o);
        }
        // A gate decision that stopped the request is the bloom stage's
        // finding; only the joined-lookup case gets far enough to be
        // discovery's.
        let snap = probe.snapshot();
        let actual = if kind == LookupOutcomeKind::Deduplicated {
            snap.discovery.reason
        } else {
            snap.bloom.reason
        };
        assert_eq!(
            actual,
            Some(expected),
            "outcome {kind:?} must not collapse into one reason"
        );
    }
}

/// Drive a probe for a key that is **not** on the mesh under a given gate
/// decision, and return the finished snapshot.
///
/// `BloomMiss` is the run where no peer's filter claimed the key. `Sent` is
/// the run where at least one did — which, for a genuinely absent key, can
/// only be a false positive, since a bloom filter has no false negatives.
/// The mesh then answers nothing and the ladder runs out.
fn absent_key_probe(gate: LookupOutcomeKind) -> crate::proto::probe::ProbeSnapshot {
    let mut pre = preflight();
    pre.coords_cached = false;
    let mut probe = Probe::new(T0, budgets(), pre);
    let claimed = gate == LookupOutcomeKind::Sent;

    for tick in 0..40u64 {
        let mut o = obs(T0 + tick * 1_000);
        o.coords_cached = false;
        if tick > 0 {
            o.lookup_outcome = Some(gate);
        }
        // The claimed run holds a pending entry while the ladder retries, then
        // clears it with no coordinates: nobody answered for the address.
        o.lookup_pending = claimed && tick < 16;
        if probe.step(&o).contains(&ProbeAction::Finish) {
            break;
        }
    }
    probe.snapshot()
}

#[test]
fn absent_key_names_the_filter_claim_instead_of_collapsing_into_no_response() {
    let clean = absent_key_probe(LookupOutcomeKind::BloomMiss);
    let claimed = absent_key_probe(LookupOutcomeKind::Sent);

    assert_eq!(
        clean.bloom.verdict,
        StageVerdict::Failed,
        "no filter claimed it, so the bloom stage is where it ended"
    );
    assert_eq!(
        claimed.bloom.verdict,
        StageVerdict::Ok,
        "a filter claimed it, so a request did go out"
    );

    assert_eq!(clean.bloom.reason, Some(FailKind::BloomMiss));
    assert_eq!(
        claimed.discovery.reason,
        Some(FailKind::BloomUnconfirmed),
        "a lookup issued on a filter claim and left unanswered is its own finding"
    );

    // The defect this guards: the claimed run must not land on any reason a
    // run that never issued a request can also produce. `no_response` was
    // exactly such a reason — the bloom stage reaches it too — so reporting
    // it here told the operator nothing about which case they were in.
    for shared in [
        FailKind::BloomMiss,
        FailKind::NoResponse,
        FailKind::BackoffSuppressed,
        FailKind::NoTreePeers,
    ] {
        assert_ne!(
            claimed.discovery.reason,
            Some(shared),
            "{} cannot distinguish a claimed lookup from one never issued",
            shared.name()
        );
    }

    // The verdict is the answer and the answer was already right: absent
    // either way. Only the reason changes.
    assert_eq!(clean.overall, Overall::Failed);
    assert_eq!(
        clean.overall, claimed.overall,
        "the key is absent on both paths; the verdict must not move"
    );
}

#[test]
fn cancelling_mid_discovery_still_names_the_filter_claim() {
    // `expire_running_stage` writes the reason for a stage that never got to
    // settle. It must give the same finding the budget path would.
    let mut pre = preflight();
    pre.coords_cached = false;
    let mut probe = Probe::new(T0, budgets(), pre);

    let mut o = obs(T0);
    o.coords_cached = false;
    probe.step(&o);

    let mut o = obs(T0 + 1_000);
    o.coords_cached = false;
    o.lookup_pending = true;
    o.lookup_outcome = Some(LookupOutcomeKind::Sent);
    probe.step(&o);
    assert_eq!(probe.snapshot().discovery.verdict, StageVerdict::Running);

    probe.cancel(T0 + 2_000);
    assert_eq!(
        probe.snapshot().discovery.reason,
        Some(FailKind::BloomUnconfirmed)
    );
}

// ---- ownership ----------------------------------------------------------

#[test]
fn session_skipped_when_entry_present_at_preflight() {
    let mut pre = preflight();
    pre.session_present = true;
    let mut probe = Probe::new(T0, budgets(), pre);

    let mut saw_teardown = false;
    let mut saw_open = false;
    for tick in 0..40u64 {
        let mut o = obs(T0 + tick * 1_000);
        o.session_present = true;
        o.session_established = true;
        for a in probe.step(&o) {
            saw_open |= a == ProbeAction::OpenSession;
            saw_teardown |= a == ProbeAction::TeardownSession;
        }
    }
    assert!(!saw_open, "must never open an existing session");
    assert!(!saw_teardown, "must never tear down someone else's session");
    assert!(!probe.owns_session());
    assert_eq!(probe.snapshot().session.reason, Some(FailKind::Preexisting));
}

#[test]
fn session_present_but_not_established_is_still_not_owned() {
    // The inbound-handshake case: an AwaitingMsg3 entry does not satisfy
    // production's established-or-initiating predicate, so a probe copying
    // that predicate would clobber it.
    let mut pre = preflight();
    pre.session_present = true;
    let mut probe = Probe::new(T0, budgets(), pre);

    let mut saw_open = false;
    let mut saw_teardown = false;
    for tick in 0..40u64 {
        let mut o = obs(T0 + tick * 1_000);
        o.session_present = true;
        o.session_established = false;
        for a in probe.step(&o) {
            saw_open |= a == ProbeAction::OpenSession;
            saw_teardown |= a == ProbeAction::TeardownSession;
        }
    }
    assert!(!saw_open);
    assert!(!saw_teardown);
    assert!(!probe.owns_session());
}

#[test]
fn session_appearing_mid_probe_is_never_owned() {
    let mut pre = preflight();
    pre.coords_cached = false;
    let mut probe = Probe::new(T0, budgets(), pre);

    // Still resolving; no session anywhere.
    let mut o = obs(T0);
    o.coords_cached = false;
    assert_eq!(probe.step(&o), vec![ProbeAction::InitiateLookup]);

    let mut saw_open = false;
    let mut saw_teardown = false;
    for tick in 1..40u64 {
        // A session appears before the probe ever asked for one.
        let mut o = obs(T0 + tick * 1_000);
        o.session_present = true;
        o.session_established = true;
        for a in probe.step(&o) {
            saw_open |= a == ProbeAction::OpenSession;
            saw_teardown |= a == ProbeAction::TeardownSession;
        }
    }
    assert!(!saw_open, "ownership must be latched at action time");
    assert!(!saw_teardown);
    assert!(!probe.owns_session());
}

#[test]
fn ownership_is_dropped_when_our_entry_is_replaced() {
    let mut probe = Probe::new(T0, budgets(), preflight());
    assert_eq!(probe.step(&obs(T0)), vec![ProbeAction::OpenSession]);

    // Confirm it was ours once...
    let mut o = obs(T0 + 1_000);
    o.session_present = true;
    o.session_established = true;
    o.session_is_ours = true;
    probe.step(&o);
    assert!(probe.owns_session());

    // ...then the driver's identity check stops matching.
    let mut saw_teardown = false;
    for tick in 2..40u64 {
        let mut o = obs(T0 + tick * 1_000);
        o.session_present = true;
        o.session_established = true;
        o.session_is_ours = false;
        for a in probe.step(&o) {
            saw_teardown |= a == ProbeAction::TeardownSession;
        }
    }
    assert!(!saw_teardown, "must not remove a replacement entry");
    assert!(!probe.owns_session());
    assert_eq!(probe.snapshot().left_intact, Some(LeftIntact::Replaced));
}

#[test]
fn owned_session_torn_down_on_every_terminal_path() {
    // 1. rtt succeeds.
    let (mut probe, t) = probe_at_rtt();
    let mut o = obs(t + 1_000);
    o.session_present = true;
    o.session_established = true;
    o.session_is_ours = true;
    o.counters = RttCounters {
        reports_seen: 1,
        samples: 1,
        zero: 0,
        arith_fail: 0,
    };
    o.last_rtt_ms = Some(18);
    probe.step(&o);
    assert_teardown_then_finish(&mut probe, t + 2_000, 40);

    // 2. rtt times out.
    let (mut probe, t) = probe_at_rtt();
    assert_teardown_then_finish(&mut probe, t + 1_000, 40);

    // 3. the handshake never completes. This path must keep its own loop: the
    //    shared helper forces `session_established`, which would silently turn
    //    this case into a repeat of case 2 and leave the probe's own half-open
    //    Initiating entry untested. A leaked entry is worse than none, because
    //    a later `initiate_session` then returns Ok on a dead session.
    let mut probe = Probe::new(T0, budgets(), preflight());
    assert_eq!(probe.step(&obs(T0)), vec![ProbeAction::OpenSession]);
    let mut seen: Vec<ProbeAction> = Vec::new();
    for tick in 1..40u64 {
        let mut o = obs(T0 + tick * 1_000);
        o.session_present = true;
        o.session_established = false;
        o.session_is_ours = true;
        seen.extend(probe.step(&o));
    }
    assert_eq!(
        seen.iter()
            .filter(|a| **a == ProbeAction::TeardownSession)
            .count(),
        1,
        "the half-open entry must be removed exactly once: {seen:?}"
    );
    let td = seen
        .iter()
        .position(|a| *a == ProbeAction::TeardownSession)
        .unwrap();
    let fin = seen
        .iter()
        .position(|a| *a == ProbeAction::Finish)
        .expect("must finish");
    assert!(td < fin, "teardown must precede finish: {seen:?}");
    assert_eq!(
        probe.snapshot().session.reason,
        Some(FailKind::HandshakeTimeout)
    );

    // 4. cancel.
    let mut probe = Probe::new(T0, budgets(), preflight());
    assert_eq!(probe.step(&obs(T0)), vec![ProbeAction::OpenSession]);
    let mut o = obs(T0 + 1_000);
    o.session_present = true;
    o.session_established = true;
    o.session_is_ours = true;
    probe.step(&o);
    assert_eq!(
        probe.cancel(T0 + 2_000),
        vec![ProbeAction::TeardownSession, ProbeAction::Finish]
    );
    assert!(probe.cancel(T0 + 3_000).is_empty());
}

/// Step forward until the probe finishes, asserting exactly one teardown and
/// that it precedes `Finish`.
fn assert_teardown_then_finish(probe: &mut Probe, from_ms: u64, ticks: u64) {
    let mut seen: Vec<ProbeAction> = Vec::new();
    for tick in 0..ticks {
        let mut o = obs(from_ms + tick * 1_000);
        o.session_present = true;
        o.session_established = true;
        o.session_is_ours = true;
        seen.extend(probe.step(&o));
    }
    let teardowns = seen
        .iter()
        .filter(|a| **a == ProbeAction::TeardownSession)
        .count();
    assert_eq!(teardowns, 1, "actions seen: {seen:?}");
    let td = seen
        .iter()
        .position(|a| *a == ProbeAction::TeardownSession)
        .unwrap();
    let fin = seen
        .iter()
        .position(|a| *a == ProbeAction::Finish)
        .expect("must finish");
    assert!(td < fin, "teardown must precede finish: {seen:?}");
}

#[test]
fn a_session_the_probe_opened_is_never_reported_preexisting() {
    // The handshake normally spans several ticks, and every one of them sees
    // `session_present`. Reporting those as pre-existing would contradict the
    // teardown the same report carries.
    let mut probe = Probe::new(T0, budgets(), preflight());
    assert_eq!(probe.step(&obs(T0)), vec![ProbeAction::OpenSession]);

    let mut o = obs(T0 + 1_000);
    o.session_present = true;
    o.session_established = false;
    o.session_is_ours = true;
    probe.step(&o);
    assert!(probe.owns_session());
    assert!(
        !probe.snapshot().session_preexisting,
        "an entry the probe opened is not pre-existing"
    );

    let mut o = obs(T0 + 2_000);
    o.session_present = true;
    o.session_established = true;
    o.session_is_ours = true;
    probe.step(&o);
    assert!(!probe.snapshot().session_preexisting);
}

#[test]
fn ownership_lost_before_confirmation_reads_as_replaced() {
    // Simultaneous initiation: the peer's inbound handshake replaces our entry
    // before the first observation that would have confirmed it was ours. The
    // probe did create one, so "preexisting" would be the wrong account.
    let mut probe = Probe::new(T0, budgets(), preflight());
    assert_eq!(probe.step(&obs(T0)), vec![ProbeAction::OpenSession]);

    let mut o = obs(T0 + 1_000);
    o.session_present = true;
    o.session_established = true;
    o.session_is_ours = false;
    probe.step(&o);

    assert!(!probe.owns_session());
    assert_eq!(probe.snapshot().left_intact, Some(LeftIntact::Replaced));
}

#[test]
fn session_send_error_drops_ownership_and_carries_the_message() {
    let mut probe = Probe::new(T0, budgets(), preflight());
    assert_eq!(probe.step(&obs(T0)), vec![ProbeAction::OpenSession]);
    assert!(probe.owns_session());

    let mut o = obs(T0 + 1_000);
    o.session_error = Some("no route to destination".to_string());
    let actions = probe.step(&o);

    assert!(
        !actions.contains(&ProbeAction::TeardownSession),
        "a failed send created nothing to tear down: {actions:?}"
    );
    assert_eq!(actions, vec![ProbeAction::Finish]);
    assert!(!probe.owns_session());
    let snap = probe.snapshot();
    assert_eq!(snap.session.reason, Some(FailKind::SendError));
    assert_eq!(
        snap.session.detail.as_deref(),
        Some("no route to destination")
    );
    assert_eq!(snap.overall.name(), "failed");
}

#[test]
fn direct_peer_with_no_coords_names_a_hop_and_no_missing_coords_reason() {
    // The routing short-circuit names a direct peer before reading the coord
    // cache, so the report must not carry a reason why no hop could be named
    // alongside a named hop.
    let mut pre = preflight();
    pre.coords_cached = false;
    let mut probe = Probe::new(T0, budgets(), pre);

    let mut o = obs(T0);
    o.coords_cached = false;
    o.target_is_direct_peer = true;
    o.path = None;
    probe.step(&o);

    let snap = probe.snapshot();
    assert!(snap.next_hop.is_some());
    assert_eq!(snap.no_hop_reason, None, "a named hop needs no excuse");
}

// ---- rtt ----------------------------------------------------------------

#[test]
fn rtt_requires_a_new_sample_not_a_present_srtt() {
    // A pre-existing session already carries an SRTT, and SRTT survives rekey,
    // so `srtt_ms.is_some()` is not attributable to this probe. Only a delta on
    // the accepted-sample counter is.
    let base = RttCounters {
        reports_seen: 5,
        samples: 5,
        zero: 0,
        arith_fail: 0,
    };
    let established = |now_ms: u64, counters: RttCounters| {
        let mut o = obs(now_ms);
        o.session_present = true;
        o.session_established = true;
        o.session_is_ours = true;
        o.counters = counters;
        o.srtt_ms = Some(12.0);
        o
    };

    let mut probe = Probe::new(T0, budgets(), preflight());
    assert_eq!(probe.step(&obs(T0)), vec![ProbeAction::OpenSession]);
    // Entering the rtt stage latches the baseline from this observation.
    assert_eq!(
        probe.step(&established(T0 + 1_000, base)),
        vec![ProbeAction::SendWarmup]
    );

    for tick in 2..4u64 {
        probe.step(&established(T0 + tick * 1_000, base));
        assert_eq!(probe.snapshot().rtt.verdict, StageVerdict::Running);
    }

    let sampled = RttCounters { samples: 6, ..base };
    let mut o = established(T0 + 4_000, sampled);
    o.last_rtt_ms = Some(18);
    probe.step(&o);
    let snap = probe.snapshot();
    assert_eq!(snap.rtt.verdict, StageVerdict::Ok);
    assert_eq!(snap.rtt_ms, Some(18));
}

#[test]
fn rtt_four_failure_modes_are_distinct() {
    let cases = [
        (RttCounters::default(), FailKind::NoReport),
        (
            RttCounters {
                reports_seen: 2,
                ..RttCounters::default()
            },
            FailKind::NoEcho,
        ),
        (
            RttCounters {
                reports_seen: 2,
                zero: 2,
                ..RttCounters::default()
            },
            FailKind::SubMillisecond,
        ),
        (
            RttCounters {
                reports_seen: 2,
                arith_fail: 2,
                ..RttCounters::default()
            },
            FailKind::BadTimestampEcho,
        ),
    ];
    for (counters, expected) in cases {
        let (mut probe, t) = probe_at_rtt();
        for tick in 1..12u64 {
            let mut o = obs(t + tick * 1_000);
            o.session_present = true;
            o.session_established = true;
            o.session_is_ours = true;
            o.counters = counters;
            probe.step(&o);
        }
        assert_eq!(
            probe.snapshot().rtt.reason,
            Some(expected),
            "counters {counters:?} must not be conflated"
        );
    }
}

#[test]
fn warmup_sent_at_most_twice() {
    let (mut probe, t) = probe_at_rtt();
    let mut warmups = 1; // the entry warmup, from probe_at_rtt
    for tick in 1..11u64 {
        let mut o = obs(t + tick * 1_000);
        o.session_present = true;
        o.session_established = true;
        o.session_is_ours = true;
        warmups += probe
            .step(&o)
            .iter()
            .filter(|a| **a == ProbeAction::SendWarmup)
            .count();
    }
    assert_eq!(warmups, 2, "a diagnostic must not become a traffic source");

    // A report arriving after the first warmup cancels the retransmit.
    let (mut probe, t) = probe_at_rtt();
    let mut warmups = 1;
    for tick in 1..11u64 {
        let mut o = obs(t + tick * 1_000);
        o.session_present = true;
        o.session_established = true;
        o.session_is_ours = true;
        o.counters = RttCounters {
            reports_seen: 1,
            ..RttCounters::default()
        };
        warmups += probe
            .step(&o)
            .iter()
            .filter(|a| **a == ProbeAction::SendWarmup)
            .count();
    }
    assert_eq!(warmups, 1);
}

// ---- verdicts and budgets ----------------------------------------------

#[test]
fn overall_ok_when_all_stages_pass() {
    let (mut probe, t) = probe_at_rtt();
    let mut o = obs(t + 1_000);
    o.session_present = true;
    o.session_established = true;
    o.session_is_ours = true;
    o.counters = RttCounters {
        reports_seen: 1,
        samples: 1,
        zero: 0,
        arith_fail: 0,
    };
    o.last_rtt_ms = Some(18);
    probe.step(&o);
    assert_teardown_then_finish(&mut probe, t + 2_000, 10);
    assert_eq!(probe.snapshot().overall.name(), "ok");
}

#[test]
fn overall_partial_when_session_ok_and_rtt_failed() {
    let (mut probe, t) = probe_at_rtt();
    assert_teardown_then_finish(&mut probe, t + 1_000, 40);
    assert_eq!(probe.snapshot().overall.name(), "partial");
}

#[test]
fn overall_failed_when_session_failed() {
    let mut probe = Probe::new(T0, budgets(), preflight());
    assert_eq!(probe.step(&obs(T0)), vec![ProbeAction::OpenSession]);
    // The handshake never completes.
    for tick in 1..40u64 {
        let mut o = obs(T0 + tick * 1_000);
        o.session_present = true;
        o.session_is_ours = true;
        probe.step(&o);
    }
    assert_eq!(
        probe.snapshot().session.reason,
        Some(FailKind::HandshakeTimeout)
    );
    assert_eq!(probe.snapshot().overall.name(), "failed");
}

#[test]
fn total_deadline_forces_terminal() {
    let b = budgets();
    let mut pre = preflight();
    pre.coords_cached = false;
    let mut probe = Probe::new(T0, b, pre);
    let mut o = obs(T0);
    o.coords_cached = false;
    probe.step(&o);

    // Jump straight past the total budget while still in resolve.
    let mut o = obs(T0 + b.total_ms() + 1);
    o.coords_cached = false;
    o.lookup_pending = true;
    assert_eq!(probe.step(&o), vec![ProbeAction::Finish]);
    assert!(probe.is_finished());
}

#[test]
fn budgets_scale_with_tick() {
    // A node with a 10s tick would otherwise expire every stage between two
    // consecutive observations.
    let b = Budgets::derive(10_000, &[1, 2, 4, 8]);
    assert!(b.session_ms >= 30_000, "session_ms = {}", b.session_ms);
    assert!(b.rtt_ms >= 40_000, "rtt_ms = {}", b.rtt_ms);
    assert_eq!(b.discovery_ms, 15_000 + 2 * 10_000);
    assert_eq!(b.bloom_ms, 2 * 10_000);
}
