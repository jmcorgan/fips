//! Flap dampening / hold-down unit tests.

use alloc::collections::{BTreeMap, BTreeSet};

use super::util::{make_coords, make_costs, make_node_addr};
use crate::NodeAddr;
use crate::proto::stp::{ParentDeclaration, ParentEval, TreeState};

#[test]
fn test_flap_dampening_engages_after_threshold() {
    // Create TreeState with flap_threshold=3, window=60s, dampening=3600s (long)
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_flap_dampening(3, 60, 3600);
    state.set_hold_down(0); // disable hold-down for this test

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Switch 1: initial parent selection (root -> peer_a)
    assert!(!state.is_flap_dampened(3000));
    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();
    assert!(!state.is_flap_dampened(3000));

    // Switch 2: peer_a -> peer_b
    state.set_parent(peer_b, 2, 2000, 2000);
    state.recompute_coords();
    assert!(!state.is_flap_dampened(3000));

    // Switch 3: peer_b -> peer_a — threshold reached, dampening engages
    let dampened = state.set_parent(peer_a, 3, 3000, 3000);
    state.recompute_coords();
    assert!(dampened);
    assert!(state.is_flap_dampened(3000));

    // The flap-dampening veto now lives at the shell edge, not inside
    // evaluate_parent. The clock-free core still finds peer_b as a discretionary
    // candidate (peer_b much better than peer_a); the shell suppresses it because
    // dampening is active — same net "no switch" as before.
    let costs = make_costs(&[(1, 10.0), (2, 1.0)]);
    assert!(state.is_switch_suppressed(3000)); // veto active at the edge
    assert!(matches!(
        state.evaluate_parent(&costs, &BTreeSet::new()),
        ParentEval::Discretionary(p) if p == peer_b
    ));
}

#[test]
fn test_flap_dampening_allows_mandatory_switches() {
    // Engage dampening, then verify mandatory switches still work
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_flap_dampening(3, 60, 3600);
    state.set_hold_down(0);

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Trigger dampening with 3 switches
    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();
    state.set_parent(peer_b, 2, 2000, 2000);
    state.recompute_coords();
    state.set_parent(peer_a, 3, 3000, 3000);
    state.recompute_coords();
    assert!(state.is_flap_dampened(3000));

    // Remove current parent (peer_a) — this is a mandatory switch
    state.remove_peer(&peer_a);
    // Dampening is still active at the edge, but a parent-lost switch is mandatory
    // and bypasses the veto: the core returns Mandatory and the switch is taken.
    assert!(state.is_switch_suppressed(3000)); // veto still active
    assert!(matches!(
        state.evaluate_parent(&BTreeMap::new(), &BTreeSet::new()),
        ParentEval::Mandatory(p) if p == peer_b
    ));
}

#[test]
fn test_flap_dampening_expires() {
    // Test with 0-second dampening duration to verify expiry logic
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_flap_dampening(3, 60, 0); // 0-second dampening
    state.set_hold_down(0);

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Trigger dampening
    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();
    state.set_parent(peer_b, 2, 2000, 2000);
    state.recompute_coords();
    let dampened = state.set_parent(peer_a, 3, 3000, 3000);
    state.recompute_coords();
    assert!(dampened); // dampening was engaged

    // With 0-second duration, dampening should have already expired
    assert!(!state.is_flap_dampened(3000));

    // Dampening has expired: the veto is no longer active at the edge, so the
    // discretionary switch to peer_b resumes and is taken.
    let costs = make_costs(&[(1, 10.0), (2, 1.0)]);
    assert!(!state.is_switch_suppressed(3000)); // veto cleared
    let result = state
        .evaluate_parent(&costs, &BTreeSet::new())
        .switch_target();
    assert_eq!(result, Some(peer_b)); // not suppressed
}

#[test]
fn test_flap_dampening_below_threshold() {
    // Fewer switches than threshold should NOT engage dampening
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_flap_dampening(4, 60, 3600); // threshold=4
    state.set_hold_down(0);

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Only 3 switches (below threshold of 4)
    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();
    state.set_parent(peer_b, 2, 2000, 2000);
    state.recompute_coords();
    state.set_parent(peer_a, 3, 3000, 3000);
    state.recompute_coords();

    assert!(!state.is_flap_dampened(3000));

    // Dampening never engaged, so the veto is inactive at the edge and the
    // discretionary switch to peer_b is taken normally.
    let costs = make_costs(&[(1, 10.0), (2, 1.0)]);
    assert!(!state.is_switch_suppressed(3000)); // veto never engaged
    let result = state
        .evaluate_parent(&costs, &BTreeSet::new())
        .switch_target();
    assert_eq!(result, Some(peer_b)); // not suppressed
}

#[test]
fn test_flap_dampening_window_reset() {
    // Test that the flap window resets after expiry.
    // Use a 0-second window so it immediately expires between switch groups.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    // threshold=3, window=0s (expires immediately), dampening=3600s
    state.set_flap_dampening(3, 0, 3600);
    state.set_hold_down(0);

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Each switch resets the window (0s window means every switch starts fresh).
    // So we never accumulate enough to reach threshold=3.
    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();
    // Window expired, counter resets on next switch
    state.set_parent(peer_b, 2, 2000, 2000);
    state.recompute_coords();
    // Window expired, counter resets on next switch
    state.set_parent(peer_a, 3, 3000, 3000);
    state.recompute_coords();

    // Dampening should NOT have engaged because each switch reset the window
    assert!(!state.is_flap_dampened(3000));
}

#[test]
fn test_flap_dampening_same_parent_no_count() {
    // Re-declaring the same parent should not count as a flap
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_flap_dampening(3, 60, 3600);
    state.set_hold_down(0);

    let peer_a = make_node_addr(1);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );

    // Initial parent selection
    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();

    // Re-declare same parent multiple times (e.g., parent ancestry changed)
    state.set_parent(peer_a, 2, 2000, 2000);
    state.recompute_coords();
    state.set_parent(peer_a, 3, 3000, 3000);
    state.recompute_coords();
    state.set_parent(peer_a, 4, 4000, 4000);
    state.recompute_coords();
    state.set_parent(peer_a, 5, 5000, 5000);
    state.recompute_coords();

    // Should NOT be dampened since only the first was a real switch
    assert!(!state.is_flap_dampened(3000));
}

#[test]
fn test_flap_dampening_engages_a_second_time_after_first_episode_lapses() {
    // A lapsed episode must re-arm the mechanism: a second flap storm has to
    // engage dampening again, and must cost a fresh threshold of switches
    // rather than re-engaging on the first switch after the lapse. The
    // injected clock is advanced past the deadline instead of using a
    // zero-length episode, so the retirement is driven by a genuinely expired
    // episode.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_flap_dampening(3, 60, 10);
    state.set_hold_down(0);

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // First episode: three switches inside the window reach the threshold.
    let first = state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();
    let second = state.set_parent(peer_b, 2, 2000, 2000);
    state.recompute_coords();
    let third = state.set_parent(peer_a, 3, 3000, 3000);
    state.recompute_coords();

    assert!(!first);
    assert!(!second);
    assert!(third, "first episode must engage at threshold");
    assert!(state.is_flap_dampened(3000));

    // The episode was stamped at 3000 for 10s, so it has lapsed by 14000.
    assert!(!state.is_flap_dampened(14_000));

    // Second episode: a fresh threshold of switches is required, so the first
    // two switches after the lapse must not re-engage.
    let fourth = state.set_parent(peer_b, 4, 4000, 14_000);
    state.recompute_coords();
    let fifth = state.set_parent(peer_a, 5, 5000, 15_000);
    state.recompute_coords();
    let sixth = state.set_parent(peer_b, 6, 6000, 16_000);
    state.recompute_coords();

    assert!(!fourth, "a lapsed episode must not re-engage on one switch");
    assert!(
        !fifth,
        "a lapsed episode must not re-engage below threshold"
    );
    assert!(sixth, "a second episode must engage after the first lapses");
    assert!(state.is_flap_dampened(16_000));
}

#[test]
fn test_flap_dampening_duration_at_u64_max_does_not_panic() {
    // A hostile node.tree.flap_dampening_secs must be clamped rather than
    // overflow the monotonic stamp when an episode engages. Unclamped, the
    // seconds-to-milliseconds conversion saturates at u64::MAX and the
    // deadline arithmetic then overflows on the switch that engages.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_flap_dampening(3, 60, u64::MAX);
    state.set_hold_down(0);

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();
    state.set_parent(peer_b, 2, 2000, 2000);
    state.recompute_coords();
    let dampened = state.set_parent(peer_a, 3, 3000, 3000);
    state.recompute_coords();

    assert!(dampened, "the threshold switch must still engage dampening");
    assert!(state.is_flap_dampened(3000));
    // Clamped to a year, which is what the episode reports to its log field.
    assert_eq!(state.dampening_secs(), 365 * 24 * 60 * 60);
}

#[test]
fn test_parent_loss_recovery_reports_the_engagement_that_arms_dampening() {
    // A parent-loss storm engages dampening on a mandatory recovery switch,
    // which bypasses the veto but still feeds the flap counter. The recovery
    // must report that engagement so the shell, which is the side holding a
    // metrics handle, can surface it.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_flap_dampening(2, 60, 120);
    state.set_hold_down(0);

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // One switch short of the threshold.
    let first = state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();
    assert!(!first, "one switch is below the threshold");

    // Parent disappears; recovery picks peer_b and crosses the threshold.
    state.remove_peer(&peer_a);
    let outcome = state.recover(&BTreeMap::new(), 2000, 2000);

    assert!(outcome.changed);
    assert_eq!(state.my_declaration().parent_id(), &peer_b);
    assert!(
        outcome.dampened,
        "parent-loss recovery must report the engagement it armed"
    );
    assert!(state.is_flap_dampened(2000));
}

#[test]
fn test_parent_loss_recovery_to_self_root_reports_no_engagement() {
    // The self-root fallthrough takes no parent switch, so it can never arm
    // an episode and must never report one.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_flap_dampening(1, 60, 120);
    state.set_hold_down(0);

    let peer_a = make_node_addr(1);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.set_parent(peer_a, 1, 1000, 1000);
    state.recompute_coords();

    state.remove_peer(&peer_a);
    let outcome = state.recover(&BTreeMap::new(), 2000, 2000);

    assert!(outcome.changed);
    assert!(state.is_root());
    assert!(!outcome.dampened, "self-root recovery arms no episode");
}

#[test]
fn test_handle_parent_lost_keeps_its_published_bool_return() {
    // `TreeState` is published, so the return type of this entry point is part
    // of the API and the richer `ParentLoss` must not displace it. Binding the
    // method to an explicitly typed function pointer is the assertion: any
    // other return type fails to compile. Calling through the pointer keeps
    // the binding live.
    let published: fn(&mut TreeState, &BTreeMap<NodeAddr, f64>, u64, u64) -> bool =
        TreeState::handle_parent_lost;

    let mut state = TreeState::new(make_node_addr(5), 1000);
    let peer = make_node_addr(1);
    state.update_peer(
        ParentDeclaration::new(peer, make_node_addr(0), 1, 1000),
        make_coords(&[1, 0]),
    );
    state.set_parent(peer, 1, 1000, 1000);
    state.recompute_coords();

    state.remove_peer(&peer);
    assert!(published(&mut state, &BTreeMap::new(), 2000, 2000));
    assert!(state.is_root());
}

#[test]
fn test_flap_dampening_counter_resets_when_the_episode_lapses_not_when_it_engages() {
    // Retirement clears the switch counter when a lapsed episode is retired,
    // not when the episode is armed, so switches taken *during* an episode do
    // not carry into the next window. Telling those two apart needs an episode
    // that is genuinely live for at least one switch, which the injected clock
    // supplies without any real elapsed time.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node, 1000);
    state.set_flap_dampening(3, 60, 2);
    state.set_hold_down(0);

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    assert!(!state.set_parent(peer_a, 1, 1000, 1000));
    state.recompute_coords();
    assert!(!state.set_parent(peer_b, 2, 2000, 2000));
    state.recompute_coords();
    assert!(
        state.set_parent(peer_a, 3, 3000, 3000),
        "the third switch inside the window must arm an episode"
    );
    state.recompute_coords();
    assert!(
        state.is_flap_dampened(3000),
        "a two-second episode must be live immediately after it is armed"
    );

    // In-episode accumulation: in production a mandatory switch bypasses the
    // veto and still feeds the counter. `set_parent` is the same entry point
    // those switches reach, and it must not re-arm the running episode.
    assert!(
        !state.set_parent(peer_b, 4, 4000, 4000),
        "a switch inside a live episode must not re-arm it"
    );
    state.recompute_coords();
    assert!(state.is_flap_dampened(4000));

    assert!(
        !state.is_flap_dampened(6000),
        "the episode must have lapsed after its two seconds"
    );

    // The lapsed episode is retired on the next switch, taking the counter
    // with it: the in-episode switch must not count toward the next episode.
    assert!(
        !state.set_parent(peer_a, 5, 5000, 6000),
        "retiring a lapsed episode must clear the switch counter"
    );
    state.recompute_coords();
    assert!(
        !state.set_parent(peer_b, 6, 6000, 7000),
        "a second episode must cost a fresh threshold of switches"
    );
    state.recompute_coords();
    assert!(
        state.set_parent(peer_a, 7, 7000, 8000),
        "a second episode must arm once the fresh threshold is reached"
    );
    state.recompute_coords();
    assert!(state.is_flap_dampened(8000));
}
