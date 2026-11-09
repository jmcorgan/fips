//! The known shapes the model's convergence with itself exempts, each
//! shown once on the schedule that found it.
//!
//! Each test here is an observation, not a pin: it passes when the shape
//! is still there. It replays the schedule with the model at both ends,
//! heals, and asserts that the world saw the shape and that the two ends
//! split; then it replays the same schedule with the model of `master` at
//! both ends and asserts that they do not split, which is where the FRC's
//! rules and the current node differ. A further test shows that each
//! start's own script shows only the shape that start carries by design,
//! with the model and with joint nodes, so an exemption is spent on its
//! shape alone, and another that the two defects left for later show their
//! shapes in the models of the current and the deployed node.
//!
//! - [`Shape::StaleFrame`]: a counterexample to the operator's late-dial
//!   rule, as the model encodes it. The responder replaces the first
//!   session at the second msg1 after sending a frame under the first; the
//!   dialer moves to its later dial and keeps the first as its fallback;
//!   the responder's earlier frame then moves the dialer back to the
//!   session the responder dropped. The comparison of the two candidate
//!   late-dial rules decides whether the rule is built.
//! - [`Shape::OldLife`]: an observation against FRC-1201, a msg1 from the
//!   peer's previous life accepted as a restart past the unheard floor,
//!   reached by a delay longer than the world allows (shown here with the
//!   bound lifted for one world) and by replay.
//! - [`Shape::RekeyInstall`]: an observation against FRC-1201, a restarted
//!   node installed from the peer's rekey msg1 and then parted from it by
//!   the peer's late crossing dial.
//! - [`Shape::LaterDialFirst`] and [`Shape::DialAsRekey`]: the late second
//!   dial answered in the other order and the dial on the peer's aged
//!   link, the two defects left for later, which only the runs against
//!   the models of deployed nodes exempt (`legacy/explore.rs`).

use alloc::string::String;
use alloc::vec::Vec;

use super::explore::{Act, apply};
use super::joint::off;
use super::legacy::maint::maint;
use super::legacy::master::master;
use super::oracle::{Oracle, every_step, heal, healed};
use super::starts::{Maker, Start, model, starts};
use super::world::{Shape, World};

/// Start `number`'s variant named with `name`, with nodes made by `mk`,
/// after `path` and a heal; `unbounded` lifts the delivery bound.
fn after(number: u8, name: &str, mk: Maker, path: &[Act], unbounded: bool) -> World {
    let st = starts()
        .into_iter()
        .find(|s| s.number == number && s.name.contains(name))
        .expect("the start exists");
    let mut w = (st.build)(mk);
    w.net.unbounded = unbounded;
    for &a in path {
        apply(&mut w, a);
    }
    heal(&mut w);
    w
}

/// The splits a healed world shows.
fn splits(w: &World) -> Vec<String> {
    every_step(w)
        .into_iter()
        .chain(healed(w))
        .filter(|b| b.oracle == Oracle::OneSession && b.what.starts_with("split:"))
        .map(|b| b.what)
        .collect()
}

/// Asserts that `path` shows `shape` and a split with the model at both
/// ends, and no split with the model of `master`.
fn observe(number: u8, name: &str, path: &[Act], unbounded: bool, shape: Shape) {
    let w = after(number, name, model, path, unbounded);
    assert_eq!(
        w.kinds(),
        [shape],
        "start {number} {name}: the model shows the shape"
    );
    assert!(
        !splits(&w).is_empty(),
        "start {number} {name}: the model splits"
    );
    let w = after(number, name, master, path, unbounded);
    assert!(
        splits(&w).is_empty(),
        "start {number} {name}: the model of master converges: {:?}",
        splits(&w)
    );
}

#[test]
fn a_stale_frame_moves_a_late_dialer_back_onto_the_session_its_peer_dropped() {
    let path = [Act::Frame(1), Act::Deliver(4), Act::Deliver(6)];
    for name in ["larger dialer", "smaller dialer"] {
        observe(5, name, &path, false, Shape::StaleFrame);
    }
}

#[test]
fn observed_a_late_msg1_from_the_peers_previous_life_is_accepted_as_a_restart() {
    let path = [
        Act::Deliver(0),
        Act::Advance,
        Act::Restart(0),
        Act::Deliver(4),
        Act::Advance,
    ];
    observe(8, "restart", &path, true, Shape::OldLife);
}

#[test]
fn observed_a_replayed_msg1_from_the_peers_previous_life_is_accepted_as_a_restart() {
    let path = [
        Act::Deliver(0),
        Act::Advance,
        Act::Restart(0),
        Act::Deliver(4),
        Act::Advance,
        Act::Replay(0),
    ];
    observe(13, "spray", &path, false, Shape::OldLife);
}

#[test]
fn observed_a_restarted_node_installed_from_the_peers_rekey_is_parted_by_its_late_crossing_dial() {
    let path = [
        Act::Deliver(15),
        Act::Deliver(16),
        Act::Restart(0),
        Act::Rekey(1, 0),
    ];
    observe(9, "drain", &path, false, Shape::RekeyInstall);
}

/// The shapes start `st`'s own script shows, healed, with nodes made by
/// `mk`.
fn scripted(st: &Start, mk: Maker) -> Vec<Shape> {
    let mut w = (st.build)(mk);
    (st.script)(&mut w);
    heal(&mut w);
    w.kinds()
}

/// The shape a start carries by design: the late second dial answered in
/// the other order, and the dial on the peer's aged link.
fn carried(number: u8) -> Vec<Shape> {
    match number {
        6 => alloc::vec![Shape::LaterDialFirst],
        7 => alloc::vec![Shape::DialAsRekey],
        _ => Vec::new(),
    }
}

#[test]
fn each_starts_own_script_shows_only_the_shape_it_carries() {
    for st in starts().into_iter().filter(|s| s.number != 12) {
        assert_eq!(
            scripted(&st, st.maker),
            carried(st.number),
            "{}: its script's shapes",
            st.name
        );
        assert_eq!(
            scripted(&st, off),
            carried(st.number),
            "{}: its script's shapes on joint nodes",
            st.name
        );
    }
}

#[test]
fn the_two_defects_left_for_later_show_their_shapes_in_the_current_and_deployed_node() {
    // The late second dial (both dialer orders) and the dial on the aged
    // link, each on its start's own script with the model of `master` at
    // both ends; the late dial also with the model of `maint`, whose
    // smaller dialer swaps onto its earlier dial as `master` does.
    for st in starts().into_iter().filter(|s| matches!(s.number, 6 | 7)) {
        assert_eq!(
            scripted(&st, master),
            carried(st.number),
            "{} with master",
            st.name
        );
    }
    let smaller = starts()
        .into_iter()
        .find(|s| s.number == 6 && s.name.contains("smaller dialer"))
        .expect("the start exists");
    assert_eq!(
        scripted(&smaller, maint),
        [Shape::LaterDialFirst],
        "{} with maint",
        smaller.name
    );
}
