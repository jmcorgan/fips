//! The three defects of the current node the settlement properties must
//! find in the model of `master`, each on its named start and at each
//! multipath setting: crossed dials leave the smaller node on the wrong
//! link, a late second dial answered in the other order splits the session,
//! and a dial on the peer's aged link leaves a pending the peer cannot
//! adopt. If one of them is not found at its property, the world is weaker
//! than the reproductions it stands for. A fourth, a forward wall step
//! letting a msg1 replace a peering heard just now, is gone from the node
//! since its gates read the peer clock, and its test says so.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::super::super::model::history::Event;
use super::super::super::model::judge::Gate;
use super::super::explore::{apply, replay};
#[cfg(feature = "slow-tests")]
use super::super::joint::explore::CAPABLE;
use super::super::oracle::{Breach, Oracle, every_step, follow, scripted};
use super::super::shadow::{Entry, Rec, Refusal};
use super::super::starts::{Do, Maker, Start, Want, starts};
use super::master::{master, master_on};

/// The model of `master` at each multipath setting, by name.
const SETTINGS: [(&str, Maker); 2] = [("off", master), ("on", master_on)];

/// Start `number`'s variant named with `name`, its nodes made by `mk`.
fn start(mk: Maker, number: u8, name: &str) -> Start {
    let mut st = starts()
        .into_iter()
        .find(|s| s.number == number && s.name.contains(name))
        .expect("the start exists");
    st.maker = mk;
    st
}

/// Every breach the model of `master` made by `mk` shows on start
/// `number`'s variant named with `name`, after `steps` (the start's own
/// script when none) and a heal.
fn found(mk: Maker, number: u8, name: &str, steps: Option<&[Do]>) -> Vec<Breach> {
    let st = start(mk, number, name);
    match steps {
        Some(steps) => follow(&mut (st.build)(st.maker), steps),
        None => scripted(&st),
    }
}

/// Whether `found` holds a breach of `oracle` at node `node` whose text
/// starts with `what`.
fn has(found: &[Breach], oracle: Oracle, node: usize, what: &str) -> bool {
    found
        .iter()
        .any(|b| b.oracle == oracle && b.node == node && b.what.starts_with(what))
}

/// The breaches, one per line, for a failure message.
fn listed(found: &[Breach]) -> String {
    found
        .iter()
        .map(|b| format!("{:?} n{}: {}", b.oracle, b.node, b.what))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Node 0's msg1 read first, then node 1's.
const SMALLER_FIRST: &[Do] = &[
    Do::Get(1, Want::Msg1, None),
    Do::Get(0, Want::Msg1, None),
    Do::Get(0, Want::Msg2, None),
    Do::Get(1, Want::Msg2, None),
];

/// Node 1's msg1 read first, then node 0's.
const LARGER_FIRST: &[Do] = &[
    Do::Get(0, Want::Msg1, None),
    Do::Get(1, Want::Msg1, None),
    Do::Get(1, Want::Msg2, None),
    Do::Get(0, Want::Msg2, None),
];

/// The connection-oriented crossing: node 0's connection is open, node
/// 1's opens after node 0's msg1 is read.
const STREAM_SMALLER_FIRST: &[Do] = &[
    Do::Get(1, Want::Msg1, None),
    Do::Open(1),
    Do::Get(0, Want::Msg1, None),
    Do::Get(0, Want::Msg2, None),
    Do::Get(1, Want::Msg2, None),
];

/// The connection-oriented crossing, node 1's msg1 read first.
const STREAM_LARGER_FIRST: &[Do] = &[
    Do::Open(1),
    Do::Get(0, Want::Msg1, None),
    Do::Get(1, Want::Msg1, None),
    Do::Get(1, Want::Msg2, None),
    Do::Get(0, Want::Msg2, None),
];

/// A crossing's `RightLink` breach at the smaller node.
fn wrong_link(number: u8, name: &str, steps: &[Do]) {
    for (setting, mk) in SETTINGS {
        let found = found(mk, number, name, Some(steps));
        assert!(
            has(&found, Oracle::RightLink, 0, ""),
            "multipath {setting}: the smaller node is on the wrong link:\n{}",
            listed(&found)
        );
    }
}

#[test]
fn against_a_model_of_master_crossed_dials_on_one_connectionless_transport_leave_the_smaller_node_on_the_wrong_link_smaller_first()
 {
    wrong_link(1, "connectionless", SMALLER_FIRST);
}

#[test]
fn against_a_model_of_master_crossed_dials_on_one_connectionless_transport_leave_the_smaller_node_on_the_wrong_link_larger_first()
 {
    wrong_link(1, "connectionless", LARGER_FIRST);
}

#[test]
fn against_a_model_of_master_crossed_dials_on_a_connection_oriented_transport_leave_the_smaller_node_on_the_wrong_link_smaller_first()
 {
    wrong_link(3, "connection-oriented", STREAM_SMALLER_FIRST);
}

#[test]
fn against_a_model_of_master_crossed_dials_on_a_connection_oriented_transport_leave_the_smaller_node_on_the_wrong_link_larger_first()
 {
    wrong_link(3, "connection-oriented", STREAM_LARGER_FIRST);
}

/// Start 6's split, with the dialer named by `name`.
fn late_split(name: &str) {
    for (setting, mk) in SETTINGS {
        let found = found(mk, 6, name, None);
        assert!(
            has(&found, Oracle::OneSession, 0, "split:"),
            "multipath {setting}: the two ends hold different sessions:\n{}",
            listed(&found)
        );
    }
}

#[test]
fn against_a_model_of_master_a_late_second_dial_answered_in_the_other_order_splits_the_session_larger_dialer()
 {
    late_split("larger dialer");
}

#[test]
fn against_a_model_of_master_a_late_second_dial_answered_in_the_other_order_splits_the_session_smaller_dialer()
 {
    late_split("smaller dialer");
}

#[test]
fn against_a_model_of_master_a_dial_on_the_peers_aged_link_leaves_a_pending_the_peer_cannot_adopt()
{
    for (setting, mk) in SETTINGS {
        let found = found(mk, 7, "aged link", None);
        assert!(
            found
                .iter()
                .any(|b| b.oracle == Oracle::OneSession && b.what.starts_with("pending:")),
            "multipath {setting}: a pending is left that the peer cannot adopt:\n{}",
            listed(&found)
        );
    }
}

#[test]
fn against_a_model_of_master_a_forward_wall_step_does_not_let_a_msg1_replace_a_peering_heard_just_now()
 {
    for (setting, mk) in SETTINGS {
        let st = start(mk, 14, "wall step");
        let mut scratch = replay(&st, &[]);
        let acts = (st.script)(&mut scratch);
        let mut w = replay(&st, &[]);
        for a in acts {
            apply(&mut w, a);
        }
        let refused = w.parties[1].view().log.iter().any(|e| {
            matches!(
                e,
                Entry::Ev {
                    ev: Event::Msg1 { .. },
                    rec: Rec {
                        refused: Some(Refusal::Gate(Gate::Heard)),
                        ..
                    },
                    ..
                }
            )
        });
        assert!(
            refused,
            "multipath {setting}: the heard floor refuses the msg1 past the wall step: {:?}",
            w.parties[1].view().log
        );
        let breaches = every_step(&w);
        assert!(
            !has(&breaches, Oracle::Classified, 1, ""),
            "multipath {setting}: the refusal is the model's:\n{}",
            listed(&breaches)
        );
    }
}

/// The starts `chosen` admits but the two paths, which `starts()` writes as
/// the stand-in's abstract events, explored to their depths with the model
/// of `master` made by `mk` at both ends and no exemption. Every breach is
/// printed with its path; a breach other than the three defects and the
/// named differences is a lead, to be reproduced on real nodes before it is
/// a finding. Returns the starts carrying one of the three defects that do
/// not show it.
#[cfg(feature = "slow-tests")]
fn against_itself(setting: &str, mk: Maker, chosen: impl Fn(&Start) -> bool) -> Vec<String> {
    use super::super::oracle::sweep;
    use super::super::world::World;
    let nothing = |_: &World, _: &Breach| false;
    let all: Vec<_> = starts()
        .into_iter()
        .filter(|s| s.number != 12 && chosen(s))
        .map(|mut s| {
            s.maker = mk;
            s
        })
        .collect();
    let report = std::thread::scope(|sc| {
        let hs: Vec<_> = all
            .iter()
            .map(|st| sc.spawn(move || sweep(st, st.depth, &nothing)))
            .collect();
        hs.into_iter()
            .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect::<Vec<_>>()
    });
    let mut missing = Vec::new();
    for (st, swept) in all.iter().zip(report) {
        std::eprintln!(
            "master {setting} {:>2} {}: {} states, {} leaves healed, {} breaches",
            st.number,
            st.name,
            swept.stats.states,
            swept.stats.leaves.len(),
            swept.found.len()
        );
        for (b, path) in &swept.found {
            std::eprintln!(
                "  {:?} at n{}: {}\n    path {path:?}",
                b.oracle,
                b.node,
                b.what
            );
        }
        let want = match st.number {
            1 | 3 => Some((Oracle::RightLink, "")),
            6 => Some((Oracle::OneSession, "")),
            7 => Some((Oracle::OneSession, "pending:")),
            _ => None,
        };
        if let Some((oracle, what)) = want
            && !swept
                .found
                .iter()
                .any(|(b, _)| b.oracle == oracle && b.what.starts_with(what))
        {
            missing.push(format!("{setting}, {}: no {oracle:?} {what}", st.name));
        }
    }
    missing
}

#[cfg(feature = "slow-tests")]
#[test]
fn the_model_of_master_against_itself_on_every_start_shows_the_three_defects() {
    // At multipath on, the starts whose links turn capable step a minute of
    // probes at each healed leaf and run in the test below.
    let mut missing = against_itself("off", master, |_| true);
    missing.extend(against_itself("on", master_on, |s| {
        !CAPABLE.contains(&s.name)
    }));
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}

/// The starts `against_itself` leaves to these at multipath on, one test
/// each, as each is a long sweep: start `index` of [`CAPABLE`].
#[cfg(feature = "slow-explorers")]
fn capable(index: usize) {
    let missing = against_itself("on", master_on, |s| s.name == CAPABLE[index]);
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}

#[cfg(feature = "slow-explorers")]
#[test]
fn the_model_of_master_with_multipath_on_against_itself_on_a_crossing_of_two_transports() {
    capable(0);
}

#[cfg(feature = "slow-explorers")]
#[test]
fn the_model_of_master_with_multipath_on_shows_the_wrong_link_on_a_connection_oriented_crossing() {
    capable(1);
}

#[cfg(feature = "slow-explorers")]
#[test]
fn the_model_of_master_with_multipath_on_against_itself_on_a_crossing_during_a_rekey() {
    capable(2);
}
