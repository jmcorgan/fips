//! The two shapes of the current node the settlement properties must find
//! in the model of `master`, each on its named start and at each multipath
//! setting: a late second dial answered in the other order splits the
//! session, and a dial on the peer's aged link leaves a pending the peer
//! cannot adopt, which the peer's next rekey displaces. If one of them is
//! not found at its property, the world is weaker than the reproductions it
//! stands for. Two that were defects are
//! gone from the node, and their tests say so: crossed dials no longer
//! leave the smaller node on the wrong link, since a move holds the link
//! the node dialed (FRC-1201 Section 5.6), and a forward wall step no
//! longer lets a msg1 replace a peering heard just now, since the gates
//! read the peer clock.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::super::super::model::history::Event;
use super::super::super::model::judge::Gate;
use super::super::explore::{apply, replay};
use super::super::oracle::{Breach, Oracle, every_step, follow, scripted};
use super::super::shadow::{Entry, Rec, Refusal};
use super::super::starts::{Do, Maker, Start, Want, starts};
use super::super::world::Dir;
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

/// A crossing leaves the smaller node on the link its own dial set up:
/// after `steps` and a heal it holds the peer on an outbound link whose
/// handshake is the one its session came from, and no step shows a
/// `RightLink` breach at either node.
fn dialed_link(number: u8, name: &str, steps: &[Do]) {
    for (setting, mk) in SETTINGS {
        let st = start(mk, number, name);
        let mut w = (st.build)(st.maker);
        let found = follow(&mut w, steps);
        assert!(
            !found.iter().any(|b| b.oracle == Oracle::RightLink),
            "multipath {setting}: no node is on the wrong link:\n{}",
            listed(&found)
        );
        let v = w.parties[0].view();
        let held: Vec<(Dir, bool)> = v
            .peers
            .iter()
            .map(|p| (p.dir, p.link == p.origin))
            .collect();
        assert_eq!(
            held,
            [(Dir::Outbound, true)],
            "multipath {setting}: the smaller node holds the link it dialed: {:?}",
            v.peers
        );
    }
}

#[test]
fn against_a_model_of_the_node_crossed_dials_on_one_connectionless_transport_leave_the_smaller_node_on_the_link_it_dialed_smaller_first()
 {
    dialed_link(1, "connectionless", SMALLER_FIRST);
}

#[test]
fn against_a_model_of_the_node_crossed_dials_on_one_connectionless_transport_leave_the_smaller_node_on_the_link_it_dialed_larger_first()
 {
    dialed_link(1, "connectionless", LARGER_FIRST);
}

#[test]
fn against_a_model_of_the_node_crossed_dials_on_a_connection_oriented_transport_leave_the_smaller_node_on_the_link_it_dialed_smaller_first()
 {
    dialed_link(3, "connection-oriented", STREAM_SMALLER_FIRST);
}

#[test]
fn against_a_model_of_the_node_crossed_dials_on_a_connection_oriented_transport_leave_the_smaller_node_on_the_link_it_dialed_larger_first()
 {
    dialed_link(3, "connection-oriented", STREAM_LARGER_FIRST);
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

/// The steps of start 7's script up to node 1's own rekey: node 1's dial
/// on the aged link read by node 0, and node 0's answer read by node 1.
const AGED_DIAL: &[Do] = &[
    Do::Get(0, Want::Msg1, Some(1)),
    Do::Get(1, Want::Msg2, Some(0)),
];

#[test]
fn against_a_model_of_master_a_dial_on_the_peers_aged_link_leaves_a_pending_the_peers_rekey_displaces()
 {
    for (setting, mk) in SETTINGS {
        let dialed = found(mk, 7, "aged link", Some(AGED_DIAL));
        assert!(
            dialed
                .iter()
                .any(|b| b.oracle == Oracle::OneSession && b.what.starts_with("pending:")),
            "multipath {setting}: the dial leaves a pending the peer cannot adopt:\n{}",
            listed(&dialed)
        );
        let whole = found(mk, 7, "aged link", None);
        assert!(
            !whole
                .iter()
                .any(|b| b.oracle == Oracle::OneSession && b.what.starts_with("pending:")),
            "multipath {setting}: node 1's rekey did not displace the pending:\n{}",
            listed(&whole)
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
