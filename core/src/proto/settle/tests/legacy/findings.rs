//! The four defects of the current node the settlement properties must
//! find in the model of `master`, each on its named start: crossed dials
//! leave the smaller node on the wrong link, a late second dial answered
//! in the other order splits the session, a dial on the peer's aged link
//! leaves a pending the peer cannot adopt, and a forward wall step lets a
//! msg1 replace a peering heard just now. If one of them is not found at
//! its property, the world is weaker than the reproductions it stands for.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::super::oracle::{Breach, Oracle, follow, scripted};
use super::super::starts::{Do, Want, starts};
use super::master::master;

/// Every breach the model of `master` shows on start `number`'s variant
/// named with `name`, after `steps` (the start's own script when none)
/// and a heal.
fn found(number: u8, name: &str, steps: Option<&[Do]>) -> Vec<Breach> {
    let mut st = starts()
        .into_iter()
        .find(|s| s.number == number && s.name.contains(name))
        .expect("the start exists");
    st.maker = master;
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
    let found = found(number, name, Some(steps));
    assert!(
        has(&found, Oracle::RightLink, 0, ""),
        "the smaller node is on the wrong link:\n{}",
        listed(&found)
    );
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
    let found = found(6, name, None);
    assert!(
        has(&found, Oracle::OneSession, 0, "split:"),
        "the two ends hold different sessions:\n{}",
        listed(&found)
    );
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
    let found = found(7, "aged link", None);
    assert!(
        found
            .iter()
            .any(|b| b.oracle == Oracle::OneSession && b.what.starts_with("pending:")),
        "a pending is left that the peer cannot adopt:\n{}",
        listed(&found)
    );
}

#[test]
fn against_a_model_of_master_a_forward_wall_step_lets_a_msg1_replace_a_peering_heard_just_now() {
    let found = found(14, "wall step", None);
    assert!(
        has(&found, Oracle::Classified, 1, ""),
        "the replacement the heard floor refuses is accepted:\n{}",
        listed(&found)
    );
}

#[cfg(feature = "slow-tests")]
#[test]
fn the_model_of_master_against_itself_on_every_start_shows_the_four_defects() {
    // Every start but the two paths, which the model of `master` does not
    // know, explored to its depth with the model of `master` at both ends
    // and no exemption. Every breach is printed with its path; a breach
    // other than the four defects and the named differences is a lead, to
    // be reproduced on real nodes before it is a finding. The test fails
    // only if a start that carries one of the four defects does not show
    // it.
    use super::super::oracle::sweep;
    use super::super::world::World;
    let nothing = |_: &World, _: &Breach| false;
    let all: Vec<_> = starts()
        .into_iter()
        .filter(|s| s.number != 12)
        .map(|mut s| {
            s.maker = master;
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
            "master {:>2} {}: {} states, {} leaves healed, {} breaches",
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
            14 => Some((Oracle::Classified, "")),
            _ => None,
        };
        if let Some((oracle, what)) = want
            && !swept
                .found
                .iter()
                .any(|(b, _)| b.oracle == oracle && b.what.starts_with(what))
        {
            missing.push(format!("{}: no {oracle:?} {what}", st.name));
        }
    }
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}
