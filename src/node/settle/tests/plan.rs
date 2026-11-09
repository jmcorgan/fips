//! Tests for `../plan.rs`: a restart's effects are the statements it ran
//! before, in the same order; no other transition has a list yet; and the
//! file denies wildcard arms.

use crate::node::settle::plan::{Effect, plan};
use crate::node::settle::table::Transition;
use crate::node::settle::table::tests::{denies_wildcards, wildcard_arms};
use crate::proto::rekey::Role;
use crate::proto::settle::output::Why;
use crate::testutil::with_lf;
use crate::transport::LinkId;

/// A restart found at a rekey ran, in this order: the end-to-end session
/// closed; the peer's tree position and filter cleared; the peer taken out
/// of the tree state, the other peers marked to be announced to if that
/// changed this node's own; the filter last sent forgotten; a filter update
/// marked to every peer; a tree announce sent to the peer; and the
/// operator's pin ended. A swap of any two is a change of behaviour.
#[test]
fn the_plan_of_a_restart_is_its_statements_in_their_order() {
    assert_eq!(
        plan(&Transition::Restarted),
        &[
            Effect::CloseSession,
            Effect::SettleData,
            Effect::TreeCleanup,
            Effect::BloomForgetSent,
            Effect::BloomMarkAll,
            Effect::TreeAnnounce,
            Effect::Unpin,
        ],
        "defect: a restart's effects are not its statements in their order"
    );
}

/// Every transition but a restart still runs its own statements at its
/// site, so its list is empty: a list there would run them twice.
#[test]
fn every_transition_but_a_restart_has_an_empty_plan() {
    let link = LinkId::new(1);
    let others = [
        Transition::Promote {
            link,
            initiator: true,
        },
        Transition::Promote {
            link,
            initiator: false,
        },
        Transition::Replace {
            link,
            initiator: false,
            why: Why::Restart,
        },
        Transition::Replace {
            link,
            initiator: false,
            why: Why::Replacement,
        },
        Transition::Replace {
            link,
            initiator: true,
            why: Why::OwnRestart,
        },
        Transition::Move {
            dial: link,
            own: true,
            built: true,
        },
        Transition::Move {
            dial: link,
            own: false,
            built: false,
        },
        Transition::Keep { dial: link },
        Transition::Cutover {
            role: Role::Initiator,
        },
        Transition::Cutover {
            role: Role::Responder,
        },
        Transition::Roam,
        Transition::Follow,
        Transition::Switch,
        Transition::Release { keep: true },
        Transition::Release { keep: false },
        Transition::Remove { why: Why::Ended },
        Transition::Remove { why: Why::Orphaned },
        Transition::Remove {
            why: Why::Disconnect,
        },
        Transition::Remove { why: Why::Dead },
        Transition::Remove { why: Why::Admin },
    ];
    let listed: Vec<String> = others
        .iter()
        .filter(|t| !plan(t).is_empty())
        .map(|t| format!("{t:?}"))
        .collect();
    assert_eq!(
        listed,
        Vec::<String>::new(),
        "defect: a transition that runs its own statements also has a plan"
    );
}

#[test]
fn the_plan_denies_wildcard_arms_and_the_scan_finds_a_planted_one() {
    wildcard_scans(&with_lf(include_str!("../plan.rs")));
}

#[test]
fn the_wildcard_scans_of_the_plan_hold_on_a_source_checked_out_with_crlf_line_endings() {
    let crlf = with_lf(include_str!("../plan.rs")).replace('\n', "\r\n");
    assert!(
        crlf.contains("=> &[],\r\n"),
        "precondition: a copy of the source with CRLF line endings"
    );
    wildcard_scans(&with_lf(&crlf));
}

/// That `source`, `../plan.rs` as read, denies wildcard arms and holds none,
/// and that the scans find a planted catch-all arm and the deny taken away.
fn wildcard_scans(source: &str) {
    assert!(
        denies_wildcards(source),
        "defect: plan.rs does not deny wildcard arms at its head"
    );
    assert_eq!(
        wildcard_arms(source),
        Vec::<String>::new(),
        "defect: a catch-all arm in plan.rs"
    );

    let planted = source.replacen(
        "        | Transition::Remove { .. } => &[],\n",
        "        | Transition::Remove { .. } => &[],\n        _ => &[],\n",
        1,
    );
    assert_eq!(
        wildcard_arms(&planted).len(),
        1,
        "defect: the scan missed a planted catch-all arm"
    );
    let undenied = source.replacen("#![deny(clippy::wildcard_enum_match_arm)]", "", 1);
    assert!(
        !denies_wildcards(&undenied),
        "defect: the scan missed the deny taken away"
    );
}
