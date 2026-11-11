//! Tests for `../exec/plan.rs` and the plan-reading parts of `../exec/mod.rs`:
//! each transition's effects are the statements its sites ran, in the same
//! order; every transition but a cutover has a list and every effect is in
//! one; each transition that announces logs its own sites' failure line; and
//! both files deny wildcard arms.

use crate::node::settle::exec::announce_line;
use crate::node::settle::exec::plan::{Effect, plan};
use crate::node::settle::table::Transition;
use crate::node::settle::table::tests::{CASES, Case, denies_wildcards, transition, wildcard_arms};
use crate::testutil::with_lf;

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

/// The removal a peer change ends with, after the peer is out of the maps:
/// the statements of its entries' tails, each run as the table's cell for the
/// cause says.
const REMOVE: &[(Effect, &str)] = &[
    (
        Effect::UnmarkHeld,
        "self.relink(&gone, held, None).await, where the cell clears the mark",
    ),
    (
        Effect::CloseHeld,
        "transport.close_connection(&addr).await, where the cell closes the pair",
    ),
    (
        Effect::Reconnect,
        "self.note_link_dead(addr, ..) or retry_pending.remove(&node_addr), as the cell says",
    ),
];

/// The tail of a promotion of this node's own dial, `handle_msg2`'s and the
/// executor's `PromoteToActive` arm's.
const PROMOTE_OUT: &[(Effect, &str)] = &[
    (
        Effect::MachineResolved,
        "machine.step(PeerEvent::PromotionResolved { result }, ..); queue.extend(follow)",
    ),
    (
        Effect::RelinkInitiator,
        "self.relink(&node_addr, None, Some(link)).await",
    ),
    (
        Effect::PathsRenewed,
        "Box::pin(self.paths_renewed(&node_addr)).await",
    ),
    (Effect::DialForget, "self.pending_outbound.forget(&key)"),
    (
        Effect::PromotedNote,
        "info!(.., \"Peer promoted to active\")",
    ),
    (
        Effect::TreeAnnounce,
        "self.send_tree_announce_to_peer(&peer_node_addr).await",
    ),
    (
        Effect::BloomMark,
        "self.bloom_state.mark_update_needed(peer_node_addr)",
    ),
    (Effect::BackoffReset, "self.reset_lookup_backoff()"),
];

/// The tail of a promotion of a msg1 this node answered, the executor's
/// `PromoteToActive` arm's and `finish_inbound`'s.
const PROMOTE_IN: &[(Effect, &str)] = &[
    (
        Effect::MachineResolved,
        "machine.step(PeerEvent::PromotionResolved { result }, ..); queue.extend(follow)",
    ),
    (
        Effect::PathsRenewed,
        "Box::pin(self.paths_renewed(&node_addr)).await",
    ),
    (
        Effect::SetupNote,
        "p.set_handshake_msg2(..); p.note_setup(&msg1, msg2); p.note_setup_ephemeral(ephemeral)",
    ),
    (
        Effect::UnheardNote,
        "self.note_unheard_promotion(&peer, ephemeral)",
    ),
    (
        Effect::TreeAnnounce,
        "self.send_tree_announce_to_peer(&peer).await",
    ),
    (
        Effect::BloomMark,
        "self.bloom_state.mark_update_needed(peer)",
    ),
    (Effect::BackoffReset, "self.reset_lookup_backoff()"),
];

/// The tail of `handle_msg2`'s crossing arm when the peer moves onto the
/// dial's session, after `move_session`.
const MOVE: &[(Effect, &str)] = &[
    (
        Effect::RunLinkOutputs,
        "self.run_link_outputs(&peer_node_addr, out)",
    ),
    (
        Effect::RunRenewed,
        "self.run_renewed(&peer_node_addr, left, paths)",
    ),
    (
        Effect::HoldDial,
        "if left: self.links.hold(&link_id, peer_node_addr); self.peer_machines.rekey(left, link_id); self.rekey_carrier(left, link_id)",
    ),
    (
        Effect::PathsRenewed,
        "self.paths_renewed(&peer_node_addr).await",
    ),
    (
        Effect::MovedRead,
        "let moved = self.peer_link(&peer_node_addr)",
    ),
    (
        Effect::ClearUdpIfMoved,
        "if moved != prior: self.clear_connected_udp_for_peer(&peer_node_addr)",
    ),
    (
        Effect::SeedMtuIfMoved,
        "if moved != prior: self.seed_path_mtu_for_link_peer(&peer_node_addr, key, *tid, addr)",
    ),
    (
        Effect::RelinkIfMoved,
        "if moved != prior: self.relink(&peer_node_addr, prior, moved).await",
    ),
    (
        Effect::UnpinIfOwn,
        "if (own_dial || later_dial) && swapped: self.step_path(&peer_node_addr, Input::Unpin).await",
    ),
    (
        Effect::MoveNote,
        "debug!(.., \"Suppressed replay detections during link transition\"); debug!(.., the swap line)",
    ),
    (
        Effect::MachineCrossed,
        "self.observe_cross_conn_resolved(&peer_node_addr, outcome)",
    ),
    (Effect::DialForget, "self.pending_outbound.forget(&key)"),
    (
        Effect::LoserClose,
        "self.close_handshake_link_connection(loser).await",
    ),
    (Effect::LoserRemoved, "self.remove_link(&loser)"),
    (
        Effect::TreeAnnounce,
        "self.send_tree_announce_to_peer(&peer_node_addr).await",
    ),
    (
        Effect::BloomMark,
        "self.bloom_state.mark_update_needed(peer_node_addr)",
    ),
    (Effect::BackoffReset, "self.reset_lookup_backoff()"),
    (
        Effect::ReplayForget,
        "if first_heard: self.replayed_msg1s.forget(&peer_node_addr)",
    ),
];

/// The tail of `handle_msg2`'s crossing arm when the peer keeps its inbound
/// session.
const KEEP: &[(Effect, &str)] = &[
    (
        Effect::KeepNote,
        "debug!(.., \"Cross-connection: keeping inbound session and original their_index (peer outbound wins)\")",
    ),
    (
        Effect::LeaseFreed,
        "self.index_allocator.free(SessionIndex::new(lease.release()))",
    ),
    (
        Effect::MachineCrossed,
        "self.observe_cross_conn_resolved(&peer_node_addr, outcome)",
    ),
    (Effect::DialForget, "self.pending_outbound.forget(&key)"),
    (
        Effect::LoserClose,
        "self.close_handshake_link_connection(link_id).await",
    ),
    (Effect::LoserRemoved, "self.remove_link(&link_id)"),
    (
        Effect::TreeAnnounce,
        "self.send_tree_announce_to_peer(&peer_node_addr).await",
    ),
    (
        Effect::BloomMark,
        "self.bloom_state.mark_update_needed(peer_node_addr)",
    ),
    (Effect::BackoffReset, "self.reset_lookup_backoff()"),
];

/// A restart found at a rekey, as `reset_restarted` ran it.
const RESTARTED: &[(Effect, &str)] = &[
    (Effect::CloseSession, "self.close_session(peer)"),
    (Effect::SettleData, "held.settle(t)"),
    (
        Effect::TreeCleanup,
        "self.handle_peer_removal_tree_cleanup(peer); other.mark_tree_announce_pending()",
    ),
    (
        Effect::BloomForgetSent,
        "self.bloom_state.forget_sent(peer)",
    ),
    (
        Effect::BloomMarkAll,
        "self.bloom_state.mark_all_updates_needed(peers)",
    ),
    (
        Effect::TreeAnnounce,
        "self.send_tree_announce_to_peer(peer).await",
    ),
    (
        Effect::Unpin,
        "self.step_path(peer, fips_core::proto::path::Input::Unpin).await",
    ),
];

/// `account_authentic`'s statements when a frame moved the link's one path.
const ROAM: &[(Effect, &str)] = &[
    (
        Effect::ClearUdpIfMoved,
        "if address_changed: self.clear_connected_udp_for_peer(node_addr)",
    ),
    (
        Effect::RelinkIfMoved,
        "self.relink(node_addr, prior, Some(link)).await",
    ),
];

/// `run_outputs`'s `Moved` arm, after the slot is cleared.
const FOLLOW: &[(Effect, &str)] = &[
    (
        Effect::LinkFollow,
        "self.links.follow(link, &old, (to.transport, to.addr.clone()))",
    ),
    (
        Effect::FollowNote,
        "debug!(.., \"Path moved to a new address\")",
    ),
];

/// `switched`.
const SWITCH: &[(Effect, &str)] = &[
    (Effect::ClearOldUdp, "slot.clear_connected_udp()"),
    (
        Effect::LinkClaim,
        "self.links.claim(link, (to.transport, to.addr.clone()))",
    ),
    (
        Effect::SeedMtu,
        "self.seed_mtu(node_addr, key, to.transport, &to.addr, true)",
    ),
    (
        Effect::TightenSessions,
        "mmp.path_mtu.seed_source_mtu(mtu) for each session via the peer",
    ),
    (Effect::SwitchNote, "info!(.., \"Path switched\")"),
];

/// `release_path`, after the slot is cleared.
const RELEASE: &[(Effect, &str)] = &[
    (
        Effect::LinkUnclaim,
        "if !removed: self.links.unclaim(link, &key)",
    ),
    (
        Effect::CloseQueued,
        "unless keep or another peer's link: self.paths.closing.push(Closing { .. })",
    ),
];

/// The statements the sites of `case` ran, in their order, each with the
/// effect that stands for it.
fn statements(case: Case) -> Vec<(Effect, &'static str)> {
    match case {
        Case::PromoteInitiator => PROMOTE_OUT.to_vec(),
        Case::PromoteResponder => PROMOTE_IN.to_vec(),
        Case::ReplaceRestart | Case::ReplaceReplacement => [REMOVE, PROMOTE_IN].concat(),
        Case::ReplaceOwnRestart => [REMOVE, PROMOTE_OUT].concat(),
        Case::MoveCrossing | Case::MoveOwn | Case::MoveCrossingRefused | Case::MoveOwnRefused => {
            MOVE.to_vec()
        }
        Case::Keep => KEEP.to_vec(),
        Case::CutoverInitiator | Case::CutoverResponder => Vec::new(),
        Case::Restarted => RESTARTED.to_vec(),
        Case::Roam => ROAM.to_vec(),
        Case::Follow => FOLLOW.to_vec(),
        Case::Switch => SWITCH.to_vec(),
        Case::ReleaseKept | Case::ReleaseUnkept => RELEASE.to_vec(),
        Case::RemoveEnded
        | Case::RemoveOrphaned
        | Case::RemoveDisconnect
        | Case::RemoveDead
        | Case::RemoveAdmin => REMOVE.to_vec(),
    }
}

/// Each transition's plan is the statements its sites ran, in their order:
/// a promotion's tail, a replacement's removal then its promotion, a move's
/// and a kept crossing's tails, a restart's reset, a roam's, a followed,
/// switched and released path's, and a removal's tail. A swap of any two is a
/// change of behaviour.
#[test]
fn the_plan_of_each_transition_is_its_statements_in_their_order() {
    let wrong: Vec<String> = CASES
        .iter()
        .filter_map(|case| {
            let want: Vec<Effect> = statements(*case).iter().map(|(e, _)| *e).collect();
            let got = plan(&transition(*case));
            (got != want.as_slice()).then(|| format!("{case:?}: plan {got:?}, statements {want:?}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "defect: a transition's effects are not its statements in their order:\n{}",
        wrong.join("\n")
    );
}

/// Every transition runs a list, but a cutover, whose statements stay at the
/// rekey handler. A new transition does not compile until `plan` gives it a
/// list.
#[test]
fn the_plan_has_a_list_for_every_transition() {
    let wrong: Vec<String> = CASES
        .iter()
        .filter_map(|case| {
            let t = transition(*case);
            let empty = plan(&t).is_empty();
            let cutover = matches!(t, Transition::Cutover { .. });
            (empty != cutover).then(|| format!("{case:?}: {} effects", plan(&t).len()))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "defect: a transition with no list, or a cutover with one:\n{}",
        wrong.join("\n")
    );
}

/// No effect is declared that no transition runs.
#[test]
fn every_effect_is_in_some_list() {
    let unused: Vec<Effect> = Effect::ALL
        .iter()
        .copied()
        .filter(|e| !CASES.iter().any(|c| plan(&transition(*c)).contains(e)))
        .collect();
    assert_eq!(
        unused,
        Vec::<Effect>::new(),
        "defect: an effect no transition's plan names"
    );
}

/// A failed tree announce logs the line its transition's sites wrote: a
/// promotion's and a replacement's the initial announce's, a crossing's the
/// one after its resolution, and a restart's its own. A transition that
/// sends no announce has no line.
#[test]
fn each_announcing_transition_logs_its_own_failure_line() {
    let wrong: Vec<String> = CASES
        .iter()
        .filter_map(|case| {
            let want = match case {
                Case::PromoteInitiator
                | Case::PromoteResponder
                | Case::ReplaceRestart
                | Case::ReplaceReplacement
                | Case::ReplaceOwnRestart => Some("Failed to send initial TreeAnnounce"),
                Case::MoveCrossing
                | Case::MoveOwn
                | Case::MoveCrossingRefused
                | Case::MoveOwnRefused
                | Case::Keep => {
                    Some("Failed to send TreeAnnounce after cross-connection resolution")
                }
                Case::Restarted => Some("Failed to send TreeAnnounce"),
                Case::CutoverInitiator
                | Case::CutoverResponder
                | Case::Roam
                | Case::Follow
                | Case::Switch
                | Case::ReleaseKept
                | Case::ReleaseUnkept
                | Case::RemoveEnded
                | Case::RemoveOrphaned
                | Case::RemoveDisconnect
                | Case::RemoveDead
                | Case::RemoveAdmin => None,
            };
            let t = transition(*case);
            let announces = plan(&t).contains(&Effect::TreeAnnounce);
            let got = announce_line(&t);
            (got != want || announces != want.is_some())
                .then(|| format!("{case:?}: line {got:?}, announces {announces}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "defect: a transition's announce failure line is not its sites':\n{}",
        wrong.join("\n")
    );
}

#[test]
fn the_plan_denies_wildcard_arms_and_the_scan_finds_a_planted_one() {
    for (name, source, anchor, arm) in SCANNED {
        wildcard_scans(name, &with_lf(source), anchor, arm);
    }
}

#[test]
fn the_wildcard_scans_of_the_plan_hold_on_a_source_checked_out_with_crlf_line_endings() {
    for (name, source, anchor, arm) in SCANNED {
        let crlf = with_lf(source).replace('\n', "\r\n");
        assert!(
            crlf.contains(&anchor.replace('\n', "\r\n")),
            "precondition: a copy of {name} with CRLF line endings"
        );
        wildcard_scans(name, &with_lf(&crlf), anchor, arm);
    }
}

/// The files the wildcard scans read: each one's name, its source, the line
/// a catch-all arm is planted after, and that arm.
const SCANNED: [(&str, &str, &str, &str); 2] = [
    (
        "exec/plan.rs",
        include_str!("../exec/plan.rs"),
        "        Transition::Remove { .. } => REMOVE,\n",
        "        _ => &[],\n",
    ),
    (
        "exec/mod.rs",
        include_str!("../exec/mod.rs"),
        "            Effect::Reconnect => remove::reconnect(self, r).await,\n",
        "            _ => {}\n",
    ),
];

/// That `source`, the file `name` as read, denies wildcard arms and holds
/// none, and that the scans find `arm` planted after `anchor` and the deny
/// taken away.
fn wildcard_scans(name: &str, source: &str, anchor: &str, arm: &str) {
    assert!(
        denies_wildcards(source),
        "defect: {name} does not deny wildcard arms at its head"
    );
    assert_eq!(
        wildcard_arms(source),
        Vec::<String>::new(),
        "defect: a catch-all arm in {name}"
    );

    assert_eq!(source.matches(anchor).count(), 1, "{name} holds the anchor");
    let planted = source.replacen(anchor, &format!("{anchor}{arm}"), 1);
    assert_eq!(
        wildcard_arms(&planted).len(),
        1,
        "defect: the scan missed a planted catch-all arm in {name}"
    );
    let undenied = source.replacen("#![deny(clippy::wildcard_enum_match_arm)]", "", 1);
    assert!(
        !denies_wildcards(&undenied),
        "defect: the scan missed the deny taken away in {name}"
    );
}
