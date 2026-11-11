//! What the explorer checks at each leaf, and its tests over the starts.
//!
//! Every path ends in a heal (`explore::heal`), and then:
//!
//! - through `settle::settled`: the two nodes of every pair the start
//!   dials hold each other on one session that carries a heartbeat each way;
//! - through the shell audit (`settle::audit::audit`): one
//!   session and nothing left unadoptable, the right link record, the maps
//!   agreeing, every open connection in use;
//! - the node's live audit, inherited: in a debug build every packet a node
//!   is handed runs it, and a breach panics there, naming its clause.
//!
//! Each peer change of each start's scripted path, healed, is held against
//! the reference model's transition (`model.rs`), on its own test. Each
//! msg1's class against the model's is not checked here.

#[cfg(unix)]
use super::super::super::link_index_audit;
use super::super::super::spanning_tree::cleanup_nodes;
use super::super::audit::{Breach, audit};
use super::super::settled;
use super::explore::{Job, build, heal, jobs, named, parallel, paths, walk, walk_from};
use super::model::Tap;
#[cfg(unix)]
use super::starts::pooled;
use super::starts::{Clause, Order, PINS, Reach, Start, starts};
use super::world::{Medium, World};
use std::sync::{Arc, Mutex};

/// What an oracle found at a leaf.
#[derive(Debug)]
pub(super) struct Finding {
    /// The clause that broke.
    pub(super) clause: Clause,
    /// The node whose maps show it, in the world's indices, where the
    /// clause names one.
    pub(super) node: Option<usize>,
    /// What was seen.
    pub(super) what: String,
}

/// The clause a breach of the shell audit breaks.
fn clause(breach: &Breach) -> Clause {
    match breach {
        Breach::Split { .. } | Breach::OneSided { .. } => Clause::Split,
        Breach::Unadoptable { .. } => Clause::Unadoptable,
        Breach::RightLink { .. } => Clause::RightLink,
        Breach::MapsAgree { .. } => Clause::MapsAgree,
        Breach::ConnectionsInUse { .. } | Breach::Unconnected { .. } => Clause::ConnectionsInUse,
    }
}

/// Heal `world`, a leaf of `start` in `order`, and check it: every pair the
/// start dials is settled, then the shell audit. Every finding, in that
/// order.
pub(super) async fn judge(world: &mut World, start: &Start, order: Order) -> Vec<Finding> {
    let mut out = Vec::new();
    if !heal(world, start, order).await {
        out.push(Finding {
            clause: Clause::Quiet,
            node: None,
            what: "the heal ended with a pair not held on one session, or the nodes still sending"
                .to_string(),
        });
    }
    for (a, b) in start.pairs(order) {
        if let Err(e) = settled(&mut world.nodes, a, b).await {
            out.push(Finding {
                clause: Clause::Settled,
                node: None,
                what: format!("nodes {a} and {b}: {e}"),
            });
        }
    }
    for breach in audit(&mut world.nodes).await {
        out.push(Finding {
            clause: clause(&breach),
            node: Some(breach.node()),
            what: format!("{breach:?}"),
        });
    }
    out
}

/// Every path of `start` in `order`, with multipath set as `on`: what
/// breaks at each leaf, but for the clauses the start names as pinned.
/// `at` names the path being walked.
async fn walked((start, order, on): Job, at: Arc<Mutex<String>>) -> Vec<String> {
    let mut bad = Vec::new();
    for path in paths(&start) {
        let name = named(&start, order, on, path);
        *at.lock().expect("precondition: the path's name") = name.clone();
        let Some(mut world) = walk(&start, order, on, path).await else {
            continue;
        };
        let found = judge(&mut world, &start, order).await;
        cleanup_nodes(&mut world.nodes).await;
        for f in found {
            if !start.pinned.contains(&f.clause) {
                bad.push(format!(
                    "{name}: {:?} at node {:?}: {}",
                    f.clause, f.node, f.what
                ));
            }
        }
    }
    bad
}

/// Every path of every start on `medium`, in both orders, with multipath
/// set as `on`, keeps every property at its leaf, but for the clauses a
/// start names as pinned. Each start and order runs on a thread of its own,
/// side by side (`parallel`).
fn properties(medium: Medium, on: bool) {
    let bad = parallel(jobs(medium, &[on]), walked);
    assert!(bad.is_empty(), "defect: on {medium:?}: {bad:#?}");
}

#[test]
fn every_named_start_keeps_its_properties_on_a_real_pair_on_loopback() {
    properties(Medium::Loopback, false);
}

#[test]
fn every_named_start_keeps_its_properties_on_a_real_pair_on_loopback_with_multipath_on() {
    properties(Medium::Loopback, true);
}

#[test]
fn every_named_start_keeps_its_properties_on_a_real_pair_on_tcp() {
    properties(Medium::Tcp, false);
}

#[test]
fn every_named_start_keeps_its_properties_on_a_real_pair_on_tcp_with_multipath_on() {
    properties(Medium::Tcp, true);
}

#[cfg(ble_available)]
#[test]
fn every_named_start_keeps_its_properties_on_a_real_pair_on_ble() {
    properties(Medium::Ble, false);
}

#[cfg(ble_available)]
#[test]
fn every_named_start_keeps_its_properties_on_a_real_pair_on_ble_with_multipath_on() {
    properties(Medium::Ble, true);
}

/// Every path of `start` in `order` with multipath set as `on`, a start
/// whose nodes run a decrypt-worker pool: what breaks at each leaf. The
/// leaf is healed, and then every node's decrypt workers must hold every
/// current session it has (`link_index_audit::audit`, which panics on a
/// breach, and `parallel` reports the panic against the path). The number
/// of paths walked must be the start's stated reach.
///
/// The shell audit and `settle::settled` are not run here: their
/// heartbeats are delivered by `settle::pump`, which hands a frame to the
/// node and never drains the node's decrypt results, so on a pooled node a
/// heartbeat under a delegated session is never counted. Those properties
/// of the crossing are the property tests', on start 1 with no pool.
#[cfg(unix)]
async fn offers((start, order, on): Job, at: Arc<Mutex<String>>) -> Vec<String> {
    let mut bad = Vec::new();
    let mut walked = 0;
    for path in paths(&start) {
        let name = named(&start, order, on, path);
        *at.lock().expect("precondition: the path's name") = name.clone();
        let Some(mut world) = walk(&start, order, on, path).await else {
            continue;
        };
        walked += 1;
        assert!(
            world
                .nodes
                .iter()
                .all(|tn| tn.node.supervisor.decrypt_workers.is_some()),
            "precondition: every node runs a decrypt-worker pool"
        );
        if heal(&mut world, &start, order).await {
            for (i, tn) in world.nodes.iter().enumerate() {
                link_index_audit::audit(&tn.node, &format!("{name}, node {i}"));
            }
        } else {
            bad.push(format!(
                "{name}: the heal ended with a pair not held on one session, or the nodes still sending"
            ));
        }
        cleanup_nodes(&mut world.nodes).await;
    }
    if walked != start.reach {
        bad.push(format!(
            "start {} {} ({order:?}, multipath on {on}): {walked} paths walked, {} stated",
            start.number, start.name, start.reach
        ));
    }
    bad
}

/// Every path of the crossing with a decrypt-worker pool at each node
/// (`starts::pooled`), in both orders, with multipath set as `on`, heals to
/// one session per pair with every node's current session held by its
/// workers: the session a crossing moves its peer onto is offered to the
/// workers when the moved machine is built, as a promotion's is.
#[cfg(unix)]
fn offered(on: bool) {
    let start = pooled();
    let jobs = Order::BOTH
        .iter()
        .map(|&order| (start, order, on))
        .collect();
    let bad = parallel(jobs, offers);
    assert!(
        bad.is_empty(),
        "defect: on the crossing with the worker pool: {bad:#?}"
    );
}

#[cfg(unix)]
#[test]
fn a_crossing_with_the_worker_pool_started_offers_the_moved_session() {
    offered(false);
}

#[cfg(unix)]
#[test]
fn a_crossing_with_the_worker_pool_started_offers_the_moved_session_with_multipath_on() {
    offered(true);
}

/// Each pinned defect the map gives a start is found there: the start's
/// scripted path, in the pin's order and at its setting, healed and checked,
/// breaks the pin's clause at the pin's node.
/// Each start, order and setting runs once for all the pins it holds.
#[tokio::test]
async fn the_explorer_finds_each_pinned_defect_at_its_oracle() {
    let all = starts();
    let mut runs: Vec<(&str, Order, bool)> = Vec::new();
    for (_, on, reach) in PINS {
        if let Reach::Start { name, order, .. } = *reach
            && all.iter().any(|s| s.name == name)
            && !runs.contains(&(name, order, *on))
        {
            runs.push((name, order, *on));
        }
    }
    let mut missed = Vec::new();
    for (name, order, on) in runs {
        let start = all
            .iter()
            .find(|s| s.name == name)
            .expect("precondition: the start is run on this build");
        let mut world = walk(start, order, on, None)
            .await
            .expect("precondition: the scripted path is a path");
        let found = judge(&mut world, start, order).await;
        cleanup_nodes(&mut world.nodes).await;
        for (pin, pinned_on, reach) in PINS {
            let Reach::Start {
                name: at,
                order: in_order,
                clause,
                node,
            } = *reach
            else {
                continue;
            };
            if at != name || in_order != order || *pinned_on != on {
                continue;
            }
            if !found
                .iter()
                .any(|f| f.clause == clause && node.is_none_or(|n| f.node == Some(n)))
            {
                missed.push(format!(
                    "{pin}: no {clause:?} at node {node:?} on {name} ({order:?}, multipath on {on}); found {found:#?}"
                ));
            }
        }
    }
    assert!(
        missed.is_empty(),
        "defect: the explorer did not find a pinned defect: {missed:#?}"
    );
}

/// `start`'s scripted path in `order`, with multipath set as `on`, healed,
/// with the reference model beside the world from its first step: each
/// change the model makes to a peer that the node did not make as the
/// model's transition says.
async fn traced((start, order, on): Job, at: Arc<Mutex<String>>) -> Vec<String> {
    let name = named(&start, order, on, None);
    *at.lock().expect("precondition: the path's name") = name.clone();
    let mut world = World::new(start.medium, start.nodes, on).await;
    let addrs = world.nodes.iter().map(|tn| *tn.node.node_addr()).collect();
    world.tap = Some(Tap::new(start.medium, addrs));
    let world = build(world, &start, order).await;
    let mut world = walk_from(world, &start, order, None)
        .await
        .expect("precondition: the scripted path is a path");
    // The leaf's properties are the property tests'; this one reads only
    // what each change did on the way there.
    heal(&mut world, &start, order).await;
    let tap = world.tap.take().expect("the tap was set");
    cleanup_nodes(&mut world.nodes).await;
    tap.verdict(&name)
}

/// Every start on every transport, in both orders, with multipath set as
/// `on`: each change the reference model makes to a peer, the node makes
/// over the same packet or rekey poll as the model's transition says.
fn modelled(on: bool) {
    let mut all = jobs(Medium::Loopback, &[on]);
    all.extend(jobs(Medium::Tcp, &[on]));
    #[cfg(ble_available)]
    all.extend(jobs(Medium::Ble, &[on]));
    let bad = parallel(all, traced);
    assert!(
        bad.is_empty(),
        "defect: a peer change does not do what the model's transition says: {bad:#?}"
    );
}

#[test]
fn each_peer_change_of_a_named_start_does_what_the_models_transition_says() {
    modelled(false);
}

#[test]
fn each_peer_change_of_a_named_start_does_what_the_models_transition_says_with_multipath_on() {
    modelled(true);
}
