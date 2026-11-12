//! The explorer: each named start's script on a real pair, then each single
//! variation of it, and the heal that ends every path at a leaf.
//!
//! A variation acts on one handshake packet the script names: the packet a
//! `Step::Handshake` at position `i` would hand over is dropped, handed
//! over twice, or swapped with the next packet of its class held at the
//! same node, and the rest of the script runs after it. The script's steps
//! before `i` run as written; a step after it that names a packet the
//! variation took away is skipped. So a start of `n` handshake steps has
//! one scripted path and up to `3n` varied ones; a swap needs a second
//! packet of the class held, and is not a path where none is.

use super::super::super::spanning_tree::cleanup_nodes;
use super::super::super::*;
use super::script::{Kind, Step, run};
use super::starts::{Clause, NOT_RUN, Order, PINS, Reach, Start, starts};
use super::world::{Medium, World};
use std::future::Future;
use std::sync::{Arc, Mutex};

/// What a variation does to the packet a handshake step names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Vary {
    /// The packet is lost.
    Drop,
    /// A copy is handed over first; then the step hands the packet over.
    Duplicate,
    /// It changes places with the next packet of its class at that node;
    /// then the step hands over what is now in its place.
    Swap,
}

/// A path through a start: the script as written, or with one variation at
/// the handshake step at a position of the script.
pub(super) type Path = Option<(usize, Vary)>;

/// Every path of `start`, the scripted one first, then each variation at
/// each handshake step in order.
pub(super) fn paths(start: &Start) -> Vec<Path> {
    let mut out = vec![None];
    for (i, step) in start.script.iter().enumerate() {
        if matches!(step, Step::Handshake { .. }) {
            for vary in [Vary::Drop, Vary::Duplicate, Vary::Swap] {
                out.push(Some((i, vary)));
            }
        }
    }
    out
}

/// The most time a leaf's heal lets pass before every pair of the start
/// holds each other on one session, in 1 s steps: short of the 30 s
/// handshake and link-dead timeouts, so a split is judged before either
/// reaps it, and past the 15 s heard floor, so a restarted node's dial can
/// be answered.
pub(super) const LEAF_SECS: usize = 25;

/// The most time a leaf's heal lets pass once every pair agrees, while a
/// node still has a dial in progress: past the 30 s handshake timeout, so
/// a dial nobody answers ends.
pub(super) const DIAL_SECS: usize = 31;

/// Whether node `at` holds its `nth` packet of class `kind`. Over a
/// connection-oriented transport a packet may still be on its way, so this
/// waits up to half a second for it.
async fn holds(world: &mut World, medium: Medium, at: usize, kind: Kind, nth: usize) -> bool {
    for _ in 0..50 {
        if world.held(at, kind) > nth {
            return true;
        }
        if medium == Medium::Loopback {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// A world for `start` with multipath set as `on`, built to the start's
/// state, with each node's decrypt-worker pool started first where the
/// start runs one.
pub(super) async fn built(start: &Start, order: Order, on: bool) -> World {
    build(
        World::new(start.medium, start.nodes, on).await,
        start,
        order,
    )
    .await
}

/// `world`, new, built to `start`'s state in `order`.
pub(super) async fn build(mut world: World, start: &Start, order: Order) -> World {
    for _ in 1..start.transports {
        world.add_transport();
    }
    #[cfg(unix)]
    if let Some(lag) = start.workers {
        use crate::node::decrypt_worker::DecryptWorkerPool;
        for tn in world.nodes.iter_mut() {
            tn.node.supervisor.decrypt_workers = Some(if lag.is_zero() {
                DecryptWorkerPool::spawn(1)
            } else {
                DecryptWorkerPool::slowed(1, lag)
            });
        }
    }
    let build: Vec<Step> = start.build.iter().map(|s| order.step(*s)).collect();
    run(&mut world, &build).await;
    world
}

/// Run `path` of `start` in `order` with multipath set as `on`, up to its
/// leaf, before the heal. `None` when the path is not one: a swap with no
/// second packet of its class held. The scripted steps before a variation
/// must find what they name; a missing packet there is a broken start,
/// and fails as a precondition.
pub(super) async fn walk(start: &Start, order: Order, on: bool, path: Path) -> Option<World> {
    walk_from(built(start, order, on).await, start, order, path).await
}

/// [`walk`] on `world`, already built to `start`'s state in `order`.
pub(super) async fn walk_from(
    mut world: World,
    start: &Start,
    order: Order,
    path: Path,
) -> Option<World> {
    for (i, step) in start.script.iter().enumerate() {
        let step = order.step(*step);
        let Step::Handshake { to, kind, nth } = step else {
            run(&mut world, &[step]).await;
            continue;
        };
        match path {
            Some((at, vary)) if at == i => {
                assert!(
                    holds(&mut world, start.medium, to, kind, nth).await,
                    "precondition: {} ({order:?}) holds the packet step {i} names",
                    start.name
                );
                if vary == Vary::Swap && !holds(&mut world, start.medium, to, kind, nth + 1).await {
                    cleanup_nodes(&mut world.nodes).await;
                    return None;
                }
                let other = match vary {
                    Vary::Drop => Step::Drop { to, kind, nth },
                    Vary::Duplicate => Step::Duplicate { to, kind, nth },
                    Vary::Swap => Step::Swap { to, kind, nth },
                };
                run(&mut world, &[other]).await;
                if vary != Vary::Drop {
                    run(&mut world, &[step]).await;
                }
            }
            Some((at, _)) if at < i => {
                if holds(&mut world, start.medium, to, kind, nth).await {
                    run(&mut world, &[step]).await;
                }
            }
            _ => {
                run(&mut world, &[step]).await;
            }
        }
    }
    Some(world)
}

/// Whether nodes `a` and `b` of `world` hold each other on one session,
/// each end's index the other's peer index.
fn agree(world: &World, a: usize, b: usize) -> bool {
    let at = |x: usize, y: usize| {
        world.nodes[x]
            .node
            .get_peer(world.nodes[y].node.node_addr())
            .map(|p| (p.our_index(), p.their_index()))
    };
    matches!(
        (at(a, b), at(b, a)),
        (Some((ao, at)), Some((bo, bt))) if ao.is_some() && ao == bt && at == bo
    )
}

/// Whether node `at` of `world` has a dial in progress: a pending transport
/// connect or a msg1 out.
fn dialing(world: &World, at: usize) -> bool {
    let node = &world.nodes[at].node;
    !node.pending_outbound.is_empty() || !node.peering.pending_connects.is_empty()
}

/// Whether node `at` of `world` still waits for a connection a held peer's
/// path machine asked for, which the path tick settles and then probes.
fn opening(world: &World, at: usize) -> bool {
    let node = &world.nodes[at].node;
    node.peers
        .keys()
        .any(|p| !node.paths.connects(p).is_empty())
}

/// Heal a leaf. Everything sent is handed over; then, until every pair of
/// the start holds each other on one session, each dialer of the start
/// holding neither its peer nor a dial in progress dials again, as a
/// configured peer is redialed, and time moves on a second, for at most
/// [`LEAF_SECS`]. Once every pair agrees, time moves on a second at a time
/// while any node still has a dial in progress, or a connection a path
/// machine asked for still opening, for at most [`DIAL_SECS`], every pair
/// still agreeing after each delivery. Returns whether the nodes went quiet
/// with every pair held on one session and no dial or path connection left.
pub(super) async fn heal(world: &mut World, start: &Start, order: Order) -> bool {
    let pairs = start.pairs(order);
    let dials = start.dials(order);
    let mut agreed: Option<usize> = None;
    for round in 0..=LEAF_SECS + DIAL_SECS {
        if !world.heal().await {
            return false;
        }
        let all = pairs.iter().all(|&(a, b)| agree(world, a, b));
        match (agreed, all) {
            (None, true) => agreed = Some(round),
            (Some(_), false) => return false,
            (None, false) if round >= LEAF_SECS => return false,
            (None, false) => {
                for &(from, to, transport) in &dials {
                    let held = world.nodes[from]
                        .node
                        .get_peer(world.nodes[to].node.node_addr())
                        .is_some();
                    if !held && !dialing(world, from) {
                        world.dial(from, to, transport).await;
                    }
                }
            }
            (Some(_), true) => {}
        }
        if let Some(at) = agreed {
            if !(0..world.nodes.len()).any(|i| dialing(world, i) || opening(world, i)) {
                return true;
            }
            if round >= at + DIAL_SECS {
                return false;
            }
        }
        world.advance(1_000).await;
    }
    false
}

/// The starts that run on `medium`.
pub(super) fn carried(medium: Medium) -> Vec<Start> {
    starts()
        .into_iter()
        .filter(|s| s.medium == medium)
        .collect()
}

/// One walk of a start: the start, its order and the multipath setting.
pub(super) type Job = (Start, Order, bool);

/// Every start on `medium` in both orders, at each setting in `settings`.
pub(super) fn jobs(medium: Medium, settings: &[bool]) -> Vec<Job> {
    let mut out = Vec::new();
    for &on in settings {
        for start in carried(medium) {
            for order in Order::BOTH {
                out.push((start, order, on));
            }
        }
    }
    out
}

/// The stack of a walk's thread.
const WALK_STACK: usize = 8 * 1024 * 1024;

/// Run `f` on each job, each on a thread of its own with its own runtime,
/// and so its own test clock, side by side, and return what they found. A
/// job names the path it is on in the string it is given; a panic in a
/// job, the node's live audit among them, is returned as a finding against
/// that path, and one marked `precondition` fails here as itself.
pub(super) fn parallel<F, Fut>(jobs: Vec<Job>, f: F) -> Vec<String>
where
    F: Fn(Job, Arc<Mutex<String>>) -> Fut + Send + Copy + 'static,
    Fut: Future<Output = Vec<String>>,
{
    let mut runs = Vec::new();
    for job in jobs {
        let at = Arc::new(Mutex::new(String::new()));
        let seen = Arc::clone(&at);
        // A walk runs a node's handlers to their full depth in a debug
        // build, which on the loopback starts alone comes within a few per
        // cent of the default 2 MiB thread stack, so each walk takes more.
        let run = std::thread::Builder::new()
            .stack_size(WALK_STACK)
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("precondition: a runtime for the walk")
                    .block_on(f(job, seen))
            })
            .expect("precondition: a thread for the walk");
        runs.push((run, at));
    }
    let mut found = Vec::new();
    for (run, at) in runs {
        match run.join() {
            Ok(more) => found.extend(more),
            Err(panic) => {
                let msg = panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                let at = at.lock().map(|s| s.clone()).unwrap_or_default();
                assert!(!msg.starts_with("precondition"), "{msg} ({at})");
                found.push(format!("{at}: a panic: {msg}"));
            }
        }
    }
    found
}

/// A path, as a finding names it.
pub(super) fn named(start: &Start, order: Order, on: bool, path: Path) -> String {
    let how = match path {
        None => "as scripted".to_string(),
        Some((at, vary)) => format!("{vary:?} at step {at} ({:?})", start.script[at]),
    };
    format!(
        "start {} {} ({order:?}, multipath on {on}), {how}",
        start.number, start.name
    )
}

// ---------------------------------------------------------------------------
// The explorer's own tests
// ---------------------------------------------------------------------------

/// Every `fips-mesh` known-defect line of the inventory is in the map once,
/// at its setting, and the map holds no other; each start it names runs on
/// this build or is the BLE start of a build with no BLE transport, and
/// names a node its world holds; every named start number of the core's,
/// 1 to 14, is run here or listed as not run, with a reason.
#[test]
fn every_pinned_defect_of_the_node_is_mapped_to_a_start_or_to_none() {
    let inventory = include_str!("../../../../../testing/ignored-tests.txt");
    let pinned: Vec<&str> = inventory
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() == 4 && f[0] == "known-defect" && f[1] == "fips-mesh").then(|| f[2])
        })
        .collect();
    let all = starts();
    let mut bad = Vec::new();
    for name in &pinned {
        if PINS.iter().filter(|(n, _, _)| n == name).count() != 1 {
            bad.push(format!("{name}: not in the map once"));
        }
    }
    for (name, on, reach) in PINS {
        if !pinned.contains(name) {
            bad.push(format!("{name}: mapped, and no known-defect line"));
        }
        if name.ends_with("_with_multipath_on") && !on {
            bad.push(format!("{name}: mapped at multipath off"));
        }
        match reach {
            Reach::Start {
                name: start,
                order,
                clause,
                node,
            } => match all.iter().find(|s| s.name == *start) {
                Some(s) if node.is_none_or(|n| n < s.nodes) => {
                    let bare = name.trim_end_matches("_with_multipath_on");
                    let larger = bare.ends_with("larger_first") || bare.ends_with("larger_dialer");
                    if larger != (*order == Order::Larger) {
                        bad.push(format!("{name}: mapped in the order {order:?}"));
                    }
                    if (*clause == Clause::RightLink) != node.is_some() {
                        bad.push(format!("{name}: {clause:?} at node {node:?}"));
                    }
                }
                Some(_) => bad.push(format!("{name}: {start} holds no node {node:?}")),
                None if cfg!(not(ble_available)) && *start == "crossing, BLE" => {}
                None => bad.push(format!("{name}: no start {start}")),
            },
            Reach::None("") => bad.push(format!("{name}: no reason")),
            Reach::None(_) => {}
        }
    }
    for number in 1..=14u8 {
        let run =
            all.iter().any(|s| s.number == number) || (number == 4 && cfg!(not(ble_available)));
        let listed = NOT_RUN
            .iter()
            .any(|(n, why)| *n == number && !why.is_empty());
        if run == listed {
            bad.push(format!(
                "start {number}: run {run}, listed as not run {listed}"
            ));
        }
    }
    assert!(bad.is_empty(), "defect: {bad:#?}");
}

/// Walk every path of `start` in `order` with multipath set as `on` to its
/// leaf, healing none, and say what is wrong with its reach: a number of
/// paths walked other than the start's stated one. A scripted step that
/// finds nothing fails as a precondition inside `walk`.
async fn reached((start, order, on): Job, at: Arc<Mutex<String>>) -> Vec<String> {
    let mut walked = 0;
    for path in paths(&start) {
        *at.lock().expect("precondition: the path's name") = named(&start, order, on, path);
        if let Some(mut world) = walk(&start, order, on, path).await {
            walked += 1;
            cleanup_nodes(&mut world.nodes).await;
        }
    }
    if walked == start.reach {
        Vec::new()
    } else {
        vec![format!(
            "start {} {} ({order:?}, multipath on {on}): {walked} paths walked, {} stated",
            start.number, start.name, start.reach
        )]
    }
}

/// Every start reaches its target: on every transport, in both orders and
/// at both settings, its scripted path runs every step to the end of its
/// script, and the explorer walks the number of paths the start states, its
/// scripted path and each variation that applies.
#[test]
fn the_explorer_reaches_each_starts_target() {
    let mut all = jobs(Medium::Loopback, &[false, true]);
    all.extend(jobs(Medium::Tcp, &[false, true]));
    #[cfg(ble_available)]
    all.extend(jobs(Medium::Ble, &[false, true]));
    let bad = parallel(all, reached);
    assert!(bad.is_empty(), "defect: {bad:#?}");
}
