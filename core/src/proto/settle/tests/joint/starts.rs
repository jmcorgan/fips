//! The joint world's starts: the stand-in's named starts with joint nodes
//! at both ends, at Off with Off and at On with On; the start with two
//! paths rebuilt on real bundles; and the starts only joint nodes run,
//! each built mid-history on real bundles, with the tests that show each.
//!
//! A stand-in start keeps its script; only its nodes change. A start on
//! real bundles runs the capability exchange in its build, so at On with
//! On its link holds two Live paths and both ends are capable, and at any
//! other pairing the link keeps its one path. A mixed pairing names node
//! 0's setting first; every other node has the second, so start 11's third
//! node is at the second setting.

use alloc::vec::Vec;

use crate::proto::path::Source;
use crate::proto::settle::links::Proven;

use super::super::super::model::history::{Addr, Event, Node};
use super::super::explore::{Act, SMALL};
use super::super::shadow::Entry;
use super::super::starts::{
    A, B, BLE, Build, Do, Maker, Start, TCP, UDP, Want, at, dial_home, home, pair, run, second,
    settle, starts as named,
};
use super::super::world::{Input, Ms, PathEv, Pkt, State, World};

/// Every named start with joint nodes at Off at both ends.
pub fn off() -> Vec<Start> {
    with(super::off)
}

/// Every named start with joint nodes at On at both ends.
pub fn on() -> Vec<Start> {
    with(super::on)
}

/// Every named start with nodes made by `maker`: the stand-in's starts,
/// the start with two paths rebuilt on real bundles, and the starts only
/// joint nodes run.
fn with(maker: Maker) -> Vec<Start> {
    named()
        .into_iter()
        .map(|mut st| {
            if st.number == 12 {
                st.build = two;
                st.script = two_script;
            }
            st
        })
        .chain(added())
        .map(|mut st| {
            st.maker = maker;
            st
        })
        .collect()
}

/// The starts only joint nodes run, each built on real bundles: their
/// nodes are set per pairing.
fn added() -> Vec<Start> {
    let s = |number, name, build: Build, script: Script| Start {
        number,
        name,
        build,
        script,
        maker: super::off,
        budget: SMALL,
        wall: false,
        forged: false,
    };
    alloc::vec![
        s(
            15,
            "crossing while capability probes are out",
            probing,
            probing_script
        ),
        s(
            16,
            "restart on a two-path link",
            restarted,
            restarted_script
        ),
        s(17, "late second dial at a capable peer", late, late_script),
        s(
            18,
            "a dial's leg reaped beside a dial sharing its BLE connection",
            shared,
            shared_script
        ),
        s(
            20,
            "carrier loss of the active path",
            carrier,
            carrier_script
        ),
        s(
            21,
            "the only path's transport removed",
            removed,
            removed_script
        ),
        s(
            22,
            "a NAT rebound of the second path",
            rebound,
            rebound_script
        ),
        s(23, "a path removed at the peer", released, released_script),
        s(
            25,
            "a NAT rebound of the active path",
            rehomed,
            rebound_script
        ),
    ]
}

/// A start's script.
type Script = fn(&mut World) -> Vec<Act>;

/// Whether each node of `w` holds the other on a link of two Live paths.
pub fn doubled(w: &World) -> bool {
    (0..2).all(|x| {
        w.parties[x].joint().is_some_and(|f| {
            f.peers.iter().any(|p| {
                p.shell.as_ref().is_some_and(|s| {
                    s.paths.len() == 2 && s.paths.iter().all(|(_, st)| *st == Proven::Live)
                })
            })
        })
    })
}

/// Run `w` wake by wake until `done` holds or the next wake is past
/// `until`, opening after each wake every connect window but those of the
/// connections `held` and delivering what is in flight: everything, or
/// with `frames` only frames and end-of-stream notices, so a handshake
/// message is lost at the next wake. What waits in a held connect window
/// stays there, so a dial left in one is still out when the walk ends.
pub fn walk(w: &mut World, held: &[u32], until: Ms, frames: bool, done: fn(&World) -> bool) {
    loop {
        for _ in 0..256 {
            let opening: Vec<u32> = w
                .net
                .conns
                .iter()
                .filter(|c| c.state == State::Connecting && !held.contains(&c.id))
                .map(|c| c.id)
                .collect();
            for c in &opening {
                w.connected(*c, true);
            }
            let next = w
                .net
                .flight
                .iter()
                .find(|f| w.net.deliverable(f) && !(frames && f.pkt.handshake()))
                .map(|f| f.id);
            match next {
                Some(id) => w.deliver(id),
                None if opening.is_empty() => break,
                None => {}
            }
        }
        if done(w) {
            return;
        }
        match w.wake() {
            Some(t) if t <= until => w.advance(),
            Some(_) | None => return,
        }
    }
}

/// Node `x` of `w` hears of its peer at `at`, reached from `from`, from a
/// feed other than its configuration and the frames it hears: the start
/// of the capability exchange.
fn heard(w: &mut World, x: usize, at: Addr, from: Option<Addr>) {
    let peer = w.ids[1 - x];
    w.input(
        x,
        Input::Path(PathEv::Candidate {
            peer,
            at,
            from,
            source: Source::Discovery,
        }),
    );
}

/// [`heard`], then the world run wake by wake until both nodes hold two
/// Live paths, or for two seconds, the connections `held` left in their
/// connect windows. At On with On the two bundles turn capable within a
/// few wakes; at a mixed pairing or at Off they do not, and the link keeps
/// its one path.
fn exchange(w: &mut World, x: usize, at: Addr, from: Option<Addr>, held: &[u32]) {
    heard(w, x, at, from);
    let until = w.net.now + 2_000;
    walk(w, held, until, false, doubled);
}

/// Whether a msg1 to node 0 is in flight.
fn resent(w: &World) -> bool {
    w.net
        .flight
        .iter()
        .any(|f| f.to == 0 && matches!(f.pkt, super::super::world::Pkt::Msg1 { .. }))
}

/// Nodes 0 and 1 made by `mk`, node 0 the smaller and dialing node 1 on
/// UDP, settled: a link of one path.
fn linked(mk: Maker, first: Node) -> World {
    let mut w = pair(mk, first, &[&[(1, UDP)], &[]]);
    dial_home(&mut w, 0, 1, UDP);
    settle(&mut w);
    w
}

/// Start 12 on real bundles: node 0's dial of node 1 on UDP holds, and node
/// 1 dials node 0 again, at its TCP home. Then node 1 hears of node 0 at
/// that address, and its bundle's connection there is the dial's own,
/// already opening; over it the capability exchange gives node 1's link a
/// second path at node 0's TCP home, and node 0's a second path at the
/// address the connection comes from. The dial's msg1 and its resends are
/// lost meanwhile, and the build ends at a resend, in flight: at On with On
/// both ends are capable, and node 1's dial, opened before, is still out
/// and comes from a pair node 0's link holds as a Live path.
fn two(mk: Maker) -> World {
    let mut w = linked(mk, A);
    dial_home(&mut w, 1, 0, TCP);
    heard(&mut w, 1, home(0, TCP), None);
    let until = w.net.now + 3_500;
    walk(&mut w, &[], until, true, |w| doubled(w) && resent(w));
    w
}

fn two_script(w: &mut World) -> Vec<Act> {
    run(w, &[Do::Get(0, Want::Msg1, None)])
}

/// Start 15: start 2's crossing over two transports, node 0 dialing node
/// 1 on UDP and node 1 dialing node 0 on TCP, built as far as node 0's
/// answer to node 1's dial. Node 0 holds node 1 on the inbound TCP link,
/// and at On its bundle, offered node 1's configured UDP home, probes it;
/// node 1 holds nothing yet. So the capability probes are out and neither
/// end is capable when the crossing resolves.
fn probing(mk: Maker) -> World {
    let mut w = pair(mk, A, &[&[(1, UDP)], &[(0, TCP)]]);
    dial_home(&mut w, 0, 1, UDP);
    dial_home(&mut w, 1, 0, TCP);
    run(&mut w, &[Do::Open(1), Do::Get(0, Want::Msg1, None)]);
    w
}

fn probing_script(w: &mut World) -> Vec<Act> {
    run(
        w,
        &[
            Do::Get(1, Want::Msg1, None),
            Do::Get(1, Want::Msg2, None),
            Do::Get(0, Want::Msg2, None),
        ],
    )
}

/// Start 16: a link of node 0's TCP dial, given a second path on UDP by
/// the capability exchange; node 1, configured to dial node 0's UDP home,
/// restarts, and its dial arrives from the pair node 0's second path is
/// at.
fn restarted(mk: Maker) -> World {
    let mut w = pair(mk, A, &[&[(1, TCP)], &[(0, UDP)]]);
    dial_home(&mut w, 0, 1, TCP);
    settle(&mut w);
    exchange(&mut w, 0, home(1, UDP), None, &[]);
    w
}

fn restarted_script(w: &mut World) -> Vec<Act> {
    run(
        w,
        &[Do::Then(Act::Restart(1)), Do::Get(0, Want::Msg1, None)],
    )
}

/// A link of node 0's UDP dial given a second path at node 1's TCP home by
/// the capability exchange, as starts 17, 20 and 23 begin.
fn doubled_link(mk: Maker) -> World {
    let mut w = linked(mk, A);
    exchange(&mut w, 0, home(1, TCP), None, &[]);
    w
}

/// Whether a msg1 from node 0 is in flight or waits in a connect window.
fn dialled(w: &World) -> bool {
    let id = w.ids[0];
    let msg1 = |p: &Pkt| matches!(p, Pkt::Msg1 { id: s, .. } if *s == id);
    w.net.flight.iter().any(|f| msg1(&f.pkt))
        || w.net
            .conns
            .iter()
            .any(|c| c.queued.iter().any(|(_, p)| msg1(p)))
}

/// The world's next wake: the next wake that is not a bundle's where a
/// bundle wakes first, else the next wake.
fn onward(w: &World) -> Act {
    if w.leaps() { Act::Leap } else { Act::Advance }
}

/// Start 17: [`doubled_link`], then node 0 dials node 1 again at its UDP
/// home. At On with On node 1 is capable and its link live, so nothing is
/// sent and the address is a requested candidate. Where node 1 is not
/// capable the dial goes out, a late second dial, and node 1's gates
/// refuse its msg1 as a replacement of a peer heard just now.
fn late(mk: Maker) -> World {
    let mut w = doubled_link(mk);
    dial_home(&mut w, 0, 1, UDP);
    w
}

fn late_script(w: &mut World) -> Vec<Act> {
    if dialled(w) {
        run(w, &[Do::Get(1, Want::Msg1, None)])
    } else {
        let a = onward(w);
        run(w, &[Do::Then(a)])
    }
}

/// Start 20: [`doubled_link`], node 0's UDP transport, its active path's,
/// able to lose carrier and regain it.
fn carrier(mk: Maker) -> World {
    let mut w = doubled_link(mk);
    w.paths = alloc::vec![
        (
            0,
            PathEv::Carrier {
                transport: UDP,
                up: false
            }
        ),
        (
            0,
            PathEv::Carrier {
                transport: UDP,
                up: true
            }
        ),
    ];
    w.used = alloc::vec![false; w.paths.len()];
    w
}

fn carrier_script(w: &mut World) -> Vec<Act> {
    run(w, &[Do::Then(Act::Path(0))])
}

/// Start 21: a link of one path, node 0's dial of node 1 on UDP, node 0
/// configured to dial node 1's TCP home; node 0's UDP transport may be
/// removed, which orphans the link, and node 0 redials on TCP.
fn removed(mk: Maker) -> World {
    let mut w = pair(mk, A, &[&[(1, TCP)], &[]]);
    dial_home(&mut w, 0, 1, UDP);
    settle(&mut w);
    w.paths = alloc::vec![(0, PathEv::Gone { transport: UDP })];
    w.used = alloc::vec![false; w.paths.len()];
    w
}

fn removed_script(w: &mut World) -> Vec<Act> {
    run(w, &[Do::Then(Act::Path(0))])
}

/// Start 22: one transport, UDP, each node's second address bound as the
/// source of a second path: node 0's dial of node 1's home holds, and the
/// capability exchange gives node 0's link a second path at node 1's
/// second address, reached from node 0's own. Then a NAT in front of node
/// 1 rebinds node 1's second address, which node 0 learns of from the
/// next path message node 1 sends on that path.
fn rebound(mk: Maker) -> World {
    let mut w = linked(mk, A);
    exchange(&mut w, 0, second(1, UDP), Some(second(0, UDP)), &[]);
    w.paths = alloc::vec![(
        1,
        PathEv::Rebound {
            from: second(1, UDP),
            to: at(UDP, NAT),
        }
    )];
    w.used = alloc::vec![false; w.paths.len()];
    super::super::explore::apply(&mut w, Act::Path(0));
    w
}

/// The address a NAT rebinds node 1's second address to, or its home.
pub const NAT: u16 = 22;

/// Start 25: start 22's link, but the NAT in front of node 1 rebinds node
/// 1's home, the address of node 0's active path. Node 0's link holds two
/// paths, so no frame roams one; its bundle follows the next path message
/// node 1 sends on that path to the new address, and the peer with it.
fn rehomed(mk: Maker) -> World {
    let mut w = linked(mk, A);
    exchange(&mut w, 0, second(1, UDP), Some(second(0, UDP)), &[]);
    w.paths = alloc::vec![(
        1,
        PathEv::Rebound {
            from: home(1, UDP),
            to: at(UDP, NAT),
        }
    )];
    w.used = alloc::vec![false; w.paths.len()];
    super::super::explore::apply(&mut w, Act::Path(0));
    w
}

fn rebound_script(w: &mut World) -> Vec<Act> {
    let a = onward(w);
    run(w, &[Do::Then(a)])
}

/// Start 23: [`doubled_link`], node 1's TCP transport, its second path's,
/// able to be removed: its bundle releases that path, the peer not
/// sending on it, and tells node 0 over UDP.
fn released(mk: Maker) -> World {
    let mut w = doubled_link(mk);
    w.paths = alloc::vec![(1, PathEv::Gone { transport: TCP })];
    w.used = alloc::vec![false; w.paths.len()];
    w
}

fn released_script(w: &mut World) -> Vec<Act> {
    run(w, &[Do::Then(Act::Path(0))])
}

/// Start 18: node 0 dials node 1 on BLE, and five seconds later again,
/// the second dial sharing the first's connection; everything either
/// sends is lost. The build ends a millisecond before the first dial's
/// deadline, which reaps its leg while the second is still out.
fn shared(mk: Maker) -> World {
    let mut w = pair(mk, A, &[&[], &[]]);
    dial_home(&mut w, 0, 1, BLE);
    let c = w.net.conns[0].id;
    w.connected(c, true);
    w.run_until(SECOND_DIAL);
    dial_home(&mut w, 0, 1, BLE);
    w.run_until(HANDSHAKE_MS - 1);
    w.net.flight.clear();
    w
}

/// When start 18's second dial goes out.
const SECOND_DIAL: Ms = 5_000;

/// The handshake deadline, after which a dial's leg is reaped.
const HANDSHAKE_MS: Ms = super::super::world::HANDSHAKE;

fn shared_script(w: &mut World) -> Vec<Act> {
    run(w, &[Do::Then(Act::Advance)])
}

use super::super::explore::{apply, replay};
use super::super::oracle::{Breach, every_step, heal, healed};

/// Start `number` at On with On.
fn on_start(number: u8) -> Start {
    on().into_iter()
        .find(|s| s.number == number)
        .unwrap_or_else(|| panic!("start {number} runs at On with On"))
}

/// What node `x`'s shell holds for its one held peer.
fn shell(w: &World, x: usize) -> super::oracle::Shell {
    w.parties[x]
        .joint()
        .and_then(|f| f.peers.into_iter().next())
        .and_then(|p| p.shell)
        .unwrap_or_else(|| panic!("node {x} holds a peer with machines"))
}

/// Run `st`'s script from its build, checking every step; then heal and
/// check again. Returns the world after the script, before the heal, and
/// every breach found on the way and after the heal, but the pinned
/// breach of a lapsed path ([`super::explore::lapsed`]).
fn scripted(st: &Start) -> (World, Vec<Breach>) {
    let mut scratch = replay(st, &[]);
    let script = (st.script)(&mut scratch);
    let mut w = replay(st, &[]);
    let mut found = every_step(&w);
    for a in script {
        apply(&mut w, a);
        found.extend(every_step(&w));
    }
    let after = replay(st, &(st.script)(&mut replay(st, &[])));
    heal(&mut w);
    found.extend(every_step(&w));
    found.extend(healed(&w));
    // The pinned finding, exempt: a pair a bundle holds acknowledged and
    // not Live, counted in use with its connection gone.
    found.retain(|b| !super::explore::lapsed(&w, b));
    (after, found)
}

#[test]
fn a_crossing_while_capability_probes_are_out_renews_the_bundle_and_keeps_both_ends_mirrored() {
    let st = on_start(15);
    let w = replay(&st, &[]);
    assert_eq!(
        (w.parties[0].held(), w.parties[1].held()),
        (alloc::vec![B], Vec::new()),
        "precondition: node 0 holds node 1, which holds nothing yet"
    );
    assert_eq!(
        shell(&w, 0).paths,
        [(
            Addr {
                transport: TCP,
                at: super::super::world::EPHEMERAL
            },
            Proven::Live
        )],
        "precondition: node 0's link holds one path, the inbound TCP connection's"
    );
    assert!(
        w.leaps(),
        "precondition: node 0's bundle has a wake of its own: the probe of node 1's configured UDP home"
    );
    let (after, found) = scripted(&st);
    assert!(
        found.is_empty(),
        "both ends stay mirrored through the move and heal: {found:?}"
    );
    let s = shell(&after, 0);
    assert_eq!(
        (s.active, s.paths.clone()),
        (
            Some(home(1, UDP)),
            alloc::vec![(home(1, UDP), Proven::Live)]
        ),
        "the crossing moved node 0 onto its own dial's link, and its bundle started again there"
    );
}

#[test]
fn a_carrier_loss_and_a_mandatory_switch_keep_both_ends_mirrored() {
    let st = on_start(20);
    let w = replay(&st, &[]);
    assert!(doubled(&w), "precondition: both ends hold two Live paths");
    assert_eq!(
        shell(&w, 0).active,
        Some(home(1, UDP)),
        "precondition: node 0's active path is on UDP"
    );
    let (after, found) = scripted(&st);
    assert!(
        found.is_empty(),
        "both ends stay mirrored through the carrier loss, the switch and the heal: {found:?}"
    );
    assert_eq!(
        shell(&after, 0).active,
        Some(home(1, TCP)),
        "node 0's bundle switched to its TCP path once UDP lost carrier"
    );
}

#[test]
fn the_only_paths_transport_removed_orphans_the_peer_and_a_redial_settles() {
    let st = on_start(21);
    let w = replay(&st, &[]);
    assert_eq!(
        w.parties[0].held(),
        alloc::vec![B],
        "precondition: node 0 holds node 1"
    );
    let mut w = replay(&st, &[Act::Path(0)]);
    assert!(
        w.parties[0].held().is_empty(),
        "the removal of the only path's transport orphaned the link, and node 0 removed node 1"
    );
    let mut found = every_step(&w);
    heal(&mut w);
    found.extend(every_step(&w));
    found.extend(healed(&w));
    assert!(
        found.is_empty(),
        "node 0 redials on TCP and the pair settles once node 1's timer frees it: {found:?}"
    );
    assert_eq!(
        (w.parties[0].held(), w.parties[1].held()),
        (alloc::vec![B], alloc::vec![A]),
        "each end holds the other once healed"
    );
}

#[test]
fn a_nat_rebound_of_the_second_path_moves_it_in_the_link_record() {
    let st = on_start(22);
    let w = replay(&st, &[]);
    assert!(doubled(&w), "precondition: both ends hold two Live paths");
    assert!(
        shell(&w, 0).paths.iter().any(|(a, _)| *a == second(1, UDP)),
        "precondition: node 0's second path is at node 1's second address"
    );
    let (after, found) = scripted(&st);
    assert!(
        found.is_empty(),
        "both ends stay mirrored through the rebound and the heal: {found:?}"
    );
    let paths: Vec<Addr> = shell(&after, 0).paths.iter().map(|(a, _)| *a).collect();
    assert!(
        paths.contains(&at(UDP, NAT)) && !paths.contains(&second(1, UDP)),
        "node 0's bundle moved its second path to the address the NAT rebound node 1's to: {paths:?}"
    );
}

#[test]
fn a_nat_rebound_of_the_active_path_moves_the_peer_with_it() {
    let st = on_start(25);
    let w = replay(&st, &[]);
    assert!(doubled(&w), "precondition: both ends hold two Live paths");
    assert_eq!(
        shell(&w, 0).active,
        Some(home(1, UDP)),
        "precondition: node 0's active path is at node 1's home"
    );
    let (after, found) = scripted(&st);
    assert!(
        found.is_empty(),
        "both ends stay mirrored, and each core agrees with the model, through the rebound and the heal: {found:?}"
    );
    assert_eq!(
        shell(&after, 0).active,
        Some(at(UDP, NAT)),
        "node 0's bundle followed its active path to the address the NAT rebound node 1's home to"
    );
    let told = after.parties[0].view().log.into_iter().any(|e| {
        matches!(
            e,
            Entry::Ev {
                ev: Event::Follow { from, to },
                ..
            } if from == home(1, UDP) && to == at(UDP, NAT)
        )
    });
    assert!(
        told,
        "node 0 told the model that its bundle moved the path the peer is at"
    );
}

#[test]
fn a_path_removed_at_the_peer_leaves_the_link_record() {
    let st = on_start(23);
    let w = replay(&st, &[]);
    assert!(doubled(&w), "precondition: both ends hold two Live paths");
    let (after, found) = scripted(&st);
    assert!(
        found.is_empty(),
        "both ends stay mirrored through the removal and the heal: {found:?}"
    );
    let paths: Vec<Addr> = shell(&after, 1).paths.iter().map(|(a, _)| *a).collect();
    assert_eq!(
        paths,
        [home(0, UDP)],
        "node 1's bundle released the path on the transport it lost"
    );
}

#[test]
fn a_link_retired_beside_a_dial_in_flight_keeps_the_connection_the_dial_uses() {
    use super::super::oracle::needs_open;
    for st in [off(), on()]
        .into_iter()
        .map(|v| v.into_iter().find(|s| s.number == 18).expect("start 18"))
    {
        let mut w = replay(&st, &[]);
        assert_eq!(
            (w.net.conns.len(), legs(&w)),
            (1, 2),
            "precondition: node 0's two dials of node 1, unanswered, share one BLE connection"
        );
        apply(&mut w, Act::Advance);
        assert_eq!(
            legs(&w),
            1,
            "precondition: the first dial's leg was reaped at its deadline, the second still out"
        );
        let shut = needs_open(&w);
        assert!(
            shut.is_empty(),
            "the retire closed the connection the dial still out uses: {shut:?}"
        );
    }
}

/// How many of node 0's own dials are in flight, by its view's legs bound.
fn legs(w: &World) -> usize {
    w.parties[0]
        .view()
        .bounds
        .iter()
        .find(|(name, _, _)| *name == "legs")
        .map_or(0, |(_, n, _)| *n)
}
