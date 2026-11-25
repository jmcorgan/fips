//! The joint world's explorer checks: that the explorer's key of a joint
//! node is sound, and that the exemption of a healed leaf's breaches spares
//! each by its own cause. The explorer is the settlement world's
//! (`../explore.rs`), run on starts whose nodes are joint nodes
//! (`starts.rs`). The reaches and sweeps that ran it over every start were
//! retired; these checks run in every build.
//!
//! The explorer rebuilds each state by replaying its path, and merges two
//! states whose keys are equal. So a joint node's key must be a function
//! of its path alone, whatever else the process ran (one node's path
//! identifiers never move another's, in this world or in another), and
//! must hold every field of a machine that a successor reads, not only
//! what the machine shows.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::proto::path::{Input as PathInput, Source};
use crate::proto::rekey::Close;

use super::super::super::model::history::{Hs, Node};
use super::super::explore::{Act, apply, explore, none, replay};
use super::super::oracle::{Breach, Oracle, by_shape};
use super::super::party::Configured;
use super::super::starts::{A, B, TCP, UDP, dial_home, home, model, settle, world_of};
use super::super::world::{Party, Pkt, World};
use super::Mode;
use super::facts::pair;
use super::machines::{Kit, Machines, exchange, kits, unused};

#[test]
fn two_worlds_on_one_path_have_one_digest() {
    let starts = super::starts::off();
    for st in starts.iter().filter(|s| matches!(s.number, 1 | 3 | 8)) {
        let stats = explore(st, 3, &none);
        for path in &stats.leaves {
            // Two worlds stepped in turn, so a draw one makes would move
            // the other's if the two shared a stream.
            let (mut a, mut b) = (replay(st, &[]), replay(st, &[]));
            for &act in path {
                apply(&mut a, act);
                apply(&mut b, act);
            }
            assert_eq!(
                a.digest(),
                b.digest(),
                "{}: {path:?} reached two worlds",
                st.name
            );
            assert_eq!(
                replay(st, path).digest(),
                a.digest(),
                "{}: {path:?} rebuilt alone reached another world",
                st.name
            );
        }
    }
}

/// Handshake names for the machines' own setups and rekeys.
const H0: Hs = Hs(0x0101_0001);

/// One of node 0's machines for node 1 at `mode`, set up on UDP at
/// instant 0, with its kit.
fn machine(mode: Mode) -> (Machines, Kit) {
    let (mut ka, mut kb) = kits();
    let ((sa, ra), (sb, _), _) = exchange(&mut ka, &mut kb, B, H0);
    unused(&mut kb, sb);
    let (m, _) = Machines::fresh(&mut ka, 0, B, mode, sa, ra, home(1, UDP), home(0, UDP));
    (m, ka)
}

/// The key `m` writes at `now`.
fn keyed(m: &Machines, now: u64) -> String {
    let mut out = String::new();
    m.key(now, &mut out);
    out
}

/// Every field of `m`'s rekey machine that can change.
fn rekeyed(m: &Machines) -> String {
    let mut out = String::new();
    let _ = m.rekey().state(&mut out);
    out
}

/// Two joint nodes at Off, node 0 dialing node 1 on UDP, settled.
fn paired() -> World {
    let mut w = world_of(super::off, &[A, B], &[&[(1, UDP)], &[]]);
    dial_home(&mut w, 0, 1, UDP);
    settle(&mut w);
    w
}

/// Node 0 sends node 1 a frame now, which is lost; its bytes.
fn lost(w: &mut World) -> Vec<u8> {
    apply(w, Act::Frame(0));
    let i = w
        .net
        .flight
        .iter()
        .position(|f| f.to == 1 && matches!(f.pkt, Pkt::Frame { .. }))
        .expect("node 0 sends node 1 a frame");
    match w.net.flight.remove(i).pkt {
        Pkt::Frame { wire, .. } => w.net.wires[wire as usize].clone(),
        other @ (Pkt::Msg1 { .. } | Pkt::Msg2 { .. } | Pkt::Eof) => panic!("a frame: {other:?}"),
    }
}

#[test]
fn a_state_differing_only_inside_a_machine_has_its_own_key() {
    let t = 1_000;
    // The rekey machine: one more frame sealed, so its session's counter
    // differs, which neither `view` nor `bindings` shows.
    let (mut a, mut ka) = machine(Mode::Off);
    let (mut b, mut kb) = machine(Mode::Off);
    let _ = b.seal(t, &[0x51, 0, 0, 0, 0]).expect("the session seals");
    assert_eq!(
        (
            format!("{:?}", a.rekey().view()),
            a.rekey().bindings(),
            format!("{:?}", a.bundle()),
        ),
        (
            format!("{:?}", b.rekey().view()),
            b.rekey().bindings(),
            format!("{:?}", b.bundle()),
        ),
        "precondition: the two rekey machines show the same and the bundles are equal"
    );
    assert_ne!(
        keyed(&a, t),
        keyed(&b, t),
        "a rekey machine that sealed one more frame has its own key"
    );
    assert_ne!(
        a.seal(t, &[0x51, 0, 0, 0, 0]),
        b.seal(t, &[0x51, 0, 0, 0, 0]),
        "and its next frame is other bytes"
    );
    a.close(&mut ka, t, Close::Admin);
    b.close(&mut kb, t, Close::Admin);

    // The bundle: a candidate held, which no path shows.
    let (mut a, mut ka) = machine(Mode::On);
    let (mut b, mut kb) = machine(Mode::On);
    let tb = pair(home(1, TCP));
    let candidate = PathInput::Candidate {
        transport: tb.transport,
        addr: tb.addr.clone(),
        source: Source::Config,
    };
    // Offered from no address of this node's, so the machines keep no
    // note of where it came from: the two differ inside the bundle alone.
    let _ = b.path(&mut kb, t, candidate, None);
    assert_eq!(
        (
            rekeyed(&a),
            a.active(),
            a.local(home(1, UDP)),
            a.local(home(1, TCP))
        ),
        (
            rekeyed(&b),
            b.active(),
            b.local(home(1, UDP)),
            b.local(home(1, TCP))
        ),
        "precondition: the two rekey machines are equal, and so are their paths and this node's addresses"
    );
    assert_ne!(
        keyed(&a, t),
        keyed(&b, t),
        "a bundle holding a candidate has its own key"
    );
    // The candidate's probes go unanswered: the bundle that holds it
    // keeps waking for them, and the other has nothing to do.
    let (mut pa, mut pb) = (Vec::new(), Vec::new());
    let mut wake = t;
    for _ in 0..20 {
        let Some(w) = b.wake() else { break };
        wake = w;
        pa.push(format!("{:?}", a.path(&mut ka, w, PathInput::Poll, None)));
        pb.push(format!("{:?}", b.path(&mut kb, w, PathInput::Poll, None)));
    }
    assert_ne!(pa, pb, "and the same polls do other things in each");
    a.close(&mut ka, wake, Close::Admin);
    b.close(&mut kb, wake, Close::Admin);

    // Through the world: two worlds that differ only in a frame node 0
    // sealed and lost have their own keys.
    let (mut x, mut y) = (paired(), paired());
    let _ = lost(&mut x);
    let _ = lost(&mut y);
    let _ = lost(&mut y);
    assert_eq!(
        format!("{:?}", x.parties[0].view()),
        format!("{:?}", y.parties[0].view()),
        "precondition: node 0 shows the same in both worlds"
    );
    assert_ne!(x.key(), y.key(), "the two worlds have their own keys");
    assert_ne!(
        lost(&mut x),
        lost(&mut y),
        "and node 0's next frame differs"
    );
}

/// Why the exemption of the joint party spares a breach at a healed leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Spared {
    /// A split on a path that showed a known shape other than the two
    /// late-dial shapes (`by_shape`).
    Shape,
    /// [`lapsed`].
    Lapsed,
    /// [`untimed`].
    Untimed,
}

/// The exemption of the joint party, and its cause: the first of
/// `by_shape`, [`lapsed`] and [`untimed`] that names `b`.
fn spared(w: &World, b: &Breach) -> Option<Spared> {
    if by_shape(w, b) {
        Some(Spared::Shape)
    } else if lapsed(w, b) {
        Some(Spared::Lapsed)
    } else if untimed(w, b) {
        Some(Spared::Untimed)
    } else {
        None
    }
}

/// What a node of the model, which runs no link-dead timer, leaves once
/// healed beside a joint node, which runs the node's: the model still
/// holds the joint node on a link whose frames were lost in flight, the
/// joint node's timer removed it, and the model refuses each redial (one
/// off the link of a peering it has not heard from while that link can be
/// reached, or one its dampener holds), so
/// the joint node holds a configured peer it cannot reach and the model
/// keeps open the connection a refused redial came on. A node would have
/// removed the silent peer too and taken the redial. Only a pairing of a
/// joint node with the model reaches it: two joint nodes both run the
/// timer.
pub fn untimed(w: &World, b: &Breach) -> bool {
    let stale = |x: usize, y: usize| {
        x != y
            && w.parties[x].joint().is_none()
            && w.parties[y].joint().is_some()
            && w.parties[x].held().contains(&w.ids[y])
            && !w.parties[y].held().contains(&w.ids[x])
    };
    let n = w.parties.len();
    if b.oracle == Oracle::OneSession && b.what.ends_with("is configured and not held") {
        (0..n).any(|x| stale(x, b.node))
    } else if b.oracle == Oracle::ConnectionsInUse && b.what.ends_with("open, no link uses it") {
        (0..n).any(|y| stale(b.node, y))
    } else {
        false
    }
}

/// A pair a node's link counts in use while its connection is closed,
/// where the node's bundle holds the pair as an acknowledged path that is
/// not Live. The bundle asks for a connection only for a path it admitted
/// from a candidate or whose connect failed, never after a failed send,
/// so a proven path whose connection failed is not connected again and
/// stays acknowledged, and counted, until its Dead grace ends. A finding
/// about the bundle, pinned in `pins.rs`.
pub fn lapsed(w: &World, b: &Breach) -> bool {
    b.oracle == Oracle::ConnectionsInUse
        && w.parties[b.node]
            .lapsed()
            .iter()
            .any(|at| b.what == format!("{at:?} in use, its connection closed"))
}

#[test]
fn each_breach_the_pins_hold_is_exempted_by_its_own_cause_and_a_settled_pair_by_none() {
    use super::super::oracle::{every_step, heal, healed};
    use Act::{Connect, Deliver, Fail, Leap};
    let on = super::starts::on();
    let start = |n: u8| on.iter().find(|s| s.number == n).expect("the start");
    let cases: [(u8, &[Act], Spared); 1] = [(
        2,
        &[
            Deliver(0),
            Deliver(1),
            Deliver(2),
            Deliver(5),
            Connect(0, true),
            Leap,
            Fail(0, 0),
        ],
        Spared::Lapsed,
    )];
    for (n, path, cause) in cases {
        let mut w = replay(start(n), path);
        heal(&mut w);
        let found: Vec<Breach> = every_step(&w).into_iter().chain(healed(&w)).collect();
        assert!(
            !found.is_empty(),
            "start {n}, {path:?}: the pinned breaches are found"
        );
        for b in &found {
            let got = spared(&w, b);
            assert_eq!(
                got,
                Some(cause),
                "start {n}, {path:?}: {b:?} is exempted by its own cause"
            );
        }
    }
    // The model at node 0 and a joint node at node 1, whose configuration
    // names the model's TCP home, and which dials the model once at its UDP
    // home: the dial completes, the frames are lost for the link-dead
    // timeout, and the joint node's timer removes the model. The model,
    // which runs no timer, still holds the joint node and has never heard
    // from it, so it refuses each redial, which comes over TCP, off the
    // link of a peering it has not heard from while that link can be
    // reached. No redial is answered, and the stale peering leaves two
    // breaches, the missing timer's. (A redial of a peering the model has
    // heard from it answers, and the first frame replaces the stale
    // peering: the pair heals with nothing to exempt.)
    let mut w = super::super::starts::pair(model_off, A, &[&[], &[(0, TCP)]]);
    dial_home(&mut w, 1, 0, UDP);
    for (to, first) in [(0, true), (1, false)] {
        let id = w
            .net
            .flight
            .iter()
            .find(|f| {
                f.to == to
                    && matches!(
                        (&f.pkt, first),
                        (Pkt::Msg1 { .. }, true) | (Pkt::Msg2 { .. }, false)
                    )
            })
            .map(|f| f.id)
            .expect("precondition: the handshake message is in flight");
        w.deliver(id);
    }
    w.run_until(w.net.now + super::feeds::LIVE);
    heal(&mut w);
    let found = healed(&w);
    assert!(
        found.len() == 2,
        "precondition: the model's stale peering leaves two breaches: {found:?}"
    );
    for b in &found {
        assert_eq!(
            spared(&w, b),
            Some(Spared::Untimed),
            "{b:?} is exempted as the model's missing timer"
        );
    }
    // Start 2's script settles both ends, capable, and then holds for a
    // heal: the cause names nothing there.
    let st = start(2);
    let mut scratch = replay(st, &[]);
    let script = (st.script)(&mut scratch);
    let mut w = replay(st, &script);
    heal(&mut w);
    for x in 0..w.parties.len() {
        assert!(
            w.parties[x].lapsed().is_empty(),
            "node {x} holds no lapsed path once settled"
        );
    }
}

/// The model at node 0, and a joint node at multipath off elsewhere.
fn model_off(ix: usize, me: Node, configured: Vec<Configured>) -> Box<dyn Party> {
    if ix == 0 {
        model(ix, me, configured)
    } else {
        super::off(ix, me, configured)
    }
}
