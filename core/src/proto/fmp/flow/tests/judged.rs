//! The transcription of next's rules (`next.rs`) checked against the
//! judge (`../model/`).
//!
//! Scripted runs put two [`NextParty`] nodes in the settlement world over
//! one connectionless transport and deliver their packets in a chosen
//! order. Each node's log is then replayed, peer by peer, through a
//! [`Judge`] with the local rules on ([`Params::local`]), and each step's
//! class, refusal, reply and peer change compared with what next did. The
//! first difference for a peer ends that peer's comparison, since the two
//! hold different state from there on.
//!
//! Each difference must be a known one ([`Known`]), and each run states
//! which it shows:
//!
//! - [`Known::Msg2RestartUngated`] (the port plan's row N1, a pinned
//!   defect until it is fixed): next replaces a restarted peer at its own
//!   msg2 with no restart gate, where FRC-2201 Section 5.6 applies the
//!   gates in both roles.
//! - [`Known::SameSideByOrder`] (row N3, a pinned defect until it is
//!   fixed): next settles a second handshake dialed by the same side by
//!   address order at both ends, where Section 5.7 has the initiator move
//!   (no live test being applied, row N2) and the responder move.
//! - [`Known::OwnLinkKept`] (row N2): the flow's larger node, holding the
//!   peer on a link it dialed, ends a second dial of its own at its msg2
//!   with no msg3 (the same-side rule's initiator half), where the judge,
//!   without the live test, moves. next's transcribed rules never show it.
//! - [`Known::KeepSendsFinal`]: the larger node of a crossing that
//!   completes at its own msg2 keeps what it holds and still sends msg3,
//!   where the judge's `KeepEndsAttempt` sends none. The FRC is silent; the
//!   smaller node then keeps its own dial at that msg3, so both ends still
//!   settle on one link.
//! - [`Known::InstallFloor`]: next's restart gate at msg3 counts from the
//!   install as well as from the last frame, so it refuses a restart of a
//!   peering installed less than 15 s ago that carried no frame, where
//!   Section 5.6's first gate counts frames only.
//!
//! The last two are not rows of the port plan's Section 1.3; this check
//! found them.

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

use super::super::model::history as xx;
use super::super::model::judge::{Class, Judge, Params, Refusal, Reply, Transition};
use super::next::{Did, Entry, Log, NextParty, Packet};
use crate::proto::settle::model::history::{Addr, Hs, Node};
use crate::proto::settle::tests::world::{Input, Kind, Net, Party, Pkt, World};

/// A difference between next and the judge, by its known cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Known {
    /// Row N1: no restart gate at next's own msg2.
    Msg2RestartUngated,
    /// Row N3: a same-side second handshake settled by address order.
    SameSideByOrder,
    /// Row N2: the larger node's second dial off a link it dialed and
    /// holds is ended at its msg2 with no msg3, by the same-side rule,
    /// where the judge, without the live test, moves onto it.
    OwnLinkKept,
    /// The larger node's keep at its msg2 sends msg3.
    KeepSendsFinal,
    /// next's restart gate counts from the install.
    InstallFloor,
}

/// One step where next and the judge differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Diff {
    /// The node whose log it is.
    pub me: Node,
    /// The peer whose history it is in.
    pub peer: Node,
    /// The event.
    pub event: xx::Event,
    /// What next did.
    pub next: Did,
    /// What the judge did.
    pub judge: Did,
}

impl Diff {
    /// The known cause this difference has, if any.
    pub fn known(&self) -> Option<Known> {
        let (n, j) = (self.next, self.judge);
        let at2 = matches!(self.event, xx::Event::Msg2 { .. });
        let at3 = matches!(self.event, xx::Event::Msg3 { .. });
        let restart = j.class == Some(Class::Restart);
        if at2
            && restart
            && matches!(j.refused, Some(Refusal::Heard | Refusal::Dampened))
            && n.change == Some(Transition::Replace)
        {
            return Some(Known::Msg2RestartUngated);
        }
        if at2
            && j.class == Some(Class::SameSide)
            && j.change == Some(Transition::Move)
            && n.class == Some(Class::SameSide)
            && n.refused.is_none()
            && n.reply == Some(Reply::Silent)
            && n.change.is_none()
        {
            return Some(Known::OwnLinkKept);
        }
        if (at2 || at3)
            && j.class == Some(Class::SameSide)
            && j.change == Some(Transition::Move)
            && n.class == Some(Class::SameSide)
            && n.change == Some(Transition::Keep)
        {
            return Some(Known::SameSideByOrder);
        }
        let sent = Did {
            reply: Some(Reply::Final),
            ..j
        };
        if at2
            && j.class == Some(Class::Crossing)
            && j.change == Some(Transition::Keep)
            && n == sent
        {
            return Some(Known::KeepSendsFinal);
        }
        if at3
            && restart
            && j.change == Some(Transition::Replace)
            && n.class == Some(Class::Restart)
            && n.refused == Some(Refusal::Heard)
        {
            return Some(Known::InstallFloor);
        }
        None
    }
}

/// The judge's node for the world's `n`.
fn xn(n: Node) -> xx::Node {
    xx::Node(n.0)
}

/// Replay node `me`'s log through one judge per peer, with the local
/// rules on, and return the first difference for each peer.
pub fn compare(me: Node, log: &[Entry]) -> Vec<Diff> {
    let mut peers: Vec<Node> = log.iter().map(|e| e.1).collect();
    peers.sort();
    peers.dedup();
    let mut out = Vec::new();
    for peer in peers {
        let mut judge = Judge::new(xn(me), xn(peer), Params::local());
        let mut last = 0;
        for &(at, _, event, next) in log.iter().filter(|e| e.1 == peer) {
            if at > last {
                judge.step(xx::Event::Advance(at - last));
                last = at;
            }
            let s = judge.step(event);
            let judged = Did {
                class: s.class,
                refused: s.refused,
                reply: s.reply,
                change: s.change,
            };
            if judged != next {
                out.push(Diff {
                    me,
                    peer,
                    event,
                    next,
                    judge: judged,
                });
                break;
            }
        }
    }
    out
}

/// The smaller node's identity.
const S: Node = Node(1);

/// The larger node's identity.
const L: Node = Node(2);

/// Node `x`'s one address.
fn home(x: usize) -> Addr {
    Addr {
        transport: 1,
        at: 1 + x as u16,
    }
}

/// Two next nodes, the smaller at index 0, over one connectionless
/// transport, and their logs.
struct Run {
    world: World<Packet>,
    logs: [Log; 2],
}

impl Run {
    fn new() -> Self {
        let logs: [Log; 2] = [
            Rc::new(RefCell::new(Vec::new())),
            Rc::new(RefCell::new(Vec::new())),
        ];
        let parties: Vec<Box<dyn Party<Packet>>> = vec![
            Box::new(NextParty::new(0, S, logs[0].clone())),
            Box::new(NextParty::new(1, L, logs[1].clone())),
        ];
        let net = Net::flowing(&[(1, Kind::Datagram)], vec![vec![home(0)], vec![home(1)]]);
        Self {
            world: World::flowing(parties, vec![S, L], net),
            logs,
        }
    }

    /// Node `x` dials the other.
    fn dial(&mut self, x: usize) {
        let peer = [L, S][x];
        self.world.input(
            x,
            Input::Dial {
                peer,
                to: home(1 - x),
                from: None,
            },
        );
    }

    /// Deliver the first packet in flight to node `to` that `kind` picks.
    fn deliver(&mut self, to: usize, kind: fn(&Pkt<Packet>) -> bool) {
        let id = self
            .world
            .net
            .flight
            .iter()
            .find(|f| f.to == to && kind(&f.pkt))
            .map(|f| f.id)
            .expect("precondition: the packet is in flight");
        self.world.deliver(id);
    }

    /// Lose every frame in flight to node `to`.
    fn lose_frames(&mut self, to: usize) {
        self.world
            .net
            .flight
            .retain(|f| !(f.to == to && matches!(f.pkt, Pkt::Frame { .. })));
    }

    /// Deliver everything in flight.
    fn drain(&mut self) {
        self.world.drain(64);
    }

    /// Move the clock to `t`; nothing may be in flight.
    fn at(&mut self, t: u64) {
        assert!(
            self.world.net.flight.is_empty(),
            "precondition: nothing in flight when the clock moves"
        );
        self.world.run_until(t);
    }

    /// The handshake node `x` holds the other on.
    fn held(&self, x: usize) -> Option<Hs> {
        let peer = [L, S][x];
        self.world.parties[x]
            .view()
            .peers
            .iter()
            .find(|p| p.peer == peer)
            .map(|p| p.cur)
    }

    /// Every difference of both nodes' logs from the judge.
    fn diffs(&self) -> Vec<Diff> {
        let mut out = compare(S, &self.logs[0].borrow());
        out.extend(compare(L, &self.logs[1].borrow()));
        out
    }

    /// The known causes of the differences, sorted, each difference
    /// required to have one.
    fn known(&self) -> Vec<(Node, Known)> {
        let mut out: Vec<(Node, Known)> = self
            .diffs()
            .iter()
            .map(|d| {
                (
                    d.me,
                    d.known().unwrap_or_else(|| {
                        panic!("defect: a difference with no known cause: {d:?}")
                    }),
                )
            })
            .collect();
        out.sort();
        out
    }
}

/// A msg1.
fn m1(p: &Pkt<Packet>) -> bool {
    matches!(p, Pkt::Flow(Packet::Msg1 { .. }))
}

/// A msg2.
fn m2(p: &Pkt<Packet>) -> bool {
    matches!(p, Pkt::Msg2 { .. })
}

/// A msg3.
fn m3(p: &Pkt<Packet>) -> bool {
    matches!(p, Pkt::Flow(Packet::Msg3 { .. }))
}

#[test]
fn a_lone_dial_settles_both_ends_as_the_judge_does() {
    let mut r = Run::new();
    r.dial(0);
    r.drain();
    assert!(r.held(0).is_some(), "precondition: the dial installs");
    assert_eq!(r.held(0), r.held(1));
    assert_eq!(r.known(), [], "next and the judge agree");
}

#[test]
fn a_simultaneous_dial_differs_from_the_judge_only_where_the_larger_node_keeps_at_its_msg2() {
    // Each order: which node reads which message, in turn, after both
    // msg1s are read. A msg3 is read only once the msg2 that draws it was.
    type Order = [(usize, fn(&Pkt<Packet>) -> bool); 4];
    let orders: [(Order, &[(Node, Known)]); 4] = [
        ([(0, m2), (1, m2), (0, m3), (1, m3)], &[]),
        (
            [(0, m2), (1, m3), (1, m2), (0, m3)],
            &[(L, Known::KeepSendsFinal)],
        ),
        ([(1, m2), (0, m3), (0, m2), (1, m3)], &[]),
        ([(0, m2), (1, m2), (1, m3), (0, m3)], &[]),
    ];
    for (i, (order, expected)) in orders.iter().enumerate() {
        let mut r = Run::new();
        r.dial(0);
        r.dial(1);
        r.deliver(0, m1);
        r.deliver(1, m1);
        for (to, kind) in order {
            r.deliver(*to, *kind);
        }
        r.drain();
        assert!(
            r.held(0).is_some(),
            "order {i}: precondition: a session held"
        );
        assert_eq!(r.held(0), r.held(1), "order {i}: both ends on one session");
        assert_eq!(r.known(), *expected, "order {i}");
    }
}

#[test]
fn two_dials_of_one_node_answered_in_turn_keep_the_first_installed_without_a_msg3_for_the_second() {
    for x in [0, 1] {
        let mut r = Run::new();
        r.dial(x);
        r.dial(x);
        r.deliver(1 - x, m1);
        r.deliver(1 - x, m1);
        r.deliver(x, m2);
        let first = r.held(x);
        assert!(
            first.is_some(),
            "node {x}: precondition: the first dial installs"
        );
        let msg3s = |r: &Run| {
            r.world
                .net
                .flight
                .iter()
                .filter(|f| f.to == 1 - x && m3(&f.pkt))
                .count()
        };
        assert_eq!(
            msg3s(&r),
            1,
            "node {x}: precondition: the first dial's msg3"
        );
        r.deliver(x, m2);
        assert_eq!(msg3s(&r), 1, "node {x}: the second dial sends no msg3");
        r.drain();
        assert_eq!(
            r.held(x),
            first,
            "node {x}: the first dial's session is kept"
        );
        assert_eq!(r.held(1 - x), first, "node {x}: both ends on it");
        assert_eq!(r.known(), [], "node {x}: next and the judge agree");
    }
}

#[test]
fn a_redial_by_the_smaller_node_while_it_holds_the_peer_agrees_with_the_judge() {
    let mut r = Run::new();
    r.dial(0);
    r.drain();
    r.at(5_000);
    let first = r.held(0);
    r.dial(0);
    r.drain();
    assert_ne!(r.held(0), first, "precondition: the redial moved the peer");
    assert_eq!(r.held(0), r.held(1));
    assert_eq!(r.known(), []);
}

#[test]
fn a_redial_by_the_larger_node_while_it_holds_the_peer_shows_the_pinned_same_side_rule_at_both_ends()
 {
    let mut r = Run::new();
    r.dial(1);
    r.drain();
    r.at(5_000);
    let first = r.held(1);
    r.dial(1);
    r.drain();
    assert_eq!(r.held(1), first, "next keeps the old link at both ends");
    assert_eq!(r.held(0), r.held(1));
    assert_eq!(
        r.known(),
        [(S, Known::SameSideByOrder), (L, Known::SameSideByOrder)],
        "the judge moves both ends onto the redial; next keeps both"
    );
}

#[test]
fn a_restart_answered_at_the_dialers_msg2_inside_the_interval_shows_the_pinned_ungated_restart() {
    let mut r = Run::new();
    r.dial(0);
    r.drain();
    r.at(2_000);
    r.world.restart(1);
    r.at(3_000);
    r.dial(0);
    r.drain();
    assert_eq!(
        r.held(0),
        r.held(1),
        "precondition: both ends on the redial"
    );
    assert_eq!(
        r.known(),
        [(S, Known::Msg2RestartUngated)],
        "the judge refuses a restart 3 s after the peer's frame; next replaces"
    );
}

#[test]
fn a_restart_at_msg3_of_a_peering_installed_inside_the_interval_with_no_frame_is_refused_by_next_alone()
 {
    let mut r = Run::new();
    r.dial(0);
    r.deliver(1, m1);
    r.deliver(0, m2);
    r.lose_frames(1);
    r.deliver(1, m3);
    r.drain();
    assert!(
        r.held(1).is_some(),
        "precondition: the responder holds the peer"
    );
    r.at(5_000);
    r.world.restart(0);
    r.at(6_000);
    r.dial(0);
    r.deliver(1, m1);
    r.deliver(0, m2);
    r.lose_frames(1);
    r.deliver(1, m3);
    r.lose_frames(0);
    r.lose_frames(1);
    assert_eq!(
        r.known(),
        [(L, Known::InstallFloor)],
        "next refuses 6 s after an install that carried no frame; the judge replaces"
    );
}

#[test]
fn every_difference_the_check_names_is_told_apart_by_its_cause() {
    let did = |class, refused, reply, change| Did {
        class: Some(class),
        refused,
        reply: Some(reply),
        change,
    };
    let msg2 = xx::Event::Msg2 {
        hs: xx::Hs(1),
        epoch: xx::Epoch(1),
        refused: false,
    };
    let msg3 = xx::Event::Msg3 {
        hs: xx::Hs(1),
        epoch: xx::Epoch(1),
        claim: xx::Claim::None,
        refused: false,
    };
    let diff = |event, next, judge| Diff {
        me: S,
        peer: L,
        event,
        next,
        judge,
    };
    let cases = [
        (
            diff(
                msg2,
                did(
                    Class::Restart,
                    None,
                    Reply::Final,
                    Some(Transition::Replace),
                ),
                did(Class::Restart, Some(Refusal::Heard), Reply::Silent, None),
            ),
            Some(Known::Msg2RestartUngated),
        ),
        (
            diff(
                msg3,
                did(Class::SameSide, None, Reply::Silent, Some(Transition::Keep)),
                did(Class::SameSide, None, Reply::Silent, Some(Transition::Move)),
            ),
            Some(Known::SameSideByOrder),
        ),
        (
            diff(
                msg2,
                did(Class::SameSide, None, Reply::Silent, None),
                did(Class::SameSide, None, Reply::Final, Some(Transition::Move)),
            ),
            Some(Known::OwnLinkKept),
        ),
        (
            diff(
                msg2,
                did(Class::Crossing, None, Reply::Final, Some(Transition::Keep)),
                did(Class::Crossing, None, Reply::Silent, Some(Transition::Keep)),
            ),
            Some(Known::KeepSendsFinal),
        ),
        (
            diff(
                msg3,
                did(Class::Restart, Some(Refusal::Heard), Reply::Silent, None),
                did(
                    Class::Restart,
                    None,
                    Reply::Silent,
                    Some(Transition::Replace),
                ),
            ),
            Some(Known::InstallFloor),
        ),
        (
            diff(
                msg3,
                did(Class::Crossing, None, Reply::Silent, Some(Transition::Keep)),
                did(Class::Crossing, None, Reply::Silent, Some(Transition::Move)),
            ),
            None,
        ),
    ];
    for (d, want) in cases {
        assert_eq!(d.known(), want, "{d:?}");
    }
}
