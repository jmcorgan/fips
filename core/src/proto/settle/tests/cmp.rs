//! The core, through the one-node driver, against the reference model on
//! the model's own table histories.
//!
//! Each history of `model/tests/` is restated here (those tests' functions
//! are private to the model), with the own-msg2 history of the gates'
//! tests one second after a frame, and two histories the model's tests
//! lack, in which a move's new address and a roamed address matter. Each
//! is run event by event through a model `Judge` and a
//! [`Drive`]. At each step the class, refusal, reply, peer change and
//! closes are compared, except on a step the model leaves open. The named
//! differences of `shadow.rs` are applied the same way here:
//!
//! - after a move, the judge takes the core's heard;
//! - at a late second dial's move, the core is expected to close what
//!   [`resync_close`] computes, and the judge's fallback is cleared;
//! - where the core's replay memory or silent-session back-off refuses a
//!   msg1 the model accepts, the history's comparison stops.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::proto::settle::model::history::{
    Addr, Binding, Bytes, Epoch, Event, Hs, LinkId, Ms, Node,
};
use crate::proto::settle::model::judge::{Judge, LocalRule, Params, Transition};

use super::drive::Drive;
use super::shadow::{Named, Refusal, resync_close};

const SMALL: Node = Node(1);
const LARGE: Node = Node(2);
const E1: Epoch = Epoch(1);
const E2: Epoch = Epoch(2);
const CL: Binding = Binding::Connectionless;
const CO: Binding = Binding::Connected;
/// Long enough for the link and its session to be eligible to rekey.
const AGED: Ms = 30_000;

fn at(port: u16) -> Addr {
    Addr {
        transport: 1,
        at: port,
    }
}

fn dial(hs: u32, link: u32, to: Addr, binding: Binding) -> Event {
    Event::Dial {
        hs: Hs(hs),
        link: LinkId(link),
        to,
        binding,
    }
}

fn msg1(hs: u32, bytes: u32, epoch: Epoch, link: u32, from: Addr, binding: Binding) -> Event {
    Event::Msg1 {
        hs: Hs(hs),
        bytes: Bytes(bytes),
        epoch,
        link: LinkId(link),
        from,
        binding,
        sent: true,
    }
}

fn unsent(hs: u32, bytes: u32, link: u32, from: Addr) -> Event {
    Event::Msg1 {
        hs: Hs(hs),
        bytes: Bytes(bytes),
        epoch: E1,
        link: LinkId(link),
        from,
        binding: CO,
        sent: false,
    }
}

fn msg2(hs: u32, epoch: Epoch, from: Addr) -> Event {
    Event::Msg2 {
        hs: Hs(hs),
        epoch,
        from,
    }
}

fn frame(hs: u32, from: Addr) -> Event {
    Event::Frame { hs: Hs(hs), from }
}

fn wait(ms: Ms) -> Event {
    Event::Advance(ms)
}

/// The model tests' responder: installed from msg1 10 at `at(9)`, one
/// frame heard at once.
fn responder() -> Vec<Event> {
    alloc::vec![msg1(10, 100, E1, 1, at(9), CL), frame(10, at(9))]
}

/// The model gate tests' unheard peering.
fn unheard() -> Vec<Event> {
    alloc::vec![msg1(10, 100, E1, 1, at(9), CL)]
}

fn replacement(hs: u32) -> Event {
    msg1(hs, hs * 10, E1, hs, at(8), CL)
}

/// One end of a crossing: dial, the peer's msg1, then the msg2.
fn crossed(me: Node, peer: Node, binding: Binding) -> Vec<Event> {
    let (mine, theirs, peer_at, peer_src) = if me < peer {
        (1, 2, 2, 12)
    } else {
        (2, 1, 1, 11)
    };
    alloc::vec![
        dial(mine, 1, at(peer_at), binding),
        msg1(theirs, theirs * 100, E1, 2, at(peer_src), binding),
        msg2(mine, E1, at(peer_at)),
    ]
}

fn with(mut a: Vec<Event>, b: &[Event]) -> Vec<Event> {
    a.extend_from_slice(b);
    a
}

/// A named history: its name, the node, the peer and the events.
type History = (&'static str, Node, Node, Vec<Event>);

/// The late second dial of the model's crossing tests, on connections.
fn late_dial() -> Vec<Event> {
    alloc::vec![
        dial(1, 1, at(1), CO),
        msg2(1, E1, at(1)),
        wait(2_000),
        dial(2, 2, at(5), CO),
        msg2(2, E1, at(5)),
    ]
}

/// Every history of the model's table tests, and the gates' own-msg2
/// histories.
fn histories() -> Vec<History> {
    let r = responder;
    let u = unheard;
    alloc::vec![
        // model/tests/classify.rs
        (
            "rule 1",
            SMALL,
            LARGE,
            alloc::vec![msg1(10, 100, E1, 1, at(9), CL)]
        ),
        (
            "rule 1 with an own dial",
            SMALL,
            LARGE,
            alloc::vec![dial(1, 7, at(9), CL), msg1(10, 100, E1, 1, at(9), CL)],
        ),
        (
            "rule 2",
            SMALL,
            LARGE,
            with(r(), &[wait(20_000), msg1(11, 110, E2, 2, at(8), CL)]),
        ),
        (
            "rule 3.1",
            SMALL,
            LARGE,
            with(r(), &[wait(500), msg1(10, 100, E1, 1, at(9), CL)]),
        ),
        (
            "rule 3.2",
            SMALL,
            LARGE,
            with(r(), &[wait(500), msg1(10, 101, E1, 1, at(9), CL)]),
        ),
        (
            "rule 3.3",
            SMALL,
            LARGE,
            with(r(), &[wait(15_000), msg1(11, 110, E1, 2, at(8), CL)]),
        ),
        (
            "rule 3.3 refused, then its resend",
            SMALL,
            LARGE,
            with(
                r(),
                &[
                    wait(500),
                    msg1(11, 110, E1, 2, at(8), CL),
                    wait(20_000),
                    msg1(11, 110, E1, 2, at(8), CL),
                ],
            ),
        ),
        (
            "rule 4.1 reachable",
            SMALL,
            LARGE,
            with(r(), &[wait(AGED), msg1(11, 110, E1, 2, at(8), CL)]),
        ),
        (
            "rule 4.1 unreachable",
            SMALL,
            LARGE,
            alloc::vec![
                msg1(10, 100, E1, 1, at(9), CO),
                frame(10, at(9)),
                wait(AGED),
                Event::Close { at: at(9) },
                msg1(11, 110, E1, 2, at(8), CO),
            ],
        ),
        (
            "rule 4.2",
            SMALL,
            LARGE,
            with(
                r(),
                &[
                    wait(AGED),
                    msg1(11, 110, E1, 1, at(9), CL),
                    msg1(11, 110, E1, 1, at(9), CL),
                    msg1(12, 120, E1, 1, at(9), CL),
                ],
            ),
        ),
        (
            "rule 4.3",
            SMALL,
            LARGE,
            with(r(), &[wait(AGED), msg1(10, 101, E1, 1, at(9), CL)]),
        ),
        (
            "rule 4.4, the smaller node",
            SMALL,
            LARGE,
            with(
                r(),
                &[
                    wait(AGED),
                    Event::RekeyStart { hs: Hs(20) },
                    msg1(11, 110, E1, 1, at(9), CL),
                ],
            ),
        ),
        (
            "rule 4.4, the larger node",
            LARGE,
            SMALL,
            with(
                r(),
                &[
                    wait(AGED),
                    Event::RekeyStart { hs: Hs(20) },
                    msg1(11, 110, E1, 1, at(9), CL),
                ],
            ),
        ),
        (
            "rule 4.5 and its frame",
            SMALL,
            LARGE,
            with(
                r(),
                &[
                    wait(AGED),
                    msg1(11, 110, E1, 1, at(9), CL),
                    frame(11, at(9))
                ],
            ),
        ),
        // model/tests/close.rs and crossing.rs
        (
            "crossing, smaller, connected",
            SMALL,
            LARGE,
            crossed(SMALL, LARGE, CO)
        ),
        (
            "crossing, larger, connected",
            LARGE,
            SMALL,
            crossed(LARGE, SMALL, CO)
        ),
        ("crossing, smaller", SMALL, LARGE, crossed(SMALL, LARGE, CL)),
        ("crossing, larger", LARGE, SMALL, crossed(LARGE, SMALL, CL)),
        (
            "crossing, 9 against 3",
            Node(9),
            Node(3),
            crossed(Node(9), Node(3), CL)
        ),
        (
            "crossing, 3 against 9",
            Node(3),
            Node(9),
            crossed(Node(3), Node(9), CL)
        ),
        (
            "a connection a remaining link needs",
            SMALL,
            LARGE,
            alloc::vec![
                dial(1, 1, at(2), CO),
                dial(3, 3, at(2), CO),
                msg1(2, 200, E1, 2, at(2), CO),
                msg2(1, E1, at(2)),
            ],
        ),
        (
            "a reaped attempt",
            SMALL,
            LARGE,
            alloc::vec![
                msg1(2, 200, E1, 2, at(12), CO),
                dial(1, 1, at(2), CO),
                dial(3, 3, at(12), CO),
                Event::Timeout { hs: Hs(1) },
                Event::Timeout { hs: Hs(3) },
            ],
        ),
        (
            "an own later dial",
            LARGE,
            SMALL,
            alloc::vec![
                dial(1, 1, at(1), CL),
                msg2(1, E1, at(1)),
                wait(2_000),
                dial(2, 2, at(5), CL),
                msg2(2, E1, at(5)),
            ],
        ),
        (
            "a msg2 with a changed epoch",
            LARGE,
            SMALL,
            alloc::vec![
                dial(2, 1, at(1), CL),
                msg1(1, 100, E1, 2, at(11), CL),
                msg2(2, E2, at(1)),
            ],
        ),
        (
            "a msg1 after the peer is held",
            LARGE,
            SMALL,
            alloc::vec![
                dial(2, 1, at(1), CL),
                msg2(2, E1, at(1)),
                msg1(1, 100, E1, 2, at(11), CL),
            ],
        ),
        (
            "a late second dial, then a frame under the old session",
            LARGE,
            SMALL,
            with(late_dial(), &[frame(1, at(1))]),
        ),
        (
            "a late second dial, then a frame under the new session",
            LARGE,
            SMALL,
            with(late_dial(), &[frame(2, at(5))]),
        ),
        (
            "a stored msg2 sent late",
            LARGE,
            SMALL,
            alloc::vec![
                dial(2, 1, at(1), CO),
                unsent(1, 100, 2, at(11)),
                msg2(2, E1, at(1)),
                Event::Msg2Sent { hs: Hs(1) },
            ],
        ),
        (
            "a stored msg2 sent with no peer held",
            SMALL,
            LARGE,
            alloc::vec![unsent(2, 200, 1, at(12)), Event::Msg2Sent { hs: Hs(2) }],
        ),
        (
            "a dial on the peer's aged link",
            LARGE,
            SMALL,
            alloc::vec![
                msg1(1, 100, E1, 1, at(11), CL),
                frame(1, at(11)),
                wait(30_000),
                dial(2, 2, at(11), CL),
                msg2(2, E1, at(11)),
            ],
        ),
        // model/tests/gates.rs
        (
            "unheard floor, early",
            SMALL,
            LARGE,
            with(u(), &[wait(999), replacement(11)])
        ),
        (
            "unheard floor, at it",
            SMALL,
            LARGE,
            with(u(), &[wait(1_000), replacement(11)])
        ),
        (
            "heard floor from the last frame",
            SMALL,
            LARGE,
            with(
                u(),
                &[
                    wait(5_000),
                    frame(10, at(9)),
                    wait(14_999),
                    replacement(11),
                    wait(1),
                    replacement(12),
                ],
            ),
        ),
        (
            "heard floor from installation",
            SMALL,
            LARGE,
            alloc::vec![
                dial(1, 1, at(9), CL),
                wait(2_000),
                msg2(1, E1, at(9)),
                wait(14_999),
                replacement(11),
                wait(1),
                replacement(12),
            ],
        ),
        (
            "heard from the first frame, before",
            SMALL,
            LARGE,
            with(u(), &[wait(1_500), replacement(11)])
        ),
        (
            "heard from the first frame, after",
            SMALL,
            LARGE,
            with(
                u(),
                &[wait(1_000), frame(10, at(9)), wait(500), replacement(11)]
            ),
        ),
        (
            "the dampener",
            SMALL,
            LARGE,
            with(
                u(),
                &[
                    frame(10, at(9)),
                    wait(15_000),
                    msg1(11, 110, E2, 2, at(8), CL),
                    wait(14_999),
                    msg1(12, 120, Epoch(3), 3, at(7), CL),
                    wait(1),
                    msg1(12, 120, Epoch(3), 3, at(7), CL),
                ],
            ),
        ),
        (
            "between the floors",
            SMALL,
            LARGE,
            with(u(), &[wait(2_000), replacement(11)])
        ),
        (
            "a heard replacement stamps",
            SMALL,
            LARGE,
            with(u(), &[frame(10, at(9)), wait(15_000), replacement(11)]),
        ),
        (
            "an own msg2 restart, 20 s after the last frame",
            SMALL,
            LARGE,
            alloc::vec![
                msg1(10, 100, E1, 1, at(9), CL),
                frame(10, at(9)),
                wait(20_000),
                dial(1, 2, at(8), CL),
                msg2(1, E2, at(8)),
            ],
        ),
        (
            "an own msg2 restart, 1 s after the last frame",
            SMALL,
            LARGE,
            alloc::vec![
                msg1(10, 100, E1, 1, at(9), CL),
                frame(10, at(9)),
                wait(1_000),
                dial(1, 2, at(8), CL),
                msg2(1, E2, at(8)),
            ],
        ),
        // Beyond the model's tests: a move's new address, and a msg1 from
        // the address a frame roamed to.
        (
            "a crossing, then the first frame from the moved-to address",
            SMALL,
            LARGE,
            with(crossed(SMALL, LARGE, CL), &[frame(1, at(2))]),
        ),
        (
            "a msg1 from the address the peer roamed to",
            SMALL,
            LARGE,
            with(
                r(),
                &[
                    frame(10, at(7)),
                    wait(AGED),
                    msg1(11, 110, E1, 1, at(7), CL)
                ],
            ),
        ),
        (
            "a restart revealed in a rekey msg2",
            SMALL,
            LARGE,
            with(
                r(),
                &[
                    wait(30_000),
                    Event::RekeyStart { hs: Hs(20) },
                    Event::RekeyMsg2 {
                        hs: Hs(20),
                        epoch: E2
                    },
                    Event::RekeyCutover,
                ],
            ),
        ),
    ]
}

/// What one history's comparison found.
#[derive(Debug, Default)]
struct Ran {
    /// Each step where the core and the model differ.
    diffs: Vec<String>,
    /// Each named difference met, at the event index it was met.
    named: Vec<(usize, Named)>,
}

/// Run `history` through a judge and a driver side by side.
fn run(me: Node, peer: Node, history: &[Event]) -> Ran {
    let mut j = Judge::new(me, peer, Params::default());
    let mut d = Drive::new(me, peer);
    let mut ran = Ran::default();
    let mut now: Ms = 0;
    for (i, ev) in history.iter().enumerate() {
        if let Event::Advance(ms) = ev {
            now += ms;
        }
        let s = j.step(*ev);
        if *ev == Event::Restart {
            j.step(Event::Advance(now));
        }
        let did = d.step(*ev);
        if s.open {
            continue;
        }
        let mut expect = s.closes.clone();
        if s.rule == Some(LocalRule::LateSecondDial)
            && s.change == Some(Transition::Move)
            && did.change == s.change
            && j.peering.as_ref().is_some_and(|p| p.fallback.is_some())
        {
            expect = resync_close(&j);
            if let Some(p) = j.peering.as_mut() {
                p.fallback = None;
            }
            ran.named.push((i, Named::LateSecondDial));
        }
        if s.change == Some(Transition::Move)
            && did.change == s.change
            && let Some(p) = j.peering.as_mut()
            && p.heard != did.heard
        {
            p.heard = did.heard;
            ran.named.push((i, Named::HeardAfterMove));
        }
        if s.refused.is_none() {
            let named = match did.refused {
                Some(Refusal::Replay) => Some(Named::Replay),
                Some(Refusal::Silent) => Some(Named::Silent),
                Some(Refusal::Gate(_) | Refusal::Full) | None => None,
            };
            if let Some(n) = named {
                ran.named.push((i, n));
                break;
            }
        }
        let model = (
            s.class,
            s.refused.map(Refusal::Gate),
            s.reply,
            s.change,
            expect,
        );
        let core = (did.class, did.refused, did.reply, did.change, did.closes);
        if model != core {
            ran.diffs.push(format!(
                "event {i} {ev:?}: the model's {model:?}, the core's {core:?}"
            ));
            break;
        }
    }
    ran
}

#[test]
fn the_core_agrees_with_the_model_on_every_model_table_history() {
    let mut failed = Vec::new();
    let all = histories();
    for (name, me, peer, history) in &all {
        let ran = run(*me, *peer, history);
        for diff in ran.diffs {
            failed.push(format!("{name}: {diff}"));
        }
    }
    assert!(all.len() >= 40, "precondition: every history is restated");
    assert!(
        failed.is_empty(),
        "{} differ:\n{}",
        failed.len(),
        failed.join("\n")
    );
}

/// A named difference's history, where it must be met, and what it is.
fn named() -> Vec<(History, usize, Named)> {
    let mut restarts = alloc::vec![msg1(10, 100, E1, 1, at(9), CL)];
    for n in 1..=8u32 {
        restarts.push(wait(1_000));
        let port = u16::try_from(20 + n).expect("a small port");
        restarts.push(msg1(
            10 + n,
            (10 + n) * 10,
            Epoch(1 + n),
            1 + n,
            at(port),
            CL,
        ));
    }
    let mut silent = alloc::vec![msg1(10, 100, E1, 1, at(9), CL)];
    for n in 1..=4u32 {
        silent.push(wait(1_000));
        let port = u16::try_from(20 + n).expect("a small port");
        silent.push(msg1(10 + n, (10 + n) * 10, E1, 1 + n, at(port), CL));
    }
    alloc::vec![
        (
            (
                "heard after a move",
                SMALL,
                LARGE,
                crossed(SMALL, LARGE, CL)
            ),
            2,
            Named::HeardAfterMove,
        ),
        (
            ("late second dial", LARGE, SMALL, late_dial()),
            4,
            Named::LateSecondDial
        ),
        (
            (
                "a replayed ephemeral",
                SMALL,
                LARGE,
                alloc::vec![
                    msg1(10, 100, E1, 1, at(9), CL),
                    wait(1_000),
                    msg1(11, 110, E1, 2, at(8), CL),
                    wait(1_000),
                    msg1(10, 100, E1, 1, at(9), CL),
                ],
            ),
            4,
            Named::Replay,
        ),
        (
            ("the replay memory full", SMALL, LARGE, restarts),
            16,
            Named::Replay
        ),
        (("silent sessions", SMALL, LARGE, silent), 8, Named::Silent),
    ]
}

#[test]
fn every_named_difference_from_the_model_still_differs() {
    let mut failed = Vec::new();
    for ((name, me, peer, history), index, expect) in named() {
        let ran = run(me, peer, &history);
        if !ran.diffs.is_empty() {
            failed.push(format!("{name}: precondition: {:?}", ran.diffs));
        }
        if !ran.named.contains(&(index, expect)) {
            failed.push(format!(
                "{name}: {expect:?} not met at event {index}; met {:?}",
                ran.named
            ));
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
}
