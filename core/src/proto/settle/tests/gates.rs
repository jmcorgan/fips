//! Tests of the restart gates: one per gate edge and source, the replay
//! memory, the silent-session refusal, and the gates run beside the
//! reference model on its gate histories.

use alloc::vec::Vec;

use super::*;
use crate::proto::settle::model::history::{
    Addr, Binding, Bytes, Epoch as MEpoch, Event, Hs, LinkId, Node as MNode,
};
use crate::proto::settle::model::judge as m;
use crate::testutil::TestInstant;

/// The peer every test faces.
fn peer() -> NodeAddr {
    NodeAddr::from_bytes([2; 16])
}

/// The ephemeral digest of handshake `n`.
fn eph(n: u32) -> EphemeralDigest {
    let mut key = [0u8; 33];
    key[..4].copy_from_slice(&n.to_be_bytes());
    EphemeralDigest::of_noise_msg1(&key).expect("33 bytes carry an ephemeral")
}

fn epoch(n: u8) -> Option<super::Epoch> {
    Some([n; 8])
}

fn t(ms: u64) -> TestInstant {
    TestInstant(ms)
}

/// An unheard peering installed at `at`.
fn unheard(at: u64) -> Liveness<TestInstant> {
    Liveness {
        heard: false,
        installed: t(at),
        last: None,
    }
}

/// A heard peering installed at `at`, its last frame at `last`.
fn heard(at: u64, last: Option<u64>) -> Liveness<TestInstant> {
    Liveness {
        heard: true,
        installed: t(at),
        last: last.map(t),
    }
}

/// A msg1 of `source` from handshake `hs` at epoch 1, facing `held`.
fn msg1(source: Source, held: Option<Liveness<TestInstant>>, hs: u32) -> Ask<TestInstant> {
    Ask {
        source,
        held,
        ephemeral: Some(eph(hs)),
        epoch: epoch(1),
        memory: None,
    }
}

/// A restart found at a msg2 of `source`, facing `held`.
fn msg2(source: Source, held: Liveness<TestInstant>) -> Ask<TestInstant> {
    Ask {
        source,
        held: Some(held),
        ephemeral: None,
        epoch: epoch(2),
        memory: None,
    }
}

fn gate(g: &mut Gates<TestInstant>, ask: Ask<TestInstant>, at: u64) -> Option<Refusal> {
    g.gate(peer(), ask, t(at), &Params::default())
}

#[test]
fn the_unheard_floor_refuses_until_one_second_and_accepts_at_it() {
    let mut g = Gates::new();
    let early = gate(&mut g, msg1(Source::Replacement, Some(unheard(0)), 2), 999);
    assert_eq!(early, Some(Refusal::Unheard));
    let at = gate(
        &mut g,
        msg1(Source::Replacement, Some(unheard(0)), 2),
        1_000,
    );
    assert_eq!(at, None, "accepted at exactly one second");
}

#[test]
fn the_heard_floor_counts_from_the_last_frame() {
    let mut g = Gates::new();
    let held = heard(0, Some(5_000));
    let early = gate(&mut g, msg1(Source::Restart, Some(held), 2), 19_999);
    assert_eq!(early, Some(Refusal::Heard), "within 15 s of the last frame");
    let late = gate(&mut g, msg1(Source::Restart, Some(held), 2), 20_000);
    assert_eq!(late, None);
}

#[test]
fn the_heard_floor_counts_from_installation_when_no_frame_has_arrived() {
    let mut g = Gates::new();
    let held = heard(2_000, None);
    let early = gate(&mut g, msg1(Source::Replacement, Some(held), 2), 16_999);
    assert_eq!(early, Some(Refusal::Heard));
    let late = gate(&mut g, msg1(Source::Replacement, Some(held), 2), 17_000);
    assert_eq!(late, None);
}

#[test]
fn the_dampener_refuses_until_its_ceiling_after_the_last_accepted_restart() {
    let mut g = Gates::new();
    let first = gate(
        &mut g,
        msg1(Source::Restart, Some(heard(0, Some(0))), 2),
        15_000,
    );
    assert_eq!(first, None, "precondition: the first restart is accepted");
    assert_eq!(
        g.stamp(&peer()),
        Some(t(15_000)),
        "a heard peering's teardown stamps"
    );
    // The new peering is unheard and past its floor; only the dampener
    // holds. A refusal at 29.999 s must not slide the ceiling.
    let next = || msg1(Source::Restart, Some(unheard(15_000)), 3);
    assert_eq!(gate(&mut g, next(), 29_999), Some(Refusal::Dampened));
    assert_eq!(
        gate(&mut g, next(), 30_000),
        None,
        "the ceiling counts from the acceptance"
    );
}

#[test]
fn an_own_msg2_restart_goes_through_the_gate_and_is_accepted_inside_its_floors() {
    // A heard peering one second after its last frame, inside the heard
    // floor and inside the dampener's ceiling: a msg1 restart is refused,
    // and a restart found at this node's own msg2 is not.
    let mut g = Gates::new();
    let held = heard(0, Some(0));
    assert_eq!(
        gate(&mut g, msg1(Source::Restart, Some(held), 2), 15_000),
        None
    );
    let now = heard(15_000, Some(16_000));
    let restart = gate(&mut g, msg1(Source::Restart, Some(now), 3), 17_000);
    assert_eq!(
        restart,
        Some(Refusal::Heard),
        "precondition: a msg1 restart is refused"
    );
    assert_eq!(gate(&mut g, msg2(Source::OwnMsg2, now), 17_000), None);
}

/// Records current behaviour (rules S-05, S-25 and S-32: neither msg2 source stamps the
/// dampener): open to change by decision. Its other assertions are not.
#[test]
fn an_own_msg2_restart_does_not_stamp_the_dampener() {
    let mut g = Gates::new();
    assert_eq!(
        gate(&mut g, msg2(Source::OwnMsg2, heard(0, Some(0))), 20_000),
        None
    );
    assert_eq!(
        gate(&mut g, msg2(Source::RekeyMsg2, heard(0, Some(0))), 20_000),
        None
    );
    assert_eq!(g.stamp(&peer()), None);
}

#[test]
fn the_replay_memory_refuses_an_ephemeral_that_already_promoted_an_unheard_peering() {
    let mut g = Gates::new();
    let p = Params::default();
    g.promoted(peer(), eph(1), t(0), None, &p);
    assert_eq!(
        gate(
            &mut g,
            msg1(Source::Replacement, Some(unheard(0)), 2),
            1_000
        ),
        None
    );
    g.promoted(peer(), eph(2), t(1_000), None, &p);
    let replay = gate(
        &mut g,
        msg1(Source::Replacement, Some(unheard(1_000)), 1),
        2_000,
    );
    assert_eq!(replay, Some(Refusal::Replayed));
    let later = gate(
        &mut g,
        msg1(Source::Replacement, Some(unheard(1_000)), 1),
        15_000,
    );
    assert_eq!(later, None, "the memory's window is the interval");
}

#[test]
fn the_replay_memory_holds_at_most_eight() {
    let mut g = Gates::new();
    let p = Params::default();
    let mut installed = 0;
    g.promoted(peer(), eph(0), t(0), None, &p);
    for hs in 1..8u32 {
        let at = u64::from(hs) * 1_000;
        let ask = msg1(Source::Replacement, Some(unheard(installed)), hs);
        assert_eq!(
            gate(&mut g, ask, at),
            None,
            "precondition: replacement {hs} accepted"
        );
        g.promoted(peer(), eph(hs), t(at), None, &p);
        installed = at;
    }
    let ninth = gate(
        &mut g,
        msg1(Source::Replacement, Some(unheard(installed)), 8),
        8_000,
    );
    assert_eq!(ninth, Some(Refusal::ReplayFull), "eight ephemerals spent");
}

#[test]
fn a_frame_forgets_the_replay_memory_and_the_silent_sessions() {
    let mut g = Gates::new();
    let p = Params::default();
    g.promoted(peer(), eph(1), t(0), None, &p);
    for hs in 10..13 {
        g.ended(peer(), epoch(1), Some(eph(hs)), t(0), None, &p);
    }
    let silent = gate(&mut g, msg1(Source::NotHeld, None, 20), 1_000);
    assert_eq!(
        silent,
        Some(Refusal::Silent),
        "precondition: the back-off runs"
    );
    g.heard(&peer());
    assert_eq!(gate(&mut g, msg1(Source::NotHeld, None, 20), 1_000), None);
    let replay = gate(
        &mut g,
        msg1(Source::Replacement, Some(unheard(0)), 1),
        2_000,
    );
    assert_eq!(replay, None, "the replayed ephemeral is forgotten");
}

/// Records current behaviour (rule S-06: the third session and the 30 s refusal): open to
/// change by decision. Its other assertions are not.
#[test]
fn silent_sessions_start_a_refusal_at_the_third_in_a_row() {
    let mut g = Gates::new();
    let p = Params::default();
    assert_eq!(
        g.ended(peer(), epoch(1), Some(eph(1)), t(0), None, &p),
        None
    );
    assert_eq!(
        g.ended(peer(), epoch(1), Some(eph(1)), t(0), None, &p),
        None,
        "a session counted once"
    );
    assert_eq!(
        g.ended(peer(), epoch(1), Some(eph(2)), t(0), None, &p),
        None
    );
    assert_eq!(
        gate(&mut g, msg1(Source::NotHeld, None, 9), 0),
        None,
        "two in a row refuse nothing"
    );
    let third = g.ended(peer(), epoch(1), Some(eph(3)), t(0), None, &p);
    assert_eq!(third, Some(Duration::from_secs(30)));
    assert_eq!(
        gate(&mut g, msg1(Source::NotHeld, None, 9), 29_999),
        Some(Refusal::Silent)
    );
    let other = Ask {
        epoch: epoch(7),
        ..msg1(Source::NotHeld, None, 9)
    };
    assert_eq!(
        gate(&mut g, other, 1_000),
        None,
        "another epoch is not refused"
    );
    assert_eq!(
        gate(&mut g, msg1(Source::NotHeld, None, 9), 30_000),
        None,
        "the back-off ends"
    );
}

/// Records current behaviour (rule S-06: the 30 s refusal doubling to 600 s): open to change by
/// decision. Its other assertions are not.
#[test]
fn each_further_silent_session_doubles_the_refusal_up_to_its_cap() {
    let mut g = Gates::new();
    let p = Params::default();
    let got: Vec<Option<u64>> = (1..=9u32)
        .map(|hs| {
            g.ended(peer(), epoch(1), Some(eph(hs)), t(u64::from(hs)), None, &p)
                .map(|d| d.as_secs())
        })
        .collect();
    let want = [
        None,
        None,
        Some(30),
        Some(60),
        Some(120),
        Some(240),
        Some(480),
        Some(600),
        Some(600),
    ];
    assert_eq!(got, want);
}

/// Identity `n` of a population, none of them [`peer`].
fn identity(n: u32) -> NodeAddr {
    let mut b = [0u8; 16];
    b[..4].copy_from_slice(&n.to_be_bytes());
    b[15] = 1;
    NodeAddr::from_bytes(b)
}

#[test]
fn gate_memory_holds_no_entry_once_an_identitys_state_has_lapsed() {
    // As the node's replay memory has it: a query that finds no memory
    // inserts none, and an entry whose stamp, replays and silence have
    // all lapsed is dropped.
    let p = Params::default();
    let mut g: Gates<TestInstant> = Gates::new();
    for i in 0..10_000u32 {
        let ask = Ask {
            source: Source::NotHeld,
            held: None,
            ephemeral: Some(eph(i)),
            epoch: epoch(1),
            memory: None,
        };
        assert_eq!(
            g.gate(identity(i), ask, t(u64::from(i)), &p),
            None,
            "precondition: a msg1 from identity {i} not held is accepted"
        );
    }
    // A hundred more identities with live state: a promotion's replay
    // entry, three silent sessions that start a refusal, and an accepted
    // restart of a heard peering, which stamps the dampener.
    for i in 20_000..20_100u32 {
        let at = t(20_000);
        g.promoted(identity(i), eph(i), at, None, &p);
        for hs in 0..3 {
            let _ = g.ended(identity(i), epoch(1), Some(eph(i * 4 + hs)), at, None, &p);
        }
        let restart = Ask {
            epoch: epoch(2),
            ..msg1(Source::Restart, Some(heard(0, Some(0))), i)
        };
        assert_eq!(
            g.gate(identity(i), restart, at, &p),
            None,
            "precondition: identity {i}'s restart is accepted"
        );
    }
    let live = g.peers.len();
    assert!(
        live >= 100,
        "precondition: every identity with live state keeps its entry, {live} held"
    );
    // An hour later every stamp, replay and silence has lapsed; one more
    // msg1 from an identity not held.
    let ask = msg1(Source::NotHeld, None, 1);
    let _ = g.gate(identity(30_000), ask, t(3_600_000), &p);
    assert_eq!(
        g.peers.len(),
        0,
        "defect: gate memory holds {} entries an hour after the last state, \
         where the node's memory holds none",
        g.peers.len()
    );
}

#[test]
fn the_refused_count_goes_with_its_silent_session_record() {
    // The msg1s a silent-session refusal refuses are counted on the
    // record, for the shell's lines, so the count lapses with the record
    // and the gates hold no count beside it to outlive it.
    let p = Params::default();
    let mut g: Gates<TestInstant> = Gates::new();
    assert_eq!(g.count_refused(&peer()), None, "no record counts nothing");
    for hs in 1..=3 {
        let _ = g.ended(peer(), epoch(1), Some(eph(hs)), t(0), None, &p);
    }
    assert_eq!(g.count_refused(&peer()), Some(1));
    assert_eq!(g.count_refused(&peer()), Some(2));
    assert!(
        g.ended(peer(), epoch(1), Some(eph(4)), t(1_000), None, &p)
            .is_some(),
        "precondition: a fourth silent session extends the refusal"
    );
    assert_eq!(
        g.take_refused(&peer()),
        2,
        "the refusal reports what the one before it refused"
    );
    assert_eq!(
        g.count_refused(&peer()),
        Some(1),
        "and counts again from none"
    );
    let _ = g.ended(peer(), epoch(2), Some(eph(5)), t(2_000), None, &p);
    assert_eq!(
        g.take_refused(&peer()),
        0,
        "a session at another epoch starts a record that has refused nothing"
    );
    assert_eq!(g.count_refused(&peer()), Some(1));
    // Long past the record's horizon, another identity's session end drops
    // the lapsed record.
    let _ = g.ended(identity(1), epoch(1), Some(eph(6)), t(3_600_000), None, &p);
    assert_eq!(
        g.count_refused(&peer()),
        None,
        "defect: an identity whose record has lapsed still has its refusals counted"
    );
}

#[test]
fn the_default_intervals_are_the_frcs() {
    let model = m::Params::default();
    let core = Params::default();
    assert_eq!(u128::from(model.unheard), core.unheard.as_millis());
    assert_eq!(u128::from(model.interval), core.interval.as_millis());
}

/// The gates beside a model `Judge`: each msg1 the model classes as rule 1,
/// 2 or 3.3, and each restart found at a msg2, asks the gate the same
/// source, and the refusal and the dampener's stamp must agree.
struct Beside {
    judge: m::Judge,
    gates: Gates<TestInstant>,
    held: Option<Liveness<TestInstant>>,
}

impl Beside {
    fn new() -> Self {
        Self {
            judge: m::Judge::new(m_small(), m_large(), m::Params::default()),
            gates: Gates::new(),
            held: None,
        }
    }

    /// Runs `history`, failing at the first disagreement.
    fn run(&mut self, name: &str, history: &[Event]) {
        let p = Params::default();
        let interval = u64::try_from(p.interval.as_millis()).expect("the interval fits");
        for (i, ev) in history.iter().enumerate() {
            let step = self.judge.step(*ev);
            let now = t(self.judge.now);
            let asked = match *ev {
                Event::Msg1 { hs, epoch, .. } => {
                    let source = match step.class {
                        Some(m::Class::NotHeld) => Some(Source::NotHeld),
                        Some(m::Class::Restart) => Some(Source::Restart),
                        Some(m::Class::Replacement) => Some(Source::Replacement),
                        _ => None,
                    };
                    source.map(|source| {
                        let ask = Ask {
                            source,
                            held: self.held,
                            ephemeral: Some(eph(hs.0)),
                            epoch: Some(epoch_of(epoch)),
                            memory: None,
                        };
                        let r = self.gates.gate(peer(), ask, now, &p);
                        if r.is_none() {
                            self.held = Some(unheard(now.0));
                            self.gates.promoted(peer(), eph(hs.0), now, None, &p);
                        }
                        r
                    })
                }
                Event::Msg2 { epoch, .. } => match step.change {
                    Some(m::Transition::Promote) => {
                        self.held = Some(heard(now.0, None));
                        None
                    }
                    Some(m::Transition::Replace) => {
                        let held = self.held.expect("a replace tears a peering down");
                        let ask = Ask {
                            epoch: Some(epoch_of(epoch)),
                            ..msg2(Source::OwnMsg2, held)
                        };
                        let r = self.gates.gate(peer(), ask, now, &p);
                        if r.is_none() {
                            self.held = Some(heard(now.0, None));
                        }
                        Some(r)
                    }
                    _ => None,
                },
                Event::RekeyCutover if step.change == Some(m::Transition::Restarted) => {
                    let held = self.held.expect("a rekey keeps its peering");
                    Some(
                        self.gates
                            .gate(peer(), msg2(Source::RekeyMsg2, held), now, &p),
                    )
                }
                Event::Frame { .. } => {
                    if let Some(h) = self.held.as_mut() {
                        h.heard = true;
                        h.last = Some(now);
                    }
                    self.gates.heard(&peer());
                    None
                }
                Event::Advance(_)
                | Event::Dial { .. }
                | Event::Msg2Sent { .. }
                | Event::Timeout { .. }
                | Event::Switch { .. }
                | Event::Follow { .. }
                | Event::RekeyStart { .. }
                | Event::RekeyMsg2 { .. }
                | Event::RekeyCutover
                | Event::Close { .. }
                | Event::Lost
                | Event::Restart => None,
            };
            if let Some(r) = asked {
                assert_eq!(
                    refusal_of(r),
                    step.refused,
                    "{name}, event {i} ({ev:?}): the refusal"
                );
            }
            // The stamp while it still counts: the gates drop an identity
            // whose stamp, replays and silence have all lapsed, where the
            // model keeps its last stamp for good, and a stamp past the
            // interval refuses nothing on either side.
            let counts = |s: u64| self.judge.now.saturating_sub(s) < interval;
            let stamp = self
                .gates
                .stamp(&peer())
                .map(|s| s.0)
                .filter(|s| counts(*s));
            assert_eq!(
                stamp,
                self.judge.stamp.filter(|s| counts(*s)),
                "{name}, event {i} ({ev:?}): the dampener's stamp"
            );
        }
    }
}

fn m_small() -> MNode {
    MNode(1)
}

fn m_large() -> MNode {
    MNode(2)
}

fn epoch_of(e: MEpoch) -> super::Epoch {
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&e.0.to_be_bytes());
    out
}

/// The model's name for a core refusal; the replay memory and the silent
/// sessions have none, and no gate history reaches them.
fn refusal_of(r: Option<Refusal>) -> Option<m::Gate> {
    r.map(|r| match r {
        Refusal::Unheard => m::Gate::Unheard,
        Refusal::Heard => m::Gate::Heard,
        Refusal::Dampened => m::Gate::Dampened,
        Refusal::Replayed | Refusal::ReplayFull | Refusal::Silent | Refusal::Redialed => {
            panic!("the model has no {r:?} refusal")
        }
    })
}

fn at(port: u16) -> Addr {
    Addr {
        transport: 1,
        at: port,
    }
}

fn ev_msg1(hs: u32, bytes: u32, epoch: u32, link: u32, from: u16) -> Event {
    Event::Msg1 {
        hs: Hs(hs),
        bytes: Bytes(bytes),
        epoch: MEpoch(epoch),
        link: LinkId(link),
        from: at(from),
        binding: Binding::Connectionless,
        sent: true,
    }
}

/// The model's gate tests' replacement: a same-epoch msg1 on the link,
/// from its setup address, on a link too young to rekey. From a new
/// address, the msg1 of a peering heard from would be a redial, which no
/// gate floor holds.
fn repl(hs: u32) -> Event {
    ev_msg1(hs, hs * 10, 1, hs, 9)
}

fn frame(hs: u32) -> Event {
    Event::frame(Hs(hs), at(9))
}

fn wait(ms: u64) -> Event {
    Event::Advance(ms)
}

#[test]
fn the_gates_agree_with_the_model_on_every_gate_history() {
    // The histories of `model/tests/gates.rs`, by its test names, and the
    // restart at an own msg2 one second after a frame.
    let first = ev_msg1(10, 100, 1, 1, 9);
    let dial = |hs: u32, link: u32, to: u16| Event::Dial {
        hs: Hs(hs),
        link: LinkId(link),
        to: at(to),
        binding: Binding::Connectionless,
    };
    let own = |hs: u32, e: u32, from: u16| Event::Msg2 {
        hs: Hs(hs),
        epoch: MEpoch(e),
        from: at(from),
    };
    let histories: Vec<(&str, Vec<Event>)> = alloc::vec![
        (
            "unheard floor, early",
            alloc::vec![first, wait(999), repl(11)]
        ),
        (
            "unheard floor, at it",
            alloc::vec![first, wait(1_000), repl(11)]
        ),
        (
            "heard floor from the last frame",
            alloc::vec![
                first,
                wait(5_000),
                frame(10),
                wait(14_999),
                repl(11),
                wait(1),
                repl(12)
            ],
        ),
        (
            "heard floor from installation",
            alloc::vec![
                dial(1, 1, 9),
                wait(2_000),
                own(1, 1, 9),
                wait(14_999),
                repl(11),
                wait(1),
                repl(12)
            ],
        ),
        (
            "heard from the first frame, before",
            alloc::vec![first, wait(1_500), repl(11)]
        ),
        (
            "heard from the first frame, after",
            alloc::vec![first, wait(1_000), frame(10), wait(500), repl(11)],
        ),
        (
            "dampener",
            alloc::vec![
                first,
                frame(10),
                wait(15_000),
                ev_msg1(11, 110, 2, 2, 8),
                wait(14_999),
                ev_msg1(12, 120, 3, 3, 7),
                wait(1),
                ev_msg1(12, 120, 3, 3, 7),
            ],
        ),
        (
            "between the floors",
            alloc::vec![first, wait(2_000), repl(11)]
        ),
        ("stamp, unheard", alloc::vec![first, wait(2_000), repl(11)]),
        (
            "stamp, heard",
            alloc::vec![first, frame(10), wait(15_000), repl(11)]
        ),
        (
            "own msg2 restart",
            alloc::vec![first, frame(10), wait(20_000), dial(1, 2, 8), own(1, 2, 8)],
        ),
        (
            "own msg2 restart inside the heard floor",
            alloc::vec![first, frame(10), wait(1_000), dial(1, 2, 8), own(1, 2, 8)],
        ),
        (
            "rekey msg2 restart",
            alloc::vec![
                first,
                frame(10),
                wait(30_000),
                Event::RekeyStart { hs: Hs(20) },
                Event::RekeyMsg2 {
                    hs: Hs(20),
                    epoch: MEpoch(2)
                },
                Event::RekeyCutover,
            ],
        ),
    ];
    for (name, history) in &histories {
        Beside::new().run(name, history);
    }
}

#[test]
fn a_redial_is_not_held_by_the_heard_floor() {
    // A heard peering whose last frame was just now: a replacement is held
    // by the heard floor, a redial is not.
    let mut g = Gates::new();
    let held = heard(0, Some(40_000));
    assert_eq!(
        gate(&mut g, msg1(Source::Replacement, Some(held), 2), 40_100),
        Some(Refusal::Heard)
    );
    assert_eq!(
        gate(&mut g, msg1(Source::Redial, Some(held), 3), 40_100),
        None
    );
    assert_eq!(g.stamp(&peer()), None, "an answered redial stamps nothing");
}

#[test]
fn the_redial_memory_refuses_a_seen_ephemeral_and_a_full_memory_until_it_ages_out() {
    let params = Params::default();
    let mut g = Gates::new();
    let held = heard(0, Some(0));
    g.redialed(peer(), eph(2), t(40_000), &params);
    assert_eq!(
        gate(&mut g, msg1(Source::Redial, Some(held), 2), 41_000),
        Some(Refusal::Redialed)
    );
    for n in 3..(3 + params.replays as u32 - 1) {
        g.redialed(peer(), eph(n), t(41_000), &params);
    }
    assert_eq!(
        gate(&mut g, msg1(Source::Redial, Some(held), 99), 42_000),
        Some(Refusal::Redialed),
        "a full memory refuses a fresh ephemeral too"
    );
    assert_eq!(
        gate(&mut g, msg1(Source::Redial, Some(held), 99), 56_000),
        None,
        "every entry has aged out"
    );
}

#[test]
fn the_swap_stamps_the_dampener_only_for_a_heard_peering_and_clears_the_redial_memory() {
    let params = Params::default();
    let mut g = Gates::new();
    g.redialed(peer(), eph(2), t(40_000), &params);
    g.swapped(peer(), false, t(40_500));
    assert_eq!(g.stamp(&peer()), None);
    assert_eq!(
        gate(
            &mut g,
            msg1(Source::Redial, Some(heard(40_500, Some(40_500))), 2),
            41_000
        ),
        None,
        "the swap forgot the memory"
    );
    g.swapped(peer(), true, t(41_000));
    assert_eq!(g.stamp(&peer()), Some(t(41_000)));
    assert_eq!(
        gate(
            &mut g,
            msg1(Source::Redial, Some(heard(41_000, Some(41_000))), 3),
            55_999
        ),
        Some(Refusal::Dampened)
    );
    assert_eq!(
        gate(
            &mut g,
            msg1(Source::Redial, Some(heard(41_000, Some(41_000))), 3),
            56_000
        ),
        None
    );
}

#[test]
fn the_redial_memory_outlives_a_frame_and_the_lapse_of_the_rest_of_the_identitys_memory() {
    // The node forgets an identity's redial memory only at its swap: a
    // frame of the held peering, which forgets the replays and the silent
    // sessions, leaves it, and an identity with no stamp, replays or
    // silence is kept while it holds a live redial ephemeral.
    let params = Params::default();
    let mut g = Gates::new();
    g.redialed(peer(), eph(2), t(40_000), &params);
    g.heard(&peer());
    assert_eq!(
        gate(
            &mut g,
            msg1(Source::Redial, Some(heard(0, Some(40_500))), 2),
            41_000
        ),
        Some(Refusal::Redialed),
        "defect: the redial memory went with the frame or the lapse"
    );
}

#[test]
fn the_redial_memory_outlives_the_first_frame_of_a_heard_session_and_a_move() {
    // The first frame of a session heard from its install and a move that
    // makes a peering heard each forget part of the identity's memory, and
    // neither forgets its redial memory, which only the swap does.
    let params = Params::default();
    let mut g = Gates::new();
    g.redialed(peer(), eph(2), t(40_000), &params);
    g.framed(&peer());
    g.forget(&peer());
    assert_eq!(
        gate(
            &mut g,
            msg1(Source::Redial, Some(heard(0, Some(40_500))), 2),
            41_000
        ),
        Some(Refusal::Redialed),
        "defect: the redial memory went with the frame or the move"
    );
}
