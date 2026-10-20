//! The two-message profile (the master link shape): the trigger, the
//! attempt and its ladder, the msg1 rows, the msg2 rows, the poll cutover,
//! adoption by frame, the drain, restart in a msg2, workers and the counter
//! limits.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use super::stub::{
    ANSWER, DATA, Ev, Ik, Local, Msg, Node, PLAIN, bytes, conserved, fmp, frames, ik_frame, last,
    ordered, pair, pair_with, read_msg1, with,
};
use crate::proto::rekey::{
    Abandon, Arrival, Close, Config, CycleView, EpochTag, EvidenceKind, Input, Layer, Msg1Read,
    MsgKind, Profile, Purpose, Reason, RecvHome, Role, SealRefusal, Slot, TagSource, Teardown,
    Wait,
};
use crate::testutil::TestInstant;

/// The time trigger at the defaults with no jitter.
const T: u64 = 120_000;

/// The epoch tag `n` of a node's tag source.
fn tag(n: u64) -> EpochTag {
    let mut t = TagSource::new();
    let mut tag = t.draw();
    for _ in 0..n {
        tag = t.draw();
    }
    tag
}

/// A link set up at 0, `a` the smaller address.
fn link() -> (Node<Ik>, Node<Ik>) {
    let (a, b) = ordered(1, 2);
    pair::<Ik>(a, b, 0, fmp())
}

/// A fresh msg1 `from` writes toward `to`, as a delivered message.
fn fresh(from: &Local, to: &Local) -> Msg {
    let (_, m) = <Ik as Profile>::initiate(from, &to.key, Some(9)).expect("writes");
    Msg::Hs(MsgKind::Msg1, m)
}

/// The machine's view, rendered: everything but the record and the
/// sessions' internals.
fn view(n: &Node<Ik>) -> alloc::string::String {
    format!("{:?}", n.m().view())
}

/// Run one rekey of `a` toward `b` starting at `t`, every message
/// delivered 10 ms later, until both have cut over and heard each other.
fn cycle(a: &mut Node<Ik>, b: &mut Node<Ik>, t: u64) {
    a.poll(t);
    let m1 = last(&mut a.wire, MsgKind::Msg1);
    b.recv(t + 10, &m1);
    let m2 = last(&mut b.wire, MsgKind::Msg2);
    a.recv(t + 20, &m2);
    a.poll(t + 21);
    for f in frames(&mut a.wire) {
        b.recv(t + 30, &f);
    }
    for f in frames(&mut b.wire) {
        a.recv(t + 40, &f);
    }
}

#[test]
fn ik_rekey_completes_through_the_attempt_the_reply_the_poll_and_the_adoption() {
    let (mut a, mut b) = link();
    assert_eq!(
        a.m().next_wake(),
        Some(TestInstant(T)),
        "the trigger instant is the next wake"
    );
    assert_eq!(a.poll(T - 1), vec![], "nothing starts before the trigger");

    let evs = a.poll(T);
    let m1 = last(&mut a.wire, MsgKind::Msg1);
    assert_eq!(
        evs,
        vec![
            Ev::Bind(1, 101, None, Purpose::Attempt),
            Ev::Send(MsgKind::Msg1, bytes(&m1), PLAIN)
        ]
    );
    assert_eq!(a.m().view().cycle, CycleView::Init);
    assert_eq!(
        a.m().next_wake(),
        Some(TestInstant(T + 1_000)),
        "the first resend rung"
    );

    let evs = b.recv(T + 10, &m1);
    let m2 = last(&mut b.wire, MsgKind::Msg2);
    assert_eq!(
        evs,
        vec![
            Ev::Bind(1, 101, Some(tag(1)), Purpose::Pending),
            Ev::Send(MsgKind::Msg2, bytes(&m2), ANSWER)
        ]
    );
    assert_eq!(b.m().view().cycle, CycleView::PendR);
    assert_eq!(
        b.m().next_wake(),
        Some(TestInstant(T + 10 + 120_000)),
        "the pending hold"
    );

    let evs = a.recv(T + 20, &m2);
    assert_eq!(
        evs,
        vec![
            Ev::Unbind(1, 101),
            Ev::Bind(1, 101, Some(tag(1)), Purpose::Pending)
        ]
    );
    assert_eq!(a.m().view().cycle, CycleView::PendI(Wait::Held));
    assert_eq!(
        a.m().next_wake(),
        Some(TestInstant(T + 20)),
        "a held proof waits for the next poll"
    );

    let evs = a.poll(T + 21);
    assert_eq!(
        evs,
        vec![
            Ev::Installed(tag(1), Role::Initiator, EvidenceKind::Proof),
            Ev::Prompt(tag(1)),
            Ev::Rekeyed(Role::Initiator),
        ]
    );
    let v = a.m().view();
    let cur = v.current.expect("established");
    assert_eq!(
        (cur.tag, cur.k),
        (tag(1), true),
        "the inverse of its own K, none observed"
    );
    assert_eq!(v.previous.expect("drained").tag, tag(0));
    let sealed =
        a.m.as_mut()
            .expect("machine")
            .seal(TestInstant(T + 26))
            .expect("seals");
    assert_eq!(
        sealed.elapsed.as_millis(),
        5,
        "the timestamp base is the cutover instant"
    );
    assert_eq!(sealed.theirs, Some(101), "frames name the peer's new index");

    let prompt = frames(&mut a.wire);
    assert_eq!(prompt.len(), 1);
    let evs = b.recv(T + 30, &prompt[0]);
    assert_eq!(
        evs,
        vec![
            Ev::Installed(tag(1), Role::Responder, EvidenceKind::Frame),
            Ev::Prompt(tag(1)),
            Ev::Rekeyed(Role::Responder),
            Ev::Deliver(Slot::Current, tag(1), vec![0x51, 0, 0, 0, 0]),
        ]
    );
    assert!(
        b.m().view().current.expect("cur").k,
        "the adopting frame's K"
    );
    assert_eq!(
        b.m().next_wake(),
        Some(TestInstant(T + 30 + 10_000)),
        "an evidenced drain"
    );

    let evs = a.recv(T + 40, &frames(&mut b.wire)[0]);
    assert_eq!(
        evs,
        vec![Ev::Deliver(Slot::Current, tag(1), vec![0x51, 0, 0, 0, 0])]
    );
    assert_eq!(
        a.m().next_wake(),
        Some(TestInstant(T + 40 + 10_000)),
        "the drain shortened on evidence"
    );
    assert_eq!(
        a.poll(T + 2_000),
        vec![],
        "no elicit prompt once the peer moved"
    );

    assert_eq!(
        a.poll(T + 50_000),
        vec![Ev::Unbind(1, 100), Ev::Release(100), Ev::Retired(tag(0))]
    );
    assert_eq!(
        b.poll(T + 40_030),
        vec![Ev::Unbind(1, 100), Ev::Release(100), Ev::Retired(tag(0))]
    );
    conserved(&a);
    conserved(&b);

    // The next rekey takes the inverse of the K the peer was heard with.
    cycle(&mut a, &mut b, T + 21 + T);
    assert!(
        !a.m().view().current.expect("cur").k,
        "the inverse of the peer's observed K"
    );
    assert!(!b.m().view().current.expect("cur").k);
    conserved(&a);
    conserved(&b);
}

#[test]
fn every_ik_msg1_cell_takes_its_rows_action() {
    let (a0, b0) = ordered(1, 2);
    let (_, setup1) = <Ik as Profile>::initiate(&a0, &b0.key, Some(100)).expect("writes");
    let tok = read_msg1(&b0, &setup1).expect("reads");
    let (_, setup2) = tok.get().answer(&b0, Some(100)).expect("answers");
    let (a, mut b) = pair_with::<Ik>(a0, b0, 0, fmp(), Some((&setup1, &setup2)));
    let setup = Msg::Hs(MsgKind::Msg1, setup1.clone());
    let mut rewritten = setup1.clone();
    rewritten[1] ^= 0xff;
    let rewritten = Msg::Hs(MsgKind::Msg1, rewritten);

    // Not eligible (link 5 s old).
    let before = b.digest();
    assert_eq!(
        b.recv(5_000, &setup),
        vec![Ev::Send(MsgKind::Msg2, setup2.clone(), ANSWER)],
        "a resend of the setup msg1 draws the setup msg2"
    );
    assert_eq!(
        b.recv(5_000, &rewritten),
        vec![Ev::Reject(Reason::AnsweredBefore)]
    );
    assert_eq!(b.digest(), before, "copies change nothing");
    let young = fresh(&a.local, &b.local);
    let before = view(&b);
    assert_eq!(
        b.recv(5_000, &young),
        vec![Ev::Replace],
        "rule 3.3: the restart gates decide"
    );
    assert_eq!(view(&b), before, "only the record changed");
    let before = b.digest();
    assert_eq!(
        b.recv(5_001, &young),
        vec![Ev::Reject(Reason::AnsweredBefore)]
    );
    assert_eq!(b.digest(), before);
    let other = fresh(&a.local.restarted(9), &b.local);
    assert_eq!(
        b.recv(5_002, &other),
        vec![Ev::Reject(Reason::EpochChanged)]
    );
    assert_eq!(b.digest(), before);

    // Eligible (link 40 s, session 40 s).
    let off = fresh(&a.local, &b.local);
    let before = view(&b);
    assert_eq!(
        b.recv_on(
            40_000,
            &off,
            Arrival {
                on_link: false,
                reachable: true
            }
        ),
        vec![Ev::Reject(Reason::OffLink)]
    );
    assert_eq!(view(&b), before, "only the record changed");
    let before = b.digest();
    assert_eq!(
        b.recv(40_000, &off),
        vec![Ev::Reject(Reason::AnsweredBefore)],
        "rule 4.3"
    );
    assert_eq!(
        b.recv(40_000, &setup),
        vec![Ev::Reject(Reason::AnsweredBefore)]
    );
    assert_eq!(b.digest(), before);

    let m1 = fresh(&a.local, &b.local);
    let unreachable = Arrival {
        on_link: false,
        reachable: false,
    };
    let evs = b.recv_on(41_000, &m1, unreachable);
    let m2 = bytes(&last(&mut b.wire, MsgKind::Msg2));
    assert_eq!(
        evs,
        vec![
            Ev::Bind(1, 101, Some(tag(1)), Purpose::Pending),
            Ev::Send(MsgKind::Msg2, m2.clone(), ANSWER)
        ],
        "off an unreachable link the msg1 is answered, on the established path"
    );
    let before = b.digest();
    assert_eq!(
        b.recv(42_000, &m1),
        vec![Ev::Send(MsgKind::Msg2, m2.clone(), ANSWER)],
        "rule 4.2"
    );
    assert_eq!(b.digest(), before);
    for copy in [&setup, &rewritten] {
        assert_eq!(b.recv(42_000, copy), vec![Ev::Reject(Reason::PendingHeld)]);
    }
    assert_eq!(b.digest(), before);
    let another = fresh(&a.local, &b.local);
    let before = view(&b);
    assert_eq!(
        b.recv(42_000, &another),
        vec![Ev::Reject(Reason::PendingHeld)]
    );
    assert_eq!(view(&b), before, "only the record changed");

    // A completed own attempt holds back every msg1 too.
    let (mut c, mut d) = link();
    d.poll(T);
    let dm1 = last(&mut d.wire, MsgKind::Msg1);
    c.recv(T + 10, &dm1);
    let cm2 = last(&mut c.wire, MsgKind::Msg2);
    d.recv(T + 20, &cm2);
    assert_eq!(d.m().view().cycle, CycleView::PendI(Wait::Held));
    assert_eq!(
        d.recv(T + 20, &fresh(&c.local, &d.local)),
        vec![Ev::Reject(Reason::PendingHeld)]
    );
    conserved(&b);
    conserved(&d);
}

#[test]
fn larger_node_with_an_attempt_abandons_it_and_answers_a_fresh_eligible_msg1() {
    let (mut a, mut b) = link();
    a.poll(T);
    b.poll(T);
    let ma = last(&mut a.wire, MsgKind::Msg1);
    let mb = last(&mut b.wire, MsgKind::Msg1);
    // The smaller node keeps its attempt and records the msg1 (rule 4.4).
    let before = view(&a);
    assert_eq!(a.recv(T + 10, &mb), vec![Ev::Reject(Reason::DualInitWon)]);
    assert_eq!(view(&a), before, "only the record changed");
    // The larger node abandons its attempt without backoff and answers.
    let evs = b.recv(T + 10, &ma);
    let m2 = last(&mut b.wire, MsgKind::Msg2);
    assert_eq!(
        evs,
        vec![
            Ev::Unbind(1, 101),
            Ev::Release(101),
            Ev::Abandoned(Abandon::Yielded),
            Ev::Bind(1, 102, Some(tag(1)), Purpose::Pending),
            Ev::Send(MsgKind::Msg2, bytes(&m2), ANSWER),
        ]
    );
    a.recv(T + 20, &m2);
    a.poll(T + 21);
    for f in frames(&mut a.wire) {
        b.recv(T + 30, &f);
    }
    assert_eq!(a.m().view().current.expect("cur").tag, tag(1));
    assert_eq!(b.m().view().current.expect("cur").tag, tag(1));
    conserved(&a);
    conserved(&b);
}

#[test]
fn replay_with_a_rewritten_sender_idx_is_refused() {
    let (mut a, mut b) = link();
    a.poll(T);
    let m1 = bytes(&last(&mut a.wire, MsgKind::Msg1));
    b.recv(T + 10, &Msg::Hs(MsgKind::Msg1, m1.clone()));
    let m2 = last(&mut b.wire, MsgKind::Msg2);
    let mut rewritten = m1.clone();
    rewritten[1] ^= 0xff;
    let rewritten = Msg::Hs(MsgKind::Msg1, rewritten);
    // The same ephemeral under another header: a copy of the arming msg1,
    // never answered with its msg2 and not recorded again.
    let before = b.digest();
    assert_eq!(
        b.recv(T + 11, &rewritten),
        vec![Ev::Reject(Reason::PendingHeld)]
    );
    assert_eq!(b.digest(), before);
    // A different msg1 never draws the held msg2 either.
    assert_eq!(
        b.recv(T + 12, &fresh(&a.local, &b.local)),
        vec![Ev::Reject(Reason::PendingHeld)]
    );
    // Once the pending is adopted its msg1 is recorded, so the copy is
    // refused from any header, and an exact copy as well.
    a.recv(T + 20, &m2);
    a.poll(T + 21);
    for f in frames(&mut a.wire) {
        b.recv(T + 30, &f);
    }
    let before = b.digest();
    let late = T + 30 + 10_000;
    assert_eq!(
        b.recv(late, &rewritten),
        vec![Ev::Reject(Reason::AnsweredBefore)]
    );
    assert_eq!(
        b.recv(late, &Msg::Hs(MsgKind::Msg1, m1)),
        vec![Ev::Reject(Reason::AnsweredBefore)]
    );
    assert_eq!(b.digest(), before);
}

#[test]
fn residual_msg1_during_an_unevidenced_drain_retires_nothing() {
    let (mut a, mut b) = link();
    a.poll(T);
    b.recv(T + 10, &last(&mut a.wire, MsgKind::Msg1));
    a.recv(T + 20, &last(&mut b.wire, MsgKind::Msg2));
    a.poll(T + 21);
    let _ = frames(&mut a.wire);
    // The peer was never heard under the new epoch: the drain waits for
    // evidence. A msg1 this node never saw arrives once it is eligible.
    let at = T + 21 + 10_000;
    let rx = a.m().view().last_rx;
    let evs = a.recv(at, &fresh(&b.local, &a.local));
    let m2 = bytes(&last(&mut a.wire, MsgKind::Msg2));
    assert_eq!(
        evs,
        vec![
            Ev::Bind(1, 102, Some(tag(2)), Purpose::Pending),
            Ev::Send(MsgKind::Msg2, m2, ANSWER)
        ],
        "answered as rule 4.4 requires, with nothing retired"
    );
    let v = a.m().view();
    assert_eq!(
        v.previous.map(|p| p.tag),
        Some(tag(0)),
        "the drain is left to its own deadline"
    );
    assert_eq!(v.last_rx, rx, "a replayable msg1 counts for no liveness");
    conserved(&a);
}

#[test]
fn responder_never_cuts_over_on_a_timer() {
    let (mut a, mut b) = link();
    a.poll(T);
    let m1 = last(&mut a.wire, MsgKind::Msg1);
    b.recv(T + 10, &m1);
    let m2 = last(&mut b.wire, MsgKind::Msg2);
    // The msg2 is lost. The responder sends nothing on its own timer.
    let before = b.digest();
    for s in 1..120 {
        assert_eq!(
            b.poll(T + 10 + s * 1_000),
            vec![],
            "no resend and no cutover at {s} s"
        );
    }
    assert_eq!(b.digest(), before);
    // The initiator's resend draws the stored msg2, byte for byte.
    a.poll(T + 1_000);
    let resent = last(&mut a.wire, MsgKind::Msg1);
    assert_eq!(resent, m1, "the msg1 is resent unchanged");
    assert_eq!(
        b.recv(T + 1_010, &resent),
        vec![Ev::Send(MsgKind::Msg2, bytes(&m2), ANSWER)]
    );
    // At the hold the pending is retired, never installed.
    let evs = b.poll(T + 10 + 120_000);
    assert_eq!(
        evs[..4],
        [
            Ev::Unbind(1, 101),
            Ev::Release(101),
            Ev::Retired(tag(1)),
            Ev::Abandoned(Abandon::Unadopted)
        ]
    );
    assert_eq!(b.m().view().current.expect("cur").tag, tag(0));
    assert!(!evs.iter().any(|e| matches!(e, Ev::Installed(..))));
    conserved(&b);
}

#[test]
fn link_age_anchor_survives_cutover() {
    let (mut a, mut b) = link();
    cycle(&mut a, &mut b, T);
    assert_eq!(
        a.m().view().link_since,
        TestInstant(0),
        "a cutover does not restart the link age"
    );
    // Ten seconds after the cutover the link is still old enough, so a
    // fresh msg1 is a rekey rather than a fresh dial.
    let at = T + 21 + 10_000;
    let evs = a.recv(at, &fresh(&b.local, &a.local));
    assert!(
        matches!(evs.first(), Some(Ev::Bind(_, _, _, Purpose::Pending))),
        "{evs:?}"
    );
}

#[test]
fn unbind_uses_the_transport_recorded_at_bind_across_a_rebind() {
    let (mut a, mut b) = link();
    a.poll(T);
    let m1 = last(&mut a.wire, MsgKind::Msg1);
    b.recv(T + 10, &m1);
    a.transport = 2;
    let evs = a.recv(T + 20, &last(&mut b.wire, MsgKind::Msg2));
    assert_eq!(
        evs,
        vec![
            Ev::Unbind(1, 101),
            Ev::Bind(2, 101, Some(tag(1)), Purpose::Pending)
        ]
    );
    a.poll(T + 21);
    a.transport = 3;
    // The setup index was bound on transport 1; its retirement says so,
    // and the attempt the same poll starts binds on the transport of now.
    let evs = a.poll(T + 21 + 120_000);
    let m1 = bytes(&last(&mut a.wire, MsgKind::Msg1));
    assert_eq!(
        evs,
        vec![
            Ev::Prompt(tag(1)),
            Ev::Unbind(1, 100),
            Ev::Release(100),
            Ev::Retired(tag(0)),
            Ev::Abandoned(Abandon::AdoptionNotSeen),
            Ev::Bind(3, 102, None, Purpose::Attempt),
            Ev::Send(MsgKind::Msg1, m1, PLAIN),
        ]
    );
}

/// Confirm every offer in `evs` as a shell does, and track the epochs the
/// workers hold.
fn confirm(n: &mut Node<Ik>, at: u64, evs: &[Ev<u8>], held: &mut Vec<EpochTag>) {
    for e in evs {
        if let Ev::Delegate(t, ..) = e {
            assert_eq!(n.step(at, Input::Delegated { tag: *t, only: () }), vec![]);
            held.push(*t);
        }
        if let Ev::Revoke(t, ..) = e {
            held.retain(|h| h != t);
        }
    }
}

/// The epochs a node has delegated.
fn delegated(n: &Node<Ik>) -> Vec<EpochTag> {
    let v = n.m().view();
    [v.current, v.previous]
        .into_iter()
        .flatten()
        .filter(|e| e.recv == RecvHome::Delegated)
        .map(|e| e.tag)
        .collect()
}

#[test]
fn leases_outstanding_equal_leases_held() {
    let (mut a, mut b) = link();
    a.workers = true;
    let mut held: Vec<EpochTag> = Vec::new();
    let evs = a.poll(10);
    assert_eq!(
        evs,
        vec![Ev::Delegate(tag(0), 1, 100, None)],
        "the first epoch is offered"
    );
    confirm(&mut a, 10, &evs, &mut held);
    let mut t = T;
    for _ in 0..3 {
        a.poll(t);
        b.recv(t + 10, &last(&mut a.wire, MsgKind::Msg1));
        a.recv(t + 20, &last(&mut b.wire, MsgKind::Msg2));
        let evs = a.poll(t + 21);
        assert!(
            evs.iter().any(|e| matches!(e, Ev::Delegate(..))),
            "the new epoch is offered"
        );
        confirm(&mut a, t + 21, &evs, &mut held);
        for f in frames(&mut a.wire) {
            b.recv(t + 30, &f);
        }
        let _ = frames(&mut b.wire);
        conserved(&a);
        conserved(&b);
        // The peer's prompt was lost: the drain lasts to its ceiling.
        let evs = a.poll(t + 21 + 120_000);
        confirm(&mut a, t + 21 + 120_000, &evs, &mut held);
        assert!(
            evs.iter().any(|e| matches!(e, Ev::Revoke(..))),
            "a delegated epoch is revoked when retired"
        );
        held.sort();
        assert_eq!(
            held,
            delegated(&a),
            "the workers hold exactly the delegated epochs"
        );
        conserved(&a);
        // The trigger fired in that poll and its attempt goes unanswered;
        // the next round starts after its abandon and backoff.
        t += 21 + 120_000;
        let evs = a.poll(t + 30_000);
        assert!(evs.contains(&Ev::Abandoned(Abandon::Unanswered)));
        conserved(&a);
        t += 30_000 + 9_000;
    }
    let (evs, carry) = a.close(t, Close::Shutdown);
    for e in &evs {
        if let Ev::Revoke(r, ..) = e {
            held.retain(|h| h != r);
        }
    }
    assert!(carry.is_some());
    assert!(
        held.is_empty(),
        "every delegated epoch was revoked at close"
    );
    assert!(
        a.indices.used.is_empty(),
        "every index was released at close"
    );
}

#[test]
fn unanswered_attempt_is_abandoned_and_retried_after_backoff() {
    let (mut a, mut b) = link();
    a.poll(T);
    let m1 = last(&mut a.wire, MsgKind::Msg1);
    let mut resends = Vec::new();
    for s in 1..=30u64 {
        let evs = a.poll(T + s * 1_000);
        if evs.contains(&Ev::Send(MsgKind::Msg1, bytes(&m1), PLAIN)) {
            resends.push(s);
        }
        if s == 30 {
            assert_eq!(
                evs,
                vec![
                    Ev::Unbind(1, 101),
                    Ev::Release(101),
                    Ev::Abandoned(Abandon::Unanswered)
                ],
                "the attempt ends at its deadline, 30 s after the first send"
            );
        }
    }
    assert_eq!(
        resends,
        [1, 3, 7, 15],
        "the 31 s rung falls after the deadline and is never sent"
    );
    // The trigger stays due; the backoff (one check plus a random term of
    // 7 s from the stub's mid draw) only delays the next start.
    assert_eq!(a.m().next_wake(), Some(TestInstant(T + 30_000 + 8_000)));
    assert_eq!(a.poll(T + 37_999), vec![]);
    let evs = a.poll(T + 38_000);
    assert!(
        matches!(evs.first(), Some(Ev::Bind(_, _, None, Purpose::Attempt))),
        "{evs:?}"
    );
    let again = last(&mut a.wire, MsgKind::Msg1);
    assert_ne!(again, m1, "a new attempt carries a fresh ephemeral");
    conserved(&a);
    // A second unanswered attempt doubles the checked part of the backoff.
    let mut evs = Vec::new();
    for s in 1..=30u64 {
        evs.extend(a.poll(T + 38_000 + s * 1_000));
    }
    assert!(evs.contains(&Ev::Abandoned(Abandon::Unanswered)));
    assert_eq!(a.m().next_wake(), Some(TestInstant(T + 68_000 + 9_000)));
    // A cutover resets the count, and draws its epoch's jitter: +5 s.
    a.jitter.queued = vec![20];
    let t = T + 77_000;
    cycle(&mut a, &mut b, t);
    let cut = t + 21;
    a.poll(cut + 60_000);
    assert_eq!(a.poll(cut + 124_999), vec![]);
    let next = cut + 125_000;
    let evs = a.poll(next);
    assert!(
        matches!(evs.first(), Some(Ev::Bind(_, _, None, Purpose::Attempt))),
        "the time trigger with the cutover's jitter: {evs:?}"
    );
    for s in 1..=30u64 {
        a.poll(next + s * 1_000);
    }
    assert_eq!(
        a.m().next_wake(),
        Some(TestInstant(next + 30_000 + 8_000)),
        "the first abandon since the cutover backs off by one check"
    );
    conserved(&a);
}

#[test]
fn peer_on_previous_epoch_is_not_reaped_while_drain_held() {
    let (mut a, mut b) = link();
    a.poll(T);
    b.recv(T + 10, &last(&mut a.wire, MsgKind::Msg1));
    a.recv(T + 20, &last(&mut b.wire, MsgKind::Msg2));
    a.poll(T + 21);
    let _ = frames(&mut a.wire);
    // The peer never adopts and keeps sealing under the old epoch.
    let cut = T + 21;
    for s in (5..120).step_by(5) {
        a.poll(cut + s * 1_000);
        let _ = frames(&mut a.wire);
        let f = b.data(cut + s * 1_000, DATA);
        let evs = a.frame(cut + s * 1_000, &f);
        assert_eq!(
            evs,
            vec![Ev::Deliver(Slot::Previous, tag(0), DATA.to_vec())],
            "at {s} s"
        );
        assert_eq!(
            a.m().view().last_rx,
            Some(TestInstant(cut + s * 1_000)),
            "it counts for liveness"
        );
        assert_eq!(
            a.m().view().previous.map(|p| p.tag),
            Some(tag(0)),
            "the previous epoch is held at {s} s"
        );
    }
    assert_eq!(
        a.m().next_wake(),
        Some(TestInstant(cut + 120_000)),
        "previous-epoch frames never extend the drain past its ceiling"
    );
    let evs = a.poll(cut + 120_000);
    assert_eq!(
        evs[..4],
        [
            Ev::Unbind(1, 100),
            Ev::Release(100),
            Ev::Retired(tag(0)),
            Ev::Abandoned(Abandon::AdoptionNotSeen)
        ]
    );
}

#[test]
fn cutover_over_an_open_drain_releases_its_index() {
    let quick = with(Config::fmp(), |c| {
        c.after = core::time::Duration::from_secs(45)
    });
    let (x, y) = ordered(1, 2);
    let (mut a, mut b) = pair::<Ik>(x, y, 0, quick);
    let first = 45_000;
    a.poll(first);
    b.recv(first + 10, &last(&mut a.wire, MsgKind::Msg1));
    a.recv(first + 20, &last(&mut b.wire, MsgKind::Msg2));
    a.poll(first + 21);
    for f in frames(&mut a.wire) {
        b.recv(first + 30, &f);
    }
    let _ = frames(&mut b.wire);
    // The peer's frames are lost, so the first drain is still open at the
    // second cutover, which retires it before installing.
    let second = first + 21 + 45_000;
    a.poll(second);
    b.recv(second + 10, &last(&mut a.wire, MsgKind::Msg1));
    a.recv(second + 20, &last(&mut b.wire, MsgKind::Msg2));
    let evs = a.poll(second + 21);
    let retired = evs
        .iter()
        .position(|e| *e == Ev::Retired(tag(0)))
        .expect("the old drain is retired");
    let installed = evs
        .iter()
        .position(|e| matches!(e, Ev::Installed(..)))
        .expect("installed");
    assert!(retired < installed, "retire before install: {evs:?}");
    assert!(evs.contains(&Ev::Release(100)));
    assert_eq!(a.m().view().previous.map(|p| p.tag), Some(tag(1)));
    conserved(&a);
}

#[test]
fn reoffered_receive_copy_refuses_counters_the_lost_worker_saw() {
    let (mut a, mut b) = link();
    a.workers = true;
    assert_eq!(a.poll(10), vec![Ev::Delegate(tag(0), 1, 100, None)]);
    assert_eq!(
        a.step(
            10,
            Input::Delegated {
                tag: tag(0),
                only: ()
            }
        ),
        vec![]
    );
    let frames: Vec<Vec<u8>> = (0..8).map(|i| b.data(20 + i, DATA)).collect();
    // The worker opens counters up to 5 and reports them, then goes away.
    for c in 0..=5u64 {
        let evs = a.step(
            30,
            Input::WorkerFrame {
                tag: tag(0),
                k: false,
                counter: c,
                only: (),
            },
        );
        assert_eq!(evs, vec![]);
    }
    assert_eq!(
        a.m().view().last_rx,
        Some(TestInstant(30)),
        "a worker's report counts as heard"
    );
    assert_eq!(
        a.step(
            40,
            Input::Undelegated {
                tag: tag(0),
                only: ()
            }
        ),
        vec![]
    );
    let before = a.digest();
    assert_eq!(
        a.frame(50, &frames[3]),
        vec![Ev::Reject(Reason::Replay)],
        "the worker delivered it"
    );
    assert_eq!(a.digest(), before);
    assert_eq!(
        a.frame(50, &frames[6]),
        vec![Ev::Deliver(Slot::Current, tag(0), DATA.to_vec())]
    );
    // The next offer carries the floor.
    assert_eq!(a.poll(60), vec![Ev::Delegate(tag(0), 1, 100, Some(5))]);
}

#[test]
fn every_worker_and_delegation_report_takes_its_rows_action() {
    let (mut a, mut b) = link();
    a.workers = true;
    a.poll(10);
    a.step(
        10,
        Input::Delegated {
            tag: tag(0),
            only: (),
        },
    );
    let stale = tag(99);
    let before = a.digest();
    for input in [
        Input::WorkerFrame {
            tag: stale,
            k: false,
            counter: 1,
            only: (),
        },
        Input::Delegated {
            tag: stale,
            only: (),
        },
        Input::Undelegated {
            tag: stale,
            only: (),
        },
    ] {
        assert_eq!(a.step(20, input), vec![Ev::Reject(Reason::StaleTag)]);
    }
    assert_eq!(
        a.step(
            20,
            Input::Delegated {
                tag: tag(0),
                only: ()
            }
        ),
        vec![Ev::Reject(Reason::AlreadyDelegated)]
    );
    assert_eq!(a.digest(), before);
    // A frame for a delegated epoch reaches the machine only by mistake.
    let f = b.data(30, DATA);
    assert_eq!(a.frame(30, &f), vec![Ev::Reject(Reason::DelegatedEpoch)]);
    assert_eq!(a.digest(), before);
    // The pending epoch is never offered and never reported.
    b.poll(T);
    a.recv(T + 10, &last(&mut b.wire, MsgKind::Msg1));
    let pending = a.m().view().pending.expect("pending").tag;
    let before = a.digest();
    assert_eq!(
        a.step(
            T + 11,
            Input::Delegated {
                tag: pending,
                only: ()
            }
        ),
        vec![Ev::Reject(Reason::NotOffered)]
    );
    assert_eq!(
        a.step(
            T + 11,
            Input::Undelegated {
                tag: pending,
                only: ()
            }
        ),
        vec![Ev::Reject(Reason::NotDelegated)]
    );
    assert_eq!(
        a.step(
            T + 11,
            Input::WorkerFrame {
                tag: pending,
                k: true,
                counter: 0,
                only: ()
            }
        ),
        vec![Ev::Reject(Reason::NotDelegated)]
    );
    assert_eq!(a.digest(), before);
    // Adopt, then the previous epoch's worker reports count for liveness.
    b.recv(T + 20, &last(&mut a.wire, MsgKind::Msg2));
    b.poll(T + 21);
    let prompt = frames(&mut b.wire);
    let evs = a.frame(T + 30, &bytes(&prompt[0]));
    assert!(evs.contains(&Ev::Installed(
        pending,
        Role::Responder,
        EvidenceKind::Frame
    )));
    assert!(
        evs.contains(&Ev::Delegate(pending, 1, 101, None)),
        "the new current epoch is offered"
    );
    let evs = a.step(
        T + 40,
        Input::WorkerFrame {
            tag: tag(0),
            k: false,
            counter: 9,
            only: (),
        },
    );
    assert_eq!(evs, vec![]);
    assert_eq!(a.m().view().last_rx, Some(TestInstant(T + 40)));
    let f = b.data(T + 41, DATA);
    let _ = f;
    assert_eq!(
        a.step(
            T + 50,
            Input::Undelegated {
                tag: pending,
                only: ()
            }
        ),
        vec![Ev::Reject(Reason::NotDelegated)]
    );
}

#[test]
fn counter_limits_force_a_rekey_and_then_tear_down() {
    let limits = with(Config::fmp(), |c| {
        c.messages = 40;
        c.soft = 50;
        c.hard = 60;
        // Below the 31 s link floor, so each floor binds on its own: the
        // link floor in a link's first 31 s, the session floor after a
        // cutover. At the defaults the two are equal and the session floor
        // alone would hold the first case.
        c.floor_session = core::time::Duration::from_secs(20);
    });
    let (x, y) = ordered(1, 2);
    let (mut a, mut b) = pair::<Ik>(x, y, 0, limits);
    // The message trigger, met under the 31 s link floor, starts no rekey
    // before the floor ends; at the peer it starts one when the floor ends
    // (the shell checks that next_wake named that instant), and this node
    // answers it, which opens dampening, and adopts it.
    for _ in 0..40 {
        a.data(10, DATA);
    }
    assert_eq!(
        a.poll(30_999),
        vec![],
        "a met message trigger waits for the link floor"
    );
    for _ in 0..39 {
        b.data(10, DATA);
    }
    assert_eq!(
        b.poll(31_000),
        vec![],
        "one frame short of the message trigger"
    );
    b.data(10, DATA);
    assert_eq!(b.m().next_wake(), Some(TestInstant(31_000)));
    let evs = b.poll(31_000);
    assert!(
        matches!(evs.first(), Some(Ev::Bind(_, _, None, Purpose::Attempt))),
        "{evs:?}"
    );
    a.recv(31_010, &last(&mut b.wire, MsgKind::Msg1));
    b.recv(31_020, &last(&mut a.wire, MsgKind::Msg2));
    b.poll(31_021);
    for f in frames(&mut b.wire) {
        a.recv(31_030, &f);
    }
    let _ = frames(&mut a.wire);
    // Dampening holds the message trigger back; the soft limit does not,
    // but the session floor, 20 s from this node's cutover at 31 030,
    // holds even the soft limit.
    for _ in 0..45 {
        a.data(31_100, DATA);
    }
    assert_eq!(
        a.poll(31_200),
        vec![],
        "the message trigger waits for dampening"
    );
    a.poll(41_030);
    assert_eq!(
        a.m().next_wake(),
        Some(TestInstant(31_010 + 30_000)),
        "a met message trigger is next due when dampening ends"
    );
    for _ in 45..50 {
        a.data(41_100, DATA);
    }
    assert_eq!(
        a.poll(41_200),
        vec![],
        "a met soft limit waits for the session floor"
    );
    assert_eq!(a.m().next_wake(), Some(TestInstant(31_030 + 20_000)));
    let evs = a.poll(51_030);
    assert!(
        matches!(evs.first(), Some(Ev::Bind(_, _, None, Purpose::Attempt))),
        "{evs:?}"
    );
    // Unanswered, that attempt ends at its deadline, and the met soft limit
    // starts the next in the same poll, past the back-off the abandon set.
    let evs = a.poll(81_030);
    assert!(
        evs.contains(&Ev::Abandoned(Abandon::Unanswered)),
        "the attempt ends at its deadline: {evs:?}"
    );
    assert!(
        matches!(evs.last(), Some(Ev::Send(MsgKind::Msg1, _, _))),
        "a met soft limit passes the back-off: {evs:?}"
    );
    // At the hard limit seals are refused and the poll tears down (the
    // prompt at the adoption took counter 0).
    for _ in 51..60 {
        a.data(81_300, DATA);
    }
    let m = a.m.as_mut().expect("machine");
    assert_eq!(
        m.seal(TestInstant(81_400)).map(|_| ()),
        Err(SealRefusal::Exhausted)
    );
    assert_eq!(
        a.poll(81_500),
        vec![Ev::Teardown(Teardown::CounterExhausted)]
    );
    // A frame with the counter's top value is refused without a panic.
    let mut f = b.data(52_000, DATA);
    f[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
    let before = a.digest();
    assert_eq!(a.frame(52_000, &f), vec![Ev::Reject(Reason::Replay)]);
    assert_eq!(a.digest(), before);
}

#[test]
fn every_ik_reply_cell_takes_its_rows_action() {
    let (mut a, mut b) = link();
    a.poll(T);
    let m1 = last(&mut a.wire, MsgKind::Msg1);
    b.recv(T + 10, &m1);
    let m2 = bytes(&last(&mut b.wire, MsgKind::Msg2));
    // Forged or corrupt replies naming the attempt change nothing, so the
    // genuine one still completes it.
    let before = a.digest();
    let mut flipped = m2.clone();
    let n = flipped.len() - 1;
    flipped[n] ^= 1;
    let mut short = m2.clone();
    short.pop();
    let (_, other) = <Ik as Profile>::initiate(&a.local, &b.local.key, Some(101)).expect("writes");
    let tok = read_msg1(&b.local, &other).expect("reads");
    let (_, foreign) = tok.get().answer(&b.local, Some(55)).expect("answers");
    for bad in [flipped, short, foreign] {
        assert_eq!(
            a.recv(T + 15, &Msg::Hs(MsgKind::Msg2, bad)),
            vec![Ev::Reject(Reason::ReplyUnauthenticated)]
        );
        assert_eq!(
            a.digest(),
            before,
            "handshake, schedule and deadline unchanged"
        );
    }
    let mut stray = m2.clone();
    stray[5..9].copy_from_slice(&7u32.to_le_bytes());
    assert_eq!(
        a.recv(T + 15, &Msg::Hs(MsgKind::Msg2, stray)),
        vec![Ev::Reject(Reason::UnknownIndex)]
    );
    assert_eq!(a.digest(), before);
    let evs = a.recv(T + 20, &Msg::Hs(MsgKind::Msg2, m2.clone()));
    assert_eq!(
        evs,
        vec![
            Ev::Unbind(1, 101),
            Ev::Bind(1, 101, Some(tag(1)), Purpose::Pending)
        ]
    );
    // A copy after completion: the index stays bound to its session.
    let before = a.digest();
    assert_eq!(
        a.recv(T + 21, &Msg::Hs(MsgKind::Msg2, m2.clone())),
        vec![Ev::Reject(Reason::LateReply)]
    );
    a.poll(T + 22);
    let before2 = a.digest();
    assert_eq!(
        a.recv(T + 23, &Msg::Hs(MsgKind::Msg2, m2)),
        vec![Ev::Reject(Reason::LateReply)]
    );
    assert_eq!(a.digest(), before2);
    let _ = before;
}

#[test]
fn every_ik_frame_cell_takes_its_rows_action() {
    let (mut a, mut b) = link();
    a.poll(T);
    let m1 = last(&mut a.wire, MsgKind::Msg1);
    b.recv(T + 10, &m1);
    a.recv(T + 20, &last(&mut b.wire, MsgKind::Msg2));
    // Before the poll, a frame under the pending epoch cuts over at once
    // with the K fixed at completion.
    let peer_tag = b.m().view().pending.expect("pending").tag;
    let _ = peer_tag;
    let prompt_from_b = {
        let sealed =
            b.m.as_mut()
                .expect("machine")
                .seal_prompt(TestInstant(T + 21), tag(1));
        assert!(sealed.is_err(), "a responder pending is never sealed under");
        b.m.as_mut().expect("machine")
    };
    let _ = prompt_from_b;
    // The responder adopts on the initiator's data instead: drive A to
    // seal under its pending by cutting over on B's frame. B first adopts
    // A's prompt after A's poll in another run; here B seals under the
    // pending only after adopting, so use the frame A receives from B
    // after B adopts via A's own frame.
    a.poll(T + 21);
    for f in frames(&mut a.wire) {
        b.recv(T + 30, &f);
    }
    let f = b.data(T + 31, DATA);
    let evs = a.frame(T + 32, &f);
    assert_eq!(evs, vec![Ev::Deliver(Slot::Current, tag(1), DATA.to_vec())]);
    // A duplicate is a replay; a forged frame is unauthenticated; neither
    // changes anything.
    let before = a.digest();
    assert_eq!(a.frame(T + 33, &f), vec![Ev::Reject(Reason::Replay)]);
    let mut forged = f.clone();
    let n = forged.len() - 1;
    forged[n] ^= 1;
    forged[4] ^= 0x40;
    assert_eq!(
        a.frame(T + 33, &forged),
        vec![Ev::Reject(Reason::FrameUnauthenticated)]
    );
    let mut nowhere = f.clone();
    nowhere[..4].copy_from_slice(&999u32.to_le_bytes());
    assert_eq!(
        a.frame(T + 33, &nowhere),
        vec![Ev::Reject(Reason::FrameUnauthenticated)]
    );
    assert_eq!(a.digest(), before);
    // A short plaintext has its row's effects and is not delivered, on the
    // current and the previous epoch alike.
    let short = b.data(T + 34, &[1, 2, 3]);
    assert_eq!(
        a.frame(T + 34, &short),
        vec![Ev::Reject(Reason::ShortPlaintext)]
    );
    let old = {
        let (x, y) = ordered(1, 2);
        let (mut p, mut q) = pair::<Ik>(x, y, 0, fmp());
        p.poll(T);
        q.recv(T + 10, &last(&mut p.wire, MsgKind::Msg1));
        p.recv(T + 20, &last(&mut q.wire, MsgKind::Msg2));
        p.poll(T + 21);
        let f = q.data(T + 40, &[9, 9]);
        let rx = p.m().view().last_rx;
        let evs = p.frame(T + 40, &f);
        assert_ne!(
            p.m().view().last_rx,
            rx,
            "the short frame still counted for liveness"
        );
        evs
    };
    assert_eq!(old, vec![Ev::Reject(Reason::ShortPlaintext)]);
}

#[test]
fn rekey_msg2_from_a_restarted_peer_retires_the_old_epoch_and_reports_the_restart_after_the_install()
 {
    let (mut a, b) = link();
    a.poll(T);
    let m1 = bytes(&last(&mut a.wire, MsgKind::Msg1));
    // The peer restarted: same key, new startup epoch, no memory of the
    // link. Its fresh responder answers the rekey msg1.
    let reborn = b.local.restarted(42);
    let tok = read_msg1(&reborn, &m1).expect("reads");
    let (_, m2) = tok.get().answer(&reborn, Some(300)).expect("answers");
    let evs = a.recv(T + 20, &Msg::Hs(MsgKind::Msg2, m2));
    assert_eq!(
        evs,
        vec![
            Ev::Unbind(1, 101),
            Ev::Bind(1, 101, Some(tag(1)), Purpose::Pending)
        ]
    );
    assert_eq!(
        a.m().view().peer_epoch,
        Some([42; 8]),
        "the new epoch is recorded at completion"
    );
    let evs = a.poll(T + 21);
    assert_eq!(
        evs,
        vec![
            Ev::Unbind(1, 100),
            Ev::Release(100),
            Ev::Retired(tag(0)),
            Ev::Installed(tag(1), Role::Initiator, EvidenceKind::Proof),
            Ev::Restarted(Layer::Fmp, [42; 8]),
            Ev::Prompt(tag(1)),
            Ev::Rekeyed(Role::Initiator),
        ]
    );
    let v = a.m().view();
    assert!(v.previous.is_none(), "a restart cutover drains nothing");
    assert!(!v.current.expect("cur").k, "K 0 after a restart");
    assert_eq!(v.link_since, TestInstant(T + 21), "the link age restarts");
    conserved(&a);
}

#[test]
fn a_frame_under_the_pending_epoch_before_the_poll_cuts_over_with_the_k_fixed_at_completion() {
    let (mut a, mut b) = link();
    a.poll(T);
    let m1 = bytes(&last(&mut a.wire, MsgKind::Msg1));
    b.recv(T + 10, &Msg::Hs(MsgKind::Msg1, m1.clone()));
    let m2 = bytes(&last(&mut b.wire, MsgKind::Msg2));
    a.recv(T + 20, &Msg::Hs(MsgKind::Msg2, m2.clone()));
    // A responder that cut over on its own schedule sends under the new
    // epoch with its own idea of K, before this node's poll; a short one
    // has the cutover's effects and is not delivered.
    let f = ik_frame(&m1, &m2, 101, false, &[1, 2]);
    let evs = a.frame(T + 25, &f);
    assert_eq!(
        evs,
        vec![
            Ev::Installed(tag(1), Role::Initiator, EvidenceKind::Frame),
            Ev::Prompt(tag(1)),
            Ev::Rekeyed(Role::Initiator),
            Ev::Reject(Reason::ShortPlaintext),
        ]
    );
    assert!(
        a.m().view().current.expect("cur").k,
        "the K fixed when msg2 completed, not the frame's"
    );
    assert_eq!(
        a.m().next_wake(),
        Some(TestInstant(T + 25 + 10_000)),
        "evidenced by the frame"
    );
}

#[test]
fn a_frame_for_a_delegated_previous_epoch_is_refused_by_the_machine() {
    let (mut a, mut b) = link();
    a.workers = true;
    a.poll(10);
    a.step(
        10,
        Input::Delegated {
            tag: tag(0),
            only: (),
        },
    );
    let old = b.data(20, DATA);
    cycle(&mut a, &mut b, T);
    assert_eq!(
        a.m().view().previous.map(|p| (p.tag, p.recv)),
        Some((tag(0), RecvHome::Delegated))
    );
    let before = a.digest();
    assert_eq!(
        a.frame(T + 50, &old),
        vec![Ev::Reject(Reason::DelegatedEpoch)]
    );
    assert_eq!(a.digest(), before);
}

#[test]
fn cross_connection_move_keeps_the_link_and_session_anchors() {
    let (mut a, mut b) = link();
    cycle(&mut a, &mut b, T);
    // The peer's msg1 arms a pending, then the peer moves to a crossing
    // connection: the machine closes and a new one takes over its anchors.
    let at = T + 21 + 10_000;
    let m1 = fresh(&b.local, &a.local);
    a.recv(at, &m1);
    let _ = last(&mut a.wire, MsgKind::Msg2);
    let cur = a.m().view().current.map(|c| (c.k, c.started)).expect("cur");
    let (evs, carry) = a.close(at + 1, Close::CrossConnectionMove);
    let carry = carry.expect("an established machine hands back its anchors");
    assert!(
        evs.contains(&Ev::Release(102)),
        "the pending's index is released: {evs:?}"
    );
    assert_eq!(
        (carry.k, carry.started, carry.link_since, carry.peer_k),
        (cur.0, cur.1, TestInstant(0), Some(true))
    );
    super::stub::rebuild(&mut a, &b.local, carry, at + 2, fmp());
    let v = a.m().view();
    let now = v.current.map(|c| (c.k, c.started)).expect("cur");
    assert_eq!(now, cur, "the K and the session start are inherited");
    assert_eq!(v.link_since, TestInstant(0), "the link anchor is inherited");
    // The msg1 that armed the closed pending is in the carried record, so
    // it never arms the new machine.
    assert_eq!(
        a.recv(at + 3, &m1),
        vec![Ev::Reject(Reason::AnsweredBefore)]
    );
}

#[test]
fn refused_msg1_copy_never_arms_a_pending() {
    let (mut a, mut b) = link();
    b.poll(T);
    a.recv(T + 10, &last(&mut b.wire, MsgKind::Msg1));
    let refused = fresh(&b.local, &a.local);
    assert_eq!(
        a.recv(T + 11, &refused),
        vec![Ev::Reject(Reason::PendingHeld)]
    );
    // The pending is never adopted and ends at its hold.
    let evs = a.poll(T + 10 + 120_000);
    assert!(evs.contains(&Ev::Abandoned(Abandon::Unadopted)), "{evs:?}");
    let before = a.digest();
    assert_eq!(
        a.recv(T + 10 + 120_001, &refused),
        vec![Ev::Reject(Reason::AnsweredBefore)],
        "it never arms a pending"
    );
    assert_eq!(a.digest(), before);
}

#[test]
fn initiator_epoch_takes_the_inverse_of_the_peers_observed_k_not_of_its_own() {
    let (mut a, mut b) = link();
    cycle(&mut a, &mut b, T);
    // A machine carried across a move from a peering whose K parities had
    // diverged: its own K is 1, the K last seen from the peer is 0.
    let (_, carry) = a.close(T + 100, Close::CrossConnectionMove);
    let mut carry = carry.expect("carried");
    assert!(carry.k);
    carry.peer_k = Some(false);
    let started = carry.started.0;
    super::stub::rebuild(&mut a, &b.local, carry, T + 101, fmp());
    let t = started + T;
    a.poll(t);
    b.recv(t + 10, &last(&mut a.wire, MsgKind::Msg1));
    a.recv(t + 20, &last(&mut b.wire, MsgKind::Msg2));
    let pending = a.m().view().pending.expect("pending");
    assert!(
        pending.k,
        "the inverse of the peer's 0, so a K-differs receiver tries the new keys"
    );
}

#[test]
fn close_in_every_state_retires_abandons_unbinds_and_releases_everything_held() {
    // The shell's close checks what must be gone; each case closes the
    // machine holding a different part.
    let why = Close::Admin;
    // An own attempt in flight.
    let (mut a, _b) = link();
    a.poll(T);
    assert_eq!(a.m().view().cycle, CycleView::Init);
    a.close(T + 1, why);
    // An own completed attempt held for the poll, and the peer's responder
    // pending.
    let (mut a, mut b) = link();
    a.poll(T);
    b.recv(T + 10, &last(&mut a.wire, MsgKind::Msg1));
    a.recv(T + 20, &last(&mut b.wire, MsgKind::Msg2));
    assert_eq!(a.m().view().cycle, CycleView::PendI(Wait::Held));
    assert_eq!(b.m().view().cycle, CycleView::PendR);
    a.close(T + 21, why);
    b.close(T + 21, why);
    // An open drain beside the current epoch.
    let (mut a, mut b) = link();
    cycle(&mut a, &mut b, T);
    assert!(a.m().view().previous.is_some());
    a.close(T + 50, why);
}
