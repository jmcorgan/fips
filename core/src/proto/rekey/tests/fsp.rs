//! The three-message profile with candidates (the master session shape):
//! setups, acks and the msg3 dispatcher, probes and the confirmation
//! deadline, the assumed cutover and its revert, prompts answering probes,
//! the drain, restart, the silence trigger, and the first handshake.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use super::stub::{
    DATA, Ev, Local, Msg, Node, PLAIN, Xk, bytes, ephemerals, forge3, frames, fsp, last, ordered,
    pair, with,
};
use crate::proto::rekey::{
    Abandon, Config, CycleView, EpochTag, EvidenceKind, Identity, Input, Layer, MsgKind, Reason,
    Role, SealRefusal, Slot, TagSource, Teardown, Wait,
};
use crate::testutil::TestInstant;

/// The time trigger at the defaults with no jitter.
const T: u64 = 120_000;

/// The stub CoordsWarmup plaintext.
const WARMUP: [u8; 6] = [0x14, 0, 0, 0, 0, 0];

/// The epoch tag `n` of a node's tag source.
fn tag(n: u64) -> EpochTag {
    let mut t = TagSource::new();
    let mut tag = t.draw();
    for _ in 0..n {
        tag = t.draw();
    }
    tag
}

/// A session set up at 0, `a` the smaller address.
fn session() -> (Node<Xk>, Node<Xk>) {
    let (a, b) = ordered(1, 2);
    pair::<Xk>(a, b, 0, fsp())
}

/// The machine's view, rendered.
fn view(n: &Node<Xk>) -> String {
    format!("{:?}", n.m().view())
}

/// Deliver every frame `from` sent to `to` at `at`, returning the events.
fn flush(from: &mut Node<Xk>, to: &mut Node<Xk>, at: u64) -> Vec<Ev<()>> {
    let mut evs = Vec::new();
    for f in frames(&mut from.wire) {
        evs.extend(to.recv(at, &f));
    }
    evs
}

/// Drive `a`'s rekey toward `b` from `t` up to `a` holding its completed
/// attempt and `b` having cut over at msg3; returns the msg3, the probe and
/// the keepalive `a` sent.
fn complete(a: &mut Node<Xk>, b: &mut Node<Xk>, t: u64) -> (Msg, Vec<Msg>) {
    a.poll(t);
    let s = last(&mut a.wire, MsgKind::Setup);
    b.recv(t + 10, &s);
    let ack = last(&mut b.wire, MsgKind::Ack);
    a.recv(t + 20, &ack);
    let m3 = last(&mut a.wire, MsgKind::Msg3);
    let f = frames(&mut a.wire);
    (m3, f)
}

#[test]
fn xk_rekey_completes_with_probes_and_the_responders_prompt() {
    let (mut a, mut b) = session();
    let evs = a.poll(T);
    let setup = last(&mut a.wire, MsgKind::Setup);
    assert_eq!(evs, vec![Ev::Send(MsgKind::Setup, bytes(&setup), PLAIN)]);

    let evs = b.recv(T + 10, &setup);
    let ack = last(&mut b.wire, MsgKind::Ack);
    assert_eq!(evs, vec![Ev::Send(MsgKind::Ack, bytes(&ack), PLAIN)]);
    assert_eq!(b.m().view().candidates, 1);

    let evs = a.recv(T + 20, &ack);
    let m3 = last(&mut a.wire, MsgKind::Msg3);
    assert_eq!(
        evs,
        vec![
            Ev::Send(MsgKind::Msg3, bytes(&m3), PLAIN),
            Ev::Prompt(tag(1)),
            Ev::Prompt(tag(0))
        ],
        "msg3, a probe under the pending epoch and a keepalive under the current one"
    );
    assert_eq!(a.m().view().cycle, CycleView::PendI(Wait::Evidence));
    assert_eq!(
        a.m().view().current.expect("cur").tag,
        tag(0),
        "data stays on the old epoch"
    );
    let sent = frames(&mut a.wire);
    let (probe, keepalive) = (&sent[0], &sent[1]);
    assert!(
        super::stub::hint(&bytes(probe)).k,
        "the probe carries the pending epoch's K"
    );
    assert!(!super::stub::hint(&bytes(keepalive)).k);
    assert_eq!(
        a.m().next_wake(),
        Some(TestInstant(T + 20 + 1_000)),
        "the 1 s probe rung"
    );

    let evs = b.recv(T + 30, &m3);
    assert_eq!(
        evs,
        vec![
            Ev::Installed(tag(1), Role::Responder, EvidenceKind::Proof),
            Ev::Prompt(tag(1)),
            Ev::Rekeyed(Role::Responder),
        ]
    );
    // The probe shows nothing about the initiator's data, so it does not
    // shorten the drain; the keepalive is a previous-epoch frame.
    assert_eq!(
        b.recv(T + 31, probe),
        vec![Ev::Deliver(Slot::Current, tag(1), WARMUP.to_vec())]
    );
    assert_eq!(
        b.recv(T + 31, keepalive),
        vec![Ev::Deliver(Slot::Previous, tag(0), WARMUP.to_vec())]
    );
    assert_eq!(b.m().view().previous.map(|p| p.tag), Some(tag(0)));

    // The prompt's K names the pending epoch, so it is tried first and no
    // trial fails.
    super::stub::failed();
    let evs = flush(&mut b, &mut a, T + 40);
    assert_eq!(super::stub::failed(), 0, "the hinted epoch is tried first");
    assert_eq!(
        evs,
        vec![
            Ev::Installed(tag(1), Role::Initiator, EvidenceKind::Frame),
            Ev::Prompt(tag(1)),
            Ev::Rekeyed(Role::Initiator),
            Ev::Deliver(Slot::Current, tag(1), WARMUP.to_vec()),
        ]
    );
    let sealed =
        a.m.as_mut()
            .expect("machine")
            .seal(TestInstant(T + 45))
            .expect("seals");
    assert_eq!(
        sealed.elapsed.as_millis(),
        25,
        "timestamps count from the completion, not the cutover"
    );
    assert_eq!(a.poll(T + 1_100), vec![], "no probe once cut over");

    let _ = frames(&mut a.wire);
    let f = a.data(T + 50, DATA);
    assert_eq!(
        b.frame(T + 50, &f),
        vec![Ev::Deliver(Slot::Current, tag(1), DATA.to_vec())]
    );
    assert_eq!(
        b.m().next_wake(),
        Some(TestInstant(T + 50 + 10_000)),
        "the initiator's data is the evidence that shortens the drain"
    );
}

/// A setup no node wrote: a valid length and a non-zero ephemeral.
fn forged(n: u8) -> Vec<u8> {
    vec![1, n, n, n, n, n, n, n, 1]
}

#[test]
fn every_xk_setup_cell_takes_its_rows_action() {
    let (mut a, mut b) = session();
    let before = b.digest();
    assert_eq!(
        b.setup_on(5_000, 1, &[1, 2, 3]),
        vec![Ev::Reject(Reason::SetupMalformed)]
    );
    assert_eq!(
        b.setup_on(5_000, 1, &[1, 0, 0, 0, 0, 0, 0, 0, 0]),
        vec![Ev::Reject(Reason::SetupMalformed)]
    );
    assert_eq!(b.digest(), before);
    // A forged setup is scratch: a candidate and its ack, nothing else.
    let evs = b.setup_on(5_000, 1, &forged(9));
    let ack = bytes(&last(&mut b.wire, MsgKind::Ack));
    assert_eq!(evs, vec![Ev::Send(MsgKind::Ack, ack.clone(), PLAIN)]);
    assert_eq!(b.m().view().candidates, 1);
    // A byte-identical setup draws the stored ack and changes nothing.
    let before = b.digest();
    assert_eq!(
        b.setup_on(6_000, 1, &forged(9)),
        vec![Ev::Send(MsgKind::Ack, ack, PLAIN)]
    );
    assert_eq!(b.digest(), before);
    // Two per carrier, four in all; an established session never evicts.
    assert!(matches!(
        b.setup_on(6_000, 1, &forged(10))[..],
        [Ev::Send(MsgKind::Ack, ..)]
    ));
    let before = b.digest();
    assert_eq!(
        b.setup_on(6_000, 1, &forged(11)),
        vec![Ev::Reject(Reason::CandidatesFull)]
    );
    assert_eq!(b.digest(), before);
    assert!(matches!(
        b.setup_on(6_000, 2, &forged(12))[..],
        [Ev::Send(MsgKind::Ack, ..)]
    ));
    assert!(matches!(
        b.setup_on(6_000, 3, &forged(13))[..],
        [Ev::Send(MsgKind::Ack, ..)]
    ));
    let before = b.digest();
    assert_eq!(
        b.setup_on(44_000, 4, &forged(14)),
        vec![Ev::Reject(Reason::CandidatesFull)]
    );
    assert_eq!(
        b.digest(),
        before,
        "no candidate is evicted before its deadline"
    );
    // At its deadline a candidate goes, and there is room again.
    assert_eq!(b.poll(45_000), vec![Ev::Reject(Reason::CandidateExpired)]);
    assert!(matches!(
        b.setup_on(45_000, 4, &forged(14))[..],
        [Ev::Send(MsgKind::Ack, ..)]
    ));
    // The smaller node refuses a new setup while its own attempt has
    // completed; the larger answers it as a candidate.
    b.poll(T - 1);
    let _ = complete(&mut a, &mut b, T);
    let before = a.digest();
    assert_eq!(
        a.setup_on(T + 21, 1, &forged(20)),
        vec![Ev::Reject(Reason::TieBreakKept)]
    );
    assert_eq!(a.digest(), before, "no candidate, no ack");
    let (mut c, mut d) = session();
    let (_, _) = complete(&mut d, &mut c, T);
    assert_eq!(d.m().view().cycle, CycleView::PendI(Wait::Evidence));
    assert!(matches!(
        d.setup_on(T + 21, 1, &forged(21))[..],
        [Ev::Send(MsgKind::Ack, ..)]
    ));
}

#[test]
fn every_xk_ack_cell_takes_its_rows_action() {
    let (mut a, mut b) = session();
    let before = a.digest();
    let stray = vec![2u8; 57];
    assert_eq!(
        a.recv(10, &Msg::Hs(MsgKind::Ack, stray.clone())),
        vec![Ev::Reject(Reason::UnknownAttempt)]
    );
    assert_eq!(a.digest(), before);
    a.poll(T);
    b.recv(T + 10, &last(&mut a.wire, MsgKind::Setup));
    let ack = bytes(&last(&mut b.wire, MsgKind::Ack));
    let mut bad = ack.clone();
    bad[3] ^= 1;
    let before = a.digest();
    assert_eq!(
        a.recv(T + 20, &Msg::Hs(MsgKind::Ack, bad)),
        vec![Ev::Reject(Reason::ReplyUnauthenticated)]
    );
    assert_eq!(
        a.recv(T + 20, &Msg::Hs(MsgKind::Ack, stray)),
        vec![Ev::Reject(Reason::ReplyUnauthenticated)]
    );
    assert_eq!(
        a.digest(),
        before,
        "handshake, schedule and deadline unchanged"
    );
    a.recv(T + 21, &Msg::Hs(MsgKind::Ack, ack.clone()));
    let before = a.digest();
    assert_eq!(
        a.recv(T + 22, &Msg::Hs(MsgKind::Ack, ack)),
        vec![Ev::Reject(Reason::LateReply)]
    );
    assert_eq!(a.digest(), before);
}

#[test]
fn completion_with_another_static_installs_nothing() {
    let (mut a, mut b) = session();
    // The larger node holds its own completed attempt and a candidate.
    let (_m3, _) = complete(&mut b, &mut a, T);
    let pending = b.m().view().pending.expect("pending").tag;
    a.skip(3);
    let setup = {
        let (_, s) = <Xk as crate::proto::rekey::Profile>::initiate(&a.local, &b.local.key, None)
            .expect("writes");
        s
    };
    b.setup_on(T + 30, 1, &setup);
    let ack = bytes(&last(&mut b.wire, MsgKind::Ack));
    let (ei, er) = ephemerals(&setup, &ack);
    // A third identity completes the exchange it observed.
    let third = Local::new(77, 77);
    let before = view(&b);
    let evs = b.recv(T + 40, &Msg::Hs(MsgKind::Msg3, forge3(&third, ei, er)));
    assert_eq!(evs, vec![Ev::Reject(Reason::KeyMismatch)]);
    assert_eq!(b.m().view().candidates, 0, "the candidate is dropped");
    assert_eq!(
        b.m().view().pending.map(|p| p.tag),
        Some(pending),
        "a failed msg3 discards no completed epoch"
    );
    assert_eq!(before.replace("candidates: 1", "candidates: 0"), view(&b));
    // The same msg3 under the right static completes nothing now either.
    assert_eq!(
        b.recv(T + 41, &Msg::Hs(MsgKind::Msg3, forge3(&a.local, ei, er))),
        vec![Ev::Reject(Reason::FinalNoAttempt)]
    );
}

#[test]
fn every_xk_final_cell_takes_its_rows_action() {
    let (mut a, mut b) = session();
    let before = b.digest();
    let garbage = Msg::Hs(MsgKind::Msg3, vec![3u8; 49]);
    assert_eq!(
        b.recv(10, &garbage),
        vec![Ev::Reject(Reason::FinalNoAttempt)]
    );
    b.setup_on(20, 1, &forged(5));
    let before2 = b.digest();
    assert_eq!(
        b.recv(30, &garbage),
        vec![Ev::Reject(Reason::FinalUnauthenticated)]
    );
    assert_eq!(b.digest(), before2);
    let _ = before;
    // An unanswered own attempt yields to the peer's msg3.
    let (mut c, mut d) = session();
    d.poll(T);
    let _ = last(&mut d.wire, MsgKind::Setup);
    let (m3, _) = complete(&mut c, &mut d, T);
    let evs = d.recv(T + 30, &m3);
    assert_eq!(
        evs,
        vec![
            Ev::Abandoned(Abandon::Yielded),
            Ev::Installed(tag(1), Role::Responder, EvidenceKind::Proof),
            Ev::Prompt(tag(1)),
            Ev::Rekeyed(Role::Responder),
        ]
    );
    // Two completed attempts: the smaller keeps its own, the larger yields.
    a.poll(T);
    b.poll(T);
    let sa = last(&mut a.wire, MsgKind::Setup);
    let sb = last(&mut b.wire, MsgKind::Setup);
    a.recv(T + 10, &sb);
    b.recv(T + 10, &sa);
    let ack_b = last(&mut b.wire, MsgKind::Ack);
    let ack_a = last(&mut a.wire, MsgKind::Ack);
    a.recv(T + 20, &ack_b);
    b.recv(T + 20, &ack_a);
    let m3a = last(&mut a.wire, MsgKind::Msg3);
    let m3b = last(&mut b.wire, MsgKind::Msg3);
    let _ = frames(&mut a.wire);
    let _ = frames(&mut b.wire);
    let mine = a.m().view().pending.expect("pending").tag;
    let before = view(&a);
    assert_eq!(a.recv(T + 30, &m3b), vec![Ev::Reject(Reason::TieBreakKept)]);
    assert_eq!(
        before.replace("candidates: 1", "candidates: 0"),
        view(&a),
        "the candidate is dropped"
    );
    let evs = b.recv(T + 30, &m3a);
    assert_eq!(
        evs[0],
        Ev::Retired(tag(1)),
        "the larger node's own pending is retired"
    );
    assert!(evs.contains(&Ev::Installed(tag(2), Role::Responder, EvidenceKind::Proof)));
    flush(&mut b, &mut a, T + 40);
    assert_eq!(a.cur(), mine, "both on the smaller node's epoch");
}

/// Two crossing rekeys that both complete: returns each node's msg3.
fn crossing(a: &mut Node<Xk>, b: &mut Node<Xk>, t: u64) -> (Msg, Msg) {
    a.poll(t);
    b.poll(t);
    let sa = last(&mut a.wire, MsgKind::Setup);
    let sb = last(&mut b.wire, MsgKind::Setup);
    a.recv(t + 10, &sb);
    b.recv(t + 10, &sa);
    let ack_b = last(&mut b.wire, MsgKind::Ack);
    let ack_a = last(&mut a.wire, MsgKind::Ack);
    a.recv(t + 20, &ack_b);
    b.recv(t + 20, &ack_a);
    let _ = frames(&mut a.wire);
    let _ = frames(&mut b.wire);
    (
        last(&mut a.wire, MsgKind::Msg3),
        last(&mut b.wire, MsgKind::Msg3),
    )
}

#[test]
fn stale_candidate_never_completes_after_a_cutover_on_evidence() {
    let (mut n, mut d) = session();
    let (m3n, m3d) = crossing(&mut n, &mut d, T);
    let winner = n.m().view().pending.expect("pending").tag;
    // The larger node yields to the smaller's msg3 and prompts; the prompt
    // overtakes its own msg3, which arrives late.
    d.recv(T + 30, &m3n);
    let evs = flush(&mut d, &mut n, T + 40);
    assert!(evs.contains(&Ev::Installed(winner, Role::Initiator, EvidenceKind::Frame)));
    assert_eq!(
        n.m().view().candidates,
        0,
        "a cutover on evidence drops every candidate"
    );
    let before = n.digest();
    assert_eq!(
        n.recv(T + 50, &m3d),
        vec![Ev::Reject(Reason::FinalNoAttempt)]
    );
    assert_eq!(n.digest(), before);
    assert_eq!(n.cur(), winner);
}

#[test]
fn late_msg3_after_a_newer_setup_keeps_the_newer_candidate() {
    let (mut i, mut r) = session();
    let (m3_1, _) = complete(&mut i, &mut r, T);
    // A second attempt by the same initiator (its repair), from another
    // shell with the same identity, reaches the responder before the late
    // msg3 of the first.
    let (mut i2, _) = session();
    i2.skip(10);
    let (m3_2, _) = complete(&mut i2, &mut r, T + 1_000);
    assert_eq!(r.m().view().candidates, 2);
    let evs = r.recv(T + 2_000, &m3_1);
    assert!(
        matches!(
            evs[0],
            Ev::Installed(_, Role::Responder, EvidenceKind::Proof)
        ),
        "{evs:?}"
    );
    assert_eq!(r.m().view().candidates, 1, "the newer candidate is kept");
    let first = r.cur();
    let evs = r.recv(T + 3_000, &m3_2);
    assert!(
        evs.contains(&Ev::Retired(tag(0))),
        "the open drain is retired before the next install"
    );
    assert!(evs.iter().any(
        |e| matches!(e, Ev::Installed(t, Role::Responder, EvidenceKind::Proof) if *t != first)
    ));
}

/// Poll `n` every second from `from` to `to` seconds after `base`,
/// dropping what it sends.
fn idle(n: &mut Node<Xk>, base: u64, from: u64, to: u64) -> Vec<Ev<()>> {
    let mut evs = Vec::new();
    for s in from..=to {
        evs.extend(n.poll(base + s * 1_000));
        let _ = n.sent();
    }
    evs
}

#[test]
fn current_epoch_frame_after_the_last_probe_marks_the_peer_as_staying() {
    // Every msg3 copy and probe is lost. A frame under the current epoch
    // inside the grace after a probe proves nothing; one after it does,
    // until the next probe rung clears it. A measured session round trip
    // widens the grace. The rekey is a silence start with the time trigger
    // far off, so only the repair flag can start the repair.
    let srtt = Some(Duration::from_secs(3));
    for (at, stays, srtt) in [
        (15_500, false, None),
        (16_500, true, None),
        (8_500, false, None),
        (16_500, false, srtt),
    ] {
        let p = with(Config::fsp(), |c| c.after = Duration::from_secs(600));
        let (x, y) = ordered(1, 2);
        let (mut a, mut b) = pair::<Xk>(x, y, 0, p);
        a.step(T, Input::DataSent { only: () });
        let _ = complete(&mut a, &mut b, T);
        let done = T + 20;
        if srtt.is_some() {
            a.step(
                done,
                Input::PathFacts {
                    reachable: true,
                    srtt,
                    only: (),
                },
            );
        }
        idle(&mut a, done, 1, at / 1_000);
        let f = b.data(done + at, DATA);
        a.frame(done + at, &f);
        let evs = idle(&mut a, done, at / 1_000 + 1, 31);
        let pending = tag(1);
        if stays {
            assert!(evs.contains(&Ev::Retired(pending)), "{evs:?}");
            assert!(evs.contains(&Ev::Abandoned(Abandon::PeerStayedOnOld)));
            assert!(
                evs.iter()
                    .any(|e| matches!(e, Ev::Send(MsgKind::Setup, ..))),
                "a repair starts at once, ignoring the backoff"
            );
            assert_eq!(a.cur(), tag(0), "its own data never left the old epoch");
            // The repair consumed the flag: once it goes unanswered, nothing
            // starts until a trigger does.
            let evs = idle(&mut a, done, 32, 61);
            assert!(evs.contains(&Ev::Abandoned(Abandon::Unanswered)), "{evs:?}");
            let evs = idle(&mut a, done, 62, 90);
            assert!(
                !evs.iter()
                    .any(|e| matches!(e, Ev::Send(MsgKind::Setup, ..))),
                "{evs:?}"
            );
        } else {
            assert!(
                evs.contains(&Ev::Installed(
                    pending,
                    Role::Initiator,
                    EvidenceKind::Assumed
                )),
                "{evs:?}"
            );
        }
    }
}

#[test]
fn probe_grace_never_outlasts_the_confirmation_deadline() {
    let (mut a, mut b) = session();
    a.step(
        10,
        Input::PathFacts {
            reachable: true,
            srtt: Some(core::time::Duration::from_secs(20)),
            only: (),
        },
    );
    let _ = complete(&mut a, &mut b, T);
    let done = T + 20;
    idle(&mut a, done, 1, 23);
    // Twice a 20 s round trip would be 40 s; the cap is 8 s after the last
    // probe at 15 s, so a frame at 23.5 s still counts.
    let f = b.data(done + 23_500, DATA);
    a.frame(done + 23_500, &f);
    let evs = idle(&mut a, done, 24, 31);
    assert!(
        evs.contains(&Ev::Abandoned(Abandon::PeerStayedOnOld)),
        "{evs:?}"
    );
}

#[test]
fn late_poll_never_sends_a_probe_it_cannot_judge_before_the_confirmation_deadline() {
    let (mut a, mut b) = session();
    let _ = complete(&mut a, &mut b, T);
    let done = T + 20;
    idle(&mut a, done, 1, 7);
    let f = b.data(done + 9_000, DATA);
    a.frame(done + 9_000, &f);
    // One poll suspended across the 15 s probe rung and the deadline.
    let evs = a.poll(done + 32_000);
    let setup = bytes(&last(&mut a.wire, MsgKind::Setup));
    assert_eq!(
        evs,
        vec![
            Ev::Prompt(tag(0)),
            Ev::Retired(tag(1)),
            Ev::Abandoned(Abandon::PeerStayedOnOld),
            Ev::Send(MsgKind::Setup, setup, PLAIN),
        ],
        "the overdue rungs send one keepalive and no probe or msg3, so the evidence stands"
    );
}

#[test]
fn no_seal_call_produces_a_ciphertext_under_a_pending_epoch() {
    let (mut a, mut b) = session();
    let _ = complete(&mut a, &mut b, T);
    let m = a.m.as_mut().expect("machine");
    let sealed = m.seal(TestInstant(T + 30)).expect("seals");
    assert_eq!(
        (sealed.tag, sealed.k),
        (tag(0), false),
        "data is sealed under the current epoch"
    );
    let probe = m
        .seal_prompt(TestInstant(T + 30), tag(1))
        .expect("a probe under the waiting epoch");
    assert_eq!((probe.sealed.tag, probe.sealed.k), (tag(1), true));
    assert_eq!(
        probe.plaintext,
        WARMUP.to_vec(),
        "only the fixed prompt, built in the core"
    );
    assert_eq!(
        probe.route,
        Some(7),
        "with the coordinates the peer's ack carried"
    );
    assert_eq!(
        m.seal_prompt(TestInstant(T + 30), tag(9)).map(|_| ()),
        Err(SealRefusal::NotSealable)
    );
    let opening = Node::<Xk>::new(Local::new(5, 5));
    let _ = opening;
}

#[test]
fn responders_only_prompt_lost_loses_no_initiator_frame() {
    let (mut a, mut b) = session();
    let (m3, probes) = complete(&mut a, &mut b, T);
    b.recv(T + 30, &m3);
    let lost = frames(&mut b.wire);
    assert_eq!(lost.len(), 1, "the cutover prompt, lost");
    let drain = b.m().next_wake();
    // The initiator keeps sealing data under the old epoch; every frame is
    // delivered.
    for (i, s) in [500u64, 700].iter().enumerate() {
        let f = a.data(T + s, DATA);
        assert_eq!(
            b.frame(T + s, &f),
            vec![Ev::Deliver(Slot::Previous, tag(0), DATA.to_vec())],
            "frame {i}"
        );
    }
    for p in &probes {
        b.recv(T + 31, p);
    }
    let _ = frames(&mut b.wire);
    assert_eq!(
        b.m().next_wake(),
        drain,
        "neither a probe nor an old-epoch frame shortens the drain"
    );
    // The next probe rung draws a prompt in answer, and that is evidence.
    // Only the probe is delivered: the keepalive beside it, an old-epoch
    // frame, would draw a prompt of its own.
    a.poll(T + 20 + 1_000);
    let mut answered = Vec::new();
    for m in a.sent() {
        if matches!(&m, Msg::Frame(_, t) if *t == tag(1)) {
            answered.extend(b.recv(T + 1_030, &m));
        }
    }
    assert!(answered.contains(&Ev::Prompt(tag(1))), "{answered:?}");
    assert_eq!(b.m().next_wake(), drain);
    let evs = flush(&mut b, &mut a, T + 1_040);
    assert!(
        evs.contains(&Ev::Installed(tag(1), Role::Initiator, EvidenceKind::Frame)),
        "{evs:?}"
    );
}

/// Drive `a` to an assumed cutover: its rekey toward `b` completes and
/// every msg3, probe and responder frame is lost. Returns `a`'s msg3 and
/// the instant of the assumed cutover.
fn assumed(a: &mut Node<Xk>, b: &mut Node<Xk>) -> (Msg, u64) {
    let (m3, _) = complete(a, b, T);
    let done = T + 20;
    let evs = idle(a, done, 1, 31);
    assert!(
        evs.contains(&Ev::Installed(
            tag(1),
            Role::Initiator,
            EvidenceKind::Assumed
        )),
        "{evs:?}"
    );
    (m3, done + 31_000)
}

#[test]
fn a_previous_epoch_frame_after_an_assumed_cutover_returns_the_epoch_to_pending() {
    let (mut a, mut b) = session();
    let (m3, cut) = assumed(&mut a, &mut b);
    // The peer never read msg3 and is still on the old epoch.
    let f = b.data(cut + 500, DATA);
    let evs = a.frame(cut + 500, &f);
    assert_eq!(
        evs,
        vec![
            Ev::Deliver(Slot::Previous, tag(0), DATA.to_vec()),
            Ev::Reverted(tag(1)),
            Ev::Prompt(tag(1)),
            Ev::Prompt(tag(0)),
        ]
    );
    assert_eq!(
        a.cur(),
        tag(0),
        "the drained epoch is current again, unchanged"
    );
    assert_eq!(a.m().view().cycle, CycleView::PendI(Wait::Evidence));
    // If the peer does hold the new epoch, its frame cuts over again.
    let (mut c, mut d) = session();
    let (m3c, cut) = assumed(&mut c, &mut d);
    let f = d.data(cut + 500, DATA);
    c.frame(cut + 500, &f);
    d.recv(cut + 600, &m3c);
    let evs = flush(&mut d, &mut c, cut + 700);
    assert!(
        evs.contains(&Ev::Installed(tag(1), Role::Initiator, EvidenceKind::Frame)),
        "{evs:?}"
    );
    // If it does not, the window ends in a retire and a repair.
    let evs = idle(&mut a, cut + 500, 1, 10);
    assert!(evs.contains(&Ev::Retired(tag(1))), "{evs:?}");
    assert!(evs.contains(&Ev::Abandoned(Abandon::RevertUnconfirmed)));
    assert!(
        evs.iter()
            .any(|e| matches!(e, Ev::Send(MsgKind::Setup, ..)))
    );
    let _ = m3;
}

#[test]
fn assumed_epoch_frame_during_a_repair_reverts_and_abandons_the_repair() {
    let (mut a, mut b) = session();
    let (_, cut) = assumed(&mut a, &mut b);
    // The silence rule starts a repair while the peer is unheard.
    a.step(cut + 1_000, Input::DataSent { only: () });
    let evs = idle(&mut a, cut, 2, 30);
    assert!(
        evs.iter()
            .any(|e| matches!(e, Ev::Send(MsgKind::Setup, ..))),
        "{evs:?}"
    );
    assert_eq!(a.m().view().cycle, CycleView::Init);
    let f = b.data(cut + 30_500, DATA);
    let evs = a.frame(cut + 30_500, &f);
    assert_eq!(
        evs,
        vec![
            Ev::Deliver(Slot::Previous, tag(0), DATA.to_vec()),
            Ev::Abandoned(Abandon::Reverted),
            Ev::Reverted(tag(1)),
            Ev::Prompt(tag(1)),
            Ev::Prompt(tag(0)),
        ]
    );
    assert_eq!(a.cur(), tag(0));
}

#[test]
fn drained_epoch_frame_during_a_confirming_repair_marks_the_peer_as_staying() {
    let (mut a, mut b) = session();
    let (_, cut) = assumed(&mut a, &mut b);
    a.step(cut + 1_000, Input::DataSent { only: () });
    idle(&mut a, cut, 2, 29);
    a.poll(cut + 30_000);
    // The peer answers the repair; every repair msg3 copy is lost.
    let s = last(&mut a.wire, MsgKind::Setup);
    b.recv(cut + 30_010, &s);
    a.recv(cut + 30_020, &last(&mut b.wire, MsgKind::Ack));
    let _ = a.sent();
    let repair = a.m().view().pending.expect("pending").tag;
    let done = cut + 30_020;
    // Frames under the drained epoch change no epoch, before or after the
    // grace.
    for at in [done + 500, done + 16_500] {
        idle(&mut a, done, 1, (at - done) / 1_000);
        let f = b.data(at, DATA);
        assert_eq!(
            a.frame(at, &f),
            vec![Ev::Deliver(Slot::Previous, tag(0), DATA.to_vec())]
        );
        let v = a.m().view();
        assert_eq!(
            (v.current.expect("cur").tag, v.previous.expect("prev").tag),
            (tag(1), tag(0))
        );
        assert_eq!(v.pending.map(|p| p.tag), Some(repair));
    }
    // The one after the grace counted: the deadline retires the repair
    // instead of assuming it over the epoch the peer was heard on.
    let evs = idle(&mut a, done, 17, 31);
    assert!(evs.contains(&Ev::Retired(repair)), "{evs:?}");
    assert!(evs.contains(&Ev::Abandoned(Abandon::PeerStayedOnOld)));
    // The next drained-epoch frame meets the new repair unanswered and
    // reverts.
    let f = b.data(done + 31_500, DATA);
    let evs = a.frame(done + 31_500, &f);
    assert!(evs.contains(&Ev::Reverted(tag(1))), "{evs:?}");
    assert_eq!(a.cur(), tag(0), "both seal under the epoch both hold");
}

#[test]
fn hs_rtt_ignores_a_reply_to_a_resent_message() {
    let (mut a, mut b) = session();
    a.poll(T);
    let _lost = last(&mut a.wire, MsgKind::Setup);
    a.poll(T + 3_000);
    let resent = last(&mut a.wire, MsgKind::Setup);
    b.recv(T + 3_100, &resent);
    // The ack answers a resend, 3.5 s after the first copy: no sample, and
    // the next setup's first rung backs off to twice that.
    a.recv(T + 3_500, &last(&mut b.wire, MsgKind::Ack));
    let _ = a.sent();
    let done = T + 3_500;
    // With no sample the grace is the 1 s floor, so a current-epoch frame
    // 2 s after the last probe shows the peer stayed. A sample of 3.5 s
    // would have stretched the grace to 7 s.
    idle(&mut a, done, 1, 15);
    let f = b.data(done + 17_000, DATA);
    a.frame(done + 17_000, &f);
    let evs = idle(&mut a, done, 18, 30);
    assert!(
        evs.is_empty() || !evs.iter().any(|e| matches!(e, Ev::Installed(..))),
        "{evs:?}"
    );
    let evs = a.poll(done + 31_000);
    assert!(
        evs.contains(&Ev::Abandoned(Abandon::PeerStayedOnOld)),
        "{evs:?}"
    );
    assert!(
        evs.iter()
            .any(|e| matches!(e, Ev::Send(MsgKind::Setup, ..))),
        "the repair starts"
    );
    assert_eq!(
        a.m().next_wake(),
        Some(TestInstant(done + 31_000 + 7_000)),
        "the repair's first rung is the kept backoff"
    );
    // A reply to the first copy is a sample and clears the backoff.
    let repair = last(&mut a.wire, MsgKind::Setup);
    b.recv(done + 31_100, &repair);
    a.recv(done + 31_200, &last(&mut b.wire, MsgKind::Ack));
    let _ = frames(&mut a.wire);
    b.recv(done + 31_300, &last(&mut a.wire, MsgKind::Msg3));
    let evs = flush(&mut b, &mut a, done + 31_400);
    assert!(
        evs.iter()
            .any(|e| matches!(e, Ev::Installed(_, Role::Initiator, EvidenceKind::Frame))),
        "{evs:?}"
    );
    let next = a.m().view().current.expect("cur").started.0 + T;
    let _ = frames(&mut a.wire);
    a.poll(next);
    assert_eq!(
        a.m().next_wake(),
        Some(TestInstant(next + 1_000)),
        "a 200 ms sample: the 1 s floor"
    );
}

#[test]
fn black_holed_sender_rekeys_within_silence() {
    let (mut a, _b) = session();
    a.step(40_000, Input::DataSent { only: () });
    let evs = a.poll(40_000);
    assert!(
        matches!(evs[..], [Ev::Send(MsgKind::Setup, ..)]),
        "silence since the start of the epoch: {evs:?}"
    );
    // Unanswered, the attempt ends; the next silence interval is doubled.
    let evs = idle(&mut a, 40_000, 1, 30);
    assert!(evs.contains(&Ev::Abandoned(Abandon::Unanswered)));
    // The doubled interval (60 s from the epoch's start) has passed; the
    // abandon backoff (8 s) is what the next start waits for.
    assert_eq!(idle(&mut a, 0, 71, 77), vec![]);
    let evs = a.poll(78_000);
    assert!(matches!(evs[..], [Ev::Send(MsgKind::Setup, ..)]), "{evs:?}");
}

#[test]
fn silence_step_doubles_per_start_and_a_heard_frame_resets_it_the_anchor_and_the_data_flag() {
    let p = with(Config::fsp(), |c| c.after = Duration::from_secs(600));
    let (x, y) = ordered(1, 2);
    let (mut a, mut b) = pair::<Xk>(x, y, 0, p);
    let setups = |evs: &[Ev<()>]| {
        evs.iter()
            .filter(|e| matches!(e, Ev::Send(MsgKind::Setup, ..)))
            .count()
    };
    // A silence start whose msg3 reaches the peer, every frame back lost:
    // the initiator cuts over assumed, still sending, its step at one.
    a.step(30_000, Input::DataSent { only: () });
    let (m3, _) = complete(&mut a, &mut b, 30_000);
    b.recv(30_030, &m3);
    let _ = b.sent();
    let done = 30_020;
    let evs = idle(&mut a, done, 1, 31);
    assert!(
        evs.contains(&Ev::Installed(
            tag(1),
            Role::Initiator,
            EvidenceKind::Assumed
        )),
        "{evs:?}"
    );
    let cut = done + 31_000;
    // Still unheard, the next start waits out the doubled interval.
    let evs = idle(&mut a, cut, 1, 59);
    assert_eq!(setups(&evs), 0, "the interval doubled to 60 s: {evs:?}");
    // Hearing the peer clears the data flag: no silence start follows
    // without new data.
    let heard = cut + 59_500;
    let f = b.data(heard, DATA);
    a.frame(heard, &f);
    let evs = idle(&mut a, heard, 1, 40);
    assert_eq!(
        setups(&evs),
        0,
        "nothing sent since the peer was heard: {evs:?}"
    );
    // It also reset the step and moved the anchor: data sent after the
    // peer is heard again starts a rekey 30 s after that frame.
    let again = heard + 40_500;
    let f = b.data(again, DATA);
    a.frame(again, &f);
    a.step(again + 100, Input::DataSent { only: () });
    let evs = idle(&mut a, again, 1, 29);
    assert_eq!(setups(&evs), 0, "anchored at the last frame heard: {evs:?}");
    assert_eq!(setups(&a.poll(again + 30_000)), 1, "the undoubled interval");
}

#[test]
fn fsp_ack_from_a_restarted_peer_cuts_over_at_msg3_and_retains_it() {
    let (mut a, b) = session();
    a.poll(T);
    let s = last(&mut a.wire, MsgKind::Setup);
    // The larger peer restarted; its fresh responder answers.
    let reborn = b.local.restarted(42);
    let (_, ack) =
        <Xk as crate::proto::rekey::Profile>::answer(&reborn, &bytes(&s)).expect("answers");
    let evs = a.recv(T + 20, &Msg::Hs(MsgKind::Ack, ack));
    let m3 = bytes(&last(&mut a.wire, MsgKind::Msg3));
    assert_eq!(
        evs,
        vec![
            Ev::Send(MsgKind::Msg3, m3.clone(), PLAIN),
            Ev::Retired(tag(0)),
            Ev::Installed(tag(1), Role::Initiator, EvidenceKind::Restart),
            Ev::Restarted(Layer::Fsp, [42; 8]),
            Ev::Prompt(tag(1)),
            Ev::Rekeyed(Role::Initiator),
        ]
    );
    assert!(!a.m().view().current.expect("cur").k, "K 0 after a restart");
    // The msg3 is retained and resent until the peer is heard; no rekey
    // starts meanwhile, and the smaller node refuses a new setup.
    assert_eq!(
        a.setup_on(T + 500, 1, &forged(3)),
        vec![Ev::Reject(Reason::TieBreakKept)]
    );
    a.step(T + 600, Input::DataSent { only: () });
    let mut resends = Vec::new();
    for s in 1..=31u64 {
        let evs = a.poll(T + 20 + s * 1_000);
        let _ = a.sent();
        if evs.contains(&Ev::Send(MsgKind::Msg3, m3.clone(), PLAIN)) {
            resends.push(s);
        }
        let started = evs
            .iter()
            .any(|e| matches!(e, Ev::Send(MsgKind::Setup, ..)));
        assert_eq!(
            started,
            s == 31,
            "a rekey starts only once the last msg3 is gone (at {s} s)"
        );
    }
    assert_eq!(resends, [1, 3, 7, 15, 31]);
}

#[test]
fn previous_epoch_frame_with_a_counter_inside_the_current_window_is_delivered() {
    let (mut a, mut b) = session();
    let (m3, probes) = complete(&mut a, &mut b, T);
    // Old-epoch frames sealed before the initiator cut over, delayed.
    let old: Vec<Vec<u8>> = (0..5).map(|_| a.data(T + 21, DATA)).collect();
    b.recv(T + 30, &m3);
    for p in &probes {
        b.recv(T + 31, p);
    }
    flush(&mut b, &mut a, T + 40);
    // New-epoch frames with the same counters arrive first.
    for _ in 0..3 {
        let f = a.data(T + 41, DATA);
        b.frame(T + 42, &f);
    }
    // Frames 0 to 2 meet the current window's refusal, frames 3 and 4 the
    // current key's failure; the trial goes on to the previous key for all.
    for (i, f) in old.iter().enumerate() {
        assert_eq!(
            b.frame(T + 50, f),
            vec![Ev::Deliver(Slot::Previous, tag(0), DATA.to_vec())],
            "old frame {i}"
        );
    }
    assert_eq!(
        b.frame(T + 51, &old[0]),
        vec![Ev::Reject(Reason::Replay)],
        "and only once"
    );
}

#[test]
fn forged_setups_never_defer_or_cancel_own_rotation() {
    let (mut a, mut b) = session();
    // Forged setups at both ends before and during the attempt.
    a.setup_on(T - 5_000, 2, &forged(40));
    b.setup_on(T - 5_000, 2, &forged(41));
    let evs = a.poll(T);
    assert!(
        matches!(evs[..], [Ev::Send(MsgKind::Setup, ..)]),
        "the trigger fires on time: {evs:?}"
    );
    let s = last(&mut a.wire, MsgKind::Setup);
    a.setup_on(T + 5, 3, &forged(42));
    assert_eq!(
        a.m().view().cycle,
        CycleView::Init,
        "a forged setup cancels nothing"
    );
    // The larger node's own attempt is not cancelled either.
    b.poll(T);
    let own = last(&mut b.wire, MsgKind::Setup);
    b.setup_on(T + 5, 3, &forged(43));
    assert_eq!(b.m().view().cycle, CycleView::Init);
    assert!(
        b.poll(T + 1_000)
            .contains(&Ev::Send(MsgKind::Setup, bytes(&own), PLAIN)),
        "it keeps resending"
    );
    let _ = b.sent();
    b.recv(T + 10, &s);
    a.recv(T + 20, &last(&mut b.wire, MsgKind::Ack));
    let m3 = last(&mut a.wire, MsgKind::Msg3);
    flush(&mut a, &mut b, T + 25);
    b.recv(T + 30, &m3);
    let evs = flush(&mut b, &mut a, T + 40);
    assert!(
        evs.contains(&Ev::Installed(tag(1), Role::Initiator, EvidenceKind::Frame)),
        "{evs:?}"
    );
    assert_eq!(b.cur(), tag(1));
}

#[test]
fn forged_frames_change_nothing() {
    let (mut a, mut b) = session();
    let f = b.data(10, DATA);
    let before = a.digest();
    for i in 0..30u8 {
        let mut x = f.clone();
        let n = x.len() - 1;
        x[n] ^= i | 1;
        assert_eq!(
            a.frame(20, &x),
            vec![Ev::Reject(Reason::FrameUnauthenticated)]
        );
    }
    assert_eq!(
        a.digest(),
        before,
        "no tear-down and no state for any count of forged frames"
    );
    assert_eq!(
        a.frame(30, &f),
        vec![Ev::Deliver(Slot::Current, tag(0), DATA.to_vec())]
    );
    let short = b.data(40, &[1, 2, 3, 4, 5]);
    assert_eq!(
        a.frame(40, &short),
        vec![Ev::Reject(Reason::ShortPlaintext)],
        "below the session floor of 6"
    );
}

/// The first handshake of `a` toward `b`: `a` opens, `b` is opened by
/// the setup. Returns `a`'s msg3, not yet delivered.
fn first(a: &mut Node<Xk>, b: &mut Node<Xk>) -> Msg {
    a.open_out(0, b.local.key, fsp());
    let s = last(&mut a.wire, MsgKind::Setup);
    b.open_in(10, a.local.addr(), &s, fsp());
    a.recv(20, &last(&mut b.wire, MsgKind::Ack));
    last(&mut a.wire, MsgKind::Msg3)
}

#[test]
fn first_handshake_installs_at_both_ends_and_the_first_frame_confirms_the_retained_msg3() {
    let (x, y) = ordered(1, 2);
    let (mut a, mut b) = (Node::<Xk>::new(x), Node::<Xk>::new(y));
    let evs = a.open_out(0, b.local.key, fsp());
    let s = last(&mut a.wire, MsgKind::Setup);
    assert_eq!(evs, vec![Ev::Send(MsgKind::Setup, bytes(&s), PLAIN)]);
    assert_eq!(
        a.m().view().identity,
        Identity::Claimed(b.local.addr()),
        "nothing proven yet"
    );
    let evs = b.open_in(10, a.local.addr(), &s, fsp());
    let ack = last(&mut b.wire, MsgKind::Ack);
    assert_eq!(evs, vec![Ev::Send(MsgKind::Ack, bytes(&ack), PLAIN)]);
    assert_eq!(b.m().view().identity, Identity::Claimed(a.local.addr()));
    // The install draws the jitter of its epoch's time trigger: -5 s.
    a.jitter.queued = vec![10];
    let evs = a.recv(20, &ack);
    let m3 = last(&mut a.wire, MsgKind::Msg3);
    assert_eq!(
        evs,
        vec![
            Ev::Send(MsgKind::Msg3, bytes(&m3), PLAIN),
            Ev::Installed(tag(0), Role::Initiator, EvidenceKind::First)
        ]
    );
    assert_eq!(a.m().view().identity, Identity::Proven(b.local.key));
    assert_eq!(a.m().view().peer_epoch, Some(b.local.epoch));
    let evs = b.recv(30, &m3);
    assert_eq!(
        evs,
        vec![
            Ev::Installed(tag(0), Role::Responder, EvidenceKind::First),
            Ev::Prompt(tag(0))
        ]
    );
    assert_eq!(b.m().view().identity, Identity::Proven(a.local.key));
    let evs = flush(&mut b, &mut a, 40);
    assert_eq!(
        evs,
        vec![Ev::Deliver(Slot::Current, tag(0), WARMUP.to_vec())]
    );
    assert_eq!(
        idle(&mut a, 0, 1, 60),
        vec![],
        "the msg3 is confirmed: no resend, no repair"
    );
    assert_eq!(a.poll(20 + 114_999), vec![]);
    let evs = a.poll(20 + 115_000);
    assert!(
        matches!(evs[..], [Ev::Send(MsgKind::Setup, ..)]),
        "the time trigger with the install's jitter: {evs:?}"
    );
}

#[test]
fn an_unconfirmed_first_handshake_msg3_is_resent_five_times_then_repaired() {
    let (x, y) = ordered(1, 2);
    let (mut a, mut b) = (Node::<Xk>::new(x), Node::<Xk>::new(y));
    let m3 = first(&mut a, &mut b);
    let mut resends = Vec::new();
    for s in 1..=31u64 {
        let evs = a.poll(20 + s * 1_000);
        if evs.contains(&Ev::Send(MsgKind::Msg3, bytes(&m3), PLAIN)) {
            resends.push(s);
        }
        if s == 31 {
            assert!(
                evs.iter()
                    .any(|e| matches!(e, Ev::Send(MsgKind::Setup, ..))),
                "a repair at the last rung: {evs:?}"
            );
        }
    }
    assert_eq!(resends, [1, 3, 7, 15, 31]);
    // The repair completes against the peer, which never read the msg3.
    let s = last(&mut a.wire, MsgKind::Setup);
    let _ = a.sent();
    b.recv(31_100, &s);
    a.recv(31_200, &last(&mut b.wire, MsgKind::Ack));
    let m3 = last(&mut a.wire, MsgKind::Msg3);
    let _ = frames(&mut a.wire);
    b.recv(31_300, &m3);
    let evs = flush(&mut b, &mut a, 31_400);
    assert!(
        evs.iter()
            .any(|e| matches!(e, Ev::Installed(_, Role::Initiator, EvidenceKind::Frame))),
        "{evs:?}"
    );
}

#[test]
fn inbound_opening_with_no_candidate_left_is_torn_down() {
    let (x, y) = ordered(1, 2);
    let mut b = Node::<Xk>::new(y.restarted(3));
    let evs = b.open_in(0, x.addr(), &Msg::Hs(MsgKind::Setup, forged(7)), fsp());
    assert!(matches!(evs[..], [Ev::Send(MsgKind::Ack, ..)]));
    assert!(
        b.m().next_wake().is_some(),
        "an opening machine always has a next wake"
    );
    assert_eq!(b.poll(39_999), vec![]);
    assert_eq!(
        b.poll(40_000),
        vec![
            Ev::Reject(Reason::CandidateExpired),
            Ev::Teardown(Teardown::OpeningIdle)
        ]
    );
    // A malformed first setup leaves nothing to hold.
    let mut c = Node::<Xk>::new(Local::new(9, 9));
    assert_eq!(
        c.open_in(0, x.addr(), &Msg::Hs(MsgKind::Setup, vec![1]), fsp()),
        vec![
            Ev::Reject(Reason::SetupMalformed),
            Ev::Teardown(Teardown::OpeningIdle)
        ]
    );
    // The last candidate failing its bond ends it too.
    let mut d = Node::<Xk>::new(Local::new(10, 10));
    let mut a = Node::<Xk>::new(Local::new(1, 1));
    a.open_out(0, d.local.key, fsp());
    let s = last(&mut a.wire, MsgKind::Setup);
    d.open_in(10, a.local.addr(), &s, fsp());
    let ack = last(&mut d.wire, MsgKind::Ack);
    let (ei, er) = ephemerals(&bytes(&s), &bytes(&ack));
    let impostor = Local::new(66, 66);
    assert_eq!(
        d.recv(20, &Msg::Hs(MsgKind::Msg3, forge3(&impostor, ei, er))),
        vec![
            Ev::Reject(Reason::KeyMismatch),
            Ev::Teardown(Teardown::OpeningIdle)
        ]
    );
    // An outbound attempt that fails with no candidate ends it.
    let evs = idle(&mut a, 0, 1, 30);
    assert_eq!(
        evs.iter()
            .filter(|e| matches!(e, Ev::Send(MsgKind::Setup, ..)))
            .count(),
        4
    );
    assert!(
        evs.ends_with(&[
            Ev::Abandoned(Abandon::Unanswered),
            Ev::Teardown(Teardown::OpeningFailed)
        ]),
        "{evs:?}"
    );
    // An outbound attempt that fails while a crossing candidate is held
    // leaves the machine opening, and the candidate still completes.
    let (x, y) = ordered(20, 21);
    let (mut p, mut q) = (Node::<Xk>::new(x), Node::<Xk>::new(y));
    p.open_out(0, q.local.key, fsp());
    q.open_out(0, p.local.key, fsp());
    let _lost = p.sent();
    let sq = last(&mut q.wire, MsgKind::Setup);
    assert!(matches!(
        p.recv(5_100, &sq)[..],
        [Ev::Send(MsgKind::Ack, ..)]
    ));
    q.recv(5_200, &last(&mut p.wire, MsgKind::Ack));
    let m3 = last(&mut q.wire, MsgKind::Msg3);
    let evs = idle(&mut p, 0, 6, 30);
    assert!(evs.contains(&Ev::Abandoned(Abandon::Unanswered)), "{evs:?}");
    assert!(
        !evs.iter().any(|e| matches!(e, Ev::Teardown(_))),
        "a candidate is left: {evs:?}"
    );
    assert_eq!(p.m().view().cycle, CycleView::Idle);
    let evs = p.recv(30_500, &m3);
    assert!(
        evs.iter()
            .any(|e| matches!(e, Ev::Installed(_, Role::Responder, EvidenceKind::First))),
        "{evs:?}"
    );
}

#[test]
fn forged_setup_before_a_wanted_session_never_delays_its_first_attempt() {
    let (x, y) = ordered(1, 2);
    let mut b = Node::<Xk>::new(y);
    b.open_in(0, x.addr(), &Msg::Hs(MsgKind::Setup, forged(7)), fsp());
    let before = b.digest();
    assert_eq!(
        b.step(
            100,
            Input::Open {
                peer: Local::new(50, 50).key,
                only: ()
            }
        ),
        vec![Ev::Reject(Reason::KeyMismatch)]
    );
    assert_eq!(b.digest(), before);
    let evs = b.step(
        100,
        Input::Open {
            peer: x.key,
            only: (),
        },
    );
    assert!(
        matches!(evs[..], [Ev::Send(MsgKind::Setup, ..)]),
        "the first attempt starts at once: {evs:?}"
    );
    assert_eq!(b.m().view().candidates, 1, "every candidate is kept");
    let before = b.digest();
    assert_eq!(
        b.step(
            200,
            Input::Open {
                peer: x.key,
                only: ()
            }
        ),
        vec![Ev::Reject(Reason::AttemptInFlight)]
    );
    let f = vec![0u8; 40];
    assert_eq!(b.frame(200, &f), vec![Ev::Reject(Reason::NotEstablished)]);
    assert_eq!(b.digest(), before);
    let m = b.m.as_mut().expect("machine");
    assert_eq!(
        m.seal(TestInstant(200)).map(|_| ()),
        Err(SealRefusal::NotEstablished)
    );
    assert_eq!(
        m.seal_prompt(TestInstant(200), tag(0)).map(|_| ()),
        Err(SealRefusal::NotEstablished)
    );
    let (mut c, _d) = session();
    assert_eq!(
        c.step(
            10,
            Input::Open {
                peer: _d.local.key,
                only: ()
            }
        ),
        vec![Ev::Reject(Reason::AlreadyEstablished)]
    );
}

#[test]
fn forged_setups_on_one_carrier_cannot_evict_another_carriers_candidate() {
    let (x, y) = ordered(1, 2);
    let (mut a, mut b) = (Node::<Xk>::new(x), Node::<Xk>::new(y));
    a.open_out(0, b.local.key, fsp());
    let s = last(&mut a.wire, MsgKind::Setup);
    b.open_in(0, a.local.addr(), &s, fsp());
    let ack = last(&mut b.wire, MsgKind::Ack);
    // A forger on carrier 2 sends setups for 30 s.
    for i in 0..30u64 {
        b.setup_on(1_000 + i * 1_000, 2, &forged(10 + i as u8));
    }
    for i in 0..3u64 {
        b.setup_on(32_000 + i, 3 + i as u8, &forged(80 + i as u8));
    }
    // The genuine candidate on carrier 1 is still there to complete.
    a.recv(35_000, &ack);
    let m3 = last(&mut a.wire, MsgKind::Msg3);
    let evs = b.recv(35_010, &m3);
    assert!(
        evs.contains(&Ev::Installed(tag(0), Role::Responder, EvidenceKind::First)),
        "{evs:?}"
    );
}

#[test]
fn the_smaller_node_refuses_a_crossing_setup_while_its_attempt_is_young_and_the_larger_holds_back_early_resends()
 {
    let (x, y) = ordered(1, 2);
    let (mut n, mut d) = (Node::<Xk>::new(x), Node::<Xk>::new(y));
    n.open_out(0, d.local.key, fsp());
    d.open_out(0, n.local.key, fsp());
    let sd = last(&mut d.wire, MsgKind::Setup);
    let sn = last(&mut n.wire, MsgKind::Setup);
    let before = n.digest();
    assert_eq!(
        n.recv(100, &sd),
        vec![Ev::Reject(Reason::TieBreakKept)],
        "young own attempt at the smaller node"
    );
    assert_eq!(n.digest(), before);
    // The larger node takes the smaller's setup as a candidate and then
    // holds back its 1 s and 3 s resends; the 7 s one goes.
    assert!(matches!(d.recv(100, &sn)[..], [Ev::Send(MsgKind::Ack, ..)]));
    let _ = d.sent();
    let evs = idle(&mut d, 0, 1, 7);
    let sends: Vec<_> = evs
        .iter()
        .filter(|e| matches!(e, Ev::Send(MsgKind::Setup, ..)))
        .collect();
    assert_eq!(sends.len(), 1, "only the 7 s rung: {evs:?}");
    // Past the young age the smaller node answers it as a candidate.
    assert!(matches!(
        n.recv(5_100, &sd)[..],
        [Ev::Send(MsgKind::Ack, ..)]
    ));
}

#[test]
fn first_handshake_candidate_is_dropped_once_the_peer_is_heard_under_cur() {
    let (x, y) = ordered(1, 2);
    let (mut n, mut d) = (Node::<Xk>::new(x), Node::<Xk>::new(y));
    n.open_out(0, d.local.key, fsp());
    d.open_out(0, n.local.key, fsp());
    let _lost = n.sent();
    // Past the young age each takes the other's later copy as a candidate.
    idle(&mut d, 0, 1, 6);
    d.poll(7_000);
    let sd = last(&mut d.wire, MsgKind::Setup);
    n.poll(7_000);
    let sn = last(&mut n.wire, MsgKind::Setup);
    n.recv(7_010, &sd);
    let ack_n = last(&mut n.wire, MsgKind::Ack);
    d.recv(7_010, &sn);
    let ack_d = last(&mut d.wire, MsgKind::Ack);
    // Each completes its own attempt and installs, keeping the candidate.
    d.recv(7_020, &ack_n);
    let m3d = last(&mut d.wire, MsgKind::Msg3);
    n.recv(7_020, &ack_d);
    let m3n = last(&mut n.wire, MsgKind::Msg3);
    let mine = n.cur();
    assert_eq!(n.m().view().candidates, 1);
    // The larger node yields to the smaller's msg3 and prompts; the prompt
    // arrives before the larger node's own msg3.
    let evs = d.recv(7_030, &m3n);
    assert!(
        evs.iter()
            .any(|e| matches!(e, Ev::Installed(_, Role::Responder, EvidenceKind::Proof))),
        "{evs:?}"
    );
    flush(&mut d, &mut n, 7_040);
    assert_eq!(
        n.m().view().candidates,
        0,
        "heard under cur: the crossing candidate goes"
    );
    assert_eq!(
        n.recv(7_050, &m3d),
        vec![Ev::Reject(Reason::FinalNoAttempt)]
    );
    assert_eq!(n.cur(), mine, "both stay on the smaller node's epoch");
    let f = d.data(7_060, DATA);
    assert_eq!(
        n.frame(7_060, &f),
        vec![Ev::Deliver(Slot::Current, mine, DATA.to_vec())]
    );
}

#[test]
fn late_first_handshake_setup_copy_never_moves_the_smaller_node_off_its_confirmed_epoch() {
    let (x, y) = ordered(1, 2);
    let (mut n, mut d) = (Node::<Xk>::new(x), Node::<Xk>::new(y));
    // The larger node opens too, but its setup copies are delayed.
    d.open_out(0, n.local.key, fsp());
    let late = last(&mut d.wire, MsgKind::Setup);
    n.open_out(10, d.local.key, fsp());
    let sn = last(&mut n.wire, MsgKind::Setup);
    d.recv(20, &sn);
    n.recv(30, &last(&mut d.wire, MsgKind::Ack));
    let mine = n.cur();
    let m3 = last(&mut n.wire, MsgKind::Msg3);
    // The late copy reaches the smaller node after its install, while its
    // msg3 is unconfirmed: refused, no candidate, no ack.
    let before = n.digest();
    assert_eq!(n.recv(40, &late), vec![Ev::Reject(Reason::TieBreakKept)]);
    assert_eq!(n.digest(), before);
    // The larger node, its own attempt unanswered, yields to the msg3.
    let evs = d.recv(50, &m3);
    assert!(evs.contains(&Ev::Abandoned(Abandon::Yielded)), "{evs:?}");
    flush(&mut d, &mut n, 60);
    assert_eq!(n.cur(), mine);
    let f = d.data(70, DATA);
    assert_eq!(
        n.frame(70, &f),
        vec![Ev::Deliver(Slot::Current, mine, DATA.to_vec())]
    );
}

#[test]
fn restart_crossing_with_a_smaller_restarted_peer_converges_on_its_epoch() {
    // X (larger) and Y (smaller) share a session; Y restarts.
    let (y0, x0) = ordered(1, 2);
    let (mut y_old, mut x) = pair::<Xk>(y0, x0, 0, fsp());
    // Step 1: X's trigger. Y's old incarnation also started a rekey,
    // which X, larger and in Init, answered; its msg3 is delayed, and then
    // Y restarts.
    x.poll(T);
    let sx = last(&mut x.wire, MsgKind::Setup);
    y_old.poll(T);
    let s_old = last(&mut y_old.wire, MsgKind::Setup);
    x.recv(T + 5, &s_old);
    y_old.recv(T + 8, &last(&mut x.wire, MsgKind::Ack));
    let m3_old = last(&mut y_old.wire, MsgKind::Msg3);
    let mut y = Node::<Xk>::new(y_old.local.restarted(42));
    // Step 2: X's setup opens Y's inbound machine; the ack is lost.
    y.open_in(T + 10, x.local.addr(), &sx, fsp());
    let _lost = last(&mut y.wire, MsgKind::Ack);
    // Steps 3 and 4: Y wants X; X, larger and in Init, takes Y's setup as
    // a candidate.
    y.step(
        T + 20,
        Input::Open {
            peer: x.local.key,
            only: (),
        },
    );
    let sy = last(&mut y.wire, MsgKind::Setup);
    x.recv(T + 30, &sy);
    // Step 5: Y completes on X's ack and installs; its msg3 is lost.
    y.recv(T + 40, &last(&mut x.wire, MsgKind::Ack));
    let _lost = last(&mut y.wire, MsgKind::Msg3);
    let y_epoch = y.cur();
    // Step 6: X's resend of its setup draws Y's stored ack, which reveals
    // the restart: X cuts over at msg3, keeping the candidates bound to
    // Y's new epoch.
    x.poll(T + 1_000);
    y.recv(T + 1_010, &last(&mut x.wire, MsgKind::Setup));
    let evs = x.recv(T + 1_020, &last(&mut y.wire, MsgKind::Ack));
    assert!(evs.contains(&Ev::Restarted(Layer::Fsp, [42; 8])), "{evs:?}");
    assert_eq!(x.m().view().candidates, 2, "kept at the larger address");
    let m3x = last(&mut x.wire, MsgKind::Msg3);
    // The old incarnation's msg3 never completes its kept candidate.
    assert_eq!(
        x.recv(T + 1_030, &m3_old),
        vec![Ev::Reject(Reason::StaleIncarnation)]
    );
    // Step 7: Y, smaller and holding its own msg3, keeps its epoch.
    assert_eq!(
        y.recv(T + 1_040, &m3x),
        vec![Ev::Reject(Reason::TieBreakKept)]
    );
    // Step 8: Y's msg3 resend completes X's bound candidate; X yields.
    y.poll(T + 40 + 1_000);
    let resent = last(&mut y.wire, MsgKind::Msg3);
    let evs = x.recv(T + 1_050, &resent);
    assert!(
        evs.iter()
            .any(|e| matches!(e, Ev::Installed(_, Role::Responder, EvidenceKind::Proof))),
        "{evs:?}"
    );
    let f = x.data(T + 1_060, DATA);
    assert_eq!(
        y.frame(T + 1_060, &f),
        vec![Ev::Deliver(Slot::Current, y_epoch, DATA.to_vec())],
        "both on Y's epoch"
    );
}

#[test]
fn previous_epoch_frame_never_confirms_or_clears_retained_msg3() {
    let (mut a, mut b) = session();
    let (m3, _) = complete(&mut a, &mut b, T);
    b.recv(T + 30, &m3);
    let _ = frames(&mut b.wire);
    let drain = b.m().next_wake();
    // The initiator's data under the old epoch: delivered as previous,
    // never evidence that it moved.
    let f = a.data(T + 500, DATA);
    let evs = b.frame(T + 500, &f);
    assert_eq!(
        evs,
        vec![Ev::Deliver(Slot::Previous, tag(0), DATA.to_vec())]
    );
    assert_eq!(
        b.poll(T + 1_030),
        vec![Ev::Prompt(tag(1))],
        "the elicit ladder goes on"
    );
    let f = a.data(T + 2_100, DATA);
    assert_eq!(
        b.frame(T + 2_100, &f),
        vec![
            Ev::Deliver(Slot::Previous, tag(0), DATA.to_vec()),
            Ev::Prompt(tag(1))
        ],
        "inside the confirmation span an old-epoch frame draws a prompt"
    );
    let _ = frames(&mut b.wire);
    assert_eq!(b.poll(T + 3_030), vec![Ev::Prompt(tag(1))]);
    let _ = drain;
    assert_eq!(
        b.m().next_wake(),
        Some(TestInstant(T + 30 + 120_000)),
        "the drain still runs to its ceiling"
    );
    // Data sent and the peer heard only under the previous epoch past the
    // silence interval: the frames count for liveness alone, so they
    // neither move the silence anchor nor clear the data flag, and the
    // poll starts a repair.
    b.step(T + 49_000, Input::DataSent { only: () });
    let f = a.data(T + 50_000, DATA);
    assert_eq!(
        b.frame(T + 50_000, &f),
        vec![Ev::Deliver(Slot::Previous, tag(0), DATA.to_vec())],
        "past the span, no prompt"
    );
    let evs = b.poll(T + 50_000);
    assert!(
        matches!(evs[..], [Ev::Send(MsgKind::Setup, ..)]),
        "a silence repair: {evs:?}"
    );
}

#[test]
fn late_poll_processes_stored_deadlines_in_order() {
    let (mut a, mut b) = session();
    // The larger node completes its own attempt and holds a candidate born
    // after it; one poll then comes late, past the confirmation deadline
    // and the candidate's.
    let _ = complete(&mut b, &mut a, T);
    b.setup_on(T + 21, 2, &forged(30));
    let _ = b.sent();
    let now = T + 50_000;
    let evs = b.poll(now);
    assert_eq!(
        evs,
        vec![
            Ev::Installed(tag(1), Role::Initiator, EvidenceKind::Assumed),
            Ev::Prompt(tag(1)),
            Ev::Rekeyed(Role::Initiator),
            Ev::Reject(Reason::CandidateExpired),
        ],
        "the overdue rungs send no probe, and their keepalive under the epoch the deadline at 31 s \
         then demoted is withdrawn; then the candidate at 40 s"
    );
    assert_eq!(
        b.m().next_wake(),
        Some(TestInstant(now + 1_000)),
        "what the pass created counts from the poll's instant and was not expired in it"
    );
    assert_eq!(b.m().view().previous.map(|p| p.tag), Some(tag(0)));
}

#[test]
fn session_address_is_stable_across_cutover_demotion_and_revert() {
    let (mut a, mut b) = session();
    let _ = complete(&mut a, &mut b, T);
    let first = a.m().session_at(tag(1)).expect("pending");
    let old = a.m().session_at(tag(0)).expect("current");
    let evs = idle(&mut a, T + 20, 1, 31);
    assert!(evs.contains(&Ev::Installed(
        tag(1),
        Role::Initiator,
        EvidenceKind::Assumed
    )));
    assert_eq!(a.m().session_at(tag(1)), Some(first), "cut over");
    assert_eq!(a.m().session_at(tag(0)), Some(old), "demoted");
    let f = b.data(T + 51_100, DATA);
    a.frame(T + 51_100, &f);
    assert_eq!(a.m().view().cycle, CycleView::PendI(Wait::Evidence));
    assert_eq!(a.m().session_at(tag(1)), Some(first), "reverted");
    assert_eq!(a.m().session_at(tag(0)), Some(old), "restored");
}

#[test]
fn assumed_cutover_at_the_larger_node_keeps_an_acknowledged_setup() {
    let (mut a, mut b) = session();
    // The larger node completes and, waiting, acknowledges the peer's own
    // setup; with nothing heard it assumes at its deadline and keeps that
    // candidate, whose msg3 then completes it.
    let _ = complete(&mut b, &mut a, T);
    let _ = b.sent();
    a.skip(3);
    let (hs, s) = <Xk as crate::proto::rekey::Profile>::initiate(&a.local, &b.local.key, None)
        .expect("writes");
    let ack = {
        b.setup_on(T + 100, 1, &s);
        bytes(&last(&mut b.wire, MsgKind::Ack))
    };
    let evs = idle(&mut b, T + 20, 1, 31);
    assert!(evs.contains(&Ev::Installed(
        tag(1),
        Role::Initiator,
        EvidenceKind::Assumed
    )));
    assert_eq!(b.m().view().candidates, 1, "kept at the larger address");
    let read = <Xk as crate::proto::rekey::Profile>::reply(&hs, &a.local, &ack).expect("reads");
    let evs = b.recv(T + 40_000, &Msg::Hs(MsgKind::Msg3, read.fin.expect("msg3")));
    assert!(
        evs.iter()
            .any(|e| matches!(e, Ev::Installed(_, Role::Responder, EvidenceKind::Proof))),
        "{evs:?}"
    );
    // At the smaller address an assumed cutover drops its candidates.
    let (mut c, mut d) = session();
    c.poll(T);
    let sc = last(&mut c.wire, MsgKind::Setup);
    c.setup_on(T + 5, 1, &forged(31));
    d.recv(T + 10, &sc);
    c.recv(T + 20, &last(&mut d.wire, MsgKind::Ack));
    assert_eq!(c.m().view().candidates, 1);
    let evs = idle(&mut c, T + 20, 1, 31);
    assert!(evs.contains(&Ev::Installed(
        tag(1),
        Role::Initiator,
        EvidenceKind::Assumed
    )));
    assert_eq!(c.m().view().candidates, 0, "dropped at the smaller address");
}

#[test]
fn deployed_rekey_acknowledged_before_the_first_handshake_is_confirmed_completes_at_the_larger_node()
 {
    // N (larger) completes its first handshake toward D (smaller); D's
    // frames are lost while D starts a rekey at once, as a deployed peer
    // with no dampening does.
    let (dl, nl) = ordered(1, 2);
    let (mut n, mut d) = (Node::<Xk>::new(nl), Node::<Xk>::new(dl));
    n.open_out(0, d.local.key, fsp());
    let s = last(&mut n.wire, MsgKind::Setup);
    d.open_in(10, n.local.addr(), &s, fsp());
    n.recv(20, &last(&mut d.wire, MsgKind::Ack));
    let m3 = last(&mut n.wire, MsgKind::Msg3);
    d.recv(30, &m3);
    let _lost = frames(&mut d.wire);
    let (hs, setup) = <Xk as crate::proto::rekey::Profile>::initiate(&d.local, &n.local.key, None)
        .expect("writes");
    let evs = n.setup_on(1_000, 1, &setup);
    let ack = bytes(&last(&mut n.wire, MsgKind::Ack));
    assert!(
        matches!(evs[..], [Ev::Send(MsgKind::Ack, ..)]),
        "the larger node answers it: {evs:?}"
    );
    // D's frame under the first epoch arrives before its msg3: it confirms
    // N's msg3 and keeps the candidate born after the install.
    let f = d.data(1_100, DATA);
    n.frame(1_200, &f);
    assert_eq!(n.m().view().candidates, 1);
    let read = <Xk as crate::proto::rekey::Profile>::reply(&hs, &d.local, &ack).expect("reads");
    let evs = n.recv(1_300, &Msg::Hs(MsgKind::Msg3, read.fin.expect("msg3")));
    assert!(
        evs.iter()
            .any(|e| matches!(e, Ev::Installed(_, Role::Responder, EvidenceKind::Proof))),
        "{evs:?}"
    );
}

#[test]
fn no_rekey_starts_without_a_route_and_one_starts_once_there_is_one() {
    let (mut a, _b) = session();
    a.step(
        10,
        Input::PathFacts {
            reachable: false,
            srtt: None,
            only: (),
        },
    );
    assert_eq!(a.poll(T), vec![], "no next hop, no rekey");
    assert_eq!(a.m().next_wake(), None, "nothing to wake for");
    a.step(
        T + 1,
        Input::PathFacts {
            reachable: true,
            srtt: None,
            only: (),
        },
    );
    assert!(matches!(a.poll(T + 2)[..], [Ev::Send(MsgKind::Setup, ..)]));
}

#[test]
fn first_rekey_after_answering_the_first_handshake_waits_for_the_measured_rtt() {
    let (x, y) = ordered(1, 2);
    let (mut a, mut b) = (Node::<Xk>::new(x), Node::<Xk>::new(y));
    a.open_out(0, b.local.key, fsp());
    b.open_in(
        10,
        a.local.addr(),
        &last(&mut a.wire, MsgKind::Setup),
        fsp(),
    );
    let ack = last(&mut b.wire, MsgKind::Ack);
    // The msg3 answers the ack 800 ms after it was sent: below the first
    // msg3 rung, so the responder samples the round trip.
    a.recv(400, &ack);
    b.recv(810, &last(&mut a.wire, MsgKind::Msg3));
    let start = 810 + T;
    let evs = b.poll(start);
    assert!(matches!(evs[..], [Ev::Send(MsgKind::Setup, ..)]), "{evs:?}");
    assert_eq!(
        b.m().next_wake(),
        Some(TestInstant(start + 1_600)),
        "the first resend waits twice the sampled 800 ms"
    );
}

#[test]
fn fsp_completion_with_a_changed_epoch_reports_a_restart() {
    // The larger node holds a session; the smaller peer restarts and opens
    // toward it again.
    let (x, y) = ordered(1, 2);
    let (a, mut b) = pair::<Xk>(x, y, 0, fsp());
    let mut reborn = Node::<Xk>::new(a.local.restarted(42));
    reborn.open_out(T - 1_000, b.local.key, fsp());
    b.recv(T - 990, &last(&mut reborn.wire, MsgKind::Setup));
    reborn.recv(T - 980, &last(&mut b.wire, MsgKind::Ack));
    let evs = b.recv(T - 970, &last(&mut reborn.wire, MsgKind::Msg3));
    assert_eq!(
        evs,
        vec![
            Ev::Retired(tag(0)),
            Ev::Installed(tag(1), Role::Responder, EvidenceKind::Proof),
            Ev::Restarted(Layer::Fsp, [42; 8]),
            Ev::Prompt(tag(1)),
            Ev::Rekeyed(Role::Responder),
        ],
        "the old epoch is retired, not drained, and the restart reported after the install"
    );
    assert!(!b.m().view().current.expect("cur").k, "K 0 after a restart");
    let f = b.data(T - 960, DATA);
    assert_eq!(
        reborn.frame(T - 960, &f),
        vec![Ev::Deliver(Slot::Current, tag(0), DATA.to_vec())]
    );
}

#[test]
fn no_own_rekey_starts_inside_dampening_or_the_drain_window_after_a_cutover() {
    let quick = with(crate::proto::rekey::Config::fsp(), |c| c.messages = 5);
    let (x, y) = ordered(1, 2);
    let (mut a, mut b) = pair::<Xk>(x, y, 0, quick);
    // `b` completes `a`'s rekey at msg3, which opens 30 s of dampening for
    // `b`; `a` cuts over on `b`'s prompt.
    a.poll(T);
    b.recv(T + 10, &last(&mut a.wire, MsgKind::Setup));
    a.recv(T + 20, &last(&mut b.wire, MsgKind::Ack));
    let m3 = last(&mut a.wire, MsgKind::Msg3);
    let _ = frames(&mut a.wire);
    b.recv(T + 30, &m3);
    flush(&mut b, &mut a, T + 40);
    let _ = frames(&mut a.wire);
    for _ in 0..5 {
        a.data(T + 41, DATA);
        b.data(T + 41, DATA);
    }
    // The message trigger is due at both ends at once.
    assert_eq!(
        idle(&mut a, T + 40, 1, 9),
        vec![],
        "inside the drain window after its cutover"
    );
    let evs = a.poll(T + 40 + 10_000);
    assert!(
        evs.iter()
            .any(|e| matches!(e, Ev::Send(MsgKind::Setup, ..))),
        "10 s after the cutover: {evs:?}"
    );
    let held: Vec<Ev<()>> = idle(&mut b, T + 30, 1, 29)
        .into_iter()
        .filter(|e| matches!(e, Ev::Send(MsgKind::Setup, ..)))
        .collect();
    assert_eq!(
        held,
        vec![],
        "dampened for 30 s after completing the peer's rekey"
    );
    assert!(
        b.poll(T + 30 + 30_000)
            .iter()
            .any(|e| matches!(e, Ev::Send(MsgKind::Setup, ..)))
    );
}
