//! The rows only next's profiles select, dormant on master: a leg table's
//! completions handed to the machine, the delayed initiator cutover with
//! its retained msg3, and a three-message responder that cuts over on the
//! initiator's frame.

use alloc::vec;
use alloc::vec::Vec;

use super::stub::{
    DATA, Ev, Hs, Local, Msg, Node, PLAIN, Xk, XkFrame, Xx, bytes, fmp, frames, fsp, last,
    leg_answer, leg_done, leg_frame, ordered, pair,
};
use crate::proto::rekey::{
    Abandon, CycleView, EpochTag, EvidenceKind, Input, Intent, MsgKind, Purpose, Reason, Role,
    Slot, TagSource, Wait, allocate,
};

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

/// A next-shaped link set up at 0, `a` the smaller.
fn link() -> (Node<Xx>, Node<Xx>) {
    let (a, b) = ordered(1, 2);
    pair::<Xx>(a, b, 0, fmp())
}

/// `from` starts its rekey at `t`; `to`'s leg table answers it with a
/// leased index. Returns the leg, the leg's lease index and the msg3 `from`
/// wrote, after `from` completed into its delayed pending.
fn attempt(
    from: &mut Node<Xx>,
    to: &mut Node<Xx>,
    t: u64,
) -> (Hs, Option<crate::proto::rekey::IndexLease>, Vec<u8>) {
    from.poll(t);
    let m1 = bytes(&last(&mut from.wire, MsgKind::Setup));
    let lease = allocate(&mut to.indices);
    let ours = lease
        .as_ref()
        .map(crate::proto::rekey::IndexLease::index)
        .unwrap_or(0);
    let (hs, m2) = leg_answer(&to.local, &m1, ours).expect("the leg answers");
    from.recv(t + 10, &Msg::Hs(MsgKind::Msg2, m2));
    let m3 = bytes(&last(&mut from.wire, MsgKind::Msg3));
    (hs, lease, m3)
}

/// Hand `to` the completion of the leg `hs` on `m3`.
fn done(
    to: &mut Node<Xx>,
    at: u64,
    hs: &Hs,
    m3: &[u8],
    lease: Option<crate::proto::rekey::IndexLease>,
    intent: Intent,
) -> Vec<Ev<u8>> {
    let tok = leg_done(hs, m3, lease).expect("the leg completes");
    to.step(at, Input::PeerDone { tok, intent })
}

#[test]
fn delayed_initiator_cuts_over_after_its_delay_and_the_responder_on_its_frame() {
    let (mut a, mut b) = link();
    let (hs, lease, m3) = attempt(&mut a, &mut b, T);
    let leg = lease
        .as_ref()
        .map(crate::proto::rekey::IndexLease::index)
        .expect("leased");
    assert_eq!(a.m().view().cycle, CycleView::PendI(Wait::Delay));
    assert!(
        a.log.contains(&Ev::Unbind(1, 501))
            && a.log
                .contains(&Ev::Bind(1, 501, Some(tag(1)), Purpose::Pending))
    );
    let evs = done(&mut b, T + 20, &hs, &m3, lease, Intent::Rekey);
    assert_eq!(evs, vec![Ev::Bind(1, leg, Some(tag(1)), Purpose::Pending)]);
    assert_eq!(b.m().view().cycle, CycleView::PendR);
    // The initiator resends msg3 on its ladder, with no probe, until its
    // delay passes, then cuts over and keeps resending it.
    assert_eq!(
        a.poll(T + 10 + 1_000),
        vec![Ev::Send(MsgKind::Msg3, m3.clone(), PLAIN)]
    );
    let evs = a.poll(T + 10 + 2_000);
    assert_eq!(
        evs,
        vec![
            Ev::Installed(tag(1), Role::Initiator, EvidenceKind::Delay),
            Ev::Prompt(tag(1)),
            Ev::Rekeyed(Role::Initiator),
        ]
    );
    assert_eq!(
        a.poll(T + 10 + 3_000),
        vec![
            Ev::Send(MsgKind::Msg3, m3.clone(), PLAIN),
            Ev::Prompt(tag(1))
        ],
        "at a tie the msg3 rung comes before the prompt repeat"
    );
    // A frame under the previous epoch neither confirms the new epoch nor
    // clears the retained msg3.
    let old = b.data(T + 10 + 3_001, DATA);
    assert_eq!(
        a.frame(T + 10 + 3_002, &old),
        vec![Ev::Deliver(Slot::Previous, tag(0), DATA.to_vec())]
    );
    assert_eq!(
        a.poll(T + 10 + 7_000),
        vec![
            Ev::Prompt(tag(1)),
            Ev::Send(MsgKind::Msg3, m3.clone(), PLAIN)
        ]
    );
    // The prompt adopts the responder's pending; its prompt is the first
    // frame the initiator hears, which drops the retained msg3.
    let f = frames(&mut a.wire);
    let evs = b.recv(T + 10 + 3_010, &f[0]);
    assert!(
        evs.contains(&Ev::Installed(tag(1), Role::Responder, EvidenceKind::Frame)),
        "{evs:?}"
    );
    for m in frames(&mut b.wire) {
        a.recv(T + 10 + 3_020, &m);
    }
    let evs = a.poll(T + 10 + 15_000);
    assert!(
        !evs.iter().any(|e| matches!(e, Ev::Send(MsgKind::Msg3, ..))),
        "no msg3 once the peer is heard: {evs:?}"
    );
}

#[test]
fn retained_msg3_never_outlives_its_ladder() {
    // With the peer silent, the msg3 retained at the delayed cutover goes
    // after its last rung and a repair falls due.
    let (mut a, mut b) = link();
    let (_hs, _lease, m3) = attempt(&mut a, &mut b, T);
    let mut sent = Vec::new();
    let mut repair = false;
    for s in 1..=40u64 {
        let evs = a.poll(T + 10 + s * 1_000);
        let _ = a.sent();
        if evs.contains(&Ev::Send(MsgKind::Msg3, m3.clone(), PLAIN)) {
            sent.push(s);
        }
        repair |= evs
            .iter()
            .any(|e| matches!(e, Ev::Send(MsgKind::Setup, ..)));
    }
    assert_eq!(
        sent,
        [1, 3, 7, 15],
        "the ladder continues across the cutover and ends"
    );
    assert!(repair, "unheard at the end of the ladder: a repair rekey");
    drop(_lease);
    // A cutover on a frame drops the retained msg3 at once.
    let (mut c, mut d) = link();
    let (hs, lease, m3) = attempt(&mut c, &mut d, T);
    let index = 501;
    let f = leg_frame(&hs, &m3, index, true, DATA).expect("seals");
    let evs = c.frame(T + 500, &f);
    assert!(
        evs.contains(&Ev::Installed(tag(1), Role::Initiator, EvidenceKind::Frame)),
        "{evs:?}"
    );
    assert!(evs.contains(&Ev::Deliver(Slot::Current, tag(1), DATA.to_vec())));
    assert_eq!(
        c.poll(T + 10 + 1_000),
        vec![],
        "no msg3 after a frame cutover"
    );
    if let Some(l) = lease {
        d.indices.free(l.release());
    }
}

#[test]
fn every_leg_completion_cell_takes_its_rows_action() {
    // An unanswered own attempt yields to a completion.
    let (mut a, mut b) = link();
    b.poll(T);
    let (hs, lease, m3) = attempt(&mut a, &mut b, T);
    let evs = done(&mut b, T + 20, &hs, &m3, lease, Intent::Rekey);
    assert_eq!(
        evs[..3],
        [
            Ev::Unbind(1, 501),
            Ev::Release(501),
            Ev::Abandoned(Abandon::Yielded)
        ]
    );
    assert!(matches!(evs[3], Ev::Bind(1, _, Some(_), Purpose::Pending)));
    // A held responder pending is superseded by a later completion.
    let (hs2, lease2, m3b) = {
        let (mut a2, _) = link();
        a2.skip(5);
        attempt(&mut a2, &mut b, T + 100)
    };
    let evs = done(&mut b, T + 200, &hs2, &m3b, lease2, Intent::Rekey);
    assert!(evs.contains(&Ev::Abandoned(Abandon::Superseded)), "{evs:?}");
    assert!(matches!(
        evs.last(),
        Some(Ev::Bind(_, _, Some(_), Purpose::Pending))
    ));
    // Completions that are not rekeys, or from another static, release
    // their leg and change nothing.
    let (mut c, mut d) = link();
    let before = d.digest();
    let (hs, lease, m3) = attempt(&mut c, &mut d, T);
    let leg = lease
        .as_ref()
        .map(crate::proto::rekey::IndexLease::index)
        .expect("leased");
    let evs = done(&mut d, T + 20, &hs, &m3, lease, Intent::Fresh);
    assert_eq!(
        evs,
        vec![
            Ev::Unbind(1, leg),
            Ev::Release(leg),
            Ev::Reject(Reason::NotRekey)
        ]
    );
    assert_eq!(d.digest(), before);
    let mut impostor = Node::<Xx>::new(Local::new(66, 66));
    let other = link_with(&mut impostor, &mut d);
    let _ = other;
}

/// An attempt by `from` (not the peer `to` is bonded to) completed by
/// `to`'s leg table; returns the events of the hand-over.
fn link_with(from: &mut Node<Xx>, to: &mut Node<Xx>) -> Vec<Ev<u8>> {
    let (m1, _) = {
        let (hs, m) =
            <Xx as crate::proto::rekey::Profile>::initiate(&from.local, &to.local.key, Some(9))
                .expect("writes");
        (m, hs)
    };
    let lease = allocate(&mut to.indices);
    let leg = lease
        .as_ref()
        .map(crate::proto::rekey::IndexLease::index)
        .expect("leased");
    let (hs, _m2) = leg_answer(&to.local, &m1, leg).expect("answers");
    let m3 = super::stub::forge3(&from.local, hs_ei(&m1), hs_er(&_m2));
    let before = to.digest();
    let evs = done(to, T + 50, &hs, &m3, lease, Intent::Rekey);
    assert_eq!(
        evs,
        vec![
            Ev::Unbind(1, leg),
            Ev::Release(leg),
            Ev::Reject(Reason::KeyMismatch)
        ]
    );
    assert_eq!(to.digest(), before);
    evs
}

/// The initiator ephemeral of an XX msg1.
fn hs_ei(m1: &[u8]) -> [u8; 8] {
    m1[5..13].try_into().expect("eight bytes")
}

/// The responder ephemeral of an XX msg2.
fn hs_er(m2: &[u8]) -> [u8; 8] {
    m2[9..17].try_into().expect("eight bytes")
}

#[test]
fn completed_own_attempts_meet_a_completion_by_the_tie_break() {
    // Both complete their own attempts toward each other's leg tables.
    let (mut a, mut b) = link();
    let (hs_a, lease_at_b, m3_a) = attempt(&mut a, &mut b, T);
    let (hs_b, lease_at_a, m3_b) = attempt(&mut b, &mut a, T);
    // The smaller keeps its own and releases the peer's leg.
    let leg = lease_at_a
        .as_ref()
        .map(crate::proto::rekey::IndexLease::index)
        .expect("leased");
    let before = a.digest();
    let evs = done(&mut a, T + 20, &hs_b, &m3_b, lease_at_a, Intent::Rekey);
    assert_eq!(
        evs,
        vec![
            Ev::Unbind(1, leg),
            Ev::Release(leg),
            Ev::Reject(Reason::TieBreakKept)
        ]
    );
    assert_eq!(a.digest(), before);
    // The larger retires its own pending, msg3 and all, and takes the
    // smaller's completion.
    let mine = b.m().view().pending.expect("pending").tag;
    let evs = done(&mut b, T + 20, &hs_a, &m3_a, lease_at_b, Intent::Rekey);
    assert!(evs.contains(&Ev::Retired(mine)), "{evs:?}");
    assert_eq!(b.m().view().cycle, CycleView::PendR);
    let msg3s = (1..20)
        .flat_map(|s| b.poll(T + 20 + s * 1_000))
        .filter(|e| matches!(e, Ev::Send(MsgKind::Msg3, ..)))
        .count();
    assert_eq!(msg3s, 0, "the retired pending's msg3 died with it");
}

#[test]
fn a_completion_while_the_own_delayed_epoch_is_unheard_is_decided_by_the_tie_break() {
    for smaller in [true, false] {
        let (mut a, mut b) = link();
        let (me, peer) = if smaller {
            (&mut a, &mut b)
        } else {
            (&mut b, &mut a)
        };
        // `me` completes and cuts over after its delay; the peer is unheard.
        let (_hs, _lease, _m3) = attempt(me, peer, T);
        me.poll(T + 10 + 2_000);
        let _ = me.sent();
        assert!(me.m().view().current.expect("cur").tag == tag(1));
        let (hs, lease, m3) = attempt(peer, me, T + 3_000);
        let evs = done(me, T + 3_020, &hs, &m3, lease, Intent::Rekey);
        if smaller {
            assert!(evs.contains(&Ev::Reject(Reason::TieBreakKept)), "{evs:?}");
            assert_eq!(me.m().view().cycle, CycleView::Idle);
        } else {
            assert!(
                matches!(evs.last(), Some(Ev::Bind(_, _, Some(_), Purpose::Pending))),
                "{evs:?}"
            );
            assert_eq!(me.m().view().cycle, CycleView::PendR);
            assert_eq!(
                me.m().view().current.expect("cur").tag,
                tag(1),
                "current until the new pending is adopted"
            );
            let resent = (1..20)
                .flat_map(|s| me.poll(T + 3_020 + s * 1_000))
                .filter(|e| matches!(e, Ev::Send(MsgKind::Msg3, ..)))
                .count();
            assert_eq!(resent, 0, "the yielded epoch's msg3 is dropped");
        }
        drop(_lease);
    }
}

#[test]
fn impostor_reply_never_reports_a_restart() {
    let (mut a, b) = link();
    a.poll(T);
    let m1 = bytes(&last(&mut a.wire, MsgKind::Setup));
    // Another static, in another epoch, answers the msg1: the read succeeds
    // on this unpinned pattern, the bond fails, and nothing is reported.
    let impostor = Local::new(66, 99);
    let (_, m2) = leg_answer(&impostor, &m1, 300).expect("answers");
    let before = a.digest();
    let evs = a.recv(T + 10, &Msg::Hs(MsgKind::Msg2, m2));
    assert_eq!(evs, vec![Ev::Reject(Reason::ReplyUnauthenticated)]);
    assert_eq!(
        a.digest(),
        before,
        "a completion with another static installs nothing"
    );
    let _ = b;
}

#[test]
fn a_frame_driven_session_responder_holds_its_completion_until_the_initiators_frame() {
    let (x, y) = ordered(1, 2);
    let (mut a, mut b) = pair::<XkFrame>(x, y, 0, fsp());
    a.poll(T);
    b.recv(T + 10, &last(&mut a.wire, MsgKind::Setup));
    a.recv(T + 20, &last(&mut b.wire, MsgKind::Ack));
    let m3 = last(&mut a.wire, MsgKind::Msg3);
    let probes = frames(&mut a.wire);
    assert_eq!(
        b.recv(T + 30, &m3),
        vec![],
        "accepted into a held pending, no cutover"
    );
    assert_eq!(b.m().view().cycle, CycleView::PendR);
    // A newer completion supersedes it.
    let (x2, y2) = ordered(1, 2);
    let (mut a2, _) = pair::<XkFrame>(x2, y2, 0, fsp());
    a2.skip(5);
    a2.poll(T + 100);
    b.recv(T + 110, &last(&mut a2.wire, MsgKind::Setup));
    a2.recv(T + 120, &last(&mut b.wire, MsgKind::Ack));
    let m3b = last(&mut a2.wire, MsgKind::Msg3);
    let probes2 = frames(&mut a2.wire);
    let evs = b.recv(T + 130, &m3b);
    assert_eq!(
        evs,
        vec![Ev::Retired(tag(1)), Ev::Abandoned(Abandon::Superseded)]
    );
    assert_eq!(b.m().view().cycle, CycleView::PendR);
    // The superseded epoch's probe now finds nothing; the newer one adopts.
    assert_eq!(
        b.recv(T + 140, &probes[0]),
        vec![Ev::Reject(Reason::FrameUnauthenticated)]
    );
    let evs = b.recv(T + 150, &probes2[0]);
    assert!(
        evs.contains(&Ev::Installed(tag(2), Role::Responder, EvidenceKind::Frame)),
        "{evs:?}"
    );
    let _ = Xk;
}

#[test]
fn a_previous_epoch_frame_beside_a_responder_pending_after_an_assumed_cutover_changes_no_epoch() {
    let (x, y) = ordered(1, 2);
    let (mut a, mut b) = pair::<XkFrame>(x, y, 0, fsp());
    // The initiator assumes its epoch with every msg3 and probe lost.
    a.poll(T);
    b.recv(T + 10, &last(&mut a.wire, MsgKind::Setup));
    a.recv(T + 20, &last(&mut b.wire, MsgKind::Ack));
    let _ = a.sent();
    for s in 1..=31u64 {
        a.poll(T + 20 + s * 1_000);
        let _ = a.sent();
    }
    let assumed = a.m().view().current.expect("cur").tag;
    // The peer, still on the old epoch, completes a rekey of its own, which
    // this frame-driven responder holds as a pending.
    b.skip(3);
    let (hs, setup) =
        <XkFrame as crate::proto::rekey::Profile>::initiate(&b.local, &a.local.key, None)
            .expect("writes");
    a.setup_on(T + 60_000, 1, &setup);
    let ack = bytes(&last(&mut a.wire, MsgKind::Ack));
    let read =
        <XkFrame as crate::proto::rekey::Profile>::reply(&hs, &b.local, &ack).expect("reads");
    assert_eq!(
        a.recv(T + 60_010, &Msg::Hs(MsgKind::Msg3, read.fin.expect("msg3"))),
        vec![]
    );
    assert_eq!(a.m().view().cycle, CycleView::PendR);
    let f = b.data(T + 60_020, DATA);
    let evs = a.frame(T + 60_020, &f);
    assert_eq!(
        evs,
        vec![Ev::Deliver(Slot::Previous, tag(0), DATA.to_vec())]
    );
    assert_eq!(
        a.m().view().current.expect("cur").tag,
        assumed,
        "no epoch changes"
    );
    assert_eq!(
        a.m().view().cycle,
        CycleView::PendR,
        "the newer pending decides"
    );
}
