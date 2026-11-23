//! Tests of the XX flow at msg1: the anonymous answer, its send, and the
//! admission cap it counts against.

use super::*;

#[test]
fn an_anonymous_msg1_opens_an_inbound_link_and_its_answer_a_leg_that_names_no_one() {
    let mut a = node(large(), false);
    let out = xx(&mut a, anon(1, 5, None), 0);
    let link = asked(&out);
    assert_eq!(out.len(), 1, "only the ask: {out:?}");
    let rec = a.links().get(link).expect("the msg1 opened a link");
    assert_eq!(
        rec.dir,
        crate::proto::settle::links::Dir::Inbound,
        "the link opens inbound"
    );
    let out = xx(&mut a, hello(link, 1), 0);
    assert!(
        out.iter().any(|o| matches!(
            o,
            Output::Answer { link: l, stored: false, .. } if *l == link
        )),
        "the answer's msg2 goes out: {out:?}"
    );
    let leg = a.legs().get(link).expect("the answer opened a leg");
    assert_eq!(leg.peer(), None, "an XX answer names no one");
    assert!(
        a.flow().answer(link).is_some_and(|ans| !ans.sent),
        "the flow keeps the answer, unsent"
    );
}

#[test]
fn an_anonymous_answer_installs_nothing_at_its_send_and_waits_for_its_msg3_after_the_peer_at_its_source_is_gone()
 {
    let mut a = node(small(), false);
    let held = held_by_dial(&mut a, large(), E1, 1, 1, 0);
    let link = answered(&mut a, 2, 1, Some(held), 10);
    go(&mut a, Input::Dead { peer: large() }, 20);
    let out = go(&mut a, Input::Sent { link }, 30);
    assert!(
        !installs(&out, large()),
        "an XX answer installs nothing at its send: {out:?}"
    );
    assert!(
        a.legs().get(link).is_some(),
        "defect: the answer's leg is gone before its msg3: {out:?}"
    );
    assert!(
        a.flow().answer(link).is_some_and(|ans| ans.sent),
        "the flow marks its msg2 sent"
    );
}

#[test]
fn the_admission_cap_counts_an_anonymous_answer_only_until_its_msg2_is_sent() {
    let params = Params {
        pending: 1,
        ..Params::default()
    };
    let mut a = node_with(large(), params);
    let link = answered(&mut a, 1, 5, None, 0);
    let stranger = || Input::Arrived {
        from: pair(6),
        bytes: 9u32.to_be_bytes().to_vec(),
    };
    let full = |out: &[O]| {
        out.iter().any(|o| {
            matches!(
                o,
                Output::Reject {
                    why: crate::proto::settle::output::Denial::Full,
                    ..
                }
            )
        })
    };
    let out = go(&mut a, stranger(), 10);
    assert!(
        full(&out),
        "precondition: an unsent answer holds the cap's one place: {out:?}"
    );
    go(&mut a, Input::Sent { link }, 20);
    let out = go(&mut a, stranger(), 30);
    assert!(
        !full(&out),
        "defect: a sent answer, waiting only for its msg3, still holds the cap: {out:?}"
    );
}

#[test]
fn an_answer_to_no_ask_hands_its_lease_back() {
    let mut a = node(large(), false);
    let out = xx(&mut a, hello(LinkNo(7), 1), 0);
    assert!(
        matches!(out.as_slice(), [Output::Free { lease }] if lease.index() == 1),
        "the lease comes back and nothing opens: {out:?}"
    );
    assert!(a.legs().get(LinkNo(7)).is_none(), "no leg opens");
}

/// A leg the table reaps at its deadline leaves the flow's entries for its
/// link behind, and the flow's next step forgets them.
#[test]
fn an_answer_reaped_at_its_deadline_is_forgotten_by_the_flows_next_step() {
    let mut a = node(large(), false);
    let link = answered(&mut a, 1, 5, None, 0);
    assert!(
        a.flow().answer(link).is_some(),
        "precondition: the answer is kept"
    );
    let late = 1_000_000;
    let out = a.poll(t(late));
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::Retire { link: l, .. } if *l == link)),
        "precondition: the poll reaps the answer's leg: {out:?}"
    );
    xx(&mut a, In::Sweep, late);
    assert!(
        a.flow().answer(link).is_none(),
        "defect: the reaped answer's entry outlives its leg"
    );
}
