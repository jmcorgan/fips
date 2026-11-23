//! Tests of what the XX flow keeps in the table, through the table's own
//! inputs: the parameters, the marks an install and a move set, and the
//! frame mark.

use super::*;
use crate::time::Duration;

#[test]
fn the_xx_parameters_keep_one_interval_floor_and_no_unheard_floor_or_replay_memory() {
    let p = super::super::params(Params::default());
    assert_eq!(p.unheard, Duration::from_secs(0), "no unheard floor");
    assert_eq!(p.replays, 0, "no replay memory");
    assert_eq!(p.interval, Duration::from_secs(15), "next's 15 s interval");
    assert_eq!(
        p.handshake,
        Params::default().handshake,
        "the rest is the base's"
    );
}

#[test]
fn an_install_marks_the_dials_in_flight_then_and_not_a_later_one() {
    let mut a = node(small(), false);
    let first = opened(&go(&mut a, dial(large(), 1, 1), 0));
    let beside = opened(&go(&mut a, dial(large(), 2, 2), 0));
    // The table's own msg2 rule installs the first dial here; the flow's
    // hook marks the install.
    let out = go(
        &mut a,
        Input::Msg2 {
            link: first,
            epoch: E1,
            from: pair(1),
        },
        10,
    );
    assert!(installs(&out, large()), "precondition: the dial installs");
    assert!(
        a.flow().predates(&large(), beside),
        "a dial in flight at the install predates it"
    );
    let later = opened(&go(&mut a, dial(large(), 3, 3), 20));
    assert!(
        !a.flow().predates(&large(), later),
        "a dial opened after the install does not"
    );
}

#[test]
fn a_frame_marks_the_session_heard_and_a_removal_forgets_the_peers_marks() {
    let mut a = node(small(), false);
    let link = opened(&go(&mut a, dial(large(), 1, 1), 0));
    let out = go(
        &mut a,
        Input::Msg2 {
            link,
            epoch: E1,
            from: pair(1),
        },
        10,
    );
    assert!(installs(&out, large()), "precondition: the dial installs");
    assert!(!a.flow().framed(&large()), "unheard under its new session");
    go(
        &mut a,
        Input::Heard {
            peer: large(),
            from: pair(1),
            kind: 0,
        },
        20,
    );
    assert!(a.flow().framed(&large()), "heard under the session held");
    go(&mut a, Input::Dead { peer: large() }, 30);
    assert!(
        !a.flow().framed(&large()),
        "a removal forgets the frame mark"
    );
    assert!(
        !a.flow().predates(&large(), LinkNo(0)),
        "and the install mark"
    );
}
