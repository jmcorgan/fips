//! Tests of the judgements for the rows the reference model has no
//! history for: path events, attribution by a proven path, a punched dial,
//! a failed msg2 send, an orphaned bundle, the admission cap, the links a
//! move retires, and the reset a move hands the per-peer data.

use alloc::vec::Vec;

use super::*;
use crate::proto::rekey::IndexLease;
use crate::testutil::TestInstant;
use crate::transport::{TransportAddr, TransportId};

fn pair(port: u16) -> Pair {
    Pair {
        transport: TransportId::new(1),
        addr: TransportAddr::from_string(&alloc::format!("10.0.0.1:{port}")),
    }
}

/// The smaller node.
fn small() -> NodeAddr {
    NodeAddr::from_bytes([1; 16])
}

/// The larger node.
fn large() -> NodeAddr {
    NodeAddr::from_bytes([2; 16])
}

fn t(ms: u64) -> TestInstant {
    TestInstant(ms)
}

fn eph(n: u32) -> EphemeralDigest {
    let mut key = [0u8; 33];
    key[..4].copy_from_slice(&n.to_be_bytes());
    EphemeralDigest::of_noise_msg1(&key).expect("33 bytes carry an ephemeral")
}

const E1: Epoch = [1; 8];

/// The msg2 answering msg1 `n`.
fn answer(n: u32) -> Vec<u8> {
    [&[2u8][..], &n.to_be_bytes()].concat()
}

/// Msg1 `n` from `peer` at `port`, epoch 1.
fn hello(peer: NodeAddr, n: u32, port: u16) -> Hello {
    Hello {
        peer,
        from: pair(port),
        bytes: n.to_be_bytes().to_vec(),
        ephemeral: eph(n),
        epoch: E1,
        msg2: answer(n),
        lease: IndexLease::for_test(n),
    }
}

fn msg1(peer: NodeAddr, n: u32, port: u16) -> Input {
    Input::Msg1 {
        hello: hello(peer, n, port),
        reachable: true,
    }
}

fn dial(peer: NodeAddr, n: u32, port: u16) -> Dial {
    Dial {
        peer,
        to: pair(port),
        msg1: n.to_be_bytes().to_vec(),
        lease: IndexLease::for_test(n),
    }
}

/// Release every lease in `out`; an install is kept as the link opened.
fn drain(out: Vec<Output>) -> Vec<Output> {
    out.into_iter()
        .filter_map(|o| match o {
            Output::Free { lease } => {
                lease.release();
                None
            }
            Output::Install(i) => {
                let link = i.link;
                i.lease.release();
                Some(Output::Opened { link })
            }
            other @ (Output::Opened { .. }
            | Output::Answer { .. }
            | Output::Resend { .. }
            | Output::Rekey { .. }
            | Output::Reset { .. }
            | Output::Remove { .. }
            | Output::Retire { .. }
            | Output::Release { .. }
            | Output::Close { .. }
            | Output::Retry { .. }
            | Output::Reject { .. }
            | Output::Hold { .. }
            | Output::Settle { .. }) => Some(other),
        })
        .collect()
}

fn go(table: &mut Table<TestInstant>, input: Input, at: u64) -> Vec<Output> {
    drain(table.step(input, t(at)))
}

/// The link a dial opened.
fn opened(out: &[Output]) -> LinkNo {
    out.iter()
        .find_map(|o| {
            if let Output::Opened { link } = o {
                Some(*link)
            } else {
                None
            }
        })
        .expect("a dial opens a link")
}

/// The link a fresh answer went out on.
fn answered(out: &[Output]) -> LinkNo {
    out.iter()
        .find_map(|o| {
            if let Output::Answer {
                link,
                stored: false,
                ..
            } = o
            {
                Some(*link)
            } else {
                None
            }
        })
        .expect("precondition: the msg1 was answered")
}

/// Whether `out` refuses for the admission cap.
fn full(out: &[Output]) -> bool {
    out.iter().any(|o| {
        matches!(
            o,
            Output::Reject {
                why: Denial::Full,
                ..
            }
        )
    })
}

/// `me` holding `large()` from its msg1 `n` at `port`, its answer sent.
fn responder(me: NodeAddr, n: u32, port: u16) -> (Table<TestInstant>, LinkNo) {
    let mut table = Table::new(me, Params::default());
    let link = answered(&go(&mut table, msg1(large(), n, port), 0));
    go(&mut table, Input::Sent { link }, 0);
    assert!(
        table.held(&large()).is_some(),
        "precondition: the peer is held"
    );
    (table, link)
}

/// `small()` holding `large()` on its own dial to `port`.
fn dialer(port: u16) -> (Table<TestInstant>, LinkNo) {
    let mut table = Table::new(small(), Params::default());
    let link = opened(&go(&mut table, Input::Dial(dial(large(), 1, port)), 0));
    let msg2 = Input::Msg2 {
        link,
        epoch: E1,
        from: pair(port),
    };
    go(&mut table, msg2, 0);
    assert_eq!(
        table.held(&large()).map(|h| h.link),
        Some(link),
        "precondition: the peer is held on the dial"
    );
    (table, link)
}

fn indexed(table: &Table<TestInstant>, port: u16, link: LinkNo) -> bool {
    table.links().index().contains(&(pair(port), link))
}

fn switched(link: LinkNo, to: u16) -> Input {
    Input::Switched {
        link,
        from: pair(1),
        to: pair(to),
    }
}

#[test]
fn a_path_moved_rekeys_the_links_index_entry_to_the_new_pair() {
    let (mut table, link) = dialer(1);
    go(&mut table, switched(link, 5), 0);
    assert!(
        indexed(&table, 5, link),
        "precondition: the path is indexed"
    );
    let moved = Input::Moved {
        link,
        from: pair(5),
        to: pair(6),
    };
    go(&mut table, moved, 0);
    assert!(
        indexed(&table, 6, link),
        "the moved path is indexed at its new pair"
    );
    assert!(!indexed(&table, 5, link), "and not at the pair it left");
}

#[test]
fn a_path_switched_adds_the_new_pair_to_the_index() {
    let (mut table, link) = dialer(1);
    go(&mut table, switched(link, 7), 0);
    assert!(indexed(&table, 7, link));
    assert!(indexed(&table, 1, link), "the setup address stays");
}

#[test]
fn a_path_released_drops_its_pair_and_closes_unless_in_use_or_kept() {
    let (mut table, link) = dialer(1);
    let other = opened(&go(&mut table, Input::Dial(dial(small(), 2, 3)), 0));
    for (port, on) in [(5, link), (6, link), (8, link), (8, other)] {
        let state = Input::State {
            link: on,
            pair: pair(port),
            proven: Proven::Live,
        };
        go(&mut table, state, 0);
    }
    let mut released = |port, keep| {
        let input = Input::Released {
            link,
            pair: pair(port),
            keep,
        };
        match go(&mut table, input, 0).as_slice() {
            [Output::Release { closes, .. }] => closes.clone(),
            other => panic!("a release reports its closes, got {other:?}"),
        }
    };
    assert_eq!(released(5, false), alloc::vec![pair(5)]);
    assert!(released(6, true).is_empty(), "kept");
    assert!(released(8, false).is_empty(), "another link's live path");
    assert!(
        !indexed(&table, 5, link),
        "a released pair leaves the index"
    );
    assert!(!indexed(&table, 8, link));
}

#[test]
fn a_path_state_change_to_probing_stops_it_counting_as_in_use() {
    let (mut table, link) = dialer(1);
    go(&mut table, switched(link, 5), 0);
    assert!(table.links().in_use(&pair(5), LinkNo(u64::MAX)));
    let probing = Input::State {
        link,
        pair: pair(5),
        proven: Proven::Probing,
    };
    go(&mut table, probing, 0);
    assert!(!indexed(&table, 5, link), "a probing path is not indexed");
    assert!(!table.links().in_use(&pair(5), LinkNo(u64::MAX)));
}

#[test]
fn a_msg1_from_a_proven_path_is_on_the_link() {
    let (mut table, link) = responder(small(), 10, 9);
    let state = Input::State {
        link,
        pair: pair(4),
        proven: Proven::Live,
    };
    go(&mut table, state, 0);
    let mut on = |n, port| {
        go(&mut table, msg1(large(), n, port), 0)
            .into_iter()
            .find_map(|o| {
                if let Output::Rekey { arrival, .. } = o {
                    Some(arrival.on_link)
                } else {
                    None
                }
            })
            .expect("a same-epoch msg1 goes to the rekey machine")
    };
    assert!(on(11, 4), "from the proven path");
    assert!(on(12, 9), "from the setup address");
    assert!(!on(13, 3), "from elsewhere");
}

#[test]
fn a_punched_input_opens_a_dial_leg_at_the_punched_pair() {
    let mut table = Table::new(small(), Params::default());
    let link = opened(&go(&mut table, Input::Punched(dial(large(), 1, 6)), 0));
    assert_eq!(
        table.links().get(link).map(|r| r.setup.clone()),
        Some(pair(6))
    );
    assert_eq!(
        table.legs().get(link).map(|l| l.kind().clone()),
        Some(Kind::Dial)
    );
}

#[test]
fn a_failed_msg2_send_keeps_the_stored_answer_for_the_resend() {
    let mut table = Table::new(small(), Params::default());
    let link = answered(&go(&mut table, msg1(large(), 10, 9), 0));
    go(&mut table, Input::SendFailed { link }, 0);
    let again = go(&mut table, msg1(large(), 10, 9), 500);
    let expect = Output::Answer {
        link,
        msg2: answer(10),
        stored: true,
    };
    assert!(
        again.contains(&expect),
        "the resend draws the stored msg2: {again:?}"
    );
}

#[test]
fn a_msg1_from_the_address_of_an_unsent_answer_draws_that_answer_whatever_its_bytes() {
    // FRC-1201 Section 5.8: the stored msg2 alone, before any Noise read,
    // to any msg1 from that address, as the model and the current node
    // answer it; a peer that restarted meanwhile sends a msg1 of its own.
    let mut table = Table::new(small(), Params::default());
    let link = answered(&go(&mut table, msg1(large(), 10, 9), 0));
    go(&mut table, Input::SendFailed { link }, 0);
    let other = go(&mut table, msg1(large(), 11, 9), 500);
    let expect = Output::Answer {
        link,
        msg2: answer(10),
        stored: true,
    };
    assert!(
        other.contains(&expect),
        "another msg1 from that address draws the stored msg2: {other:?}"
    );
}

#[test]
fn an_orphaned_bundle_removes_the_peer_and_retires_its_link() {
    let (mut table, link) = dialer(1);
    let out = go(&mut table, Input::Orphaned { peer: large() }, 0);
    assert!(out.contains(&Output::Remove {
        peer: large(),
        why: Why::Orphaned,
    }));
    assert!(table.held(&large()).is_none());
    assert!(table.links().get(link).is_none(), "its link is retired");
}

#[test]
fn a_msg1_past_the_admission_cap_is_rejected_and_holds_no_leg() {
    let params = Params {
        pending: 2,
        ..Params::default()
    };
    let mut table = Table::new(small(), params);
    for n in 3..5u8 {
        let peer = NodeAddr::from_bytes([n; 16]);
        let link = answered(&go(&mut table, msg1(peer, n.into(), n.into()), 0));
        go(&mut table, Input::SendFailed { link }, 0);
    }
    assert_eq!(
        table.legs().answering(),
        2,
        "precondition: two answers in flight"
    );
    let out = go(&mut table, msg1(NodeAddr::from_bytes([5; 16]), 5, 5), 0);
    assert!(full(&out), "the third is refused: {out:?}");
    assert_eq!(table.legs().answering(), 2, "and holds no leg");
    let early = Input::Arrived {
        from: pair(6),
        bytes: alloc::vec![6],
    };
    assert!(
        full(&go(&mut table, early, 0)),
        "refused before any Diffie-Hellman too"
    );
}

/// The smaller node's crossing: its dial to `at(2)`, the larger node's
/// msg1 from `at(12)` answered and sent, then the dial's msg2.
fn crossing() -> (Table<TestInstant>, LinkNo, LinkNo, Vec<Output>) {
    let mut table = Table::new(small(), Params::default());
    let dialed = opened(&go(&mut table, Input::Dial(dial(large(), 1, 2)), 0));
    let inbound = answered(&go(&mut table, msg1(large(), 2, 12), 0));
    go(&mut table, Input::Sent { link: inbound }, 0);
    let msg2 = Input::Msg2 {
        link: dialed,
        epoch: E1,
        from: pair(2),
    };
    let out = go(&mut table, msg2, 0);
    (table, dialed, inbound, out)
}

#[test]
fn a_crossing_moves_the_smaller_node_and_retires_the_inbound_link() {
    let (table, dialed, inbound, out) = crossing();
    assert_eq!(table.held(&large()).map(|h| h.link), Some(dialed));
    let retired = Output::Retire {
        link: inbound,
        closes: alloc::vec![pair(12)],
    };
    assert!(
        out.contains(&retired),
        "the inbound link is retired and its connection closed: {out:?}"
    );
    assert!(table.links().get(inbound).is_none());
}

#[test]
fn a_late_second_dial_in_order_retires_the_link_moved_off() {
    let mut table = Table::new(large(), Params::default());
    let first = opened(&go(&mut table, Input::Dial(dial(small(), 1, 1)), 0));
    let msg2 = Input::Msg2 {
        link: first,
        epoch: E1,
        from: pair(1),
    };
    go(&mut table, msg2, 0);
    let second = opened(&go(&mut table, Input::Dial(dial(small(), 2, 5)), 2_000));
    let msg2 = Input::Msg2 {
        link: second,
        epoch: E1,
        from: pair(5),
    };
    let out = go(&mut table, msg2, 2_000);
    assert_eq!(table.held(&small()).map(|h| h.link), Some(second));
    let retired = Output::Retire {
        link: first,
        closes: alloc::vec![pair(1)],
    };
    assert!(
        out.contains(&retired),
        "the link moved off is retired: {out:?}"
    );
}

#[test]
fn a_move_resets_peer_data() {
    let (_, _, _, out) = crossing();
    let reset = Output::Reset {
        peer: large(),
        transition: Transition::Move,
    };
    assert!(out.contains(&reset));
}
