//! Tests of the link records, their derived index and the close rule.

use alloc::vec::Vec;

use super::*;

fn pair(transport: u32, port: u16) -> Pair {
    Pair {
        transport: TransportId::new(transport),
        addr: TransportAddr::from_string(&alloc::format!("10.0.0.1:{port}")),
    }
}

fn peer(n: u8) -> Holder {
    Holder::Peer(NodeAddr::from_bytes([n; 16]))
}

#[test]
fn the_index_holds_each_live_links_setup_address_and_proven_paths() {
    let mut links = Links::new();
    let a = links.open(pair(1, 1), Dir::Outbound, peer(2));
    let b = links.open(pair(1, 2), Dir::Inbound, Holder::Leg);
    links.path(a, pair(1, 3), Proven::Live);
    links.path(a, pair(1, 4), Proven::Probing);
    let want: BTreeSet<(Pair, LinkNo)> = [(pair(1, 1), a), (pair(1, 2), b), (pair(1, 3), a)]
        .into_iter()
        .collect();
    assert_eq!(*links.index(), want, "setup addresses and proven paths");
    assert_eq!(
        links.retire(b),
        [pair(1, 2)],
        "precondition: the leg's link closes"
    );
    assert_eq!(
        links.index().iter().filter(|(_, l)| *l == b).count(),
        0,
        "a retired link leaves the index"
    );
    assert_eq!(*links.index(), links.derived(), "the index is the records'");
}

#[test]
fn retiring_a_link_closes_only_addresses_no_other_live_link_uses() {
    // Two legs of a crossing share one connection at one pair, as on BLE:
    // retiring the peer's link leaves the pair to the leg still in flight.
    let mut links = Links::new();
    let held = links.open(pair(2, 1), Dir::Inbound, peer(2));
    let _leg = links.open(pair(2, 1), Dir::Outbound, Holder::Leg);
    let alone = links.open(pair(2, 5), Dir::Inbound, peer(3));
    assert!(links.retire(held).is_empty(), "the leg still uses the pair");
    assert_eq!(
        links.retire(alone),
        [pair(2, 5)],
        "nothing else uses this one"
    );
}

#[test]
fn a_retired_links_address_that_is_another_links_live_path_stays_open() {
    let mut links = Links::new();
    let other = links.open(pair(1, 7), Dir::Outbound, peer(2));
    links.path(other, pair(1, 8), Proven::Live);
    let retired = links.open(pair(1, 8), Dir::Inbound, peer(3));
    assert!(
        links.retire(retired).is_empty(),
        "the other link's live path keeps the connection"
    );
}

/// Records current behaviour (rule S-57: a Probing path not in use): open to change by
/// decision. Its other assertions are not.
#[test]
fn a_probing_path_keeps_no_connection_open() {
    let mut links = Links::new();
    let other = links.open(pair(1, 7), Dir::Outbound, peer(2));
    links.path(other, pair(1, 8), Proven::Probing);
    let retired = links.open(pair(1, 8), Dir::Inbound, peer(3));
    assert_eq!(
        links.retire(retired),
        [pair(1, 8)],
        "a probing path does not keep it"
    );
}

#[test]
fn a_released_path_marked_keep_closes_nothing() {
    let mut links = Links::new();
    let link = links.open(pair(1, 1), Dir::Outbound, peer(2));
    links.path(link, pair(1, 1), Proven::Live);
    links.path(link, pair(1, 2), Proven::Live);
    links.path(link, pair(1, 3), Proven::Live);
    assert!(
        links.release(link, &pair(1, 2), true).is_empty(),
        "the peer may still send there"
    );
    assert_eq!(
        links.release(link, &pair(1, 3), false),
        [pair(1, 3)],
        "precondition: a release not kept closes its address"
    );
    let left: Vec<Pair> = links.at(&pair(1, 2)).map(|_| pair(1, 2)).collect();
    assert!(left.is_empty(), "the released path leaves the index");
}

/// Records current behaviour (rule S-58: the released setup pair out of the index): open to
/// change by decision. Its other assertions are not.
#[test]
fn a_released_setup_address_leaves_the_index_and_a_roamed_one_stays() {
    let mut links = Links::new();
    let released = links.open(pair(1, 1), Dir::Outbound, peer(2));
    links.path(released, pair(1, 1), Proven::Live);
    links.path(released, pair(1, 2), Proven::Live);
    let roamed = links.open(pair(1, 5), Dir::Inbound, peer(3));
    links.path(roamed, pair(1, 5), Proven::Live);
    links.moved(roamed, &pair(1, 5), pair(1, 6));
    links.release(released, &pair(1, 1), true);
    assert_eq!(
        links.at(&pair(1, 2)).collect::<Vec<_>>(),
        [released],
        "precondition: the link's other path stays named"
    );
    assert_eq!(
        links.at(&pair(1, 1)).count(),
        0,
        "a released setup address leaves the index"
    );
    assert_eq!(
        links.at(&pair(1, 5)).collect::<Vec<_>>(),
        [roamed],
        "a setup address the path roamed away from stays named"
    );
    assert_eq!(
        links.at(&pair(1, 6)).collect::<Vec<_>>(),
        [roamed],
        "the roamed pair is named"
    );
    assert_eq!(*links.index(), links.derived(), "the index is the records'");
}

/// The four answers a msg1's source gets: whether a link owns it, the
/// identity it is to prove, the answered leg it is a resend to, and
/// whether it is on the held link.
#[derive(Debug, PartialEq, Eq)]
struct Answers {
    established: bool,
    expected: Option<NodeAddr>,
    unanswered: Option<LinkNo>,
    on: bool,
}

/// The identity of peer `n`.
fn id(n: u8) -> NodeAddr {
    NodeAddr::from_bytes([n; 16])
}

/// Each question the node asks of a msg1's source before any
/// Diffie-Hellman, answered from the records as the node answers it
/// (`is_established_link_msg1`, `msg1_waiver`, the duplicate check and
/// `msg1_to_link`'s `on_link`, in `src/node/handlers/handshake.rs`), over
/// one state per row. Peer 2 is held on link `held`, set up at port 1; a
/// leg expects peer 3, unless it was set up at port 7, where it expects no
/// identity.
#[test]
fn each_attribution_question_answers_as_the_node_does() {
    type Build = fn(&mut Links, LinkNo) -> Pair;
    let rows: &[(&str, Build, Answers)] = &[
        (
            "the held link's setup pair, its path Live",
            |l, held| {
                l.path(held, pair(1, 1), Proven::Live);
                pair(1, 1)
            },
            Answers {
                established: true,
                expected: Some(id(2)),
                unanswered: None,
                on: true,
            },
        ),
        (
            "a pair a leg the peer dialled holds, expecting peer 3",
            |l, _| {
                l.open(pair(1, 5), Dir::Inbound, Holder::Leg);
                pair(1, 5)
            },
            Answers {
                established: true,
                expected: Some(id(3)),
                unanswered: Some(LinkNo(1)),
                on: false,
            },
        ),
        (
            "a pair this node's dial to peer 3 holds",
            |l, _| {
                l.open(pair(1, 5), Dir::Outbound, Holder::Leg);
                pair(1, 5)
            },
            Answers {
                established: true,
                expected: Some(id(3)),
                unanswered: None,
                on: false,
            },
        ),
        (
            "the pair the held link's one path roamed to",
            |l, held| {
                l.path(held, pair(1, 1), Proven::Live);
                l.moved(held, &pair(1, 1), pair(1, 5));
                pair(1, 5)
            },
            Answers {
                established: true,
                expected: Some(id(2)),
                unanswered: None,
                on: true,
            },
        ),
        (
            "the setup pair the held link's one path roamed from",
            |l, held| {
                l.path(held, pair(1, 1), Proven::Live);
                l.moved(held, &pair(1, 1), pair(1, 5));
                pair(1, 1)
            },
            Answers {
                established: true,
                expected: Some(id(2)),
                unanswered: None,
                on: true,
            },
        ),
        (
            "the same, the peer capable",
            |l, held| {
                l.path(held, pair(1, 1), Proven::Live);
                l.moved(held, &pair(1, 1), pair(1, 5));
                l.capable(held);
                pair(1, 1)
            },
            Answers {
                established: true,
                expected: Some(id(2)),
                unanswered: None,
                on: false,
            },
        ),
        (
            "a pair the held link holds a probing path at",
            |l, held| {
                l.path(held, pair(1, 5), Proven::Probing);
                pair(1, 5)
            },
            Answers {
                established: false,
                expected: None,
                unanswered: None,
                on: false,
            },
        ),
        (
            "another held peer's acknowledged path",
            |l, _| {
                let other = l.open(pair(1, 6), Dir::Inbound, peer(4));
                l.path(other, pair(1, 5), Proven::Acked);
                pair(1, 5)
            },
            Answers {
                established: true,
                expected: Some(id(4)),
                unanswered: None,
                on: false,
            },
        ),
        (
            "a pair a leg expecting no identity holds, beside another held peer's acknowledged path",
            |l, _| {
                let other = l.open(pair(1, 6), Dir::Inbound, peer(4));
                l.path(other, pair(1, 7), Proven::Acked);
                l.open(pair(1, 7), Dir::Inbound, Holder::Leg);
                pair(1, 7)
            },
            Answers {
                established: true,
                expected: Some(id(4)),
                unanswered: Some(LinkNo(2)),
                on: false,
            },
        ),
        (
            "a pair no link uses",
            |_, _| pair(1, 5),
            Answers {
                established: false,
                expected: None,
                unanswered: None,
                on: false,
            },
        ),
    ];
    for (what, build, want) in rows {
        let mut links = Links::new();
        let held = links.open(pair(1, 1), Dir::Outbound, peer(2));
        let from = build(&mut links, held);
        let legs = |l: LinkNo| {
            let r = links.get(l).filter(|r| r.holder == Holder::Leg)?;
            (r.setup != pair(1, 7)).then_some(id(3))
        };
        let place = links.placement(&from, legs);
        let got = Answers {
            established: place.established(),
            expected: place.expected(),
            unanswered: place.unanswered(),
            on: place.on_link(held),
        };
        assert!(
            got == *want,
            "defect: {what}: answered {got:?}, the node answers {want:?}"
        );
    }
}
