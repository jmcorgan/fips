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
