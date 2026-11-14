//! Tests for the map wrappers and the link table: each writer does what the
//! sites it transcribes did, and only the `raw` ways past the writers mark a
//! map.

use super::*;
use crate::peer::ActivePeer;
use crate::peer::machine::{PeerMachine, TimerKind};
use crate::proto::fmp::LegStamp;
use crate::transport::{Link, LinkDirection, LinkId, TransportAddr, TransportId};
use crate::{Identity, NodeAddr, PeerIdentity};
use std::time::Duration;

mod census;
mod defaults;
mod links;
mod plan;
mod remove;
mod scans;

/// An inbound machine for `link`, with no handshake started.
fn machine(link: LinkId) -> PeerMachine {
    PeerMachine::new_inbound(link, LegStamp::at(1000))
}

#[test]
fn dropping_a_machine_drops_its_timers_and_leaves_other_links() {
    let (one, two) = (LinkId::new(1), LinkId::new(2));
    let mut map = MachineMap::default();
    map.add(one, machine(one));
    map.add(two, machine(two));
    map.arm(one, TimerKind::HandshakeTimeout, 5000);
    map.arm(two, TimerKind::HandshakeTimeout, 6000);

    map.drop(one);

    assert!(!map.contains_key(&one), "the machine is dropped");
    assert!(
        !map.timers().contains_key(&one),
        "its timers are dropped with it"
    );
    assert!(map.contains_key(&two), "another link keeps its machine");
    assert_eq!(
        map.timers()[&two].get(&TimerKind::HandshakeTimeout),
        Some(&6000),
        "another link keeps its timers"
    );
}

#[test]
fn arming_a_timer_again_replaces_its_deadline_and_cancelling_keeps_the_links_store() {
    let link = LinkId::new(1);
    let mut map = MachineMap::default();
    map.arm(link, TimerKind::HandshakeRetransmit, 1000);
    map.arm(link, TimerKind::HandshakeRetransmit, 2000);
    map.arm(link, TimerKind::HandshakeTimeout, 9000);
    assert_eq!(
        map.timers()[&link].get(&TimerKind::HandshakeRetransmit),
        Some(&2000),
        "the second arm replaces the deadline"
    );

    map.cancel(link, TimerKind::HandshakeRetransmit);
    assert_eq!(
        map.timers()[&link].get(&TimerKind::HandshakeTimeout),
        Some(&9000),
        "cancelling one kind leaves the other armed"
    );
    map.cancel(link, TimerKind::HandshakeTimeout);
    assert!(
        map.timers()[&link].is_empty(),
        "the link keeps an empty store, as the timer sites left it"
    );
    map.cancel(LinkId::new(2), TimerKind::HandshakeTimeout);
    assert!(
        !map.timers().contains_key(&LinkId::new(2)),
        "cancelling on a link with no store makes none"
    );
}

#[test]
fn ensuring_a_machine_keeps_the_one_the_link_has_and_makes_one_otherwise() {
    let link = LinkId::new(1);
    let mut map = MachineMap::default();
    map.ensure(link, || machine(link));
    assert!(map.contains_key(&link), "a link with none gets a machine");
    map.ensure(link, || panic!("the link already has a machine"));
    assert_eq!(map.len(), 1);
}

#[test]
fn noting_a_dial_again_replaces_its_link_and_forgetting_leaves_other_dials() {
    let tid = TransportId::new(1);
    let mut map = DialMap::default();
    map.note((tid, 7), LinkId::new(1));
    map.note((tid, 7), LinkId::new(2));
    map.note((tid, 8), LinkId::new(3));
    assert_eq!(map.get(&(tid, 7)), Some(&LinkId::new(2)));

    map.forget(&(tid, 7));
    assert!(!map.contains_key(&(tid, 7)), "the dial is forgotten");
    assert_eq!(
        map.get(&(tid, 8)),
        Some(&LinkId::new(3)),
        "another dial stays"
    );
}

/// A peer with a fresh identity on `link`, and its address.
fn peer(link: LinkId) -> (NodeAddr, ActivePeer) {
    let identity = PeerIdentity::from_pubkey(Identity::generate().pubkey());
    (*identity.node_addr(), ActivePeer::new(identity, link, 0))
}

#[test]
fn installing_a_peer_at_a_held_address_replaces_it_and_taking_leaves_other_peers() {
    let mut map = PeerMap::default();
    let (addr, first) = peer(LinkId::new(1));
    let (other, second) = peer(LinkId::new(2));
    map.install(addr, first);
    map.install(other, second);
    let (_, replacement) = peer(LinkId::new(3));
    map.install(addr, replacement);
    assert_eq!(map.len(), 2);
    assert_eq!(
        map[&addr].link_id(),
        LinkId::new(3),
        "the second install replaces the peer"
    );

    let taken = map.take(&addr).expect("the peer is held");
    assert_eq!(taken.link_id(), LinkId::new(3), "take hands back the peer");
    assert!(!map.contains_key(&addr), "and the map no longer holds it");
    assert!(map.contains_key(&other), "another peer stays");
    assert!(map.take(&addr).is_none(), "a second take finds nothing");
}

#[test]
fn binding_an_index_again_replaces_its_peer_and_unbinding_leaves_other_indices() {
    let (one, two) = (NodeAddr::from_bytes([1; 16]), NodeAddr::from_bytes([2; 16]));
    let mut map = BindMap::default();
    map.bind(7, one);
    map.bind(7, two);
    map.bind(8, one);
    assert_eq!(map.get(&7), Some(&two), "the second bind replaces the peer");

    map.unbind(&7);
    assert!(!map.contains_key(&7), "the index is unbound");
    assert_eq!(map.get(&8), Some(&one), "another index stays bound");
    map.unbind(&9);
    assert_eq!(map.len(), 1, "unbinding an unbound index changes nothing");
}

/// The index key at `addr` on transport 1.
fn key(addr: &str) -> (TransportId, TransportAddr) {
    (TransportId::new(1), TransportAddr::from_string(addr))
}

/// A link `id` set up at `addr` on transport 1.
fn link(id: u64, addr: &str) -> Link {
    Link::connectionless(
        LinkId::new(id),
        TransportId::new(1),
        TransportAddr::from_string(addr),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    )
}

#[test]
fn a_pair_two_links_are_set_up_at_names_the_newest_and_then_the_one_left() {
    let (one, two) = (LinkId::new(1), LinkId::new(2));
    let mut table = LinkTable::default();
    table.open(link(1, "10.0.0.1:2121"));
    assert_eq!(table.index().get(&key("10.0.0.1:2121")), Some(&one));

    table.open(link(2, "10.0.0.1:2121"));
    assert_eq!(
        table.index().get(&key("10.0.0.1:2121")),
        Some(&two),
        "the pair names the link opened last"
    );
    assert!(table.contains_key(&one), "the first link stays open");

    let closed = table.close(&two).expect("the link is open");
    assert_eq!(closed.link_id(), two, "close hands back the link");
    assert_eq!(
        table.index().get(&key("10.0.0.1:2121")),
        Some(&one),
        "closing the second link leaves the pair naming the first"
    );
    assert!(table.contains_key(&one) && !table.contains_key(&two));
    assert!(table.close(&two).is_none(), "a second close finds nothing");
}

#[test]
fn closing_a_link_drops_every_entry_naming_it_and_leaves_other_links_entries() {
    let (one, two) = (LinkId::new(1), LinkId::new(2));
    let mut table = LinkTable::default();
    table.open(link(1, "10.0.0.1:2121"));
    table.open(link(2, "10.0.0.2:2121"));
    table.claim(one, key("10.0.0.3:2121"));
    assert_eq!(table.index().len(), 3, "precondition: three entries");

    table.close(&one);
    assert!(
        !table.index().contains_key(&key("10.0.0.1:2121")),
        "the link's own key goes"
    );
    assert!(
        !table.index().contains_key(&key("10.0.0.3:2121")),
        "so does an entry at another pair naming it"
    );
    assert_eq!(
        table.index().get(&key("10.0.0.2:2121")),
        Some(&two),
        "another link's entry stays"
    );
}

#[test]
fn forgetting_a_link_retires_it_and_leaves_the_entry_naming_another_link() {
    let (one, two) = (LinkId::new(1), LinkId::new(2));
    let mut table = LinkTable::default();
    table.open(link(1, "10.0.0.1:2121"));
    table.open(link(2, "10.0.0.1:2121"));
    table.claim(one, key("10.0.0.3:2121"));
    assert_eq!(
        table.index().get(&key("10.0.0.1:2121")),
        Some(&two),
        "precondition: the key names the second link"
    );

    table.forget(&one, &key("10.0.0.1:2121"));
    assert!(!table.contains_key(&one), "the link is dropped");
    assert!(table.contains_key(&two), "the other link stays");
    assert_eq!(
        table.index().get(&key("10.0.0.1:2121")),
        Some(&two),
        "the entry at the key still names the other link"
    );
    assert!(
        !table.index().contains_key(&key("10.0.0.3:2121")),
        "the forgotten link is named nowhere"
    );
}

#[test]
fn a_moved_path_moves_the_links_entry_with_its_record_and_its_setup_pair_stays() {
    let (one, three) = (LinkId::new(1), LinkId::new(3));
    let mut table = LinkTable::default();
    table.open(link(1, "10.0.0.1:2121"));
    table.open(link(2, "10.0.0.2:2121"));
    table.open(link(3, "10.0.0.3:2121"));
    let no = table.no(&one).expect("precondition: the link has a number");
    let at = |addr: &str| {
        let (transport, addr) = key(addr);
        crate::proto::settle::links::Pair { transport, addr }
    };
    table.claim(one, key("10.0.0.1:2121"));
    let moved = |from: &str, to: &str| crate::proto::settle::input::Input::Moved {
        link: no,
        from: at(from),
        to: at(to),
    };

    table.mirror(&moved("10.0.0.1:2121", "10.0.0.4:2121"));
    assert_eq!(
        table.index().get(&key("10.0.0.4:2121")),
        Some(&one),
        "the new pair names the link"
    );
    assert_eq!(
        table.index().get(&key("10.0.0.1:2121")),
        Some(&one),
        "the setup pair the path roamed from stays named"
    );

    table.claim(one, key("10.0.0.5:2121"));
    table.mirror(&moved("10.0.0.5:2121", "10.0.0.6:2121"));
    assert!(
        !table.index().contains_key(&key("10.0.0.5:2121")),
        "another pair the path left goes"
    );
    assert_eq!(
        table.index().get(&key("10.0.0.6:2121")),
        Some(&one),
        "and the pair it moved to names the link"
    );

    table.mirror(&moved("10.0.0.6:2121", "10.0.0.3:2121"));
    assert_eq!(
        table.index().get(&key("10.0.0.3:2121")),
        Some(&three),
        "a pair a newer link was set up at keeps naming it"
    );
}

#[test]
fn a_claimed_path_takes_only_a_free_key() {
    let (one, two) = (LinkId::new(1), LinkId::new(2));
    let mut table = LinkTable::default();
    table.open(link(1, "10.0.0.1:2121"));
    table.open(link(2, "10.0.0.2:2121"));

    table.claim(one, key("10.0.0.3:2121"));
    assert_eq!(
        table.index().get(&key("10.0.0.3:2121")),
        Some(&one),
        "a free key names the link"
    );
    table.claim(one, key("10.0.0.2:2121"));
    assert_eq!(
        table.index().get(&key("10.0.0.2:2121")),
        Some(&two),
        "a key another link holds keeps naming it"
    );
}

#[test]
fn an_unclaimed_pair_loses_only_an_entry_naming_the_link() {
    let (one, two) = (LinkId::new(1), LinkId::new(2));
    let mut table = LinkTable::default();
    table.open(link(1, "10.0.0.1:2121"));
    table.open(link(2, "10.0.0.2:2121"));
    table.claim(one, key("10.0.0.3:2121"));

    table.unclaim(one, &key("10.0.0.3:2121"));
    assert!(
        !table.index().contains_key(&key("10.0.0.3:2121")),
        "an entry naming the link goes"
    );
    table.unclaim(one, &key("10.0.0.2:2121"));
    assert_eq!(
        table.index().get(&key("10.0.0.2:2121")),
        Some(&two),
        "an entry naming another link stays"
    );
    assert!(table.contains_key(&one), "the link stays open");
}

#[test]
fn an_inbound_leg_at_a_free_key_names_it_and_closing_it_leaves_the_key_empty() {
    let mut table = LinkTable::default();
    table.open(link(1, "a"));
    assert_eq!(table.index()[&key("a")], LinkId::new(1));

    table.close(&LinkId::new(1));

    assert!(table.index().is_empty());
}

#[test]
fn an_inbound_leg_hands_nothing_back_to_a_link_already_gone_or_a_key_a_newer_link_holds() {
    let mut table = LinkTable::default();
    table.open(link(1, "a"));
    table.open(link(2, "a"));
    table.close(&LinkId::new(1));
    table.close(&LinkId::new(2));
    assert!(
        table.index().is_empty(),
        "the link the leg took the key from is gone, so the key stays empty"
    );

    table.open(link(3, "b"));
    table.open(link(4, "b"));
    table.open(link(5, "b"));
    table.close(&LinkId::new(4));
    assert_eq!(
        table.index()[&key("b")],
        LinkId::new(5),
        "a key a newer link holds stays with it"
    );
}

#[test]
fn a_key_three_links_take_in_turn_goes_back_to_the_newest_left_as_each_closes() {
    let mut table = LinkTable::default();
    table.open(link(1, "a"));
    table.open(link(2, "a"));
    table.open(link(3, "a"));
    assert_eq!(table.index()[&key("a")], LinkId::new(3));

    table.close(&LinkId::new(2));
    assert_eq!(
        table.index()[&key("a")],
        LinkId::new(3),
        "closing an older leg leaves the newest named"
    );

    table.close(&LinkId::new(3));
    assert_eq!(table.index()[&key("a")], LinkId::new(1));
}

#[test]
fn a_released_setup_pair_keeps_naming_its_link_while_the_link_lives() {
    let one = LinkId::new(1);
    let mut table = LinkTable::default();
    table.open(link(1, "a"));
    table.claim(one, key("b"));

    table.unclaim(one, &key("a"));
    table.unclaim(one, &key("b"));

    assert_eq!(
        table.index().get(&key("a")),
        Some(&one),
        "the link record's own pair stays named"
    );
    assert!(
        !table.index().contains_key(&key("b")),
        "a released pair that is not the setup pair goes"
    );
    assert_eq!(
        table.index(),
        &table.derived(),
        "the cache is the index the records give"
    );
}

#[test]
fn a_leg_noted_again_replaces_its_link_and_taking_or_forgetting_leaves_other_legs() {
    let (first, second) = ((TransportId::new(1), 1), (TransportId::new(1), 2));
    let mut map = LegMap::default();
    map.note(first, LinkId::new(1), None);
    map.note(first, LinkId::new(2), None);
    map.note(second, LinkId::new(3), None);
    assert_eq!(
        map[&first],
        LinkId::new(2),
        "the second note replaces the link"
    );

    assert_eq!(map.take(&first).map(|leg| leg.link), Some(LinkId::new(2)));
    assert_eq!(map.take(&first), None, "a taken entry is gone");
    assert_eq!(map[&second], LinkId::new(3), "another leg keeps its entry");

    map.forget(&second);
    assert!(map.is_empty());
}

#[test]
fn only_a_candidate_rekeys_leg_is_taken_from_another_transport_and_only_for_a_peer_that_holds_the_pair()
 {
    let (t1, t2) = (TransportId::new(1), TransportId::new(2));
    let (peer, other) = (NodeAddr::from_bytes([1; 16]), NodeAddr::from_bytes([2; 16]));
    let mut map = LegMap::default();
    map.note((t1, 7), LinkId::new(1), Some(peer));
    map.note((t1, 8), LinkId::new(2), None);

    assert_eq!(
        map.take_moved(8, |_| true),
        None,
        "a leg that is not a candidate rekey stays bound to its transport"
    );
    assert_eq!(
        map.take_moved(7, |p| *p == other),
        None,
        "a candidate rekey's leg is not taken for a pair its peer does not hold"
    );
    assert_eq!(map.take_moved(9, |_| true), None, "no leg holds index 9");
    assert_eq!(
        map.take_moved(7, |p| *p == peer),
        Some((
            (t1, 7),
            Leg {
                link: LinkId::new(1),
                rekey_of: Some(peer)
            }
        )),
        "a candidate rekey's leg is taken with its own key"
    );
    assert!(
        !map.contains_key(&(t1, 7)),
        "and its entry is gone with the record"
    );
    assert_eq!(map.take_moved(7, |_| true), None, "taken once");

    map.note((t2, 9), LinkId::new(3), Some(peer));
    map.note((t2, 9), LinkId::new(3), None);
    assert_eq!(
        map.take_moved(9, |_| true),
        None,
        "a note without a peer drops the record a previous note made"
    );
    map.note((t2, 10), LinkId::new(4), Some(peer));
    map.forget(&(t2, 10));
    map.note((t2, 10), LinkId::new(5), None);
    assert_eq!(
        map.take_moved(10, |_| true),
        None,
        "forgetting a leg drops its record"
    );
}

#[test]
fn dropping_a_machine_hands_it_back_with_any_lease_it_still_holds() {
    let link = LinkId::new(1);
    let mut map = MachineMap::default();
    map.add(link, machine(link));
    assert!(map.drop(link).is_some(), "the machine comes back");
    assert!(map.drop(link).is_none(), "and it is gone");
}

#[test]
fn only_the_ways_past_the_writers_mark_a_map_planted() {
    let link = LinkId::new(1);
    let mut machines = MachineMap::default();
    machines.add(link, machine(link));
    machines.arm(link, TimerKind::HandshakeTimeout, 1);
    machines.cancel(link, TimerKind::HandshakeTimeout);
    machines.ensure(link, || machine(link));
    machines.drop(link);
    let mut dials = DialMap::default();
    dials.note((TransportId::new(1), 1), link);
    dials.forget(&(TransportId::new(1), 1));
    let mut peers = PeerMap::default();
    let (addr, held) = peer(link);
    peers.install(addr, held);
    if let Some(p) = peers.get_mut(&addr) {
        p.touch(1);
    }
    peers.values_mut().for_each(|p| p.touch(2));
    peers.iter_mut().for_each(|(_, p)| p.touch(3));
    peers.take(&addr);
    let mut indices = BindMap::default();
    indices.bind(1, addr);
    indices.unbind(&1);
    let mut links = LinkTable::default();
    links.open(self::link(1, "10.0.0.1:2121"));
    links.claim(link, key("10.0.0.2:2121"));
    links.follow();
    links.unclaim(link, &key("10.0.0.3:2121"));
    if let Some(l) = links.get_mut(&link) {
        l.set_connected();
    }
    links.close(&link);
    links.open(self::link(1, "10.0.0.1:2121"));
    links.forget(&link, &key("10.0.0.1:2121"));
    assert!(
        !machines.planted()
            && !dials.planted()
            && !peers.planted()
            && !indices.planted()
            && !links.planted(),
        "no writer marks its map"
    );

    machines.raw();
    dials.raw();
    peers.raw();
    indices.raw();
    let mut timers = MachineMap::default();
    timers.raw_timers();
    links.raw();
    let mut index = LinkTable::default();
    index.raw_index();
    assert!(machines.planted(), "raw marks the machines");
    assert!(dials.planted(), "raw marks the dials");
    assert!(peers.planted(), "raw marks the peers");
    assert!(indices.planted(), "raw marks the indices");
    assert!(timers.planted(), "raw_timers marks the machines");
    assert!(links.planted(), "raw marks the link table");
    assert!(index.planted(), "raw_index marks the link table");
}

// Each clause of the live audit against a state that breaks it alone,
// written through the writers, so the node is not marked planted.

/// A node with no links, peers, machines or dials.
#[cfg(debug_assertions)]
fn bare() -> crate::node::Node {
    crate::node::tests::make_node()
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "audit_live: test: peer-link")]
fn the_live_audit_fails_a_peer_whose_link_is_not_in_the_link_map() {
    let mut node = bare();
    let (addr, held) = peer(LinkId::new(1));
    node.peers.install(addr, held);
    audit::live(&node, "test");
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "audit_live: test: link-named")]
fn the_live_audit_fails_a_link_no_peer_machine_or_dial_names() {
    let mut node = bare();
    node.links.open(link(1, "10.0.0.1:2121"));
    audit::live(&node, "test");
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "audit_live: test: dial-link")]
fn the_live_audit_fails_a_pending_dial_whose_link_is_not_in_the_link_map() {
    let mut node = bare();
    node.pending_outbound
        .note((TransportId::new(1), 5), LinkId::new(1));
    audit::live(&node, "test");
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "audit_live: test: entry-live")]
fn the_live_audit_fails_an_index_entry_naming_no_live_link() {
    let mut node = bare();
    node.links.open(link(1, "10.0.0.1:2121"));
    node.pending_outbound
        .note((TransportId::new(1), 5), LinkId::new(1));
    node.links.plant_entry(key("10.0.0.2:2121"), LinkId::new(2));
    audit::live(&node, "test");
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "audit_live: test: entry-pair")]
fn the_live_audit_fails_an_index_entry_off_its_links_pair_and_every_path() {
    let mut node = bare();
    let one = LinkId::new(1);
    node.links.open(link(1, "10.0.0.1:2121"));
    node.pending_outbound.note((TransportId::new(1), 5), one);
    node.links.claim(one, key("10.0.0.9:2121"));
    audit::live(&node, "test");
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "audit_live: test: held-entry")]
fn the_live_audit_fails_a_held_link_no_index_entry_names() {
    let mut node = bare();
    let one = LinkId::new(1);
    node.links.open(link(1, "10.0.0.1:2121"));
    // A released setup pair stays named here, so the entry is taken past
    // the writers.
    node.links.take_entry(&key("10.0.0.1:2121"));
    let (addr, held) = peer(one);
    node.peers.install(addr, held);
    audit::live(&node, "test");
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "audit_live: test: leg-entry")]
fn the_live_audit_fails_a_handshake_leg_whose_pair_names_no_live_link() {
    let mut node = bare();
    let one = LinkId::new(1);
    let identity = PeerIdentity::from_pubkey(Identity::generate().pubkey());
    node.seed_handshake_machine(crate::node::HandshakeSeed::outbound(one, identity, 1000))
        .expect("precondition: the leg is seeded");
    node.links.open(link(1, "10.0.0.1:2121"));
    // A released setup pair stays named here, so the entry is taken past
    // the writers.
    node.links.take_entry(&key("10.0.0.1:2121"));
    audit::live(&node, "test");
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "audit_live: test: index: peers_by_index must map exactly")]
fn the_live_audit_fails_a_session_index_no_link_machine_binds() {
    let mut node = bare();
    let (addr, _) = peer(LinkId::new(1));
    node.peers_by_index.bind(7, addr);
    audit::live(&node, "test");
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "audit_live: test: carrier")]
fn the_live_audit_fails_a_handshake_machine_with_no_carrier() {
    let mut node = bare();
    let one = LinkId::new(1);
    node.peer_machines.add(one, machine(one));
    audit::live(&node, "test");
}

/// A node with nothing in its maps passes every clause, so each test above
/// fails at its own clause alone.
#[cfg(debug_assertions)]
#[test]
fn the_live_audit_passes_a_bare_node() {
    audit::live(&bare(), "test");
}
