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
fn opening_a_link_at_a_taken_key_overwrites_it_and_closing_it_leaves_the_key_empty() {
    let (one, two) = (LinkId::new(1), LinkId::new(2));
    let mut table = LinkTable::default();
    table.open(link(1, "10.0.0.1:2121"));
    assert_eq!(table.index().get(&key("10.0.0.1:2121")), Some(&one));

    table.open(link(2, "10.0.0.1:2121"));
    assert_eq!(
        table.index().get(&key("10.0.0.1:2121")),
        Some(&two),
        "the second link's open overwrites the key"
    );
    assert!(table.contains_key(&one), "the first link stays open");

    let closed = table.close(&two).expect("the link is open");
    assert_eq!(closed.link_id(), two, "close hands back the link");
    assert!(
        table.index().is_empty(),
        "closing the second link leaves the key empty, not naming the first"
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
fn forgetting_a_link_drops_the_entry_at_its_key_whichever_link_it_names() {
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
    assert!(
        !table.index().contains_key(&key("10.0.0.1:2121")),
        "the entry at the key goes though it named the other link"
    );
    assert_eq!(
        table.index().get(&key("10.0.0.3:2121")),
        Some(&one),
        "an entry at another key is left, even naming the forgotten link"
    );
}

#[test]
fn a_followed_path_moves_only_an_entry_that_names_the_link() {
    let (one, two, three) = (LinkId::new(1), LinkId::new(2), LinkId::new(3));
    let mut table = LinkTable::default();
    table.open(link(1, "10.0.0.1:2121"));
    table.open(link(2, "10.0.0.2:2121"));
    table.open(link(3, "10.0.0.3:2121"));

    table.follow(one, &key("10.0.0.1:2121"), key("10.0.0.4:2121"));
    assert!(
        !table.index().contains_key(&key("10.0.0.1:2121")),
        "the old pair's entry goes"
    );
    assert_eq!(
        table.index().get(&key("10.0.0.4:2121")),
        Some(&one),
        "the new pair names the link"
    );

    table.follow(one, &key("10.0.0.2:2121"), key("10.0.0.5:2121"));
    assert_eq!(
        table.index().get(&key("10.0.0.2:2121")),
        Some(&two),
        "an old pair naming another link is left"
    );
    assert!(
        !table.index().contains_key(&key("10.0.0.5:2121")),
        "and the new pair gets no entry"
    );

    table.follow(one, &key("10.0.0.4:2121"), key("10.0.0.3:2121"));
    assert!(
        !table.index().contains_key(&key("10.0.0.4:2121")),
        "the old pair's entry goes"
    );
    assert_eq!(
        table.index().get(&key("10.0.0.3:2121")),
        Some(&three),
        "a new pair another link holds keeps naming it"
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
fn an_inbound_leg_at_a_taken_key_hands_it_back_to_the_link_it_displaced_when_it_closes() {
    let mut table = LinkTable::default();
    table.open(link(1, "a"));
    table.open_leg(link(2, "a"));
    assert_eq!(
        table.index()[&key("a")],
        LinkId::new(2),
        "the leg takes the key"
    );
    assert_eq!(table.prior(&LinkId::new(2)), Some(LinkId::new(1)));

    table.close(&LinkId::new(2));

    assert_eq!(
        table.index()[&key("a")],
        LinkId::new(1),
        "the key returns to the link the leg displaced"
    );
    assert_eq!(
        table.prior(&LinkId::new(2)),
        None,
        "the record goes with the leg"
    );
}

#[test]
fn an_inbound_leg_at_a_free_key_records_nothing_and_closing_it_leaves_the_key_empty() {
    let mut table = LinkTable::default();
    table.open_leg(link(1, "a"));
    assert_eq!(table.prior(&LinkId::new(1)), None);

    table.close(&LinkId::new(1));

    assert!(table.index().is_empty());
}

#[test]
fn an_inbound_leg_hands_nothing_back_to_a_link_already_gone_or_a_key_already_claimed() {
    let mut table = LinkTable::default();
    table.open(link(1, "a"));
    table.open_leg(link(2, "a"));
    table.close(&LinkId::new(1));
    table.close(&LinkId::new(2));
    assert!(
        table.index().is_empty(),
        "the displaced link is gone, so the key stays empty"
    );

    table.open(link(3, "b"));
    table.open_leg(link(4, "b"));
    table.open(link(5, "b"));
    table.close(&LinkId::new(4));
    assert_eq!(
        table.index()[&key("b")],
        LinkId::new(5),
        "a key another link has claimed stays with it"
    );
}

#[test]
fn a_newer_leg_at_the_same_key_inherits_what_a_closed_leg_displaced() {
    let mut table = LinkTable::default();
    table.open(link(1, "a"));
    table.open_leg(link(2, "a"));
    table.open_leg(link(3, "a"));
    assert_eq!(table.prior(&LinkId::new(3)), Some(LinkId::new(2)));

    table.close(&LinkId::new(2));
    assert_eq!(
        table.prior(&LinkId::new(3)),
        Some(LinkId::new(1)),
        "the newer leg now displaces the older leg's link"
    );

    table.close(&LinkId::new(3));
    assert_eq!(table.index()[&key("a")], LinkId::new(1));
}

#[test]
fn closing_a_leg_with_no_link_still_drops_its_record() {
    let mut table = LinkTable::default();
    table.open(link(1, "a"));
    table.open_leg(link(2, "a"));
    table.raw().remove(&LinkId::new(2));

    assert!(table.close(&LinkId::new(2)).is_none());

    assert_eq!(table.prior(&LinkId::new(2)), None);
}

#[test]
fn awarding_a_key_points_it_at_the_winner_whatever_it_named() {
    let mut table = LinkTable::default();
    table.open(link(1, "a"));
    table.open(link(2, "b"));

    table.award(key("a"), LinkId::new(2));

    assert_eq!(table.index()[&key("a")], LinkId::new(2));
    assert_eq!(table.index()[&key("b")], LinkId::new(2));
}

#[test]
fn a_lifted_waiver_leaves_the_links_others() {
    let mut table = LinkTable::default();
    table.open(link(1, "a"));
    table.waive(LinkId::new(1), Waiver::AnonymousConnect);
    table.waive(LinkId::new(1), Waiver::HeldLinkEntry);

    table.lift(&LinkId::new(1), Waiver::AnonymousConnect);

    assert!(!table.carries(&LinkId::new(1), Waiver::AnonymousConnect));
    assert!(table.carries(&LinkId::new(1), Waiver::HeldLinkEntry));
    assert!(
        table.waived(&LinkId::new(1)),
        "held-entry's own waiver stays"
    );
}

#[test]
fn only_the_held_entry_waiver_lets_a_link_off_held_entry() {
    let mut table = LinkTable::default();
    table.open(link(1, "a"));
    for waiver in [
        Waiver::AnonymousConnect,
        Waiver::CrossedInbound,
        Waiver::MovedOwnDial,
        Waiver::SettledAtMsg3,
    ] {
        table.waive(LinkId::new(1), waiver);
        assert!(!table.waived(&LinkId::new(1)), "{waiver:?} waives no entry");
    }
    table.waive(LinkId::new(1), Waiver::HeldLinkEntry);
    assert!(table.waived(&LinkId::new(1)));
}

#[test]
fn a_leg_noted_again_replaces_its_link_and_taking_or_forgetting_leaves_other_legs() {
    let (first, second) = ((TransportId::new(1), 1), (TransportId::new(1), 2));
    let mut map = LegMap::default();
    map.note(first, LinkId::new(1));
    map.note(first, LinkId::new(2));
    map.note(second, LinkId::new(3));
    assert_eq!(
        map[&first],
        LinkId::new(2),
        "the second note replaces the link"
    );

    assert_eq!(map.take(&first), Some(LinkId::new(2)));
    assert_eq!(map.take(&first), None, "a taken entry is gone");
    assert_eq!(map[&second], LinkId::new(3), "another leg keeps its entry");

    map.forget(&second);
    assert!(map.is_empty());
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
    links.follow(link, &key("10.0.0.2:2121"), key("10.0.0.3:2121"));
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
    node.links.forget(&LinkId::new(1), &key("10.0.0.2:2121"));
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
    node.links.unclaim(one, &key("10.0.0.1:2121"));
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
    node.links.unclaim(one, &key("10.0.0.1:2121"));
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
