//! Tests for the map wrappers and the link table: each writer does what the
//! sites it transcribes did, and only the `raw` ways past the writers mark a
//! map.

use super::*;
use crate::peer::ActivePeer;
use crate::peer::handshake::Handshake;
use crate::proto::fmp::LegStamp;
use crate::transport::{Link, LinkDirection, LinkId, TransportAddr, TransportId};
use crate::{Identity, NodeAddr, PeerIdentity};
use std::time::Duration;

mod census;
mod defaults;
mod links;
mod plan;
mod remove;
mod rules;
mod scans;

/// The peer's handshake entry for `link`, with no handshake started.
fn entry(link: LinkId) -> Handshake {
    Handshake::new_inbound(link, LegStamp::at(1000))
}

#[test]
fn dropping_a_handshake_entry_leaves_other_links() {
    let (one, two) = (LinkId::new(1), LinkId::new(2));
    let mut map = HandshakeMap::default();
    map.add(one, entry(one));
    map.add(two, entry(two));

    map.drop(one);

    assert!(!map.contains_key(&one), "the entry is dropped");
    assert!(map.contains_key(&two), "another link keeps its entry");
}

#[test]
fn ensuring_a_handshake_entry_keeps_the_one_the_link_has_and_makes_one_otherwise() {
    let link = LinkId::new(1);
    let mut map = HandshakeMap::default();
    map.ensure(link, || entry(link));
    assert!(map.contains_key(&link), "a link with none gets an entry");
    map.ensure(link, || panic!("the link already has an entry"));
    assert_eq!(map.len(), 1);
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

/// Records current behaviour (rule S-58: the newest link named): open to change by decision.
/// Its other assertions are not.
#[test]
fn a_pair_two_links_are_set_up_at_names_the_newest_and_then_the_one_left() {
    let (one, two) = (LinkId::new(1), LinkId::new(2));
    let mut table = LinkTable::default();
    let mut core =
        crate::node::settle::Core::new(crate::NodeAddr::from_bytes([0; 16]), Default::default());
    table.open(&mut core, link(1, "10.0.0.1:2121"));
    assert_eq!(table.index().get(&key("10.0.0.1:2121")), Some(&one));

    table.open(&mut core, link(2, "10.0.0.1:2121"));
    assert_eq!(
        table.index().get(&key("10.0.0.1:2121")),
        Some(&two),
        "the pair names the link opened last"
    );
    assert!(table.contains_key(&one), "the first link stays open");

    let closed = table.close(&mut core, &two).expect("the link is open");
    assert_eq!(closed.link_id(), two, "close hands back the link");
    assert_eq!(
        table.index().get(&key("10.0.0.1:2121")),
        Some(&one),
        "closing the second link leaves the pair naming the first"
    );
    assert!(table.contains_key(&one) && !table.contains_key(&two));
    assert!(
        table.close(&mut core, &two).is_none(),
        "a second close finds nothing"
    );
}

#[test]
fn closing_a_link_drops_every_entry_naming_it_and_leaves_other_links_entries() {
    let (one, two) = (LinkId::new(1), LinkId::new(2));
    let mut table = LinkTable::default();
    let mut core =
        crate::node::settle::Core::new(crate::NodeAddr::from_bytes([0; 16]), Default::default());
    table.open(&mut core, link(1, "10.0.0.1:2121"));
    table.open(&mut core, link(2, "10.0.0.2:2121"));
    table.claim(&mut core, one, key("10.0.0.3:2121"));
    assert_eq!(table.index().len(), 3, "precondition: three entries");

    table.close(&mut core, &one);
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
    let mut core =
        crate::node::settle::Core::new(crate::NodeAddr::from_bytes([0; 16]), Default::default());
    table.open(&mut core, link(1, "10.0.0.1:2121"));
    table.open(&mut core, link(2, "10.0.0.1:2121"));
    table.claim(&mut core, one, key("10.0.0.3:2121"));
    assert_eq!(
        table.index().get(&key("10.0.0.1:2121")),
        Some(&two),
        "precondition: the key names the second link"
    );

    table.forget(&mut core, &one, &key("10.0.0.1:2121"));
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
    let mut core =
        crate::node::settle::Core::new(crate::NodeAddr::from_bytes([0; 16]), Default::default());
    table.open(&mut core, link(1, "10.0.0.1:2121"));
    table.open(&mut core, link(2, "10.0.0.2:2121"));
    table.open(&mut core, link(3, "10.0.0.3:2121"));
    let no = table.no(&one).expect("precondition: the link has a number");
    let at = |addr: &str| {
        let (transport, addr) = key(addr);
        crate::proto::settle::links::Pair { transport, addr }
    };
    table.claim(&mut core, one, key("10.0.0.1:2121"));
    let moved = |from: &str, to: &str| crate::proto::settle::input::Input::Moved {
        link: no,
        from: at(from),
        to: at(to),
        roam: true,
    };

    table.mirror(&mut core, &moved("10.0.0.1:2121", "10.0.0.4:2121"));
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

    table.claim(&mut core, one, key("10.0.0.5:2121"));
    table.mirror(&mut core, &moved("10.0.0.5:2121", "10.0.0.6:2121"));
    assert!(
        !table.index().contains_key(&key("10.0.0.5:2121")),
        "another pair the path left goes"
    );
    assert_eq!(
        table.index().get(&key("10.0.0.6:2121")),
        Some(&one),
        "and the pair it moved to names the link"
    );

    table.mirror(&mut core, &moved("10.0.0.6:2121", "10.0.0.3:2121"));
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
    let mut core =
        crate::node::settle::Core::new(crate::NodeAddr::from_bytes([0; 16]), Default::default());
    table.open(&mut core, link(1, "10.0.0.1:2121"));
    table.open(&mut core, link(2, "10.0.0.2:2121"));

    table.claim(&mut core, one, key("10.0.0.3:2121"));
    assert_eq!(
        table.index().get(&key("10.0.0.3:2121")),
        Some(&one),
        "a free key names the link"
    );
    table.claim(&mut core, one, key("10.0.0.2:2121"));
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
    let mut core =
        crate::node::settle::Core::new(crate::NodeAddr::from_bytes([0; 16]), Default::default());
    table.open(&mut core, link(1, "10.0.0.1:2121"));
    table.open(&mut core, link(2, "10.0.0.2:2121"));
    table.claim(&mut core, one, key("10.0.0.3:2121"));

    table.unclaim(&mut core, one, &key("10.0.0.3:2121"));
    assert!(
        !table.index().contains_key(&key("10.0.0.3:2121")),
        "an entry naming the link goes"
    );
    table.unclaim(&mut core, one, &key("10.0.0.2:2121"));
    assert_eq!(
        table.index().get(&key("10.0.0.2:2121")),
        Some(&two),
        "an entry naming another link stays"
    );
    assert!(table.contains_key(&one), "the link stays open");
}

#[test]
fn only_the_ways_past_the_writers_mark_a_map_planted() {
    let link = LinkId::new(1);
    let mut handshakes = HandshakeMap::default();
    handshakes.add(link, entry(link));
    handshakes.ensure(link, || entry(link));
    handshakes.drop(link);
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
    let mut core =
        crate::node::settle::Core::new(crate::NodeAddr::from_bytes([0; 16]), Default::default());
    links.open(&mut core, self::link(1, "10.0.0.1:2121"));
    links.claim(&mut core, link, key("10.0.0.2:2121"));
    links.follow(&mut core);
    links.unclaim(&mut core, link, &key("10.0.0.3:2121"));
    if let Some(l) = links.get_mut(&link) {
        l.set_connected();
    }
    links.close(&mut core, &link);
    links.open(&mut core, self::link(1, "10.0.0.1:2121"));
    links.forget(&mut core, &link, &key("10.0.0.1:2121"));
    assert!(
        !handshakes.planted() && !peers.planted() && !indices.planted() && !links.planted(),
        "no writer marks its map"
    );

    handshakes.raw();
    peers.raw();
    indices.raw();
    links.raw();
    let mut index = LinkTable::default();
    index.raw_index();
    assert!(handshakes.planted(), "raw marks the handshake entries");
    assert!(peers.planted(), "raw marks the peers");
    assert!(indices.planted(), "raw marks the indices");
    assert!(links.planted(), "raw marks the link table");
    assert!(index.planted(), "raw_index marks the link table");
}

// Each clause of the live audit against a state that breaks it alone,
// written through the writers, so the node is not marked planted.

/// A node with no links, peers, handshakes or dials.
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
fn the_live_audit_fails_a_link_no_peer_handshake_or_dial_names() {
    let mut node = bare();
    node.links.open(&mut node.core, link(1, "10.0.0.1:2121"));
    audit::live(&node, "test");
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "audit_live: test: dial-link")]
fn the_live_audit_fails_a_pending_dial_whose_link_is_not_in_the_link_map() {
    let mut node = bare();
    node.links.open(&mut node.core, link(1, "10.0.0.1:2121"));
    node.plant_dial_at((TransportId::new(1), 5), LinkId::new(1), None);
    node.links.close(&mut node.core, &LinkId::new(1));
    audit::live(&node, "test");
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "audit_live: test: entry-live")]
fn the_live_audit_fails_an_index_entry_naming_no_live_link() {
    let mut node = bare();
    node.links.open(&mut node.core, link(1, "10.0.0.1:2121"));
    node.plant_dial_at((TransportId::new(1), 5), LinkId::new(1), None);
    node.links.plant_entry(key("10.0.0.2:2121"), LinkId::new(2));
    audit::live(&node, "test");
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "audit_live: test: entry-pair")]
fn the_live_audit_fails_an_index_entry_off_its_links_pair_and_every_path() {
    let mut node = bare();
    let one = LinkId::new(1);
    node.links.open(&mut node.core, link(1, "10.0.0.1:2121"));
    node.plant_dial_at((TransportId::new(1), 5), one, None);
    node.links.claim(&mut node.core, one, key("10.0.0.9:2121"));
    audit::live(&node, "test");
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "audit_live: test: held-entry")]
fn the_live_audit_fails_a_held_link_no_index_entry_names() {
    let mut node = bare();
    let one = LinkId::new(1);
    node.links.open(&mut node.core, link(1, "10.0.0.1:2121"));
    node.links
        .unclaim(&mut node.core, one, &key("10.0.0.1:2121"));
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
    node.seed_handshake(crate::node::HandshakeSeed::outbound(one, identity, 1000))
        .expect("precondition: the leg is seeded");
    node.links.open(&mut node.core, link(1, "10.0.0.1:2121"));
    node.links
        .unclaim(&mut node.core, one, &key("10.0.0.1:2121"));
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
fn the_live_audit_fails_a_handshake_entry_with_no_carrier() {
    let mut node = bare();
    let one = LinkId::new(1);
    node.handshakes.add(one, entry(one));
    audit::live(&node, "test");
}

/// A node with nothing in its maps passes every clause, so each test above
/// fails at its own clause alone.
#[cfg(debug_assertions)]
#[test]
fn the_live_audit_passes_a_bare_node() {
    audit::live(&bare(), "test");
}
