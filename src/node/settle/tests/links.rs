//! The settlement core's link records the link table keeps, and the live
//! audit's `links-mirror` clause, on states built through the writers, and
//! the node's resync of the records from a state a test planted past them. The
//! clause on real nodes, fed through the core's join, is in
//! `node/tests/settle/live.rs`.

use super::*;
use crate::Identity;
use crate::node::tests::keyed_peer;
use crate::peer::{Medium, peer_now};
use crate::proto::link::LinkMessageType;
use crate::proto::settle::links::{Dir, Holder, Links, Pair, Proven};

/// The core's pair for the index key at `addr` on transport 1.
fn at(addr: &str) -> Pair {
    let (transport, addr) = key(addr);
    Pair { transport, addr }
}

/// The table opens a core record with each link, set up at the link's pair
/// and held by its handshake leg; a promotion holds it for its peer; closing
/// the link or forgetting a dial retires the record, and leaves every other
/// link's.
#[test]
fn the_core_records_a_link_from_its_open_to_its_close_or_its_forget() {
    let (one, two) = (LinkId::new(1), LinkId::new(2));
    let mut table = LinkTable::default();
    let mut core = Links::new();
    table.open(&mut core, link(1, "10.0.0.1:2121"));
    table.open(&mut core, link(2, "10.0.0.2:2121"));
    let no = table
        .no(&one)
        .expect("defect: an open link has no core record");
    let rec = core.get(no).expect("defect: the number names no record");
    assert_eq!(rec.setup, at("10.0.0.1:2121"), "defect: the setup pair");
    assert_eq!(rec.dir, Dir::Outbound, "defect: the direction");
    assert_eq!(rec.holder, Holder::Leg, "defect: a new link is the leg's");
    assert!(rec.paths.is_empty(), "defect: a new link holds no path");

    let (peer, _) = super::peer(one);
    table.hold(&mut core, &one, peer);
    assert_eq!(
        core.get(no).map(|r| r.holder),
        Some(Holder::Peer(peer)),
        "defect: a promotion holds the record for its peer"
    );

    table.close(&mut core, &one);
    assert!(
        table.no(&one).is_none(),
        "defect: a closed link keeps a number"
    );
    assert!(
        core.get(no).is_none(),
        "defect: a closed link's record stays"
    );
    let other = table
        .no(&two)
        .expect("defect: another link loses its number");
    assert!(
        core.get(other).is_some(),
        "defect: closing one link retires another's record"
    );

    table.forget(&mut core, &two, &key("10.0.0.2:2121"));
    assert!(
        table.no(&two).is_none() && core.get(other).is_none(),
        "defect: a forgotten dial's record stays"
    );
}

/// A held peer's bundle turns capable: the join gives the core the input
/// it stands for, the node feeds it, and the core's record of the peer's
/// link holds it capable, as the bundle does from then on. Every other
/// record stays not capable.
#[test]
fn a_link_turning_capable_marks_the_nodes_record_capable() {
    use crate::node::settle::exec::pathed;
    use crate::proto::settle::join::Step;
    use fips_core::proto::path::Output;

    let mut node = crate::node::tests::make_node();
    let remote = Identity::generate();
    let (one, two) = (LinkId::new(1), LinkId::new(2));
    node.links
        .open(node.core.parts_mut().0, link(1, "127.0.0.1:1"));
    node.links
        .open(node.core.parts_mut().0, link(2, "127.0.0.1:2"));
    let peer = keyed_peer(&node, &remote, one, 0);
    let addr = *peer.node_addr();
    node.peers.install(addr, peer);
    node.links.hold(node.core.parts_mut().0, &one, addr);
    let no = node
        .links
        .no(&one)
        .expect("precondition: the link has a number");
    let capable = |node: &crate::node::Node, id: &LinkId| {
        node.links
            .no(id)
            .and_then(|no| node.core.links().get(no))
            .is_some_and(|r| r.capable)
    };
    assert!(
        !capable(&node, &one),
        "precondition: a new link's record is not capable"
    );

    let bundle = node.peers.get(&addr).and_then(|p| p.bundle());
    let steps = pathed(addr, vec![Output::Capable], bundle, Some(no), None)
        .expect("precondition: the join takes the bundle's step");
    let inputs: Vec<_> = steps
        .filter_map(|step| match step {
            Step::Core(input) => Some(input),
            Step::Path(_) | Step::Rekey(_) | Step::Replace(_) | Step::Redial { .. } => None,
        })
        .collect();
    for input in &inputs {
        node.feed(input);
    }
    assert!(
        capable(&node, &one),
        "defect: the peer's link turned capable and its record does not hold it so: {inputs:?}"
    );
    assert!(
        !capable(&node, &two),
        "defect: another link's record turned capable"
    );
}

/// A dial to the pair of a link a peer is held on is abandoned: the pair
/// names the dial's link, the newest there, while the dial lives, and the
/// held link again once it is forgotten. The written index dropped the entry
/// at the dial's pair whichever link it named, leaving the held link with
/// none.
#[test]
fn forgetting_a_dial_leaves_the_held_links_entry() {
    let (held, dial) = (LinkId::new(1), LinkId::new(2));
    let mut table = LinkTable::default();
    let mut core = Links::new();
    table.open(&mut core, link(1, "10.0.0.1:2121"));
    let (peer, _) = super::peer(held);
    table.hold(&mut core, &held, peer);
    table.open(&mut core, link(2, "10.0.0.1:2121"));
    assert_eq!(
        table.index().get(&key("10.0.0.1:2121")),
        Some(&dial),
        "precondition: the pair names the dial's link while it lives"
    );
    table.forget(&mut core, &dial, &key("10.0.0.1:2121"));
    assert_eq!(
        table.index().get(&key("10.0.0.1:2121")),
        Some(&held),
        "defect: forgetting the dial took the held link's entry"
    );
}

/// A node holding two peers on links opened through the writers, neither
/// with a bundle: the first bound past the feed by a test mutator, so its
/// record holds none of the path its bundle now holds, and the second's
/// record holding a path though the peer holds none. `links-mirror` names
/// the second and skips only the first; every other clause still reads the
/// first, and fails on a breach of its own.
#[test]
fn a_flagged_peer_is_the_only_one_links_mirror_skips() {
    let mut node = crate::node::tests::make_node();
    let (one, two) = (LinkId::new(1), LinkId::new(2));
    node.links
        .open(node.core.parts_mut().0, link(1, "10.0.0.1:2121"));
    node.links
        .open(node.core.parts_mut().0, link(2, "10.0.0.2:2121"));
    let (flagged, mut first) = peer(one);
    let (wrong, second) = peer(two);
    first.rebind_transport(
        TransportId::new(1),
        at("10.0.0.1:2121").addr,
        Medium::Unknown,
    );
    assert!(
        first.past_feed(),
        "precondition: the mutator flags the peer"
    );
    node.peers.install(flagged, first);
    node.peers.install(wrong, second);
    node.links.plant_path(
        node.core.parts_mut().0,
        &two,
        &key("10.0.0.2:2121"),
        Proven::Live,
    );

    let found = audit::links_mirror(&node);
    assert_eq!(
        found.unmirrored,
        vec![flagged],
        "defect: links-mirror skipped other than the flagged peer"
    );
    assert_eq!(found.bad.len(), 1, "defect: {:?}", found.bad);
    assert!(
        found.bad[0].starts_with(&wrong.to_string()),
        "defect: links-mirror did not name the unflagged peer: {:?}",
        found.bad
    );

    // The flagged peer's link loses its index entry, taken past the writers
    // since a released setup pair stays named here: `held-entry` still reads
    // that peer, ahead of `links-mirror`.
    #[cfg(debug_assertions)]
    {
        node.links.take_entry(&key("10.0.0.1:2121"));
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            audit::live(&node, "test");
        }));
        let message = caught
            .expect_err("defect: the live audit passed a flagged peer's breach")
            .downcast::<String>()
            .map(|m| *m)
            .unwrap_or_default();
        assert!(
            message.contains("audit_live: test: held-entry"),
            "defect: the flagged peer's other clauses were not read: {message}"
        );
    }
}

/// Each way a test changes a peer's bundle past the feed flags the peer,
/// one row per mutator, on a keyed peer built outside link setup, which no
/// mutator has touched; an authentic frame from the pair the peer is at,
/// which roams nothing, does not.
#[test]
fn each_test_mutator_of_a_bundle_flags_its_peer() {
    let node = crate::node::tests::make_node();
    let remote = Identity::generate();
    let t1 = TransportId::new(1);
    let held = TransportAddr::from_string("127.0.0.1:1");
    let other = TransportAddr::from_string("127.0.0.1:2");
    let heartbeat = LinkMessageType::Heartbeat.to_byte();
    type Mutator = fn(&mut ActivePeer, TransportId, &TransportAddr, &TransportAddr, u8);
    let rows: &[(&str, Mutator)] = &[
        ("set_current_addr", |p, t, _, o, _| {
            p.set_current_addr(t, o.clone());
        }),
        ("account", |p, t, _, o, hb| {
            p.account(peer_now(), t, o, 0, hb);
        }),
        ("rebind_transport", |p, t, _, o, _| {
            p.rebind_transport(t, o.clone(), Medium::Unknown);
        }),
        ("repin", |p, _, _, o, _| {
            p.repin(TransportId::new(2), o.clone())
        }),
        ("admit_path", |p, t, _, o, _| p.admit_path(t, o.clone())),
        ("ack_path", |p, t, h, _, _| p.ack_path(t, h)),
        ("idle_active", |p, _, _, _, _| p.idle_active()),
        ("kill_path", |p, t, h, _, _| p.kill_path(t, h)),
    ];
    let mut unflagged = Vec::new();
    for (name, mutate) in rows {
        let mut p = keyed_peer(&node, &remote, LinkId::new(1), 0);
        assert!(!p.past_feed(), "precondition: a keyed peer is not flagged");
        mutate(&mut p, t1, &held, &other, heartbeat);
        if !p.past_feed() {
            unflagged.push(*name);
        }
    }
    assert!(
        unflagged.is_empty(),
        "defect: these mutators left their peer unflagged: {unflagged:?}"
    );

    let mut p = keyed_peer(&node, &remote, LinkId::new(1), 0);
    p.account(peer_now(), t1, &held, 0, heartbeat);
    assert!(
        !p.past_feed(),
        "defect: a frame that roamed nothing flagged its peer"
    );
}

/// A link a test put in the link map itself has a record once the node
/// resyncs, held as a leg at its setup pair; an index entry a test wrote at
/// a pair no record names is named there by its link's records, not held as
/// a path its bundle does not hold, and opens a record there if the link has
/// none, which is no inbound leg, as the node answers no duplicate msg1 on a
/// link its map lacks.
#[test]
fn a_planted_link_and_a_planted_index_entry_are_in_the_records_after_a_resync() {
    let mut node = crate::node::tests::make_node();
    let (planted, other, missing) = (LinkId::new(1), LinkId::new(2), LinkId::new(3));
    node.links.raw().insert(planted, link(1, "10.0.0.1:2121"));
    node.links
        .open(node.core.parts_mut().0, link(2, "10.0.0.2:2121"));
    node.links.raw_index().insert(key("10.0.0.3:2121"), other);
    node.links.raw_index().insert(key("10.0.0.4:2121"), missing);
    node.resync();

    let rec = node
        .links
        .no(&planted)
        .and_then(|no| node.core.links().get(no))
        .expect("defect: the planted link has no record");
    assert_eq!(
        (rec.setup.clone(), rec.holder),
        (at("10.0.0.1:2121"), Holder::Leg),
        "defect: the planted link's record is not a leg at its setup pair"
    );
    let no = node.links.no(&other);
    let paths = no
        .and_then(|no| node.core.links().get(no))
        .map(|r| r.paths.clone())
        .unwrap_or_default();
    let named: Vec<_> = node.core.links().at(&at("10.0.0.3:2121")).collect();
    assert_eq!(
        (named, paths.is_empty()),
        (no.into_iter().collect(), true),
        "defect: the entry is not named by its link's records alone: {paths:?}"
    );
    let opened = node
        .links
        .no(&missing)
        .and_then(|no| node.core.links().get(no))
        .map(|r| (r.setup.clone(), r.dir, r.holder));
    assert_eq!(
        opened,
        Some((at("10.0.0.4:2121"), Dir::Outbound, Holder::Leg)),
        "defect: the entry naming a link with no record opened none, or an inbound one"
    );
}

/// A peer a test planted on a link the link map lacks has a record once the
/// node resyncs, set up at the pair the peer is at and held by it, so the
/// records place the peer at that pair as the node does; and an index entry
/// naming a link the map lacks opens a record that is no inbound leg, until
/// the test puts the link in the map, when the record is opened again from
/// the link.
#[test]
fn a_planted_peers_link_and_an_entrys_link_put_in_the_map_after_are_in_the_records() {
    let mut node = crate::node::tests::make_node();
    let remote = Identity::generate();
    let mut peer = keyed_peer(&node, &remote, LinkId::new(1), 0);
    let addr = *peer.identity().node_addr();
    let (t1, at1) = key("10.0.0.1:2121");
    peer.set_current_addr(t1, at1.clone());
    node.peers.raw().insert(addr, peer);
    let orphan = LinkId::new(2);
    node.links.raw_index().insert(key("10.0.0.2:2121"), orphan);
    node.resync();

    assert_eq!(
        node.links.held_at(node.core.links(), &(t1, at1)),
        Some(addr),
        "defect: the planted peer's link has no record held by it at its pair"
    );
    assert_eq!(
        node.links.placed(node.core.links(), &key("10.0.0.2:2121")),
        Some((orphan, Dir::Outbound, Holder::Leg)),
        "defect: an entry naming a link the map lacks is an inbound leg's"
    );

    let (t2, at2) = key("10.0.0.2:2121");
    let mapped = Link::connectionless(
        orphan,
        t2,
        at2,
        LinkDirection::Inbound,
        Duration::from_millis(100),
    );
    node.links.raw().insert(orphan, mapped);
    node.resync();
    assert_eq!(
        node.links.placed(node.core.links(), &key("10.0.0.2:2121")),
        Some((orphan, Dir::Inbound, Holder::Leg)),
        "defect: the entry's link, now an inbound link in the map, is no leg"
    );
}
