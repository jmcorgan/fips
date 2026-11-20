//! The settlement core's link records the link table keeps, and the live
//! audit's `links-mirror` clause, on states built through the writers. The
//! clause on real nodes, fed through the core's join, is in
//! `node/tests/settle/live.rs`.

use super::*;
use crate::Identity;
use crate::node::Node;
use crate::node::settle::links::Paths;
use crate::node::settle::recorded;
use crate::node::tests::keyed_peer;
use crate::peer::{Medium, peer_now};
use crate::proto::link::LinkMessageType;
use crate::proto::settle::links::{Dir, Holder, Pair, Proven};

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
    let mut core =
        crate::node::settle::Core::new(crate::NodeAddr::from_bytes([0; 16]), Default::default());
    table.open(&mut core, link(1, "10.0.0.1:2121"));
    table.open(&mut core, link(2, "10.0.0.2:2121"));
    let no = table
        .no(&one)
        .expect("defect: an open link has no core record");
    let rec = core
        .links()
        .get(no)
        .expect("defect: the number names no record");
    assert_eq!(rec.setup, at("10.0.0.1:2121"), "defect: the setup pair");
    assert_eq!(rec.dir, Dir::Outbound, "defect: the direction");
    assert_eq!(rec.holder, Holder::Leg, "defect: a new link is the leg's");
    assert!(rec.paths.is_empty(), "defect: a new link holds no path");

    let (peer, _) = super::peer(one);
    table.hold(&mut core, &one, peer);
    assert_eq!(
        core.links().get(no).map(|r| r.holder),
        Some(Holder::Peer(peer)),
        "defect: a promotion holds the record for its peer"
    );

    table.close(&mut core, &one);
    assert!(
        table.no(&one).is_none(),
        "defect: a closed link keeps a number"
    );
    assert!(
        core.links().get(no).is_none(),
        "defect: a closed link's record stays"
    );
    let other = table
        .no(&two)
        .expect("defect: another link loses its number");
    assert!(
        core.links().get(other).is_some(),
        "defect: closing one link retires another's record"
    );

    table.forget(&mut core, &two, &key("10.0.0.2:2121"));
    assert!(
        table.no(&two).is_none() && core.links().get(other).is_none(),
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
    node.links.open(&mut node.core, link(1, "127.0.0.1:1"));
    node.links.open(&mut node.core, link(2, "127.0.0.1:2"));
    let peer = keyed_peer(&node, &remote, one, 0);
    let addr = *peer.node_addr();
    node.peers.install(addr, peer);
    node.links.hold(&mut node.core, &one, addr);
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
    let mut core =
        crate::node::settle::Core::new(crate::NodeAddr::from_bytes([0; 16]), Default::default());
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
    node.links.open(&mut node.core, link(1, "10.0.0.1:2121"));
    node.links.open(&mut node.core, link(2, "10.0.0.2:2121"));
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
    node.links
        .plant_path(&mut node.core, &two, &key("10.0.0.2:2121"), Proven::Live);

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

    // The flagged peer's link loses its index entry: `held-entry` still
    // reads that peer, ahead of `links-mirror`.
    #[cfg(debug_assertions)]
    {
        node.links
            .unclaim(&mut node.core, one, &key("10.0.0.1:2121"));
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

/// A test mutator of a peer's bundle, given transport 1, the pair the peer
/// is at, another pair, and the heartbeat's message type.
type Mutator = fn(&mut ActivePeer, TransportId, &TransportAddr, &TransportAddr, u8);

/// Each way a test changes a peer's bundle past the feed, by name.
fn mutators() -> &'static [(&'static str, Mutator)] {
    &[
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
        ("kill_path", |p, t, h, _, _| p.kill_path(t, h)),
    ]
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
    let mut unflagged = Vec::new();
    for (name, mutate) in mutators() {
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

/// The paths the core's record of `peer`'s link holds, and the paths its
/// bundle holds as the feed tells them, each in one order.
fn record_and_bundle(node: &Node, peer: &NodeAddr) -> (Paths, Paths) {
    let p = node
        .peers
        .get(peer)
        .expect("precondition: the node holds the peer");
    let order = |mut paths: Paths| {
        paths.sort_by(|(a, _), (b, _)| a.cmp(b));
        paths
    };
    let rec = node
        .links
        .no(&p.link_id())
        .and_then(|no| node.core.links().get(no))
        .map(|r| r.paths.clone())
        .unwrap_or_default();
    (order(rec), order(recorded(p)))
}

/// A node holding a keyed peer at 127.0.0.1:1 on link 1, opened and held
/// through the writers, its record told nothing of the peer's bundle.
fn held_node(remote: &Identity) -> (Node, NodeAddr) {
    let mut node = crate::node::tests::make_node();
    let peer = keyed_peer(&node, remote, LinkId::new(1), 0);
    let addr = *peer.identity().node_addr();
    node.links.open(&mut node.core, link(1, "127.0.0.1:1"));
    node.links.hold(&mut node.core, &LinkId::new(1), addr);
    node.peers.install(addr, peer);
    (node, addr)
}

/// Each test mutator, run on a free-standing peer the test then puts in the
/// peer map itself and on a peer the node holds, leaves the core's record of
/// the peer's link equal to its bundle once the node next asks the close
/// rule: the node resyncs the record from the bundle and the peer is no
/// longer flagged.
#[tokio::test]
async fn a_bundle_a_test_mutator_changed_is_in_its_links_record_at_the_next_close() {
    let remote = Identity::generate();
    let t1 = TransportId::new(1);
    let held = TransportAddr::from_string("127.0.0.1:1");
    let other = TransportAddr::from_string("127.0.0.1:2");
    let heartbeat = LinkMessageType::Heartbeat.to_byte();
    let mut stale = Vec::new();
    for (name, mutate) in mutators() {
        for planted in [false, true] {
            let (mut node, addr) = held_node(&remote);
            if planted {
                let mut p = node
                    .peers
                    .take(&addr)
                    .expect("precondition: the peer is held");
                mutate(&mut p, t1, &held, &other, heartbeat);
                node.peers.raw().insert(addr, p);
            } else {
                let p = node
                    .get_peer_mut(&addr)
                    .expect("precondition: the peer is held");
                mutate(p, t1, &held, &other, heartbeat);
            }
            let (before, _) = record_and_bundle(&node, &addr);
            assert!(
                before.is_empty(),
                "precondition: the record is told nothing of the bundle"
            );
            node.close_unused(LinkId::new(99)).await;
            let (rec, bundle) = record_and_bundle(&node, &addr);
            let flagged = node.peers.get(&addr).is_some_and(|p| p.past_feed());
            if rec != bundle || bundle.is_empty() || flagged {
                stale.push(format!(
                    "{name} (planted {planted}): record {rec:?}, bundle {bundle:?}, flagged {flagged}"
                ));
            }
        }
    }
    assert!(
        stale.is_empty(),
        "defect: a mutated bundle is not in its link's record at the next close: {stale:#?}"
    );
}

/// A node holding a peer that acked a path at 127.0.0.1:2 on transport 1
/// past the feed, so the record lacks it until the node resyncs; planted,
/// since the keyed peer's index binding is not run, which the live audit
/// after a handshake message would fail on.
fn acked_node(remote: &Identity) -> (Node, NodeAddr) {
    let (mut node, addr) = held_node(remote);
    node.plant();
    let other = TransportAddr::from_string("127.0.0.1:2");
    let p = node
        .get_peer_mut(&addr)
        .expect("precondition: the peer is held");
    p.admit_path(TransportId::new(1), other.clone());
    p.ack_path(TransportId::new(1), &other);
    (node, addr)
}

/// The record of `peer`'s link equals its bundle, which holds the path
/// [`acked_node`] acked, once the node has done `what`.
fn assert_synced(node: &Node, peer: &NodeAddr, what: &str) {
    let (rec, bundle) = record_and_bundle(node, peer);
    assert!(
        bundle.contains(&(at("127.0.0.1:2"), Proven::Acked)),
        "precondition: the bundle holds the acked path"
    );
    assert_eq!(
        rec, bundle,
        "defect: the acked path is not in the link's record after {what}"
    );
}

/// A one-byte handshake message from 127.0.0.1:3 on transport 1, which
/// fails its header's parse.
fn malformed() -> crate::transport::ReceivedPacket {
    crate::transport::ReceivedPacket::new(
        TransportId::new(1),
        TransportAddr::from_string("127.0.0.1:3"),
        vec![0x01],
    )
}

/// A msg1 refused at its parse runs no close, yet a path a test acked past
/// the feed before it is in the record after it: the node resyncs at the
/// head of the msg1 handler, before anything reads the records.
#[tokio::test]
async fn a_path_acked_past_the_feed_is_in_its_links_record_after_a_refused_msg1() {
    let remote = Identity::generate();
    let (mut node, addr) = acked_node(&remote);
    let refused = node.stats().handshake.bad_state;
    node.handle_msg1(malformed()).await;
    assert_eq!(
        node.stats().handshake.bad_state,
        refused + 1,
        "precondition: the msg1 is refused at its parse"
    );
    assert_synced(&node, &addr, "the msg1");
}

/// The same for a msg2 refused at its parse: the node resyncs at the head
/// of the msg2 handler too.
#[tokio::test]
async fn a_path_acked_past_the_feed_is_in_its_links_record_after_a_refused_msg2() {
    let remote = Identity::generate();
    let (mut node, addr) = acked_node(&remote);
    let refused = node.stats().handshake.bad_state;
    node.handle_msg2(malformed()).await;
    assert_eq!(
        node.stats().handshake.bad_state,
        refused + 1,
        "precondition: the msg2 is refused at its parse"
    );
    assert_synced(&node, &addr, "the msg2");
}

/// A drain with no close queued, as a new node has none, reads nothing, yet a path a test acked past
/// the feed before it is in the record after it: the node resyncs at the
/// head of the drain, before it asks the close rule of a queued close.
#[tokio::test]
async fn a_path_acked_past_the_feed_is_in_its_links_record_after_a_drain() {
    let remote = Identity::generate();
    let (mut node, addr) = acked_node(&remote);
    node.drain_closes().await;
    assert_synced(&node, &addr, "the drain");
}

/// A link a test put in the link map itself has a record once the node
/// resyncs, held as a leg at its setup pair, so the close rule counts its
/// pair; an index entry a test wrote at a pair no record names is named
/// there by its link's records, not held as a path its bundle does not
/// hold, and opens a record as a leg there if the link has none.
#[tokio::test]
async fn a_planted_link_and_a_planted_index_entry_are_in_the_records_after_a_resync() {
    let mut node = crate::node::tests::make_node();
    let (planted, other, missing) = (LinkId::new(1), LinkId::new(2), LinkId::new(3));
    node.links.raw().insert(planted, link(1, "10.0.0.1:2121"));
    node.links.open(&mut node.core, link(2, "10.0.0.2:2121"));
    node.links.raw_index().insert(key("10.0.0.3:2121"), other);
    node.links.raw_index().insert(key("10.0.0.4:2121"), missing);
    node.close_unused(LinkId::new(99)).await;

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
    assert!(
        node.in_use(TransportId::new(1), &at("10.0.0.1:2121").addr, other),
        "defect: the planted link does not use its setup pair"
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
        .map(|r| (r.setup.clone(), r.holder));
    assert_eq!(
        opened,
        Some((at("10.0.0.4:2121"), Holder::Leg)),
        "defect: the entry naming a link with no record opened none"
    );
}

/// A peer a test planted on a link the link map lacks has a record once the
/// node resyncs, set up at the pair the peer is at and held by it, so the
/// records place a msg1 from that pair on its link as the node does; and an
/// index entry naming a link the map lacks opens a record that is no
/// inbound leg, as the node answers no duplicate msg1 on a link it does not
/// hold, until the test puts the link in the map, when the record is opened
/// again from the link.
#[tokio::test]
async fn a_planted_peers_link_and_an_entrys_link_put_in_the_map_after_are_in_the_records() {
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

    let place = node.placement(&(t1, at1));
    assert_eq!(
        (
            place.established(),
            place.expected(),
            node.links.no(&LinkId::new(1)).map(|no| place.on_link(no)),
        ),
        (true, Some(addr), Some(true)),
        "defect: the planted peer's link has no record at its pair: {place:?}"
    );
    assert_eq!(
        node.placement(&key("10.0.0.2:2121")).unanswered(),
        None,
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
        node.placement(&key("10.0.0.2:2121"))
            .unanswered()
            .and_then(|no| node.links.id(no)),
        Some(orphan),
        "defect: the entry's link, now an inbound link in the map, is no leg"
    );
}
