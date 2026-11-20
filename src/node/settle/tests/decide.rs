//! The shadow core beside the node: what it is fed, and the leases it
//! holds.

use std::time::Duration;

use super::*;
use crate::proto::settle::input::{Dial, Input, Read};
use crate::proto::settle::links::Pair;
use crate::transport::{TransportAddr, TransportId};

/// The pair at `port` on transport 1.
fn at(port: u16) -> Pair {
    Pair {
        transport: TransportId::new(1),
        addr: TransportAddr::from_string(&format!("10.0.0.1:{port}")),
    }
}

/// A node address for `byte`.
fn addr(byte: u8) -> NodeAddr {
    crate::node::tests::make_node_addr(byte)
}

/// The shadow dials `peer` at `to` on the node's link `id`, under a lease
/// on `index`.
fn dial(node: &mut Node, id: LinkId, peer: NodeAddr, to: Pair, index: u32) {
    let lease = node.shadow.lease(index);
    let dial = Dial {
        peer,
        to,
        msg1: vec![1, index as u8],
        lease,
        resends: None,
        link: None,
    };
    node.decide_at(Some(id), Input::Dial(dial));
}

/// The shadow takes a dial it reaps at its deadline, a msg1 it answers and
/// installs, and a second dial still in flight, so it has handed one lease
/// back and holds one for the installed peer and one in a leg. Dropping the node releases the
/// two it still holds.
#[test]
fn the_shadow_frees_every_lease_it_takes_when_its_node_drops() {
    let mut node = crate::node::tests::make_node();
    let wait = Duration::from_secs(node.config().node.rate_limit.handshake_timeout_secs);
    let leases = node.shadow.leases();
    dial(&mut node, LinkId::new(1), addr(1), at(1), 1);
    // The first dial is reaped at its deadline; the second, made two
    // seconds later, is still in flight then.
    crate::time::advance(Duration::from_secs(1));
    let read = Read {
        peer: addr(2),
        from: at(2),
        bytes: vec![9],
        ephemeral: crate::proto::fmp::EphemeralDigest::of_noise_msg1(&[9; 33])
            .expect("a public key's length carries an ephemeral"),
        epoch: [2; 8],
    };
    node.decide_at(
        Some(LinkId::new(2)),
        Input::Msg1 {
            read,
            reachable: true,
        },
    );
    node.shadow_hello(LinkId::new(2), 2, b"msg2", Node::interval_ms());
    node.shadow_sent(LinkId::new(2), true);
    let installed = node.shadow.table().and_then(|t| t.held(&addr(2))).is_some();
    crate::time::advance(Duration::from_secs(1));
    dial(&mut node, LinkId::new(3), addr(3), at(3), 3);
    crate::time::advance(wait - Duration::from_secs(1));
    node.shadow_tick();
    let reaped =
        node.shadow.no(LinkId::new(1)).is_none() && node.shadow.no(LinkId::new(3)).is_some();
    let (minted, freed) = (leases.minted(), leases.freed());
    drop(node);
    assert!(installed, "precondition: the answered msg1's peer is held");
    assert!(
        reaped,
        "precondition: the first dial was reaped at its deadline, the second not"
    );
    assert_eq!(
        (minted, freed),
        (3, 1),
        "precondition: three leases minted, the reaped dial's handed back"
    );
    assert_eq!(
        (leases.minted(), leases.freed()),
        (3, 3),
        "defect: a dropped node's shadow kept leases"
    );
}

/// A peer planted as a restart test plants it (the plant of
/// `install_peering_at_a_different_epoch` in the node's handshake tests): a
/// keyed peer promoted and last heard a minute ago, at a pair and an epoch
/// the test sets, put in the peer map and the index past the writers. The
/// node's resync writes it into the shadow, which holds it on the link the
/// index names, with the plant's epoch, pair and instants.
#[test]
fn a_planted_peer_is_held_by_the_shadow_with_the_plants_epoch_and_instants() {
    let mut node = crate::node::tests::make_node();
    let remote = crate::Identity::generate();
    let link = node.allocate_link_id();
    let (tid, from) = (
        TransportId::new(1),
        TransportAddr::from_string("127.0.0.1:41001"),
    );
    let idle = Duration::from_secs(60);
    let authenticated = Node::now_ms().saturating_sub(60_000);
    let mut peer = crate::node::tests::keyed_peer(&node, &remote, link, authenticated);
    peer.test_backdate_promoted(idle);
    peer.test_backdate_heard(idle);
    peer.set_current_addr(tid, from.clone());
    peer.set_remote_epoch(Some([0xAA; 8]));
    let (addr, promoted, heard) = (*peer.node_addr(), peer.promoted_at(), peer.heard_at());
    node.peers.raw().insert(addr, peer);
    node.links.raw_index().insert((tid, from.clone()), link);
    node.resync();
    let no = node.shadow.no(link);
    let held = node.shadow.table().and_then(|t| t.held(&addr)).cloned();
    let held = held.expect("defect: the shadow does not hold the planted peer");
    assert_eq!(
        Some(held.link),
        no,
        "the shadow holds the peer on the planted link's record"
    );
    assert_eq!(held.epoch, [0xAA; 8], "the plant's epoch");
    assert_eq!(
        held.current,
        Pair {
            transport: tid,
            addr: from
        },
        "the plant's pair"
    );
    assert_eq!(held.installed, promoted, "the plant's promotion instant");
    // Backdated together and with no frame, the peer was last heard at its
    // promotion, which is where the core reads a heard peer's floor from
    // when no frame is recorded.
    assert_eq!(
        held.last.unwrap_or(held.installed),
        heard,
        "the plant's last-heard instant"
    );
}

/// Each decision site of the node, by its file, with the shadow call it
/// makes (the input it builds, or the helper that builds it) and how many
/// sites in that file make it. Section 1.1's families: the dial and its
/// connection (lifecycle, the executor's connect), the msg1 before and
/// after its read, its replacement, its answer and its refusal
/// (handshake), the msg2 send (the executor), the legs' timers and resends
/// (timeout), the completed dial (handshake), the restart at a rekey
/// (rekey), the frame (encrypted), the removals (`Node::remove`), and the
/// path inputs (the feed of the node's link records, which carries the
/// roam). A call several sites share is counted, so that one of them
/// losing its call is seen although the others still make it.
const SITES: &[(&str, &str, usize)] = &[
    ("lifecycle/mod.rs", "Input::Connecting {", 1),
    ("lifecycle/mod.rs", "input::Input::Dial(dial)", 1),
    // A dial that could take no index, a handshake that could not start,
    // a connect that failed, and a dial a traversal's adoption gave up.
    ("lifecycle/mod.rs", "self.shadow_abandon(", 4),
    // A connect that could not start, and a msg2 that could not be sent.
    ("dataplane/peer_actions.rs", "self.shadow_abandon(", 1),
    ("dataplane/peer_actions.rs", "self.shadow_unsendable(", 1),
    (
        "dataplane/peer_actions.rs",
        "self.shadow_sent(link, true)",
        1,
    ),
    (
        "dataplane/peer_actions.rs",
        "self.shadow_sent(link, false)",
        1,
    ),
    ("handlers/handshake.rs", "Input::Arrived {", 1),
    (
        "handlers/handshake.rs",
        "Input::Msg1 { read, reachable }",
        1,
    ),
    ("handlers/handshake.rs", "Input::Replace(read)", 1),
    // The answer built at the restart tail and at the promotion tail.
    ("handlers/handshake.rs", "self.shadow_hello(", 2),
    // The refusal and the failed allocation, at each of the two tails.
    ("handlers/handshake.rs", "self.shadow_unasked(", 4),
    // A stored answer resent for a duplicate msg1, sent or failed.
    (
        "handlers/handshake.rs",
        "self.shadow_sent(existing_link_id, true)",
        1,
    ),
    (
        "handlers/handshake.rs",
        "self.shadow_sent(existing_link_id, false)",
        1,
    ),
    ("handlers/handshake.rs", "Input::Msg2 {", 1),
    // The peers' timers, where the node resends and reaps its dials, a
    // failed leg the handshake timeouts reap, and the core's own reap of a
    // leg the node reaps at its deadline, at the timers and at the
    // handshake timeouts.
    ("handlers/timeout.rs", "self.shadow_tick()", 1),
    ("handlers/timeout.rs", "self.shadow_abandon(", 1),
    ("handlers/timeout.rs", "self.shadow_reap(", 2),
    ("handlers/timeout.rs", "self.shadow_sent(link, sent)", 1),
    ("handlers/rekey.rs", "self.decide(In::Restarted {", 1),
    ("dataplane/encrypted.rs", "Input::Heard {", 1),
    ("settle/exec/remove.rs", "self.shadow_remove(", 1),
    ("settle/exec/links.rs", "self.shadow_feed(input)", 1),
];

/// The source of the node file `file`, under `src/node/`.
fn source(file: &str) -> &'static str {
    match file {
        "lifecycle/mod.rs" => include_str!("../../lifecycle/mod.rs"),
        "dataplane/peer_actions.rs" => include_str!("../../dataplane/peer_actions.rs"),
        "dataplane/encrypted.rs" => include_str!("../../dataplane/encrypted.rs"),
        "handlers/handshake.rs" => include_str!("../../handlers/handshake.rs"),
        "handlers/timeout.rs" => include_str!("../../handlers/timeout.rs"),
        "handlers/rekey.rs" => include_str!("../../handlers/rekey.rs"),
        "settle/exec/remove.rs" => include_str!("../exec/remove.rs"),
        "settle/exec/links.rs" => include_str!("../exec/links.rs"),
        _ => panic!("no source listed for {file}"),
    }
}

/// The lines of `source` that make `call` under `#[cfg(test)]`: each line
/// holding the call within the block that follows a `#[cfg(test)]` line,
/// taken as the twenty-five lines after it.
fn fed(source: &str, call: &str) -> Vec<usize> {
    let lines: Vec<&str> = source.lines().collect();
    lines
        .iter()
        .enumerate()
        .filter(|(i, line)| {
            line.contains(call)
                && lines[i.saturating_sub(25)..*i]
                    .iter()
                    .any(|l| l.trim() == "#[cfg(test)]")
        })
        .map(|(i, _)| i)
        .collect()
}

/// The rows of `SITES` whose file, as `text` gives it, makes the row's call
/// under `#[cfg(test)]` a number of times other than the row's count, with
/// the number found.
fn unfed(text: impl Fn(&str) -> String) -> Vec<(&'static str, &'static str, usize)> {
    SITES
        .iter()
        .filter_map(|&(file, call, sites)| {
            let found = fed(&text(file), call).len();
            (found != sites).then_some((file, call, found))
        })
        .collect()
}

/// Every decision site feeds the shadow core what it decided: each site's
/// file makes its shadow call under `#[cfg(test)]` once per site. How often
/// each input reached the shadow over a run is the `seen` row each node's
/// shadow writes to `FIPS_CORE_SHADOW` when dropped; a run of the suite
/// with it set counts every site. The scan finds any one site's call
/// removed, a site whose call other sites in its file share included.
#[test]
fn the_shadow_sees_every_decision_site() {
    let text = |file: &str| source(file).replace("\r\n", "\n");
    let missing = unfed(text);
    assert!(
        missing.is_empty(),
        "defect: sites feed the shadow other than SITES counts (file, call, found): {missing:?}"
    );
    for &(file, call, sites) in SITES {
        let planted = unfed(|f| {
            let source = text(f);
            if f != file {
                return source;
            }
            let last = *fed(&source, call).last().expect("the site is fed");
            source
                .lines()
                .enumerate()
                .filter(|(i, _)| *i != last)
                .map(|(_, l)| l)
                .collect::<Vec<_>>()
                .join("\n")
        });
        assert_eq!(
            planted,
            vec![(file, call, sites - 1)],
            "the scan finds one site's call removed"
        );
    }
}

/// The shadow counts each input it takes by its kind, which the `seen`
/// row reports.
#[test]
fn the_shadow_counts_each_input_by_its_kind() {
    let mut node = crate::node::tests::make_node();
    dial(&mut node, LinkId::new(1), addr(1), at(1), 1);
    node.shadow_sent(LinkId::new(1), false);
    node.shadow_tick();
    assert_eq!(
        (
            node.shadow.seen("Dial"),
            node.shadow.seen("SendFailed"),
            node.shadow.seen("tick"),
            node.shadow.seen("Msg2"),
        ),
        (1, 1, 1, 0)
    );
}

/// The node's reap of a leg at its deadline gives the shadow core its own
/// reap of the leg at the node's instant plus the skew: a leg the core
/// took a tenth of a second after the node is reaped by the core, and one
/// taken further apart than the skew is still held, for the comparison to
/// find. Neither is handed the node's give-up.
#[test]
fn the_shadow_core_reaps_a_leg_the_node_reaps_only_within_the_skew_of_its_own_deadline() {
    for (late, kept) in [(100, false), (400, true)] {
        let mut node = crate::node::tests::make_node();
        let wait = Duration::from_secs(node.config().node.rate_limit.handshake_timeout_secs);
        let link = LinkId::new(1);
        dial(&mut node, link, addr(1), at(1), 1);
        node.shadow_delay(link, Duration::from_millis(late));
        crate::time::advance(wait);
        node.shadow_tick();
        let due = node.shadow.no(link).is_none();
        node.shadow_reap(link);
        let held = node.shadow.no(link).is_some();
        let fed = node.shadow.seen("ConnectFailed");
        drop(node);
        assert!(
            !due,
            "precondition: the core's leg, {late} ms late, is not due at the node's instant"
        );
        assert_eq!(
            held, kept,
            "defect: the core's leg {late} ms behind the node's deadline is held: {held}"
        );
        assert_eq!(fed, 0, "defect: the core was handed the node's give-up");
    }
}

/// A test's removal of a peer (`remove_active_peer`, the routine for a link
/// its rekey machine ended) feeds the shadow its `Ended` and records the
/// node's side of it, so `core-agrees` finds the two the same rather than
/// a removal the core decided and the node did not.
#[test]
fn a_test_removal_is_recorded_on_the_nodes_side_as_the_core_decides_it() {
    let mut node = crate::node::tests::make_node();
    let remote = crate::Identity::generate();
    let link = node.allocate_link_id();
    let (tid, from) = (
        TransportId::new(1),
        TransportAddr::from_string("127.0.0.1:41002"),
    );
    let mut peer = crate::node::tests::keyed_peer(&node, &remote, link, Node::now_ms());
    peer.set_current_addr(tid, from.clone());
    let addr = *peer.node_addr();
    node.peers.raw().insert(addr, peer);
    node.links.raw_index().insert((tid, from), link);
    node.resync();
    node.shadow_resync(None);
    let held = node.shadow.table().and_then(|t| t.held(&addr)).is_some();
    let _ = node.shadow.take();
    let removed = node.remove_active_peer(&addr).is_some();
    let logs = node.shadow.take();
    assert!(held, "precondition: the shadow holds the planted peer");
    assert!(removed, "precondition: the node held the peer to remove");
    let remove = crate::node::settle::exec::Did::Remove {
        peer: addr,
        why: crate::proto::settle::output::Why::Ended,
    };
    assert_eq!(
        logs.core,
        vec![remove.clone()],
        "precondition: the core decided the removal"
    );
    assert_eq!(
        logs.node,
        vec![remove],
        "defect: the node's side of a test's removal is not recorded"
    );
}

/// `gates-agree` reads every identity either side's memory holds, the
/// node's replay memory and silent-session record included: a silent
/// session and a remembered msg1 the node holds for an identity the shadow
/// core's gates know nothing of are each a difference.
#[test]
fn gates_agree_reads_an_identity_only_the_nodes_replay_or_silent_memory_holds() {
    let mut node = crate::node::tests::make_node();
    node.shadow_resync(None);
    let now = crate::peer::peer_now();
    let params = node.gate_params();
    node.gates.ended(addr(7), None, None, now, None, &params);
    let digest = crate::proto::fmp::EphemeralDigest::of_noise_msg1(&[7; 33])
        .expect("a public key's length carries an ephemeral");
    node.gates.promoted(addr(8), digest, now, None, &params);
    let bad = crate::node::settle::audit::gates_agree(&node);
    assert!(
        node.shadow.table().is_some(),
        "precondition: the shadow has a table"
    );
    assert_eq!(
        bad.len(),
        2,
        "defect: gates-agree did not read both identities only the node remembers: {bad:?}"
    );
}

/// A link a test put in the link map past its writers: the shadow's resync
/// opens a record for it, and the node's link table has none until its own
/// resync adopts the link, so `links-agree` has nothing of the node's to
/// compare and finds no difference.
#[test]
fn links_agree_skips_a_planted_link_the_nodes_table_has_not_recorded() {
    let mut node = crate::node::tests::make_node();
    let link = node.allocate_link_id();
    let to = at(6);
    node.links.raw().insert(
        link,
        crate::transport::Link::connectionless(
            link,
            to.transport,
            to.addr.clone(),
            crate::transport::LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.shadow_resync(None);
    let bad = crate::node::settle::audit::links_agree(&node);
    assert!(
        node.shadow.no(link).is_some() && node.links.no(&link).is_none(),
        "precondition: the shadow numbers the planted link and the node's table holds no record of it"
    );
    assert!(
        bad.is_empty(),
        "defect: links-agree compared a planted link the node's table has not recorded: {bad:?}"
    );
}

/// A dial on a link the node holds, which the shadow reaps by its own
/// timers before the node does, later in the same entry: the shadow's
/// resync meanwhile does not take the link for one a test planted and
/// number it again.
#[test]
fn a_link_whose_leg_the_shadow_reaped_is_not_taken_for_a_plant_while_the_node_holds_it() {
    let mut node = crate::node::tests::make_node();
    let wait = Duration::from_secs(node.config().node.rate_limit.handshake_timeout_secs);
    let link = node.allocate_link_id();
    let to = at(5);
    node.links.raw().insert(
        link,
        crate::transport::Link::connectionless(
            link,
            to.transport,
            to.addr.clone(),
            crate::transport::LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    dial(&mut node, link, addr(5), to, 5);
    crate::time::advance(wait + Duration::from_secs(1));
    node.shadow_tick();
    let reaped = node.shadow.no(link).is_none();
    node.shadow_resync(None);
    assert!(reaped, "precondition: the shadow reaped the dial");
    assert!(
        node.shadow.no(link).is_none(),
        "defect: the resync took a link whose leg the shadow reaped for a plant"
    );
}

/// A link opened on the node's link table through its writer.
fn open(node: &mut Node, to: &Pair) -> LinkId {
    let link = node.allocate_link_id();
    node.links.open(crate::transport::Link::connectionless(
        link,
        to.transport,
        to.addr.clone(),
        crate::transport::LinkDirection::Outbound,
        Duration::from_millis(100),
    ));
    link
}

/// A link a test opens through the node's link table but past every
/// decision site, with no handshake of its own, on a node not planted: the
/// shadow's resync opens a record for it as the node's table does, so
/// `links-agree` finds nothing.
#[test]
fn a_link_opened_past_the_decision_sites_on_an_unplanted_node_is_taken_by_the_resync() {
    let mut node = crate::node::tests::make_node();
    let link = open(&mut node, &at(7));
    node.shadow_resync(None);
    let bad = crate::node::settle::audit::links_agree(&node);
    assert!(!node.planted(), "precondition: the node is not planted");
    assert!(
        bad.is_empty(),
        "defect: the resync left a link opened past the sites unrecorded: {bad:?}"
    );
    assert!(node.shadow.no(link).is_some());
}

/// A link a decision site named as the link its input opens, which the
/// core did not number: the resync does not take it for a plant, so
/// `links-agree` still shows that the core has no record of it.
#[test]
fn a_link_a_decision_site_named_is_not_taken_by_the_resync() {
    let mut node = crate::node::tests::make_node();
    let to = at(8);
    let link = open(&mut node, &to);
    node.decide_at(
        Some(link),
        Input::Arrived {
            from: to,
            bytes: vec![1],
        },
    );
    node.shadow_resync(None);
    let bad = crate::node::settle::audit::links_agree(&node);
    assert_eq!(
        bad,
        vec![format!("link {link}: the core has no record")],
        "defect: the resync took a link a decision site named for a plant"
    );
}

/// A peering the shadow installed on a link, whose record the shadow then
/// retires at an input, a removal, while the node still holds the link:
/// the resync does not take the link back, so the comparison shows the
/// difference. The link is set as one no decision site named, as a link
/// the resync took from a test's plant is, so only the retirement keeps it
/// out.
#[test]
fn a_link_the_shadow_retired_at_an_input_is_not_taken_back_by_the_resync() {
    let mut node = crate::node::tests::make_node();
    let peer = addr(9);
    let to = at(9);
    let link = open(&mut node, &to);
    dial(&mut node, link, peer, to.clone(), 9);
    let no = node
        .shadow
        .no(link)
        .expect("precondition: the dial is numbered");
    node.decide(Input::Msg2 {
        link: no,
        epoch: [9; 8],
        from: to,
    });
    let held = node.shadow.table().and_then(|t| t.held(&peer)).is_some();
    node.shadow.fed.clear();
    node.decide(Input::Ended { peer });
    let retired = node.shadow.no(link).is_none();
    node.shadow_resync(None);
    assert!(held, "precondition: the shadow installed the peer");
    assert!(
        retired,
        "precondition: the removal retired the link's record"
    );
    assert!(
        node.shadow.no(link).is_none(),
        "defect: the resync took back a link the shadow retired at an input"
    );
}

/// A peer a test planted on a link its node's link map does not hold: the
/// shadow holds the peer on a record of its own for the link, and the
/// node's table has none to compare, so `links-agree` passes the link
/// over.
#[test]
fn links_agree_skips_the_link_of_a_planted_peer_the_nodes_link_map_does_not_hold() {
    let mut node = crate::node::tests::make_node();
    let remote = crate::Identity::generate();
    let link = node.allocate_link_id();
    let peer = crate::node::tests::keyed_peer(&node, &remote, link, Node::now_ms());
    let addr = *peer.node_addr();
    node.peers.raw().insert(addr, peer);
    node.shadow_resync(None);
    let bad = crate::node::settle::audit::links_agree(&node);
    assert!(
        node.shadow.no(link).is_some() && !node.links.contains_key(&link),
        "precondition: the shadow numbers the planted peer's link and the node's map lacks it"
    );
    assert!(
        bad.is_empty(),
        "defect: links-agree compared a planted peer's link the node's map does not hold: {bad:?}"
    );
}

/// A peer a test plants afresh over one the shadow already holds, on a new
/// link and at another epoch, as a test that re-installs a peering between
/// two msg1s does: the shadow takes the peer again from its facts, on the
/// new link's record and at the new epoch, and forgets the record of the
/// link it held the peer on, which the node's map never held.
#[test]
fn a_peer_planted_afresh_on_a_new_link_is_taken_again_by_the_resync() {
    let mut node = crate::node::tests::make_node();
    let remote = crate::Identity::generate();
    let (tid, from) = (
        TransportId::new(1),
        TransportAddr::from_string("127.0.0.1:41003"),
    );
    let plant = |node: &mut Node, epoch: [u8; 8]| {
        let link = node.allocate_link_id();
        let mut peer = crate::node::tests::keyed_peer(node, &remote, link, Node::now_ms());
        peer.set_current_addr(tid, from.clone());
        peer.set_remote_epoch(Some(epoch));
        let addr = *peer.node_addr();
        node.peers.raw().insert(addr, peer);
        node.links.raw_index().insert((tid, from.clone()), link);
        node.shadow_resync(None);
        (addr, link)
    };
    let (addr, first) = plant(&mut node, [0xAA; 8]);
    let held = |node: &Node| node.shadow.table().and_then(|t| t.held(&addr)).cloned();
    let before = held(&node).map(|h| h.link);
    assert!(
        before.is_some() && before == node.shadow.no(first),
        "precondition: the shadow holds the first plant on its link"
    );
    let (_, second) = plant(&mut node, [0xBB; 8]);
    let after = held(&node).map(|h| (Some(h.link) == node.shadow.no(second), h.epoch));
    assert_eq!(
        (after, node.shadow.no(first)),
        (Some((true, [0xBB; 8])), None),
        "defect: the shadow kept the peer where the first plant put it"
    );
}

/// A link the node's table records from an index entry a test planted,
/// with no link in the node's map, and whose planted peer is gone: no
/// removal reaches a link the map lacks, so the node's record keeps the
/// plant's holder while the shadow core's follows its decisions, and
/// `links-agree` passes the link over.
#[test]
fn links_agree_skips_a_link_the_node_records_with_no_link_in_its_map() {
    let mut node = crate::node::tests::make_node();
    let remote = crate::Identity::generate();
    let link = node.allocate_link_id();
    let (tid, from) = (
        TransportId::new(1),
        TransportAddr::from_string("127.0.0.1:41004"),
    );
    let mut peer = crate::node::tests::keyed_peer(&node, &remote, link, Node::now_ms());
    peer.set_current_addr(tid, from.clone());
    let addr = *peer.node_addr();
    node.peers.raw().insert(addr, peer);
    node.links.raw_index().insert((tid, from), link);
    node.resync();
    // The peer goes as a decision of the core's would take it, the node's
    // record of its link untouched.
    node.peers.raw().remove(&addr);
    if let Some(no) = node.shadow.no(link)
        && let Some(table) = node.shadow.table.as_mut()
    {
        table
            .records()
            .hold(no, crate::proto::settle::links::Holder::Leg);
    }
    let bad = crate::node::settle::audit::links_agree(&node);
    assert!(
        node.links.no(&link).is_some() && !node.links.contains_key(&link),
        "precondition: the node records the link and its map lacks it"
    );
    assert!(
        bad.is_empty(),
        "defect: links-agree compared a link the node records with no link in its map: {bad:?}"
    );
}

/// A first difference of the shadow core from the node that `shadow.txt`
/// does not list fails the test when its node is dropped, and not before,
/// so a test that breaks the node fails at its own assertion first: here
/// the node records a refusal the shadow core never decided.
#[cfg(debug_assertions)]
#[test]
fn a_first_difference_shadow_txt_does_not_list_fails_the_test_when_its_node_drops() {
    let mut node = crate::node::tests::make_node();
    node.did(crate::node::settle::exec::Did::Reject { peer: None });
    let audited = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        node.audit_live("test");
    }));
    let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(node)));
    let message = dropped.err().map(|e| {
        e.downcast_ref::<String>().cloned().unwrap_or_else(|| {
            e.downcast_ref::<&str>()
                .map(|s| s.to_string())
                .unwrap_or_default()
        })
    });
    assert!(
        audited.is_ok(),
        "precondition: the audit that finds the difference does not itself fail"
    );
    assert!(
        message.as_deref().is_some_and(
            |m| m.contains("test: core-agrees") && m.contains("shadow.txt does not list it")
        ),
        "defect: an unlisted first difference did not fail the test at its node's drop: {message:?}"
    );
}

/// `closes-agree` passes when the node closed the pairs the shadow core
/// decided to close, each pair once and in any order, and finds a close made
/// on either side alone; each audit takes what it compared, so the next
/// compares what follows.
#[test]
fn closes_agree_passes_the_cores_closes_in_any_order_and_finds_a_close_on_either_side_alone() {
    use crate::node::settle::audit::closes_agree;
    use crate::proto::settle::output::Output;
    let node = crate::node::tests::make_node();
    let close = |node: &Node, p: Pair| node.closed(p.transport, &p.addr);
    close(&node, at(1));
    close(&node, at(2));
    close(&node, at(1));
    node.shadow.closing(&[Output::Close {
        closes: vec![at(2), at(1)],
    }]);
    let same = closes_agree(&node);
    close(&node, at(3));
    let node_alone = closes_agree(&node);
    node.shadow.closing(&[Output::Close {
        closes: vec![at(4)],
    }]);
    let core_alone = closes_agree(&node);
    let taken = closes_agree(&node);
    let (only_node, only_core) = (
        format!("the node closed {:?}, the core decided []", [at(3)]),
        format!("the node closed [], the core decided {:?}", [at(4)]),
    );
    assert!(
        same.is_empty(),
        "defect: the same closes in another order, one made twice, differ: {same:?}"
    );
    assert!(
        node_alone == [only_node],
        "defect: a close the node made alone is not found: {node_alone:?}"
    );
    assert!(
        core_alone == [only_core],
        "defect: a close the core decided alone is not found: {core_alone:?}"
    );
    assert!(
        taken.is_empty(),
        "defect: an audit left what it compared to the next: {taken:?}"
    );
}

/// A line of `shadow.txt` names a first difference by its test, site and
/// clause, tab-separated, and names no other; blank and `#` lines name
/// nothing, and every line of the committed file that names one has the
/// three fields.
#[cfg(debug_assertions)]
#[test]
fn a_shadow_txt_line_names_one_test_site_and_clause() {
    use crate::node::settle::audit::{SHADOW_KNOWN, known};
    let list = "# a\tb\tc\n\nnode::tests::x\thandle_msg1\tcore-agrees\n";
    assert!(
        known(list, "node::tests::x", "handle_msg1", "core-agrees"),
        "defect: a listed difference is not known"
    );
    for (test, site, clause) in [
        ("node::tests::y", "handle_msg1", "core-agrees"),
        ("node::tests::x", "handle_msg2", "core-agrees"),
        ("node::tests::x", "handle_msg1", "links-agree"),
        ("# a", "b", "c"),
    ] {
        assert!(
            !known(list, test, site, clause),
            "defect: {test} {site} {clause} is known from a line that does not name it"
        );
    }
    let malformed: Vec<&str> = SHADOW_KNOWN
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter(|l| l.split('\t').count() != 3)
        .collect();
    assert!(
        malformed.is_empty(),
        "defect: shadow.txt lines without three tab-separated fields: {malformed:?}"
    );
}

/// `CORE_READS` names exactly the switches the settlement core reads by
/// `node_fault!`, by a scan of the core's settlement sources, so a switch
/// added there is not taken for one that breaks only the node.
#[test]
fn the_switches_the_core_reads_are_the_ones_its_sources_read() {
    fn scan(dir: &std::path::Path, found: &mut std::collections::BTreeSet<String>) {
        let entries = std::fs::read_dir(dir).expect("precondition: the core's settlement sources");
        for entry in entries {
            let path = entry.expect("precondition: a directory entry").path();
            if path.is_dir() {
                scan(&path, found);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("precondition: a source file");
                for part in text.split("node_fault!(").skip(1) {
                    let name: String = part.chars().take_while(|c| c.is_alphanumeric()).collect();
                    if part[name.len()..].starts_with(')') && name != "X" {
                        found.insert(name);
                    }
                }
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("core/src/proto/settle");
    let mut found = std::collections::BTreeSet::new();
    scan(&root, &mut found);
    let listed: std::collections::BTreeSet<String> = crate::node::settle::decide::CORE_READS
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(
        !found.is_empty(),
        "precondition: the scan finds the core's switches"
    );
    assert_eq!(
        listed, found,
        "defect: CORE_READS is not the switches the core reads by node_fault!"
    );
}
