//! Path candidate intake (`handlers/path_intake.rs`): which reports of a
//! linked peer's pairs become `Candidate` and `Unlisted` inputs, which UDP
//! instance an mDNS advert is a candidate on, and a linked peer's advert
//! reaching its link. The last test opens a UDP socket, so this module is
//! in the `node-synthetic` group.

use crate::NodeAddr;
use crate::node::handlers::path_intake::{
    BEACON_SILENCE, Feed, LISTED_MAX, Listings, UdpLane, mdns_lane,
};
use crate::transport::{TransportAddr, TransportId};
use fips_core::proto::path::{Input, Source};

/// The node address numbered `n`.
fn peer(n: u8) -> NodeAddr {
    NodeAddr::from_bytes([n; 16])
}

/// The beacon silence in milliseconds.
fn silence() -> u64 {
    BEACON_SILENCE.as_millis() as u64
}

/// The pair numbered `n` on transport 2.
fn pair(n: u32) -> (TransportId, TransportAddr) {
    (
        TransportId::new(2),
        TransportAddr::from_string(&format!("loopback:{n}")),
    )
}

/// The `Candidate` from `source` for `pair(n)`.
fn candidate(n: u32, source: Source) -> Input {
    let (transport, addr) = pair(n);
    Input::Candidate {
        transport,
        addr,
        source,
    }
}

/// The `Unlisted` from `source` for `pair(n)`.
fn unlisted(n: u32, source: Source) -> Input {
    let (transport, addr) = pair(n);
    Input::Unlisted {
        transport,
        addr,
        source,
    }
}

/// `feed` reports `pair(n)` for `who` at `now`.
fn report(l: &mut Listings, who: NodeAddr, feed: Feed, n: u32, now: u64) -> Vec<Input> {
    let (transport, addr) = pair(n);
    l.report(who, feed, transport, addr, now)
}

/// A pair a feed already lists gives nothing when reported again: the
/// core would take it as a repeat. Mutation: every report gives a
/// `Candidate`.
#[test]
fn a_known_pairs_report_gives_no_input() {
    let mut l = Listings::default();
    assert_eq!(
        report(&mut l, peer(1), Feed::Beacon, 1, 0),
        [candidate(1, Source::Discovery)]
    );
    assert_eq!(report(&mut l, peer(1), Feed::Beacon, 1, 1000), []);
    assert_eq!(
        report(&mut l, peer(2), Feed::Beacon, 1, 1000),
        [candidate(1, Source::Discovery)],
        "another peer's listing is its own"
    );
}

/// A pair unreported for the beacon silence is unlisted, and its next
/// report is a `Candidate` again; one reported within the silence keeps
/// its listing, its silence counted from its latest report. Mutations:
/// never expire; expire at the first check after a report.
#[test]
fn a_pair_silent_for_its_feeds_silence_is_unlisted_and_offered_again_when_next_reported() {
    let mut l = Listings::default();
    report(&mut l, peer(1), Feed::Beacon, 1, 0);
    report(&mut l, peer(1), Feed::Beacon, 2, 0);
    assert_eq!(l.expire(1000, |_| true), [], "nothing is silent yet");
    report(&mut l, peer(1), Feed::Beacon, 2, silence() - 1);
    assert_eq!(
        l.expire(silence() - 1, |_| true),
        [],
        "a beacon short of the silence"
    );
    assert_eq!(
        l.expire(silence(), |_| true),
        [(peer(1), unlisted(1, Source::Discovery))],
        "pair 1 unheard for the silence; pair 2 heard since"
    );
    assert_eq!(l.listed(&peer(1), Feed::Beacon), [pair(2)]);
    assert_eq!(
        report(&mut l, peer(1), Feed::Beacon, 1, silence() + 1),
        [candidate(1, Source::Discovery)],
        "the pair's next report is fresh"
    );
}

/// A feed lists at most `LISTED_MAX` pairs for a peer: a new one past that
/// unlists the least recently reported. Mutation: no bound.
#[test]
fn a_peers_listing_is_bounded_and_the_oldest_pair_is_unlisted() {
    let mut l = Listings::default();
    for n in 0..LISTED_MAX as u32 {
        report(&mut l, peer(1), Feed::Beacon, n, u64::from(n));
    }
    // Pair 0 is reported again, so pair 1 is now the least recent.
    report(&mut l, peer(1), Feed::Beacon, 0, 100);
    assert_eq!(
        report(&mut l, peer(1), Feed::Beacon, 99, 200),
        [
            candidate(99, Source::Discovery),
            unlisted(1, Source::Discovery)
        ]
    );
    assert_eq!(l.listed(&peer(1), Feed::Beacon).len(), LISTED_MAX);
}

/// The listings of a peer no longer linked are dropped, with no input,
/// since its machine is gone with its link. Mutation: keep every peer.
#[test]
fn a_peer_no_longer_linked_is_dropped_without_inputs() {
    let mut l = Listings::default();
    report(&mut l, peer(1), Feed::Beacon, 1, 0);
    report(&mut l, peer(2), Feed::Beacon, 1, 0);
    assert_eq!(l.expire(1000, |p| *p == peer(2)), []);
    assert_eq!(l.listed(&peer(1), Feed::Beacon), []);
    assert_eq!(l.listed(&peer(2), Feed::Beacon), [pair(1)]);
    assert_eq!(
        report(&mut l, peer(1), Feed::Beacon, 1, 2000),
        [candidate(1, Source::Discovery)],
        "a peer linked again starts afresh"
    );
}

/// `forget` drops everything listed for one peer, so each feed's next
/// report is a `Candidate` for its new machine, and leaves the others.
/// Mutation: `forget` does nothing.
#[test]
fn forget_drops_one_peers_listings_and_leaves_the_others() {
    let mut l = Listings::default();
    report(&mut l, peer(1), Feed::Beacon, 1, 0);
    report(&mut l, peer(2), Feed::Beacon, 1, 0);
    l.forget(&peer(1));
    assert_eq!(
        report(&mut l, peer(1), Feed::Beacon, 1, 10),
        [candidate(1, Source::Discovery)]
    );
    assert_eq!(report(&mut l, peer(2), Feed::Beacon, 1, 10), []);
}

/// A whole-list feed gives a `Candidate` for a pair new to its list, an
/// `Unlisted` for one gone from it, and nothing for an unchanged list.
/// Mutation: never unlist from a whole list.
#[test]
fn a_whole_list_gives_candidates_for_new_pairs_and_unlisted_for_dropped_ones() {
    let mut l = Listings::default();
    let (p1, p2, p3) = (pair(1), pair(2), pair(3));
    assert_eq!(
        l.list(peer(1), Feed::Config, &[p1.clone(), p2.clone()], 0),
        [candidate(1, Source::Config), candidate(2, Source::Config)]
    );
    assert_eq!(
        l.list(peer(1), Feed::Config, &[p2.clone(), p1.clone()], 10),
        [],
        "the same list in another order"
    );
    assert_eq!(
        l.list(peer(1), Feed::Config, &[p2.clone(), p3], 20),
        [unlisted(1, Source::Config), candidate(3, Source::Config)]
    );
    assert_eq!(
        l.list(peer(1), Feed::Nostr, &[p2], 30),
        [candidate(2, Source::Nostr)],
        "each feed lists for itself"
    );
    assert_eq!(
        l.expire(u64::MAX, |_| true),
        [],
        "a whole list does not expire by silence"
    );
}

/// A UDP lane numbered `id`, bound to interface `ifindex` if any, local at
/// `local`.
fn lane(id: u32, ifindex: Option<u32>, local: &str) -> UdpLane {
    UdpLane {
        id: TransportId::new(id),
        ifindex,
        local: local.parse().unwrap(),
    }
}

/// An mDNS advert is a candidate on the UDP instance bound to the interface
/// it arrived on, of its address family, not on the lowest-numbered one.
/// Mutation: always the lowest id.
#[test]
fn an_mdns_advert_is_attributed_to_the_instance_bound_to_its_interface() {
    let lanes = [
        lane(1, Some(2), "0.0.0.0:2121"),
        lane(2, Some(3), "0.0.0.0:2122"),
        lane(3, Some(3), "[::]:2121"),
        lane(4, Some(3), "0.0.0.0:2123"),
    ];
    let v4: std::net::SocketAddr = "192.0.2.7:2121".parse().unwrap();
    assert_eq!(mdns_lane(&lanes, v4, &[3]), Some(TransportId::new(2)));
    assert_eq!(mdns_lane(&lanes, v4, &[9, 2]), Some(TransportId::new(1)));
    let v6: std::net::SocketAddr = "[fe80::7%3]:2121".parse().unwrap();
    assert_eq!(mdns_lane(&lanes, v6, &[3]), Some(TransportId::new(3)));
}

/// An advert on no interface a lane is bound to falls back to the lowest
/// compatible instance, the one a dial of its address takes; an advert of
/// a family no lane has gets none.
#[test]
fn an_advert_on_no_bound_interface_falls_back_to_the_lowest_compatible_instance() {
    let lanes = [
        lane(5, Some(2), "0.0.0.0:2121"),
        lane(3, None, "0.0.0.0:2122"),
        lane(1, Some(4), "[::]:2121"),
    ];
    let v4: std::net::SocketAddr = "192.0.2.7:2121".parse().unwrap();
    assert_eq!(mdns_lane(&lanes, v4, &[9]), Some(TransportId::new(3)));
    assert_eq!(mdns_lane(&lanes, v4, &[]), Some(TransportId::new(3)));
    assert_eq!(
        mdns_lane(&lanes[..2], "[fe80::7%4]:2121".parse().unwrap(), &[4]),
        None
    );
}

/// With multipath enabled, an mDNS advert of a peer the node holds a link
/// with is a path candidate from local discovery on the UDP instance it is
/// attributed to, once it has passed the on-link and impostor checks; it
/// starts no dial. Mutation: no report from mDNS.
#[tokio::test]
async fn a_linked_peers_mdns_advert_is_a_path_candidate_and_not_dialled() {
    use super::paths::{enabled, sources_at};
    use super::rekey_parity::linked_pair;
    use crate::config::UdpConfig;
    use crate::transport::udp::UdpTransport;
    use crate::transport::{TransportHandle, packet_channel};

    let mut nodes = linked_pair(enabled(), enabled()).await;
    let b = *nodes[1].node.node_addr();
    let udp_id = TransportId::new(7);
    let (packet_tx, _packet_rx) = packet_channel(64);
    let mut udp = UdpTransport::new(
        udp_id,
        None,
        UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(1280),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    nodes[0]
        .node
        .transports
        .insert(udp_id, TransportHandle::Udp(udp));
    let at: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    let advert = crate::mdns::LanEvent::Discovered(crate::mdns::LanDiscoveredPeer {
        npub: nodes[1].node.npub(),
        scope: None,
        addr: at,
        interfaces: vec![super::bootstrap::LAN_TEST_IF],
        observed_at: std::time::Instant::now(),
    });
    let before = nodes[0].node.connection_count();
    nodes[0]
        .node
        .handle_lan_events(vec![advert], &super::bootstrap::loopback_prefix())
        .await;
    assert!(
        sources_at(&nodes[0], &b, udp_id, &TransportAddr::from_socket_addr(at))
            .is_some_and(|s| s.has(Source::Discovery)),
        "the linked peer's advert is a candidate from local discovery"
    );
    assert_eq!(
        nodes[0].node.connection_count(),
        before,
        "a linked peer's advert is not dialled"
    );
    super::bootstrap::stop_transports(&mut nodes[0].node).await;
    super::spanning_tree::cleanup_nodes(&mut nodes).await;
}

/// Each feed expires on its own silence: a beacon unheard for the beacon
/// silence is unlisted, while an mDNS listing does not expire by silence,
/// since mdns-sd does not report a current service again. A pair that
/// both list stays listed with the core's discovery source until both
/// are done with it. Mutations: one silence for every feed; unlist a pair
/// whatever another feed of the same source lists.
#[test]
fn each_feed_expires_on_its_own_silence() {
    let mut l = Listings::default();
    report(&mut l, peer(1), Feed::Beacon, 1, 0);
    report(&mut l, peer(1), Feed::Beacon, 2, 0);
    assert_eq!(
        report(&mut l, peer(1), Feed::Mdns, 2, 0),
        [],
        "the core already lists pair 2 from discovery"
    );
    report(&mut l, peer(1), Feed::Mdns, 3, 0);
    assert_eq!(
        l.expire(silence(), |_| true),
        [(peer(1), unlisted(1, Source::Discovery))],
        "pair 2 is still listed by mDNS, and pair 3 does not expire"
    );
    assert_eq!(l.listed(&peer(1), Feed::Beacon), []);
    assert_eq!(l.listed(&peer(1), Feed::Mdns), [pair(2), pair(3)]);
    assert_eq!(l.expire(u64::MAX, |_| true), []);
}

/// A source that feeds a linked peer's path machine a candidate, for the
/// test of a change in the facts.
#[derive(Clone, Copy, Debug)]
enum Fed {
    /// An mDNS advert, on A's second transport.
    Mdns,
    /// A frame heard from no path, on A's second transport.
    Heard,
    /// The operator's `connect`, at a second address of B's on t1.
    Connect,
    /// The configuration, at a second address of B's on t1.
    Config,
}

/// One case of the test below: A and B linked with multipath on, B not
/// known to be capable (nothing from B reaches A after the link is made);
/// A's ACL denies B while `fed` reports a candidate, so no capability probe
/// goes; then the ACL allows B again, and A runs one discovery tick and
/// path ticks over one second with nothing delivered to it. Returns
/// whether a capability probe went in that second, and why not.
async fn acl_reload(fed: Fed) -> Result<(), String> {
    use super::paths::{capable_at, configure, enabled, second_transport, sources_at, t2};
    use super::rekey_parity::linked_pair;
    use super::spanning_tree::{add_loopback_alias, cleanup_nodes};
    use crate::config::PeerAddress;
    use crate::node::acl::PeerAclContext;
    use crate::node::handlers::path_intake::Feed;
    use std::time::Duration;

    let mut nodes = linked_pair(enabled(), enabled()).await;
    let b = *nodes[1].node.node_addr();
    let t1 = nodes[0].transport_id;
    let (transport, b2) = match fed {
        Fed::Mdns | Fed::Heard => {
            second_transport(&mut nodes[0], t2(), 1280);
            (t2(), second_transport(&mut nodes[1], t2(), 1280))
        }
        Fed::Connect | Fed::Config => (
            t1,
            add_loopback_alias(&nodes[1].addr, nodes[1].transport_id),
        ),
    };
    assert!(!capable_at(&nodes[0], &b), "precondition: B not capable");

    let dir = tempfile::tempdir().unwrap();
    let deny = dir.path().join("peers.deny");
    std::fs::write(&deny, format!("{}\n", nodes[1].node.npub())).unwrap();
    // The reloader loads the files it is given when it is made.
    nodes[0]
        .node
        .isolate_peer_acl_for_test(dir.path().join("peers.allow"), deny.clone());
    assert!(
        nodes[0].node.get_peer(&b).is_some(),
        "precondition: the link stays"
    );
    let b_id = crate::PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    assert!(
        nodes[0]
            .node
            .authorize_peer(&b_id, PeerAclContext::OutboundConnect, transport, &b2)
            .is_err(),
        "precondition: A would not dial B"
    );

    let source = match fed {
        Fed::Mdns => {
            nodes[0]
                .node
                .intake(&b, Feed::Mdns, transport, b2.clone())
                .await;
            Source::Discovery
        }
        Fed::Heard => {
            nodes[0]
                .node
                .intake(&b, Feed::Heard, transport, b2.clone())
                .await;
            Source::Heard
        }
        Fed::Connect => {
            let to = PeerAddress::new("loopback", b2.to_string());
            nodes[0].node.connect_candidate(&b, &to).await;
            Source::Request
        }
        Fed::Config => {
            configure(&mut nodes, 0, std::slice::from_ref(&b2)).await;
            Source::Config
        }
    };
    assert!(
        sources_at(&nodes[0], &b, transport, &b2).is_some_and(|s| s.has(source)),
        "precondition: the candidate is held from {source:?}"
    );
    let sent = |nodes: &[super::spanning_tree::TestNode]| {
        let bundle = nodes[0].node.get_peer(&b).unwrap().bundle().unwrap();
        (bundle.capability().sent(), bundle.next_wake())
    };
    let (before, wake) = sent(&nodes);
    assert_eq!(before, 0, "precondition: no capability probe while denied");
    assert_eq!(wake, None, "precondition: no capability wake while denied");
    while nodes[1].packet_rx.try_recv().is_ok() {}

    std::fs::remove_file(&deny).unwrap();
    assert!(
        nodes[0].node.reload_peer_acl().await,
        "precondition: the empty ACL is published"
    );
    // Nothing is delivered to A from here on, so no report from B steps
    // its machine: whatever does must be the node's own tick.
    let unhandled = nodes[0].packet_rx.len();
    nodes[0].node.poll_transport_discovery().await;
    for _ in 0..20 {
        crate::time::advance(Duration::from_millis(50));
        nodes[0].node.path_tick().await;
    }
    assert_eq!(
        nodes[0].packet_rx.len(),
        unhandled,
        "precondition: nothing taken from A's queue"
    );

    let (after, _) = sent(&nodes);
    let mut at_b = Vec::new();
    while let Ok(packet) = nodes[1].packet_rx.try_recv() {
        at_b.push((packet.transport_id, packet.remote_addr));
    }
    cleanup_nodes(&mut nodes).await;
    let a1 = (t1, nodes[0].addr.clone());
    if after != before + 1 {
        return Err(format!(
            "{fed:?}: {} capability probes in the second after the ACL allowed B",
            after - before
        ));
    }
    if at_b != [a1] {
        return Err(format!("{fed:?}: B holds {at_b:?}, not one frame from A1"));
    }
    Ok(())
}

/// A change in the facts the path rules read takes effect within one
/// discovery tick whatever source fed the candidate: once the ACL allows a
/// peer not known to be capable again, A sends its capability probe within
/// a second, with nothing from the peer stepping its machine. Each source
/// is its own case on its own pair of nodes, and the verdict names every
/// failing one. Mutation: step only the machines whose listings hold a
/// configured, Nostr or beaconed pair (red for mDNS, heard and connect).
#[tokio::test]
async fn a_change_in_the_acl_starts_capability_probing_within_one_discovery_tick_whatever_fed_the_candidate()
 {
    let mut failed = Vec::new();
    for fed in [Fed::Mdns, Fed::Heard, Fed::Connect, Fed::Config] {
        if let Err(e) = acl_reload(fed).await {
            failed.push(e);
        }
    }
    assert!(failed.is_empty(), "failing cases: {failed:#?}");
}

/// A transport added takes effect within one discovery tick as the ACL's
/// change does in the test above: a candidate reported on a transport A does
/// not hold yet gives no probe and no wake, and once the transport appears A
/// sends its capability probe within a second, with no further report and
/// nothing from the peer stepping its machine. Mutation: no step on a poll.
#[tokio::test]
async fn a_transport_added_starts_capability_probing_within_one_discovery_tick() {
    use super::paths::{enabled, second_transport, sources_at, t2};
    use super::rekey_parity::linked_pair;
    use super::spanning_tree::cleanup_nodes;
    use crate::node::handlers::path_intake::Feed;
    use std::time::Duration;

    let mut nodes = linked_pair(enabled(), enabled()).await;
    let b = *nodes[1].node.node_addr();
    let b2 = second_transport(&mut nodes[1], t2(), 1280);
    nodes[0].node.intake(&b, Feed::Mdns, t2(), b2.clone()).await;
    assert!(
        sources_at(&nodes[0], &b, t2(), &b2).is_some_and(|s| s.has(Source::Discovery)),
        "precondition: the candidate is held"
    );
    let sent = |nodes: &[super::spanning_tree::TestNode]| {
        let bundle = nodes[0].node.get_peer(&b).unwrap().bundle().unwrap();
        (bundle.capability().sent(), bundle.next_wake())
    };
    let (before, wake) = sent(&nodes);
    assert_eq!(
        before, 0,
        "precondition: no capability probe while the transport is absent"
    );
    assert_eq!(
        wake, None,
        "precondition: no capability wake while the transport is absent"
    );

    second_transport(&mut nodes[0], t2(), 1280);
    nodes[0].node.poll_transport_discovery().await;
    for _ in 0..20 {
        crate::time::advance(Duration::from_millis(50));
        nodes[0].node.path_tick().await;
    }
    let (after, _) = sent(&nodes);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(after, 1, "one capability probe within the tick");
}

/// The "Path input refused" lines in `logs`.
fn refused_lines(logs: &crate::testutil::LogCapture) -> usize {
    logs.lines()
        .iter()
        .filter(|line| line.contains("Path input refused"))
        .count()
}

/// A capable peer's configured candidate, refused while the ACL denied the
/// peer, is admitted within one discovery tick of the ACL allowing it, with
/// no fresh report of it, and its refusal is logged once, not at every
/// tick (multipath v1 draft, Section 5.5; the operator's choice that a
/// change in the facts takes effect at the next poll). Mutations: no
/// re-offer on a poll (no admission); a re-offer reports its refusal every
/// time (a refusal at every tick).
#[tokio::test]
async fn a_configured_candidate_refused_while_the_acl_denied_the_peer_is_admitted_within_one_discovery_tick_of_the_acl_allowing_it()
 {
    use super::paths::{capable_at, configure, enabled, probe, sources_at, state_at};
    use super::rekey_parity::{deliver, linked_pair};
    use super::spanning_tree::{add_loopback_alias, cleanup_nodes};
    use crate::node::acl::PeerAclContext;
    use crate::peer::PathState;
    use std::time::Duration;

    let mut nodes = linked_pair(enabled(), enabled()).await;
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    let t1 = nodes[0].transport_id;
    let b2 = add_loopback_alias(&nodes[1].addr, nodes[1].transport_id);

    // B shows A it implements multipath: one probe from B on p.
    let id = nodes[1]
        .node
        .get_peer(&a)
        .unwrap()
        .bundle()
        .unwrap()
        .paths()
        .get(0)
        .unwrap()
        .path_id();
    nodes[1]
        .node
        .send_encrypted_link_message(&a, &probe(id, 64))
        .await
        .expect("B's probe goes out");
    deliver(&mut nodes[0]).await;
    assert!(capable_at(&nodes[0], &b), "precondition: B capable at A");
    assert_eq!(
        nodes[0].node.get_peer(&b).unwrap().paths().len(),
        1,
        "precondition: A holds one path"
    );
    while nodes[1].packet_rx.try_recv().is_ok() {}

    // A's ACL denies B; the reloader loads the files it is given when it
    // is made.
    let dir = tempfile::tempdir().unwrap();
    let deny = dir.path().join("peers.deny");
    std::fs::write(&deny, format!("{}\n", nodes[1].node.npub())).unwrap();
    nodes[0]
        .node
        .isolate_peer_acl_for_test(dir.path().join("peers.allow"), deny.clone());
    let b_id = crate::PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let denied = |nodes: &[super::spanning_tree::TestNode]| {
        nodes[0]
            .node
            .authorize_peer(&b_id, PeerAclContext::OutboundConnect, t1, &b2)
            .is_err()
    };
    assert!(denied(&nodes), "precondition: A would not dial B");
    assert!(
        nodes[0].node.get_peer(&b).is_some(),
        "precondition: the link stays"
    );

    let (logs, _guard) = crate::testutil::capture_logs_scoped();
    configure(&mut nodes, 0, std::slice::from_ref(&b2)).await;
    assert!(
        denied(&nodes),
        "precondition: still denied after the update"
    );
    assert!(
        sources_at(&nodes[0], &b, t1, &b2).is_some_and(|s| s.has(Source::Config)),
        "precondition: the configured address is a candidate"
    );
    assert_eq!(
        state_at(&nodes[0], &b, t1, &b2),
        None,
        "precondition: refused, not admitted"
    );
    assert_eq!(refused_lines(&logs), 1, "precondition: one refusal");

    for _ in 0..3 {
        crate::time::advance(Duration::from_secs(1));
        nodes[0].node.path_tick().await;
        nodes[0].node.poll_transport_discovery().await;
        assert_eq!(state_at(&nodes[0], &b, t1, &b2), None, "still refused");
    }
    assert_eq!(
        refused_lines(&logs),
        1,
        "a refusal with the rule unchanged is not logged at every tick"
    );
    while nodes[1].packet_rx.try_recv().is_ok() {}

    std::fs::remove_file(&deny).unwrap();
    assert!(
        nodes[0].node.reload_peer_acl().await,
        "precondition: the empty ACL is published"
    );
    nodes[0].node.poll_transport_discovery().await;
    assert_eq!(
        state_at(&nodes[0], &b, t1, &b2),
        Some(PathState::Probing),
        "admitted within one discovery tick of the ACL allowing B"
    );
    let mut at_b = Vec::new();
    while let Ok(packet) = nodes[1].packet_rx.try_recv() {
        at_b.push(packet.transport_id);
    }
    assert!(
        at_b.contains(&nodes[1].transport_id),
        "A's probe reached B on t1: {at_b:?}"
    );
    assert_eq!(refused_lines(&logs), 1, "no refusal since");
    cleanup_nodes(&mut nodes).await;
}
