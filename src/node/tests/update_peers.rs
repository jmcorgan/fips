//! Replacing the peer list at runtime must carry peer aliases into every map
//! that reads them: the display host map, the peer ACL's alias entries and
//! the running `.fips` DNS responder.

use super::*;
use crate::config::{ConnectPolicy, PeerAddress, PeerConfig};
use crate::hosts::HostMap;
use crate::node::acl::{PeerAclDecision, PeerAclReloader};
use crate::node::reloadable::HostMapReloadable;
use std::net::Ipv6Addr;

/// A suffix taken from a fresh npub's data part, so alias names cannot
/// collide with a hosts file on the build host.
fn suffix() -> String {
    Identity::generate().npub()[5..17].to_string()
}

/// A peer entry with an explicit address and connect policy.
fn peer_at(id: &Identity, alias: Option<&str>, addr: &str, policy: ConnectPolicy) -> PeerConfig {
    PeerConfig {
        npub: id.npub(),
        alias: alias.map(String::from),
        addresses: vec![PeerAddress::new("udp", addr)],
        connect_policy: policy,
        auto_reconnect: false,
        via_nostr: false,
    }
}

/// An on-demand peer entry on the placeholder address, which nothing dials.
fn peer(id: &Identity, alias: Option<&str>) -> PeerConfig {
    peer_at(id, alias, "127.0.0.1:9", ConnectPolicy::OnDemand)
}

/// The identity form of a test identity, as the ACL and display paths see it.
fn ident(id: &Identity) -> PeerIdentity {
    PeerIdentity::from_npub(&id.npub()).unwrap()
}

/// The node address of a test identity.
fn addr(id: &Identity) -> NodeAddr {
    *ident(id).node_addr()
}

/// Build a node from `peers`, with its host map and peer ACL rebuilt exactly
/// as construction builds them but on temp paths, and its display-name map
/// seeded as `start()` seeds it (alias or else short npub).
///
/// `allow`, `deny` and `hosts` are file contents; `None` leaves the file
/// absent. The returned directory must outlive the node.
fn alias_node(
    peers: Vec<PeerConfig>,
    allow: Option<&str>,
    deny: Option<&str>,
    hosts: Option<&str>,
) -> (tempfile::TempDir, Node) {
    let dir = tempfile::tempdir().unwrap();
    let allow_path = dir.path().join("peers.allow");
    let deny_path = dir.path().join("peers.deny");
    let hosts_path = dir.path().join("hosts");
    for (path, contents) in [
        (&allow_path, allow),
        (&deny_path, deny),
        (&hosts_path, hosts),
    ] {
        if let Some(contents) = contents {
            std::fs::write(path, contents).unwrap();
        }
    }

    let mut config = Config::new();
    config.peers = peers;
    let mut node = make_node_with(config);
    let base = || HostMap::from_peer_configs(node.config().peers());
    let host_map = HostMapReloadable::new(base(), hosts_path.clone());
    let peer_acl = PeerAclReloader::with_alias_sources(allow_path, deny_path, base(), hosts_path);
    node.host_map = host_map;
    node.peer_acl = peer_acl;

    let seeded: Vec<_> = node
        .config()
        .peers()
        .iter()
        .map(|pc| {
            let id = PeerIdentity::from_npub(&pc.npub).unwrap();
            let name = pc.alias.clone().unwrap_or_else(|| id.short_npub());
            (*id.node_addr(), name)
        })
        .collect();
    node.peer_aliases.extend(seeded);
    (dir, node)
}

/// The npub a name resolves to in the node's display host map.
fn resolved(node: &Node, name: &str) -> Option<String> {
    node.host_map.load().lookup_npub(name).map(String::from)
}

/// The ACL decision the node's authorization path would make for `id`.
fn decision(node: &Node, id: &Identity) -> PeerAclDecision {
    node.peer_acl.acl().check(&ident(id))
}

/// Aliases renamed, removed and moved by `update_peers` are reflected in the
/// display host map, in display names and in the stats snapshot, with the
/// hosts file still overlaid and winning as at startup.
#[tokio::test]
async fn update_peers_rebuilds_host_map_display_names_and_the_stats_snapshot_from_the_new_aliases()
{
    let s = suffix();
    let [a, b, c, d, e, f, g] = std::array::from_fn(|_| Identity::generate());
    let (alpha, alpha2, bravo) = (
        format!("alpha-{s}"),
        format!("alpha2-{s}"),
        format!("bravo-{s}"),
    );
    let (charlie, delta, echo) = (
        format!("charlie-{s}"),
        format!("delta-{s}"),
        format!("echo-{s}"),
    );
    let hosts = format!("{echo} {}\n{charlie} {}\n", f.npub(), g.npub());
    let (_dir, mut node) = alias_node(
        vec![
            peer(&a, Some(&alpha)),
            peer(&b, Some(&bravo)),
            peer(&d, Some(&delta)),
        ],
        None,
        None,
        Some(&hosts),
    );

    assert_eq!(resolved(&node, &alpha), Some(a.npub()), "before: alpha");
    assert_eq!(resolved(&node, &bravo), Some(b.npub()), "before: bravo");
    assert_eq!(
        resolved(&node, &echo),
        Some(f.npub()),
        "before: echo from file"
    );
    assert_eq!(node.peer_display_name(&addr(&a)), alpha, "before: A's name");
    assert_eq!(
        node.peer_aliases.get(&addr(&d)),
        Some(&delta),
        "before: D's seeded display entry"
    );
    assert_eq!(node.peer_display_name(&addr(&d)), delta, "before: D's name");

    node.update_peers(vec![
        peer(&a, Some(&alpha2)),
        peer(&c, Some(&charlie)),
        peer(&d, None),
        peer(&e, Some(&delta)),
    ])
    .await
    .unwrap();

    assert_eq!(
        resolved(&node, &alpha2),
        Some(a.npub()),
        "renamed alias resolves"
    );
    assert_eq!(resolved(&node, &alpha), None, "old name of a renamed alias");
    assert_eq!(resolved(&node, &bravo), None, "alias of a removed peer");
    assert_eq!(resolved(&node, &delta), Some(e.npub()), "moved alias");
    assert_eq!(resolved(&node, &echo), Some(f.npub()), "file entry kept");
    assert_eq!(
        resolved(&node, &charlie),
        Some(g.npub()),
        "file entry still wins over a peer alias"
    );

    let d_short = ident(&d).short_npub();
    assert_eq!(node.peer_display_name(&addr(&a)), alpha2, "renamed display");
    assert_eq!(node.peer_display_name(&addr(&e)), delta, "moved display");
    assert_eq!(
        node.peer_display_name(&addr(&d)),
        d_short,
        "a peer whose alias was removed shows its short npub"
    );

    node.record_stats_history();
    let snapshot = node.stats_snapshot.load();
    assert_eq!(
        snapshot.peer_aliases.get(&addr(&d)),
        Some(&d_short),
        "snapshot: removed alias"
    );
    assert_eq!(
        snapshot.peer_aliases.get(&addr(&a)),
        Some(&alpha2),
        "snapshot: renamed alias"
    );
}

/// A deny entry written as an alias follows the alias to its new npub: the
/// new key is refused and the old one is no longer denied.
#[tokio::test]
async fn update_peers_moves_a_deny_entry_written_as_an_alias_onto_the_new_npub() {
    let blocked = format!("blocked-{}", suffix());
    let [x, y] = std::array::from_fn(|_| Identity::generate());
    let (_dir, mut node) = alias_node(
        vec![peer(&x, Some(&blocked))],
        None,
        Some(&format!("{blocked}\n")),
        None,
    );
    assert_eq!(decision(&node, &x), PeerAclDecision::DenyList, "before: X");
    assert_eq!(
        decision(&node, &y),
        PeerAclDecision::DefaultAllow,
        "before: Y"
    );

    node.update_peers(vec![peer(&x, None), peer(&y, Some(&blocked))])
        .await
        .unwrap();

    assert_eq!(decision(&node, &y), PeerAclDecision::DenyList, "after: Y");
    assert_eq!(
        decision(&node, &x),
        PeerAclDecision::DefaultAllow,
        "after: X"
    );
}

/// Under deny `ALL`, an allow entry written as an alias follows the alias:
/// the new key is admitted and the old key falls to the deny.
#[tokio::test]
async fn update_peers_moves_an_allow_entry_written_as_an_alias_under_deny_all() {
    let trusted = format!("trusted-{}", suffix());
    let [a, b] = std::array::from_fn(|_| Identity::generate());
    let (_dir, mut node) = alias_node(
        vec![peer(&a, Some(&trusted))],
        Some(&format!("{trusted}\n")),
        Some("ALL\n"),
        None,
    );
    assert_eq!(decision(&node, &a), PeerAclDecision::AllowList, "before: A");
    assert_eq!(decision(&node, &b), PeerAclDecision::DenyList, "before: B");

    node.update_peers(vec![peer(&a, None), peer(&b, Some(&trusted))])
        .await
        .unwrap();

    assert_eq!(decision(&node, &b), PeerAclDecision::AllowList, "after: B");
    assert_eq!(decision(&node, &a), PeerAclDecision::DenyList, "after: A");
}

/// The rebuilt ACL is in force before `update_peers` dials an added peer: a
/// deny entry moved onto the added peer Y stops its dial, while a control
/// peer Z added in the same call is dialed.
#[tokio::test]
async fn update_peers_applies_the_rebuilt_acl_before_dialing_an_added_peer() {
    let blocked = format!("blocked-{}", suffix());
    let [x, y, z] = std::array::from_fn(|_| Identity::generate());
    let x_at = |alias| peer_at(&x, alias, "127.0.0.1:29", ConnectPolicy::OnDemand);
    let (_dir, mut node) = alias_node(
        vec![x_at(Some(&blocked))],
        None,
        Some(&format!("{blocked}\n")),
        None,
    );
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);
    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    node.update_peers(vec![
        x_at(None),
        peer_at(
            &y,
            Some(&blocked),
            "127.0.0.1:9",
            ConnectPolicy::AutoConnect,
        ),
        peer_at(&z, None, "127.0.0.1:19", ConnectPolicy::AutoConnect),
    ])
    .await
    .unwrap();

    let dialed: Vec<_> = node
        .connections()
        .filter_map(|(_, machine)| machine.conn_expected_identity().copied())
        .map(|id| *id.node_addr())
        .collect();
    assert_eq!(
        dialed.len(),
        1,
        "only the control peer is dialed; Y's dial must meet the moved deny entry"
    );
    assert_eq!(dialed[0], addr(&z), "the one dial is the control peer Z");

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

/// Send an AAAA query for `name` to the responder at `dns` and return the
/// address answered, or `None` for a reply without an answer. Fails if no
/// reply arrives within two seconds.
async fn query_aaaa(dns: std::net::SocketAddr, name: &str) -> Option<Ipv6Addr> {
    use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question, TYPE};
    let mut packet = Packet::new_query(0x4242);
    packet.questions.push(Question::new(
        Name::new_unchecked(name).into_owned(),
        QTYPE::TYPE(TYPE::AAAA),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    let query = packet.build_bytes_vec().unwrap();
    let client = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    client.send_to(&query, dns).await.unwrap();

    let mut buf = [0u8; 512];
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .unwrap_or_else(|_| panic!("no DNS reply for {name} within the timeout"))
        .unwrap();
    let reply = Packet::parse(&buf[..len]).expect("well-formed DNS response");
    reply.answers.first().map(|answer| match &answer.rdata {
        simple_dns::rdata::RData::AAAA(aaaa) => Ipv6Addr::from(aaaa.address),
        other => panic!("expected an AAAA record for {name}, got {other:?}"),
    })
}

/// A running DNS responder answers `.fips` alias names from the new peer
/// list after `update_peers`, through the node's real DNS start path.
#[tokio::test]
async fn update_peers_republishes_aliases_to_the_running_dns_responder() {
    let s = suffix();
    let (alpha, charlie, delta) = (
        format!("alpha-{s}"),
        format!("charlie-{s}"),
        format!("delta-{s}"),
    );
    let [a, b, c, d] = std::array::from_fn(|_| Identity::generate());
    let mut config = Config::new();
    config.transports.udp = crate::config::TransportInstances::Single(crate::config::UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    });
    config.dns.enabled = true;
    config.dns.bind_addr = Some("::1".to_string());
    config.dns.port = Some(0);
    config.peers = vec![peer(&a, Some(&alpha)), peer(&d, Some(&delta))];
    let mut node = make_node_with(config);
    node.start().await.unwrap();
    let dns = node.dns_local_addr().expect("responder is up");
    let fips = |name: &str| format!("{name}.fips");
    let v6 = |id: &Identity| id.address().to_ipv6();

    assert_eq!(
        query_aaaa(dns, &fips(&alpha)).await,
        Some(v6(&a)),
        "before: alpha"
    );
    assert_eq!(
        query_aaaa(dns, &fips(&charlie)).await,
        None,
        "before: charlie"
    );

    node.update_peers(vec![peer(&b, Some(&alpha)), peer(&c, Some(&charlie))])
        .await
        .unwrap();

    assert_eq!(
        query_aaaa(dns, &fips(&alpha)).await,
        Some(v6(&b)),
        "after: alpha moved to B"
    );
    assert_eq!(
        query_aaaa(dns, &fips(&charlie)).await,
        Some(v6(&c)),
        "after: charlie added"
    );
    assert_eq!(
        query_aaaa(dns, &fips(&delta)).await,
        None,
        "after: delta removed"
    );

    node.stop().await.unwrap();
}

/// A node with a UDP transport, a DNS responder on an ephemeral loopback
/// port and no control socket, with `peers`.
fn dns_node(peers: Vec<PeerConfig>) -> Node {
    let mut config = Config::new();
    config.node.control.enabled = false;
    config.transports.udp = crate::config::TransportInstances::Single(crate::config::UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    });
    config.dns.enabled = true;
    config.dns.bind_addr = Some("::1".to_string());
    config.dns.port = Some(0);
    config.peers = peers;
    make_node_with(config)
}

/// A responder started after `update_peers` answers for the new aliases, as
/// it did when each start read the node's peer list.
#[tokio::test]
async fn a_dns_start_after_update_peers_answers_for_the_new_aliases() {
    let alpha = format!("alpha-{}", suffix());
    let [a, b] = std::array::from_fn(|_| Identity::generate());
    let mut node = dns_node(vec![peer(&a, Some(&alpha))]);
    node.start().await.unwrap();
    node.stop().await.unwrap();

    node.update_peers(vec![peer(&b, Some(&alpha))])
        .await
        .unwrap();
    node.start().await.unwrap();
    let dns = node.dns_local_addr().expect("responder is up");
    let answer = query_aaaa(dns, &format!("{alpha}.fips")).await;
    assert_eq!(answer, Some(b.address().to_ipv6()));
    node.stop().await.unwrap();
}

/// The message logged for each peer alias the maps skip.
const SKIPPED: &str = "Skipping invalid peer alias for host map";

/// A responder's start warns about an invalid alias once, as it did when it
/// built its map from the peer list itself.
#[tokio::test]
async fn a_dns_start_warns_once_about_an_invalid_alias() {
    let a = Identity::generate();
    let mut node = dns_node(vec![peer(&a, Some("not_an_alias"))]);
    let (logs, _guard) = crate::testutil::capture_logs_scoped();
    node.start().await.unwrap();
    assert!(node.dns_local_addr().is_some(), "responder is up");
    assert_eq!(logs.lines_with(SKIPPED).len(), 1, "{:?}", logs.lines());
    node.stop().await.unwrap();
}

/// Replacing the peer list warns about an invalid alias once, from the
/// node's own maps; the running responder takes the same list quietly.
#[tokio::test]
async fn update_peers_warns_once_about_an_invalid_alias_with_the_responder_running() {
    let [a, b] = std::array::from_fn(|_| Identity::generate());
    let mut node = dns_node(vec![peer(&a, None)]);
    node.start().await.unwrap();
    assert!(node.dns_local_addr().is_some(), "responder is up");
    let (logs, _guard) = crate::testutil::capture_logs_scoped();
    node.update_peers(vec![peer(&b, Some("not_an_alias"))])
        .await
        .unwrap();
    assert_eq!(logs.lines_with(SKIPPED).len(), 1, "{:?}", logs.lines());
    node.stop().await.unwrap();
}
