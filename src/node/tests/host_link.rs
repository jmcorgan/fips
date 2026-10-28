//! The node's link to the IPv6 adapter: the attach, its replay, and the
//! node-wide and per-peer payload limits it keeps pushing.
//!
//! The adapter's copy is read the way its TUN threads read it, through the
//! state the link leaves in the adapter's handles. Every path that changes
//! the node's path MTU map is driven through its real handler, and after
//! each one the adapter's copy must equal the map.

use super::spanning_tree::{
    TestNode, cleanup_nodes, populate_all_coord_caches, process_available_packets, run_tree_test,
    verify_tree_convergence,
};
use super::*;
use crate::LookupResponse;
use crate::ipv6tun::icmp::{effective_ipv6_mtu, mss_ceiling};
use crate::ipv6tun::link::{PeerKey, any_key};
use crate::node::path_mtu::{PathMtuEntry, payload_limit};
use crate::node::session::session_at;
use crate::proto::stp::TreeCoordinate;
use std::collections::HashMap;
use std::sync::atomic::Ordering;

/// A node with the TUN enabled, so the adapter asks for the path MTU feed.
fn tun_node() -> Node {
    let mut config = Config::new();
    config.tun.enabled = true;
    config.dns.enabled = false;
    make_node_with(config)
}

/// A started-looking node: the TUN enabled and the adapter attached.
fn attached_node() -> Node {
    let mut node = tun_node();
    node.attach_host();
    node
}

/// The adapter's per-peer limits once it has applied everything queued.
fn replica(node: &mut Node) -> HashMap<crate::Ipv6Address, u16> {
    node.supervisor.ipv6tun.applied().2.read().unwrap().clone()
}

/// The node's own map in the terms the adapter holds it.
fn published(node: &Node) -> HashMap<crate::Ipv6Address, u16> {
    node.path_mtu_lookup
        .iter()
        .map(|(addr, e)| (*addr, payload_limit(e.mtu)))
        .collect()
}

/// The adapter's copy must equal the node's map, and `addr` must be in both
/// or neither as `present` says.
fn assert_replica(node: &mut Node, addr: &crate::Ipv6Address, present: bool, after: &str) {
    let replica = replica(node);
    assert_eq!(replica, published(node), "after {after}");
    assert_eq!(replica.contains_key(addr), present, "after {after}");
}

/// A node with one UDP transport of `mtu` bytes registered as transport 1.
async fn with_udp(node: &mut Node, mtu: u16) {
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);
    let (tx, _rx) = packet_channel(64);
    let mut udp = crate::transport::udp::UdpTransport::new(
        crate::transport::TransportId::new(1),
        Some("udp1".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(mtu),
            ..Default::default()
        },
        tx,
    );
    udp.start_async().await.unwrap();
    node.transports.insert(
        crate::transport::TransportId::new(1),
        crate::transport::TransportHandle::Udp(udp),
    );
}

/// Stop every transport the test registered.
async fn stop_transports(node: &mut Node) {
    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

/// An established session with MMP running, toward `remote`.
fn install_established(node: &mut Node, remote: &Identity) {
    let session = crate::node::tests::session::make_noise_session(node.identity(), remote);
    let addr = *remote.node_addr();
    let mut entry =
        crate::node::session::SessionEntry::keyed(addr, session, session_at(1000), true);
    entry.init_mmp(&node.config().node.session_mmp);
    node.sessions.insert(addr, entry);
}

/// A session this node opened toward `remote`, its handshake in flight.
fn install_initiating(node: &mut Node, remote: &Identity) {
    let entry = crate::node::session::SessionEntry::opened_for_test(
        &remote.pubkey_full(),
        node.identity().keypair(),
        session_at(1000),
    );
    node.sessions.insert(*remote.node_addr(), entry);
}

/// An `MtuExceeded` body naming `dest`, as the dispatcher hands it on.
fn mtu_exceeded(dest: &NodeAddr, reporter: &NodeAddr, mtu: u16) -> Vec<u8> {
    let mut buf = vec![0x00];
    buf.extend_from_slice(dest.as_bytes());
    buf.extend_from_slice(reporter.as_bytes());
    buf.extend_from_slice(&mtu.to_le_bytes());
    buf
}

#[tokio::test]
async fn the_attach_replays_every_entry_before_the_adapter_reads_any() {
    let mut node = tun_node();
    let keys: Vec<PeerKey> = (0..3).map(|_| any_key()).collect();
    for (i, key) in keys.iter().enumerate() {
        node.path_mtu_lookup
            .insert(key.address(), *key, PathMtuEntry::held(1200 + i as u16));
    }
    node.attach_host();
    // Nothing applied after the attach returned: the replay is in place
    // because the attach itself applied it, up to the end marker.
    let replay = node
        .supervisor
        .ipv6tun
        .mesh()
        .paths()
        .read()
        .unwrap()
        .clone();
    assert_eq!(replay, published(&node));
    assert_eq!(replay.len(), 3);
}

#[tokio::test]
async fn a_second_attach_drops_what_changed_while_detached() {
    // A stopped node can start again. An entry released between the two
    // attaches must not survive in the adapter's copy.
    let mut node = tun_node();
    let (kept, gone) = (any_key(), any_key());
    for key in [kept, gone] {
        node.path_mtu_lookup
            .insert(key.address(), key, PathMtuEntry::held(1300));
    }
    node.attach_host();
    node.detach_host().await;
    node.path_mtu_lookup.remove(&gone.address());
    node.attach_host();
    assert_replica(&mut node, &gone.address(), false, "a second attach");
    assert!(replica(&mut node).contains_key(&kept.address()));
}

#[tokio::test]
async fn an_adapter_without_the_tun_asks_for_no_path_feed() {
    let mut config = Config::new();
    config.tun.enabled = false;
    let mut node = make_node_with(config);
    let key = any_key();
    node.path_mtu_lookup
        .insert(key.address(), key, PathMtuEntry::held(1300));
    node.attach_host();
    assert!(replica(&mut node).is_empty());
}

#[tokio::test]
async fn the_adapter_copy_follows_a_link_seed_and_both_releases() {
    let mut node = attached_node();
    with_udp(&mut node, 1452).await;

    let identity = make_peer_identity();
    let peer_addr = *identity.node_addr();
    let fips_addr = crate::Ipv6Address::from_node_addr(&peer_addr);
    let key = PeerKey::from_xonly(&identity.pubkey());
    let transport_addr = TransportAddr::from_string("10.0.0.12:2121");
    let tid = crate::transport::TransportId::new(1);

    node.seed_path_mtu_for_link_peer(&peer_addr, key, tid, &transport_addr);
    assert_replica(&mut node, &fips_addr, true, "a link seed");

    // Released with no link to re-seed from: the departed-peer case.
    node.path_mtu_lookup_release(&peer_addr);
    assert_replica(
        &mut node,
        &fips_addr,
        false,
        "a release with no linked peer",
    );

    // Released while the link is up: removed, then re-seeded.
    let mut peer = crate::peer::ActivePeer::new(identity, LinkId::new(1), 0);
    peer.set_current_addr(tid, transport_addr.clone());
    node.peers.insert(peer_addr, peer);
    node.seed_path_mtu_for_link_peer(&peer_addr, key, tid, &transport_addr);
    node.path_mtu_lookup_release(&peer_addr);
    assert_replica(&mut node, &fips_addr, true, "a release that re-seeds");

    stop_transports(&mut node).await;
}

#[tokio::test]
async fn the_adapter_copy_follows_the_expiry_pass_and_its_re_seed() {
    let mut node = attached_node();
    with_udp(&mut node, 1452).await;
    let now = Node::now_ms();
    let ttl = node.config().node.cache.coord_ttl_secs * 1000;

    // A remote-learned entry for a destination with no link: expires.
    let far = any_key();
    node.path_mtu_lookup
        .insert(far.address(), far, PathMtuEntry::learned(1300, now));
    // A remote-learned entry on top of a linked peer's seed: expires, and
    // the seed comes back.
    let identity = make_peer_identity();
    let peer_addr = *identity.node_addr();
    let near = PeerKey::from_xonly(&identity.pubkey());
    let tid = crate::transport::TransportId::new(1);
    let transport_addr = TransportAddr::from_string("10.0.0.13:2121");
    let mut peer = crate::peer::ActivePeer::new(identity, LinkId::new(1), 0);
    peer.set_current_addr(tid, transport_addr);
    node.peers.insert(peer_addr, peer);
    node.path_mtu_lookup
        .insert(near.address(), near, PathMtuEntry::learned(1280, now));
    assert_replica(
        &mut node,
        &far.address(),
        true,
        "two remote-learned entries",
    );

    node.purge_expired_path_mtu(now + ttl);
    assert_replica(&mut node, &far.address(), false, "the expiry pass");
    assert_eq!(
        replica(&mut node).get(&near.address()),
        Some(&payload_limit(1452))
    );

    stop_transports(&mut node).await;
}

#[tokio::test]
async fn the_adapter_copy_follows_a_discovery_response() {
    let mut node = attached_node();
    let from = make_node_addr(0xAA);
    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let target_fips = crate::Ipv6Address::from_node_addr(&target);
    let coords = TreeCoordinate::from_addrs(vec![target, make_node_addr(0xF0)]).unwrap();
    node.register_identity(target, target_identity.pubkey_full());
    node.lookup
        .pending_lookups
        .entry(target)
        .or_insert_with(|| crate::proto::lookup::PendingLookup::new(Node::now_ms()))
        .record(802);
    let proof = target_identity.sign(&LookupResponse::proof_bytes(802, &target, &coords));
    let mut response = LookupResponse::new(802, target, coords, proof);
    response.path_mtu = 1400;

    node.handle_lookup_response(&from, &response.encode()[1..])
        .await;
    assert_eq!(node.path_mtu_lookup_get(&target_fips), Some(1400));
    assert_replica(&mut node, &target_fips, true, "a discovery response");
}

#[tokio::test]
async fn the_adapter_copy_follows_a_path_mtu_notification() {
    let mut node = attached_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_fips = crate::Ipv6Address::from_node_addr(&remote_addr);
    install_established(&mut node, &remote);

    node.handle_session_path_mtu_notification(&remote_addr, &1280u16.to_le_bytes());
    assert_eq!(node.path_mtu_lookup_get(&remote_fips), Some(1280));
    assert_replica(&mut node, &remote_fips, true, "a path MTU notification");
}

#[tokio::test]
async fn the_adapter_copy_follows_mtu_exceeded_on_an_established_and_an_initiating_session() {
    let mut node = attached_node();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    for (remote, established) in [(Identity::generate(), true), (Identity::generate(), false)] {
        let dest = *remote.node_addr();
        let dest_fips = crate::Ipv6Address::from_node_addr(&dest);
        if established {
            install_established(&mut node, &remote);
        } else {
            install_initiating(&mut node, &remote);
        }
        node.sessions
            .get_mut(&dest)
            .unwrap()
            .record_sent_wire_len(1400);
        node.handle_mtu_exceeded(&reporter, &mtu_exceeded(&dest, &reporter, 1280))
            .await;
        assert_eq!(node.path_mtu_lookup_get(&dest_fips), Some(1280));
        let what = if established {
            "MtuExceeded on an established session"
        } else {
            "MtuExceeded on a session still being opened"
        };
        assert_replica(&mut node, &dest_fips, true, what);
    }
}

#[tokio::test]
async fn the_tun_threads_start_with_the_limit_published_just_before_them() {
    let mut node = attached_node();
    with_udp(&mut node, 1452).await;
    // The Tun child publishes the live limit just before it spawns the
    // threads; the threads' inputs must already carry it.
    node.refresh_tun_mss_ceiling();
    let (ceiling, ipv6_mtu, _) = node.supervisor.ipv6tun.applied();
    assert_eq!(ceiling.load(Ordering::Relaxed), mss_ceiling(1452));
    assert_eq!(ipv6_mtu, effective_ipv6_mtu(1452));
    stop_transports(&mut node).await;
}

#[tokio::test]
async fn a_transport_change_no_site_publishes_reaches_the_adapter_within_one_tick() {
    // Started with the TUN enabled but app-owned, so no device and no Tun
    // child: nothing publishes the bound transport's MTU at start, and the
    // adapter holds the IPv6-minimum value until the first tick.
    let mut config = Config::new();
    config.transports.udp = crate::config::TransportInstances::Single(crate::config::UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1452),
        ..Default::default()
    });
    config.tun.enabled = true;
    config.dns.enabled = false;
    config.node.control.enabled = false;
    let mut node = make_node_with(config);
    let (_outbound, _inbound) = node.enable_app_owned_tun();
    node.start().await.unwrap();
    let state = node.supervisor.ipv6tun.mesh().clone();
    assert_eq!(
        state.ipv6_mtu(),
        effective_ipv6_mtu(crate::ipv6tun::tun::IPV6_MIN_MTU)
    );

    // The receive loop's first tick runs at once, so the change normally
    // lands within milliseconds; the deadline only bounds a broken run.
    let target = effective_ipv6_mtu(1452);
    let reached = async {
        while state.ipv6_mtu() != target {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::select! {
        result = node.run_rx_loop() => panic!("the rx loop exited: {result:?}"),
        within = tokio::time::timeout(Duration::from_secs(10), reached) => {
            within.expect("the adapter's IPv6 MTU never followed the bound transport");
        }
    }
    assert_eq!(state.ipv6_mtu(), target);
    assert_eq!(state.ceiling().load(Ordering::Relaxed), mss_ceiling(1452));
    node.stop().await.unwrap();
}

#[tokio::test]
async fn a_restart_applies_nothing_the_previous_start_left_queued_on_its_link() {
    // The first start's link task still holds a message when the node
    // detaches it. Nothing it held may land after the next attach has
    // replaced the adapter's copy.
    let mut node = tun_node();
    let gone = any_key();
    node.attach_host();
    node.supervisor.ipv6tun.run_link();
    node.path_mtu_lookup
        .insert(gone.address(), gone, PathMtuEntry::held(1300));
    node.detach_host().await;
    node.path_mtu_lookup.remove(&gone.address());
    node.attach_host();
    // Give a task left over from the first start every chance to run.
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert_replica(&mut node, &gone.address(), false, "a restart");
}

#[tokio::test]
async fn an_unkeyed_entry_over_a_keyed_one_releases_it_in_the_adapter_copy() {
    let mut node = attached_node();
    let key = any_key();
    node.path_mtu_lookup
        .insert(key.address(), key, PathMtuEntry::held(1300));
    node.path_mtu_lookup_insert(key.address(), 1200);
    assert!(!replica(&mut node).contains_key(&key.address()));
}

#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "another peer's key")]
fn a_path_mtu_entry_under_another_peers_key_is_refused() {
    let mut node = tun_node();
    let (addr, other) = (any_key().address(), any_key());
    node.path_mtu_lookup
        .insert(addr, other, PathMtuEntry::held(1300));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_start_attaches_the_adapter_before_it_opens_a_tun_device() {
    // The device open checks the attach in debug builds. A name longer than
    // the kernel allows makes the open itself fail on any host, privileged
    // or not, so the start continues without a TUN.
    let mut config = Config::new();
    config.transports.udp = crate::config::TransportInstances::Single(crate::config::UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    });
    config.tun.enabled = true;
    config.tun.name = Some("fips-attach-order".to_string());
    config.dns.enabled = false;
    config.node.control.enabled = false;
    let mut node = make_node_with(config);
    node.start().await.unwrap();
    assert_eq!(node.tun_state(), crate::ipv6tun::tun::TunState::Failed);
    node.stop().await.unwrap();
}

#[tokio::test]
async fn a_restart_applies_no_node_limit_the_previous_start_left_queued_on_its_link() {
    // The node-wide form of the test above: a limit pushed to the first
    // start's link task must not overwrite the one the next attach carries.
    // Nothing between the detach and the second attach yields, so a task
    // left over could only run after it.
    let mut node = tun_node();
    with_udp(&mut node, 1452).await;
    node.attach_host();
    node.supervisor.ipv6tun.run_link();
    node.publish_mtu();
    node.detach_host().await;
    let udp = node
        .transports
        .remove(&crate::transport::TransportId::new(1))
        .unwrap();
    node.publish_mtu();
    let expected = effective_ipv6_mtu(node.transport_mtu());
    assert_ne!(expected, effective_ipv6_mtu(1452), "precondition");
    node.attach_host();
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        node.supervisor.ipv6tun.mesh().ipv6_mtu(),
        expected,
        "the adapter holds the limit the second attach carried"
    );
    node.transports
        .insert(crate::transport::TransportId::new(1), udp);
    stop_transports(&mut node).await;
}

// ============================================================================
// Outbound through the link: datagrams, refusals and the identity feed
// ============================================================================

/// An IPv6 packet of `len` bytes from our address to `dst`, with a payload
/// that differs per byte.
fn host_packet(node: &Node, dst: &crate::Ipv6Address, len: usize) -> Vec<u8> {
    let mut p = vec![0u8; len];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
    p[6] = 17;
    p[7] = 64;
    p[8..24].copy_from_slice(node.identity().address().as_bytes());
    p[24..40].copy_from_slice(dst.as_bytes());
    for (i, byte) in p[40..].iter_mut().enumerate() {
        *byte = (i * 13) as u8;
    }
    p
}

/// The keys the adapter holds once it has applied everything queued.
fn adapter_keys(node: &mut Node) -> std::collections::BTreeSet<[u8; 32]> {
    node.supervisor.ipv6tun.settle();
    node.supervisor
        .ipv6tun
        .mesh()
        .keys()
        .iter()
        .map(|k| *k.bytes())
        .collect()
}

/// The x-only keys of the node's identity cache.
fn cached_keys(node: &Node) -> std::collections::BTreeSet<[u8; 32]> {
    node.identity_cache
        .values()
        .map(|(_, pk, _)| pk.x_only_public_key().0.serialize())
        .collect()
}

/// A node with the TUN enabled, a TUN channel installed, and the adapter
/// attached with the identity feed.
fn fed_node(config: Config) -> (Node, std::sync::mpsc::Receiver<Vec<u8>>) {
    let mut node = make_node_with(config);
    let rx = super::discovery::install_tun_channel(&mut node);
    node.attach_host();
    (node, rx)
}

/// The TUN-enabled configuration with an identity cache of `size`.
fn identity_config(size: usize) -> Config {
    let mut config = Config::new();
    config.tun.enabled = true;
    config.dns.enabled = false;
    config.node.cache.identity_size = size;
    config
}

#[tokio::test]
async fn the_adapter_key_map_follows_the_identity_cache_through_registration_and_eviction() {
    // The replay, each registration, and an eviction at the cache's bound,
    // with and without a session holding the key.
    let mut node = make_node_with(identity_config(3));
    let early = Identity::generate();
    node.register_identity(*early.node_addr(), early.pubkey_full());
    let _rx = super::discovery::install_tun_channel(&mut node);
    node.attach_host();
    assert_eq!(
        adapter_keys(&mut node),
        cached_keys(&node),
        "after the replay"
    );

    let held = Identity::generate();
    tokio::time::sleep(Duration::from_millis(2)).await;
    node.register_identity(*held.node_addr(), held.pubkey_full());
    install_established(&mut node, &held);
    assert_eq!(
        adapter_keys(&mut node),
        cached_keys(&node),
        "after a registration"
    );

    // Push `early` and then `held` out; `held` stays with the adapter while
    // its session holds it, `early` goes at the next sweep.
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(2)).await;
        let other = Identity::generate();
        node.register_identity(*other.node_addr(), other.pubkey_full());
    }
    assert!(!node.has_cached_identity(early.node_addr()));
    assert!(!node.has_cached_identity(held.node_addr()));
    let before_sweep = adapter_keys(&mut node);
    assert!(
        before_sweep.contains(&early.pubkey().serialize()),
        "kept until a sweep"
    );
    node.sweep_identities();
    let swept = adapter_keys(&mut node);
    let mut expected = cached_keys(&node);
    expected.insert(held.pubkey().serialize());
    assert_eq!(swept, expected, "a session's key stays, an unheld one goes");

    node.sessions.remove(held.node_addr());
    node.sweep_identities();
    assert_eq!(
        adapter_keys(&mut node),
        cached_keys(&node),
        "after the session ended"
    );
}

#[tokio::test]
async fn a_key_the_dns_responder_handed_out_survives_a_forget_decided_before_its_report() {
    // The node decides to forget a key, then the responder hands the same
    // key to the host before the node has seen that report. The forget
    // carries the number of the last report the node handled, so the
    // adapter keeps the key.
    let mut node = make_node_with(identity_config(1));
    let _rx = super::discovery::install_tun_channel(&mut node);
    node.attach_host();
    let peer = Identity::generate();
    node.register_identity(*peer.node_addr(), peer.pubkey_full());
    tokio::time::sleep(Duration::from_millis(2)).await;
    let other = Identity::generate();
    node.register_identity(*other.node_addr(), other.pubkey_full());
    assert!(!node.has_cached_identity(peer.node_addr()));

    let learner = node.supervisor.ipv6tun.learner().expect("attached");
    learner.learn(PeerKey::from_xonly(&peer.pubkey())).await;
    node.sweep_identities();
    assert!(
        adapter_keys(&mut node).contains(&peer.pubkey().serialize()),
        "a forget decided before the report must not remove the learned key"
    );

    // Once the node handles the report it registers the key again.
    let learned = node.supervisor.learned_rx.as_mut().unwrap();
    let report = learned.try_recv().expect("the report waits on the link");
    node.register_learned(report);
    assert!(node.has_cached_identity(peer.node_addr()));
}

#[tokio::test]
async fn a_learned_report_whose_key_does_not_parse_is_counted_handled_and_registers_nothing() {
    // The responder reports only keys it parsed, but a peer key holds any 32
    // bytes. A report of bytes off the curve names no node: the node must
    // not panic or register anything, and must still count the report as
    // handled, which the next forget's number shows. The first report is
    // left unhandled, so only the second can make that number cover it.
    let mut node = make_node_with(identity_config(1));
    let _rx = super::discovery::install_tun_channel(&mut node);
    node.attach_host();
    let peer = Identity::generate();
    node.register_identity(*peer.node_addr(), peer.pubkey_full());
    tokio::time::sleep(Duration::from_millis(2)).await;
    let other = Identity::generate();
    node.register_identity(*other.node_addr(), other.pubkey_full());
    assert!(!node.has_cached_identity(peer.node_addr()));

    let learner = node.supervisor.ipv6tun.learner().expect("attached");
    learner.learn(PeerKey::from_xonly(&peer.pubkey())).await;
    learner.learn(PeerKey::new([0xff; 32])).await;
    let learned = node.supervisor.learned_rx.as_mut().unwrap();
    let _unhandled = learned
        .try_recv()
        .expect("the first report waits on the link");
    let invalid = learned
        .try_recv()
        .expect("the second report waits on the link");
    assert_eq!(invalid.seq, 2);
    let cached = node.identity_cache.len();
    node.register_learned(invalid);
    assert_eq!(node.identity_cache.len(), cached, "nothing registered");
    assert!(
        adapter_keys(&mut node).contains(&peer.pubkey().serialize()),
        "the adapter holds the key the first report named"
    );

    node.sweep_identities();
    assert!(
        !adapter_keys(&mut node).contains(&peer.pubkey().serialize()),
        "the forget must carry the second report's number"
    );
}

#[tokio::test]
async fn a_packet_to_a_key_the_node_has_forgotten_but_the_adapter_has_not_is_answered_as_before() {
    // Between an eviction and the sweep that tells the adapter, the adapter
    // still sends datagrams to the key. The node resolves them exactly as
    // the TUN path did, so a destination nothing answers for is told no
    // route, byte for byte as the raw packet would have been.
    let (mut node, rx) = fed_node(identity_config(1));
    let gone = Identity::generate();
    node.register_identity(*gone.node_addr(), gone.pubkey_full());
    tokio::time::sleep(Duration::from_millis(2)).await;
    let other = Identity::generate();
    node.register_identity(*other.node_addr(), other.pubkey_full());
    assert!(adapter_keys(&mut node).contains(&gone.pubkey().serialize()));

    let packet = host_packet(&node, gone.address(), 120);
    node.handle_tun_outbound(packet.clone()).await;

    let expected = crate::ipv6tun::icmp::build_dest_unreachable(
        &packet,
        crate::ipv6tun::icmp::DestUnreachableCode::NoRoute,
        node.identity().address().to_ipv6(),
    )
    .unwrap();
    assert_eq!(super::discovery::drain_tun(&rx), vec![expected]);
    assert!(
        !node.has_cached_identity(gone.node_addr()),
        "nothing registered it"
    );

    // The node-wide size check still comes before the key is resolved, so
    // an oversized packet to the same key gets Packet Too Big at the live
    // limit, not no route.
    let ipv6_mtu = node.effective_ipv6_mtu();
    let oversized = host_packet(&node, gone.address(), usize::from(ipv6_mtu) + 1);
    node.handle_tun_outbound(oversized.clone()).await;
    assert_eq!(
        super::discovery::drain_tun(&rx),
        vec![
            crate::ipv6tun::icmp::build_packet_too_big(
                &oversized,
                u32::from(ipv6_mtu),
                gone.address().to_ipv6()
            )
            .unwrap()
        ],
        "the size check comes first"
    );
}

#[tokio::test]
async fn a_key_the_attach_replays_only_for_a_session_is_forgotten_once_the_session_ends() {
    // The attach tells the adapter of every key a session holds, cached or
    // not. One that is not cached must still leave the adapter at the first
    // sweep after its session ends, as a removed key does.
    let mut node = make_node_with(identity_config(100));
    let _rx = super::discovery::install_tun_channel(&mut node);
    let remote = Identity::generate();
    install_established(&mut node, &remote);
    node.attach_host();
    let key = remote.pubkey().serialize();
    assert!(adapter_keys(&mut node).contains(&key), "replayed at attach");
    node.sweep_identities();
    assert!(
        adapter_keys(&mut node).contains(&key),
        "kept while the session holds it"
    );

    node.sessions.remove(remote.node_addr());
    node.sweep_identities();
    assert!(!node.has_cached_identity(remote.node_addr()));
    assert!(
        !adapter_keys(&mut node).contains(&key),
        "forgotten once the session ended"
    );
}

#[test]
fn the_path_refusal_matches_the_tun_paths_packet_too_big_for_every_path_mtu_and_length() {
    // The TUN path compared the IPv6 length with
    // `path_mtu - 77` when that was below the node-wide `t - 77`, and
    // answered Packet Too Big at `path_mtu - 77`. The node now compares the
    // payload, 33 bytes shorter, with `path_mtu - 110`, and the adapter
    // answers at the limit plus 33.
    for t in [110u16, 576, 1280, 1357, 1452, 1500, 9000] {
        let limit = payload_limit(t);
        for path_mtu in 110..=u16::MAX {
            let old_path = effective_ipv6_mtu(path_mtu) as usize;
            let old_node = effective_ipv6_mtu(t) as usize;
            let boundary = old_path.max(40);
            for len in [
                40,
                boundary.saturating_sub(1).max(40),
                boundary,
                boundary + 1,
            ] {
                let old = (old_path < old_node && len > old_path).then_some(old_path as u32);
                let new =
                    super::super::handlers::host_link::path_refusal(len - 33, path_mtu, limit)
                        .map(|l| u32::from(crate::ipv6tun::mtu::ipv6_mtu(l)));
                assert_eq!(new, old, "t {t}, path MTU {path_mtu}, length {len}");
            }
        }
    }
}

/// A node with a session whose path MTU is 1000 to a fresh destination,
/// which it returns, at most one session allowed.
fn narrow_node() -> (Node, std::sync::mpsc::Receiver<Vec<u8>>, Identity) {
    let mut config = identity_config(100);
    config.node.limits.max_sessions = 1;
    let (mut node, rx) = fed_node(config);
    let narrow = Identity::generate();
    node.register_identity(*narrow.node_addr(), narrow.pubkey_full());
    install_established(&mut node, &narrow);
    node.sessions
        .get_mut(narrow.node_addr())
        .unwrap()
        .mmp_mut()
        .unwrap()
        .path_mtu
        .seed_source_mtu(1000);
    (node, rx, narrow)
}

#[tokio::test]
async fn refusals_reach_the_host_byte_for_byte_as_the_tun_path_answered_them() {
    // Through the node: the node-wide limit, a session's
    // path MTU, and a full session table, each on its own node since Packet
    // Too Big is rate limited per source.
    use crate::ipv6tun::icmp::{DestUnreachableCode, build_dest_unreachable, build_packet_too_big};

    let (mut node, rx, narrow) = narrow_node();
    let ipv6_mtu = node.effective_ipv6_mtu();
    let over_node = host_packet(&node, narrow.address(), usize::from(ipv6_mtu) + 1);
    node.handle_tun_outbound(over_node.clone()).await;
    assert_eq!(
        super::discovery::drain_tun(&rx),
        vec![
            build_packet_too_big(&over_node, u32::from(ipv6_mtu), narrow.address().to_ipv6())
                .unwrap()
        ],
        "the node-wide limit"
    );

    let (mut node, rx, narrow) = narrow_node();
    let over_path = host_packet(&node, narrow.address(), 1000 - 77 + 1);
    let fits_path = host_packet(&node, narrow.address(), 1000 - 77);
    node.handle_tun_outbound(fits_path).await;
    node.handle_tun_outbound(over_path.clone()).await;
    assert_eq!(
        super::discovery::drain_tun(&rx),
        vec![build_packet_too_big(&over_path, 1000 - 77, narrow.address().to_ipv6()).unwrap()],
        "the session's path MTU"
    );

    let (mut node, rx, _) = narrow_node();
    let crowded = Identity::generate();
    node.register_identity(*crowded.node_addr(), crowded.pubkey_full());
    let to_crowded = host_packet(&node, crowded.address(), 80);
    node.handle_tun_outbound(to_crowded.clone()).await;
    let us = node.identity().address().to_ipv6();
    assert_eq!(
        super::discovery::drain_tun(&rx),
        vec![build_dest_unreachable(&to_crowded, DestUnreachableCode::NoRoute, us).unwrap()],
        "a full session table"
    );
}

#[tokio::test]
async fn a_lookup_that_times_out_for_a_destination_evicted_while_it_waited_answers_each_held_packet()
 {
    // The held queue keeps the key it was sent to, so its packets are
    // answered even after the identity cache let the entry go.
    let (mut node, rx) = fed_node(identity_config(1));
    let target = Identity::generate();
    node.register_identity(*target.node_addr(), target.pubkey_full());
    let first = host_packet(&node, target.address(), 60);
    let second = host_packet(&node, target.address(), 70);
    node.handle_tun_outbound(first.clone()).await;
    node.handle_tun_outbound(second.clone()).await;
    assert_eq!(node.pending_tun_total_packets(), 2, "held behind discovery");
    assert!(super::discovery::drain_tun(&rx).is_empty());

    let other = Identity::generate();
    tokio::time::sleep(Duration::from_millis(2)).await;
    node.register_identity(*other.node_addr(), other.pubkey_full());
    assert!(!node.has_cached_identity(target.node_addr()));

    // A lookup sent at time 0 times out finally at 15 s.
    node.lookup.pending_lookups.insert(
        *target.node_addr(),
        crate::proto::lookup::PendingLookup::new(0),
    );
    for at in [1_100, 3_100, 7_100, 15_100] {
        node.check_pending_lookups(at).await;
    }
    assert!(node.lookup.pending_lookups.is_empty(), "timed out");

    use crate::ipv6tun::icmp::{DestUnreachableCode, build_dest_unreachable};
    let us = node.identity().address().to_ipv6();
    assert_eq!(
        super::discovery::drain_tun(&rx),
        vec![
            build_dest_unreachable(&first, DestUnreachableCode::NoRoute, us).unwrap(),
            build_dest_unreachable(&second, DestUnreachableCode::NoRoute, us).unwrap(),
        ]
    );
}

/// A started-ready configuration: the TUN enabled for an app-owned TUN, one
/// loopback UDP transport, no DNS responder and no control socket.
fn app_config() -> Config {
    let mut config = identity_config(100);
    config.transports.udp = crate::config::TransportInstances::Single(crate::config::UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    });
    config.node.control.enabled = false;
    config
}

#[tokio::test]
async fn a_packet_to_a_name_the_responder_just_resolved_is_held_even_when_it_overtakes_the_report()
{
    // The first-packet race: the responder has handed the host a key and
    // reported it, and the host's packet reaches the node's receive loop
    // before the report does. The node must hold the packet behind
    // discovery, not answer it with no route.
    let mut node = make_node_with(app_config());
    let (app_outbound, app_inbound) = node.enable_app_owned_tun();
    node.start().await.unwrap();
    let peer = Identity::generate();
    let learner = node.supervisor.ipv6tun.learner().expect("attached");
    learner.learn(PeerKey::from_xonly(&peer.pubkey())).await;
    app_outbound
        .send(host_packet(&node, peer.address(), 80))
        .await
        .unwrap();

    // Both are waiting when the receive loop starts; the packet's arm is
    // polled first.
    let _ = tokio::time::timeout(Duration::from_millis(300), node.run_rx_loop()).await;

    let answers: Vec<Vec<u8>> = std::iter::from_fn(|| app_inbound.try_recv().ok()).collect();
    assert!(
        answers.is_empty(),
        "the packet must not be answered: {answers:?}"
    );
    assert!(node.has_cached_identity(peer.node_addr()));
    assert_eq!(node.pending_tun_total_packets(), 1, "held behind discovery");
    node.stop().await.unwrap();
}

#[tokio::test]
async fn a_datagram_from_the_system_tun_reader_to_a_name_just_resolved_is_held_even_when_it_overtakes_the_report()
 {
    // The same race on the system TUN path, where the reader thread runs the
    // host half and sends the datagram on the link. The test stands in for
    // the reader: it runs the adapter's host half on the packet and sends
    // the datagram on the link's datagram channel, then the receive loop
    // finds the datagram and the report both waiting, the datagram's arm
    // first.
    let mut node = make_node_with(app_config());
    let (_app_outbound, app_inbound) = node.enable_app_owned_tun();
    node.start().await.unwrap();
    let peer = Identity::generate();
    let learner = node.supervisor.ipv6tun.learner().expect("attached");
    learner.learn(PeerKey::from_xonly(&peer.pubkey())).await;
    let datagram = node
        .supervisor
        .ipv6tun
        .outbound(&host_packet(&node, peer.address(), 80))
        .expect("the adapter names the key the responder recorded");
    let datagrams = node.supervisor.ipv6tun.datagram_sender().expect("attached");
    datagrams.send(datagram).await.unwrap();

    let _ = tokio::time::timeout(Duration::from_millis(300), node.run_rx_loop()).await;

    let answers: Vec<Vec<u8>> = std::iter::from_fn(|| app_inbound.try_recv().ok()).collect();
    assert!(
        answers.is_empty(),
        "the datagram must not be answered: {answers:?}"
    );
    assert!(node.has_cached_identity(peer.node_addr()));
    assert_eq!(node.pending_tun_total_packets(), 1, "held behind discovery");
    node.stop().await.unwrap();
}

#[tokio::test]
async fn a_send_to_a_cached_key_initiates_with_the_parity_the_cache_holds() {
    // The key in the cache, not its even-parity lift.
    let (mut node, _rx) = fed_node(identity_config(100));
    let dest = (1u8..=64)
        .map(|n| {
            let mut secret = [0u8; 32];
            secret[31] = n;
            Identity::from_secret_bytes(&secret).unwrap()
        })
        .find(|id| id.pubkey_full().x_only_public_key().1 == secp256k1::Parity::Odd)
        .unwrap();
    node.register_identity(*dest.node_addr(), dest.pubkey_full());
    // A direct peer, so the destination has a route and the initiation
    // registers the key it is given before it opens the session (with no
    // route it fails before registering anything). The open itself fails
    // here, with no transport, which does not matter.
    let link = crate::transport::LinkId::new(1);
    let mut peer =
        crate::peer::ActivePeer::new(crate::PeerIdentity::from_pubkey(dest.pubkey()), link, 0);
    peer.touch(1);
    node.peers.insert(*dest.node_addr(), peer);
    node.handle_tun_outbound(host_packet(&node, dest.address(), 80))
        .await;

    let prefix = dest.node_addr().prefix();
    let (_, cached) = node.lookup_by_fips_prefix(&prefix).unwrap();
    assert_eq!(cached, dest.pubkey_full(), "the cached parity is kept");
}

#[tokio::test]
async fn a_packet_sent_once_the_adapter_has_applied_a_new_key_is_forwarded() {
    // Until the adapter applies the key the node pushed, it answers no
    // route itself: the one channel hop a new key takes to reach it.
    let (mut node, rx) = fed_node(identity_config(100));
    let dest = Identity::generate();
    let packet = host_packet(&node, dest.address(), 80);
    assert!(
        node.supervisor.ipv6tun.outbound(&packet).is_none(),
        "unknown to the adapter: answered there"
    );
    assert_eq!(super::discovery::drain_tun(&rx).len(), 1);

    node.register_identity(*dest.node_addr(), dest.pubkey_full());
    node.handle_tun_outbound(packet).await;
    assert!(super::discovery::drain_tun(&rx).is_empty(), "not answered");
    assert_eq!(node.pending_tun_total_packets(), 1, "held behind discovery");
}

#[tokio::test]
async fn at_start_a_packet_to_a_configured_peer_is_held_not_answered() {
    // The attach replays the keys peer connect registered,
    // before the receive loop runs.
    let peer = Identity::generate();
    let mut config = app_config();
    config.peers.push(crate::config::PeerConfig::new(
        peer.npub(),
        "udp",
        "127.0.0.1:9".to_string(),
    ));
    let mut node = make_node_with(config);
    let (app_outbound, app_inbound) = node.enable_app_owned_tun();
    node.start().await.unwrap();
    app_outbound
        .send(host_packet(&node, peer.address(), 80))
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_millis(300), node.run_rx_loop()).await;
    let answers: Vec<Vec<u8>> = std::iter::from_fn(|| app_inbound.try_recv().ok()).collect();
    assert!(
        answers.is_empty(),
        "the packet must not be answered: {answers:?}"
    );
    node.stop().await.unwrap();
}

#[tokio::test]
async fn a_lower_limit_the_adapter_has_not_applied_is_enforced_by_the_node_at_the_live_value() {
    // The adapter still judges by the last published limit; the node checks
    // the live one, so a decrease is answered exactly as the TUN path did.
    let (mut node, rx) = fed_node(identity_config(100));
    with_udp(&mut node, 1000).await;
    let dest = Identity::generate();
    node.register_identity(*dest.node_addr(), dest.pubkey_full());
    node.supervisor.ipv6tun.settle();
    let live = node.effective_ipv6_mtu();
    assert_eq!(live, 1000 - 77);
    assert!(
        node.supervisor.ipv6tun.mesh().ipv6_mtu() > live,
        "precondition: stale"
    );

    let packet = host_packet(&node, dest.address(), usize::from(live) + 1);
    let datagram = node
        .supervisor
        .ipv6tun
        .outbound(&packet)
        .expect("the adapter lets it through");
    node.handle_datagram(datagram).await;
    assert_eq!(
        super::discovery::drain_tun(&rx),
        vec![
            crate::ipv6tun::icmp::build_packet_too_big(
                &packet,
                u32::from(live),
                dest.address().to_ipv6()
            )
            .unwrap()
        ]
    );
    stop_transports(&mut node).await;
}

#[tokio::test]
async fn a_lower_limit_the_adapter_has_not_applied_answers_an_unknown_destination_as_unreachable() {
    // A packet to a destination the adapter cannot name, between a lowered
    // live limit and the limit the adapter last applied, is answered
    // Destination Unreachable where the TUN path answered Packet Too Big at
    // the live limit, until the next tick or datagram publishes the new
    // limit.
    let (mut node, rx) = fed_node(identity_config(100));
    with_udp(&mut node, 1000).await;
    node.supervisor.ipv6tun.settle();
    let live = node.effective_ipv6_mtu();
    assert!(
        node.supervisor.ipv6tun.mesh().ipv6_mtu() > live,
        "precondition: stale"
    );
    let stranger = Identity::generate();
    let packet = host_packet(&node, stranger.address(), usize::from(live) + 1);

    assert!(node.supervisor.ipv6tun.outbound(&packet).is_none());
    let replies = super::discovery::drain_tun(&rx);
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0][40], 1, "Destination Unreachable");

    node.publish_mtu();
    assert!(node.supervisor.ipv6tun.outbound(&packet).is_none());
    let replies = super::discovery::drain_tun(&rx);
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0][40], 2, "Packet Too Big once the adapter has it");
    assert_eq!(
        u32::from_be_bytes(replies[0][44..48].try_into().unwrap()),
        u32::from(live)
    );
    stop_transports(&mut node).await;
}

#[tokio::test]
async fn a_higher_limit_the_adapter_has_not_applied_is_used_for_a_destination_it_knows() {
    // Until the adapter applies a raised limit, it still sends a packet to a
    // destination it knows to the node, which judges it by the live limit
    // as the TUN path did.
    let (mut node, rx) = fed_node(identity_config(100));
    with_udp(&mut node, 1500).await;
    let dest = Identity::generate();
    node.register_identity(*dest.node_addr(), dest.pubkey_full());
    node.supervisor.ipv6tun.settle();
    let stale = node.supervisor.ipv6tun.mesh().ipv6_mtu();
    assert!(node.effective_ipv6_mtu() > stale, "precondition: stale");

    let packet = host_packet(&node, dest.address(), usize::from(stale) + 1);
    let datagram = node
        .supervisor
        .ipv6tun
        .outbound(&packet)
        .expect("sent to the node");
    node.handle_datagram(datagram).await;
    assert!(super::discovery::drain_tun(&rx).is_empty(), "not refused");
    assert_eq!(node.pending_tun_total_packets(), 1, "held behind discovery");
    stop_transports(&mut node).await;
}

#[tokio::test]
async fn a_higher_limit_the_adapter_has_not_applied_answers_an_unknown_destination_at_the_last_published_value()
 {
    // A packet to a destination the adapter cannot name, between the limit
    // it last applied and a raised live limit, is answered Packet Too Big at
    // the old limit where the TUN path answered Destination Unreachable,
    // until the next tick or datagram publishes the new limit.
    let (mut node, rx) = fed_node(identity_config(100));
    with_udp(&mut node, 1500).await;
    node.supervisor.ipv6tun.settle();
    let stale = node.supervisor.ipv6tun.mesh().ipv6_mtu();
    assert!(node.effective_ipv6_mtu() > stale, "precondition: stale");
    let stranger = Identity::generate();
    let packet = host_packet(&node, stranger.address(), usize::from(stale) + 1);

    assert!(node.supervisor.ipv6tun.outbound(&packet).is_none());
    let replies = super::discovery::drain_tun(&rx);
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0][40], 2, "Packet Too Big");
    assert_eq!(
        u32::from_be_bytes(replies[0][44..48].try_into().unwrap()),
        u32::from(stale)
    );

    node.publish_mtu();
    assert!(node.supervisor.ipv6tun.outbound(&packet).is_none());
    assert_eq!(
        super::discovery::drain_tun(&rx)[0][40],
        1,
        "Destination Unreachable once the adapter has the live limit"
    );
    stop_transports(&mut node).await;
}

#[tokio::test]
async fn the_tick_tells_the_adapter_to_forget_an_evicted_key_no_session_holds() {
    // The sweep runs on every tick of the receive loop; the first tick fires
    // at once.
    let mut config = app_config();
    config.node.cache.identity_size = 1;
    let mut node = make_node_with(config);
    let (_app_outbound, _app_inbound) = node.enable_app_owned_tun();
    node.start().await.unwrap();
    let gone = Identity::generate();
    node.register_identity(*gone.node_addr(), gone.pubkey_full());
    tokio::time::sleep(Duration::from_millis(2)).await;
    let kept = Identity::generate();
    node.register_identity(*kept.node_addr(), kept.pubkey_full());
    let state = node.supervisor.ipv6tun.mesh().clone();
    let gone_key = PeerKey::from_xonly(&gone.pubkey());
    let kept_key = PeerKey::from_xonly(&kept.pubkey());

    // Both keys reach the adapter before the receive loop, and so before
    // any sweep, runs; otherwise the wait below could pass on a key that
    // had not arrived yet.
    let told = async {
        while !(state.keys().contains(&gone_key) && state.keys().contains(&kept_key)) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(10), told)
        .await
        .expect("the adapter was never told of both keys");

    let forgotten = async {
        while state.keys().contains(&gone_key) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::select! {
        result = node.run_rx_loop() => panic!("the rx loop exited: {result:?}"),
        within = tokio::time::timeout(Duration::from_secs(10), forgotten) => {
            within.expect("the adapter never forgot the evicted key");
        }
    }
    assert!(state.keys().contains(&kept_key));
    node.stop().await.unwrap();
}

/// Process packets on every node until two rounds in a row find none.
async fn settle_all(nodes: &mut [TestNode]) {
    let mut idle = 0;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if process_available_packets(nodes).await == 0 {
            idle += 1;
            if idle >= 2 {
                break;
            }
        } else {
            idle = 0;
        }
    }
}

/// A chain of `n` nodes in a line with the first node's session to the
/// last established through the others.
async fn chain_with_session(n: usize) -> Vec<TestNode> {
    let edges: Vec<(usize, usize)> = (1..n).map(|i| (i - 1, i)).collect();
    let mut nodes = run_tree_test(n, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    let last = *nodes[n - 1].node.node_addr();
    let last_key = nodes[n - 1].node.identity().pubkey_full();
    nodes[0]
        .node
        .initiate_session(last, last_key)
        .await
        .unwrap();
    settle_all(&mut nodes).await;
    assert!(
        nodes[0]
            .node
            .get_session(&last)
            .is_some_and(|s| s.is_established()),
        "precondition: the first node's session to the last is established"
    );
    nodes
}

/// A chain A—B—C with A's session to C established through B, and B
/// marking everything it forwards Congestion Experienced, as a transport
/// that drops does.
async fn congested_chain() -> Vec<TestNode> {
    let mut nodes = chain_with_session(3).await;
    nodes[1].node.transport_drops.insert(
        crate::transport::TransportId::new(1),
        crate::node::TransportDropState {
            prev_drops: 100,
            dropping: true,
        },
    );
    nodes
}

/// An ECT(0) IPv6 packet from `src` to `dst` with a 16-byte payload.
fn ect_packet(src: &crate::Ipv6Address, dst: &crate::Ipv6Address) -> Vec<u8> {
    let mut packet = vec![0u8; 56];
    packet[0] = 0x60;
    packet[1] = 0x20;
    packet[5] = 16;
    packet[6] = 59;
    packet[7] = 64;
    packet[8..24].copy_from_slice(src.as_bytes());
    packet[24..40].copy_from_slice(dst.as_bytes());
    packet
}

/// Send `packet`, compressed, from `nodes[from]` to `nodes[to]` on the IPv6
/// port.
async fn send_ipv6(nodes: &mut [TestNode], from: usize, to: usize, packet: &[u8]) {
    let dest = *nodes[to].node.node_addr();
    nodes[from]
        .node
        .send_session_data(
            &dest,
            256,
            256,
            &crate::ipv6tun::ipv6_shim::compress_ipv6(packet).unwrap(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn a_datagram_marked_congestion_experienced_reaches_the_host_marked_and_is_counted() {
    let mut nodes = congested_chain().await;
    let a_addr = *nodes[0].node.node_addr();
    let c_addr = *nodes[2].node.node_addr();
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[2].node.install_tun(tun_tx);
    let before = nodes[2].node.metrics().congestion.ce_received.get();

    let sent = ect_packet(
        &crate::Ipv6Address::from_node_addr(&a_addr),
        &crate::Ipv6Address::from_node_addr(&c_addr),
    );
    send_ipv6(&mut nodes, 0, 2, &sent).await;
    settle_all(&mut nodes).await;

    let delivered: Vec<Vec<u8>> = tun_rx.try_iter().collect();
    assert_eq!(delivered.len(), 1, "the packet reaches C's host");
    assert_eq!(delivered[0][1] & 0x30, 0x30, "and arrives marked CE");
    assert_eq!(&delivered[0][2..], &sent[2..], "with nothing else changed");
    assert_eq!(
        nodes[2].node.metrics().congestion.ce_received.get(),
        before + 1
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_datagram_marked_congestion_experienced_that_holds_no_packet_is_counted_and_not_delivered()
 {
    let mut nodes = congested_chain().await;
    let c_addr = *nodes[2].node.node_addr();
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[2].node.install_tun(tun_tx);
    let before = nodes[2].node.metrics().congestion.ce_received.get();

    nodes[0]
        .node
        .send_session_data(&c_addr, 256, 256, &[0x60, 1, 2])
        .await
        .unwrap();
    settle_all(&mut nodes).await;

    assert_eq!(tun_rx.try_iter().count(), 0, "nothing reaches C's host");
    assert_eq!(
        nodes[2].node.metrics().congestion.ce_received.get(),
        before + 1,
        "the marked datagram is counted as it arrives"
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn ipv6_traffic_to_a_node_with_no_tun_touches_no_native_counter_or_flow() {
    let mut nodes = congested_chain().await;
    let a_addr = *nodes[0].node.node_addr();
    let c_addr = *nodes[2].node.node_addr();
    let native = format!("{:?}", nodes[2].node.metrics().native.snapshot());
    let before = nodes[2].node.metrics().congestion.ce_received.get();

    let sent = ect_packet(
        &crate::Ipv6Address::from_node_addr(&a_addr),
        &crate::Ipv6Address::from_node_addr(&c_addr),
    );
    send_ipv6(&mut nodes, 0, 2, &sent).await;
    settle_all(&mut nodes).await;

    assert_eq!(
        format!("{:?}", nodes[2].node.metrics().native.snapshot()),
        native,
        "no native counter moves"
    );
    assert_eq!(nodes[2].node.native_registry_for_test().flow_count(), 0);
    assert_eq!(nodes[2].node.native_registry_for_test().port_count(), 0);
    assert_eq!(
        nodes[2].node.metrics().congestion.ce_received.get(),
        before + 1,
        "a marked datagram is counted with no TUN, as it always was"
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_delivery_and_then_a_refusal_reach_the_host_in_the_order_the_node_made_them() {
    // Node 1's host is handed node 0's datagram while the receive path
    // handles it, then has its own oversized packet to node 0 refused. Both
    // are written toward the host where they are decided, so the host reads
    // them in that order with nothing run in between.
    let mut nodes = chain_with_session(2).await;
    let node0 = crate::Ipv6Address::from_node_addr(nodes[0].node.node_addr());
    let node1 = crate::Ipv6Address::from_node_addr(nodes[1].node.node_addr());
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[1].node.install_tun(tun_tx);
    // Attach now, with the identity feed, so the refused packet below names
    // a key the adapter holds and reaches the node.
    nodes[1]
        .node
        .handle_tun_outbound(ect_packet(&node1, &node0))
        .await;
    settle_all(&mut nodes).await;
    let _ = tun_rx.try_iter().count();
    let _ = std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok()).count();

    let sent = ect_packet(&node0, &node1);
    send_ipv6(&mut nodes, 0, 1, &sent).await;
    let frames: Vec<_> = std::iter::from_fn(|| nodes[1].packet_rx.try_recv().ok()).collect();
    assert!(!frames.is_empty(), "node 0's datagram is waiting at node 1");
    for frame in frames {
        nodes[1].node.handle_encrypted_frame(frame).await;
    }
    let mtu = nodes[1].node.effective_ipv6_mtu() as usize;
    let mut oversized = vec![0u8; mtu + 1];
    oversized[..40].copy_from_slice(&ect_packet(&node1, &node0)[..40]);
    oversized[4..6].copy_from_slice(&((mtu + 1 - 40) as u16).to_be_bytes());
    nodes[1].node.handle_tun_outbound(oversized).await;
    // Anything the node had left to run later gets its chance here.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let at_host: Vec<Vec<u8>> = tun_rx.try_iter().collect();
    assert_eq!(
        at_host.len(),
        2,
        "a delivery and an answer, got {at_host:?}"
    );
    assert_eq!(at_host[0], sent, "the delivery first");
    assert_eq!(
        (at_host[1][6], at_host[1][40]),
        (58, 2),
        "then the Packet Too Big answer"
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_delivery_toward_a_host_that_has_gone_logs_the_closed_queue() {
    let mut nodes = chain_with_session(2).await;
    let node0 = crate::Ipv6Address::from_node_addr(nodes[0].node.node_addr());
    let node1 = crate::Ipv6Address::from_node_addr(nodes[1].node.node_addr());
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[1].node.install_tun(tun_tx);
    drop(tun_rx);

    let (capture, _guard) = crate::testutil::capture_logs_scoped();
    send_ipv6(&mut nodes, 0, 1, &ect_packet(&node0, &node1)).await;
    settle_all(&mut nodes).await;
    assert!(
        capture
            .line("Failed to deliver decompressed IPv6 packet to TUN")
            .is_some(),
        "got: {:?}",
        capture.lines()
    );
    cleanup_nodes(&mut nodes).await;
}

/// The adapter is handed the node's TUN and DNS sections, both queue sizes
/// it reads, the control socket path and the aliases of the peers that have
/// one, as configured.
#[test]
fn the_adapter_settings_are_the_node_configuration_it_reads() {
    let a = Identity::generate();
    let peer = |id: &Identity, alias: Option<&str>| crate::config::PeerConfig {
        npub: id.npub(),
        alias: alias.map(String::from),
        ..Default::default()
    };
    let mut config = Config::new();
    config.tun.name = Some("mesh9".to_string());
    config.dns.port = Some(5399);
    config.node.buffers.host_channel = 77;
    config.node.buffers.tun_channel = 11;
    config.node.control.socket_path = "/run/x/node.sock".to_string();
    config.peers = vec![peer(&a, Some("alpha")), peer(&Identity::generate(), None)];

    let settings = crate::node::adapter_settings(&config);
    assert_eq!(settings.tun.name(), "mesh9");
    assert_eq!(settings.dns.port(), 5399);
    assert_eq!(settings.host_channel, 77);
    assert_eq!(settings.tun_channel, 11);
    assert_eq!(settings.control, "/run/x/node.sock");
    assert_eq!(
        settings.aliases,
        vec![crate::ipv6tun::config::Alias {
            name: "alpha".to_string(),
            npub: a.npub(),
        }]
    );
}

/// The IPv6-minimum warning is owed once each time the transports newly fall
/// short while a TUN is up: not before a TUN is up, not again while they
/// stay short, and again after they recover and fall short anew.
#[test]
fn the_ipv6_minimum_watch_warns_once_per_fall_short_while_a_tun_is_up_and_never_while_idle() {
    use crate::node::handlers::host_link::ShortWatch::{Clear, Idle, Warned};
    // (state, short, next state, warn)
    let table = [
        (Idle, false, Idle, false),
        (Idle, true, Idle, false),
        (Clear, false, Clear, false),
        (Clear, true, Warned, true),
        (Warned, true, Warned, false),
        (Warned, false, Clear, false),
    ];
    for (state, short, next, warn) in table {
        assert_eq!(
            state.judge(short),
            (next, warn),
            "{state:?} judged short={short}"
        );
    }

    // The same rules through the node's feed, as a run of changes.
    let feed = crate::node::handlers::host_link::NodeMtuFeed::new();
    let warned: Vec<bool> = [true, true]
        .iter()
        .map(|short| feed.judge_short(*short))
        .collect();
    assert_eq!(warned, [false, false], "no TUN is up yet, so nothing warns");
    feed.arm_short();
    let warned: Vec<bool> = [true, true, false, true, true]
        .iter()
        .map(|short| feed.judge_short(*short))
        .collect();
    assert_eq!(
        warned,
        [true, false, false, true, false],
        "warn at each fall short, once"
    );
    feed.idle_short();
    assert!(!feed.judge_short(true), "an idle watch does not warn");
}
