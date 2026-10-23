//! The node's link to the IPv6 adapter: the attach, its replay, and the
//! node-wide and per-peer payload limits it keeps pushing.
//!
//! The adapter's copy is read the way its TUN threads read it, through the
//! state the link leaves in the adapter's handles. Every path that changes
//! the node's path MTU map is driven through its real handler, and after
//! each one the adapter's copy must equal the map.

use super::*;
use crate::LookupResponse;
use crate::ipv6tun::icmp::{effective_ipv6_mtu, mss_ceiling};
use crate::ipv6tun::link::PeerKey;
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
        .read()
        .unwrap()
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
    let keys: Vec<PeerKey> = (0..3).map(|_| PeerKey::any()).collect();
    for (i, key) in keys.iter().enumerate() {
        node.path_mtu_lookup.write().unwrap().insert(
            key.address(),
            *key,
            PathMtuEntry::held(1200 + i as u16),
        );
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
    let (kept, gone) = (PeerKey::any(), PeerKey::any());
    for key in [kept, gone] {
        node.path_mtu_lookup
            .write()
            .unwrap()
            .insert(key.address(), key, PathMtuEntry::held(1300));
    }
    node.attach_host();
    node.detach_host().await;
    node.path_mtu_lookup
        .write()
        .unwrap()
        .remove(&gone.address());
    node.attach_host();
    assert_replica(&mut node, &gone.address(), false, "a second attach");
    assert!(replica(&mut node).contains_key(&kept.address()));
}

#[tokio::test]
async fn an_adapter_without_the_tun_asks_for_no_path_feed() {
    let mut config = Config::new();
    config.tun.enabled = false;
    let mut node = make_node_with(config);
    let key = PeerKey::any();
    node.path_mtu_lookup
        .write()
        .unwrap()
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
    let key = PeerKey::new(identity.pubkey());
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
    let far = PeerKey::any();
    node.path_mtu_lookup.write().unwrap().insert(
        far.address(),
        far,
        PathMtuEntry::learned(1300, now),
    );
    // A remote-learned entry on top of a linked peer's seed: expires, and
    // the seed comes back.
    let identity = make_peer_identity();
    let peer_addr = *identity.node_addr();
    let near = PeerKey::new(identity.pubkey());
    let tid = crate::transport::TransportId::new(1);
    let transport_addr = TransportAddr::from_string("10.0.0.13:2121");
    let mut peer = crate::peer::ActivePeer::new(identity, LinkId::new(1), 0);
    peer.set_current_addr(tid, transport_addr);
    node.peers.insert(peer_addr, peer);
    node.path_mtu_lookup.write().unwrap().insert(
        near.address(),
        near,
        PathMtuEntry::learned(1280, now),
    );
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
    let gone = PeerKey::any();
    node.attach_host();
    node.supervisor.ipv6tun.run_link();
    node.path_mtu_lookup
        .write()
        .unwrap()
        .insert(gone.address(), gone, PathMtuEntry::held(1300));
    node.detach_host().await;
    node.path_mtu_lookup
        .write()
        .unwrap()
        .remove(&gone.address());
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
    let key = PeerKey::any();
    node.path_mtu_lookup
        .write()
        .unwrap()
        .insert(key.address(), key, PathMtuEntry::held(1300));
    node.path_mtu_lookup_insert(key.address(), 1200);
    assert!(!replica(&mut node).contains_key(&key.address()));
}

#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "another peer's key")]
fn a_path_mtu_entry_under_another_peers_key_is_refused() {
    let node = tun_node();
    let (addr, other) = (PeerKey::any().address(), PeerKey::any());
    node.path_mtu_lookup
        .write()
        .unwrap()
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
