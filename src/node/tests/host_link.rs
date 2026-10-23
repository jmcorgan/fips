//! The node's link to the IPv6 adapter: the attach, and the node-wide
//! payload limit it keeps pushing.
//!
//! The adapter's copy is read the way its TUN threads read it, through the
//! state the link leaves in the adapter's handles.

use super::*;
use crate::ipv6tun::icmp::{effective_ipv6_mtu, mss_ceiling};
use std::sync::atomic::Ordering;

/// A node with the TUN enabled, so the adapter asks for port 256.
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

#[tokio::test]
async fn the_tun_threads_start_with_the_limit_published_just_before_them() {
    let mut node = attached_node();
    with_udp(&mut node, 1452).await;
    // The Tun child publishes the live limit just before it spawns the
    // threads; the threads' inputs must already carry it.
    node.refresh_tun_mss_ceiling();
    let (ceiling, ipv6_mtu) = node.supervisor.ipv6tun.applied();
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
