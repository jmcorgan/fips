//! End-to-end tests of the app-owned TUN, the form an embedder that owns
//! the TUN file descriptor (an Android `VpnService`) uses.
//!
//! Two started nodes run their receive loops in-process. The embedder's
//! side is played by the channel pair `Node::enable_app_owned_tun`
//! returns: packets go in through the outbound sender and replies and
//! deliveries come out of the inbound receiver. Nothing else in the node is
//! reached, so these tests hold whatever carries the packet in between.

use super::*;
use std::net::Ipv6Addr;
use std::sync::mpsc::Receiver;

/// ICMPv6 Destination Unreachable type.
const DEST_UNREACHABLE: u8 = 1;
/// ICMPv6 Packet Too Big type.
const PACKET_TOO_BIG: u8 = 2;

/// A node configuration with one loopback UDP transport, the TUN enabled
/// (so only the app-owned channels keep a system device from being made),
/// and no DNS responder or control socket.
fn app_tun_config() -> Config {
    let mut config = Config::new();
    config.transports.udp = crate::config::TransportInstances::Single(crate::config::UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    });
    config.tun.enabled = true;
    config.dns.enabled = false;
    config.node.control.enabled = false;
    config
}

/// The address of the node's first UDP transport.
fn udp_addr(node: &Node) -> std::net::SocketAddr {
    node.transport_ids()
        .find_map(|id| node.get_transport(id).and_then(|t| t.local_addr()))
        .expect("the node has a bound UDP transport")
}

/// An IPv6 packet of `len` bytes, No Next Header, from `src` to `dst`.
fn ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr, len: usize) -> Vec<u8> {
    let mut packet = vec![0u8; len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
    packet[6] = 59;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&src.octets());
    packet[24..40].copy_from_slice(&dst.octets());
    for (i, byte) in packet[40..].iter_mut().enumerate() {
        *byte = i as u8;
    }
    packet
}

/// Source address of an IPv6 packet.
fn source(packet: &[u8]) -> Ipv6Addr {
    Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap())
}

/// Destination address of an IPv6 packet.
fn destination(packet: &[u8]) -> Ipv6Addr {
    Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap())
}

/// The next ICMPv6 message of `kind` on `rx` that quotes a packet sent to
/// `quoted_dst`, skipping any other packet, or `None` after `wait`.
async fn icmp_reply(
    rx: &Receiver<Vec<u8>>,
    kind: u8,
    quoted_dst: Ipv6Addr,
    wait: Duration,
) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + wait;
    while tokio::time::Instant::now() < deadline {
        while let Ok(packet) = rx.try_recv() {
            let quoted = packet.get(48..).unwrap_or_default();
            if packet.len() >= 48
                && packet[6] == 58
                && packet[40] == kind
                && quoted.len() >= 40
                && destination(quoted) == quoted_dst
            {
                return Some(packet);
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    None
}

/// An app-owned TUN carries a packet from one embedder to its peer's, and
/// answers the embedder with ICMPv6 for an address nobody resolves and for
/// a packet over the node-wide MTU.
#[tokio::test]
async fn an_app_owned_tun_carries_a_packet_to_the_peer_app_and_answers_refusals_with_icmpv6() {
    let mut node_b = Node::new(app_tun_config()).unwrap();
    let (_b_outbound, b_inbound) = node_b.enable_app_owned_tun();
    node_b.start().await.unwrap();

    let mut config_a = app_tun_config();
    config_a.peers.push(crate::config::PeerConfig::new(
        node_b.npub(),
        "udp",
        udp_addr(&node_b).to_string(),
    ));
    let mut node_a = Node::new(config_a).unwrap();
    let (a_outbound, a_inbound) = node_a.enable_app_owned_tun();
    node_a.start().await.unwrap();

    let addr_a = node_a.identity().address().to_ipv6();
    let addr_b = node_b.identity().address().to_ipv6();
    let stranger = crate::Identity::generate().address().to_ipv6();
    let node_mtu = node_a.effective_ipv6_mtu();

    let embedder = async {
        // Nobody resolves the stranger's address: Destination Unreachable,
        // from our own address, back to the sender.
        a_outbound
            .send(ipv6_packet(addr_a, stranger, 80))
            .await
            .unwrap();
        let unreachable = icmp_reply(
            &a_inbound,
            DEST_UNREACHABLE,
            stranger,
            Duration::from_secs(5),
        )
        .await
        .expect("Destination Unreachable reaches the app");
        assert_eq!(unreachable[41], 0, "code 0, no route to destination");
        assert_eq!(source(&unreachable), addr_a, "sent from our address");
        assert_eq!(destination(&unreachable), addr_a, "sent to the sender");

        // One byte over the node-wide IPv6 MTU: Packet Too Big at that MTU,
        // from the address the packet was sent to.
        a_outbound
            .send(ipv6_packet(addr_a, addr_b, node_mtu as usize + 1))
            .await
            .unwrap();
        let too_big = icmp_reply(&a_inbound, PACKET_TOO_BIG, addr_b, Duration::from_secs(5))
            .await
            .expect("Packet Too Big reaches the app");
        assert_eq!(
            u32::from_be_bytes(too_big[44..48].try_into().unwrap()),
            u32::from(node_mtu),
            "reports the node-wide IPv6 MTU",
        );
        assert_eq!(source(&too_big), addr_b, "sent from the destination");
        assert_eq!(destination(&too_big), addr_a, "sent to the sender");

        // A packet to the peer reaches the peer's app unchanged. The link
        // and session come up while it is offered, so offer it until it
        // arrives.
        let packet = ipv6_packet(addr_a, addr_b, 120);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the packet never reached the peer's app"
            );
            a_outbound.send(packet.clone()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            if std::iter::from_fn(|| b_inbound.try_recv().ok()).any(|p| p == packet) {
                break;
            }
        }
    };

    tokio::select! {
        result = node_a.run_rx_loop() => panic!("node A's rx loop exited: {result:?}"),
        result = node_b.run_rx_loop() => panic!("node B's rx loop exited: {result:?}"),
        () = embedder => {}
    }

    node_a.stop().await.unwrap();
    node_b.stop().await.unwrap();
}

/// The node's queue toward an app-owned TUN whose embedder has stopped
/// reading holds no more than `node.buffers.host_channel` packets, however
/// many more its peers send, and counts every packet it drops.
#[tokio::test]
async fn the_queue_toward_an_embedder_that_stops_reading_is_bounded() {
    const BOUND: usize = 16;
    const SENT: usize = 200;

    let mut config_b = app_tun_config();
    config_b.node.buffers.host_channel = BOUND;
    let mut node_b = Node::new(config_b).unwrap();
    let (_b_outbound, b_inbound) = node_b.enable_app_owned_tun();
    node_b.start().await.unwrap();

    let mut config_a = app_tun_config();
    config_a.peers.push(crate::config::PeerConfig::new(
        node_b.npub(),
        "udp",
        udp_addr(&node_b).to_string(),
    ));
    let mut node_a = Node::new(config_a).unwrap();
    let (a_outbound, _a_inbound) = node_a.enable_app_owned_tun();
    node_a.start().await.unwrap();

    let addr_a = node_a.identity().address().to_ipv6();
    let addr_b = node_b.identity().address().to_ipv6();

    // Packets B's embedder read before it stopped.
    let mut read = 0u64;
    let embedder = async {
        // Bring the session up: offer a packet until B's app receives it.
        let packet = ipv6_packet(addr_a, addr_b, 120);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        'up: loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "precondition: the session never came up"
            );
            a_outbound.send(packet.clone()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            while let Ok(p) = b_inbound.try_recv() {
                read += 1;
                if p == packet {
                    break 'up;
                }
            }
        }
        // B's embedder now stops reading while A keeps sending.
        for _ in 0..SENT {
            a_outbound.send(packet.clone()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    tokio::select! {
        result = node_a.run_rx_loop() => panic!("node A's rx loop exited: {result:?}"),
        result = node_b.run_rx_loop() => panic!("node B's rx loop exited: {result:?}"),
        () = embedder => {}
    }

    let queued = b_inbound.try_iter().count();
    let dropped = node_b.tun_tx().map_or(0, |tx| tx.dropped());
    // Every data packet B's session took from A went to the queue: read,
    // still queued, or dropped.
    let received = node_b
        .get_session(node_a.node_addr())
        .map_or(0, |entry| entry.traffic_counters().1);
    node_a.stop().await.unwrap();
    node_b.stop().await.unwrap();
    assert!(
        queued > 0,
        "precondition: packets reached B while its embedder was not reading"
    );
    assert!(
        queued <= BOUND,
        "{queued} packets queued after {SENT} were sent toward an embedder that stopped reading, \
         past the bound of {BOUND}"
    );
    assert!(
        dropped > 0,
        "{queued} queued and none dropped after {SENT} were sent past a bound of {BOUND}"
    );
    assert_eq!(
        read + queued as u64 + dropped,
        received,
        "the packets B took from the session ({received}) are not those read ({read}), \
         queued ({queued}) and dropped ({dropped})"
    );
}

/// With the TUN disabled in the configuration, a user may be granted port
/// 256. An embedder that then installs an app-owned TUN would have the
/// adapter serve that port too, so the node refuses to start, naming the
/// conflict, and never attaches the adapter.
#[tokio::test]
async fn an_app_owned_tun_on_a_node_that_grants_port_256_to_a_user_fails_start_unattached() {
    let mut config = app_tun_config();
    config.tun.enabled = false;
    config.node.native_api.grants = vec![crate::config::GrantConfig {
        uid: Some(0),
        ports: vec![256],
        ..Default::default()
    }];
    config
        .validate()
        .expect("precondition: the configuration loads");
    let mut node = Node::new(config).unwrap();
    let (_outbound, _inbound) = node.enable_app_owned_tun();

    let err = node
        .start()
        .await
        .expect_err("the adapter cannot have port 256");
    assert!(
        matches!(&err, NodeError::Config(_)) && err.to_string().contains("port 256"),
        "got: {err}"
    );
    assert!(
        node.supervisor.host_link.is_none(),
        "the adapter was attached"
    );
    let _ = node.stop().await;
}

/// With no grants configured, an app-owned TUN's adapter is attached
/// serving port 256 at start, as it always was.
#[tokio::test]
async fn with_no_grants_an_app_owned_tun_is_attached_serving_port_256() {
    let mut node = Node::new(app_tun_config()).unwrap();
    let (_outbound, _inbound) = node.enable_app_owned_tun();
    node.start().await.unwrap();
    assert!(
        node.supervisor.host_link.is_some(),
        "the adapter is attached"
    );
    assert_eq!(
        node.supervisor.ipv6tun.attach_request().port,
        Some(crate::ipv6tun::link::IPV6_PORT)
    );
    node.stop().await.unwrap();
}

/// Throughput of the app-owned TUN between two in-process nodes over
/// loopback UDP: packets of `FIPS_TPUT_SIZE` bytes (default 1200) pushed as
/// fast as the outbound channel takes them for `FIPS_TPUT_SECS` seconds
/// (default 3), counted at the peer's app. `FIPS_TPUT_HOSTQ` sets the peer's
/// `node.buffers.host_channel`. Prints one `TPUT` line, ending with how many
/// packets the peer's queue toward its app dropped.
#[tokio::test]
#[ignore = "a throughput measurement, run by hand"]
async fn app_owned_tun_throughput_between_two_nodes() {
    let secs: u64 = std::env::var("FIPS_TPUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let size: usize = std::env::var("FIPS_TPUT_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1200);
    let mut config_b = app_tun_config();
    if let Some(n) = std::env::var("FIPS_TPUT_HOSTQ")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        config_b.node.buffers.host_channel = n;
    }
    let mut node_b = Node::new(config_b).unwrap();
    let (_b_outbound, b_inbound) = node_b.enable_app_owned_tun();
    node_b.start().await.unwrap();
    let mut config_a = app_tun_config();
    config_a.peers.push(crate::config::PeerConfig::new(
        node_b.npub(),
        "udp",
        udp_addr(&node_b).to_string(),
    ));
    let mut node_a = Node::new(config_a).unwrap();
    let (a_outbound, _a_inbound) = node_a.enable_app_owned_tun();
    node_a.start().await.unwrap();
    let addr_a = node_a.identity().address().to_ipv6();
    let addr_b = node_b.identity().address().to_ipv6();
    let size = size.min(node_a.effective_ipv6_mtu() as usize);

    let b_tx = node_b.tun_tx().cloned();
    let embedder = async {
        let packet = ipv6_packet(addr_a, addr_b, size);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            assert!(tokio::time::Instant::now() < deadline, "no session");
            a_outbound.send(packet.clone()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            if std::iter::from_fn(|| b_inbound.try_recv().ok()).count() > 0 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        while b_inbound.try_recv().is_ok() {}
        let start = tokio::time::Instant::now();
        let end = start + Duration::from_secs(secs);
        let mut received = 0usize;
        let mut sent = 0usize;
        while tokio::time::Instant::now() < end {
            if a_outbound.try_send(packet.clone()).is_ok() {
                sent += 1;
            } else {
                tokio::task::yield_now().await;
            }
            while let Ok(p) = b_inbound.try_recv() {
                received += p.len();
            }
        }
        let elapsed = start.elapsed().as_secs_f64();
        println!(
            "TPUT size={size} secs={elapsed:.2} sent={sent} recv_pkts={} mbps={:.1} hostq_dropped={}",
            received / size,
            received as f64 * 8.0 / elapsed / 1e6,
            b_tx.as_ref().map_or(0, |tx| tx.dropped())
        );
    };
    tokio::select! {
        result = node_a.run_rx_loop() => panic!("node A's rx loop exited: {result:?}"),
        result = node_b.run_rx_loop() => panic!("node B's rx loop exited: {result:?}"),
        () = embedder => {}
    }
    node_a.stop().await.unwrap();
    node_b.stop().await.unwrap();
}
