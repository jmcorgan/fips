//! The msg1 ceiling on a handshake that an mDNS discovery result directs: a
//! node must not send more than 6 msg1 in one such attempt to a node it is
//! not configured to dial, its first transmission and its resends together
//! (FRC-1201, Section 3.1). A dial to a configured peer keeps the configured
//! resend count, at whatever address it is made.
//!
//! The target is a bare UDP socket on loopback standing in for the address
//! an advert named, which never answers, so every msg1 the attempt sends is
//! counted there.

use super::bootstrap::{
    LAN_TEST_IF, lan_node_with, loopback_prefix, on_demand_peer, stop_transports,
};
use super::*;
use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG1};
use tokio::net::UdpSocket;

/// `DISCOVERY_MSG1_PER_ATTEMPT` (FRC-1201, Section 3.5).
const MSG1_PER_ATTEMPT: usize = 6;

/// Take every datagram queued at `sock` and count the msg1s among them.
fn take_msg1s(sock: &UdpSocket) -> usize {
    let mut buf = [0u8; 2048];
    let mut count = 0;
    while let Ok((n, _)) = sock.try_recv_from(&mut buf) {
        if CommonPrefix::parse(&buf[..n]).is_some_and(|p| p.phase == PHASE_MSG1) {
            count += 1;
        }
    }
    count
}

/// One mDNS advert naming `npub` at `addr` on the tests' interface.
fn advert(npub: String, addr: std::net::SocketAddr) -> crate::mdns::LanEvent {
    crate::mdns::LanEvent::Discovered(crate::mdns::LanDiscoveredPeer {
        npub,
        scope: None,
        addr,
        interfaces: vec![LAN_TEST_IF],
        observed_at: std::time::Instant::now(),
    })
}

/// Build a LAN node from `config`, let one mDNS advert for `npub` at a
/// silent loopback socket start a handshake, and drive the node's handshake
/// timers once a second through 29 s, inside the 30 s handshake timeout, so
/// only the one attempt is counted. Returns the msg1s the socket received.
async fn msg1s_of_one_discovery_attempt(config: Config, npub: String) -> usize {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = sock.local_addr().unwrap();
    let mut node = lan_node_with(config).await;
    let before = node.connection_count();
    node.handle_lan_events(vec![advert(npub, target)], &loopback_prefix())
        .await;
    assert_eq!(
        node.connection_count(),
        before + 1,
        "control: the advert started one handshake"
    );

    let start = Node::now_ms();
    let mut count = 0;
    for s in 0..=29u64 {
        node.drive_peer_timers(start + s * 1_000).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        count += take_msg1s(&sock);
    }
    stop_transports(&mut node).await;
    count
}

/// A configuration allowing ten msg1 resends one second apart.
fn ten_resends() -> Config {
    let mut config = Config::new();
    config.node.rate_limit.handshake_max_resends = 10;
    config.node.rate_limit.handshake_resend_backoff = 1.0;
    config
}

/// With ten resends configured, one second apart, one attempt an advert
/// directs at a node this node is not configured to dial sends at most six
/// msg1.
#[tokio::test]
async fn a_discovery_directed_attempt_sends_at_most_six_msg1_even_with_ten_resends_configured() {
    let npub = make_peer_identity().npub();
    let sent = msg1s_of_one_discovery_attempt(ten_resends(), npub).await;
    assert!(
        sent <= MSG1_PER_ATTEMPT,
        "one discovery-directed attempt sent {sent} msg1, past the ceiling of {MSG1_PER_ATTEMPT}"
    );
}

/// Healthy path, and the control that the counter sees resends at all: at
/// the stock settings one attempt sends more than one msg1 and no more than
/// six.
#[tokio::test]
async fn at_stock_settings_a_discovery_directed_attempt_resends_its_msg1_and_stays_within_six() {
    let npub = make_peer_identity().npub();
    let sent = msg1s_of_one_discovery_attempt(Config::new(), npub).await;
    assert!(
        (2..=MSG1_PER_ATTEMPT).contains(&sent),
        "stock settings: one attempt sent {sent} msg1"
    );
}

/// The cap is for nodes this node is not configured to dial: a configured
/// peer dialled at the address an advert gave keeps the ten configured
/// resends, so its attempt sends more than six msg1.
#[tokio::test]
async fn a_configured_peer_dialled_at_an_mdns_address_keeps_the_configured_resend_count() {
    let npub = make_peer_identity().npub();
    let mut config = ten_resends();
    config.peers = vec![on_demand_peer(npub.clone())];
    let sent = msg1s_of_one_discovery_attempt(config, npub).await;
    assert!(
        sent > MSG1_PER_ATTEMPT,
        "a configured peer's attempt at an advertised address sent {sent} msg1, \
         so the discovery cap reached a configured dial"
    );
}

/// The dial an advert starts toward a node this node is not configured to
/// dial is marked as such, so the retransmit driver caps it; the dial an
/// advert starts toward a configured peer is not.
#[tokio::test]
async fn an_mdns_dial_to_an_unconfigured_node_is_marked_as_such_and_a_configured_one_is_not() {
    use crate::peer::machine::DialOrigin;

    let stranger = make_peer_identity();
    let friend = make_peer_identity();
    let mut config = Config::new();
    config.peers = vec![on_demand_peer(friend.npub())];
    let socks = [
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    ];
    let mut node = lan_node_with(config).await;
    let adverts = vec![
        advert(stranger.npub(), socks[0].local_addr().unwrap()),
        advert(friend.npub(), socks[1].local_addr().unwrap()),
    ];
    node.handle_lan_events(adverts, &loopback_prefix()).await;
    let origin_of = |peer: &PeerIdentity| {
        node.dials_in_flight()
            .find(|dial| dial.peer == *peer.node_addr())
            .map(|dial| dial.origin)
    };
    assert_eq!(origin_of(&stranger), Some(DialOrigin::MdnsAdvert));
    assert_eq!(origin_of(&friend), Some(DialOrigin::Addressed));
    stop_transports(&mut node).await;
}
