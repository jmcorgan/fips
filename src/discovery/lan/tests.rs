use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::Identity;
use mdns_sd::ScopedIp;

use super::{LanDiscovery, LanDiscoveryConfig, LanEvent};

/// Distinct service type per test run so concurrent cargo-test workers
/// on the same machine don't cross-feed each other's adverts via the
/// shared 224.0.0.251 multicast group. The trailing `.local.` is
/// required by RFC 6763 — mdns-sd will reject anything else.
fn isolated_service_type(tag: &str) -> String {
    let rand: u32 = rand::random();
    format!("_fipstest-{tag}-{rand:08x}._udp.local.")
}

fn config_for(service_type: String) -> LanDiscoveryConfig {
    LanDiscoveryConfig {
        enabled: true,
        service_type,
        scope: None,
    }
}

#[test]
fn scoped_ipv4_advert_becomes_socket_addr() {
    let scoped = ScopedIp::from(IpAddr::V4(Ipv4Addr::new(192, 168, 178, 91)));
    let addr = super::socket_addr_from_scoped_ip(&scoped, 51820);

    assert_eq!(addr, Some(SocketAddr::from(([192, 168, 178, 91], 51820))));
}

#[test]
fn scope_less_ipv6_link_local_advert_is_skipped() {
    let scoped = ScopedIp::from(IpAddr::V6("fe80::32c5:99ff:fea7:5fe9".parse().unwrap()));

    assert!(super::socket_addr_from_scoped_ip(&scoped, 51820).is_none());
}

#[test]
fn non_link_local_ipv6_advert_is_preserved() {
    let scoped = ScopedIp::from(IpAddr::V6(Ipv6Addr::LOCALHOST));
    let addr = super::socket_addr_from_scoped_ip(&scoped, 51820);

    assert_eq!(addr, Some("[::1]:51820".parse().unwrap()));
}

async fn wait_for_peer(
    discovery: &LanDiscovery,
    expected_npub: &str,
    timeout: Duration,
) -> Option<super::LanDiscoveredPeer> {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        for event in discovery.drain_events().await {
            let LanEvent::Discovered(peer) = event;
            if peer.npub == expected_npub {
                return Some(peer);
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

/// Two LanDiscovery instances on isolated service types — `a` browses
/// only its own type and never sees `b`, and vice versa. Sanity check
/// that the scope-isolation defense works (we'd lose isolation if mdns-
/// sd ever leaked across service types).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn isolated_service_types_do_not_cross_feed() {
    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let service_a = isolated_service_type("isolated-a");
    let service_b = isolated_service_type("isolated-b");

    let lan_a = LanDiscovery::start(
        &identity_a,
        Some("scope-x".to_string()),
        61001,
        config_for(service_a.clone()),
    )
    .await
    .expect("start a");
    let lan_b = LanDiscovery::start(
        &identity_b,
        Some("scope-x".to_string()),
        61002,
        config_for(service_b.clone()),
    )
    .await
    .expect("start b");

    // Give mDNS multicast time to settle, then confirm neither side saw
    // the other (different service type isolates them).
    tokio::time::sleep(Duration::from_secs(2)).await;
    let saw_b_from_a = wait_for_peer(
        &lan_a,
        identity_b.npub().as_str(),
        Duration::from_millis(500),
    )
    .await
    .is_some();
    let saw_a_from_b = wait_for_peer(
        &lan_b,
        identity_a.npub().as_str(),
        Duration::from_millis(500),
    )
    .await
    .is_some();

    lan_a.shutdown().await;
    lan_b.shutdown().await;

    assert!(!saw_b_from_a, "isolated service types must not cross-feed");
    assert!(!saw_a_from_b, "isolated service types must not cross-feed");
}

/// Two LanDiscovery instances on the same service type and the same
/// scope: each should observe the other's advert within a few seconds.
/// Exercises the responder + browser + TXT plumbing end-to-end.
///
/// Ignored by default: relies on multicast-loopback semantics that
/// vary across macOS/Linux/Windows when two `ServiceDaemon` instances
/// run in the same process. Real cross-host LAN deployment exercises
/// the same code path correctly — verify with `cargo test -- --ignored
/// matched_scope_peers_observe_each_other` on a setup where this
/// matters, or via end-to-end integration with two daemons.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matched_scope_peers_observe_each_other() {
    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let service = isolated_service_type("matched");

    let lan_a = LanDiscovery::start(
        &identity_a,
        Some("scope-shared".to_string()),
        61101,
        config_for(service.clone()),
    )
    .await
    .expect("start a");
    let lan_b = LanDiscovery::start(
        &identity_b,
        Some("scope-shared".to_string()),
        61102,
        config_for(service.clone()),
    )
    .await
    .expect("start b");

    // Loopback mDNS resolution on macOS/Linux takes a moment.
    let observed_b =
        wait_for_peer(&lan_a, identity_b.npub().as_str(), Duration::from_secs(10)).await;
    let observed_a =
        wait_for_peer(&lan_b, identity_a.npub().as_str(), Duration::from_secs(10)).await;

    lan_a.shutdown().await;
    lan_b.shutdown().await;

    let observed_b = observed_b.expect("a must see b");
    let observed_a = observed_a.expect("b must see a");

    assert_eq!(observed_b.scope.as_deref(), Some("scope-shared"));
    assert_eq!(observed_a.scope.as_deref(), Some("scope-shared"));
    assert_eq!(observed_b.addr.port(), 61102);
    assert_eq!(observed_a.addr.port(), 61101);
}

/// Different scopes on the same service type must be filtered out by
/// the browser — peer in scope X does not surface to a browser in
/// scope Y, even if both adverts arrive on the same multicast group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_scope_advert_is_filtered() {
    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let service = isolated_service_type("cross-scope");

    let lan_a = LanDiscovery::start(
        &identity_a,
        Some("scope-a".to_string()),
        61201,
        config_for(service.clone()),
    )
    .await
    .expect("start a");
    let lan_b = LanDiscovery::start(
        &identity_b,
        Some("scope-b".to_string()),
        61202,
        config_for(service.clone()),
    )
    .await
    .expect("start b");

    tokio::time::sleep(Duration::from_secs(3)).await;
    let saw_b = wait_for_peer(
        &lan_a,
        identity_b.npub().as_str(),
        Duration::from_millis(500),
    )
    .await;

    lan_a.shutdown().await;
    lan_b.shutdown().await;

    assert!(saw_b.is_none(), "cross-scope advert must be filtered");
}
