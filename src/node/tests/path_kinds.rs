//! A link that started on a local medium and an Internet address of the
//! peer's, as for a phone whose link to a home node came up over BLE and
//! that then reaches the node's public UDP address. Each test builds two
//! nodes whose first loopback transport is typed BLE, so the link's
//! original path is local, gives each a second loopback transport typed UDP
//! at a public address, so a path between those addresses is of the
//! Internet kind, and has A offer B's public address. Whether a path is
//! made there depends on `node.path.mix_kinds` at each end. The tests of
//! the defaults leave it as the configuration sets it; every other test
//! sets it at both ends itself.

use super::paths::{enabled, loopback_mut, state_at, transport_at};
use super::spanning_tree::{TestNode, cleanup_nodes};
use super::*;
use crate::config::Config;
use crate::peer::{PathState, peer_now};
use crate::transport::TransportType;
use std::sync::atomic::{AtomicU16, Ordering};

/// The port of the next pair of public addresses a test takes.
static NEXT_PORT: AtomicU16 = AtomicU16::new(2121);

/// A's and B's public UDP addresses for one test. The loopback registry is
/// shared by every test in the process, so two tests running at once on the
/// same addresses would deliver each other's frames: the hosts are ones no
/// other test in the crate registers, and each test takes its own port.
fn public_pair() -> (String, String) {
    let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
    (format!("9.9.9.9:{port}"), format!("149.112.112.112:{port}"))
}

/// A configuration with multipath enabled and `mix_kinds` as given.
fn mixing(mix: bool) -> Config {
    let mut cfg = enabled();
    cfg.node.path.mix_kinds = mix;
    cfg
}

/// The earliest wake of either node's machine for the other.
fn next_wake(nodes: &[TestNode]) -> Option<crate::peer::PeerInstant> {
    let wake = |k: usize| {
        let peer = nodes[1 - k].node.node_addr();
        nodes[k].node.get_peer(peer)?.bundle()?.next_wake()
    };
    match (wake(0), wake(1)) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// What each end holds after A offers B's public address.
#[derive(Debug, PartialEq)]
struct Held {
    /// A's path to B's public address.
    at_a: Option<PathState>,
    /// B's path to A's public address.
    at_b: Option<PathState>,
    /// Each node's paths to the other, as `path_show` lists them: their
    /// transport type, address and state.
    paths: [Vec<String>; 2],
}

/// Link A, configured by `cfg_a`, and B, configured by `cfg_b`, over a
/// BLE-typed transport, give each a UDP-typed transport 2 at a public
/// address, have A offer B's, and step both machines at each wake for 10 s
/// of node clock, every frame delivered between steps. With `tor`,
/// transport 2 is typed Tor instead.
async fn offer_public(cfg_a: Config, cfg_b: Config, tor: bool) -> Held {
    let (mix_a, mix_b) = (cfg_a.node.path.mix_kinds, cfg_b.node.path.mix_kinds);
    let mut nodes = vec![
        super::spanning_tree::make_test_node_with_config(cfg_a, 1280).await,
        super::spanning_tree::make_test_node_with_config(cfg_b, 1280).await,
    ];
    for tn in nodes.iter_mut() {
        let t1 = tn.transport_id;
        loopback_mut(tn, t1).typed(TransportType::BLE);
    }
    super::spanning_tree::initiate_handshake(&mut nodes, 0, 1).await;
    super::spanning_tree::drain_all_packets(&mut nodes, false).await;
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    assert!(
        nodes[0].node.get_peer(&b).is_some() && nodes[1].node.get_peer(&a).is_some(),
        "precondition: linked over BLE"
    );
    let t2 = TransportId::new(2);
    let (a_public, b_public) = public_pair();
    let ty = if tor {
        TransportType::TOR
    } else {
        TransportType::UDP
    };
    let a2 = transport_at(&mut nodes[0], t2, &a_public);
    loopback_mut(&mut nodes[0], t2).typed(ty.clone());
    let b2 = transport_at(&mut nodes[1], t2, &b_public);
    loopback_mut(&mut nodes[1], t2).typed(ty);

    nodes[0].node.offer_path(&b, t2, b2.clone()).await;
    super::rekey_parity::pump(&mut nodes).await;
    let end = fips_core::time::deadline(peer_now(), Duration::from_secs(10));
    while let Some(wake) = next_wake(&nodes).filter(|w| *w <= end) {
        {
            use fips_core::time::Instant as _;
            crate::time::advance(wake.saturating_duration_since(peer_now()));
        }
        for tn in nodes.iter_mut() {
            tn.node.path_tick().await;
        }
        super::rekey_parity::pump(&mut nodes).await;
    }
    let paths = |k: usize| -> Vec<String> {
        let npub = nodes[1 - k].node.npub();
        let shown = nodes[k].node.show_paths(&npub).unwrap_or_default();
        shown["paths"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .map(|p| format!("{} {} {}", p["transport_type"], p["addr"], p["state"]))
                    .collect()
            })
            .unwrap_or_default()
    };
    let held = Held {
        at_a: state_at(&nodes[0], &b, t2, &b2),
        at_b: state_at(&nodes[1], &a, t2, &a2),
        paths: [paths(0), paths(1)],
    };
    eprintln!("mix_kinds A {mix_a}, B {mix_b}, tor {tor}: {held:?}");
    cleanup_nodes(&mut nodes).await;
    held
}

/// At the defaults, which mix kinds, a link that started on BLE gains a Live
/// path to the peer's public address, at both ends.
#[tokio::test]
async fn at_the_defaults_a_link_that_started_on_ble_gains_the_public_path() {
    let held = offer_public(enabled(), enabled(), false).await;
    assert_eq!(held.at_a, Some(PathState::Live), "{held:?}");
    assert_eq!(held.at_b, Some(PathState::Live), "{held:?}");
}

/// At the defaults the anonymity-class rule still holds: a link that
/// started on BLE gains no path over a Tor transport.
#[tokio::test]
async fn at_the_defaults_a_link_that_started_on_ble_gains_no_tor_path() {
    let held = offer_public(enabled(), enabled(), true).await;
    assert_eq!((held.at_a, held.at_b), (None, None), "{held:?}");
}

/// With `mix_kinds` off at both ends, a link that started on BLE gains no
/// path to the peer's public address: A does not probe it, and neither end
/// holds a path.
#[tokio::test]
async fn with_mix_kinds_off_at_both_ends_a_link_that_started_on_ble_gains_no_path_to_the_peers_public_address()
 {
    let held = offer_public(mixing(false), mixing(false), false).await;
    assert_eq!((held.at_a, held.at_b), (None, None), "{held:?}");
}

/// With `mix_kinds` on at A only, A probes the public address, but B
/// refuses to make a path from the probe, so A's path never becomes Live:
/// the rule is applied at both ends.
#[tokio::test]
async fn with_mix_kinds_at_the_prober_only_the_peer_refuses_the_path() {
    let held = offer_public(mixing(true), mixing(false), false).await;
    assert_eq!(held.at_b, None, "B made no path: {held:?}");
    assert!(
        held.at_a.is_some() && held.at_a != Some(PathState::Live),
        "A probed the address and the path did not prove: {held:?}"
    );
}

/// With `mix_kinds` on at B only, A never probes the public address.
#[tokio::test]
async fn with_mix_kinds_at_the_answerer_only_the_prober_does_not_probe() {
    let held = offer_public(mixing(false), mixing(true), false).await;
    assert_eq!((held.at_a, held.at_b), (None, None), "{held:?}");
}

/// With `mix_kinds` on at both ends, the link that started on BLE gains a
/// Live path to the peer's public address, at both ends.
#[tokio::test]
async fn with_mix_kinds_at_both_ends_a_link_that_started_on_ble_gains_the_public_path() {
    let held = offer_public(mixing(true), mixing(true), false).await;
    assert_eq!(held.at_a, Some(PathState::Live), "{held:?}");
    assert_eq!(held.at_b, Some(PathState::Live), "{held:?}");
}

/// With `mix_kinds` on at both ends, the anonymity-class rule still holds:
/// the BLE link gains no path over a Tor transport.
#[tokio::test]
async fn with_mix_kinds_at_both_ends_a_link_that_started_on_ble_gains_no_tor_path() {
    let held = offer_public(mixing(true), mixing(true), true).await;
    assert_eq!((held.at_a, held.at_b), (None, None), "{held:?}");
}
