//! A peer the configuration names by its npub in upper or mixed case is the
//! same peer as one named by its canonical npub. The node holds the canonical
//! npub for it, so the Nostr open-discovery sweep, which compares the cached
//! adverts' authors with the configured npubs, recognises its advert as a
//! configured peer's rather than queueing it as a stranger's.

use super::*;
use crate::config::{ConnectPolicy, NostrRendezvousPolicy, PeerAddress, PeerConfig};
use crate::nostr::{NostrRendezvous, OverlayEndpointAdvert, OverlayTransportKind};

/// An on-demand peer entry naming `npub` as written, on the placeholder
/// address, which nothing dials.
fn peer_named(npub: &str) -> PeerConfig {
    PeerConfig {
        npub: npub.to_string(),
        alias: None,
        addresses: vec![PeerAddress::new("udp", "127.0.0.1:9")],
        connect_policy: ConnectPolicy::OnDemand,
        auto_reconnect: false,
        via_nostr: false,
    }
}

/// `text` with every other letter upper-cased.
fn alternating_case(text: &str) -> String {
    text.chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect()
}

#[test]
fn a_node_holds_the_canonical_npub_of_a_peer_configured_in_any_case() {
    let peer = Identity::generate();
    let npub = peer.npub();
    for spelling in [
        npub.clone(),
        npub.to_ascii_uppercase(),
        alternating_case(&npub),
    ] {
        let mut config = Config::new();
        config.peers = vec![peer_named(&spelling)];
        let node = make_node_with(config);
        assert_eq!(
            node.config().peers()[0].npub,
            npub,
            "a peer configured as {spelling}"
        );
    }
}

#[tokio::test]
async fn update_peers_holds_the_canonical_npub_of_a_peer_named_in_upper_case() {
    let peer = Identity::generate();
    let npub = peer.npub();
    let mut node = make_node_with(Config::new());
    node.update_peers(vec![peer_named(&npub.to_ascii_uppercase())])
        .await
        .expect("an upper-case npub names a peer");
    assert_eq!(node.config().peers()[0].npub, npub);
}

#[tokio::test]
async fn the_open_discovery_sweep_does_not_queue_a_peer_configured_in_upper_case_as_a_stranger() {
    let peer = Identity::generate();
    let npub = peer.npub();
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.rendezvous.nostr.enabled = true;
    config.node.rendezvous.nostr.policy = NostrRendezvousPolicy::Open;
    config.peers = vec![peer_named(&npub.to_ascii_uppercase())];
    let mut node = make_node_with(config);
    node.supervisor.state = crate::node::NodeState::Running;

    let bootstrap = std::sync::Arc::new(NostrRendezvous::new_for_test());
    let endpoint = OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: "203.0.113.7:2121".to_string(),
    };
    let now_secs = Node::now_ms() / 1000;
    let advert = NostrRendezvous::cached_advert_for_test(npub.clone(), endpoint, now_secs);
    bootstrap.insert_advert_for_test(npub.clone(), advert).await;

    node.run_open_discovery_sweep(&bootstrap, Some(3_600)).await;

    let queued = node.peering.reconciler.retry_pending.get(&peer_addr);
    assert!(
        queued.is_none(),
        "the configured peer's advert was queued as an open-discovery candidate: {:?}",
        queued.map(|state| &state.peer_config)
    );
}
