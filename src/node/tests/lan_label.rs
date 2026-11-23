//! mDNS adverts under forged npubs that share a known peer's host label.
//!
//! The mDNS browser accepts an advert only when its service host is the
//! advertised npub's own FIPS host label (`fips-` and the npub's first 16
//! characters), because mdns-sd does not say which interface an SRV record
//! arrived on. That label carries 55 bits of the key, so a sender with no
//! private key can mint valid npubs sharing the label of a FIPS node on
//! another of this node's links, and so name that node's host under keys
//! whose handshakes never complete. When the named node is one this node
//! already knows (a configured or connected peer), such adverts are refused.

use super::bootstrap::{LAN_TEST_IF, lan_node, loopback_prefix, on_demand_peer, stop_transports};
use super::*;
use crate::mdns::{LanDiscoveredPeer, LanEvent};
use secp256k1::XOnlyPublicKey;

/// `n` valid identities other than `of` whose npubs share its first 16
/// characters, and so its mDNS host label, made by changing the key's last
/// byte. No private key is needed for any of them.
fn label_twins(of: &PeerIdentity, n: usize) -> Vec<PeerIdentity> {
    let bytes = of.pubkey().serialize();
    let twins: Vec<PeerIdentity> = (1..=u8::MAX)
        .filter_map(|flip| {
            let mut key = bytes;
            key[31] ^= flip;
            XOnlyPublicKey::from_slice(&key).ok()
        })
        .map(PeerIdentity::from_pubkey)
        .take(n)
        .collect();
    assert_eq!(twins.len(), n, "not enough valid keys");
    for twin in &twins {
        assert_eq!(twin.npub()[..16], of.npub()[..16], "label not shared");
        assert_ne!(twin.node_addr(), of.node_addr());
    }
    twins
}

/// An on-link mDNS discovery of `npub` at `addr`.
fn discovered(npub: String, addr: &str) -> LanEvent {
    LanEvent::Discovered(LanDiscoveredPeer {
        npub,
        scope: None,
        addr: addr.parse().unwrap(),
        interfaces: vec![LAN_TEST_IF],
        observed_at: std::time::Instant::now(),
    })
}

/// Adverts for `identities`, each at its own on-link address.
fn adverts(identities: &[PeerIdentity], first_port: u16) -> Vec<LanEvent> {
    identities
        .iter()
        .enumerate()
        .map(|(i, id)| discovered(id.npub(), &format!("127.0.0.1:{}", first_port + i as u16)))
        .collect()
}

/// How many of `events` the node took up: held as pending LAN candidates
/// or dialled at once.
async fn taken_up(node: &mut Node, events: Vec<LanEvent>) -> usize {
    let before = node.peering.lan.len() + node.connection_count();
    node.handle_lan_events(events, &loopback_prefix()).await;
    node.peering.lan.len() + node.connection_count() - before
}

/// A node with one connected peer, returned with that peer's identity.
async fn lan_node_with_connected_peer() -> (Node, PeerIdentity) {
    let mut node = lan_node().await;
    let link_id = LinkId::new(1);
    let peer = seed_completed_connection(&mut node, link_id, TransportId::new(1), 1000);
    node.install_handshake(link_id, peer, 2000).unwrap();
    assert!(node.peers.contains_key(peer.node_addr()));
    (node, peer)
}

#[tokio::test]
async fn adverts_under_minted_npubs_sharing_a_connected_peers_host_label_are_refused() {
    let (mut node, peer) = lan_node_with_connected_peer().await;

    let forged = adverts(&label_twins(&peer, 8), 20_001);
    assert_eq!(
        taken_up(&mut node, forged).await,
        0,
        "forged adverts naming a connected peer's host were held or dialled"
    );

    // Control: the same number of adverts under unrelated keys is taken up,
    // so the refusal above is the shared label and not the budget.
    let strangers: Vec<PeerIdentity> = (0..8).map(|_| make_peer_identity()).collect();
    assert_eq!(taken_up(&mut node, adverts(&strangers, 21_001)).await, 8);
    stop_transports(&mut node).await;
}

#[tokio::test]
async fn adverts_under_minted_npubs_sharing_a_configured_peers_host_label_are_refused() {
    let mut node = lan_node().await;
    let configured = make_peer_identity();
    node.update_peers(vec![on_demand_peer(configured.npub())])
        .await
        .unwrap();

    let forged = adverts(&label_twins(&configured, 8), 20_001);
    assert_eq!(
        taken_up(&mut node, forged).await,
        0,
        "forged adverts naming a configured peer's host were held or dialled"
    );

    // The configured peer's own advert is still taken up.
    assert_eq!(
        taken_up(&mut node, adverts(&[configured], 22_001)).await,
        1,
        "the configured peer's own advert was refused"
    );
    stop_transports(&mut node).await;
}

/// The configured npub may be written in upper case; the label is compared
/// on the canonical npub, so forgeries are still refused.
#[tokio::test]
async fn an_upper_case_configured_npub_still_has_its_label_defended() {
    let mut node = lan_node().await;
    let configured = make_peer_identity();
    node.update_peers(vec![on_demand_peer(configured.npub().to_ascii_uppercase())])
        .await
        .unwrap();

    let forged = adverts(&label_twins(&configured, 4), 20_001);
    assert_eq!(taken_up(&mut node, forged).await, 0);
    stop_transports(&mut node).await;
}

/// Once the peer is neither connected nor configured, its label is no longer
/// defended: the check covers only identities this node knows.
#[tokio::test]
async fn a_label_is_defended_only_while_its_peer_is_known() {
    let (mut node, peer) = lan_node_with_connected_peer().await;
    let twins = label_twins(&peer, 2);
    assert_eq!(taken_up(&mut node, adverts(&twins[..1], 20_001)).await, 0);

    node.remove_peer(peer.node_addr());
    assert_eq!(taken_up(&mut node, adverts(&twins[1..], 20_002)).await, 1);
    stop_transports(&mut node).await;
}
