//! Tests that a peer's Nostr traversal offer or overlay advert carrying an
//! oversized string or list is refused before anything from it is kept: the
//! refusal of an offer whose session id or nonce is over its byte bound is a
//! warning (the responder's checks are tested in
//! `machine/rendezvous/tests/traversal.rs`), and
//! `parse_overlay_advert_event` refuses an advert whose content is over
//! its byte bound or whose `endpoints`, `signalRelays` or `stunServers` list
//! is over its entry bound. The advert this node publishes stays inside the
//! bounds, with an over-long configured list cut to the bound.

use nostr::event::FinalizeEvent;
use nostr::nips::nip19::ToBech32;
use nostr::prelude::{EventBuilder, Kind, Tag};

use nostr::key::SecretKey;

use super::super::machine::NodeSigner;
use super::super::machine::params::Params;
use super::super::machine::rendezvous::{Action, Input, Rendezvous};
use super::super::runtime::{NostrRendezvous, adversarial_offer_reject};
use super::super::types::BootstrapError;
use super::super::{
    ADVERT_IDENTIFIER, ADVERT_KIND, ADVERT_VERSION, AdvertTransportSnapshot, OverlayAdvert,
    OverlayEndpointAdvert, OverlayTransportKind,
};
use crate::config::NostrRendezvousConfig;

/// The largest advert event content, in bytes, that is parsed at all.
const ADVERT_CONTENT_CAP: usize = 8 * 1024;

/// The most entries an advert's `endpoints`, `signalRelays` or `stunServers`
/// list may carry.
const ADVERT_LIST_CAP: usize = 32;

/// The protocol tag value the default configuration expects on an advert.
fn app() -> String {
    NostrRendezvousConfig::default().app
}

/// The refusal is one of the classes ordinary relay lag cannot explain, so it
/// is logged at warn.
#[test]
fn an_oversized_offer_refusal_is_logged_at_the_default_level() {
    assert!(
        adversarial_offer_reject(&BootstrapError::Protocol("oversized-offer".to_string())),
        "defect: an oversized-offer refusal is not logged at the default level"
    );
}

/// A signed advert event carrying `content` and the default protocol tag.
fn advert_event(content: &str) -> nostr::event::Event {
    EventBuilder::new(Kind::Custom(ADVERT_KIND), content)
        .tags([Tag::custom("protocol", [app()])])
        .finalize(&nostr::key::Keys::generate())
        .unwrap()
}

fn endpoint(transport: OverlayTransportKind, addr: &str) -> OverlayEndpointAdvert {
    OverlayEndpointAdvert {
        transport,
        addr: addr.to_string(),
    }
}

/// A `udp:nat` advert followed by `onions` Tor endpoints, with `relays`
/// signal relays and `stuns` STUN servers.
fn nat_advert(onions: usize, relays: usize, stuns: usize) -> OverlayAdvert {
    let mut endpoints = vec![endpoint(OverlayTransportKind::Udp, "nat")];
    endpoints
        .extend((0..onions).map(|i| endpoint(OverlayTransportKind::Tor, &format!("o{i}.onion:1"))));
    OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: ADVERT_VERSION,
        endpoints,
        signal_relays: Some((0..relays).map(|i| format!("wss://r{i}")).collect()),
        stun_servers: Some((0..stuns).map(|i| format!("stun:s{i}:1")).collect()),
    }
}

/// An advert with a single Tor endpoint, padded so its JSON is `len` bytes.
fn advert_json_of_len(len: usize) -> String {
    let with = |pad: usize| {
        serde_json::to_string(&OverlayAdvert {
            identifier: ADVERT_IDENTIFIER.to_string(),
            version: ADVERT_VERSION,
            endpoints: vec![endpoint(
                OverlayTransportKind::Tor,
                &format!("{}.onion:443", "x".repeat(pad)),
            )],
            signal_relays: None,
            stun_servers: None,
        })
        .unwrap()
    };
    let json = with(len - with(0).len());
    assert_eq!(
        json.len(),
        len,
        "precondition: the padded advert is {len} bytes"
    );
    json
}

fn parse(content: &str) -> Result<OverlayAdvert, BootstrapError> {
    NostrRendezvous::parse_overlay_advert_event(&advert_event(content), &app())
}

/// An advert whose content is one byte over the bound is refused, and one at
/// the bound is parsed.
#[test]
fn an_advert_event_over_the_content_bound_is_refused() {
    let at = parse(&advert_json_of_len(ADVERT_CONTENT_CAP));
    assert!(
        at.is_ok(),
        "defect: an advert of exactly {ADVERT_CONTENT_CAP} bytes was refused: {at:?}"
    );
    let over = parse(&advert_json_of_len(ADVERT_CONTENT_CAP + 1));
    assert!(
        matches!(over, Err(BootstrapError::InvalidAdvert(_))),
        "defect: an advert of {} bytes was not refused",
        ADVERT_CONTENT_CAP + 1
    );
}

/// Content over the bound is refused for its size before it is decoded: a
/// body that is not JSON at all gets the size refusal, not a decode error.
#[test]
fn an_advert_over_the_content_bound_is_refused_before_it_is_decoded() {
    let r = parse(&"x".repeat(ADVERT_CONTENT_CAP + 1));
    assert!(
        matches!(r, Err(BootstrapError::InvalidAdvert(_))),
        "defect: {} bytes of non-JSON content were decoded before the size check: {r:?}",
        ADVERT_CONTENT_CAP + 1
    );
}

/// The issue's shape: an advert of 1000 Tor endpoints of about 4 KB each,
/// which kept about 4 MB in the cache, is refused.
#[test]
fn an_advert_of_a_thousand_four_kilobyte_endpoints_is_refused() {
    let mut advert = nat_advert(0, 1, 1);
    advert.endpoints = (0..1000)
        .map(|i| {
            endpoint(
                OverlayTransportKind::Tor,
                &format!("{}{i}.onion:443", "x".repeat(4000)),
            )
        })
        .collect();
    let r = parse(&serde_json::to_string(&advert).unwrap());
    assert!(
        matches!(r, Err(BootstrapError::InvalidAdvert(_))),
        "defect: an advert of 1000 endpoints of about 4 KB each was accepted"
    );
}

/// Each of the three lists, one entry past the bound in an advert kept under
/// the byte bound, gets the whole advert refused; at the bound every list is
/// kept whole.
#[test]
fn an_advert_with_any_list_past_its_entry_bound_is_refused() {
    let over = ADVERT_LIST_CAP + 1;
    // nat_advert's endpoint list starts with the udp:nat entry.
    let cases = [
        ("endpoints", nat_advert(over - 1, 1, 1)),
        ("signalRelays", nat_advert(0, over, 1)),
        ("stunServers", nat_advert(0, 1, over)),
    ];
    for (name, advert) in cases {
        let json = serde_json::to_string(&advert).unwrap();
        assert!(
            json.len() <= ADVERT_CONTENT_CAP,
            "precondition: the {name} case fits the byte bound"
        );
        let r = parse(&json);
        assert!(
            matches!(r, Err(BootstrapError::InvalidAdvert(_))),
            "defect: an advert with {over} {name} entries was not refused"
        );
    }

    let at = nat_advert(ADVERT_LIST_CAP - 1, ADVERT_LIST_CAP, ADVERT_LIST_CAP);
    let json = serde_json::to_string(&at).unwrap();
    assert!(
        json.len() <= ADVERT_CONTENT_CAP,
        "precondition: the at-bound case fits the byte bound"
    );
    let parsed = parse(&json).expect("defect: an advert with every list at its bound was refused");
    assert_eq!(
        parsed.endpoints.len(),
        ADVERT_LIST_CAP,
        "defect: endpoints were dropped"
    );
    assert_eq!(parsed.signal_relays.map(|l| l.len()), Some(ADVERT_LIST_CAP));
    assert_eq!(parsed.stun_servers.map(|l| l.len()), Some(ADVERT_LIST_CAP));
}

/// The entry bound counts the endpoints the peer sent, not the ones left
/// after unusable ones are dropped: 33 endpoints, 16 of them loopback, get
/// the whole advert refused even though 17 would survive the filter.
#[test]
fn the_endpoint_bound_counts_entries_before_unusable_ones_are_dropped() {
    let mut advert = nat_advert(ADVERT_LIST_CAP / 2, 1, 1);
    advert.endpoints.extend(
        (0..ADVERT_LIST_CAP / 2)
            .map(|i| endpoint(OverlayTransportKind::Udp, &format!("127.0.0.1:{}", i + 1))),
    );
    assert_eq!(
        advert.endpoints.len(),
        ADVERT_LIST_CAP + 1,
        "precondition: one endpoint past the bound"
    );
    let r = parse(&serde_json::to_string(&advert).unwrap());
    assert!(
        matches!(r, Err(BootstrapError::InvalidAdvert(_))),
        "defect: an advert of {} endpoints was accepted once its loopback ones were dropped: {:?}",
        ADVERT_LIST_CAP + 1,
        r.map(|a| a.endpoints.len())
    );
}

/// The shape a byte bound alone lets through: `udp:nat` with as many
/// one-character signal relays as fit under the byte bound (about 2000),
/// which holds about 51 KB once parsed. It is refused.
#[test]
fn an_advert_of_one_character_relays_under_the_byte_bound_is_refused() {
    let advert_with = |n: usize| {
        let mut advert = nat_advert(0, 0, 1);
        advert.signal_relays = Some(vec!["r".to_string(); n]);
        serde_json::to_string(&advert).unwrap()
    };
    let mut n = ADVERT_LIST_CAP + 1;
    while advert_with(n + 1).len() <= ADVERT_CONTENT_CAP {
        n += 1;
    }
    assert!(
        n > 2000,
        "precondition: about 2000 relays fit under the byte bound, not {n}"
    );
    let r = parse(&advert_with(n));
    assert!(
        matches!(r, Err(BootstrapError::InvalidAdvert(_))),
        "defect: an advert of {n} one-character signal relays was accepted"
    );
}

/// The advert a node with discovery enabled on `config` publishes once its
/// advert is assembled from `snapshot`, taken from the publish the
/// rendezvous machine asks for, and that advert parsed as a peer would parse
/// it.
async fn published(
    config: NostrRendezvousConfig,
    snapshot: Vec<AdvertTransportSnapshot>,
) -> (nostr::event::Event, OverlayAdvert) {
    let config = NostrRendezvousConfig {
        enabled: true,
        ..config
    };
    let signer = NodeSigner::new(SecretKey::generate());
    let npub = signer.public_key().to_bech32().expect("bech32");
    let now = super::super::pump::now();
    let mut machine = Rendezvous::<crate::time::HostInstant, crate::identity::OsEntropy>::new(
        Params::from(&config),
        signer,
        npub,
        now,
    );
    machine.handle(
        Input::Transports {
            snapshot,
            reply: None,
        },
        now,
    );
    let event = std::iter::from_fn(|| machine.poll_action())
        .find_map(|action| match action {
            Action::Publish { event, .. } => Some(event),
            _ => None,
        })
        .expect("an advert to publish");
    let advert = NostrRendezvous::parse_overlay_advert_event(&event, &config.app)
        .expect("defect: a peer refuses the advert this node publishes");
    (event, advert)
}

fn nat_snapshot() -> AdvertTransportSnapshot {
    AdvertTransportSnapshot::Udp {
        advertise: true,
        is_public: false,
        external_addr: None,
        local_addr: None,
        transport_key: 1,
    }
}

fn tor_snapshot(i: usize) -> AdvertTransportSnapshot {
    AdvertTransportSnapshot::Tor {
        advertise: true,
        onion_addr: Some(format!("{}{i:04}.onion", "v".repeat(52))),
        advertised_port: 443,
    }
}

/// The advert published from the default configuration, with a NAT UDP
/// transport and an onion, is inside every bound and kept whole.
#[tokio::test]
async fn the_advert_published_from_the_default_config_is_inside_every_bound() {
    let defaults = NostrRendezvousConfig::default();
    let (event, advert) = published(defaults.clone(), vec![nat_snapshot(), tor_snapshot(0)]).await;
    assert!(event.content.len() <= ADVERT_CONTENT_CAP);
    assert_eq!(advert.endpoints.len(), 2);
    assert_eq!(advert.signal_relays.as_ref(), Some(&defaults.dm_relays));
    assert_eq!(advert.stun_servers.as_ref(), Some(&defaults.stun_servers));
}

/// A configuration with one entry past the bound in each list publishes an
/// advert cut to the bound, keeping the configured order, which a peer
/// accepts.
#[tokio::test]
async fn a_config_with_lists_past_the_bound_publishes_a_clamped_advert_peers_accept() {
    let over = ADVERT_LIST_CAP + 1;
    let config = NostrRendezvousConfig {
        dm_relays: (0..over)
            .map(|i| format!("wss://relay{i}.example"))
            .collect(),
        stun_servers: (0..over)
            .map(|i| format!("stun:stun{i}.example:3478"))
            .collect(),
        ..Default::default()
    };
    let mut snapshot = vec![nat_snapshot()];
    snapshot.extend((0..over - 1).map(tor_snapshot));
    let (event, advert) = published(config.clone(), snapshot).await;
    assert!(event.content.len() <= ADVERT_CONTENT_CAP);
    assert_eq!(advert.endpoints.len(), ADVERT_LIST_CAP);
    assert!(
        advert.has_udp_nat_endpoint(),
        "defect: the clamp dropped the udp:nat endpoint"
    );
    assert_eq!(
        advert.endpoints.last().map(|e| e.addr.clone()),
        Some(format!(
            "{}{:04}.onion:443",
            "v".repeat(52),
            ADVERT_LIST_CAP - 2
        )),
        "defect: the clamp did not keep the first endpoints in order"
    );
    assert_eq!(
        advert.signal_relays,
        Some(config.dm_relays[..ADVERT_LIST_CAP].to_vec()),
        "defect: signal relays were not cut to the first {ADVERT_LIST_CAP} in order"
    );
    assert_eq!(
        advert.stun_servers,
        Some(config.stun_servers[..ADVERT_LIST_CAP].to_vec()),
        "defect: STUN servers were not cut to the first {ADVERT_LIST_CAP} in order"
    );
}
