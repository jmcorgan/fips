//! Tests of the pump: one task owning the rendezvous machine, with the real
//! relay client against nostr-sdk's in-process relay. The keys are FRC-1601
//! Appendix C.1's; nothing here uses nostr's own clock or random source.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use nostr::key::SecretKey;
use nostr::nips::nip19::ToBech32;
use nostr::types::RelayUrl;
use nostr_sdk::local_relay::{LocalRelay, LocalRelayBuilderNip42};

use super::super::machine::NodeSigner;
use super::super::machine::event::advert::advert_event;
use super::super::machine::params::Params;
use super::super::relay::aux;
use super::super::runtime::NostrRendezvous;
use super::super::signal_route::SignalRouter;
use super::super::tests::SignerAuthenticator;
use super::super::types::{
    ADVERT_IDENTIFIER, ADVERT_VERSION, BootstrapError, OverlayAdvert, OverlayTransportKind,
};
use super::*;

/// Node A's secret key, FRC-1601 C.1.
const NODE_A_SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000003";
/// Node B's secret key, FRC-1601 C.1.
const NODE_B_SECRET: &str = "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef";

/// How long a test waits for something the pump should do at once.
const SOON: Duration = Duration::from_secs(5);

fn signer(hex: &str) -> Arc<NodeSigner> {
    Arc::new(NodeSigner::new(SecretKey::from_hex(hex).unwrap()))
}

fn npub(hex: &str) -> String {
    signer(hex).public_key().to_bech32().unwrap()
}

/// A running in-process relay, requiring NIP-42 to read and write when
/// `auth`, and its URL.
async fn relay(auth: bool) -> (LocalRelay, String) {
    let mut builder = LocalRelay::builder();
    if auth {
        builder = builder.nip42(LocalRelayBuilderNip42::read_and_write());
    }
    let relay = builder.build();
    relay.run().await.expect("the in-process relay starts");
    let url = relay.url().await.to_string();
    (relay, url)
}

/// Node B's advert, created now, stored on `url` through a client that
/// answers authentication itself.
async fn store_b_advert(url: &str) {
    let (router, _signals) = SignalRouter::new();
    let b = RelayClient::build(
        SignerAuthenticator {
            signer: signer(NODE_B_SECRET),
        },
        router,
    );
    b.add_relays([url]).await.unwrap();
    b.connect().await;
    let body = OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: ADVERT_VERSION,
        endpoints: vec![super::super::types::OverlayEndpointAdvert {
            transport: OverlayTransportKind::Tcp,
            addr: "8.8.8.8:443".to_string(),
        }],
        signal_relays: None,
        stun_servers: None,
    };
    let event = advert_event(
        &signer(NODE_B_SECRET),
        serde_json::to_string(&body).unwrap(),
        ADVERT_IDENTIFIER,
        "fips-overlay-v1",
        600,
        now_ms(),
        aux(),
    )
    .unwrap();
    b.send(&[url.to_string()], &event).await.unwrap();
}

/// A running engine for a fresh identity with `url` as its only relay,
/// built by `NostrRendezvous::start`.
async fn started(url: &str) -> Arc<NostrRendezvous> {
    let config = crate::config::NostrRendezvousConfig {
        enabled: true,
        advert_relays: vec![url.to_string()],
        dm_relays: vec![url.to_string()],
        stun_servers: Vec::new(),
        ..Default::default()
    };
    NostrRendezvous::start(&crate::Identity::generate(), config)
        .await
        .expect("the engine starts")
}

/// Whether `engine` caches node B's advert within [`SOON`].
async fn b_cached(engine: &NostrRendezvous) -> bool {
    tokio::time::timeout(SOON, async {
        loop {
            if engine
                .cached_endpoints(&npub(NODE_B_SECRET))
                .await
                .is_some()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .is_ok()
}

/// A pump for node A on `params`, with `pooled` in its client's pool and
/// connected, and not started: its inbox, its handle and its count of
/// operations in flight.
async fn pump(
    params: Params,
    pooled: &[String],
) -> (
    Inbox,
    tokio::task::JoinHandle<()>,
    Arc<AtomicUsize>,
    RelayClient,
) {
    let (inbox, rx) = mpsc::unbounded_channel();
    let (router, signals) = SignalRouter::new();
    let forwarder = router.forwarder();
    let client = RelayClient::build(
        super::super::relay::PumpAuthenticator::new(inbox.clone()),
        router,
    );
    if !pooled.is_empty() {
        client.add_relays(pooled).await.unwrap();
        client.connect().await;
    }
    let notifications = client.notifications();
    let machine = Rendezvous::new(params, signer(NODE_A_SECRET), npub(NODE_A_SECRET), now());
    let pump = Pump::new(
        machine,
        client.clone(),
        inbox.clone(),
        Box::new(|_| {}),
        forwarder,
        Arc::new(FirstEvent::new()),
    );
    let in_flight = pump.in_flight();
    drop(signals);
    (
        inbox,
        tokio::spawn(pump.run(notifications, rx)),
        in_flight,
        client,
    )
}

/// A relay requiring NIP-42 to read and write: the pump answers its
/// challenge through the machine, its subscription then delivers a peer's
/// stored advert, and a node query sees it cached.
#[tokio::test(flavor = "multi_thread")]
async fn the_pump_answers_nip42_through_the_machine_and_caches_the_replay() {
    let (_relay, url) = relay(true).await;
    store_b_advert(&url).await;
    let engine = started(&url).await;
    assert!(
        b_cached(&engine).await,
        "the replayed advert was not cached"
    );
    engine.shutdown().await.unwrap();
}

/// A subscribe that fails as a whole (its advert relay is not in the pool)
/// is retried after 2 s, then 4 s, on the machine's deadline, under tokio's
/// paused clock, without the pump spinning.
#[tokio::test(start_paused = true)]
async fn a_failed_subscribe_is_retried_on_the_machines_deadline_under_paused_time() {
    let real = std::time::Instant::now();
    let (capture, _guard) = crate::testutil::capture_logs_scoped();
    let failures = || {
        capture
            .lines_with("failed to subscribe to Nostr discovery relays")
            .len()
    };
    let params = Params {
        advert_relays: vec!["wss://not-in-pool.example".to_string()],
        dm_relays: Vec::new(),
        ..Params::from(&crate::config::NostrRendezvousConfig::default())
    };
    let (inbox, _pump, _, _) = pump(params, &[]).await;
    inbox.send(Msg::Input(Input::Start)).unwrap();
    tokio::time::sleep(Duration::from_millis(1_900)).await;
    assert_eq!(failures(), 1);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(failures(), 2, "retried at 2 s");
    tokio::time::sleep(Duration::from_millis(3_800)).await;
    assert_eq!(failures(), 2);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(failures(), 3, "retried 4 s later");
    assert!(
        real.elapsed() < Duration::from_secs(1),
        "the paused-clock run took {:?} of real time",
        real.elapsed()
    );
}

/// The relay replays its stored advert in answer to the first subscribe;
/// the stream that carries the replay must exist before that subscribe is
/// sent, as `start` makes it.
#[tokio::test(flavor = "multi_thread")]
async fn the_stream_is_taken_before_the_first_subscribe_is_sent() {
    let (_relay, url) = relay(false).await;
    store_b_advert(&url).await;
    let engine = started(&url).await;
    assert!(
        b_cached(&engine).await,
        "the advert the relay replayed to the first subscribe was not cached"
    );
    engine.shutdown().await.unwrap();
}

/// A traversal signal that ever reached the pool's stream is put on the
/// signal router's channel, where the signal task opens it.
#[tokio::test]
async fn a_signal_on_the_pool_stream_reaches_the_signal_task() {
    use super::super::signal::{build_signal_event, create_traversal_answer, rumor};
    let runtime = NostrRendezvous::new_for_test();
    let ours = runtime.npub_for_test().to_string();
    let to = nostr::key::PublicKey::parse(&ours).unwrap();
    let peer = signer(NODE_B_SECRET);
    let waiting = runtime.await_answer_for_test("n1").await;
    let answer = create_traversal_answer(
        "session-1".to_string(),
        now_ms(),
        120_000,
        "answer-1".to_string(),
        npub(NODE_B_SECRET),
        ours.clone(),
        "n1".to_string(),
        false,
        None,
        Vec::new(),
        None,
        None,
        Some("busy".to_string()),
        None,
    );
    let wrap = build_signal_event(
        &peer,
        to,
        rumor(
            peer.public_key(),
            to,
            serde_json::to_string(&answer).unwrap(),
            now_ms(),
        ),
        nostr::types::Timestamp::from(now_ms() / 1000 + 120),
    )
    .unwrap();
    let signals = runtime.spawn_signals_for_test();
    runtime.deliver_unfiltered_for_test(ClientNotification::Event {
        relay_url: RelayUrl::parse("ws://127.0.0.1:1").unwrap(),
        subscription_id: nostr::message::SubscriptionId::new("s"),
        event: Box::new(wrap),
    });
    let handed = tokio::time::timeout(SOON, waiting).await;
    signals.abort();
    assert!(
        matches!(handed, Ok(Ok(_))),
        "the signal on the pool's stream was not opened"
    );
}

/// Once the pump has stopped, every request gets the empty answer at once.
#[tokio::test]
async fn a_request_to_a_stopped_pump_gets_the_empty_answer() {
    let runtime = NostrRendezvous::new_for_test();
    runtime.shutdown().await.unwrap();
    let peer = npub(NODE_B_SECRET);
    let answers = tokio::time::timeout(SOON, async {
        (
            runtime.advert_endpoints_for_peer(&peer).await,
            runtime.assemble_advert(Vec::new()).await,
            runtime.refetch_advert_for_stale_check(&peer).await,
            runtime
                .cached_open_discovery_candidates(10, &HashSet::new())
                .await,
            runtime.cached_endpoints(&peer).await,
        )
    })
    .await
    .expect("a stopped pump does not hold a request");
    assert!(matches!(answers.0, Err(BootstrapError::Disabled)));
    assert!(matches!(answers.1, Err(BootstrapError::Disabled)));
    assert_eq!(
        answers.2,
        crate::nostr::NostrRefetchOutcome::Skipped,
        "a refetch is skipped"
    );
    assert!(answers.3.is_empty());
    assert!(answers.4.is_none());
}

/// The pump handles its inbox in order, so a query sees the effect of every
/// input sent before it, even one whose sender did not wait.
#[tokio::test]
async fn each_query_sees_the_inputs_sent_before_it() {
    let runtime = NostrRendezvous::new_for_test();
    let peer = npub(NODE_B_SECRET);
    let advert = NostrRendezvous::cached_advert_for_test(
        peer.clone(),
        super::super::types::OverlayEndpointAdvert {
            transport: OverlayTransportKind::Tcp,
            addr: "8.8.8.8:443".to_string(),
        },
        now_ms() / 1000,
    );
    runtime.insert_advert_for_test(peer.clone(), advert).await;
    for round in 0..20 {
        // Protected entries are listed beyond `max`; with `max` 0 only a
        // protected author is a candidate.
        let protected = round % 2 == 0;
        runtime.set_advert_protection(if protected {
            HashSet::from([peer.clone()])
        } else {
            HashSet::new()
        });
        let candidates = runtime
            .cached_open_discovery_candidates(0, &HashSet::new())
            .await;
        assert_eq!(
            !candidates.is_empty(),
            protected,
            "round {round}: the query did not see the protection sent before it"
        );
    }
    // The barrier on its own: a read after it sees the send before it.
    runtime.set_advert_protection(HashSet::from([peer.clone()]));
    runtime.settled_for_test().await;
    assert_eq!(
        runtime.advert_protection_for_test().await,
        HashSet::from([peer])
    );
}

/// A relay operation in flight when the engine shuts down is cancelled with
/// the pump, not left to run to its own timeout. The relay client is left
/// open until after the check: closing it would end a relay call by itself,
/// while an operation that is not one, such as a DNS lookup, has only the
/// pump's abort to end it.
#[tokio::test]
async fn shutdown_cancels_a_relay_operation_in_flight() {
    let runtime = Arc::new(NostrRendezvous::new_for_test());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let blackhole = format!("ws://127.0.0.1:{}", listener.local_addr().unwrap().port());
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept() {
            held.push(stream);
        }
    });
    runtime.set_advert_relays_for_test(vec![blackhole]).await;
    let asking = Arc::clone(&runtime);
    let refetch = tokio::spawn(async move {
        asking
            .refetch_advert_for_stale_check(&npub(NODE_B_SECRET))
            .await
    });
    assert!(
        crate::testutil::wait_until(|| runtime.in_flight_for_test() == 1, SOON).await,
        "setup: the refetch's fetch is in flight"
    );
    runtime.end_pump_for_test().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        runtime.in_flight_for_test(),
        0,
        "the fetch outlived the pump (its timeout is 2 s)"
    );
    runtime.shutdown().await.unwrap();
    let _ = refetch.await;
}

/// A STUN server on loopback that answers each binding request with a
/// binding success naming `mapped`, from the address it was asked on.
fn loopback_stun_server(mapped: std::net::SocketAddrV4) -> std::net::SocketAddr {
    let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();
    std::thread::spawn(move || {
        const COOKIE: u32 = 0x2112_a442;
        let mut buf = [0u8; 2048];
        while let Ok((len, from)) = server.recv_from(&mut buf) {
            if len < 20 {
                continue;
            }
            let mut packet = Vec::new();
            packet.extend_from_slice(&0x0101u16.to_be_bytes());
            packet.extend_from_slice(&12u16.to_be_bytes());
            packet.extend_from_slice(&COOKIE.to_be_bytes());
            packet.extend_from_slice(&buf[8..20]);
            packet.extend_from_slice(&0x0020u16.to_be_bytes());
            packet.extend_from_slice(&8u16.to_be_bytes());
            packet.push(0);
            packet.push(1);
            packet.extend_from_slice(&(mapped.port() ^ (COOKIE >> 16) as u16).to_be_bytes());
            for (octet, mask) in mapped.ip().octets().iter().zip(COOKIE.to_be_bytes()) {
                packet.push(octet ^ mask);
            }
            let _ = server.send_to(&packet, from);
        }
    });
    addr
}

/// The start-up assembly of an advert with a wildcard public UDP transport
/// waits for the public address, which the pump learns from a STUN server
/// over a socket of its own, and the advert names it with the transport's
/// port.
#[tokio::test]
async fn the_advert_learns_its_public_address_from_a_loopback_stun_server() {
    let mapped = std::net::SocketAddrV4::new([8, 8, 4, 4].into(), 50_000);
    let server = loopback_stun_server(mapped);
    let (capture, _guard) = crate::testutil::capture_logs_scoped();
    let runtime = NostrRendezvous::new_for_test_with_config(crate::config::NostrRendezvousConfig {
        stun_servers: vec![format!("stun:{server}")],
        ..Default::default()
    });
    let snapshot = vec![super::super::AdvertTransportSnapshot::Udp {
        advertise: true,
        is_public: true,
        external_addr: None,
        local_addr: Some("0.0.0.0:2121".parse().unwrap()),
        transport_key: 7,
    }];
    tokio::time::timeout(SOON, runtime.assemble_advert(snapshot))
        .await
        .expect("assembled within the wait")
        .expect("the pump answered");
    let observed = capture
        .line("public-udp-addr: STUN observation")
        .expect("the observation was logged");
    assert!(
        observed.contains(&format!("stun=stun:{server} reflexive=8.8.4.4:50000")),
        "{observed}"
    );
    assert!(
        capture
            .line("advert: udp public=true bound to wildcard but STUN observation failed; advertising no UDP endpoint. Either set transports.udp.external_addr, bind to a specific public IP, or ensure node.rendezvous.nostr.stun_servers is reachable")
            .is_none(),
        "the advert names the learned address"
    );
}

/// A subscribe retried after a whole-call failure (its advert relay is not
/// in the pool) names the subscriptions of the first attempt, so the relay
/// that took the first attempt's signal subscription is not given a second.
#[tokio::test(start_paused = true)]
async fn a_retried_subscribe_reuses_the_ids_of_the_first() {
    let (_relay, url) = relay(false).await;
    let params = Params {
        dm_relays: vec![url.clone()],
        advert_relays: vec!["wss://not-in-pool.example".to_string()],
        ..Params::from(&crate::config::NostrRendezvousConfig::default())
    };
    let (capture, _guard) = crate::testutil::capture_logs_scoped();
    let (inbox, _pump, _, client) = pump(params, std::slice::from_ref(&url)).await;
    inbox.send(Msg::Input(Input::Start)).unwrap();
    let retried = crate::testutil::wait_until(
        || {
            capture
                .lines_with("failed to subscribe to Nostr discovery relays")
                .len()
                >= 2
        },
        Duration::from_secs(10),
    )
    .await;
    assert!(retried, "setup: the subscribe failed and was retried");
    assert_eq!(client.subscription_count().await, 1);
}

/// Shutdown closes the engine's relay connections rather than leaving them
/// to time out.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_closes_the_relay_connections() {
    use nostr_sdk::relay::RelayStatus;
    let (_relay, url) = relay(false).await;
    let engine = started(&url).await;
    let relays = engine.relays_for_test().await;
    assert_eq!(relays.len(), 1);
    let connected = crate::testutil::wait_until(
        || relays.iter().all(|r| r.status() == RelayStatus::Connected),
        SOON,
    )
    .await;
    assert!(connected, "setup: the relay connected");
    engine.shutdown().await.unwrap();
    let closed = crate::testutil::wait_until(
        || {
            relays
                .iter()
                .all(|r| matches!(r.status(), RelayStatus::Terminated | RelayStatus::Shutdown))
        },
        SOON,
    )
    .await;
    assert!(
        closed,
        "a relay connection outlived shutdown: {:?}",
        relays.iter().map(|r| r.status()).collect::<Vec<_>>()
    );
}
