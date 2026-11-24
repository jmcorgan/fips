//! Tests of the relay adapter against nostr-sdk's in-process relay: the
//! calls the shell makes (subscribe, the notification stream, fetch, send),
//! the signal router on a real relay connection, the answer to a relay that
//! requires NIP-42 authentication, and the order of the stream against a
//! subscribe. The keys are those of FRC-1601 Appendix C.1; nothing here uses
//! nostr's own clock or random source.

use std::time::Duration;

use futures::StreamExt;
use nostr::event::{Event, Kind};
use nostr::filter::Filter;
use nostr::key::SecretKey;
use nostr::message::RelayMessage;
use nostr::types::{RelayUrl, Timestamp};
use nostr_sdk::client::{ClientBuilder, ClientNotification};
use nostr_sdk::local_relay::{LocalRelay, LocalRelayBuilderNip42};
use tokio::sync::broadcast;

use std::sync::Arc;

use super::super::machine::NodeSigner;
use super::super::machine::event::advert::advert_event;
use super::super::machine::event::signal::{open_signal, rumor, seal_and_wrap};
use super::super::tests::SignerAuthenticator;
use super::super::traversal::now_ms;
use super::super::types::{ADVERT_IDENTIFIER, ADVERT_KIND, SIGNAL_KIND};
use super::*;

/// Node A's secret key, FRC-1601 C.1.
const NODE_A_SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000003";
/// Node B's secret key, FRC-1601 C.1.
const NODE_B_SECRET: &str = "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef";

/// How long a test waits for a relay to deliver what it should.
const DELIVERY: Duration = Duration::from_secs(5);

/// The signer for the secret key written as `hex`.
fn signer(hex: &str) -> Arc<NodeSigner> {
    Arc::new(NodeSigner::new(
        SecretKey::from_hex(hex).expect("a C.1 secret key"),
    ))
}

/// A running in-process relay, requiring NIP-42 authentication to read and
/// write when `auth` is set, and its URL.
async fn relay(auth: bool) -> (LocalRelay, RelayUrl) {
    let mut builder = LocalRelay::builder();
    if auth {
        builder = builder.nip42(LocalRelayBuilderNip42::read_and_write());
    }
    let relay = builder.build();
    relay.run().await.expect("the in-process relay starts");
    let url = relay.url().await;
    (relay, url)
}

/// An adapter for `signer` with `url` in its pool, connecting, and the
/// receiver of its signal router's channel.
async fn adapter(
    signer: Arc<NodeSigner>,
    url: &RelayUrl,
) -> (RelayClient, broadcast::Receiver<ClientNotification>) {
    let (router, signals) = SignalRouter::new();
    let client = RelayClient::build(SignerAuthenticator { signer }, router);
    client
        .add_relays([url.to_string()])
        .await
        .expect("add the relay");
    client.connect().await;
    (client, signals)
}

/// `signer`'s advert, created now, valid for ten minutes.
fn advert(signer: &NodeSigner) -> Event {
    advert_event(
        signer,
        "{}".to_string(),
        ADVERT_IDENTIFIER,
        "fips-overlay-v1",
        600,
        now_ms(),
        aux(),
    )
    .expect("advert")
}

/// A fixed subscription id named `name`.
fn test_id(name: &str) -> nostr::message::SubscriptionId {
    nostr::message::SubscriptionId::new(name)
}

/// The filter for every node's advert.
fn adverts() -> Filter {
    Filter::new()
        .kind(Kind::Custom(ADVERT_KIND))
        .identifier(ADVERT_IDENTIFIER)
}

/// The next event on `stream` whose id is `id`, with the subscription id it
/// was delivered under, and every other event delivered before it; `None`
/// if none arrives within [`DELIVERY`].
async fn await_event(
    stream: &mut Notifications,
    id: nostr::event::EventId,
) -> Option<(String, Vec<Event>)> {
    let mut before = Vec::new();
    tokio::time::timeout(DELIVERY, async {
        while let Some(notification) = stream.next().await {
            if let ClientNotification::Event {
                subscription_id,
                event,
                ..
            } = notification
            {
                if event.id == id {
                    return Some((subscription_id.to_string(), before));
                }
                before.push(*event);
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

/// Wait until `stream` has carried `count` EOSE messages, the relay's
/// answer to a REQ once it holds the subscription.
async fn await_eose(stream: &mut Notifications, count: usize) {
    let mut seen = 0;
    tokio::time::timeout(DELIVERY, async {
        while seen < count {
            if let Some(ClientNotification::Message { message, .. }) = stream.next().await
                && matches!(*message, RelayMessage::EndOfStoredEvents(_))
            {
                seen += 1;
            }
        }
    })
    .await
    .expect("the relay took the subscriptions");
}

/// Through a plain relay: a subscription delivers a peer's advert on the
/// stream under the subscription's id, a fetch by author finds it, and a
/// send naming a relay outside the pool is refused as a whole.
#[tokio::test(flavor = "multi_thread")]
async fn the_adapter_subscribes_fetches_and_sends_through_a_plain_relay() {
    let (_relay, url) = relay(false).await;
    let a = signer(NODE_A_SECRET);
    let b = signer(NODE_B_SECRET);
    let (to_a, _) = adapter(a.clone(), &url).await;
    let (to_b, _) = adapter(b, &url).await;

    let mut stream = to_b.notifications();
    to_b.subscribe(vec![url.to_string()], adverts(), test_id("adverts"))
        .await
        .expect("subscribe");
    let event = advert(&a);
    to_a.send(&[url.to_string()], &event).await.expect("send");
    let (subscription, _) = await_event(&mut stream, event.id)
        .await
        .expect("the advert reached the subscriber's stream");
    assert!(
        !subscription.is_empty(),
        "the advert arrived under no subscription"
    );

    let fetched = to_b
        .fetch(
            vec![url.to_string()],
            adverts().author(a.public_key()),
            Duration::from_secs(2),
        )
        .await
        .expect("fetch");
    assert!(
        fetched.iter().any(|e| e.id == event.id),
        "a fetch by author did not find the advert: {} events",
        fetched.len()
    );

    let outside = to_a
        .send(
            &[url.to_string(), "wss://not-in-pool.example".to_string()],
            &event,
        )
        .await;
    assert!(
        outside.is_err(),
        "a send naming a relay outside the pool was not refused"
    );
}

/// A traversal signal delivered through a relay goes to the router's channel
/// and opens to its sender, and never reaches the notification stream: an
/// advert sent after it arrives on the stream with no signal ahead of it.
#[tokio::test(flavor = "multi_thread")]
async fn the_router_takes_a_signal_off_the_stream_onto_its_own_channel() {
    let (_relay, url) = relay(false).await;
    let a = signer(NODE_A_SECRET);
    let b = signer(NODE_B_SECRET);
    let (to_a, _) = adapter(a.clone(), &url).await;
    let (to_b, mut signals) = adapter(b.clone(), &url).await;

    let mut stream = to_b.notifications();
    to_b.subscribe(
        vec![url.to_string()],
        Filter::new()
            .kind(Kind::Custom(SIGNAL_KIND))
            .pubkey(b.public_key())
            .limit(0),
        test_id("signals"),
    )
    .await
    .expect("subscribe to signals");
    to_b.subscribe(vec![url.to_string()], adverts(), test_id("adverts"))
        .await
        .expect("subscribe to adverts");
    // The relay keeps no copy of a signal, whose kind is ephemeral, so one
    // sent before the relay holds the subscription is never delivered. It
    // answers each REQ with EOSE once it holds it.
    await_eose(&mut stream, 2).await;

    let wrap = seal_and_wrap::<crate::identity::OsEntropy>(
        &a,
        b.public_key(),
        rumor(a.public_key(), b.public_key(), "{}".to_string(), now_ms()),
        now_ms(),
        Timestamp::from(now_ms() / 1000 + 120),
    )
    .expect("wrap");
    to_a.send(&[url.to_string()], &wrap).await.expect("send");
    let queued = tokio::time::timeout(DELIVERY, signals.recv())
        .await
        .expect("the signal reached the router's channel")
        .expect("the router's channel is open");
    let ClientNotification::Event { event, .. } = queued else {
        panic!("the router queued something other than an event: {queued:?}");
    };
    assert_eq!(event.id, wrap.id);
    let opened = open_signal(&b, &event).expect("the recipient opens the signal");
    assert_eq!(opened.sender, a.public_key());

    let marker = advert(&a);
    to_a.send(&[url.to_string()], &marker).await.expect("send");
    let (_, before) = await_event(&mut stream, marker.id)
        .await
        .expect("the advert sent after the signal reached the stream");
    assert!(
        before.iter().all(|e| e.kind != Kind::Custom(SIGNAL_KIND)),
        "a traversal signal reached the notification stream"
    );
}

/// A relay that requires NIP-42 authentication to read and to write takes
/// the adapter's advert and serves it back to another adapter: each answers
/// the relay's challenge with an event signed by its node key.
#[tokio::test(flavor = "multi_thread")]
async fn the_adapter_answers_a_relay_that_requires_authentication() {
    let (_relay, url) = relay(true).await;
    let a = signer(NODE_A_SECRET);
    let b = signer(NODE_B_SECRET);
    let (to_a, _) = adapter(a.clone(), &url).await;
    let (to_b, _) = adapter(b, &url).await;

    let event = advert(&a);
    to_a.send(&[url.to_string()], &event).await.expect("send");
    let fetched = to_b
        .fetch(
            vec![url.to_string()],
            adverts().author(a.public_key()),
            Duration::from_secs(2),
        )
        .await
        .expect("fetch");
    assert!(
        fetched.iter().any(|e| e.id == event.id),
        "the advert did not reach the relay and come back: {} events",
        fetched.len()
    );
}

/// The break test of the one before: a client with no authenticator cannot
/// publish to that relay, which refuses it as `auth-required`, and the
/// adapter then finds nothing there.
#[tokio::test(flavor = "multi_thread")]
async fn without_an_authenticator_a_relay_that_requires_authentication_refuses_the_publish() {
    let (_relay, url) = relay(true).await;
    let a = signer(NODE_A_SECRET);
    let b = signer(NODE_B_SECRET);
    let bare = ClientBuilder::new().build();
    bare.add_relay(url.clone()).await.expect("add the relay");
    bare.connect().await;

    let event = advert(&a);
    let output = bare
        .send_event(&event)
        .to([url.clone()])
        .await
        .expect("the send is attempted");
    assert!(
        output.success.is_empty(),
        "the relay took a publish from a client that cannot authenticate"
    );
    assert!(
        output
            .failed
            .values()
            .any(|reason| reason.contains("auth-required")),
        "the publish failed, but not for want of authentication: {:?}",
        output.failed
    );

    let (to_b, _) = adapter(b, &url).await;
    let fetched = to_b
        .fetch(
            vec![url.to_string()],
            adverts().author(a.public_key()),
            Duration::from_secs(2),
        )
        .await
        .expect("fetch");
    assert!(
        fetched.iter().all(|e| e.id != event.id),
        "the relay stored a publish it refused"
    );
}

/// A stream taken before a subscribe receives the events the relay sends in
/// reply, including those it had stored: the order the runtime's start takes
/// them in, so a restarted node learns the adverts already published.
#[tokio::test(flavor = "multi_thread")]
async fn a_stream_taken_before_a_subscribe_receives_the_relays_stored_replay() {
    let (_relay, url) = relay(false).await;
    let a = signer(NODE_A_SECRET);
    let b = signer(NODE_B_SECRET);
    let (to_a, _) = adapter(a.clone(), &url).await;
    let stored = advert(&a);
    to_a.send(&[url.to_string()], &stored).await.expect("send");

    let (to_b, _) = adapter(b, &url).await;
    let mut stream = to_b.notifications();
    to_b.subscribe(vec![url.to_string()], adverts(), test_id("adverts"))
        .await
        .expect("subscribe");
    assert!(
        await_event(&mut stream, stored.id).await.is_some(),
        "the stored advert the relay replayed did not reach the stream"
    );
}

/// A send to a relay that is in the pool but not connected is accepted by
/// the client and reaches no relay: the count is zero, not an error.
#[tokio::test(start_paused = true)]
async fn a_send_to_a_pooled_relay_that_is_not_connected_reaches_none() {
    let (router, _signals) = SignalRouter::new();
    let client = RelayClient::build(
        SignerAuthenticator {
            signer: signer(NODE_A_SECRET),
        },
        router,
    );
    client.add_relays(["ws://127.0.0.1:1"]).await.unwrap();
    let event = advert(&signer(NODE_A_SECRET));
    let reached = client
        .send(&["ws://127.0.0.1:1".to_string()], &event)
        .await
        .expect("the client accepts the send");
    assert_eq!(reached, 0);
}

/// A subscribe repeated under the id of one the client holds is refused by
/// the client for that relay, before any REQ is sent, so the client keeps
/// one subscription rather than two.
#[tokio::test(flavor = "multi_thread")]
async fn a_subscribe_repeated_under_its_id_leaves_the_client_one_subscription() {
    let (_relay, url) = relay(false).await;
    let (client, _) = adapter(signer(NODE_B_SECRET), &url).await;
    for _ in 0..2 {
        client
            .subscribe(vec![url.to_string()], adverts(), test_id("adverts"))
            .await
            .expect("the subscribe call succeeds as a whole");
    }
    assert_eq!(client.subscription_count().await, 1);
}
