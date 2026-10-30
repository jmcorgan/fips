//! Tests that a traversal signal is not lost when a flood of advertisements
//! overruns the relay pool's notification channel. A node may discard a wrap
//! unopened, to bound what signals cost it, only once it has begun to open at
//! least 5 wraps in the second before; a wrap overwritten in a lagging channel
//! is discarded whatever that count is.

use std::sync::Arc;
use std::time::Duration;

use nostr::ToBech32;
use nostr::prelude::{
    Event, EventBuilder, FromBech32, Keys, Kind, PublicKey, RelayUrl, SubscriptionId, Timestamp,
};
use nostr_sdk::prelude::{
    DEFAULT_NOTIFICATION_CHANNEL_SIZE as POOL_CHANNEL, RelayPoolNotification,
};
use tokio::sync::broadcast;

use super::super::ADVERT_KIND;
use super::super::runtime::NostrRendezvous;
use super::super::signal::{build_signal_event, create_traversal_answer};
use super::super::traversal::now_ms;

/// How long the test waits for an answer the loop should hand over.
const HANDOFF_WAIT: Duration = Duration::from_secs(5);

/// `event` as the pool delivers it from a relay.
fn delivered(event: Event) -> RelayPoolNotification {
    RelayPoolNotification::Event {
        relay_url: RelayUrl::parse("ws://127.0.0.1:1").expect("relay url"),
        subscription_id: SubscriptionId::new("signals"),
        event: Box::new(event),
    }
}

/// A refusing answer from `from` to `to`, replying to our offer `nonce`,
/// wrapped as a traversal signal.
async fn answer_wrap(from: &Keys, to_npub: &str, nonce: &str) -> Event {
    let to = PublicKey::from_bech32(to_npub).expect("our npub");
    let answer = create_traversal_answer(
        format!("session-{nonce}"),
        now_ms(),
        120_000,
        format!("answer-{nonce}"),
        from.public_key().to_bech32().expect("bech32"),
        to_npub.to_string(),
        nonce.to_string(),
        false,
        None,
        Vec::new(),
        None,
        None,
        Some("busy".to_string()),
        None,
    );
    let rumor = EventBuilder::private_msg_rumor(to, serde_json::to_string(&answer).unwrap())
        .build(from.public_key());
    build_signal_event(from, to, rumor, Timestamp::from(now_ms() / 1000 + 120))
        .await
        .expect("signal event should build")
}

/// An advertisement-kind event from a stranger, as an advert flood delivers.
fn advert_event() -> Event {
    EventBuilder::new(Kind::Custom(ADVERT_KIND), "{}")
        .sign_with_keys(&Keys::generate())
        .expect("sign advert")
}

/// Deliver our peer's answer to `first`, then `flood` advertisements, through
/// the runtime's relay client before the notify loop reads any of them, as
/// when a burst arrives while the loop is busy. `pool` stands in for the relay
/// pool's notification channel, `POOL_CHANNEL` deep as the pool makes it. Then
/// start the loop, wait for that answer, deliver a second answer, to `second`,
/// and report whether each answer reached its waiting traversal, and how many
/// notifications were waiting unread on `pool` when the loop started.
async fn answers_handed_over_after_a_flood(flood: usize) -> (bool, bool, usize) {
    let runtime = Arc::new(NostrRendezvous::new_for_test());
    let our_npub = runtime.npub_for_test().to_string();
    let peer = Keys::generate();
    let first = runtime.await_answer_for_test("first").await;
    let second = runtime.await_answer_for_test("second").await;

    let (pool, rx) = broadcast::channel(POOL_CHANNEL);
    runtime
        .deliver_for_test(
            &pool,
            delivered(answer_wrap(&peer, &our_npub, "first").await),
        )
        .await;
    let advert = advert_event();
    for _ in 0..flood {
        runtime
            .deliver_for_test(&pool, delivered(advert.clone()))
            .await;
    }
    let backlog = rx.len();
    let notify = runtime.clone().spawn_notify_loop_for_test(rx);
    let first = tokio::time::timeout(HANDOFF_WAIT, first).await;

    // Delivered only once the loop has read the queue, so it overwrites
    // nothing.
    runtime
        .deliver_for_test(
            &pool,
            delivered(answer_wrap(&peer, &our_npub, "second").await),
        )
        .await;
    let second = tokio::time::timeout(HANDOFF_WAIT, second).await;
    notify.abort();
    (
        matches!(first, Ok(Ok(_))),
        matches!(second, Ok(Ok(_))),
        backlog,
    )
}

/// The control: a flood one short of the channel's size overwrites nothing,
/// and both answers reach their traversals.
#[tokio::test]
async fn an_answer_queued_ahead_of_a_flood_that_fits_the_channel_is_handed_over() {
    let (first, second, _) = answers_handed_over_after_a_flood(POOL_CHANNEL - 1).await;
    assert!(
        first,
        "the answer queued ahead of the flood was not handed over"
    );
    assert!(
        second,
        "the answer sent after the flood was not handed over"
    );
}

/// A flood of twice the channel's size overruns the channel adverts arrive on
/// by a full channel's worth, so it would overwrite an answer queued ahead of
/// it in the same channel. The node has opened no wrap at all, so the floor
/// forbids discarding the answer. The test runtime is single-threaded and the
/// loop starts only once the whole flood is queued, so the overrun is certain
/// rather than a race. The second answer is the sign that the loop is still
/// running.
#[tokio::test]
async fn an_answer_queued_ahead_of_an_advert_flood_twice_the_channel_size_is_still_handed_over() {
    let (first, second, backlog) = answers_handed_over_after_a_flood(2 * POOL_CHANNEL).await;
    assert!(
        backlog > POOL_CHANNEL,
        "control: only {backlog} notifications were waiting, so the flood did not overrun \
         the channel adverts arrive on"
    );
    assert!(
        second,
        "control: the answer sent after the flood was not handed over, so the loop is not running"
    );
    assert!(
        first,
        "the answer queued ahead of {} advertisements was dropped in the \
         notification channel, with no wrap opened in the second before",
        2 * POOL_CHANNEL
    );
}
