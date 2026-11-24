//! Tests of how the two readers of the relay client's feeds end: a lag on
//! the signals' channel is logged and read past, and the signal task ends
//! only when that channel closes; the pump ends when the relay client's
//! notification stream ends.

use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::Duration;

use nostr::event::FinalizeEvent;
use nostr::prelude::{EventBuilder, Keys, Kind, RelayUrl, SubscriptionId};
use nostr_sdk::client::ClientNotification;
use tokio::sync::broadcast::error::RecvError;

use super::super::runtime::{NostrRendezvous, received};

/// A notification carrying an event of no kind the loop handles.
fn notification() -> ClientNotification {
    ClientNotification::Event {
        relay_url: RelayUrl::parse("ws://127.0.0.1:1").expect("relay url"),
        subscription_id: SubscriptionId::new("test"),
        event: Box::new(
            EventBuilder::new(Kind::TextNote, "x")
                .finalize(&Keys::generate())
                .expect("sign event"),
        ),
    }
}

/// Guards the loop's liveness on the signals' channel: a lag loses only what
/// was overwritten, so ending the loop on one would stop all discovery.
#[test]
fn a_lag_on_the_signal_channel_is_logged_and_read_past_rather_than_ending_the_loop() {
    assert!(
        matches!(
            received(Err(RecvError::Lagged(7))),
            ControlFlow::Continue(None)
        ),
        "a lag on the signal channel did not read on"
    );
    assert!(
        matches!(received(Ok(notification())), ControlFlow::Continue(Some(_))),
        "a notification on the signal channel was not handed on"
    );
}

/// A closed channel can deliver nothing more, so the loop must end and let
/// the runtime see that it has stopped rather than spin on the error.
#[test]
fn a_closed_signal_channel_ends_the_notify_loop() {
    assert!(
        matches!(received(Err(RecvError::Closed)), ControlFlow::Break(())),
        "a closed signal channel did not end the loop"
    );
}

/// The relay client's stream ends when the client shuts down, and can then
/// deliver nothing more, so the pump, which reads it, must end cleanly
/// rather than poll a finished stream.
#[tokio::test]
async fn the_pool_stream_ending_ends_the_notify_loop() {
    let runtime = Arc::new(NostrRendezvous::new_for_test());
    let notify = runtime.take_pump_for_test().await.expect("the pump runs");
    runtime.deliver_for_test(notification()).await;
    runtime.close_pool_for_test();
    let ended = tokio::time::timeout(Duration::from_secs(5), notify).await;
    assert!(
        matches!(ended, Ok(Ok(()))),
        "the notify loop did not end cleanly when the pool stream ended: {ended:?}"
    );
}
