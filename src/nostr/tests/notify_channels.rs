//! Tests of how the notify loop treats a read of either of its two channels:
//! a lag is logged and read past, and only a closed channel ends the loop.

use std::ops::ControlFlow;

use nostr::prelude::{EventBuilder, Keys, Kind, RelayUrl, SubscriptionId};
use nostr_sdk::prelude::RelayPoolNotification;
use tokio::sync::broadcast::error::RecvError;

use super::super::runtime::{Feed, received};

/// A notification carrying an event of no kind the loop handles.
fn notification() -> RelayPoolNotification {
    RelayPoolNotification::Event {
        relay_url: RelayUrl::parse("ws://127.0.0.1:1").expect("relay url"),
        subscription_id: SubscriptionId::new("test"),
        event: Box::new(
            EventBuilder::new(Kind::TextNote, "x")
                .sign_with_keys(&Keys::generate())
                .expect("sign event"),
        ),
    }
}

/// Guards the loop's liveness on both channels: a lag loses only what was
/// overwritten, so ending the loop on one would stop all discovery.
#[test]
fn a_lag_on_either_channel_is_logged_and_read_past_rather_than_ending_the_loop() {
    for feed in [Feed::Pool, Feed::Signals] {
        assert!(
            matches!(
                received(Err(RecvError::Lagged(7)), feed),
                ControlFlow::Continue(None)
            ),
            "a lag on the {feed:?} channel did not read on"
        );
        assert!(
            matches!(
                received(Ok(notification()), feed),
                ControlFlow::Continue(Some(_))
            ),
            "a notification on the {feed:?} channel was not handed on"
        );
    }
}

/// A closed channel can deliver nothing more, so the loop must end and let
/// the runtime see that it has stopped rather than spin on the error.
#[test]
fn a_closed_channel_ends_the_notify_loop() {
    for feed in [Feed::Pool, Feed::Signals] {
        assert!(
            matches!(
                received(Err(RecvError::Closed), feed),
                ControlFlow::Break(())
            ),
            "a closed {feed:?} channel did not end the loop"
        );
    }
}
