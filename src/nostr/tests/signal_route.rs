//! Tests of the admission policy that takes traversal signals off the relay
//! pool's notification channel.

use nostr::prelude::{EventBuilder, Keys};
use tokio::sync::broadcast::error::TryRecvError;

use super::super::types::ADVERT_KIND;
use super::*;

/// An event of `kind`, signed by a stranger.
fn event_of(kind: u16) -> Event {
    EventBuilder::new(Kind::Custom(kind), "x")
        .sign_with_keys(&Keys::generate())
        .expect("sign event")
}

/// A relay URL for the test, distinct per `port`.
fn relay(port: u16) -> RelayUrl {
    RelayUrl::parse(&format!("ws://127.0.0.1:{port}")).expect("relay url")
}

/// The fix itself: a signal must leave the pool before the shared channel,
/// where adverts could overwrite it, and still reach the loop.
#[tokio::test]
async fn a_traversal_signal_is_taken_off_the_pool_channel_and_queued_on_its_own() {
    let (router, mut signals) = SignalRouter::new();
    let signal = event_of(SIGNAL_KIND);
    let status = router
        .admit_event(&relay(1), &SubscriptionId::new("signals"), &signal)
        .await
        .expect("admission");
    assert!(
        matches!(status, AdmitStatus::Rejected { .. }),
        "a signal was admitted to the pool channel: {status:?}"
    );
    match signals.try_recv() {
        Ok(RelayPoolNotification::Event {
            relay_url, event, ..
        }) => {
            assert_eq!(event.id, signal.id);
            assert_eq!(relay_url, relay(1));
        }
        other => panic!("the signal was not queued on its own channel: {other:?}"),
    }
}

/// Adverts must keep their old path, so an advert flood cannot fill the
/// channel kept for signals.
#[tokio::test]
async fn an_advert_is_left_to_the_pool_channel_and_not_queued() {
    let (router, mut signals) = SignalRouter::new();
    let status = router
        .admit_event(
            &relay(1),
            &SubscriptionId::new("adverts"),
            &event_of(ADVERT_KIND),
        )
        .await
        .expect("admission");
    assert_eq!(status, AdmitStatus::Success);
    assert!(matches!(signals.try_recv(), Err(TryRecvError::Empty)));
}

/// A signal sent through three relays would otherwise be queued, opened and
/// charged to the signal gate three times.
#[tokio::test]
async fn a_second_copy_of_a_signal_from_another_relay_is_not_queued_again() {
    let (router, mut signals) = SignalRouter::new();
    let signal = event_of(SIGNAL_KIND);
    for port in [1, 2] {
        let status = router
            .admit_event(&relay(port), &SubscriptionId::new("signals"), &signal)
            .await
            .expect("admission");
        assert!(
            matches!(status, AdmitStatus::Rejected { .. }),
            "the copy from relay {port} was admitted to the pool channel: {status:?}"
        );
    }
    assert!(signals.try_recv().is_ok(), "the signal was not queued");
    assert!(
        matches!(signals.try_recv(), Err(TryRecvError::Empty)),
        "the second copy of the signal was queued again"
    );
}
