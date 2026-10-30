//! Inbound traversal signals, taken off the relay pool's notification channel
//! onto a channel of their own.
//!
//! The relay pool puts every event its relays deliver on one broadcast
//! channel, and a full broadcast channel overwrites its oldest entries. Anyone
//! may publish adverts to the advert relays, so a flood of them could
//! overwrite a signal queued among them before the notify loop read it. A node
//! may discard a signal unopened only while it is opening at least five a
//! second (FRC-1601 Section 5.4), and a signal lost in the channel cannot be
//! fetched again: its kind is ephemeral, so relays do not store it.
//!
//! [`SignalRouter`] is the relay client's event admission policy. The pool
//! consults it for each event a relay delivers, after checking the event's
//! size, subscription, expiry and signature, and before recording the event
//! as seen and putting it on the pool's channel. The router copies each
//! signal onto its own channel and refuses it to the pool; every other event
//! it admits. Only signals fill the router's channel, so no number of adverts
//! can overrun it, and nothing that reads the pool, such as a fetch, ever sees
//! a signal.

use nostr::prelude::{Event, Kind, RelayUrl, SubscriptionId};
use nostr::util::BoxedFuture;
use nostr_sdk::prelude::{
    AdmitPolicy, AdmitStatus, DatabaseEventStatus, MemoryDatabase, NostrDatabase, PolicyError,
    RelayPoolNotification,
};
use tokio::sync::broadcast;

use super::types::SIGNAL_KIND;

/// How many signals the router's channel holds unread: the depth the relay
/// pool gives its own channel. Only signals addressed to this node fill it,
/// one entry each, so only a flood of those can overrun it, and the signal
/// gate already sheds such a flood before opening it.
pub(super) const SIGNAL_BACKLOG: usize = 4096;

/// The admission policy that takes traversal signals off the relay pool's
/// notification channel and queues each one, once, on a channel of its own.
#[derive(Debug)]
pub(super) struct SignalRouter {
    signals: broadcast::Sender<RelayPoolNotification>,
    /// The signals already queued, so a copy of one that a second relay
    /// delivers is not queued again, as the pool does not notify an event
    /// twice. Its own record rather than the pool's: the pool's is shared
    /// with every advert, and a flood of those would evict signal ids from it.
    seen: MemoryDatabase,
}

impl SignalRouter {
    /// A router and the receiver of its channel. The receiver exists from
    /// the start, so a signal delivered before the notify loop first reads it
    /// is held rather than dropped.
    pub(super) fn new() -> (Self, broadcast::Receiver<RelayPoolNotification>) {
        let (signals, receiver) = broadcast::channel(SIGNAL_BACKLOG);
        let router = Self {
            signals,
            seen: MemoryDatabase::default(),
        };
        (router, receiver)
    }
}

impl AdmitPolicy for SignalRouter {
    /// Admit every event but a traversal signal. A signal is refused to the
    /// pool, and queued on the router's channel unless a copy of it has been
    /// queued already.
    fn admit_event<'a>(
        &'a self,
        relay_url: &'a RelayUrl,
        subscription_id: &'a SubscriptionId,
        event: &'a Event,
    ) -> BoxedFuture<'a, Result<AdmitStatus, PolicyError>> {
        Box::pin(async move {
            if event.kind != Kind::Custom(SIGNAL_KIND) {
                return Ok(AdmitStatus::Success);
            }
            let status = self
                .seen
                .check_id(&event.id)
                .await
                .map_err(PolicyError::backend)?;
            if status == DatabaseEventStatus::NotExistent {
                self.seen
                    .save_event(event)
                    .await
                    .map_err(PolicyError::backend)?;
                // A send fails only when no receiver is left, which means the
                // runtime is shutting down and nothing would read the signal.
                let _ = self.signals.send(RelayPoolNotification::Event {
                    relay_url: relay_url.clone(),
                    subscription_id: subscription_id.clone(),
                    event: Box::new(event.clone()),
                });
            }
            Ok(AdmitStatus::rejected(
                "traversal signal taken onto its own channel",
            ))
        })
    }
}

#[cfg(test)]
#[path = "tests/signal_route.rs"]
mod tests;
