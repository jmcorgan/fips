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

use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;

use nostr::prelude::{Event, EventId, Kind, RelayUrl, SubscriptionId};
use nostr::util::BoxedFuture;
use nostr_sdk::prelude::{AdmitPolicy, AdmitStatus, PolicyError, RelayPoolNotification};
use tokio::sync::broadcast;

use super::types::SIGNAL_KIND;

/// How many signals the router's channel holds unread: the depth the relay
/// pool gives its own channel. Only signals addressed to this node fill it,
/// one entry each, so only a flood of those can overrun it, and the signal
/// gate already sheds such a flood before opening it.
pub(super) const SIGNAL_BACKLOG: usize = 4096;

/// How many signal ids [`SeenSignals`] holds: the size of the record it
/// replaced, `nostr-database` 0.44's `MemoryDatabase`, whose default event-id
/// tracker held 35,000 (`MAX_EVENTS`, `src/memory.rs`).
pub(super) const SEEN_SIGNALS: usize = 35_000;

/// The ids of the signals the router has queued: the last [`SEEN_SIGNALS`],
/// forgetting the oldest first.
///
/// This is the record `nostr-database` 0.44's `MemoryDatabase` kept for the
/// router: an LRU tracker that the router asked whether an id was present and
/// then told to record it if not. Asking does not promote an id in that
/// tracker, and an id already present is never recorded again, so it forgets
/// ids in the order they were first recorded. A set and a queue under one lock
/// keep that order; the lock is never held across an await.
#[derive(Debug, Default)]
pub(super) struct SeenSignals {
    inner: Mutex<SeenInner>,
}

/// The set of ids [`SeenSignals`] holds, and the order they arrived in.
#[derive(Debug, Default)]
struct SeenInner {
    ids: HashSet<EventId>,
    order: VecDeque<EventId>,
}

impl SeenSignals {
    /// Record `id`, returning whether it was new. Recording a new id when
    /// [`SEEN_SIGNALS`] are held forgets the oldest.
    pub(super) fn insert(&self, id: EventId) -> bool {
        let mut inner = self.inner.lock().expect("seen-signals mutex poisoned");
        if !inner.ids.insert(id) {
            return false;
        }
        inner.order.push_back(id);
        if inner.order.len() > SEEN_SIGNALS
            && let Some(oldest) = inner.order.pop_front()
        {
            inner.ids.remove(&oldest);
        }
        true
    }
}

/// The admission policy that takes traversal signals off the relay pool's
/// notification channel and queues each one, once, on a channel of its own.
#[derive(Debug)]
pub(super) struct SignalRouter {
    signals: broadcast::Sender<RelayPoolNotification>,
    /// The signals already queued, so a copy of one that a second relay
    /// delivers is not queued again, as the pool does not notify an event
    /// twice. Its own record rather than the pool's: the pool's is shared
    /// with every advert, and a flood of those would evict signal ids from it.
    seen: SeenSignals,
}

impl SignalRouter {
    /// A router and the receiver of its channel. The receiver exists from
    /// the start, so a signal delivered before the notify loop first reads it
    /// is held rather than dropped.
    pub(super) fn new() -> (Self, broadcast::Receiver<RelayPoolNotification>) {
        let (signals, receiver) = broadcast::channel(SIGNAL_BACKLOG);
        let router = Self {
            signals,
            seen: SeenSignals::default(),
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
            if self.seen.insert(event.id) {
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
