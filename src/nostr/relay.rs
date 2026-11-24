//! The relay client, behind the calls the shell makes on it.
//!
//! Every call the shell makes on the Nostr relay client goes through
//! [`RelayClient`], one method per call, so the relay client's API is named in
//! this file alone. Each method returns the client's own error; its caller
//! maps that onto `BootstrapError`, as it did when it called the client
//! itself.
//!
//! The client is nostr-sdk 0.45's. Where that release's default differs from
//! the 0.44 client FIPS ran before, the setting that keeps the 0.44 value is
//! made here, with both values beside it.

use std::collections::HashSet;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
#[cfg(test)]
use std::sync::Arc;
use std::time::Duration;

use futures::Stream;
use nostr::event::Event;
use nostr::filter::Filter;
use nostr::message::SubscriptionId;
use nostr::types::RelayUrl;
use nostr_sdk::authenticator::Authenticator;
use nostr_sdk::client::{Client, ClientBuilder, ClientNotification, ReqTarget};
#[cfg(test)]
use nostr_sdk::policy::AdmitPolicy;

use super::pump::{Inbox, Msg, ask};
use super::signal_route::SignalRouter;

/// The error every relay-client call returns.
pub(super) type Error = nostr_sdk::error::Error;

/// The stream of what the pool's relays deliver.
pub(super) type Notifications = Pin<Box<dyn Stream<Item = ClientNotification> + Send>>;

/// How many notifications the client's channel holds unread: 4096, the
/// default of both nostr-sdk 0.44 and 0.45, set here so it cannot move
/// with a release. A `usize`, for the tests that size a channel by it.
pub(crate) const POOL_CHANNEL: usize = 4096;

/// [`POOL_CHANNEL`] as the client builder takes it.
const POOL_CHANNEL_SIZE: NonZeroUsize = NonZeroUsize::new(POOL_CHANNEL).unwrap();

/// How long a relay connection may take to open. nostr-sdk 0.45 defaults to
/// 15 s (`ClientBuilder::default`, `client/builder.rs`); 0.44 used 60 s
/// (`relay/constants.rs`), which this keeps.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a send waits for a relay that asked for authentication to accept
/// it. nostr-sdk 0.45 waits 10 s (`SendEvent::new`,
/// `client/api/send_event.rs`); 0.44 waited 7 s (`relay/constants.rs`), which
/// this keeps.
const AUTH_TIMEOUT: Duration = Duration::from_secs(7);

/// The client's NIP-42 authenticator: it posts a relay's challenge to the
/// pump, whose machine answers it with an authentication event signed by
/// the node key, and awaits that answer.
#[derive(Debug)]
pub(super) struct PumpAuthenticator {
    inbox: Inbox,
}

impl PumpAuthenticator {
    /// An authenticator asking the pump behind `inbox`.
    pub(super) fn new(inbox: Inbox) -> Self {
        Self { inbox }
    }
}

impl Authenticator for PumpAuthenticator {
    /// The machine's answer to `relay_url`'s `challenge`. A pump that has
    /// stopped answers nothing, and the relay is told so.
    fn make_auth_event<'a>(
        &'a self,
        relay_url: &'a RelayUrl,
        challenge: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Event, Error>> + Send + 'a>> {
        Box::pin(async move {
            let answer = ask(&self.inbox, |tx| Msg::Auth {
                relay: relay_url.clone(),
                challenge: challenge.to_string(),
                tx,
            })
            .await;
            match answer {
                Some(Ok(event)) => Ok(event),
                Some(Err(e)) => Err(Error::other(e.to_string())),
                None => Err(Error::other("rendezvous stopped")),
            }
        })
    }
}

/// Fresh auxiliary randomness for a signature, from the host's source.
#[cfg(test)]
pub(super) fn aux() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    <crate::identity::OsEntropy as fips_core::entropy::EntropySource>::fill(&mut bytes);
    bytes
}

/// The relay client, with inbound traversal signals taken off its
/// notification channel by a [`SignalRouter`], and relay authentication
/// answered by the authenticator it was built with. It holds no signer of
/// its own: the events it sends are signed before they reach it. One client
/// serves signals and adverts alike, so the signals' channel adds no relay
/// connection. Clones share the one client.
#[derive(Clone)]
pub(super) struct RelayClient {
    client: Client,
    /// The admission policy the client was built with, as the client holds
    /// it, so unit tests can deliver events through it as a relay connection
    /// does.
    #[cfg(test)]
    policy: Option<Arc<dyn AdmitPolicy>>,
}

impl RelayClient {
    /// A client answering relay authentication with `authenticator` and
    /// admitting each delivered event through `router`. It connects to
    /// nothing until [`Self::connect`].
    ///
    /// `verify_subscriptions` and `ban_relay_on_mismatch` stay off, their
    /// default in both nostr-sdk 0.44 and 0.45: the callers check what a
    /// relay returns themselves.
    pub(super) fn build(authenticator: impl Authenticator + 'static, router: SignalRouter) -> Self {
        let builder = ClientBuilder::new()
            .admit_policy(router)
            .authenticator(authenticator)
            .connect_timeout(CONNECT_TIMEOUT)
            .notification_channel_size(POOL_CHANNEL_SIZE);
        #[cfg(test)]
        let policy = builder.admit_policy.clone();
        Self {
            client: builder.build(),
            #[cfg(test)]
            policy,
        }
    }

    /// Add each of `urls` to the client's pool, stopping at the first that
    /// is refused.
    pub(super) async fn add_relays<I, S>(&self, urls: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for url in urls {
            self.client.add_relay(url.as_ref()).await?;
        }
        Ok(())
    }

    /// Start connecting to every relay in the pool. Returns once each
    /// relay's connection task is started, not once it is connected.
    pub(super) async fn connect(&self) {
        self.client.connect().await;
    }

    /// A stream of every event the pool's relays deliver from now on, but a
    /// traversal signal, which the router takes. An event delivered before
    /// this call is not on it. It skips past what it missed when it falls
    /// behind, and ends when the client shuts down.
    pub(super) fn notifications(&self) -> Notifications {
        self.client.notifications()
    }

    /// Open a long-lived subscription to `filter` on `urls` under `id`.
    /// Returns how many relays took it. A relay that already holds a
    /// subscription under `id` refuses it, before any REQ is sent, and keeps
    /// the one it holds; that refusal is per relay, not an error.
    pub(super) async fn subscribe(
        &self,
        urls: Vec<String>,
        filter: Filter,
        id: SubscriptionId,
    ) -> Result<usize, Error> {
        let targets: Vec<(String, Vec<Filter>)> = urls
            .into_iter()
            .map(|url| (url, vec![filter.clone()]))
            .collect();
        let output = self
            .client
            .subscribe(ReqTarget::manual(targets))
            .with_id(id)
            .await?;
        Ok(output.success.len())
    }

    /// Close every relay connection and end the notification stream.
    pub(super) async fn shutdown(&self) {
        self.client.shutdown().await;
    }

    /// The pool's relays, whose status a test reads; a shut-down client
    /// holds none, so a test takes them before.
    #[cfg(test)]
    pub(super) async fn relays(&self) -> Vec<nostr_sdk::relay::Relay> {
        self.client.relays().await.into_values().collect()
    }

    /// How many subscriptions the client holds.
    #[cfg(test)]
    pub(super) async fn subscription_count(&self) -> usize {
        self.client.subscriptions().await.len()
    }

    /// The events `urls` hold that match `filter`, collected until every
    /// relay has said it has sent them all or `timeout` has passed, newest
    /// first.
    ///
    /// nostr-sdk 0.45 refuses a fetch past 10,000 events by default
    /// (`DEFAULT_FETCH_EVENTS_LIMIT`, `relay/constants.rs`); 0.44 had no such
    /// limit, which `max_events(usize::MAX)` keeps.
    pub(super) async fn fetch(
        &self,
        urls: Vec<String>,
        filter: Filter,
        timeout: Duration,
    ) -> Result<Vec<Event>, Error> {
        let targets: Vec<(String, Vec<Filter>)> = urls
            .into_iter()
            .map(|url| (url, vec![filter.clone()]))
            .collect();
        let events = self
            .client
            .fetch_events(ReqTarget::manual(targets))
            .timeout(timeout)
            .max_events(usize::MAX)
            .await?;
        Ok(events.into_iter().collect())
    }

    /// Send `event` to `urls`, returning how many relays accepted it. An
    /// error means the send was refused as a whole, as when one of `urls` is
    /// not in the pool; relays that took the send and then failed it do not
    /// make it an error, and are not counted.
    pub(super) async fn send(&self, urls: &[String], event: &Event) -> Result<usize, Error> {
        let output = self
            .client
            .send_event(event)
            .to(urls)
            .authentication_timeout(AUTH_TIMEOUT)
            .await?;
        Ok(output.success.len())
    }

    /// The relays in the client's pool.
    pub(super) async fn pool_urls(&self) -> HashSet<RelayUrl> {
        self.client.relays().all().await.into_keys().collect()
    }

    /// The admission policy the client was built with.
    #[cfg(test)]
    pub(super) fn policy(&self) -> Option<&Arc<dyn AdmitPolicy>> {
        self.policy.as_ref()
    }
}

#[cfg(test)]
#[path = "tests/relay.rs"]
mod tests;
