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
use std::sync::Arc;
use std::time::Duration;

use futures::Stream;
use nostr::event::Event;
use nostr::filter::Filter;
use nostr::types::RelayUrl;
use nostr_sdk::authenticator::Authenticator;
use nostr_sdk::client::{Client, ClientBuilder, ClientNotification, ReqTarget};
#[cfg(test)]
use nostr_sdk::policy::AdmitPolicy;

use super::machine::NodeSigner;
use super::machine::event::auth::auth_event;
use super::signal_route::SignalRouter;
use super::traversal::now_ms;

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

/// The client's NIP-42 authenticator: it answers a relay's challenge with an
/// authentication event signed by the node key.
#[derive(Debug)]
struct NodeAuthenticator {
    signer: Arc<NodeSigner>,
}

impl Authenticator for NodeAuthenticator {
    /// The node's answer to `relay_url`'s `challenge`, created now, with
    /// fresh randomness for its signature.
    fn make_auth_event<'a>(
        &'a self,
        relay_url: &'a RelayUrl,
        challenge: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Event, Error>> + Send + 'a>> {
        Box::pin(async move {
            auth_event(&self.signer, relay_url, challenge, now_ms(), aux())
                .map_err(|e| Error::other(e.to_string()))
        })
    }
}

/// Fresh auxiliary randomness for a signature, from the host's source.
pub(super) fn aux() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    <crate::identity::OsEntropy as fips_core::entropy::EntropySource>::fill(&mut bytes);
    bytes
}

/// The relay client, with inbound traversal signals taken off its
/// notification channel by a [`SignalRouter`], and relay authentication
/// answered with the node key. It holds no signer of its own: the events it
/// sends are signed before they reach it. One client serves signals and
/// adverts alike, so the signals' channel adds no relay connection.
pub(super) struct RelayClient {
    client: Client,
    /// The admission policy the client was built with, as the client holds
    /// it, so unit tests can deliver events through it as a relay connection
    /// does.
    #[cfg(test)]
    policy: Option<Arc<dyn AdmitPolicy>>,
}

impl RelayClient {
    /// A client answering relay authentication with `signer` and admitting
    /// each delivered event through `router`. It connects to nothing until
    /// [`Self::connect`].
    ///
    /// `verify_subscriptions` and `ban_relay_on_mismatch` stay off, their
    /// default in both nostr-sdk 0.44 and 0.45: the callers check what a
    /// relay returns themselves.
    pub(super) fn build(signer: Arc<NodeSigner>, router: SignalRouter) -> Self {
        let builder = ClientBuilder::new()
            .admit_policy(router)
            .authenticator(NodeAuthenticator { signer })
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

    /// Open a long-lived subscription to `filter` on `urls`, under an id the
    /// client chooses.
    pub(super) async fn subscribe(&self, urls: Vec<String>, filter: Filter) -> Result<(), Error> {
        let targets: Vec<(String, Vec<Filter>)> = urls
            .into_iter()
            .map(|url| (url, vec![filter.clone()]))
            .collect();
        self.client.subscribe(ReqTarget::manual(targets)).await?;
        Ok(())
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

    /// Send `event` to `urls`. An error means the send was refused as a
    /// whole, as when one of `urls` is not in the pool; relays that took the
    /// send and then failed it do not make it an error.
    pub(super) async fn send(&self, urls: &[String], event: &Event) -> Result<(), Error> {
        self.client
            .send_event(event)
            .to(urls)
            .authentication_timeout(AUTH_TIMEOUT)
            .await?;
        Ok(())
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
