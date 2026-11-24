//! The relay client, behind the calls the shell makes on it.
//!
//! Every call the shell makes on the Nostr relay client goes through
//! [`RelayClient`], one method per call, so the relay client's API is named in
//! this file alone. Each method returns the client's own error; its caller
//! maps that onto `BootstrapError`, as it did when it called the client
//! itself.

use std::collections::HashSet;
#[cfg(test)]
use std::sync::Arc;
use std::time::Duration;

use nostr::prelude::{Event, Filter, Keys, RelayUrl};
#[cfg(test)]
use nostr_sdk::prelude::AdmitPolicy;
use nostr_sdk::prelude::RelayPoolNotification;
use nostr_sdk::{Client, ClientOptions};
use tokio::sync::broadcast;

use super::signal_route::SignalRouter;

/// The error every relay-client call returns.
pub(super) type Error = nostr_sdk::client::Error;

/// The relay client, signing with the node's keys, with inbound traversal
/// signals taken off its notification channel by a [`SignalRouter`]. One
/// client serves signals and adverts alike, so the signals' channel adds no
/// relay connection.
pub(super) struct RelayClient {
    client: Client,
    /// The admission policy the client was built with, as the client holds
    /// it, so unit tests can deliver events through it as a relay connection
    /// does.
    #[cfg(test)]
    policy: Option<Arc<dyn AdmitPolicy>>,
}

impl RelayClient {
    /// A client signing with `keys` and admitting each delivered event
    /// through `router`. It connects to nothing until [`Self::connect`].
    pub(super) fn build(keys: &Keys, router: SignalRouter) -> Self {
        let builder = Client::builder()
            .signer(keys.clone())
            .admit_policy(router)
            .opts(ClientOptions::new().autoconnect(false));
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

    /// A receiver of every event the pool's relays deliver from now on, but
    /// a traversal signal, which the router takes. An event delivered before
    /// this call is not on it.
    pub(super) fn notifications(&self) -> broadcast::Receiver<RelayPoolNotification> {
        self.client.notifications()
    }

    /// Open a long-lived subscription to `filter` on `urls`, under an id the
    /// client chooses.
    pub(super) async fn subscribe(&self, urls: Vec<String>, filter: Filter) -> Result<(), Error> {
        self.client.subscribe_to(urls, filter, None).await?;
        Ok(())
    }

    /// The events `urls` hold that match `filter`, collected until every
    /// relay has said it has sent them all or `timeout` has passed, newest
    /// first.
    pub(super) async fn fetch(
        &self,
        urls: Vec<String>,
        filter: Filter,
        timeout: Duration,
    ) -> Result<Vec<Event>, Error> {
        let events = self.client.fetch_events_from(urls, filter, timeout).await?;
        Ok(events.into_iter().collect())
    }

    /// Send `event` to `urls`. An error means the send was refused as a
    /// whole, as when one of `urls` is not in the pool; relays that took the
    /// send and then failed it do not make it an error.
    pub(super) async fn send(&self, urls: &[String], event: &Event) -> Result<(), Error> {
        self.client.send_event_to(urls.to_vec(), event).await?;
        Ok(())
    }

    /// The relays in the client's pool.
    pub(super) async fn pool_urls(&self) -> HashSet<RelayUrl> {
        self.client.pool().all_relays().await.into_keys().collect()
    }

    /// The admission policy the client was built with.
    #[cfg(test)]
    pub(super) fn policy(&self) -> Option<&Arc<dyn AdmitPolicy>> {
        self.policy.as_ref()
    }
}
