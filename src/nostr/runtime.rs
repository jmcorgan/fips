//! The node's handle on Nostr rendezvous, and the start of the engine
//! behind it.
//!
//! The engine is one task, the pump (`pump.rs`), which owns the rendezvous
//! machine. The handle posts the node's calls to it: a send for a command,
//! a request with a `oneshot` for a query. Two queries the node makes on its
//! event loop never wait on it: the cooldown and the failure snapshot read
//! the status the pump stores after each step that changed it. Events back
//! to the node (an adopted traversal, a failed connect) arrive on one
//! channel, drained each tick.

use std::collections::{BTreeSet, HashSet};
use std::ops::ControlFlow;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::Ordering;

use arc_swap::ArcSwap;
#[cfg(test)]
use nostr::event::Event;
use nostr::key::{PublicKey, SecretKey};
use nostr::nips::nip19::ToBech32;
#[cfg(test)]
use nostr::types::{RelayUrl, Timestamp};
use nostr_sdk::client::ClientNotification;
#[cfg(test)]
use nostr_sdk::policy::AdmitStatus;
#[cfg(test)]
use serde::Serialize;
use tokio::sync::{Mutex, broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::warn;

use super::machine::NodeSigner;
use super::machine::adverts::assemble::AdvertTransportSnapshot;
#[cfg(test)]
use super::machine::event::advert as advert_codec;
#[cfg(test)]
use super::machine::event::inbox as inbox_codec;
use super::machine::params::Params;
use super::machine::rendezvous::status::Status;
use super::machine::rendezvous::{Input, PeerKey, Rendezvous};
use super::machine::traversal::rules;
#[cfg(test)]
use super::machine::traversal::rules::RejectReason;
pub(super) use super::machine::traversal::rules::{canonical_npub, short_id, short_npub};
use super::pump::{self, Inbox, Msg, Pump, ToNode, ask};
#[cfg(test)]
use super::relay::aux;
use super::relay::{PumpAuthenticator, RelayClient};
#[cfg(test)]
use super::signal::{build_signal_event, rumor};
use super::signal_route::SignalRouter;
use super::traversal::now_ms;
#[cfg(test)]
use super::types::ADVERT_IDENTIFIER;
#[cfg(test)]
use super::types::OverlayAdvert;
use super::types::{
    BootstrapError, BootstrapEvent, FailureReply, NostrFailureDecision, NostrPeerFailureView,
    NostrRefetchOutcome, OverlayEndpointAdvert,
};
use crate::config::{NostrRendezvousConfig, PeerConfig};

/// The key `npub` names, and its canonical npub (`rules::peer_key`).
fn peer_key(npub: &str) -> Result<(PublicKey, String), BootstrapError> {
    Ok(rules::peer_key(npub)?)
}

/// Which of its two feeds the notify loop was reading when it ended, as the
/// line it logs then names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Feed {
    /// The relay client's notification stream: adverts, and every other event
    /// but a traversal signal.
    Pool,
    /// The channel only traversal signals are put on.
    Signals,
}

/// What the notify loop does with one read of the signals' channel:
/// `Continue(Some(_))` hands the notification on, `Continue(None)` reads on
/// past a lag it has logged, and `Break(())` ends the loop because the
/// channel has closed. A lag does not end the loop, which would lose every
/// later signal along with those already overwritten. The relay client's own
/// stream skips past a lag of its own without a word, so only this channel's
/// lag is logged.
pub(super) fn received(
    result: Result<ClientNotification, broadcast::error::RecvError>,
) -> ControlFlow<(), Option<ClientNotification>> {
    match result {
        Ok(notification) => ControlFlow::Continue(Some(notification)),
        Err(broadcast::error::RecvError::Lagged(skipped)) => {
            warn!(
                skipped,
                "nostr signal channel lagged; traversal signals dropped"
            );
            ControlFlow::Continue(None)
        }
        Err(broadcast::error::RecvError::Closed) => {
            super::log::channel_closed(Feed::Signals);
            ControlFlow::Break(())
        }
    }
}

/// Whether an inbound-offer rejection belongs to a class that cannot be
/// explained by ordinary relay delivery lag (`RejectReason::adversarial`).
#[cfg(test)]
pub(super) fn adversarial_offer_reject(err: &BootstrapError) -> bool {
    matches!(
        err,
        BootstrapError::Protocol(reason)
            if RejectReason::from_code(reason).is_some_and(|r| r.adversarial())
    )
}

/// The endpoints as one field value, `transport:addr` per endpoint.
pub(super) fn endpoint_summary(endpoints: &[OverlayEndpointAdvert]) -> String {
    endpoints
        .iter()
        .map(|e| format!("{:?}:{}", e.transport, e.addr).to_lowercase())
        .collect::<Vec<_>>()
        .join(",")
}

/// The node's handle on Nostr rendezvous: the pump's inbox, the pump, the
/// status it stores and the events it sends.
pub struct NostrRendezvous {
    /// The pump's inbox.
    inbox: Inbox,
    /// The pump.
    pump_task: Mutex<Option<JoinHandle<()>>>,
    /// The relay client, closed at shutdown.
    client: RelayClient,
    /// What the node reads without waiting, as of the pump's last step that
    /// changed it.
    status: Arc<ArcSwap<Status>>,
    /// The events the pump sends the node, drained each tick.
    event_rx: Mutex<mpsc::UnboundedReceiver<BootstrapEvent>>,
    /// `protocol_mismatch_cooldown_secs`, as configured.
    protocol_mismatch_cooldown_secs: u64,
    /// This node's npub.
    #[cfg(test)]
    npub: String,
    /// Where the pump sends its events, for tests that queue one.
    #[cfg(test)]
    event_tx: mpsc::UnboundedSender<BootstrapEvent>,
    /// The pump's count of relay operations in flight.
    #[cfg(test)]
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
    /// The test's stand-in for the relay client's notification channel,
    /// which the pump reads, and the signal that closes it.
    #[cfg(test)]
    pool: Option<broadcast::Sender<ClientNotification>>,
    #[cfg(test)]
    pool_closed: Arc<tokio::sync::Notify>,
}

impl NostrRendezvous {
    /// Whether the Nostr subsystem has stopped being able to do its job
    /// (runtime liveness).
    ///
    /// "Nostr exited" is defined as its one task, the pump, having
    /// finished. The pump owns the rendezvous machine: it reads the relay
    /// client's stream and the signal router's channel, publishes this
    /// node's advert, keeps the relay subscriptions and runs every
    /// traversal. It runs until the client's stream or the signals' channel
    /// ends, which means the client is gone, or until `shutdown`, so a
    /// finished handle means the task panicked, was aborted or was stopped:
    /// unrecoverable, which matches the one-way `ChildExited` → `Degraded`
    /// latch in the supervisor FSM.
    ///
    /// The handle is `Some` for the engine's whole running life (installed
    /// in `start`); `shutdown` takes it, leaving `None` — a taken handle
    /// means the engine has been shut down, which counts as finished, so a
    /// `None` inner maps to `true` (this lets the liveness poll monitor
    /// terminate after a stop rather than spinning forever). The slot is a
    /// `tokio::sync::Mutex`, so this sync accessor uses the non-blocking
    /// `try_lock`: a momentarily-contended lock (only start/stop hold it,
    /// briefly) reports "not finished", the safe direction — the 2s liveness
    /// poll re-checks next tick and never spuriously degrades a healthy node.
    pub fn is_finished(&self) -> bool {
        self.pump_task
            .try_lock()
            .map(|g| g.as_ref().is_none_or(|h| h.is_finished()))
            .unwrap_or(false)
    }

    pub async fn start(
        identity: &crate::Identity,
        config: NostrRendezvousConfig,
    ) -> Result<Arc<Self>, BootstrapError> {
        if !config.enabled {
            return Err(BootstrapError::Disabled);
        }

        // Two copies of the private key are made to reach the signer: the
        // keypair and its secret key. Each is bound and cleared here; nostr's
        // `SecretKey`, which the signer holds, clears its own on drop. The
        // machine then holds the only copy.
        let mut our_keypair = identity.keypair();
        let mut secret = our_keypair.secret_key();
        let signer = NodeSigner::new(SecretKey::from(secret));
        secret.non_secure_erase();
        our_keypair.non_secure_erase();
        let npub = crate::encode_npub(&identity.pubkey());

        let (inbox, inbox_rx) = mpsc::unbounded_channel();
        let (router, signals) = SignalRouter::new();
        let client = RelayClient::build(PumpAuthenticator::new(inbox.clone()), router);

        let mut relay_union = HashSet::new();
        relay_union.extend(config.advert_relays.iter().cloned());
        relay_union.extend(config.dm_relays.iter().cloned());
        client
            .add_relays(&relay_union)
            .await
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;

        let protocol_mismatch_cooldown_secs = config.protocol_mismatch_cooldown_secs;
        let machine = Rendezvous::new(Params::from(&config), signer, npub, pump::now());
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let status = Arc::new(ArcSwap::from_pointee(Status::default()));

        // Take the relay client's notification stream BEFORE the pump can
        // issue the Nostr REQs. The stream reads a broadcast channel that
        // only delivers messages sent after it subscribes, which it does when
        // it is taken — historical events that arrive in response to a
        // subscribe (REQ replays) would otherwise be sent while no subscriber
        // exists yet, and dropped. Without this, freshly-restarted nodes with
        // `policy: open` waited up to one `advert_refresh_secs` interval
        // (default 30 min) for non-configured peers to re-publish before
        // discovering them. The signals' own channel needs no such care: its
        // receiver was made with it.
        let notifications = client.notifications();
        let pump = Pump::new(
            machine,
            client.clone(),
            inbox.clone(),
            ToNode {
                events: event_tx.clone(),
                status: Arc::clone(&status),
            },
        );
        #[cfg(test)]
        let in_flight = pump.in_flight();
        let pump_task = tokio::spawn(pump.run(notifications, signals, inbox_rx));
        // Starts each relay's connection task and returns, so the first
        // subscribe meets relays that have left their initial state.
        client.connect().await;
        let _ = inbox.send(Msg::Input(Input::Start));

        Ok(Arc::new(Self {
            inbox,
            pump_task: Mutex::new(Some(pump_task)),
            client,
            status,
            event_rx: Mutex::new(event_rx),
            protocol_mismatch_cooldown_secs,
            #[cfg(test)]
            npub: crate::encode_npub(&identity.pubkey()),
            #[cfg(test)]
            event_tx,
            #[cfg(test)]
            in_flight,
            #[cfg(test)]
            pool: None,
            #[cfg(test)]
            pool_closed: Default::default(),
        }))
    }

    /// Tell the engine whether the node has room for another peer:
    /// `Node::outbound_admission_check()`, sent when it changes. While it
    /// is `false` the engine starts no traversal and answers no offer.
    /// Loose by design: the inbound msg1 gate in `handshake.rs` remains the
    /// authoritative cap.
    pub fn set_capacity(&self, allow: bool) {
        let _ = self.inbox.send(Msg::Input(Input::Capacity(allow)));
    }

    /// Start a traversal to the peer `peer_config` names, unless one to it
    /// is already running. Its outcome arrives as an event: an adopted
    /// socket, or a failure carrying `peer_config` as given.
    pub async fn request_connect(self: &Arc<Self>, peer_config: PeerConfig) {
        let _ = self.inbox.send(Msg::Connect { peer_config });
    }

    /// Record a NAT-traversal failure for `npub`, returning the
    /// resulting decision (WARN suppression + extended cooldown +
    /// threshold-crossing flag for the B6 re-fetch) and the Unix time in
    /// milliseconds it was computed at, from which the caller measures the
    /// cooldown. With the engine stopped, the failure is not recorded: the
    /// answer is a first failure, warned, with no cooldown, at the time of
    /// the call.
    pub async fn record_traversal_failure(&self, npub: &str) -> FailureReply {
        let npub = npub.to_string();
        ask(&self.inbox, |tx| Msg::RecordFailure { npub, tx })
            .await
            .unwrap_or_else(|| FailureReply {
                decision: NostrFailureDecision {
                    consecutive_failures: 0,
                    should_warn: true,
                    cooldown_until_ms: None,
                    crossed_threshold: false,
                },
                at_ms: now_ms(),
            })
    }

    /// Cooldown wall-clock ms if the peer is currently suppressed,
    /// else None. Used by the open-discovery sweep to skip enqueue. Reads
    /// the status as of the engine's last change to it.
    pub fn cooldown_until(&self, npub: &str, now_ms: u64) -> Option<u64> {
        self.status
            .load()
            .cooldown_until(&canonical_npub(npub), now_ms)
    }

    /// Note that a datagram from the address a traversal adopted for `npub`
    /// carried an FMP version other than ours, on `transport_id` from
    /// `remote_addr`. The peer's discovery cooldown is bumped to the long
    /// protocol-mismatch window, and a fresh observation, one not already
    /// inside a comparable cooldown, is logged once at warning level, as
    /// the receive loop logged it. Does not wait.
    pub fn note_version_mismatch(
        &self,
        npub: &str,
        transport_id: impl std::fmt::Display,
        remote_addr: impl std::fmt::Display,
        peer_version: u8,
        our_version: u8,
    ) {
        let _ = self.inbox.send(Msg::Input(Input::VersionMismatch {
            npub: npub.to_string(),
            transport_id: transport_id.to_string(),
            remote_addr: remote_addr.to_string(),
            peer_version,
            our_version,
        }));
    }

    /// Configured protocol-mismatch cooldown in seconds. Exposed so log
    /// emitters can include the duration without re-reading config.
    pub fn protocol_mismatch_cooldown_secs(&self) -> u64 {
        self.protocol_mismatch_cooldown_secs
    }

    /// Snapshot of per-npub failure state for `show_peers` rendering, as of
    /// the engine's last change to it.
    pub fn failure_state_snapshot(&self) -> Vec<NostrPeerFailureView> {
        self.status.load().failure_views()
    }

    /// Stale-advert re-check (B6). Called by lifecycle on the
    /// streak-threshold transition. Actively re-queries the peer's
    /// Kind 37195 advert from `advert_relays`; evicts the cache entry
    /// if absent, refreshes if newer than the cached `created_at`,
    /// otherwise leaves the cache untouched.
    pub async fn refetch_advert_for_stale_check(&self, peer_npub: &str) -> NostrRefetchOutcome {
        // The caller passes the configured text; the cache and the failure
        // state are keyed by the canonical npub.
        let Ok((pubkey, npub)) = peer_key(peer_npub) else {
            return NostrRefetchOutcome::Skipped;
        };
        let key = PeerKey { pubkey, npub };
        ask(&self.inbox, |tx| Msg::Refetch { key, tx })
            .await
            .unwrap_or(NostrRefetchOutcome::Skipped)
    }

    pub async fn drain_events(&self) -> Vec<BootstrapEvent> {
        let mut out = Vec::new();
        let mut rx = self.event_rx.lock().await;
        while let Ok(event) = rx.try_recv() {
            out.push(event);
        }
        out
    }

    /// Hand the node's advertisable transports to the pump, which assembles
    /// and publishes the advert from them once any public address they need
    /// is learned. Does not wait.
    pub fn set_transports(&self, snapshot: Vec<AdvertTransportSnapshot>) {
        let _ = self.inbox.send(Msg::Input(Input::Transports {
            snapshot,
            reply: None,
        }));
    }

    /// As [`Self::set_transports`], and wait until the advert has been
    /// assembled from `snapshot`, which is after any public address it
    /// needs has been learned.
    pub async fn assemble_advert(
        &self,
        snapshot: Vec<AdvertTransportSnapshot>,
    ) -> Result<(), BootstrapError> {
        ask(&self.inbox, |tx| Msg::Assemble { snapshot, tx })
            .await
            .ok_or(BootstrapError::Disabled)
    }

    pub async fn advert_endpoints_for_peer(
        &self,
        peer_npub: &str,
    ) -> Result<Vec<OverlayEndpointAdvert>, BootstrapError> {
        let (pubkey, npub) = peer_key(peer_npub)?;
        let key = PeerKey { pubkey, npub };
        match ask(&self.inbox, |tx| Msg::Endpoints { key, tx }).await {
            Some(result) => Ok(result?),
            None => Err(BootstrapError::Disabled),
        }
    }

    /// `peer_npub`'s advert endpoints from the cache alone, without asking
    /// the relays: `None` when no current advert is cached or the npub does
    /// not parse. For callers on the node's event loop, which must not wait
    /// on a relay; this waits only for the pump.
    pub async fn cached_endpoints(&self, peer_npub: &str) -> Option<Vec<OverlayEndpointAdvert>> {
        let npub = PublicKey::parse(peer_npub).ok()?.to_bech32().ok()?;
        ask(&self.inbox, |tx| Msg::CachedEndpoints { npub, tx })
            .await
            .flatten()
    }

    /// Replace the set of authors whose cached adverts survive a full cache:
    /// the configured peers and the authors with an established link.
    pub fn set_advert_protection(&self, npubs: HashSet<String>) {
        let _ = self
            .inbox
            .send(Msg::Input(Input::Protection(npubs.into_iter().collect())));
    }

    /// The cached adverts the open-discovery sweep should consider: the
    /// protected entries not in `skip`, plus up to `max` unprotected entries
    /// not in `skip`, drawn at random on each call.
    pub async fn cached_open_discovery_candidates(
        &self,
        max: usize,
        skip: &HashSet<String>,
    ) -> Vec<(String, Vec<OverlayEndpointAdvert>, u64)> {
        let skip: BTreeSet<String> = skip.iter().cloned().collect();
        ask(&self.inbox, |tx| Msg::OpenDiscovery { max, skip, tx })
            .await
            .unwrap_or_default()
    }

    pub async fn shutdown(&self) -> Result<(), BootstrapError> {
        // Shutdown sends no NIP-09 retraction of the advert.
        // Parameterized-replaceable semantics handle restart supersedence,
        // and NIP-40 expiration (advert_ttl_secs) bounds staleness on
        // permanent shutdown. An explicit retraction races with the next
        // daemon's republish on strict relays (e.g. Damus rate-limits the
        // burst, leaving the advert deleted and never restored).
        let _ = self.inbox.send(Msg::Input(Input::Shutdown));
        if let Some(handle) = self.pump_task.lock().await.take() {
            // The pump aborts its operations in flight and closes its
            // sockets as it ends.
            let _ = handle.await;
        }
        // Tell the relays the connections are closed rather than leave them
        // to time out.
        self.client.shutdown().await;
        Ok(())
    }
}

#[cfg(test)]
/// Build our kind 37195 advert carrying `advert`, signed by `signer`: the
/// identifier, `app` as its protocol, the protocol version, and an
/// expiration `ttl_secs` after `now_ms`.
pub(super) fn advert_event(
    signer: &NodeSigner,
    advert: &OverlayAdvert,
    app: &str,
    ttl_secs: u64,
    now_ms: u64,
) -> Result<Event, BootstrapError> {
    let content = serde_json::to_string(advert)?;
    Ok(advert_codec::advert_event(
        signer,
        content,
        ADVERT_IDENTIFIER,
        app,
        ttl_secs,
        now_ms,
        aux(),
    )?)
}

/// Build a traversal signal carrying `payload` from `signer` to `receiver`:
/// a private message rumor written at `now_ms`, sealed and gift-wrapped,
/// expiring `ttl_secs` after `now_ms`.
#[cfg(test)]
pub(super) fn signal_event<T: Serialize>(
    signer: &NodeSigner,
    receiver: PublicKey,
    payload: &T,
    ttl_secs: u64,
    now_ms: u64,
) -> Result<Event, BootstrapError> {
    let rumor = rumor(
        signer.public_key(),
        receiver,
        serde_json::to_string(payload)?,
        now_ms,
    );
    build_signal_event(
        signer,
        receiver,
        rumor,
        Timestamp::from((now_ms + ttl_secs * 1000) / 1000),
    )
}

/// Build our kind 10050 inbox relay list: one `["r", url]` tag per relay that
/// parses, signed by `signer`.
#[cfg(test)]
pub(super) fn inbox_list(signer: &NodeSigner, relays: &[String]) -> Result<Event, BootstrapError> {
    Ok(inbox_codec::inbox_list(signer, relays, now_ms(), aux())?)
}

/// The relays a kind 10050 inbox relay list names, in order, each once.
///
/// Both the NIP-17 `["relay", url]` form and the bare `["r", url]` form are
/// read: every deployed FIPS node publishes the `r` form. An `r` tag with a
/// read or write marker is a NIP-65 entry and has no meaning here.
#[cfg(test)]
pub(super) fn inbox_relays(event: &Event) -> Vec<String> {
    inbox_codec::inbox_relays(event)
}

/// Choose the relays a traversal signal for one peer should be sent to, from
/// those the client pool holds (`rules::signal_relays`).
#[cfg(test)]
pub(super) fn signal_relays(
    inbox: &[String],
    advert_signal: Option<&[String]>,
    dm_relays: &[String],
    pool: &HashSet<RelayUrl>,
) -> Vec<String> {
    let pool: BTreeSet<RelayUrl> = pool.iter().cloned().collect();
    rules::signal_relays(inbox, advert_signal, dm_relays, &pool)
}

#[cfg(test)]
impl NostrRendezvous {
    /// Build a `NostrRendezvous` for unit tests. Its pump runs, with the
    /// real relay client, on a stand-in for the client's notification
    /// channel that [`Self::deliver_for_test`] feeds, and reads the signal
    /// router's channel as `start` has it do; it is not started (no
    /// subscribe, no publish) and its client is connected to nothing until
    /// a test adds relays. Needs a tokio runtime.
    pub(crate) fn new_for_test() -> Self {
        Self::new_for_test_with_config(NostrRendezvousConfig::default())
    }

    /// As [`Self::new_for_test`], with `config` in place of the default.
    /// The configuration is fixed here: the machine holds its copy.
    pub(crate) fn new_for_test_with_config(config: NostrRendezvousConfig) -> Self {
        let secret = loop {
            let mut bytes = [0u8; 32];
            <crate::identity::OsEntropy as fips_core::entropy::EntropySource>::fill(&mut bytes);
            if let Ok(secret) = SecretKey::from_slice(&bytes) {
                break secret;
            }
        };
        Self::new_for_test_with_secret_key(config, secret)
    }

    /// As [`Self::new_for_test_with_config`], signing as `secret_key` rather
    /// than a fresh key, for tests that need fixed keys.
    pub(crate) fn new_for_test_with_secret_key(
        config: NostrRendezvousConfig,
        secret_key: SecretKey,
    ) -> Self {
        let signer = NodeSigner::new(secret_key);
        let npub = signer.public_key().to_bech32().expect("bech32 encode");
        let (inbox, inbox_rx) = mpsc::unbounded_channel();
        let (router, signals) = SignalRouter::new();
        let client = RelayClient::build(PumpAuthenticator::new(inbox.clone()), router);
        let protocol_mismatch_cooldown_secs = config.protocol_mismatch_cooldown_secs;
        let machine = Rendezvous::new(Params::from(&config), signer, npub.clone(), pump::now());
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let status = Arc::new(ArcSwap::from_pointee(Status::default()));
        let (pool, pool_rx) = broadcast::channel(super::relay::POOL_CHANNEL);
        // Read as the client's stream reads its channel: a lag is skipped
        // and a closed channel ends the stream (nostr-sdk 0.45.6,
        // `src/stream.rs`, `NotificationStream`).
        // Closing it ends the stream, as the client's shutdown ends its own.
        let pool_closed = Arc::new(tokio::sync::Notify::new());
        let closed = Arc::clone(&pool_closed);
        let stand_in = futures::StreamExt::take_until(
            futures::stream::unfold(pool_rx, |mut receiver| async move {
                loop {
                    match receiver.recv().await {
                        Ok(notification) => return Some((notification, receiver)),
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => return None,
                    }
                }
            }),
            async move { closed.notified().await },
        );
        let pump = Pump::new(
            machine,
            client.clone(),
            inbox.clone(),
            ToNode {
                events: event_tx.clone(),
                status: Arc::clone(&status),
            },
        );
        let in_flight = pump.in_flight();
        let pump_task = tokio::spawn(pump.run(Box::pin(stand_in), signals, inbox_rx));
        Self {
            inbox,
            pump_task: Mutex::new(Some(pump_task)),
            client,
            status,
            event_rx: Mutex::new(event_rx),
            protocol_mismatch_cooldown_secs,
            npub,
            event_tx,
            in_flight,
            pool: Some(pool),
            pool_closed,
        }
    }

    /// The advert `event` carries, if it is for `expected_app` and passes
    /// every content rule (`ingest::parse`, which checks no signature).
    pub(super) fn parse_overlay_advert_event(
        event: &Event,
        expected_app: &str,
    ) -> Result<OverlayAdvert, BootstrapError> {
        use super::machine::adverts::ingest;
        ingest::parse(event, expected_app).map_err(|e| match e {
            ingest::ParseError::Invalid(e) => e.into(),
            ingest::ParseError::Json(e) => BootstrapError::Serde(e),
        })
    }

    /// A peer's advert body, checked (`ingest::validate`).
    pub(super) fn validate_overlay_advert(
        advert: OverlayAdvert,
    ) -> Result<OverlayAdvert, BootstrapError> {
        Ok(super::machine::adverts::ingest::validate(advert)?)
    }

    /// Newest event in `events` whose `pubkey` field is `author`, with no
    /// signature check (`ingest::newest_by_author`).
    pub(super) fn newest_event_by_author<'a>(
        events: impl Iterator<Item = &'a Event>,
        author: PublicKey,
    ) -> Option<&'a Event> {
        super::machine::adverts::ingest::newest_by_author(events, author)
    }

    /// The time `event`, an advert, stops being valid at `now_ms`, or `None`
    /// if it already has (`ingest::valid_until_ms`).
    pub(super) fn compute_advert_valid_until_ms(
        event: &Event,
        advert_max_age_ms: u64,
        now_ms: u64,
    ) -> Option<u64> {
        super::machine::adverts::ingest::valid_until_ms(event, advert_max_age_ms, now_ms)
    }

    /// Wait until the pump has handled everything sent to it before this
    /// call, so a read after it sees the effect of every earlier send.
    pub(crate) async fn settled_for_test(&self) {
        let _ = ask(&self.inbox, |tx| Msg::Settle { tx }).await;
    }

    /// How many relay operations the pump has in flight.
    pub(crate) fn in_flight_for_test(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Close the stand-in for the relay client's notification channel, as
    /// the client's shutdown ends its stream.
    pub(super) fn close_pool_for_test(&self) {
        self.pool_closed.notify_one();
    }

    /// A receiver of the stand-in for the relay client's notification
    /// channel, from now on, to count what is queued on it.
    pub(super) fn pool_receiver_for_test(&self) -> broadcast::Receiver<ClientNotification> {
        self.pool
            .as_ref()
            .expect("the stand-in is open")
            .subscribe()
    }

    /// Take the pump's handle out of its slot.
    pub(super) async fn take_pump_for_test(&self) -> Option<JoinHandle<()>> {
        self.pump_task.lock().await.take()
    }

    /// End the pump as `shutdown` does and wait for it, leaving the rest of
    /// the engine, the relay client among it, as it is.
    pub(super) async fn end_pump_for_test(&self) {
        let _ = self.inbox.send(Msg::Input(Input::Shutdown));
        if let Some(handle) = self.take_pump_for_test().await {
            let _ = handle.await;
        }
    }

    /// Deliver `notification` as the relay client does with an event a relay
    /// sent: through the admission policy the client was built with, and if
    /// admitted onto the stand-in for the client's notification channel
    /// (nostr-sdk 0.45.6, `src/relay/inner.rs` lines 1265 to 1320,
    /// `handle_event_msg`). Each admitted delivery takes one slot of the
    /// stand-in. The client's step that records an event as seen is not
    /// modelled; a repeat delivery costs the real channel a slot all the
    /// same, as a relay message rather than an event.
    pub(super) async fn deliver_for_test(&self, notification: ClientNotification) {
        if let ClientNotification::Event {
            relay_url,
            subscription_id,
            event,
        } = &notification
            && let Some(policy) = self.client.policy()
            && let AdmitStatus::Rejected { .. } = policy
                .admit_event(relay_url, subscription_id, event)
                .await
                .expect("admission policy")
        {
            return;
        }
        if let Some(pool) = self.pool.as_ref() {
            let _ = pool.send(notification);
        }
    }

    /// Put `notification` on the stand-in for the relay client's
    /// notification channel without the admission policy, as if a relay's
    /// event had reached the pool's stream some other way.
    pub(super) fn deliver_unfiltered_for_test(&self, notification: ClientNotification) {
        if let Some(pool) = self.pool.as_ref() {
            let _ = pool.send(notification);
        }
    }

    /// Build a `CachedOverlayAdvert` for tests with a single endpoint and
    /// a generous validity window (one hour from `now_ms()`).
    pub(crate) fn cached_advert_for_test(
        author_npub: String,
        endpoint: OverlayEndpointAdvert,
        created_at_secs: u64,
    ) -> super::types::CachedOverlayAdvert {
        super::types::CachedOverlayAdvert {
            author_npub: author_npub.clone(),
            advert: OverlayAdvert {
                identifier: ADVERT_IDENTIFIER.to_string(),
                version: super::types::ADVERT_VERSION,
                endpoints: vec![endpoint],
                signal_relays: None,
                stun_servers: None,
            },
            created_at: created_at_secs,
            valid_until_ms: now_ms().saturating_add(3_600_000),
        }
    }

    /// Point the engine's advert relays at explicit URLs, adding them to the
    /// pool and connecting. `SetAdvertRelays` replaces the machine's
    /// `params.advert_relays`, which the advert fetches read and so do a
    /// traversal's fetch of the peer's advert and its inbox relay lookup.
    /// Unit tests that exercise `refetch_advert_for_stale_check` use this to
    /// replace the default public relay list with a local relay or
    /// blackhole.
    pub(crate) async fn set_advert_relays_for_test(&self, relays: Vec<String>) {
        for url in &relays {
            let _ = self.client.add_relays([url]).await;
        }
        self.client.connect().await;
        let _ = self.inbox.send(Msg::Input(Input::SetAdvertRelays(relays)));
    }

    /// Insert a cached advert directly into the advert cache. Used by unit
    /// tests to set up consumer-side state without needing live relays.
    pub(crate) async fn insert_advert_for_test(
        &self,
        npub: String,
        advert: super::types::CachedOverlayAdvert,
    ) {
        let _ = ask(&self.inbox, |tx| Msg::InsertAdvert { npub, advert, tx }).await;
    }

    /// The authors the advert cache currently protects.
    pub(crate) async fn advert_protection_for_test(&self) -> HashSet<String> {
        let npub = String::new();
        ask(&self.inbox, |tx| Msg::Inspect { npub, tx })
            .await
            .map(|inspection| inspection.protected.into_iter().collect())
            .unwrap_or_default()
    }

    /// The relay client's relays, for their connection status.
    pub(crate) async fn relays_for_test(&self) -> Vec<nostr_sdk::relay::Relay> {
        self.client.relays().await
    }

    /// How many sets of transports the engine has been handed.
    pub(crate) async fn transports_received_for_test(&self) -> u64 {
        let npub = String::new();
        ask(&self.inbox, |tx| Msg::Inspect { npub, tx })
            .await
            .map(|inspection| inspection.transports)
            .unwrap_or_default()
    }

    /// The cached `created_at` for `npub`, or `None` when nothing is cached.
    /// Lets a unit test observe whether a refetch evicted an entry.
    pub(crate) async fn cached_created_at_for_test(&self, npub: &str) -> Option<u64> {
        let npub = npub.to_string();
        ask(&self.inbox, |tx| Msg::Inspect { npub, tx })
            .await
            .and_then(|inspection| inspection.created_at)
    }

    /// How many times the node has sent its capacity.
    pub(crate) async fn capacity_received_for_test(&self) -> u64 {
        let npub = String::new();
        ask(&self.inbox, |tx| Msg::Inspect { npub, tx })
            .await
            .map(|inspection| inspection.capacity)
            .unwrap_or_default()
    }

    /// Wait for an answer to our offer whose nonce is `nonce`: the returned
    /// receiver completes when the engine routes such an answer, as it
    /// hands one to the traversal that sent the offer. The engine counts
    /// the wait as a traversal waiting on an answer.
    pub(super) async fn await_answer_for_test(
        &self,
        nonce: &str,
    ) -> tokio::sync::oneshot::Receiver<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let nonce = nonce.to_string();
        let _ = self.inbox.send(Msg::AwaitAnswer { nonce, tx });
        self.settled_for_test().await;
        rx
    }

    /// This runtime's own npub.
    pub(crate) fn npub_for_test(&self) -> &str {
        &self.npub
    }

    /// Install the pump's handle, so liveness tests can drive
    /// `is_finished()` without live relays. The handle it replaces is
    /// dropped, which leaves its task running.
    pub(crate) async fn install_task_handle_for_test(&self, pump: JoinHandle<()>) {
        *self.pump_task.lock().await = Some(pump);
    }

    /// Take the pump's handle out of its slot, as `shutdown` does.
    pub(crate) async fn take_task_handle_for_test(&self) {
        self.pump_task.lock().await.take();
    }

    /// Queue a bootstrap event directly for lifecycle tests without live relays
    /// or a running traversal.
    pub(crate) fn push_event_for_test(&self, event: BootstrapEvent) {
        let _ = self.event_tx.send(event);
    }
}
