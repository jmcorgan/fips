use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use nostr::nips::nip17;
use nostr::nips::nip19::ToBech32;
use nostr::prelude::{
    Alphabet, Event, EventBuilder, EventId, Filter, Kind, PublicKey, RelayUrl, SingleLetterTag,
    Tag, TagKind, Timestamp,
};
use nostr_sdk::{Client, ClientOptions, prelude::RelayPoolNotification};
use serde::Serialize;
use tokio::sync::{Mutex, Notify, RwLock, broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

use super::advert::{AdvertMachine, PublishPlan};
use super::failure_state::FailureState;
use super::handoff::EstablishedTraversal;
use super::offer_admission::{AdmissionReject, OfferAdmission};
use super::signal::{
    FreshnessOutcome, SignalEnvelope, build_signal_event, create_traversal_answer,
    create_traversal_offer, estimate_clock_skew, unwrap_signal_event, validate_offer_freshness,
    validate_traversal_answer_for_offer,
};
use super::stun::observe_traversal_addresses;
use super::traversal::{
    PunchTargetTally, is_doc_ip, is_never_punchable_ip, is_private_ip, nonce, now_ms,
    planned_remote_endpoints, run_punch_attempt,
};
use super::traversal_machine::{OfferDisposition, SeenDecision, TraversalMachine};
use super::types::{
    ADVERT_IDENTIFIER, ADVERT_KIND, ADVERT_VERSION, BootstrapError, BootstrapEvent,
    CachedOverlayAdvert, NostrFailureDecision, NostrPeerFailureView, NostrRefetchOutcome,
    OverlayAdvert, OverlayEndpointAdvert, PROTOCOL_VERSION, PunchHint, SIGNAL_KIND,
    TraversalAnswer, TraversalOffer,
};
use crate::PeerIdentity;
use crate::config::{NostrRendezvousConfig, PeerConfig};

const ADVERT_CACHE_STALE_GRACE_MULTIPLIER: u64 = 2;

fn short_npub(npub: &str) -> String {
    npub.strip_prefix("npub1")
        .filter(|s| s.len() >= 8)
        .map(|s| format!("npub1{}..{}", &s[..4], &s[s.len() - 4..]))
        .unwrap_or_else(|| npub.to_string())
}

/// Whether an inbound-offer rejection belongs to a class that cannot be
/// explained by ordinary relay delivery lag, and therefore warrants a warning
/// on a node running at the default log level. A stale offer is benign and is
/// deliberately excluded.
pub(super) fn adversarial_offer_reject(err: &BootstrapError) -> bool {
    matches!(
        err,
        BootstrapError::Protocol(reason)
            if reason == "future-dated-offer"
                || reason == "identity-mismatch"
                || reason == "invalid-offer"
    )
}

/// Shorten a peer-supplied identifier for logging.
///
/// Truncates on a character boundary rather than a byte index. The input is a
/// session id taken straight from a remote party's JSON with no charset
/// validation, and slicing by byte offset panics when the boundary falls
/// inside a multi-byte character.
pub(super) fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

/// Record, once per planning call, the punch candidates a peer named that we
/// declined to punch.
///
/// One aggregated record rather than one per candidate: a peer's candidate
/// list is unbounded, so per-candidate logging would trade the packet
/// amplification the filter closes for a log amplification. `warn` is used for
/// the shapes no honest peer produces, because `info` is the level a shipped
/// node collects by default and those refusals are the ones an operator needs
/// to see; the routine off-subnet case stays at `debug`.
fn log_refusals(tally: &PunchTargetTally, peer: &str, session: &str) {
    if tally.offered <= tally.admitted && tally.capped == 0 {
        return;
    }
    let sample = tally.sample.as_deref().unwrap_or("-");
    let reflexive = tally.reflexive.unwrap_or("-");
    if tally.suspicious() {
        warn!(
            peer = %peer,
            session = %session,
            offered = tally.offered,
            admitted = tally.admitted,
            unparsable = tally.unparsable,
            zeroport = tally.zeroport,
            unroutable = tally.unroutable,
            offsubnet = tally.offsubnet,
            capped = tally.capped,
            reflexive = %reflexive,
            sample = %sample,
            "traversal: punch candidates refused"
        );
    } else {
        debug!(
            peer = %peer,
            session = %session,
            offered = tally.offered,
            admitted = tally.admitted,
            unparsable = tally.unparsable,
            zeroport = tally.zeroport,
            unroutable = tally.unroutable,
            offsubnet = tally.offsubnet,
            capped = tally.capped,
            reflexive = %reflexive,
            sample = %sample,
            "traversal: punch candidates refused"
        );
    }
}

fn endpoint_summary(endpoints: &[OverlayEndpointAdvert]) -> String {
    endpoints
        .iter()
        .map(|e| format!("{:?}:{}", e.transport, e.addr).to_lowercase())
        .collect::<Vec<_>>()
        .join(",")
}

/// Addresses an advert must not name as a directly dialable endpoint: the
/// never-punchable ranges plus the private and documentation ones, which are
/// useless to a peer that found the advert on a relay.
pub(super) fn is_unroutable_direct_advert_ip(ip: std::net::IpAddr) -> bool {
    is_never_punchable_ip(ip) || is_private_ip(ip) || is_doc_ip(ip)
}

pub(super) fn endpoint_advert_is_publicly_usable(endpoint: &OverlayEndpointAdvert) -> bool {
    let addr = endpoint.addr.trim();
    if addr.is_empty() {
        return false;
    }

    if endpoint.transport == super::types::OverlayTransportKind::Udp
        && addr.eq_ignore_ascii_case("nat")
    {
        return true;
    }
    if addr.eq_ignore_ascii_case("nat") {
        return false;
    }

    match endpoint.transport {
        super::types::OverlayTransportKind::Udp | super::types::OverlayTransportKind::Tcp => {
            let Ok(socket_addr) = addr.parse::<SocketAddr>() else {
                let Some((host, port)) = addr.rsplit_once(':') else {
                    return false;
                };
                let host = host.trim().trim_start_matches('[').trim_end_matches(']');
                if host.is_empty() || port.trim().parse::<u16>().ok().is_none_or(|p| p == 0) {
                    return false;
                }
                if host.eq_ignore_ascii_case("localhost") {
                    return false;
                }
                return host
                    .parse::<std::net::IpAddr>()
                    .ok()
                    .is_none_or(|ip| !is_unroutable_direct_advert_ip(ip));
            };
            socket_addr.port() != 0 && !is_unroutable_direct_advert_ip(socket_addr.ip())
        }
        super::types::OverlayTransportKind::Tor => true,
    }
}

/// Cached STUN-derived public address for an advert-eligible UDP transport
/// bound to a wildcard. Lives on `NostrRendezvous` so the freshness window
/// survives advert refresh cycles.
struct CachedPublicUdpAddr {
    /// Most recent STUN observation. `None` means the last attempt failed
    /// (recorded so we don't re-spam STUN every refresh tick on broken
    /// network conditions).
    addr: Option<SocketAddr>,
    fetched_at: Instant,
}

/// Cache lifetime for a *failed* STUN observation. Held briefly so that
/// transient flakes (slow startup network, momentary STUN-server
/// blip) get retried within ~a minute and the advert grows its UDP
/// endpoint as soon as STUN starts working — rather than waiting a
/// full `advert_refresh_secs` (30 min) for the success-path TTL to
/// expire. Successful results use the longer per-config TTL.
const PUBLIC_UDP_ADDR_FAILURE_TTL: Duration = Duration::from_secs(60);
const RELAY_STARTUP_OP_TIMEOUT: Duration = Duration::from_secs(5);
const ADVERT_PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);

pub struct NostrRendezvous {
    client: Client,
    keys: nostr::Keys,
    pubkey: PublicKey,
    npub: String,
    config: NostrRendezvousConfig,
    advert: AdvertMachine,
    traversal: TraversalMachine,
    pending_answers: Mutex<HashMap<String, oneshot::Sender<SignalEnvelope<TraversalAnswer>>>>,
    admission: OfferAdmission,
    event_tx: mpsc::UnboundedSender<BootstrapEvent>,
    event_rx: Mutex<mpsc::UnboundedReceiver<BootstrapEvent>>,
    connect_task: Mutex<Option<JoinHandle<()>>>,
    relay_startup_task: Mutex<Option<JoinHandle<()>>>,
    publish_task: Mutex<Option<JoinHandle<()>>>,
    publish_notify: Notify,
    notify_task: Mutex<Option<JoinHandle<()>>>,
    advertise_task: Mutex<Option<JoinHandle<()>>>,
    failure_state: FailureState,
    /// STUN-derived public address per advert-eligible UDP transport
    /// (keyed by `TransportId.as_u32()`). Populated on demand by
    /// `learn_public_udp_addr()` and refreshed by TTL.
    public_udp_addr_cache: RwLock<HashMap<u32, CachedPublicUdpAddr>>,
    /// Outbound-admission flag refreshed once per Node tick from
    /// `Node::outbound_admission_check()`. Used to suppress NAT-traversal
    /// punch initiation (initiator path) and offer acceptance (responder
    /// path) when the Node is at `max_peers`. Loose granularity by
    /// design: the inbound msg1 gate in `handshake.rs` remains the
    /// authoritative cap.
    outbound_admission: AtomicBool,
}

impl NostrRendezvous {
    /// Whether the Nostr subsystem has stopped being able to do its job
    /// (runtime liveness).
    ///
    /// "Nostr exited" is defined as *any* of the three service loops that never
    /// return by design having finished:
    ///
    /// - `notify_task` — the inbound receive loop. Without it no advert and no
    ///   traversal signal is ever observed again.
    /// - `publish_task` — the advert publisher. Without it this node stops being
    ///   discoverable.
    /// - `advertise_task` — the refresh ticker that drives the publisher.
    ///
    /// Each of these is an unconditional `loop` (the notify loop's only `break`
    /// is the relay-pool broadcast channel closing, i.e. the pool itself is
    /// gone), so a finished handle means the task panicked or was aborted:
    /// unrecoverable, which matches the one-way `ChildExited` → `Degraded`
    /// latch in the supervisor FSM.
    ///
    /// Deliberately *not* watched: `connect_task` and `relay_startup_task`.
    /// `Client::connect()` only spawns a per-relay background connection task
    /// and returns, so `connect_task` finishes moments after start on a
    /// perfectly healthy node; `relay_startup_task` breaks out of its retry loop
    /// on the first successful subscribe. Watching either reports Degraded on
    /// every node forever.
    ///
    /// Each handle is `Some` for the engine's whole running life (installed in
    /// `start`); `shutdown` takes them all, leaving `None` — a taken handle
    /// means the engine has been shut down, which counts as finished, so a
    /// `None` inner maps to `true` (this lets the liveness poll monitor
    /// terminate after a stop rather than spinning forever). The slots are
    /// `tokio::sync::Mutex`es, so this sync accessor uses the non-blocking
    /// `try_lock`: a momentarily-contended lock (only start/stop hold it,
    /// briefly) reports "not finished", the safe direction — the 2s liveness
    /// poll re-checks next tick and never spuriously degrades a healthy node.
    pub fn is_finished(&self) -> bool {
        Self::task_finished(&self.notify_task)
            || Self::task_finished(&self.publish_task)
            || Self::task_finished(&self.advertise_task)
    }

    /// Liveness of one task slot: finished if the handle is gone (shut down) or
    /// the task has completed; "not finished" when the slot is momentarily
    /// locked by start/stop.
    fn task_finished(slot: &Mutex<Option<JoinHandle<()>>>) -> bool {
        slot.try_lock()
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

        let keys = nostr::Keys::parse(&hex::encode(identity.keypair().secret_bytes()))
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        let client = Client::builder()
            .signer(keys.clone())
            .opts(ClientOptions::new().autoconnect(false))
            .build();

        let mut relay_union = HashSet::new();
        relay_union.extend(config.advert_relays.iter().cloned());
        relay_union.extend(config.dm_relays.iter().cloned());
        for relay in relay_union {
            client
                .add_relay(&relay)
                .await
                .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        }
        let pubkey = keys.public_key();
        let npub = crate::encode_npub(&identity.pubkey());
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let admission = OfferAdmission::new(
            config.max_concurrent_incoming_offers,
            config.max_concurrent_offers_per_npub,
        );

        let failure_state = FailureState::new(
            config.failure_streak_threshold,
            config.extended_cooldown_secs,
            config.warn_log_interval_secs,
            config.failure_state_max_entries,
        );

        let advert = AdvertMachine::new(
            npub.clone(),
            config.advertise,
            config.advert_ttl_secs * 1000 * ADVERT_CACHE_STALE_GRACE_MULTIPLIER,
            config.advert_cache_max_entries,
        );
        let traversal = TraversalMachine::new(
            config.replay_window_secs * 1000,
            config.seen_sessions_max_entries,
        );
        let runtime = Arc::new(Self {
            client,
            keys,
            pubkey,
            npub,
            config,
            advert,
            traversal,
            pending_answers: Mutex::new(HashMap::new()),
            admission,
            event_tx,
            event_rx: Mutex::new(event_rx),
            connect_task: Mutex::new(None),
            relay_startup_task: Mutex::new(None),
            publish_task: Mutex::new(None),
            publish_notify: Notify::new(),
            notify_task: Mutex::new(None),
            advertise_task: Mutex::new(None),
            failure_state,
            public_udp_addr_cache: RwLock::new(HashMap::new()),
            outbound_admission: AtomicBool::new(true),
        });

        // Subscribe to the relay-pool broadcast channel BEFORE issuing the
        // Nostr REQs. tokio's broadcast channel only delivers messages sent
        // after the receiver is created — historical events that arrive in
        // response to subscribe() (REQ replays) would otherwise be dropped
        // by the pool's `external_notification_sender.send(...)` returning
        // `Err(SendError)` when no subscriber exists yet. Without this,
        // freshly-restarted nodes with `policy: open` waited up to one
        // `advert_refresh_secs` interval (default 30 min) for non-configured
        // peers to re-publish before discovering them.
        let notifications = runtime.client.notifications();
        *runtime.publish_task.lock().await = Some(runtime.clone().spawn_publish_loop());
        *runtime.connect_task.lock().await = Some(runtime.clone().spawn_connect_loop());
        *runtime.relay_startup_task.lock().await = Some(runtime.clone().spawn_relay_startup_loop());
        *runtime.advertise_task.lock().await = Some(runtime.clone().spawn_advertise_loop());
        *runtime.notify_task.lock().await = Some(runtime.clone().spawn_notify_loop(notifications));

        Ok(runtime)
    }

    /// Update the cached outbound-admission flag. Called once per Node
    /// tick with the current value of `Node::outbound_admission_check()`.
    /// Cheap atomic store; safe to call unconditionally.
    pub fn set_outbound_admission(&self, allow: bool) {
        self.outbound_admission.store(allow, Ordering::Relaxed);
    }

    /// Read the cached outbound-admission flag. Returns `true` when the
    /// Node is below `max_peers` (or `max_peers == 0`), `false` otherwise.
    pub(crate) fn outbound_admission_allowed(&self) -> bool {
        self.outbound_admission.load(Ordering::Relaxed)
    }

    pub async fn request_connect(self: &Arc<Self>, peer_config: PeerConfig) {
        let peer_npub = peer_config.npub.clone();
        if !self.traversal.begin_initiator(&peer_npub) {
            return;
        }

        let runtime = Arc::clone(self);
        tokio::spawn(async move {
            let event = match runtime.connect_peer(peer_config.clone()).await {
                Ok(traversal) => BootstrapEvent::Established { traversal },
                Err(err) => BootstrapEvent::Failed {
                    peer_config,
                    reason: err.to_string(),
                },
            };
            let _ = runtime.event_tx.send(event);
            runtime.traversal.end_initiator(&peer_npub);
        });
    }

    /// Record a NAT-traversal failure for `npub`, returning the
    /// resulting decision (WARN suppression + extended cooldown +
    /// threshold-crossing flag for the B6 re-fetch).
    pub fn record_traversal_failure(&self, npub: &str, now_ms: u64) -> NostrFailureDecision {
        let d = self.failure_state.record_failure(npub, now_ms);
        NostrFailureDecision {
            consecutive_failures: d.consecutive_failures,
            should_warn: d.should_warn,
            cooldown_until_ms: d.cooldown_until_ms,
            crossed_threshold: d.crossed_threshold,
        }
    }

    /// Record a successful traversal — clears the streak/cooldown.
    pub fn record_traversal_success(&self, npub: &str, now_ms: u64) {
        self.failure_state.record_success(npub, now_ms);
    }

    /// Cooldown wall-clock ms if the peer is currently suppressed,
    /// else None. Used by the open-discovery sweep to skip enqueue.
    pub fn cooldown_until(&self, npub: &str, now_ms: u64) -> Option<u64> {
        self.failure_state.cooldown_until(npub, now_ms)
    }

    /// Record a fatal protocol mismatch (e.g. `Unknown FMP version` on a
    /// Nostr-adopted bootstrap transport). Returns `true` if this is a
    /// fresh observation worth a WARN log; `false` if the peer is already
    /// inside a comparable mismatch cooldown.
    ///
    /// The cooldown is `protocol_mismatch_cooldown_secs` from config —
    /// much longer than `extended_cooldown_secs` because mismatches are
    /// structural (only resolves when one side upgrades) rather than
    /// transient.
    pub fn record_protocol_mismatch(&self, npub: &str, now_ms: u64) -> bool {
        let cooldown_ms = self
            .config
            .protocol_mismatch_cooldown_secs
            .saturating_mul(1000);
        self.failure_state
            .record_protocol_mismatch(npub, now_ms, cooldown_ms)
    }

    /// Configured protocol-mismatch cooldown in seconds. Exposed so log
    /// emitters can include the duration without re-reading config.
    pub fn protocol_mismatch_cooldown_secs(&self) -> u64 {
        self.config.protocol_mismatch_cooldown_secs
    }

    /// Snapshot of per-npub failure state for `show_peers` rendering.
    pub fn failure_state_snapshot(&self) -> Vec<NostrPeerFailureView> {
        self.failure_state
            .snapshot()
            .into_iter()
            .map(|(npub, rec)| NostrPeerFailureView {
                npub,
                consecutive_failures: rec.consecutive_failures,
                cooldown_until_ms: rec.cooldown_until_ms,
                last_observed_skew_ms: rec.last_observed_skew_ms,
            })
            .collect()
    }

    /// Discover (or return cached) the public-Internet address for an
    /// advert-eligible UDP transport bound to a wildcard. Used by
    /// `build_overlay_advert` to avoid emitting `udp:0.0.0.0:port`,
    /// which is invalid as an advertised endpoint. Result is the
    /// reflexive IP (from STUN against the daemon's first
    /// `stun_servers` reachable) combined with the configured
    /// `advertise_port`.
    ///
    /// Asymmetric cache TTL: a successful observation is cached for
    /// `advert_refresh_secs` (default 1800 = same as advert refresh)
    /// so we don't re-STUN every refresh tick. A failed observation
    /// is cached for `PUBLIC_UDP_ADDR_FAILURE_TTL` (60s) so we retry
    /// soon after a transient STUN flake at startup, instead of
    /// blocking advertise-as-public for half an hour. Once a success
    /// is cached, subsequent ticks are zero-overhead.
    pub async fn learn_public_udp_addr(
        &self,
        transport_id_key: u32,
        advertise_port: u16,
    ) -> Option<SocketAddr> {
        if let Some(entry) = self
            .public_udp_addr_cache
            .read()
            .await
            .get(&transport_id_key)
        {
            let ttl = if entry.addr.is_some() {
                Duration::from_secs(self.config.advert_refresh_secs.max(60))
            } else {
                PUBLIC_UDP_ADDR_FAILURE_TTL
            };
            if entry.fetched_at.elapsed() < ttl {
                return entry.addr;
            }
        }
        let resolved = self.stun_observe_public_ip(advertise_port).await;
        let mut cache = self.public_udp_addr_cache.write().await;
        cache.insert(
            transport_id_key,
            CachedPublicUdpAddr {
                addr: resolved,
                fetched_at: Instant::now(),
            },
        );
        resolved
    }

    /// Run a one-shot STUN observation against an ephemeral UDP socket
    /// to learn this host's public IPv4 (or IPv6, if the local STUN
    /// server returns one). Returns `<reflexive_ip>:<advertise_port>`,
    /// or `None` if STUN failed or no `stun_servers` are configured.
    ///
    /// The STUN-reported port is the ephemeral source port and is
    /// discarded — what we want to advertise is the bound listener
    /// port, which the kernel preserves through 1:1 NAT (AWS EIP,
    /// GCP/Azure external IPs) and which the operator has explicitly
    /// chosen via `bind_addr`.
    async fn stun_observe_public_ip(&self, advertise_port: u16) -> Option<SocketAddr> {
        if self.config.stun_servers.is_empty() {
            return None;
        }
        let socket = match std::net::UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(err) => {
                debug!(error = %err, "public-udp-addr: ephemeral bind failed");
                return None;
            }
        };
        if let Err(err) = socket.set_nonblocking(true) {
            debug!(error = %err, "public-udp-addr: set_nonblocking failed");
            return None;
        }
        let observed = match super::stun::observe_traversal_addresses(
            &socket,
            &self.config.stun_servers,
            false,
            super::stun::ADVERT_STUN_TIMEOUT,
        )
        .await
        {
            Ok((reflexive, _local, stun_server)) => {
                debug!(
                    stun = %stun_server.as_deref().unwrap_or("-"),
                    reflexive = %reflexive
                        .as_ref()
                        .map(|a| format!("{}:{}", a.ip, a.port))
                        .unwrap_or_else(|| "-".into()),
                    "public-udp-addr: STUN observation"
                );
                reflexive
            }
            Err(err) => {
                debug!(error = %err, "public-udp-addr: STUN failed");
                return None;
            }
        };
        observed.and_then(|addr| {
            let parsed_ip: std::net::IpAddr = addr.ip.parse().ok()?;
            Some(SocketAddr::new(parsed_ip, advertise_port))
        })
    }

    /// Stale-advert re-check (B6). Called by lifecycle on the
    /// streak-threshold transition. Actively re-queries the peer's
    /// Kind 37195 advert from `advert_relays`; evicts the cache entry
    /// if absent, refreshes if newer than the cached `created_at`,
    /// otherwise leaves the cache untouched.
    pub async fn refetch_advert_for_stale_check(&self, peer_npub: &str) -> NostrRefetchOutcome {
        let target_pubkey = match PublicKey::parse(peer_npub) {
            Ok(p) => p,
            Err(_) => return NostrRefetchOutcome::Skipped,
        };
        if self.config.advert_relays.is_empty() {
            return NostrRefetchOutcome::Skipped;
        }
        let cached_created_at = self.advert.cached_created_at(peer_npub);

        let events = match self
            .client
            .fetch_events_from(
                self.config.advert_relays.clone(),
                Filter::new()
                    .author(target_pubkey)
                    .kind(Kind::Custom(ADVERT_KIND))
                    .identifier(ADVERT_IDENTIFIER),
                Duration::from_secs(2),
            )
            .await
        {
            Ok(e) => e,
            Err(_) => return NostrRefetchOutcome::Skipped,
        };

        let mut newest: Option<(u64, &Event)> = None;
        for ev in events.iter() {
            let ts = ev.created_at.as_secs();
            match newest {
                Some((cur, _)) if ts <= cur => {}
                _ => newest = Some((ts, ev)),
            }
        }

        let Some((relay_created_at, ev)) = newest else {
            // Absent on relays. Evict any stale cache entry.
            self.advert.remove(peer_npub);
            self.failure_state.reset_streak_after_refresh(peer_npub);
            return NostrRefetchOutcome::Evicted;
        };

        match cached_created_at {
            Some(cached) if relay_created_at <= cached => NostrRefetchOutcome::SameAdvert,
            _ => {
                let Some(valid_until_ms) = self.event_valid_until_ms(ev) else {
                    return NostrRefetchOutcome::Skipped;
                };
                let Ok(advert) = Self::parse_overlay_advert_event(ev, &self.config.app) else {
                    return NostrRefetchOutcome::Skipped;
                };
                let updated = CachedOverlayAdvert {
                    author_npub: peer_npub.to_string(),
                    advert,
                    created_at: relay_created_at,
                    valid_until_ms,
                };
                self.advert.insert_fetched(peer_npub, updated);
                self.failure_state.reset_streak_after_refresh(peer_npub);
                NostrRefetchOutcome::Refreshed
            }
        }
    }

    pub async fn drain_events(&self) -> Vec<BootstrapEvent> {
        let mut out = Vec::new();
        let mut rx = self.event_rx.lock().await;
        while let Ok(event) = rx.try_recv() {
            out.push(event);
        }
        out
    }

    pub async fn update_local_advert(
        self: &Arc<Self>,
        advert: Option<OverlayAdvert>,
    ) -> Result<(), BootstrapError> {
        if self.advert.set_local_advert(advert) {
            self.request_publish_advert();
        }
        Ok(())
    }

    pub async fn advert_endpoints_for_peer(
        &self,
        peer_npub: &str,
    ) -> Result<Vec<OverlayEndpointAdvert>, BootstrapError> {
        let target_pubkey =
            PublicKey::parse(peer_npub).map_err(|e| BootstrapError::InvalidPeerNpub {
                npub: peer_npub.to_string(),
                reason: e.to_string(),
            })?;
        let advert = self.fetch_advert(peer_npub, target_pubkey).await?;
        Ok(advert.endpoints)
    }

    pub async fn cached_open_discovery_candidates(
        &self,
        max: usize,
    ) -> Vec<(String, Vec<OverlayEndpointAdvert>, u64)> {
        self.prune_advert_cache();
        self.advert.open_discovery_candidates(max, now_ms())
    }

    pub async fn shutdown(&self) -> Result<(), BootstrapError> {
        if let Some(handle) = self.advertise_task.lock().await.take() {
            handle.abort();
        }
        if let Some(handle) = self.connect_task.lock().await.take() {
            handle.abort();
        }
        if let Some(handle) = self.relay_startup_task.lock().await.take() {
            handle.abort();
        }
        if let Some(handle) = self.publish_task.lock().await.take() {
            handle.abort();
        }

        // Don't proactively retract the advert via NIP-09 on shutdown.
        // Parameterized-replaceable semantics handle restart supersedence,
        // and NIP-40 expiration (advert_ttl_secs) bounds staleness on
        // permanent shutdown. An explicit retraction races with the next
        // daemon's republish on strict relays (e.g. Damus rate-limits the
        // burst, leaving the advert deleted and never restored).
        let _ = self.advert.take_event_id();

        if let Some(handle) = self.notify_task.lock().await.take() {
            handle.abort();
        }

        Ok(())
    }

    fn spawn_notify_loop(
        self: Arc<Self>,
        mut notifications: broadcast::Receiver<RelayPoolNotification>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let started_at = Instant::now();
            let mut first_event_seen = false;
            info!("nostr notify loop entered");
            loop {
                let notification = match notifications.recv().await {
                    Ok(notification) => notification,
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(
                            skipped,
                            "nostr notification channel lagged; advert/signal events dropped"
                        );
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        warn!("nostr notification channel closed; notify loop exiting");
                        break;
                    }
                };
                if !first_event_seen {
                    first_event_seen = true;
                    info!(
                        elapsed_ms = started_at.elapsed().as_millis() as u64,
                        "nostr notify loop received first event"
                    );
                }
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == Kind::Custom(ADVERT_KIND) {
                        let author_npub = event.pubkey.to_bech32().expect("infallible");
                        if let Some(valid_until_ms) = self.event_valid_until_ms(&event)
                            && let Ok(advert) =
                                Self::parse_overlay_advert_event(&event, &self.config.app)
                        {
                            let endpoints = endpoint_summary(&advert.endpoints);
                            let created_at = event.created_at.as_secs();
                            if self.advert.observe_advert(
                                &author_npub,
                                advert,
                                created_at,
                                valid_until_ms,
                            ) {
                                debug!(
                                    peer = %short_npub(&author_npub),
                                    endpoints = %endpoints,
                                    event = %short_id(&event.id.to_string()),
                                    "advert: peer cached"
                                );
                            }
                        }
                        self.prune_advert_cache();
                        continue;
                    }

                    if event.kind != Kind::Custom(SIGNAL_KIND) {
                        continue;
                    }

                    let unwrapped = match unwrap_signal_event(&self.keys, &event).await {
                        Ok(unwrapped) => unwrapped,
                        Err(err) => {
                            trace!(error = %err, "failed to unwrap traversal signal");
                            continue;
                        }
                    };
                    let sender_npub = match unwrapped.sender.to_bech32() {
                        Ok(npub) => npub,
                        Err(err) => {
                            debug!(error = %err, "failed to encode traversal sender npub");
                            continue;
                        }
                    };

                    if let Ok(answer) =
                        serde_json::from_str::<TraversalAnswer>(&unwrapped.rumor.content)
                        && answer.message_type == "answer"
                        && answer.recipient_npub == self.npub
                    {
                        if let Some(tx) = self
                            .pending_answers
                            .lock()
                            .await
                            .remove(&answer.in_reply_to)
                        {
                            let _ = tx.send(SignalEnvelope {
                                payload: answer,
                                event_id: event.id,
                                sender_npub: sender_npub.clone(),
                            });
                        }
                        continue;
                    }

                    if let Ok(offer) =
                        serde_json::from_str::<TraversalOffer>(&unwrapped.rumor.content)
                        && offer.message_type == "offer"
                        && offer.recipient_npub == self.npub
                    {
                        let permit = match self.admission.try_admit(&sender_npub) {
                            Ok(permit) => permit,
                            Err(AdmissionReject::GlobalFull) => {
                                warn!(
                                    sender_npub = %sender_npub,
                                    limit = self.config.max_concurrent_incoming_offers,
                                    "rate-limited inbound traversal offer (max_concurrent_incoming_offers reached); offer dropped"
                                );
                                continue;
                            }
                            // Debug, not warn: the party that trips this is by
                            // definition sending faster than the node wants, so
                            // a record per rejection turns the spam into log
                            // volume. The global-full arm above stays at warn
                            // and remains the operator's signal that the node
                            // is actually saturated.
                            Err(AdmissionReject::SenderFull) => {
                                debug!(
                                    sender_npub = %sender_npub,
                                    limit = self.config.max_concurrent_offers_per_npub,
                                    "inbound traversal offer refused: sender is at its per-npub offer allowance"
                                );
                                continue;
                            }
                        };
                        let runtime = Arc::clone(&self);
                        let peer_short = short_npub(&sender_npub);
                        let session_short = short_id(&offer.session_id);
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(err) = runtime
                                .handle_incoming_offer(offer, unwrapped.sender, sender_npub)
                                .await
                            {
                                // An offer arriving stale is the expected
                                // consequence of relay lag and stays at debug.
                                // The remaining classes cannot arise from lag,
                                // so they are the operator's only evidence that
                                // a node is being fed malformed or forged
                                // signals, and must clear the default level.
                                if adversarial_offer_reject(&err) {
                                    warn!(
                                        peer = %peer_short,
                                        session = %session_short,
                                        error = %err,
                                        "rejected traversal offer"
                                    );
                                } else {
                                    debug!(
                                        peer = %peer_short,
                                        session = %session_short,
                                        error = %err,
                                        "failed to handle traversal offer"
                                    );
                                }
                            }
                        });
                    }
                }
            }
        })
    }

    fn spawn_advertise_loop(self: Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(self.config.advert_refresh_secs.max(1)));
            // Swallow the immediate first tick: Node::start() requests the
            // initial advert publish via update_local_advert().
            interval.tick().await;
            loop {
                interval.tick().await;
                self.request_publish_advert();
            }
        })
    }

    fn spawn_relay_startup_loop(self: Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut retry_delay = Duration::from_secs(2);
            loop {
                let subscribed =
                    match tokio::time::timeout(RELAY_STARTUP_OP_TIMEOUT, self.subscribe()).await {
                        Ok(Ok(())) => true,
                        Ok(Err(err)) => {
                            warn!(error = %err, "failed to subscribe to Nostr discovery relays");
                            false
                        }
                        Err(_) => {
                            warn!(
                                timeout_ms = RELAY_STARTUP_OP_TIMEOUT.as_millis() as u64,
                                "Nostr discovery relay subscribe timed out"
                            );
                            false
                        }
                    };
                match tokio::time::timeout(RELAY_STARTUP_OP_TIMEOUT, self.publish_inbox_relays())
                    .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        warn!(error = %err, "failed to publish Nostr inbox relay list");
                    }
                    Err(_) => {
                        warn!(
                            timeout_ms = RELAY_STARTUP_OP_TIMEOUT.as_millis() as u64,
                            "Nostr inbox relay publish timed out"
                        );
                    }
                }

                self.request_publish_advert();

                if subscribed {
                    break;
                }

                tokio::time::sleep(retry_delay).await;
                retry_delay = retry_delay.saturating_mul(2).min(Duration::from_secs(60));
            }
        })
    }

    fn spawn_connect_loop(self: Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(async move {
            self.client.connect().await;
        })
    }

    fn spawn_publish_loop(self: Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                self.publish_notify.notified().await;
                match tokio::time::timeout(ADVERT_PUBLISH_TIMEOUT, self.publish_advert()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        warn!(error = %err, "failed to publish traversal advert");
                    }
                    Err(_) => {
                        warn!(
                            timeout_ms = ADVERT_PUBLISH_TIMEOUT.as_millis() as u64,
                            "Nostr traversal advert publish timed out"
                        );
                    }
                }
            }
        })
    }

    fn request_publish_advert(&self) {
        self.publish_notify.notify_one();
    }

    fn punch_hint(&self) -> PunchHint {
        PunchHint {
            start_at_ms: now_ms() + self.config.punch_start_delay_ms,
            interval_ms: self.config.punch_interval_ms,
            duration_ms: self.config.punch_duration_ms,
        }
    }

    async fn subscribe(&self) -> Result<(), BootstrapError> {
        self.client
            .subscribe_to(
                self.config.dm_relays.clone(),
                Filter::new()
                    .kind(Kind::Custom(SIGNAL_KIND))
                    .pubkey(self.pubkey)
                    .limit(0),
                None,
            )
            .await
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;

        self.client
            .subscribe_to(
                self.config.advert_relays.clone(),
                Filter::new()
                    .kind(Kind::Custom(ADVERT_KIND))
                    .identifier(ADVERT_IDENTIFIER),
                None,
            )
            .await
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;

        Ok(())
    }

    async fn publish_inbox_relays(&self) -> Result<(), BootstrapError> {
        let tags = self
            .config
            .dm_relays
            .iter()
            .filter_map(|relay| RelayUrl::parse(relay).ok())
            .map(|relay| {
                Tag::custom(
                    TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::R)),
                    [relay.to_string()],
                )
            })
            .collect::<Vec<_>>();

        let event = EventBuilder::new(Kind::InboxRelays, "")
            .tags(tags)
            .sign_with_keys(&self.keys)
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        self.client
            .send_event_to(self.config.dm_relays.clone(), &event)
            .await
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        Ok(())
    }

    async fn publish_advert(&self) -> Result<(), BootstrapError> {
        let advert = match self.advert.plan_publish()? {
            PublishPlan::Nothing => return Ok(()),
            PublishPlan::Delete(event_id) => {
                self.publish_delete(&self.config.advert_relays, [event_id])
                    .await?;
                self.advert.clear_event_id();
                return Ok(());
            }
            PublishPlan::Publish(advert) => advert,
        };

        let expires_at = now_ms() + self.config.advert_ttl_secs * 1000;
        let tags = vec![
            Tag::identifier(ADVERT_IDENTIFIER.to_string()),
            Tag::custom(TagKind::custom("protocol"), [self.config.app.clone()]),
            Tag::custom(TagKind::custom("version"), [PROTOCOL_VERSION.to_string()]),
            Tag::expiration(Timestamp::from((expires_at / 1000).max(1))),
        ];

        let event = EventBuilder::new(Kind::Custom(ADVERT_KIND), serde_json::to_string(&advert)?)
            .tags(tags)
            .sign_with_keys(&self.keys)
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        self.client
            .send_event_to(self.config.advert_relays.clone(), &event)
            .await
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        debug!(
            event = %short_id(&event.id.to_string()),
            relays = self.config.advert_relays.len(),
            endpoints = %endpoint_summary(&advert.endpoints),
            ttl_secs = self.config.advert_ttl_secs,
            "advert: published"
        );
        // Kind 37195 lives in NIP-01's parameterized replaceable range
        // (30000–39999). Relays supersede the previous event for the same
        // (pubkey, kind, d-tag) triple by created_at — emitting an explicit
        // NIP-09 delete here is redundant and races with the replacement
        // publish, which strict relays (e.g. Damus) honor by removing the
        // new advert too.
        self.advert.set_event_id(event.id);
        Ok(())
    }

    async fn connect_peer(
        &self,
        peer_config: PeerConfig,
    ) -> Result<EstablishedTraversal, BootstrapError> {
        let peer_short = short_npub(&peer_config.npub);
        if !self.outbound_admission_allowed() {
            debug!(
                peer = %peer_short,
                "traversal: initiator suppressed, Node at capacity"
            );
            return Err(BootstrapError::Disabled);
        }
        debug!(peer = %peer_short, "traversal: initiator starting");
        let target_pubkey =
            PublicKey::parse(&peer_config.npub).map_err(|e| BootstrapError::InvalidPeerNpub {
                npub: peer_config.npub.clone(),
                reason: e.to_string(),
            })?;
        let advert = self.fetch_advert(&peer_config.npub, target_pubkey).await?;
        if !advert.has_udp_nat_endpoint() {
            return Err(BootstrapError::MissingNatEndpoint(peer_config.npub.clone()));
        }
        let relays = self
            .preferred_signal_relays(target_pubkey, Some(&advert))
            .await?;
        if relays.is_empty() {
            return Err(BootstrapError::MissingRelays(peer_config.npub));
        }

        let base_socket = std::net::UdpSocket::bind(("0.0.0.0", 0))?;
        base_socket.set_nonblocking(true)?;

        let (reflexive_address, local_addresses, stun_server) = observe_traversal_addresses(
            &base_socket,
            &self.config.stun_servers,
            self.config.share_local_candidates,
            super::stun::TRAVERSAL_STUN_TIMEOUT,
        )
        .await?;
        debug!(
            peer = %peer_short,
            reflexive = %reflexive_address.as_ref().map(|a| format!("{}:{}", a.ip, a.port)).unwrap_or_else(|| "-".into()),
            local = local_addresses.len(),
            stun = %stun_server.as_deref().unwrap_or("-"),
            "traversal: initiator STUN observed"
        );
        let session_id = nonce();
        let offer = create_traversal_offer(
            session_id.clone(),
            now_ms(),
            self.config.signal_ttl_secs * 1000,
            session_id.clone(),
            self.npub.clone(),
            peer_config.npub.clone(),
            reflexive_address,
            local_addresses,
            stun_server,
        );

        let (tx, rx) = oneshot::channel();
        self.pending_answers
            .lock()
            .await
            .insert(offer.nonce.clone(), tx);
        let offer_event = self.send_signal(&relays, target_pubkey, &offer).await?;
        debug!(
            peer = %peer_short,
            session = %short_id(&offer.session_id),
            relays = relays.len(),
            event = %short_id(&offer_event.id.to_string()),
            "traversal: offer sent"
        );

        let answer = match tokio::time::timeout(
            Duration::from_secs(self.config.signal_ttl_secs),
            rx,
        )
        .await
        {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) => {
                let _ = self.pending_answers.lock().await.remove(&offer.nonce);
                return Err(BootstrapError::Protocol(
                    "answer channel closed".to_string(),
                ));
            }
            Err(_) => {
                let _ = self.pending_answers.lock().await.remove(&offer.nonce);
                return Err(BootstrapError::SignalTimeout(peer_config.npub));
            }
        };

        let answer_received_at = now_ms();
        debug!(
            peer = %peer_short,
            session = %short_id(&offer.session_id),
            accepted = answer.payload.accepted,
            reflexive = %answer.payload.reflexive_address.as_ref().map(|a| format!("{}:{}", a.ip, a.port)).unwrap_or_else(|| "-".into()),
            local = answer.payload.local_addresses.len(),
            "traversal: answer received"
        );
        if let Some(observed_skew_ms) =
            estimate_clock_skew(&offer, &answer.payload, answer_received_at)
        {
            self.failure_state.note_observed_skew(
                &peer_config.npub,
                observed_skew_ms,
                answer_received_at,
            );
            let abs_skew = observed_skew_ms.unsigned_abs();
            // 30s threshold: well below the 60s SKEW_TOLERANCE wall but loud
            // enough to surface a real clock problem on either side.
            if abs_skew >= 30_000 {
                debug!(
                    peer = %peer_short,
                    session = %short_id(&offer.session_id),
                    skew_ms = observed_skew_ms,
                    "traversal: significant peer clock skew observed"
                );
            } else {
                trace!(
                    peer = %peer_short,
                    skew_ms = observed_skew_ms,
                    "traversal: peer clock skew within nominal range"
                );
            }
        }
        let outcome = validate_traversal_answer_for_offer(
            &offer,
            &answer.payload,
            answer_received_at,
            self.config.signal_ttl_secs * 1000,
            &answer.sender_npub,
            &self.npub,
        )?;
        if outcome == FreshnessOutcome::FreshWithinSkewTolerance {
            debug!(
                peer = %peer_short,
                session = %short_id(&offer.session_id),
                answer_issued_at = answer.payload.issued_at,
                answer_expires_at = answer.payload.expires_at,
                "traversal: answer accepted within freshness tolerance"
            );
        }
        if !answer.payload.accepted {
            return Err(BootstrapError::Protocol(
                answer
                    .payload
                    .reason
                    .unwrap_or_else(|| "remote rejected traversal".to_string()),
            ));
        }

        let (remotes, tally) = planned_remote_endpoints(
            &offer.local_addresses,
            offer.reflexive_address.as_ref(),
            &answer.payload.local_addresses,
            answer.payload.reflexive_address.as_ref(),
        )?;
        log_refusals(&tally, &peer_short, &short_id(&session_id));

        let remote_addr = run_punch_attempt(
            &base_socket,
            &session_id,
            &remotes,
            self.punch_hint(),
            Duration::from_secs(self.config.attempt_timeout_secs),
        )
        .await
        .map_err(|_| BootstrapError::PunchTimeout(peer_config.npub.clone()))?;
        debug!(
            peer = %peer_short,
            session = %short_id(&session_id),
            remote = %remote_addr,
            "traversal: initiator punch succeeded"
        );

        let _ = self
            .publish_delete(&relays, [offer_event.id, answer.event_id])
            .await;

        self.failure_state
            .record_success(&peer_config.npub, now_ms());

        Ok(
            EstablishedTraversal::new(session_id, peer_config.npub, remote_addr, base_socket)
                .with_transport_name("nostr-nat"),
        )
    }

    async fn handle_incoming_offer(
        self: Arc<Self>,
        offer: TraversalOffer,
        sender: PublicKey,
        sender_npub: String,
    ) -> Result<(), BootstrapError> {
        let peer_short = short_npub(&sender_npub);
        if !self.outbound_admission_allowed() {
            debug!(
                peer = %peer_short,
                session = %short_id(&offer.session_id),
                "traversal: incoming offer dropped, Node at capacity"
            );
            return Ok(());
        }
        let offer_received_at = now_ms();
        debug!(
            peer = %peer_short,
            session = %short_id(&offer.session_id),
            reflexive = %offer.reflexive_address.as_ref().map(|a| format!("{}:{}", a.ip, a.port)).unwrap_or_else(|| "-".into()),
            local = offer.local_addresses.len(),
            "traversal: offer received"
        );
        let outcome = validate_offer_freshness(
            &offer,
            offer_received_at,
            self.config.signal_ttl_secs * 1000,
            &sender_npub,
            &self.npub,
        )?;
        if outcome == FreshnessOutcome::FreshWithinSkewTolerance {
            debug!(
                peer = %peer_short,
                session = %short_id(&offer.session_id),
                offer_issued_at = offer.issued_at,
                offer_expires_at = offer.expires_at,
                offer_received_at = offer_received_at,
                "traversal: offer accepted within freshness tolerance"
            );
        }
        // Collapse the dual-`auto_connect` four-socket dance to a single
        // session. When we also have an in-flight outbound initiator for this
        // same peer (genuine symmetric duplication), both nodes deterministically
        // keep the session initiated by the smaller NodeAddr. If our own
        // initiator session is the preferred one, decline to answer this offer:
        // not answering lets the peer's redundant initiator time out, so only the
        // single matching socket pair survives on both sides. Asymmetric /
        // one-sided `auto_connect` (no co-active initiator) is never suppressed,
        // preserving connectivity. See `suppress_responder_for_own_initiator`.
        match (
            PeerIdentity::from_npub(&self.npub),
            PeerIdentity::from_npub(&sender_npub),
        ) {
            (Ok(ours), Ok(theirs)) => {
                match self.traversal.classify_incoming_offer(
                    &sender_npub,
                    ours.node_addr(),
                    theirs.node_addr(),
                ) {
                    OfferDisposition::Suppress => {
                        debug!(
                            peer = %peer_short,
                            session = %short_id(&offer.session_id),
                            "traversal: responder session suppressed, our outbound initiator wins (smaller addr)"
                        );
                        return Ok(());
                    }
                    OfferDisposition::Proceed => {}
                }
            }
            _ => {
                // Could not derive a NodeAddr for one side; fall through and
                // answer rather than risk suppressing the only session.
                trace!(
                    peer = %peer_short,
                    "traversal: could not derive NodeAddr for dedup, answering offer"
                );
            }
        }

        match self
            .traversal
            .note_session_seen(&offer.session_id, now_ms())
        {
            SeenDecision::Replay => {
                return Err(BootstrapError::Replay(offer.session_id.clone()));
            }
            SeenDecision::Fresh { evicted } => {
                if let Some((evicted, retained)) = evicted {
                    debug!(
                        evicted = evicted,
                        retained = retained,
                        cap = self.config.seen_sessions_max_entries,
                        "seen-sessions cache overflow; evicted oldest entries"
                    );
                }
            }
        }

        // Resolve the answer's relays before binding a socket and running STUN.
        // Nothing in the relay choice depends on what STUN observes, and an offer
        // from a peer we share no relay with cannot be answered at all — doing it
        // in this order spends a STUN round trip, and holds an offer slot for its
        // duration, only to discard the result.
        let relays = self.preferred_signal_relays(sender, None).await?;
        if relays.is_empty() {
            return Err(BootstrapError::MissingRelays(offer.sender_npub.clone()));
        }

        let base_socket = std::net::UdpSocket::bind(("0.0.0.0", 0))?;
        base_socket.set_nonblocking(true)?;
        let (reflexive_address, local_addresses, stun_server) = observe_traversal_addresses(
            &base_socket,
            &self.config.stun_servers,
            self.config.share_local_candidates,
            super::stun::TRAVERSAL_STUN_TIMEOUT,
        )
        .await?;
        let accepted = reflexive_address.is_some() || !local_addresses.is_empty();
        debug!(
            peer = %peer_short,
            session = %short_id(&offer.session_id),
            accepted = accepted,
            reflexive = %reflexive_address.as_ref().map(|a| format!("{}:{}", a.ip, a.port)).unwrap_or_else(|| "-".into()),
            local = local_addresses.len(),
            "traversal: responder STUN observed"
        );
        let answer = create_traversal_answer(
            offer.session_id.clone(),
            now_ms(),
            self.config.signal_ttl_secs * 1000,
            nonce(),
            self.npub.clone(),
            offer.sender_npub.clone(),
            offer.nonce.clone(),
            accepted,
            reflexive_address,
            local_addresses,
            stun_server,
            accepted.then(|| self.punch_hint()),
            (!accepted).then_some("no-usable-addresses".to_string()),
            Some(offer_received_at),
        );
        let answer_event = self.send_signal(&relays, sender, &answer).await?;
        debug!(
            peer = %peer_short,
            session = %short_id(&offer.session_id),
            accepted = accepted,
            relays = relays.len(),
            event = %short_id(&answer_event.id.to_string()),
            "traversal: answer sent"
        );
        if !accepted {
            let _ = self.publish_delete(&relays, [answer_event.id]).await;
            return Ok(());
        }

        let (remotes, tally) = planned_remote_endpoints(
            &answer.local_addresses,
            answer.reflexive_address.as_ref(),
            &offer.local_addresses,
            offer.reflexive_address.as_ref(),
        )?;
        log_refusals(&tally, &peer_short, &short_id(&offer.session_id));

        let punch = run_punch_attempt(
            &base_socket,
            &offer.session_id,
            &remotes,
            answer
                .punch
                .clone()
                .expect("accepted answers always include a punch hint"),
            Duration::from_secs(self.config.attempt_timeout_secs),
        )
        .await;
        match punch {
            Ok(remote_addr) => {
                debug!(
                    peer = %peer_short,
                    session = %short_id(&offer.session_id),
                    remote = %remote_addr,
                    "traversal: responder punch succeeded"
                );
                let _ = self.event_tx.send(BootstrapEvent::Established {
                    traversal: EstablishedTraversal::new(
                        offer.session_id,
                        offer.sender_npub,
                        remote_addr,
                        base_socket,
                    )
                    .with_transport_name("nostr-nat"),
                });
            }
            Err(err) => {
                debug!(
                    peer = %peer_short,
                    session = %short_id(&offer.session_id),
                    error = %err,
                    "traversal: responder punch failed"
                );
            }
        }

        let _ = self.publish_delete(&relays, [answer_event.id]).await;
        Ok(())
    }

    async fn fetch_advert(
        &self,
        peer_npub: &str,
        target_pubkey: PublicKey,
    ) -> Result<OverlayAdvert, BootstrapError> {
        self.prune_advert_cache();
        if let Some(advert) = self.advert.cached_advert(peer_npub) {
            debug!(
                peer = %short_npub(peer_npub),
                source = "cache",
                endpoints = %endpoint_summary(&advert.endpoints),
                "advert: resolved"
            );
            return Ok(advert);
        }

        let events = self
            .client
            .fetch_events_from(
                self.config.advert_relays.clone(),
                Filter::new()
                    .author(target_pubkey)
                    .kind(Kind::Custom(ADVERT_KIND))
                    .identifier(ADVERT_IDENTIFIER),
                Duration::from_secs(2),
            )
            .await
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;

        let mut best: Option<CachedOverlayAdvert> = None;
        for event in events.iter() {
            let Some(valid_until_ms) = self.event_valid_until_ms(event) else {
                continue;
            };
            let Ok(advert) = Self::parse_overlay_advert_event(event, &self.config.app) else {
                continue;
            };
            let author_npub = event.pubkey.to_bech32().expect("infallible");
            if author_npub != peer_npub {
                continue;
            }
            let replace = best
                .as_ref()
                .map(|current| event.created_at.as_secs() >= current.created_at)
                .unwrap_or(true);
            if replace {
                best = Some(CachedOverlayAdvert {
                    author_npub,
                    advert,
                    created_at: event.created_at.as_secs(),
                    valid_until_ms,
                });
            }
        }

        let cached = best.ok_or_else(|| BootstrapError::MissingAdvert(peer_npub.to_string()))?;
        debug!(
            peer = %short_npub(peer_npub),
            source = "relay-fetch",
            endpoints = %endpoint_summary(&cached.advert.endpoints),
            "advert: resolved"
        );
        self.advert.insert_fetched(peer_npub, cached.clone());
        self.prune_advert_cache();
        Ok(cached.advert)
    }

    async fn preferred_signal_relays(
        &self,
        target_pubkey: PublicKey,
        advert: Option<&OverlayAdvert>,
    ) -> Result<Vec<String>, BootstrapError> {
        let inbox = self.find_recipient_inbox_relays(target_pubkey).await?;
        let pool: HashSet<RelayUrl> = self.client.pool().all_relays().await.into_keys().collect();
        let usable = signal_relays(
            &inbox,
            advert.and_then(|advert| advert.signal_relays.as_deref()),
            &self.config.dm_relays,
            &pool,
        );
        debug!(
            peer = %target_pubkey.to_bech32().map(|npub| short_npub(&npub)).unwrap_or_default(),
            inbox = inbox.len(),
            usable = usable.len(),
            "traversal: signal relays resolved against the client pool"
        );
        Ok(usable)
    }

    async fn find_recipient_inbox_relays(
        &self,
        target_pubkey: PublicKey,
    ) -> Result<Vec<String>, BootstrapError> {
        let mut lookup_relays = self.config.dm_relays.clone();
        for relay in &self.config.advert_relays {
            if !lookup_relays.contains(relay) {
                lookup_relays.push(relay.clone());
            }
        }
        let events = self
            .client
            .fetch_events_from(
                lookup_relays,
                Filter::new()
                    .author(target_pubkey)
                    .kind(Kind::InboxRelays)
                    .since(Timestamp::from(
                        Timestamp::now().as_secs().saturating_sub(30 * 24 * 60 * 60),
                    )),
                Duration::from_millis(1500),
            )
            .await;
        let events = match events {
            Ok(events) => events,
            Err(err) => {
                debug!(error = %err, "failed to fetch inbox relays, falling back to configured DM relays");
                return Ok(self.config.dm_relays.clone());
            }
        };
        let newest = events.iter().max_by_key(|event| event.created_at.as_secs());
        if let Some(event) = newest {
            let relays = nip17::extract_relay_list(event)
                .map(|relay| relay.to_string())
                .collect::<Vec<_>>();
            if !relays.is_empty() {
                return Ok(relays);
            }
        }
        Ok(self.config.dm_relays.clone())
    }

    fn parse_overlay_advert_event(
        event: &Event,
        expected_app: &str,
    ) -> Result<OverlayAdvert, BootstrapError> {
        let advertised_app = event
            .tags
            .find(TagKind::custom("protocol"))
            .and_then(|tag| tag.content())
            .ok_or_else(|| {
                BootstrapError::InvalidAdvert("missing required protocol tag".to_string())
            })?;
        if advertised_app != expected_app {
            return Err(BootstrapError::InvalidAdvert(format!(
                "unsupported protocol '{}'",
                advertised_app
            )));
        }

        let advert: OverlayAdvert = serde_json::from_str(&event.content)?;
        Self::validate_overlay_advert(advert)
    }

    pub(super) fn validate_overlay_advert(
        mut advert: OverlayAdvert,
    ) -> Result<OverlayAdvert, BootstrapError> {
        if advert.identifier != ADVERT_IDENTIFIER {
            return Err(BootstrapError::InvalidAdvert(format!(
                "unsupported identifier '{}'",
                advert.identifier
            )));
        }
        if advert.version != ADVERT_VERSION {
            return Err(BootstrapError::InvalidAdvert(format!(
                "unsupported version '{}'",
                advert.version
            )));
        }
        if advert.endpoints.is_empty() {
            return Err(BootstrapError::InvalidAdvert(
                "missing required endpoints".to_string(),
            ));
        }
        advert.endpoints.retain(endpoint_advert_is_publicly_usable);
        if advert.endpoints.is_empty() {
            return Err(BootstrapError::InvalidAdvert(
                "missing publicly routable endpoints".to_string(),
            ));
        }

        let has_nat = advert.has_udp_nat_endpoint();
        if has_nat {
            if advert
                .signal_relays
                .as_ref()
                .is_none_or(|relays| relays.is_empty())
            {
                return Err(BootstrapError::InvalidAdvert(
                    "udp:nat endpoint requires signalRelays".to_string(),
                ));
            }
            if advert
                .stun_servers
                .as_ref()
                .is_none_or(|servers| servers.is_empty())
            {
                return Err(BootstrapError::InvalidAdvert(
                    "udp:nat endpoint requires stunServers".to_string(),
                ));
            }
        } else {
            advert.signal_relays = None;
            advert.stun_servers = None;
        }

        Ok(advert)
    }

    fn prune_advert_cache(&self) {
        if let Some((evicted, retained)) = self.advert.prune(now_ms()) {
            debug!(
                evicted,
                retained,
                cap = self.config.advert_cache_max_entries,
                "advert cache overflow; evicted oldest entries"
            );
        }
    }

    fn event_valid_until_ms(&self, event: &Event) -> Option<u64> {
        self.advert.event_valid_until_ms(event, now_ms())
    }

    pub(super) fn compute_advert_valid_until_ms(
        event: &Event,
        advert_max_age_ms: u64,
        now_ms: u64,
    ) -> Option<u64> {
        if event.is_expired() {
            return None;
        }

        let created_ms = event.created_at.as_secs().saturating_mul(1000);
        let created_window_until = created_ms.saturating_add(advert_max_age_ms);
        if created_window_until <= now_ms {
            return None;
        }

        let expires_ms = event
            .tags
            .expiration()
            .map(|timestamp| timestamp.as_secs().saturating_mul(1000));
        let valid_until_ms = expires_ms
            .map(|expires| expires.min(created_window_until))
            .unwrap_or(created_window_until);

        (valid_until_ms > now_ms).then_some(valid_until_ms)
    }

    async fn send_signal<T: Serialize>(
        &self,
        relays: &[String],
        receiver: PublicKey,
        payload: &T,
    ) -> Result<Event, BootstrapError> {
        let rumor = EventBuilder::private_msg_rumor(receiver, serde_json::to_string(payload)?)
            .build(self.pubkey);
        let signal = build_signal_event(
            &self.keys,
            receiver,
            rumor,
            Timestamp::from((now_ms() + self.config.signal_ttl_secs * 1000) / 1000),
        )
        .await?;
        self.client
            .send_event_to(relays.to_vec(), &signal)
            .await
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        Ok(signal)
    }

    async fn publish_delete<I>(&self, relays: &[String], ids: I) -> Result<(), BootstrapError>
    where
        I: IntoIterator<Item = EventId>,
    {
        let event = EventBuilder::delete(nostr::nips::nip09::EventDeletionRequest::new().ids(ids))
            .sign_with_keys(&self.keys)
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        self.client
            .send_event_to(relays.to_vec(), &event)
            .await
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        Ok(())
    }
}

/// Retain only the candidates the client pool actually holds.
///
/// `send_event_to` rejects the whole send with `RelayNotFound` if any single URL
/// is outside the pool, so a signal addressed to a peer's advertised relays fails
/// entirely on one relay we are not configured with. Filtering first turns that
/// into a send to the relays we share.
///
/// Comparison is on the normalized `RelayUrl` rather than the raw string, because
/// the pool is keyed that way: a candidate spelled `wss://relay.example/` matches
/// a configured `wss://relay.example`. Order is preserved, candidates that fail
/// to parse are dropped, and duplicates that normalize alike are collapsed.
fn retain_pooled_relays(candidates: &[String], pool: &HashSet<RelayUrl>) -> Vec<String> {
    let mut seen: HashSet<RelayUrl> = HashSet::new();
    let mut usable = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let Ok(url) = RelayUrl::parse(candidate) else {
            continue;
        };
        if pool.contains(&url) && seen.insert(url.clone()) {
            usable.push(url.to_string());
        }
    }
    usable
}

/// Choose the relays a traversal signal for one peer should be sent to.
///
/// The candidates are the peer's NIP-17 inbox relays, then the relays its advert
/// nominates for signaling, then our own DM relays — remote-supplied first, ours
/// last, so a peer's preference is honored where we can act on it. The result is
/// whatever survives [`retain_pooled_relays`].
///
/// This is the whole decision, kept synchronous so it can be exercised without a
/// relay client: the caller's only job is to supply the fetched inbox list and
/// the pool.
pub(super) fn signal_relays(
    inbox: &[String],
    advert_signal: Option<&[String]>,
    dm_relays: &[String],
    pool: &HashSet<RelayUrl>,
) -> Vec<String> {
    let mut merged: Vec<String> = inbox.to_vec();
    for relay in advert_signal.unwrap_or_default().iter().chain(dm_relays) {
        if !merged.contains(relay) {
            merged.push(relay.clone());
        }
    }
    retain_pooled_relays(&merged, pool)
}

#[cfg(test)]
impl NostrRendezvous {
    /// Build a minimal `NostrRendezvous` for unit tests. No relay client is
    /// connected and no background tasks are spawned; only the in-memory
    /// `advert_cache` and `npub` are usable. Intended for cache-injection
    /// tests of consumers (e.g. `Node::run_open_discovery_sweep`).
    pub(crate) fn new_for_test() -> Self {
        let keys = nostr::Keys::generate();
        let pubkey = keys.public_key();
        let npub = pubkey.to_bech32().expect("bech32 encode");
        let client = Client::builder()
            .signer(keys.clone())
            .opts(ClientOptions::new().autoconnect(false))
            .build();
        let config = NostrRendezvousConfig::default();
        let admission = OfferAdmission::new(
            config.max_concurrent_incoming_offers,
            config.max_concurrent_offers_per_npub,
        );
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let failure_state = FailureState::new(
            config.failure_streak_threshold,
            config.extended_cooldown_secs,
            config.warn_log_interval_secs,
            config.failure_state_max_entries,
        );
        let advert = AdvertMachine::new(
            npub.clone(),
            config.advertise,
            config.advert_ttl_secs * 1000 * ADVERT_CACHE_STALE_GRACE_MULTIPLIER,
            config.advert_cache_max_entries,
        );
        let traversal = TraversalMachine::new(
            config.replay_window_secs * 1000,
            config.seen_sessions_max_entries,
        );
        Self {
            client,
            keys,
            pubkey,
            npub,
            config,
            advert,
            traversal,
            pending_answers: Mutex::new(HashMap::new()),
            admission,
            event_tx,
            event_rx: Mutex::new(event_rx),
            connect_task: Mutex::new(None),
            relay_startup_task: Mutex::new(None),
            publish_task: Mutex::new(None),
            publish_notify: Notify::new(),
            notify_task: Mutex::new(None),
            advertise_task: Mutex::new(None),
            failure_state,
            public_udp_addr_cache: RwLock::new(HashMap::new()),
            outbound_admission: AtomicBool::new(true),
        }
    }

    /// Install the five background-task handles that `start` would install, so
    /// liveness tests can drive `is_finished()` without live relays. Each
    /// argument is the handle to place in the matching slot.
    pub(crate) async fn install_tasks_for_test(
        &self,
        connect: JoinHandle<()>,
        relay_startup: JoinHandle<()>,
        notify: JoinHandle<()>,
        publish: JoinHandle<()>,
        advertise: JoinHandle<()>,
    ) {
        *self.connect_task.lock().await = Some(connect);
        *self.relay_startup_task.lock().await = Some(relay_startup);
        *self.notify_task.lock().await = Some(notify);
        *self.publish_task.lock().await = Some(publish);
        *self.advertise_task.lock().await = Some(advertise);
    }

    /// Build a `CachedOverlayAdvert` for tests with a single endpoint and
    /// a generous validity window (one hour from `now_ms()`).
    pub(crate) fn cached_advert_for_test(
        author_npub: String,
        endpoint: OverlayEndpointAdvert,
        created_at_secs: u64,
    ) -> CachedOverlayAdvert {
        CachedOverlayAdvert {
            author_npub: author_npub.clone(),
            advert: OverlayAdvert {
                identifier: ADVERT_IDENTIFIER.to_string(),
                version: ADVERT_VERSION,
                endpoints: vec![endpoint],
                signal_relays: None,
                stun_servers: None,
            },
            created_at: created_at_secs,
            valid_until_ms: now_ms().saturating_add(3_600_000),
        }
    }

    /// Point the test instance's advert relays at explicit URLs. Unit tests
    /// that exercise `refetch_advert_for_stale_check` use this to replace the
    /// default public relay list with a local blackhole, so the refetch runs
    /// its full 2s timeout without touching the network.
    pub(crate) async fn set_advert_relays_for_test(&mut self, relays: Vec<String>) {
        for url in &relays {
            let _ = self.client.add_relay(url.as_str()).await;
        }
        self.client.connect().await;
        self.config.advert_relays = relays;
    }

    /// Insert a cached advert directly into the in-memory cache. Used by
    /// unit tests to set up consumer-side state without needing live relays.
    pub(crate) async fn insert_advert_for_test(&self, npub: String, advert: CachedOverlayAdvert) {
        self.advert.insert_fetched(&npub, advert);
    }

    /// Queue a bootstrap event directly for lifecycle tests without live relays
    /// or a running traversal task.
    pub(crate) fn push_event_for_test(&self, event: BootstrapEvent) {
        let _ = self.event_tx.send(event);
    }
}
