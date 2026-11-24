use portable_atomic::AtomicU64;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use nostr::event::{Event, Kind};
use nostr::key::{PublicKey, SecretKey};
use nostr::nips::nip19::ToBech32;
use nostr::types::{RelayUrl, Timestamp};
use nostr_sdk::client::ClientNotification;
#[cfg(test)]
use nostr_sdk::policy::AdmitStatus;
use serde::Serialize;
use tokio::sync::{Mutex, broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};

use super::handoff::EstablishedTraversal;
use super::log::FirstEvent;
use super::machine::NodeSigner;
use super::machine::adverts::assemble::AdvertTransportSnapshot;
use super::machine::error::Error as MachineError;
#[cfg(test)]
use super::machine::event::advert as advert_codec;
#[cfg(test)]
use super::machine::event::inbox as inbox_codec;
use super::machine::params::Params;
use super::machine::rendezvous::status::Status;
use super::machine::rendezvous::{Input, PeerKey, Rendezvous};
use super::machine::traversal::election::{Election, OfferDisposition, SeenDecision};
use super::machine::traversal::failures::FailureState;
use super::machine::traversal::gate::SignalGate;
use super::machine::traversal::rules::{self, RejectReason};
pub(super) use super::machine::traversal::rules::{canonical_npub, short_id, short_npub};
use super::offer_admission::{AdmissionReject, OfferAdmission};
use super::pump::{self, Inbox, Msg, Pump, ask};
#[cfg(test)]
use super::relay::aux;
use super::relay::{PumpAuthenticator, RelayClient};
use super::signal::{
    FreshnessOutcome, SignalEnvelope, build_signal_event, create_traversal_answer,
    create_traversal_offer, estimate_clock_skew, rumor, unwrap_signal_event,
    validate_offer_freshness, validate_traversal_answer_for_offer,
};
use super::signal_route::SignalRouter;
use super::stun::observe_traversal_addresses;
use super::traversal::{
    PunchTargetTally, RefusalWarnGate, bind_traversal, nonce, now_ms, planned_remote_endpoints,
    run_punch_attempt,
};
#[cfg(test)]
use super::types::ADVERT_IDENTIFIER;
use super::types::{
    BootstrapError, BootstrapEvent, FailureReply, NostrFailureDecision, NostrPeerFailureView,
    NostrRefetchOutcome, OverlayAdvert, OverlayEndpointAdvert, PunchHint, SIGNAL_KIND,
    TraversalAnswer, TraversalOffer,
};
use crate::PeerIdentity;
use crate::config::{NostrRendezvousConfig, PeerConfig};
use crate::time::{HostClock, HostInstant};
use fips_core::time::Clock;

/// Refuse an inbound offer whose session id or nonce is longer than the
/// machine's bound (`rules::check_offer_bounds`).
fn check_offer_bounds(offer: &TraversalOffer) -> Result<(), BootstrapError> {
    Ok(rules::check_offer_bounds(offer).map_err(MachineError::from)?)
}

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

/// An offer we sent and are still waiting on, with what is needed to send it
/// again. `resend` allows at most one successful re-send per offer.
struct InflightOffer {
    offer: TraversalOffer,
    relays: Vec<String>,
    receiver: PublicKey,
    resend: Resend,
}

/// Where the one re-send an in-flight offer is allowed stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resend {
    /// Not published yet; the next suppression may try.
    Available,
    /// A suppression is publishing it now, so a concurrent one must not.
    Sending,
    /// Published; the offer gets no further re-send.
    Done,
}

/// Whether an inbound-offer rejection belongs to a class that cannot be
/// explained by ordinary relay delivery lag (`RejectReason::adversarial`).
pub(super) fn adversarial_offer_reject(err: &BootstrapError) -> bool {
    matches!(
        err,
        BootstrapError::Protocol(reason)
            if RejectReason::from_code(reason).is_some_and(|r| r.adversarial())
    )
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
///
/// `warn` is the refusal-warning gate's decision for a suspicious record:
/// `Some(suppressed)` when this record is the one warning allowed in the
/// last minute, `None` otherwise, in which case it is logged at `debug`.
fn log_refusals(tally: &PunchTargetTally, peer: &str, session: &str, warn: Option<u64>) {
    if !tally.has_refusals() {
        return;
    }
    let sample = tally.sample.as_deref().unwrap_or("-");
    let reflexive = tally.reflexive.unwrap_or("-");
    if let Some(suppressed) = warn.filter(|_| tally.suspicious()) {
        warn!(
            peer = %peer,
            suppressed,
            session = %session,
            offered = tally.offered,
            admitted = tally.admitted,
            unparsable = tally.unparsable,
            zeroport = tally.zeroport,
            unroutable = tally.unroutable,
            offsubnet = tally.offsubnet,
            capped = tally.capped,
            over_offered = tally.over_offered,
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
            over_offered = tally.over_offered,
            reflexive = %reflexive,
            sample = %sample,
            "traversal: punch candidates refused"
        );
    }
}

/// The endpoints as one field value, `transport:addr` per endpoint.
pub(super) fn endpoint_summary(endpoints: &[OverlayEndpointAdvert]) -> String {
    endpoints
        .iter()
        .map(|e| format!("{:?}:{}", e.transport, e.addr).to_lowercase())
        .collect::<Vec<_>>()
        .join(",")
}

/// The node's handle on Nostr rendezvous.
///
/// The advert half (the peer advert cache, this node's advert, the relay
/// subscriptions and the inbox relay list) is owned by one task, the pump,
/// which steps the rendezvous machine; the handle's advert methods post to
/// it. The traversal half is [`TraversalShared`], served here until the
/// traversal flows move into the machine.
pub struct NostrRendezvous {
    /// The pump's inbox.
    inbox: Inbox,
    /// The pump.
    pump_task: Mutex<Option<JoinHandle<()>>>,
    /// The task that reads the signal router's channel.
    signal_task: Mutex<Option<JoinHandle<()>>>,
    traversal: Arc<TraversalShared>,
    /// The relay client, closed at shutdown.
    client: RelayClient,
    /// The pump's count of relay operations in flight.
    #[cfg(test)]
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
    /// How many times the node has sent its capacity.
    #[cfg(test)]
    capacity_sent: std::sync::atomic::AtomicUsize,
    /// The test's stand-in for the relay client's notification channel,
    /// which the pump reads; `None` once a test closes it.
    #[cfg(test)]
    pool: std::sync::Mutex<Option<broadcast::Sender<ClientNotification>>>,
    /// The signal router's receiver until a test starts the signal task on
    /// it.
    #[cfg(test)]
    signal_rx: std::sync::Mutex<Option<broadcast::Receiver<ClientNotification>>>,
    /// Shared by the pump and the signal task.
    #[cfg(test)]
    first: Arc<FirstEvent>,
}

/// The traversal half of Nostr rendezvous, shared by the handle, the signal
/// task and the traversal tasks: the initiator election and seen sessions,
/// the answers awaited and offers in flight, the offer admission, the
/// signal gate and the failure state. Served by the flows below until they
/// move into the machine; until then they reach the advert half only
/// through the pump (a peer's advert), and the pump reaches them only to
/// reset a failure streak.
pub(super) struct TraversalShared {
    /// The relay client, for the traversal signals and inbox lookups.
    client: RelayClient,
    /// The node key, shared with the machine.
    signer: Arc<NodeSigner>,
    npub: String,
    config: NostrRendezvousConfig,
    /// The pump's inbox, for a peer's advert.
    inbox: Inbox,
    traversal: std::sync::Mutex<Election>,
    pending_answers: Mutex<HashMap<String, oneshot::Sender<SignalEnvelope<TraversalAnswer>>>>,
    /// Our outbound offer per peer npub while we wait for its answer, kept so
    /// a dual-init election that suppresses the peer's offer can re-send ours.
    inflight_offers: Mutex<HashMap<String, InflightOffer>>,
    /// The payload of every signal `send_signal` published, in order, so unit
    /// tests can observe what was sent.
    #[cfg(test)]
    sent_signals: std::sync::Mutex<Vec<String>>,
    admission: OfferAdmission,
    signal_gate: std::sync::Mutex<SignalGate<HostInstant>>,
    /// Limits the suspicious-offer warning to one a minute.
    refusal_warn: std::sync::Mutex<RefusalWarnGate<HostInstant>>,
    /// Inbound traversal signals shed before decryption, since process start.
    shed_signals: AtomicU64,
    event_tx: mpsc::UnboundedSender<BootstrapEvent>,
    event_rx: Mutex<mpsc::UnboundedReceiver<BootstrapEvent>>,
    failure_state: std::sync::Mutex<FailureState>,
    /// The failure state as of its last change, which the node's
    /// synchronous queries read.
    status: ArcSwap<Status>,
    /// Outbound-admission flag refreshed once per Node tick from
    /// `Node::outbound_admission_check()`. Used to suppress NAT-traversal
    /// punch initiation (initiator path) and offer acceptance (responder
    /// path) when the Node is at `max_peers`. Loose granularity by
    /// design: the inbound msg1 gate in `handshake.rs` remains the
    /// authoritative cap.
    outbound_admission: AtomicBool,
}

impl TraversalShared {
    /// The traversal half for the node whose key `signer` holds, sending on
    /// `client` and asking the pump behind `inbox` for adverts.
    fn new(
        client: RelayClient,
        signer: Arc<NodeSigner>,
        npub: String,
        config: NostrRendezvousConfig,
        inbox: Inbox,
    ) -> Self {
        let params = Params::from(&config);
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        Self {
            client,
            signer,
            npub,
            inbox,
            admission: OfferAdmission::new(
                config.max_concurrent_incoming_offers,
                config.max_concurrent_offers_per_npub,
            ),
            failure_state: std::sync::Mutex::new(FailureState::new(
                params.failure_streak_threshold,
                params.extended_cooldown_secs,
                params.warn_log_interval_secs,
                params.failure_state_max_entries,
                fips_core::utils::hash::KeyedHasher::new::<crate::identity::OsEntropy>(),
            )),
            traversal: std::sync::Mutex::new(Election::new(
                params.replay_window_secs * 1000,
                params.seen_sessions_max_entries,
                fips_core::utils::hash::KeyedHasher::new::<crate::identity::OsEntropy>(),
            )),
            config,
            pending_answers: Mutex::new(HashMap::new()),
            inflight_offers: Mutex::new(HashMap::new()),
            #[cfg(test)]
            sent_signals: std::sync::Mutex::new(Vec::new()),
            signal_gate: std::sync::Mutex::new(SignalGate::new(HostClock.now())),
            refusal_warn: std::sync::Mutex::new(RefusalWarnGate::default()),
            shed_signals: AtomicU64::new(0),
            event_tx,
            event_rx: Mutex::new(event_rx),
            outbound_admission: AtomicBool::new(true),
            status: ArcSwap::from_pointee(Status::default()),
        }
    }

    /// Reset `npub`'s failure streak after its advert was refreshed or
    /// evicted, as the machine asks.
    fn reset_streak(&self, npub: &str) {
        self.change_failures(|failures| failures.reset_streak_after_refresh(npub));
    }

    /// Read the signal router's channel until it closes, opening each
    /// traversal signal: the traversal flows' only inbound feed.
    async fn run_signals(
        self: Arc<Self>,
        mut signals: broadcast::Receiver<ClientNotification>,
        first: Arc<FirstEvent>,
    ) {
        loop {
            let notification = match received(signals.recv().await) {
                ControlFlow::Continue(Some(notification)) => notification,
                ControlFlow::Continue(None) => continue,
                ControlFlow::Break(()) => break,
            };
            first.note();
            if let ClientNotification::Event { event, .. } = notification
                && event.kind == Kind::Custom(SIGNAL_KIND)
            {
                self.handle_signal(event).await;
            }
        }
    }

    /// `key`'s advert, from the pump: the cache, or else the advert relays.
    async fn resolve_advert(&self, key: PeerKey) -> Result<OverlayAdvert, BootstrapError> {
        match ask(&self.inbox, |tx| Msg::ResolveAdvert { key, tx }).await {
            Some(result) => Ok(result?),
            None => Err(BootstrapError::Disabled),
        }
    }

    /// Update the cached outbound-admission flag. Called once per Node
    /// tick with the current value of `Node::outbound_admission_check()`.
    /// Cheap atomic store; safe to call unconditionally.
    fn set_outbound_admission(&self, allow: bool) {
        self.outbound_admission.store(allow, Ordering::Relaxed);
    }

    /// Read the cached outbound-admission flag. Returns `true` when the
    /// Node is below `max_peers` (or `max_peers == 0`), `false` otherwise.
    pub(crate) fn outbound_admission_allowed(&self) -> bool {
        self.outbound_admission.load(Ordering::Relaxed)
    }

    async fn request_connect(self: &Arc<Self>, peer_config: PeerConfig) {
        // The configuration may name the peer by any spelling of its key. The
        // traversal runs under the canonical npub, so the initiator set dedupes
        // spellings and the offer names the recipient as it names itself; the
        // failure event hands back the configuration as it was given.
        let peer_npub = canonical_npub(&peer_config.npub);
        if !self.election().begin_initiator(&peer_npub) {
            return;
        }
        let target = PeerConfig {
            npub: peer_npub.clone(),
            ..peer_config.clone()
        };

        let runtime = Arc::clone(self);
        tokio::spawn(async move {
            let event = match runtime.connect_peer(target).await {
                Ok(traversal) => BootstrapEvent::Established { traversal },
                Err(err) => BootstrapEvent::Failed {
                    peer_config,
                    reason: err.to_string(),
                },
            };
            let _ = runtime.event_tx.send(event);
            runtime.election().end_initiator(&peer_npub);
        });
    }

    /// The initiator election and the seen-sessions cache, under their lock.
    fn election(&self) -> std::sync::MutexGuard<'_, Election> {
        self.traversal
            .lock()
            .expect("traversal-machine mutex poisoned")
    }

    /// The pre-decrypt signal allowance, under its lock.
    fn gate(&self) -> std::sync::MutexGuard<'_, SignalGate<HostInstant>> {
        self.signal_gate.lock().expect("signal-gate mutex poisoned")
    }

    /// Change the per-peer failure state with `change`, under its lock,
    /// and store the status the node reads from it.
    fn change_failures<R>(&self, change: impl FnOnce(&mut FailureState) -> R) -> R {
        let mut failures = self
            .failure_state
            .lock()
            .expect("failure-state mutex poisoned");
        let result = change(&mut failures);
        self.status.store(Arc::new(Status::of(&failures)));
        result
    }

    /// Record a NAT-traversal failure for `npub` now, returning the
    /// resulting decision (WARN suppression + extended cooldown +
    /// threshold-crossing flag for the B6 re-fetch) and the time it used.
    fn record_traversal_failure(&self, npub: &str) -> FailureReply {
        let at_ms = now_ms();
        let d =
            self.change_failures(|failures| failures.record_failure(&canonical_npub(npub), at_ms));
        FailureReply {
            decision: NostrFailureDecision {
                consecutive_failures: d.consecutive_failures,
                should_warn: d.should_warn,
                cooldown_until_ms: d.cooldown_until_ms,
                crossed_threshold: d.crossed_threshold,
            },
            at_ms,
        }
    }

    /// Record a successful traversal — clears the streak/cooldown.
    fn record_traversal_success(&self, npub: &str, now_ms: u64) {
        self.change_failures(|failures| failures.record_success(&canonical_npub(npub), now_ms));
    }

    /// Cooldown wall-clock ms if the peer is currently suppressed,
    /// else None. Used by the open-discovery sweep to skip enqueue.
    fn cooldown_until(&self, npub: &str, now_ms: u64) -> Option<u64> {
        self.status
            .load()
            .cooldown_until(&canonical_npub(npub), now_ms)
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
    fn record_protocol_mismatch(&self, npub: &str, now_ms: u64) -> bool {
        let cooldown_ms = self
            .config
            .protocol_mismatch_cooldown_secs
            .saturating_mul(1000);
        self.change_failures(|failures| {
            failures.record_protocol_mismatch(&canonical_npub(npub), now_ms, cooldown_ms)
        })
    }

    /// Configured protocol-mismatch cooldown in seconds. Exposed so log
    /// emitters can include the duration without re-reading config.
    fn protocol_mismatch_cooldown_secs(&self) -> u64 {
        self.config.protocol_mismatch_cooldown_secs
    }

    /// Snapshot of per-npub failure state for `show_peers` rendering.
    fn failure_state_snapshot(&self) -> Vec<NostrPeerFailureView> {
        self.status.load().failure_views()
    }

    async fn drain_events(&self) -> Vec<BootstrapEvent> {
        let mut out = Vec::new();
        let mut rx = self.event_rx.lock().await;
        while let Ok(event) = rx.try_recv() {
            out.push(event);
        }
        out
    }

    /// Open an inbound traversal signal, unless the signal gate sheds it, and
    /// hand an answer to the traversal waiting for it or admit an offer.
    async fn handle_signal(self: &Arc<Self>, event: Box<Event>) {
        // Ahead of the unwrap, which is two NIP-44 decrypts and a
        // signature verify run inline on the single task that also
        // routes answers and processes adverts. Nothing about the
        // sender is known yet — the outer event is signed by a key
        // generated per event — so the allowance is necessarily
        // shared and indiscriminate, and the reserve is what keeps
        // a flood from also shedding the answers to traversals
        // this node started.
        let awaiting_answers = match self.pending_answers.try_lock() {
            Ok(pending) => !pending.is_empty(),
            // Contended rather than known empty, so treat it as
            // outstanding: the fail-open direction here spends the
            // reserve, it does not shed.
            Err(_) => true,
        };
        let admitted = self.gate().admit(awaiting_answers, HostClock.now());
        if let Err(shed) = admitted {
            let total = self.shed_signals.fetch_add(1, Ordering::Relaxed) + 1;
            // Debug, not warn, per event: the party that trips this
            // is by definition sending faster than the node wants,
            // so a record per drop turns the flood into log volume.
            // The doubling summary below is the operator's signal.
            debug!(
                reason = ?shed,
                total,
                "shed inbound traversal signal before decrypt"
            );
            if total.is_power_of_two() {
                warn!(
                    shed = total,
                    "inbound traversal signals shed before decrypt"
                );
            }
            return;
        }

        let unwrapped = match unwrap_signal_event(&self.signer, &event).await {
            Ok(unwrapped) => unwrapped,
            Err(err) => {
                trace!(error = %err, "failed to unwrap traversal signal");
                return;
            }
        };
        let sender_npub = match unwrapped.sender.to_bech32() {
            Ok(npub) => npub,
            Err(err) => {
                debug!(error = %err, "failed to encode traversal sender npub");
                return;
            }
        };

        if let Ok(answer) = serde_json::from_str::<TraversalAnswer>(&unwrapped.rumor.content)
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
                    sender_npub: sender_npub.clone(),
                });
            }
            return;
        }

        if let Ok(offer) = serde_json::from_str::<TraversalOffer>(&unwrapped.rumor.content)
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
                    return;
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
                    return;
                }
            };
            let runtime = Arc::clone(self);
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

    fn punch_hint(&self) -> PunchHint {
        rules::punch_hint(
            now_ms(),
            self.config.punch_start_delay_ms,
            self.config.punch_interval_ms,
            self.config.punch_duration_ms,
        )
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
        let (target_pubkey, canonical) = peer_key(&peer_config.npub)?;
        let advert = self
            .resolve_advert(PeerKey {
                pubkey: target_pubkey,
                npub: canonical,
            })
            .await?;
        if !advert.has_udp_nat_endpoint() {
            return Err(BootstrapError::MissingNatEndpoint(peer_config.npub.clone()));
        }
        let relays = self
            .preferred_signal_relays(target_pubkey, Some(&advert))
            .await?;
        if relays.is_empty() {
            return Err(BootstrapError::MissingRelays(peer_config.npub));
        }

        let base_socket = bind_traversal(SocketAddr::from(([0, 0, 0, 0], 0)))?;

        // This drains every datagram on the traversal socket until the STUN
        // deadline, so it must complete before any punch can be in flight: a
        // retry or re-observation once punching has started would swallow the
        // peer's punch packets.
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
        self.inflight_offers.lock().await.insert(
            peer_config.npub.clone(),
            InflightOffer {
                offer: offer.clone(),
                relays: relays.clone(),
                receiver: target_pubkey,
                resend: Resend::Available,
            },
        );

        let answer =
            tokio::time::timeout(Duration::from_secs(self.config.signal_ttl_secs), rx).await;
        self.inflight_offers.lock().await.remove(&peer_config.npub);
        let answer = match answer {
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
            self.change_failures(|failures| {
                failures.note_observed_skew(&peer_config.npub, observed_skew_ms, answer_received_at)
            });
            if rules::skew_is_significant(observed_skew_ms) {
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
            &crate::utils::onlink::read_system(),
        )?;
        self.log_punch_refusals(&tally, &peer_short, &short_id(&session_id));

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

        self.change_failures(|failures| failures.record_success(&peer_config.npub, now_ms()));

        Ok(
            EstablishedTraversal::new(session_id, peer_config.npub, remote_addr, base_socket)
                .with_transport_name("nostr-nat"),
        )
    }

    /// Send our in-flight offer to `peer_npub` once more.
    ///
    /// Called when the dual-init election suppresses the peer's offer. If the
    /// peer received our offer, it answers that one and this copy is dropped by
    /// its replay check. If our offer was lost, or published before the peer
    /// was listening, the suppression leaves neither side answering, and the
    /// connect would stall for `signal_ttl_secs`; this copy lets the peer answer
    /// now.
    ///
    /// At most one successful re-send per offer. The re-send is marked done only
    /// once a publish succeeds, so a failed publish leaves it available to the
    /// next suppression; while one is publishing, a concurrent suppression
    /// sends nothing.
    async fn resend_inflight_offer(&self, peer_npub: &str) {
        let (offer, relays, receiver) = {
            let mut inflight = self.inflight_offers.lock().await;
            let Some(entry) = inflight
                .get_mut(peer_npub)
                .filter(|e| e.resend == Resend::Available)
            else {
                return;
            };
            entry.resend = Resend::Sending;
            (entry.offer.clone(), entry.relays.clone(), entry.receiver)
        };
        let peer_short = short_npub(peer_npub);
        let result = self.send_signal(&relays, receiver, &offer).await;
        // The entry may have been removed (answered or timed out) or replaced
        // by a newer offer while the publish ran; only this offer's entry is
        // updated.
        if let Some(entry) = self
            .inflight_offers
            .lock()
            .await
            .get_mut(peer_npub)
            .filter(|e| e.offer.session_id == offer.session_id)
        {
            entry.resend = if result.is_ok() {
                Resend::Done
            } else {
                Resend::Available
            };
        }
        match result {
            Ok(event) => debug!(
                peer = %peer_short,
                session = %short_id(&offer.session_id),
                event = %short_id(&event.id.to_string()),
                "traversal: offer re-sent after suppressing the peer's"
            ),
            Err(err) => debug!(
                peer = %peer_short,
                session = %short_id(&offer.session_id),
                error = %err,
                "traversal: offer re-send failed"
            ),
        }
    }

    async fn handle_incoming_offer(
        self: Arc<Self>,
        offer: TraversalOffer,
        sender: PublicKey,
        sender_npub: String,
    ) -> Result<(), BootstrapError> {
        // Before anything logs, records or copies the session id or nonce.
        check_offer_bounds(&offer)?;
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
                // Bound before the match: the Suppress arm awaits, and the
                // election's lock must not be held across it.
                let disposition = self.election().classify_incoming_offer(
                    &sender_npub,
                    ours.node_addr(),
                    theirs.node_addr(),
                );
                match disposition {
                    OfferDisposition::Suppress => {
                        debug!(
                            peer = %peer_short,
                            session = %short_id(&offer.session_id),
                            "traversal: responder session suppressed, our outbound initiator wins (smaller addr)"
                        );
                        self.resend_inflight_offer(&sender_npub).await;
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

        let seen = self
            .election()
            .note_session_seen(&offer.session_id, now_ms());
        match seen {
            SeenDecision::Replay => {
                return Err(BootstrapError::Replay(offer.session_id.clone()));
            }
            SeenDecision::Full => {
                return Err(BootstrapError::Protocol("seen-sessions-full".to_string()));
            }
            SeenDecision::Fresh => {}
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

        let base_socket = bind_traversal(SocketAddr::from(([0, 0, 0, 0], 0)))?;
        // This drains every datagram on the traversal socket until the STUN
        // deadline, so it must complete before any punch can be in flight: a
        // retry or re-observation once punching has started would swallow the
        // peer's punch packets.
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
            return Ok(());
        }

        let (remotes, tally) = planned_remote_endpoints(
            &answer.local_addresses,
            answer.reflexive_address.as_ref(),
            &offer.local_addresses,
            offer.reflexive_address.as_ref(),
            &crate::utils::onlink::read_system(),
        )?;
        self.log_punch_refusals(&tally, &peer_short, &short_id(&offer.session_id));

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
        Ok(())
    }

    async fn preferred_signal_relays(
        &self,
        target_pubkey: PublicKey,
        advert: Option<&OverlayAdvert>,
    ) -> Result<Vec<String>, BootstrapError> {
        let inbox = self.find_recipient_inbox_relays(target_pubkey).await?;
        let pool: HashSet<RelayUrl> = self.client.pool_urls().await;
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

    /// The relays `target_pubkey`'s newest kind 10050 inbox relay list names,
    /// looked up on our own DM and advert relays (`rules::inbox_lookup`).
    /// Falls back to our `dm_relays` when the fetch fails or no non-empty
    /// list is found (`rules::inbox_or_fallback`).
    async fn find_recipient_inbox_relays(
        &self,
        target_pubkey: PublicKey,
    ) -> Result<Vec<String>, BootstrapError> {
        let (lookup_relays, filter) = rules::inbox_lookup(
            target_pubkey,
            &self.config.dm_relays,
            &self.config.advert_relays,
            now_ms(),
        );
        let events = self
            .client
            .fetch(lookup_relays, filter, rules::INBOX_FETCH_TIMEOUT)
            .await;
        if let Err(err) = &events {
            debug!(error = %err, "failed to fetch inbox relays, falling back to configured DM relays");
        }
        Ok(rules::inbox_or_fallback(
            events.as_deref(),
            target_pubkey,
            &self.config.dm_relays,
        ))
    }

    /// Log one planning call's refused punch candidates, giving at most one
    /// warning a minute for suspicious offers.
    fn log_punch_refusals(&self, tally: &PunchTargetTally, peer: &str, session: &str) {
        let warn = self
            .refusal_warn
            .lock()
            .expect("refusal-warn mutex poisoned")
            .decide(tally, HostClock.now());
        log_refusals(tally, peer, session, warn);
    }

    async fn send_signal<T: Serialize>(
        &self,
        relays: &[String],
        receiver: PublicKey,
        payload: &T,
    ) -> Result<Event, BootstrapError> {
        let signal = signal_event(
            &self.signer,
            receiver,
            payload,
            self.config.signal_ttl_secs,
            now_ms(),
        )?;
        self.client
            .send(relays, &signal)
            .await
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
        #[cfg(test)]
        self.sent_signals
            .lock()
            .expect("sent_signals lock")
            .push(serde_json::to_string(payload)?);
        Ok(signal)
    }
}

impl NostrRendezvous {
    /// Whether the Nostr subsystem has stopped being able to do its job
    /// (runtime liveness).
    ///
    /// "Nostr exited" is defined as either of its two tasks having finished:
    ///
    /// - the pump, which owns the advert half: it reads the relay client's
    ///   stream, publishes this node's advert and keeps the relay
    ///   subscriptions. Without it no advert is received or published again.
    /// - the signal task, which reads the signal router's channel. Without it
    ///   no traversal signal is ever received again.
    ///
    /// Each runs until the relay client's stream or the signals' channel
    /// ends, which means the client is gone, or until `shutdown`, so a
    /// finished handle means the task panicked, was aborted or was stopped:
    /// unrecoverable, which matches the one-way `ChildExited` → `Degraded`
    /// latch in the supervisor FSM.
    ///
    /// Each handle is `Some` for the engine's whole running life (installed in
    /// `start`); `shutdown` takes them both, leaving `None` — a taken handle
    /// means the engine has been shut down, which counts as finished, so a
    /// `None` inner maps to `true` (this lets the liveness poll monitor
    /// terminate after a stop rather than spinning forever). The slots are
    /// `tokio::sync::Mutex`es, so this sync accessor uses the non-blocking
    /// `try_lock`: a momentarily-contended lock (only start/stop hold it,
    /// briefly) reports "not finished", the safe direction — the 2s liveness
    /// poll re-checks next tick and never spuriously degrades a healthy node.
    pub fn is_finished(&self) -> bool {
        Self::task_finished(&self.pump_task) || Self::task_finished(&self.signal_task)
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

        // Two copies of the private key are made to reach the signer: the
        // keypair and its secret key. Each is bound and cleared here; nostr's
        // `SecretKey`, which the signer holds, clears its own on drop.
        let mut our_keypair = identity.keypair();
        let mut secret = our_keypair.secret_key();
        let signer = Arc::new(NodeSigner::new(SecretKey::from(secret)));
        secret.non_secure_erase();
        our_keypair.non_secure_erase();
        let npub = crate::encode_npub(&identity.pubkey());

        let (inbox, inbox_rx) = mpsc::unbounded_channel();
        let (router, signals) = SignalRouter::new();
        let forwarder = router.forwarder();
        let client = RelayClient::build(PumpAuthenticator::new(inbox.clone()), router);

        let mut relay_union = HashSet::new();
        relay_union.extend(config.advert_relays.iter().cloned());
        relay_union.extend(config.dm_relays.iter().cloned());
        client
            .add_relays(&relay_union)
            .await
            .map_err(|e| BootstrapError::Nostr(e.to_string()))?;

        let params = Params::from(&config);
        let machine = Rendezvous::new(params, Arc::clone(&signer), npub.clone(), pump::now());
        let traversal = Arc::new(TraversalShared::new(
            client.clone(),
            signer,
            npub,
            config,
            inbox.clone(),
        ));
        let first = Arc::new(FirstEvent::new());

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
        let reset = Arc::clone(&traversal);
        let pump = Pump::new(
            machine,
            client.clone(),
            inbox.clone(),
            Box::new(move |npub| reset.reset_streak(npub)),
            forwarder,
            Arc::clone(&first),
        );
        #[cfg(test)]
        let in_flight = pump.in_flight();
        let pump_task = tokio::spawn(pump.run(notifications, inbox_rx));
        // Starts each relay's connection task and returns, so the first
        // subscribe meets relays that have left their initial state.
        client.connect().await;
        let signal_task =
            tokio::spawn(Arc::clone(&traversal).run_signals(signals, Arc::clone(&first)));
        let _ = inbox.send(Msg::Input(Input::Start));

        Ok(Arc::new(Self {
            inbox,
            pump_task: Mutex::new(Some(pump_task)),
            signal_task: Mutex::new(Some(signal_task)),
            traversal,
            client,
            #[cfg(test)]
            in_flight,
            #[cfg(test)]
            capacity_sent: Default::default(),
            #[cfg(test)]
            pool: std::sync::Mutex::new(None),
            #[cfg(test)]
            signal_rx: std::sync::Mutex::new(None),
            #[cfg(test)]
            first,
        }))
    }

    /// Tell the engine whether the node has room for another peer:
    /// `Node::outbound_admission_check()`, sent when it changes. While it
    /// is `false` the engine starts no traversal and answers no offer.
    /// Loose by design: the inbound msg1 gate in `handshake.rs` remains the
    /// authoritative cap.
    pub fn set_capacity(&self, allow: bool) {
        #[cfg(test)]
        self.capacity_sent
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.traversal.set_outbound_admission(allow);
    }

    /// Read the cached outbound-admission flag. Returns `true` when the
    /// Node is below `max_peers` (or `max_peers == 0`), `false` otherwise.
    #[cfg(test)]
    pub(crate) fn outbound_admission_allowed(&self) -> bool {
        self.traversal.outbound_admission_allowed()
    }

    pub async fn request_connect(self: &Arc<Self>, peer_config: PeerConfig) {
        self.traversal.request_connect(peer_config).await;
    }

    /// Record a NAT-traversal failure for `npub`, returning the
    /// resulting decision (WARN suppression + extended cooldown +
    /// threshold-crossing flag for the B6 re-fetch) and the Unix time in
    /// milliseconds it was computed at, from which the caller measures the
    /// cooldown.
    pub async fn record_traversal_failure(&self, npub: &str) -> FailureReply {
        self.traversal.record_traversal_failure(npub)
    }

    /// Record a successful traversal — clears the streak/cooldown.
    pub fn record_traversal_success(&self, npub: &str, now_ms: u64) {
        self.traversal.record_traversal_success(npub, now_ms);
    }

    /// Cooldown wall-clock ms if the peer is currently suppressed,
    /// else None. Used by the open-discovery sweep to skip enqueue.
    pub fn cooldown_until(&self, npub: &str, now_ms: u64) -> Option<u64> {
        self.traversal.cooldown_until(npub, now_ms)
    }

    /// Note that a datagram from the address a traversal adopted for `npub`
    /// carried an FMP version other than ours, on `transport_id` from
    /// `remote_addr`. The peer's discovery cooldown is bumped to the long
    /// protocol-mismatch window, and a fresh observation, one not already
    /// inside a comparable cooldown, is logged once at warning level, as
    /// the receive loop logged it.
    pub fn note_version_mismatch(
        &self,
        npub: &str,
        transport_id: impl std::fmt::Display,
        remote_addr: impl std::fmt::Display,
        peer_version: u8,
        our_version: u8,
    ) {
        if self.traversal.record_protocol_mismatch(npub, now_ms()) {
            super::log::version_mismatch(
                npub,
                &transport_id.to_string(),
                &remote_addr.to_string(),
                peer_version,
                our_version,
                self.traversal.protocol_mismatch_cooldown_secs(),
            );
        }
    }

    /// Configured protocol-mismatch cooldown in seconds. Exposed so log
    /// emitters can include the duration without re-reading config.
    pub fn protocol_mismatch_cooldown_secs(&self) -> u64 {
        self.traversal.protocol_mismatch_cooldown_secs()
    }

    /// Snapshot of per-npub failure state for `show_peers` rendering.
    pub fn failure_state_snapshot(&self) -> Vec<NostrPeerFailureView> {
        self.traversal.failure_state_snapshot()
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
        self.traversal.drain_events().await
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
            // The pump aborts its relay operations in flight as it ends.
            let _ = handle.await;
        }
        if let Some(handle) = self.signal_task.lock().await.take() {
            handle.abort();
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
impl TraversalShared {
    /// Register `offer` as our in-flight offer to `peer_npub`, sent to `relays`,
    /// with an active initiator, as `connect_peer` would after publishing it.
    async fn insert_inflight_offer_for_test(
        &self,
        peer_npub: &str,
        offer: TraversalOffer,
        receiver: PublicKey,
        relays: Vec<String>,
    ) {
        self.election().begin_initiator(peer_npub);
        self.inflight_offers.lock().await.insert(
            peer_npub.to_string(),
            InflightOffer {
                offer,
                relays,
                receiver,
                resend: Resend::Available,
            },
        );
    }
}

#[cfg(test)]
impl NostrRendezvous {
    /// The advert `event` carries, if it is for `expected_app` and passes
    /// every content rule (`ingest::parse`).
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

    /// Newest event in `events` that was actually signed by `author`
    /// (`ingest::newest_by_author`).
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

    /// Build a `NostrRendezvous` for unit tests. Its pump runs, with the
    /// real relay client, on a stand-in for the client's notification
    /// channel that [`Self::deliver_for_test`] feeds; it is not started
    /// (no subscribe, no publish) and its client is connected to nothing
    /// until a test adds relays. The signal task is not running until
    /// [`Self::spawn_signals_for_test`]. Needs a tokio runtime.
    pub(crate) fn new_for_test() -> Self {
        Self::new_for_test_with_config(NostrRendezvousConfig::default())
    }

    /// As [`Self::new_for_test`], with `config` in place of the default.
    /// The configuration is fixed here: the pump and the traversal flows
    /// each hold their copy.
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
        let signer = Arc::new(NodeSigner::new(secret_key));
        let npub = signer.public_key().to_bech32().expect("bech32 encode");
        let (inbox, inbox_rx) = mpsc::unbounded_channel();
        let (router, signals) = SignalRouter::new();
        let forwarder = router.forwarder();
        let client = RelayClient::build(PumpAuthenticator::new(inbox.clone()), router);
        let params = Params::from(&config);
        let machine = Rendezvous::new(params, Arc::clone(&signer), npub.clone(), pump::now());
        let traversal = Arc::new(TraversalShared::new(
            client.clone(),
            signer,
            npub,
            config,
            inbox.clone(),
        ));
        let first = Arc::new(FirstEvent::new());
        let (pool, pool_rx) = broadcast::channel(super::relay::POOL_CHANNEL);
        // Read as the client's stream reads its channel: a lag is skipped
        // and a closed channel ends the stream (nostr-sdk 0.45.6,
        // `src/stream.rs`, `NotificationStream`).
        let stand_in = futures::stream::unfold(pool_rx, |mut receiver| async move {
            loop {
                match receiver.recv().await {
                    Ok(notification) => return Some((notification, receiver)),
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        });
        let reset = Arc::clone(&traversal);
        let pump = Pump::new(
            machine,
            client.clone(),
            inbox.clone(),
            Box::new(move |npub| reset.reset_streak(npub)),
            forwarder,
            Arc::clone(&first),
        );
        let in_flight = pump.in_flight();
        let pump_task = tokio::spawn(pump.run(Box::pin(stand_in), inbox_rx));
        Self {
            inbox,
            pump_task: Mutex::new(Some(pump_task)),
            signal_task: Mutex::new(None),
            traversal,
            client,
            in_flight,
            capacity_sent: Default::default(),
            pool: std::sync::Mutex::new(Some(pool)),
            signal_rx: std::sync::Mutex::new(Some(signals)),
            first,
        }
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

    /// How many times the node has sent its capacity.
    pub(crate) fn capacity_received_for_test(&self) -> usize {
        self.capacity_sent.load(Ordering::SeqCst)
    }

    /// Register `offer` as our in-flight offer to `peer_npub`, sent to `relays`,
    /// with an active initiator, as `connect_peer` would after publishing it.
    pub(crate) async fn insert_inflight_offer_for_test(
        &self,
        peer_npub: &str,
        offer: TraversalOffer,
        receiver: PublicKey,
        relays: Vec<String>,
    ) {
        self.traversal
            .insert_inflight_offer_for_test(peer_npub, offer, receiver, relays)
            .await;
    }

    /// Whether our in-flight offer to `peer_npub` has been re-sent, or `None`
    /// when there is none.
    pub(crate) async fn inflight_offer_resent_for_test(&self, peer_npub: &str) -> Option<bool> {
        self.traversal
            .inflight_offers
            .lock()
            .await
            .get(peer_npub)
            .map(|e| e.resend == Resend::Done)
    }

    /// The traversal offers `send_signal` has published, in order.
    pub(crate) fn sent_offers_for_test(&self) -> Vec<TraversalOffer> {
        self.traversal
            .sent_signals
            .lock()
            .expect("sent_signals lock")
            .iter()
            .filter_map(|json| serde_json::from_str::<TraversalOffer>(json).ok())
            .filter(|offer| offer.message_type == "offer")
            .collect()
    }

    /// Add `url` to the client pool without connecting to it. A send naming
    /// only that relay then returns `Ok` from the pool, with the relay listed
    /// as failed, and touches no network; a send naming a relay outside the
    /// pool fails.
    pub(crate) async fn add_unconnected_relay_for_test(&self, url: &str) {
        self.client.add_relays([url]).await.expect("add relay");
    }

    /// Close the stand-in for the relay client's notification channel, as
    /// the client's shutdown ends its stream.
    pub(super) fn close_pool_for_test(&self) {
        self.pool.lock().expect("pool lock").take();
    }

    /// A receiver of the stand-in for the relay client's notification
    /// channel, from now on, to count what is queued on it.
    pub(super) fn pool_receiver_for_test(&self) -> broadcast::Receiver<ClientNotification> {
        self.pool
            .lock()
            .expect("pool lock")
            .as_ref()
            .expect("the stand-in is open")
            .subscribe()
    }

    /// Start the signal task on the signal router's channel, as `start`
    /// does, and return its handle.
    pub(super) fn spawn_signals_for_test(&self) -> JoinHandle<()> {
        let signals = self
            .signal_rx
            .lock()
            .expect("signal_rx lock")
            .take()
            .expect("the signal channel's receiver is taken once");
        tokio::spawn(Arc::clone(&self.traversal).run_signals(signals, Arc::clone(&self.first)))
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
        if let Some(pool) = self.pool.lock().expect("pool lock").as_ref() {
            let _ = pool.send(notification);
        }
    }

    /// Put `notification` on the stand-in for the relay client's
    /// notification channel without the admission policy, as if a relay's
    /// event had reached the pool's stream some other way.
    pub(super) fn deliver_unfiltered_for_test(&self, notification: ClientNotification) {
        if let Some(pool) = self.pool.lock().expect("pool lock").as_ref() {
            let _ = pool.send(notification);
        }
    }

    /// Register a traversal waiting for the answer to our offer whose nonce is
    /// `nonce`, as `connect_peer` does once the offer is sent, and return the
    /// receiver the signal task hands that answer to.
    pub(super) async fn await_answer_for_test(
        &self,
        nonce: &str,
    ) -> oneshot::Receiver<SignalEnvelope<TraversalAnswer>> {
        let (tx, rx) = oneshot::channel();
        self.traversal
            .pending_answers
            .lock()
            .await
            .insert(nonce.to_string(), tx);
        rx
    }

    /// This runtime's own npub.
    pub(crate) fn npub_for_test(&self) -> &str {
        &self.traversal.npub
    }

    /// Run the incoming-offer handler.
    pub(crate) async fn handle_incoming_offer_for_test(
        self: Arc<Self>,
        offer: TraversalOffer,
        sender: PublicKey,
        sender_npub: String,
    ) -> Result<(), BootstrapError> {
        Arc::clone(&self.traversal)
            .handle_incoming_offer(offer, sender, sender_npub)
            .await
    }

    /// Install the pump's and the signal task's handles, so liveness tests
    /// can drive `is_finished()` without live relays. The handles they
    /// replace are dropped, which leaves their tasks running.
    pub(crate) async fn install_task_handles_for_test(
        &self,
        pump: JoinHandle<()>,
        signals: JoinHandle<()>,
    ) {
        *self.pump_task.lock().await = Some(pump);
        *self.signal_task.lock().await = Some(signals);
    }

    /// Take both task handles out of their slots, as `shutdown` does.
    pub(crate) async fn take_task_handles_for_test(&self) {
        self.pump_task.lock().await.take();
        self.signal_task.lock().await.take();
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

    /// Point the advert half's relays at explicit URLs, adding them to the
    /// pool and connecting. Unit tests that exercise
    /// `refetch_advert_for_stale_check` use this to replace the default
    /// public relay list with a local relay or blackhole. The traversal
    /// half keeps the relays it was built with.
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

    /// Queue a bootstrap event directly for lifecycle tests without live relays
    /// or a running traversal task.
    pub(crate) fn push_event_for_test(&self, event: BootstrapEvent) {
        let _ = self.traversal.event_tx.send(event);
    }

    /// Whether an outbound initiator is registered under `npub` as written.
    pub(crate) fn initiator_active_for_test(&self, npub: &str) -> bool {
        let mut election = self.traversal.election();
        if election.begin_initiator(npub) {
            election.end_initiator(npub);
            false
        } else {
            true
        }
    }
}
