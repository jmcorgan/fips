//! Node-side driver state for the Nostr overlay peer-rendezvous subsystem.
//!
//! [`RendezvousDriver`] consolidates the rendezvous-subsystem state that
//! previously lived as loose fields on the `Node` struct: the engine handle,
//! its startup timestamp, the one-shot startup-sweep latch, and the
//! per-peer bootstrap-transport bookkeeping adopted from NAT-traversal
//! handoffs. Keeping it in the `nostr` module gives the subsystem a single
//! home while leaving the transport/connection-table mutations that consume
//! this state on `Node`.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use tracing::{debug, info};

use crate::NodeAddr;
use crate::config::{NostrRendezvousConfig, NostrRendezvousPolicy, PeerAddress, PeerConfig};
use crate::transport::TransportId;

use super::{BootstrapError, NostrRendezvous, OverlayEndpointAdvert, OverlayTransportKind};

pub use super::machine::adverts::assemble::AdvertTransportSnapshot;

/// The peer a bootstrap transport was adopted for: who it is and the address
/// the traversal reached it at.
#[derive(Debug, Clone)]
pub struct BootstrapPeer {
    /// The peer's npub (bech32).
    pub npub: String,
    /// The peer's node address, derived from `npub`.
    pub node_addr: NodeAddr,
    /// The remote address the traversal punched through to.
    pub remote_addr: SocketAddr,
    /// Set once a link to this peer has been seen on any transport.
    linked: bool,
}

/// Whether an unknown-version datagram may set the protocol-mismatch
/// cooldown for the peer a bootstrap transport was adopted for.
///
/// The datagram is unauthenticated. The evidence it can carry is only that
/// it came from the address the traversal reached and arrived before any
/// link to that peer existed; after a link, the peer has already completed a
/// handshake in our version. This is not proof of origin: an off-path sender
/// who can spoof that address and port can still set the cooldown once,
/// before the first link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MismatchEvidence<'a> {
    /// The transport is not an adopted bootstrap transport.
    NotBootstrap,
    /// The datagram did not come from the traversed address.
    ForeignSource,
    /// A link to the traversed peer exists or has existed.
    AfterLink,
    /// From the traversed address before any link: the cooldown applies to
    /// this npub.
    Traversed(&'a str),
}

impl MismatchEvidence<'_> {
    /// The stable field value naming this case in a log record.
    pub fn label(&self) -> &'static str {
        match self {
            MismatchEvidence::NotBootstrap => "not-bootstrap",
            MismatchEvidence::ForeignSource => "foreign-source",
            MismatchEvidence::AfterLink => "after-link",
            MismatchEvidence::Traversed(_) => "traversed",
        }
    }
}

/// A socket address with an IPv4-mapped IPv6 address taken as IPv4, so a
/// dual-stack socket's view of a source matches the traversal's.
fn canonical_socket(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// Node-side rendezvous-subsystem state and bootstrap-transport bookkeeping.
#[derive(Default)]
pub struct RendezvousDriver {
    /// Optional Nostr/STUN overlay discovery coordinator for `udp:nat` peers.
    engine: Option<Arc<NostrRendezvous>>,
    /// Wall-clock ms when Nostr discovery successfully started, used to
    /// schedule the one-shot startup advert sweep after a settle delay.
    /// `None` until discovery comes up; remains `None` if discovery is
    /// disabled or failed to start.
    started_at_ms: Option<u64>,
    /// Whether the one-shot startup advert sweep has run. Set to true
    /// after the first sweep fires (under `policy: open`); thereafter
    /// only the per-tick `queue_open_discovery_retries` continues.
    startup_sweep_done: bool,
    /// Per-peer UDP transports adopted from NAT traversal handoff.
    bootstrap_transports: HashSet<TransportId>,
    /// The originating peer of each adopted bootstrap transport, captured
    /// at `adopt_established_traversal` time. Populated alongside
    /// `bootstrap_transports`; cleared in
    /// `cleanup_bootstrap_transport_if_unused`. Used by the rx loop to
    /// route fatal-protocol-mismatch observations back to the
    /// Nostr-discovery `failure_state` for long cooldown application.
    bootstrap_peers: HashMap<TransportId, BootstrapPeer>,
    /// The transports last handed to the engine, so the tick sends them
    /// again only when they change.
    sent_transports: Option<Vec<AdvertTransportSnapshot>>,
}

impl RendezvousDriver {
    /// Borrow the engine handle if discovery is running.
    pub fn engine(&self) -> Option<&NostrRendezvous> {
        self.engine.as_deref()
    }

    /// Clone the engine `Arc` handle if discovery is running.
    pub fn engine_arc(&self) -> Option<Arc<NostrRendezvous>> {
        self.engine.clone()
    }

    /// Install the engine handle once discovery starts.
    pub fn set_engine(&mut self, engine: Arc<NostrRendezvous>) {
        self.engine = Some(engine);
    }

    /// Take the engine handle for shutdown, clearing it and what was last
    /// handed to it.
    pub fn take_engine(&mut self) -> Option<Arc<NostrRendezvous>> {
        self.sent_transports = None;
        self.engine.take()
    }

    /// Record the wall-clock ms at which discovery successfully started.
    pub fn set_started_at_ms(&mut self, now_ms: u64) {
        self.started_at_ms = Some(now_ms);
    }

    /// Wall-clock ms when discovery started, if it has.
    pub fn started_at_ms(&self) -> Option<u64> {
        self.started_at_ms
    }

    /// Whether the one-shot startup sweep has already run.
    pub fn startup_sweep_done(&self) -> bool {
        self.startup_sweep_done
    }

    /// Latch the one-shot startup sweep as done.
    pub fn set_startup_sweep_done(&mut self) {
        self.startup_sweep_done = true;
    }

    /// Whether `transport_id` is an adopted bootstrap transport.
    pub fn is_bootstrap_transport(&self, transport_id: &TransportId) -> bool {
        self.bootstrap_transports.contains(transport_id)
    }

    /// Originating peer npub for an adopted bootstrap transport, if any.
    pub fn bootstrap_transport_npub(&self, transport_id: &TransportId) -> Option<&String> {
        self.bootstrap_peers
            .get(transport_id)
            .map(|peer| &peer.npub)
    }

    /// The originating peer of an adopted bootstrap transport, if any.
    pub fn bootstrap_peer(&self, transport_id: &TransportId) -> Option<&BootstrapPeer> {
        self.bootstrap_peers.get(transport_id)
    }

    /// Register an adopted bootstrap transport, its originating peer and the
    /// address the traversal reached that peer at.
    pub fn insert_bootstrap_transport(
        &mut self,
        transport_id: TransportId,
        npub: String,
        node_addr: NodeAddr,
        remote_addr: SocketAddr,
    ) {
        self.bootstrap_transports.insert(transport_id);
        self.bootstrap_peers.insert(
            transport_id,
            BootstrapPeer {
                npub,
                node_addr,
                remote_addr,
                linked: false,
            },
        );
    }

    /// Judge whether an unknown-version datagram on `transport_id` from
    /// `source` may set the protocol-mismatch cooldown. `peer_linked` says
    /// whether a node currently has an established link.
    pub fn mismatch_evidence(
        &self,
        transport_id: &TransportId,
        source: Option<SocketAddr>,
        peer_linked: impl Fn(&NodeAddr) -> bool,
    ) -> MismatchEvidence<'_> {
        let Some(peer) = self.bootstrap_peers.get(transport_id) else {
            return MismatchEvidence::NotBootstrap;
        };
        if source.map(canonical_socket) != Some(canonical_socket(peer.remote_addr)) {
            return MismatchEvidence::ForeignSource;
        }
        if peer.linked || peer_linked(&peer.node_addr) {
            return MismatchEvidence::AfterLink;
        }
        MismatchEvidence::Traversed(&peer.npub)
    }

    /// Latch every bootstrap peer that now has an established link, so a
    /// mismatch from its address stays refused after the link drops.
    pub fn note_linked_bootstraps(&mut self, peer_linked: impl Fn(&NodeAddr) -> bool) {
        for peer in self.bootstrap_peers.values_mut() {
            if peer_linked(&peer.node_addr) {
                peer.linked = true;
            }
        }
    }

    /// Drop an adopted bootstrap transport from both bookkeeping maps.
    pub fn remove_bootstrap_transport(&mut self, transport_id: &TransportId) {
        self.bootstrap_transports.remove(transport_id);
        self.bootstrap_peers.remove(transport_id);
    }

    /// Convert an advertised overlay endpoint into a `PeerAddress` candidate.
    /// Pure mapping; `seen_at_ms` is supplied by the caller.
    pub fn overlay_endpoint_to_peer_address(
        endpoint: &OverlayEndpointAdvert,
        priority: u8,
        seen_at_ms: u64,
    ) -> Option<PeerAddress> {
        let transport = match endpoint.transport {
            OverlayTransportKind::Udp => "udp",
            OverlayTransportKind::Tcp => "tcp",
            OverlayTransportKind::Tor => "tor",
            OverlayTransportKind::Unknown => return None,
        };
        Some(
            PeerAddress::with_priority(transport, endpoint.addr.clone(), priority)
                .with_seen_at_ms(seen_at_ms),
        )
    }

    /// Kick off a Nostr-mediated UDP NAT-traversal attempt for `peer_config`.
    /// Returns whether an attempt was started (false if discovery is down).
    pub async fn request_nostr_bootstrap(&self, peer_config: &PeerConfig) -> bool {
        let Some(bootstrap) = self.engine_arc() else {
            debug!(npub = %peer_config.npub, "No Nostr overlay runtime for udp:nat address");
            return false;
        };
        bootstrap.request_connect(peer_config.clone()).await;
        info!(npub = %peer_config.npub, "Started Nostr UDP NAT traversal attempt");
        true
    }

    /// Resolve additional overlay `PeerAddress` candidates for a `via_nostr`
    /// configured peer by fetching its published advert endpoints. `existing`
    /// is the already-known static address list (used for priority and dedup);
    /// `now_ms` stamps the returned candidates' `seen_at`.
    pub async fn nostr_peer_fallback_addresses(
        &self,
        peer_config: &PeerConfig,
        existing: &[PeerAddress],
        nostr_cfg: &NostrRendezvousConfig,
        now_ms: u64,
    ) -> Vec<PeerAddress> {
        if !Self::nostr_wanted(peer_config, nostr_cfg) {
            return Vec::new();
        }

        let Some(bootstrap) = self.engine_arc() else {
            return Vec::new();
        };
        let endpoints = match bootstrap.advert_endpoints_for_peer(&peer_config.npub).await {
            Ok(endpoints) => endpoints,
            Err(err) => {
                debug!(
                    npub = %peer_config.npub,
                    error = %err,
                    "Failed to resolve Nostr advert endpoints for configured peer"
                );
                return Vec::new();
            }
        };
        Self::fallback_from(endpoints, existing, now_ms)
    }

    /// [`Self::nostr_peer_fallback_addresses`] from the advert cache alone:
    /// a peer whose advert is not cached, or no longer current, gives none.
    /// Never waits on a relay, only on the engine's queue, so the node's
    /// event loop may call it on every tick.
    pub async fn cached_addresses(
        &self,
        peer_config: &PeerConfig,
        existing: &[PeerAddress],
        nostr_cfg: &NostrRendezvousConfig,
        now_ms: u64,
    ) -> Vec<PeerAddress> {
        if !Self::nostr_wanted(peer_config, nostr_cfg) {
            return Vec::new();
        }
        let Some(bootstrap) = self.engine_arc() else {
            return Vec::new();
        };
        let Some(endpoints) = bootstrap.cached_endpoints(&peer_config.npub).await else {
            return Vec::new();
        };
        Self::fallback_from(endpoints, existing, now_ms)
    }

    /// Whether `peer_config`'s advert is to be read for candidates: Nostr
    /// rendezvous is on and the peer is configured to use it.
    fn nostr_wanted(peer_config: &PeerConfig, nostr_cfg: &NostrRendezvousConfig) -> bool {
        nostr_cfg.enabled
            && peer_config.via_nostr
            && nostr_cfg.policy != NostrRendezvousPolicy::Disabled
    }

    /// The candidates an advert's `endpoints` give beside the static list
    /// `existing`: each endpoint not already listed, in advert order, with
    /// priorities after the highest of `existing` and `seen_at` `now_ms`.
    fn fallback_from(
        endpoints: Vec<OverlayEndpointAdvert>,
        existing: &[PeerAddress],
        now_ms: u64,
    ) -> Vec<PeerAddress> {
        let mut fallback = Vec::new();
        let mut next_priority = existing
            .iter()
            .map(|addr| addr.priority)
            .max()
            .unwrap_or(100)
            .saturating_add(1);
        let seen_at_ms = now_ms;
        for endpoint in endpoints {
            let Some(candidate) =
                Self::overlay_endpoint_to_peer_address(&endpoint, next_priority, seen_at_ms)
            else {
                continue;
            };
            if existing
                .iter()
                .any(|addr| addr.transport == candidate.transport && addr.addr == candidate.addr)
                || fallback.iter().any(|addr: &PeerAddress| {
                    addr.transport == candidate.transport && addr.addr == candidate.addr
                })
            {
                continue;
            }
            fallback.push(candidate);
            next_priority = next_priority.saturating_add(1);
        }
        fallback
    }

    /// Hand the transports in `snapshot` to the engine when they differ from
    /// those last handed over; the engine assembles the local overlay advert
    /// from them and publishes it, once any public address it needs has been
    /// learned, and observes that address again when it ages out. Does not
    /// wait. When discovery is disabled no transport is advertised, so no
    /// advert results; publishing then stops, and the advert already on
    /// relays is not withdrawn but ages out by its NIP-40 expiration.
    /// `bootstrap` is passed explicitly because the startup path refreshes the
    /// advert before the engine handle is installed on the driver.
    pub async fn refresh_overlay_advert(
        &mut self,
        bootstrap: &Arc<NostrRendezvous>,
        snapshot: Vec<AdvertTransportSnapshot>,
        nostr_cfg: &NostrRendezvousConfig,
    ) -> Result<(), BootstrapError> {
        let advertised = Self::advertised(snapshot, nostr_cfg);
        if self.sent_transports.as_ref() == Some(&advertised) {
            return Ok(());
        }
        bootstrap.set_transports(advertised.clone());
        self.sent_transports = Some(advertised);
        Ok(())
    }

    /// As [`Self::refresh_overlay_advert`], waiting until the advert has
    /// been assembled from `snapshot`, so start-up reports the node running
    /// only once its first advert exists.
    pub async fn publish_initial_advert(
        &mut self,
        bootstrap: &Arc<NostrRendezvous>,
        snapshot: Vec<AdvertTransportSnapshot>,
        nostr_cfg: &NostrRendezvousConfig,
    ) -> Result<(), BootstrapError> {
        let advertised = Self::advertised(snapshot, nostr_cfg);
        self.sent_transports = Some(advertised.clone());
        bootstrap.assemble_advert(advertised).await
    }

    /// The transports to advertise: `snapshot`, or none when discovery is
    /// disabled.
    fn advertised(
        snapshot: Vec<AdvertTransportSnapshot>,
        nostr_cfg: &NostrRendezvousConfig,
    ) -> Vec<AdvertTransportSnapshot> {
        if nostr_cfg.enabled {
            snapshot
        } else {
            Vec::new()
        }
    }
}
