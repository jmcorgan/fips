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

use tracing::{debug, info, warn};

use crate::NodeAddr;
use crate::config::{NostrRendezvousConfig, NostrRendezvousPolicy, PeerAddress, PeerConfig};
use crate::transport::TransportId;

use super::{
    ADVERT_IDENTIFIER, ADVERT_VERSION, BootstrapError, NostrRendezvous, OverlayAdvert,
    OverlayEndpointAdvert, OverlayTransportKind,
};

/// Snapshot of a single operational transport's advertisable endpoint
/// inputs, captured on `Node` at advert-build time so the driver can
/// assemble the overlay advert without borrowing the transport table.
/// Only transports whose type matched a configured listener are included;
/// the `advertise` gate is carried verbatim so the driver reproduces the
/// original per-transport branch logic exactly.
pub enum AdvertTransportSnapshot {
    Udp {
        advertise: bool,
        is_public: bool,
        external_addr: Option<SocketAddr>,
        local_addr: Option<SocketAddr>,
        transport_key: u32,
    },
    Tcp {
        advertise: bool,
        external_addr: Option<SocketAddr>,
        local_addr: Option<SocketAddr>,
    },
    Tor {
        advertise: bool,
        onion_addr: Option<String>,
        advertised_port: u16,
    },
}

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

    /// Take the engine handle for shutdown, clearing it.
    pub fn take_engine(&mut self) -> Option<Arc<NostrRendezvous>> {
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
        if !nostr_cfg.enabled
            || !peer_config.via_nostr
            || nostr_cfg.policy == NostrRendezvousPolicy::Disabled
        {
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

    /// Publish (or withdraw) the local overlay advert built from `snapshot`.
    /// `bootstrap` is passed explicitly because the startup path refreshes the
    /// advert before the engine handle is installed on the driver.
    pub async fn refresh_overlay_advert(
        &self,
        bootstrap: &Arc<NostrRendezvous>,
        snapshot: Vec<AdvertTransportSnapshot>,
        nostr_cfg: &NostrRendezvousConfig,
    ) -> Result<(), BootstrapError> {
        let advert = self
            .build_overlay_advert(bootstrap, snapshot, nostr_cfg)
            .await;
        bootstrap.update_local_advert(advert).await
    }

    /// Assemble the local `OverlayAdvert` from the per-transport `snapshot`.
    /// The STUN `learn_public_udp_addr` await for wildcard-bound public UDP
    /// sockets is reached through the `bootstrap` handle.
    async fn build_overlay_advert(
        &self,
        bootstrap: &Arc<NostrRendezvous>,
        snapshot: Vec<AdvertTransportSnapshot>,
        nostr_cfg: &NostrRendezvousConfig,
    ) -> Option<OverlayAdvert> {
        if !nostr_cfg.enabled {
            return None;
        }

        let mut endpoints = Vec::new();
        let mut has_udp_nat = false;

        for entry in snapshot {
            match entry {
                AdvertTransportSnapshot::Udp {
                    advertise,
                    is_public,
                    external_addr,
                    local_addr,
                    transport_key,
                } => {
                    if !advertise {
                        continue;
                    }
                    if is_public {
                        // Precedence:
                        // 1. operator-supplied `external_addr` (skips STUN)
                        // 2. non-wildcard `local_addr` (operator bound to
                        //    a specific public IP directly)
                        // 3. STUN auto-discovery against ephemeral socket
                        // 4. loud warn + omit endpoint
                        if let Some(explicit) = external_addr {
                            endpoints.push(OverlayEndpointAdvert {
                                transport: OverlayTransportKind::Udp,
                                addr: explicit.to_string(),
                            });
                        } else {
                            match local_addr {
                                Some(addr) if !addr.ip().is_unspecified() => {
                                    endpoints.push(OverlayEndpointAdvert {
                                        transport: OverlayTransportKind::Udp,
                                        addr: addr.to_string(),
                                    });
                                }
                                Some(addr) => {
                                    let key = transport_key;
                                    let port = addr.port();
                                    if let Some(public) =
                                        bootstrap.learn_public_udp_addr(key, port).await
                                    {
                                        endpoints.push(OverlayEndpointAdvert {
                                            transport: OverlayTransportKind::Udp,
                                            addr: public.to_string(),
                                        });
                                    } else {
                                        warn!(
                                            transport_id = key,
                                            bind_addr = %addr,
                                            "advert: udp public=true bound to wildcard but \
                                            STUN observation failed; advertising no UDP \
                                            endpoint. Either set transports.udp.external_addr, \
                                            bind to a specific public IP, or ensure \
                                            node.rendezvous.nostr.stun_servers is reachable"
                                        );
                                    }
                                }
                                None => {}
                            }
                        }
                    } else {
                        endpoints.push(OverlayEndpointAdvert {
                            transport: OverlayTransportKind::Udp,
                            addr: "nat".to_string(),
                        });
                        has_udp_nat = true;
                    }
                }
                AdvertTransportSnapshot::Tcp {
                    advertise,
                    external_addr,
                    local_addr,
                } => {
                    if !advertise {
                        continue;
                    }
                    // Precedence:
                    // 1. operator-supplied `external_addr` (only path that
                    //    works on cloud-NAT setups where the public IP is
                    //    not on a host interface).
                    // 2. non-wildcard `local_addr` (operator bound to a
                    //    specific public IP directly).
                    // 3. loud warn + omit endpoint (no TCP STUN equivalent).
                    if let Some(explicit) = external_addr {
                        endpoints.push(OverlayEndpointAdvert {
                            transport: OverlayTransportKind::Tcp,
                            addr: explicit.to_string(),
                        });
                    } else {
                        match local_addr {
                            Some(addr) if !addr.ip().is_unspecified() => {
                                endpoints.push(OverlayEndpointAdvert {
                                    transport: OverlayTransportKind::Tcp,
                                    addr: addr.to_string(),
                                });
                            }
                            Some(addr) => {
                                warn!(
                                    bind_addr = %addr,
                                    "advert: tcp advertise_on_nostr=true bound to wildcard \
                                    and no transports.tcp.external_addr set; advertising no \
                                    TCP endpoint. Either set external_addr to the public \
                                    IP (recommended for cloud 1:1-NAT setups) or bind \
                                    explicitly to the public IP"
                                );
                            }
                            None => {}
                        }
                    }
                }
                AdvertTransportSnapshot::Tor {
                    advertise,
                    onion_addr,
                    advertised_port,
                } => {
                    if !advertise {
                        continue;
                    }
                    if let Some(addr) = onion_addr {
                        endpoints.push(OverlayEndpointAdvert {
                            transport: OverlayTransportKind::Tor,
                            addr: format!("{}:{}", addr, advertised_port),
                        });
                    }
                }
            }
        }

        if endpoints.is_empty() {
            return None;
        }

        Some(OverlayAdvert {
            identifier: ADVERT_IDENTIFIER.to_string(),
            version: ADVERT_VERSION,
            endpoints,
            signal_relays: has_udp_nat.then(|| nostr_cfg.dm_relays.clone()),
            stun_servers: has_udp_nat.then(|| nostr_cfg.stun_servers.clone()),
        })
    }
}
