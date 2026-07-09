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
    /// Originating peer npub (bech32) for each adopted bootstrap
    /// transport, captured at `adopt_established_traversal` time.
    /// Populated alongside `bootstrap_transports`; cleared in
    /// `cleanup_bootstrap_transport_if_unused`. Used by the rx loop to
    /// route fatal-protocol-mismatch observations back to the
    /// Nostr-discovery `failure_state` for long cooldown application.
    bootstrap_transport_npubs: HashMap<TransportId, String>,
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
        self.bootstrap_transport_npubs.get(transport_id)
    }

    /// Register an adopted bootstrap transport and its originating npub.
    pub fn insert_bootstrap_transport(&mut self, transport_id: TransportId, npub: String) {
        self.bootstrap_transports.insert(transport_id);
        self.bootstrap_transport_npubs.insert(transport_id, npub);
    }

    /// Drop an adopted bootstrap transport from both bookkeeping maps.
    pub fn remove_bootstrap_transport(&mut self, transport_id: &TransportId) {
        self.bootstrap_transports.remove(transport_id);
        self.bootstrap_transport_npubs.remove(transport_id);
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
