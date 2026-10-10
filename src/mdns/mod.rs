//! LAN peer discovery via mDNS / DNS-SD (RFC 6762 / RFC 6763).
//!
//! Publishes a `_fips._udp.local.` service advert carrying our `npub` and
//! optional discovery scope on the local link, and concurrently browses for the
//! same service type to learn peers reachable on the same broadcast
//! domain. The result is sub-second peer pairing without any Nostr-relay
//! roundtrip, STUN observation, or NAT traversal — the observed
//! endpoint is by construction routable from the consumer's LAN.
//!
//! ## Trust model
//!
//! mDNS adverts are unauthenticated: anyone on the LAN can multicast a
//! TXT carrying `npub=...`. Identity is still proven end-to-end by the
//! Noise XX handshake the Node initiates against the observed endpoint
//! — a spoofed advert with another peer's npub fails the handshake and
//! is silently dropped. Treat the mDNS advert as a routing hint, not as
//! identity. LAN discovery is link-local mDNS only. It is not a Nostr advert
//! and does not leave the broadcast domain unless the operator's LAN bridges
//! mDNS.
//!
//! ## Scope filtering
//!
//! When a `discovery_scope` is configured, the advert carries it in a
//! `scope=<name>` TXT entry and the browser only surfaces peers with a
//! matching scope. Nodes on the same physical LAN but configured for
//! different mesh networks don't cross-feed each other.

use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Instant;

use mdns_sd::{ResolvedService, ScopedIp, ServiceDaemon, ServiceEvent, ServiceInfo};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::Identity;

/// DNS-SD service type for the FIPS LAN advert. RFC 6763 §4.1.2: must
/// end with `.local.`. The `_udp` is the IP transport, not the upper
/// protocol — both UDP and TCP FIPS endpoints announce under the same
/// service type because the link-layer punch/handshake travels over UDP
/// either way.
pub const SERVICE_TYPE: &str = "_fips._udp.local.";

/// TXT key carrying the bech32-encoded npub of the publishing node.
pub const TXT_KEY_NPUB: &str = "npub";

/// TXT key carrying the publishing node's `discovery_scope`, if any.
pub const TXT_KEY_SCOPE: &str = "scope";

/// TXT key carrying the FIPS protocol version (matches the Nostr advert
/// `PROTOCOL_VERSION`).
pub const TXT_KEY_VERSION: &str = "v";

/// FIPS protocol version advertised in the mDNS TXT `v` key. Kept in sync
/// with the Nostr rendezvous `PROTOCOL_VERSION` (same value, `"1"`).
const TXT_PROTOCOL_VERSION: &str = "1";

#[derive(Debug, Error)]
pub enum LanRendezvousError {
    #[error("mDNS daemon init failed: {0}")]
    Daemon(String),
    #[error("mDNS register failed: {0}")]
    Register(String),
    #[error("mDNS browse failed: {0}")]
    Browse(String),
    #[error("no advertised UDP port — start a UDP transport first")]
    NoAdvertisedPort,
    #[error("LAN discovery disabled in config")]
    Disabled,
}

/// A peer we learned about via mDNS. Identity is unverified at this
/// point; the Node initiates a Noise XX handshake against `addr` to
/// confirm `npub` actually controls the matching private key.
#[derive(Debug, Clone)]
pub struct LanDiscoveredPeer {
    pub npub: String,
    pub scope: Option<String>,
    pub addr: SocketAddr,
    /// OS indexes of the interfaces the address record arrived on; empty
    /// when mdns-sd recorded none.
    pub interfaces: Vec<u32>,
    pub observed_at: Instant,
}

/// Browser-side events surfaced by `LanRendezvous::drain_events`.
#[derive(Debug, Clone)]
pub enum LanEvent {
    Discovered(LanDiscoveredPeer),
}

/// Runtime configuration for the mDNS responder + browser.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LanRendezvousConfig {
    /// Master switch. Default: `false` — LAN discovery is opt-in. Operators
    /// who want sub-second same-LAN pairing enable it via
    /// `node.rendezvous.lan.enabled: true`. Default-off avoids reintroducing
    /// a per-LAN identity broadcast on nodes that have deliberately disabled
    /// other discovery channels, and avoids any multicast surprise on upgrade.
    #[serde(default = "LanRendezvousConfig::default_enabled")]
    pub enabled: bool,
    /// Overridable service type, primarily so integration tests can run
    /// multiple isolated services on the same loopback interface.
    #[serde(default = "LanRendezvousConfig::default_service_type")]
    pub service_type: String,
    /// Optional application/network scope carried in the LAN-only TXT
    /// record. Browsers that set a scope ignore adverts for other scopes.
    ///
    /// This is intentionally separate from Nostr discovery's public `app`
    /// tag so applications can keep relay-visible adverts generic while
    /// still isolating LAN discovery per private network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl Default for LanRendezvousConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            service_type: Self::default_service_type(),
            scope: None,
        }
    }
}

impl LanRendezvousConfig {
    fn default_enabled() -> bool {
        false
    }
    fn default_service_type() -> String {
        SERVICE_TYPE.to_string()
    }
}

/// Running mDNS responder + browser bound to the node's UDP advert port.
pub struct LanRendezvous {
    daemon: ServiceDaemon,
    own_npub: String,
    instance_fullname: String,
    events_rx: Mutex<tokio::sync::mpsc::UnboundedReceiver<LanEvent>>,
    event_pump: tokio::task::JoinHandle<()>,
}

impl LanRendezvous {
    /// Whether the mDNS event-pump task has exited (runtime liveness).
    pub fn is_finished(&self) -> bool {
        self.event_pump.is_finished()
    }

    /// Start the mDNS responder and browser.
    ///
    /// `advertised_port` is the UDP port the operational UDP transport
    /// is bound to — peers receiving our advert will initiate Noise XX
    /// against that port. `scope` mirrors the Nostr discovery scope and
    /// is used to filter the browser stream.
    pub async fn start(
        identity: &Identity,
        scope: Option<String>,
        advertised_port: u16,
        config: LanRendezvousConfig,
    ) -> Result<Arc<Self>, LanRendezvousError> {
        if !config.enabled {
            return Err(LanRendezvousError::Disabled);
        }
        if advertised_port == 0 {
            return Err(LanRendezvousError::NoAdvertisedPort);
        }

        let daemon = ServiceDaemon::new().map_err(|e| LanRendezvousError::Daemon(e.to_string()))?;

        let npub = identity.npub();
        let instance_name = advert_label(&npub);
        let host_name = format!("{instance_name}.local.");

        let mut props: HashMap<String, String> = HashMap::new();
        props.insert(TXT_KEY_NPUB.to_string(), npub.clone());
        if let Some(s) = scope.as_deref()
            && !s.is_empty()
        {
            props.insert(TXT_KEY_SCOPE.to_string(), s.to_string());
        }
        props.insert(
            TXT_KEY_VERSION.to_string(),
            TXT_PROTOCOL_VERSION.to_string(),
        );

        // host_ipv4 is set to "127.0.0.1" *and* enable_addr_auto() is
        // called: the loopback seed makes the advert resolve for
        // same-host peers (and same-host integration tests) while the
        // auto-flag still appends every non-loopback interface address
        // mdns-sd discovers. Belt-and-braces because addr_auto alone
        // skips loopback by default on some platforms.
        let service_info = ServiceInfo::new(
            &config.service_type,
            &instance_name,
            &host_name,
            "127.0.0.1",
            advertised_port,
            Some(props),
        )
        .map_err(|e| LanRendezvousError::Register(e.to_string()))?
        .enable_addr_auto();

        let instance_fullname = service_info.get_fullname().to_string();

        daemon
            .register(service_info)
            .map_err(|e| LanRendezvousError::Register(e.to_string()))?;

        let browse_rx = daemon
            .browse(&config.service_type)
            .map_err(|e| LanRendezvousError::Browse(e.to_string()))?;

        let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel();
        let own_npub = npub.clone();
        let scope_filter = scope.clone().filter(|s| !s.is_empty());
        let event_pump = tokio::spawn(async move {
            // mdns-sd browse returns a flume::Receiver; pump until the
            // daemon shuts down and the channel closes.
            loop {
                let event = match browse_rx.recv_async().await {
                    Ok(e) => e,
                    Err(_) => break,
                };
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        let advert = match check_advert(&info, &own_npub, scope_filter.as_deref()) {
                            Ok(advert) => advert,
                            Err(skip) => {
                                log_skipped_advert(&info, &skip, scope_filter.as_deref());
                                continue;
                            }
                        };
                        let AdvertFields {
                            npub: peer_npub,
                            scope: peer_scope,
                            port,
                        } = advert;
                        let observed_at = Instant::now();
                        // mdns-sd may report multiple interface IPs for
                        // a multi-homed responder. Surface all routable
                        // candidates — the Node side filters/dedups and
                        // only dials addresses compatible with an active
                        // UDP socket family. IPv6 link-local addresses
                        // require an interface scope; preserve it when
                        // mdns-sd provides one, and skip unusable
                        // scope-less link-local records.
                        for scoped in info.get_addresses() {
                            let Some(addr) = socket_addr_from_scoped_ip(scoped, port) else {
                                debug!(
                                    npub = %short(&peer_npub),
                                    addr = %scoped.to_ip_addr(),
                                    "lan: skip scope-less IPv6 link-local advert"
                                );
                                continue;
                            };
                            if events_tx
                                .send(LanEvent::Discovered(LanDiscoveredPeer {
                                    npub: peer_npub.clone(),
                                    scope: peer_scope.clone(),
                                    addr,
                                    interfaces: arrival_interfaces(scoped),
                                    observed_at,
                                }))
                                .is_err()
                            {
                                return;
                            }
                        }
                    }
                    ServiceEvent::ServiceRemoved(_, fullname) => {
                        debug!(fullname = %fullname, "lan: service removed");
                    }
                    other => {
                        debug!(?other, "lan: mDNS event");
                    }
                }
            }
        });

        info!(
            instance = %instance_fullname,
            port = advertised_port,
            scope = ?scope,
            "lan: mDNS discovery started"
        );
        Ok(Arc::new(Self {
            daemon,
            own_npub: npub,
            instance_fullname,
            events_rx: Mutex::new(events_rx),
            event_pump,
        }))
    }

    /// Bech32 npub published by this node.
    pub fn own_npub(&self) -> &str {
        &self.own_npub
    }

    /// Drain pending browser events. Called once per Node tick.
    pub async fn drain_events(&self) -> Vec<LanEvent> {
        let mut rx = self.events_rx.lock().await;
        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        events
    }

    /// Tear down the responder, browser, and event pump.
    pub async fn shutdown(self: &Arc<Self>) {
        if let Err(e) = self.daemon.unregister(&self.instance_fullname) {
            warn!(error = %e, "lan: unregister failed");
        }
        if let Err(e) = self.daemon.shutdown() {
            warn!(error = %e, "lan: daemon shutdown failed");
        }
        self.event_pump.abort();
    }
}

/// The instance and host label a FIPS responder registers for `npub`:
/// `fips-` and the npub's first 16 characters. mDNS DNS labels are capped
/// at 63 bytes; the 11 bech32 characters after `npub1` make collisions on
/// one LAN unlikely. `None` when `npub` has no 16-character ASCII prefix.
fn advert_label_of(npub: &str) -> Option<String> {
    let prefix = npub.get(..16)?;
    prefix.is_ascii().then(|| format!("fips-{prefix}"))
}

/// [`advert_label_of`] for this node's own npub, which is always ASCII.
fn advert_label(npub: &str) -> String {
    advert_label_of(npub).unwrap_or_else(|| format!("fips-{npub}"))
}

/// Whether `host`, the service host an advert's SRV record names, is the
/// host a FIPS responder for `npub` registers: [`advert_label_of`] under
/// `.local.`, or that label with the `-N` suffix an mDNS responder appends
/// to settle a name conflict. DNS names compare without regard to ASCII case.
///
/// mdns-sd resolves an advert's addresses by its host name on every
/// interface, and does not say which interface the SRV record arrived on.
/// Without this check, a sender on one link could name the host of a
/// machine on another of this node's links and so aim dials there.
fn host_is_advertisers(host: &str, npub: &str) -> bool {
    let Some(expected) = advert_label_of(npub) else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    let Some(label) = host
        .strip_suffix(".local.")
        .or_else(|| host.strip_suffix(".local"))
    else {
        return false;
    };
    match label.strip_prefix(&expected.to_ascii_lowercase()) {
        Some("") => true,
        Some(rest) => rest
            .strip_prefix('-')
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())),
        None => false,
    }
}

/// The FIPS fields of a resolved advert that passed [`check_advert`].
#[derive(Debug)]
struct AdvertFields {
    npub: String,
    scope: Option<String>,
    port: u16,
}

/// Why [`check_advert`] skips a resolved advert as a whole.
#[derive(Debug, PartialEq, Eq)]
enum AdvertSkip {
    /// No `npub` TXT entry.
    NoNpub,
    /// Our own advert, echoed back on a loopback or multi-homed interface.
    Own,
    /// A discovery scope other than ours.
    CrossScope { npub: String, scope: Option<String> },
    /// The service host is not the one the advertised npub registers.
    ForeignHost,
    /// No port to dial.
    ZeroPort,
}

/// The service-level checks on a resolved advert, before its addresses are
/// read: it must carry an npub other than ours, match our discovery scope
/// when we have one, name the advertised npub's own host, and give a port.
fn check_advert(
    info: &ResolvedService,
    own_npub: &str,
    scope_filter: Option<&str>,
) -> Result<AdvertFields, AdvertSkip> {
    let mut npub: Option<String> = None;
    let mut scope: Option<String> = None;
    for prop in info.get_properties().iter() {
        match prop.key() {
            TXT_KEY_NPUB => npub = Some(prop.val_str().to_string()),
            TXT_KEY_SCOPE => scope = Some(prop.val_str().to_string()),
            _ => {}
        }
    }
    let npub = npub.ok_or(AdvertSkip::NoNpub)?;
    if npub == own_npub {
        return Err(AdvertSkip::Own);
    }
    if scope_filter.is_some() && scope_filter != scope.as_deref() {
        return Err(AdvertSkip::CrossScope { npub, scope });
    }
    if !host_is_advertisers(info.get_hostname(), &npub) {
        return Err(AdvertSkip::ForeignHost);
    }
    let port = info.get_port();
    if port == 0 {
        return Err(AdvertSkip::ZeroPort);
    }
    Ok(AdvertFields { npub, scope, port })
}

/// Log why a resolved advert was skipped; an echo of our own advert and a
/// zero port are skipped silently, as before.
fn log_skipped_advert(info: &ResolvedService, skip: &AdvertSkip, scope_filter: Option<&str>) {
    match skip {
        AdvertSkip::NoNpub => debug!(
            instance = info.get_fullname(),
            "lan: skip advert without npub TXT"
        ),
        AdvertSkip::CrossScope { npub, scope } => debug!(
            npub = %short(npub),
            their_scope = ?scope,
            our_scope = ?scope_filter,
            "lan: skip cross-scope advert"
        ),
        AdvertSkip::ForeignHost => debug!(
            instance = info.get_fullname(),
            host = info.get_hostname(),
            reason = "foreign-host",
            "lan: skip advert whose service host is not the advertised node's"
        ),
        AdvertSkip::Own | AdvertSkip::ZeroPort => {}
    }
}

/// The first 16 bytes of `npub` for a log line, cut back to a character
/// boundary: the text comes from a sender's TXT record and need not be ASCII.
fn short(npub: &str) -> &str {
    let end = (0..=16.min(npub.len()))
        .rev()
        .find(|&i| npub.is_char_boundary(i))
        .unwrap_or(0);
    &npub[..end]
}

fn socket_addr_from_scoped_ip(scoped: &ScopedIp, port: u16) -> Option<SocketAddr> {
    match scoped {
        ScopedIp::V4(v4) => Some(SocketAddr::V4(SocketAddrV4::new(*v4.addr(), port))),
        ScopedIp::V6(v6) => {
            let ip = *v6.addr();
            let scope_id = v6.scope_id().index;
            if ipv6_is_unicast_link_local(ip) && scope_id == 0 {
                return None;
            }
            Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope_id)))
        }
        _ => None,
    }
}

/// The OS indexes of the interfaces an address record arrived on, as
/// mdns-sd records them: every interface an IPv4 record was seen on, and the
/// scope of an IPv6 one. Index 0 means unknown and is left out.
fn arrival_interfaces(scoped: &ScopedIp) -> Vec<u32> {
    match scoped {
        ScopedIp::V4(v4) => v4
            .interface_ids()
            .iter()
            .map(|id| id.index)
            .filter(|index| *index != 0)
            .collect(),
        ScopedIp::V6(v6) => Some(v6.scope_id().index)
            .filter(|index| *index != 0)
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

fn ipv6_is_unicast_link_local(ip: std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests;
