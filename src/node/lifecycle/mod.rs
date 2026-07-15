//! Node lifecycle management: start, stop, and peer connection initiation.

pub(crate) mod supervisor;

use super::{Node, NodeError, NodeState};
use supervisor::{Action, Child, Event, PeeringDesired, SupervisorFsm};

use super::peering::reconcile::{
    Budget, Candidate, DiscoveryPools, Gate, Observed, PeeringAction, Policy,
};
use super::peering::retry::MAX_RETRY_CONNECTIONS_PER_TICK;

use crate::config::{ConnectPolicy, PeerAddress, PeerConfig};
use crate::node::acl::PeerAclContext;
use crate::node::dataplane::PeerActionCtx;
use crate::nostr::{BootstrapEvent, NostrRendezvous};
use crate::nostr::{BootstrapHandoffResult, EstablishedTraversal};
use crate::peer::PeerConnection;
use crate::peer::machine::{PeerEvent, PeerMachine};
use crate::proto::fmp::wire::build_msg1;
use crate::proto::fmp::{Disconnect, DisconnectReason};
use crate::transport::{Link, LinkDirection, LinkId, TransportAddr, TransportId, packet_channel};
use crate::upper::tun::{TunDevice, TunState, run_tun_reader, shutdown_tun_interface};
use crate::{NodeAddr, PeerIdentity};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;
use tracing::{debug, info, warn};

const OPEN_DISCOVERY_RETRY_LIFETIME_MULTIPLIER: u64 = 2;
const MAX_PARALLEL_PATH_CANDIDATES_PER_PEER: usize = 4;
const MAX_DISCOVERY_CONNECTS_PER_TICK: usize = 16;

fn socket_addr_families_compatible(local: SocketAddr, remote: SocketAddr) -> bool {
    matches!(
        (local, remote),
        (SocketAddr::V4(_), SocketAddr::V4(_)) | (SocketAddr::V6(_), SocketAddr::V6(_))
    )
}

impl Node {
    /// Replace the runtime peer list.
    ///
    /// Newly added auto-connect peers are dialed immediately, removed peers
    /// are dropped from retry bookkeeping, and existing peers get fresh
    /// address hints without tearing down an active link. If an existing peer
    /// is already connected and a new concrete candidate appears, FIPS starts
    /// an alternate handshake in parallel; promotion switches only after that
    /// handshake authenticates.
    pub async fn update_peers(
        &mut self,
        new_peers: Vec<PeerConfig>,
    ) -> Result<crate::node::UpdatePeersOutcome, NodeError> {
        let mut new_by_addr: HashMap<NodeAddr, PeerConfig> =
            HashMap::with_capacity(new_peers.len());
        for peer in new_peers {
            let identity =
                PeerIdentity::from_npub(&peer.npub).map_err(|e| NodeError::InvalidPeerNpub {
                    npub: peer.npub.clone(),
                    reason: e.to_string(),
                })?;
            new_by_addr.insert(*identity.node_addr(), peer);
        }

        // Read the current peer set from the context *before* the swap below:
        // update_peers is the config-source mutation owner. It reads the current
        // (pre-update) peer set here, builds a fresh Config + context, then swaps
        // the whole Arc. Reading the live context Arc before the swap yields the
        // pre-update set the diff needs (the `update_peers_races_*` canary depends
        // on this ordering).
        let current_by_addr: HashMap<NodeAddr, PeerConfig> = self
            .context
            .config
            .peers()
            .iter()
            .filter_map(|peer| {
                PeerIdentity::from_npub(&peer.npub)
                    .ok()
                    .map(|identity| (*identity.node_addr(), peer.clone()))
            })
            .collect();

        let new_addrs: HashSet<_> = new_by_addr.keys().copied().collect();
        let current_addrs: HashSet<_> = current_by_addr.keys().copied().collect();

        let removed: Vec<_> = current_addrs.difference(&new_addrs).copied().collect();
        let added: Vec<_> = new_addrs.difference(&current_addrs).copied().collect();
        let kept: Vec<_> = new_addrs.intersection(&current_addrs).copied().collect();

        let mut outcome = crate::node::UpdatePeersOutcome::default();
        let mut refresh_configs = Vec::new();

        for node_addr in &removed {
            if self
                .peering
                .reconciler
                .retry_pending
                .remove(node_addr)
                .is_some()
            {
                debug!(
                    peer = %self.peer_display_name(node_addr),
                    "Dropping retry entry for peer removed from runtime peer list"
                );
            }
            self.peer_aliases.remove(node_addr);
            outcome.removed += 1;
        }

        for node_addr in &kept {
            let new_peer = &new_by_addr[node_addr];
            let current_peer = &current_by_addr[node_addr];
            let changed = new_peer.addresses != current_peer.addresses
                || new_peer.alias != current_peer.alias
                || new_peer.connect_policy != current_peer.connect_policy
                || new_peer.auto_reconnect != current_peer.auto_reconnect
                || new_peer.via_nostr != current_peer.via_nostr;

            if changed {
                outcome.updated += 1;
                if let Some(state) = self.peering.reconciler.retry_pending.get_mut(node_addr) {
                    state.peer_config = new_peer.clone();
                    state.retry_after_ms = Self::now_ms();
                }
                if let Some(alias) = new_peer.alias.clone() {
                    self.peer_aliases.insert(*node_addr, alias);
                }
            } else {
                outcome.unchanged += 1;
            }

            if new_peer.is_auto_connect() && (!new_peer.addresses.is_empty() || new_peer.via_nostr)
            {
                refresh_configs.push(new_peer.clone());
            }
        }

        let added_configs: Vec<_> = added
            .iter()
            .map(|node_addr| new_by_addr[node_addr].clone())
            .collect();

        let mut new_config = (*self.context.config).clone();
        new_config.peers = new_by_addr.into_values().collect();
        self.replace_context(|ctx| ctx.config = std::sync::Arc::new(new_config));

        for peer_config in added_configs {
            outcome.added += 1;
            let Ok(identity) = PeerIdentity::from_npub(&peer_config.npub) else {
                continue;
            };
            let name = peer_config
                .alias
                .clone()
                .unwrap_or_else(|| identity.short_npub());
            self.peer_aliases.insert(*identity.node_addr(), name);
            self.register_identity(*identity.node_addr(), identity.pubkey_full());

            if peer_config.is_auto_connect()
                && let Err(err) = self.initiate_peer_connection(&peer_config).await
            {
                debug!(
                    npub = %peer_config.npub,
                    error = %err,
                    "Failed to initiate connection for newly added runtime peer"
                );
                self.note_handshake_timeout(*identity.node_addr(), Self::now_ms());
            }
        }

        for peer_config in refresh_configs {
            let Ok(identity) = PeerIdentity::from_npub(&peer_config.npub) else {
                continue;
            };
            let node_addr = *identity.node_addr();

            if self.peers.contains_key(&node_addr) {
                match self
                    .try_active_peer_alternative_addresses(&peer_config, identity)
                    .await
                {
                    Ok(true) => debug!(
                        peer = %self.peer_display_name(&node_addr),
                        "Started alternate-path handshake for active peer"
                    ),
                    Ok(false) => {}
                    Err(err) => debug!(
                        npub = %peer_config.npub,
                        error = %err,
                        "Active peer alternate-path refresh did not start"
                    ),
                }
            } else {
                match self.initiate_peer_connection(&peer_config).await {
                    Ok(()) => {
                        let handshake_timeout_secs =
                            self.config().node.rate_limit.handshake_timeout_secs;
                        if let Some(state) =
                            self.peering.reconciler.retry_pending.get_mut(&node_addr)
                        {
                            state.peer_config = peer_config;
                            state.retry_after_ms =
                                Self::now_ms().saturating_add(handshake_timeout_secs * 1000);
                        }
                    }
                    Err(err) => {
                        debug!(
                            npub = %peer_config.npub,
                            error = %err,
                            "Refreshed peer addresses did not initiate a direct connection"
                        );
                        self.note_handshake_timeout(node_addr, Self::now_ms());
                    }
                }
            }
        }

        Ok(outcome)
    }

    /// Initiate connections to configured static peers.
    ///
    /// For each peer configured with AutoConnect policy, creates a link and
    /// peer entry, then starts the Noise handshake by sending the first message.
    pub(super) async fn initiate_peer_connections(&mut self) {
        // Build display name map from all configured peers (alias or short npub),
        // and pre-seed the identity cache from each peer's npub so that TUN packets
        // addressed to a configured peer can be dispatched (and trigger session
        // initiation) immediately on startup — without waiting for the link-layer
        // handshake to complete first.
        let peer_identities: Vec<(PeerIdentity, Option<String>)> = self
            .config()
            .peers()
            .iter()
            .filter_map(|pc| {
                PeerIdentity::from_npub(&pc.npub)
                    .ok()
                    .map(|id| (id, pc.alias.clone()))
            })
            .collect();

        for (identity, alias) in peer_identities {
            let name = alias.unwrap_or_else(|| identity.short_npub());
            self.peer_aliases.insert(*identity.node_addr(), name);
            // Pre-seed identity cache. The parity may be wrong (npub is x-only)
            // but will be corrected to the real value when the peer is promoted
            // after a successful Noise handshake.
            self.register_identity(*identity.node_addr(), identity.pubkey_full());
        }

        // Collect the auto-connect peer configs and build the mandatory-floor
        // reconcile inputs. This is the startup-gate seam: the
        // substrate is up (transports created, before TUN) but the published
        // NodeState is still `Starting`, so pass `Gate::Reconciling` EXPLICITLY
        // rather than deriving it from the published state (which would map to
        // `NotRunning` and dial nothing). This preserves today's startup dial
        // position exactly.
        let auto_connect_peers: Vec<PeerConfig> =
            self.config().auto_connect_peers().cloned().collect();

        if auto_connect_peers.is_empty() {
            debug!("No static peers configured");
            return;
        }

        // Recover the full `PeerConfig` for each emitted floor `Connect` from its
        // candidate identity (the core carries identity + a placeholder address;
        // the driver dial needs the config to expand addresses).
        let configs_by_addr: HashMap<NodeAddr, PeerConfig> = auto_connect_peers
            .iter()
            .filter_map(|pc| {
                PeerIdentity::from_npub(&pc.npub)
                    .ok()
                    .map(|id| (*id.node_addr(), pc.clone()))
            })
            .collect();

        debug!(
            count = configs_by_addr.len(),
            "Initiating static peer connections"
        );

        let policy = self.build_peering_policy(auto_connect_peers);
        let observed = self.observe_peering();
        let budget = self.build_peering_budget();
        let now_ms = Self::now_ms();
        let actions = self.peering.reconciler.reconcile(
            &policy,
            &observed,
            &budget,
            &DiscoveryPools::default(),
            now_ms,
            Gate::Reconciling,
        );

        for action in actions {
            let PeeringAction::Connect(candidate) = action else {
                continue;
            };
            let Some(identity) = candidate.identity else {
                continue;
            };
            let node_addr = *identity.node_addr();
            let Some(peer_config) = configs_by_addr.get(&node_addr).cloned() else {
                continue;
            };
            if let Err(e) = self.initiate_peer_connection(&peer_config).await {
                warn!(
                    npub = %peer_config.npub,
                    alias = ?peer_config.alias,
                    error = %e,
                    "Failed to initiate peer connection"
                );
                // Schedule a retry so transient address-resolution failures
                // (e.g. cached endpoints stale, NAT rebinds, all addresses
                // currently unreachable) recover without a daemon restart.
                self.note_handshake_timeout(node_addr, now_ms);
                // No-transport failures most often mean the cached overlay
                // advert is pointing at a dead post-NAT-rebind address. The
                // advert cache is read-only inside fetch_advert, so retries
                // would loop on the same dead address until expiry. Force a
                // re-fetch so the next retry tick picks up fresh endpoints.
                if matches!(e, crate::node::NodeError::NoTransportForType(_))
                    && let Some(bootstrap) = self.supervisor.nostr_rendezvous.engine_arc()
                {
                    let npub = peer_config.npub.clone();
                    tokio::spawn(async move {
                        let _ = bootstrap.refetch_advert_for_stale_check(&npub).await;
                    });
                }
            }
        }
    }

    /// Initiate a connection to a single peer.
    ///
    /// Creates a link, starts the Noise handshake, and sends the first message.
    pub(super) async fn initiate_peer_connection(
        &mut self,
        peer_config: &crate::config::PeerConfig,
    ) -> Result<(), NodeError> {
        // Parse the peer's npub to get their identity
        let peer_identity =
            PeerIdentity::from_npub(&peer_config.npub).map_err(|e| NodeError::InvalidPeerNpub {
                npub: peer_config.npub.clone(),
                reason: e.to_string(),
            })?;

        let peer_node_addr = *peer_identity.node_addr();

        // Check if peer already exists (fully authenticated)
        if self.peers.contains_key(&peer_node_addr) {
            debug!(
                npub = %peer_config.npub,
                "Peer already exists, skipping"
            );
            return Ok(());
        }

        // Check if connection already in progress to this peer
        if self.is_connecting_to_peer(&peer_node_addr) {
            debug!(
                npub = %peer_config.npub,
                "Connection already in progress, skipping"
            );
            return Ok(());
        }

        self.try_peer_addresses(peer_config, peer_identity, true)
            .await
    }

    fn is_connecting_to_peer(&self, peer_node_addr: &NodeAddr) -> bool {
        self.connections.values().any(|conn| {
            conn.expected_identity()
                .map(|id| id.node_addr() == peer_node_addr)
                .unwrap_or(false)
        })
    }

    fn is_connecting_to_peer_on_path(
        &self,
        peer_node_addr: &NodeAddr,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
    ) -> bool {
        self.connections.values().any(|conn| {
            conn.expected_identity()
                .map(|id| id.node_addr() == peer_node_addr)
                .unwrap_or(false)
                && conn.transport_id() == Some(transport_id)
                && conn.source_addr() == Some(remote_addr)
        }) || self.peering.pending_connects.iter().any(|pending| {
            pending.peer_identity.node_addr() == peer_node_addr
                && pending.transport_id == transport_id
                && pending.remote_addr == *remote_addr
        })
    }

    /// Find a UDP transport whose bound socket can send to `remote_addr`.
    ///
    /// LAN discovery can surface both IPv4 and IPv6 addresses for the same
    /// service. A wildcard IPv4 socket cannot send to an IPv6 link-local
    /// target, and vice versa, so callers must choose by socket family rather
    /// than by transport type alone.
    fn find_udp_transport_for_remote_addr(
        &self,
        remote_addr: SocketAddr,
    ) -> Option<(TransportId, SocketAddr)> {
        self.transports
            .iter()
            .filter(|(id, handle)| {
                handle.transport_type().name == "udp"
                    && handle.is_operational()
                    && !self.supervisor.nostr_rendezvous.is_bootstrap_transport(id)
            })
            .filter_map(|(id, handle)| {
                let local_addr = handle.local_addr()?;
                socket_addr_families_compatible(local_addr, remote_addr)
                    .then_some((*id, local_addr))
            })
            .min_by_key(|(id, _)| id.as_u32())
    }

    /// Initiate a connection to a peer on a specific transport and address.
    ///
    /// For connectionless transports (UDP, Ethernet): allocates a link, starts
    /// the Noise IK handshake, sends msg1, and registers the connection for
    /// msg2 dispatch.
    ///
    /// For connection-oriented transports (TCP, Tor): allocates a link and
    /// starts a non-blocking transport connect. The handshake is deferred
    /// until the transport connection is established — the tick handler
    /// polls `connection_state()` and initiates the handshake when ready.
    pub(super) async fn initiate_connection(
        &mut self,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        peer_identity: PeerIdentity,
    ) -> Result<(), NodeError> {
        let peer_node_addr = *peer_identity.node_addr();

        self.authorize_peer(
            &peer_identity,
            PeerAclContext::OutboundConnect,
            transport_id,
            &remote_addr,
        )?;

        let is_connection_oriented = self
            .transports
            .get(&transport_id)
            .map(|t| t.transport_type().connection_oriented)
            .unwrap_or(false);

        // Allocate link ID and create link
        let link_id = self.allocate_link_id();

        let link = if is_connection_oriented {
            Link::new(
                link_id,
                transport_id,
                remote_addr.clone(),
                LinkDirection::Outbound,
                Duration::from_millis(self.config().node.base_rtt_ms),
            )
        } else {
            Link::connectionless(
                link_id,
                transport_id,
                remote_addr.clone(),
                LinkDirection::Outbound,
                Duration::from_millis(self.config().node.base_rtt_ms),
            )
        };

        self.links.insert(link_id, link);

        // Add reverse lookup for packet dispatch
        self.addr_to_link
            .insert((transport_id, remote_addr.clone()), link_id);

        // Persist the outbound control machine at dial, keyed by the same
        // `link_id` as the (soon-to-be-built) connection. It parks in
        // `Discovered` (inert to reap and rekey — absent from `peers`, never
        // established) until `handle_msg2` looks it up to drive the promote, or
        // a connectionless dial drives it to `Handshaking` to send. Its
        // `our_index` is deliberately left unset so a later inbound restart does
        // not emit a spurious `UnregisterDecryptSession`. It is removed on every
        // failure path in the dial window (below and in `prepare_outbound_msg1`
        // / `poll_pending_connects`), mirroring the connection's own lifetime.
        let machine = PeerMachine::new_outbound(link_id, peer_identity, Self::now_ms());
        self.peer_machines.insert(link_id, machine);

        if is_connection_oriented {
            // Connection-oriented: start non-blocking connect, defer handshake
            if let Some(transport) = self.transports.get(&transport_id) {
                match transport.connect(&remote_addr).await {
                    Ok(()) => {
                        debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            transport_id = %transport_id,
                            remote_addr = %remote_addr,
                            link_id = %link_id,
                            "Transport connect initiated (non-blocking)"
                        );
                        self.peering.pending_connects.push(super::PendingConnect {
                            link_id,
                            transport_id,
                            remote_addr,
                            peer_identity,
                        });
                    }
                    Err(e) => {
                        // Clean up link and the dial-time control machine
                        self.links.remove(&link_id);
                        self.addr_to_link.remove(&(transport_id, remote_addr));
                        self.peer_machines.remove(&link_id);
                        return Err(NodeError::TransportError(e.to_string()));
                    }
                }
            }
            Ok(())
        } else {
            // Connectionless: no connect step. Prepare msg1 in the shell — the
            // index alloc, Noise leaf, and framing can fail and the error must
            // propagate to the caller (matching the pre-cutover path) — then drive
            // the machine to send it. The machine goes straight to
            // `start_outbound_handshake`; the executor's `SendHandshake` msg1
            // branch sends the wire `prepare_outbound_msg1` armed on the
            // connection.
            self.prepare_outbound_msg1(link_id, transport_id, &remote_addr, peer_identity)?;
            let now = Self::now_ms();
            let ambient = PeerActionCtx {
                verified_identity: peer_identity,
                transport_id,
                remote_addr: remote_addr.clone(),
                our_index: None,
                their_index: None,
                now_ms: now,
                is_outbound: true,
            };
            self.advance_peer_machine(
                link_id,
                PeerEvent::Dial {
                    transport_id,
                    remote_addr,
                    peer_identity,
                    connection_oriented: false,
                },
                now,
                &ambient,
            )
            .await;
            Ok(())
        }
    }

    /// Start the Noise handshake on a link and send msg1.
    ///
    /// Called after a connection-oriented transport connects. (Connectionless
    /// dials `prepare_outbound_msg1` + drive the machine to send in
    /// `initiate_connection`.)
    pub(super) async fn start_handshake(
        &mut self,
        link_id: LinkId,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        peer_identity: PeerIdentity,
    ) -> Result<(), NodeError> {
        self.prepare_outbound_msg1(link_id, transport_id, &remote_addr, peer_identity)?;
        self.send_stored_msg1(link_id, transport_id, &remote_addr)
            .await;
        Ok(())
    }

    /// Prepare an outbound Noise msg1 at dial: allocate the session index, run
    /// the Noise leaf, frame the wire, arm the shell-side resend, track
    /// `pending_outbound`, and persist the connection. Returns `Err` on
    /// index-allocation or Noise failure (cleaning the partial leg, including
    /// the dial-time control machine), leaving the armed wire on the connection
    /// for `send_stored_msg1` to transmit. Does NOT send — so the fallible setup
    /// can propagate its error synchronously before any machine drive. The
    /// control machine itself is persisted at dial in `initiate_connection`;
    /// this function no longer touches `peer_machines` except to clean it up on
    /// the failure paths.
    pub(in crate::node) fn prepare_outbound_msg1(
        &mut self,
        link_id: LinkId,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
        peer_identity: PeerIdentity,
    ) -> Result<(), NodeError> {
        let peer_node_addr = *peer_identity.node_addr();

        // Create connection in handshake phase (outbound knows expected identity)
        let current_time_ms = Self::now_ms();
        let mut connection = PeerConnection::outbound(link_id, peer_identity, current_time_ms);

        // Allocate a session index for this handshake
        let our_index = match self.index_allocator.allocate() {
            Ok(idx) => idx,
            Err(e) => {
                // Clean up the link and dial-time machine we just created
                self.links.remove(&link_id);
                self.addr_to_link
                    .remove(&(transport_id, remote_addr.clone()));
                self.peer_machines.remove(&link_id);
                return Err(NodeError::IndexAllocationFailed(e.to_string()));
            }
        };

        // Start the Noise handshake and get message 1
        let our_keypair = self.identity().keypair();
        let noise_msg1 =
            match connection.start_handshake(our_keypair, self.startup_epoch(), current_time_ms) {
                Ok(msg) => msg,
                Err(e) => {
                    // Clean up the index, link, and dial-time machine
                    let _ = self.index_allocator.free(our_index);
                    self.links.remove(&link_id);
                    self.addr_to_link
                        .remove(&(transport_id, remote_addr.clone()));
                    self.peer_machines.remove(&link_id);
                    return Err(NodeError::HandshakeFailed(e.to_string()));
                }
            };

        // Set index and transport info on the connection
        connection.set_our_index(our_index);
        connection.set_transport_id(transport_id);
        connection.set_source_addr(remote_addr.clone());

        // Build wire format msg1: [0x01][sender_idx:4 LE][noise_msg1:82]
        let wire_msg1 = build_msg1(our_index, &noise_msg1);

        debug!(
            peer = %self.peer_display_name(&peer_node_addr),
            transport_id = %transport_id,
            remote_addr = %remote_addr,
            link_id = %link_id,
            our_index = %our_index,
            "Connection initiated"
        );

        // Store msg1 for resend and schedule first resend
        let resend_interval = self.config().node.rate_limit.handshake_resend_interval_ms;
        connection.set_handshake_msg1(wire_msg1, current_time_ms + resend_interval);

        // Track in pending_outbound for msg2 dispatch
        self.pending_outbound
            .insert((transport_id, our_index.as_u32()), link_id);
        self.connections.insert(link_id, connection);

        Ok(())
    }

    /// Send the msg1 wire that `prepare_outbound_msg1` armed on the connection.
    /// On send error, marks the connection failed and RETAINS it (the legacy
    /// resend tick retries); a missing wire or transport is a no-op. This is the
    /// body of the executor's `SendHandshake` msg1 action and the send tail of
    /// the connection-oriented `start_handshake`.
    pub(in crate::node) async fn send_stored_msg1(
        &mut self,
        link_id: LinkId,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
    ) {
        let wire_msg1 = match self
            .connections
            .get(&link_id)
            .and_then(|c| c.handshake_msg1())
        {
            Some(w) => w.to_vec(),
            None => return,
        };
        let our_index = self.connections.get(&link_id).and_then(|c| c.our_index());

        // Send the wire format handshake message
        if let Some(transport) = self.transports.get(&transport_id) {
            match transport.send(remote_addr, &wire_msg1).await {
                Ok(bytes) => {
                    if let Some(idx) = our_index {
                        debug!(
                            link_id = %link_id,
                            our_index = %idx,
                            bytes,
                            "Sent Noise handshake message 1 (wire format)"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        link_id = %link_id,
                        error = %e,
                        "Failed to send handshake message"
                    );
                    // Mark connection as failed but don't remove it yet
                    // The event loop can handle retry logic
                    if let Some(conn) = self.connections.get_mut(&link_id) {
                        conn.mark_failed();
                    }
                }
            }
        }
    }

    /// Poll all transports for discovered peers and auto-connect.
    ///
    /// Called from the tick handler. Iterates operational transports,
    /// drains their discovery buffers, and initiates connections to
    /// newly discovered peers (if auto_connect is enabled).
    pub(super) async fn poll_transport_discovery(&mut self) {
        let self_node_addr = *self.identity().node_addr();

        // Drain each auto-connect transport's discovery buffer (the I/O) and
        // apply the driver-only prefilters that read live path-granular state the
        // sans-IO core cannot observe: self-skip, the active-peer
        // "fresh enough to skip" check, and the "already connecting on this exact
        // path" check. The surviving beacons become the opportunistic pool, in
        // transport-then-beacon iteration order; the core owns the connected /
        // discovery-connect-budget / per-peer-cap decisions over them.
        //
        // Collect-then-dial (as before): the pool snapshot is frozen while the
        // dataplane maps are unmutated, so the core's per-peer cap sees a stable
        // in-flight count — the same guarantee the old collect-then-dial had.
        let mut transport_neighbors: Vec<Candidate> = Vec::new();
        for (transport_id, transport) in &self.transports {
            if !transport.is_operational() {
                continue;
            }
            if !transport.auto_connect() {
                // Still drain the buffer so it doesn't grow unbounded.
                let _ = transport.discover();
                continue;
            }
            let discovered = match transport.discover() {
                Ok(peers) => peers,
                Err(_) => continue,
            };
            for peer in discovered {
                let Some(pubkey) = peer.pubkey_hint else {
                    continue;
                };
                let identity = PeerIdentity::from_pubkey(pubkey);
                let node_addr = *identity.node_addr();

                // Skip self.
                if node_addr == self_node_addr {
                    continue;
                }

                let candidate_transport_id = *transport_id;
                let remote_addr = peer.addr;
                let connected = self.peers.contains_key(&node_addr);

                if connected {
                    // Active peer: skip a candidate whose path is already the
                    // current, still-fresh one (avoid churning a healthy link).
                    let transport_name = transport.transport_type().name;
                    let peer_addr_candidate =
                        PeerAddress::new(transport_name, remote_addr.to_string());
                    if self.active_peer_candidate_is_fresh_enough_to_skip(
                        &node_addr,
                        std::slice::from_ref(&peer_addr_candidate),
                    ) {
                        continue;
                    }
                    if self.is_connecting_to_peer_on_path(
                        &node_addr,
                        candidate_transport_id,
                        &remote_addr,
                    ) {
                        continue;
                    }
                } else if self.is_connecting_to_peer_on_path(
                    &node_addr,
                    candidate_transport_id,
                    &remote_addr,
                ) {
                    continue;
                }

                transport_neighbors.push(Candidate {
                    transport_id: candidate_transport_id,
                    remote_addr,
                    identity: Some(identity),
                    // Log-only flag; the core recomputes it from `connected`.
                    active_refresh: connected,
                });
            }
        }

        if transport_neighbors.is_empty() {
            return;
        }

        let pools = DiscoveryPools {
            transport_neighbors,
            ..DiscoveryPools::default()
        };
        let policy = self.build_peering_policy(Vec::new());
        let observed = self.observe_peering();
        let budget = self.build_peering_budget();
        let now_ms = Self::now_ms();
        let gate = Gate::from_state(self.supervisor.state);
        let actions = self
            .peering
            .reconciler
            .reconcile_opportunistic(&policy, &observed, &budget, &pools, now_ms, gate);

        for action in actions {
            let PeeringAction::Connect(candidate) = action else {
                continue;
            };
            let Some(identity) = candidate.identity else {
                continue;
            };
            info!(
                peer = %self.peer_display_name(identity.node_addr()),
                transport_id = %candidate.transport_id,
                remote_addr = %candidate.remote_addr,
                active_refresh = candidate.active_refresh,
                "Auto-connecting to discovered peer"
            );
            if let Err(e) = self
                .initiate_connection(candidate.transport_id, candidate.remote_addr, identity)
                .await
            {
                warn!(error = %e, "Failed to auto-connect to discovered peer");
            }
        }
    }

    pub(super) async fn poll_nostr_rendezvous(&mut self) {
        let Some(bootstrap) = self.supervisor.nostr_rendezvous.engine_arc() else {
            return;
        };

        // Refresh the runtime's outbound-admission view once per tick.
        // The runtime task lives in a separate tokio context with no Node
        // reference, so we publish current capacity state through a
        // cheap atomic store. One-tick lag is acceptable: the inbound
        // msg1 gate in handshake.rs remains the authoritative cap.
        bootstrap.set_outbound_admission(self.outbound_admission_check());

        if let Err(err) = self.refresh_overlay_advert(&bootstrap).await {
            debug!(error = %err, "Failed to refresh local Nostr overlay advert");
        }

        for event in bootstrap.drain_events().await {
            match event {
                BootstrapEvent::Established { traversal } => {
                    if !self.outbound_admission_check() {
                        debug!(
                            peer_npub = %traversal.peer_npub,
                            peers = self.peers.len(),
                            max_peers = self.max_peers(),
                            "Dropping established NAT traversal: at capacity"
                        );
                        continue;
                    }
                    let peer_npub = traversal.peer_npub.clone();
                    if let Ok(peer_identity) = PeerIdentity::from_npub(&peer_npub) {
                        let peer_addr = *peer_identity.node_addr();
                        if self.peers.contains_key(&peer_addr) {
                            debug!(
                                peer_npub = %peer_npub,
                                "Ignoring established NAT traversal for already-connected peer"
                            );
                            continue;
                        }
                        if self.is_connecting_to_peer(&peer_addr) {
                            // Dual cross-init: both nodes' Nostr-mediated punches
                            // completed simultaneously, and each side already
                            // holds in-flight handshake state for the other.
                            // Apply the deterministic NodeAddr tie-breaker —
                            // smaller NodeAddr wins as adopter (same convention
                            // as cross_connection_winner and the rekey dual-
                            // init resolution at handshake.rs:269). The winner
                            // tears down its in-flight state and adopts the
                            // fresh traversal socket; the loser keeps continue
                            // semantics, and its existing cross-connection
                            // logic in handle_msg1 reconciles when the winner's
                            // fresh msg1 arrives over the adopted socket.
                            let our_addr = self.identity().node_addr();
                            if our_addr >= &peer_addr {
                                debug!(
                                    peer_npub = %peer_npub,
                                    "Dual cross-init NAT traversal: we lose (larger addr), keeping in-flight handshake"
                                );
                                continue;
                            }
                            debug!(
                                peer_npub = %peer_npub,
                                "Dual cross-init NAT traversal: we win (smaller addr), tearing down in-flight handshake to adopt fresh socket"
                            );
                            let now_ms = Self::now_ms();
                            let stale: Vec<LinkId> = self
                                .connections
                                .iter()
                                .filter(|(_, conn)| {
                                    conn.expected_identity()
                                        .map(|id| id.node_addr() == &peer_addr)
                                        .unwrap_or(false)
                                })
                                .map(|(link_id, _)| *link_id)
                                .collect();
                            for link_id in stale {
                                self.cleanup_stale_connection(link_id, now_ms);
                            }
                        }
                    }
                    match self.adopt_established_traversal(traversal).await {
                        Ok(_) => {
                            info!(peer_npub = %peer_npub, "Adopted NAT traversal socket");
                        }
                        Err(err) => {
                            warn!(peer_npub = %peer_npub, error = %err, "Failed to adopt NAT traversal");
                            if let Ok(peer_identity) = PeerIdentity::from_npub(&peer_npub) {
                                self.note_handshake_timeout(
                                    *peer_identity.node_addr(),
                                    Self::now_ms(),
                                );
                            }
                        }
                    }
                }
                BootstrapEvent::Failed {
                    peer_config,
                    reason,
                } => {
                    let peer_identity = match PeerIdentity::from_npub(&peer_config.npub) {
                        Ok(identity) => identity,
                        Err(_) => continue,
                    };
                    let node_addr = *peer_identity.node_addr();
                    if self.peers.contains_key(&node_addr) {
                        debug!(
                            npub = %peer_config.npub,
                            error = %reason,
                            "Ignoring failed NAT traversal for already-connected peer"
                        );
                        continue;
                    }
                    if self.is_connecting_to_peer(&node_addr) {
                        debug!(
                            npub = %peer_config.npub,
                            error = %reason,
                            "Ignoring failed NAT traversal while peer handshake is already in progress"
                        );
                        continue;
                    }

                    let now_ms = Self::now_ms();
                    let decision = bootstrap.record_traversal_failure(&peer_config.npub, now_ms);
                    if decision.should_warn {
                        warn!(
                            npub = %peer_config.npub,
                            error = %reason,
                            consecutive_failures = decision.consecutive_failures,
                            cooldown_secs = decision
                                .cooldown_until_ms
                                .map(|t| t.saturating_sub(now_ms) / 1000),
                            "NAT traversal failed"
                        );
                    } else {
                        debug!(
                            npub = %peer_config.npub,
                            error = %reason,
                            consecutive_failures = decision.consecutive_failures,
                            "NAT traversal failed (suppressed by warn-rate-limit)"
                        );
                    }

                    // B6: stale-advert eviction on the streak-threshold
                    // crossing. Fire-and-forget; the outcome is logged so
                    // operators can see when peers get cleaned up.
                    if decision.crossed_threshold {
                        let bootstrap = bootstrap.clone();
                        let npub = peer_config.npub.clone();
                        tokio::spawn(async move {
                            let outcome = bootstrap.refetch_advert_for_stale_check(&npub).await;
                            match outcome {
                                crate::nostr::NostrRefetchOutcome::Evicted => info!(
                                    npub = %npub,
                                    "stale-advert sweep: peer evicted from advert cache"
                                ),
                                crate::nostr::NostrRefetchOutcome::Refreshed => info!(
                                    npub = %npub,
                                    "stale-advert sweep: peer republished, cache refreshed and streak reset"
                                ),
                                crate::nostr::NostrRefetchOutcome::SameAdvert => debug!(
                                    npub = %npub,
                                    "stale-advert sweep: advert unchanged, cooldown stands"
                                ),
                                crate::nostr::NostrRefetchOutcome::Skipped => debug!(
                                    npub = %npub,
                                    "stale-advert sweep: skipped (relay error or no advert_relays)"
                                ),
                            }
                        });
                    }

                    if self
                        .try_peer_addresses(&peer_config, peer_identity, false)
                        .await
                        .is_ok()
                    {
                        continue;
                    }

                    self.note_handshake_timeout(node_addr, now_ms);
                    if let Some(cooldown_until_ms) = decision.cooldown_until_ms
                        && let Some(state) =
                            self.peering.reconciler.retry_pending.get_mut(&node_addr)
                    {
                        // Push the next retry past the cooldown so the
                        // open-discovery sweep doesn't re-enqueue and the
                        // per-attempt backoff doesn't fire sooner.
                        state.retry_after_ms = state.retry_after_ms.max(cooldown_until_ms);
                    }
                }
            }
        }

        self.maybe_run_startup_open_discovery_sweep(&bootstrap)
            .await;
        self.queue_open_discovery_retries(&bootstrap).await;
    }

    /// Resolve the LAN-only discovery scope. Applications with explicit
    /// connectivity config can set `node.rendezvous.lan.scope` without
    /// changing the public Nostr discovery `app` tag. The older fallback
    /// extracts a scope from the Nostr app tag used by default scoped
    /// discovery.
    pub(super) fn lan_rendezvous_scope(&self) -> Option<String> {
        if let Some(scope) = self.config().node.rendezvous.lan.scope.as_deref() {
            let scope = scope.trim();
            if !scope.is_empty() {
                return Some(scope.to_string());
            }
        }

        let app = self.config().node.rendezvous.nostr.app.trim();
        if app.is_empty() {
            return None;
        }
        if let Some(rest) = app.strip_prefix("fips-overlay-v1:") {
            let scope = rest.trim();
            if scope.is_empty() {
                None
            } else {
                Some(scope.to_string())
            }
        } else {
            Some(app.to_string())
        }
    }

    /// Drain mDNS-discovered peers and initiate Noise IK handshakes.
    /// The handshake itself is the authentication — a spoofed mDNS advert
    /// with someone else's npub fails the IK exchange and is dropped.
    pub(super) async fn poll_lan_rendezvous(&mut self) {
        let Some(runtime) = self.supervisor.lan_rendezvous.clone() else {
            return;
        };
        let events = runtime.drain_events().await;
        if events.is_empty() {
            return;
        }

        // Resolve each mDNS beacon to a dialable candidate (the driver I/O: pick a
        // socket-family-compatible UDP transport, parse the npub). The
        // connected / connecting skip is the core's decision — LAN growth has no
        // discovery budget or per-peer cap, only the connected/connecting guard,
        // applied in event order.
        //
        // First-wins per-peer dedup: mdns-sd emits one
        // `Discovered` event per interface IP of a multi-homed responder, and the
        // old inline-dial loop dialed the first compatible address then skipped
        // the rest via `is_connecting_to_peer` (which turned true after that
        // dial). The frozen-snapshot core cannot see that intra-tick feedback, so
        // the driver reproduces it here: keep only the first surviving candidate
        // per peer this tick. (In the ACL-reject case the old loop retried every
        // address, but each attempt failed `authorize_peer` before touching any
        // state, so no connection resulted either way — the dedup is neutral on
        // the dataplane.)
        let mut lan: Vec<Candidate> = Vec::new();
        let mut seen: HashSet<NodeAddr> = HashSet::new();
        for event in events {
            let crate::mdns::LanEvent::Discovered(peer) = event;
            let Some((transport_id, _local_addr)) =
                self.find_udp_transport_for_remote_addr(peer.addr)
            else {
                debug!(
                    addr = %peer.addr,
                    "lan: skip discovered peer with no compatible UDP transport"
                );
                continue;
            };
            let identity = match crate::PeerIdentity::from_npub(&peer.npub) {
                Ok(id) => id,
                Err(err) => {
                    debug!(npub = %peer.npub, error = %err, "lan: skip bad npub");
                    continue;
                }
            };
            let peer_node_addr = *identity.node_addr();
            if !seen.insert(peer_node_addr) {
                continue;
            }
            let remote_addr = crate::transport::TransportAddr::from_string(&peer.addr.to_string());
            lan.push(Candidate {
                transport_id,
                remote_addr,
                identity: Some(identity),
                active_refresh: false,
            });
        }

        if lan.is_empty() {
            return;
        }

        let pools = DiscoveryPools {
            lan,
            ..DiscoveryPools::default()
        };
        let policy = self.build_peering_policy(Vec::new());
        let observed = self.observe_peering();
        let budget = self.build_peering_budget();
        let now_ms = Self::now_ms();
        let gate = Gate::from_state(self.supervisor.state);
        let actions = self
            .peering
            .reconciler
            .reconcile_opportunistic(&policy, &observed, &budget, &pools, now_ms, gate);

        for action in actions {
            let PeeringAction::Connect(candidate) = action else {
                continue;
            };
            let Some(identity) = candidate.identity else {
                continue;
            };
            let local_addr = self
                .transports
                .get(&candidate.transport_id)
                .and_then(|transport| transport.local_addr());
            info!(
                npub = %identity.short_npub(),
                addr = %candidate.remote_addr,
                local_addr = ?local_addr,
                "lan: initiating handshake to discovered peer"
            );
            if let Err(err) = self
                .initiate_connection(candidate.transport_id, candidate.remote_addr, identity)
                .await
            {
                debug!(
                    npub = %identity.short_npub(),
                    error = %err,
                    "lan: failed to initiate connection to discovered peer"
                );
            }
        }
    }

    /// Poll pending transport connects and initiate handshakes for ready ones.
    ///
    /// Called from the tick handler. For each pending connect, queries the
    /// transport's connection state. When a connection is established,
    /// marks the link as Connected and starts the Noise handshake.
    /// Failed connections are cleaned up and scheduled for retry.
    pub(super) async fn poll_pending_connects(&mut self) {
        if self.peering.pending_connects.is_empty() {
            return;
        }

        let mut completed = Vec::new();

        for (i, pending) in self.peering.pending_connects.iter().enumerate() {
            let state = if let Some(transport) = self.transports.get(&pending.transport_id) {
                transport.connection_state(&pending.remote_addr)
            } else {
                crate::transport::ConnectionState::Failed("transport removed".into())
            };

            match state {
                crate::transport::ConnectionState::Connected => {
                    completed.push((i, true, None));
                }
                crate::transport::ConnectionState::Failed(reason) => {
                    completed.push((i, false, Some(reason)));
                }
                crate::transport::ConnectionState::Connecting => {
                    // Still in progress, check on next tick
                }
                crate::transport::ConnectionState::None => {
                    // Shouldn't happen — treat as failure
                    completed.push((i, false, Some("no connection attempt found".into())));
                }
            }
        }

        // Process completions in reverse order to preserve indices
        for (i, success, reason) in completed.into_iter().rev() {
            let pending = self.peering.pending_connects.remove(i);

            if success {
                // Mark link as Connected
                if let Some(link) = self.links.get_mut(&pending.link_id) {
                    link.set_connected();
                }

                debug!(
                    peer = %self.peer_display_name(pending.peer_identity.node_addr()),
                    transport_id = %pending.transport_id,
                    remote_addr = %pending.remote_addr,
                    link_id = %pending.link_id,
                    "Transport connected, starting handshake"
                );

                // Start the handshake now that the transport is connected
                if let Err(e) = self
                    .start_handshake(
                        pending.link_id,
                        pending.transport_id,
                        pending.remote_addr.clone(),
                        pending.peer_identity,
                    )
                    .await
                {
                    warn!(
                        link_id = %pending.link_id,
                        error = %e,
                        "Failed to start handshake after transport connect"
                    );
                    // Clean up link and dial-time machine on handshake failure
                    self.remove_link(&pending.link_id);
                    self.peer_machines.remove(&pending.link_id);
                }
            } else {
                let reason = reason.unwrap_or_default();
                warn!(
                    peer = %self.peer_display_name(pending.peer_identity.node_addr()),
                    transport_id = %pending.transport_id,
                    remote_addr = %pending.remote_addr,
                    link_id = %pending.link_id,
                    reason = %reason,
                    "Transport connect failed"
                );

                // Clean up link and dial-time machine, then schedule retry
                self.remove_link(&pending.link_id);
                self.links.remove(&pending.link_id);
                self.peer_machines.remove(&pending.link_id);
                self.note_handshake_timeout(*pending.peer_identity.node_addr(), Self::now_ms());
            }
        }
    }

    // === State Transitions ===

    /// Start the node.
    ///
    /// Initializes the TUN interface (if configured), spawns I/O threads,
    /// and transitions to the Running state.
    pub async fn start(&mut self) -> Result<(), NodeError> {
        if !self.supervisor.state.can_start() {
            return Err(NodeError::AlreadyStarted);
        }
        self.supervisor.state = NodeState::Starting;

        // Create packet channel for transport -> Node communication
        let packet_buffer_size = self.config().node.buffers.packet_channel;
        let (packet_tx, packet_rx) = packet_channel(packet_buffer_size);
        self.supervisor.packet_tx = Some(packet_tx.clone());
        self.packet_rx = Some(packet_rx);

        // Runtime child-liveness channel. Created before any
        // child is spawned so each directly-observable child (TUN threads, the
        // DNS task, and the mDNS/Nostr liveness monitor) can clone the sender
        // and self-report its `Child` on exit. The sender stored on `self` is
        // the keep-alive; the rx_loop takes only the receiver, so the channel
        // never closes spuriously while the node runs.
        let (child_exit_tx, child_exit_rx) = tokio::sync::mpsc::channel(16);
        self.child_exit_tx = Some(child_exit_tx);
        self.child_exit_rx = Some(child_exit_rx);

        // Initialize transports first (before TUN, before Nostr discovery).
        // Creation allocates each transport's id; the supervisor FSM authors
        // the start order over those ids.
        let transport_handles = self.create_transports(&packet_tx).await;
        let transport_ids: Vec<TransportId> =
            transport_handles.iter().map(|h| h.transport_id()).collect();
        let mut pending_handles: HashMap<_, _> = transport_handles
            .into_iter()
            .map(|h| (h.transport_id(), h))
            .collect();

        // Singleton child booleans, with today's exact enable conditions.
        let nostr = self.config().node.rendezvous.nostr.enabled;
        let mdns = self.config().node.rendezvous.lan.enabled;
        let tun = self.config().tun.enabled;
        let dns = self.config().dns.enabled;

        // Worker-pool booleans + counts. Unix only — the workers issue
        // sendmmsg(2) / sendmsg+UDP_GSO on raw fds via `AsRawFd`. Encrypt
        // always spawns on unix; decrypt spawns iff FIPS_DECRYPT_WORKERS != 0.
        // Counts are parsed up-front so the FSM can decide whether the decrypt
        // child exists; the actual spawns run when the SpawnChild actions do.
        #[cfg(unix)]
        let (encrypt_workers, decrypt_workers, encrypt_worker_count, decrypt_worker_count) = {
            let cpu_default = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
                .max(1);
            let encrypt_worker_count: usize = std::env::var("FIPS_ENCRYPT_WORKERS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(cpu_default)
                .max(1);
            let decrypt_worker_count: usize = std::env::var("FIPS_DECRYPT_WORKERS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(cpu_default);
            (
                true,
                decrypt_worker_count != 0,
                encrypt_worker_count,
                decrypt_worker_count,
            )
        };
        #[cfg(not(unix))]
        let (encrypt_workers, decrypt_workers) = (false, false);

        // Ask the supervisor FSM for the canonical spawn order.
        let actions = self.supervisor.fsm.step(Event::Start {
            transports: transport_ids,
            encrypt_workers,
            decrypt_workers,
            nostr,
            mdns,
            tun,
            dns,
        });

        // The FSM resolves start-completion health (Full/Degraded/Failed) when
        // `Starting.pending` empties and emits it as a `PublishState`
        // action. Capture that outcome — from the degenerate
        // no-children path (published on the `Event::Start` step itself) or from
        // the final `SubstrateUp`/`SubstrateFailed` below — to drive the
        // start-completion behavior after the spawn loop.
        let mut start_outcome: Option<NodeState> = None;
        for action in &actions {
            if let Action::PublishState(ns) = action {
                start_outcome = Some(*ns);
            }
        }

        // Execute each SpawnChild in order, reporting the outcome back so the
        // FSM's up-set tracks what actually came up. Optional failures are
        // warn/debug-and-continue (today's behavior); start still reaches
        // Running. Two driver seams are woven in at their current positions:
        // the post-transport-loop "Transports initialized" info!, and the
        // peer-connect that today sits after mDNS and before TUN.
        let mut transports_info_emitted = false;
        let mut peer_connect_done = false;
        for action in actions {
            let Action::SpawnChild(child) = action else {
                continue;
            };

            // Post-transport-loop seam: once, after all transport spawns and
            // before the first non-transport child.
            if !transports_info_emitted && !matches!(child, Child::Transport(_)) {
                if !self.transports.is_empty() {
                    info!(count = self.transports.len(), "Transports initialized");
                }
                transports_info_emitted = true;
            }

            // Peer-connect seam: once, immediately before the first Tun-or-Dns
            // child. Connect to static peers before TUN is active so handshake
            // messages can be sent before we start accepting packets.
            if !peer_connect_done && matches!(child, Child::Tun | Child::Dns) {
                self.initiate_peer_connections().await;
                peer_connect_done = true;
            }

            let feedback = match child {
                Child::Transport(id) => {
                    let mut handle = pending_handles
                        .remove(&id)
                        .expect("supervisor emitted SpawnChild for a created transport");
                    let transport_type = handle.transport_type().name;
                    let name = handle.name().map(|s| s.to_string());

                    match handle.start().await {
                        Ok(()) => {
                            self.transports.insert(id, handle);
                            Event::SubstrateUp { child }
                        }
                        Err(e) => {
                            if let Some(ref n) = name {
                                warn!(transport_type, name = %n, error = %e, "Transport failed to start");
                            } else {
                                warn!(transport_type, error = %e, "Transport failed to start");
                            }
                            Event::SubstrateFailed { child }
                        }
                    }
                }
                Child::EncryptWorkers => {
                    // Hash-by-destination pins a TCP flow to one worker
                    // (preserves wire ordering); additional workers light up
                    // under multi-flow load. Infallible → always up.
                    #[cfg(unix)]
                    {
                        self.supervisor.encrypt_workers = Some(
                            super::encrypt_worker::EncryptWorkerPool::spawn(encrypt_worker_count),
                        );
                        info!(
                            workers = encrypt_worker_count,
                            "Spawned FMP-encrypt worker pool"
                        );

                        // `FIPS_DECRYPT_WORKERS=0` disables the pool entirely
                        // and forces the in-line rx_loop decrypt path. When 0
                        // no DecryptWorkers child is emitted, so this info!
                        // sits here — exactly where the decrypt spawn would be
                        // in today's sequence (after the encrypt spawn+info,
                        // before nostr).
                        if decrypt_worker_count == 0 {
                            info!("FIPS_DECRYPT_WORKERS=0 → in-line decrypt in rx_loop");
                        }
                    }
                    Event::SubstrateUp { child }
                }
                Child::DecryptWorkers => {
                    // Shard-owned decrypt pool. Infallible → always up.
                    #[cfg(unix)]
                    {
                        self.supervisor.decrypt_workers = Some(
                            super::decrypt_worker::DecryptWorkerPool::spawn(decrypt_worker_count),
                        );
                        info!(
                            workers = decrypt_worker_count,
                            "Spawned FMP-decrypt worker pool"
                        );
                    }
                    Event::SubstrateUp { child }
                }
                Child::Nostr => {
                    match NostrRendezvous::start(
                        self.identity(),
                        self.config().node.rendezvous.nostr.clone(),
                    )
                    .await
                    {
                        Ok(runtime) => {
                            if let Err(err) = self.refresh_overlay_advert(&runtime).await {
                                warn!(error = %err, "Failed to publish initial Nostr overlay advert");
                            }
                            self.supervisor.nostr_rendezvous.set_engine(runtime);
                            self.supervisor
                                .nostr_rendezvous
                                .set_started_at_ms(Self::now_ms());
                            info!("Nostr overlay discovery enabled");
                            Event::SubstrateUp { child }
                        }
                        Err(err) => {
                            warn!(error = %err, "Failed to start Nostr overlay discovery");
                            Event::SubstrateFailed { child }
                        }
                    }
                }
                Child::Mdns => {
                    // Advertise the port of a non-bootstrap operational UDP
                    // transport. Bootstrap transports must be excluded (they
                    // are not the node's listening data-plane socket), and a
                    // stable selector (lowest TransportId) is used so the
                    // advertised port is deterministic across restarts rather
                    // than dependent on HashMap iteration order. This mirrors
                    // find_udp_transport_for_remote_addr.
                    let advertised_udp_port = self
                        .transports
                        .iter()
                        .filter(|(id, h)| {
                            h.transport_type().name == "udp"
                                && h.is_operational()
                                && !self.supervisor.nostr_rendezvous.is_bootstrap_transport(id)
                        })
                        .filter_map(|(id, h)| h.local_addr().map(|addr| (*id, addr.port())))
                        .min_by_key(|(id, _)| id.as_u32())
                        .map(|(_, port)| port)
                        .unwrap_or(0);
                    let scope = self.lan_rendezvous_scope();
                    match crate::mdns::LanRendezvous::start(
                        self.identity(),
                        scope,
                        advertised_udp_port,
                        self.config().node.rendezvous.lan.clone(),
                    )
                    .await
                    {
                        Ok(runtime) => {
                            self.supervisor.lan_rendezvous = Some(runtime);
                            info!("LAN mDNS discovery enabled");
                            Event::SubstrateUp { child }
                        }
                        Err(err) => {
                            debug!(error = %err, "LAN mDNS discovery not started");
                            Event::SubstrateFailed { child }
                        }
                    }
                }
                Child::Tun => {
                    // Initialize TUN interface after transports and peers are
                    // ready.
                    let address = *self.identity().address();
                    match TunDevice::create(&self.config().tun, address).await {
                        Ok(device) => {
                            let mtu = device.mtu();
                            let name = device.name().to_string();
                            let our_addr = *device.address();

                            info!("TUN device active:");
                            info!("     name: {}", name);
                            info!("  address: {}", device.address());
                            info!("      mtu: {}", mtu);

                            // Calculate max MSS for TCP clamping
                            let effective_mtu = self.effective_ipv6_mtu();
                            let max_mss = effective_mtu.saturating_sub(40).saturating_sub(20); // IPv6 + TCP headers

                            info!("effective MTU: {} bytes", effective_mtu);
                            debug!("   max TCP MSS: {} bytes", max_mss);

                            // On macOS, create a shutdown pipe. Writing to it unblocks the
                            // reader thread's select() loop without closing the TUN fd
                            // (which would cause a double-close when TunDevice drops).
                            #[cfg(target_os = "macos")]
                            let (shutdown_read_fd, shutdown_write_fd) = {
                                let mut fds = [0i32; 2];
                                if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
                                    return Err(NodeError::Tun(
                                        crate::upper::tun::TunError::Configure(
                                            "failed to create shutdown pipe".into(),
                                        ),
                                    ));
                                }
                                (fds[0], fds[1])
                            };

                            // Create writer (dups the fd for independent write access).
                            // Pass path_mtu_lookup so inbound SYN-ACK clamp can read
                            // per-destination path MTU learned via discovery.
                            let (writer, tun_tx) =
                                device.create_writer(max_mss, self.path_mtu_lookup.clone())?;

                            // Spawn writer thread. On exit it self-reports
                            // `Child::Tun` (sync context → `blocking_send`); TUN
                            // is one compound child, so both threads reporting is
                            // fine (the FSM de-dups via `up.remove`).
                            let writer_child_tx = self.child_exit_tx.clone();
                            let writer_handle = thread::spawn(move || {
                                writer.run();
                                if let Some(tx) = &writer_child_tx {
                                    let _ = tx.blocking_send(Child::Tun);
                                }
                            });

                            // Clone tun_tx for the reader
                            let reader_tun_tx = tun_tx.clone();

                            // Create outbound channel for TUN reader → Node
                            let tun_channel_size = self.config().node.buffers.tun_channel;
                            let (outbound_tx, outbound_rx) =
                                tokio::sync::mpsc::channel(tun_channel_size);

                            // Spawn reader thread. Like the writer, it
                            // self-reports `Child::Tun` on exit (sync context →
                            // `blocking_send`). Exactly one cfg variant compiles,
                            // so the single clone is moved into that closure.
                            let transport_mtu = self.transport_mtu();
                            let path_mtu_lookup = self.path_mtu_lookup.clone();
                            let reader_child_tx = self.child_exit_tx.clone();
                            #[cfg(target_os = "macos")]
                            let reader_handle = thread::spawn(move || {
                                run_tun_reader(
                                    device,
                                    mtu,
                                    our_addr,
                                    reader_tun_tx,
                                    outbound_tx,
                                    transport_mtu,
                                    path_mtu_lookup,
                                    shutdown_read_fd,
                                );
                                if let Some(tx) = &reader_child_tx {
                                    let _ = tx.blocking_send(Child::Tun);
                                }
                            });
                            #[cfg(not(target_os = "macos"))]
                            let reader_handle = thread::spawn(move || {
                                run_tun_reader(
                                    device,
                                    mtu,
                                    our_addr,
                                    reader_tun_tx,
                                    outbound_tx,
                                    transport_mtu,
                                    path_mtu_lookup,
                                );
                                if let Some(tx) = &reader_child_tx {
                                    let _ = tx.blocking_send(Child::Tun);
                                }
                            });

                            self.tun_state = TunState::Active;
                            self.tun_name = Some(name);
                            self.supervisor.tun_tx = Some(tun_tx);
                            self.supervisor.tun_outbound_rx = Some(outbound_rx);
                            self.supervisor.tun_reader_handle = Some(reader_handle);
                            self.supervisor.tun_writer_handle = Some(writer_handle);
                            #[cfg(target_os = "macos")]
                            {
                                self.supervisor.tun_shutdown_fd = Some(shutdown_write_fd);
                            }
                            Event::SubstrateUp { child }
                        }
                        Err(e) => {
                            self.tun_state = TunState::Failed;
                            warn!(error = %e, "Failed to initialize TUN, continuing without it");
                            Event::SubstrateFailed { child }
                        }
                    }
                }
                Child::Dns => {
                    // Initialize DNS responder (independent of TUN).
                    //
                    // Default bind_addr is "::1" (IPv6 loopback). The shipped
                    // fips-dns-setup configures systemd-resolved via a global
                    // /etc/systemd/resolved.conf.d/fips.conf drop-in pointing at
                    // [::1]:5354, which sidesteps a Linux IPV6_PKTINFO behaviour
                    // where self-destined traffic to fips0's address is attributed
                    // to fips0 in PKTINFO and gets silently dropped by the
                    // mesh-interface filter in src/upper/dns.rs.
                    //
                    // For mesh-reachable resolution (rare), set bind_addr: "::"
                    // in fips.yaml. The mesh-interface filter remains active to
                    // prevent hosts-file alias enumeration in that mode.
                    // `IPV6_V6ONLY=0` is set explicitly so IPv4 clients on
                    // 127.0.0.1 still reach us regardless of kernel sysctl
                    // defaults — but only when bind is on a wildcard / IPv6 path.
                    let addr_str = self.config().dns.bind_addr();
                    match addr_str.parse::<std::net::IpAddr>() {
                        Ok(ip) => {
                            let bind = std::net::SocketAddr::new(ip, self.config().dns.port());
                            match Self::bind_dns_socket(bind) {
                                Ok(socket) => {
                                    let dns_channel_size = self.config().node.buffers.dns_channel;
                                    let (identity_tx, identity_rx) =
                                        tokio::sync::mpsc::channel(dns_channel_size);
                                    let dns_ttl = self.config().dns.ttl();
                                    let base_hosts =
                                        crate::upper::hosts::HostMap::from_peer_configs(
                                            self.config().peers(),
                                        );
                                    let hosts_path = std::path::PathBuf::from(
                                        crate::upper::hosts::DEFAULT_HOSTS_PATH,
                                    );
                                    let reloader = crate::upper::hosts::HostMapReloader::new(
                                        base_hosts, hosts_path,
                                    );
                                    // Resolve the TUN ifindex so the responder can
                                    // drop queries arriving on the mesh interface
                                    // (fips0). Without this, the `::` bind exposes
                                    // /etc/fips/hosts alias probing to any mesh peer.
                                    // When TUN isn't enabled or the name can't be
                                    // resolved, `None` disables the filter (there
                                    // is no mesh surface to defend anyway).
                                    let mesh_ifindex =
                                        Self::lookup_mesh_ifindex(self.config().tun.name());
                                    info!(
                                        bind = %bind,
                                        hosts = reloader.hosts().len(),
                                        mesh_ifindex = ?mesh_ifindex,
                                        "DNS responder started for .fips domain (auto-reload enabled)"
                                    );
                                    // Self-report on exit so the supervisor FSM
                                    // routes health when the DNS task dies at
                                    // runtime. On a deliberate stop the task is
                                    // `.abort()`ed before this send; even if it
                                    // fired, the FSM ignores it outside `Running`.
                                    let dns_child_tx = self.child_exit_tx.clone();
                                    let handle = tokio::spawn(async move {
                                        crate::upper::dns::run_dns_responder(
                                            socket,
                                            identity_tx,
                                            dns_ttl,
                                            reloader,
                                            mesh_ifindex,
                                        )
                                        .await;
                                        if let Some(tx) = dns_child_tx {
                                            let _ = tx.send(Child::Dns).await;
                                        }
                                    });
                                    self.supervisor.dns_identity_rx = Some(identity_rx);
                                    self.supervisor.dns_task = Some(handle);
                                    Event::SubstrateUp { child }
                                }
                                Err(e) => {
                                    warn!(bind = %bind, error = %e, "Failed to start DNS responder");
                                    Event::SubstrateFailed { child }
                                }
                            }
                        }
                        Err(e) => {
                            warn!(addr = %addr_str, error = %e, "Invalid dns.bind_addr; DNS responder not started");
                            Event::SubstrateFailed { child }
                        }
                    }
                }
            };

            let feedback_actions = self.supervisor.fsm.step(feedback);
            for action in &feedback_actions {
                if let Action::PublishState(ns) = action {
                    start_outcome = Some(*ns);
                }
            }
        }

        // Seams that never triggered inside the loop: the "Transports
        // initialized" info! when there was no non-transport child, and the
        // peer-connect when there was no Tun/Dns child (today it still runs,
        // after mDNS).
        if !transports_info_emitted && !self.transports.is_empty() {
            info!(count = self.transports.len(), "Transports initialized");
        }
        if !peer_connect_done {
            self.initiate_peer_connections().await;
        }

        // Publish the FSM-resolved start-completion state
        // instead of the old unconditional `Running`.
        let outcome = start_outcome
            .expect("supervisor publishes a start-completion state when bring-up resolves");
        self.supervisor.state = outcome;

        match outcome {
            NodeState::Failed => {
                // Zero transports came up — fatal. Tear down cleanly any
                // children that DID come up (a failed start must not leave the
                // node half-up), then return an error. `broadcast_disconnect =
                // false`: there is nothing to gracefully disconnect on a start
                // that never reached service. The daemon exits on this error.
                warn!(
                    "Node start failed: no operational transports came up; tearing down partially-started children"
                );
                let up = self.reconstruct_supervised_up();
                self.supervisor.fsm = SupervisorFsm::running_with(up);
                let teardown = self.supervisor.fsm.step(Event::Stop);
                self.execute_teardown(teardown, false).await;
                return Err(NodeError::NoOperationalTransports);
            }
            NodeState::Degraded => {
                // Operational but missing one or more configured optional
                // children. Enumerate them for the operator, then proceed —
                // a degraded node serves traffic.
                warn!(
                    degraded_children = ?self.supervisor.fsm.failed(),
                    "Node started DEGRADED: one or more configured optional children failed to start"
                );
            }
            _ => {}
        }

        // Runtime liveness monitor for the two poll-observable children (mDNS +
        // Nostr). Unlike the TUN threads and DNS task, these expose no exit hook,
        // so one task polls their `is_finished` accessors every 2s and reports
        // `Child::Mdns` / `Child::Nostr` on exit. It self-terminates once both
        // have been reported (or were never present), and is only armed when at
        // least one of them is actually running.
        let mon_lan = self.supervisor.lan_rendezvous.clone();
        let mon_nostr = self.supervisor.nostr_rendezvous.engine_arc();
        if let Some(mon_tx) = self.child_exit_tx.clone()
            && (mon_lan.is_some() || mon_nostr.is_some())
        {
            tokio::spawn(async move {
                let mut mdns_reported = mon_lan.is_none();
                let mut nostr_reported = mon_nostr.is_none();
                while !(mdns_reported && nostr_reported) {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    if !mdns_reported && mon_lan.as_ref().is_some_and(|l| l.is_finished()) {
                        let _ = mon_tx.send(Child::Mdns).await;
                        mdns_reported = true;
                    }
                    if !nostr_reported && mon_nostr.as_ref().is_some_and(|n| n.is_finished()) {
                        let _ = mon_tx.send(Child::Nostr).await;
                        nostr_reported = true;
                    }
                }
            });
        }

        info!("Node started:");
        info!("       state: {}", self.supervisor.state);
        info!("  transports: {}", self.transports.len());
        info!(" connections: {}", self.connections.len());
        Ok(())
    }

    /// Bind a UDP socket for the DNS responder.
    ///
    /// For IPv6 binds (including `::`), sets `IPV6_V6ONLY=0` so the socket
    /// also accepts IPv4-mapped addresses. This guarantees dual-stack
    /// delivery regardless of `net.ipv6.bindv6only` sysctl on the host —
    /// v4 clients on 127.0.0.1 and v6 clients on the fips0 address both
    /// land on the same socket.
    ///
    /// Also enables `IPV6_RECVPKTINFO` on IPv6 sockets so the responder
    /// can learn the arrival interface per packet. The responder uses that
    /// to drop queries arriving on the mesh TUN, closing the hosts-file
    /// probing side-channel created by the `::` bind.
    fn bind_dns_socket(
        addr: std::net::SocketAddr,
    ) -> Result<tokio::net::UdpSocket, std::io::Error> {
        use socket2::{Domain, Protocol, Socket, Type};
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        if addr.is_ipv6() {
            sock.set_only_v6(false)?;
            #[cfg(unix)]
            Self::set_recv_pktinfo_v6(&sock)?;
        }
        sock.set_nonblocking(true)?;
        sock.bind(&addr.into())?;
        tokio::net::UdpSocket::from_std(sock.into())
    }

    /// Enable `IPV6_RECVPKTINFO` on an IPv6 UDP socket.
    ///
    /// After this setsockopt, each `recvmsg()` call on the socket receives
    /// an `IPV6_PKTINFO` control message containing the arrival interface
    /// index, which the DNS responder uses for its mesh-interface filter.
    #[cfg(unix)]
    fn set_recv_pktinfo_v6(sock: &socket2::Socket) -> Result<(), std::io::Error> {
        use std::os::fd::AsRawFd;
        let enable: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVPKTINFO,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Resolve the mesh TUN interface index by name.
    ///
    /// Returns `None` if the interface does not exist (e.g. TUN disabled
    /// or not yet created). A `None` result disables the DNS responder's
    /// mesh-interface filter — safe, because if there is no fips0 there
    /// is no mesh exposure to defend against.
    fn lookup_mesh_ifindex(name: &str) -> Option<u32> {
        #[cfg(unix)]
        {
            let c_name = std::ffi::CString::new(name).ok()?;
            let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
            if idx == 0 { None } else { Some(idx) }
        }
        #[cfg(not(unix))]
        {
            let _ = name;
            None
        }
    }

    /// Stop the node.
    ///
    /// Shuts down TUN interface, stops I/O threads, and transitions to
    /// the Stopped state.
    pub async fn stop(&mut self) -> Result<(), NodeError> {
        if !self.supervisor.state.can_stop() {
            return Err(NodeError::NotStarted);
        }
        self.supervisor.state = NodeState::Stopping;
        info!(state = %self.supervisor.state, "Node stopping");

        // Reconstruct the supervised up-set from observed runtime presence and
        // let the FSM author the teardown order (dns → nostr → mdns →
        // transports (ascending id) → tun).
        let up = self.reconstruct_supervised_up();
        self.supervisor.fsm = SupervisorFsm::running_with(up);
        let actions = self.supervisor.fsm.step(Event::Stop);

        // Execute the teardown plan. `broadcast_disconnect = true`: the
        // immediate-stop path owns the single shutdown-Disconnect fan-out,
        // which the helper emits at the Dns→rest seam.
        self.execute_teardown(actions, true).await;

        self.supervisor.state = NodeState::Stopped;
        info!(state = %self.supervisor.state, "Node stopped");
        Ok(())
    }

    /// Execute an ordered `StopChild` teardown plan authored by the supervisor
    /// FSM, reporting each `ChildStopped` back so the machine reaches `Stopped`.
    ///
    /// This is the teardown body factored out of [`Self::stop`] so the drain
    /// path can reuse the exact same per-child teardown and channel-drop
    /// ordering. Two driver seams are woven in at their current positions:
    ///
    /// - **Seam (a), the shutdown-Disconnect fan-out** (after any Dns teardown,
    ///   before everything else) is gated on `broadcast_disconnect`. The
    ///   immediate `stop()` path passes `true` and emits it here; the drain path
    ///   passes `false` because it already broadcast once at drain entry and
    ///   must not re-broadcast.
    /// - **Seam (b), dropping the packet channels** (after all transports, before
    ///   TUN) always runs.
    async fn execute_teardown(&mut self, actions: Vec<Action>, broadcast_disconnect: bool) {
        // `broadcast_disconnect = false` (drain path) marks the fan-out already
        // done so neither the in-loop seam nor the trailing seam fires.
        let mut disconnect_done = !broadcast_disconnect;
        let mut packet_taken = false;
        for action in actions {
            let Action::StopChild(child) = action else {
                continue;
            };

            // Seam (a): send disconnect notifications to all active peers
            // before closing transports — after any Dns teardown, before
            // everything else.
            if !disconnect_done && !matches!(child, Child::Dns) {
                self.send_disconnect_to_all_peers(DisconnectReason::Shutdown)
                    .await;
                disconnect_done = true;
            }

            // Seam (b): drop the packet channels after all transports have
            // stopped and before the TUN teardown.
            if !packet_taken && matches!(child, Child::Tun) {
                self.supervisor.packet_tx.take();
                self.packet_rx.take();
                packet_taken = true;
            }

            match child {
                Child::Dns => {
                    // Stop DNS responder
                    if let Some(handle) = self.supervisor.dns_task.take() {
                        handle.abort();
                        debug!("DNS responder stopped");
                    }
                }
                Child::Nostr => {
                    // Stop Nostr overlay discovery background work and withdraw
                    // any advert.
                    if let Some(bootstrap) = self.supervisor.nostr_rendezvous.take_engine()
                        && let Err(e) = bootstrap.shutdown().await
                    {
                        warn!(error = %e, "Failed to shutdown Nostr overlay discovery");
                    }
                }
                Child::Mdns => {
                    // Tear down LAN mDNS responder + browser. Best-effort: the
                    // OS will eventually time the advert out via its TTL even if
                    // we don't get a clean unregister out before the daemon exits.
                    if let Some(lan) = self.supervisor.lan_rendezvous.take() {
                        lan.shutdown().await;
                    }
                }
                Child::Transport(id) => {
                    // Shutdown transport (they're packet producers)
                    if let Some(mut handle) = self.transports.remove(&id) {
                        let transport_type = handle.transport_type().name;
                        match handle.stop().await {
                            Ok(()) => {
                                info!(transport_id = %id, transport_type, "Transport stopped");
                            }
                            Err(e) => {
                                warn!(
                                    transport_id = %id,
                                    transport_type,
                                    error = %e,
                                    "Transport stop failed"
                                );
                            }
                        }
                    }
                }
                Child::Tun => {
                    // Shutdown TUN interface
                    if let Some(name) = self.tun_name.take() {
                        info!(name = %name, "Shutting down TUN interface");

                        // Drop the tun_tx to signal the writer to stop
                        self.supervisor.tun_tx.take();

                        // Delete the interface (on Linux, causes reader to get EFAULT)
                        if let Err(e) = shutdown_tun_interface(&name).await {
                            warn!(name = %name, error = %e, "Failed to shutdown TUN interface");
                        }

                        // On macOS, signal the reader thread to exit by writing to the
                        // shutdown pipe. The reader's select() will wake up and break.
                        #[cfg(target_os = "macos")]
                        if let Some(fd) = self.supervisor.tun_shutdown_fd.take() {
                            unsafe {
                                libc::write(fd, b"x".as_ptr() as *const libc::c_void, 1);
                                libc::close(fd);
                            }
                        }

                        // Wait for threads to finish
                        if let Some(handle) = self.supervisor.tun_reader_handle.take() {
                            let _ = handle.join();
                        }
                        if let Some(handle) = self.supervisor.tun_writer_handle.take() {
                            let _ = handle.join();
                        }

                        self.tun_state = TunState::Disabled;
                    }
                }
                Child::EncryptWorkers | Child::DecryptWorkers => {
                    // Worker pools are never torn down in stop() (matches
                    // today); the FSM never emits StopChild for them, so this
                    // is unreachable.
                }
            }

            self.supervisor.fsm.step(Event::ChildStopped { child });
        }

        // Seams that never triggered inside the loop (no non-Dns child for the
        // disconnect fan-out, no Tun child for dropping the packet channels).
        if !disconnect_done {
            self.send_disconnect_to_all_peers(DisconnectReason::Shutdown)
                .await;
        }
        if !packet_taken {
            self.supervisor.packet_tx.take();
            self.packet_rx.take();
        }
    }

    /// Reconstruct the supervised up-set from observed runtime presence, so the
    /// FSM authors the teardown order regardless of how the node reached
    /// `Running`. Worker pools are deliberately excluded: today's teardown never
    /// stops them. Shared by [`Self::stop`] and [`Self::enter_drain`].
    fn reconstruct_supervised_up(&self) -> Vec<Child> {
        let mut up: Vec<Child> = Vec::new();
        if self.supervisor.dns_task.is_some() {
            up.push(Child::Dns);
        }
        if self.supervisor.nostr_rendezvous.engine().is_some() {
            up.push(Child::Nostr);
        }
        if self.supervisor.lan_rendezvous.is_some() {
            up.push(Child::Mdns);
        }
        for id in self.transports.keys() {
            up.push(Child::Transport(*id));
        }
        if self.tun_name.is_some() {
            up.push(Child::Tun);
        }
        up
    }

    /// Enter the bounded graceful drain **in place**, called once by
    /// [`Self::run_rx_loop_with_shutdown`] when the shutdown signal fires.
    ///
    /// Seeds the FSM at `Running` from observed presence (same pattern as
    /// [`Self::stop`]), steps it into `Draining`, and executes the entry
    /// actions: broadcast a single shutdown `Disconnect`, and no-op the
    /// reconciler-gate actions (the reconciler that consumes them is not yet
    /// built; the `SetTimer` is likewise a no-op — the bounded wait is the rx
    /// loop's deadline arm). Teardown is deferred to [`Self::finish_shutdown`].
    ///
    /// Called from an rx-loop `select!` arm body: the channel receivers are
    /// already moved into the loop's locals, so borrowing `self` here is sound.
    pub(in crate::node) async fn enter_drain(&mut self) {
        let up = self.reconstruct_supervised_up();
        self.supervisor.fsm = SupervisorFsm::running_with(up);

        let drain_timeout = self.config().node.drain_timeout();
        // Absolute driver-clock ms, carried into `Draining`/`SetTimer` for
        // observability; the real bounded wait is the rx loop's deadline arm.
        let deadline_ms = Self::now_ms().saturating_add(drain_timeout.as_millis() as u64);

        let actions = self.supervisor.fsm.step(Event::Drain { deadline_ms });

        // Publish the operator-visible `Draining` state (a direct write, like
        // the other `self.state` transitions this module uses). The
        // FSM-owned `PublishState` *action* is not needed for this single
        // transition; it arrives with the Full/Degraded health split (c), which
        // a direct write cannot express.
        self.supervisor.state = NodeState::Draining;
        info!(state = %self.supervisor.state, "Node draining");

        for action in actions {
            match action {
                Action::BroadcastDisconnect => {
                    self.send_disconnect_to_all_peers(DisconnectReason::Shutdown)
                        .await;
                }
                Action::SetTimer(_, _) => {
                    // The rx loop owns the bounded wait; the FSM's timer is
                    // carried for observability only. No-op here.
                }
                Action::SetPeeringDesired(PeeringDesired::Empty) => {
                    // reconciler drain-gate: clear the queued
                    // retry schedule so the disconnects the drain itself causes
                    // cannot leave reconnect entries behind.
                    self.peering.reconciler.retry_pending.clear();
                }
                Action::SuspendReplenish => {
                    // reconciler drain-gate: no extra latch needed. The whole
                    // drain window is `Gate::Suspended`
                    // (`Gate::from_state(NodeState::Draining)`), so the per-tick
                    // retry-dial reconcile and every peer-loss reflex read that
                    // gate and self-suppress for the duration of the drain.
                }
                Action::SpawnChild(_) | Action::StopChild(_) | Action::PublishState(_) => {
                    // Drain entry never emits child or publish-state actions
                    // (the `Draining` state is a direct write above); ignore
                    // defensively.
                }
            }
        }

        info!(
            drain_timeout_secs = drain_timeout.as_secs(),
            peers = self.peers.len(),
            "Draining: broadcast shutdown Disconnect, waiting for peers to clear"
        );
    }

    /// Finish shutdown after [`Self::run_rx_loop_with_shutdown`] returns.
    ///
    /// Branches on the supervisor's state:
    /// - if the loop drained (FSM in `Draining`), close the window
    ///   (`DrainDeadlineElapsed`) and tear down **without re-broadcasting** —
    ///   the fan-out already went out at drain entry;
    /// - otherwise the loop exited some other way (the packet channel closed
    ///   while still `Running` — the degenerate/error path), so fall back to the
    ///   immediate [`Self::stop`] (which broadcasts and tears down).
    pub async fn finish_shutdown(&mut self) {
        if self.supervisor.fsm.is_draining() {
            self.supervisor.state = NodeState::Stopping;
            info!(state = %self.supervisor.state, "Node stopping (drain complete)");
            let stop_actions = self.supervisor.fsm.step(Event::DrainDeadlineElapsed);
            self.execute_teardown(stop_actions, false).await;
            self.supervisor.state = NodeState::Stopped;
            info!(state = %self.supervisor.state, "Node stopped");
        } else if let Err(e) = self.stop().await {
            warn!(error = %e, "Error during shutdown");
        }
    }

    /// Send disconnect notifications to all active peers.
    ///
    /// Best-effort: send failures are logged and ignored since the transport
    /// may already be degraded. This runs before transports are shut down.
    async fn send_disconnect_to_all_peers(&mut self, reason: DisconnectReason) {
        // Collect node_addrs to avoid borrow conflict with send helper
        let peer_addrs: Vec<NodeAddr> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.can_send() && peer.has_session())
            .map(|(addr, _)| *addr)
            .collect();

        if peer_addrs.is_empty() {
            debug!(
                total_peers = self.peers.len(),
                "No sendable peers for disconnect notification"
            );
            return;
        }

        let mut sent = 0usize;
        for node_addr in &peer_addrs {
            if self.send_disconnect_to_peer(node_addr, reason).await {
                sent += 1;
            }
        }

        info!(sent, total = peer_addrs.len(), reason = %reason, "Sent disconnect notifications");
    }

    /// Send a Disconnect notification to a single peer.
    ///
    /// Best-effort: a send failure (peer already gone, transport down) is
    /// logged and swallowed so callers can proceed with teardown regardless.
    /// Returns `true` if the message was sent successfully.
    async fn send_disconnect_to_peer(
        &mut self,
        node_addr: &NodeAddr,
        reason: DisconnectReason,
    ) -> bool {
        let plaintext = Disconnect::new(reason).encode();
        match self
            .send_encrypted_link_message(node_addr, &plaintext)
            .await
        {
            Ok(()) => true,
            Err(e) => {
                debug!(
                    peer = %self.peer_display_name(node_addr),
                    error = %e,
                    "Failed to send disconnect (transport may be down)"
                );
                false
            }
        }
    }

    fn static_peer_addresses(&self, peer_config: &PeerConfig) -> Vec<PeerAddress> {
        peer_config
            .addresses_by_priority()
            .into_iter()
            .cloned()
            .collect()
    }

    async fn attempt_peer_address_list(
        &mut self,
        peer_config: &PeerConfig,
        peer_identity: PeerIdentity,
        allow_bootstrap_nat: bool,
        addresses: &[PeerAddress],
    ) -> Result<(), NodeError> {
        let peer_node_addr = *peer_identity.node_addr();
        let mut attempted = 0usize;
        let max_attempts = self.path_candidate_attempt_budget(&peer_node_addr);
        if max_attempts == 0 {
            return Err(NodeError::NoTransportForType(format!(
                "no outbound slots available for {}",
                peer_config.npub
            )));
        }

        for addr in addresses {
            if attempted >= max_attempts {
                break;
            }
            if addr.transport == "udp" && addr.addr.eq_ignore_ascii_case("nat") {
                if !allow_bootstrap_nat {
                    continue;
                }
                if self
                    .supervisor
                    .nostr_rendezvous
                    .request_nostr_bootstrap(peer_config)
                    .await
                {
                    attempted = attempted.saturating_add(1);
                }
                continue;
            }

            let (transport_id, remote_addr) = if addr.transport == "ethernet" {
                match self.resolve_ethernet_addr(&addr.addr) {
                    Ok(result) => result,
                    Err(e) => {
                        debug!(
                            transport = %addr.transport,
                            addr = %addr.addr,
                            error = %e,
                            "Failed to resolve Ethernet address"
                        );
                        continue;
                    }
                }
            } else if addr.transport == "ble" {
                #[cfg(bluer_available)]
                {
                    match self.resolve_ble_addr(&addr.addr) {
                        Ok(result) => result,
                        Err(e) => {
                            debug!(
                                transport = %addr.transport,
                                addr = %addr.addr,
                                error = %e,
                                "Failed to resolve BLE address"
                            );
                            continue;
                        }
                    }
                }
                #[cfg(not(bluer_available))]
                {
                    debug!(transport = %addr.transport, "BLE transport not available on this build");
                    continue;
                }
            } else {
                let tid = if addr.transport == "udp"
                    && let Ok(remote_socket_addr) = addr.addr.parse::<SocketAddr>()
                {
                    match self.find_udp_transport_for_remote_addr(remote_socket_addr) {
                        Some((id, _)) => id,
                        None => {
                            debug!(
                                transport = %addr.transport,
                                addr = %addr.addr,
                                "No compatible operational UDP transport for address"
                            );
                            continue;
                        }
                    }
                } else {
                    match self.find_transport_for_type(&addr.transport) {
                        Some(id) => id,
                        None => {
                            debug!(
                                transport = %addr.transport,
                                addr = %addr.addr,
                                "No operational transport for address type"
                            );
                            continue;
                        }
                    }
                };
                (tid, TransportAddr::from_string(&addr.addr))
            };

            if self.is_connecting_to_peer_on_path(&peer_node_addr, transport_id, &remote_addr) {
                continue;
            }

            match self
                .initiate_connection(transport_id, remote_addr, peer_identity)
                .await
            {
                Ok(()) => attempted = attempted.saturating_add(1),
                Err(e @ NodeError::AccessDenied(_)) => return Err(e),
                Err(e) => {
                    debug!(
                        npub = %peer_config.npub,
                        transport_id = %transport_id,
                        error = %e,
                        "Connection attempt failed, trying next address"
                    );
                }
            }
        }

        if attempted > 0 {
            return Ok(());
        }

        Err(NodeError::NoTransportForType(format!(
            "no operational transport for any of {}'s addresses",
            peer_config.npub
        )))
    }

    async fn queue_open_discovery_retries(&mut self, bootstrap: &std::sync::Arc<NostrRendezvous>) {
        self.run_open_discovery_sweep(bootstrap, None).await;
    }

    /// Open-discovery cache sweep — drains the cached overlay adverts and
    /// enqueues retries for eligible peers via the sans-IO reconciler's overlay
    /// layer.
    ///
    /// The driver builds the [`DiscoveryPools`] overlay input from
    /// `bootstrap.cached_open_discovery_candidates(64)` (the I/O), excluding the
    /// node's own advert (the sans-IO core has no self-identity
    /// input), and supplies the configured-npub set, the per-npub cooldown set,
    /// and the startup-sweep max-age. `max_age_secs` is `None` for the per-tick
    /// sweep and `Some(startup_sweep_max_age_secs)` for the one-shot startup
    /// sweep.
    ///
    /// The core reproduces the old sweep's full skip order, configured-advert
    /// expedite, and enqueue budget internally: it inserts due-now entries into
    /// the relocated `retry_pending`, and the retry-slot `process_pending_retries`
    /// dials them later in the same tick (two-phase). This
    /// calls the reconciler's `reconcile_overlay` (the overlay layer only) —
    /// NOT the monolithic `reconcile()` — so the always-on retry-dial phase does
    /// not re-fire at this slot (which would double-dial the due entries and
    /// apply the per-tick 16-cap twice). The returned `ScheduleRetry` actions
    /// name exactly the newly enqueued peers; the driver consumes them to
    /// pre-seed the alias + identity caches for that set (the old sweep's
    /// per-enqueue `peer_aliases` / `register_identity` side effects).
    pub(in crate::node) async fn run_open_discovery_sweep(
        &mut self,
        bootstrap: &std::sync::Arc<NostrRendezvous>,
        max_age_secs: Option<u64>,
    ) {
        if !self.config().node.rendezvous.nostr.enabled
            || self.config().node.rendezvous.nostr.policy
                != crate::config::NostrRendezvousPolicy::Open
        {
            return;
        }

        let now_ms = Self::now_ms();
        let self_node_addr = *self.identity().node_addr();

        let configured_npubs = self
            .config()
            .peers()
            .iter()
            .map(|peer| peer.npub.clone())
            .collect::<HashSet<_>>();

        // Drain the cached overlay adverts (the I/O). Exclude our own advert
        // (O6): the sans-IO core has no self-identity input, so the driver
        // filters self here, reproducing the old sweep's self-skip. The cooldown
        // set mirrors the old per-candidate `bootstrap.cooldown_until` skip.
        //
        // `candidate_identities` keeps each forwarded candidate's `PeerIdentity`
        // keyed by NodeAddr so that, once the core decides which candidates to
        // enqueue, the driver can pre-seed the alias + identity caches for
        // exactly that set (below) — reproducing the old sweep's per-enqueue
        // `peer_aliases` / `register_identity` side effects byte-for-byte.
        let now_secs = now_ms / 1000;
        let candidates = bootstrap.cached_open_discovery_candidates(64).await;
        // `cached` and the self buckets feed the operator sweep summary below: the
        // raw cache size and the self-advert filter are the driver's to count,
        // since the sans-IO core never sees self (it is excluded from the pool).
        // The old sweep checked self at position 4 — *after* the age and
        // configured filters, which `continue` first — so a stale (startup only)
        // or self-configured own-advert was attributed to `skipped_age` /
        // `skipped_configured`, not `skipped_self`. Reproduce that precedence here
        // (the two predicates that preceded the old self check) so the restored
        // summary buckets self exactly as before; only a self-advert that clears
        // both counts as `skipped_self`.
        let cached_count = candidates.len();
        let mut skipped_self = 0usize;
        let mut skipped_self_as_age = 0usize;
        let mut skipped_self_as_configured = 0usize;
        let mut overlay = Vec::with_capacity(candidates.len());
        let mut overlay_cooldown = HashSet::new();
        let mut candidate_identities: HashMap<NodeAddr, PeerIdentity> = HashMap::new();
        for (npub, endpoints, created_at_secs) in candidates {
            if let Ok(identity) = PeerIdentity::from_npub(&npub) {
                let node_addr = *identity.node_addr();
                if node_addr == self_node_addr {
                    if max_age_secs
                        .is_some_and(|max_age| now_secs.saturating_sub(created_at_secs) > max_age)
                    {
                        skipped_self_as_age = skipped_self_as_age.saturating_add(1);
                    } else if configured_npubs.contains(&npub) {
                        skipped_self_as_configured = skipped_self_as_configured.saturating_add(1);
                    } else {
                        skipped_self = skipped_self.saturating_add(1);
                    }
                    continue;
                }
                candidate_identities.insert(node_addr, identity);
            }
            if bootstrap.cooldown_until(&npub, now_ms).is_some() {
                overlay_cooldown.insert(npub.clone());
            }
            overlay.push((npub, endpoints, created_at_secs));
        }

        let pools = DiscoveryPools {
            overlay,
            configured_npubs,
            overlay_cooldown,
            startup_sweep_max_age_secs: max_age_secs,
            ..DiscoveryPools::default()
        };

        let policy = self.build_peering_policy(Vec::new());
        let observed = self.observe_peering();
        let budget = self.build_peering_budget();
        let gate = Gate::from_state(self.supervisor.state);

        // Two-phase enqueue: reconcile_overlay inserts due-now
        // entries into retry_pending; the retry slot dials them. The core emits
        // a `ScheduleRetry` for exactly the NEW enqueues (the configured-advert
        // expedite bumps `retry_after_ms` without emitting), which is precisely
        // the set the old sweep pre-seeded — its `register_identity` /
        // `peer_aliases` sat after every skip `continue`, so only enqueued
        // candidates reached it. Consuming the core's own output here to drive
        // that I/O bookkeeping is legitimate sans-IO: the core decides WHICH to
        // enqueue, the driver performs the side effects for exactly that set.
        let (actions, tally) = self
            .peering
            .reconciler
            .reconcile_overlay(&policy, &observed, &budget, &pools, now_ms, gate);

        for action in actions {
            let PeeringAction::ScheduleRetry { peer, .. } = action else {
                continue;
            };
            let Some(identity) = candidate_identities.get(&peer).copied() else {
                continue;
            };
            self.peer_aliases
                .entry(peer)
                .or_insert_with(|| identity.short_npub());
            self.register_identity(peer, identity.pubkey_full());
        }

        // Operator-facing sweep summary. Restores the log dropped when the sweep
        // moved into the sans-IO core: the core tallies each enqueue/skip
        // decision, the driver adds the two values only it holds (`cached`, the
        // raw cache size, and `skipped_self`), derives the caller label from the
        // sweep kind (startup passes a max-age, per-tick passes `None`), and
        // reproduces the old summarize gate (always on startup; per-tick only
        // when something was enqueued). Only summarizes when the core actually
        // reconciled — a not-running/suspended gate yields an empty default tally
        // that must not read as "ran, enqueued nothing".
        if matches!(gate, Gate::Reconciling) {
            let caller = if max_age_secs.is_some() {
                "startup"
            } else {
                "per-tick"
            };
            if tally.budget_zero {
                debug!(
                    caller = %caller,
                    "open-discovery sweep: enqueue budget is 0, skipping"
                );
            } else if caller == "startup" || tally.enqueued > 0 {
                // Fold the self-advert cases the old sweep attributed to the age
                // and configured buckets back into those buckets.
                let skipped_age = tally.skipped_age + skipped_self_as_age;
                let skipped_configured = tally.skipped_configured + skipped_self_as_configured;
                let skipped_total = skipped_self
                    + skipped_age
                    + skipped_configured
                    + tally.skipped_connected
                    + tally.skipped_retry_pending
                    + tally.skipped_connecting
                    + tally.skipped_no_endpoints
                    + tally.skipped_invalid_npub
                    + tally.skipped_cooldown;
                info!(
                    caller = %caller,
                    cached = cached_count,
                    queued = tally.enqueued,
                    skipped_age = skipped_age,
                    skipped_configured = skipped_configured,
                    skipped_self = skipped_self,
                    skipped_connected = tally.skipped_connected,
                    skipped_retry_pending = tally.skipped_retry_pending,
                    skipped_connecting = tally.skipped_connecting,
                    skipped_no_endpoints = tally.skipped_no_endpoints,
                    skipped_invalid_npub = tally.skipped_invalid_npub,
                    skipped_cooldown = tally.skipped_cooldown,
                    skipped_total = skipped_total,
                    "open-discovery sweep complete"
                );
            }
        }
    }

    /// One-shot startup sweep: runs once after the configured settle
    /// delay, iterating the cached overlay adverts and queueing retries
    /// for any peer with a recent enough advert that we haven't already
    /// configured statically or established a link to.
    ///
    /// Gated identically to [`run_open_discovery_sweep`]: requires
    /// `node.rendezvous.nostr.enabled` and `policy == open`.
    async fn maybe_run_startup_open_discovery_sweep(
        &mut self,
        bootstrap: &std::sync::Arc<NostrRendezvous>,
    ) {
        if self.supervisor.nostr_rendezvous.startup_sweep_done() {
            return;
        }
        if !self.config().node.rendezvous.nostr.enabled
            || self.config().node.rendezvous.nostr.policy
                != crate::config::NostrRendezvousPolicy::Open
        {
            // Mark done so we don't keep re-checking on every tick.
            self.supervisor.nostr_rendezvous.set_startup_sweep_done();
            return;
        }
        let Some(started_at_ms) = self.supervisor.nostr_rendezvous.started_at_ms() else {
            return;
        };
        let now_ms = Self::now_ms();
        let delay_ms = self
            .config()
            .node
            .rendezvous
            .nostr
            .startup_sweep_delay_secs
            .saturating_mul(1000);
        if now_ms < started_at_ms.saturating_add(delay_ms) {
            return;
        }

        let max_age_secs = self
            .config()
            .node
            .rendezvous
            .nostr
            .startup_sweep_max_age_secs;
        self.run_open_discovery_sweep(bootstrap, Some(max_age_secs))
            .await;
        self.supervisor.nostr_rendezvous.set_startup_sweep_done();
    }

    /// Build the reconciler [`Policy`] from config. `auto_connect_peers` is
    /// filled by the caller: the startup floor and the reflex wrappers pass the
    /// configured auto-connect set; the per-tick retry-dial slot passes an empty
    /// set so the config floor stays silent (cadence contract).
    pub(in crate::node) fn build_peering_policy(
        &self,
        auto_connect_peers: Vec<PeerConfig>,
    ) -> Policy {
        let cfg = self.config();
        let retry = &cfg.node.retry;
        let nostr = &cfg.node.rendezvous.nostr;
        Policy {
            auto_connect_peers,
            max_peers: self.max_peers(),
            max_connections: self.max_connections(),
            max_links: self.max_links(),
            retry_base_interval_ms: retry.base_interval_secs.saturating_mul(1000),
            retry_max_backoff_ms: retry.max_backoff_secs.saturating_mul(1000),
            retry_max_retries: retry.max_retries,
            handshake_timeout_ms: cfg
                .node
                .rate_limit
                .handshake_timeout_secs
                .saturating_mul(1000),
            open_discovery_enabled: nostr.enabled
                && nostr.policy == crate::config::NostrRendezvousPolicy::Open,
            open_discovery_max_pending: nostr.open_discovery_max_pending,
            open_discovery_expires_ms: nostr
                .advert_ttl_secs
                .saturating_mul(1000)
                .saturating_mul(OPEN_DISCOVERY_RETRY_LIFETIME_MULTIPLIER),
        }
    }

    /// Snapshot the live dataplane maps into the reconciler's [`Observed`] input.
    ///
    /// The `connected` / `connecting` sets gate the floor, retry-dial, overlay,
    /// and LAN layers; `in_flight_by_peer` feeds the opportunistic layer's
    /// per-peer parallel cap, computed exactly as the deleted
    /// `path_candidate_attempt_budget` did: `connections(expected == addr) +
    /// pending_connects(addr)`. The scalar counts stay unpopulated at the
    /// ceiling-only posture (no layer reads them; see [`Observed`]).
    pub(in crate::node) fn observe_peering(&self) -> Observed {
        let connected: HashSet<NodeAddr> = self.peers.keys().copied().collect();
        let connecting: HashSet<NodeAddr> = self
            .connections
            .values()
            .filter_map(|conn| conn.expected_identity().map(|id| *id.node_addr()))
            .collect();
        let mut in_flight_by_peer: HashMap<NodeAddr, usize> = HashMap::new();
        for conn in self.connections.values() {
            if let Some(id) = conn.expected_identity() {
                *in_flight_by_peer.entry(*id.node_addr()).or_default() += 1;
            }
        }
        for pending in &self.peering.pending_connects {
            *in_flight_by_peer
                .entry(*pending.peer_identity.node_addr())
                .or_default() += 1;
        }
        Observed {
            connected,
            connecting,
            in_flight_by_peer,
            ..Observed::default()
        }
    }

    /// Build the admission [`Budget`] from the live maps. This is the surviving
    /// home for the slot arithmetic; the shared helpers it wraps stay until the
    /// overlay/opportunistic cutovers consume them.
    pub(in crate::node) fn build_peering_budget(&self) -> Budget {
        let peer_slots = if self.max_peers() == 0 {
            usize::MAX
        } else {
            self.max_peers().saturating_sub(self.peers.len())
        };
        Budget {
            handshake_slots: self.outbound_handshake_slots(),
            link_slots: self.outbound_link_slots(),
            peer_slots,
            admission_ok: self.outbound_admission_check(),
            discovery_per_tick: MAX_DISCOVERY_CONNECTS_PER_TICK,
            retry_per_tick: MAX_RETRY_CONNECTIONS_PER_TICK,
            per_peer_cap: MAX_PARALLEL_PATH_CANDIDATES_PER_PEER,
        }
    }

    fn outbound_handshake_slots(&self) -> usize {
        let used = self
            .connections
            .len()
            .saturating_add(self.peering.pending_connects.len());
        if self.max_connections() == 0 {
            usize::MAX
        } else {
            self.max_connections().saturating_sub(used)
        }
    }

    fn outbound_link_slots(&self) -> usize {
        if self.max_links() == 0 {
            usize::MAX
        } else {
            self.max_links().saturating_sub(self.links.len())
        }
    }

    fn path_candidate_attempt_budget(&self, peer_node_addr: &NodeAddr) -> usize {
        if !self.peers.contains_key(peer_node_addr)
            && self.max_peers() > 0
            && self.peers.len() >= self.max_peers()
        {
            return 0;
        }

        let in_flight_for_peer = self
            .connections
            .values()
            .filter(|conn| {
                conn.expected_identity()
                    .map(|identity| identity.node_addr() == peer_node_addr)
                    .unwrap_or(false)
            })
            .count()
            .saturating_add(
                self.peering
                    .pending_connects
                    .iter()
                    .filter(|pending| pending.peer_identity.node_addr() == peer_node_addr)
                    .count(),
            );

        self.outbound_handshake_slots()
            .min(self.outbound_link_slots())
            .min(MAX_PARALLEL_PATH_CANDIDATES_PER_PEER.saturating_sub(in_flight_for_peer))
    }

    /// Capture the advertisable-endpoint inputs of every operational
    /// transport into a snapshot the rendezvous driver can turn into an
    /// `OverlayAdvert` without borrowing the transport table across the
    /// STUN await. Iteration order matches `self.transports.values()`, and
    /// only transports whose type matched a configured listener are
    /// included, mirroring the original per-transport branch structure.
    fn advert_transport_snapshot(&self) -> Vec<crate::nostr::AdvertTransportSnapshot> {
        use crate::nostr::AdvertTransportSnapshot;
        let mut snapshot = Vec::new();
        for handle in self.transports.values() {
            if !handle.is_operational() {
                continue;
            }
            match handle.transport_type().name {
                "udp" => {
                    let Some(cfg) = self.lookup_udp_config(handle.name()) else {
                        continue;
                    };
                    snapshot.push(AdvertTransportSnapshot::Udp {
                        advertise: cfg.advertise_on_nostr(),
                        is_public: cfg.is_public(),
                        external_addr: cfg.external_advert_addr(),
                        local_addr: handle.local_addr(),
                        transport_key: handle.transport_id().as_u32(),
                    });
                }
                "tcp" => {
                    let Some(cfg) = self.lookup_tcp_config(handle.name()) else {
                        continue;
                    };
                    snapshot.push(AdvertTransportSnapshot::Tcp {
                        advertise: cfg.advertise_on_nostr(),
                        external_addr: cfg.external_advert_addr(),
                        local_addr: handle.local_addr(),
                    });
                }
                "tor" => {
                    let Some(cfg) = self.lookup_tor_config(handle.name()) else {
                        continue;
                    };
                    snapshot.push(AdvertTransportSnapshot::Tor {
                        advertise: cfg.advertise_on_nostr(),
                        onion_addr: handle.onion_address().map(|s| s.to_string()),
                        advertised_port: cfg.advertised_port(),
                    });
                }
                _ => {}
            }
        }
        snapshot
    }

    async fn refresh_overlay_advert(
        &self,
        bootstrap: &std::sync::Arc<NostrRendezvous>,
    ) -> Result<(), crate::nostr::BootstrapError> {
        let snapshot = self.advert_transport_snapshot();
        self.supervisor
            .nostr_rendezvous
            .refresh_overlay_advert(bootstrap, snapshot, &self.config().node.rendezvous.nostr)
            .await
    }

    fn lookup_udp_config(&self, transport_name: Option<&str>) -> Option<&crate::config::UdpConfig> {
        match (&self.config().transports.udp, transport_name) {
            (crate::config::TransportInstances::Single(cfg), None) => Some(cfg),
            (crate::config::TransportInstances::Named(configs), Some(name)) => configs.get(name),
            _ => None,
        }
    }

    fn lookup_tcp_config(&self, transport_name: Option<&str>) -> Option<&crate::config::TcpConfig> {
        match (&self.config().transports.tcp, transport_name) {
            (crate::config::TransportInstances::Single(cfg), None) => Some(cfg),
            (crate::config::TransportInstances::Named(configs), Some(name)) => configs.get(name),
            _ => None,
        }
    }

    fn lookup_tor_config(&self, transport_name: Option<&str>) -> Option<&crate::config::TorConfig> {
        match (&self.config().transports.tor, transport_name) {
            (crate::config::TransportInstances::Single(cfg), None) => Some(cfg),
            (crate::config::TransportInstances::Named(configs), Some(name)) => configs.get(name),
            _ => None,
        }
    }

    pub(in crate::node) async fn try_peer_addresses(
        &mut self,
        peer_config: &PeerConfig,
        peer_identity: PeerIdentity,
        allow_bootstrap_nat: bool,
    ) -> Result<(), NodeError> {
        let peer_node_addr = *peer_identity.node_addr();
        if self.peers.contains_key(&peer_node_addr) {
            debug!(
                npub = %peer_config.npub,
                "Peer already exists, skipping address attempts"
            );
            return Ok(());
        }
        if self.is_connecting_to_peer(&peer_node_addr) {
            debug!(
                npub = %peer_config.npub,
                "Connection already in progress, skipping address attempts"
            );
            return Ok(());
        }

        let candidates = self.peer_address_candidates(peer_config).await;

        if candidates.is_empty() {
            return Err(NodeError::NoTransportForType(format!(
                "no addresses known for {}",
                peer_config.npub
            )));
        }

        if self
            .attempt_peer_address_list(peer_config, peer_identity, allow_bootstrap_nat, &candidates)
            .await
            .is_ok()
        {
            return Ok(());
        }

        Err(NodeError::NoTransportForType(format!(
            "no operational transport for any of {}'s addresses",
            peer_config.npub
        )))
    }

    async fn try_active_peer_alternative_addresses(
        &mut self,
        peer_config: &PeerConfig,
        peer_identity: PeerIdentity,
    ) -> Result<bool, NodeError> {
        let peer_node_addr = *peer_identity.node_addr();
        let candidates = self.peer_address_candidates(peer_config).await;

        if candidates.is_empty() {
            return Err(NodeError::NoTransportForType(format!(
                "no addresses known for {}",
                peer_config.npub
            )));
        }

        let concrete: Vec<_> = candidates
            .into_iter()
            .filter(|addr| !(addr.transport == "udp" && addr.addr.eq_ignore_ascii_case("nat")))
            .collect();
        let has_alternative = concrete
            .iter()
            .any(|addr| !self.active_peer_matches_candidate(&peer_node_addr, addr));
        let attempt_candidates: Vec<_> = if has_alternative {
            concrete
                .into_iter()
                .filter(|addr| !self.active_peer_matches_candidate(&peer_node_addr, addr))
                .collect()
        } else if self.active_peer_needs_same_path_refresh(&peer_node_addr) {
            concrete
        } else {
            Vec::new()
        };

        if attempt_candidates.is_empty() {
            return Ok(false);
        }

        self.attempt_peer_address_list(peer_config, peer_identity, false, &attempt_candidates)
            .await?;
        Ok(true)
    }

    async fn peer_address_candidates(&self, peer_config: &PeerConfig) -> Vec<PeerAddress> {
        let static_addresses = self.static_peer_addresses(peer_config);
        let overlay_addresses = self
            .supervisor
            .nostr_rendezvous
            .nostr_peer_fallback_addresses(
                peer_config,
                &static_addresses,
                &self.config().node.rendezvous.nostr,
                Self::now_ms(),
            )
            .await;

        let mut candidates = Vec::with_capacity(overlay_addresses.len() + static_addresses.len());
        for addr in overlay_addresses.into_iter().chain(static_addresses) {
            if !candidates.iter().any(|existing: &PeerAddress| {
                existing.transport == addr.transport && existing.addr == addr.addr
            }) {
                candidates.push(addr);
            }
        }

        candidates.sort_by(|a, b| match (a.seen_at_ms, b.seen_at_ms) {
            (Some(a_ts), Some(b_ts)) => b_ts.cmp(&a_ts),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });
        candidates
    }

    pub(in crate::node) fn active_peer_candidate_is_fresh_enough_to_skip(
        &self,
        peer_node_addr: &NodeAddr,
        candidates: &[PeerAddress],
    ) -> bool {
        if !self.active_peer_matches_any_candidate(peer_node_addr, candidates) {
            return false;
        }
        !self.active_peer_needs_same_path_refresh(peer_node_addr)
    }

    fn active_peer_needs_same_path_refresh(&self, peer_node_addr: &NodeAddr) -> bool {
        let Some(peer) = self.peers.get(peer_node_addr) else {
            return false;
        };
        let stale_after_ms = self
            .config()
            .node
            .heartbeat_interval_secs
            .saturating_mul(1000)
            .max(1000);
        peer.idle_time(Self::now_ms()) > stale_after_ms
    }

    fn active_peer_matches_any_candidate(
        &self,
        peer_node_addr: &NodeAddr,
        candidates: &[PeerAddress],
    ) -> bool {
        candidates
            .iter()
            .any(|candidate| self.active_peer_matches_candidate(peer_node_addr, candidate))
    }

    fn active_peer_matches_candidate(
        &self,
        peer_node_addr: &NodeAddr,
        candidate: &PeerAddress,
    ) -> bool {
        let Some(peer) = self.peers.get(peer_node_addr) else {
            return false;
        };
        let Some(current_addr) = peer.current_addr() else {
            return false;
        };
        if peer
            .transport_id()
            .map(|id| self.supervisor.nostr_rendezvous.is_bootstrap_transport(&id))
            .unwrap_or(false)
        {
            return false;
        }
        let current_addr = current_addr.to_string();
        let current_transport = peer
            .transport_id()
            .and_then(|id| self.transports.get(&id))
            .map(|transport| transport.transport_type().name);

        candidate.addr == current_addr
            && current_transport
                .map(|transport| transport == candidate.transport)
                .unwrap_or(true)
    }

    // === Control API methods ===

    /// Connect to a peer via the control API.
    ///
    /// Creates an ephemeral peer connection (not persisted to config, no
    /// auto-reconnect). Reuses the same connection path as auto-connect
    /// peers. Returns JSON data on success or an error message.
    pub(crate) async fn api_connect(
        &mut self,
        npub: &str,
        address: &str,
        transport: &str,
    ) -> Result<serde_json::Value, String> {
        let peer_config = PeerConfig {
            npub: npub.to_string(),
            alias: None,
            addresses: vec![PeerAddress::new(transport, address)],
            connect_policy: ConnectPolicy::Manual,
            auto_reconnect: false,
            via_nostr: false,
        };

        // Pre-seed identity cache (same as initiate_peer_connections does)
        if let Ok(identity) = PeerIdentity::from_npub(npub) {
            self.peer_aliases
                .insert(*identity.node_addr(), identity.short_npub());
            self.register_identity(*identity.node_addr(), identity.pubkey_full());
        }

        self.initiate_peer_connection(&peer_config)
            .await
            .map(|()| {
                info!(
                    npub = %npub,
                    address = %address,
                    transport = %transport,
                    "API connect initiated"
                );
                serde_json::json!({
                    "npub": npub,
                    "address": address,
                    "transport": transport,
                })
            })
            .map_err(|e| e.to_string())
    }

    /// Disconnect a peer via the control API.
    ///
    /// Notifies the peer, removes it locally, and suppresses auto-reconnect.
    pub(crate) async fn api_disconnect(&mut self, npub: &str) -> Result<serde_json::Value, String> {
        let peer_identity =
            PeerIdentity::from_npub(npub).map_err(|e| format!("invalid npub '{npub}': {e}"))?;
        let node_addr = *peer_identity.node_addr();

        if !self.peers.contains_key(&node_addr) {
            return Err(format!("peer not found: {npub}"));
        }

        // Notify the peer before we tear down the link, so it drops its own
        // session and re-handshakes symmetrically rather than holding a stale
        // session that never re-emits its tree/filter announcements. The link
        // must still exist for the send, so this runs before removal.
        // Best-effort: a send failure must not block the local teardown.
        self.send_disconnect_to_peer(&node_addr, DisconnectReason::ConfigurationChange)
            .await;

        // Remove the peer (full cleanup: sessions, indices, links, tree, bloom)
        self.remove_active_peer(&node_addr);

        // Suppress any pending auto-reconnect
        self.peering.reconciler.retry_pending.remove(&node_addr);

        info!(npub = %npub, "API disconnect completed");

        Ok(serde_json::json!({
            "npub": npub,
            "disconnected": true,
        }))
    }

    /// Adopt an already-established UDP traversal and start the normal FIPS
    /// Noise handshake over it.
    ///
    /// This is intended for integration with an external rendezvous runtime
    /// that has already completed relay signaling, STUN observation, and UDP
    /// hole punching. After handoff, the adopted socket is owned by FIPS.
    pub async fn adopt_established_traversal(
        &mut self,
        traversal: EstablishedTraversal,
    ) -> Result<BootstrapHandoffResult, NodeError> {
        debug!(
            peer_npub = %traversal.peer_npub,
            session_id = %traversal.session_id,
            remote_addr = %traversal.remote_addr,
            "adopting established traversal socket"
        );

        if !self.supervisor.state.is_operational() {
            return Err(NodeError::NotStarted);
        }

        let packet_tx = self
            .supervisor
            .packet_tx
            .clone()
            .ok_or(NodeError::NotStarted)?;
        let peer_identity = PeerIdentity::from_npub(&traversal.peer_npub).map_err(|e| {
            NodeError::InvalidPeerNpub {
                npub: traversal.peer_npub.clone(),
                reason: e.to_string(),
            }
        })?;
        let peer_node_addr = *peer_identity.node_addr();
        if self.peers.contains_key(&peer_node_addr) {
            debug!(
                peer_npub = %traversal.peer_npub,
                "Ignoring NAT traversal handoff for already-connected peer"
            );
            return Err(NodeError::PeerAlreadyExists(peer_node_addr));
        }
        if self.is_connecting_to_peer(&peer_node_addr) {
            debug!(
                peer_npub = %traversal.peer_npub,
                "Ignoring NAT traversal handoff while peer handshake is already in progress"
            );
            return Err(NodeError::PeerAlreadyExists(peer_node_addr));
        }

        self.peer_aliases
            .insert(peer_node_addr, peer_identity.short_npub());
        self.register_identity(peer_node_addr, peer_identity.pubkey_full());

        let transport_id = self.allocate_transport_id();
        // Adopted ephemeral UDP transports inherit MTU + socket-buffer sizing
        // (and accept_connections / advertise flags) from the operator's
        // configured [transports.udp] when the bootstrap runtime doesn't
        // pass an explicit override. Lookup tries `transport_name` first
        // (covers the `Named` multi-listener variant) and falls back to the
        // unnamed `Single` listener, so single- and named-listener configs
        // both inherit cleanly.
        //
        // Tradeoff: `UdpConfig::default()` sets MTU 1280 (IPv6 minimum), the
        // only value guaranteed to survive arbitrary middlebox paths.
        // Inheriting a higher operator-chosen MTU means NAT-traversed flows
        // initially attempt that MTU and may black-hole on tighter paths
        // until reactive `MtuExceeded` recovery kicks in. Operators who
        // raise the primary MTU based on known-clean topology accept that
        // tradeoff; the silent drop on a too-low default was strictly
        // worse for the common case where the primary MTU is reachable.
        //
        // Bind / external address fields are cleared since the socket is
        // already bound.
        let inherited_config = traversal.transport_config.clone().unwrap_or_else(|| {
            let mut cfg = self
                .lookup_udp_config(traversal.transport_name.as_deref())
                .or_else(|| self.lookup_udp_config(None))
                .cloned()
                .unwrap_or_default();
            cfg.bind_addr = None;
            cfg.external_addr = None;
            cfg
        });
        let mut transport = crate::transport::udp::UdpTransport::new(
            transport_id,
            traversal.transport_name.clone(),
            inherited_config,
            packet_tx,
        );

        transport
            .adopt_socket_async(traversal.socket)
            .await
            .map_err(|e| NodeError::BootstrapHandoff(e.to_string()))?;

        let local_addr = transport.local_addr().ok_or_else(|| {
            NodeError::BootstrapHandoff("adopted UDP transport has no local address".into())
        })?;

        self.transports.insert(
            transport_id,
            crate::transport::TransportHandle::Udp(transport),
        );
        self.supervisor
            .nostr_rendezvous
            .insert_bootstrap_transport(transport_id, traversal.peer_npub.clone());

        let remote_addr = TransportAddr::from_string(&traversal.remote_addr.to_string());
        if let Err(err) = self
            .initiate_connection(transport_id, remote_addr.clone(), peer_identity)
            .await
        {
            self.supervisor
                .nostr_rendezvous
                .remove_bootstrap_transport(&transport_id);
            if let Some(mut handle) = self.transports.remove(&transport_id) {
                let _ = handle.stop().await;
            }
            return Err(err);
        }

        info!(
            peer = %self.peer_display_name(&peer_node_addr),
            transport_id = %transport_id,
            local_addr = %local_addr,
            remote_addr = %traversal.remote_addr,
            session_id = %traversal.session_id,
            "adopted NAT traversal socket; handshake initiated"
        );

        Ok(BootstrapHandoffResult {
            transport_id,
            local_addr,
            remote_addr: traversal.remote_addr,
            peer_node_addr,
            session_id: traversal.session_id,
        })
    }
}
