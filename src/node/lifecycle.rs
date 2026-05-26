//! Node lifecycle management: start, stop, and peer connection initiation.

use super::{Node, NodeError, NodeState};
use crate::config::{ConnectPolicy, PeerAddress, PeerConfig};
use crate::discovery::nostr::{
    ADVERT_IDENTIFIER, ADVERT_VERSION, BootstrapEvent, NostrDiscovery, OverlayAdvert,
    OverlayEndpointAdvert, OverlayTransportKind,
};
use crate::discovery::{BootstrapHandoffResult, EstablishedTraversal};
use crate::node::acl::PeerAclContext;
use crate::node::wire::build_msg1;
use crate::peer::PeerConnection;
use crate::protocol::{Disconnect, DisconnectReason};
use crate::transport::{Link, LinkDirection, LinkId, TransportAddr, TransportId, packet_channel};
use crate::upper::tun::{TunDevice, TunState, run_tun_reader, shutdown_tun_interface};
use crate::{NodeAddr, PeerIdentity};
use std::collections::HashSet;
use std::thread;
use std::time::Duration;
use tracing::{debug, info, warn};

const OPEN_DISCOVERY_RETRY_LIFETIME_MULTIPLIER: u64 = 2;

impl Node {
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
            .config
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

        // Collect peer configs to avoid borrow conflicts
        let peer_configs: Vec<_> = self.config.auto_connect_peers().cloned().collect();

        if peer_configs.is_empty() {
            debug!("No static peers configured");
            return;
        }

        debug!(
            count = peer_configs.len(),
            "Initiating static peer connections"
        );

        for peer_config in peer_configs {
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
                if let Ok(peer_identity) = PeerIdentity::from_npub(&peer_config.npub) {
                    self.schedule_retry(*peer_identity.node_addr(), Self::now_ms());
                }
                // No-transport failures most often mean the cached overlay
                // advert is pointing at a dead post-NAT-rebind address. The
                // advert cache is read-only inside fetch_advert, so retries
                // would loop on the same dead address until expiry. Force a
                // re-fetch so the next retry tick picks up fresh endpoints.
                if matches!(e, crate::node::NodeError::NoTransportForType(_))
                    && let Some(bootstrap) = self.nostr_discovery.clone()
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

    /// Initiate a connection to a peer on a specific transport and address.
    ///
    /// For connectionless transports (UDP, Ethernet): allocates a link, starts
    /// the Noise XX handshake, sends msg1, and registers the connection for
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
        peer_identity: Option<PeerIdentity>,
    ) -> Result<(), NodeError> {
        if let Some(ref identity) = peer_identity {
            self.authorize_peer(
                identity,
                PeerAclContext::OutboundConnect,
                transport_id,
                &remote_addr,
            )?;
        }

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
                Duration::from_millis(self.config.node.base_rtt_ms),
            )
        } else {
            Link::connectionless(
                link_id,
                transport_id,
                remote_addr.clone(),
                LinkDirection::Outbound,
                Duration::from_millis(self.config.node.base_rtt_ms),
            )
        };

        self.links.insert(link_id, link);

        // Add reverse lookup for packet dispatch
        self.addr_to_link
            .insert((transport_id, remote_addr.clone()), link_id);

        if is_connection_oriented {
            // Connection-oriented: start non-blocking connect, defer handshake
            if let Some(transport) = self.transports.get(&transport_id) {
                match transport.connect(&remote_addr).await {
                    Ok(()) => {
                        if let Some(ref id) = peer_identity {
                            debug!(
                                peer = %self.peer_display_name(id.node_addr()),
                                transport_id = %transport_id,
                                remote_addr = %remote_addr,
                                link_id = %link_id,
                                "Transport connect initiated (non-blocking)"
                            );
                        } else {
                            debug!(
                                transport_id = %transport_id,
                                remote_addr = %remote_addr,
                                link_id = %link_id,
                                "Transport connect initiated (anonymous discovery)"
                            );
                        }
                        self.pending_connects.push(super::PendingConnect {
                            link_id,
                            transport_id,
                            remote_addr,
                            peer_identity,
                        });
                    }
                    Err(e) => {
                        // Clean up link
                        self.links.remove(&link_id);
                        self.addr_to_link.remove(&(transport_id, remote_addr));
                        return Err(NodeError::TransportError(e.to_string()));
                    }
                }
            }
            Ok(())
        } else {
            // Connectionless: proceed with immediate handshake
            self.start_handshake(link_id, transport_id, remote_addr, peer_identity)
                .await
        }
    }

    /// Start the Noise handshake on a link and send msg1.
    ///
    /// Called immediately for connectionless transports, or after the
    /// transport connection is established for connection-oriented transports.
    pub(super) async fn start_handshake(
        &mut self,
        link_id: LinkId,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        peer_identity: Option<PeerIdentity>,
    ) -> Result<(), NodeError> {
        // Create connection in handshake phase. Anonymous discovery
        // (no peer_identity) leaves identity to be learned from XX msg2.
        let current_time_ms = Self::now_ms();
        let mut connection = if let Some(identity) = peer_identity {
            PeerConnection::outbound(link_id, identity, current_time_ms)
        } else {
            PeerConnection::outbound_anonymous(link_id, current_time_ms)
        };

        // Allocate a session index for this handshake
        let our_index = match self.index_allocator.allocate() {
            Ok(idx) => idx,
            Err(e) => {
                // Clean up the link we just created
                self.links.remove(&link_id);
                self.addr_to_link.remove(&(transport_id, remote_addr));
                return Err(NodeError::IndexAllocationFailed(e.to_string()));
            }
        };

        // Start the Noise handshake and get message 1
        let our_keypair = self.identity.keypair();
        let noise_msg1 =
            match connection.start_handshake(our_keypair, self.startup_epoch, current_time_ms) {
                Ok(msg) => msg,
                Err(e) => {
                    // Clean up the index and link
                    let _ = self.index_allocator.free(our_index);
                    self.links.remove(&link_id);
                    self.addr_to_link.remove(&(transport_id, remote_addr));
                    return Err(NodeError::HandshakeFailed(e.to_string()));
                }
            };

        // Set index and transport info on the connection
        connection.set_our_index(our_index);
        connection.set_transport_id(transport_id);
        connection.set_source_addr(remote_addr.clone());

        // Build wire format msg1: [0x01][sender_idx:4 LE][noise_msg1:82]
        let wire_msg1 = build_msg1(our_index, &noise_msg1);

        if let Some(id) = connection.expected_identity() {
            debug!(
                peer = %self.peer_display_name(id.node_addr()),
                transport_id = %transport_id,
                remote_addr = %remote_addr,
                link_id = %link_id,
                our_index = %our_index,
                "Connection initiated"
            );
        } else {
            debug!(
                transport_id = %transport_id,
                remote_addr = %remote_addr,
                link_id = %link_id,
                our_index = %our_index,
                "Anonymous discovery connection initiated"
            );
        }

        // Store msg1 for resend and schedule first resend
        let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
        connection.set_handshake_msg1(wire_msg1.clone(), current_time_ms + resend_interval);

        // Track in pending_outbound for msg2 dispatch
        self.pending_outbound
            .insert((transport_id, our_index.as_u32()), link_id);
        self.connections.insert(link_id, connection);

        // Send the wire format handshake message
        if let Some(transport) = self.transports.get(&transport_id) {
            match transport.send(&remote_addr, &wire_msg1).await {
                Ok(bytes) => {
                    debug!(
                        link_id = %link_id,
                        our_index = %our_index,
                        bytes,
                        "Sent Noise handshake message 1 (wire format)"
                    );
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

        Ok(())
    }

    /// Poll all transports for discovered peers and auto-connect.
    ///
    /// Called from the tick handler. Iterates operational transports,
    /// drains their discovery buffers, and initiates connections to
    /// newly discovered peers (if auto_connect is enabled).
    pub(super) async fn poll_transport_discovery(&mut self) {
        // Collect discoveries first to avoid borrow conflict with self
        let mut to_connect: Vec<(TransportId, TransportAddr, Option<PeerIdentity>)> = Vec::new();

        for (transport_id, transport) in &self.transports {
            if !transport.is_operational() {
                continue;
            }
            if !transport.auto_connect() {
                // Still drain the buffer so it doesn't grow unbounded
                let _ = transport.discover();
                continue;
            }
            let discovered = match transport.discover() {
                Ok(peers) => peers,
                Err(_) => continue,
            };
            for peer in discovered {
                if let Some(pubkey) = peer.pubkey_hint {
                    // Identity known from discovery (e.g., config-based auto-connect)
                    let identity = PeerIdentity::from_pubkey(pubkey);
                    let node_addr = *identity.node_addr();

                    // Skip self
                    if node_addr == *self.identity.node_addr() {
                        continue;
                    }
                    // Skip if already connected
                    if self.peers.contains_key(&node_addr) {
                        continue;
                    }
                    // Skip if connection already in progress
                    let connecting = self.connections.values().any(|c| {
                        c.expected_identity()
                            .map(|id| id.node_addr() == &node_addr)
                            .unwrap_or(false)
                    });
                    if connecting {
                        continue;
                    }

                    to_connect.push((*transport_id, peer.addr, Some(identity)));
                } else {
                    // Anonymous discovery (shared-media beacon without identity).
                    // Identity will be learned from XX handshake msg2.
                    // Dedup by transport address — skip if link already exists.
                    if self
                        .addr_to_link
                        .contains_key(&(*transport_id, peer.addr.clone()))
                    {
                        continue;
                    }

                    to_connect.push((*transport_id, peer.addr, None));
                }
            }
        }

        for (transport_id, remote_addr, identity) in to_connect {
            if let Some(ref id) = identity {
                info!(
                    peer = %self.peer_display_name(id.node_addr()),
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    "Auto-connecting to discovered peer"
                );
            } else {
                info!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    "Auto-connecting to anonymous discovered peer"
                );
            }
            if let Err(e) = self
                .initiate_connection(transport_id, remote_addr, identity)
                .await
            {
                warn!(error = %e, "Failed to auto-connect to discovered peer");
            }
        }
    }

    pub(super) async fn poll_nostr_discovery(&mut self) {
        let Some(bootstrap) = self.nostr_discovery.clone() else {
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
                            max_peers = self.max_peers,
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
                            let our_addr = self.identity.node_addr();
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
                                self.schedule_retry(*peer_identity.node_addr(), Self::now_ms());
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
                                crate::discovery::nostr::NostrRefetchOutcome::Evicted => info!(
                                    npub = %npub,
                                    "stale-advert sweep: peer evicted from advert cache"
                                ),
                                crate::discovery::nostr::NostrRefetchOutcome::Refreshed => info!(
                                    npub = %npub,
                                    "stale-advert sweep: peer republished, cache refreshed and streak reset"
                                ),
                                crate::discovery::nostr::NostrRefetchOutcome::SameAdvert => debug!(
                                    npub = %npub,
                                    "stale-advert sweep: advert unchanged, cooldown stands"
                                ),
                                crate::discovery::nostr::NostrRefetchOutcome::Skipped => debug!(
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

                    self.schedule_retry(node_addr, now_ms);
                    if let Some(cooldown_until_ms) = decision.cooldown_until_ms
                        && let Some(state) = self.retry_pending.get_mut(&node_addr)
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

    /// Poll pending transport connects and initiate handshakes for ready ones.
    ///
    /// Called from the tick handler. For each pending connect, queries the
    /// transport's connection state. When a connection is established,
    /// marks the link as Connected and starts the Noise handshake.
    /// Failed connections are cleaned up and scheduled for retry.
    pub(super) async fn poll_pending_connects(&mut self) {
        if self.pending_connects.is_empty() {
            return;
        }

        let mut completed = Vec::new();

        for (i, pending) in self.pending_connects.iter().enumerate() {
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
            let pending = self.pending_connects.remove(i);

            if success {
                // Mark link as Connected
                if let Some(link) = self.links.get_mut(&pending.link_id) {
                    link.set_connected();
                }

                debug!(
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
                    // Clean up link on handshake failure
                    self.remove_link(&pending.link_id);
                }
            } else {
                let reason = reason.unwrap_or_default();
                warn!(
                    transport_id = %pending.transport_id,
                    remote_addr = %pending.remote_addr,
                    link_id = %pending.link_id,
                    reason = %reason,
                    "Transport connect failed"
                );

                // Clean up link and schedule retry. Anonymous discovery
                // connections (no expected identity) don't retry —
                // they'll be rediscovered via the shared-medium beacon.
                self.remove_link(&pending.link_id);
                self.links.remove(&pending.link_id);
                if let Some(ref id) = pending.peer_identity {
                    self.schedule_retry(*id.node_addr(), Self::now_ms());
                }
            }
        }
    }

    // === State Transitions ===

    /// Start the node.
    ///
    /// Initializes the TUN interface (if configured), spawns I/O threads,
    /// and transitions to the Running state.
    pub async fn start(&mut self) -> Result<(), NodeError> {
        if !self.state.can_start() {
            return Err(NodeError::AlreadyStarted);
        }
        self.state = NodeState::Starting;

        // Create packet channel for transport -> Node communication
        let packet_buffer_size = self.config.node.buffers.packet_channel;
        let (packet_tx, packet_rx) = packet_channel(packet_buffer_size);
        self.packet_tx = Some(packet_tx.clone());
        self.packet_rx = Some(packet_rx);

        // Initialize transports first (before TUN, before Nostr discovery).
        let transport_handles = self.create_transports(&packet_tx).await;

        for mut handle in transport_handles {
            let transport_id = handle.transport_id();
            let transport_type = handle.transport_type().name;
            let name = handle.name().map(|s| s.to_string());

            match handle.start().await {
                Ok(()) => {
                    self.transports.insert(transport_id, handle);
                }
                Err(e) => {
                    if let Some(ref n) = name {
                        warn!(transport_type, name = %n, error = %e, "Transport failed to start");
                    } else {
                        warn!(transport_type, error = %e, "Transport failed to start");
                    }
                }
            }
        }

        if !self.transports.is_empty() {
            info!(count = self.transports.len(), "Transports initialized");
        }

        // Spawn the off-task FMP-encrypt + UDP-send worker pool.
        // Unix only — the worker issues sendmmsg(2) / sendmsg+UDP_GSO
        // calls on raw fds via `AsRawFd`, a unix-only trait. Worker
        // count defaults to num_cpus, overridable via FIPS_ENCRYPT_WORKERS.
        // Hash-by-destination pins a TCP flow to one worker (preserves
        // wire ordering); additional workers light up under multi-flow load.
        #[cfg(unix)]
        {
            let cpu_default = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
                .max(1);
            let encrypt_worker_count: usize = std::env::var("FIPS_ENCRYPT_WORKERS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(cpu_default)
                .max(1);
            self.encrypt_workers = Some(super::encrypt_worker::EncryptWorkerPool::spawn(
                encrypt_worker_count,
            ));
            info!(
                workers = encrypt_worker_count,
                "Spawned FMP-encrypt worker pool"
            );

            // `FIPS_DECRYPT_WORKERS=0` disables the pool entirely and
            // forces the in-line rx_loop decrypt path (useful as an A/B
            // against the worker pipeline). Any non-zero value (env or
            // default) spawns the shard-owned decrypt pool.
            let decrypt_worker_count: usize = std::env::var("FIPS_DECRYPT_WORKERS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(cpu_default);
            if decrypt_worker_count == 0 {
                info!("FIPS_DECRYPT_WORKERS=0 → in-line decrypt in rx_loop");
            } else {
                self.decrypt_workers = Some(super::decrypt_worker::DecryptWorkerPool::spawn(
                    decrypt_worker_count,
                ));
                info!(
                    workers = decrypt_worker_count,
                    "Spawned FMP-decrypt worker pool"
                );
            }
        }

        if self.config.node.discovery.nostr.enabled {
            match NostrDiscovery::start(&self.identity, self.config.node.discovery.nostr.clone())
                .await
            {
                Ok(runtime) => {
                    if let Err(err) = self.refresh_overlay_advert(&runtime).await {
                        warn!(error = %err, "Failed to publish initial Nostr overlay advert");
                    }
                    self.nostr_discovery = Some(runtime);
                    self.nostr_discovery_started_at_ms = Some(Self::now_ms());
                    info!("Nostr overlay discovery enabled");
                }
                Err(err) => {
                    warn!(error = %err, "Failed to start Nostr overlay discovery");
                }
            }
        }

        // Connect to static peers before TUN is active
        // This allows handshake messages to be sent before we start accepting packets
        self.initiate_peer_connections().await;

        // Initialize TUN interface last, after transports and peers are ready
        if self.config.tun.enabled {
            let address = *self.identity.address();
            match TunDevice::create(&self.config.tun, address).await {
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
                            return Err(NodeError::Tun(crate::upper::tun::TunError::Configure(
                                "failed to create shutdown pipe".into(),
                            )));
                        }
                        (fds[0], fds[1])
                    };

                    // Create writer (dups the fd for independent write access).
                    // Pass path_mtu_lookup so inbound SYN-ACK clamp can read
                    // per-destination path MTU learned via discovery.
                    let (writer, tun_tx) =
                        device.create_writer(max_mss, self.path_mtu_lookup.clone())?;

                    // Spawn writer thread
                    let writer_handle = thread::spawn(move || {
                        writer.run();
                    });

                    // Clone tun_tx for the reader
                    let reader_tun_tx = tun_tx.clone();

                    // Create outbound channel for TUN reader → Node
                    let tun_channel_size = self.config.node.buffers.tun_channel;
                    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(tun_channel_size);

                    // Spawn reader thread
                    let transport_mtu = self.transport_mtu();
                    let path_mtu_lookup = self.path_mtu_lookup.clone();
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
                    });

                    self.tun_state = TunState::Active;
                    self.tun_name = Some(name);
                    self.tun_tx = Some(tun_tx);
                    self.tun_outbound_rx = Some(outbound_rx);
                    self.tun_reader_handle = Some(reader_handle);
                    self.tun_writer_handle = Some(writer_handle);
                    #[cfg(target_os = "macos")]
                    {
                        self.tun_shutdown_fd = Some(shutdown_write_fd);
                    }
                }
                Err(e) => {
                    self.tun_state = TunState::Failed;
                    warn!(error = %e, "Failed to initialize TUN, continuing without it");
                }
            }
        }

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
        if self.config.dns.enabled {
            let addr_str = self.config.dns.bind_addr();
            match addr_str.parse::<std::net::IpAddr>() {
                Ok(ip) => {
                    let bind = std::net::SocketAddr::new(ip, self.config.dns.port());
                    match Self::bind_dns_socket(bind) {
                        Ok(socket) => {
                            let dns_channel_size = self.config.node.buffers.dns_channel;
                            let (identity_tx, identity_rx) =
                                tokio::sync::mpsc::channel(dns_channel_size);
                            let dns_ttl = self.config.dns.ttl();
                            let base_hosts = crate::upper::hosts::HostMap::from_peer_configs(
                                self.config.peers(),
                            );
                            let hosts_path =
                                std::path::PathBuf::from(crate::upper::hosts::DEFAULT_HOSTS_PATH);
                            let reloader =
                                crate::upper::hosts::HostMapReloader::new(base_hosts, hosts_path);
                            // Resolve the TUN ifindex so the responder can
                            // drop queries arriving on the mesh interface
                            // (fips0). Without this, the `::` bind exposes
                            // /etc/fips/hosts alias probing to any mesh peer.
                            // When TUN isn't enabled or the name can't be
                            // resolved, `None` disables the filter (there
                            // is no mesh surface to defend anyway).
                            let mesh_ifindex = Self::lookup_mesh_ifindex(self.config.tun.name());
                            info!(
                                bind = %bind,
                                hosts = reloader.hosts().len(),
                                mesh_ifindex = ?mesh_ifindex,
                                "DNS responder started for .fips domain (auto-reload enabled)"
                            );
                            let handle = tokio::spawn(crate::upper::dns::run_dns_responder(
                                socket,
                                identity_tx,
                                dns_ttl,
                                reloader,
                                mesh_ifindex,
                            ));
                            self.dns_identity_rx = Some(identity_rx);
                            self.dns_task = Some(handle);
                        }
                        Err(e) => {
                            warn!(bind = %bind, error = %e, "Failed to start DNS responder");
                        }
                    }
                }
                Err(e) => {
                    warn!(addr = %addr_str, error = %e, "Invalid dns.bind_addr; DNS responder not started");
                }
            }
        }

        self.state = NodeState::Running;
        info!("Node started:");
        info!("       state: {}", self.state);
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
        if !self.state.can_stop() {
            return Err(NodeError::NotStarted);
        }
        self.state = NodeState::Stopping;
        info!(state = %self.state, "Node stopping");

        // Stop DNS responder
        if let Some(handle) = self.dns_task.take() {
            handle.abort();
            debug!("DNS responder stopped");
        }

        // Send disconnect notifications to all active peers before closing transports
        self.send_disconnect_to_all_peers(DisconnectReason::Shutdown)
            .await;

        // Stop Nostr overlay discovery background work and withdraw any advert.
        if let Some(bootstrap) = self.nostr_discovery.take()
            && let Err(e) = bootstrap.shutdown().await
        {
            warn!(error = %e, "Failed to shutdown Nostr overlay discovery");
        }

        // Shutdown transports (they're packet producers)
        let transport_ids: Vec<_> = self.transports.keys().cloned().collect();
        for transport_id in transport_ids {
            if let Some(mut handle) = self.transports.remove(&transport_id) {
                let transport_type = handle.transport_type().name;
                match handle.stop().await {
                    Ok(()) => {
                        info!(transport_id = %transport_id, transport_type, "Transport stopped");
                    }
                    Err(e) => {
                        warn!(
                            transport_id = %transport_id,
                            transport_type,
                            error = %e,
                            "Transport stop failed"
                        );
                    }
                }
            }
        }

        // Drop packet channels
        self.packet_tx.take();
        self.packet_rx.take();

        // Shutdown TUN interface
        if let Some(name) = self.tun_name.take() {
            info!(name = %name, "Shutting down TUN interface");

            // Drop the tun_tx to signal the writer to stop
            self.tun_tx.take();

            // Delete the interface (on Linux, causes reader to get EFAULT)
            if let Err(e) = shutdown_tun_interface(&name).await {
                warn!(name = %name, error = %e, "Failed to shutdown TUN interface");
            }

            // On macOS, signal the reader thread to exit by writing to the
            // shutdown pipe. The reader's select() will wake up and break.
            #[cfg(target_os = "macos")]
            if let Some(fd) = self.tun_shutdown_fd.take() {
                unsafe {
                    libc::write(fd, b"x".as_ptr() as *const libc::c_void, 1);
                    libc::close(fd);
                }
            }

            // Wait for threads to finish
            if let Some(handle) = self.tun_reader_handle.take() {
                let _ = handle.join();
            }
            if let Some(handle) = self.tun_writer_handle.take() {
                let _ = handle.join();
            }

            self.tun_state = TunState::Disabled;
        }

        self.state = NodeState::Stopped;
        info!(state = %self.state, "Node stopped");
        Ok(())
    }

    /// Send disconnect notifications to all active peers.
    ///
    /// Best-effort: send failures are logged and ignored since the transport
    /// may already be degraded. This runs before transports are shut down.
    async fn send_disconnect_to_all_peers(&mut self, reason: DisconnectReason) {
        let disconnect = Disconnect::new(reason);
        let plaintext = disconnect.encode();

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
            match self
                .send_encrypted_link_message(node_addr, &plaintext)
                .await
            {
                Ok(()) => sent += 1,
                Err(e) => {
                    debug!(
                        peer = %self.peer_display_name(node_addr),
                        error = %e,
                        "Failed to send disconnect (transport may be down)"
                    );
                }
            }
        }

        info!(sent, total = peer_addrs.len(), reason = %reason, "Sent disconnect notifications");
    }

    fn static_peer_addresses(&self, peer_config: &PeerConfig) -> Vec<PeerAddress> {
        peer_config
            .addresses_by_priority()
            .into_iter()
            .cloned()
            .collect()
    }

    async fn nostr_peer_fallback_addresses(
        &self,
        peer_config: &PeerConfig,
        existing: &[PeerAddress],
    ) -> Vec<PeerAddress> {
        if !self.config.node.discovery.nostr.enabled
            || !peer_config.via_nostr
            || self.config.node.discovery.nostr.policy
                == crate::config::NostrDiscoveryPolicy::Disabled
        {
            return Vec::new();
        }

        let Some(bootstrap) = self.nostr_discovery.clone() else {
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
        for endpoint in endpoints {
            let Some(candidate) = Self::overlay_endpoint_to_peer_address(&endpoint, next_priority)
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

    fn overlay_endpoint_to_peer_address(
        endpoint: &OverlayEndpointAdvert,
        priority: u8,
    ) -> Option<PeerAddress> {
        let transport = match endpoint.transport {
            OverlayTransportKind::Udp => "udp",
            OverlayTransportKind::Tcp => "tcp",
            OverlayTransportKind::Tor => "tor",
        };
        Some(PeerAddress::with_priority(
            transport,
            endpoint.addr.clone(),
            priority,
        ))
    }

    async fn attempt_peer_address_list(
        &mut self,
        peer_config: &PeerConfig,
        peer_identity: PeerIdentity,
        allow_bootstrap_nat: bool,
        addresses: &[PeerAddress],
    ) -> Result<(), NodeError> {
        for addr in addresses {
            if addr.transport == "udp" && addr.addr.eq_ignore_ascii_case("nat") {
                if !allow_bootstrap_nat {
                    continue;
                }
                let Some(bootstrap) = self.nostr_discovery.clone() else {
                    debug!(npub = %peer_config.npub, "No Nostr overlay runtime for udp:nat address");
                    continue;
                };
                bootstrap.request_connect(peer_config.clone()).await;
                info!(npub = %peer_config.npub, "Started Nostr UDP NAT traversal attempt");
                return Ok(());
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
                let tid = match self.find_transport_for_type(&addr.transport) {
                    Some(id) => id,
                    None => {
                        debug!(
                            transport = %addr.transport,
                            addr = %addr.addr,
                            "No operational transport for address type"
                        );
                        continue;
                    }
                };
                (tid, TransportAddr::from_string(&addr.addr))
            };

            match self
                .initiate_connection(transport_id, remote_addr, Some(peer_identity))
                .await
            {
                Ok(()) => return Ok(()),
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

        Err(NodeError::NoTransportForType(format!(
            "no operational transport for any of {}'s addresses",
            peer_config.npub
        )))
    }

    async fn queue_open_discovery_retries(&mut self, bootstrap: &std::sync::Arc<NostrDiscovery>) {
        self.run_open_discovery_sweep(bootstrap, None, "per-tick")
            .await;
    }

    /// Open-discovery cache sweep. Iterates the cached overlay adverts and
    /// queues retries for non-configured, not-yet-connected peers.
    ///
    /// `max_age_secs`, if set, filters out adverts whose `created_at` is
    /// older than `now - max_age_secs`. The per-tick sweep passes `None`
    /// (relies on the cache's own `valid_until_ms` filter); the one-shot
    /// startup sweep passes `Some(startup_sweep_max_age_secs)`.
    ///
    /// `caller` is a short label included in log lines so per-tick and
    /// startup sweeps are distinguishable in operator-facing logs.
    pub(in crate::node) async fn run_open_discovery_sweep(
        &mut self,
        bootstrap: &std::sync::Arc<NostrDiscovery>,
        max_age_secs: Option<u64>,
        caller: &'static str,
    ) {
        if !self.config.node.discovery.nostr.enabled
            || self.config.node.discovery.nostr.policy != crate::config::NostrDiscoveryPolicy::Open
        {
            return;
        }

        let configured_npubs = self
            .config
            .peers()
            .iter()
            .map(|peer| peer.npub.clone())
            .collect::<HashSet<_>>();
        let now_ms = Self::now_ms();
        let now_secs = now_ms / 1000;
        let mut enqueue_budget = self.open_discovery_enqueue_budget(&configured_npubs);
        if enqueue_budget == 0 {
            debug!(
                caller = %caller,
                "open-discovery sweep: enqueue budget is 0, skipping"
            );
            return;
        }

        let candidates = bootstrap.cached_open_discovery_candidates(64).await;
        let cached_count = candidates.len();
        let mut enqueued = 0usize;
        let mut skipped_age = 0usize;
        let mut skipped_configured = 0usize;
        let mut skipped_self = 0usize;
        let mut skipped_connected = 0usize;
        let mut skipped_retry_pending = 0usize;
        let mut skipped_connecting = 0usize;
        let mut skipped_no_endpoints = 0usize;
        let mut skipped_invalid_npub = 0usize;
        let mut skipped_cooldown = 0usize;

        for (npub, endpoints, created_at_secs) in candidates {
            if enqueue_budget == 0 {
                break;
            }

            if let Some(max_age) = max_age_secs
                && now_secs.saturating_sub(created_at_secs) > max_age
            {
                skipped_age = skipped_age.saturating_add(1);
                continue;
            }

            if configured_npubs.contains(&npub) {
                skipped_configured = skipped_configured.saturating_add(1);
                continue;
            }

            let peer_identity = match PeerIdentity::from_npub(&npub) {
                Ok(identity) => identity,
                Err(_) => {
                    skipped_invalid_npub = skipped_invalid_npub.saturating_add(1);
                    continue;
                }
            };
            let node_addr = *peer_identity.node_addr();
            if node_addr == *self.identity.node_addr() {
                skipped_self = skipped_self.saturating_add(1);
                continue;
            }
            if self.peers.contains_key(&node_addr) {
                skipped_connected = skipped_connected.saturating_add(1);
                continue;
            }
            if self.retry_pending.contains_key(&node_addr) {
                skipped_retry_pending = skipped_retry_pending.saturating_add(1);
                continue;
            }
            if bootstrap.cooldown_until(&npub, now_ms).is_some() {
                skipped_cooldown = skipped_cooldown.saturating_add(1);
                continue;
            }
            let connecting = self.connections.values().any(|conn| {
                conn.expected_identity()
                    .map(|id| id.node_addr() == &node_addr)
                    .unwrap_or(false)
            });
            if connecting {
                skipped_connecting = skipped_connecting.saturating_add(1);
                continue;
            }

            let mut addresses = Vec::new();
            let mut priority = 120u8;
            for endpoint in endpoints {
                let Some(candidate) = Self::overlay_endpoint_to_peer_address(&endpoint, priority)
                else {
                    continue;
                };
                if addresses.iter().any(|existing: &PeerAddress| {
                    existing.transport == candidate.transport && existing.addr == candidate.addr
                }) {
                    continue;
                }
                addresses.push(candidate);
                priority = priority.saturating_add(1);
            }
            if addresses.is_empty() {
                skipped_no_endpoints = skipped_no_endpoints.saturating_add(1);
                continue;
            }

            self.peer_aliases
                .entry(node_addr)
                .or_insert_with(|| peer_identity.short_npub());
            self.register_identity(node_addr, peer_identity.pubkey_full());

            let mut state = super::retry::RetryState::new(PeerConfig {
                npub: npub.clone(),
                alias: None,
                addresses,
                connect_policy: ConnectPolicy::AutoConnect,
                auto_reconnect: true,
                via_nostr: false,
            });
            state.reconnect = false;
            state.retry_after_ms = now_ms;
            state.expires_at_ms = Some(self.open_discovery_retry_expires_at_ms(now_ms));
            self.retry_pending.insert(node_addr, state);
            info!(
                caller = %caller,
                peer = %peer_identity.short_npub(),
                advert_age_secs = now_secs.saturating_sub(created_at_secs),
                "open-discovery sweep: queued retry for cached advert"
            );
            enqueue_budget = enqueue_budget.saturating_sub(1);
            enqueued = enqueued.saturating_add(1);
        }

        // Always log a one-line summary on the startup sweep so operators
        // can verify it ran. Per-tick sweeps are noisier; only summarize
        // when something happened.
        let total_skipped = skipped_age
            + skipped_configured
            + skipped_self
            + skipped_connected
            + skipped_retry_pending
            + skipped_connecting
            + skipped_no_endpoints
            + skipped_invalid_npub
            + skipped_cooldown;
        let should_summarize = caller == "startup" || enqueued > 0;
        if should_summarize {
            info!(
                caller = %caller,
                cached = cached_count,
                queued = enqueued,
                skipped_age = skipped_age,
                skipped_configured = skipped_configured,
                skipped_self = skipped_self,
                skipped_connected = skipped_connected,
                skipped_retry_pending = skipped_retry_pending,
                skipped_connecting = skipped_connecting,
                skipped_no_endpoints = skipped_no_endpoints,
                skipped_invalid_npub = skipped_invalid_npub,
                skipped_cooldown = skipped_cooldown,
                skipped_total = total_skipped,
                "open-discovery sweep complete"
            );
        }
    }

    /// One-shot startup sweep: runs once after the configured settle
    /// delay, iterating the cached overlay adverts and queueing retries
    /// for any peer with a recent enough advert that we haven't already
    /// configured statically or established a link to.
    ///
    /// Gated identically to [`run_open_discovery_sweep`]: requires
    /// `node.discovery.nostr.enabled` and `policy == open`.
    async fn maybe_run_startup_open_discovery_sweep(
        &mut self,
        bootstrap: &std::sync::Arc<NostrDiscovery>,
    ) {
        if self.startup_open_discovery_sweep_done {
            return;
        }
        if !self.config.node.discovery.nostr.enabled
            || self.config.node.discovery.nostr.policy != crate::config::NostrDiscoveryPolicy::Open
        {
            // Mark done so we don't keep re-checking on every tick.
            self.startup_open_discovery_sweep_done = true;
            return;
        }
        let Some(started_at_ms) = self.nostr_discovery_started_at_ms else {
            return;
        };
        let now_ms = Self::now_ms();
        let delay_ms = self
            .config
            .node
            .discovery
            .nostr
            .startup_sweep_delay_secs
            .saturating_mul(1000);
        if now_ms < started_at_ms.saturating_add(delay_ms) {
            return;
        }

        let max_age_secs = self.config.node.discovery.nostr.startup_sweep_max_age_secs;
        self.run_open_discovery_sweep(bootstrap, Some(max_age_secs), "startup")
            .await;
        self.startup_open_discovery_sweep_done = true;
    }

    fn available_outbound_slots(&self) -> usize {
        let connection_used = self
            .connections
            .len()
            .saturating_add(self.pending_connects.len());
        let connection_slots = if self.max_connections == 0 {
            usize::MAX
        } else {
            self.max_connections.saturating_sub(connection_used)
        };

        let peer_slots = if self.max_peers == 0 {
            usize::MAX
        } else {
            self.max_peers.saturating_sub(self.peers.len())
        };

        connection_slots.min(peer_slots)
    }

    fn open_discovery_enqueue_budget(&self, configured_npubs: &HashSet<String>) -> usize {
        let current_open_discovery_pending = self
            .retry_pending
            .values()
            .filter(|state| !configured_npubs.contains(&state.peer_config.npub))
            .count();

        let cap_remaining = self
            .config
            .node
            .discovery
            .nostr
            .open_discovery_max_pending
            .saturating_sub(current_open_discovery_pending);

        cap_remaining.min(self.available_outbound_slots())
    }

    fn open_discovery_retry_expires_at_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_add(
            self.config
                .node
                .discovery
                .nostr
                .advert_ttl_secs
                .saturating_mul(1000)
                .saturating_mul(OPEN_DISCOVERY_RETRY_LIFETIME_MULTIPLIER),
        )
    }

    async fn build_overlay_advert(
        &self,
        bootstrap: &std::sync::Arc<NostrDiscovery>,
    ) -> Option<OverlayAdvert> {
        if !self.config.node.discovery.nostr.enabled {
            return None;
        }

        let mut endpoints = Vec::new();
        let mut has_udp_nat = false;

        for handle in self.transports.values() {
            if !handle.is_operational() {
                continue;
            }

            match handle.transport_type().name {
                "udp" => {
                    let Some(cfg) = self.lookup_udp_config(handle.name()) else {
                        continue;
                    };
                    if !cfg.advertise_on_nostr() {
                        continue;
                    }
                    if cfg.is_public() {
                        // Precedence:
                        // 1. operator-supplied `external_addr` (skips STUN)
                        // 2. non-wildcard `local_addr` (operator bound to
                        //    a specific public IP directly)
                        // 3. STUN auto-discovery against ephemeral socket
                        // 4. loud warn + omit endpoint
                        if let Some(explicit) = cfg.external_advert_addr() {
                            endpoints.push(OverlayEndpointAdvert {
                                transport: OverlayTransportKind::Udp,
                                addr: explicit.to_string(),
                            });
                        } else {
                            match handle.local_addr() {
                                Some(addr) if !addr.ip().is_unspecified() => {
                                    endpoints.push(OverlayEndpointAdvert {
                                        transport: OverlayTransportKind::Udp,
                                        addr: addr.to_string(),
                                    });
                                }
                                Some(addr) => {
                                    let key = handle.transport_id().as_u32();
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
                                            node.discovery.nostr.stun_servers is reachable"
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
                "tcp" => {
                    let Some(cfg) = self.lookup_tcp_config(handle.name()) else {
                        continue;
                    };
                    if !cfg.advertise_on_nostr() {
                        continue;
                    }
                    // Precedence:
                    // 1. operator-supplied `external_addr` (only path that
                    //    works on cloud-NAT setups where the public IP is
                    //    not on a host interface).
                    // 2. non-wildcard `local_addr` (operator bound to a
                    //    specific public IP directly).
                    // 3. loud warn + omit endpoint (no TCP STUN equivalent).
                    if let Some(explicit) = cfg.external_advert_addr() {
                        endpoints.push(OverlayEndpointAdvert {
                            transport: OverlayTransportKind::Tcp,
                            addr: explicit.to_string(),
                        });
                    } else {
                        match handle.local_addr() {
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
                "tor" => {
                    let Some(cfg) = self.lookup_tor_config(handle.name()) else {
                        continue;
                    };
                    if !cfg.advertise_on_nostr() {
                        continue;
                    }
                    if let Some(addr) = handle.onion_address() {
                        endpoints.push(OverlayEndpointAdvert {
                            transport: OverlayTransportKind::Tor,
                            addr: format!("{}:{}", addr, cfg.advertised_port()),
                        });
                    }
                }
                _ => {}
            }
        }

        if endpoints.is_empty() {
            return None;
        }

        Some(OverlayAdvert {
            identifier: ADVERT_IDENTIFIER.to_string(),
            version: ADVERT_VERSION,
            endpoints,
            signal_relays: has_udp_nat.then(|| self.config.node.discovery.nostr.dm_relays.clone()),
            stun_servers: has_udp_nat
                .then(|| self.config.node.discovery.nostr.stun_servers.clone()),
        })
    }

    async fn refresh_overlay_advert(
        &self,
        bootstrap: &std::sync::Arc<NostrDiscovery>,
    ) -> Result<(), crate::discovery::nostr::BootstrapError> {
        let advert = self.build_overlay_advert(bootstrap).await;
        bootstrap.update_local_advert(advert).await
    }

    fn lookup_udp_config(&self, transport_name: Option<&str>) -> Option<&crate::config::UdpConfig> {
        match (&self.config.transports.udp, transport_name) {
            (crate::config::TransportInstances::Single(cfg), None) => Some(cfg),
            (crate::config::TransportInstances::Named(configs), Some(name)) => configs.get(name),
            _ => None,
        }
    }

    fn lookup_tcp_config(&self, transport_name: Option<&str>) -> Option<&crate::config::TcpConfig> {
        match (&self.config.transports.tcp, transport_name) {
            (crate::config::TransportInstances::Single(cfg), None) => Some(cfg),
            (crate::config::TransportInstances::Named(configs), Some(name)) => configs.get(name),
            _ => None,
        }
    }

    fn lookup_tor_config(&self, transport_name: Option<&str>) -> Option<&crate::config::TorConfig> {
        match (&self.config.transports.tor, transport_name) {
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

        // Static-first dialing: avoid delaying configured address attempts on
        // advert fetch/network latency.
        let static_addresses = self.static_peer_addresses(peer_config);
        if self
            .attempt_peer_address_list(
                peer_config,
                peer_identity,
                allow_bootstrap_nat,
                &static_addresses,
            )
            .await
            .is_ok()
        {
            return Ok(());
        }

        {
            let fallback = self
                .nostr_peer_fallback_addresses(peer_config, &static_addresses)
                .await;
            if !fallback.is_empty()
                && self
                    .attempt_peer_address_list(
                        peer_config,
                        peer_identity,
                        allow_bootstrap_nat,
                        &fallback,
                    )
                    .await
                    .is_ok()
            {
                return Ok(());
            }
        }

        Err(NodeError::NoTransportForType(format!(
            "no operational transport for any of {}'s addresses",
            peer_config.npub
        )))
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
    /// Removes the peer and suppresses auto-reconnect.
    pub(crate) fn api_disconnect(&mut self, npub: &str) -> Result<serde_json::Value, String> {
        let peer_identity =
            PeerIdentity::from_npub(npub).map_err(|e| format!("invalid npub '{npub}': {e}"))?;
        let node_addr = *peer_identity.node_addr();

        if !self.peers.contains_key(&node_addr) {
            return Err(format!("peer not found: {npub}"));
        }

        // Remove the peer (full cleanup: sessions, indices, links, tree, bloom)
        self.remove_active_peer(&node_addr);

        // Suppress any pending auto-reconnect
        self.retry_pending.remove(&node_addr);

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

        if !self.state.is_operational() {
            return Err(NodeError::NotStarted);
        }

        let packet_tx = self.packet_tx.clone().ok_or(NodeError::NotStarted)?;
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
        self.bootstrap_transports.insert(transport_id);
        self.bootstrap_transport_npubs
            .insert(transport_id, traversal.peer_npub.clone());

        let remote_addr = TransportAddr::from_string(&traversal.remote_addr.to_string());
        if let Err(err) = self
            .initiate_connection(transport_id, remote_addr.clone(), Some(peer_identity))
            .await
        {
            self.bootstrap_transports.remove(&transport_id);
            self.bootstrap_transport_npubs.remove(&transport_id);
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
