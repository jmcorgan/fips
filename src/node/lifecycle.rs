//! Node lifecycle management: start, stop, and peer connection initiation.

use super::{Node, NodeError, NodeState};
use crate::peer::PeerConnection;
use crate::protocol::{Disconnect, DisconnectReason};
use crate::transport::{packet_channel, Link, LinkDirection, TransportAddr, TransportId};
use crate::upper::tun::{run_tun_reader, shutdown_tun_interface, TunDevice, TunState};
use crate::node::wire::build_msg1;
use crate::{NodeAddr, PeerIdentity};
use std::thread;
use std::time::Duration;
use tracing::{debug, info, warn};

impl Node {
    /// Initiate connections to configured static peers.
    ///
    /// For each peer configured with AutoConnect policy, creates a link and
    /// peer entry, then starts the Noise handshake by sending the first message.
    pub(super) async fn initiate_peer_connections(&mut self) {
        // Build display name map from all configured peers (alias or short npub)
        for peer_config in self.config.peers() {
            if let Ok(identity) = PeerIdentity::from_npub(&peer_config.npub) {
                let name = peer_config
                    .alias
                    .clone()
                    .unwrap_or_else(|| identity.short_npub());
                self.peer_aliases.insert(*identity.node_addr(), name);
            }
        }

        // Collect peer configs to avoid borrow conflicts
        let peer_configs: Vec<_> = self.config.auto_connect_peers().cloned().collect();

        if peer_configs.is_empty() {
            debug!("No static peers configured");
            return;
        }

        info!(count = peer_configs.len(), "Initiating static peer connections");

        for peer_config in peer_configs {
            if let Err(e) = self.initiate_peer_connection(&peer_config).await {
                warn!(
                    npub = %peer_config.npub,
                    alias = ?peer_config.alias,
                    error = %e,
                    "Failed to initiate peer connection"
                );
            }
        }
    }

    /// Initiate a connection to a single peer.
    ///
    /// Creates a link, starts the Noise handshake, and sends the first message.
    pub(super) async fn initiate_peer_connection(&mut self, peer_config: &crate::config::PeerConfig) -> Result<(), NodeError> {
        // Parse the peer's npub to get their identity
        let peer_identity = PeerIdentity::from_npub(&peer_config.npub).map_err(|e| {
            NodeError::InvalidPeerNpub {
                npub: peer_config.npub.clone(),
                reason: e.to_string(),
            }
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
        let already_connecting = self.connections.values().any(|conn| {
            conn.expected_identity()
                .map(|id| id.node_addr() == &peer_node_addr)
                .unwrap_or(false)
        });
        if already_connecting {
            debug!(
                npub = %peer_config.npub,
                "Connection already in progress, skipping"
            );
            return Ok(());
        }

        // Try addresses in priority order until one works
        for addr in peer_config.addresses_by_priority() {
            // For Ethernet addresses ("interface/mac"), find the transport
            // instance matching the interface name and parse the MAC.
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
            } else {
                // Find a transport matching this address type
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

            match self.initiate_connection(transport_id, remote_addr, peer_identity).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    debug!(
                        npub = %peer_config.npub,
                        transport_id = %transport_id,
                        error = %e,
                        "Connection attempt failed, trying next address"
                    );
                    continue;
                }
            }
        }

        // No address worked
        Err(NodeError::NoTransportForType(format!(
            "no operational transport for any of {}'s addresses",
            peer_config.npub
        )))
    }

    /// Initiate a connection to a peer on a specific transport and address.
    ///
    /// Allocates a link, starts the Noise IK handshake, sends msg1, and
    /// registers the connection for msg2 dispatch. Used by both static peer
    /// config and transport discovery auto-connect paths.
    pub(super) async fn initiate_connection(
        &mut self,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        peer_identity: PeerIdentity,
    ) -> Result<(), NodeError> {
        let peer_node_addr = *peer_identity.node_addr();

        // Allocate link ID and create link
        let link_id = self.allocate_link_id();

        // Use Link::new() for connection-oriented transports (Connecting state)
        // and Link::connectionless() for connectionless transports (Connected state)
        let link = if self.transports.get(&transport_id)
            .map(|t| t.transport_type().connection_oriented)
            .unwrap_or(false)
        {
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

        // Create connection in handshake phase (outbound knows expected identity)
        let current_time_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut connection = PeerConnection::outbound(link_id, peer_identity, current_time_ms);

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
        let noise_msg1 = match connection.start_handshake(our_keypair, self.startup_epoch, current_time_ms) {
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

        debug!(
            peer = %self.peer_display_name(&peer_node_addr),
            transport_id = %transport_id,
            remote_addr = %remote_addr,
            link_id = %link_id,
            our_index = %our_index,
            "Connection initiated"
        );

        // Store msg1 for resend and schedule first resend
        let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
        connection.set_handshake_msg1(wire_msg1.clone(), current_time_ms + resend_interval);

        // Track in pending_outbound for msg2 dispatch
        self.pending_outbound.insert((transport_id, our_index.as_u32()), link_id);
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
        let mut to_connect = Vec::new();

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
                let pubkey = match peer.pubkey_hint {
                    Some(pk) => pk,
                    None => continue,
                };
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

                to_connect.push((*transport_id, peer.addr, identity));
            }
        }

        for (transport_id, remote_addr, identity) in to_connect {
            info!(
                peer = %self.peer_display_name(identity.node_addr()),
                transport_id = %transport_id,
                remote_addr = %remote_addr,
                "Auto-connecting to discovered peer"
            );
            if let Err(e) = self.initiate_connection(transport_id, remote_addr, identity).await {
                warn!(error = %e, "Failed to auto-connect to discovered peer");
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

        // Initialize transports first (before TUN)
        let transport_handles = self.create_transports(&packet_tx);

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
                    info!("   max TCP MSS: {} bytes", max_mss);

                    // Create writer (dups the fd for independent write access)
                    let (writer, tun_tx) = device.create_writer(max_mss)?;

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
                    let reader_handle = thread::spawn(move || {
                        run_tun_reader(device, mtu, our_addr, reader_tun_tx, outbound_tx, transport_mtu);
                    });

                    self.tun_state = TunState::Active;
                    self.tun_name = Some(name);
                    self.tun_tx = Some(tun_tx);
                    self.tun_outbound_rx = Some(outbound_rx);
                    self.tun_reader_handle = Some(reader_handle);
                    self.tun_writer_handle = Some(writer_handle);
                }
                Err(e) => {
                    self.tun_state = TunState::Failed;
                    warn!(error = %e, "Failed to initialize TUN, continuing without it");
                }
            }
        }

        // Initialize DNS responder (independent of TUN)
        if self.config.dns.enabled {
            let bind = format!("{}:{}", self.config.dns.bind_addr(), self.config.dns.port());
            match tokio::net::UdpSocket::bind(&bind).await {
                Ok(socket) => {
                    let dns_channel_size = self.config.node.buffers.dns_channel;
                    let (identity_tx, identity_rx) = tokio::sync::mpsc::channel(dns_channel_size);
                    let dns_ttl = self.config.dns.ttl();
                    let handle = tokio::spawn(crate::upper::dns::run_dns_responder(socket, identity_tx, dns_ttl));
                    self.dns_identity_rx = Some(identity_rx);
                    self.dns_task = Some(handle);
                    info!(bind = %bind, "DNS responder started for .fips domain");
                }
                Err(e) => {
                    warn!(bind = %bind, error = %e, "Failed to start DNS responder");
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
        self.send_disconnect_to_all_peers(DisconnectReason::Shutdown).await;

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

            // Delete the interface (causes reader to get EFAULT)
            if let Err(e) = shutdown_tun_interface(&name).await {
                warn!(name = %name, error = %e, "Failed to shutdown TUN interface");
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
        let peer_addrs: Vec<NodeAddr> = self.peers.iter()
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
            match self.send_encrypted_link_message(node_addr, &plaintext).await {
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
}
