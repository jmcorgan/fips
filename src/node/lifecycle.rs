//! Node lifecycle management: start, stop, and peer connection initiation.

use super::*;

impl Node {
    /// Initiate connections to configured static peers.
    ///
    /// For each peer configured with AutoConnect policy, creates a link and
    /// peer entry, then starts the Noise handshake by sending the first message.
    pub(super) async fn initiate_peer_connections(&mut self) {
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
    async fn initiate_peer_connection(&mut self, peer_config: &crate::config::PeerConfig) -> Result<(), NodeError> {
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
            // Find a transport matching this address type
            let transport_id = match self.find_transport_for_type(&addr.transport) {
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

            // Allocate link ID and create link
            let link_id = self.allocate_link_id();
            let remote_addr = TransportAddr::from_string(&addr.addr);

            // For UDP, links are immediately "connected" (connectionless)
            // TODO: For connection-oriented transports, state would be Connecting
            let link = Link::connectionless(
                link_id,
                transport_id,
                remote_addr.clone(),
                LinkDirection::Outbound,
                Duration::from_millis(100), // Base RTT estimate for UDP
            );

            self.links.insert(link_id, link);

            // Add reverse lookup for packet dispatch
            self.addr_to_link
                .insert((transport_id, remote_addr.clone()), link_id);

            // Create connection in handshake phase (outbound knows expected identity)
            let current_time_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let mut connection = PeerConnection::outbound(link_id, peer_identity.clone(), current_time_ms);

            // Allocate a session index for this handshake
            let our_index = match self.index_allocator.allocate() {
                Ok(idx) => idx,
                Err(e) => {
                    warn!(
                        npub = %peer_config.npub,
                        error = %e,
                        "Failed to allocate session index"
                    );
                    // Clean up the link we just created
                    self.links.remove(&link_id);
                    self.addr_to_link.remove(&(transport_id, remote_addr));
                    continue;
                }
            };

            // Start the Noise handshake and get message 1
            let our_keypair = self.identity.keypair();
            let noise_msg1 = match connection.start_handshake(our_keypair, current_time_ms) {
                Ok(msg) => msg,
                Err(e) => {
                    warn!(
                        npub = %peer_config.npub,
                        error = %e,
                        "Failed to start handshake"
                    );
                    // Clean up the index and link
                    let _ = self.index_allocator.free(our_index);
                    self.links.remove(&link_id);
                    self.addr_to_link.remove(&(transport_id, remote_addr));
                    continue;
                }
            };

            // Set index and transport info on the connection
            connection.set_our_index(our_index);
            connection.set_transport_id(transport_id);
            connection.set_source_addr(remote_addr.clone());

            // Build wire format msg1: [0x01][sender_idx:4 LE][noise_msg1:82]
            let wire_msg1 = build_msg1(our_index, &noise_msg1);

            let alias_display = peer_config
                .alias
                .as_deref()
                .map(|a| format!(" ({})", a))
                .unwrap_or_default();

            info!("Peer connection initiated{}", alias_display);
            info!("  npub: {}", peer_config.npub);
            info!("  node_addr: {}", peer_node_addr);
            info!("  transport: {}", addr.transport);
            info!("  addr: {}", addr.addr);
            info!("  link_id: {}", link_id);
            info!("  our_index: {}", our_index);

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

            // Successfully initiated connection via this address
            return Ok(());
        }

        // No address worked
        Err(NodeError::NoTransportForType(format!(
            "no operational transport for any of {}'s addresses",
            peer_config.npub
        )))
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
        const PACKET_BUFFER_SIZE: usize = 1024;
        let (packet_tx, packet_rx) = packet_channel(PACKET_BUFFER_SIZE);
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

                    // Create writer (dups the fd for independent write access)
                    let (writer, tun_tx) = device.create_writer()?;

                    // Spawn writer thread
                    let writer_handle = thread::spawn(move || {
                        writer.run();
                    });

                    // Clone tun_tx for the reader
                    let reader_tun_tx = tun_tx.clone();

                    // Spawn reader thread
                    let reader_handle = thread::spawn(move || {
                        run_tun_reader(device, mtu, our_addr, reader_tun_tx);
                    });

                    self.tun_state = TunState::Active;
                    self.tun_name = Some(name);
                    self.tun_tx = Some(tun_tx);
                    self.tun_reader_handle = Some(reader_handle);
                    self.tun_writer_handle = Some(writer_handle);
                }
                Err(e) => {
                    self.tun_state = TunState::Failed;
                    warn!(error = %e, "Failed to initialize TUN, continuing without it");
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

        // Shutdown transports first (they're packet producers)
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
}
