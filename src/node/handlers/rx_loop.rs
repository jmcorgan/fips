//! RX event loop and packet dispatch.

use crate::control::queries;
use crate::control::{ControlSocket, commands};
use crate::node::wire::{
    COMMON_PREFIX_SIZE, CommonPrefix, FMP_VERSION, PHASE_ESTABLISHED, PHASE_MSG1, PHASE_MSG2,
    PHASE_MSG3,
};
use crate::node::{Node, NodeError};
use crate::transport::ReceivedPacket;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Inside the packet_rx burst drain, run a fallback drain every
/// N packets so bounced FMP plaintexts can't sit behind a full
/// 256-packet UDP burst. Used on unix; on Windows the decrypt-worker
/// pool isn't spawned so the fallback channel is always empty —
/// hold the constants at module scope anyway so the burst-loop
/// dispatch in `run_rx_loop` doesn't need a `#[cfg]` on every site.
const FALLBACK_INTERLEAVE_EVERY: usize = 32;
/// How many fallback events to drain per interleave step. Bounded so
/// the inner loop can keep making forward progress on packet_rx.
#[cfg(unix)]
const FALLBACK_INTERLEAVE_BUDGET: usize = 32;

impl Node {
    /// Run the receive event loop.
    ///
    /// Processes packets from all transports, dispatching based on
    /// the phase field in the 4-byte common prefix:
    /// - Phase 0x0: Encrypted frame (session data)
    /// - Phase 0x1: Handshake message 1 (initiator -> responder)
    /// - Phase 0x2: Handshake message 2 (responder -> initiator)
    /// - Phase 0x3: Handshake message 3 (initiator -> responder, XX completion)
    ///
    /// Also processes outbound IPv6 packets from the TUN reader for session
    /// encapsulation and routing through the mesh.
    ///
    /// Also processes DNS-resolved identities for identity cache population.
    ///
    /// Also runs a periodic tick (1s) to clean up stale handshake connections
    /// that never received a response. This prevents resource leaks when peers
    /// are unreachable.
    ///
    /// This method takes ownership of the packet_rx channel and runs
    /// until the channel is closed (typically when stop() is called).
    pub async fn run_rx_loop(&mut self) -> Result<(), NodeError> {
        let mut packet_rx = self.packet_rx.take().ok_or(NodeError::NotStarted)?;

        // Take the TUN outbound receiver, or create a dummy channel that never
        // produces messages (when TUN is disabled). Holding the sender prevents
        // the channel from closing.
        let (mut tun_outbound_rx, _tun_guard) = match self.tun_outbound_rx.take() {
            Some(rx) => (rx, None),
            None => {
                let (tx, rx) = tokio::sync::mpsc::channel(1);
                (rx, Some(tx))
            }
        };

        // Take the DNS identity receiver, or create a dummy channel (when DNS
        // is disabled). Same pattern as TUN outbound.
        let (mut dns_identity_rx, _dns_guard) = match self.dns_identity_rx.take() {
            Some(rx) => (rx, None),
            None => {
                let (tx, rx) = tokio::sync::mpsc::channel(1);
                (rx, Some(tx))
            }
        };

        let mut tick =
            tokio::time::interval(Duration::from_secs(self.config().node.tick_interval_secs));

        // Set up control socket channel
        let (control_tx, mut control_rx) =
            tokio::sync::mpsc::channel::<crate::control::ControlMessage>(32);

        if self.config().node.control.enabled {
            let config = self.config().node.control.clone();
            let tx = control_tx.clone();
            let read_handle = self.control_read_handle();
            tokio::spawn(async move {
                match ControlSocket::bind(&config) {
                    Ok(socket) => {
                        socket.accept_loop(tx, read_handle).await;
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to bind control socket");
                    }
                }
            });
        }
        // Drop unused sender to avoid keeping channel open if control is disabled
        drop(control_tx);

        // Decrypt-worker fallback receiver. The worker pushes each
        // authenticated FMP plaintext here so rx_loop can finish the
        // per-peer side-effects (stats, MMP, ECN, link dispatch).
        // Always declared so the `tokio::select!` arm doesn't need
        // a `cfg` (which the macro doesn't support); on Windows the
        // channel just never sees events.
        let (mut decrypt_fallback_rx, _decrypt_fallback_guard) = {
            #[cfg(unix)]
            {
                match self.decrypt_fallback_rx.take() {
                    Some(rx) => (rx, None),
                    None => {
                        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                        (rx, Some(tx))
                    }
                }
            }
            #[cfg(not(unix))]
            {
                // On non-unix nothing ever sends, but the macro arm
                // still needs an existing rx. Keep the sender alive to
                // avoid the channel closing into an Err loop.
                let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<()>();
                (rx, Some(tx))
            }
        };

        info!("RX event loop started");
        // Optional per-stage perf profiler (FIPS_PERF=1). No-op otherwise.
        crate::perf_profile::maybe_spawn_reporter();

        loop {
            tokio::select! {
                biased;
                // Decrypt-worker fallback drains FIRST. Under sustained
                // inbound bursts the packet_rx drain (up to 256 packets)
                // can starve fallback work for tens of ms — TCP doesn't
                // tolerate that (late ACKs → dup-ACK fast retransmits →
                // cwnd collapse). Promoting fallback gives the kernel's
                // TCP machinery a fair chance to ACK in time.
                Some(event) = decrypt_fallback_rx.recv() => {
                    #[cfg(unix)]
                    {
                        self.process_decrypt_worker_event(event).await;
                        let mut drained = 0;
                        while drained < 255 {
                            match decrypt_fallback_rx.try_recv() {
                                Ok(ev) => {
                                    self.process_decrypt_worker_event(ev).await;
                                    drained += 1;
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    #[cfg(not(unix))]
                    let _ = event;
                }
                packet = packet_rx.recv() => {
                    match packet {
                        Some(p) => self.process_packet(p).await,
                        None => break, // channel closed
                    }
                    // Drain remaining ready inbound packets in a tight loop
                    // before yielding back to select! — every yield is a
                    // futex hop on tokio's multi-thread scheduler, and at
                    // line rate the kernel UDP queue typically has several
                    // datagrams available per wake. Caps at a batch
                    // boundary so other branches (tick, control) eventually
                    // get a turn even under sustained load.
                    //
                    // **Interleave fallback drain** every N packets so
                    // bounced FMP plaintexts (heartbeats, post-FMP-
                    // decrypt forwarding payloads, control frames) don't
                    // sit in the fallback queue for a full 256-packet
                    // burst. Even with the priority-first ordering of
                    // the outer select!, once we're inside this inner
                    // loop only this interleave can free queued
                    // fallbacks. On multihop forwarding paths this is
                    // the difference between back-to-back encrypt-
                    // worker dispatches happening promptly vs piling up
                    // behind the rx burst.
                    let mut drained: usize = 1; // count the packet processed above
                    while drained < 256 {
                        if drained.is_multiple_of(FALLBACK_INTERLEAVE_EVERY) {
                            #[cfg(unix)]
                            {
                                let mut fb_drained = 0;
                                while fb_drained < FALLBACK_INTERLEAVE_BUDGET {
                                    match decrypt_fallback_rx.try_recv() {
                                        Ok(ev) => {
                                            self.process_decrypt_worker_event(ev).await;
                                            fb_drained += 1;
                                        }
                                        Err(_) => break,
                                    }
                                }
                            }
                        }
                        match packet_rx.try_recv() {
                            Ok(p) => {
                                self.process_packet(p).await;
                                drained += 1;
                            }
                            Err(_) => break,
                        }
                    }
                    // Trailing fallback drain so the last bounced
                    // packets of the burst aren't held up by the
                    // next select! iteration.
                    #[cfg(unix)]
                    {
                        let mut fb_drained = 0;
                        while fb_drained < 256 {
                            match decrypt_fallback_rx.try_recv() {
                                Ok(ev) => {
                                    self.process_decrypt_worker_event(ev).await;
                                    fb_drained += 1;
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
                Some(ipv6_packet) = tun_outbound_rx.recv() => {
                    self.handle_tun_outbound(ipv6_packet).await;
                    let mut drained = 0;
                    while drained < 256 {
                        match tun_outbound_rx.try_recv() {
                            Ok(p) => {
                                self.handle_tun_outbound(p).await;
                                drained += 1;
                            }
                            Err(_) => break,
                        }
                    }
                }
                Some(identity) = dns_identity_rx.recv() => {
                    debug!(
                        node_addr = %identity.node_addr,
                        "Registering identity from DNS resolution"
                    );
                    self.register_identity(identity.node_addr, identity.pubkey);
                }
                Some((request, response_tx)) = control_rx.recv() => {
                    let response = if request.command.starts_with("show_") {
                        queries::dispatch(self, &request.command, request.params.as_ref())
                    } else {
                        commands::dispatch(
                            self,
                            &request.command,
                            request.params.as_ref(),
                        ).await
                    };
                    let _ = response_tx.send(response);
                }
                _ = tick.tick() => {
                    self.check_timeouts();
                    let now_ms = Self::now_ms();
                    self.reload_peer_acl().await;
                    // The host map hot-reloads on the same tick as the ACL. It
                    // is polled separately from `reload_peer_acl` because the
                    // ACL's embedded alias reloader and this snapshot are
                    // distinct resources; the `path_mtu_lookup` cache and the
                    // `nostr_discovery` subsystem are deliberately excluded
                    // from `Reloadable` since neither reloads from a backing
                    // file (see `node::reloadable`).
                    self.reload_host_map().await;
                    self.poll_pending_connects().await;
                    self.poll_nostr_discovery().await;
                    self.poll_lan_discovery().await;
                    self.resend_pending_handshakes(now_ms).await;
                    self.resend_pending_rekeys(now_ms).await;
                    self.resend_pending_fmp_rekey_msg3(now_ms).await;
                    self.resend_pending_session_handshakes(now_ms).await;
                    self.resend_pending_session_msg3(now_ms).await;
                    self.purge_idle_sessions(now_ms);
                    self.process_pending_retries(now_ms).await;
                    self.check_tree_state().await;
                    self.check_bloom_state().await;
                    self.compute_mesh_size();
                    self.record_stats_history();
                    self.check_mmp_reports().await;
                    self.check_session_mmp_reports().await;
                    self.check_link_heartbeats().await;
                    self.check_rekey().await;
                    self.check_session_rekey().await;
                    self.check_pending_lookups(now_ms).await;
                    self.poll_transport_discovery().await;
                    self.sample_transport_congestion();
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    self.activate_connected_udp_sessions().await;
                }
            }
        }

        info!("RX event loop stopped (channel closed)");
        Ok(())
    }

    /// Process a single received packet.
    ///
    /// Dispatches based on the phase field in the 4-byte common prefix.
    async fn process_packet(&mut self, packet: ReceivedPacket) {
        if packet.data.len() < COMMON_PREFIX_SIZE {
            return; // Drop packets too short for common prefix
        }

        let prefix = match CommonPrefix::parse(&packet.data) {
            Some(p) => p,
            None => return, // Malformed prefix
        };

        if prefix.version != FMP_VERSION {
            debug!(
                version = prefix.version,
                transport_id = %packet.transport_id,
                "Unknown FMP version, dropping"
            );

            // If the packet arrived on an adopted Nostr-NAT bootstrap
            // transport, the originating peer is necessarily on a
            // different FMP-protocol version than us — the discovery
            // sweep would otherwise re-traverse them every cycle even
            // though no msg1/msg2 exchange can ever succeed. Bump the
            // discovery-layer cooldown to the long protocol-mismatch
            // window and emit a single WARN per fresh observation.
            if self.bootstrap_transports.contains(&packet.transport_id)
                && let Some(npub) = self
                    .bootstrap_transport_npubs
                    .get(&packet.transport_id)
                    .cloned()
                && let Some(handle) = self.nostr_discovery_handle()
            {
                let now_ms = Self::now_ms();
                let cooldown_secs = handle.protocol_mismatch_cooldown_secs();
                if handle.record_protocol_mismatch(&npub, now_ms) {
                    warn!(
                        peer_npub = %npub,
                        transport_id = %packet.transport_id,
                        peer_version = prefix.version,
                        our_version = FMP_VERSION,
                        cooldown_secs,
                        "Nostr-discovered peer speaks a different FMP version; suppressing retraversal"
                    );
                }
            }
            return;
        }

        match prefix.phase {
            PHASE_ESTABLISHED => {
                self.handle_encrypted_frame(packet).await;
            }
            PHASE_MSG1 => {
                self.handle_msg1(packet).await;
            }
            PHASE_MSG2 => {
                self.handle_msg2(packet).await;
            }
            PHASE_MSG3 => {
                self.handle_msg3(packet).await;
            }
            _ => {
                debug!(
                    phase = prefix.phase,
                    transport_id = %packet.transport_id,
                    "Unknown FMP phase, dropping"
                );
            }
        }
    }
}
