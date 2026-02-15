//! RX event loop and packet dispatch.

use crate::node::{Node, NodeError};
use crate::transport::ReceivedPacket;
use crate::node::wire::{DISCRIMINATOR_ENCRYPTED, DISCRIMINATOR_MSG1, DISCRIMINATOR_MSG2};
use std::time::Duration;
use tracing::{debug, info};

impl Node {
    /// Run the receive event loop.
    ///
    /// Processes packets from all transports, dispatching based on
    /// the discriminator byte in the wire protocol:
    /// - 0x00: Encrypted frame (session data)
    /// - 0x01: Handshake message 1 (initiator -> responder)
    /// - 0x02: Handshake message 2 (responder -> initiator)
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
        let mut packet_rx = self.packet_rx.take()
            .ok_or(NodeError::NotStarted)?;

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

        let mut tick = tokio::time::interval(Duration::from_secs(self.config.node.tick_interval_secs));

        info!("RX event loop started");

        loop {
            tokio::select! {
                packet = packet_rx.recv() => {
                    match packet {
                        Some(p) => self.process_packet(p).await,
                        None => break, // channel closed
                    }
                }
                Some(ipv6_packet) = tun_outbound_rx.recv() => {
                    self.handle_tun_outbound(ipv6_packet).await;
                }
                Some(identity) = dns_identity_rx.recv() => {
                    debug!(
                        node_addr = %identity.node_addr,
                        "Registering identity from DNS resolution"
                    );
                    self.register_identity(identity.node_addr, identity.pubkey);
                }
                _ = tick.tick() => {
                    self.check_timeouts();
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    self.process_pending_retries(now_ms).await;
                    self.check_tree_state().await;
                    self.check_bloom_state().await;
                    self.purge_stale_lookups(now_ms);
                }
            }
        }

        info!("RX event loop stopped (channel closed)");
        Ok(())
    }

    /// Process a single received packet.
    ///
    /// Dispatches based on the discriminator byte.
    async fn process_packet(&mut self, packet: ReceivedPacket) {
        if packet.data.is_empty() {
            return; // Drop empty packets
        }

        let discriminator = packet.data[0];
        match discriminator {
            DISCRIMINATOR_ENCRYPTED => {
                self.handle_encrypted_frame(packet).await;
            }
            DISCRIMINATOR_MSG1 => {
                self.handle_msg1(packet).await;
            }
            DISCRIMINATOR_MSG2 => {
                self.handle_msg2(packet).await;
            }
            _ => {
                // Unknown discriminator, drop silently
                debug!(
                    discriminator = discriminator,
                    transport_id = %packet.transport_id,
                    "Unknown packet discriminator, dropping"
                );
            }
        }
    }
}
