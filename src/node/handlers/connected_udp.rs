//! Lifecycle for per-peer connected UDP sockets.
//!
//! Tick-driven, idempotent, **on by default** for established UDP peers on
//! Linux and macOS:
//!
//! - **Tick-driven:** every node tick, scan established UDP peers
//!   that don't yet have a connected socket installed and try to
//!   open one. No need to thread an activation call through every
//!   handshake-completion code path.
//! - **Idempotent:** if `peer.connected_udp()` is already `Some`,
//!   skip. Replaces stale sockets lazily by clearing them on
//!   address change / rekey from elsewhere (see
//!   `deregister_session_index` and the rekey handler).
//!
//! Implementation note: only the **listen socket → wildcard** demux
//! path delivers the very first packets of a session (handshakes).
//! Once the peer's session is established, Linux/macOS install the connected
//! socket; from that moment on the kernel routes that peer's traffic
//! to it (most-specific 5-tuple match wins under `SO_REUSEPORT`), and
//! the drain thread feeds the existing `packet_tx` just like the
//! wildcard listen socket does. The rx_loop dispatch sees no
//! difference.
//!
//! macOS originally defaulted to the wildcard UDP socket because early
//! Darwin tests found liveness regressions under load. Later testing
//! showed the problem was mismatched listener/peer `SO_REUSE*` state:
//! with the live listener and connected sibling in the same reuse group,
//! the connected `send(2)` path improves the MacBook Wi-Fi sender case
//! and is now the default. Operators can still disable it with
//! `FIPS_MACOS_CONNECTED_UDP=0` or `FIPS_CONNECTED_UDP=0` for A/B tests.

use crate::NodeAddr;
use crate::node::Node;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::transport::TransportHandle;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tracing::{debug, info, warn};

impl Node {
    /// Tick-driven activation of per-peer connected UDP sockets.
    /// Scans established UDP peers that don't yet have a connected
    /// socket and opens one. No-op when there are no eligible peers
    /// (e.g. only non-UDP transports). Enabled on Linux and macOS:
    /// both kernels route a matching peer 5-tuple to the connected
    /// socket when it shares the wildcard listen port via SO_REUSEPORT.
    pub(in crate::node) async fn activate_connected_udp_sessions(&mut self) {
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            // No-op on platforms without the connected-UDP fast path.
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            if !connected_udp_enabled() {
                return;
            }

            // Collect candidate NodeAddrs first so we can iterate
            // without holding the &mut on self.peers across awaits.
            let candidates: Vec<NodeAddr> = self
                .peers
                .iter()
                .filter_map(|(addr, peer)| {
                    let has_session = peer.noise_session().is_some();
                    let has_transport = peer.transport_id().is_some();
                    let has_addr = peer.current_addr().is_some();
                    let already_active = peer.connected_udp().is_some();
                    if has_session && has_transport && has_addr && !already_active {
                        Some(*addr)
                    } else {
                        None
                    }
                })
                .collect();
            for addr in candidates {
                if let Err(e) = self.activate_connected_udp_for_peer(&addr).await {
                    static FAILURES: AtomicU64 = AtomicU64::new(0);
                    crate::perf_profile::record_event(
                        crate::perf_profile::Event::ConnectedUdpActivationFailed,
                    );
                    let n = FAILURES.fetch_add(1, Relaxed);
                    if n < 8 || n.is_multiple_of(1000) {
                        warn!(peer = %addr, error = %e, failures = n + 1, "connected UDP activation deferred");
                    } else {
                        debug!(peer = %addr, error = %e, "connected UDP activation deferred");
                    }
                }
            }
        }
    }

    /// Open the connected UDP socket + spawn its drain thread for
    /// one peer. Idempotent — re-checks the eligibility conditions
    /// inside the &mut so a race with peer drop doesn't install on a
    /// freshly-removed peer. Returns `Ok(())` on success or if the
    /// peer is no longer eligible (treated as benign).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    async fn activate_connected_udp_for_peer(
        &mut self,
        node_addr: &NodeAddr,
    ) -> Result<(), String> {
        // Read-only pass: figure out which transport + remote addr we need.
        let (transport_id, peer_transport_addr) = {
            let Some(peer) = self.peers.get(node_addr) else {
                return Ok(());
            };
            if peer.connected_udp().is_some() {
                return Ok(()); // already activated
            }
            let Some(tid) = peer.transport_id() else {
                return Ok(());
            };
            let Some(addr) = peer.current_addr().cloned() else {
                return Ok(());
            };
            (tid, addr)
        };

        // Resolve the peer's TransportAddr → kernel SocketAddr via
        // the UDP transport's DNS cache. This may await on a DNS
        // lookup the very first time we see a hostname; subsequent
        // calls hit the cache.
        let (peer_socket_addr, local_addr, recv_buf, send_buf, packet_tx) = {
            let Some(transport) = self.transports.get(&transport_id) else {
                return Ok(());
            };
            let udp = match transport {
                TransportHandle::Udp(u) => u,
                _ => return Ok(()), // not a UDP transport — feature N/A
            };
            let peer_sa = udp
                .resolve_for_off_task(&peer_transport_addr)
                .await
                .map_err(|e| format!("address resolve: {e}"))?;
            let local = udp
                .local_addr()
                .ok_or_else(|| "udp transport not started".to_string())?;
            let recv_buf = udp.recv_buf_size();
            let send_buf = udp.send_buf_size();
            let tx = udp.clone_packet_tx();
            (peer_sa, local, recv_buf, send_buf, tx)
        };

        // Open the connected socket on the kernel side.
        let socket = std::sync::Arc::new(
            crate::transport::udp::connected_peer::ConnectedPeerSocket::open(
                local_addr,
                peer_socket_addr,
                recv_buf,
                send_buf,
            )
            .map_err(|e| format!("ConnectedPeerSocket::open: {e}"))?,
        );

        // Spawn the drain thread. It feeds `packet_tx` exactly like
        // the wildcard listen socket — rx_loop dispatches identically.
        let drain = crate::transport::udp::peer_drain::PeerRecvDrain::spawn(
            socket.clone(),
            transport_id,
            peer_socket_addr,
            packet_tx,
        )
        .map_err(|e| format!("PeerRecvDrain::spawn: {e}"))?;

        // Install on the peer, idempotent re-check.
        if let Some(peer) = self.peers.get_mut(node_addr) {
            if peer.connected_udp().is_some() {
                // Lost the race — somebody else activated us first.
                // Drop the new socket + drain so we don't leak.
                drop(drain);
                drop(socket);
                return Ok(());
            }
            peer.set_connected_udp(socket, drain);
            crate::perf_profile::record_event(crate::perf_profile::Event::ConnectedUdpInstalled);
            info!(
                peer = %self.peer_display_name(node_addr),
                peer_addr = %peer_socket_addr,
                "connected UDP socket installed"
            );
        } else {
            // Peer disappeared between read-only pass and now.
            drop(drain);
            drop(socket);
        }
        Ok(())
    }

    /// Clear the per-peer connected UDP socket + drain for a peer.
    /// Called on peer disconnect / removal. The drain thread exits
    /// via self-pipe; the kernel fd closes when the last `Arc`
    /// drops.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[allow(dead_code)] // wired by session-deregister + rekey teardown follow-up
    pub(in crate::node) fn clear_connected_udp_for_peer(&mut self, node_addr: &NodeAddr) {
        if let Some(peer) = self.peers.get_mut(node_addr)
            && peer.connected_udp().is_some()
        {
            peer.clear_connected_udp();
            debug!(peer = %self.peer_display_name(node_addr), "connected UDP socket cleared");
        }
    }

    /// No-op shim for non-Linux builds so the rx_loop tick site can
    /// call us unconditionally.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[allow(dead_code)] // wired by session-deregister + rekey teardown follow-up
    pub(in crate::node) fn clear_connected_udp_for_peer(&mut self, _node_addr: &NodeAddr) {}
}

#[cfg(target_os = "linux")]
fn connected_udp_enabled() -> bool {
    env_flag("FIPS_CONNECTED_UDP").unwrap_or(true)
}

#[cfg(target_os = "macos")]
fn connected_udp_enabled() -> bool {
    env_flag("FIPS_MACOS_CONNECTED_UDP")
        .or_else(|| env_flag("FIPS_CONNECTED_UDP"))
        .unwrap_or(true)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn env_flag(name: &str) -> Option<bool> {
    let value = std::env::var(name).ok()?;
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}
