//! The node's reaction to a transport-medium change.
//!
//! [`crate::node::netmon`] detects that the host's network attachment moved and
//! publishes one [`NetChange`]; everything the node *does* about it lives here.
//! The split is deliberate — the per-OS backends feed the same channel, so none
//! of them has to restate this policy.
//!
//! # The problem
//!
//! Established UDP peers get a per-peer `connect()`-ed socket for the send fast
//! path. `open_connected_fd` binds the wildcard and then calls `connect(2)`,
//! which makes the kernel resolve the route **once** and auto-bind the local
//! source address to whichever interface was carrying it at that moment. It
//! never re-evaluates.
//!
//! So when the host changes medium — a laptop between WLAN and LAN, a phone
//! between Wi-Fi and cellular — every established peer goes on transmitting
//! from an address the routing table has abandoned. The peer, which re-pins to
//! whatever address it last heard from, answers somewhere the node is no longer
//! sending from. The peering stays marked connected and carries nothing until
//! `node.link_dead_timeout_secs` tears it down, and the reconnect then has to
//! redo the Noise handshake and the tree position. Measured on a live node
//! before this landed: 60–90s of black-holed traffic per switch.
//!
//! The mirror-image case — the *peer* rotating its address — is already handled
//! where the rotation is observed (`dataplane::encrypted`, on `address_changed`).
//! This is the local half, and it has no other signal to hang off: a medium
//! change is not visible anywhere in the data plane, which is precisely why it
//! went unhandled.
//!
//! # The reaction
//!
//! Two steps, both cheap enough to run on every detected change:
//!
//! 1. **Drop the stale sockets.** Self-healing rather than disruptive: the
//!    wildcard listen socket resolves a route per packet, so sends keep working
//!    immediately, and `activate_connected_udp_sessions` reinstalls a
//!    correctly-bound connected socket on a later tick.
//! 2. **Heartbeat every peer whose send path cannot block.** The frame leaves
//!    over the new path and carries the node's new source address, so the far
//!    side re-pins on receipt instead of waiting out its own
//!    `heartbeat_interval_secs`. Without it the forward direction is fixed but
//!    the reverse still points at the old address until the node next happens
//!    to send. This runs on the rx loop, so it covers the connectionless
//!    transports only — see
//!    [`Node::heartbeat_all_peers_after_net_change`] for why awaiting a
//!    connection-oriented write here would hold the loop, and what a peer on
//!    one of those gets instead.
//!
//! Nothing here tears a peering down. On a live node both WLAN→LAN and
//! LAN→WLAN now cost no reconnection at all — the Noise session, the tree
//! position and the routes all survive the switch. `link_dead_timeout_secs`
//! remains the backstop for a peer that genuinely cannot be reached on the new
//! medium.

use std::time::Instant;

use tracing::{debug, info, warn};

use crate::NodeAddr;
use crate::node::Node;
use crate::node::netmon::NetChange;
use crate::proto::link::LinkMessageType;

impl Node {
    /// React to a settled transport-medium change.
    pub(in crate::node) async fn handle_net_change(&mut self, change: NetChange) {
        let peers = self.peers.len();
        // Before the heartbeats: they must go out over a socket that resolves
        // the route now, not one still pinned to the interface just left.
        let sockets_rebound = self.drop_connected_sockets_after_net_change();

        let heartbeated = self.heartbeat_all_peers_after_net_change().await;

        info!(
            generation = change.generation,
            change = %change.summary,
            peers,
            sockets_rebound,
            heartbeated,
            "Transport medium changed; rebinding sends and re-pinning peers"
        );
    }

    /// Drop every per-peer `connect()`-ed UDP socket, returning how many were
    /// released.
    ///
    /// See the module docs for why they are stale: `connect(2)` pins the local
    /// source address to the interface that carried the route at connect time,
    /// and never re-evaluates it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn drop_connected_sockets_after_net_change(&mut self) -> usize {
        let pinned: Vec<NodeAddr> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.connected_udp().is_some())
            .map(|(addr, _)| *addr)
            .collect();
        for addr in &pinned {
            self.clear_connected_udp_for_peer(addr);
        }
        pinned.len()
    }

    /// No per-peer connected sockets on this platform, so nothing to rebind.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn drop_connected_sockets_after_net_change(&mut self) -> usize {
        0
    }

    /// Send one heartbeat to every peer whose send path cannot block, so each
    /// learns the node's new source address in one RTT rather than at the next
    /// due interval. Returns how many went out.
    ///
    /// The filter is not an optimisation. A connectionless transport's send
    /// completes without ever awaiting the wire: the UDP fast path hands the
    /// frame to the encrypt workers and returns, and a raw datagram write does
    /// not wait for a peer. A connection-oriented one awaits `write_all` on a
    /// stream, unbounded — the connect above it is wrapped in a timeout, the
    /// write is not — and a medium change is precisely the condition that
    /// leaves a send window full against a path that has just gone away. This
    /// runs on the rx loop, so that write would hold every other arm of the
    /// select for as long as the stranded socket takes to fail.
    ///
    /// Bounding it with a timeout is not the fix either: dropping a partial
    /// `write_all` would leave a half-written frame on the stream, which the
    /// peer cannot resynchronise from. Nor can the fan-out simply be spawned,
    /// because the send needs `&mut self` for the session counter and the MMP
    /// sender record.
    ///
    /// So a peer on TCP, Tor, Nym or BLE keeps the periodic heartbeat it had
    /// before this detector existed. It is not stranded by the omission: those
    /// transports re-dial on send, and `link_dead_timeout_secs` remains the
    /// backstop. Doing better for them means dropping the stale connection
    /// rather than writing into it, which is a different change with a real
    /// cost behind it — a Tor peer pays a fresh circuit — and is not this one.
    async fn heartbeat_all_peers_after_net_change(&mut self) -> usize {
        let now = Instant::now();
        let heartbeat = [LinkMessageType::Heartbeat.to_byte()];
        let targets: Vec<NodeAddr> = self
            .peers
            .iter()
            .filter(|(_, peer)| {
                peer.transport_id()
                    .and_then(|id| self.transports.get(&id))
                    .is_some_and(|t| !t.transport_type().connection_oriented)
            })
            .map(|(addr, _)| *addr)
            .collect();

        let sent = targets.len();
        for addr in targets {
            if let Some(peer) = self.peers.get_mut(&addr) {
                peer.mark_heartbeat_sent(now);
            }
            if let Err(e) = self.send_encrypted_link_message(&addr, &heartbeat).await {
                debug!(
                    peer = %self.peer_display_name(&addr),
                    error = %e,
                    "Failed to send post-medium-change heartbeat"
                );
            }
        }
        sent
    }
}

/// Emitted once at startup when detection is configured off, so an operator
/// reading a slow recovery has something to find.
pub(in crate::node) fn warn_detection_disabled() {
    warn!(
        "node.netmon.enabled = false; a transport medium change will strand \
         established peers on sockets bound to the old path until the link \
         dead timeout"
    );
}
