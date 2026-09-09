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
//! 2. **Heartbeat each moved peer whose send path cannot block.** The frame
//!    leaves over the new path and carries the node's new source address, so
//!    the far side re-pins on receipt instead of waiting out its own
//!    `heartbeat_interval_secs`. Without it the forward direction is fixed but
//!    the reverse still points at the old address until the node next happens
//!    to send. This runs on the rx loop, and it covers the connectionless
//!    transports only — see
//!    [`Node::heartbeat_moved_peers_after_net_change`] for what a peer on a
//!    connection-oriented transport gets instead, and for why that filter has
//!    outlived the reason it was written for.
//!
//! Nothing here tears a peering down. On a live node both WLAN→LAN and
//! LAN→WLAN now cost no reconnection at all — the Noise session, the tree
//! position and the routes all survive the switch. `link_dead_timeout_secs`
//! remains the backstop for a peer that genuinely cannot be reached on the new
//! medium.
//!
//! # Why the reaction is scoped to the peers that moved
//!
//! [`NetChange`] names them, and the reaction acts on exactly that set. It is
//! not an optimisation: keying the sample on peers put the trigger within
//! reach of a remote party for the first time. `probe_target` is the observed
//! source address of every authentic packet, updated with no throttle, so a
//! peer alternating between two addresses that resolve to different local
//! sources can move the fingerprint at will. Node-wide, that peer could drive
//! every other peering's socket teardown, bounded only by the poll interval.
//! Scoped, the only peer in the set is the roamer itself — whose connected
//! socket `dataplane::encrypted` has already cleared on the address change.
//!
//! A peer is absent from that set for one of two reasons. The first is the
//! one the narrowing rests on: its local source address still resolves to the
//! same place, which is the whole content of the fingerprint — a peer that did
//! not move is a peer whose socket is not stale. The second is that it never
//! reached the sample. `PeerRow::probe_target` parses the peer's current
//! address, so a peer still carrying the hostname it was configured with is
//! `None` there and is skipped while any `connect()`-ed socket it holds stays
//! pinned; the node-wide reaction repaired that peer as collateral and this one
//! does not. Where the node dialled out, that is transient —
//! `set_current_addr` replaces the configured string with the observed numeric
//! source on the first authentic frame. Which side supplies `current_addr` on
//! an inbound peering is not established here, so the second group is not
//! claimed to be empty in general.

use std::time::Instant;

use tracing::{debug, info, warn};

use crate::NodeAddr;
use crate::node::Node;
use crate::node::netmon::NetChange;
use crate::proto::link::LinkMessageType;

impl Node {
    /// React to a settled transport-medium change, on the peers it names.
    pub(in crate::node) async fn handle_net_change(&mut self, change: NetChange) {
        let moved: Vec<NodeAddr> = change.summary.moved.iter().map(|m| m.peer).collect();
        let peers = self.peers.len();
        // Before the heartbeats: they must go out over a socket that resolves
        // the route now, not one still pinned to the interface just left.
        let sockets_rebound = self.drop_connected_sockets_after_net_change(&moved);

        let heartbeated = self.heartbeat_moved_peers_after_net_change(&moved).await;

        info!(
            generation = change.generation,
            change = %change.summary,
            peers,
            moved = moved.len(),
            sockets_rebound,
            heartbeated,
            "Transport medium changed; rebinding sends and re-pinning peers"
        );
    }

    /// Drop the per-peer `connect()`-ed UDP socket of each peer that moved,
    /// returning how many were released.
    ///
    /// See the module docs for why they are stale: `connect(2)` pins the local
    /// source address to the interface that carried the route at connect time,
    /// and never re-evaluates it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn drop_connected_sockets_after_net_change(&mut self, moved: &[NodeAddr]) -> usize {
        let pinned: Vec<NodeAddr> = moved
            .iter()
            .filter(|addr| {
                self.peers
                    .get(*addr)
                    .is_some_and(|peer| peer.connected_udp().is_some())
            })
            .copied()
            .collect();
        for addr in &pinned {
            self.clear_connected_udp_for_peer(addr);
        }
        pinned.len()
    }

    /// No per-peer connected sockets on this platform, so nothing to rebind.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn drop_connected_sockets_after_net_change(&mut self, _moved: &[NodeAddr]) -> usize {
        0
    }

    /// Send one heartbeat to each moved peer whose send path cannot block, so
    /// each learns the node's new source address in one RTT rather than at the
    /// next due interval. Returns how many sends actually succeeded, which is
    /// what the operator log reports — a count of peers *selected* would read
    /// the same whether every frame left or none did, and a medium change is
    /// exactly when sends start failing.
    ///
    /// The filter was written for a hazard that no longer exists, and it is
    /// kept deliberately rather than by oversight. It was this: a
    /// connectionless transport's send completes without ever awaiting the
    /// wire, because the UDP fast path hands the frame to the encrypt workers
    /// and returns and a raw datagram write does not wait for a peer, while a
    /// connection-oriented one awaited `write_all` on a stream, unbounded. A
    /// medium change is precisely the condition that leaves a send window full
    /// against a path that has just gone away, and this runs on the rx loop, so
    /// that write held every other arm of the select for as long as the
    /// stranded socket took to fail.
    ///
    /// Every connection-oriented send now enqueues onto its connection's
    /// bounded queue and returns, so none of them can await the wire from here.
    /// Widening the fan-out to those transports is therefore open work rather
    /// than something the send path forbids; it is left out of the change that
    /// removed the hazard so the two stay separable. Note that the fan-out
    /// still cannot simply be spawned, because the send needs `&mut self` for
    /// the session counter and the MMP sender record.
    ///
    /// So a peer on TCP, Tor, Nym or BLE keeps the periodic heartbeat it had
    /// before this detector existed, and `link_dead_timeout_secs` remains the
    /// backstop. Note that it does *not* recover by redialling: `send_async`
    /// only dials when the pool holds no connection for the address, and a
    /// connection stranded by a medium change is still in the pool. It is
    /// evicted after a write to it fails, so the redial happens on the send
    /// after the failure, not on the first one. Doing better for them means
    /// dropping the stale connection
    /// rather than writing into it, which is a different change with a real
    /// cost behind it — a Tor peer pays a fresh circuit — and is not this one.
    pub(in crate::node) async fn heartbeat_moved_peers_after_net_change(
        &mut self,
        moved: &[NodeAddr],
    ) -> usize {
        let now = Instant::now();
        let heartbeat = [LinkMessageType::Heartbeat.to_byte()];
        let targets: Vec<NodeAddr> = moved
            .iter()
            .filter(|addr| {
                self.peers.get(*addr).is_some_and(|peer| {
                    peer.transport_id()
                        .and_then(|id| self.transports.get(&id))
                        .is_some_and(|t| !t.transport_type().connection_oriented)
                })
            })
            .copied()
            .collect();

        let mut sent = 0usize;
        for addr in targets {
            if let Some(peer) = self.peers.get_mut(&addr) {
                peer.mark_heartbeat_attempt(now);
            }
            match self.send_encrypted_link_message(&addr, &heartbeat).await {
                Ok(()) => {
                    if let Some(peer) = self.peers.get_mut(&addr) {
                        peer.mark_heartbeat_sent(now);
                    }
                    sent += 1;
                }
                Err(e) => {
                    debug!(
                        peer = %self.peer_display_name(&addr),
                        error = %e,
                        "Failed to send post-medium-change heartbeat"
                    );
                }
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
