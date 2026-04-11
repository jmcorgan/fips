//! Periodic rekey (key rotation) for FMP link sessions.
//!
//! Checks all active peers on each tick for:
//! 1. Rekey trigger (time elapsed or send counter exceeded)
//! 2. Drain window expiry (clean up previous session after cutover)
//! 3. Initiator-side cutover (first send after handshake completion)

use crate::NodeAddr;
use crate::node::Node;
use crate::node::wire::build_msg1;
use crate::noise::HandshakeState;
use crate::protocol::{SessionDatagram, SessionSetup};
use tracing::{debug, trace, warn};

/// Keep previous session alive for this long after cutover.
const DRAIN_WINDOW_SECS: u64 = 10;

/// Suppress local rekey initiation for this long after receiving
/// a peer's rekey msg1.
const REKEY_DAMPENING_SECS: u64 = 30;

/// Delay FSP initiator cutover after handshake completion to allow
/// XX msg3 to reach the responder before K-bit-flipped data arrives.
const FSP_CUTOVER_DELAY_MS: u64 = 2000;

impl Node {
    /// Periodic rekey check. Called from the tick loop.
    ///
    /// For each active peer with a session:
    /// - If the initiator has a pending session, perform K-bit cutover
    /// - If the drain window has expired, clean up the previous session
    /// - If the rekey timer/counter fires, initiate a new handshake
    pub(in crate::node) async fn check_rekey(&mut self) {
        if !self.config.node.rekey.enabled {
            return;
        }

        let rekey_after_secs = self.config.node.rekey.after_secs;
        let rekey_after_messages = self.config.node.rekey.after_messages;

        // Collect peers that need action (to avoid borrow conflicts)
        let mut peers_to_cutover: Vec<NodeAddr> = Vec::new();
        let mut peers_to_drain: Vec<NodeAddr> = Vec::new();
        let mut peers_to_rekey: Vec<NodeAddr> = Vec::new();

        for (node_addr, peer) in &self.peers {
            if !peer.has_session() || !peer.is_healthy() {
                continue;
            }

            // 1. Initiator-side cutover: we completed a rekey and have
            //    a pending session ready. Cut over on the next tick.
            if peer.pending_new_session().is_some() && !peer.rekey_in_progress() {
                peers_to_cutover.push(*node_addr);
                continue;
            }

            // 2. Drain window expiry
            if peer.is_draining() && peer.drain_expired(DRAIN_WINDOW_SECS) {
                peers_to_drain.push(*node_addr);
            }

            // 3. Rekey trigger
            if peer.rekey_in_progress() {
                continue;
            }
            if peer.is_rekey_dampened(REKEY_DAMPENING_SECS) {
                continue;
            }

            let elapsed = peer.session_established_at().elapsed().as_secs();
            let counter = peer
                .noise_session()
                .map(|s| s.current_send_counter())
                .unwrap_or(0);

            if elapsed >= rekey_after_secs || counter >= rekey_after_messages {
                peers_to_rekey.push(*node_addr);
            }
        }

        // Execute cutover for initiator side
        for node_addr in peers_to_cutover {
            if let Some(peer) = self.peers.get_mut(&node_addr)
                && let Some(_old_our_index) = peer.cutover_to_new_session()
            {
                // New index was pre-registered in peers_by_index during
                // msg2 handling (handshake.rs). Verify, don't duplicate.
                debug_assert!(
                    peer.transport_id().is_some()
                        && peer.our_index().is_some()
                        && self.peers_by_index.contains_key(&(
                            peer.transport_id().unwrap(),
                            peer.our_index().unwrap().as_u32()
                        )),
                    "peers_by_index should contain pre-registered new index after cutover"
                );
                debug!(
                    peer = %self.peer_display_name(&node_addr),
                    "Rekey cutover complete (initiator), K-bit flipped"
                );
            }
        }

        // Execute drain completion
        for node_addr in peers_to_drain {
            if let Some(peer) = self.peers.get_mut(&node_addr)
                && let Some(old_our_index) = peer.complete_drain()
            {
                if let Some(transport_id) = peer.transport_id() {
                    self.peers_by_index
                        .remove(&(transport_id, old_our_index.as_u32()));
                }
                let _ = self.index_allocator.free(old_our_index);
                trace!(
                    peer = %self.peer_display_name(&node_addr),
                    old_index = %old_our_index,
                    "Drain complete, previous session erased"
                );
            }
        }

        // Initiate new rekeys
        for node_addr in peers_to_rekey {
            self.initiate_rekey(&node_addr).await;
        }
    }

    /// Initiate an outbound rekey to a peer.
    ///
    /// Creates a new XX handshake as initiator, sends msg1 over the existing
    /// link (same transport, same remote address), and stores the handshake
    /// state on the ActivePeer. No new Link or PeerConnection is created.
    async fn initiate_rekey(&mut self, node_addr: &NodeAddr) {
        let peer = match self.peers.get(node_addr) {
            Some(p) => p,
            None => return,
        };

        let transport_id = match peer.transport_id() {
            Some(t) => t,
            None => return,
        };
        let remote_addr = match peer.current_addr() {
            Some(a) => a.clone(),
            None => return,
        };
        let link_id = peer.link_id();

        // Allocate a new session index for the rekey
        let our_index = match self.index_allocator.allocate() {
            Ok(idx) => idx,
            Err(e) => {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    error = %e,
                    "Failed to allocate index for rekey"
                );
                return;
            }
        };

        // Create XX initiator handshake directly (no PeerConnection)
        let our_keypair = self.identity.keypair();
        let mut hs = HandshakeState::new_initiator(our_keypair);
        hs.set_local_epoch(self.startup_epoch);

        let noise_msg1 = match hs.write_message_1() {
            Ok(msg) => msg,
            Err(e) => {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    error = %e,
                    "Failed to generate rekey msg1"
                );
                let _ = self.index_allocator.free(our_index);
                return;
            }
        };

        let wire_msg1 = build_msg1(our_index, &noise_msg1);

        // Send msg1 on the existing link (same transport + address)
        if let Some(transport) = self.transports.get(&transport_id) {
            match transport.send(&remote_addr, &wire_msg1).await {
                Ok(_) => {
                    debug!(
                        peer = %self.peer_display_name(node_addr),
                        our_index = %our_index,
                        "Rekey initiated, sent msg1 on existing link"
                    );
                }
                Err(e) => {
                    warn!(
                        peer = %self.peer_display_name(node_addr),
                        error = %e,
                        "Failed to send rekey msg1"
                    );
                    let _ = self.index_allocator.free(our_index);
                    return;
                }
            }
        }

        // Store handshake state on the ActivePeer (not a separate PeerConnection)
        let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
        let now_ms = Self::now_ms();
        if let Some(peer) = self.peers.get_mut(node_addr) {
            peer.set_rekey_state(hs, our_index, wire_msg1, now_ms + resend_interval);
        }

        // Register in pending_outbound for msg2 dispatch (maps to existing link)
        self.pending_outbound
            .insert((transport_id, our_index.as_u32()), link_id);
    }

    /// Resend pending rekey msg1s and abandon timed-out rekeys.
    ///
    /// Called from the tick loop. Uses the same resend interval and max
    /// resend count as initial handshakes.
    pub(in crate::node) async fn resend_pending_rekeys(&mut self, now_ms: u64) {
        if !self.config.node.rekey.enabled {
            return;
        }

        let interval_ms = self.config.node.rate_limit.handshake_resend_interval_ms;

        // Collect peers needing action
        let mut to_resend: Vec<(NodeAddr, Vec<u8>)> = Vec::new();

        for (node_addr, peer) in &self.peers {
            if !peer.rekey_in_progress() || peer.rekey_msg1().is_none() {
                continue;
            }
            if peer.needs_msg1_resend(now_ms)
                && let Some(msg1) = peer.rekey_msg1()
            {
                to_resend.push((*node_addr, msg1.to_vec()));
            }
        }

        for (node_addr, msg1_bytes) in to_resend {
            let (transport_id, remote_addr) = match self.peers.get(&node_addr) {
                Some(p) => match (p.transport_id(), p.current_addr()) {
                    (Some(tid), Some(addr)) => (tid, addr.clone()),
                    _ => continue,
                },
                None => continue,
            };

            let sent = if let Some(transport) = self.transports.get(&transport_id) {
                transport.send(&remote_addr, &msg1_bytes).await.is_ok()
            } else {
                false
            };

            if sent {
                if let Some(peer) = self.peers.get_mut(&node_addr) {
                    peer.set_msg1_next_resend(now_ms + interval_ms);
                }
                trace!(
                    peer = %self.peer_display_name(&node_addr),
                    "Resent rekey msg1"
                );
            }
        }
    }

    /// Periodic session (FSP) rekey check. Called from the tick loop.
    ///
    /// For each established session:
    /// - If the initiator has a pending session, perform K-bit cutover
    /// - If the drain window has expired, clean up the previous session
    /// - If the rekey timer/counter fires, initiate a new XX handshake
    pub(in crate::node) async fn check_session_rekey(&mut self) {
        if !self.config.node.rekey.enabled {
            return;
        }

        let rekey_after_secs = self.config.node.rekey.after_secs;
        let rekey_after_messages = self.config.node.rekey.after_messages;
        let now_ms = Self::now_ms();
        let drain_ms = DRAIN_WINDOW_SECS * 1000;
        let dampening_ms = REKEY_DAMPENING_SECS * 1000;

        let mut sessions_to_cutover: Vec<NodeAddr> = Vec::new();
        let mut sessions_to_drain: Vec<NodeAddr> = Vec::new();
        let mut sessions_to_rekey: Vec<NodeAddr> = Vec::new();

        for (node_addr, entry) in &self.sessions {
            if !entry.is_established() {
                continue;
            }

            // 1. Initiator-side cutover: completed rekey, pending session ready.
            //    Defer cutover until msg3 has had time to reach the responder.
            //    Without this delay, K-bit-flipped data can arrive before
            //    msg3, causing decryption failures on the responder.
            if entry.pending_new_session().is_some()
                && !entry.has_rekey_in_progress()
                && entry.is_rekey_initiator()
                && now_ms.saturating_sub(entry.rekey_completed_ms()) >= FSP_CUTOVER_DELAY_MS
            {
                sessions_to_cutover.push(*node_addr);
                continue;
            }

            // 2. Drain window expiry
            if entry.is_draining() && entry.drain_expired(now_ms, drain_ms) {
                sessions_to_drain.push(*node_addr);
            }

            // 3. Rekey trigger
            if entry.has_rekey_in_progress() {
                continue;
            }
            if entry.pending_new_session().is_some() {
                continue; // Responder with pending session, wait for initiator's K-bit
            }
            if entry.is_rekey_dampened(now_ms, dampening_ms) {
                continue;
            }

            let elapsed_secs = now_ms.saturating_sub(entry.session_start_ms()) / 1000;
            let counter = entry.send_counter();

            if elapsed_secs >= rekey_after_secs || counter >= rekey_after_messages {
                sessions_to_rekey.push(*node_addr);
            }
        }

        // Execute cutover for initiator side
        for node_addr in sessions_to_cutover {
            if let Some(entry) = self.sessions.get_mut(&node_addr)
                && entry.cutover_to_new_session(now_ms)
            {
                debug!(
                    peer = %self.peer_display_name(&node_addr),
                    "FSP rekey cutover complete (initiator), K-bit flipped"
                );
            }
        }

        // Execute drain completion
        for node_addr in sessions_to_drain {
            if let Some(entry) = self.sessions.get_mut(&node_addr) {
                entry.complete_drain();
                trace!(
                    peer = %self.peer_display_name(&node_addr),
                    "FSP drain complete, previous session erased"
                );
            }
        }

        // Initiate new rekeys
        for node_addr in sessions_to_rekey {
            self.initiate_session_rekey(&node_addr).await;
        }
    }

    /// Initiate an FSP session rekey.
    ///
    /// Creates a new XX handshake as initiator, sends SessionSetup msg1
    /// through the mesh, and stores the handshake state on the existing entry.
    async fn initiate_session_rekey(&mut self, dest_addr: &NodeAddr) {
        // Check route availability before paying crypto cost
        if self.find_next_hop(dest_addr).is_none() {
            trace!(
                peer = %self.peer_display_name(dest_addr),
                "FSP rekey skipped: no route to destination"
            );
            return;
        }

        let entry = match self.sessions.get(dest_addr) {
            Some(e) => e,
            None => return,
        };
        let _dest_pubkey = *entry.remote_pubkey();

        // Create Noise XX initiator handshake (rekey: no negotiation payload)
        let our_keypair = self.identity.keypair();
        let mut handshake = HandshakeState::new_initiator(our_keypair);
        handshake.set_local_epoch(self.startup_epoch);

        let msg1 = match handshake.write_message_1() {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    peer = %self.peer_display_name(dest_addr),
                    error = %e,
                    "Failed to generate FSP rekey XX msg1"
                );
                return;
            }
        };

        // Build SessionSetup with coordinates
        let our_coords = self.tree_state.my_coords().clone();
        let dest_coords = self.get_dest_coords(dest_addr);
        let setup = SessionSetup::new(our_coords, dest_coords).with_handshake(msg1);
        let setup_payload = setup.encode();

        // Send through the mesh
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *dest_addr, setup_payload)
            .with_ttl(self.config.node.session.default_ttl);

        if let Err(e) = self.send_session_datagram(&mut datagram).await {
            debug!(
                peer = %self.peer_display_name(dest_addr),
                error = %e,
                "Failed to send FSP rekey SessionSetup"
            );
            return;
        }

        // Store rekey state on the existing session entry
        if let Some(entry) = self.sessions.get_mut(dest_addr) {
            entry.set_rekey_state(handshake, true);
        }

        debug!(
            peer = %self.peer_display_name(dest_addr),
            "FSP rekey initiated, sent SessionSetup"
        );
    }
}
