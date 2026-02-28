//! LookupRequest/LookupResponse discovery protocol handlers.
//!
//! Handles coordinate discovery requests: flood-based lookup with TTL,
//! visited filter for loop prevention, and reverse-path forwarding for
//! responses.

use crate::node::{Node, RecentRequest};
use crate::protocol::{LookupRequest, LookupResponse};
use crate::{NodeAddr, PeerIdentity};
use tracing::{debug, trace, warn};

impl Node {
    /// Handle an incoming LookupRequest from a peer.
    ///
    /// Processing steps:
    /// 1. Decode and validate
    /// 2. Check request_id for duplicates (dedup)
    /// 3. Record request for reverse-path forwarding
    /// 4. Lazy purge expired entries
    /// 5. Check visited filter (loop prevention)
    /// 6. If we're the target, generate and send response
    /// 7. If TTL > 0, forward to peers not in visited filter
    pub(in crate::node) async fn handle_lookup_request(
        &mut self,
        from: &NodeAddr,
        payload: &[u8],
    ) {
        self.stats_mut().discovery.req_received += 1;

        let request = match LookupRequest::decode(payload) {
            Ok(req) => req,
            Err(e) => {
                self.stats_mut().discovery.req_decode_error += 1;
                debug!(from = %self.peer_display_name(from), error = %e, "Malformed LookupRequest");
                return;
            }
        };

        let now_ms = Self::now_ms();

        // Dedup: drop if we've already seen this request_id
        if self.recent_requests.contains_key(&request.request_id) {
            self.stats_mut().discovery.req_duplicate += 1;
            trace!(
                request_id = request.request_id,
                from = %self.peer_display_name(from),
                "Duplicate LookupRequest, dropping"
            );
            return;
        }

        // Record for reverse-path forwarding and dedup
        self.recent_requests.insert(
            request.request_id,
            RecentRequest::new(*from, now_ms),
        );

        // Lazy purge expired entries
        self.purge_expired_requests(now_ms);

        // Loop prevention: drop if we've already been visited
        if request.was_visited(self.node_addr()) {
            self.stats_mut().discovery.req_already_visited += 1;
            trace!(
                request_id = request.request_id,
                target = %self.peer_display_name(&request.target),
                "Already visited, dropping LookupRequest"
            );
            return;
        }

        // Are we the target?
        if request.target == *self.node_addr() {
            self.stats_mut().discovery.req_target_is_us += 1;
            debug!(
                request_id = request.request_id,
                origin = %self.peer_display_name(&request.origin),
                "We are the lookup target, generating response"
            );
            self.send_lookup_response(&request).await;
            return;
        }

        // Forward if TTL permits
        if request.can_forward() {
            self.stats_mut().discovery.req_forwarded += 1;
            self.forward_lookup_request(request).await;
        } else {
            self.stats_mut().discovery.req_ttl_exhausted += 1;
            trace!(
                request_id = request.request_id,
                target = %self.peer_display_name(&request.target),
                "LookupRequest TTL exhausted, not forwarding"
            );
        }
    }

    /// Handle an incoming LookupResponse from a peer.
    ///
    /// Processing steps:
    /// 1. Decode and validate
    /// 2. Check recent_requests to determine if we originated or are forwarding
    /// 3. If originator: verify proof signature, then cache target_coords and path_mtu in coord_cache
    /// 4. If transit: apply path_mtu min(outgoing_link_mtu), reverse-path forward to from_peer
    pub(in crate::node) async fn handle_lookup_response(
        &mut self,
        from: &NodeAddr,
        payload: &[u8],
    ) {
        self.stats_mut().discovery.resp_received += 1;

        let mut response = match LookupResponse::decode(payload) {
            Ok(resp) => resp,
            Err(e) => {
                self.stats_mut().discovery.resp_decode_error += 1;
                debug!(from = %self.peer_display_name(from), error = %e, "Malformed LookupResponse");
                return;
            }
        };

        let now_ms = Self::now_ms();

        // Check if we forwarded this request (transit node) or originated it
        if let Some(recent) = self.recent_requests.get(&response.request_id) {
            // Transit node: reverse-path forward
            let from_peer = recent.from_peer;
            self.stats_mut().discovery.resp_forwarded += 1;

            // Apply path_mtu min() from the outgoing link's transport MTU
            if let Some(peer) = self.peers.get(&from_peer)
                && let Some(tid) = peer.transport_id()
                && let Some(transport) = self.transports.get(&tid)
            {
                if let Some(addr) = peer.current_addr() {
                    response.path_mtu = response.path_mtu.min(transport.link_mtu(addr));
                } else {
                    response.path_mtu = response.path_mtu.min(transport.mtu());
                }
            }

            debug!(
                request_id = response.request_id,
                target = %self.peer_display_name(&response.target),
                next_hop = %self.peer_display_name(&from_peer),
                path_mtu = response.path_mtu,
                "Reverse-path forwarding LookupResponse"
            );

            let encoded = response.encode();
            if let Err(e) = self.send_encrypted_link_message(&from_peer, &encoded).await {
                debug!(
                    next_hop = %self.peer_display_name(&from_peer),
                    error = %e,
                    "Failed to forward LookupResponse"
                );
            }
        } else {
            // We originated this request — verify proof before caching
            let target = response.target;
            let path_mtu = response.path_mtu;

            // Look up the target's public key from identity_cache
            let mut prefix = [0u8; 15];
            prefix.copy_from_slice(&target.as_bytes()[0..15]);
            let target_pubkey = match self.lookup_by_fips_prefix(&prefix) {
                Some((_addr, pubkey)) => pubkey,
                None => {
                    self.stats_mut().discovery.resp_identity_miss += 1;
                    warn!(
                        request_id = response.request_id,
                        target = %self.peer_display_name(&target),
                        "identity_cache miss for lookup target, cannot verify proof"
                    );
                    return;
                }
            };

            // Verify the proof signature
            let (xonly, _parity) = target_pubkey.x_only_public_key();
            let peer_id = PeerIdentity::from_pubkey(xonly);
            let proof_data = LookupResponse::proof_bytes(
                response.request_id,
                &target,
                &response.target_coords,
            );
            if !peer_id.verify(&proof_data, &response.proof) {
                self.stats_mut().discovery.resp_proof_failed += 1;
                warn!(
                    request_id = response.request_id,
                    target = %self.peer_display_name(&target),
                    "LookupResponse proof verification failed, discarding"
                );
                return;
            }

            self.stats_mut().discovery.resp_accepted += 1;

            debug!(
                request_id = response.request_id,
                target = %self.peer_display_name(&target),
                depth = response.target_coords.depth(),
                path_mtu = path_mtu,
                "Received LookupResponse, proof verified, caching route"
            );

            self.coord_cache.insert_with_path_mtu(
                target,
                response.target_coords,
                now_ms,
                path_mtu,
            );

            // Clean up pending lookup tracking
            self.pending_lookups.remove(&target);

            // If an established session exists, reset the warmup counter.
            // Discovery has completed and transit nodes along the response
            // path now have fresh coords. Reset warmup so the next N
            // data packets include COORDS_PRESENT to re-warm the forward path.
            if let Some(entry) = self.sessions.get_mut(&target)
                && entry.is_established()
            {
                let n = self.config.node.session.coords_warmup_packets;
                entry.set_coords_warmup_remaining(n);
                debug!(
                    dest = %self.peer_display_name(&target),
                    warmup_packets = n,
                    "Reset coords warmup after discovery for existing session"
                );
            }

            // If we have pending TUN packets for this target, retry session
            // initiation. The coord_cache now has coords, so find_next_hop()
            // should succeed.
            if self.pending_tun_packets.contains_key(&target) {
                self.retry_session_after_discovery(target).await;
            }
        }
    }

    /// Generate and send a LookupResponse when we are the target.
    ///
    /// Signs a proof using our identity and routes the response back
    /// toward the origin via reverse-path forwarding. The first hop
    /// uses the `recent_requests` entry (which records who sent us the
    /// request), ensuring the response follows the same path the
    /// request took. This is critical because greedy tree routing
    /// might send the response to a peer that never forwarded the
    /// request and thus has no `recent_requests` entry, causing the
    /// response to be discarded.
    async fn send_lookup_response(&mut self, request: &LookupRequest) {
        let our_coords = self.tree_state().my_coords().clone();

        // Sign proof: Identity::sign hashes with SHA-256 internally
        let proof_data = LookupResponse::proof_bytes(request.request_id, &request.target, &our_coords);
        let proof = self.identity().sign(&proof_data);

        let response = LookupResponse::new(
            request.request_id,
            request.target,
            our_coords,
            proof,
        );

        // Route toward origin via reverse path. The recent_requests entry
        // was recorded before we got here (line 49-51), so from_peer is
        // the node that forwarded the request to us — the correct first
        // hop for the response's reverse path.
        let next_hop_addr = if let Some(recent) = self.recent_requests.get(&request.request_id) {
            recent.from_peer
        } else {
            // Fallback: try greedy tree routing toward origin
            match self.find_next_hop(&request.origin) {
                Some(peer) => *peer.node_addr(),
                None => {
                    debug!(
                        origin = %self.peer_display_name(&request.origin),
                        "Cannot route LookupResponse: no reverse path or tree route to origin"
                    );
                    return;
                }
            }
        };

        debug!(
            request_id = request.request_id,
            origin = %self.peer_display_name(&request.origin),
            next_hop = %self.peer_display_name(&next_hop_addr),
            "Sending LookupResponse"
        );

        let encoded = response.encode();
        if let Err(e) = self.send_encrypted_link_message(&next_hop_addr, &encoded).await {
            debug!(
                next_hop = %self.peer_display_name(&next_hop_addr),
                error = %e,
                "Failed to send LookupResponse"
            );
        }
    }

    /// Forward a LookupRequest to peers not in the visited filter.
    ///
    /// Decrements TTL, adds self to visited, and sends to all eligible peers.
    async fn forward_lookup_request(&mut self, mut request: LookupRequest) {
        if !request.forward(self.node_addr()) {
            return;
        }

        // Collect peers not in visited filter
        let forward_to: Vec<NodeAddr> = self
            .peers
            .keys()
            .filter(|addr| !request.was_visited(addr))
            .copied()
            .collect();

        if forward_to.is_empty() {
            trace!(
                request_id = request.request_id,
                "No eligible peers to forward LookupRequest"
            );
            return;
        }

        debug!(
            request_id = request.request_id,
            target = %self.peer_display_name(&request.target),
            ttl = request.ttl,
            peer_count = forward_to.len(),
            "Forwarding LookupRequest"
        );

        let encoded = request.encode();

        for peer_addr in forward_to {
            if let Err(e) = self.send_encrypted_link_message(&peer_addr, &encoded).await {
                debug!(
                    peer = %self.peer_display_name(&peer_addr),
                    error = %e,
                    "Failed to forward LookupRequest to peer"
                );
            }
        }
    }

    /// Initiate a discovery lookup for a target node.
    ///
    /// Creates a LookupRequest and floods it to all peers. The originator
    /// does NOT record the request_id in recent_requests, so when the
    /// response arrives, it's recognized as "our request" and the
    /// target's coordinates are cached in coord_cache.
    pub(in crate::node) async fn initiate_lookup(&mut self, target: &NodeAddr, ttl: u8) {
        self.stats_mut().discovery.req_initiated += 1;

        let origin = *self.node_addr();
        let origin_coords = self.tree_state().my_coords().clone();
        let mut request = LookupRequest::generate(*target, origin, origin_coords, ttl, 0);

        // Add ourselves to the visited filter so forwarding nodes
        // won't send the request back to us
        request.visited.insert(&origin);

        debug!(
            request_id = request.request_id,
            target = %self.peer_display_name(target),
            ttl = ttl,
            "Initiating LookupRequest"
        );

        // Send to all peers (flood)
        let peer_addrs: Vec<NodeAddr> = self.peers.keys().copied().collect();
        let encoded = request.encode();

        for peer_addr in peer_addrs {
            if let Err(e) = self.send_encrypted_link_message(&peer_addr, &encoded).await {
                debug!(
                    peer = %self.peer_display_name(&peer_addr),
                    error = %e,
                    "Failed to send LookupRequest to peer"
                );
            }
        }
    }

    /// Initiate a discovery lookup if one is not already pending for this target.
    ///
    /// Deduplicates lookups using `pending_lookups` with a timeout. If a
    /// lookup was recently initiated and hasn't timed out, this is a no-op.
    pub(in crate::node) async fn maybe_initiate_lookup(&mut self, dest: &NodeAddr) {
        let now_ms = Self::now_ms();
        let lookup_timeout_ms = self.config.node.discovery.timeout_secs * 1000;
        if let Some(&initiated_at) = self.pending_lookups.get(dest)
            && now_ms.saturating_sub(initiated_at) < lookup_timeout_ms
        {
            self.stats_mut().discovery.req_deduplicated += 1;
            return;
        }
        self.pending_lookups.insert(*dest, now_ms);
        let ttl = self.config.node.discovery.ttl;
        self.initiate_lookup(dest, ttl).await;
    }

    /// Remove timed-out pending lookups and drain their queued packets.
    ///
    /// Called periodically from the tick handler. For each timed-out lookup,
    /// sends ICMPv6 Destination Unreachable for any queued TUN packets and
    /// removes them from the pending queue.
    pub(in crate::node) fn purge_stale_lookups(&mut self, now_ms: u64) {
        let timed_out: Vec<NodeAddr> = self
            .pending_lookups
            .iter()
            .filter(|&(_, &ts)| now_ms.saturating_sub(ts) >= self.config.node.discovery.timeout_secs * 1000)
            .map(|(addr, _)| *addr)
            .collect();

        for addr in timed_out {
            self.stats_mut().discovery.resp_timed_out += 1;
            self.pending_lookups.remove(&addr);
            if let Some(packets) = self.pending_tun_packets.remove(&addr) {
                for pkt in &packets {
                    self.send_icmpv6_dest_unreachable(pkt);
                }
            }
        }
    }

    /// Remove expired entries from the recent_requests cache.
    fn purge_expired_requests(&mut self, current_time_ms: u64) {
        let expiry_ms = self.config.node.discovery.recent_expiry_secs * 1000;
        self.recent_requests
            .retain(|_, entry| !entry.is_expired(current_time_ms, expiry_ms));
    }

}
