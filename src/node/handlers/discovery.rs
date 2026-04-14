//! LookupRequest/LookupResponse discovery protocol handlers.
//!
//! Handles coordinate discovery via bloom-filter-guided tree routing.
//! Requests are forwarded only to tree peers (parent + children) whose
//! bloom filter contains the target. TTL and request_id dedup provide
//! safety bounds.

use crate::node::{Node, RecentRequest};
use crate::protocol::{LookupRequest, LookupResponse};
use crate::{NodeAddr, PeerIdentity};
use tracing::{debug, info, trace, warn};

impl Node {
    /// Handle an incoming LookupRequest from a peer.
    ///
    /// Processing steps:
    /// 1. Decode and validate
    /// 2. Check request_id for duplicates (dedup / reverse-path routing)
    /// 3. Record request for reverse-path forwarding
    /// 4. Lazy purge expired entries
    /// 5. If we're the target, generate and send response
    /// 6. If TTL > 0, forward to tree peers whose bloom filter matches
    pub(in crate::node) async fn handle_lookup_request(&mut self, from: &NodeAddr, payload: &[u8]) {
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

        // Dedup: drop if we've already seen this request_id.
        // Also serves as loop protection — tree routing is loop-free,
        // but request_id dedup catches edge cases during tree restructuring.
        if self.recent_requests.contains_key(&request.request_id) {
            self.stats_mut().discovery.req_duplicate += 1;
            debug!(
                request_id = request.request_id,
                from = %self.peer_display_name(from),
                "Duplicate LookupRequest, dropping"
            );
            return;
        }

        // Record for reverse-path forwarding and dedup
        self.recent_requests
            .insert(request.request_id, RecentRequest::new(*from, now_ms));

        // Lazy purge expired entries
        self.purge_expired_requests(now_ms);

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
            // Transit-side rate limit: collapse rapid-fire lookups for the
            // same target from misbehaving nodes generating fresh request_ids.
            if !self
                .discovery_forward_limiter
                .should_forward(&request.target)
            {
                self.stats_mut().discovery.req_forward_rate_limited += 1;
                debug!(
                    request_id = request.request_id,
                    target = %self.peer_display_name(&request.target),
                    "Forward rate limited, suppressing LookupRequest"
                );
                return;
            }
            self.stats_mut().discovery.req_forwarded += 1;
            self.forward_lookup_request(request).await;
        } else {
            self.stats_mut().discovery.req_ttl_exhausted += 1;
            debug!(
                request_id = request.request_id,
                target = %self.peer_display_name(&request.target),
                "LookupRequest TTL exhausted"
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
        if let Some(recent) = self.recent_requests.get_mut(&response.request_id) {
            // Already forwarded a response for this request — drop to
            // prevent response routing loops.
            if recent.response_forwarded {
                debug!(
                    request_id = response.request_id,
                    target = %self.peer_display_name(&response.target),
                    "Response already forwarded for this request, dropping"
                );
                return;
            }
            recent.response_forwarded = true;

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
            let proof_data =
                LookupResponse::proof_bytes(response.request_id, &target, &response.target_coords);
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

            // Clear backoff on success — target is reachable
            self.discovery_backoff.record_success(&target);

            info!(
                request_id = response.request_id,
                target = %self.peer_display_name(&target),
                depth = response.target_coords.depth(),
                path_mtu = path_mtu,
                "Discovery succeeded, proof verified, route cached"
            );

            self.coord_cache
                .insert_with_path_mtu(target, response.target_coords, now_ms, path_mtu);

            // Clean up pending lookup tracking
            self.pending_lookups.remove(&target);

            // If an established session exists, reset the warmup counter.
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
            if let Some(packets) = self.pending_tun_packets.get(&target) {
                debug!(
                    dest = %self.peer_display_name(&target),
                    queued_packets = packets.len(),
                    "Retrying queued packets after discovery"
                );
                self.retry_session_after_discovery(target).await;
            }
        }
    }

    /// Generate and send a LookupResponse when we are the target.
    async fn send_lookup_response(&mut self, request: &LookupRequest) {
        let our_coords = self.tree_state().my_coords().clone();

        // Sign proof: Identity::sign hashes with SHA-256 internally
        let proof_data =
            LookupResponse::proof_bytes(request.request_id, &request.target, &our_coords);
        let proof = self.identity().sign(&proof_data);

        let response = LookupResponse::new(request.request_id, request.target, our_coords, proof);

        // Route toward origin via reverse path.
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
        if let Err(e) = self
            .send_encrypted_link_message(&next_hop_addr, &encoded)
            .await
        {
            debug!(
                next_hop = %self.peer_display_name(&next_hop_addr),
                error = %e,
                "Failed to send LookupResponse"
            );
        }
    }

    /// Forward a LookupRequest to eligible peers.
    ///
    /// Primary path: tree peers (parent + children) whose bloom filter
    /// contains the target. Restricting to tree peers follows the spanning
    /// tree partition, producing a single directed path.
    ///
    /// Fallback: if no tree peer's bloom matches, try non-tree peers whose
    /// bloom contains the target. This recovers from dead ends caused by
    /// stale bloom filters, tree restructuring, or transit node failures.
    async fn forward_lookup_request(&mut self, mut request: LookupRequest) {
        if !request.forward() {
            return;
        }

        // Collect tree peers whose bloom filter contains the target
        let forward_to: Vec<NodeAddr> = self
            .peers
            .iter()
            .filter(|(addr, peer)| self.is_tree_peer(addr) && peer.may_reach(&request.target))
            .map(|(addr, _)| *addr)
            .collect();

        // Fallback: if no tree peer matches, try non-tree bloom-matching peers
        let (forward_to, used_fallback) = if forward_to.is_empty() {
            let fallback: Vec<NodeAddr> = self
                .peers
                .iter()
                .filter(|(addr, peer)| !self.is_tree_peer(addr) && peer.may_reach(&request.target))
                .map(|(addr, _)| *addr)
                .collect();
            if fallback.is_empty() {
                self.stats_mut().discovery.req_no_tree_peer += 1;
                trace!(
                    request_id = request.request_id,
                    "No eligible peers to forward LookupRequest"
                );
                return;
            }
            (fallback, true)
        } else {
            (forward_to, false)
        };

        if used_fallback {
            self.stats_mut().discovery.req_fallback_forwarded += 1;
            debug!(
                request_id = request.request_id,
                target = %self.peer_display_name(&request.target),
                ttl = request.ttl,
                peer_count = forward_to.len(),
                "Forwarding LookupRequest via non-tree fallback"
            );
        } else {
            debug!(
                request_id = request.request_id,
                target = %self.peer_display_name(&request.target),
                ttl = request.ttl,
                peer_count = forward_to.len(),
                "Forwarding LookupRequest"
            );
        }

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
    /// Creates a LookupRequest and sends it to tree peers whose bloom
    /// filters contain the target. Returns the number of peers sent to.
    /// The originator does NOT record the request_id in recent_requests,
    /// so when the response arrives, it's recognized as "our request".
    pub(in crate::node) async fn initiate_lookup(&mut self, target: &NodeAddr, ttl: u8) -> usize {
        self.stats_mut().discovery.req_initiated += 1;

        let origin = *self.node_addr();
        let origin_coords = self.tree_state().my_coords().clone();
        let request = LookupRequest::generate(*target, origin, origin_coords, ttl, 0);

        // Send only to tree peers whose bloom filter contains the target
        let peer_addrs: Vec<NodeAddr> = self
            .peers
            .iter()
            .filter(|(addr, peer)| self.is_tree_peer(addr) && peer.may_reach(target))
            .map(|(addr, _)| *addr)
            .collect();

        let peer_count = peer_addrs.len();

        debug!(
            request_id = request.request_id,
            target = %self.peer_display_name(target),
            ttl = ttl,
            peer_count = peer_count,
            total_peers = self.peers.len(),
            "Discovery lookup initiated"
        );

        if peer_count == 0 {
            return 0;
        }

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

        peer_count
    }

    /// Initiate a discovery lookup if one is not already pending for this target.
    ///
    /// Checks: pending dedup, backoff, bloom filter pre-check. If all pass,
    /// initiates the lookup. If no tree peers have the target in their bloom
    /// filter, the lookup is skipped (bloom miss) and recorded as a failure
    /// for backoff purposes.
    pub(in crate::node) async fn maybe_initiate_lookup(&mut self, dest: &NodeAddr) {
        let now_ms = Self::now_ms();
        let lookup_timeout_ms = self.config.node.discovery.timeout_secs * 1000;

        // Check pending lookup dedup (in-flight)
        if let Some(entry) = self.pending_lookups.get(dest) {
            let age_ms = now_ms.saturating_sub(entry.initiated_ms);
            let attempt = entry.attempt;
            if age_ms < lookup_timeout_ms {
                self.stats_mut().discovery.req_deduplicated += 1;
                debug!(
                    target_node = %self.peer_display_name(dest),
                    age_ms = age_ms,
                    attempt = attempt,
                    "Discovery lookup deduplicated, already pending"
                );
                return;
            }
        }

        // Check backoff from previous failures
        if self.discovery_backoff.is_suppressed(dest) {
            self.stats_mut().discovery.req_backoff_suppressed += 1;
            debug!(
                target_node = %self.peer_display_name(dest),
                failures = self.discovery_backoff.failure_count(dest),
                "Discovery lookup suppressed by backoff"
            );
            return;
        }

        // Bloom filter pre-check: if no peer's filter contains the target,
        // it's not in the mesh — skip the lookup and record as failure.
        let reachable = self.peers.values().any(|peer| peer.may_reach(dest));
        if !reachable {
            self.stats_mut().discovery.req_bloom_miss += 1;
            self.discovery_backoff.record_failure(dest);
            debug!(
                target_node = %self.peer_display_name(dest),
                "Discovery skipped, target not in any peer bloom filter"
            );
            return;
        }

        self.pending_lookups
            .insert(*dest, PendingLookup::new(now_ms));
        let ttl = self.config.node.discovery.ttl;
        let sent = self.initiate_lookup(dest, ttl).await;

        // If no tree peers had the target, fail immediately
        if sent == 0 {
            self.pending_lookups.remove(dest);
            self.discovery_backoff.record_failure(dest);
            debug!(
                target_node = %self.peer_display_name(dest),
                "Discovery failed, no tree peers with bloom match"
            );
        }
    }

    /// Check pending lookups for retry or timeout.
    ///
    /// Called periodically from the tick handler. For each pending lookup:
    /// - If retry interval elapsed and attempts remain: resend
    /// - If total timeout elapsed: fail, record backoff, send ICMP unreachable
    pub(in crate::node) async fn check_pending_lookups(&mut self, now_ms: u64) {
        let timeout_ms = self.config.node.discovery.timeout_secs * 1000;
        let retry_ms = self.config.node.discovery.retry_interval_secs * 1000;

        // Collect targets needing action
        let mut to_retry: Vec<NodeAddr> = Vec::new();
        let mut to_timeout: Vec<NodeAddr> = Vec::new();

        for (&target, entry) in &self.pending_lookups {
            let age = now_ms.saturating_sub(entry.initiated_ms);
            if age >= timeout_ms {
                to_timeout.push(target);
            } else if entry.attempt < self.config.node.discovery.max_attempts
                && now_ms.saturating_sub(entry.last_sent_ms) >= retry_ms
            {
                to_retry.push(target);
            }
        }

        // Process retries
        for target in to_retry {
            if let Some(entry) = self.pending_lookups.get_mut(&target) {
                entry.attempt += 1;
                entry.last_sent_ms = now_ms;
                let attempt = entry.attempt;

                let ttl = self.config.node.discovery.ttl;
                let sent = self.initiate_lookup(&target, ttl).await;
                if sent > 0 {
                    debug!(
                        target_node = %self.peer_display_name(&target),
                        attempt = attempt,
                        "Discovery retry sent"
                    );
                }
            }
        }

        // Process timeouts
        for addr in to_timeout {
            self.stats_mut().discovery.resp_timed_out += 1;
            self.pending_lookups.remove(&addr);

            // Record failure for backoff
            self.discovery_backoff.record_failure(&addr);
            let failures = self.discovery_backoff.failure_count(&addr);

            let queued = self.pending_tun_packets.remove(&addr);
            let pkt_count = queued.as_ref().map_or(0, |p| p.len());
            info!(
                target_node = %self.peer_display_name(&addr),
                queued_packets = pkt_count,
                failures = failures,
                "Discovery lookup timed out, destination unreachable"
            );
            if let Some(packets) = queued {
                for pkt in &packets {
                    self.send_icmpv6_dest_unreachable(pkt);
                }
            }
        }
    }

    /// Reset discovery backoff on topology changes.
    pub(in crate::node) fn reset_discovery_backoff(&mut self) {
        if !self.discovery_backoff.is_empty() {
            debug!(
                entries = self.discovery_backoff.entry_count(),
                "Resetting discovery backoff on topology change"
            );
            self.discovery_backoff.reset_all();
        }
    }

    /// Remove expired entries from the recent_requests cache.
    fn purge_expired_requests(&mut self, current_time_ms: u64) {
        let expiry_ms = self.config.node.discovery.recent_expiry_secs * 1000;
        self.recent_requests
            .retain(|_, entry| !entry.is_expired(current_time_ms, expiry_ms));
    }
}

/// Tracks a pending discovery lookup with retry state.
pub struct PendingLookup {
    /// When the lookup was first initiated.
    pub initiated_ms: u64,
    /// When the last attempt was sent.
    pub last_sent_ms: u64,
    /// Current attempt number (1 = initial, 2 = first retry, ...).
    pub attempt: u8,
}

impl PendingLookup {
    pub fn new(now_ms: u64) -> Self {
        Self {
            initiated_ms: now_ms,
            last_sent_ms: now_ms,
            attempt: 1,
        }
    }
}
