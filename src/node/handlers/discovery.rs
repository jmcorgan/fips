//! LookupRequest/LookupResponse discovery protocol handlers.
//!
//! Handles coordinate discovery via bloom-filter-guided tree routing.
//! Requests are forwarded only to tree peers (parent + children) whose
//! bloom filter contains the target. TTL and request_id dedup provide
//! safety bounds.

use crate::node::Node;
use crate::node::reject::DiscoveryReject;
use crate::proto::lookup::{
    LookupAction, LookupRequest, LookupResponse, MAX_RECENT_LOOKUP_REQUESTS,
};
use crate::transport::{TransportAddr, TransportId};
use crate::{NodeAddr, PeerIdentity};
use tracing::{debug, info, trace, warn};

/// Shell adapter exposing the live routing tables to the sans-IO discovery
/// core's `RoutingView` read seam. Lives in `node` so it can read `Node`'s
/// private `peers` map and call the crate-private tree/bloom predicates.
///
/// Holding `&Node` whole is fine for the forward path because it does not
/// also need `&mut self.discovery` concurrently. A later commit whose core
/// step needs `&mut discovery` while reading routing state should narrow this
/// to borrow only `peers` + `tree_state` instead of the whole node.
struct NodeRoutingView<'a> {
    node: &'a Node,
}

impl crate::proto::lookup::RoutingView for NodeRoutingView<'_> {
    fn is_tree_peer(&self, addr: &NodeAddr) -> bool {
        self.node.is_tree_peer(addr)
    }
    fn peers_reaching(&self, target: &NodeAddr) -> Vec<NodeAddr> {
        self.node
            .peers
            .iter()
            .filter(|(_, peer)| peer.may_reach(target))
            .map(|(addr, _)| *addr)
            .collect()
    }
    fn node_is_leaf(&self) -> bool {
        self.node.node_profile() == crate::proto::fmp::NodeProfile::Leaf
    }
    fn peer_is_full(&self, addr: &NodeAddr) -> bool {
        self.node
            .peers
            .get(addr)
            .is_some_and(|peer| peer.peer_profile() == crate::proto::fmp::NodeProfile::Full)
    }
    fn peer_meets_mtu(&self, addr: &NodeAddr, min_mtu: u16) -> bool {
        self.node
            .peers
            .get(addr)
            .is_some_and(|peer| self.node.peer_meets_mtu(peer, min_mtu))
    }
}

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
        self.metrics().discovery.req_received.inc();

        let request = match LookupRequest::decode(payload) {
            Ok(req) => req,
            Err(e) => {
                self.metrics()
                    .discovery
                    .record_reject(DiscoveryReject::ReqDecodeError);
                debug!(from = %self.peer_display_name(from), error = %e, "Malformed LookupRequest");
                return;
            }
        };

        let now_ms = Self::now_ms();
        let recent_expiry_ms = self.config().node.discovery.recent_expiry_secs * 1000;
        let my_addr = *self.node_addr();
        use crate::proto::lookup::RequestOutcome;
        match crate::proto::lookup::classify_request(
            &mut self.discovery,
            &request,
            from,
            &my_addr,
            now_ms,
            recent_expiry_ms,
            MAX_RECENT_LOOKUP_REQUESTS,
        ) {
            RequestOutcome::Duplicate => {
                self.metrics()
                    .discovery
                    .record_reject(DiscoveryReject::ReqDuplicate);
                debug!(
                    request_id = request.request_id,
                    from = %self.peer_display_name(from),
                    "Duplicate LookupRequest, dropping"
                );
            }
            RequestOutcome::DedupCacheFull { len } => {
                self.metrics()
                    .discovery
                    .record_reject(DiscoveryReject::ReqDedupCacheFull);
                debug!(
                    request_id = request.request_id,
                    from = %self.peer_display_name(from),
                    recent_requests = len,
                    max_recent_requests = MAX_RECENT_LOOKUP_REQUESTS,
                    "Discovery request dedup cache full, dropping LookupRequest"
                );
            }
            RequestOutcome::RespondAsTarget => {
                self.metrics().discovery.req_target_is_us.inc();
                debug!(
                    request_id = request.request_id,
                    origin = %self.peer_display_name(&request.origin),
                    "We are the lookup target, generating response"
                );
                self.send_lookup_response(&request).await;
            }
            RequestOutcome::Forward => {
                self.metrics().discovery.req_forwarded.inc();
                self.forward_lookup_request(request).await;
            }
            RequestOutcome::ForwardRateLimited => {
                self.metrics().discovery.req_forward_rate_limited.inc();
                debug!(
                    request_id = request.request_id,
                    target = %self.peer_display_name(&request.target),
                    "Forward rate limited, suppressing LookupRequest"
                );
            }
            RequestOutcome::TtlExhausted => {
                self.metrics()
                    .discovery
                    .record_reject(DiscoveryReject::ReqTtlExhausted);
                debug!(
                    request_id = request.request_id,
                    target = %self.peer_display_name(&request.target),
                    "LookupRequest TTL exhausted"
                );
            }
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
        self.metrics().discovery.resp_received.inc();

        let mut response = match LookupResponse::decode(payload) {
            Ok(resp) => resp,
            Err(e) => {
                self.metrics()
                    .discovery
                    .record_reject(DiscoveryReject::RespDecodeError);
                debug!(from = %self.peer_display_name(from), error = %e, "Malformed LookupResponse");
                return;
            }
        };

        let now_ms = Self::now_ms();

        // Check if we forwarded this request (transit node) or originated it
        match crate::proto::lookup::classify_response(&mut self.discovery, response.request_id) {
            crate::proto::lookup::ResponseRoute::AlreadyForwarded => {
                // Already forwarded a response for this request — drop to
                // prevent response routing loops.
                debug!(
                    request_id = response.request_id,
                    target = %self.peer_display_name(&response.target),
                    "Response already forwarded for this request, dropping"
                );
            }
            crate::proto::lookup::ResponseRoute::Transit { from_peer } => {
                // Transit node: reverse-path forward
                self.metrics().discovery.resp_forwarded.inc();

                // Apply path_mtu min() from the outgoing link's transport MTU
                self.apply_outgoing_link_mtu_to_response(&mut response, &from_peer);

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
            }
            crate::proto::lookup::ResponseRoute::Originator => {
                // We originated this request — verify proof before caching
                let target = response.target;
                let path_mtu = response.path_mtu;

                // Look up the target's public key from identity_cache
                let mut prefix = [0u8; 15];
                prefix.copy_from_slice(&target.as_bytes()[0..15]);
                let target_pubkey = match self.lookup_by_fips_prefix(&prefix) {
                    Some((_addr, pubkey)) => pubkey,
                    None => {
                        self.metrics()
                            .discovery
                            .record_reject(DiscoveryReject::RespIdentityMiss);
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
                    self.metrics()
                        .discovery
                        .record_reject(DiscoveryReject::RespProofFailed);
                    warn!(
                        request_id = response.request_id,
                        target = %self.peer_display_name(&target),
                        "LookupResponse proof verification failed, discarding"
                    );
                    return;
                }

                self.metrics().discovery.resp_accepted.inc();

                info!(
                    request_id = response.request_id,
                    target = %self.peer_display_name(&target),
                    depth = response.target_coords.depth(),
                    path_mtu = path_mtu,
                    "Discovery succeeded, proof verified, route cached"
                );

                // Apply the accept-side effects: the core clears the success
                // state (backoff + pending lookup) and returns the
                // cross-subsystem effects for us to drive.
                let actions = crate::proto::lookup::on_response_accepted(
                    &mut self.discovery,
                    &target,
                    response.target_coords,
                    now_ms,
                    path_mtu,
                );
                self.drive_response_actions(actions).await;
            }
        }
    }

    /// Drive the cross-subsystem effects returned by the discovery core's
    /// accept-side planning. Each arm reproduces the original inline effect
    /// exactly (same metrics/logs/writes, same order).
    async fn drive_response_actions(&mut self, actions: Vec<LookupAction>) {
        for action in actions {
            match action {
                LookupAction::CacheCoords {
                    target,
                    coords,
                    now_ms,
                    path_mtu,
                } => {
                    self.coord_cache
                        .insert_with_path_mtu(target, coords, now_ms, path_mtu);
                }
                LookupAction::WritePathMtu { target, path_mtu } => {
                    // Mirror path_mtu into the FipsAddress-keyed read-only lookup
                    // map used by the TUN reader/writer at TCP MSS clamp time.
                    let fips_addr = crate::FipsAddress::from_node_addr(&target);
                    match self.path_mtu_lookup.write() {
                        Ok(mut map) => {
                            let prior = map.insert(fips_addr, path_mtu);
                            debug!(
                                target = %self.peer_display_name(&target),
                                fips_addr = %fips_addr,
                                path_mtu = path_mtu,
                                prior = ?prior,
                                map_len = map.len(),
                                "Wrote path_mtu_lookup from discovery LookupResponse"
                            );
                        }
                        Err(e) => {
                            warn!(
                                target = %self.peer_display_name(&target),
                                fips_addr = %fips_addr,
                                path_mtu = path_mtu,
                                error = %e,
                                "path_mtu_lookup write lock poisoned; clamp will not see this update"
                            );
                        }
                    }
                }
                LookupAction::ResetWarmupIfEstablished { target } => {
                    // If an established session exists, reset the warmup counter.
                    let n = self.config().node.session.coords_warmup_packets;
                    if let Some(entry) = self.sessions.get_mut(&target)
                        && entry.is_established()
                    {
                        entry.set_coords_warmup_remaining(n);
                        debug!(
                            dest = %self.peer_display_name(&target),
                            warmup_packets = n,
                            "Reset coords warmup after discovery for existing session"
                        );
                    }
                }
                LookupAction::RetryQueuedPackets { target } => {
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
                LookupAction::SendLink { peer, bytes } => {
                    if let Err(e) = self.send_encrypted_link_message(&peer, &bytes).await {
                        debug!(
                            peer = %self.peer_display_name(&peer),
                            error = %e,
                            "Failed to send discovery link message"
                        );
                    }
                }
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

        let mut response =
            LookupResponse::new(request.request_id, request.target, our_coords, proof);

        // Route toward origin. The reverse-path decision (the peer the request
        // arrived from, recorded in recent_requests) is the sans-IO core's; the
        // greedy tree-route fallback is a &mut coord-cache op kept in the shell.
        use crate::proto::lookup::ResponseRouteDecision;
        let next_hop_addr = match crate::proto::lookup::plan_response_route(
            &self.discovery,
            request.request_id,
        ) {
            ResponseRouteDecision::ReversePath(peer) => peer,
            ResponseRouteDecision::NeedsTreeRoute => match self.find_next_hop(&request.origin) {
                Some(peer) => *peer.node_addr(),
                None => {
                    debug!(
                        origin = %self.peer_display_name(&request.origin),
                        "Cannot route LookupResponse: no reverse path or tree route to origin"
                    );
                    self.metrics()
                        .discovery
                        .record_reject(DiscoveryReject::RespNoRoute);
                    return;
                }
            },
        };

        // Fold our outgoing-link MTU into path_mtu so the target-edge link
        // appears in the bottleneck calculation. Without this, the response
        // leaves the target with path_mtu = u16::MAX and only intermediate
        // transits min-fold; the target's first reverse-path hop is missed.
        self.apply_outgoing_link_mtu_to_response(&mut response, &next_hop_addr);

        debug!(
            request_id = request.request_id,
            origin = %self.peer_display_name(&request.origin),
            next_hop = %self.peer_display_name(&next_hop_addr),
            path_mtu = response.path_mtu,
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
        // Plan the forward with the sans-IO decision core. The core owns the
        // TTL decrement, Leaf suppression, Full+MTU eligibility, tree/fallback
        // peer selection, and single-encode fan-out; the shell keeps all
        // metrics/logging and drives the sends.
        let outcome = {
            let rv = NodeRoutingView { node: self };
            crate::proto::lookup::plan_forward(&mut request, &rv)
        };
        match outcome {
            crate::proto::lookup::ForwardOutcome::TtlExhausted => {}
            crate::proto::lookup::ForwardOutcome::LeafNoForward => {}
            crate::proto::lookup::ForwardOutcome::NoPeers => {
                self.metrics().discovery.req_no_tree_peer.inc();
                trace!(
                    request_id = request.request_id,
                    "No eligible peers to forward LookupRequest"
                );
            }
            crate::proto::lookup::ForwardOutcome::Forward {
                actions,
                used_fallback,
            } => {
                let peer_count = actions.len();
                if used_fallback {
                    self.metrics().discovery.req_fallback_forwarded.inc();
                    debug!(
                        request_id = request.request_id,
                        target = %self.peer_display_name(&request.target),
                        ttl = request.ttl,
                        peer_count,
                        "Forwarding LookupRequest via non-tree fallback"
                    );
                } else {
                    debug!(
                        request_id = request.request_id,
                        target = %self.peer_display_name(&request.target),
                        ttl = request.ttl,
                        peer_count,
                        "Forwarding LookupRequest"
                    );
                }
                for action in actions {
                    if let LookupAction::SendLink { peer, bytes } = action
                        && let Err(e) = self.send_encrypted_link_message(&peer, &bytes).await
                    {
                        debug!(
                            peer = %self.peer_display_name(&peer),
                            error = %e,
                            "Failed to forward LookupRequest to peer"
                        );
                    }
                }
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
        self.metrics().discovery.req_initiated.inc();

        let origin = *self.node_addr();
        let min_mtu = self.config().tun.mtu();
        let request_id = {
            use rand::RngExt;
            rand::rng().random()
        };
        let request = LookupRequest::new(request_id, *target, origin, ttl, min_mtu);

        // Tree-peer selection restricted to Full peers meeting min_mtu, plus the
        // single encode, live in the sans-IO core. The core keeps the tree-only
        // (no non-tree fallback) behavior; the shell drives the sends and keeps
        // all metrics/logging.
        let actions = {
            let rv = NodeRoutingView { node: self };
            crate::proto::lookup::plan_initiate(&request, &rv)
        };

        let peer_count = actions.len();

        debug!(
            request_id = request.request_id,
            target = %self.peer_display_name(target),
            ttl = ttl,
            peer_count = peer_count,
            total_peers = self.peers.len(),
            "Discovery lookup initiated"
        );

        for action in actions {
            if let LookupAction::SendLink { peer, bytes } = action
                && let Err(e) = self.send_encrypted_link_message(&peer, &bytes).await
            {
                debug!(
                    peer = %self.peer_display_name(&peer),
                    error = %e,
                    "Failed to send LookupRequest to peer"
                );
            }
        }

        peer_count
    }

    /// Initiate a discovery lookup if one is not already pending for this target.
    ///
    /// Checks: pending dedup, post-failure backoff (off by default), bloom
    /// filter pre-check. If all pass, sends the first attempt's LookupRequest.
    /// Subsequent attempts (with fresh request_ids) are scheduled by
    /// [`Self::check_pending_lookups`] when each attempt's per-attempt timeout
    /// expires, using the sequence in `node.discovery.attempt_timeouts_secs`.
    pub(in crate::node) async fn maybe_initiate_lookup(&mut self, dest: &NodeAddr) {
        let now_ms = Self::now_ms();

        // Bloom filter pre-check (view read) BEFORE the core call: if no peer's
        // filter contains the target, it's not in the mesh. Reading `self.peers`
        // here keeps the `&mut self.discovery` borrow in `initiate_gate` from
        // overlapping the immutable peer-table read.
        let reachable = self.peers.values().any(|peer| peer.may_reach(dest));

        use crate::proto::lookup::InitiateDecision;
        match crate::proto::lookup::initiate_gate(&mut self.discovery, dest, now_ms, reachable) {
            InitiateDecision::Deduplicated => {
                self.metrics().discovery.req_deduplicated.inc();
                debug!(
                    target_node = %self.peer_display_name(dest),
                    "Discovery lookup deduplicated, already pending"
                );
            }
            InitiateDecision::Suppressed { failures } => {
                self.metrics().discovery.req_backoff_suppressed.inc();
                debug!(
                    target_node = %self.peer_display_name(dest),
                    failures = failures,
                    "Discovery lookup suppressed by backoff"
                );
            }
            InitiateDecision::BloomMiss => {
                self.metrics().discovery.req_bloom_miss.inc();
                debug!(
                    target_node = %self.peer_display_name(dest),
                    "Discovery skipped, target not in any peer bloom filter"
                );
            }
            InitiateDecision::Proceed => {
                let ttl = self.config().node.discovery.ttl;
                let sent = self.initiate_lookup(dest, ttl).await;

                // If no tree peers had the target, fail immediately
                if sent == 0 {
                    crate::proto::lookup::initiate_failed(&mut self.discovery, dest, now_ms);
                    debug!(
                        target_node = %self.peer_display_name(dest),
                        "Discovery failed, no tree peers with bloom match"
                    );
                }
            }
        }
    }

    /// Check pending lookups for next-attempt or final timeout.
    ///
    /// Called periodically from the tick handler. The lookup state machine
    /// runs through `node.discovery.attempt_timeouts_secs` (default
    /// `[1, 2, 4, 8]`): each entry is the deadline for one attempt. When the
    /// current attempt's deadline elapses:
    /// - If more entries remain: send the next attempt with a fresh
    ///   `request_id`.
    /// - Otherwise: declare the destination unreachable, drop queued packets,
    ///   and emit ICMPv6 destination-unreachable for each.
    pub(in crate::node) async fn check_pending_lookups(&mut self, now_ms: u64) {
        let attempt_timeouts = self.config().node.discovery.attempt_timeouts_secs.clone();
        let outcome =
            crate::proto::lookup::poll_pending(&mut self.discovery, now_ms, &attempt_timeouts);

        for (target, attempt) in outcome.retries {
            let ttl = self.config().node.discovery.ttl;
            let sent = self.initiate_lookup(&target, ttl).await;
            if sent > 0 {
                debug!(
                    target_node = %self.peer_display_name(&target),
                    attempt = attempt,
                    "Discovery retry sent"
                );
            }
        }

        for (addr, failures) in outcome.timeouts {
            self.metrics().discovery.resp_timed_out.inc();
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
        let cleared = self.discovery.reset_backoff();
        if cleared > 0 {
            debug!(
                entries = cleared,
                "Resetting discovery backoff on topology change"
            );
        }
    }

    /// Check if a peer's outgoing link MTU meets the min_mtu requirement.
    ///
    /// Returns true if min_mtu is 0 (no requirement) or if the peer's
    /// transport link MTU is >= min_mtu.
    fn peer_meets_mtu(&self, peer: &crate::peer::ActivePeer, min_mtu: u16) -> bool {
        if min_mtu == 0 {
            return true;
        }
        if let Some(tid) = peer.transport_id()
            && let Some(transport) = self.transports.get(&tid)
        {
            let link_mtu = peer
                .current_addr()
                .map(|addr| transport.link_mtu(addr))
                .unwrap_or_else(|| transport.mtu());
            link_mtu >= min_mtu
        } else {
            // No transport info available — don't prune
            true
        }
    }

    /// Min-fold our outgoing-link MTU into a LookupResponse's `path_mtu`.
    ///
    /// Used at both transit-side reverse-path forward and at the target's
    /// own send_lookup_response. The link MTU we apply is the MTU of the
    /// transport+addr we'll use to deliver the response toward `next_hop`.
    /// No-op when `next_hop` is not a directly-connected peer or its
    /// transport is not registered.
    pub(in crate::node) fn apply_outgoing_link_mtu_to_response(
        &self,
        response: &mut LookupResponse,
        next_hop: &NodeAddr,
    ) {
        if let Some(peer) = self.peers.get(next_hop)
            && let Some(tid) = peer.transport_id()
            && let Some(transport) = self.transports.get(&tid)
        {
            let link_mtu = if let Some(addr) = peer.current_addr() {
                transport.link_mtu(addr)
            } else {
                transport.mtu()
            };
            response.path_mtu = response.path_mtu.min(link_mtu);
        }
    }

    /// Seed `path_mtu_lookup` for a directly-connected peer.
    ///
    /// Called when an FMP link-layer peer is promoted to active. The seed
    /// value is the local outgoing-link MTU on the peer's transport, which
    /// is the actual link constraint for direct-link traffic. Stored only
    /// when no tighter value exists: discovery's reverse-path bottleneck
    /// or MMP `MtuExceeded` reactive learning take precedence when smaller.
    ///
    /// Without this seed, configured/auto-connect peers (which establish
    /// sessions without going through the discovery Lookup flow) leave
    /// `path_mtu_lookup` empty for their FipsAddress, causing
    /// `per_flow_max_mss` to fall back to the global ceiling and the
    /// SYN-time TCP MSS clamp to over-estimate the effective path.
    pub(in crate::node) fn seed_path_mtu_for_link_peer(
        &self,
        peer_addr: &NodeAddr,
        transport_id: TransportId,
        addr: &TransportAddr,
    ) {
        let Some(transport) = self.transports.get(&transport_id) else {
            debug!(
                peer = %self.peer_display_name(peer_addr),
                transport_id = %transport_id,
                "seed_path_mtu_for_link_peer: transport not registered, skipping seed"
            );
            return;
        };
        let link_mtu = transport.link_mtu(addr);
        let fips_addr = crate::FipsAddress::from_node_addr(peer_addr);
        let Ok(mut map) = self.path_mtu_lookup.write() else {
            warn!(
                peer = %self.peer_display_name(peer_addr),
                "seed_path_mtu_for_link_peer: path_mtu_lookup write lock poisoned"
            );
            return;
        };
        match map.get(&fips_addr).copied() {
            Some(existing) if existing <= link_mtu => {
                // Keep the tighter learned value; never loosen the clamp.
                debug!(
                    peer = %self.peer_display_name(peer_addr),
                    fips_addr = %fips_addr,
                    link_mtu = link_mtu,
                    existing = existing,
                    "seed_path_mtu_for_link_peer: keeping tighter existing value"
                );
            }
            other => {
                map.insert(fips_addr, link_mtu);
                debug!(
                    peer = %self.peer_display_name(peer_addr),
                    fips_addr = %fips_addr,
                    link_mtu = link_mtu,
                    prior = ?other,
                    map_len = map.len(),
                    "seed_path_mtu_for_link_peer: wrote link MTU"
                );
            }
        }
    }
}
