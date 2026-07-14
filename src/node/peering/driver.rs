//! Thin async driver for the peering reconciler.
//!
//! These `impl Node` methods are the I/O edge of the sans-IO
//! [`super::reconcile::PeeringReconciler`]: they snapshot the live dataplane
//! maps into the reconciler's plain-data inputs, invoke the pure core, and
//! perform the dial / advert-refetch I/O each [`PeeringAction`] names. They also
//! host the two gate-guarded reflex wrappers every peer-loss call site routes
//! through, so drain suppression and the connected-guard live in one place.
//!
//! The `Policy` / `Observed` / `Budget` builders these methods consume live in
//! [`crate::node::lifecycle`] next to the surviving budget helpers and limit
//! constants they wrap.

use crate::identity::NodeAddr;
use crate::node::{Node, NodeError};
use tracing::warn;

use super::reconcile::{DiscoveryPools, Gate, PeeringAction};

impl Node {
    /// Reflex: an outbound handshake timed out (replaces the old
    /// `Node::schedule_retry` call sites).
    ///
    /// Replicates `schedule_retry`'s connected-guard — the pure core cannot
    /// observe the peers map, so the driver drops the event when the peer is
    /// already connected — then feeds the gate-guarded reconciler reflex with
    /// the gate derived from the live published state.
    pub(in crate::node) fn note_handshake_timeout(&mut self, node_addr: NodeAddr, now_ms: u64) {
        if self.peers.contains_key(&node_addr) {
            return;
        }
        let policy =
            self.build_peering_policy(self.config().auto_connect_peers().cloned().collect());
        let gate = Gate::from_state(self.supervisor.state);
        let _ = self
            .peering
            .reconciler
            .on_handshake_timeout(node_addr, now_ms, &policy, gate);
    }

    /// Reflex: a link went dead / a peer was lost (replaces the old
    /// `Node::schedule_reconnect` call sites).
    ///
    /// No connected-guard — the peer is already gone by the time a link-dead /
    /// disconnect event fires (`schedule_reconnect` had none). The gate is
    /// derived from the live published state so a drain self-suppresses the
    /// reconnect.
    pub(in crate::node) fn note_link_dead(&mut self, node_addr: NodeAddr, now_ms: u64) {
        let policy =
            self.build_peering_policy(self.config().auto_connect_peers().cloned().collect());
        let gate = Gate::from_state(self.supervisor.state);
        let _ = self
            .peering
            .reconciler
            .on_link_dead(node_addr, now_ms, &policy, gate);
    }

    /// Process pending retries whose time has arrived (replaces the old
    /// `Node::process_pending_retries` body).
    ///
    /// The pure retry-dial phase owns the decision — drop expired entries, refuse
    /// to grow when admission binds, dial the first `retry_per_tick` due entries
    /// (bumping their `retry_after_ms` past the handshake window). This driver
    /// performs the advert-refetch + dial I/O each emitted `Connect` names, and
    /// on an immediate dial error feeds the `on_handshake_timeout` reflex so the
    /// optimistic re-fire suppression is overwritten by proper backoff. During a
    /// drain the gate is `Suspended`, so the reconcile clears the schedule and
    /// emits nothing.
    pub(in crate::node) async fn process_pending_retries(&mut self, now_ms: u64) {
        if self.peering.reconciler.retry_pending.is_empty() {
            return;
        }

        // Retry-dial cadence slot: empty config floor and empty discovery
        // pools, so only the retry-dial phase acts.
        let policy = self.build_peering_policy(Vec::new());
        let observed = self.observe_peering();
        let budget = self.build_peering_budget();
        let gate = Gate::from_state(self.supervisor.state);
        let actions = self.peering.reconciler.reconcile(
            &policy,
            &observed,
            &budget,
            &DiscoveryPools::default(),
            now_ms,
            gate,
        );

        for action in actions {
            let PeeringAction::Connect(candidate) = action else {
                continue;
            };
            let Some(identity) = candidate.identity else {
                continue;
            };
            let node_addr = *identity.node_addr();
            let Some(peer_config) = self
                .peering
                .reconciler
                .retry_pending
                .get(&node_addr)
                .map(|state| state.peer_config.clone())
            else {
                continue;
            };

            // Refresh the peer's overlay advert before retrying. The cache is
            // read-only on hit, so a retry without a refetch dials the same
            // cached endpoint — and the most common reason a peer landed in the
            // retry schedule is that endpoint just stopped working (NAT rebind,
            // port change, peer restart). Cheap (one Filter fetch, bounded by
            // the retry backoff cadence).
            if let Some(bootstrap) = self.supervisor.nostr_rendezvous.engine_arc() {
                let _ = bootstrap
                    .refetch_advert_for_stale_check(&peer_config.npub)
                    .await;
            }

            match self.initiate_peer_connection(&peer_config).await {
                // The core already pushed `retry_after_ms` past the handshake
                // window; a successful promotion clears the entry, a later
                // timeout re-fires the reflex with proper backoff.
                Ok(()) => {}
                Err(e) => {
                    warn!(
                        peer = %self.peer_display_name(&node_addr),
                        error = %e,
                        "Retry connection initiation failed"
                    );
                    // No-transport failures usually mean the cached overlay
                    // advert is stale; force a re-fetch so the next tick picks up
                    // fresh endpoints.
                    if matches!(e, NodeError::NoTransportForType(_))
                        && let Some(bootstrap) = self.supervisor.nostr_rendezvous.engine_arc()
                    {
                        let npub = peer_config.npub.clone();
                        tokio::spawn(async move {
                            let _ = bootstrap.refetch_advert_for_stale_check(&npub).await;
                        });
                    }
                    // Immediate failure counts as an attempt: overwrite the
                    // optimistic re-fire suppression with backoff.
                    self.note_handshake_timeout(node_addr, now_ms);
                }
            }
        }
    }
}
