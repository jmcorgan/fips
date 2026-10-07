//! Path probe / path ack: adding a second path to a peer under the session
//! it already has.
//!
//! `docs/design/fips-multi-path-switchover.md` §4. A probe is an ordinary
//! encrypted frame sent on a candidate transport. The receiver, having
//! decrypted it against the session found by index, has proof the peer is
//! reachable on that `(transport, addr)`: it adds the path as `Probing`,
//! marks it `rx_live`, and answers with an ack **on that same path**. The
//! prober's receipt of the ack proves the reverse direction: the path goes
//! `Live`, `tx_live`, and takes an RTT sample. No handshake, no new key
//! material, no index allocation.
//!
//! This is also where the active path moves: selection on the fast tick
//! (`run_path_selection`), withdrawal when a transport goes
//! (`withdraw_transport`), a peer's `PathClose`, and the switch side
//! effects (`apply_path_switch`). The carrier edge and the per-path
//! heartbeats that feed selection live here too.

use crate::NodeAddr;
use crate::node::Node;
use crate::peer::{HeartbeatTiming, PathPolicy, PathSwitch, PathWithdrawal};
use crate::proto::link::{PathClose, PathCloseReason, PathMessage};
use crate::transport::{TransportAddr, TransportId};
use tracing::{debug, info, trace};

impl Node {
    /// The selection knobs, from `node.path.*`.
    pub(in crate::node) fn path_policy(&self) -> PathPolicy {
        let cfg = &self.config().node.path;
        let standby_ms = cfg.standby_heartbeat_ms.max(1);
        PathPolicy {
            margin: cfg.switch_margin,
            dwell_ms: cfg.switch_dwell_secs.saturating_mul(1000),
            min_samples: cfg.min_samples,
            rtt_window_ms: standby_ms
                .saturating_mul(u64::from(cfg.min_samples).max(1))
                .saturating_mul(2)
                .max(30_000),
        }
    }

    /// The role of the transport `transport_id`, or `Normal` if it is not
    /// registered.
    fn transport_role(&self, transport_id: TransportId) -> crate::config::TransportRole {
        self.transports
            .get(&transport_id)
            .map(|t| t.role())
            .unwrap_or_default()
    }

    /// Run selection for every peer. Called from the tick. A switch here is
    /// discretionary or pinned, or mandatory after a `Suspect` mark that
    /// nothing else acted on; the presence edge runs its own.
    pub(in crate::node) fn run_path_selection(&mut self) {
        let policy = self.path_policy();
        let now_ms = crate::time::mono_ms();
        let switches: Vec<(NodeAddr, PathSwitch)> = self
            .peers
            .iter_mut()
            .filter_map(|(addr, peer)| peer.select_path(now_ms, &policy).map(|s| (*addr, s)))
            .collect();
        for (node_addr, switch) in switches {
            info!(
                peer = %self.peer_display_name(&node_addr),
                from_transport = %switch.from.0,
                to_transport = %switch.to.0,
                to_addr = %switch.to.1,
                reason = ?switch.reason,
                "Path switched, session kept"
            );
            self.apply_path_switch(&node_addr, switch.to);
        }
    }

    /// Pin a peer's traffic to its path on `transport_id`. Applies on the
    /// next selection run. `false` if the peer or the path is unknown.
    pub(crate) fn pin_peer_path(
        &mut self,
        node_addr: &NodeAddr,
        transport_id: TransportId,
    ) -> bool {
        self.peers
            .get_mut(node_addr)
            .is_some_and(|p| p.pin_path(transport_id))
    }

    /// Clear a peer's pin. `false` if the peer is unknown.
    pub(crate) fn unpin_peer_path(&mut self, node_addr: &NodeAddr) -> bool {
        match self.peers.get_mut(node_addr) {
            Some(p) => {
                p.unpin_paths();
                true
            }
            None => false,
        }
    }

    /// The peer named by `npub`, if it is an active peer.
    pub(in crate::node) fn resolve_peer_npub(&self, npub: &str) -> Result<NodeAddr, String> {
        let identity = crate::PeerIdentity::from_npub(npub)
            .map_err(|e| format!("invalid npub '{npub}': {e}"))?;
        let node_addr = *identity.node_addr();
        if !self.peers.contains_key(&node_addr) {
            return Err(format!("peer not found: {npub}"));
        }
        Ok(node_addr)
    }

    /// A transport named by its instance name (`cable`, `main`) or its
    /// numeric id.
    fn resolve_transport_name(&self, name: &str) -> Result<TransportId, String> {
        if let Some((id, _)) = self.transports.iter().find(|(_, t)| t.name() == Some(name)) {
            return Ok(*id);
        }
        if let Ok(n) = name.parse::<u32>()
            && self.transports.contains_key(&TransportId::new(n))
        {
            return Ok(TransportId::new(n));
        }
        Err(format!("transport not found: {name}"))
    }

    /// `fipsctl path show <peer>`: every path to the peer, per direction.
    ///
    /// The per-path object is the `show_peers` one (`project_peer_paths`,
    /// rendered by `render_peer_paths`) plus the three fields only a
    /// now-relative read can give: the liveness ages and `acked_once`.
    /// Built from the same projection so the two field lists cannot drift.
    pub(crate) fn api_path_show(&self, npub: &str) -> Result<serde_json::Value, String> {
        let node_addr = self.resolve_peer_npub(npub)?;
        let peer = &self.peers[&node_addr];
        let now_ms = crate::time::mono_ms();
        let ago = |at: Option<u64>| at.map(|t| now_ms.saturating_sub(t));
        let mut paths = crate::control::queries::render_peer_paths(&self.project_peer_paths(peer));
        if let Some(rows) = paths.as_array_mut() {
            for (row, path) in rows.iter_mut().zip(peer.paths()) {
                row["rx_live_ms_ago"] = serde_json::json!(ago(path.rx_live_at_ms()));
                row["tx_live_ms_ago"] = serde_json::json!(ago(path.tx_live_at_ms()));
                row["acked_once"] = serde_json::json!(path.acked_once());
            }
        }
        Ok(serde_json::json!({
            "peer": npub,
            "link_cost": peer.link_cost(now_ms),
            "link_cost_held": peer.link_cost_held(now_ms),
            "paths": paths,
        }))
    }

    /// `fipsctl path pin <peer> <transport>`.
    pub(crate) fn api_path_pin(
        &mut self,
        npub: &str,
        transport: &str,
    ) -> Result<serde_json::Value, String> {
        let node_addr = self.resolve_peer_npub(npub)?;
        let transport_id = self.resolve_transport_name(transport)?;
        if !self.pin_peer_path(&node_addr, transport_id) {
            return Err(format!("peer {npub} has no path on transport {transport}"));
        }
        info!(peer = %self.peer_display_name(&node_addr), %transport_id, "Path pinned by operator");
        Ok(serde_json::json!({ "pinned": transport_id.as_u32() }))
    }

    /// `fipsctl path unpin <peer>`.
    pub(crate) fn api_path_unpin(&mut self, npub: &str) -> Result<serde_json::Value, String> {
        let node_addr = self.resolve_peer_npub(npub)?;
        self.unpin_peer_path(&node_addr);
        info!(peer = %self.peer_display_name(&node_addr), "Path unpinned by operator");
        Ok(serde_json::json!({ "pinned": serde_json::Value::Null }))
    }

    /// A live peer beaconed on `transport_id` at `remote_addr`, a transport
    /// we hold no path to it over: add the path as `Probing`.
    ///
    /// Nothing is sent here. The heartbeat tick is the one issuer of
    /// probes: it picks the new path up within one fast interval, probes
    /// it full-size, and applies the discovery backoff if the peer never
    /// answers (an old node that drops `0x52` at debug), so the path is
    /// probed at the capped cadence and never becomes eligible. The backoff
    /// is reset when the transport's presence cycles.
    pub(in crate::node) fn add_path_candidate(
        &mut self,
        node_addr: NodeAddr,
        transport_id: TransportId,
        remote_addr: TransportAddr,
    ) {
        let role = self.transport_role(transport_id);
        let Some(peer) = self.peers.get_mut(&node_addr) else {
            return;
        };
        if peer.transport_id() == Some(transport_id)
            && peer.path_on(transport_id).is_some_and(|p| p.is_eligible())
        {
            // The active path, and it is answering: nothing to add, and an
            // address that has proven nothing does not displace it. An
            // active path that has stopped answering falls through to the
            // re-pointing below like any other.
            return;
        }
        let was_new = peer.path_on(transport_id).is_none();
        peer.add_path(transport_id, remote_addr.clone())
            .set_role(role);
        // A known transport at a new address: the peer moved there (an
        // Aware data path that re-formed, a DHCP lease that changed) and
        // the old address answers nothing. Re-point the path; the heartbeat
        // tick probes it from here. Only while the path is not eligible: an
        // address that is carrying acknowledged traffic is not displaced by
        // one that has proven nothing — a probe from the new address
        // (`note_path_probe`) is what moves a working path.
        let moved = !was_new
            && peer.path_on(transport_id).is_some_and(|p| !p.is_eligible())
            && peer.refresh_path_addr(transport_id, remote_addr.clone());
        if was_new {
            debug!(
                peer = %self.peer_display_name(&node_addr),
                transport_id = %transport_id,
                remote_addr = %remote_addr,
                "Peer beaconed on a new transport; path added, probing"
            );
        } else if moved {
            debug!(
                peer = %self.peer_display_name(&node_addr),
                transport_id = %transport_id,
                remote_addr = %remote_addr,
                "Peer beaconed at a new address on a known transport; path re-addressed, probing"
            );
        }
    }

    /// A `PathProbe` arrived from `from` on `arrival`.
    ///
    /// The frame decrypted under `from`'s session, so `from` is reachable
    /// over `arrival`. Record the path and answer on it. The ack says
    /// whether `arrival` is the path *we* send on, which it usually is not.
    pub(in crate::node) async fn handle_path_probe(
        &mut self,
        from: &NodeAddr,
        payload: &[u8],
        arrival: (TransportId, &TransportAddr),
    ) {
        let probe = match PathMessage::decode(payload) {
            Ok(p) => p,
            Err(e) => {
                debug!(peer = %self.peer_display_name(from), error = %e, "Malformed path probe");
                return;
            }
        };
        let (transport_id, remote_addr) = arrival;
        let now_ms = crate::time::mono_ms();
        let role = self.transport_role(transport_id);
        let Some(peer) = self.peers.get_mut(from) else {
            return;
        };
        let was_new = peer.path_on(transport_id).is_none();
        peer.note_path_probe(
            transport_id,
            remote_addr.clone(),
            probe.remote_active,
            probe.path_id,
            now_ms,
        );
        if was_new {
            peer.set_path_role(transport_id, role);
        }
        let ours_active = peer.transport_id() == Some(transport_id);
        let our_path_id = peer
            .path_on(transport_id)
            .map(|p| p.local_id())
            .unwrap_or(0);
        if was_new {
            debug!(
                peer = %self.peer_display_name(from),
                transport_id = %transport_id,
                remote_addr = %remote_addr,
                "Peer probed a new path; added"
            );
        }

        // The ack echoes the probe's size, so a full-size probe proves the
        // path for data-sized frames in both directions.
        let ack = PathMessage {
            probe_id: probe.probe_id,
            remote_active: ours_active,
            path_id: our_path_id,
        };
        let mut wire = ack.encode_ack().to_vec();
        let probe_len = payload.len() + 1;
        if wire.len() < probe_len {
            wire.resize(probe_len, 0);
        }
        if let Err(e) = self
            .send_encrypted_link_message_on_path(from, &wire, transport_id, remote_addr.clone())
            .await
        {
            debug!(
                peer = %self.peer_display_name(from),
                transport_id = %transport_id,
                error = %e,
                "Path ack send failed"
            );
        }
    }

    /// A `PathAck` arrived from `from` on `arrival`: our probe on that path
    /// reached the peer and the answer reached us, so the path works in
    /// both directions.
    pub(in crate::node) fn handle_path_ack(
        &mut self,
        from: &NodeAddr,
        payload: &[u8],
        arrival: (TransportId, &TransportAddr),
    ) {
        let ack = match PathMessage::decode(payload) {
            Ok(a) => a,
            Err(e) => {
                debug!(peer = %self.peer_display_name(from), error = %e, "Malformed path ack");
                return;
            }
        };
        let (transport_id, _) = arrival;
        let now_ms = crate::time::mono_ms();
        let window_ms = self.path_policy().rtt_window_ms;
        let Some(peer) = self.peers.get_mut(from) else {
            return;
        };
        let was_live = peer
            .path_on(transport_id)
            .is_some_and(|p| p.state() == crate::peer::PathState::Live);
        match peer.note_path_ack(
            transport_id,
            ack.probe_id,
            ack.remote_active,
            ack.path_id,
            now_ms,
            window_ms,
        ) {
            Some(rtt_ms) if !was_live => info!(
                peer = %self.peer_display_name(from),
                transport_id = %transport_id,
                rtt_ms,
                "Path live: the peer answers on this transport"
            ),
            Some(rtt_ms) => trace!(
                peer = %self.peer_display_name(from),
                transport_id = %transport_id,
                rtt_ms,
                "Path ack"
            ),
            None => trace!(
                peer = %self.peer_display_name(from),
                transport_id = %transport_id,
                probe_id = ack.probe_id,
                "Path ack matched no outstanding probe"
            ),
        }
    }

    /// A transport's presence went away: withdraw the path every peer held
    /// over it. Returns how many peers were reaped for want of another path.
    ///
    /// For each peer: the path goes `Dead` with its history kept. If it was
    /// a standby, nothing else happens. If it was the active path and an
    /// eligible standby exists, traffic moves there now, under the same
    /// session, and the switch side effects run
    /// ([`apply_path_switch`](Self::apply_path_switch)). Only a peer with
    /// no eligible path left is reaped, through the same routed link-dead
    /// teardown the liveness reaper uses.
    ///
    /// The peer machine sees nothing while any path remains: a switch is
    /// not a link event. Deliberately undamped, like the reap it grew from.
    pub(in crate::node) async fn withdraw_transport(&mut self, transport_id: TransportId) -> usize {
        let now_ms = crate::time::mono_ms();
        let policy = self.path_policy();
        let affected: Vec<NodeAddr> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.path_on(transport_id).is_some())
            .map(|(node_addr, _)| *node_addr)
            .collect();
        if affected.is_empty() {
            return 0;
        }

        let wall_ms = Self::now_ms();

        let mut reaped = 0;
        for node_addr in affected {
            let outcome = match self.peers.get_mut(&node_addr) {
                Some(peer) => peer.withdraw_path(transport_id, now_ms, &policy),
                None => continue,
            };
            match outcome {
                PathWithdrawal::NoPath => {}
                PathWithdrawal::Standby => {
                    debug!(
                        peer = %self.peer_display_name(&node_addr),
                        %transport_id,
                        "Standby path withdrawn: its interface went away"
                    );
                    self.send_path_close(&node_addr, transport_id, PathCloseReason::InterfaceGone)
                        .await;
                }
                PathWithdrawal::Switched { from, to } => {
                    info!(
                        peer = %self.peer_display_name(&node_addr),
                        from_transport = %from.0,
                        to_transport = %to.0,
                        to_addr = %to.1,
                        "Active path withdrawn: traffic moved to the standby, session kept"
                    );
                    self.apply_path_switch(&node_addr, to);
                    self.send_path_close(&node_addr, transport_id, PathCloseReason::InterfaceGone)
                        .await;
                }
                PathWithdrawal::NoAlternative => {
                    self.reap_peer_without_path(node_addr, transport_id, wall_ms)
                        .await;
                    reaped += 1;
                }
            }
        }
        reaped
    }

    /// Everything that follows the peer's active path changing to `to`.
    ///
    /// A switch is also an MTU change, and three things size traffic from
    /// the peer's transport without re-running on their own
    /// (`docs/design/fips-multi-path-switchover.md` §5):
    ///
    /// - the peer's `path_mtu_lookup` seed, which only ever tightens within
    ///   a link and would leave one cable→BLE excursion clamping every new
    ///   flow to this peer at the BLE MTU after fail-back; its relinked
    ///   branch is the hook, so re-seed from the new path;
    /// - the per-session source MTU, which tightens on the next send anyway
    ///   but only loosens after tens of seconds; tighten it now for every
    ///   session this peer is the next hop of, so the TUN gate answers with
    ///   PTB instead of losing the first packet per flow at the transport;
    /// - the node-wide MSS ceiling.
    ///
    /// The link record follows the traffic so everything that reports the
    /// peer's transport and address by link stays truthful; the control
    /// machine is keyed on the link and is untouched.
    pub(in crate::node) fn apply_path_switch(
        &mut self,
        node_addr: &NodeAddr,
        to: (TransportId, TransportAddr),
    ) {
        let (transport_id, addr) = to;
        if let Some(link_id) = self.peers.get(node_addr).map(|p| p.link_id())
            && let Some(link) = self.links.get_mut(&link_id)
        {
            self.addr_to_link.retain(|_, mapped| *mapped != link_id);
            link.rebind(transport_id, addr.clone());
            self.addr_to_link
                .insert((transport_id, addr.clone()), link_id);
        }

        self.seed_path_mtu_for_link_peer(node_addr, transport_id, &addr);

        let link_mtu = self
            .transports
            .get(&transport_id)
            .map(|t| t.link_mtu(&addr));
        if let Some(link_mtu) = link_mtu {
            let dests: Vec<NodeAddr> = self.sessions.keys().copied().collect();
            for dest in dests {
                let via_peer = self
                    .find_next_hop(&dest)
                    .is_some_and(|hop| hop.node_addr() == node_addr);
                if !via_peer {
                    continue;
                }
                if let Some(mmp) = self.sessions.get_mut(&dest).and_then(|s| s.mmp_mut()) {
                    mmp.path_mtu.seed_source_mtu(link_mtu);
                }
            }
        }

        self.refresh_tun_mss_ceiling();
    }

    /// The fast path tick: per-path heartbeats, the carrier edge, and the
    /// selection that a `Suspect` mark may call for.
    ///
    /// Runs every `node.path.active_heartbeat_ms`. Detection is near-instant
    /// for direct peers because each medium's own failure signal is used,
    /// not a faster timer: carrier here, a failed echo from the heartbeat
    /// plan, an unreachable send from the send path. All three mark a path
    /// `Suspect`; selection acts on `Suspect` at once because the standby is
    /// warm.
    pub(in crate::node) async fn run_path_heartbeats(&mut self) {
        let carrier_closes = self.poll_carrier_edges();

        let now_ms = crate::time::mono_ms();
        let timing = self.heartbeat_timing();

        let mut sends = Vec::new();
        for (node_addr, peer) in self.peers.iter_mut() {
            let plan = peer.plan_heartbeats(now_ms, &timing);
            for transport_id in plan.suspects {
                debug!(
                    peer = %node_addr,
                    %transport_id,
                    "Path suspect: heartbeat echo timed out"
                );
            }
            for send in plan.sends {
                sends.push((*node_addr, send));
            }
        }
        for (node_addr, send) in sends {
            let probe = PathMessage {
                probe_id: send.probe_id,
                remote_active: send.remote_active,
                path_id: send.path_id,
            };
            let mut wire = probe.encode_probe().to_vec();
            if send.full_size {
                wire = self.pad_to_link_mtu(wire, send.transport_id, &send.addr);
            }
            if let Err(e) = self
                .send_encrypted_link_message_on_path(
                    &node_addr,
                    &wire,
                    send.transport_id,
                    send.addr,
                )
                .await
            {
                trace!(
                    peer = %self.peer_display_name(&node_addr),
                    transport_id = %send.transport_id,
                    error = %e,
                    "Path heartbeat send failed"
                );
            }
        }

        self.run_path_selection();

        // After selection: a close for the path we were sending on can only
        // go out once traffic has moved off it, and `send_path_close` sends
        // nothing for the path that is still active.
        for (node_addr, transport_id) in carrier_closes {
            self.send_path_close(&node_addr, transport_id, PathCloseReason::CarrierLost)
                .await;
        }
    }

    /// The heartbeat intervals from `node.path.*` and `node.heartbeat_interval_secs`.
    fn heartbeat_timing(&self) -> HeartbeatTiming {
        let cfg = &self.config().node;
        let fast_ms = cfg.path.active_heartbeat_ms.max(50);
        let slow_ms = cfg.path.standby_heartbeat_ms.max(fast_ms);
        HeartbeatTiming {
            fast_ms,
            slow_ms,
            // Two fast intervals: one echo lost is loss, two is a path.
            // Stretched per path by its own round trip inside
            // `plan_heartbeats`.
            timeout_ms: fast_ms.saturating_mul(2),
            // A path the peer never acknowledges is probed full-size at
            // this cadence for as long as it exists: the link heartbeat
            // interval, not the standby one.
            discovery_cap_ms: cfg
                .heartbeat_interval_secs
                .saturating_mul(1000)
                .max(slow_ms),
        }
    }

    /// Read carrier on every interface-bound transport and mark the paths
    /// over one that just lost it `Suspect`. Unplugging a cable drops
    /// carrier on both NICs, so both ends see this inside one fast tick.
    /// Returns the `(peer, transport)` pairs to send a `PathClose` for.
    fn poll_carrier_edges(&mut self) -> Vec<(NodeAddr, TransportId)> {
        let mut closes = Vec::new();
        let readings: Vec<(TransportId, bool)> = self
            .transports
            .iter()
            .filter_map(|(id, t)| t.interface_presence().map(|p| (*id, p.carrier)))
            .collect();
        for (transport_id, carrier) in readings {
            let previous = self.carrier_seen.insert(transport_id, carrier);
            if previous == Some(true) && !carrier {
                let mut marked = Vec::new();
                for (node_addr, peer) in self.peers.iter_mut() {
                    if peer.mark_path_suspect(transport_id) {
                        marked.push(*node_addr);
                    }
                }
                if !marked.is_empty() {
                    info!(%transport_id, paths = marked.len(), "Carrier lost: paths suspect");
                    closes.extend(marked.into_iter().map(|a| (a, transport_id)));
                }
            }
        }
        closes
    }

    /// Tell `node_addr` that our path over `transport_id` is closing, on
    /// whichever path we now send on. Best effort: the peer would learn
    /// from the echo timeout anyway, this just makes it immediate. Nothing
    /// is sent if that path is the one we send on (there is no other way to
    /// reach the peer) or the peer never told us its id for it, which it
    /// does with its first probe or ack on the path.
    pub(in crate::node) async fn send_path_close(
        &mut self,
        node_addr: &NodeAddr,
        transport_id: TransportId,
        reason: PathCloseReason,
    ) {
        let Some(peer) = self.peers.get(node_addr) else {
            return;
        };
        if peer.transport_id() == Some(transport_id) {
            return;
        }
        let Some(remote_id) = peer.path_on(transport_id).and_then(|p| p.remote_id()) else {
            return;
        };
        let close = PathClose {
            path_id: remote_id,
            reason,
        };
        if let Err(e) = self
            .send_encrypted_link_message(node_addr, &close.encode())
            .await
        {
            trace!(
                peer = %self.peer_display_name(node_addr),
                %transport_id,
                error = %e,
                "Path close send failed"
            );
        }
    }

    /// The peer is closing the path it calls `path_id` (a `PathClose`
    /// arrived). Withdraw our side of it as if its transport had gone: Dead
    /// with history, traffic moved if it was there. Advisory: the peer's
    /// next probe on it revives it.
    pub(in crate::node) async fn handle_path_close(&mut self, from: &NodeAddr, payload: &[u8]) {
        let close = match PathClose::decode(payload) {
            Ok(c) => c,
            Err(e) => {
                debug!(peer = %self.peer_display_name(from), error = %e, "Malformed path close");
                return;
            }
        };
        let now_ms = crate::time::mono_ms();
        let policy = self.path_policy();
        let Some(peer) = self.peers.get_mut(from) else {
            return;
        };
        let Some((transport_id, outcome)) =
            peer.withdraw_path_by_local_id(close.path_id, now_ms, &policy)
        else {
            trace!(peer = %self.peer_display_name(from), path_id = close.path_id, "Path close named no path");
            return;
        };
        match outcome {
            PathWithdrawal::NoPath => {}
            PathWithdrawal::Standby => debug!(
                peer = %self.peer_display_name(from),
                %transport_id,
                reason = ?close.reason,
                "Peer closed a standby path"
            ),
            PathWithdrawal::Switched { from: was, to } => {
                info!(
                    peer = %self.peer_display_name(from),
                    from_transport = %was.0,
                    to_transport = %to.0,
                    reason = ?close.reason,
                    "Peer closed our active path: traffic moved to the standby, session kept"
                );
                self.apply_path_switch(from, to);
            }
            PathWithdrawal::NoAlternative => {
                // The peer says the only path we have to it is going. Leave
                // the peer to the echo timeout and the liveness reaper: a
                // close is advisory, and the path may outlive the warning.
                debug!(
                    peer = %self.peer_display_name(from),
                    %transport_id,
                    reason = ?close.reason,
                    "Peer closed our only path; waiting for liveness to confirm"
                );
            }
        }
    }

    /// Pad a link message to fill the link MTU on `transport_id` to `addr`,
    /// so the frame is data-sized: outer header, inner timestamp and AEAD
    /// tag are accounted for.
    fn pad_to_link_mtu(
        &self,
        mut wire: Vec<u8>,
        transport_id: TransportId,
        addr: &TransportAddr,
    ) -> Vec<u8> {
        let Some(transport) = self.transports.get(&transport_id) else {
            return wire;
        };
        let room = usize::from(transport.link_mtu(addr))
            .saturating_sub(super::session::LINK_FRAME_OVERHEAD);
        if wire.len() < room {
            wire.resize(room, 0);
        }
        wire
    }

    /// The kernel refused a send to the peer on `transport_id` for want of
    /// a route: the path is `Suspect` now, not after an echo timeout.
    pub(in crate::node) fn note_path_unreachable(
        &mut self,
        node_addr: &NodeAddr,
        transport_id: TransportId,
    ) {
        if let Some(peer) = self.peers.get_mut(node_addr)
            && peer.mark_path_suspect(transport_id)
        {
            debug!(
                peer = %self.peer_display_name(node_addr),
                %transport_id,
                "Path suspect: send unreachable"
            );
        }
    }

    /// A transport's presence came back: clear the probe backoff on every
    /// path over it so the next heartbeat tick may probe at once, and
    /// revive every path that went `Dead` with it — a replugged NIC, a
    /// wifi interface that cycled — as `Probing`, history kept. Without
    /// this nothing on our side ever probed a `Dead` path again: traffic
    /// stayed on the standby until the grace pruned the path and a fresh
    /// beacon found it with no history.
    pub(in crate::node) fn reset_probe_backoff_on_transport(&mut self, transport_id: TransportId) {
        for (node_addr, peer) in self.peers.iter_mut() {
            if peer.reset_probe_backoff_on(transport_id) {
                debug!(
                    peer = %node_addr,
                    %transport_id,
                    "Transport returned: dead path probing again"
                );
            }
        }
    }
}
