//! The operator's view and control of each link's paths: the projection
//! of a link's path machine into the `paths` array of a `show_peers` row,
//! read from [`Bundle::view`](fips_core::proto::path::Bundle::view) and the
//! node's transports, which the loop and the published snapshot both build
//! their rows with, so the two renders cannot drift; and the control
//! socket's `path_show`, `path_pin` and `path_unpin`, served on the loop
//! because they read the machine at the instant of the request.

use std::time::Duration;

use fips_core::proto::path::{Facts, Input, PathState, PathView, PinView, Role};
use serde_json::{Value, json};
use tracing::info;

use crate::control::queries::render_paths;
use crate::control::snapshot::PeerPathRow;
use crate::node::Node;
use crate::node::handlers::path::NodeFacts;
use crate::peer::{ActivePeer, PeerInstant, peer_now};
use crate::transport::{TransportAddr, TransportId};
use crate::{NodeAddr, PeerIdentity};

impl Node {
    /// Each path of `peer`'s link as a `show_peers` row shows it at `now`,
    /// in the path set's order; empty for a peer whose link has no path
    /// machine yet.
    pub(crate) fn peer_paths(&self, peer: &ActivePeer, now: PeerInstant) -> Vec<PeerPathRow> {
        peer.bundle().map_or_else(Vec::new, |bundle| {
            bundle
                .view(now)
                .paths
                .iter()
                .map(|path| self.path_row(path))
                .collect()
        })
    }

    /// `path_show`: the link to the peer `npub` at this instant: whether
    /// multipath is enabled and the peer capable, the link's cost and
    /// whether it is held, the pin and whether it is in force, and each
    /// path's `show_peers` entry with what only a read at the instant can
    /// give: its identifier, whether it is acked, the age of its latest
    /// authentic frame, its unanswered probes, its proven MTU, the frames
    /// and bytes attributed to it and its failed frames.
    pub(crate) fn show_paths(&self, npub: &str) -> Result<Value, String> {
        let node_addr = self.peer_named(npub)?;
        let peer = &self.peers[&node_addr];
        let live = peer.live_cost();
        let Some(bundle) = peer.bundle() else {
            return Ok(json!({
                "peer": npub,
                "enabled": self.config().node.path.enabled,
                "capable": false,
                "link_cost": live,
                "link_cost_held": false,
                "pin": Value::Null,
                "paths": [],
            }));
        };
        // One instant for the cost, the hold and the ages, so that the
        // cost and `link_cost_held` agree near the end of a hold.
        let now = peer_now();
        let view = bundle.view(now);
        let rows: Vec<PeerPathRow> = view.paths.iter().map(|p| self.path_row(p)).collect();
        let mut paths = render_paths(&rows);
        if let Some(entries) = paths.as_array_mut() {
            for (entry, path) in entries.iter_mut().zip(&view.paths) {
                entry["path_id"] = json!(path.id);
                entry["acked"] = json!(path.acked);
                entry["heard_ms_ago"] = json!(path.heard.map(millis));
                entry["unanswered"] = json!(path.misses);
                entry["mtu"] = json!(path.mtu);
                entry["rx_frames"] = json!(path.frames);
                entry["rx_bytes"] = json!(path.bytes);
                entry["auth_failures"] = json!(path.fails);
            }
        }
        Ok(json!({
            "peer": npub,
            "enabled": view.enabled,
            "capable": view.capable,
            "link_cost": bundle.cost(now, live),
            "link_cost_held": view.held,
            "pin": self.pin_json(view.pin.as_ref()),
            "paths": paths,
        }))
    }

    /// `path_pin`: pin the link to the peer `npub` to `transport`, an
    /// instance name or a numeric id, and with `address` to the peer's
    /// path at that address on it, a choice the draft leaves to the node.
    /// A pin naming no path held, or none Live, is kept, suspended until a
    /// path it names turns Live, and a pin in force moves the link at once.
    /// Checked in order: the npub, the peer, that multipath is enabled,
    /// the transport. With multipath disabled the link never changes path,
    /// so a pin would be taken and do nothing; it is refused.
    pub(crate) async fn pin_path(
        &mut self,
        npub: &str,
        transport: &str,
        address: Option<&str>,
    ) -> Result<Value, String> {
        let node_addr = self.peer_named(npub)?;
        self.multipath_on(&node_addr)?;
        let transport = self.resolve_transport(transport)?;
        let addr = address.map(|a| self.held_addr(&node_addr, transport, a));
        self.step_path(&node_addr, Input::Pin { transport, addr })
            .await;
        let pin = self.pin_now(&node_addr);
        info!(
            peer = %self.peer_display_name(&node_addr),
            pin = %pin,
            "Path pinned by operator"
        );
        Ok(json!({ "pinned": pin }))
    }

    /// `path_unpin`: lift the pin on the link to the peer `npub`, if any,
    /// so the usual rules choose its active path again. Refused with
    /// multipath disabled, as [`Self::pin_path`] is.
    pub(crate) async fn unpin_path(&mut self, npub: &str) -> Result<Value, String> {
        let node_addr = self.peer_named(npub)?;
        self.multipath_on(&node_addr)?;
        self.step_path(&node_addr, Input::Unpin).await;
        info!(
            peer = %self.peer_display_name(&node_addr),
            pin = %self.pin_now(&node_addr),
            "Path unpinned by operator"
        );
        Ok(json!({ "pinned": Value::Null }))
    }

    /// A transport named by its configured instance name, else by its
    /// numeric id. Instance names are scoped per transport type, so two
    /// transports can carry one name; such a name is refused, with the
    /// ids that carry it, for the operator to choose one by id. A shared
    /// name that is itself the id of one of the transports carrying it
    /// selects that transport, since no other text could.
    fn resolve_transport(&self, name: &str) -> Result<TransportId, String> {
        let mut named: Vec<(u32, &str)> = self
            .transports
            .iter()
            .filter(|(_, t)| t.name() == Some(name))
            .map(|(id, t)| (id.as_u32(), t.transport_type().name))
            .collect();
        named.sort_unstable();
        match named.as_slice() {
            [] => {}
            [(id, _)] => return Ok(TransportId::new(*id)),
            all => {
                let own_id = name
                    .parse::<u32>()
                    .ok()
                    .filter(|n| all.iter().any(|(id, _)| id == n));
                if let Some(id) = own_id {
                    return Ok(TransportId::new(id));
                }
                let ids: Vec<String> = all.iter().map(|(id, ty)| format!("{id} ({ty})")).collect();
                return Err(format!(
                    "transport name '{name}' is shared by transports {}; give one by id",
                    ids.join(", ")
                ));
            }
        }
        name.parse::<u32>()
            .ok()
            .map(TransportId::new)
            .filter(|id| self.transports.contains_key(id))
            .ok_or_else(|| format!("transport not found: {name}"))
    }

    /// The active peer whose npub is `npub`.
    fn peer_named(&self, npub: &str) -> Result<NodeAddr, String> {
        let identity =
            PeerIdentity::from_npub(npub).map_err(|e| format!("invalid npub '{npub}': {e}"))?;
        let node_addr = *identity.node_addr();
        if !self.peers.contains_key(&node_addr) {
            return Err(format!("peer not found: {npub}"));
        }
        Ok(node_addr)
    }

    /// `Ok` when the link to `peer` runs with multipath enabled.
    fn multipath_on(&self, peer: &NodeAddr) -> Result<(), String> {
        let enabled = self.peers[peer]
            .bundle()
            .map_or(self.config().node.path.enabled, |b| {
                b.view(peer_now()).enabled
            });
        if enabled {
            Ok(())
        } else {
            Err("multipath is disabled on this node".to_string())
        }
    }

    /// The address `text` on `transport` as `peer`'s link holds it: the
    /// address of a path held there that displays as `text`, so a pin
    /// takes an address as `path_show` prints it, whatever its bytes; else
    /// `text` itself, for a path not held yet.
    fn held_addr(&self, peer: &NodeAddr, transport: TransportId, text: &str) -> TransportAddr {
        self.peers[peer]
            .bundle()
            .and_then(|b| {
                b.paths()
                    .paths()
                    .iter()
                    .find(|p| p.transport_id() == transport && p.addr().to_string() == text)
                    .map(|p| p.addr().clone())
            })
            .unwrap_or_else(|| TransportAddr::from_string(text))
    }

    /// The pin on the link to `peer` as a reply shows it, read now.
    fn pin_now(&self, peer: &NodeAddr) -> Value {
        let view = self.peers[peer].bundle().map(|b| b.view(peer_now()));
        self.pin_json(view.as_ref().and_then(|v| v.pin.as_ref()))
    }

    /// A pin as a reply shows it: its transport's id and name, the address
    /// or null for any path on the transport, and whether it is in force;
    /// null for no pin.
    fn pin_json(&self, pin: Option<&PinView>) -> Value {
        pin.map_or(Value::Null, |pin| {
            let transport = pin.pin.transport;
            json!({
                "transport_id": transport.as_u32(),
                "transport": self.transports.get(&transport).and_then(|t| t.name()),
                "addr": pin.pin.addr.as_ref().map(ToString::to_string),
                "in_force": pin.enforced,
            })
        })
    }

    /// One path's row: what the view shows of it, with its transport's
    /// name, type and role as the node holds them now.
    fn path_row(&self, path: &PathView) -> PeerPathRow {
        let transport = path.to.transport;
        let handle = self.transports.get(&transport);
        let facts = NodeFacts {
            transports: &self.transports,
            denied: false,
        };
        PeerPathRow {
            transport_id: transport.as_u32(),
            transport: handle.and_then(|h| h.name()).map(str::to_string),
            transport_type: handle.map(|h| h.transport_type().name.to_string()),
            addr: path.to.addr.to_string(),
            state: state_name(path.state),
            active: path.active,
            remote_active: path.remote,
            role: role_name(facts.role(transport)),
            pinned: path.pinned,
            last: path.rtt.map(millis),
            least: path.least.map(millis),
            samples: path.samples,
            etx: path.etx,
            score: path.score,
        }
    }
}

/// The name a path's state goes by in the control socket's replies.
fn state_name(state: PathState) -> &'static str {
    match state {
        PathState::Probing => "probing",
        PathState::Live => "live",
        PathState::Suspect => "suspect",
        PathState::Dead => "dead",
    }
}

/// The name a transport's role goes by in the control socket's replies.
fn role_name(role: Role) -> &'static str {
    match role {
        Role::Preferred => "preferred",
        Role::Normal => "normal",
        Role::Backup => "backup",
        Role::Never => "never",
    }
}

/// `d` in whole milliseconds, saturating.
fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}
