//! Control query implementations.
//!
//! Each function takes `&Node` and returns a `serde_json::Value`.
//! Query logic is kept separate from socket handling.

use crate::identity::{NodeAddr, PeerIdentity, encode_npub};
use crate::node::Node;
use crate::node::stats_history::{ALL_METRICS, ALL_PEER_METRICS, Granularity, Metric, PeerMetric};
use serde_json::{Value, json};
use std::str::FromStr;
use std::time::Duration;

/// Resolve an `npub1...` string to the corresponding `NodeAddr`.
fn parse_peer_npub(s: &str) -> Result<NodeAddr, String> {
    PeerIdentity::from_npub(s)
        .map(|p| *p.node_addr())
        .map_err(|e| format!("invalid peer npub: {e}"))
}

/// Helper: get current Unix time in milliseconds.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Classify a DualEwma trend as "rising", "falling", or "stable".
pub(crate) fn trend_label(short: f64, long: f64) -> &'static str {
    if !short.is_finite() || !long.is_finite() || long == 0.0 {
        return "stable";
    }
    let ratio = short / long;
    if ratio > 1.05 {
        "rising"
    } else if ratio < 0.95 {
        "falling"
    } else {
        "stable"
    }
}

/// `show_status` — Node overview.
pub fn show_status(node: &Node) -> Value {
    let pid = std::process::id();
    let exe_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "-".into());
    let uptime_secs = node.uptime().as_secs();
    let fwd = node.metrics().forwarding.snapshot();

    // Inline last-N-second sparklines for dashboard rendering. Kept
    // short so the status payload stays compact; longer windows use
    // `show_stats_history`.
    const SPARK_N: usize = 30;
    let hist = node.stats_history();
    let sparklines = json!({
        "mesh_size": hist.recent(Metric::MeshSize, SPARK_N),
        "tree_depth": hist.recent(Metric::TreeDepth, SPARK_N),
        "peer_count": hist.recent(Metric::PeerCount, SPARK_N),
        "bytes_in": hist.recent(Metric::BytesIn, SPARK_N),
        "bytes_out": hist.recent(Metric::BytesOut, SPARK_N),
        "loss_rate": hist.recent(Metric::LossRate, SPARK_N),
    });

    let tree = node.tree_state();
    let transport_peer_counts = status_transport_peer_counts(node);

    json!({
        "version": crate::version::short_version(),
        "npub": node.npub(),
        "node_addr": hex::encode(node.node_addr().as_bytes()),
        "ipv6_addr": format!("{}", node.identity().address()),
        "state": format!("{}", node.state()),
        "is_leaf_only": node.is_leaf_only(),
        "peer_count": node.peer_count(),
        "session_count": node.session_count(),
        "link_count": node.link_count(),
        "transport_count": node.transport_count(),
        "connection_count": node.connection_count(),
        "tun_state": format!("{}", node.tun_state()),
        "tun_name": node.tun_name().unwrap_or("-"),
        "effective_ipv6_mtu": node.effective_ipv6_mtu(),
        "control_socket": &node.config().node.control.socket_path,
        "pid": pid,
        "exe_path": exe_path,
        "uptime_secs": uptime_secs,
        "estimated_mesh_size": node.estimated_mesh_size(),
        "persistent": effective_persistent(&node.config().node.identity),
        "root": hex::encode(tree.root().as_bytes()),
        "is_root": tree.is_root(),
        "transport_peer_counts": transport_peer_counts,
        "forwarding": serde_json::to_value(&fwd).unwrap_or_default(),
        "sparklines": sparklines,
    })
}

/// Effective identity persistence: an explicit `nsec` behaves as persistent
/// regardless of the `persistent` flag, so the honest "survives a restart"
/// signal is `persistent || nsec.is_some()`.
fn effective_persistent(identity: &crate::config::IdentityConfig) -> bool {
    identity.persistent || identity.nsec.is_some()
}

/// Per-configured-transport-type peer counts for `show_status`. Seeds every
/// configured transport type at 0 (so an idle-but-configured type stays
/// visible), then tallies peers by their active link's transport type. Returns
/// a sorted-key JSON object (via `BTreeMap`) so the on-loop and off-loop
/// outputs match.
fn status_transport_peer_counts(node: &Node) -> Value {
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for id in node.transport_ids() {
        if let Some(handle) = node.get_transport(id) {
            counts
                .entry(handle.transport_type().name.to_string())
                .or_insert(0);
        }
    }
    for peer in node.peers() {
        if let Some(link) = node.get_link(&peer.link_id())
            && let Some(handle) = node.get_transport(&link.transport_id())
        {
            *counts
                .entry(handle.transport_type().name.to_string())
                .or_insert(0) += 1;
        }
    }
    serde_json::to_value(&counts).unwrap_or_default()
}

/// Off-loop variant of [`show_status`]: renders from the
/// [`ControlReadHandle`](super::read_handle::ControlReadHandle) in the control
/// task. Reads the effectively-immutable `NodeContext`, the `MetricsRegistry`
/// counters, and the tick-published [`StatsSnapshot`](super::snapshot::StatsSnapshot)
/// (rings + scalar gauges/counts), with no `Node` state, so it never
/// round-trips the rx_loop. Output is byte-identical to [`show_status`].
pub(crate) fn show_status_from_handle(handle: &super::read_handle::ControlReadHandle) -> Value {
    let ctx = handle.context();
    let stats = handle.stats();
    let pid = std::process::id();
    let exe_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "-".into());
    let uptime_secs = ctx.started_at.elapsed().as_secs();
    let fwd = handle.metrics().forwarding.snapshot();

    const SPARK_N: usize = 30;
    let hist = &stats.history;
    let sparklines = json!({
        "mesh_size": hist.recent(Metric::MeshSize, SPARK_N),
        "tree_depth": hist.recent(Metric::TreeDepth, SPARK_N),
        "peer_count": hist.recent(Metric::PeerCount, SPARK_N),
        "bytes_in": hist.recent(Metric::BytesIn, SPARK_N),
        "bytes_out": hist.recent(Metric::BytesOut, SPARK_N),
        "loss_rate": hist.recent(Metric::LossRate, SPARK_N),
    });

    json!({
        "version": crate::version::short_version(),
        "npub": ctx.identity.npub(),
        "node_addr": hex::encode(ctx.identity.node_addr().as_bytes()),
        "ipv6_addr": format!("{}", ctx.identity.address()),
        "state": format!("{}", stats.state),
        "is_leaf_only": ctx.is_leaf_only,
        "peer_count": stats.peer_count,
        "session_count": stats.session_count,
        "link_count": stats.link_count,
        "transport_count": stats.transport_count,
        "connection_count": stats.connection_count,
        "tun_state": format!("{}", stats.tun_state),
        "tun_name": stats.tun_name.as_deref().unwrap_or("-"),
        "effective_ipv6_mtu": stats.effective_ipv6_mtu,
        "control_socket": &ctx.config.node.control.socket_path,
        "pid": pid,
        "exe_path": exe_path,
        "uptime_secs": uptime_secs,
        "estimated_mesh_size": stats.estimated_mesh_size,
        "persistent": effective_persistent(&ctx.config.node.identity),
        "root": hex::encode(stats.root.as_bytes()),
        "is_root": stats.is_root,
        "transport_peer_counts": serde_json::to_value(&stats.transport_peer_counts).unwrap_or_default(),
        "forwarding": serde_json::to_value(&fwd).unwrap_or_default(),
        "sparklines": sparklines,
    })
}

/// `show_acl` — Loaded peer ACL state.
pub fn show_acl(node: &Node) -> Value {
    let status = node.peer_acl_status();

    json!({
        "allow_file": status.allow_file,
        "deny_file": status.deny_file,
        "enforcement_active": status.enforcement_active,
        "effective_mode": status.effective_mode,
        "default_decision": status.default_decision,
        "allow_all": status.allow_all,
        "deny_all": status.deny_all,
        "allow_file_entries": status.allow_file_entries,
        "deny_file_entries": status.deny_file_entries,
        "allow_entries": status.allow_entries,
        "deny_entries": status.deny_entries,
    })
}

/// Off-loop variant of [`show_acl`]: renders from the tick-published
/// [`StatsSnapshot`](super::snapshot::StatsSnapshot) ACL status. The ACL is an
/// `arc_swap::ArcSwap<PeerAcl>` reloaded only on the tick, and the status is a
/// cheap projection of it captured at the same tick, so this renders entirely
/// off the rx_loop. Output is byte-identical to [`show_acl`].
pub(crate) fn show_acl_from_handle(handle: &super::read_handle::ControlReadHandle) -> Value {
    let status = &handle.stats().acl_status;

    json!({
        "allow_file": status.allow_file,
        "deny_file": status.deny_file,
        "enforcement_active": status.enforcement_active,
        "effective_mode": status.effective_mode,
        "default_decision": status.default_decision,
        "allow_all": status.allow_all,
        "deny_all": status.deny_all,
        "allow_file_entries": status.allow_file_entries,
        "deny_file_entries": status.deny_file_entries,
        "allow_entries": status.allow_entries,
        "deny_entries": status.deny_entries,
    })
}

/// `show_peers` — Authenticated peers.
pub fn show_peers(node: &Node) -> Value {
    let tree = node.tree_state();
    let my_addr = *tree.my_node_addr();
    let parent_id = *tree.my_declaration().parent_id();
    let is_root = tree.is_root();

    // Per-npub Nostr-traversal failure-state snapshot, indexed by npub
    // for O(1) per-peer lookup. Empty if Nostr discovery is disabled.
    let nostr_state: std::collections::HashMap<String, _> = node
        .nostr_rendezvous_handle()
        .map(|d| {
            d.failure_state_snapshot()
                .into_iter()
                .map(|view| (view.npub.clone(), view))
                .collect()
        })
        .unwrap_or_default();

    // Cold-start gate for effective_depth, mirroring `evaluate_parent`: when any
    // peer has an SRTT measurement, unmeasured peers are excluded; during cold
    // start (no peer has SRTT) every peer uses the default link cost of 1.0.
    let any_peer_has_srtt = node.peers().any(|p| p.has_srtt());

    let peers: Vec<Value> = node
        .peers()
        .map(|peer| {
            let node_addr = *peer.node_addr();
            let addr_hex = hex::encode(node_addr.as_bytes());

            // Determine tree relationship
            let is_parent = !is_root && node_addr == parent_id;
            let is_child = tree
                .peer_declaration(&node_addr)
                .is_some_and(|decl| *decl.parent_id() == my_addr);

            let mut peer_json = json!({
                "node_addr": addr_hex,
                "npub": peer.npub(),
                "display_name": node.peer_display_name(&node_addr),
                "ipv6_addr": format!("{}", peer.address()),
                "connectivity": format!("{}", peer.connectivity()),
                "link_id": peer.link_id().as_u64(),
                "authenticated_at_ms": peer.authenticated_at(),
                "last_seen_ms": peer.last_seen(),
                "has_tree_position": peer.has_tree_position(),
                "has_bloom_filter": peer.filter_sequence() > 0,
                "filter_sequence": peer.filter_sequence(),
                "is_parent": is_parent,
                "is_child": is_child,
            });

            // Add transport address if available
            if let Some(addr) = peer.current_addr() {
                peer_json["transport_addr"] = json!(format!("{}", addr));
            }

            // Add link info (direction, transport type)
            let link_id = peer.link_id();
            if let Some(link) = node.get_link(&link_id) {
                peer_json["direction"] = json!(format!("{}", link.direction()));
                let transport_id = link.transport_id();
                if let Some(handle) = node.get_transport(&transport_id) {
                    peer_json["transport_type"] = json!(handle.transport_type().name);
                }
            }

            // Add tree depth if available
            if let Some(coords) = peer.coords() {
                peer_json["tree_depth"] = json!(coords.depth());
            }

            // effective_depth = tree_depth + link_cost, the value
            // `evaluate_parent` ranks on. `null` when the peer has no coords or
            // is unmeasured while other peers have SRTT (cold-start gate).
            let effective_depth: Option<f64> = peer.coords().and_then(|coords| {
                if any_peer_has_srtt && !peer.has_srtt() {
                    None
                } else {
                    Some(coords.depth() as f64 + peer.link_cost())
                }
            });
            peer_json["effective_depth"] = match effective_depth {
                Some(v) => json!(v),
                None => Value::Null,
            };

            // Add link stats
            let stats = peer.link_stats();
            peer_json["stats"] = json!({
                "packets_sent": stats.packets_sent,
                "packets_recv": stats.packets_recv,
                "bytes_sent": stats.bytes_sent,
                "bytes_recv": stats.bytes_recv,
            });

            // Security signals
            peer_json["replay_suppressed"] = json!(peer.replay_suppressed_count());
            peer_json["consecutive_decrypt_failures"] = json!(peer.consecutive_decrypt_failures());

            // Nostr-traversal state if this peer's npub appears in
            // failure-state. Always emitted (even null) so the schema
            // stays stable; values populated only when Nostr discovery
            // is enabled and the npub has been seen.
            let npub = peer.npub();
            let mut nostr_obj = json!({
                "consecutive_failures": 0,
                "in_cooldown": false,
                "cooldown_until_ms": Value::Null,
                "last_observed_skew_ms": Value::Null,
            });
            if let Some(state) = nostr_state.get(&npub) {
                nostr_obj["consecutive_failures"] = json!(state.consecutive_failures);
                nostr_obj["in_cooldown"] = json!(state.cooldown_until_ms.is_some());
                nostr_obj["cooldown_until_ms"] = state
                    .cooldown_until_ms
                    .map(|t| json!(t))
                    .unwrap_or(Value::Null);
                nostr_obj["last_observed_skew_ms"] = state
                    .last_observed_skew_ms
                    .map(|s| json!(s))
                    .unwrap_or(Value::Null);
            }
            peer_json["nostr_traversal"] = nostr_obj;

            // Noise session counters (rekey urgency, replay window state)
            if let Some(session) = peer.noise_session() {
                peer_json["noise"] = json!({
                    "send_counter": session.current_send_counter(),
                    "highest_recv_counter": session.highest_received_counter(),
                });
            }

            // Session indices (hijack detection)
            if let Some(idx) = peer.our_index() {
                peer_json["our_session_index"] = json!(format!("{:08x}", idx.as_u32()));
            }

            // Rekey state
            if peer.rekey_in_progress() {
                peer_json["rekey_in_progress"] = json!(true);
            }
            if peer.is_draining() {
                peer_json["rekey_draining"] = json!(true);
            }
            peer_json["current_k_bit"] = json!(peer.current_k_bit());

            // Add MMP metrics if available
            if let Some(mmp) = peer.mmp() {
                let mut mmp_json = json!({
                    "mode": format!("{}", mmp.mode()),
                });
                if let Some(srtt) = mmp.metrics.srtt_ms() {
                    mmp_json["srtt_ms"] = json!(srtt);
                }
                mmp_json["loss_rate"] = json!(mmp.metrics.loss_rate());
                mmp_json["etx"] = json!(mmp.metrics.etx);
                mmp_json["goodput_bps"] = json!(mmp.metrics.goodput_bps);
                mmp_json["delivery_ratio_forward"] = json!(mmp.metrics.delivery_ratio_forward);
                mmp_json["delivery_ratio_reverse"] = json!(mmp.metrics.delivery_ratio_reverse);
                if let Some(smoothed_loss) = mmp.metrics.smoothed_loss() {
                    mmp_json["smoothed_loss"] = json!(smoothed_loss);
                }
                if let Some(smoothed_etx) = mmp.metrics.smoothed_etx() {
                    mmp_json["smoothed_etx"] = json!(smoothed_etx);
                }
                if let Some(srtt) = mmp.metrics.srtt_ms()
                    && let Some(setx) = mmp.metrics.smoothed_etx()
                {
                    mmp_json["lqi"] = json!(setx * (1.0 + srtt / 100.0));
                }
                peer_json["mmp"] = mmp_json;
            }

            peer_json
        })
        .collect();

    json!({ "peers": peers })
}

/// Render a snapshot [`EntityMmp`](super::snapshot::EntityMmp) into the inline
/// MMP JSON block, with the quality-index key named `quality_key` (`lqi` for
/// peers, `sqi` for sessions). Reproduces the on-loop key insertion order
/// exactly. `path_mtu` is emitted (inside the leading literal) only when
/// present (session-layer); for peers it is `None` and omitted.
fn render_entity_mmp(mmp: &super::snapshot::EntityMmp, quality_key: &str) -> Value {
    // The on-loop `show_sessions` block places loss_rate/etx/goodput_bps/
    // delivery ratios/path_mtu in the leading json! literal, while `show_peers`
    // emits mode first then loss_rate/etx/goodput_bps/delivery ratios after the
    // conditional srtt_ms. Both orderings are reproduced by branching on whether
    // a session path_mtu is present.
    if let Some(path_mtu) = mmp.path_mtu {
        // Session-layer ordering (show_sessions).
        let mut j = json!({
            "mode": mmp.mode,
            "loss_rate": mmp.loss_rate,
            "etx": mmp.etx,
            "goodput_bps": mmp.goodput_bps,
            "delivery_ratio_forward": mmp.delivery_ratio_forward,
            "delivery_ratio_reverse": mmp.delivery_ratio_reverse,
            "path_mtu": path_mtu,
        });
        if let Some(srtt) = mmp.srtt_ms {
            j["srtt_ms"] = json!(srtt);
        }
        if let Some(smoothed_loss) = mmp.smoothed_loss {
            j["smoothed_loss"] = json!(smoothed_loss);
        }
        if let Some(smoothed_etx) = mmp.smoothed_etx {
            j["smoothed_etx"] = json!(smoothed_etx);
        }
        if let Some(qi) = mmp.quality_index {
            j[quality_key] = json!(qi);
        }
        j
    } else {
        // Link-layer ordering (show_peers).
        let mut j = json!({
            "mode": mmp.mode,
        });
        if let Some(srtt) = mmp.srtt_ms {
            j["srtt_ms"] = json!(srtt);
        }
        j["loss_rate"] = json!(mmp.loss_rate);
        j["etx"] = json!(mmp.etx);
        j["goodput_bps"] = json!(mmp.goodput_bps);
        j["delivery_ratio_forward"] = json!(mmp.delivery_ratio_forward);
        j["delivery_ratio_reverse"] = json!(mmp.delivery_ratio_reverse);
        if let Some(smoothed_loss) = mmp.smoothed_loss {
            j["smoothed_loss"] = json!(smoothed_loss);
        }
        if let Some(smoothed_etx) = mmp.smoothed_etx {
            j["smoothed_etx"] = json!(smoothed_etx);
        }
        if let Some(qi) = mmp.quality_index {
            j[quality_key] = json!(qi);
        }
        j
    }
}

/// Off-loop variant of [`show_peers`]: renders from the tick-published
/// [`EntitySnapshot`](super::snapshot::EntitySnapshot) peer table (display
/// names, tree-relationship flags, Nostr-traversal state resolved at publish
/// time). Output is byte-identical to [`show_peers`].
pub(crate) fn show_peers_from_handle(handle: &super::read_handle::ControlReadHandle) -> Value {
    let entities = handle.entities();
    let peers: Vec<Value> = entities
        .peers
        .iter()
        .map(|peer| {
            let mut peer_json = json!({
                "node_addr": hex::encode(peer.node_addr.as_bytes()),
                "npub": peer.npub,
                "display_name": peer.display_name,
                "ipv6_addr": peer.ipv6_addr,
                "connectivity": peer.connectivity,
                "link_id": peer.link_id,
                "authenticated_at_ms": peer.authenticated_at_ms,
                "last_seen_ms": peer.last_seen_ms,
                "has_tree_position": peer.has_tree_position,
                "has_bloom_filter": peer.has_bloom_filter,
                "filter_sequence": peer.filter_sequence,
                "is_parent": peer.is_parent,
                "is_child": peer.is_child,
            });

            if let Some(addr) = &peer.transport_addr {
                peer_json["transport_addr"] = json!(addr);
            }

            if let Some(link) = &peer.link_info {
                peer_json["direction"] = json!(link.direction);
                if let Some(tt) = &link.transport_type {
                    peer_json["transport_type"] = json!(tt);
                }
            }

            if let Some(depth) = peer.tree_depth {
                peer_json["tree_depth"] = json!(depth);
            }

            peer_json["effective_depth"] = match peer.effective_depth {
                Some(v) => json!(v),
                None => Value::Null,
            };

            peer_json["stats"] = json!({
                "packets_sent": peer.stats.packets_sent,
                "packets_recv": peer.stats.packets_recv,
                "bytes_sent": peer.stats.bytes_sent,
                "bytes_recv": peer.stats.bytes_recv,
            });

            peer_json["replay_suppressed"] = json!(peer.replay_suppressed);
            peer_json["consecutive_decrypt_failures"] = json!(peer.consecutive_decrypt_failures);

            let nostr = &peer.nostr_traversal;
            peer_json["nostr_traversal"] = json!({
                "consecutive_failures": nostr.consecutive_failures,
                "in_cooldown": nostr.cooldown_until_ms.is_some(),
                "cooldown_until_ms": nostr.cooldown_until_ms.map(|t| json!(t)).unwrap_or(Value::Null),
                "last_observed_skew_ms": nostr
                    .last_observed_skew_ms
                    .map(|s| json!(s))
                    .unwrap_or(Value::Null),
            });

            if let Some(noise) = &peer.noise {
                peer_json["noise"] = json!({
                    "send_counter": noise.send_counter,
                    "highest_recv_counter": noise.highest_recv_counter,
                });
            }

            if let Some(idx) = peer.our_session_index {
                peer_json["our_session_index"] = json!(format!("{:08x}", idx));
            }

            if peer.rekey_in_progress {
                peer_json["rekey_in_progress"] = json!(true);
            }
            if peer.rekey_draining {
                peer_json["rekey_draining"] = json!(true);
            }
            peer_json["current_k_bit"] = json!(peer.current_k_bit);

            if let Some(mmp) = &peer.mmp {
                peer_json["mmp"] = render_entity_mmp(mmp, "lqi");
            }

            peer_json
        })
        .collect();

    json!({ "peers": peers })
}

/// `show_links` — Active links.
pub fn show_links(node: &Node) -> Value {
    let links: Vec<Value> = node
        .links()
        .map(|link| {
            let stats = link.stats();
            json!({
                "link_id": link.link_id().as_u64(),
                "transport_id": link.transport_id().as_u32(),
                "remote_addr": format!("{}", link.remote_addr()),
                "direction": format!("{}", link.direction()),
                "state": format!("{}", link.state()),
                "created_at_ms": link.created_at(),
                "stats": {
                    "packets_sent": stats.packets_sent,
                    "packets_recv": stats.packets_recv,
                    "bytes_sent": stats.bytes_sent,
                    "bytes_recv": stats.bytes_recv,
                    "last_recv_ms": stats.last_recv_ms,
                },
            })
        })
        .collect();

    json!({ "links": links })
}

/// Off-loop variant of [`show_links`]: renders from the tick-published
/// [`EntitySnapshot`](super::snapshot::EntitySnapshot) link table. Output is
/// byte-identical to [`show_links`].
pub(crate) fn show_links_from_handle(handle: &super::read_handle::ControlReadHandle) -> Value {
    let entities = handle.entities();
    let links: Vec<Value> = entities
        .links
        .iter()
        .map(|link| {
            json!({
                "link_id": link.link_id,
                "transport_id": link.transport_id,
                "remote_addr": link.remote_addr,
                "direction": link.direction,
                "state": link.state,
                "created_at_ms": link.created_at_ms,
                "stats": {
                    "packets_sent": link.stats.packets_sent,
                    "packets_recv": link.stats.packets_recv,
                    "bytes_sent": link.stats.bytes_sent,
                    "bytes_recv": link.stats.bytes_recv,
                    "last_recv_ms": link.stats.last_recv_ms,
                },
            })
        })
        .collect();

    json!({ "links": links })
}

/// `show_tree` — Spanning tree state.
pub fn show_tree(node: &Node) -> Value {
    let tree = node.tree_state();
    let my_coords = tree.my_coords();
    let decl = tree.my_declaration();

    // Build coords array as hex strings
    let coords: Vec<String> = my_coords
        .entries()
        .iter()
        .map(|e| hex::encode(e.node_addr.as_bytes()))
        .collect();

    // Build peer tree data
    let peers: Vec<Value> = tree
        .peer_ids()
        .map(|peer_id| {
            let mut peer_json = json!({
                "node_addr": hex::encode(peer_id.as_bytes()),
                "display_name": node.peer_display_name(peer_id),
            });
            if let Some(coords) = tree.peer_coords(peer_id) {
                let coord_path: Vec<String> = coords
                    .entries()
                    .iter()
                    .map(|e| hex::encode(e.node_addr.as_bytes()))
                    .collect();
                peer_json["depth"] = json!(coords.depth());
                peer_json["root"] = json!(hex::encode(coords.root_id().as_bytes()));
                peer_json["coords"] = json!(coord_path);
                peer_json["distance_to_us"] = json!(my_coords.distance_to(coords));
            }
            peer_json
        })
        .collect();

    // Determine parent display name
    let parent_addr = my_coords.parent_id();
    let parent_hex = hex::encode(parent_addr.as_bytes());
    let parent_display = node.peer_display_name(parent_addr);

    let tree_stats = node.metrics().tree.snapshot();
    let root_npub = node.resolve_root_npub(tree);

    json!({
        "my_node_addr": hex::encode(tree.my_node_addr().as_bytes()),
        "root": hex::encode(tree.root().as_bytes()),
        "root_npub": root_npub,
        "is_root": tree.is_root(),
        "depth": my_coords.depth(),
        "my_coords": coords,
        "parent": parent_hex,
        "parent_display_name": parent_display,
        "declaration_sequence": decl.sequence(),
        "declaration_signed": decl.is_signed(),
        "peer_tree_count": tree.peer_count(),
        "peers": peers,
        "stats": serde_json::to_value(&tree_stats).unwrap_or_default(),
    })
}

/// Off-loop variant of [`show_tree`]: renders from the tick-published
/// [`RoutingSnapshot`](super::snapshot::RoutingSnapshot) tree view (display
/// names resolved at publish time) plus the `tree` counter family from the
/// `MetricsRegistry`. Output is byte-identical to [`show_tree`].
pub(crate) fn show_tree_from_handle(handle: &super::read_handle::ControlReadHandle) -> Value {
    let routing = handle.routing();
    let tree = &routing.tree;

    let coords: Vec<String> = tree
        .my_coords
        .iter()
        .map(|a| hex::encode(a.as_bytes()))
        .collect();

    let peers: Vec<Value> = tree
        .peers
        .iter()
        .map(|peer| {
            let mut peer_json = json!({
                "node_addr": hex::encode(peer.node_addr.as_bytes()),
                "display_name": peer.display_name,
            });
            if let Some(coords) = &peer.coords {
                let coord_path: Vec<String> = coords
                    .coord_path
                    .iter()
                    .map(|a| hex::encode(a.as_bytes()))
                    .collect();
                peer_json["depth"] = json!(coords.depth);
                peer_json["root"] = json!(hex::encode(coords.root.as_bytes()));
                peer_json["coords"] = json!(coord_path);
                peer_json["distance_to_us"] = json!(coords.distance_to_us);
            }
            peer_json
        })
        .collect();

    let tree_stats = handle.metrics().tree.snapshot();

    json!({
        "my_node_addr": hex::encode(tree.my_node_addr.as_bytes()),
        "root": hex::encode(tree.root.as_bytes()),
        "root_npub": tree.root_npub,
        "is_root": tree.is_root,
        "depth": tree.depth,
        "my_coords": coords,
        "parent": hex::encode(tree.parent.as_bytes()),
        "parent_display_name": tree.parent_display_name,
        "declaration_sequence": tree.declaration_sequence,
        "declaration_signed": tree.declaration_signed,
        "peer_tree_count": tree.peer_tree_count,
        "peers": peers,
        "stats": serde_json::to_value(&tree_stats).unwrap_or_default(),
    })
}

/// `show_sessions` — End-to-end sessions.
pub fn show_sessions(node: &Node) -> Value {
    let sessions: Vec<Value> = node
        .session_entries()
        .map(|(addr, entry)| {
            let state_str = if entry.is_established() {
                "established"
            } else if entry.is_initiating() {
                "initiating"
            } else if entry.is_awaiting_msg3() {
                "awaiting_msg3"
            } else {
                "unknown"
            };

            let mut session_json = json!({
                "remote_addr": hex::encode(addr.as_bytes()),
                "display_name": node.peer_display_name(addr),
                "state": state_str,
                "is_initiator": entry.is_initiator(),
                "last_activity_ms": entry.last_activity(),
            });

            // Derive npub from session's remote public key
            let (xonly, _parity) = entry.remote_pubkey().x_only_public_key();
            session_json["npub"] = json!(encode_npub(&xonly));

            // Traffic counters
            let (pkts_tx, pkts_rx, bytes_tx, bytes_rx) = entry.traffic_counters();
            session_json["stats"] = json!({
                "packets_sent": pkts_tx,
                "packets_recv": pkts_rx,
                "bytes_sent": bytes_tx,
                "bytes_recv": bytes_rx,
            });

            // Handshake health (visible during initiating/awaiting_msg3)
            if !entry.is_established() {
                session_json["resend_count"] = json!(entry.resend_count());
            }

            // Rekey and session health (visible when established)
            if entry.is_established() {
                session_json["session_start_ms"] = json!(entry.session_start_ms());
                session_json["current_k_bit"] = json!(entry.current_k_bit());
                session_json["coords_warmup_remaining"] = json!(entry.coords_warmup_remaining());
                session_json["is_draining"] = json!(entry.is_draining());
            }

            // Add session MMP if available
            if let Some(mmp) = entry.mmp() {
                let mut mmp_json = json!({
                    "mode": format!("{}", mmp.mode()),
                    "loss_rate": mmp.metrics.loss_rate(),
                    "etx": mmp.metrics.etx,
                    "goodput_bps": mmp.metrics.goodput_bps,
                    "delivery_ratio_forward": mmp.metrics.delivery_ratio_forward,
                    "delivery_ratio_reverse": mmp.metrics.delivery_ratio_reverse,
                    "path_mtu": mmp.path_mtu.current_mtu(),
                });
                if let Some(srtt) = mmp.metrics.srtt_ms() {
                    mmp_json["srtt_ms"] = json!(srtt);
                }
                if let Some(smoothed_loss) = mmp.metrics.smoothed_loss() {
                    mmp_json["smoothed_loss"] = json!(smoothed_loss);
                }
                if let Some(smoothed_etx) = mmp.metrics.smoothed_etx() {
                    mmp_json["smoothed_etx"] = json!(smoothed_etx);
                }
                if let Some(srtt) = mmp.metrics.srtt_ms()
                    && let Some(setx) = mmp.metrics.smoothed_etx()
                {
                    mmp_json["sqi"] = json!(setx * (1.0 + srtt / 100.0));
                }
                session_json["mmp"] = mmp_json;
            }

            session_json
        })
        .collect();

    json!({ "sessions": sessions })
}

/// Off-loop variant of [`show_sessions`]: renders from the tick-published
/// [`EntitySnapshot`](super::snapshot::EntitySnapshot) session table (display
/// name, npub, established/handshake state resolved at publish time). Output is
/// byte-identical to [`show_sessions`].
pub(crate) fn show_sessions_from_handle(handle: &super::read_handle::ControlReadHandle) -> Value {
    let entities = handle.entities();
    let sessions: Vec<Value> = entities
        .sessions
        .iter()
        .map(|session| {
            let mut session_json = json!({
                "remote_addr": hex::encode(session.remote_addr.as_bytes()),
                "display_name": session.display_name,
                "state": session.state,
                "is_initiator": session.is_initiator,
                "last_activity_ms": session.last_activity_ms,
            });

            session_json["npub"] = json!(session.npub);

            session_json["stats"] = json!({
                "packets_sent": session.stats.packets_sent,
                "packets_recv": session.stats.packets_recv,
                "bytes_sent": session.stats.bytes_sent,
                "bytes_recv": session.stats.bytes_recv,
            });

            if let Some(resend) = session.resend_count {
                session_json["resend_count"] = json!(resend);
            }

            if let Some(est) = &session.established {
                session_json["session_start_ms"] = json!(est.session_start_ms);
                session_json["current_k_bit"] = json!(est.current_k_bit);
                session_json["coords_warmup_remaining"] = json!(est.coords_warmup_remaining);
                session_json["is_draining"] = json!(est.is_draining);
            }

            if let Some(mmp) = &session.mmp {
                session_json["mmp"] = render_entity_mmp(mmp, "sqi");
            }

            session_json
        })
        .collect();

    json!({ "sessions": sessions })
}

/// `show_bloom` — Bloom filter state.
pub fn show_bloom(node: &Node) -> Value {
    let bloom = node.bloom_state();

    let leaf_deps: Vec<String> = bloom
        .leaf_dependents()
        .iter()
        .map(|addr| hex::encode(addr.as_bytes()))
        .collect();

    // Build per-peer filter info
    let peer_filters: Vec<Value> = node
        .peers()
        .map(|peer| {
            let addr = *peer.node_addr();
            let mut pf = json!({
                "peer": hex::encode(addr.as_bytes()),
                "display_name": node.peer_display_name(&addr),
                "has_filter": peer.filter_sequence() > 0,
                "filter_sequence": peer.filter_sequence(),
            });
            if let Some(filter) = peer.inbound_filter() {
                let max_fpr = node.config().node.bloom.max_inbound_fpr;
                pf["estimated_count"] = json!(filter.estimated_count(max_fpr));
                pf["set_bits"] = json!(filter.count_ones());
                pf["fill_ratio"] = json!(filter.fill_ratio());
            }
            pf
        })
        .collect();

    let bloom_stats = node.metrics().bloom.snapshot();

    // Uptree filter metrics: the last filter actually sent to the tree parent
    // (`record_sent_filter`). `null` for a root node or before the first
    // announce. The estimate is this node's whole subtree (split-horizon), not
    // the mesh.
    let tree = node.tree_state();
    let (uptree_fill_ratio, uptree_estimated_count): (Option<f64>, Option<f64>) = if tree.is_root()
    {
        (None, None)
    } else {
        let parent = tree.my_coords().parent_id();
        match bloom.last_sent_filter(parent) {
            Some(filter) => {
                let max_fpr = node.config().node.bloom.max_inbound_fpr;
                (Some(filter.fill_ratio()), filter.estimated_count(max_fpr))
            }
            None => (None, None),
        }
    };

    json!({
        "own_node_addr": hex::encode(node.node_addr().as_bytes()),
        "is_leaf_only": node.is_leaf_only(),
        "sequence": bloom.sequence(),
        "leaf_dependent_count": bloom.leaf_dependents().len(),
        "leaf_dependents": leaf_deps,
        "peer_filters": peer_filters,
        "uptree_fill_ratio": uptree_fill_ratio,
        "uptree_estimated_count": uptree_estimated_count,
        "stats": serde_json::to_value(&bloom_stats).unwrap_or_default(),
    })
}

/// Off-loop variant of [`show_bloom`]: renders from the tick-published
/// [`RoutingSnapshot`](super::snapshot::RoutingSnapshot) bloom view (display
/// names resolved at publish time) plus the `bloom` counter family from the
/// `MetricsRegistry`. Output is byte-identical to [`show_bloom`].
pub(crate) fn show_bloom_from_handle(handle: &super::read_handle::ControlReadHandle) -> Value {
    let routing = handle.routing();
    let bloom = &routing.bloom;

    let leaf_deps: Vec<String> = bloom
        .leaf_dependents
        .iter()
        .map(|addr| hex::encode(addr.as_bytes()))
        .collect();

    let peer_filters: Vec<Value> = bloom
        .peer_filters
        .iter()
        .map(|peer| {
            let mut pf = json!({
                "peer": hex::encode(peer.peer.as_bytes()),
                "display_name": peer.display_name,
                "has_filter": peer.has_filter,
                "filter_sequence": peer.filter_sequence,
            });
            if let Some(filter) = &peer.filter {
                pf["estimated_count"] = json!(filter.estimated_count);
                pf["set_bits"] = json!(filter.set_bits);
                pf["fill_ratio"] = json!(filter.fill_ratio);
            }
            pf
        })
        .collect();

    let bloom_stats = handle.metrics().bloom.snapshot();

    json!({
        "own_node_addr": hex::encode(bloom.own_node_addr.as_bytes()),
        "is_leaf_only": bloom.is_leaf_only,
        "sequence": bloom.sequence,
        "leaf_dependent_count": bloom.leaf_dependents.len(),
        "leaf_dependents": leaf_deps,
        "peer_filters": peer_filters,
        "uptree_fill_ratio": bloom.uptree_fill_ratio,
        "uptree_estimated_count": bloom.uptree_estimated_count,
        "stats": serde_json::to_value(&bloom_stats).unwrap_or_default(),
    })
}

/// `show_mmp` — MMP metrics summary.
pub fn show_mmp(node: &Node) -> Value {
    // Link-layer MMP per peer
    let peers: Vec<Value> = node.peers().filter_map(|peer| {
        let mmp = peer.mmp()?;
        let addr = *peer.node_addr();
        let metrics = &mmp.metrics;

        let mut link_layer = json!({
            "loss_rate": metrics.loss_rate(),
            "etx": metrics.etx,
            "goodput_bps": metrics.goodput_bps,
            "spin_bit_role": if mmp.spin_bit.is_initiator() { "initiator" } else { "responder" },
        });

        if let Some(smoothed_loss) = metrics.smoothed_loss() {
            link_layer["smoothed_loss"] = json!(smoothed_loss);
        }
        if let Some(smoothed_etx) = metrics.smoothed_etx() {
            link_layer["smoothed_etx"] = json!(smoothed_etx);
        }
        if let Some(srtt) = metrics.srtt_ms() {
            link_layer["srtt_ms"] = json!(srtt);
            if let Some(setx) = metrics.smoothed_etx() {
                link_layer["lqi"] = json!(setx * (1.0 + srtt / 100.0));
            }
        }

        // Trend indicators
        if metrics.rtt_trend.initialized() {
            link_layer["rtt_trend"] = json!(trend_label(metrics.rtt_trend.short(), metrics.rtt_trend.long()));
        }
        if metrics.loss_trend.initialized() {
            link_layer["loss_trend"] = json!(trend_label(metrics.loss_trend.short(), metrics.loss_trend.long()));
        }
        if metrics.goodput_trend.initialized() {
            link_layer["goodput_trend"] = json!(trend_label(metrics.goodput_trend.short(), metrics.goodput_trend.long()));
        }
        if metrics.jitter_trend.initialized() {
            link_layer["jitter_trend"] = json!(trend_label(metrics.jitter_trend.short(), metrics.jitter_trend.long()));
        }

        link_layer["delivery_ratio_forward"] = json!(metrics.delivery_ratio_forward);
        link_layer["delivery_ratio_reverse"] = json!(metrics.delivery_ratio_reverse);
        link_layer["ecn_ce_count"] = json!(metrics.last_ecn_ce_count());

        Some(json!({
            "peer": hex::encode(addr.as_bytes()),
            "display_name": node.peer_display_name(&addr),
            "mode": format!("{}", mmp.mode()),
            "link_layer": link_layer,
        }))
    }).collect();

    // Session-layer MMP
    let sessions: Vec<Value> = node
        .session_entries()
        .filter_map(|(addr, entry)| {
            let mmp = entry.mmp()?;
            let metrics = &mmp.metrics;

            let mut session_layer = json!({
                "loss_rate": metrics.loss_rate(),
                "etx": metrics.etx,
                "path_mtu": mmp.path_mtu.current_mtu(),
            });

            if let Some(smoothed_loss) = metrics.smoothed_loss() {
                session_layer["smoothed_loss"] = json!(smoothed_loss);
            }
            if let Some(smoothed_etx) = metrics.smoothed_etx() {
                session_layer["smoothed_etx"] = json!(smoothed_etx);
            }
            if let Some(srtt) = metrics.srtt_ms() {
                session_layer["srtt_ms"] = json!(srtt);
                if let Some(setx) = metrics.smoothed_etx() {
                    session_layer["sqi"] = json!(setx * (1.0 + srtt / 100.0));
                }
            }

            // Session-layer trend indicators (srtt / loss / etx), mirroring the
            // link-layer arrow semantics on the session columns.
            if metrics.rtt_trend.initialized() {
                session_layer["rtt_trend"] = json!(trend_label(
                    metrics.rtt_trend.short(),
                    metrics.rtt_trend.long()
                ));
            }
            if metrics.loss_trend.initialized() {
                session_layer["loss_trend"] = json!(trend_label(
                    metrics.loss_trend.short(),
                    metrics.loss_trend.long()
                ));
            }
            if metrics.etx_trend.initialized() {
                session_layer["etx_trend"] = json!(trend_label(
                    metrics.etx_trend.short(),
                    metrics.etx_trend.long()
                ));
            }

            Some(json!({
                "remote": hex::encode(addr.as_bytes()),
                "display_name": node.peer_display_name(addr),
                "mode": format!("{}", mmp.mode()),
                "session_layer": session_layer,
            }))
        })
        .collect();

    json!({
        "peers": peers,
        "sessions": sessions,
    })
}

/// Off-loop variant of [`show_mmp`]: renders from the tick-published
/// [`EntitySnapshot`](super::snapshot::EntitySnapshot) mmp tables (display
/// names and trend labels resolved at publish time). Output is byte-identical
/// to [`show_mmp`].
pub(crate) fn show_mmp_from_handle(handle: &super::read_handle::ControlReadHandle) -> Value {
    let entities = handle.entities();

    let peers: Vec<Value> = entities
        .mmp_peers
        .iter()
        .map(|peer| {
            let mut link_layer = json!({
                "loss_rate": peer.loss_rate,
                "etx": peer.etx,
                "goodput_bps": peer.goodput_bps,
                "spin_bit_role": if peer.spin_bit_initiator { "initiator" } else { "responder" },
            });

            if let Some(smoothed_loss) = peer.smoothed_loss {
                link_layer["smoothed_loss"] = json!(smoothed_loss);
            }
            if let Some(smoothed_etx) = peer.smoothed_etx {
                link_layer["smoothed_etx"] = json!(smoothed_etx);
            }
            if let Some(srtt) = peer.srtt_ms {
                link_layer["srtt_ms"] = json!(srtt);
                if let Some(lqi) = peer.lqi {
                    link_layer["lqi"] = json!(lqi);
                }
            }

            if let Some(t) = peer.trends.rtt_trend {
                link_layer["rtt_trend"] = json!(t);
            }
            if let Some(t) = peer.trends.loss_trend {
                link_layer["loss_trend"] = json!(t);
            }
            if let Some(t) = peer.trends.goodput_trend {
                link_layer["goodput_trend"] = json!(t);
            }
            if let Some(t) = peer.trends.jitter_trend {
                link_layer["jitter_trend"] = json!(t);
            }

            link_layer["delivery_ratio_forward"] = json!(peer.delivery_ratio_forward);
            link_layer["delivery_ratio_reverse"] = json!(peer.delivery_ratio_reverse);
            link_layer["ecn_ce_count"] = json!(peer.ecn_ce_count);

            json!({
                "peer": hex::encode(peer.peer.as_bytes()),
                "display_name": peer.display_name,
                "mode": peer.mode,
                "link_layer": link_layer,
            })
        })
        .collect();

    let sessions: Vec<Value> = entities
        .mmp_sessions
        .iter()
        .map(|session| {
            let mut session_layer = json!({
                "loss_rate": session.loss_rate,
                "etx": session.etx,
                "path_mtu": session.path_mtu,
            });

            if let Some(smoothed_loss) = session.smoothed_loss {
                session_layer["smoothed_loss"] = json!(smoothed_loss);
            }
            if let Some(smoothed_etx) = session.smoothed_etx {
                session_layer["smoothed_etx"] = json!(smoothed_etx);
            }
            if let Some(srtt) = session.srtt_ms {
                session_layer["srtt_ms"] = json!(srtt);
                if let Some(sqi) = session.sqi {
                    session_layer["sqi"] = json!(sqi);
                }
            }

            if let Some(t) = session.trends.rtt_trend {
                session_layer["rtt_trend"] = json!(t);
            }
            if let Some(t) = session.trends.loss_trend {
                session_layer["loss_trend"] = json!(t);
            }
            if let Some(t) = session.trends.etx_trend {
                session_layer["etx_trend"] = json!(t);
            }

            json!({
                "remote": hex::encode(session.remote.as_bytes()),
                "display_name": session.display_name,
                "mode": session.mode,
                "session_layer": session_layer,
            })
        })
        .collect();

    json!({
        "peers": peers,
        "sessions": sessions,
    })
}

/// `show_cache` — Coordinate cache stats and entries.
pub fn show_cache(node: &Node) -> Value {
    let cache = node.coord_cache();
    let now = now_ms();
    let stats = cache.stats(now);

    // Include individual entries for route debugging
    let entries: Vec<Value> = cache
        .iter(now)
        .map(|(addr, entry)| {
            let fips_addr = crate::identity::FipsAddress::from_node_addr(addr);
            let coord_path: Vec<String> = entry
                .coords()
                .entries()
                .iter()
                .map(|e| hex::encode(e.node_addr.as_bytes()))
                .collect();
            let mut entry_json = json!({
                "node_addr": hex::encode(addr.as_bytes()),
                "display_name": node.peer_display_name(addr),
                "ipv6_addr": format!("{}", fips_addr),
                "depth": entry.coords().depth(),
                "coords": coord_path,
                "age_ms": now.saturating_sub(entry.created_at()),
                "last_used_ms": entry.last_used(),
            });
            if let Some(mtu) = entry.path_mtu() {
                entry_json["path_mtu"] = json!(mtu);
            }
            entry_json
        })
        .collect();

    json!({
        "count": stats.entries,
        "max_entries": stats.max_entries,
        "fill_ratio": stats.fill_ratio(),
        "default_ttl_ms": cache.default_ttl_ms(),
        "expired": stats.expired,
        "avg_age_ms": stats.avg_age_ms,
        "entries": entries,
    })
}

/// Off-loop variant of [`show_cache`]: renders from the tick-published
/// [`RoutingSnapshot`](super::snapshot::RoutingSnapshot) coord-cache view
/// (display names resolved at publish time). `age_ms` is derived at render
/// time from the captured `created_at`, exactly as [`show_cache`] computed it,
/// so the rendered age stays fresh relative to the read. Output is
/// byte-identical to [`show_cache`].
pub(crate) fn show_cache_from_handle(handle: &super::read_handle::ControlReadHandle) -> Value {
    let routing = handle.routing();
    let cache = &routing.cache;
    let now = now_ms();

    let entries: Vec<Value> = cache
        .entries
        .iter()
        .map(|entry| {
            let fips_addr = crate::identity::FipsAddress::from_node_addr(&entry.node_addr);
            let coord_path: Vec<String> = entry
                .coord_path
                .iter()
                .map(|a| hex::encode(a.as_bytes()))
                .collect();
            let mut entry_json = json!({
                "node_addr": hex::encode(entry.node_addr.as_bytes()),
                "display_name": entry.display_name,
                "ipv6_addr": format!("{}", fips_addr),
                "depth": entry.depth,
                "coords": coord_path,
                "age_ms": now.saturating_sub(entry.created_at),
                "last_used_ms": entry.last_used_ms,
            });
            if let Some(mtu) = entry.path_mtu {
                entry_json["path_mtu"] = json!(mtu);
            }
            entry_json
        })
        .collect();

    json!({
        "count": cache.count,
        "max_entries": cache.max_entries,
        "fill_ratio": cache.fill_ratio,
        "default_ttl_ms": cache.default_ttl_ms,
        "expired": cache.expired,
        "avg_age_ms": cache.avg_age_ms,
        "entries": entries,
    })
}

/// `show_connections` — Pending handshakes.
pub fn show_connections(node: &Node) -> Value {
    let now = now_ms();
    let connections: Vec<Value> = node
        .connections()
        .map(|conn| {
            let mut conn_json = json!({
                "link_id": conn.link_id().as_u64(),
                "direction": format!("{}", conn.direction()),
                "handshake_state": node.connection_handshake_state(conn.link_id()),
                "started_at_ms": conn.started_at(),
                "idle_ms": now.saturating_sub(conn.last_activity()),
                "resend_count": node.connection_resend_count(conn.link_id()),
            });

            if let Some(identity) = conn.expected_identity() {
                conn_json["expected_peer"] = json!(identity.npub());
            }

            conn_json
        })
        .collect();

    json!({ "connections": connections })
}

/// Off-loop variant of [`show_connections`]: renders from the tick-published
/// [`EntitySnapshot`](super::snapshot::EntitySnapshot) connection table.
/// `idle_ms` is derived at render time from the captured `last_activity_ms`,
/// exactly as [`show_connections`] computed it. Output is byte-identical to
/// [`show_connections`].
pub(crate) fn show_connections_from_handle(
    handle: &super::read_handle::ControlReadHandle,
) -> Value {
    let entities = handle.entities();
    let now = now_ms();
    let connections: Vec<Value> = entities
        .connections
        .iter()
        .map(|conn| {
            let mut conn_json = json!({
                "link_id": conn.link_id,
                "direction": conn.direction,
                "handshake_state": conn.handshake_state,
                "started_at_ms": conn.started_at_ms,
                "idle_ms": now.saturating_sub(conn.last_activity_ms),
                "resend_count": conn.resend_count,
            });

            if let Some(expected) = &conn.expected_peer {
                conn_json["expected_peer"] = json!(expected);
            }

            conn_json
        })
        .collect();

    json!({ "connections": connections })
}

/// `show_transports` — Transport instances.
pub fn show_transports(node: &Node) -> Value {
    let transports: Vec<Value> = node
        .transport_ids()
        .map(|id| {
            let handle = node.get_transport(id).unwrap();
            let mut t_json = json!({
                "transport_id": id.as_u32(),
                "type": handle.transport_type().name,
                "state": format!("{}", handle.state()),
                "mtu": handle.mtu(),
            });

            if let Some(name) = handle.name() {
                t_json["name"] = json!(name);
            }
            if let Some(addr) = handle.local_addr() {
                t_json["local_addr"] = json!(format!("{}", addr));
            }

            // Tor-specific fields
            if let Some(mode) = handle.tor_mode() {
                t_json["tor_mode"] = json!(mode);
            }
            if let Some(onion) = handle.onion_address() {
                t_json["onion_address"] = json!(onion);
            }
            if let Some(monitoring) = handle.tor_monitoring() {
                t_json["tor_monitoring"] = serde_json::to_value(&monitoring).unwrap_or_default();
            }

            t_json["stats"] = handle.transport_stats();

            t_json
        })
        .collect();

    json!({ "transports": transports })
}

/// Off-loop variant of [`show_transports`]: renders from the tick-published
/// [`EntitySnapshot`](super::snapshot::EntitySnapshot) transport table. The
/// `stats` and `tor_monitoring` blocks are already-projected `serde_json::Value`
/// data captured at publish time. Output is byte-identical to
/// [`show_transports`].
pub(crate) fn show_transports_from_handle(handle: &super::read_handle::ControlReadHandle) -> Value {
    let entities = handle.entities();
    let transports: Vec<Value> = entities
        .transports
        .iter()
        .map(|t| {
            let mut t_json = json!({
                "transport_id": t.transport_id,
                "type": t.transport_type,
                "state": t.state,
                "mtu": t.mtu,
            });

            if let Some(name) = &t.name {
                t_json["name"] = json!(name);
            }
            if let Some(addr) = &t.local_addr {
                t_json["local_addr"] = json!(addr);
            }

            if let Some(mode) = &t.tor_mode {
                t_json["tor_mode"] = json!(mode);
            }
            if let Some(onion) = &t.onion_address {
                t_json["onion_address"] = json!(onion);
            }
            if let Some(monitoring) = &t.tor_monitoring {
                t_json["tor_monitoring"] = monitoring.clone();
            }

            t_json["stats"] = t.stats.clone();

            t_json
        })
        .collect();

    json!({ "transports": transports })
}

/// `show_routing` — Routing table summary and node statistics.
pub fn show_routing(node: &Node) -> Value {
    let cache = node.coord_cache();
    let now = now_ms();
    let cache_stats = cache.stats(now);
    let metrics = node.metrics();

    // Pending discovery lookups (individual targets)
    let lookups: Vec<Value> = node
        .pending_lookups_iter()
        .map(|(addr, lookup)| {
            json!({
                "target": hex::encode(addr.as_bytes()),
                "display_name": node.peer_display_name(addr),
                "initiated_ms": lookup.initiated_ms,
                "last_sent_ms": lookup.last_sent_ms,
                "attempt": lookup.attempt,
                "age_ms": now.saturating_sub(lookup.initiated_ms),
            })
        })
        .collect();

    // Connection retry state
    let retries: Vec<Value> = node
        .retry_state_iter()
        .map(|(addr, state)| {
            json!({
                "node_addr": hex::encode(addr.as_bytes()),
                "display_name": node.peer_display_name(addr),
                "retry_count": state.retry_count,
                "retry_after_ms": state.retry_after_ms,
                "auto_reconnect": state.reconnect,
            })
        })
        .collect();

    json!({
        "coord_cache_entries": cache_stats.entries,
        "identity_cache_entries": node.identity_cache_len(),
        "pending_lookups": lookups,
        "pending_tun_destinations": node.pending_tun_destinations(),
        "pending_tun_packets": node.pending_tun_total_packets(),
        "recent_requests": node.recent_request_count(),
        "retries": retries,
        "forwarding": serde_json::to_value(metrics.forwarding.snapshot()).unwrap_or_default(),
        // COMPAT: `discovery` is the deprecated alias for `lookup`; drop at the v2 cutover.
        "discovery": serde_json::to_value(metrics.lookup.snapshot()).unwrap_or_default(),
        "lookup": serde_json::to_value(metrics.lookup.snapshot()).unwrap_or_default(),
        "error_signals": serde_json::to_value(metrics.errors.snapshot()).unwrap_or_default(),
        "congestion": serde_json::to_value(metrics.congestion.snapshot()).unwrap_or_default(),
    })
}

/// Off-loop variant of [`show_routing`]: renders from the tick-published
/// [`RoutingSnapshot`](super::snapshot::RoutingSnapshot) (coord-cache count,
/// identity-cache count, F-queue scalars, pending lookups, retries — display
/// names resolved at publish time) plus the forwarding / discovery / error /
/// congestion counter families from the `MetricsRegistry`. `age_ms` is derived
/// at render time. Output is byte-identical to [`show_routing`].
pub(crate) fn show_routing_from_handle(handle: &super::read_handle::ControlReadHandle) -> Value {
    let routing = handle.routing();
    let view = &routing.routing;
    let now = now_ms();
    let metrics = handle.metrics();

    let lookups: Vec<Value> = view
        .pending_lookups
        .iter()
        .map(|lookup| {
            json!({
                "target": hex::encode(lookup.target.as_bytes()),
                "display_name": lookup.display_name,
                "initiated_ms": lookup.initiated_ms,
                "last_sent_ms": lookup.last_sent_ms,
                "attempt": lookup.attempt,
                "age_ms": now.saturating_sub(lookup.initiated_ms),
            })
        })
        .collect();

    let retries: Vec<Value> = view
        .retries
        .iter()
        .map(|state| {
            json!({
                "node_addr": hex::encode(state.node_addr.as_bytes()),
                "display_name": state.display_name,
                "retry_count": state.retry_count,
                "retry_after_ms": state.retry_after_ms,
                "auto_reconnect": state.auto_reconnect,
            })
        })
        .collect();

    json!({
        "coord_cache_entries": routing.cache.count,
        "identity_cache_entries": routing.identity.entries.len(),
        "pending_lookups": lookups,
        "pending_tun_destinations": view.pending_tun_destinations,
        "pending_tun_packets": view.pending_tun_packets,
        "recent_requests": view.recent_requests,
        "retries": retries,
        "forwarding": serde_json::to_value(metrics.forwarding.snapshot()).unwrap_or_default(),
        // COMPAT: `discovery` is the deprecated alias for `lookup`; drop at the v2 cutover.
        "discovery": serde_json::to_value(metrics.lookup.snapshot()).unwrap_or_default(),
        "lookup": serde_json::to_value(metrics.lookup.snapshot()).unwrap_or_default(),
        "error_signals": serde_json::to_value(metrics.errors.snapshot()).unwrap_or_default(),
        "congestion": serde_json::to_value(metrics.congestion.snapshot()).unwrap_or_default(),
    })
}

/// `show_identity_cache` — Known node identities.
///
/// Lists every node whose public key has been cached by this daemon.
/// Identities are learned from DNS resolution, peer handshakes, session
/// establishment, and configured peer npubs.  The cache uses LRU eviction
/// bounded by `node.cache.identity_size`.
pub fn show_identity_cache(node: &Node) -> Value {
    let now = now_ms();
    let entries: Vec<Value> = node
        .identity_cache_iter()
        .map(|(node_addr, pubkey, last_seen_ms)| {
            let (xonly, _parity) = pubkey.x_only_public_key();
            let fips_addr = crate::identity::FipsAddress::from_node_addr(node_addr);
            json!({
                "node_addr": hex::encode(node_addr.as_bytes()),
                "npub": encode_npub(&xonly),
                "display_name": node.peer_display_name(node_addr),
                "ipv6_addr": format!("{}", fips_addr),
                "last_seen_ms": last_seen_ms,
                "age_ms": now.saturating_sub(last_seen_ms),
            })
        })
        .collect();
    let count = entries.len();

    json!({
        "entries": entries,
        "count": count,
        "max_entries": node.identity_cache_max(),
    })
}

/// Off-loop variant of [`show_identity_cache`]: renders from the tick-published
/// [`RoutingSnapshot`](super::snapshot::RoutingSnapshot) identity view (npub /
/// ipv6 / display name resolved at publish time). `age_ms` is derived at render
/// time from the captured `last_seen_ms`, exactly as [`show_identity_cache`]
/// computed it. Output is byte-identical to [`show_identity_cache`].
pub(crate) fn show_identity_cache_from_handle(
    handle: &super::read_handle::ControlReadHandle,
) -> Value {
    let routing = handle.routing();
    let identity = &routing.identity;
    let now = now_ms();

    let entries: Vec<Value> = identity
        .entries
        .iter()
        .map(|entry| {
            json!({
                "node_addr": hex::encode(entry.node_addr.as_bytes()),
                "npub": entry.npub,
                "display_name": entry.display_name,
                "ipv6_addr": entry.ipv6_addr,
                "last_seen_ms": entry.last_seen_ms,
                "age_ms": now.saturating_sub(entry.last_seen_ms),
            })
        })
        .collect();
    let count = entries.len();

    json!({
        "entries": entries,
        "count": count,
        "max_entries": identity.max_entries,
    })
}

/// `show_stats_list` — Enumerate available history metrics and their units.
pub fn show_stats_list() -> Value {
    let metrics: Vec<Value> = ALL_METRICS
        .iter()
        .map(|m| {
            json!({
                "name": m.name(),
                "unit": m.unit(),
                "scope": "node",
            })
        })
        .chain(ALL_PEER_METRICS.iter().map(|m| {
            json!({
                "name": m.name(),
                "unit": m.unit(),
                "scope": "peer",
            })
        }))
        .collect();
    json!({
        "metrics": metrics,
        "fast_ring_seconds": crate::node::stats_history::FAST_RING_CAPACITY,
        "slow_ring_minutes": crate::node::stats_history::SLOW_RING_CAPACITY,
        "peer_retention_seconds": crate::node::stats_history::PEER_EVICTION_SECS,
    })
}

/// `show_stats_history` — Time-series samples for one metric.
///
/// Params:
/// - `metric` (required): metric name. Node-level metrics (e.g.
///   `mesh_size`) are resolved against `Metric`; per-peer metrics (e.g.
///   `srtt_ms`, `ecn_ce`) require the `peer` param and resolve against
///   `PeerMetric`.
/// - `peer` (optional): `npub1...` of the peer; required for per-peer
///   metrics.
/// - `window` (default `10m`): duration `<N>s`, `<N>m`, or `<N>h`.
/// - `granularity` (default `1s`): `1s` or `1m`.
pub fn show_stats_history(node: &Node, params: Option<&Value>) -> super::protocol::Response {
    use super::protocol::Response;
    let Some(params) = params else {
        return Response::error("missing params for show_stats_history");
    };

    let metric_name = match params.get("metric").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return Response::error("missing 'metric' parameter"),
    };

    let window_str = params
        .get("window")
        .and_then(|v| v.as_str())
        .unwrap_or("10m");
    let window = match parse_duration(window_str) {
        Ok(d) => d,
        Err(e) => return Response::error(e),
    };

    let granularity_str = params
        .get("granularity")
        .and_then(|v| v.as_str())
        .unwrap_or("1s");
    let granularity = match Granularity::from_str(granularity_str) {
        Ok(g) => g,
        Err(e) => return Response::error(e),
    };

    let peer_npub = params.get("peer").and_then(|v| v.as_str());
    let hist = node.stats_history();

    if let Some(npub) = peer_npub {
        let addr = match parse_peer_npub(npub) {
            Ok(a) => a,
            Err(e) => return Response::error(e),
        };
        let peer_metric = match PeerMetric::from_str(metric_name) {
            Ok(m) => m,
            Err(e) => return Response::error(e),
        };
        match hist.peer_query(&addr, peer_metric, window, granularity) {
            Some(series) => Response::ok(serde_json::to_value(&series).unwrap_or(Value::Null)),
            None => Response::error(format!(
                "peer not tracked in stats history: {}",
                node.peer_display_name(&addr)
            )),
        }
    } else {
        let metric = match Metric::from_str(metric_name) {
            Ok(m) => m,
            Err(e) => return Response::error(e),
        };
        let series = hist.query(metric, window, granularity);
        Response::ok(serde_json::to_value(&series).unwrap_or(Value::Null))
    }
}

/// Parse a duration of the form `<N>s`, `<N>m`, or `<N>h` into a `Duration`.
fn parse_duration(s: &str) -> Result<Duration, String> {
    if s.is_empty() {
        return Err("empty duration".to_string());
    }
    let (num_part, unit) = s.split_at(s.len() - 1);
    let n: u64 = num_part
        .parse()
        .map_err(|_| format!("invalid duration: {s}"))?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        _ => return Err(format!("unknown duration unit: {unit} (expected s, m, h)")),
    };
    Ok(Duration::from_secs(secs))
}

/// `show_stats_all_history` — Return a series for every tracked metric
/// in one round trip. Intended for the fipstop Graphs tab.
///
/// Without `peer`: returns the 10 node-level metrics.
/// With `peer` (npub): returns the 7 per-peer metrics for that peer.
///
/// Params: `{"peer": "<npub>"?, "window": "<dur>", "granularity": "<1s|1m>"}`.
pub fn show_stats_all_history(node: &Node, params: Option<&Value>) -> super::protocol::Response {
    use super::protocol::Response;
    let params = params.cloned().unwrap_or_else(|| json!({}));

    let window_str = params
        .get("window")
        .and_then(|v| v.as_str())
        .unwrap_or("10m");
    let window = match parse_duration(window_str) {
        Ok(d) => d,
        Err(e) => return Response::error(e),
    };

    let granularity_str = params
        .get("granularity")
        .and_then(|v| v.as_str())
        .unwrap_or("1s");
    let granularity = match Granularity::from_str(granularity_str) {
        Ok(g) => g,
        Err(e) => return Response::error(e),
    };

    let peer_npub = params.get("peer").and_then(|v| v.as_str());
    let hist = node.stats_history();

    let series: Vec<Value> = if let Some(npub) = peer_npub {
        let addr = match parse_peer_npub(npub) {
            Ok(a) => a,
            Err(e) => return Response::error(e),
        };
        if !hist.has_peer(&addr) {
            return Response::error(format!(
                "peer not tracked in stats history: {}",
                node.peer_display_name(&addr)
            ));
        }
        ALL_PEER_METRICS
            .iter()
            .map(|m| {
                let s = hist
                    .peer_query(&addr, *m, window, granularity)
                    .unwrap_or_else(|| {
                        // Unreachable: has_peer checked above, but degrade
                        // gracefully rather than panic.
                        crate::node::stats_history::Series {
                            metric: m.name(),
                            unit: m.unit(),
                            granularity_seconds: granularity.seconds(),
                            values: Vec::new(),
                        }
                    });
                serde_json::to_value(&s).unwrap_or(Value::Null)
            })
            .collect()
    } else {
        ALL_METRICS
            .iter()
            .map(|m| {
                let s = hist.query(*m, window, granularity);
                serde_json::to_value(&s).unwrap_or(Value::Null)
            })
            .collect()
    };

    Response::ok(json!({
        "granularity_seconds": granularity.seconds(),
        "window_seconds": window.as_secs(),
        "peer": peer_npub,
        "series": series,
    }))
}

/// Off-loop display name for the stats-history error paths. The full
/// [`Node::peer_display_name`](crate::node::Node) lookup also consults the
/// host map and live peer/session tables, which are not in the snapshot;
/// off-loop we resolve a configured alias, else fall back to truncated hex.
/// Only reached on the "peer not tracked" error branch, never on the golden
/// happy path.
fn snapshot_display_name(
    aliases: &std::collections::HashMap<NodeAddr, String>,
    addr: &NodeAddr,
) -> String {
    match aliases.get(addr) {
        Some(name) => name.clone(),
        None => addr.short_hex(),
    }
}

/// Off-loop variant of [`show_stats_history`]: serves one metric's series from
/// the tick-published [`StatsSnapshot`](super::snapshot::StatsSnapshot) rings
/// (node-level or per-peer) in the control task, off the rx_loop. Output is
/// byte-identical to [`show_stats_history`] for the series; the "peer not
/// tracked" error message uses [`snapshot_display_name`] (alias-or-hex).
pub(crate) fn show_stats_history_from_handle(
    handle: &super::read_handle::ControlReadHandle,
    params: Option<&Value>,
) -> super::protocol::Response {
    use super::protocol::Response;
    let Some(params) = params else {
        return Response::error("missing params for show_stats_history");
    };

    let metric_name = match params.get("metric").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return Response::error("missing 'metric' parameter"),
    };

    let window_str = params
        .get("window")
        .and_then(|v| v.as_str())
        .unwrap_or("10m");
    let window = match parse_duration(window_str) {
        Ok(d) => d,
        Err(e) => return Response::error(e),
    };

    let granularity_str = params
        .get("granularity")
        .and_then(|v| v.as_str())
        .unwrap_or("1s");
    let granularity = match Granularity::from_str(granularity_str) {
        Ok(g) => g,
        Err(e) => return Response::error(e),
    };

    let peer_npub = params.get("peer").and_then(|v| v.as_str());
    let stats = handle.stats();
    let hist = &stats.history;

    if let Some(npub) = peer_npub {
        let addr = match parse_peer_npub(npub) {
            Ok(a) => a,
            Err(e) => return Response::error(e),
        };
        let peer_metric = match PeerMetric::from_str(metric_name) {
            Ok(m) => m,
            Err(e) => return Response::error(e),
        };
        match hist.peer_query(&addr, peer_metric, window, granularity) {
            Some(series) => Response::ok(serde_json::to_value(&series).unwrap_or(Value::Null)),
            None => Response::error(format!(
                "peer not tracked in stats history: {}",
                snapshot_display_name(&stats.peer_aliases, &addr)
            )),
        }
    } else {
        let metric = match Metric::from_str(metric_name) {
            Ok(m) => m,
            Err(e) => return Response::error(e),
        };
        let series = hist.query(metric, window, granularity);
        Response::ok(serde_json::to_value(&series).unwrap_or(Value::Null))
    }
}

/// Off-loop variant of [`show_stats_all_history`]: serves every node-level
/// (or per-peer) series from the tick-published
/// [`StatsSnapshot`](super::snapshot::StatsSnapshot) rings, off the rx_loop.
/// Output is byte-identical to [`show_stats_all_history`]; the "peer not
/// tracked" error message uses [`snapshot_display_name`] (alias-or-hex).
pub(crate) fn show_stats_all_history_from_handle(
    handle: &super::read_handle::ControlReadHandle,
    params: Option<&Value>,
) -> super::protocol::Response {
    use super::protocol::Response;
    let params = params.cloned().unwrap_or_else(|| json!({}));

    let window_str = params
        .get("window")
        .and_then(|v| v.as_str())
        .unwrap_or("10m");
    let window = match parse_duration(window_str) {
        Ok(d) => d,
        Err(e) => return Response::error(e),
    };

    let granularity_str = params
        .get("granularity")
        .and_then(|v| v.as_str())
        .unwrap_or("1s");
    let granularity = match Granularity::from_str(granularity_str) {
        Ok(g) => g,
        Err(e) => return Response::error(e),
    };

    let peer_npub = params.get("peer").and_then(|v| v.as_str());
    let stats = handle.stats();
    let hist = &stats.history;

    let series: Vec<Value> = if let Some(npub) = peer_npub {
        let addr = match parse_peer_npub(npub) {
            Ok(a) => a,
            Err(e) => return Response::error(e),
        };
        if !hist.has_peer(&addr) {
            return Response::error(format!(
                "peer not tracked in stats history: {}",
                snapshot_display_name(&stats.peer_aliases, &addr)
            ));
        }
        ALL_PEER_METRICS
            .iter()
            .map(|m| {
                let s = hist
                    .peer_query(&addr, *m, window, granularity)
                    .unwrap_or_else(|| crate::node::stats_history::Series {
                        metric: m.name(),
                        unit: m.unit(),
                        granularity_seconds: granularity.seconds(),
                        values: Vec::new(),
                    });
                serde_json::to_value(&s).unwrap_or(Value::Null)
            })
            .collect()
    } else {
        ALL_METRICS
            .iter()
            .map(|m| {
                let s = hist.query(*m, window, granularity);
                serde_json::to_value(&s).unwrap_or(Value::Null)
            })
            .collect()
    };

    Response::ok(json!({
        "granularity_seconds": granularity.seconds(),
        "window_seconds": window.as_secs(),
        "peer": peer_npub,
        "series": series,
    }))
}

/// `show_stats_peers` — Enumerate peers tracked in the stats history
/// with their lifecycle metadata. Used by operator tools to populate
/// peer selectors and to confirm a peer is in the retention window.
pub fn show_stats_peers(node: &Node) -> Value {
    let hist = node.stats_history();
    let now = std::time::Instant::now();

    let mut peers: Vec<Value> = hist
        .peers()
        .map(|(addr, rings)| {
            let last_contact_secs = now.duration_since(rings.last_contact()).as_secs();
            let first_seen_secs = now.duration_since(rings.first_seen()).as_secs();
            let is_active = node.peers().any(|p| p.node_addr() == addr);
            let npub = node
                .peers()
                .find(|p| p.node_addr() == addr)
                .map(|p| p.npub())
                .unwrap_or_else(|| hex::encode(addr.as_bytes()));
            json!({
                "npub": npub,
                "node_addr": hex::encode(addr.as_bytes()),
                "display_name": node.peer_display_name(addr),
                "is_active": is_active,
                "first_seen_secs_ago": first_seen_secs,
                "last_contact_secs_ago": last_contact_secs,
            })
        })
        .collect();

    // Stable display order: active peers first, then by display name.
    peers.sort_by(|a, b| {
        let a_active = a
            .get("is_active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let b_active = b
            .get("is_active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        match (b_active, a_active) {
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            _ => a
                .get("display_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .cmp(b.get("display_name").and_then(|v| v.as_str()).unwrap_or("")),
        }
    });

    json!({ "peers": peers, "count": peers.len() })
}

/// Off-loop variant of [`show_stats_peers`]: renders from the tick-published
/// [`StatsSnapshot`](super::snapshot::StatsSnapshot). The lifecycle timestamps
/// (`first_seen` / `last_contact`) and the tracked-peer set come from the
/// snapshot's `history` rings; the cross-subsystem fields (`is_active`, npub,
/// display name) come from the per-peer `peer_meta` resolved at publish time.
/// The `*_secs_ago` deltas are derived at render time from the captured
/// `Instant`s, exactly as [`show_stats_peers`] computed them. Output is
/// byte-identical to [`show_stats_peers`].
pub(crate) fn show_stats_peers_from_handle(
    handle: &super::read_handle::ControlReadHandle,
) -> Value {
    let stats = handle.stats();
    let hist = &stats.history;
    let meta = &stats.peer_meta;
    let now = std::time::Instant::now();

    let mut peers: Vec<Value> = hist
        .peers()
        .map(|(addr, rings)| {
            let last_contact_secs = now.duration_since(rings.last_contact()).as_secs();
            let first_seen_secs = now.duration_since(rings.first_seen()).as_secs();
            let (is_active, npub, display_name) = match meta.get(addr) {
                Some(m) => (m.is_active, m.npub.clone(), m.display_name.clone()),
                None => (false, hex::encode(addr.as_bytes()), addr.short_hex()),
            };
            json!({
                "npub": npub,
                "node_addr": hex::encode(addr.as_bytes()),
                "display_name": display_name,
                "is_active": is_active,
                "first_seen_secs_ago": first_seen_secs,
                "last_contact_secs_ago": last_contact_secs,
            })
        })
        .collect();

    // Stable display order: active peers first, then by display name.
    peers.sort_by(|a, b| {
        let a_active = a
            .get("is_active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let b_active = b
            .get("is_active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        match (b_active, a_active) {
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            _ => a
                .get("display_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .cmp(b.get("display_name").and_then(|v| v.as_str()).unwrap_or("")),
        }
    });

    json!({ "peers": peers, "count": peers.len() })
}

/// `show_stats_history_all_peers` — One metric across every tracked
/// peer in one round trip. Backs the fipstop MetricByPeer grid view.
///
/// Params: `{"metric": "<name>", "window": "<dur>", "granularity": "<1s|1m>"}`.
/// `metric` must be a per-peer metric name (see `PeerMetric`).
pub fn show_stats_history_all_peers(
    node: &Node,
    params: Option<&Value>,
) -> super::protocol::Response {
    use super::protocol::Response;
    let Some(params) = params else {
        return Response::error("missing params for show_stats_history_all_peers");
    };

    let metric_name = match params.get("metric").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return Response::error("missing 'metric' parameter"),
    };
    let metric = match PeerMetric::from_str(metric_name) {
        Ok(m) => m,
        Err(e) => return Response::error(e),
    };

    let window_str = params
        .get("window")
        .and_then(|v| v.as_str())
        .unwrap_or("10m");
    let window = match parse_duration(window_str) {
        Ok(d) => d,
        Err(e) => return Response::error(e),
    };

    let granularity_str = params
        .get("granularity")
        .and_then(|v| v.as_str())
        .unwrap_or("1s");
    let granularity = match Granularity::from_str(granularity_str) {
        Ok(g) => g,
        Err(e) => return Response::error(e),
    };

    let hist = node.stats_history();
    let peer_addrs: Vec<NodeAddr> = hist.peer_addrs().copied().collect();

    let mut peers: Vec<Value> = peer_addrs
        .iter()
        .filter_map(|addr| {
            let s = hist.peer_query(addr, metric, window, granularity)?;
            let is_active = node.peers().any(|p| p.node_addr() == addr);
            Some(json!({
                "node_addr": hex::encode(addr.as_bytes()),
                "display_name": node.peer_display_name(addr),
                "is_active": is_active,
                "values": serde_json::to_value(&s.values).unwrap_or(Value::Null),
            }))
        })
        .collect();

    // Active peers first, then by display name.
    peers.sort_by(|a, b| {
        let a_active = a
            .get("is_active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let b_active = b
            .get("is_active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        match (b_active, a_active) {
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            _ => a
                .get("display_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .cmp(b.get("display_name").and_then(|v| v.as_str()).unwrap_or("")),
        }
    });

    Response::ok(json!({
        "metric": metric.name(),
        "unit": metric.unit(),
        "granularity_seconds": granularity.seconds(),
        "window_seconds": window.as_secs(),
        "peers": peers,
    }))
}

/// Off-loop variant of [`show_stats_history_all_peers`]: serves one per-peer
/// metric across every tracked peer from the tick-published
/// [`StatsSnapshot`](super::snapshot::StatsSnapshot). The per-peer rings and
/// tracked-peer set come from the snapshot's `history`; `is_active` and the
/// display name come from the per-peer `peer_meta` resolved at publish time.
/// Output is byte-identical to [`show_stats_history_all_peers`].
pub(crate) fn show_stats_history_all_peers_from_handle(
    handle: &super::read_handle::ControlReadHandle,
    params: Option<&Value>,
) -> super::protocol::Response {
    use super::protocol::Response;
    let Some(params) = params else {
        return Response::error("missing params for show_stats_history_all_peers");
    };

    let metric_name = match params.get("metric").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return Response::error("missing 'metric' parameter"),
    };
    let metric = match PeerMetric::from_str(metric_name) {
        Ok(m) => m,
        Err(e) => return Response::error(e),
    };

    let window_str = params
        .get("window")
        .and_then(|v| v.as_str())
        .unwrap_or("10m");
    let window = match parse_duration(window_str) {
        Ok(d) => d,
        Err(e) => return Response::error(e),
    };

    let granularity_str = params
        .get("granularity")
        .and_then(|v| v.as_str())
        .unwrap_or("1s");
    let granularity = match Granularity::from_str(granularity_str) {
        Ok(g) => g,
        Err(e) => return Response::error(e),
    };

    let stats = handle.stats();
    let hist = &stats.history;
    let meta = &stats.peer_meta;
    let peer_addrs: Vec<NodeAddr> = hist.peer_addrs().copied().collect();

    let mut peers: Vec<Value> = peer_addrs
        .iter()
        .filter_map(|addr| {
            let s = hist.peer_query(addr, metric, window, granularity)?;
            let (is_active, display_name) = match meta.get(addr) {
                Some(m) => (m.is_active, m.display_name.clone()),
                None => (false, addr.short_hex()),
            };
            Some(json!({
                "node_addr": hex::encode(addr.as_bytes()),
                "display_name": display_name,
                "is_active": is_active,
                "values": serde_json::to_value(&s.values).unwrap_or(Value::Null),
            }))
        })
        .collect();

    // Active peers first, then by display name.
    peers.sort_by(|a, b| {
        let a_active = a
            .get("is_active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let b_active = b
            .get("is_active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        match (b_active, a_active) {
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            _ => a
                .get("display_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .cmp(b.get("display_name").and_then(|v| v.as_str()).unwrap_or("")),
        }
    });

    Response::ok(json!({
        "metric": metric.name(),
        "unit": metric.unit(),
        "granularity_seconds": granularity.seconds(),
        "window_seconds": window.as_secs(),
        "peers": peers,
    }))
}

/// `show_listening_sockets` — IPv6 listeners reachable from fips0,
/// each annotated with its current `inet fips` filter classification.
///
/// Powers the fipstop "Listening on fips0" panel. See
/// [`crate::control::listening`] and [`crate::control::firewall_state`]
/// for the per-half implementations.
pub fn show_listening_sockets(node: &Node) -> Value {
    render_listening_sockets(node.identity().node_addr())
}

/// Off-loop variant of [`show_listening_sockets`]: renders from the
/// [`ControlReadHandle`](super::read_handle::ControlReadHandle) in the control
/// task. Reads only the node identity (from `NodeContext`) plus host-OS facts
/// (`/proc` socket enumeration, nftables firewall classification) — no `Node`
/// state — so it never round-trips the rx_loop.
pub(crate) fn show_listening_sockets_from_handle(
    handle: &super::read_handle::ControlReadHandle,
) -> Value {
    render_listening_sockets(handle.context().identity.node_addr())
}

/// Shared renderer for the listening-sockets panel. Given the node's
/// `NodeAddr` it derives the fips0 address, enumerates listening sockets, and
/// classifies each against the shipped firewall baseline.
fn render_listening_sockets(node_addr: &NodeAddr) -> Value {
    let fips0 = crate::FipsAddress::from_node_addr(node_addr).to_ipv6();
    let sockets = super::listening::enumerate(fips0);
    let classifier = super::firewall_state::FilterClassifier::query();

    let rows: Vec<Value> = sockets
        .iter()
        .map(|s| {
            let filter = classifier.classify(s.proto, s.port);
            json!({
                "proto": s.proto.as_str(),
                "local_addr": s.local_addr.to_string(),
                "port": s.port,
                "pid": s.pid,
                "process": s.process,
                "filter": filter.as_str(),
                "wildcard_bind": s.wildcard_bind,
            })
        })
        .collect();

    json!({
        "fips0_addr": fips0.to_string(),
        "firewall_active": classifier.is_active(),
        "sockets": rows,
    })
}

/// `show_metrics` — Counter-family snapshot served off the rx_loop.
///
/// Renders every counter family in the [`MetricsRegistry`] as a flat JSON
/// object keyed by family name. Each family's value is its
/// `*StatsSnapshot` (a `u64`-per-counter struct). Counter-only by design:
/// gauges and histograms that need live `Node` state are out of scope and
/// stay on the rx_loop path. This is the Prometheus-exporter enabler — an
/// automated scraper reads this without ever touching the hot path.
pub(crate) fn show_metrics_from_handle(handle: &super::read_handle::ControlReadHandle) -> Value {
    let m = handle.metrics();
    json!({
        "forwarding": m.forwarding.snapshot(),
        // COMPAT: `discovery` is the deprecated alias for `lookup`; drop at the v2 cutover.
        "discovery": m.lookup.snapshot(),
        "lookup": m.lookup.snapshot(),
        "tree": m.tree.snapshot(),
        "bloom": m.bloom.snapshot(),
        "congestion": m.congestion.snapshot(),
        "errors": m.errors.snapshot(),
    })
}

// No on-loop `show_*` dispatcher remains: every pure-read query is served
// off-loop from the read handle via
// [`snapshot_dispatch`](super::read_handle::snapshot_dispatch) in the control
// accept task, and the rx_loop's control path now carries only the mutating
// COMMAND handlers (`connect` / `disconnect`) in
// [`crate::control::commands::dispatch`]. The on-loop `show_*` functions above
// are retained as the byte-identity oracle the snapshot tests compare each
// off-loop renderer against.

#[cfg(test)]
mod tests {
    //! Schema-stability snapshot tests for all 18 control-socket query
    //! handlers.
    //!
    //! Each handler is invoked against a deterministically-constructed
    //! `Node` (fixed identity seed, empty peer/link/transport/cache
    //! state). The resulting JSON is normalized — fields whose values
    //! depend on wall-clock, PID, build environment, or filesystem
    //! layout are replaced with the literal string `"<redacted>"` —
    //! and compared against versioned fixtures under
    //! `src/control/snapshots/`.
    //!
    //! The point is to catch accidental schema drift (renames, type
    //! changes, dropped fields) in the operator-facing wire format.
    //! Empty-state snapshots are sufficient because every top-level
    //! key still appears, and per-element shapes inside `[]` arrays
    //! are covered by the dispatcher contract test plus serde
    //! derives elsewhere.
    //!
    //! ## Updating snapshots
    //!
    //! When a schema change is intentional, regenerate fixtures by
    //! deleting the relevant `.json` files (or the whole
    //! `snapshots/` directory) and re-running this test. Missing
    //! fixtures are written from the current output rather than
    //! failing — the next run then enforces the new shape. Review
    //! the resulting diff before committing.
    //!
    //! ## Determinism
    //!
    //! The `Node` is built via `Node::with_identity` from a fixed
    //! 32-byte seed (`[0xAB; 32]`), so `npub`, `node_addr`, and
    //! `ipv6_addr` are stable across runs and machines.
    //! Time-dependent scalars are redacted in `normalize_value` —
    //! see the `VOLATILE_KEYS` list there for the exact set.
    //! Empty arrays/maps are intrinsically stable and need no
    //! redaction.
    //!
    //! Schnorr signatures are non-deterministic, but the only
    //! signature surfaced by these handlers is `declaration_signed:
    //! bool` (a flag, not the signature itself), so no redaction is
    //! needed for that.
    use super::*;
    use crate::config::Config;
    use crate::identity::Identity;
    use crate::node::Node;
    use serde_json::{Map, Value, json};
    use std::path::PathBuf;

    /// 32-byte seed for the deterministic test identity.
    /// Any non-zero secret-key-shaped value works; 0xAB-fill is just
    /// readable in hex.
    const TEST_SEED: [u8; 32] = [0xAB; 32];

    /// Fields whose value is environment-, time-, or build-dependent
    /// and therefore must be redacted before comparison. Matched by
    /// JSON key name anywhere in the document.
    const VOLATILE_KEYS: &[&str] = &[
        // Process / build environment
        "version",
        "pid",
        "exe_path",
        "control_socket",
        "tun_name",
        // Filesystem layout (ACL, hosts, etc.)
        "allow_file",
        "deny_file",
        // Wall-clock derived
        "uptime_secs",
        "started_at_ms",
        "session_start_ms",
        "authenticated_at_ms",
        "last_seen_ms",
        "last_activity_ms",
        "last_recv_ms",
        "created_at_ms",
        "initiated_ms",
        "last_sent_ms",
        "age_ms",
        "last_used_ms",
        "idle_ms",
        "first_seen_secs_ago",
        "last_contact_secs_ago",
    ];

    /// Build a Node with a fixed identity, default config, and empty
    /// runtime state (no peers, links, sessions, transports, or cache
    /// entries). This keeps every per-element list empty and every
    /// scalar deterministic modulo `VOLATILE_KEYS`.
    fn build_test_node() -> Node {
        let identity =
            Identity::from_secret_bytes(&TEST_SEED).expect("test seed is a valid secret key");
        let config = Config::new();
        Node::with_identity(identity, config).expect("default config is valid")
    }

    /// Recursively walk a JSON value, replacing the value of any key
    /// listed in `VOLATILE_KEYS` with the literal string
    /// `"<redacted>"`. Array elements are recursed into.
    fn normalize_value(value: &mut Value) {
        match value {
            Value::Object(map) => {
                for (key, v) in map.iter_mut() {
                    if VOLATILE_KEYS.contains(&key.as_str()) {
                        *v = Value::String("<redacted>".to_string());
                    } else {
                        normalize_value(v);
                    }
                }
            }
            Value::Array(items) => {
                for item in items.iter_mut() {
                    normalize_value(item);
                }
            }
            _ => {}
        }
    }

    /// Wrap a handler value in the on-the-wire `Response` envelope so
    /// the snapshot reflects exactly what a control-socket client
    /// receives. Pretty-printed and sorted-keyed for readable diffs.
    fn render(value: Value) -> String {
        let mut wrapped = json!({ "status": "ok", "data": value });
        normalize_value(&mut wrapped);
        let sorted = sort_object_keys(&wrapped);
        serde_json::to_string_pretty(&sorted).expect("json serialization is infallible")
    }

    /// Same as `render` but takes a `Response` directly (for handlers
    /// that return `Response`, not `Value`).
    fn render_response(resp: super::super::protocol::Response) -> String {
        let value = serde_json::to_value(&resp).expect("response always serializes");
        let mut value = value;
        normalize_value(&mut value);
        let sorted = sort_object_keys(&value);
        serde_json::to_string_pretty(&sorted).expect("json serialization is infallible")
    }

    /// Recursively sort object keys for stable diff-friendly output.
    /// `serde_json::Value` preserves insertion order; handlers don't
    /// guarantee any particular emit order, so normalize here.
    fn sort_object_keys(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut sorted: Map<String, Value> = Map::new();
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                for key in keys {
                    sorted.insert(key.clone(), sort_object_keys(&map[key]));
                }
                Value::Object(sorted)
            }
            Value::Array(items) => Value::Array(items.iter().map(sort_object_keys).collect()),
            other => other.clone(),
        }
    }

    fn snapshot_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("control")
            .join("snapshots")
    }

    /// Compare `actual` against the on-disk fixture for `name`. If the
    /// fixture does not exist, write it (first-run convention) and
    /// pass. Any subsequent mismatch fails with an inline diff hint.
    fn assert_snapshot(name: &str, actual: &str) {
        let path = snapshot_dir().join(format!("{name}.json"));
        if !path.exists() {
            std::fs::create_dir_all(path.parent().unwrap())
                .expect("failed to create snapshots dir");
            std::fs::write(&path, actual).expect("failed to write new snapshot");
            // Newly written: nothing to compare. Subsequent runs enforce.
            return;
        }
        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read snapshot {}: {e}", path.display()));
        // Normalize line endings: Windows checkouts with core.autocrlf=true
        // convert fixture files to CRLF; the in-memory JSON output is LF.
        let expected = expected.replace("\r\n", "\n");
        // Tolerate trailing newline differences from editors.
        if expected.trim_end() != actual.trim_end() {
            panic!(
                "snapshot mismatch for {name}\n\
                 fixture: {}\n\
                 -- expected --\n{expected}\n\
                 -- actual --\n{actual}\n\
                 -- end --\n\
                 If the schema change is intentional, delete the fixture \
                 and re-run to regenerate.",
                path.display()
            );
        }
    }

    // ---- 18 handler snapshot tests --------------------------------------

    #[test]
    fn snapshot_show_status() {
        let node = build_test_node();
        assert_snapshot("show_status", &render(show_status(&node)));
    }

    #[test]
    fn snapshot_show_acl() {
        let node = build_test_node();
        assert_snapshot("show_acl", &render(show_acl(&node)));
    }

    #[test]
    fn snapshot_show_peers() {
        let node = build_test_node();
        assert_snapshot("show_peers", &render(show_peers(&node)));
    }

    #[test]
    fn snapshot_show_links() {
        let node = build_test_node();
        assert_snapshot("show_links", &render(show_links(&node)));
    }

    #[test]
    fn snapshot_show_tree() {
        let node = build_test_node();
        assert_snapshot("show_tree", &render(show_tree(&node)));
    }

    #[test]
    fn snapshot_show_sessions() {
        let node = build_test_node();
        assert_snapshot("show_sessions", &render(show_sessions(&node)));
    }

    #[test]
    fn snapshot_show_bloom() {
        let node = build_test_node();
        assert_snapshot("show_bloom", &render(show_bloom(&node)));
    }

    #[test]
    fn snapshot_show_mmp() {
        let node = build_test_node();
        assert_snapshot("show_mmp", &render(show_mmp(&node)));
    }

    #[test]
    fn snapshot_show_cache() {
        let node = build_test_node();
        assert_snapshot("show_cache", &render(show_cache(&node)));
    }

    #[test]
    fn snapshot_show_connections() {
        let node = build_test_node();
        assert_snapshot("show_connections", &render(show_connections(&node)));
    }

    #[test]
    fn snapshot_show_transports() {
        let node = build_test_node();
        assert_snapshot("show_transports", &render(show_transports(&node)));
    }

    #[test]
    fn snapshot_show_routing() {
        let node = build_test_node();
        assert_snapshot("show_routing", &render(show_routing(&node)));
    }

    #[test]
    fn snapshot_show_identity_cache() {
        let node = build_test_node();
        assert_snapshot("show_identity_cache", &render(show_identity_cache(&node)));
    }

    #[test]
    fn snapshot_show_stats_list() {
        // Static — no Node needed.
        assert_snapshot("show_stats_list", &render(show_stats_list()));
    }

    #[test]
    fn snapshot_show_stats_history() {
        let node = build_test_node();
        // Pin the empty-history series shape for one node-level metric.
        let params = json!({ "metric": "mesh_size", "window": "10s", "granularity": "1s" });
        let resp = show_stats_history(&node, Some(&params));
        assert_snapshot("show_stats_history", &render_response(resp));
    }

    #[test]
    fn snapshot_show_stats_all_history() {
        let node = build_test_node();
        // Empty-history all-node series; small window keeps the
        // per-series `values` arrays short and stable.
        let params = json!({ "window": "10s", "granularity": "1s" });
        let resp = show_stats_all_history(&node, Some(&params));
        assert_snapshot("show_stats_all_history", &render_response(resp));
    }

    #[test]
    fn snapshot_show_stats_peers() {
        let node = build_test_node();
        assert_snapshot("show_stats_peers", &render(show_stats_peers(&node)));
    }

    #[test]
    fn snapshot_show_stats_history_all_peers() {
        let node = build_test_node();
        // No peers tracked → empty `peers: []` envelope. Per-peer
        // `values` shape is exercised once a real peer is wired in;
        // here we only pin the envelope.
        let params = json!({ "metric": "srtt_ms", "window": "10s", "granularity": "1s" });
        let resp = show_stats_history_all_peers(&node, Some(&params));
        assert_snapshot("show_stats_history_all_peers", &render_response(resp));
    }

    /// The five Category-D queries cut over to off-loop serving in R3. Served
    /// via `snapshot_dispatch`; coverage asserted in
    /// `snapshot_dispatch_serves_category_d_queries` below.
    const OFF_LOOP_CATEGORY_D: &[&str] = &[
        "show_tree",
        "show_bloom",
        "show_cache",
        "show_routing",
        "show_identity_cache",
    ];

    /// The six Category-E queries cut over to off-loop serving in R4. Served via
    /// `snapshot_dispatch`; coverage asserted in
    /// `snapshot_dispatch_serves_category_e_queries`.
    const OFF_LOOP_CATEGORY_E: &[&str] = &[
        "show_peers",
        "show_sessions",
        "show_links",
        "show_connections",
        "show_transports",
        "show_mmp",
    ];

    /// Milestone-completion contract: every pure-read `show_*` query is served
    /// off-loop via `snapshot_dispatch`, and the rx_loop control path carries no
    /// `show_*` arm at all — only the mutating COMMAND handlers (`connect` /
    /// `disconnect`) reach it. This test enumerates the full read surface and
    /// asserts each renders off-loop, then asserts the mutations do NOT.
    #[test]
    fn snapshot_dispatch_serves_every_read_query() {
        use super::super::protocol::Request;
        use super::super::read_handle::snapshot_dispatch;

        let mut node = build_test_node();
        // Publish every snapshot from the tick before reading.
        node.record_stats_history();
        let handle = node.control_read_handle();

        // The complete pure-read `show_*` surface, with params where required.
        let read_queries: &[(&str, Option<Value>)] = &[
            ("show_status", None),
            ("show_acl", None),
            ("show_listening_sockets", None),
            ("show_metrics", None),
            ("show_stats_list", None),
            (
                "show_stats_history",
                Some(json!({ "metric": "mesh_size", "window": "10s", "granularity": "1s" })),
            ),
            (
                "show_stats_all_history",
                Some(json!({ "window": "10s", "granularity": "1s" })),
            ),
            ("show_stats_peers", None),
            (
                "show_stats_history_all_peers",
                Some(json!({ "metric": "srtt_ms", "window": "10s", "granularity": "1s" })),
            ),
            ("show_tree", None),
            ("show_bloom", None),
            ("show_cache", None),
            ("show_routing", None),
            ("show_identity_cache", None),
            ("show_peers", None),
            ("show_sessions", None),
            ("show_links", None),
            ("show_connections", None),
            ("show_transports", None),
            ("show_mmp", None),
        ];
        for (cmd, params) in read_queries {
            let req = Request {
                command: cmd.to_string(),
                params: params.clone(),
            };
            let resp = snapshot_dispatch(&req, &handle)
                .unwrap_or_else(|| panic!("{cmd} must be served off-loop"));
            assert_eq!(resp.status, "ok", "{cmd} off-loop response not ok");
        }

        // Mutations are NOT served off-loop; they take the rx_loop COMMAND path.
        for cmd in ["connect", "disconnect"] {
            let req = Request {
                command: cmd.to_string(),
                params: None,
            };
            assert!(
                snapshot_dispatch(&req, &handle).is_none(),
                "{cmd} must fall through to the rx_loop command path"
            );
        }
    }

    /// Structural confirmation that the rx_loop no longer dispatches `show_*`:
    /// the rx_loop source carries no `queries::dispatch` call and no
    /// `starts_with("show_")` routing branch. Reads the committed source of
    /// `src/node/dataplane/rx_loop.rs` and asserts both markers are absent. This
    /// is the milestone's "remove `show_*` from the data-plane dispatch path"
    /// invariant, guarded against regression.
    #[test]
    fn rx_loop_has_no_show_dispatch() {
        let src = include_str!("../node/dataplane/rx_loop.rs");
        assert!(
            !src.contains("queries::dispatch"),
            "rx_loop must not call queries::dispatch (show_* served off-loop)"
        );
        assert!(
            !src.contains("starts_with(\"show_\")"),
            "rx_loop must not branch on a show_* command prefix"
        );
    }

    // ---- off-loop (snapshot_dispatch) coverage ---------------------------

    /// `show_metrics` is counter-only and served off the rx_loop. Raw
    /// counter values are runtime-varying, so instead of a value-exact
    /// golden fixture this pins the *shape*: every counter family appears
    /// as a key, each maps to an object, and a representative counter key
    /// is present in each family. This catches family renames / drops
    /// without flaking on live values.
    #[test]
    fn show_metrics_shape_covers_all_families() {
        let node = build_test_node();
        let handle = node.control_read_handle();
        let value = show_metrics_from_handle(&handle);
        let obj = value.as_object().expect("show_metrics renders an object");

        let expected_families = [
            ("forwarding", "received_packets"),
            // `discovery` is the deprecated dual-emit alias for `lookup`; drop at the v2 cutover.
            ("discovery", "req_received"),
            ("lookup", "req_received"),
            ("tree", "accepted"),
            ("bloom", "accepted"),
            ("congestion", "ce_forwarded"),
            ("errors", "coords_required"),
        ];
        assert_eq!(
            obj.len(),
            expected_families.len(),
            "show_metrics has exactly {} counter families, got keys {:?}",
            expected_families.len(),
            obj.keys().collect::<Vec<_>>()
        );
        for (family, sample_key) in expected_families {
            let fam = obj
                .get(family)
                .unwrap_or_else(|| panic!("missing counter family {family}"))
                .as_object()
                .unwrap_or_else(|| panic!("family {family} is not an object"));
            assert!(
                fam.contains_key(sample_key),
                "family {family} missing expected counter {sample_key}"
            );
            // On a fresh node every counter is zero.
            assert_eq!(
                fam.get(sample_key).and_then(Value::as_u64),
                Some(0),
                "fresh-node counter {family}.{sample_key} should be 0"
            );
        }
    }

    /// The R1/R2 scalar-and-series queries are served off-loop via
    /// `snapshot_dispatch`; mutations return `None` and take the rx_loop COMMAND
    /// path. (`show_stats_peers` / `show_stats_history_all_peers`, formerly
    /// asserted on-loop here, were cut over in R5 — see
    /// `snapshot_dispatch_serves_every_read_query` for the full read surface.)
    #[test]
    fn snapshot_dispatch_serves_scalar_and_series_queries() {
        use super::super::protocol::Request;
        use super::super::read_handle::snapshot_dispatch;

        let node = build_test_node();
        let handle = node.control_read_handle();

        let req = |command: &str| Request {
            command: command.to_string(),
            params: None,
        };

        // Cut over to off-loop serving. The parameterized stats-series
        // queries need their params to render; everything else is
        // parameterless.
        let req_params = |command: &str, params: Option<Value>| Request {
            command: command.to_string(),
            params,
        };
        let off_loop = [
            ("show_listening_sockets", None),
            ("show_stats_list", None),
            ("show_metrics", None),
            ("show_status", None),
            (
                "show_stats_history",
                Some(json!({ "metric": "mesh_size", "window": "10s", "granularity": "1s" })),
            ),
            (
                "show_stats_all_history",
                Some(json!({ "window": "10s", "granularity": "1s" })),
            ),
            // R3 Category-D cutover.
            ("show_tree", None),
            ("show_bloom", None),
            ("show_cache", None),
            ("show_routing", None),
            ("show_identity_cache", None),
        ];
        for (cmd, params) in off_loop {
            let resp = snapshot_dispatch(&req_params(cmd, params), &handle)
                .unwrap_or_else(|| panic!("{cmd} must be served off-loop"));
            assert_eq!(resp.status, "ok", "{cmd} off-loop response not ok");
        }

        // Mutations take the rx_loop COMMAND path.
        for cmd in ["connect", "disconnect"] {
            assert!(
                snapshot_dispatch(&req(cmd), &handle).is_none(),
                "{cmd} must fall through to the rx_loop command path"
            );
        }
    }

    /// R5 cutover + byte-identity: after a `record_stats_history()` tick the
    /// off-loop `show_acl` / `show_stats_peers` / `show_stats_history_all_peers`
    /// renders each equal their on-loop oracle byte-for-byte, and all three are
    /// served off-loop via `snapshot_dispatch`.
    #[test]
    fn snapshot_dispatch_serves_r5_queries() {
        use super::super::protocol::Request;
        use super::super::read_handle::snapshot_dispatch;

        let mut node = build_test_node();
        node.record_stats_history();
        let handle = node.control_read_handle();

        // All three served off-loop (return Some, status ok).
        let cases: &[(&str, Option<Value>)] = &[
            ("show_acl", None),
            ("show_stats_peers", None),
            (
                "show_stats_history_all_peers",
                Some(json!({ "metric": "srtt_ms", "window": "10s", "granularity": "1s" })),
            ),
        ];
        for (cmd, params) in cases {
            let req = Request {
                command: cmd.to_string(),
                params: params.clone(),
            };
            let resp = snapshot_dispatch(&req, &handle)
                .unwrap_or_else(|| panic!("{cmd} must be served off-loop"));
            assert_eq!(resp.status, "ok", "{cmd} off-loop response not ok");
        }

        // Byte-identity vs the on-loop oracle.
        assert_eq!(
            render(show_acl(&node)),
            render(show_acl_from_handle(&handle)),
            "off-loop show_acl must match on-loop output"
        );
        assert_eq!(
            render(show_stats_peers(&node)),
            render(show_stats_peers_from_handle(&handle)),
            "off-loop show_stats_peers must match on-loop output"
        );
        let params = json!({ "metric": "srtt_ms", "window": "10s", "granularity": "1s" });
        assert_eq!(
            render_response(show_stats_history_all_peers(&node, Some(&params))),
            render_response(show_stats_history_all_peers_from_handle(
                &handle,
                Some(&params)
            )),
            "off-loop show_stats_history_all_peers must match on-loop output"
        );
    }

    /// The tick-published `StatsSnapshot` reflects node state: after a
    /// simulated `record_stats_history()` tick, the snapshot's counts and
    /// scalar gauges match the node, and the off-loop `show_status` render
    /// equals the on-loop `show_status` render byte-for-byte.
    #[test]
    fn stats_snapshot_reflects_state_after_tick() {
        let mut node = build_test_node();

        // Before any tick the seeded snapshot is empty.
        let handle = node.control_read_handle();
        assert!(
            !handle.stats().history.has_data(),
            "seed snapshot has no history before first tick"
        );

        // Advance one tick (the natural publisher site).
        node.record_stats_history();

        let handle = node.control_read_handle();
        let snap = handle.stats();
        assert!(
            snap.history.has_data(),
            "snapshot history reflects the tick"
        );
        // Scalar gauges / counts match the node's live accessors.
        assert_eq!(snap.peer_count, node.peer_count());
        assert_eq!(snap.session_count, node.session_count());
        assert_eq!(snap.link_count, node.link_count());
        assert_eq!(snap.transport_count, node.transport_count());
        assert_eq!(snap.connection_count, node.connection_count());
        assert_eq!(snap.estimated_mesh_size, node.estimated_mesh_size());
        assert_eq!(snap.effective_ipv6_mtu, node.effective_ipv6_mtu());
        // R5: the ACL status projection matches the node's live ACL status.
        assert_eq!(snap.acl_status, node.peer_acl_status());

        // Off-loop render must equal the on-loop render byte-for-byte.
        let on_loop = render(show_status(&node));
        let off_loop = render(show_status_from_handle(&handle));
        assert_eq!(
            on_loop, off_loop,
            "off-loop show_status must match on-loop output"
        );
    }

    /// The five Category-D queries are served off-loop via `snapshot_dispatch`
    /// (return `Some` with status ok); everything not cut over stays on the
    /// rx_loop path (`None`).
    #[test]
    fn snapshot_dispatch_serves_category_d_queries() {
        use super::super::protocol::Request;
        use super::super::read_handle::snapshot_dispatch;

        let mut node = build_test_node();
        // Publish the routing snapshot from its tick before reading it.
        node.record_stats_history();
        let handle = node.control_read_handle();

        let req = |command: &str| Request {
            command: command.to_string(),
            params: None,
        };

        for cmd in OFF_LOOP_CATEGORY_D {
            let resp = snapshot_dispatch(&req(cmd), &handle)
                .unwrap_or_else(|| panic!("{cmd} must be served off-loop"));
            assert_eq!(resp.status, "ok", "{cmd} off-loop response not ok");
        }

        // Mutations take the rx_loop COMMAND path. (Every read query, including
        // the per-peer stats-series queries, is served off-loop as of R5.)
        for cmd in ["connect", "disconnect"] {
            assert!(
                snapshot_dispatch(&req(cmd), &handle).is_none(),
                "{cmd} must fall through to the rx_loop command path"
            );
        }
    }

    /// The tick-published `RoutingSnapshot` reflects node state, and each
    /// off-loop Category-D render equals its on-loop render byte-for-byte
    /// (modulo the volatile-key redaction the wire-schema tests already apply).
    #[test]
    fn routing_snapshot_matches_on_loop_after_tick() {
        let mut node = build_test_node();

        // Before any tick the seeded routing snapshot is empty.
        let handle = node.control_read_handle();
        assert!(
            handle.routing().tree.peers.is_empty(),
            "seed routing snapshot has no tree peers before first tick"
        );

        // Advance one tick (the publisher site).
        node.record_stats_history();
        let handle = node.control_read_handle();

        // Snapshot reflects the node's own tree identity.
        let routing = handle.routing();
        assert_eq!(
            routing.tree.my_node_addr,
            *node.node_addr(),
            "routing snapshot tree identity reflects the node"
        );
        assert_eq!(
            routing.identity.max_entries,
            node.identity_cache_max(),
            "routing snapshot carries the identity-cache capacity"
        );
        drop(routing);

        // Each off-loop render must equal the on-loop render byte-for-byte.
        assert_eq!(
            render(show_tree(&node)),
            render(show_tree_from_handle(&handle)),
            "off-loop show_tree must match on-loop output"
        );
        assert_eq!(
            render(show_bloom(&node)),
            render(show_bloom_from_handle(&handle)),
            "off-loop show_bloom must match on-loop output"
        );
        assert_eq!(
            render(show_cache(&node)),
            render(show_cache_from_handle(&handle)),
            "off-loop show_cache must match on-loop output"
        );
        assert_eq!(
            render(show_routing(&node)),
            render(show_routing_from_handle(&handle)),
            "off-loop show_routing must match on-loop output"
        );
        assert_eq!(
            render(show_identity_cache(&node)),
            render(show_identity_cache_from_handle(&handle)),
            "off-loop show_identity_cache must match on-loop output"
        );
    }

    // ---- R4 Category-E coverage ------------------------------------------

    /// The six Category-E queries are served off-loop via `snapshot_dispatch`
    /// (return `Some` with status ok); mutations take the rx_loop COMMAND path.
    #[test]
    fn snapshot_dispatch_serves_category_e_queries() {
        use super::super::protocol::Request;
        use super::super::read_handle::snapshot_dispatch;

        let mut node = build_test_node();
        // Publish the entity snapshot from its tick before reading it.
        node.record_stats_history();
        let handle = node.control_read_handle();

        let req = |command: &str| Request {
            command: command.to_string(),
            params: None,
        };

        for cmd in OFF_LOOP_CATEGORY_E {
            let resp = snapshot_dispatch(&req(cmd), &handle)
                .unwrap_or_else(|| panic!("{cmd} must be served off-loop"));
            assert_eq!(resp.status, "ok", "{cmd} off-loop response not ok");
        }

        // Mutations take the rx_loop COMMAND path. (Every read query is served
        // off-loop as of R5.)
        for cmd in ["connect", "disconnect"] {
            assert!(
                snapshot_dispatch(&req(cmd), &handle).is_none(),
                "{cmd} must fall through to the rx_loop command path"
            );
        }
    }

    /// Freshness + fidelity: after a `record_stats_history()` tick (the entity
    /// publisher site) each off-loop Category-E render equals its on-loop render
    /// byte-for-byte, and the seeded snapshot is empty before the first tick.
    #[test]
    fn entity_snapshot_matches_on_loop_after_tick() {
        let mut node = build_test_node();

        // Before any tick the seeded entity snapshot is empty.
        let handle = node.control_read_handle();
        assert!(
            handle.entities().peers.is_empty(),
            "seed entity snapshot has no peers before first tick"
        );

        // Advance one tick (the publisher site).
        node.record_stats_history();
        let handle = node.control_read_handle();

        // Each off-loop render must equal the on-loop render byte-for-byte.
        assert_eq!(
            render(show_peers(&node)),
            render(show_peers_from_handle(&handle)),
            "off-loop show_peers must match on-loop output"
        );
        assert_eq!(
            render(show_sessions(&node)),
            render(show_sessions_from_handle(&handle)),
            "off-loop show_sessions must match on-loop output"
        );
        assert_eq!(
            render(show_links(&node)),
            render(show_links_from_handle(&handle)),
            "off-loop show_links must match on-loop output"
        );
        assert_eq!(
            render(show_connections(&node)),
            render(show_connections_from_handle(&handle)),
            "off-loop show_connections must match on-loop output"
        );
        assert_eq!(
            render(show_transports(&node)),
            render(show_transports_from_handle(&handle)),
            "off-loop show_transports must match on-loop output"
        );
        assert_eq!(
            render(show_mmp(&node)),
            render(show_mmp_from_handle(&handle)),
            "off-loop show_mmp must match on-loop output"
        );
    }

    /// Structural sharing (the R4 umbrella mandate): a republish in which only
    /// one row changed re-allocates only that one `Arc<Row>` — every unchanged
    /// row is reused by pointer (`Arc::ptr_eq`). Exercises
    /// [`reconcile_rows`](super::super::snapshot::reconcile_rows), the
    /// `Vec<Arc<Row>>` reconciliation the per-tick publisher uses for every
    /// entity table.
    #[test]
    fn entity_snapshot_structural_sharing() {
        use super::super::snapshot::{LinkRow, LinkStats, reconcile_rows};

        let mk = |link_id: u64, bytes_recv: u64| LinkRow {
            link_id,
            transport_id: 1,
            remote_addr: "0.0.0.0:0".to_string(),
            direction: "outbound".to_string(),
            state: "up".to_string(),
            created_at_ms: 1000,
            stats: LinkStats {
                packets_sent: 0,
                packets_recv: 0,
                bytes_sent: 0,
                bytes_recv,
                last_recv_ms: 0,
            },
        };

        // First publish: two distinct rows, both freshly allocated.
        let prev = reconcile_rows::<LinkRow, _, _>(&[], vec![mk(1, 10), mk(2, 20)], |r| r.link_id);
        assert_eq!(prev.len(), 2);

        // Second publish: row 1 unchanged, row 2 changed (bytes_recv differs).
        let next = reconcile_rows(&prev, vec![mk(1, 10), mk(2, 999)], |r| r.link_id);
        assert_eq!(next.len(), 2);

        // The unchanged row is the SAME Arc (reused by pointer).
        assert!(
            std::sync::Arc::ptr_eq(&prev[0], &next[0]),
            "unchanged row must be reused by pointer (structural sharing)"
        );
        // The changed row is a fresh allocation.
        assert!(
            !std::sync::Arc::ptr_eq(&prev[1], &next[1]),
            "changed row must be re-allocated"
        );
        assert_eq!(next[1].stats.bytes_recv, 999);

        // A republish with no changes reuses every row.
        let again = reconcile_rows(&next, vec![mk(1, 10), mk(2, 999)], |r| r.link_id);
        assert!(
            std::sync::Arc::ptr_eq(&next[0], &again[0])
                && std::sync::Arc::ptr_eq(&next[1], &again[1]),
            "an unchanged republish must reuse every row Arc"
        );
    }
}
