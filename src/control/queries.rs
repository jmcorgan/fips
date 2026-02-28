//! Control query implementations.
//!
//! Each function takes `&Node` and returns a `serde_json::Value`.
//! Query logic is kept separate from socket handling.

use crate::node::Node;
use serde_json::{json, Value};

/// Helper: get current Unix time in milliseconds.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Classify a DualEwma trend as "rising", "falling", or "stable".
fn trend_label(short: f64, long: f64) -> &'static str {
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
    json!({
        "npub": node.npub(),
        "node_addr": hex::encode(node.node_addr().as_bytes()),
        "fips_address": format!("{}", node.identity().address()),
        "state": format!("{}", node.state()),
        "is_leaf_only": node.is_leaf_only(),
        "peer_count": node.peer_count(),
        "session_count": node.session_count(),
        "link_count": node.link_count(),
        "transport_count": node.transport_count(),
        "connection_count": node.connection_count(),
        "tun_state": format!("{}", node.tun_state()),
        "effective_ipv6_mtu": node.effective_ipv6_mtu(),
    })
}

/// `show_peers` — Authenticated peers.
pub fn show_peers(node: &Node) -> Value {
    let peers: Vec<Value> = node.peers().map(|peer| {
        let node_addr = *peer.node_addr();
        let addr_hex = hex::encode(node_addr.as_bytes());

        let mut peer_json = json!({
            "node_addr": addr_hex,
            "npub": peer.npub(),
            "display_name": node.peer_display_name(&node_addr),
            "fips_address": format!("{}", peer.address()),
            "connectivity": format!("{}", peer.connectivity()),
            "link_id": peer.link_id().as_u64(),
            "authenticated_at_ms": peer.authenticated_at(),
            "last_seen_ms": peer.last_seen(),
            "has_tree_position": peer.has_tree_position(),
            "has_bloom_filter": peer.filter_sequence() > 0,
            "filter_sequence": peer.filter_sequence(),
        });

        // Add transport address if available
        if let Some(addr) = peer.current_addr() {
            peer_json["transport_addr"] = json!(format!("{}", addr));
        }

        // Add tree depth if available
        if let Some(coords) = peer.coords() {
            peer_json["tree_depth"] = json!(coords.depth());
        }

        // Add link stats
        let stats = peer.link_stats();
        peer_json["stats"] = json!({
            "packets_sent": stats.packets_sent,
            "packets_recv": stats.packets_recv,
            "bytes_sent": stats.bytes_sent,
            "bytes_recv": stats.bytes_recv,
        });

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
            peer_json["mmp"] = mmp_json;
        }

        peer_json
    }).collect();

    json!({ "peers": peers })
}

/// `show_links` — Active links.
pub fn show_links(node: &Node) -> Value {
    let links: Vec<Value> = node.links().map(|link| {
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
    }).collect();

    json!({ "links": links })
}

/// `show_tree` — Spanning tree state.
pub fn show_tree(node: &Node) -> Value {
    let tree = node.tree_state();
    let my_coords = tree.my_coords();
    let decl = tree.my_declaration();

    // Build coords array as hex strings
    let coords: Vec<String> = my_coords.entries()
        .iter()
        .map(|e| hex::encode(e.node_addr.as_bytes()))
        .collect();

    // Build peer tree data
    let peers: Vec<Value> = tree.peer_ids().map(|peer_id| {
        let mut peer_json = json!({
            "node_addr": hex::encode(peer_id.as_bytes()),
            "display_name": node.peer_display_name(peer_id),
        });
        if let Some(coords) = tree.peer_coords(peer_id) {
            let coord_path: Vec<String> = coords.entries()
                .iter()
                .map(|e| hex::encode(e.node_addr.as_bytes()))
                .collect();
            peer_json["depth"] = json!(coords.depth());
            peer_json["root"] = json!(hex::encode(coords.root_id().as_bytes()));
            peer_json["coords"] = json!(coord_path);
            peer_json["distance_to_us"] = json!(my_coords.distance_to(coords));
        }
        peer_json
    }).collect();

    // Determine parent display name
    let parent_addr = my_coords.parent_id();
    let parent_hex = hex::encode(parent_addr.as_bytes());
    let parent_display = node.peer_display_name(parent_addr);

    let tree_stats = node.stats().snapshot().tree;

    json!({
        "my_node_addr": hex::encode(tree.my_node_addr().as_bytes()),
        "root": hex::encode(tree.root().as_bytes()),
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

/// `show_sessions` — End-to-end sessions.
pub fn show_sessions(node: &Node) -> Value {
    let sessions: Vec<Value> = node.session_entries().map(|(addr, entry)| {
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

        // Add session MMP if available
        if let Some(mmp) = entry.mmp() {
            let mut mmp_json = json!({
                "mode": format!("{}", mmp.mode()),
            });
            if let Some(srtt) = mmp.metrics.srtt_ms() {
                mmp_json["srtt_ms"] = json!(srtt);
            }
            mmp_json["path_mtu"] = json!(mmp.path_mtu.current_mtu());
            session_json["mmp"] = mmp_json;
        }

        session_json
    }).collect();

    json!({ "sessions": sessions })
}

/// `show_bloom` — Bloom filter state.
pub fn show_bloom(node: &Node) -> Value {
    let bloom = node.bloom_state();

    let leaf_deps: Vec<String> = bloom.leaf_dependents()
        .iter()
        .map(|addr| hex::encode(addr.as_bytes()))
        .collect();

    // Build per-peer filter info
    let peer_filters: Vec<Value> = node.peers().map(|peer| {
        let addr = *peer.node_addr();
        let mut pf = json!({
            "peer": hex::encode(addr.as_bytes()),
            "display_name": node.peer_display_name(&addr),
            "has_filter": peer.filter_sequence() > 0,
            "filter_sequence": peer.filter_sequence(),
        });
        if let Some(filter) = peer.inbound_filter() {
            pf["estimated_count"] = json!(filter.estimated_count());
            pf["set_bits"] = json!(filter.count_ones());
            pf["fill_ratio"] = json!(filter.fill_ratio());
        }
        pf
    }).collect();

    let bloom_stats = node.stats().snapshot().bloom;

    json!({
        "own_node_addr": hex::encode(node.node_addr().as_bytes()),
        "is_leaf_only": node.is_leaf_only(),
        "sequence": bloom.sequence(),
        "leaf_dependent_count": bloom.leaf_dependents().len(),
        "leaf_dependents": leaf_deps,
        "peer_filters": peer_filters,
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

        if let Some(srtt) = metrics.srtt_ms() {
            link_layer["srtt_ms"] = json!(srtt);
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

        Some(json!({
            "peer": hex::encode(addr.as_bytes()),
            "display_name": node.peer_display_name(&addr),
            "mode": format!("{}", mmp.mode()),
            "link_layer": link_layer,
        }))
    }).collect();

    // Session-layer MMP
    let sessions: Vec<Value> = node.session_entries().filter_map(|(addr, entry)| {
        let mmp = entry.mmp()?;
        let metrics = &mmp.metrics;

        let mut session_layer = json!({
            "loss_rate": metrics.loss_rate(),
            "etx": metrics.etx,
            "path_mtu": mmp.path_mtu.current_mtu(),
        });

        if let Some(srtt) = metrics.srtt_ms() {
            session_layer["srtt_ms"] = json!(srtt);
        }

        Some(json!({
            "remote": hex::encode(addr.as_bytes()),
            "display_name": node.peer_display_name(addr),
            "mode": format!("{}", mmp.mode()),
            "session_layer": session_layer,
        }))
    }).collect();

    json!({
        "peers": peers,
        "sessions": sessions,
    })
}

/// `show_cache` — Coordinate cache stats.
pub fn show_cache(node: &Node) -> Value {
    let cache = node.coord_cache();
    let stats = cache.stats(now_ms());

    json!({
        "entries": stats.entries,
        "max_entries": stats.max_entries,
        "fill_ratio": stats.fill_ratio(),
        "default_ttl_ms": cache.default_ttl_ms(),
        "expired": stats.expired,
        "avg_age_ms": stats.avg_age_ms,
    })
}

/// `show_connections` — Pending handshakes.
pub fn show_connections(node: &Node) -> Value {
    let now = now_ms();
    let connections: Vec<Value> = node.connections().map(|conn| {
        let mut conn_json = json!({
            "link_id": conn.link_id().as_u64(),
            "direction": format!("{}", conn.direction()),
            "handshake_state": format!("{}", conn.handshake_state()),
            "started_at_ms": conn.started_at(),
            "idle_ms": now.saturating_sub(conn.last_activity()),
            "resend_count": conn.resend_count(),
        });

        if let Some(identity) = conn.expected_identity() {
            conn_json["expected_peer"] = json!(identity.npub());
        }

        conn_json
    }).collect();

    json!({ "connections": connections })
}

/// `show_transports` — Transport instances.
pub fn show_transports(node: &Node) -> Value {
    let transports: Vec<Value> = node.transport_ids().map(|id| {
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

        t_json["stats"] = handle.transport_stats();

        t_json
    }).collect();

    json!({ "transports": transports })
}

/// `show_routing` — Routing table summary and node statistics.
pub fn show_routing(node: &Node) -> Value {
    let cache = node.coord_cache();
    let cache_stats = cache.stats(now_ms());
    let node_stats = node.stats().snapshot();

    json!({
        "coord_cache_entries": cache_stats.entries,
        "identity_cache_entries": node.identity_cache_len(),
        "pending_lookups": node.pending_lookup_count(),
        "recent_requests": node.recent_request_count(),
        "forwarding": serde_json::to_value(&node_stats.forwarding).unwrap_or_default(),
        "discovery": serde_json::to_value(&node_stats.discovery).unwrap_or_default(),
        "error_signals": serde_json::to_value(&node_stats.errors).unwrap_or_default(),
    })
}

/// Dispatch a command string to the appropriate query function.
pub fn dispatch(node: &Node, command: &str) -> super::protocol::Response {
    match command {
        "show_status" => super::protocol::Response::ok(show_status(node)),
        "show_peers" => super::protocol::Response::ok(show_peers(node)),
        "show_links" => super::protocol::Response::ok(show_links(node)),
        "show_tree" => super::protocol::Response::ok(show_tree(node)),
        "show_sessions" => super::protocol::Response::ok(show_sessions(node)),
        "show_bloom" => super::protocol::Response::ok(show_bloom(node)),
        "show_mmp" => super::protocol::Response::ok(show_mmp(node)),
        "show_cache" => super::protocol::Response::ok(show_cache(node)),
        "show_connections" => super::protocol::Response::ok(show_connections(node)),
        "show_transports" => super::protocol::Response::ok(show_transports(node)),
        "show_routing" => super::protocol::Response::ok(show_routing(node)),
        _ => super::protocol::Response::error(format!("unknown command: {}", command)),
    }
}
