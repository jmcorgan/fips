//! Control query implementations.
//!
//! Each function takes `&Node` and returns a `serde_json::Value`.
//! Query logic is kept separate from socket handling.

use crate::identity::encode_npub;
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
    let pid = std::process::id();
    let exe_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "-".into());
    let uptime_secs = node.uptime().as_secs();
    let fwd = node.stats().snapshot().forwarding;

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
        "forwarding": serde_json::to_value(&fwd).unwrap_or_default(),
    })
}

/// `show_peers` — Authenticated peers.
pub fn show_peers(node: &Node) -> Value {
    let tree = node.tree_state();
    let my_addr = *tree.my_node_addr();
    let parent_id = *tree.my_declaration().parent_id();
    let is_root = tree.is_root();

    let peers: Vec<Value> = node.peers().map(|peer| {
        let node_addr = *peer.node_addr();
        let addr_hex = hex::encode(node_addr.as_bytes());

        // Determine tree relationship
        let is_parent = !is_root && node_addr == parent_id;
        let is_child = tree.peer_declaration(&node_addr)
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
    let sessions: Vec<Value> = node.session_entries().filter_map(|(addr, entry)| {
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

/// `show_cache` — Coordinate cache stats and entries.
pub fn show_cache(node: &Node) -> Value {
    let cache = node.coord_cache();
    let now = now_ms();
    let stats = cache.stats(now);

    // Include individual entries for route debugging
    let entries: Vec<Value> = cache.iter(now).map(|(addr, entry)| {
        let fips_addr = crate::identity::FipsAddress::from_node_addr(addr);
        let coord_path: Vec<String> = entry.coords().entries()
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
    }).collect();

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

        // Tor-specific fields
        if let Some(mode) = handle.tor_mode() {
            t_json["tor_mode"] = json!(mode);
        }
        if let Some(onion) = handle.onion_address() {
            t_json["onion_address"] = json!(onion);
        }
        if let Some(monitoring) = handle.tor_monitoring() {
            t_json["tor_monitoring"] =
                serde_json::to_value(&monitoring).unwrap_or_default();
        }

        t_json["stats"] = handle.transport_stats();

        t_json
    }).collect();

    json!({ "transports": transports })
}

/// `show_routing` — Routing table summary and node statistics.
pub fn show_routing(node: &Node) -> Value {
    let cache = node.coord_cache();
    let now = now_ms();
    let cache_stats = cache.stats(now);
    let node_stats = node.stats().snapshot();

    // Pending discovery lookups (individual targets)
    let lookups: Vec<Value> = node.pending_lookups_iter().map(|(addr, lookup)| {
        json!({
            "target": hex::encode(addr.as_bytes()),
            "display_name": node.peer_display_name(addr),
            "initiated_ms": lookup.initiated_ms,
            "last_sent_ms": lookup.last_sent_ms,
            "attempt": lookup.attempt,
            "age_ms": now.saturating_sub(lookup.initiated_ms),
        })
    }).collect();

    // Connection retry state
    let retries: Vec<Value> = node.retry_state_iter().map(|(addr, state)| {
        json!({
            "node_addr": hex::encode(addr.as_bytes()),
            "display_name": node.peer_display_name(addr),
            "retry_count": state.retry_count,
            "retry_after_ms": state.retry_after_ms,
            "auto_reconnect": state.reconnect,
        })
    }).collect();

    json!({
        "coord_cache_entries": cache_stats.entries,
        "identity_cache_entries": node.identity_cache_len(),
        "pending_lookups": lookups,
        "pending_tun_destinations": node.pending_tun_destinations(),
        "pending_tun_packets": node.pending_tun_total_packets(),
        "recent_requests": node.recent_request_count(),
        "retries": retries,
        "forwarding": serde_json::to_value(&node_stats.forwarding).unwrap_or_default(),
        "discovery": serde_json::to_value(&node_stats.discovery).unwrap_or_default(),
        "error_signals": serde_json::to_value(&node_stats.errors).unwrap_or_default(),
        "congestion": serde_json::to_value(&node_stats.congestion).unwrap_or_default(),
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
    let entries: Vec<Value> = node.identity_cache_iter().map(|(node_addr, pubkey, last_seen_ms)| {
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
    }).collect();

    json!({
        "entries": entries,
        "count": entries.len(),
        "max_entries": node.identity_cache_max(),
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
        "show_identity_cache" => super::protocol::Response::ok(show_identity_cache(node)),
        _ => super::protocol::Response::error(format!("unknown command: {}", command)),
    }
}
