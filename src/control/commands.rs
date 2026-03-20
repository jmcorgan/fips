//! Mutating control socket commands.
//!
//! Commands that modify node state (connect, disconnect) are handled here,
//! separate from read-only queries in `queries.rs`.

use super::protocol::Response;
use crate::node::Node;
use serde_json::Value;
use tracing::info;

/// Dispatch a mutating command to the appropriate handler.
pub async fn dispatch(node: &mut Node, command: &str, params: Option<&Value>) -> Response {
    match command {
        "connect" => connect(node, params).await,
        "disconnect" => disconnect(node, params),
        _ => Response::error(format!("unknown command: {command}")),
    }
}

/// Connect to a peer.
///
/// Params: `{"npub": "npub1...", "address": "host:port", "transport": "udp"}`
async fn connect(node: &mut Node, params: Option<&Value>) -> Response {
    let Some(params) = params else {
        return Response::error("missing params for connect");
    };

    let npub = match params.get("npub").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return Response::error("missing 'npub' parameter"),
    };
    let address = match params.get("address").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return Response::error("missing 'address' parameter"),
    };
    let transport = match params.get("transport").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return Response::error("missing 'transport' parameter"),
    };

    info!(npub = %npub, address = %address, transport = %transport, "API connect requested");

    match node.api_connect(npub, address, transport).await {
        Ok(data) => Response::ok(data),
        Err(msg) => Response::error(msg),
    }
}

/// Disconnect a peer.
///
/// Params: `{"npub": "npub1..."}`
fn disconnect(node: &mut Node, params: Option<&Value>) -> Response {
    let Some(params) = params else {
        return Response::error("missing params for disconnect");
    };

    let npub = match params.get("npub").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return Response::error("missing 'npub' parameter"),
    };

    info!(npub = %npub, "API disconnect requested");

    match node.api_disconnect(npub) {
        Ok(data) => Response::ok(data),
        Err(msg) => Response::error(msg),
    }
}
