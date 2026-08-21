//! Mutating control socket commands.
//!
//! Commands that modify node state (connect, disconnect) are handled here,
//! separate from read-only queries in `queries.rs`.

use super::protocol::Response;
use crate::node::Node;
use serde_json::Value;
use tracing::debug;

/// Dispatch a mutating command to the appropriate handler.
pub async fn dispatch(node: &mut Node, command: &str, params: Option<&Value>) -> Response {
    match command {
        "connect" => connect(node, params).await,
        "disconnect" => disconnect(node, params).await,
        "probe_start" => probe_start(node, params).await,
        "probe_poll" => probe_poll(node, params),
        "probe_cancel" => probe_cancel(node, params).await,
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

    debug!(npub = %npub, address = %address, transport = %transport, "API connect requested");

    match node.api_connect(npub, address, transport).await {
        Ok(data) => Response::ok(data),
        Err(msg) => Response::error(msg),
    }
}

/// Disconnect a peer.
///
/// Params: `{"npub": "npub1..."}`
async fn disconnect(node: &mut Node, params: Option<&Value>) -> Response {
    let Some(params) = params else {
        return Response::error("missing params for disconnect");
    };

    let npub = match params.get("npub").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return Response::error("missing 'npub' parameter"),
    };

    debug!(npub = %npub, "API disconnect requested");

    match node.api_disconnect(npub).await {
        Ok(data) => Response::ok(data),
        Err(msg) => Response::error(msg),
    }
}

/// Start a diagnostic probe. Returns as soon as the job is admitted; the
/// stages run on the tick and the client polls for the report.
///
/// Params: `{"npub": "npub1..."}`
async fn probe_start(node: &mut Node, params: Option<&Value>) -> Response {
    let Some(params) = params else {
        return Response::error("missing params for probe_start");
    };

    let npub = match params.get("npub").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return Response::error("missing 'npub' parameter"),
    };

    debug!(npub = %npub, "API probe requested");

    match node.api_probe_start(npub).await {
        Ok(data) => Response::ok(data),
        Err(msg) => Response::error(msg),
    }
}

/// Read a probe's progress.
///
/// Params: `{"probe_id": 7}`
fn probe_poll(node: &mut Node, params: Option<&Value>) -> Response {
    let Some(id) = probe_id(params) else {
        return Response::error("missing 'probe_id' parameter");
    };

    match node.api_probe_poll(id) {
        Ok(data) => Response::ok(data),
        Err(msg) => Response::error(msg),
    }
}

/// Cancel a probe.
///
/// Params: `{"probe_id": 7}`
async fn probe_cancel(node: &mut Node, params: Option<&Value>) -> Response {
    let Some(id) = probe_id(params) else {
        return Response::error("missing 'probe_id' parameter");
    };

    match node.api_probe_cancel(id).await {
        Ok(data) => Response::ok(data),
        Err(msg) => Response::error(msg),
    }
}

fn probe_id(params: Option<&Value>) -> Option<u64> {
    params?.get("probe_id").and_then(|v| v.as_u64())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use serde_json::json;

    fn test_node() -> Node {
        Node::new(Config::new()).expect("default config is valid")
    }

    /// A known-good npub that is not this node's own.
    const OTHER_NPUB: &str = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";

    #[tokio::test]
    async fn probe_poll_unknown_id_errors() {
        let mut node = test_node();
        let resp = dispatch(&mut node, "probe_poll", Some(&json!({"probe_id": 999}))).await;
        assert_eq!(resp.status, "error");
    }

    #[tokio::test]
    async fn probe_start_rejects_bad_npub() {
        let mut node = test_node();
        let resp = dispatch(
            &mut node,
            "probe_start",
            Some(&json!({"npub": "npub1nonsense"})),
        )
        .await;
        assert_eq!(resp.status, "error");
        assert!(
            resp.message
                .as_deref()
                .is_some_and(|m| m.contains("invalid peer npub")),
            "message was {:?}",
            resp.message
        );
    }

    #[tokio::test]
    async fn probe_start_missing_npub_errors() {
        let mut node = test_node();
        let resp = dispatch(&mut node, "probe_start", Some(&json!({}))).await;
        assert_eq!(resp.status, "error");
    }

    #[tokio::test]
    async fn probe_start_rejects_self() {
        // The most natural first thing a user tries. Unguarded it produces an
        // uninterpretable result, since routing returns no next hop for the
        // local address.
        let mut node = test_node();
        let own = node.identity().npub();
        let resp = dispatch(&mut node, "probe_start", Some(&json!({"npub": own}))).await;
        assert_eq!(resp.status, "error");
        assert_eq!(resp.message.as_deref(), Some("cannot probe this node"));
    }

    #[tokio::test]
    async fn probe_start_admits_a_valid_target() {
        let mut node = test_node();
        let resp = dispatch(&mut node, "probe_start", Some(&json!({"npub": OTHER_NPUB}))).await;
        assert_eq!(resp.status, "ok", "message: {:?}", resp.message);
        let data = resp.data.expect("probe_start returns data");
        assert_eq!(data["probe_id"], 1);
        assert!(data["budget_ms"].as_u64().is_some_and(|b| b > 0));
    }

    #[tokio::test]
    async fn probe_cancel_missing_id_errors() {
        let mut node = test_node();
        let resp = dispatch(&mut node, "probe_cancel", None).await;
        assert_eq!(resp.status, "error");
    }
}
