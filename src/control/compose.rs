//! Merge the IPv6 adapter's answer into the node's, as `fipsctl` and
//! `fipstop` show it.
//!
//! The adapter answers its keys of `show_status` on a socket of its own
//! (see [`crate::ipv6tun::status`]). A client asks that socket only when the
//! node's reply leaves one of those keys out ([`composes`]), and merges the
//! two replies with [`compose`]. A key the node answers keeps the node's
//! value, so against a daemon whose node still answers every key the output
//! is the node's alone. JSON objects here keep their keys sorted, so where a
//! key came from does not change the printed bytes.

use serde_json::Value;

/// The only command whose reply the adapter has a part in.
const COMMAND: &str = "show_status";

/// The keys of `show_status` the adapter answers, each with the value shown
/// when neither the node nor the adapter answers it: no TUN, and an MTU of 0.
fn adapter_keys() -> [(&'static str, Value); 3] {
    [
        ("tun_state", Value::from("disabled")),
        ("tun_name", Value::from("-")),
        ("effective_ipv6_mtu", Value::from(0)),
    ]
}

/// Whether a client should also ask the adapter's socket, given the node's
/// `data` for `command`: only for `show_status` when the node left out one of
/// the adapter's keys.
pub fn composes(command: &str, node: &Value) -> bool {
    command == COMMAND
        && node.as_object().is_some_and(|data| {
            adapter_keys()
                .iter()
                .any(|(key, _)| !data.contains_key(*key))
        })
}

/// Merge the adapter's `data` for `command` into the node's `data`.
///
/// `adapter` is `None` when the adapter's socket did not answer. Each of the
/// adapter's keys keeps the node's value when the node gave one; otherwise it
/// takes the adapter's value when the adapter answered that key, and the
/// fallback when neither did. Keys the adapter adds beyond these are left
/// out, so what a client shows stays what it was. A command the adapter has
/// no part in is left as the node gave it.
pub fn compose(command: &str, node: &mut Value, adapter: Option<&Value>) {
    if command != COMMAND {
        return;
    }
    let Some(node) = node.as_object_mut() else {
        return;
    };
    for (key, fallback) in adapter_keys() {
        let answered = adapter.and_then(|a| a.get(key));
        node.entry(key)
            .or_insert_with(|| answered.cloned().unwrap_or(fallback));
    }
}

#[cfg(test)]
#[path = "tests/compose.rs"]
mod tests;
