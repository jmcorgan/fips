//! What `fipsctl` and `fipstop` show for `show_status` now that the IPv6
//! adapter answers its own keys: the node's reply with the adapter's merged
//! in is the reply the node alone gave before, byte for byte, and without
//! the adapter the keys carry the fallback values. The node's control socket
//! answers none of the adapter's keys, and no longer answers
//! `show_listening_sockets`.

use super::tests::{assert_snapshot, build_test_node, render};
use super::*;
use crate::control::compose;
use crate::control::protocol::Request;
use crate::control::read_handle::snapshot_dispatch;
use crate::ipv6tun::status::render_status;

/// The test node's `show_status` with the adapter's reply merged in, as a
/// client prints it.
fn composed(adapter: Option<&Value>) -> String {
    let node = build_test_node();
    let mut data = show_status(&node);
    compose("show_status", &mut data, adapter);
    render(data)
}

#[test]
fn the_node_status_with_the_adapter_reply_merged_in_is_the_status_the_node_alone_gave() {
    let node = build_test_node();
    let adapter = render_status(&node.ipv6tun_status());
    // The fixture is a byte copy of the node's `show_status` fixture from
    // before the adapter answered its own keys.
    assert_snapshot("show_status_composed", &composed(Some(&adapter)));
}

#[test]
fn a_fixed_adapter_reply_merges_into_the_status_the_node_alone_gave() {
    let adapter = json!({
        "tun_state": "disabled",
        "tun_name": "-",
        "effective_ipv6_mtu": 1203,
        "host_drops": 0,
    });
    assert_snapshot("show_status_composed", &composed(Some(&adapter)));
}

#[test]
fn without_the_adapter_the_status_shows_no_tun_and_an_mtu_of_zero() {
    assert_snapshot("show_status_fallback", &composed(None));
}

#[test]
fn the_node_status_alone_carries_none_of_the_adapter_keys() {
    let mut node = build_test_node();
    node.record_stats_history();
    let handle = node.control_read_handle();
    for data in [show_status(&node), show_status_from_handle(&handle)] {
        for key in ["tun_state", "tun_name", "effective_ipv6_mtu", "host_drops"] {
            assert!(data.get(key).is_none(), "{key} is the adapter's to answer");
        }
    }
}

#[tokio::test]
async fn the_node_socket_answers_show_listening_sockets_as_an_unknown_command() {
    let mut node = build_test_node();
    node.record_stats_history();
    let request = Request {
        command: "show_listening_sockets".to_string(),
        params: None,
    };
    let handle = node.control_read_handle();
    assert!(
        snapshot_dispatch(&request, &handle).is_none(),
        "the read handle no longer serves the panel"
    );
    let reply = crate::control::commands::dispatch(&mut node, &request.command, None).await;
    assert_eq!(reply.status, "error");
    assert_eq!(
        reply.message.as_deref(),
        Some("unknown command: show_listening_sockets")
    );
}
