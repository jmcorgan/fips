//! How a client merges the IPv6 adapter's `show_status` keys into the
//! node's reply, and when it asks the adapter at all.

use super::*;
use serde_json::json;

#[test]
fn an_adapter_answer_fills_the_keys_the_node_leaves_out() {
    let mut data = json!({"npub": "npub1node"});
    let adapter = json!({"tun_state": "active", "tun_name": "fips0", "effective_ipv6_mtu": 1323});
    compose("show_status", &mut data, Some(&adapter));
    assert_eq!(
        data,
        json!({
            "npub": "npub1node",
            "tun_state": "active",
            "tun_name": "fips0",
            "effective_ipv6_mtu": 1323,
        })
    );
}

#[test]
fn a_key_the_node_answers_keeps_the_node_value() {
    let mut data = json!({"tun_state": "disabled", "tun_name": "-", "effective_ipv6_mtu": 1203});
    let adapter = json!({"tun_state": "active", "tun_name": "fips0", "effective_ipv6_mtu": 1323});
    compose("show_status", &mut data, Some(&adapter));
    assert_eq!(
        data,
        json!({"tun_state": "disabled", "tun_name": "-", "effective_ipv6_mtu": 1203})
    );
}

#[test]
fn without_either_the_keys_take_the_fallback_disabled_dash_and_zero() {
    let mut data = json!({"npub": "npub1node"});
    compose("show_status", &mut data, None);
    assert_eq!(
        data,
        json!({
            "npub": "npub1node",
            "tun_state": "disabled",
            "tun_name": "-",
            "effective_ipv6_mtu": 0,
        })
    );
}

#[test]
fn keys_the_adapter_adds_beyond_its_three_are_not_shown() {
    let mut data = json!({});
    let adapter = json!({
        "tun_state": "active",
        "tun_name": "fips0",
        "effective_ipv6_mtu": 1323,
        "host_drops": 7,
    });
    compose("show_status", &mut data, Some(&adapter));
    assert!(data.get("host_drops").is_none());
}

#[test]
fn a_command_the_adapter_has_no_part_in_is_left_as_the_node_gave_it() {
    let mut data = json!({"peers": []});
    compose(
        "show_peers",
        &mut data,
        Some(&json!({"tun_state": "active"})),
    );
    assert_eq!(data, json!({"peers": []}));
}

#[test]
fn the_adapter_is_asked_for_show_status_only_when_the_node_left_a_key_out() {
    let all = json!({"tun_state": "disabled", "tun_name": "-", "effective_ipv6_mtu": 1203});
    assert!(!composes("show_peers", &json!({})));
    assert!(!composes("show_status", &all));
    for key in ["tun_state", "tun_name", "effective_ipv6_mtu"] {
        let mut data = all.clone();
        data.as_object_mut().unwrap().remove(key);
        assert!(composes("show_status", &data), "{key} left out");
    }
}
