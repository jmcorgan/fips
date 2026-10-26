//! The scope warning keeps the log target it had before the module moved
//! into the IPv6 adapter.

use super::*;
use crate::testutil::capture_logs_scoped;
use serde_json::json;

/// A table whose inbound chain opens with `iifname != "fips0" return`.
fn fips0_table() -> FilterClassifier {
    FilterClassifier::from_nft_json(&json!({"nftables": [
        {"table": {"family": "inet", "name": "fips", "handle": 1}},
        {"chain": {"family": "inet", "table": "fips", "name": "inbound", "handle": 1,
            "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
        {"rule": {"family": "inet", "table": "fips", "chain": "inbound", "handle": 2, "expr": [
            {"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "fips0"}},
            {"return": null}
        ]}}
    ]}))
}

#[test]
fn the_scope_warning_is_logged_under_the_control_module_target_it_had_before_the_move() {
    let (logs, _guard) = capture_logs_scoped();
    warn_scope(&fips0_table(), "mesh0");
    assert_eq!(
        logs.targets(
            "The inet fips firewall polices fips0, not the TUN mesh0: listeners on mesh0 \
             are reachable from the mesh. Set fips_if in /etc/fips/fips.nft to the tun.name \
             and reload the firewall"
        ),
        vec!["fips::control::firewall_state"],
    );
}

#[test]
fn a_table_that_polices_the_tun_draws_no_scope_warning() {
    let (logs, _guard) = capture_logs_scoped();
    warn_scope(&fips0_table(), "fips0");
    assert!(logs.lines().is_empty(), "{:?}", logs.lines());
}
