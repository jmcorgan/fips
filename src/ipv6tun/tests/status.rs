//! The listening-sockets panel's reply: a loaded table that polices another
//! interface reports no firewall, and one that polices the TUN classifies
//! each listener by its rules. And the adapter's status: what its TUN and
//! DNS starts and stops publish, the drop count read live, and what its
//! status socket answers.

use super::*;
use crate::ipv6tun::config::DnsConfig;
use crate::ipv6tun::lifecycle::Handles;
use crate::ipv6tun::link::{DatagramRx, Feeds, HostLink, LearnedRx, pair};
use crate::ipv6tun::queue::TunTx;
use serde_json::json;

/// `nft -j list table inet fips` output for the shipped
/// `packaging/common/fips.nft` (drop-in include removed), captured
/// from nft 1.0.9 with the table loaded in a scratch network
/// namespace. Its inbound chain opens with `iifname != "fips0" return`.
fn stock_fips_nft_json() -> Value {
    json!({"nftables": [
        {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
        {"table": {"family": "inet", "name": "fips", "handle": 1}},
        {"chain": {"family": "inet", "table": "fips", "name": "inbound", "handle": 1,
            "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
        {"rule": {"family": "inet", "table": "fips", "chain": "inbound", "handle": 2, "expr": [
            {"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "fips0"}},
            {"return": null}
        ]}},
        {"rule": {"family": "inet", "table": "fips", "chain": "inbound", "handle": 3, "expr": [
            {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}},
            {"accept": null}
        ]}},
        {"rule": {"family": "inet", "table": "fips", "chain": "inbound", "handle": 4, "expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": "icmpv6", "field": "type"}}, "right": "echo-request"}},
            {"accept": null}
        ]}},
        {"rule": {"family": "inet", "table": "fips", "chain": "inbound", "handle": 5, "expr": [
            {"counter": {"packets": 0, "bytes": 0}},
            {"drop": null}
        ]}}
    ]})
}

/// Two wildcard listeners with no drop-in allow rule: one TCP, one UDP.
fn two_wildcard_listeners() -> Vec<super::super::listening::ListeningSocket> {
    use super::super::listening::{ListeningSocket, Proto};
    vec![
        ListeningSocket {
            proto: Proto::Tcp,
            local_addr: std::net::Ipv6Addr::UNSPECIFIED,
            port: 22,
            pid: Some(100),
            process: Some("sshd".into()),
            wildcard_bind: true,
        },
        ListeningSocket {
            proto: Proto::Udp,
            local_addr: std::net::Ipv6Addr::UNSPECIFIED,
            port: 5353,
            pid: Some(200),
            process: Some("avahi-daemon".into()),
            wildcard_bind: true,
        },
    ]
}

/// The mesh address the fixtures report as `fips0_addr`.
fn fixture_fips0_addr() -> std::net::Ipv6Addr {
    "fd97::1".parse().unwrap()
}

#[test]
fn listening_sockets_report_no_firewall_when_the_table_polices_another_interface() {
    let classifier = FilterClassifier::from_nft_json(&stock_fips_nft_json());
    let sockets = two_wildcard_listeners();
    let out = render(&classifier, "mesh0", fixture_fips0_addr(), &sockets);

    let rows = out["sockets"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "both fixture listeners must be rendered");
    assert_eq!(
        out["firewall_active"],
        json!(false),
        "a table scoped to fips0 does not police TUN mesh0, so the report \
         must not claim an active firewall; got {out}"
    );
    for row in rows {
        assert_eq!(
            row["filter"],
            json!("no_firewall"),
            "a listener reachable on unpoliced mesh0 must be reported as \
             unfiltered; got {row}"
        );
    }
}

#[test]
fn listening_sockets_report_filtered_rows_when_the_table_polices_the_tun() {
    let classifier = FilterClassifier::from_nft_json(&stock_fips_nft_json());
    let sockets = two_wildcard_listeners();
    let out = render(&classifier, "fips0", fixture_fips0_addr(), &sockets);

    let rows = out["sockets"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(out["firewall_active"], json!(true));
    for row in rows {
        assert_eq!(row["filter"], json!("drop"), "row {row}");
    }
}

/// Handles for a node with the TUN enabled, attached over a fresh link so
/// that the DNS responder can start, with the node's ends of the link.
fn attached() -> (Handles, HostLink, DatagramRx, LearnedRx) {
    let mut handles = Handles::new(fixture_fips0_addr(), true);
    let (mesh, host, datagrams, learned) = pair(8, 8);
    let feeds = Feeds {
        path_mtu: true,
        identity: true,
    };
    handles.attached(mesh, feeds);
    (handles, host, datagrams, learned)
}

/// A DNS responder on the IPv6 loopback at a port the kernel picks.
fn loopback_dns() -> DnsConfig {
    DnsConfig {
        bind_addr: Some("::1".to_string()),
        port: Some(0),
        ..Default::default()
    }
}

/// Install an embedder's TUN channels on `handles`, returning the ends the
/// embedder keeps.
fn install_app_tun(
    handles: &mut Handles,
    capacity: usize,
) -> (
    std::sync::mpsc::Receiver<Vec<u8>>,
    tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    let (tun_tx, host_rx) = TunTx::bounded(capacity);
    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(capacity);
    handles.install_app_tun(tun_tx, outbound_rx);
    (host_rx, outbound_tx)
}

/// Assert that the published status shows what the node's facades read
/// from `handles` after `step`.
fn assert_published(handles: &Handles, step: &str) {
    let read = handles.status().read();
    assert_eq!(
        read.tun_state,
        handles.tun_state(),
        "tun_state after {step}"
    );
    assert_eq!(read.tun_name, handles.tun_name, "tun_name after {step}");
    assert_eq!(
        read.dns_local_addr, handles.dns_local_addr,
        "dns_local_addr after {step}"
    );
}

#[tokio::test]
async fn the_published_status_follows_each_tun_and_dns_change() {
    // A DNS responder that the node retracts after it exited on its own.
    let (mut handles, _host, _datagrams, _learned) = attached();
    assert_published(&handles, "the start");
    let _tun = install_app_tun(&mut handles, 4);
    assert_eq!(handles.status().read().tun_state, TunState::Active);
    assert_published(&handles, "install_app_tun");
    assert!(handles.start_dns(&loopback_dns(), &[], None));
    assert!(handles.status().read().dns_local_addr.is_some());
    assert_published(&handles, "start_dns");
    handles.retract_dns();
    assert_published(&handles, "retract_dns");
    handles.stop_dns();

    // A DNS responder stopped with no retract first.
    let (mut handles, _host, _datagrams, _learned) = attached();
    assert!(handles.start_dns(&loopback_dns(), &[], None));
    assert!(handles.status().read().dns_local_addr.is_some());
    assert_published(&handles, "start_dns");
    handles.stop_dns();
    assert_published(&handles, "stop_dns");
}

#[test]
fn the_status_reads_the_drop_count_of_the_current_queue_live() {
    let mut handles = Handles::new(fixture_fips0_addr(), true);
    let _tun = install_app_tun(&mut handles, 1);
    let source = handles.status();
    assert_eq!(source.read().host_drops, 0);
    let tun_tx = handles.tun_tx.as_ref().unwrap();
    tun_tx.send(vec![0x60]).unwrap();
    tun_tx.send(vec![0x60]).unwrap();
    assert_eq!(
        source.read().host_drops,
        1,
        "the second packet found no room"
    );
}

/// A responder over unattached handles with the TUN disabled.
fn disabled_responder() -> Responder {
    let handles = Handles::new(fixture_fips0_addr(), false);
    Responder {
        source: handles.status(),
        fips0: fixture_fips0_addr(),
        configured: "fips0".to_string(),
    }
}

/// A request for `command` with no parameters.
fn request(command: &str) -> Request {
    Request {
        command: command.to_string(),
        params: None,
    }
}

#[test]
fn the_adapter_answers_show_status_with_its_four_keys() {
    let response = disabled_responder().answer(&request("show_status"));
    assert_eq!(response.status, "ok");
    assert_eq!(
        response.data,
        Some(json!({
            "tun_state": "disabled",
            "tun_name": "-",
            "effective_ipv6_mtu": 1203,
            "host_drops": 0,
        }))
    );
}

#[test]
fn an_unknown_command_is_answered_unknown_command() {
    let response = disabled_responder().answer(&request("show_peers"));
    assert_eq!(response.status, "error");
    assert_eq!(
        response.message.as_deref(),
        Some("unknown command: show_peers")
    );
}

#[test]
fn the_panel_reads_the_configured_tun_while_none_is_up() {
    assert_eq!(disabled_responder().panel_tun(), "fips0");
}

#[test]
fn a_named_tun_is_rendered_by_its_name() {
    let mut status = Ipv6TunStatus {
        tun_state: TunState::Active,
        tun_name: Some("fips0".into()),
        effective_ipv6_mtu: 1323,
        dns_local_addr: None,
        host_drops: 0,
    };
    assert_eq!(render_status(&status)["tun_name"], "fips0");
    status.tun_name = None;
    assert_eq!(render_status(&status)["tun_name"], "-");
}

#[cfg(windows)]
#[tokio::test]
async fn the_status_listener_binds_on_loopback() {
    let listener = Listener::bind(PathBuf::from("0")).unwrap();
    let addr = listener.inner.local_addr().unwrap();
    assert!(addr.ip().is_loopback(), "bound at {addr}");
}
