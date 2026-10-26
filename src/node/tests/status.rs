//! The IPv6 adapter's status socket, through real sockets: it sits beside
//! the control socket it is derived from, so nodes with different control
//! sockets each show their own adapter's TUN keys in the status a client
//! composes; it is bound only while the control socket is; and the MTU a
//! client shows follows the bound transports within the first tick. Also
//! what the adapter publishes when its TUN fails to open.

use super::*;
use crate::config::{TransportInstances, UdpConfig, ipv6tun_socket};
use crate::control::{compose, composes};
use serde_json::Value;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Ask the socket at `path` for `command` as `fipsctl` does, returning the
/// reply's data, or `None` when nothing answers there or the reply is an
/// error.
async fn ask(path: &Path, command: &str) -> Option<Value> {
    let mut stream = tokio::net::UnixStream::connect(path).await.ok()?;
    let line = format!("{{\"command\":\"{command}\"}}\n");
    stream.write_all(line.as_bytes()).await.ok()?;
    stream.shutdown().await.ok()?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply).await.ok()?;
    let reply: Value = serde_json::from_str(reply.trim()).ok()?;
    (reply["status"] == "ok").then(|| reply["data"].clone())
}

/// `show_status` as a client given `-s control` shows it: the node's reply,
/// with the reply of the adapter beside `control` merged in when the node
/// left one of the adapter's keys out.
async fn status(control: &Path) -> Option<Value> {
    let mut data = ask(control, "show_status").await?;
    let adapter = if composes("show_status", &data) {
        ask(&ipv6tun_socket(control).unwrap(), "show_status").await
    } else {
        None
    };
    compose("show_status", &mut data, adapter.as_ref());
    Some(data)
}

/// A node configuration whose control socket is at `control`, with one UDP
/// transport of `mtu` bytes on loopback and no DNS responder.
fn config_at(control: &Path, mtu: u16) -> Config {
    let mut config = Config::new();
    config.node.control.enabled = true;
    config.node.control.socket_path = control.to_string_lossy().into_owned();
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(mtu),
        ..Default::default()
    });
    config.dns.enabled = false;
    config
}

/// Poll the status a client shows for `control` until `check` holds for it,
/// within ten seconds.
async fn until(control: &Path, check: impl Fn(&Value) -> bool) -> Value {
    let poll = async {
        loop {
            if let Some(data) = status(control).await
                && check(&data)
            {
                return data;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(10), poll)
        .await
        .expect("the composed status never showed what was expected")
}

#[tokio::test]
async fn two_nodes_on_one_host_each_answer_for_their_own_tun_at_their_own_sockets() {
    // One directory, and control sockets that differ only in extension.
    let dir = tempfile::tempdir().unwrap();
    let control_a = dir.path().join("lab").join("node.sock");
    let control_b = dir.path().join("lab").join("node.ctl");
    // Node A's TUN is the embedder's, so its state is active; B has none.
    let mut config_a = config_at(&control_a, 1400);
    config_a.tun.enabled = true;
    let mut node_a = make_node_with(config_a);
    let mut node_b = make_node_with(config_at(&control_b, 1300));
    let (_outbound, _inbound) = node_a.enable_app_owned_tun();
    node_a.start().await.unwrap();
    node_b.start().await.unwrap();

    let clients = async {
        let a = until(&control_a, |d| d["effective_ipv6_mtu"] == 1400 - 77).await;
        let b = until(&control_b, |d| d["effective_ipv6_mtu"] == 1300 - 77).await;
        assert_eq!(a["tun_state"], "active");
        assert_eq!(a["tun_name"], "-", "an app-owned TUN has no device name");
        assert_eq!(b["tun_state"], "disabled");
        assert_eq!(b["tun_name"], "-");
        assert!(ipv6tun_socket(&control_a).unwrap().exists());
        assert!(ipv6tun_socket(&control_b).unwrap().exists());
    };
    tokio::select! {
        result = node_a.run_rx_loop() => panic!("node A's rx loop exited: {result:?}"),
        result = node_b.run_rx_loop() => panic!("node B's rx loop exited: {result:?}"),
        () = clients => {}
    }
    node_a.stop().await.unwrap();
    node_b.stop().await.unwrap();
}

#[tokio::test]
async fn no_adapter_socket_is_bound_while_the_control_socket_is_off() {
    let dir = tempfile::tempdir().unwrap();
    let control = dir.path().join("control.sock");
    let mut config = config_at(&control, 1400);
    config.node.control.enabled = false;
    let mut node = make_node_with(config);
    node.start().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_millis(300), node.run_rx_loop()).await;
    assert!(!control.exists(), "the control socket is off");
    assert!(
        !ipv6tun_socket(&control).unwrap().exists(),
        "the adapter's socket follows the control socket's switch"
    );
    node.stop().await.unwrap();
}

#[tokio::test]
async fn the_composed_mtu_follows_a_transport_no_site_publishes_within_the_first_tick() {
    // An app-owned TUN starts no TUN child, so nothing publishes the bound
    // transport's MTU at start and only the tick moves the adapter off the
    // IPv6 minimum it starts at. At a 3600 s tick the only tick that runs
    // here is the one the loop's interval completes at once on entering
    // the loop, so a value that moves at all moved within that tick.
    let dir = tempfile::tempdir().unwrap();
    let control = dir.path().join("control.sock");
    let mut config = config_at(&control, 1400);
    config.tun.enabled = true;
    config.node.tick_interval_secs = 3600;
    let mut node = make_node_with(config);
    let (_outbound, _inbound) = node.enable_app_owned_tun();
    node.start().await.unwrap();
    assert_eq!(node.ipv6tun_status().effective_ipv6_mtu, 1203);
    let clients = until(&control, |d| d["effective_ipv6_mtu"] == 1400 - 77);
    tokio::select! {
        result = node.run_rx_loop() => panic!("the rx loop exited: {result:?}"),
        _ = clients => {}
    }
    node.stop().await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_tun_that_fails_to_open_is_published_as_failed() {
    // A name longer than the kernel allows makes the open fail on any host,
    // privileged or not, so the start continues without a TUN.
    let mut config = Config::new();
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    });
    config.tun.enabled = true;
    config.tun.name = Some("fips-status-failed".to_string());
    config.dns.enabled = false;
    config.node.control.enabled = false;
    let mut node = make_node_with(config);
    node.start().await.unwrap();
    let failed = crate::ipv6tun::tun::TunState::Failed;
    assert_eq!(node.ipv6tun_status().tun_state, failed);
    assert_eq!(node.ipv6tun_status().tun_state, node.tun_state());
    node.stop().await.unwrap();
}
