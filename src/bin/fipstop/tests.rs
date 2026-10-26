//! How `fipstop` reads the IPv6 adapter's socket beside the control socket
//! it was given, against fake sockets in a temporary directory. Unix only:
//! the fakes are Unix domain sockets.
#![cfg(unix)]

use super::*;
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

/// A runtime like the one `main` builds, on which the fakes run while
/// `fetch_data` blocks on it.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// A fake socket at `path` that counts the connections it accepts and
/// answers each request with the `data` that `replies` holds under its
/// command, or with an error for a command it does not hold. A command held
/// as `null` is closed without an answer, and with no `replies` every
/// connection is.
fn fake(rt: &tokio::runtime::Runtime, path: &Path, replies: Option<Value>) -> Arc<AtomicUsize> {
    let listener = rt.block_on(async { UnixListener::bind(path) }).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    rt.spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
            let Some(replies) = &replies else {
                continue;
            };
            let (reader, mut writer) = tokio::io::split(stream);
            let mut line = String::new();
            let _ = BufReader::new(reader).read_line(&mut line).await;
            let request: Value = serde_json::from_str(&line).unwrap_or_default();
            let command = request["command"].as_str().unwrap_or_default();
            let reply = match replies.get(command) {
                Some(Value::Null) => continue,
                Some(data) => json!({"status": "ok", "data": data}),
                None => {
                    json!({"status": "error", "message": format!("unknown command: {command}")})
                }
            };
            let _ = writer.write_all(format!("{reply}\n").as_bytes()).await;
        }
    });
    count
}

/// The Node tab's fetch, as `main` runs it on each refresh.
fn fetch(rt: &tokio::runtime::Runtime, control: &Path, adapter: Option<&mut Adapter>) -> App {
    let mut app = App::new(Duration::from_secs(2));
    let client = ControlClient::new(control);
    let gateway = ControlClient::new(&control.with_file_name("gateway.sock"));
    fetch_data(rt, &client, adapter, &gateway, &mut app);
    app
}

#[test]
fn fetch_data_with_a_socket_path_composes_the_adapter_beside_it() {
    let rt = runtime();
    let dir = tempfile::tempdir().unwrap();
    let control = dir.path().join("node.sock");
    fake(
        &rt,
        &control,
        Some(json!({"show_status": {"npub": "npub1node"}})),
    );
    fake(
        &rt,
        &dir.path().join("node-ipv6tun.sock"),
        Some(json!({
            "show_status": {
                "tun_state": "active",
                "tun_name": "fips-a",
                "effective_ipv6_mtu": 1323,
            },
            "show_listening_sockets": {"fips0_addr": "fd00::a", "sockets": []},
        })),
    );

    let mut adapter = adapter(&control);
    let app = fetch(&rt, &control, adapter.as_mut());
    let node = &app.data[&Tab::Node];
    assert_eq!(node["npub"], "npub1node");
    assert_eq!(node["tun_state"], "active");
    assert_eq!(node["tun_name"], "fips-a");
    assert_eq!(node["effective_ipv6_mtu"], 1323);
    assert_eq!(
        app.listening_sockets,
        Some(json!({"fips0_addr": "fd00::a", "sockets": []}))
    );
}

#[test]
fn the_panel_falls_back_to_the_node_socket_when_no_adapter_answers() {
    let rt = runtime();
    let dir = tempfile::tempdir().unwrap();
    let control = dir.path().join("control.sock");
    fake(
        &rt,
        &control,
        Some(json!({
            "show_status": {"tun_state": "disabled", "tun_name": "-", "effective_ipv6_mtu": 1203},
            "show_listening_sockets": {"fips0_addr": "fd00::b", "sockets": []},
        })),
    );

    let mut adapter = adapter(&control);
    let app = fetch(&rt, &control, adapter.as_mut());
    assert_eq!(app.data[&Tab::Node]["effective_ipv6_mtu"], 1203);
    assert_eq!(
        app.listening_sockets,
        Some(json!({"fips0_addr": "fd00::b", "sockets": []}))
    );
}

#[test]
fn an_absent_adapter_is_not_asked_again_for_ten_fetches() {
    let rt = runtime();
    let dir = tempfile::tempdir().unwrap();
    let control = dir.path().join("control.sock");
    // The node answers every TUN key, so only the panel asks the adapter.
    fake(
        &rt,
        &control,
        Some(json!({
            "show_status": {"tun_state": "disabled", "tun_name": "-", "effective_ipv6_mtu": 1203},
            "show_listening_sockets": {"fips0_addr": "fd00::c", "sockets": []},
        })),
    );

    let mut adapter = adapter(&control);
    let app = fetch(&rt, &control, adapter.as_mut());
    assert_eq!(app.listening_sockets.unwrap()["fips0_addr"], "fd00::c");

    // The adapter's socket appears after the first fetch found none.
    let asked = fake(
        &rt,
        &dir.path().join("control-ipv6tun.sock"),
        Some(json!({"show_listening_sockets": {"fips0_addr": "fd00::d", "sockets": []}})),
    );
    for fetches in 2..=12 {
        let app = fetch(&rt, &control, adapter.as_mut());
        let (expected, panel) = if fetches < 12 {
            (0, "fd00::c")
        } else {
            (1, "fd00::d")
        };
        assert_eq!(asked.load(Ordering::SeqCst), expected, "fetch {fetches}");
        assert_eq!(
            app.listening_sockets.unwrap()["fips0_addr"],
            panel,
            "fetch {fetches}"
        );
    }
}

#[test]
fn a_failed_panel_answer_keeps_the_adapter_status_shown() {
    let rt = runtime();
    let dir = tempfile::tempdir().unwrap();
    let control = dir.path().join("control.sock");
    // The node leaves the TUN keys and the panel to the adapter, which
    // answers its status and closes the panel's request unanswered.
    fake(
        &rt,
        &control,
        Some(json!({"show_status": {"npub": "npub1node"}})),
    );
    let asked = fake(
        &rt,
        &dir.path().join("control-ipv6tun.sock"),
        Some(json!({
            "show_status": {
                "tun_state": "active",
                "tun_name": "fips0",
                "effective_ipv6_mtu": 1323,
            },
            "show_listening_sockets": null,
        })),
    );

    let mut adapter = adapter(&control);
    for fetches in 1..=3 {
        let app = fetch(&rt, &control, adapter.as_mut());
        let node = &app.data[&Tab::Node];
        assert_eq!(node["tun_state"], "active", "fetch {fetches}");
        assert_eq!(node["effective_ipv6_mtu"], 1323, "fetch {fetches}");
        assert_eq!(app.listening_sockets, None, "fetch {fetches}");
        assert_eq!(asked.load(Ordering::SeqCst), 2 * fetches, "fetch {fetches}");
    }
}
