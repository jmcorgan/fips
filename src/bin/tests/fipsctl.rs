//! How `fipsctl` reads the IPv6 adapter's socket beside the control socket
//! it was given, against fake sockets in a temporary directory. Unix only:
//! the fakes are Unix domain sockets.
#![cfg(unix)]

use super::*;
use serde_json::{Value, json};
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A fake socket at `path` that answers every request with `reply` and
/// counts the connections it accepts.
fn fake(path: &Path, reply: Value) -> Arc<AtomicUsize> {
    let listener = UnixListener::bind(path).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                return;
            };
            seen.fetch_add(1, Ordering::SeqCst);
            let mut line = String::new();
            let _ = BufReader::new(&stream).read_line(&mut line);
            let _ = writeln!(stream, "{reply}");
        }
    });
    count
}

/// A successful reply carrying `data`.
fn ok(data: Value) -> Value {
    json!({"status": "ok", "data": data})
}

/// The `data` of the reply `query` gives for `show_status` at `control`.
fn status(control: &Path) -> Value {
    let reply = query(control, "show_status", &build_query("show_status")).unwrap();
    reply["data"].clone()
}

#[test]
fn query_with_a_socket_path_reads_the_adapter_socket_beside_it() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();
    // Each node leaves the adapter's keys out, and each adapter names its node.
    fake(&a.join("control.sock"), ok(json!({"npub": "npub1a"})));
    fake(
        &a.join("control-ipv6tun.sock"),
        ok(json!({"tun_state": "active", "tun_name": "fips-a", "effective_ipv6_mtu": 1323})),
    );
    fake(&b.join("node.sock"), ok(json!({"npub": "npub1b"})));
    fake(
        &b.join("node-ipv6tun.sock"),
        ok(json!({"tun_state": "active", "tun_name": "fips-b", "effective_ipv6_mtu": 1223})),
    );

    let data = status(&a.join("control.sock"));
    assert_eq!(data["npub"], "npub1a");
    assert_eq!(data["tun_name"], "fips-a");
    assert_eq!(data["effective_ipv6_mtu"], 1323);
    let data = status(&b.join("node.sock"));
    assert_eq!(data["npub"], "npub1b");
    assert_eq!(data["tun_name"], "fips-b");
    assert_eq!(data["effective_ipv6_mtu"], 1223);
}

#[test]
fn an_error_from_the_node_is_returned_without_asking_the_adapter() {
    let dir = tempfile::tempdir().unwrap();
    let error = json!({"status": "error", "message": "unknown command: show_status"});
    fake(&dir.path().join("control.sock"), error.clone());
    let adapter = fake(
        &dir.path().join("control-ipv6tun.sock"),
        ok(json!({"tun_state": "active"})),
    );

    let control = dir.path().join("control.sock");
    let reply = query(&control, "show_status", &build_query("show_status")).unwrap();
    assert_eq!(reply, error);
    assert_eq!(adapter.load(Ordering::SeqCst), 0);
}

#[test]
fn a_node_that_answers_the_tun_keys_itself_is_not_followed_by_an_adapter_query() {
    let dir = tempfile::tempdir().unwrap();
    let node = json!({"tun_state": "disabled", "tun_name": "-", "effective_ipv6_mtu": 1203});
    fake(&dir.path().join("control.sock"), ok(node.clone()));
    let adapter = fake(
        &dir.path().join("control-ipv6tun.sock"),
        ok(json!({"tun_state": "active", "tun_name": "fips0", "effective_ipv6_mtu": 1323})),
    );

    assert_eq!(status(&dir.path().join("control.sock")), node);
    assert_eq!(adapter.load(Ordering::SeqCst), 0);
}
