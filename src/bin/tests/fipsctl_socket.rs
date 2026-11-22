//! Tests for `fipsctl`'s control socket client: whom it talks to, and what it
//! passes on from a reply.

use super::send_request;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::thread::JoinHandle;

/// A reply message carrying a terminal title change, a screen clear and
/// colour codes, as a stand-in server would send to take over the terminal.
const HOSTILE: &str =
    "\u{1b}]0;PWNED-TITLE\u{7}\u{1b}[2J\u{1b}[31mdaemon says: all peers healthy\u{1b}[0m";

/// `HOSTILE` with each control character replaced by U+FFFD.
const SCRUBBED: &str = "\u{fffd}]0;PWNED-TITLE\u{fffd}\u{fffd}[2J\u{fffd}[31mdaemon says: all peers healthy\u{fffd}[0m";

/// Bind a listener in a fresh directory and answer one request with `reply`.
///
/// The handle yields the request line the listener read.
fn serve_once(reply: Value) -> (tempfile::TempDir, std::path::PathBuf, JoinHandle<String>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(&conn).read_line(&mut line).unwrap();
        writeln!(conn, "{reply}").unwrap();
        line
    });
    (dir, path, server)
}

/// Collect every string in `value`, object keys included.
fn strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => items.iter().for_each(|v| strings(v, out)),
        Value::Object(map) => {
            for (key, v) in map {
                out.push(key.clone());
                strings(v, out);
            }
        }
        _ => {}
    }
}

#[test]
fn a_server_message_carrying_terminal_escapes_is_printed_without_them() {
    let (_dir, path, server) = serve_once(json!({"status": "error", "message": HOSTILE}));

    let reply = send_request(&path, "{\"command\":\"show_status\"}\n").unwrap();
    server.join().unwrap();

    let message = reply["message"].as_str().unwrap();
    assert!(
        !message.chars().any(char::is_control),
        "message kept a control character: {message:?}"
    );
    assert_eq!(message, SCRUBBED);
}

#[test]
fn every_string_in_a_server_reply_comes_back_without_control_characters() {
    let (_dir, path, server) = serve_once(json!({
        "status": "ok",
        "data": {
            "peers": [{"name": HOSTILE, "note": "tab\there, line\nthere, csi\u{9b}2J"}],
            HOSTILE: [HOSTILE],
        },
    }));

    let reply = send_request(&path, "{\"command\":\"show_peers\"}\n").unwrap();
    server.join().unwrap();

    let mut found = Vec::new();
    strings(&reply, &mut found);
    assert!(found.len() >= 6, "walked too few strings: {found:?}");
    for s in &found {
        assert!(
            !s.chars().any(char::is_control),
            "reply string kept a control character: {s:?}"
        );
    }
    assert_eq!(reply["data"]["peers"][0]["name"], SCRUBBED);
    assert_eq!(reply["data"][SCRUBBED][0], SCRUBBED);
}

#[test]
fn a_server_running_as_this_user_is_trusted() {
    let sent = json!({
        "status": "ok",
        "data": {"peers": [{"name": "node-a", "rtt_ms": 12.5}], "note": "unicode é ✓"},
    });
    let (_dir, path, server) = serve_once(sent.clone());

    let reply = send_request(&path, "{\"command\":\"show_peers\"}\n").unwrap();

    assert_eq!(server.join().unwrap(), "{\"command\":\"show_peers\"}\n");
    assert_eq!(reply, sent, "an honest reply must come back unchanged");
}
