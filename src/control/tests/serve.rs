//! Tests for `serve`, the connection loop every control socket shares, driven
//! over in-memory streams rather than sockets.

use super::*;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::{AsyncReadExt, duplex};

/// What one served connection produced.
struct Exchange {
    /// Everything the client read before the stream closed.
    reply: String,
    /// What `serve` returned: whether the reply was written in time.
    written: bool,
    /// The command and parameters the dispatcher was called with, if it was.
    seen: Option<(String, Option<Value>)>,
}

impl Exchange {
    /// The reply parsed as one JSON value.
    fn json(&self) -> Value {
        serde_json::from_str(self.reply.trim_end()).expect("reply is not JSON")
    }

    /// The reply's error message.
    fn message(&self) -> String {
        let reply = self.json();
        assert_eq!(reply["status"], "error", "reply: {}", self.reply);
        reply["message"].as_str().expect("no message").to_string()
    }
}

/// Send `raw` and close the client's sending side, serve the connection with
/// a dispatcher that records its request and answers ok, and read the reply
/// until the stream closes, for at most one second.
///
/// The server's stream outlives `serve`, so the client sees the stream close
/// only if `serve` closed it.
async fn exchange(raw: &[u8]) -> Exchange {
    let (mut client, mut server) = duplex(64 * 1024);
    client.write_all(raw).await.unwrap();
    client.shutdown().await.unwrap();
    let (seen_tx, mut seen_rx) = oneshot::channel();
    let dispatch = |request: Request| async move {
        let answered = json!({ "answered": request.command });
        let _ = seen_tx.send((request.command, request.params));
        Response::ok(answered)
    };
    let mut reply = Vec::new();
    let (served, read) = tokio::join!(
        serve(&mut server, dispatch),
        tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut reply)),
    );
    read.expect("the stream did not close after the reply")
        .unwrap();
    Exchange {
        reply: String::from_utf8(reply).unwrap(),
        written: served.unwrap(),
        seen: seen_rx.try_recv().ok(),
    }
}

#[tokio::test]
async fn a_request_line_is_answered_by_the_dispatcher_with_one_line_and_the_stream_closes() {
    let done = exchange(b"{\"command\":\"show_peers\",\"params\":{\"limit\":3}}\n").await;
    assert_eq!(
        done.seen,
        Some(("show_peers".to_string(), Some(json!({ "limit": 3 }))))
    );
    assert!(done.reply.ends_with('\n'), "reply: {:?}", done.reply);
    assert_eq!(
        done.reply.matches('\n').count(),
        1,
        "reply: {:?}",
        done.reply
    );
    assert_eq!(
        done.json(),
        json!({ "status": "ok", "data": { "answered": "show_peers" } })
    );
    assert!(done.written);
}

#[tokio::test]
async fn a_request_over_4096_bytes_is_refused_without_reaching_the_dispatcher() {
    let raw = format!(
        "{{\"command\":\"show_status\",\"params\":\"{}\"}}\n",
        "a".repeat(MAX_REQUEST_SIZE)
    );
    let done = exchange(raw.as_bytes()).await;
    assert_eq!(done.message(), "read error: request too large");
    assert_eq!(done.seen, None);
}

#[tokio::test]
async fn an_empty_request_is_answered_empty_request() {
    let done = exchange(b"").await;
    assert_eq!(done.message(), "empty request");
    assert_eq!(done.seen, None);
}

#[tokio::test]
async fn an_unparsable_line_is_answered_invalid_request() {
    let done = exchange(b"not json\n").await;
    let message = done.message();
    assert!(
        message.starts_with("invalid request: "),
        "message: {message}"
    );
    assert_ne!(message, "invalid request: ");
    assert_eq!(done.seen, None);
}

#[tokio::test(start_paused = true)]
async fn a_client_that_sends_nothing_is_answered_read_timeout_after_five_seconds() {
    let (mut client, server) = duplex(1024);
    let start = tokio::time::Instant::now();
    let dispatch = |_: Request| async { Response::ok(json!(null)) };
    let mut line = String::new();
    let mut reader = BufReader::new(&mut client);
    let (served, read) = tokio::join!(
        serve(server, dispatch),
        tokio::time::timeout(Duration::from_secs(6), reader.read_line(&mut line)),
    );
    read.expect("no reply within six seconds").unwrap();
    assert!(start.elapsed() >= Duration::from_secs(5), "answered early");
    let reply: Value = serde_json::from_str(line.trim_end()).unwrap();
    assert_eq!(
        reply,
        json!({ "status": "error", "message": "read timeout" })
    );
    assert!(served.unwrap());
}

#[tokio::test]
async fn a_reply_the_client_cannot_take_reports_false() {
    let (mut client, server) = duplex(1024);
    client
        .write_all(b"{\"command\":\"show_status\"}\n")
        .await
        .unwrap();
    drop(client);
    let dispatch = |_: Request| async { Response::ok(json!({ "answered": true })) };
    assert!(!serve(server, dispatch).await.unwrap());
}
