//! Tests for the Tor control client in `control.rs`: reply parsing, its size
//! caps, the connect and reply deadlines, what a failure part-way through a
//! reply leaves behind, and what the client sends to a control port it
//! cannot trust.

use super::*;
use crate::testutil::capture_logs_scoped;
use crate::transport::tor::mock_control::{MockOptions, MockTorControlServer};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// A stand-in control port. It records every byte the client sends, answers
/// the first line with `reply` (nothing, if `reply` is empty), and holds the
/// connection open until the client closes it. The handle yields the bytes
/// it received.
async fn standin(reply: &'static [u8]) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        let mut got = Vec::new();
        let mut answered = false;
        loop {
            let mut line = Vec::new();
            match reader.read_until(b'\n', &mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            got.extend_from_slice(&line);
            if !answered && !reply.is_empty() {
                answered = true;
                let _ = writer.write_all(reply).await;
                let _ = writer.flush().await;
            }
        }
        got
    });
    (addr, handle)
}

/// A client whose control port sends exactly `bytes` and then closes.
fn client_reading(bytes: Vec<u8>) -> TorControlClient {
    TorControlClient {
        reader: BufReader::new(Box::new(std::io::Cursor::new(bytes))),
        writer: Box::new(tokio::io::sink()),
        out_of_step: false,
        remote_peer: None,
    }
}

/// Write a 32-byte cookie with a recognisable pattern to a temporary file.
fn cookie_file() -> (tempfile::TempDir, PathBuf, Vec<u8>) {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("cookie");
    let bytes: Vec<u8> = (0u8..32)
        .map(|b| b.wrapping_mul(7).wrapping_add(3))
        .collect();
    std::fs::write(&path, &bytes).unwrap();
    (dir, path, bytes)
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Assert no line a port received carries the cookie in hex, in either case.
fn assert_cookie_absent(lines: &[String], cookie: &[u8]) {
    let cookie_hex = lower_hex(cookie);
    for line in lines {
        assert!(
            !line.to_lowercase().contains(&cookie_hex),
            "defect: the port received the cookie: {line:?}"
        );
    }
}

/// `count` data lines of `width` bytes of content each, then `250 OK`.
fn reply_with_lines(count: usize, width: usize) -> Vec<u8> {
    let mut reply = Vec::new();
    for _ in 0..count {
        reply.extend_from_slice(b"250-");
        reply.extend(std::iter::repeat_n(b'a', width));
        reply.extend_from_slice(b"\r\n");
    }
    reply.extend_from_slice(b"250 OK\r\n");
    reply
}

fn protocol_error(result: Result<ControlResponse, TorControlError>) -> String {
    match result {
        Err(TorControlError::ProtocolError(msg)) => msg,
        Err(other) => panic!("expected a protocol error, got {other}"),
        Ok(r) => panic!(
            "expected a protocol error, got a {} reply with {} data lines",
            r.code,
            r.data_lines.len()
        ),
    }
}

// === Reply parsing ===

#[tokio::test]
async fn a_plain_250_ok_reply_authenticates() {
    let (addr, _h) = standin(b"250 OK\r\n").await;
    let mut client = TorControlClient::connect(&addr).await.unwrap();
    client
        .authenticate(&ControlAuth::Password("pw".into()))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_dot_encoded_data_reply_under_the_caps_parses_and_unescapes() {
    let mut client =
        client_reading(b"250+config-text=\r\n..dotted\r\nplain\r\n.\r\n250 OK\r\n".to_vec());
    let reply = client.read_response().await.unwrap();
    assert_eq!(reply.code, 250);
    assert_eq!(reply.message, "OK");
    assert_eq!(reply.data_lines, vec!["config-text=", ".dotted", "plain"]);
}

#[tokio::test]
async fn an_error_reply_keeps_its_code_and_message() {
    let mut client = client_reading(b"515 Authentication failed\r\n".to_vec());
    let reply = client.read_response().await.unwrap();
    assert_eq!(reply.code, 515);
    assert_eq!(reply.message, "Authentication failed");
}

#[tokio::test]
async fn reply_content_that_is_not_utf8_is_a_protocol_error() {
    let mut client = client_reading(b"250 \xff\xfe\r\n".to_vec());
    let msg = protocol_error(client.read_response().await);
    assert!(msg.contains("not UTF-8"), "{msg}");
}

#[tokio::test]
async fn a_reply_cut_off_mid_line_is_a_protocol_error() {
    let mut client = client_reading(b"250-version=0.4".to_vec());
    let msg = protocol_error(client.read_response().await);
    assert!(msg.contains("closed"), "{msg}");
}

// === Size caps ===

#[tokio::test]
async fn a_line_of_exactly_8_kib_with_its_terminator_is_accepted() {
    // 4 bytes of code and separator, the content, and CR LF.
    let mut client = client_reading(reply_with_lines(1, MAX_LINE - 6));
    let reply = client.read_response().await.unwrap();
    assert_eq!(reply.data_lines[0].len(), MAX_LINE - 6);
}

#[tokio::test]
async fn a_line_longer_than_8_kib_is_a_protocol_error() {
    let mut client = client_reading(reply_with_lines(1, MAX_LINE - 5));
    let msg = protocol_error(client.read_response().await);
    assert!(msg.contains("line longer than 8192"), "{msg}");
}

#[tokio::test]
async fn a_reply_just_under_64_kib_is_accepted() {
    // 63 lines of 1,000 bytes (1,006 with code and CR LF) and `250 OK`.
    let mut client = client_reading(reply_with_lines(63, 1000));
    let reply = client.read_response().await.unwrap();
    assert_eq!(reply.data_lines.len(), 63);
}

#[tokio::test]
async fn a_reply_longer_than_64_kib_is_a_protocol_error() {
    // 66 lines of 1,006 bytes each pass every line cap but not the reply cap.
    let mut client = client_reading(reply_with_lines(66, 1000));
    let msg = protocol_error(client.read_response().await);
    assert!(msg.contains("reply longer than 65536"), "{msg}");
}

#[tokio::test]
async fn a_reply_with_1024_data_lines_is_accepted() {
    let mut client = client_reading(reply_with_lines(MAX_DATA_LINES, 1));
    let reply = client.read_response().await.unwrap();
    assert_eq!(reply.data_lines.len(), MAX_DATA_LINES);
}

#[tokio::test]
async fn a_reply_with_more_than_1024_data_lines_is_a_protocol_error() {
    let mut client = client_reading(reply_with_lines(MAX_DATA_LINES + 1, 1));
    let msg = protocol_error(client.read_response().await);
    assert!(msg.contains("more than 1024 data lines"), "{msg}");
}

// === Malformed replies from a port ===

#[tokio::test]
async fn a_reply_with_a_multibyte_separator_is_a_protocol_error_not_a_panic() {
    let (addr, _h) = standin("250\u{3bc} OK\r\n".as_bytes()).await;
    let mut client = TorControlClient::connect(&addr).await.unwrap();
    let result = client
        .authenticate(&ControlAuth::Password("pw".into()))
        .await;
    assert!(
        matches!(result, Err(TorControlError::ProtocolError(_))),
        "defect: a non-ASCII separator was not a protocol error: {result:?}"
    );
}

#[tokio::test]
async fn a_reply_with_a_multibyte_code_is_a_protocol_error_not_a_panic() {
    let (addr, _h) = standin("\u{3bc}\u{3bc} OK\r\n".as_bytes()).await;
    let mut client = TorControlClient::connect(&addr).await.unwrap();
    let result = client
        .authenticate(&ControlAuth::Password("pw".into()))
        .await;
    assert!(
        matches!(result, Err(TorControlError::ProtocolError(_))),
        "defect: a non-ASCII status code was not a protocol error: {result:?}"
    );
}

// === Deadline ===

#[tokio::test]
async fn a_silent_control_port_fails_authenticate_at_the_30_second_deadline() {
    let (addr, _h) = standin(b"").await;
    let mut client = TorControlClient::connect(&addr).await.unwrap();

    tokio::time::pause();
    let start = tokio::time::Instant::now();
    let outcome = tokio::time::timeout(
        Duration::from_secs(60),
        client.authenticate(&ControlAuth::Password("pw".into())),
    )
    .await;
    let elapsed = start.elapsed();

    let result = outcome.expect("defect: authenticate still waiting after 60 s on a silent port");
    assert!(
        result.is_err(),
        "defect: a silent port authenticated: {result:?}"
    );
    assert!(
        elapsed >= Duration::from_secs(30) && elapsed < Duration::from_secs(31),
        "defect: a silent port failed after {elapsed:?}, not at the 30 s deadline"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_control_port_that_never_accepts_fails_connect_at_the_30_second_deadline() {
    // A listener with a backlog of 0 queues one finished handshake. While
    // that one is not accepted, Linux drops each further SYN, so the next
    // connect neither completes nor is refused.
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(0).unwrap();
    let addr = listener.local_addr().unwrap();
    let mut queued = Vec::new();
    let mut queue_full = false;
    for _ in 0..8 {
        match tokio::time::timeout(
            Duration::from_millis(500),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        {
            Ok(stream) => queued.push(stream.unwrap()),
            Err(_) => {
                queue_full = true;
                break;
            }
        }
    }
    assert!(
        queue_full,
        "the listener's queue never filled, so this host cannot hold a connect open"
    );

    tokio::time::pause();
    let start = tokio::time::Instant::now();
    let outcome = tokio::time::timeout(
        Duration::from_secs(60),
        TorControlClient::connect(&addr.to_string()),
    )
    .await;
    let elapsed = start.elapsed();

    let result = outcome.expect("defect: connect still waiting after 60 s");
    assert!(
        matches!(result, Err(TorControlError::ConnectionFailed(_))),
        "defect: a connect that never completes did not fail: {result:?}"
    );
    assert!(
        elapsed >= Duration::from_secs(30) && elapsed < Duration::from_secs(31),
        "defect: the connect failed after {elapsed:?}, not at the 30 s deadline"
    );
    drop(queued);
}

// === A failure part-way leaves the connection out of step ===

#[tokio::test]
async fn after_a_reply_over_the_line_cap_later_queries_fail_instead_of_reading_its_remainder() {
    let mut bytes = b"250-version=".to_vec();
    bytes.extend(std::iter::repeat_n(b'a', 9000));
    bytes.extend_from_slice(b"\r\n250 OK\r\n250-version=0.4.9.15\r\n250 OK\r\n");
    let mut client = client_reading(bytes);

    assert!(client.version().await.is_err());
    assert!(client.is_out_of_step());
    for _ in 0..3 {
        match client.version().await {
            Err(TorControlError::ProtocolError(msg)) => {
                assert!(msg.contains("out of step"), "{msg}");
            }
            other => panic!("defect: a later query read the rest of the stream: {other:?}"),
        }
    }
    let snapshot = client.monitoring_snapshot().await;
    assert!(
        snapshot.is_err(),
        "defect: an out-of-step client gave a snapshot: {snapshot:?}"
    );
}

#[tokio::test]
async fn an_error_reply_read_in_full_leaves_the_connection_usable() {
    let mut client =
        client_reading(b"552 Unrecognized key\r\n250-version=0.4.9.15\r\n250 OK\r\n".to_vec());

    assert!(client.version().await.is_err());
    assert!(!client.is_out_of_step());
    assert_eq!(client.version().await.unwrap(), "0.4.9.15");
}

// === What the client sends ===

#[tokio::test]
async fn a_password_with_a_line_break_never_reaches_the_port_as_a_second_command() {
    let (addr, h) = standin(b"515 Authentication failed\r\n").await;
    let mut client = TorControlClient::connect(&addr).await.unwrap();
    let result = client
        .authenticate(&ControlAuth::Password("pw\r\nGETINFO version".into()))
        .await;
    drop(client);
    let got = h.await.unwrap();
    let lines = got.split(|b| *b == b'\n').filter(|l| !l.is_empty()).count();
    let text = String::from_utf8_lossy(&got);
    assert!(
        lines <= 1 && !text.contains("GETINFO"),
        "defect: {lines} control lines sent: {text:?}"
    );
    assert!(
        result.is_err(),
        "defect: a password with a line break authenticated"
    );
}

#[test]
fn a_configured_password_with_a_line_break_is_refused_without_echoing_it() {
    for setting in ["password:pw\nsecret", "password:pw\rsecret"] {
        let err = ControlAuth::from_config(setting, "/x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("line break"), "{err}");
        assert!(!err.contains("secret"), "defect: password echoed: {err}");
    }
}

#[test]
fn an_unknown_control_auth_string_is_not_echoed_in_the_error() {
    let err = ControlAuth::from_config("passwrd:hunter2", "/x")
        .unwrap_err()
        .to_string();
    assert!(!err.contains("hunter2"), "defect: setting echoed: {err}");
}

// === SAFECOOKIE ===

#[tokio::test]
async fn a_standin_port_that_lacks_the_cookie_never_receives_it() {
    let (_dir, path, bytes) = cookie_file();
    let (addr, h) = standin(b"515 Authentication failed\r\n").await;
    let mut client = TorControlClient::connect(&addr).await.unwrap();
    let result = client.authenticate(&ControlAuth::Cookie(path)).await;
    drop(client);
    let got = String::from_utf8_lossy(&h.await.unwrap()).to_lowercase();
    assert!(
        !got.contains(&lower_hex(&bytes)),
        "defect: the stand-in received the cookie: {got:?}"
    );
    assert!(result.is_err(), "defect: authenticated against a stand-in");
}

#[tokio::test]
async fn safecookie_authenticates_against_a_port_that_holds_the_cookie() {
    let (_dir, path, bytes) = cookie_file();
    let mock = MockTorControlServer::start_with_options(MockOptions {
        cookie: Some(bytes.clone().try_into().unwrap()),
        ..Default::default()
    })
    .await;
    let mut client = TorControlClient::connect(&mock.addr().to_string())
        .await
        .unwrap();
    client
        .authenticate(&ControlAuth::Cookie(path))
        .await
        .unwrap();
    assert_eq!(client.version().await.unwrap(), "0.4.8.10");

    let log = mock.log();
    assert!(log[0].starts_with("AUTHCHALLENGE SAFECOOKIE "), "{log:?}");
    assert!(log[1].starts_with("AUTHENTICATE "), "{log:?}");
    assert_cookie_absent(&log, &bytes);
}

#[tokio::test]
async fn safecookie_fails_against_a_port_with_the_wrong_cookie_before_sending_a_hash() {
    let (_dir, path, bytes) = cookie_file();
    let mock = MockTorControlServer::start_with_options(MockOptions {
        cookie: Some([0x11; 32]),
        ..Default::default()
    })
    .await;
    let mut client = TorControlClient::connect(&mock.addr().to_string())
        .await
        .unwrap();
    let result = client.authenticate(&ControlAuth::Cookie(path)).await;
    assert!(
        matches!(&result, Err(TorControlError::AuthFailed(msg)) if msg.contains("SERVERHASH")),
        "{result:?}"
    );
    drop(client);

    // The client sent its nonce and stopped: nothing derived from the cookie
    // reached the port.
    let log = mock.log();
    assert_eq!(log.len(), 1, "{log:?}");
    assert!(log[0].starts_with("AUTHCHALLENGE SAFECOOKIE "), "{log:?}");
    assert_cookie_absent(&log, &bytes);
}

#[tokio::test]
async fn a_port_that_refuses_authchallenge_gets_no_plain_cookie_fallback() {
    let (_dir, path, bytes) = cookie_file();
    // With no cookie, the mock answers AUTHCHALLENGE with 510 and would
    // accept any AUTHENTICATE, so a fallback would authenticate here.
    let mock = MockTorControlServer::start().await;
    let mut client = TorControlClient::connect(&mock.addr().to_string())
        .await
        .unwrap();
    let result = client.authenticate(&ControlAuth::Cookie(path)).await;
    assert!(
        matches!(&result, Err(TorControlError::AuthFailed(msg)) if msg.contains("510")),
        "defect: no AuthFailed after a refused AUTHCHALLENGE: {result:?}"
    );
    drop(client);

    let log = mock.log();
    assert!(
        log.iter().all(|line| !line.starts_with("AUTHENTICATE")),
        "defect: the client fell back to AUTHENTICATE: {log:?}"
    );
    assert_cookie_absent(&log, &bytes);
}

#[tokio::test]
async fn a_malformed_authchallenge_reply_is_an_auth_failure() {
    let (_dir, path, _bytes) = cookie_file();
    let (addr, _h) = standin(b"250 AUTHCHALLENGE SERVERHASH=zz SERVERNONCE=00\r\n").await;
    let mut client = TorControlClient::connect(&addr).await.unwrap();
    let result = client.authenticate(&ControlAuth::Cookie(path)).await;
    assert!(
        matches!(&result, Err(TorControlError::AuthFailed(msg)) if msg.contains("malformed")),
        "{result:?}"
    );
}

// === Password over a remote TCP connection ===

#[test]
fn loopback_peers_include_ipv4_mapped_loopback() {
    for peer in [
        "127.0.0.1:9051",
        "127.1.2.3:9051",
        "[::1]:9051",
        "[::ffff:127.0.0.1]:9051",
    ] {
        assert!(is_loopback_peer(&peer.parse().unwrap()), "{peer}");
    }
    for peer in [
        "192.0.2.10:9051",
        "[2001:db8::1]:9051",
        "[::ffff:192.0.2.10]:9051",
    ] {
        assert!(!is_loopback_peer(&peer.parse().unwrap()), "{peer}");
    }
}

#[tokio::test]
async fn a_loopback_tcp_connection_is_not_remote() {
    let (addr, _h) = standin(b"250 OK\r\n").await;
    let client = TorControlClient::connect(&addr).await.unwrap();
    assert_eq!(client.remote_peer, None);
}

#[tokio::test]
async fn a_tcp_connection_to_a_non_loopback_address_records_the_peer() {
    // Learn an address of this host that is not loopback by routing a UDP
    // socket towards a documentation address; connecting a UDP socket sends
    // nothing. A host with no route has no such address to connect through,
    // and that case alone is skipped.
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let local = match probe
        .connect("192.0.2.1:9")
        .and_then(|()| probe.local_addr())
    {
        Ok(addr) if !addr.ip().is_loopback() && !addr.ip().is_unspecified() => addr.ip(),
        other => {
            eprintln!("skipped: no non-loopback IPv4 address on this host ({other:?})");
            return;
        }
    };
    let listener = TcpListener::bind((local, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _accept = tokio::spawn(async move { listener.accept().await });

    let client = TorControlClient::connect(&addr.to_string()).await.unwrap();
    assert_eq!(
        client.remote_peer,
        Some(addr),
        "defect: a connection to {addr} was not recorded as remote"
    );
}

#[tokio::test]
async fn a_password_sent_to_a_remote_peer_is_warned_about_once() {
    let (capture, _guard) = capture_logs_scoped();
    let mut client = client_reading(b"250 OK\r\n".to_vec());
    client.remote_peer = Some("192.0.2.10:9051".parse().unwrap());
    client
        .authenticate(&ControlAuth::Password("pw".into()))
        .await
        .unwrap();

    let warnings = capture.warnings();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("in clear"), "{warnings:?}");
    assert!(warnings[0].contains("192.0.2.10:9051"), "{warnings:?}");
    assert!(!warnings[0].contains("pw\""), "{warnings:?}");
}

#[tokio::test]
async fn a_password_sent_over_loopback_is_not_warned_about() {
    let (capture, _guard) = capture_logs_scoped();
    let mut client = client_reading(b"250 OK\r\n".to_vec());
    client
        .authenticate(&ControlAuth::Password("pw".into()))
        .await
        .unwrap();
    assert!(capture.warnings().is_empty(), "{:?}", capture.warnings());
}
