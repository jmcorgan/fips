//! Tests for the Tor control client in `control.rs`: reply parsing, its size
//! caps, the connect and reply deadlines, and what a failure part-way
//! through a reply leaves behind.

use super::*;
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
