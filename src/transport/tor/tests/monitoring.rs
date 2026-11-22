//! Tests for the control-port monitoring task in `mod.rs`: how it recovers
//! when a query leaves the control connection out of step.

use super::*;
use crate::transport::packet_channel;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// The value a healthy control port gives for each GETINFO key the
/// monitoring snapshot asks for.
fn value_for(key: &str) -> &'static str {
    match key {
        "status/bootstrap-phase" => "NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"",
        "status/circuit-established" => "1",
        "traffic/read" => "1048576",
        "traffic/written" => "524288",
        "network-liveness" => "up",
        "version" => "0.4.9.15",
        "dormant" => "0",
        _ => "",
    }
}

/// A control port that accepts any number of connections and any
/// AUTHENTICATE, and answers every GETINFO at once except the first one it
/// ever receives, which it answers 31 s late: just past the client's reply
/// deadline.
struct SlowFirstReplyPort {
    addr: String,
    connections: Arc<AtomicUsize>,
}

impl SlowFirstReplyPort {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let connections = Arc::new(AtomicUsize::new(0));
        let stalled = Arc::new(AtomicBool::new(false));
        let counter = Arc::clone(&connections);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(Self::serve(stream, Arc::clone(&stalled)));
            }
        });
        Self { addr, connections }
    }

    async fn serve(stream: tokio::net::TcpStream, stalled: Arc<AtomicBool>) {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            let reply = if let Some(key) = line.trim().strip_prefix("GETINFO ") {
                if !stalled.swap(true, Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_secs(31)).await;
                }
                format!("250-{key}={}\r\n250 OK\r\n", value_for(key))
            } else {
                "250 OK\r\n".to_string()
            };
            if writer.write_all(reply.as_bytes()).await.is_err() {
                return;
            }
        }
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

#[tokio::test]
async fn monitoring_reconnects_after_a_reply_misses_the_deadline_and_reports_true_values() {
    let port = SlowFirstReplyPort::start().await;
    let (tx, _rx) = packet_channel(32);
    let config = TorConfig {
        mode: Some("control_port".to_string()),
        socks5_addr: Some("127.0.0.1:19050".to_string()),
        control_addr: Some(port.addr.clone()),
        control_auth: Some("password:pw".to_string()),
        ..Default::default()
    };
    let mut transport = TorTransport::new(TransportId::new(1), None, config, tx);
    transport.start_async().await.unwrap();

    // The deadline and the monitoring interval run on tokio's paused clock,
    // so the test does not wait in real time.
    tokio::time::pause();
    let start = tokio::time::Instant::now();
    let mut last = None;
    while start.elapsed() < Duration::from_secs(120) {
        tokio::time::sleep(Duration::from_secs(1)).await;
        last = transport.cached_monitoring();
        if last
            .as_ref()
            .is_some_and(|info| info.version == "0.4.9.15" && info.bootstrap == 100)
        {
            break;
        }
    }

    let info = last.expect("defect: no monitoring snapshot was cached within 120 s");
    assert_eq!(
        (
            info.version.as_str(),
            info.bootstrap,
            info.network_liveness.as_str()
        ),
        ("0.4.9.15", 100, "up"),
        "defect: after a late reply, monitoring still reports wrong values: {info:?}"
    );
    assert_eq!(
        port.connections(),
        2,
        "the task should have opened exactly one new connection"
    );

    transport.stop_async().await.unwrap();
}
