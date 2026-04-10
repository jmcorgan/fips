//! Mock Tor control port server for testing.
//!
//! Implements enough of the Tor control protocol to validate
//! AUTHENTICATE and GETINFO commands.

use std::net::SocketAddr;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// Options for configuring mock behavior.
#[derive(Default)]
pub struct MockOptions {
    /// If true, reject all AUTHENTICATE attempts.
    pub reject_auth: bool,
}

/// A mock Tor control port server.
///
/// Accepts a single client connection and responds to control protocol
/// commands with valid-looking responses for testing.
pub struct MockTorControlServer {
    addr: SocketAddr,
    _handle: JoinHandle<()>,
}

impl MockTorControlServer {
    /// Start a mock control server with default options.
    pub async fn start() -> Self {
        Self::start_with_options(MockOptions::default()).await
    }

    /// Start a mock control server with custom options.
    pub async fn start_with_options(options: MockOptions) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock control");
        let addr = listener.local_addr().expect("local addr");

        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            let mut authenticated = false;

            loop {
                line.clear();
                let n = match reader.read_line(&mut line).await {
                    Ok(n) => n,
                    Err(_) => break,
                };
                if n == 0 {
                    break;
                }

                let cmd = line.trim();

                if cmd.starts_with("AUTHENTICATE") {
                    if options.reject_auth {
                        let _ = writer.write_all(b"515 Authentication failed\r\n").await;
                    } else {
                        authenticated = true;
                        let _ = writer.write_all(b"250 OK\r\n").await;
                    }
                } else if !authenticated {
                    let _ = writer.write_all(b"514 Authentication required\r\n").await;
                } else if cmd.starts_with("GETINFO status/bootstrap-phase") {
                    let _ = writer.write_all(
                        b"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n",
                    ).await;
                } else if cmd.starts_with("GETINFO status/circuit-established") {
                    let _ = writer
                        .write_all(b"250-status/circuit-established=1\r\n250 OK\r\n")
                        .await;
                } else if cmd.starts_with("GETINFO traffic/read") {
                    let _ = writer
                        .write_all(b"250-traffic/read=1048576\r\n250 OK\r\n")
                        .await;
                } else if cmd.starts_with("GETINFO traffic/written") {
                    let _ = writer
                        .write_all(b"250-traffic/written=524288\r\n250 OK\r\n")
                        .await;
                } else if cmd.starts_with("GETINFO network-liveness") {
                    let _ = writer
                        .write_all(b"250-network-liveness=up\r\n250 OK\r\n")
                        .await;
                } else if cmd.starts_with("GETINFO version") {
                    let _ = writer
                        .write_all(b"250-version=0.4.8.10\r\n250 OK\r\n")
                        .await;
                } else if cmd.starts_with("GETINFO dormant") {
                    let _ = writer.write_all(b"250-dormant=0\r\n250 OK\r\n").await;
                } else if cmd.starts_with("GETINFO net/listeners/socks") {
                    let _ = writer
                        .write_all(b"250-net/listeners/socks=\"127.0.0.1:9050\"\r\n250 OK\r\n")
                        .await;
                } else {
                    let _ = writer.write_all(b"510 Unrecognized command\r\n").await;
                }

                let _ = writer.flush().await;
            }
        });

        Self {
            addr,
            _handle: handle,
        }
    }

    /// Get the address the mock server is listening on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}
