//! Mock Tor control port server for testing.
//!
//! Implements enough of the Tor control protocol to validate
//! AUTHCHALLENGE, AUTHENTICATE and GETINFO commands.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// The server nonce the mock returns in every AUTHCHALLENGE reply.
const SERVER_NONCE: [u8; 32] = [0x5a; 32];

/// Options for configuring mock behavior.
#[derive(Default)]
pub struct MockOptions {
    /// If true, reject all AUTHENTICATE attempts.
    pub reject_auth: bool,
    /// The cookie the mock holds. With a cookie, the mock answers
    /// `AUTHCHALLENGE SAFECOOKIE` as Tor does and accepts only an
    /// AUTHENTICATE carrying the matching client hash. Without one, it
    /// answers AUTHCHALLENGE with `510` and accepts any AUTHENTICATE.
    pub cookie: Option<[u8; 32]>,
}

/// HMAC-SHA256 under the SAFECOOKIE key named by `direction`, over the
/// cookie and the two nonces. Written out here rather than shared with the
/// client, so a mistake in one does not hide in the other.
fn safecookie_hash(direction: &str, cookie: &[u8], client_nonce: &[u8]) -> [u8; 32] {
    let key = format!("Tor safe cookie authentication {direction} hash");
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("any key length");
    mac.update(cookie);
    mac.update(client_nonce);
    mac.update(&SERVER_NONCE);
    mac.finalize().into_bytes().into()
}

/// A mock Tor control port server.
///
/// Accepts a single client connection and responds to control protocol
/// commands with valid-looking responses for testing.
pub struct MockTorControlServer {
    addr: SocketAddr,
    log: Arc<Mutex<Vec<String>>>,
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
        let log = Arc::new(Mutex::new(Vec::new()));
        let task_log = Arc::clone(&log);

        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            let mut authenticated = false;
            let mut expected_client_hash: Option<String> = None;

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
                task_log.lock().expect("mock log").push(cmd.to_string());

                if let Some(nonce_hex) = cmd.strip_prefix("AUTHCHALLENGE SAFECOOKIE ") {
                    let client_nonce = hex::decode(nonce_hex).unwrap_or_default();
                    let reply = match options.cookie {
                        Some(cookie) if !client_nonce.is_empty() => {
                            let server_hash =
                                safecookie_hash("server-to-controller", &cookie, &client_nonce);
                            let client_hash =
                                safecookie_hash("controller-to-server", &cookie, &client_nonce);
                            expected_client_hash = Some(hex::encode_upper(client_hash));
                            format!(
                                "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                                hex::encode_upper(server_hash),
                                hex::encode_upper(SERVER_NONCE)
                            )
                        }
                        Some(_) => "512 Invalid base16 client nonce\r\n".to_string(),
                        None => "510 Unrecognized command\r\n".to_string(),
                    };
                    let _ = writer.write_all(reply.as_bytes()).await;
                } else if let Some(arg) = cmd.strip_prefix("AUTHENTICATE") {
                    let accepted = match (&options.cookie, &expected_client_hash) {
                        _ if options.reject_auth => false,
                        (None, _) => true,
                        (Some(_), Some(expected)) => arg.trim().eq_ignore_ascii_case(expected),
                        (Some(_), None) => false,
                    };
                    if accepted {
                        authenticated = true;
                        let _ = writer.write_all(b"250 OK\r\n").await;
                    } else {
                        let _ = writer.write_all(b"515 Authentication failed\r\n").await;
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
            log,
            _handle: handle,
        }
    }

    /// Every command line the mock has received so far, trimmed.
    pub fn log(&self) -> Vec<String> {
        self.log.lock().expect("mock log").clone()
    }

    /// Get the address the mock server is listening on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}
