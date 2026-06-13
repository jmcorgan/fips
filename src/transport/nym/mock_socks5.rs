//! Mock SOCKS5 server for testing the Nym transport's connect path.
//!
//! A copy of the Tor transport's mock, implementing just enough of the
//! SOCKS5 protocol (RFC 1928) to support the no-auth (and, defensively,
//! username/password) CONNECT flow, then proxying bytes bidirectionally to a
//! fixed target.
//!
//! Difference from the Tor mock: this one accepts connections in a loop and
//! handles each on its own task. `NymTransport::start_async` first probes the
//! proxy port for readiness (opening and immediately dropping a connection);
//! looping lets the mock shrug that probe off — its handler returns on the
//! short first read — and still serve the real data connection that follows.

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// SOCKS5 protocol constants.
const SOCKS_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_PASSWORD: u8 = 0x02;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const REP_SUCCESS: u8 = 0x00;

/// Username/password auth sub-negotiation version (RFC 1929).
const AUTH_SUBNEG_VERSION: u8 = 0x01;
const AUTH_SUBNEG_SUCCESS: u8 = 0x00;

/// A minimal mock SOCKS5 proxy server for testing.
///
/// Accepts connections in a loop, performs the SOCKS5 handshake (supporting
/// both no-auth and username/password auth), then connects to a fixed target
/// address and proxies bytes bidirectionally.
pub struct MockSocks5Server {
    /// Address the mock proxy is listening on.
    addr: SocketAddr,
    /// The real target address to connect to (ignores SOCKS5 requested target).
    target_addr: SocketAddr,
    /// Listener handle.
    listener: Option<TcpListener>,
}

impl MockSocks5Server {
    /// Create a new mock SOCKS5 server that forwards to the given target.
    ///
    /// Binds to `127.0.0.1:0` (OS-assigned port).
    pub async fn new(target_addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        Ok(Self {
            addr,
            target_addr,
            listener: Some(listener),
        })
    }

    /// Get the proxy's listen address (for `NymConfig.socks5_addr`).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Run the proxy, accepting connections in a loop and proxying each.
    ///
    /// Returns a JoinHandle for the accept loop.
    pub fn spawn(mut self) -> JoinHandle<()> {
        let listener = self.listener.take().expect("listener already consumed");
        let target_addr = self.target_addr;

        tokio::spawn(async move {
            loop {
                let (client, _) = match listener.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                // Handle each connection independently so the readiness probe
                // (which opens and drops a connection) cannot block the real
                // data connection behind it.
                tokio::spawn(handle_conn(client, target_addr));
            }
        })
    }
}

/// Handle a single accepted connection: SOCKS5 handshake then byte proxy.
async fn handle_conn(mut client: tokio::net::TcpStream, target_addr: SocketAddr) {
    // === Method negotiation ===
    // Client sends: [version, nmethods, methods...]
    let mut ver_nmethods = [0u8; 2];
    if client.read_exact(&mut ver_nmethods).await.is_err() {
        // Readiness probe (or any early close) — nothing to serve.
        return;
    }
    assert_eq!(ver_nmethods[0], SOCKS_VERSION, "expected SOCKS5");
    let nmethods = ver_nmethods[1] as usize;

    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await.expect("read methods");

    // Prefer username/password auth if offered, fall back to no-auth.
    let selected = if methods.contains(&AUTH_PASSWORD) {
        AUTH_PASSWORD
    } else if methods.contains(&AUTH_NONE) {
        AUTH_NONE
    } else {
        panic!("no supported auth method offered");
    };

    // Reply: [version, selected_method]
    client
        .write_all(&[SOCKS_VERSION, selected])
        .await
        .expect("write method reply");

    // === Username/password sub-negotiation (RFC 1929) ===
    if selected == AUTH_PASSWORD {
        // Client sends: [ver(1), ulen(1), uname(ulen), plen(1), passwd(plen)]
        let mut subneg_header = [0u8; 2];
        client
            .read_exact(&mut subneg_header)
            .await
            .expect("read subneg header");
        assert_eq!(
            subneg_header[0], AUTH_SUBNEG_VERSION,
            "expected auth subneg v1"
        );

        let ulen = subneg_header[1] as usize;
        let mut uname = vec![0u8; ulen];
        client.read_exact(&mut uname).await.expect("read username");

        let mut plen_buf = [0u8; 1];
        client.read_exact(&mut plen_buf).await.expect("read plen");
        let plen = plen_buf[0] as usize;
        let mut passwd = vec![0u8; plen];
        client.read_exact(&mut passwd).await.expect("read password");

        client
            .write_all(&[AUTH_SUBNEG_VERSION, AUTH_SUBNEG_SUCCESS])
            .await
            .expect("write subneg reply");
    }

    // === Connect request ===
    // Client sends: [version, cmd, rsv, atyp, addr..., port]
    let mut header = [0u8; 4];
    client
        .read_exact(&mut header)
        .await
        .expect("read connect header");
    assert_eq!(header[0], SOCKS_VERSION);
    assert_eq!(header[1], CMD_CONNECT);

    // Read and skip the address (we connect to target_addr regardless).
    match header[3] {
        ATYP_IPV4 => {
            let mut addr_port = [0u8; 6]; // 4 IP + 2 port
            client
                .read_exact(&mut addr_port)
                .await
                .expect("read IPv4 addr");
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            client
                .read_exact(&mut len_buf)
                .await
                .expect("read domain len");
            let domain_len = len_buf[0] as usize;
            let mut domain_port = vec![0u8; domain_len + 2]; // domain + 2 port
            client
                .read_exact(&mut domain_port)
                .await
                .expect("read domain addr");
        }
        other => panic!("unsupported ATYP: {}", other),
    }

    // Connect to the real target.
    let mut target = tokio::net::TcpStream::connect(target_addr)
        .await
        .expect("connect to target");

    // Reply: success, bind addr = 0.0.0.0:0
    let reply = [
        SOCKS_VERSION,
        REP_SUCCESS,
        0x00, // RSV
        ATYP_IPV4,
        0,
        0,
        0,
        0, // bind addr
        0,
        0, // bind port
    ];
    client.write_all(&reply).await.expect("write connect reply");

    // Proxy bytes bidirectionally.
    let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
}
