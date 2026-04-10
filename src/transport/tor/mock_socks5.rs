//! Mock SOCKS5 server for testing.
//!
//! Implements just enough of the SOCKS5 protocol (RFC 1928) to support
//! the username/password auth + CONNECT flow used by TorTransport.
//! Proxies bytes bidirectionally between the SOCKS5 client and a real
//! TCP target.

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
/// Accepts a single connection, performs the SOCKS5 handshake (supporting
/// both no-auth and username/password auth), then connects to a fixed
/// target address and proxies bytes bidirectionally.
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

    /// Get the proxy's listen address (for TorConfig.socks5_addr).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Run the proxy, accepting one connection and proxying it.
    ///
    /// Returns a JoinHandle that completes when the proxied connection ends.
    pub fn spawn(mut self) -> JoinHandle<()> {
        let listener = self.listener.take().expect("listener already consumed");
        let target_addr = self.target_addr;

        tokio::spawn(async move {
            // Accept one SOCKS5 client
            let (mut client, _) = listener.accept().await.expect("accept failed");

            // === Method negotiation ===
            // Client sends: [version, nmethods, methods...]
            let mut ver_nmethods = [0u8; 2];
            client
                .read_exact(&mut ver_nmethods)
                .await
                .expect("read version+nmethods");
            assert_eq!(ver_nmethods[0], SOCKS_VERSION, "expected SOCKS5");
            let nmethods = ver_nmethods[1] as usize;

            let mut methods = vec![0u8; nmethods];
            client.read_exact(&mut methods).await.expect("read methods");

            // Prefer username/password auth if offered, fall back to no-auth
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

                // Always accept (Tor uses these as isolation keys, not real auth)
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

            // Read and skip the address (we connect to target_addr regardless)
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

            // Connect to the real target
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

            // Proxy bytes bidirectionally
            let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
        })
    }
}
