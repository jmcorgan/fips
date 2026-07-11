//! Shared SOCKS5 dialer for the proxied (Tor / Nym) transports.
//!
//! Collapses the six near-identical dial cores (nym×3 + tor×3) into one
//! timeout-wrapped, auth-branched SOCKS5 CONNECT followed by socket
//! configuration. The dialer records **no** stats and emits **no** logs —
//! callers classify the returned [`DialError`] (e.g. tor's refused-vs-error
//! split) and do their own logging.

use std::net::SocketAddr;
use std::time::Duration;

use socket2::TcpKeepalive;
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

use crate::transport::TransportError;

/// Target of a SOCKS5 CONNECT request.
///
/// A tor `.onion` host and a clearnet hostname both map to `Hostname` (the
/// proxy / exit resolves it); numeric `IP:port` maps to `Ip`.
#[derive(Clone, Debug)]
pub enum SocksTarget {
    /// Numeric IP:port — dialed as a `SocketAddr`.
    Ip(SocketAddr),
    /// Hostname:port — resolved by the SOCKS5 proxy / exit node.
    Hostname(String, u16),
}

/// SOCKS5 authentication mode for a dial.
#[derive(Clone, Debug)]
pub enum Socks5Auth {
    /// No authentication (nym).
    None,
    /// Username/password auth (tor: `("fips", isolation_key)` for
    /// per-destination circuit isolation via `IsolateSOCKSAuth`).
    Password { username: String, password: String },
}

/// Failure classification returned by [`Socks5Dialer::dial`].
///
/// Carries the raw `tokio_socks::Error` so callers can classify it (tor's
/// `matches!(e, ConnectionRefused)` split) without the dialer recording stats.
pub enum DialError {
    /// The SOCKS5 CONNECT did not complete within the connect timeout.
    Timeout,
    /// The SOCKS5 CONNECT returned an error (refusal, ruleset, I/O, protocol).
    Socks(tokio_socks::Error),
    /// Post-connect socket setup (`into_std` / `configure_socket` / `from_std`)
    /// failed.
    Setup(TransportError),
}

/// Timeout-wrapped, auth-branched SOCKS5 dialer.
///
/// Carries no stats and does no logging — callers classify/record/log.
pub struct Socks5Dialer {
    /// SOCKS5 proxy address (`host:port`).
    pub proxy_addr: String,
    /// Timeout applied to the `Socks5Stream::connect*` call only.
    pub connect_timeout: Duration,
    /// Authentication mode.
    pub auth: Socks5Auth,
}

impl Socks5Dialer {
    /// Perform a timeout-wrapped SOCKS5 CONNECT and configure the socket.
    ///
    /// Only the `Socks5Stream::connect*` call is wrapped in
    /// `tokio::time::timeout`; `into_inner → into_std → configure_socket →
    /// from_std` run **outside** the timeout. Elapsed → [`DialError::Timeout`];
    /// an inner `Err(e)` → [`DialError::Socks`]; setup failures →
    /// [`DialError::Setup`].
    pub async fn dial(&self, target: &SocksTarget) -> Result<TcpStream, DialError> {
        let socks_result = tokio::time::timeout(self.connect_timeout, async {
            match (&self.auth, target) {
                (Socks5Auth::None, SocksTarget::Ip(socket_addr)) => {
                    Socks5Stream::connect(self.proxy_addr.as_str(), *socket_addr).await
                }
                (Socks5Auth::None, SocksTarget::Hostname(host, port)) => {
                    Socks5Stream::connect(self.proxy_addr.as_str(), (host.as_str(), *port)).await
                }
                (Socks5Auth::Password { username, password }, SocksTarget::Ip(socket_addr)) => {
                    Socks5Stream::connect_with_password(
                        self.proxy_addr.as_str(),
                        *socket_addr,
                        username.as_str(),
                        password.as_str(),
                    )
                    .await
                }
                (
                    Socks5Auth::Password { username, password },
                    SocksTarget::Hostname(host, port),
                ) => {
                    Socks5Stream::connect_with_password(
                        self.proxy_addr.as_str(),
                        (host.as_str(), *port),
                        username.as_str(),
                        password.as_str(),
                    )
                    .await
                }
            }
        })
        .await;

        let stream = match socks_result {
            Ok(Ok(socks_stream)) => socks_stream.into_inner(),
            Ok(Err(e)) => return Err(DialError::Socks(e)),
            Err(_) => return Err(DialError::Timeout),
        };

        // Configure socket options via socket2 — OUTSIDE the timeout.
        let std_stream = stream.into_std().map_err(|e| {
            DialError::Setup(TransportError::StartFailed(format!("into_std: {}", e)))
        })?;
        configure_socket(&std_stream).map_err(DialError::Setup)?;

        // Convert back to tokio.
        let stream = TcpStream::from_std(std_stream).map_err(|e| {
            DialError::Setup(TransportError::StartFailed(format!("from_std: {}", e)))
        })?;

        Ok(stream)
    }
}

/// Configure socket options on a SOCKS5-connected stream.
///
/// Sets TCP_NODELAY and a 30 s keepalive on the underlying TCP connection.
fn configure_socket(stream: &std::net::TcpStream) -> Result<(), TransportError> {
    let socket = socket2::SockRef::from(stream);

    // TCP_NODELAY — always enable for FIPS (latency-sensitive protocol messages)
    socket
        .set_tcp_nodelay(true)
        .map_err(|e| TransportError::StartFailed(format!("set nodelay: {}", e)))?;

    // TCP keepalive (30s, matching TCP transport)
    let keepalive = TcpKeepalive::new().with_time(Duration::from_secs(30));
    socket
        .set_tcp_keepalive(&keepalive)
        .map_err(|e| TransportError::StartFailed(format!("set keepalive: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::socks5::mock::MockSocks5Server;

    async fn dest_listener() -> (tokio::net::TcpListener, SocketAddr) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    }

    #[tokio::test]
    async fn test_dial_no_auth_success() {
        let (dest, dest_addr) = dest_listener().await;
        let mock = MockSocks5Server::new(dest_addr).await.unwrap();
        let proxy_addr = mock.addr();
        let _proxy = mock.spawn();

        let dialer = Socks5Dialer {
            proxy_addr: proxy_addr.to_string(),
            connect_timeout: Duration::from_secs(5),
            auth: Socks5Auth::None,
        };

        let result = dialer.dial(&SocksTarget::Ip(dest_addr)).await;
        assert!(result.is_ok(), "no-auth dial should succeed");
        drop(dest);
    }

    #[tokio::test]
    async fn test_dial_password_success() {
        let (dest, dest_addr) = dest_listener().await;
        let mock = MockSocks5Server::new(dest_addr).await.unwrap();
        let proxy_addr = mock.addr();
        let _proxy = mock.spawn();

        let dialer = Socks5Dialer {
            proxy_addr: proxy_addr.to_string(),
            connect_timeout: Duration::from_secs(5),
            auth: Socks5Auth::Password {
                username: "fips".to_string(),
                password: "isolation-key".to_string(),
            },
        };

        // Hostname target exercises the domain ATYP path through the mock.
        let result = dialer
            .dial(&SocksTarget::Hostname("example.com".to_string(), 2121))
            .await;
        assert!(result.is_ok(), "password-auth dial should succeed");
        drop(dest);
    }

    #[tokio::test]
    async fn test_dial_refused_maps_to_socks_error() {
        let dummy: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mock = MockSocks5Server::with_reply_code(dummy, 0x05)
            .await
            .unwrap();
        let proxy_addr = mock.addr();
        let _proxy = mock.spawn();

        let dialer = Socks5Dialer {
            proxy_addr: proxy_addr.to_string(),
            connect_timeout: Duration::from_secs(5),
            auth: Socks5Auth::None,
        };

        let result = dialer.dial(&SocksTarget::Ip(dummy)).await;
        assert!(
            matches!(result, Err(DialError::Socks(_))),
            "refused CONNECT should surface as DialError::Socks carrying the raw error"
        );
    }

    #[tokio::test]
    async fn test_dial_timeout() {
        // 192.0.2.1 is TEST-NET-1: non-routable, so the connect stalls until
        // the short timeout elapses.
        let dialer = Socks5Dialer {
            proxy_addr: "192.0.2.1:9050".to_string(),
            connect_timeout: Duration::from_millis(300),
            auth: Socks5Auth::None,
        };

        let target: SocketAddr = "10.0.0.1:2121".parse().unwrap();
        let result = dialer.dial(&SocksTarget::Ip(target)).await;
        assert!(matches!(result, Err(DialError::Timeout)));
    }
}
