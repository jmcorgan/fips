//! TCP Transport Implementation
//!
//! Provides TCP-based transport for FIPS peer communication. TCP enables
//! firewall traversal (many networks allow TCP on port 443 but block UDP)
//! and serves as the foundation for the future Tor transport.
//!
//! FIPS protocols (FMP, FSP, MMP) are all unreliable datagrams. This
//! transport carries those datagrams over TCP — the main pathology is
//! head-of-line blocking, which adds latency jitter that MMP correctly
//! measures and cost-based parent selection correctly penalizes.
//!
//! ## Architecture
//!
//! Unlike UDP (one socket serves all peers), TCP requires one `TcpStream`
//! per peer. The transport maintains a connection pool mapping
//! `TransportAddr` to per-connection state, plus an optional `TcpListener`
//! for inbound connections.
//!
//! ## Framing
//!
//! Uses the existing 4-byte FMP common prefix to recover packet boundaries.
//! No additional framing overhead — packets are written directly to the
//! TCP stream and the receiver uses phase-dependent size computation.

pub mod stream;

use super::{
    DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr, TransportError,
    TransportId, TransportState, TransportType,
};
use crate::config::TcpConfig;
use stream::read_fmp_packet;

use socket2::TcpKeepalive;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info, trace, warn};

// ============================================================================
// Connection Pool
// ============================================================================

/// State for a single TCP connection to a peer.
struct TcpConnection {
    /// Write half of the split stream.
    writer: Arc<Mutex<OwnedWriteHalf>>,
    /// Receive task for this connection.
    recv_task: JoinHandle<()>,
    /// MSS-derived MTU for this connection (used for dynamic MTU re-reading).
    #[allow(dead_code)]
    mtu: u16,
    /// When the connection was established.
    #[allow(dead_code)]
    established_at: Instant,
}

/// Shared connection pool.
type ConnectionPool = Arc<Mutex<HashMap<TransportAddr, TcpConnection>>>;

// ============================================================================
// TCP Transport
// ============================================================================

/// TCP transport for FIPS.
///
/// Provides connection-oriented, reliable byte stream delivery over TCP/IP.
/// Each peer has its own TCP connection; links are managed per-connection
/// with a connection pool keyed by `TransportAddr`.
pub struct TcpTransport {
    /// Unique transport identifier.
    transport_id: TransportId,
    /// Optional instance name (for named instances in config).
    name: Option<String>,
    /// Configuration.
    config: TcpConfig,
    /// Current state.
    state: TransportState,
    /// Connection pool: addr -> per-connection state.
    pool: ConnectionPool,
    /// Channel for delivering received packets to Node.
    packet_tx: PacketTx,
    /// Accept loop task handle (if listener bound).
    accept_task: Option<JoinHandle<()>>,
    /// Local listener address (after start, if bind_addr configured).
    local_addr: Option<SocketAddr>,
}

impl TcpTransport {
    /// Create a new TCP transport.
    pub fn new(
        transport_id: TransportId,
        name: Option<String>,
        config: TcpConfig,
        packet_tx: PacketTx,
    ) -> Self {
        Self {
            transport_id,
            name,
            config,
            state: TransportState::Configured,
            pool: Arc::new(Mutex::new(HashMap::new())),
            packet_tx,
            accept_task: None,
            local_addr: None,
        }
    }

    /// Get the instance name (if configured as a named instance).
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the local listener address (only valid after start with bind_addr).
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Start the transport asynchronously.
    ///
    /// If `bind_addr` is configured, binds a TCP listener and spawns
    /// the accept loop. Otherwise, operates in outbound-only mode.
    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }

        self.state = TransportState::Starting;

        // Bind listener if configured
        if let Some(ref bind_addr) = self.config.bind_addr {
            let addr: SocketAddr = bind_addr
                .parse()
                .map_err(|e| TransportError::StartFailed(format!("invalid bind address: {}", e)))?;

            let listener = TcpListener::bind(addr)
                .await
                .map_err(|e| TransportError::StartFailed(format!("bind failed: {}", e)))?;

            self.local_addr = Some(
                listener
                    .local_addr()
                    .map_err(|e| TransportError::StartFailed(format!("get local addr: {}", e)))?,
            );

            // Spawn accept loop
            let transport_id = self.transport_id;
            let packet_tx = self.packet_tx.clone();
            let pool = self.pool.clone();
            let cfg = AcceptConfig {
                mtu: self.config.mtu(),
                max_inbound: self.config.max_inbound_connections(),
                nodelay: self.config.nodelay(),
                keepalive_secs: self.config.keepalive_secs(),
                recv_buf: self.config.recv_buf_size(),
                send_buf: self.config.send_buf_size(),
            };

            let accept_task = tokio::spawn(async move {
                accept_loop(listener, transport_id, packet_tx, pool, cfg).await;
            });
            self.accept_task = Some(accept_task);
        }

        self.state = TransportState::Up;

        if let Some(ref name) = self.name {
            info!(
                name = %name,
                local_addr = ?self.local_addr,
                mtu = self.config.mtu(),
                "TCP transport started"
            );
        } else {
            info!(
                local_addr = ?self.local_addr,
                mtu = self.config.mtu(),
                "TCP transport started"
            );
        }

        Ok(())
    }

    /// Stop the transport asynchronously.
    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        // Abort accept loop
        if let Some(task) = self.accept_task.take() {
            task.abort();
            let _ = task.await;
        }

        // Close all connections
        let mut pool = self.pool.lock().await;
        for (addr, conn) in pool.drain() {
            conn.recv_task.abort();
            let _ = conn.recv_task.await;
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "TCP connection closed (transport stopping)"
            );
        }
        drop(pool);

        self.local_addr = None;
        self.state = TransportState::Down;

        info!(
            transport_id = %self.transport_id,
            "TCP transport stopped"
        );

        Ok(())
    }

    /// Send a packet asynchronously.
    ///
    /// If no connection exists to the given address, performs connect-on-send:
    /// establishes a new TCP connection, configures socket options, splits the
    /// stream, spawns a receive task, and stores the connection in the pool.
    pub async fn send_async(
        &self,
        addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        // Pre-send MTU check: reject oversize packets before writing them
        // to the TCP stream. Without this, the receiver's FMP stream reader
        // would see payload_len > max and close the connection, causing a
        // disruptive reset-reconnect cycle.
        let mtu = self.config.mtu() as usize;
        if data.len() > mtu {
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu: self.config.mtu(),
            });
        }

        // Get or create connection
        let writer = {
            let pool = self.pool.lock().await;
            pool.get(addr).map(|c| c.writer.clone())
        };

        let writer = match writer {
            Some(w) => w,
            None => {
                // Connect-on-send
                self.connect(addr).await?
            }
        };

        // Write packet directly (no framing transformation needed)
        let mut w = writer.lock().await;
        match w.write_all(data).await {
            Ok(()) => {
                trace!(
                    transport_id = %self.transport_id,
                    remote_addr = %addr,
                    bytes = data.len(),
                    "TCP packet sent"
                );
                Ok(data.len())
            }
            Err(e) => {
                drop(w);
                // Remove failed connection from pool
                let mut pool = self.pool.lock().await;
                if let Some(conn) = pool.remove(addr) {
                    conn.recv_task.abort();
                }
                Err(TransportError::SendFailed(format!("{}", e)))
            }
        }
    }

    /// Establish a new TCP connection to the given address.
    ///
    /// Configures socket options, reads TCP_MAXSEG for MTU, splits the
    /// stream, spawns a receive task, and stores in the pool.
    async fn connect(
        &self,
        addr: &TransportAddr,
    ) -> Result<Arc<Mutex<OwnedWriteHalf>>, TransportError> {
        let socket_addr = parse_socket_addr(addr)?;
        let timeout_ms = self.config.connect_timeout_ms();

        // Connect with timeout
        let stream = tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            TcpStream::connect(socket_addr),
        )
        .await
        .map_err(|_| TransportError::Timeout)?
        .map_err(|_| TransportError::ConnectionRefused)?;

        // Configure socket options via socket2
        let std_stream = stream.into_std()
            .map_err(|e| TransportError::StartFailed(format!("into_std: {}", e)))?;
        configure_socket(&std_stream, &self.config)?;

        // Read TCP_MAXSEG for per-connection MTU
        let mss_mtu = read_mss_mtu(&std_stream, self.config.mtu());

        // Convert back to tokio
        let stream = TcpStream::from_std(std_stream)
            .map_err(|e| TransportError::StartFailed(format!("from_std: {}", e)))?;

        // Split and spawn receive task
        let (read_half, write_half) = stream.into_split();
        let writer = Arc::new(Mutex::new(write_half));

        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let pool = self.pool.clone();
        let remote_addr = addr.clone();
        let mtu = mss_mtu;

        let recv_task = tokio::spawn(async move {
            tcp_receive_loop(read_half, transport_id, remote_addr.clone(), packet_tx, pool, mtu).await;
        });

        let conn = TcpConnection {
            writer: writer.clone(),
            recv_task,
            mtu: mss_mtu,
            established_at: Instant::now(),
        };

        let mut pool = self.pool.lock().await;
        pool.insert(addr.clone(), conn);

        debug!(
            transport_id = %self.transport_id,
            remote_addr = %addr,
            mtu = mss_mtu,
            "TCP connection established (connect-on-send)"
        );

        Ok(writer)
    }

    /// Close a specific connection asynchronously.
    ///
    /// Removes the connection from the pool, aborts its receive task,
    /// and drops the write half (sends FIN to remote).
    pub async fn close_connection_async(&self, addr: &TransportAddr) {
        let mut pool = self.pool.lock().await;
        if let Some(conn) = pool.remove(addr) {
            conn.recv_task.abort();
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "TCP connection closed (close_connection)"
            );
        }
    }
}

impl Transport for TcpTransport {
    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::TCP
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn mtu(&self) -> u16 {
        self.config.mtu()
    }

    fn link_mtu(&self, _addr: &TransportAddr) -> u16 {
        // Per-link MTU would require synchronous pool access.
        // For now, return the configured default. The async send path
        // uses the per-connection MSS-derived MTU for validation.
        self.config.mtu()
    }

    fn start(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use start_async() for TCP transport".into(),
        ))
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use stop_async() for TCP transport".into(),
        ))
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use send_async() for TCP transport".into(),
        ))
    }

    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        // TCP has no discovery mechanism
        Ok(Vec::new())
    }

    fn accept_connections(&self) -> bool {
        // If bind_addr is configured, we accept inbound connections
        self.config.bind_addr.is_some()
    }
}

// ============================================================================
// Accept Loop
// ============================================================================

/// Socket configuration parameters passed to the accept loop.
struct AcceptConfig {
    mtu: u16,
    max_inbound: usize,
    nodelay: bool,
    keepalive_secs: u64,
    recv_buf: usize,
    send_buf: usize,
}

/// TCP accept loop — runs as a spawned task when bind_addr is configured.
#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    listener: TcpListener,
    transport_id: TransportId,
    packet_tx: PacketTx,
    pool: ConnectionPool,
    cfg: AcceptConfig,
) {
    let AcceptConfig { mtu, max_inbound, nodelay, keepalive_secs, recv_buf, send_buf } = cfg;
    debug!(transport_id = %transport_id, "TCP accept loop starting");

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                // Check connection limit
                {
                    let pool_guard = pool.lock().await;
                    if pool_guard.len() >= max_inbound {
                        warn!(
                            transport_id = %transport_id,
                            peer_addr = %peer_addr,
                            max = max_inbound,
                            "Rejecting inbound TCP connection (max_inbound_connections reached)"
                        );
                        continue;
                    }
                }

                // Configure socket options
                let std_stream = match stream.into_std() {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(
                            transport_id = %transport_id,
                            error = %e,
                            "Failed to convert accepted stream to std"
                        );
                        continue;
                    }
                };

                if let Err(e) = configure_accepted_socket(&std_stream, nodelay, keepalive_secs, recv_buf, send_buf) {
                    warn!(
                        transport_id = %transport_id,
                        peer_addr = %peer_addr,
                        error = %e,
                        "Failed to configure accepted socket"
                    );
                    continue;
                }

                // Read MSS for per-connection MTU
                let conn_mtu = read_mss_mtu(&std_stream, mtu);

                let stream = match TcpStream::from_std(std_stream) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(
                            transport_id = %transport_id,
                            error = %e,
                            "Failed to convert accepted stream back to tokio"
                        );
                        continue;
                    }
                };

                let remote_addr = TransportAddr::from_string(&peer_addr.to_string());

                // Split and spawn receive task
                let (read_half, write_half) = stream.into_split();
                let writer = Arc::new(Mutex::new(write_half));

                let recv_pool = pool.clone();
                let recv_packet_tx = packet_tx.clone();
                let recv_addr = remote_addr.clone();

                let recv_task = tokio::spawn(async move {
                    tcp_receive_loop(
                        read_half,
                        transport_id,
                        recv_addr,
                        recv_packet_tx,
                        recv_pool,
                        conn_mtu,
                    )
                    .await;
                });

                let conn = TcpConnection {
                    writer,
                    recv_task,
                    mtu: conn_mtu,
                    established_at: Instant::now(),
                };

                let mut pool_guard = pool.lock().await;
                pool_guard.insert(remote_addr.clone(), conn);

                debug!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    mtu = conn_mtu,
                    "Accepted inbound TCP connection"
                );
            }
            Err(e) => {
                warn!(
                    transport_id = %transport_id,
                    error = %e,
                    "TCP accept error"
                );
            }
        }
    }
}

// ============================================================================
// Receive Loop (per-connection)
// ============================================================================

/// Per-connection TCP receive loop.
///
/// Reads complete FMP packets using the stream reader, delivers them to
/// the node via the packet channel. On error or EOF, removes the
/// connection from the pool and exits.
async fn tcp_receive_loop(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    packet_tx: PacketTx,
    pool: ConnectionPool,
    mtu: u16,
) {
    debug!(
        transport_id = %transport_id,
        remote_addr = %remote_addr,
        "TCP receive loop starting"
    );

    loop {
        match read_fmp_packet(&mut reader, mtu).await {
            Ok(data) => {
                trace!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    bytes = data.len(),
                    "TCP packet received"
                );

                let packet = ReceivedPacket::new(
                    transport_id,
                    remote_addr.clone(),
                    data,
                );

                if packet_tx.send(packet).await.is_err() {
                    info!(
                        transport_id = %transport_id,
                        "Packet channel closed, stopping TCP receive loop"
                    );
                    break;
                }
            }
            Err(e) => {
                // EOF or protocol error — remove connection from pool
                debug!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    error = %e,
                    "TCP receive error, removing connection"
                );
                break;
            }
        }
    }

    // Clean up: remove ourselves from the pool
    let mut pool_guard = pool.lock().await;
    pool_guard.remove(&remote_addr);

    debug!(
        transport_id = %transport_id,
        remote_addr = %remote_addr,
        "TCP receive loop stopped"
    );
}

// ============================================================================
// Socket Configuration Helpers
// ============================================================================

/// Parse a TransportAddr as SocketAddr.
fn parse_socket_addr(addr: &TransportAddr) -> Result<SocketAddr, TransportError> {
    addr.as_str()
        .ok_or_else(|| TransportError::InvalidAddress("not valid UTF-8".into()))?
        .parse()
        .map_err(|e| TransportError::InvalidAddress(format!("{}", e)))
}

/// Configure a TCP socket with the transport's settings.
fn configure_socket(
    stream: &std::net::TcpStream,
    config: &TcpConfig,
) -> Result<(), TransportError> {
    let socket = socket2::SockRef::from(stream).try_clone()
        .map_err(|e| TransportError::StartFailed(format!("clone socket: {}", e)))?;

    // TCP_NODELAY
    socket.set_tcp_nodelay(config.nodelay())
        .map_err(|e| TransportError::StartFailed(format!("set nodelay: {}", e)))?;

    // Keepalive
    let keepalive_secs = config.keepalive_secs();
    if keepalive_secs > 0 {
        let keepalive = TcpKeepalive::new()
            .with_time(Duration::from_secs(keepalive_secs));
        socket.set_tcp_keepalive(&keepalive)
            .map_err(|e| TransportError::StartFailed(format!("set keepalive: {}", e)))?;
    }

    // Buffer sizes
    socket.set_recv_buffer_size(config.recv_buf_size())
        .map_err(|e| TransportError::StartFailed(format!("set recv buffer: {}", e)))?;
    socket.set_send_buffer_size(config.send_buf_size())
        .map_err(|e| TransportError::StartFailed(format!("set send buffer: {}", e)))?;

    Ok(())
}

/// Configure an accepted TCP socket (without TcpConfig reference).
fn configure_accepted_socket(
    stream: &std::net::TcpStream,
    nodelay: bool,
    keepalive_secs: u64,
    recv_buf: usize,
    send_buf: usize,
) -> Result<(), TransportError> {
    let socket = socket2::SockRef::from(stream).try_clone()
        .map_err(|e| TransportError::StartFailed(format!("clone socket: {}", e)))?;

    socket.set_tcp_nodelay(nodelay)
        .map_err(|e| TransportError::StartFailed(format!("set nodelay: {}", e)))?;

    if keepalive_secs > 0 {
        let keepalive = TcpKeepalive::new()
            .with_time(Duration::from_secs(keepalive_secs));
        socket.set_tcp_keepalive(&keepalive)
            .map_err(|e| TransportError::StartFailed(format!("set keepalive: {}", e)))?;
    }

    socket.set_recv_buffer_size(recv_buf)
        .map_err(|e| TransportError::StartFailed(format!("set recv buffer: {}", e)))?;
    socket.set_send_buffer_size(send_buf)
        .map_err(|e| TransportError::StartFailed(format!("set send buffer: {}", e)))?;

    Ok(())
}

/// Read TCP_MAXSEG and derive per-connection MTU, falling back to default.
fn read_mss_mtu(stream: &std::net::TcpStream, default_mtu: u16) -> u16 {
    // Try to read TCP_MAXSEG. Not all platforms support this.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        unsafe {
            let mut mss: libc::c_int = 0;
            let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            let fd = stream.as_raw_fd();
            let ret = libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_MAXSEG,
                &mut mss as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            );
            if ret == 0 && mss > 0 {
                let mss_mtu = (mss as u32).min(u16::MAX as u32) as u16;
                // Use the smaller of MSS and configured default
                return mss_mtu.min(default_mtu);
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    let _ = stream;

    // Fallback: use configured default MTU
    default_mtu
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::packet_channel;
    use tokio::time::{timeout, Duration};

    fn make_config() -> TcpConfig {
        TcpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(1400),
            ..Default::default()
        }
    }

    fn make_outbound_config() -> TcpConfig {
        TcpConfig {
            bind_addr: None,
            mtu: Some(1400),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_start_stop() {
        let (tx, _rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);

        assert_eq!(transport.state(), TransportState::Configured);

        transport.start_async().await.unwrap();
        assert_eq!(transport.state(), TransportState::Up);
        assert!(transport.local_addr().is_some());

        transport.stop_async().await.unwrap();
        assert_eq!(transport.state(), TransportState::Down);
    }

    #[tokio::test]
    async fn test_start_outbound_only() {
        let (tx, _rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx);

        transport.start_async().await.unwrap();
        assert_eq!(transport.state(), TransportState::Up);
        // No listener, so no local_addr
        assert!(transport.local_addr().is_none());

        transport.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn test_double_start_fails() {
        let (tx, _rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);

        transport.start_async().await.unwrap();

        let result = transport.start_async().await;
        assert!(matches!(result, Err(TransportError::AlreadyStarted)));

        transport.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn test_stop_not_started_fails() {
        let (tx, _rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);

        let result = transport.stop_async().await;
        assert!(matches!(result, Err(TransportError::NotStarted)));
    }

    #[tokio::test]
    async fn test_send_not_started() {
        let (tx, _rx) = packet_channel(100);
        let transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);

        let result = transport
            .send_async(&TransportAddr::from_string("127.0.0.1:9999"), b"test")
            .await;

        assert!(matches!(result, Err(TransportError::NotStarted)));
    }

    #[tokio::test]
    async fn test_send_recv() {
        let (tx1, _rx1) = packet_channel(100);
        let (tx2, mut rx2) = packet_channel(100);

        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
        let mut t2 = TcpTransport::new(TransportId::new(2), None, make_config(), tx2);

        t1.start_async().await.unwrap();
        t2.start_async().await.unwrap();

        let addr2 = t2.local_addr().unwrap();

        // Build a valid FMP established frame to send
        // [ver+phase:1][flags:1][payload_len:2 LE][12 bytes header][payload bytes][16 bytes tag]
        let payload_len = 4u16;
        let total = 4 + 12 + payload_len as usize + 16;
        let mut frame = vec![0u8; total];
        frame[0] = 0x00; // ver=0, phase=0 (established)
        frame[1] = 0x00; // flags
        frame[2..4].copy_from_slice(&payload_len.to_le_bytes());
        // Fill the rest with a recognizable pattern
        for i in 4..total {
            frame[i] = (i & 0xFF) as u8;
        }

        let bytes_sent = t1
            .send_async(
                &TransportAddr::from_string(&addr2.to_string()),
                &frame,
            )
            .await
            .unwrap();
        assert_eq!(bytes_sent, frame.len());

        // Receive on t2
        let packet = timeout(Duration::from_secs(2), rx2.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        assert_eq!(packet.data, frame);

        t1.stop_async().await.unwrap();
        t2.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn test_bidirectional() {
        let (tx1, mut rx1) = packet_channel(100);
        let (tx2, mut rx2) = packet_channel(100);

        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_config(), tx1);
        let mut t2 = TcpTransport::new(TransportId::new(2), None, make_config(), tx2);

        t1.start_async().await.unwrap();
        t2.start_async().await.unwrap();

        let addr1 = t1.local_addr().unwrap();
        let addr2 = t2.local_addr().unwrap();

        // Build valid FMP msg1 frame (114 bytes)
        let mut msg1_frame = vec![0xAA; 114];
        msg1_frame[0] = 0x01; // phase=msg1
        msg1_frame[1] = 0x00;
        msg1_frame[2..4].copy_from_slice(&110u16.to_le_bytes()); // payload_len = 110

        // Send from t1 to t2
        t1.send_async(
            &TransportAddr::from_string(&addr2.to_string()),
            &msg1_frame,
        )
        .await
        .unwrap();

        let packet = timeout(Duration::from_secs(2), rx2.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(packet.data, msg1_frame);

        // Build valid FMP msg2 frame (69 bytes)
        let mut msg2_frame = vec![0xBB; 69];
        msg2_frame[0] = 0x02; // phase=msg2
        msg2_frame[1] = 0x00;
        msg2_frame[2..4].copy_from_slice(&65u16.to_le_bytes()); // payload_len = 65

        // Send from t2 to t1
        t2.send_async(
            &TransportAddr::from_string(&addr1.to_string()),
            &msg2_frame,
        )
        .await
        .unwrap();

        let packet = timeout(Duration::from_secs(2), rx1.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(packet.data, msg2_frame);

        t1.stop_async().await.unwrap();
        t2.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn test_connect_timeout() {
        let (tx, _rx) = packet_channel(100);
        let config = TcpConfig {
            bind_addr: None,
            connect_timeout_ms: Some(100), // Very short timeout
            ..Default::default()
        };
        let mut transport = TcpTransport::new(TransportId::new(1), None, config, tx);
        transport.start_async().await.unwrap();

        // Try to connect to a non-routable address (should timeout)
        let result = transport
            .send_async(&TransportAddr::from_string("192.0.2.1:2121"), b"\x00\x00\x04\x00test1234567890123456789012345678")
            .await;

        assert!(result.is_err());

        transport.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn test_close_connection() {
        let (tx1, _rx1) = packet_channel(100);
        let (tx2, _rx2) = packet_channel(100);

        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
        let mut t2 = TcpTransport::new(TransportId::new(2), None, make_config(), tx2);

        t1.start_async().await.unwrap();
        t2.start_async().await.unwrap();

        let addr2 = t2.local_addr().unwrap();
        let remote = TransportAddr::from_string(&addr2.to_string());

        // Build valid msg1 frame to establish connection
        let mut msg1 = vec![0xAA; 114];
        msg1[0] = 0x01;
        msg1[1] = 0x00;
        msg1[2..4].copy_from_slice(&110u16.to_le_bytes());

        t1.send_async(&remote, &msg1).await.unwrap();

        // Connection should exist
        {
            let pool = t1.pool.lock().await;
            assert!(pool.contains_key(&remote));
        }

        // Close it
        t1.close_connection_async(&remote).await;

        // Connection should be gone
        {
            let pool = t1.pool.lock().await;
            assert!(!pool.contains_key(&remote));
        }

        t1.stop_async().await.unwrap();
        t2.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn test_discover_returns_empty() {
        let (tx, _rx) = packet_channel(100);
        let transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);

        let peers = transport.discover().unwrap();
        assert!(peers.is_empty());
    }

    #[test]
    fn test_transport_type() {
        let (tx, _rx) = packet_channel(100);
        let transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);

        assert_eq!(transport.transport_type().name, "tcp");
        assert!(transport.transport_type().connection_oriented);
        assert!(transport.transport_type().reliable);
    }

    #[test]
    fn test_sync_methods_return_not_supported() {
        let (tx, _rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);

        assert!(matches!(
            transport.start(),
            Err(TransportError::NotSupported(_))
        ));
        assert!(matches!(
            transport.stop(),
            Err(TransportError::NotSupported(_))
        ));
        assert!(matches!(
            transport.send(&TransportAddr::from_string("test"), b"data"),
            Err(TransportError::NotSupported(_))
        ));
    }

    #[test]
    fn test_accept_connections_with_bind() {
        let (tx, _rx) = packet_channel(100);
        let config = TcpConfig {
            bind_addr: Some("0.0.0.0:0".to_string()),
            ..Default::default()
        };
        let transport = TcpTransport::new(TransportId::new(1), None, config, tx);
        assert!(transport.accept_connections());
    }

    #[test]
    fn test_accept_connections_without_bind() {
        let (tx, _rx) = packet_channel(100);
        let config = TcpConfig {
            bind_addr: None,
            ..Default::default()
        };
        let transport = TcpTransport::new(TransportId::new(1), None, config, tx);
        assert!(!transport.accept_connections());
    }

    #[tokio::test]
    async fn test_connection_drop_and_reconnect() {
        let (tx1, _rx1) = packet_channel(100);
        let (tx2, mut rx2) = packet_channel(100);

        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
        let mut t2 = TcpTransport::new(TransportId::new(2), None, make_config(), tx2);

        t1.start_async().await.unwrap();
        t2.start_async().await.unwrap();

        let addr2 = t2.local_addr().unwrap();
        let remote = TransportAddr::from_string(&addr2.to_string());

        // Build valid msg1 frame
        let mut msg1 = vec![0xAA; 114];
        msg1[0] = 0x01;
        msg1[1] = 0x00;
        msg1[2..4].copy_from_slice(&110u16.to_le_bytes());

        // First send establishes connection
        t1.send_async(&remote, &msg1).await.unwrap();
        let _ = timeout(Duration::from_secs(1), rx2.recv()).await;

        // Force-close the connection
        t1.close_connection_async(&remote).await;

        // Second send should reconnect (connect-on-send)
        t1.send_async(&remote, &msg1).await.unwrap();

        let packet = timeout(Duration::from_secs(2), rx2.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(packet.data, msg1);

        t1.stop_async().await.unwrap();
        t2.stop_async().await.unwrap();
    }
}
