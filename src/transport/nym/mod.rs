//! Nym Mixnet Transport Implementation
//!
//! Provides Nym-based transport for FIPS peer communication using the
//! "Mixnet-As-Proxy" pattern. Traffic is routed through a local
//! nym-socks5-client SOCKS5 proxy into the Nym mixnet, providing
//! anonymity via Sphinx packet routing and timing obfuscation.
//!
//! ## Architecture
//!
//! Outbound-only: connects to remote TCP peers through the local
//! nym-socks5-client SOCKS5 proxy. Like the Tor transport, reuses FMP
//! stream framing from `tcp::stream` and follows the same connection
//! pool pattern. No inbound service is supported.

pub mod stats;

use super::{
    ConnectionState, DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr,
    TransportError, TransportId, TransportState, TransportType,
};
use crate::config::NymConfig;
use crate::transport::tcp::stream::read_fmp_packet;
use stats::NymStats;

use futures::FutureExt;
use socket2::TcpKeepalive;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_socks::tcp::Socks5Stream;
use tracing::{debug, info, trace, warn};

// ============================================================================
// Connection Pool
// ============================================================================

/// State for a single Nym connection to a peer.
struct NymConnection {
    /// Write half of the split stream.
    writer: Arc<Mutex<OwnedWriteHalf>>,
    /// Receive task for this connection.
    recv_task: JoinHandle<()>,
    /// MTU for this connection.
    #[allow(dead_code)]
    mtu: u16,
    /// When the connection was established.
    #[allow(dead_code)]
    established_at: Instant,
}

/// Shared connection pool.
type ConnectionPool = Arc<Mutex<HashMap<TransportAddr, NymConnection>>>;

/// A pending background connection attempt.
struct ConnectingEntry {
    /// Background task performing SOCKS5 connect + socket configuration.
    task: JoinHandle<Result<(TcpStream, u16), TransportError>>,
}

/// Map of addresses with background connection attempts in progress.
type ConnectingPool = Arc<Mutex<HashMap<TransportAddr, ConnectingEntry>>>;

// ============================================================================
// Nym Transport
// ============================================================================

/// Nym mixnet transport for FIPS.
///
/// Provides connection-oriented, reliable byte stream delivery through
/// the Nym mixnet via a local nym-socks5-client SOCKS5 proxy.
/// Outbound-only — no inbound service.
pub struct NymTransport {
    /// Unique transport identifier.
    transport_id: TransportId,
    /// Optional instance name (for named instances in config).
    name: Option<String>,
    /// Configuration.
    config: NymConfig,
    /// Current state.
    state: TransportState,
    /// Connection pool: addr -> per-connection state.
    pool: ConnectionPool,
    /// Pending connection attempts: addr -> background connect task.
    connecting: ConnectingPool,
    /// Channel for delivering received packets to Node.
    packet_tx: PacketTx,
    /// Transport statistics.
    stats: Arc<NymStats>,
}

impl NymTransport {
    /// Create a new Nym transport.
    pub fn new(
        transport_id: TransportId,
        name: Option<String>,
        config: NymConfig,
        packet_tx: PacketTx,
    ) -> Self {
        Self {
            transport_id,
            name,
            config,
            state: TransportState::Configured,
            pool: Arc::new(Mutex::new(HashMap::new())),
            connecting: Arc::new(Mutex::new(HashMap::new())),
            packet_tx,
            stats: Arc::new(NymStats::new()),
        }
    }

    /// Get the instance name (if configured as a named instance).
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the transport statistics.
    pub fn stats(&self) -> &Arc<NymStats> {
        &self.stats
    }

    /// Start the transport asynchronously.
    ///
    /// Validates the SOCKS5 proxy address and transitions to Up.
    /// The nym-socks5-client must already be running and listening
    /// on the configured address.
    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }

        self.state = TransportState::Starting;

        let socks5_addr = self.config.socks5_addr().to_string();
        validate_host_port(&socks5_addr, "socks5_addr")?;

        // Wait for nym-socks5-client to be ready by probing the SOCKS5 port
        let ready = self.wait_for_socks5_ready(&socks5_addr).await;
        if !ready {
            warn!(
                transport_id = %self.transport_id,
                socks5_addr = %socks5_addr,
                "Nym SOCKS5 client not reachable after waiting — starting anyway \
                 (connections will fail until it becomes available)"
            );
        }

        self.state = TransportState::Up;

        if let Some(ref name) = self.name {
            info!(
                name = %name,
                socks5_addr = %socks5_addr,
                mtu = self.config.mtu(),
                "Nym mixnet transport started"
            );
        } else {
            info!(
                socks5_addr = %socks5_addr,
                mtu = self.config.mtu(),
                "Nym mixnet transport started"
            );
        }

        Ok(())
    }

    /// Wait for the nym-socks5-client SOCKS5 proxy to become reachable.
    ///
    /// Probes the TCP port with exponential backoff. Returns true if the
    /// proxy is reachable within the timeout, false otherwise.
    async fn wait_for_socks5_ready(&self, socks5_addr: &str) -> bool {
        let max_wait = Duration::from_secs(self.config.startup_timeout_secs());
        let start = Instant::now();
        let mut delay = Duration::from_secs(1);

        info!(
            transport_id = %self.transport_id,
            socks5_addr = %socks5_addr,
            timeout_secs = max_wait.as_secs(),
            "Waiting for Nym SOCKS5 client to become ready..."
        );

        loop {
            match TcpStream::connect(socks5_addr).await {
                Ok(_) => {
                    info!(
                        transport_id = %self.transport_id,
                        socks5_addr = %socks5_addr,
                        elapsed_secs = start.elapsed().as_secs(),
                        "Nym SOCKS5 client is ready"
                    );
                    return true;
                }
                Err(e) => {
                    if start.elapsed() >= max_wait {
                        warn!(
                            transport_id = %self.transport_id,
                            socks5_addr = %socks5_addr,
                            error = %e,
                            elapsed_secs = start.elapsed().as_secs(),
                            "Nym SOCKS5 client not ready after timeout"
                        );
                        return false;
                    }
                    debug!(
                        transport_id = %self.transport_id,
                        socks5_addr = %socks5_addr,
                        error = %e,
                        retry_in_secs = delay.as_secs(),
                        "Nym SOCKS5 client not ready yet, retrying..."
                    );
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(10));
                }
            }
        }
    }

    /// Stop the transport asynchronously.
    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        // Abort pending connection attempts
        let mut connecting = self.connecting.lock().await;
        for (addr, entry) in connecting.drain() {
            entry.task.abort();
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "Nym connect aborted (transport stopping)"
            );
        }
        drop(connecting);

        // Close all connections
        let mut pool = self.pool.lock().await;
        for (addr, conn) in pool.drain() {
            conn.recv_task.abort();
            let _ = conn.recv_task.await;
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "Nym connection closed (transport stopping)"
            );
        }
        drop(pool);

        self.state = TransportState::Down;

        info!(
            transport_id = %self.transport_id,
            "Nym transport stopped"
        );

        Ok(())
    }

    /// Send a packet asynchronously.
    ///
    /// If no connection exists, performs connect-on-send through the
    /// Nym SOCKS5 proxy.
    pub async fn send_async(
        &self,
        addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        // Pre-send MTU check
        let mtu = self.config.mtu() as usize;
        if data.len() > mtu {
            self.stats.record_mtu_exceeded();
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

        // Write packet
        let mut w = writer.lock().await;
        match w.write_all(data).await {
            Ok(()) => {
                self.stats.record_send(data.len());
                trace!(
                    transport_id = %self.transport_id,
                    remote_addr = %addr,
                    bytes = data.len(),
                    "Nym packet sent"
                );
                Ok(data.len())
            }
            Err(e) => {
                self.stats.record_send_error();
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

    /// Establish a new connection through the Nym SOCKS5 proxy.
    async fn connect(
        &self,
        addr: &TransportAddr,
    ) -> Result<Arc<Mutex<OwnedWriteHalf>>, TransportError> {
        let target_addr = parse_target_addr(addr)?;
        let proxy_addr = self.config.socks5_addr();
        let timeout_ms = self.config.connect_timeout_ms();

        info!(
            transport_id = %self.transport_id,
            remote_addr = %addr,
            proxy = %proxy_addr,
            timeout_secs = timeout_ms / 1000,
            "Connecting via Nym mixnet SOCKS5 proxy"
        );

        let connect_start = Instant::now();
        let socks_result = tokio::time::timeout(Duration::from_millis(timeout_ms), async {
            match target_addr {
                TargetAddr::Ip(socket_addr) => Socks5Stream::connect(proxy_addr, socket_addr).await,
                TargetAddr::Hostname(host, port) => {
                    Socks5Stream::connect(proxy_addr, (host.as_str(), port)).await
                }
            }
        })
        .await;

        let stream = match socks_result {
            Ok(Ok(socks_stream)) => socks_stream.into_inner(),
            Ok(Err(e)) => {
                self.stats.record_socks5_error();
                warn!(
                    transport_id = %self.transport_id,
                    remote_addr = %addr,
                    error = %e,
                    elapsed_secs = connect_start.elapsed().as_secs(),
                    "Nym SOCKS5 connection failed"
                );
                return Err(TransportError::ConnectionRefused);
            }
            Err(_) => {
                self.stats.record_connect_timeout();
                warn!(
                    transport_id = %self.transport_id,
                    remote_addr = %addr,
                    timeout_secs = timeout_ms / 1000,
                    "Nym SOCKS5 connection timed out"
                );
                return Err(TransportError::Timeout);
            }
        };

        // Configure socket options via socket2
        let std_stream = stream
            .into_std()
            .map_err(|e| TransportError::StartFailed(format!("into_std: {}", e)))?;
        configure_socket(&std_stream)?;

        // Convert back to tokio
        let stream = TcpStream::from_std(std_stream)
            .map_err(|e| TransportError::StartFailed(format!("from_std: {}", e)))?;

        // Split and spawn receive task
        let (read_half, write_half) = stream.into_split();
        let writer = Arc::new(Mutex::new(write_half));

        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let pool = self.pool.clone();
        let recv_stats = self.stats.clone();
        let remote_addr = addr.clone();
        let mtu = self.config.mtu();

        let recv_task = tokio::spawn(async move {
            nym_receive_loop(
                read_half,
                transport_id,
                remote_addr.clone(),
                packet_tx,
                pool,
                mtu,
                recv_stats,
            )
            .await;
        });

        let conn = NymConnection {
            writer: writer.clone(),
            recv_task,
            mtu,
            established_at: Instant::now(),
        };

        let mut pool = self.pool.lock().await;
        pool.insert(addr.clone(), conn);

        self.stats.record_connection_established();

        info!(
            transport_id = %self.transport_id,
            remote_addr = %addr,
            elapsed_secs = connect_start.elapsed().as_secs(),
            "Nym mixnet connection established via SOCKS5"
        );

        Ok(writer)
    }

    /// Initiate a non-blocking connection to a remote address.
    pub async fn connect_async(&self, addr: &TransportAddr) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        // Already established?
        {
            let pool = self.pool.lock().await;
            if pool.contains_key(addr) {
                return Ok(());
            }
        }

        // Already connecting?
        {
            let connecting = self.connecting.lock().await;
            if connecting.contains_key(addr) {
                return Ok(());
            }
        }

        let target_addr = parse_target_addr(addr)?;
        let proxy_addr = self.config.socks5_addr().to_string();
        let timeout_ms = self.config.connect_timeout_ms();
        let transport_id = self.transport_id;
        let remote_addr = addr.clone();
        let config = self.config.clone();

        info!(
            transport_id = %transport_id,
            remote_addr = %remote_addr,
            timeout_ms,
            "Initiating background Nym SOCKS5 connect"
        );

        let task = tokio::spawn(async move {
            let connect_start = Instant::now();
            info!(
                transport_id = %transport_id,
                remote_addr = %remote_addr,
                proxy = %proxy_addr,
                timeout_secs = timeout_ms / 1000,
                "Nym SOCKS5 CONNECT starting (this may take several minutes through mixnet)"
            );

            let socks_result = tokio::time::timeout(Duration::from_millis(timeout_ms), async {
                match target_addr {
                    TargetAddr::Ip(socket_addr) => {
                        Socks5Stream::connect(proxy_addr.as_str(), socket_addr).await
                    }
                    TargetAddr::Hostname(host, port) => {
                        Socks5Stream::connect(proxy_addr.as_str(), (host.as_str(), port)).await
                    }
                }
            })
            .await;

            let stream = match socks_result {
                Ok(Ok(socks_stream)) => {
                    info!(
                        transport_id = %transport_id,
                        remote_addr = %remote_addr,
                        elapsed_secs = connect_start.elapsed().as_secs(),
                        "Nym SOCKS5 CONNECT succeeded"
                    );
                    socks_stream.into_inner()
                }
                Ok(Err(e)) => {
                    warn!(
                        transport_id = %transport_id,
                        remote_addr = %remote_addr,
                        error = %e,
                        elapsed_secs = connect_start.elapsed().as_secs(),
                        "Background Nym SOCKS5 connect failed"
                    );
                    return Err(TransportError::ConnectionRefused);
                }
                Err(_) => {
                    warn!(
                        transport_id = %transport_id,
                        remote_addr = %remote_addr,
                        timeout_secs = timeout_ms / 1000,
                        elapsed_secs = connect_start.elapsed().as_secs(),
                        "Background Nym SOCKS5 connect timed out after {}s",
                        connect_start.elapsed().as_secs()
                    );
                    return Err(TransportError::Timeout);
                }
            };

            // Configure socket options via socket2
            let std_stream = stream
                .into_std()
                .map_err(|e| TransportError::StartFailed(format!("into_std: {}", e)))?;
            configure_socket(&std_stream)?;

            let mtu = config.mtu();

            // Convert back to tokio
            let stream = TcpStream::from_std(std_stream)
                .map_err(|e| TransportError::StartFailed(format!("from_std: {}", e)))?;

            Ok((stream, mtu))
        });

        let mut connecting = self.connecting.lock().await;
        connecting.insert(addr.clone(), ConnectingEntry { task });

        Ok(())
    }

    /// Query the state of a connection to a remote address.
    pub fn connection_state_sync(&self, addr: &TransportAddr) -> ConnectionState {
        // Check established pool first
        if let Ok(pool) = self.pool.try_lock() {
            if pool.contains_key(addr) {
                return ConnectionState::Connected;
            }
        } else {
            return ConnectionState::Connecting;
        }

        // Check connecting pool
        let mut connecting = match self.connecting.try_lock() {
            Ok(c) => c,
            Err(_) => return ConnectionState::Connecting,
        };

        let entry = match connecting.get_mut(addr) {
            Some(e) => e,
            None => return ConnectionState::None,
        };

        if !entry.task.is_finished() {
            return ConnectionState::Connecting;
        }

        // Task is done — take the result
        let addr_clone = addr.clone();
        let task = connecting.remove(&addr_clone).unwrap().task;

        match task.now_or_never() {
            Some(Ok(Ok((stream, mtu)))) => {
                self.promote_connection(addr, stream, mtu);
                ConnectionState::Connected
            }
            Some(Ok(Err(e))) => ConnectionState::Failed(format!("{}", e)),
            Some(Err(e)) => ConnectionState::Failed(format!("task failed: {}", e)),
            None => ConnectionState::Connecting,
        }
    }

    /// Promote a completed background connection to the established pool.
    fn promote_connection(&self, addr: &TransportAddr, stream: TcpStream, mtu: u16) {
        let (read_half, write_half) = stream.into_split();
        let writer = Arc::new(Mutex::new(write_half));

        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let pool = self.pool.clone();
        let recv_stats = self.stats.clone();
        let remote_addr = addr.clone();

        let recv_task = tokio::spawn(async move {
            nym_receive_loop(
                read_half,
                transport_id,
                remote_addr.clone(),
                packet_tx,
                pool,
                mtu,
                recv_stats,
            )
            .await;
        });

        let conn = NymConnection {
            writer,
            recv_task,
            mtu,
            established_at: Instant::now(),
        };

        if let Ok(mut pool) = self.pool.try_lock() {
            pool.insert(addr.clone(), conn);
            self.stats.record_connection_established();
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "Nym connection established (background connect)"
            );
        } else {
            conn.recv_task.abort();
            warn!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "Failed to promote Nym connection (pool locked)"
            );
        }
    }

    /// Close a specific connection asynchronously.
    pub async fn close_connection_async(&self, addr: &TransportAddr) {
        let mut pool = self.pool.lock().await;
        if let Some(conn) = pool.remove(addr) {
            conn.recv_task.abort();
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "Nym connection closed"
            );
        }
    }
}

impl Transport for NymTransport {
    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::NYM
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn mtu(&self) -> u16 {
        self.config.mtu()
    }

    fn link_mtu(&self, _addr: &TransportAddr) -> u16 {
        self.config.mtu()
    }

    fn start(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use start_async() for Nym transport".into(),
        ))
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use stop_async() for Nym transport".into(),
        ))
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use send_async() for Nym transport".into(),
        ))
    }

    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        Ok(Vec::new())
    }

    fn accept_connections(&self) -> bool {
        false
    }
}

// ============================================================================
// Address Parsing
// ============================================================================

/// Target address for the SOCKS5 CONNECT request.
#[derive(Clone, Debug)]
enum TargetAddr {
    /// Numeric IP:port.
    Ip(SocketAddr),
    /// Hostname:port (DNS resolved by the exit node).
    Hostname(String, u16),
}

/// Parse a TransportAddr string into a target address.
fn parse_target_addr(addr: &TransportAddr) -> Result<TargetAddr, TransportError> {
    let s = addr.as_str().ok_or_else(|| {
        TransportError::InvalidAddress("Nym address must be a valid UTF-8 string".into())
    })?;

    if let Ok(socket_addr) = s.parse::<SocketAddr>() {
        Ok(TargetAddr::Ip(socket_addr))
    } else {
        let (host, port_str) = s.rsplit_once(':').ok_or_else(|| {
            TransportError::InvalidAddress(format!("invalid address (expected host:port): {}", s))
        })?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| TransportError::InvalidAddress(format!("invalid port: {}", s)))?;
        Ok(TargetAddr::Hostname(host.to_string(), port))
    }
}

// ============================================================================
// Receive Loop (per-connection)
// ============================================================================

/// Per-connection Nym receive loop.
async fn nym_receive_loop(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    packet_tx: PacketTx,
    pool: ConnectionPool,
    mtu: u16,
    stats: Arc<NymStats>,
) {
    debug!(
        transport_id = %transport_id,
        remote_addr = %remote_addr,
        "Nym receive loop starting"
    );

    loop {
        match read_fmp_packet(&mut reader, mtu).await {
            Ok(data) => {
                stats.record_recv(data.len());

                trace!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    bytes = data.len(),
                    "Nym packet received"
                );

                let packet = ReceivedPacket::new(transport_id, remote_addr.clone(), data);

                if packet_tx.send(packet).await.is_err() {
                    debug!(
                        transport_id = %transport_id,
                        "Packet channel closed, stopping Nym receive loop"
                    );
                    break;
                }
            }
            Err(e) => {
                stats.record_recv_error();
                debug!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    error = %e,
                    "Nym receive error, removing connection"
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
        "Nym receive loop stopped"
    );
}

// ============================================================================
// Socket Configuration
// ============================================================================

/// Configure socket options on a SOCKS5-connected stream.
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

// ============================================================================
// Address Validation
// ============================================================================

/// Validate that a string is a valid host:port address.
fn validate_host_port(addr: &str, field: &str) -> Result<(), TransportError> {
    let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(TransportError::InvalidAddress(format!(
            "{} must be host:port, got: {}",
            field, addr
        )));
    }
    let _port: u16 = parts[0].parse().map_err(|_| {
        TransportError::InvalidAddress(format!("{} has invalid port: {}", field, addr))
    })?;
    Ok(())
}
