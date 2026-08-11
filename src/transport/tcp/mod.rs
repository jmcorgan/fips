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

mod pool;
pub mod stats;

use super::resolve_socket_addr;
use super::{
    ConnectionState, DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr,
    TransportError, TransportId, TransportState, TransportType,
};
use crate::config::TcpConfig;
use crate::transport::framing::read_fmp_packet;
use pool::{ConnectingEntry, ConnectingPool, ConnectionPool, Direction, TcpConnection};
use stats::TcpStats;

use futures::FutureExt;
use socket2::TcpKeepalive;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info, trace, warn};

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
    /// Connection pool: addr -> established connections.
    pool: ConnectionPool,
    /// Pending connection attempts: addr -> background connect task.
    connecting: ConnectingPool,
    /// Channel for delivering received packets to Node.
    packet_tx: PacketTx,
    /// Accept loop task handle (if listener bound).
    accept_task: Option<JoinHandle<()>>,
    /// Local listener address (after start, if bind_addr configured).
    local_addr: Option<SocketAddr>,
    /// Node-wide `node.limits.max_connections`, used as the inbound cap
    /// fallback when this transport has no explicit `max_inbound_connections`.
    /// `None` means "not provided" — fall through to the built-in default.
    node_max_connections: Option<usize>,
    /// Deadline from accept to the first complete inbound frame. Defaults to
    /// `INBOUND_FIRST_FRAME_TIMEOUT`; overridable only from tests.
    first_frame_timeout: Duration,
    /// Transport statistics.
    stats: Arc<TcpStats>,
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
            connecting: Arc::new(Mutex::new(HashMap::new())),
            packet_tx,
            accept_task: None,
            local_addr: None,
            node_max_connections: None,
            first_frame_timeout: INBOUND_FIRST_FRAME_TIMEOUT,
            stats: Arc::new(TcpStats::new()),
        }
    }

    /// Override the accept-to-first-frame deadline.
    ///
    /// Test-only: the accept loop is reachable from the test module only
    /// through `start_async()`, which reads this field when it builds the
    /// `AcceptConfig`, so there is no other way to drive the deadline at a
    /// duration a unit test can wait for.
    #[cfg(test)]
    pub(crate) fn set_first_frame_timeout(&mut self, d: Duration) {
        self.first_frame_timeout = d;
    }

    /// Set the node-wide `node.limits.max_connections` value.
    ///
    /// Used as the inbound-cap fallback when this transport instance has no
    /// explicit `transports.tcp.*.max_inbound_connections` set, so raising
    /// `node.limits.max_connections` actually raises the per-transport TCP
    /// accept ceiling instead of silently capping at the built-in default.
    pub fn set_node_max_connections(&mut self, max: usize) {
        self.node_max_connections = Some(max);
    }

    /// Resolve the effective inbound connection cap for the accept loop.
    ///
    /// Precedence: explicit per-transport `max_inbound_connections` >
    /// node-wide `node.limits.max_connections` > built-in default. This is a
    /// per-transport *raw-accept* ceiling; the true node-wide peer budget is
    /// still enforced downstream by the handshake-phase `max_connections`
    /// admission check, so deriving this ceiling
    /// from `max_connections` does not let multiple transports exceed the
    /// node-wide total — it only stops the transport from rejecting inbound
    /// below the configured node budget.
    fn effective_max_inbound(&self) -> usize {
        match (
            self.config.max_inbound_connections,
            self.node_max_connections,
        ) {
            // Explicit per-transport key always wins.
            (Some(explicit), _) => explicit,
            // No per-transport key: fall back to the node-wide budget.
            (None, Some(node_max)) => node_max,
            // Neither set: the transport's built-in default (256).
            (None, None) => self.config.max_inbound_connections(),
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

    /// Get the transport statistics.
    pub fn stats(&self) -> &Arc<TcpStats> {
        &self.stats
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
            let stats = self.stats.clone();
            let cfg = AcceptConfig {
                mtu: self.config.mtu(),
                max_inbound: self.effective_max_inbound(),
                nodelay: self.config.nodelay(),
                keepalive_secs: self.config.keepalive_secs(),
                recv_buf: self.config.recv_buf_size(),
                send_buf: self.config.send_buf_size(),
                first_frame_timeout: self.first_frame_timeout,
            };

            let accept_task = tokio::spawn(async move {
                accept_loop(listener, transport_id, packet_tx, pool, cfg, stats).await;
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

        // Abort pending connection attempts
        let mut connecting = self.connecting.lock().await;
        for (addr, entry) in connecting.drain() {
            entry.task.abort();
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "TCP connect aborted (transport stopping)"
            );
        }
        drop(connecting);

        // Close all established connections. The receive-loop cleanup
        // would normally decrement pool_inbound / pool_outbound, but
        // aborting the task skips that path; decrement explicitly here
        // using the direction we stored on the connection record.
        let mut pool = self.pool.lock().await;
        for (addr, conn) in pool.drain() {
            conn.recv_task.abort();
            let _ = conn.recv_task.await;
            match conn.direction {
                Direction::Inbound => self.stats.record_pool_inbound_removed(),
                Direction::Outbound => self.stats.record_pool_outbound_removed(),
            }
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                direction = ?conn.direction,
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

        // Write packet directly (no framing transformation needed)
        let mut w = writer.lock().await;
        match w.write_all(data).await {
            Ok(()) => {
                self.stats.record_send(data.len());
                trace!(
                    transport_id = %self.transport_id,
                    remote_addr = %addr,
                    bytes = data.len(),
                    "TCP packet sent"
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
                    match conn.direction {
                        Direction::Inbound => self.stats.record_pool_inbound_removed(),
                        Direction::Outbound => self.stats.record_pool_outbound_removed(),
                    }
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
        let socket_addr = resolve_socket_addr(addr).await?;
        let timeout_ms = self.config.connect_timeout_ms();

        // Connect with timeout
        let stream = match tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            TcpStream::connect(socket_addr),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(_)) => {
                self.stats.record_connect_refused();
                return Err(TransportError::ConnectionRefused);
            }
            Err(_) => {
                self.stats.record_connect_timeout();
                return Err(TransportError::Timeout);
            }
        };

        // Configure socket options via socket2
        let std_stream = stream
            .into_std()
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
        let recv_stats = self.stats.clone();
        let remote_addr = addr.clone();
        let mtu = mss_mtu;

        let recv_task = tokio::spawn(async move {
            tcp_receive_loop(
                read_half,
                transport_id,
                remote_addr.clone(),
                packet_tx,
                pool,
                mtu,
                recv_stats,
                Direction::Outbound,
                // Outbound connections hold no inbound slot and are not
                // gated on an accept-loop insert.
                None,
                None,
            )
            .await;
        });

        let conn = TcpConnection {
            writer: writer.clone(),
            recv_task,
            mtu: mss_mtu,
            established_at: Instant::now(),
            direction: Direction::Outbound,
        };

        let mut pool = self.pool.lock().await;
        pool.insert(addr.clone(), conn);

        self.stats.record_connection_established();
        self.stats.record_pool_outbound_added();

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
            match conn.direction {
                Direction::Inbound => self.stats.record_pool_inbound_removed(),
                Direction::Outbound => self.stats.record_pool_outbound_removed(),
            }
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                direction = ?conn.direction,
                "TCP connection closed (close_connection)"
            );
        }
    }

    /// Initiate a non-blocking connection to a remote address.
    ///
    /// Spawns a background task that performs TCP connect with timeout,
    /// configures socket options, and reads MSS. The connection becomes
    /// available for `send_async()` once the task completes successfully.
    ///
    /// Poll `connection_state_sync()` to check progress.
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

        // Validate address is UTF-8 before spawning (fail fast on bad input)
        let addr_string = addr
            .as_str()
            .ok_or_else(|| TransportError::InvalidAddress("not valid UTF-8".into()))?
            .to_string();
        let timeout_ms = self.config.connect_timeout_ms();
        let config = self.config.clone();
        let transport_id = self.transport_id;
        let remote_addr = addr.clone();

        debug!(
            transport_id = %transport_id,
            remote_addr = %remote_addr,
            timeout_ms,
            "Initiating background TCP connect"
        );

        let task = tokio::spawn(async move {
            // Resolve address (may involve DNS for hostnames)
            let socket_addr: SocketAddr = if let Ok(sa) = addr_string.parse() {
                sa
            } else {
                tokio::net::lookup_host(&addr_string)
                    .await
                    .map_err(|e| {
                        TransportError::InvalidAddress(format!(
                            "DNS resolution failed for {}: {}",
                            addr_string, e
                        ))
                    })?
                    .next()
                    .ok_or_else(|| {
                        TransportError::InvalidAddress(format!(
                            "DNS resolution returned no addresses for {}",
                            addr_string
                        ))
                    })?
            };

            // Connect with timeout
            let stream = match tokio::time::timeout(
                Duration::from_millis(timeout_ms),
                TcpStream::connect(socket_addr),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    debug!(
                        transport_id = %transport_id,
                        remote_addr = %remote_addr,
                        error = %e,
                        "Background TCP connect refused"
                    );
                    return Err(TransportError::ConnectionRefused);
                }
                Err(_) => {
                    debug!(
                        transport_id = %transport_id,
                        remote_addr = %remote_addr,
                        "Background TCP connect timed out"
                    );
                    return Err(TransportError::Timeout);
                }
            };

            // Configure socket options via socket2
            let std_stream = stream
                .into_std()
                .map_err(|e| TransportError::StartFailed(format!("into_std: {}", e)))?;
            configure_socket(&std_stream, &config)?;

            // Read TCP_MAXSEG for per-connection MTU
            let mss_mtu = read_mss_mtu(&std_stream, config.mtu());

            // Convert back to tokio
            let stream = TcpStream::from_std(std_stream)
                .map_err(|e| TransportError::StartFailed(format!("from_std: {}", e)))?;

            Ok((stream, mss_mtu))
        });

        let mut connecting = self.connecting.lock().await;
        connecting.insert(addr.clone(), ConnectingEntry { task });

        Ok(())
    }

    /// Query the state of a connection to a remote address.
    ///
    /// Checks both established and connecting pools. If a background
    /// connect task has completed, promotes it to the established pool
    /// (spawning a receive loop) or reports the failure.
    ///
    /// This method is synchronous but uses `try_lock` internally.
    /// Returns `ConnectionState::Connecting` if locks can't be acquired.
    pub fn connection_state_sync(&self, addr: &TransportAddr) -> ConnectionState {
        // Check established pool first
        if let Ok(pool) = self.pool.try_lock() {
            if pool.contains_key(addr) {
                return ConnectionState::Connected;
            }
        } else {
            return ConnectionState::Connecting; // can't tell, assume still going
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

        // Check if the background task has completed
        if !entry.task.is_finished() {
            return ConnectionState::Connecting;
        }

        // Task is done — take the result and remove from connecting pool.
        // We need to poll the finished task. Since it's finished, we use
        // now_or_never to get the result without blocking.
        let addr_clone = addr.clone();
        let task = connecting.remove(&addr_clone).unwrap().task;

        // Use futures::FutureExt::now_or_never or block_on for the finished task.
        // Since the task is finished, we can safely poll it.
        match task.now_or_never() {
            Some(Ok(Ok((stream, mss_mtu)))) => {
                // Promote to established pool
                self.promote_connection(addr, stream, mss_mtu);
                ConnectionState::Connected
            }
            Some(Ok(Err(e))) => ConnectionState::Failed(format!("{}", e)),
            Some(Err(e)) => {
                // JoinError (panic or cancel)
                ConnectionState::Failed(format!("task failed: {}", e))
            }
            None => {
                // Shouldn't happen since is_finished() was true
                ConnectionState::Connecting
            }
        }
    }

    /// Promote a completed background connection to the established pool.
    ///
    /// Splits the stream, spawns a receive loop, and inserts into the pool.
    /// Called from `connection_state_sync()` when a background task completes.
    fn promote_connection(&self, addr: &TransportAddr, stream: TcpStream, mss_mtu: u16) {
        let (read_half, write_half) = stream.into_split();
        let writer = Arc::new(Mutex::new(write_half));

        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let pool = self.pool.clone();
        let recv_stats = self.stats.clone();
        let remote_addr = addr.clone();

        let recv_task = tokio::spawn(async move {
            tcp_receive_loop(
                read_half,
                transport_id,
                remote_addr.clone(),
                packet_tx,
                pool,
                mss_mtu,
                recv_stats,
                Direction::Outbound,
                // Outbound connections hold no inbound slot and are not
                // gated on an accept-loop insert.
                None,
                None,
            )
            .await;
        });

        let conn = TcpConnection {
            writer,
            recv_task,
            mtu: mss_mtu,
            established_at: Instant::now(),
            direction: Direction::Outbound,
        };

        // Use try_lock since we're in a sync context and the pool
        // should be available (connection_state_sync already checked it)
        if let Ok(mut pool) = self.pool.try_lock() {
            pool.insert(addr.clone(), conn);
            self.stats.record_connection_established();
            self.stats.record_pool_outbound_added();
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                mtu = mss_mtu,
                "TCP connection established (background connect)"
            );
        } else {
            // Pool locked — abort the recv task, connection will be retried
            conn.recv_task.abort();
            warn!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "Failed to promote connection (pool locked)"
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

/// Deadline from accept to the first complete inbound FMP frame.
///
/// An accepted socket takes an inbound pool slot before any byte is read,
/// so without a deadline a remote that connects and stays silent holds
/// that slot for as long as it keeps the socket open. The node-layer
/// reaper cannot see such a socket: no frame means no link and no node
/// state to time out. The value matches the node-layer handshake reaper
/// (`handshake_timeout_secs`, `src/config/node.rs:101`), so a peer that
/// misses this deadline would have been reaped node-side anyway.
///
/// Deliberately not a config key: `maint` takes no new operator-facing
/// TOML surface.
pub(crate) const INBOUND_FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(30);

/// Socket configuration parameters passed to the accept loop.
struct AcceptConfig {
    mtu: u16,
    max_inbound: usize,
    nodelay: bool,
    keepalive_secs: u64,
    recv_buf: usize,
    send_buf: usize,
    first_frame_timeout: Duration,
}

/// TCP accept loop — runs as a spawned task when bind_addr is configured.
#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    listener: TcpListener,
    transport_id: TransportId,
    packet_tx: PacketTx,
    pool: ConnectionPool,
    cfg: AcceptConfig,
    stats: Arc<TcpStats>,
) {
    let AcceptConfig {
        mtu,
        max_inbound,
        nodelay,
        keepalive_secs,
        recv_buf,
        send_buf,
        first_frame_timeout,
    } = cfg;
    debug!(transport_id = %transport_id, "TCP accept loop starting");

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                // Check inbound connection cap. Counts only inbound (accepted)
                // connections currently held in the pool; outbound (connect-on-send)
                // connections live in the same pool but are not subject to the
                // operator-facing inbound cap.
                if stats.pool_inbound_count() >= max_inbound as u64 {
                    stats.record_connection_rejected();
                    debug!(
                        transport_id = %transport_id,
                        peer_addr = %peer_addr,
                        max = max_inbound,
                        "Rejecting inbound TCP connection (max_inbound_connections reached)"
                    );
                    continue;
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

                if let Err(e) = configure_accepted_socket(
                    &std_stream,
                    nodelay,
                    keepalive_secs,
                    recv_buf,
                    send_buf,
                ) {
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
                let recv_stats = stats.clone();
                let recv_addr = remote_addr.clone();

                // Readiness barrier: the receive task must not reach its
                // cleanup path before the pool insert and counter bump below,
                // or it would remove nothing and leave an orphaned entry with
                // a permanently incremented inbound counter.
                let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

                let recv_task = tokio::spawn(async move {
                    tcp_receive_loop(
                        read_half,
                        transport_id,
                        recv_addr,
                        recv_packet_tx,
                        recv_pool,
                        conn_mtu,
                        recv_stats,
                        Direction::Inbound,
                        Some(first_frame_timeout),
                        Some(ready_rx),
                    )
                    .await;
                });

                let conn = TcpConnection {
                    writer,
                    recv_task,
                    mtu: conn_mtu,
                    established_at: Instant::now(),
                    direction: Direction::Inbound,
                };

                let mut pool_guard = pool.lock().await;
                pool_guard.insert(remote_addr.clone(), conn);
                drop(pool_guard);

                stats.record_connection_accepted();
                stats.record_pool_inbound_added();

                // Release the receive task now that both the pool entry and
                // the inbound counter are in place.
                let _ = ready_tx.send(());

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
/// connection from the pool and exits. `direction` is captured here so
/// the cleanup path can decrement the correct `pool_inbound` /
/// `pool_outbound` counter regardless of whether the matching pool
/// entry survived to be removed.
///
/// `first_frame_timeout` bounds the wait for the *first* complete frame
/// only, and is `Some` for inbound connections (which hold a capped pool
/// slot from accept) and `None` for outbound ones. `ready_rx`, when
/// present, is the accept loop's readiness barrier: the loop must not run
/// its cleanup before the accept loop has inserted the pool entry.
#[allow(clippy::too_many_arguments)]
async fn tcp_receive_loop(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    packet_tx: PacketTx,
    pool: ConnectionPool,
    mtu: u16,
    stats: Arc<TcpStats>,
    direction: Direction,
    first_frame_timeout: Option<Duration>,
    ready_rx: Option<tokio::sync::oneshot::Receiver<()>>,
) {
    debug!(
        transport_id = %transport_id,
        remote_addr = %remote_addr,
        "TCP receive loop starting"
    );

    // An `Err` here means the accept loop went away between the insert and
    // the signal. Fall through to the cleanup below rather than returning,
    // so a pooled entry cannot be stranded with the counter incremented.
    let admitted = match ready_rx {
        Some(rx) => rx.await.is_ok(),
        None => true,
    };

    if admitted {
        let mut first = true;
        loop {
            let read = match first_frame_timeout {
                // Bound the first read only. A silent remote otherwise holds
                // its inbound slot for as long as it keeps the socket open.
                Some(d) if first => {
                    match tokio::time::timeout(d, read_fmp_packet(&mut reader, mtu)).await {
                        Ok(result) => result,
                        Err(_) => {
                            // Not a recv error: `record_recv_error` means
                            // framing or I/O failure, and folding deadline
                            // expiries into it corrupts that counter.
                            debug!(
                                transport_id = %transport_id,
                                remote_addr = %remote_addr,
                                timeout_secs = d.as_secs_f64(),
                                "No complete frame within the first-frame deadline, dropping inbound connection"
                            );
                            break;
                        }
                    }
                }
                _ => read_fmp_packet(&mut reader, mtu).await,
            };
            first = false;

            match read {
                Ok(data) => {
                    stats.record_recv(data.len());

                    trace!(
                        transport_id = %transport_id,
                        remote_addr = %remote_addr,
                        bytes = data.len(),
                        "TCP packet received"
                    );

                    let packet = ReceivedPacket::new(transport_id, remote_addr.clone(), data);

                    if packet_tx.send(packet).await.is_err() {
                        debug!(
                            transport_id = %transport_id,
                            "Packet channel closed, stopping TCP receive loop"
                        );
                        break;
                    }
                }
                Err(e) => {
                    stats.record_recv_error();
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
    }

    // Clean up: remove ourselves from the pool, then decrement the
    // direction-specific pool counter. Decrement is conditional on the
    // entry actually being removed so a double-cleanup never drives
    // the counter below zero.
    let mut pool_guard = pool.lock().await;
    let removed = pool_guard.remove(&remote_addr).is_some();
    drop(pool_guard);
    if removed {
        match direction {
            Direction::Inbound => stats.record_pool_inbound_removed(),
            Direction::Outbound => stats.record_pool_outbound_removed(),
        }
    }

    debug!(
        transport_id = %transport_id,
        remote_addr = %remote_addr,
        direction = ?direction,
        "TCP receive loop stopped"
    );
}

// ============================================================================
// Socket Configuration Helpers
// ============================================================================

/// Configure a TCP socket with the transport's settings.
fn configure_socket(
    stream: &std::net::TcpStream,
    config: &TcpConfig,
) -> Result<(), TransportError> {
    let socket = socket2::SockRef::from(stream)
        .try_clone()
        .map_err(|e| TransportError::StartFailed(format!("clone socket: {}", e)))?;

    // TCP_NODELAY
    socket
        .set_tcp_nodelay(config.nodelay())
        .map_err(|e| TransportError::StartFailed(format!("set nodelay: {}", e)))?;

    // Keepalive
    let keepalive_secs = config.keepalive_secs();
    if keepalive_secs > 0 {
        let keepalive = TcpKeepalive::new().with_time(Duration::from_secs(keepalive_secs));
        socket
            .set_tcp_keepalive(&keepalive)
            .map_err(|e| TransportError::StartFailed(format!("set keepalive: {}", e)))?;
    }

    // Buffer sizes
    socket
        .set_recv_buffer_size(config.recv_buf_size())
        .map_err(|e| TransportError::StartFailed(format!("set recv buffer: {}", e)))?;
    socket
        .set_send_buffer_size(config.send_buf_size())
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
    let socket = socket2::SockRef::from(stream)
        .try_clone()
        .map_err(|e| TransportError::StartFailed(format!("clone socket: {}", e)))?;

    socket
        .set_tcp_nodelay(nodelay)
        .map_err(|e| TransportError::StartFailed(format!("set nodelay: {}", e)))?;

    if keepalive_secs > 0 {
        let keepalive = TcpKeepalive::new().with_time(Duration::from_secs(keepalive_secs));
        socket
            .set_tcp_keepalive(&keepalive)
            .map_err(|e| TransportError::StartFailed(format!("set keepalive: {}", e)))?;
    }

    socket
        .set_recv_buffer_size(recv_buf)
        .map_err(|e| TransportError::StartFailed(format!("set recv buffer: {}", e)))?;
    socket
        .set_send_buffer_size(send_buf)
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
    use crate::transport::framing::build_msg1_frame;
    use crate::transport::packet_channel;
    use tokio::time::{Duration, timeout};

    /// Poll `f` every 10ms until it holds or `limit` elapses.
    async fn wait_until<F: FnMut() -> bool>(mut f: F, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        loop {
            if f() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn capped_config(max_inbound: usize) -> TcpConfig {
        TcpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(1400),
            max_inbound_connections: Some(max_inbound),
            ..Default::default()
        }
    }

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
        let mut transport =
            TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx);

        transport.start_async().await.unwrap();
        assert_eq!(transport.state(), TransportState::Up);
        // No listener, so no local_addr
        assert!(transport.local_addr().is_none());

        transport.stop_async().await.unwrap();
    }

    #[test]
    fn effective_max_inbound_precedence() {
        let (tx, _rx) = packet_channel(100);

        // Neither set: built-in transport default (256).
        let t = TcpTransport::new(TransportId::new(1), None, make_config(), tx.clone());
        assert_eq!(t.effective_max_inbound(), 256);

        // Node-wide max_connections drives the cap when no per-transport key.
        let mut t = TcpTransport::new(TransportId::new(1), None, make_config(), tx.clone());
        t.set_node_max_connections(512);
        assert_eq!(t.effective_max_inbound(), 512);

        // Explicit per-transport key wins over the node-wide value.
        let cfg = TcpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            max_inbound_connections: Some(64),
            ..Default::default()
        };
        let mut t = TcpTransport::new(TransportId::new(1), None, cfg, tx);
        t.set_node_max_connections(512);
        assert_eq!(t.effective_max_inbound(), 64);
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
        frame[0] = 0x10; // ver=1, phase=0 (established)
        frame[1] = 0x00; // flags
        frame[2..4].copy_from_slice(&payload_len.to_le_bytes());
        // Fill the rest with a recognizable pattern
        for (i, byte) in frame[4..total].iter_mut().enumerate() {
            *byte = ((4 + i) & 0xFF) as u8;
        }

        let bytes_sent = t1
            .send_async(&TransportAddr::from_string(&addr2.to_string()), &frame)
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
        let mut msg1_frame = vec![0xAA; 41];
        msg1_frame[0] = 0x11; // ver=1, phase=msg1
        msg1_frame[1] = 0x00;
        msg1_frame[2..4].copy_from_slice(&37u16.to_le_bytes()); // payload_len = 37

        // Send from t1 to t2
        t1.send_async(&TransportAddr::from_string(&addr2.to_string()), &msg1_frame)
            .await
            .unwrap();

        let packet = timeout(Duration::from_secs(2), rx2.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(packet.data, msg1_frame);

        // Build valid FMP msg2 frame (69 bytes)
        let mut msg2_frame = vec![0xBB; 118];
        msg2_frame[0] = 0x12; // ver=1, phase=msg2
        msg2_frame[1] = 0x00;
        msg2_frame[2..4].copy_from_slice(&114u16.to_le_bytes()); // payload_len = 114

        // Send from t2 to t1
        t2.send_async(&TransportAddr::from_string(&addr1.to_string()), &msg2_frame)
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
            .send_async(
                &TransportAddr::from_string("192.0.2.1:2121"),
                b"\x00\x00\x04\x00test1234567890123456789012345678",
            )
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
        let mut msg1 = vec![0xAA; 41];
        msg1[0] = 0x11;
        msg1[1] = 0x00;
        msg1[2..4].copy_from_slice(&37u16.to_le_bytes());

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
        let mut msg1 = vec![0xAA; 41];
        msg1[0] = 0x11;
        msg1[1] = 0x00;
        msg1[2..4].copy_from_slice(&37u16.to_le_bytes());

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

    #[tokio::test]
    async fn test_connect_async_success() {
        let (tx1, mut rx1) = packet_channel(100);
        let (tx2, _rx2) = packet_channel(100);

        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
        let mut t2 = TcpTransport::new(TransportId::new(2), None, make_config(), tx2);

        t1.start_async().await.unwrap();
        t2.start_async().await.unwrap();

        let addr2 = t2.local_addr().unwrap();
        let remote = TransportAddr::from_string(&addr2.to_string());

        // State should be None before connect
        assert_eq!(t1.connection_state_sync(&remote), ConnectionState::None);

        // Initiate non-blocking connect
        t1.connect_async(&remote).await.unwrap();

        // Wait for the background connect to complete
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Poll state — should be Connected now
        let state = t1.connection_state_sync(&remote);
        assert_eq!(state, ConnectionState::Connected);

        // Now send should work (connection already established)
        let mut msg1 = vec![0xAA; 41];
        msg1[0] = 0x11;
        msg1[1] = 0x00;
        msg1[2..4].copy_from_slice(&37u16.to_le_bytes());

        t1.send_async(&remote, &msg1).await.unwrap();

        let packet = timeout(Duration::from_secs(2), rx1.recv()).await;
        // We receive on rx1 but that's the wrong receiver — t2's rx gets the packet
        // Just verify send didn't error
        drop(packet);

        t1.stop_async().await.unwrap();
        t2.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn test_connect_async_timeout() {
        let (tx, _rx) = packet_channel(100);
        let config = TcpConfig {
            bind_addr: None,
            connect_timeout_ms: Some(100), // Very short timeout
            ..Default::default()
        };
        let mut transport = TcpTransport::new(TransportId::new(1), None, config, tx);
        transport.start_async().await.unwrap();

        let remote = TransportAddr::from_string("192.0.2.1:2121");
        transport.connect_async(&remote).await.unwrap();

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(500)).await;

        let state = transport.connection_state_sync(&remote);
        assert!(matches!(state, ConnectionState::Failed(_)));

        transport.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn test_connect_async_not_started() {
        let (tx, _rx) = packet_channel(100);
        let transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);

        let result = transport
            .connect_async(&TransportAddr::from_string("127.0.0.1:9999"))
            .await;

        assert!(matches!(result, Err(TransportError::NotStarted)));
    }

    #[tokio::test]
    async fn test_connect_async_already_connected() {
        let (tx1, _rx1) = packet_channel(100);
        let (tx2, _rx2) = packet_channel(100);

        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
        let mut t2 = TcpTransport::new(TransportId::new(2), None, make_config(), tx2);

        t1.start_async().await.unwrap();
        t2.start_async().await.unwrap();

        let addr2 = t2.local_addr().unwrap();
        let remote = TransportAddr::from_string(&addr2.to_string());

        // Connect first time
        t1.connect_async(&remote).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            t1.connection_state_sync(&remote),
            ConnectionState::Connected
        );

        // Second connect should be a no-op (already connected)
        t1.connect_async(&remote).await.unwrap();

        t1.stop_async().await.unwrap();
        t2.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn test_connect_async_then_send_recv() {
        let (tx1, _rx1) = packet_channel(100);
        let (tx2, mut rx2) = packet_channel(100);

        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
        let mut t2 = TcpTransport::new(TransportId::new(2), None, make_config(), tx2);

        t1.start_async().await.unwrap();
        t2.start_async().await.unwrap();

        let addr2 = t2.local_addr().unwrap();
        let remote = TransportAddr::from_string(&addr2.to_string());

        // Connect first, then send
        t1.connect_async(&remote).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            t1.connection_state_sync(&remote),
            ConnectionState::Connected
        );

        // Build valid FMP msg1 frame
        let mut msg1 = vec![0xAA; 41];
        msg1[0] = 0x11;
        msg1[1] = 0x00;
        msg1[2..4].copy_from_slice(&37u16.to_le_bytes());

        // Send using the pre-established connection
        t1.send_async(&remote, &msg1).await.unwrap();

        let packet = timeout(Duration::from_secs(2), rx2.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(packet.data, msg1);

        t1.stop_async().await.unwrap();
        t2.stop_async().await.unwrap();
    }

    #[test]
    fn test_connection_state_none_for_unknown() {
        let (tx, _rx) = packet_channel(100);
        let transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);

        let state = transport.connection_state_sync(&TransportAddr::from_string("unknown:1234"));
        assert_eq!(state, ConnectionState::None);
    }

    #[tokio::test]
    async fn test_connect_ip_string() {
        let (tx1, _rx1) = packet_channel(100);
        let (tx2, mut rx2) = packet_channel(100);

        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_config(), tx1);
        let mut t2 = TcpTransport::new(
            TransportId::new(2),
            None,
            TcpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            tx2,
        );

        t1.start_async().await.unwrap();
        t2.start_async().await.unwrap();

        let port2 = t2.local_addr().unwrap().port();

        // Connect using IP string — build a valid FMP frame (114 bytes)
        let addr = TransportAddr::from_string(&format!("127.0.0.1:{}", port2));
        let mut frame = vec![0xAA; 41];
        frame[0] = 0x11; // ver=1, phase=1
        frame[1] = 0x00; // flags
        frame[2..4].copy_from_slice(&37u16.to_le_bytes()); // payload_len
        t1.send_async(&addr, &frame).await.unwrap();

        // Receive on t2
        let packet = tokio::time::timeout(Duration::from_secs(5), rx2.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        assert_eq!(packet.data, frame);

        t1.stop_async().await.unwrap();
        t2.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn test_connect_async_ip_string() {
        let (tx1, _rx1) = packet_channel(100);
        let (tx2, _rx2) = packet_channel(100);

        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_config(), tx1);
        let mut t2 = TcpTransport::new(
            TransportId::new(2),
            None,
            TcpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            tx2,
        );

        t1.start_async().await.unwrap();
        t2.start_async().await.unwrap();

        let port2 = t2.local_addr().unwrap().port();
        let addr = TransportAddr::from_string(&format!("127.0.0.1:{}", port2));

        // Non-blocking connect via IP string
        t1.connect_async(&addr).await.unwrap();

        // Poll until connected
        for _ in 0..50 {
            let state = t1.connection_state_sync(&addr);
            if state == ConnectionState::Connected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        assert_eq!(t1.connection_state_sync(&addr), ConnectionState::Connected,);

        t1.stop_async().await.unwrap();
        t2.stop_async().await.unwrap();
    }

    // ========================================================================
    // Inbound first-frame deadline
    // ========================================================================

    /// A socket that connects and sends nothing must have its inbound slot
    /// released by the first-frame deadline.
    ///
    /// Break-check: with the `tokio::time::timeout` wrapper removed from the
    /// first read, the socket parks on an unbounded `read_exact` and the
    /// count stays at 1 for as long as the peer keeps the socket open, so
    /// the second assertion fails.
    #[tokio::test]
    async fn idle_inbound_socket_releases_its_slot() {
        let (tx, _rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);
        transport.set_first_frame_timeout(Duration::from_millis(200));
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();

        // Connect and say nothing. Held open for the whole test so that any
        // slot release is the deadline's doing and not a client disconnect.
        let squatter = TcpStream::connect(listen).await.unwrap();

        assert!(
            wait_until(
                || transport.stats().pool_inbound_count() == 1,
                Duration::from_secs(2)
            )
            .await,
            "an accepted socket should take an inbound slot"
        );
        assert!(
            wait_until(
                || transport.stats().pool_inbound_count() == 0,
                Duration::from_secs(2)
            )
            .await,
            "a silent inbound socket should lose its slot at the first-frame deadline"
        );
        assert!(
            transport.pool.lock().await.is_empty(),
            "the pool entry should go with the slot"
        );

        drop(squatter);
        transport.stop_async().await.unwrap();
    }

    /// With the cap filled by a silent socket, a genuine peer is refused
    /// until the deadline frees the slot, and admitted afterwards.
    ///
    /// Break-check: without the deadline the squatter never releases, so the
    /// genuine peer's frame is never delivered and the final receive times
    /// out.
    #[tokio::test]
    async fn inbound_cap_recovers_after_first_frame_deadline() {
        let (tx, mut rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, capped_config(1), tx);
        transport.set_first_frame_timeout(Duration::from_millis(300));
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();

        let squatter = TcpStream::connect(listen).await.unwrap();
        assert!(
            wait_until(
                || transport.stats().pool_inbound_count() == 1,
                Duration::from_secs(2)
            )
            .await,
            "the squatter should fill the cap of one"
        );

        // While the cap is full a genuine peer is rejected outright.
        let mut early = TcpStream::connect(listen).await.unwrap();
        let _ = early.write_all(&build_msg1_frame()).await;
        assert!(
            timeout(Duration::from_millis(200), rx.recv())
                .await
                .is_err(),
            "a peer arriving while the cap is full must not be admitted"
        );
        drop(early);

        // The deadline frees the slot without the squatter disconnecting.
        assert!(
            wait_until(
                || transport.stats().pool_inbound_count() == 0,
                Duration::from_secs(2)
            )
            .await,
            "the deadline should free the slot the squatter took"
        );

        let mut genuine = TcpStream::connect(listen).await.unwrap();
        genuine.write_all(&build_msg1_frame()).await.unwrap();
        let packet = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for the genuine peer's frame")
            .expect("packet channel closed");
        assert_eq!(packet.data, build_msg1_frame());

        drop(squatter);
        drop(genuine);
        transport.stop_async().await.unwrap();
    }

    /// Regression guard, not evidence that the fix works.
    ///
    /// The deadline is scoped to the first iteration, so an established
    /// connection that then goes quiet cannot be dropped by it: this test
    /// passes by construction under the current design. It is kept so that a
    /// future general (every-read) idle deadline cannot silently start
    /// reaping quiet links without a test going red.
    #[tokio::test]
    async fn established_connection_survives_long_idle() {
        let (tx, mut rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);
        transport.set_first_frame_timeout(Duration::from_millis(200));
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();

        let mut peer = TcpStream::connect(listen).await.unwrap();
        peer.write_all(&build_msg1_frame()).await.unwrap();
        let packet = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout")
            .expect("packet channel closed");
        assert_eq!(packet.data, build_msg1_frame());

        // Four deadlines' worth of silence after the first frame.
        tokio::time::sleep(Duration::from_millis(800)).await;

        assert_eq!(
            transport.stats().pool_inbound_count(),
            1,
            "an established connection must not be dropped by the first-frame deadline"
        );
        assert!(!transport.pool.lock().await.is_empty());

        drop(peer);
        transport.stop_async().await.unwrap();
    }

    /// A genuine peer that is slow to start, but finishes its first frame
    /// inside the deadline, is admitted.
    #[tokio::test]
    async fn slow_first_frame_within_deadline_is_admitted() {
        let (tx, mut rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);
        transport.set_first_frame_timeout(Duration::from_secs(1));
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();

        let mut peer = TcpStream::connect(listen).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        peer.write_all(&build_msg1_frame()).await.unwrap();

        let packet = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout")
            .expect("packet channel closed");
        assert_eq!(packet.data, build_msg1_frame());
        assert_eq!(transport.stats().pool_inbound_count(), 1);

        drop(peer);
        transport.stop_async().await.unwrap();
    }

    /// The honest-slow-peer case the wrapper actually kills: a first frame
    /// that *starts* inside the deadline but completes after it. The
    /// deadline covers the whole frame, not its first byte, so the drip is
    /// dropped and its slot released.
    #[tokio::test]
    async fn byte_dripped_first_frame_past_deadline_is_dropped() {
        let (tx, mut rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);
        transport.set_first_frame_timeout(Duration::from_millis(300));
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();

        let frame = build_msg1_frame();
        let mut peer = TcpStream::connect(listen).await.unwrap();
        // Prefix inside the deadline, remainder well past it.
        peer.write_all(&frame[..4]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(600)).await;
        let _ = peer.write_all(&frame[4..]).await;

        assert!(
            timeout(Duration::from_millis(500), rx.recv())
                .await
                .is_err(),
            "a first frame completing after the deadline must not be delivered"
        );
        assert!(
            wait_until(
                || transport.stats().pool_inbound_count() == 0,
                Duration::from_secs(2)
            )
            .await,
            "the dripped connection should have released its slot"
        );

        drop(peer);
        transport.stop_async().await.unwrap();
    }

    /// Break-check for the readiness barrier's error path.
    ///
    /// Stands in for an accept loop aborted between the pool insert and the
    /// `ready_tx.send()`: the sender is dropped, so `ready_rx.await` returns
    /// `Err`. The receive loop must still fall through to its cleanup, or
    /// the pooled entry and its inbound-counter increment are stranded with
    /// no task left to undo them. A bare `return` on the error path fails
    /// both assertions below.
    #[tokio::test]
    async fn receive_loop_cleans_up_when_readiness_signal_is_dropped() {
        let (tx, _rx) = packet_channel(10);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = listener.local_addr().unwrap();
        let client = TcpStream::connect(listen).await.unwrap();
        let (server, peer_addr) = listener.accept().await.unwrap();
        let remote = TransportAddr::from_string(&peer_addr.to_string());
        let (read_half, write_half) = server.into_split();

        let pool: ConnectionPool = Arc::new(Mutex::new(HashMap::new()));
        let stats = Arc::new(TcpStats::new());
        pool.lock().await.insert(
            remote.clone(),
            TcpConnection {
                writer: Arc::new(Mutex::new(write_half)),
                recv_task: tokio::spawn(async {}),
                mtu: 1400,
                established_at: Instant::now(),
                direction: Direction::Inbound,
            },
        );
        stats.record_pool_inbound_added();
        assert_eq!(stats.pool_inbound_count(), 1);

        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
        drop(ready_tx);

        tcp_receive_loop(
            read_half,
            TransportId::new(1),
            remote.clone(),
            tx,
            pool.clone(),
            1400,
            stats.clone(),
            Direction::Inbound,
            Some(Duration::from_millis(50)),
            Some(ready_rx),
        )
        .await;

        assert!(
            pool.lock().await.is_empty(),
            "an aborted accept must not strand a pool entry"
        );
        assert_eq!(
            stats.pool_inbound_count(),
            0,
            "an aborted accept must not strand an inbound-counter increment"
        );
        drop(client);
    }

    /// Invariant guard: a deadline that expires immediately still leaves no
    /// orphaned pool entry or counter increment behind.
    ///
    /// This is not a break-check for the readiness barrier. On the
    /// current-thread test runtime the accept loop queues for the pool lock
    /// before the spawned receive task can run at all, so the insert wins
    /// the race with or without the barrier. The barrier's error path is
    /// break-checked in `receive_loop_cleans_up_when_readiness_signal_is_dropped`.
    #[tokio::test]
    async fn zero_deadline_leaves_no_orphaned_pool_entry() {
        let (tx, _rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);
        transport.set_first_frame_timeout(Duration::ZERO);
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();

        // Hold the pool across the accept so the receive task cannot reach
        // its cleanup while the accept loop is mid-insert.
        let guard = transport.pool.lock().await;
        let client = TcpStream::connect(listen).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(guard);

        // Sequence the checks off `connections_accepted`, which the accept
        // loop bumps only after its insert. Reading the pool counter first
        // would otherwise observe the pre-accept zero and prove nothing.
        assert!(
            wait_until(
                || transport.stats().snapshot().connections_accepted == 1,
                Duration::from_secs(2)
            )
            .await,
            "the accept loop should have admitted the connection"
        );
        assert!(
            wait_until(
                || transport.stats().pool_inbound_count() == 0
                    && transport
                        .pool
                        .try_lock()
                        .map(|p| p.is_empty())
                        .unwrap_or(false),
                Duration::from_secs(2)
            )
            .await,
            "an immediately expired deadline should leave neither a pool entry nor a counter increment"
        );

        drop(client);
        transport.stop_async().await.unwrap();
    }
}
