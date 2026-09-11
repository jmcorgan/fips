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
//! per peer. The transport maintains a connection pool mapping each
//! connection's four-tuple to its per-connection state, plus an optional
//! `TcpListener` for inbound connections.
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
use crate::transport::stream::{
    ConnId, WRITER_DRAIN_TIMEOUT, drain_writer, next_conn_id, remove_own,
};
use pool::{
    ConnectingEntry, ConnectingPool, ConnectionPool, Direction, PoolKey, TcpConnection,
    key_for_remote,
};
use stats::TcpStats;

use futures::FutureExt;
use socket2::TcpKeepalive;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
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
/// with a connection pool keyed by `PoolKey`, the connection's four-tuple.
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
        for (key, conn) in pool.drain() {
            conn.recv_task.abort();
            conn.send_task.abort();
            let _ = conn.recv_task.await;
            match conn.direction {
                Direction::Inbound => self.stats.record_pool_inbound_removed(),
                Direction::Outbound => self.stats.record_pool_outbound_removed(),
            }
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %key.remote,
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

        // Get or create connection. What comes back is the queue into the
        // connection's writer task, never the write half itself: this function
        // must not be able to await the wire (see `tcp_send_loop`).
        let send_tx = {
            let pool = self.pool.lock().await;
            key_for_remote(&pool, addr).and_then(|key| pool.get(&key).map(|c| c.send_tx.clone()))
        };

        let send_tx = match send_tx {
            Some(tx) => tx,
            None => {
                // Connect-on-send
                self.connect(addr).await?
            }
        };

        // Hand the frame to the writer task. The copy buys the caller its
        // freedom from the wire: `write_all` borrows, a queue must own. One
        // memcpy of at most an MTU is a good trade for not stalling the rx
        // loop on a peer that has stopped reading.
        //
        // `try_send` rather than `send`: awaiting a full queue would reinstate
        // exactly the block this removes, one level up. A full queue means the
        // writer task has not drained a frame in the time it took to fill 64 of
        // them, which is a peer that is not receiving, so the send fails and
        // the caller's own retry policy takes over.
        //
        // The byte count is what was queued, not what reached the wire — the
        // same prediction the UDP fast path reports when it dispatches to the
        // encrypt workers. Bytes actually written are recorded by the writer
        // task as they go.
        match send_tx.try_send(data.to_vec()) {
            Ok(()) => Ok(data.len()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.stats.record_send_error();
                debug!(
                    transport_id = %self.transport_id,
                    remote_addr = %addr,
                    depth = crate::transport::tcp::pool::SEND_QUEUE_DEPTH,
                    "TCP outbound queue full; peer is not draining"
                );
                Err(TransportError::SendFailed(
                    "outbound queue full: peer not draining".to_string(),
                ))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.stats.record_send_error();
                Err(TransportError::SendFailed(
                    "connection writer gone".to_string(),
                ))
            }
        }
    }

    /// Establish a new TCP connection to the given address.
    ///
    /// Configures socket options, reads TCP_MAXSEG for MTU, splits the
    /// stream, spawns a receive task, and stores in the pool.
    async fn connect(&self, addr: &TransportAddr) -> Result<mpsc::Sender<Vec<u8>>, TransportError> {
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

        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let pool = self.pool.clone();
        let recv_stats = self.stats.clone();
        let key = PoolKey::outbound(addr.clone());
        let recv_key = key.clone();
        let send_key = key.clone();
        let mtu = mss_mtu;
        let id = next_conn_id();

        let recv_task = tokio::spawn(async move {
            tcp_receive_loop(
                read_half,
                transport_id,
                recv_key,
                id,
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

        let (send_tx, send_rx) = mpsc::channel(crate::transport::tcp::pool::SEND_QUEUE_DEPTH);
        let send_task = tokio::spawn(tcp_send_loop(
            write_half,
            send_rx,
            transport_id,
            send_key,
            id,
            self.pool.clone(),
            self.stats.clone(),
        ));

        let conn = TcpConnection {
            send_tx: send_tx.clone(),
            send_task,
            recv_task,
            mtu: mss_mtu,
            established_at: Instant::now(),
            direction: Direction::Outbound,
            id,
        };

        let mut pool = self.pool.lock().await;
        pool.insert(key, conn);

        self.stats.record_connection_established();
        self.stats.record_pool_outbound_added();

        debug!(
            transport_id = %self.transport_id,
            remote_addr = %addr,
            mtu = mss_mtu,
            "TCP connection established (connect-on-send)"
        );

        Ok(send_tx)
    }

    /// Close a specific connection asynchronously.
    ///
    /// Removes the connection from the pool and aborts its receive task. The
    /// writer is not aborted: dropping the queue lets it finish writing the
    /// frames already queued, such as a Disconnect sent just before this close,
    /// and then exit, which drops the write half and sends FIN. A detached
    /// timer aborts it if it is still writing after [`WRITER_DRAIN_TIMEOUT`],
    /// so this call never waits on the peer. Stopping the transport, and every
    /// teardown after a connection has failed, abort the writer instead and
    /// discard what it had queued.
    pub async fn close_connection_async(&self, addr: &TransportAddr) {
        let mut pool = self.pool.lock().await;
        let key = key_for_remote(&pool, addr);
        if let Some(conn) = key.and_then(|key| pool.remove(&key)) {
            let TcpConnection {
                send_tx,
                send_task,
                recv_task,
                direction,
                ..
            } = conn;
            drop(send_tx);
            recv_task.abort();
            drain_writer(send_task, WRITER_DRAIN_TIMEOUT);
            match direction {
                Direction::Inbound => self.stats.record_pool_inbound_removed(),
                Direction::Outbound => self.stats.record_pool_outbound_removed(),
            }
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                direction = ?direction,
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
            if key_for_remote(&pool, addr).is_some() {
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
            if key_for_remote(&pool, addr).is_some() {
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

        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let pool = self.pool.clone();
        let recv_stats = self.stats.clone();
        let key = PoolKey::outbound(addr.clone());
        let recv_key = key.clone();
        let send_key = key.clone();
        let id = next_conn_id();

        let recv_task = tokio::spawn(async move {
            tcp_receive_loop(
                read_half,
                transport_id,
                recv_key,
                id,
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

        let (send_tx, send_rx) = mpsc::channel(crate::transport::tcp::pool::SEND_QUEUE_DEPTH);
        let send_task = tokio::spawn(tcp_send_loop(
            write_half,
            send_rx,
            transport_id,
            send_key,
            id,
            self.pool.clone(),
            self.stats.clone(),
        ));

        let conn = TcpConnection {
            send_tx,
            send_task,
            recv_task,
            mtu: mss_mtu,
            established_at: Instant::now(),
            direction: Direction::Outbound,
            id,
        };

        // Use try_lock since we're in a sync context and the pool
        // should be available (connection_state_sync already checked it)
        if let Ok(mut pool) = self.pool.try_lock() {
            pool.insert(key, conn);
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
            conn.send_task.abort();
            warn!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "Failed to promote connection (pool locked)"
            );
        }
    }
}

impl Transport for TcpTransport {
    fn role(&self) -> crate::config::TransportRole {
        self.config.role()
    }

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
                // The pool key is the four-tuple, so the local address is
                // needed before anything else is done with the socket. A
                // socket whose local address cannot be read is already
                // broken; drop it rather than pool it under a key that could
                // collide with another connection.
                let local_addr = match stream.local_addr() {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(
                            transport_id = %transport_id,
                            peer_addr = %peer_addr,
                            error = %e,
                            "Failed to read local address of accepted socket"
                        );
                        stats.record_connection_rejected();
                        continue;
                    }
                };

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
                let key = PoolKey::inbound(remote_addr.clone(), local_addr);

                // Split and spawn receive task
                let (read_half, write_half) = stream.into_split();

                let recv_pool = pool.clone();
                let recv_packet_tx = packet_tx.clone();
                let recv_stats = stats.clone();
                let recv_key = key.clone();
                let send_key = key.clone();

                // Readiness barrier: the receive task must not reach its
                // cleanup path before the pool insert and counter bump below,
                // or it would remove nothing and leave an orphaned entry with
                // a permanently incremented inbound counter.
                let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
                let id = next_conn_id();

                let recv_task = tokio::spawn(async move {
                    tcp_receive_loop(
                        read_half,
                        transport_id,
                        recv_key,
                        id,
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

                let (send_tx, send_rx) =
                    mpsc::channel(crate::transport::tcp::pool::SEND_QUEUE_DEPTH);
                let send_task = tokio::spawn(tcp_send_loop(
                    write_half,
                    send_rx,
                    transport_id,
                    send_key,
                    id,
                    pool.clone(),
                    stats.clone(),
                ));

                let conn = TcpConnection {
                    send_tx,
                    send_task,
                    recv_task,
                    mtu: conn_mtu,
                    established_at: Instant::now(),
                    direction: Direction::Inbound,
                    id,
                };

                let mut pool_guard = pool.lock().await;
                pool_guard.insert(key, conn);
                drop(pool_guard);

                stats.record_connection_accepted();
                stats.record_pool_inbound_added();

                // Release the receive task now that both the pool entry and
                // the inbound counter are in place.
                let _ = ready_tx.send(());

                debug!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    local_addr = %local_addr,
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
// Per-connection Loops (writer and receiver)
// ============================================================================

/// Per-connection writer task: the only place a TCP write is ever awaited.
///
/// This exists so the caller does not await the wire. `write_all` on a stream
/// blocks once the kernel send buffer fills, which is precisely what a peer
/// that has stopped draining causes — and the callers are the rx loop's tick
/// handlers, where blocking holds every other arm of the select behind it. The
/// loop owns the write half outright, so no other task can hold it and no
/// other task can be held by it.
///
/// On a write error the connection is removed from the pool, mirroring
/// `tcp_receive_loop`'s teardown contract: the pool entry is removed and the
/// direction counter decremented only when the removal returned `Some`, so a
/// concurrent `close`/`stop` of the same address cannot double-count. The
/// receive task is aborted here rather than left to notice on its own, because
/// a half-closed connection is not something either side should keep.
///
/// The entry is removed only when it carries this connection's `id`. A writer
/// can outlive its entry, and by the time its write fails a newer connection
/// may hold the same four-tuple; that one is left alone.
///
/// Frames are written whole. A partial write followed by an error takes the
/// connection down with it, so the peer never sees a frame it cannot
/// resynchronise from.
async fn tcp_send_loop(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut frames: mpsc::Receiver<Vec<u8>>,
    transport_id: TransportId,
    key: PoolKey,
    id: ConnId,
    pool: ConnectionPool,
    stats: Arc<TcpStats>,
) {
    let remote_addr = &key.remote;
    while let Some(frame) = frames.recv().await {
        match writer.write_all(&frame).await {
            Ok(()) => {
                stats.record_send(frame.len());
                trace!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    bytes = frame.len(),
                    "TCP packet sent"
                );
            }
            Err(e) => {
                stats.record_send_error();
                debug!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    error = %e,
                    "TCP write failed; dropping connection"
                );
                let removed = {
                    let mut pool = pool.lock().await;
                    remove_own(&mut pool, &key, id)
                };
                // The removed entry's `send_task` is this task, which returns
                // below, so only the receive task needs stopping.
                if let Some(conn) = removed {
                    conn.recv_task.abort();
                    match conn.direction {
                        Direction::Inbound => stats.record_pool_inbound_removed(),
                        Direction::Outbound => stats.record_pool_outbound_removed(),
                    }
                }
                return;
            }
        }
    }
    // The sender side is gone: the pool entry was dropped, so the connection
    // is already being torn down and there is nothing to clean up here.
    trace!(
        transport_id = %transport_id,
        remote_addr = %remote_addr,
        "TCP writer task exiting"
    );
}

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
///
/// `id` is the connection's identity. The cleanup removes the entry at
/// `remote_addr` only when it carries this id, so a loop whose entry has
/// already been replaced by a newer connection at the same address leaves
/// that connection alone. When it does remove its own entry it also stops the
/// entry's writer: the loop ended on EOF, a read error or a missed deadline,
/// and frames still queued for a connection in that state are not worth
/// writing.
#[allow(clippy::too_many_arguments)]
async fn tcp_receive_loop(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    transport_id: TransportId,
    key: PoolKey,
    id: ConnId,
    packet_tx: PacketTx,
    pool: ConnectionPool,
    mtu: u16,
    stats: Arc<TcpStats>,
    direction: Direction,
    first_frame_timeout: Option<Duration>,
    ready_rx: Option<tokio::sync::oneshot::Receiver<()>>,
) {
    let remote_addr = &key.remote;
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

                    let packet = ReceivedPacket::new(transport_id, key.remote.clone(), data);

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
    let removed = remove_own(&mut pool_guard, &key, id);
    drop(pool_guard);
    if let Some(conn) = removed {
        conn.send_task.abort();
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
    use super::pool::PoolMap;
    use super::*;
    use crate::transport::framing::build_msg1_frame;
    use crate::transport::packet_channel;
    use crate::transport::stream::park_writer;
    use tokio::time::{Duration, timeout};

    /// The pooled connection for `remote`, whatever key it sits under.
    ///
    /// The pool is keyed by four-tuple, so a test that knows only the peer
    /// address resolves the key the same way the transport does.
    fn conn_for<'a>(pool: &'a PoolMap, remote: &TransportAddr) -> Option<&'a TcpConnection> {
        let key = key_for_remote(pool, remote)?;
        pool.get(&key)
    }

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
        frame[0] = 0x00; // ver=0, phase=0 (established)
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
        let mut msg1_frame = vec![0xAA; 114];
        msg1_frame[0] = 0x01; // phase=msg1
        msg1_frame[1] = 0x00;
        msg1_frame[2..4].copy_from_slice(&110u16.to_le_bytes()); // payload_len = 110

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
        let mut msg2_frame = vec![0xBB; 69];
        msg2_frame[0] = 0x02; // phase=msg2
        msg2_frame[1] = 0x00;
        msg2_frame[2..4].copy_from_slice(&65u16.to_le_bytes()); // payload_len = 65

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
        let mut msg1 = vec![0xAA; 114];
        msg1[0] = 0x01;
        msg1[1] = 0x00;
        msg1[2..4].copy_from_slice(&110u16.to_le_bytes());

        t1.send_async(&remote, &msg1).await.unwrap();

        // Connection should exist
        {
            let pool = t1.pool.lock().await;
            assert!(conn_for(&pool, &remote).is_some());
        }

        // Close it
        t1.close_connection_async(&remote).await;

        // Connection should be gone
        {
            let pool = t1.pool.lock().await;
            assert!(conn_for(&pool, &remote).is_none());
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

    /// **The property this transport's send path exists to guarantee.**
    ///
    /// A peer that stops reading fills its receive window, then this node's
    /// kernel send buffer, and from that moment `write_all` blocks until the
    /// peer drains or the connection dies. The callers are the rx loop's tick
    /// handlers — the heartbeat sweep among them — so a blocking send holds
    /// every other arm of the select behind it: control RPCs, forwarding,
    /// every other peer's liveness. A medium change is precisely the condition
    /// that produces such a peer, which is how this was found.
    ///
    /// The writer task owns the write half, so `send_async` can only ever
    /// enqueue. This drives a peer that accepts the connection and then never
    /// reads, pushes far more than any socket buffer will hold, and asserts
    /// every call returns promptly — failing once the queue fills, rather than
    /// blocking on a peer that is not listening.
    #[tokio::test]
    async fn a_peer_that_stops_reading_cannot_block_the_sender() {
        let (tx1, _rx1) = packet_channel(100);
        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
        t1.start_async().await.unwrap();

        // A listener that accepts and then never reads a byte. Holding the
        // stream is the point: dropping it would close the connection and turn
        // the writes into fast errors, which is not the case under test.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let deaf = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(stream);
        });
        let remote = TransportAddr::from_string(&listen_addr.to_string());

        // Enough to overrun any plausible socket buffer plus the queue behind
        // it, so the blocking case cannot be missed by sending too little.
        let frame = vec![0xAB; 1400];
        let mut queued = 0usize;
        let mut refused = 0usize;
        for _ in 0..8000 {
            // The budget is per call and generous: a healthy enqueue is
            // microseconds, while the old unbounded write parked here until
            // the peer drained, which it never does.
            match timeout(Duration::from_secs(2), t1.send_async(&remote, &frame)).await {
                Ok(Ok(_)) => queued += 1,
                Ok(Err(_)) => refused += 1,
                Err(_) => panic!(
                    "send blocked on a peer that stopped reading; \
                     the write is back on the caller's task"
                ),
            }
        }

        assert!(queued > 0, "the first sends must be accepted");
        assert!(
            refused > 0,
            "a peer that never drains must eventually have sends refused rather than \
             queued without bound: queued={queued}"
        );

        deaf.abort();
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
        let mut msg1 = vec![0xAA; 114];
        msg1[0] = 0x01;
        msg1[1] = 0x00;
        msg1[2..4].copy_from_slice(&110u16.to_le_bytes());

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
        let mut msg1 = vec![0xAA; 114];
        msg1[0] = 0x01;
        msg1[1] = 0x00;
        msg1[2..4].copy_from_slice(&110u16.to_le_bytes());

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
        let mut frame = vec![0xAA; 114];
        frame[0] = 0x01; // ver=0, phase=1
        frame[1] = 0x00; // flags
        frame[2..4].copy_from_slice(&110u16.to_le_bytes()); // payload_len
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
        let (read_half, _write_half) = server.into_split();

        let pool: ConnectionPool = Arc::new(Mutex::new(HashMap::new()));
        let stats = Arc::new(TcpStats::new());
        let id = next_conn_id();
        pool.lock().await.insert(
            PoolKey::outbound(remote.clone()),
            TcpConnection {
                send_tx: mpsc::channel(1).0,
                send_task: tokio::spawn(async {}),
                recv_task: tokio::spawn(async {}),
                mtu: 1400,
                established_at: Instant::now(),
                direction: Direction::Inbound,
                id,
            },
        );
        stats.record_pool_inbound_added();
        assert_eq!(stats.pool_inbound_count(), 1);

        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
        drop(ready_tx);

        tcp_receive_loop(
            read_half,
            TransportId::new(1),
            PoolKey::outbound(remote.clone()),
            id,
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

    // ========================================================================
    // Connection identity and failure teardown
    // ========================================================================

    /// Bind a listener whose accepted sockets get a small receive buffer.
    ///
    /// Setting `SO_RCVBUF` before `listen` locks the size on every accepted
    /// socket, so kernel autotuning cannot grow it past what a test's fill
    /// can overrun.
    fn capped_deaf_listener() -> TcpListener {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(64 * 1024).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        socket.listen(8).unwrap()
    }

    /// Fill `remote`'s send queue behind a peer that does not read until the
    /// writer is parked in `write_all`, and return how many frames were
    /// queued. The fill and the parked-writer check are `park_writer`'s.
    async fn park_tcp_writer(t: &TcpTransport, remote: &TransportAddr, frame: &[u8]) -> usize {
        park_writer(
            async || match timeout(Duration::from_secs(2), t.send_async(remote, frame)).await {
                Ok(Ok(_)) => true,
                Ok(Err(_)) => false,
                Err(_) => panic!("send blocked on a peer that stopped reading"),
            },
            async || conn_for(&*t.pool.lock().await, remote).map(|c| c.send_tx.capacity()),
        )
        .await
    }

    /// Read `stream` to EOF within `limit`, returning the byte count, or
    /// `None` if EOF did not arrive in time.
    async fn read_to_eof(stream: &mut TcpStream, limit: Duration) -> Option<usize> {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 64 * 1024];
        timeout(limit, async {
            let mut total = 0usize;
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return total,
                    Ok(n) => total += n,
                }
            }
        })
        .await
        .ok()
    }

    /// A writer whose write fails must not remove a newer connection that has
    /// taken its address in the pool.
    ///
    /// The successor is marked by its MTU. The peer resets the connection, and
    /// frames are pushed until the writer's write fails, since the first write
    /// after a reset can still succeed.
    #[tokio::test]
    async fn tcp_writer_error_leaves_a_newer_connection_at_the_same_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = listener.local_addr().unwrap();
        let client = TcpStream::connect(listen).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        socket2::SockRef::from(&server)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        drop(server);
        let (_read_half, write_half) = client.into_split();
        let remote = TransportAddr::from_string(&listen.to_string());

        let pool: ConnectionPool = Arc::new(Mutex::new(HashMap::new()));
        let stats = Arc::new(TcpStats::new());
        pool.lock().await.insert(
            PoolKey::outbound(remote.clone()),
            TcpConnection {
                send_tx: mpsc::channel(1).0,
                send_task: tokio::spawn(async {}),
                recv_task: tokio::spawn(async {}),
                mtu: 1234,
                established_at: Instant::now(),
                direction: Direction::Outbound,
                id: next_conn_id(),
            },
        );

        let (send_tx, send_rx) = mpsc::channel(pool::SEND_QUEUE_DEPTH);
        let writer = tokio::spawn(tcp_send_loop(
            write_half,
            send_rx,
            TransportId::new(1),
            PoolKey::outbound(remote.clone()),
            next_conn_id(),
            pool.clone(),
            stats.clone(),
        ));

        let frame = build_msg1_frame();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !writer.is_finished() && Instant::now() < deadline {
            let _ = send_tx.try_send(frame.clone());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(writer.is_finished(), "the writer never hit a write error");
        assert_eq!(
            stats.snapshot().send_errors,
            1,
            "the writer's error path must have run"
        );

        assert_eq!(
            conn_for(&*pool.lock().await, &remote).map(|c| c.mtu),
            Some(1234),
            "a failed writer removed the newer connection at its address"
        );
    }

    /// A receive loop that ends on EOF must stop its writer rather than leave
    /// it writing to a peer that has gone.
    ///
    /// The writer is parked on a peer that does not read, with a full queue.
    /// The peer then half-closes, which ends the receive loop, and only
    /// afterwards reads. A writer left running delivers every frame it had
    /// queued; a stopped one delivers fewer, since the queue alone holds
    /// more frames than the kernel buffers leave unread.
    #[tokio::test]
    async fn tcp_receive_teardown_stops_the_writer() {
        let (tx1, _rx1) = packet_channel(100);
        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
        t1.start_async().await.unwrap();
        let listener = capped_deaf_listener();
        let remote = TransportAddr::from_string(&listener.local_addr().unwrap().to_string());
        let frame = vec![0xAB; 1400];

        let queued = park_tcp_writer(&t1, &remote, &frame).await;
        let (mut peer, _) = listener.accept().await.unwrap();

        peer.shutdown().await.unwrap();
        assert!(
            wait_until(
                || t1.stats().snapshot().pool_outbound == 0,
                Duration::from_secs(5)
            )
            .await,
            "the receive loop should have torn the connection down on EOF"
        );

        let read = read_to_eof(&mut peer, Duration::from_secs(10))
            .await
            .expect("the connection was never closed toward the peer");
        assert!(read > 0, "the kernel buffers held written frames");
        assert!(
            read < queued * frame.len(),
            "the writer kept writing after its receive loop tore the connection down: \
             read={read} queued_bytes={}",
            queued * frame.len()
        );

        t1.stop_async().await.unwrap();
    }

    /// A connection displaced from the pool by a newer one at the same address
    /// must not remove the newer one when its own receive loop ends.
    ///
    /// Both are built by `promote_connection`, and the MTU marks which entry
    /// is pooled. The last step checks the newer connection still removes its
    /// own entry.
    #[tokio::test]
    async fn tcp_displaced_connection_cannot_remove_its_successor() {
        let (tx1, _rx1) = packet_channel(100);
        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
        t1.start_async().await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = listener.local_addr().unwrap();
        let remote = TransportAddr::from_string(&listen.to_string());

        let a = TcpStream::connect(listen).await.unwrap();
        let (sa, _) = listener.accept().await.unwrap();
        let b = TcpStream::connect(listen).await.unwrap();
        let (sb, _) = listener.accept().await.unwrap();

        t1.promote_connection(&remote, a, 1400);
        t1.promote_connection(&remote, b, 1300);
        {
            let pool = t1.pool.lock().await;
            assert_eq!(pool.len(), 1);
            assert_eq!(conn_for(&pool, &remote).map(|c| c.mtu), Some(1300));
        }

        drop(sa);
        assert!(
            wait_until(
                || t1.stats().snapshot().recv_errors == 1,
                Duration::from_secs(2)
            )
            .await,
            "the displaced connection's receive loop should have read EOF"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            conn_for(&*t1.pool.lock().await, &remote).map(|c| c.mtu),
            Some(1300),
            "the displaced connection's teardown removed its successor"
        );

        drop(sb);
        assert!(
            wait_until(
                || t1.stats().snapshot().recv_errors == 2,
                Duration::from_secs(2)
            )
            .await,
            "the newer connection's receive loop should have read EOF"
        );
        assert!(
            wait_until(
                || t1.pool.try_lock().map(|p| p.is_empty()).unwrap_or(false),
                Duration::from_secs(2)
            )
            .await,
            "the newer connection's teardown should remove its own entry"
        );

        t1.stop_async().await.unwrap();
    }

    /// A receive loop's teardown must leave alone a newer entry at its address,
    /// and must not decrement the counter for it.
    ///
    /// Calls the loop directly against a hand-built successor, so the check is
    /// on the teardown alone and not on how a constructor wires it.
    #[tokio::test]
    async fn tcp_receive_teardown_leaves_a_newer_connection_at_the_same_address() {
        let (tx, _rx) = packet_channel(10);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = listener.local_addr().unwrap();
        let client = TcpStream::connect(listen).await.unwrap();
        let (server, peer_addr) = listener.accept().await.unwrap();
        let remote = TransportAddr::from_string(&peer_addr.to_string());
        let (read_half, _write_half) = server.into_split();

        let pool: ConnectionPool = Arc::new(Mutex::new(HashMap::new()));
        let stats = Arc::new(TcpStats::new());
        pool.lock().await.insert(
            PoolKey::outbound(remote.clone()),
            TcpConnection {
                send_tx: mpsc::channel(1).0,
                send_task: tokio::spawn(async {}),
                recv_task: tokio::spawn(async {}),
                mtu: 1234,
                established_at: Instant::now(),
                direction: Direction::Outbound,
                id: next_conn_id(),
            },
        );
        stats.record_pool_outbound_added();
        assert_eq!(stats.snapshot().pool_outbound, 1);

        drop(client);
        tcp_receive_loop(
            read_half,
            TransportId::new(1),
            PoolKey::outbound(remote.clone()),
            next_conn_id(),
            tx,
            pool.clone(),
            1400,
            stats.clone(),
            Direction::Outbound,
            None,
            None,
        )
        .await;
        assert_eq!(
            stats.snapshot().recv_errors,
            1,
            "the loop should have ended on EOF"
        );

        assert_eq!(
            conn_for(&*pool.lock().await, &remote).map(|c| c.mtu),
            Some(1234),
            "the teardown removed a newer connection at its address"
        );
        assert_eq!(
            stats.snapshot().pool_outbound,
            1,
            "the teardown decremented for a connection it did not remove"
        );
    }

    /// A connection built by connect-on-send removes its own entry when its
    /// receive loop ends.
    #[tokio::test]
    async fn tcp_connect_teardown_removes_its_own_entry() {
        use tokio::io::AsyncReadExt;
        let (tx1, _rx1) = packet_channel(100);
        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
        t1.start_async().await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = TransportAddr::from_string(&listener.local_addr().unwrap().to_string());
        let frame = build_msg1_frame();

        t1.send_async(&remote, &frame).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; frame.len()];
        timeout(Duration::from_secs(2), server.read_exact(&mut buf))
            .await
            .expect("timeout waiting for the frame")
            .unwrap();
        assert_eq!(buf, frame);
        assert_eq!(t1.stats().snapshot().pool_outbound, 1);

        drop(server);
        assert!(
            wait_until(
                || t1.stats().snapshot().pool_outbound == 0,
                Duration::from_secs(2)
            )
            .await,
            "the receive loop should release the outbound slot"
        );
        assert!(
            t1.pool.lock().await.is_empty(),
            "the receive loop should remove its own entry"
        );

        t1.stop_async().await.unwrap();
    }

    /// Two live inbound connections can share one remote address when they
    /// reach a wildcard listener on different local addresses. Each gets its
    /// own pool entry, and closing the older one leaves the newer one's entry
    /// and its connection alone.
    ///
    /// The pool is keyed by four-tuple, so the two no longer share a key. That
    /// closes the gap this test previously recorded: the second accept used to
    /// replace the first entry without stopping its tasks while counting a
    /// second inbound slot, so the inbound counter ended one above the pool
    /// once both connections closed. The counter gates accepts, so repeating
    /// that locked the listener out until the daemon restarted.
    ///
    /// Break-check: with `PoolKey::inbound` ignoring its local address, the
    /// pool holds one entry rather than two and the inbound counter does not
    /// return to zero.
    ///
    /// Linux only: it needs `127.0.0.2` on the loopback interface and Linux
    /// `SO_REUSEADDR` semantics to bind two client sockets to one port.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn closing_the_older_of_two_inbound_connections_sharing_a_remote_address_keeps_the_newer_entry()
     {
        use socket2::{Domain, Socket, Type};
        use tokio::io::AsyncReadExt;

        let (tx, mut rx) = packet_channel(100);
        let config = TcpConfig {
            bind_addr: Some("0.0.0.0:0".to_string()),
            mtu: Some(1400),
            ..Default::default()
        };
        let mut transport = TcpTransport::new(TransportId::new(1), None, config, tx);
        transport.start_async().await.unwrap();
        let port = transport.local_addr().unwrap().port();

        let client = |local: SocketAddr| {
            let sock = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
            sock.set_reuse_address(true).unwrap();
            sock.bind(&local.into()).unwrap();
            sock
        };
        let into_tokio = |sock: Socket| {
            let std_stream: std::net::TcpStream = sock.into();
            std_stream.set_nonblocking(true).unwrap();
            TcpStream::from_std(std_stream).unwrap()
        };
        let sock_a = client("127.0.0.1:0".parse().unwrap());
        let source = sock_a.local_addr().unwrap().as_socket().unwrap();
        let sock_b = client(source);
        let remote = TransportAddr::from_string(&source.to_string());
        let frame = build_msg1_frame();

        // Admit A before B dials, so B's entry is the one left in the pool.
        let target_a: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        sock_a.connect(&target_a.into()).unwrap();
        let mut a = into_tokio(sock_a);
        a.write_all(&frame).await.unwrap();
        let first = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for A's frame")
            .expect("packet channel closed");
        assert_eq!(first.remote_addr, remote);
        assert_eq!(transport.stats().snapshot().connections_accepted, 1);

        let target_b: SocketAddr = format!("127.0.0.2:{port}").parse().unwrap();
        sock_b.connect(&target_b.into()).unwrap();
        let mut b = into_tokio(sock_b);
        b.write_all(&frame).await.unwrap();
        let second = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for B's frame")
            .expect("packet channel closed");
        assert_eq!(
            second.remote_addr, remote,
            "B must arrive with the same remote address as A"
        );
        assert_eq!(transport.stats().snapshot().connections_accepted, 2);
        assert!(
            wait_until(
                || transport.stats().pool_inbound_count() == 2,
                Duration::from_secs(2)
            )
            .await,
            "both connections should hold an inbound slot"
        );
        {
            let pool = transport.pool.lock().await;
            assert_eq!(
                pool.len(),
                2,
                "two live connections must not share one pool entry"
            );
            let mut locals: Vec<_> = pool
                .keys()
                .map(|key| key.local.expect("an inbound key carries a local address"))
                .collect();
            locals.sort();
            assert_eq!(
                locals,
                vec![
                    SocketAddr::from(([127, 0, 0, 1], port)),
                    SocketAddr::from(([127, 0, 0, 2], port)),
                ],
                "the two entries should be the two four-tuples"
            );
            assert!(conn_for(&pool, &remote).is_some());
        }

        drop(a);
        assert!(
            wait_until(
                || transport.stats().snapshot().recv_errors == 1,
                Duration::from_secs(2)
            )
            .await,
            "A's receive loop should have read EOF"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;

        let send_tx = conn_for(&*transport.pool.lock().await, &remote)
            .map(|c| c.send_tx.clone())
            .expect("closing the older connection removed the newer connection's entry");
        send_tx.try_send(frame.clone()).unwrap();
        drop(send_tx);
        let mut buf = vec![0u8; frame.len()];
        timeout(Duration::from_secs(2), b.read_exact(&mut buf))
            .await
            .expect("the surviving entry is not B's live connection")
            .unwrap();
        assert_eq!(buf, frame);

        drop(b);
        assert!(
            wait_until(
                || transport.stats().snapshot().recv_errors == 2,
                Duration::from_secs(2)
            )
            .await,
            "B's receive loop should have read EOF"
        );
        assert!(
            wait_until(
                || transport
                    .pool
                    .try_lock()
                    .map(|p| p.is_empty())
                    .unwrap_or(false),
                Duration::from_secs(2)
            )
            .await,
            "B's teardown should remove its own entry"
        );

        transport.stop_async().await.unwrap();
    }

    // ========================================================================
    // Deliberate close finishes the frames already queued
    // ========================================================================

    /// A frame queued immediately before a deliberate close must still be
    /// written.
    ///
    /// Sending only queues the frame for the connection's writer task. A close
    /// that aborts that task before it has run discards the frame, which is
    /// how a Disconnect sent just before a close, or a handshake message sent
    /// just before the losing side of a crossed connection is closed, never
    /// reaches the peer. The second half checks the close still closes: the
    /// peer sees FIN and releases its inbound slot, so a writer that never
    /// exits cannot pass.
    #[tokio::test]
    async fn a_frame_queued_just_before_close_still_reaches_the_peer() {
        let (tx1, _rx1) = packet_channel(100);
        let (tx2, mut rx2) = packet_channel(100);
        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
        let mut t2 = TcpTransport::new(TransportId::new(2), None, make_config(), tx2);
        t1.start_async().await.unwrap();
        t2.start_async().await.unwrap();
        let remote = TransportAddr::from_string(&t2.local_addr().unwrap().to_string());
        let frame = build_msg1_frame();

        // Pool the connection and let its writer go idle.
        t1.send_async(&remote, &frame).await.unwrap();
        let first = timeout(Duration::from_secs(2), rx2.recv())
            .await
            .expect("timeout waiting for the first frame")
            .expect("packet channel closed");
        assert_eq!(first.data, frame);

        // Queue, then close with nothing in between.
        t1.send_async(&remote, &frame).await.unwrap();
        t1.close_connection_async(&remote).await;

        let second = timeout(Duration::from_secs(2), rx2.recv())
            .await
            .expect("a frame queued just before close was never written")
            .expect("packet channel closed");
        assert_eq!(second.data, frame);

        assert!(
            wait_until(
                || t2.stats().snapshot().pool_inbound == 0,
                Duration::from_secs(5)
            )
            .await,
            "the close must still end the connection once the queue is written"
        );

        t1.stop_async().await.unwrap();
        t2.stop_async().await.unwrap();
    }

    /// A deliberate close must return at once even when the writer cannot
    /// finish, because the peer has stopped reading. Draining happens after
    /// the close returns, never inside it.
    #[tokio::test]
    async fn close_does_not_wait_for_a_writer_parked_on_a_deaf_peer() {
        let (tx1, _rx1) = packet_channel(100);
        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
        t1.start_async().await.unwrap();
        let listener = capped_deaf_listener();
        let remote = TransportAddr::from_string(&listener.local_addr().unwrap().to_string());
        let frame = vec![0xAB; 1400];

        park_tcp_writer(&t1, &remote, &frame).await;
        let (_peer, _) = listener.accept().await.unwrap();

        assert!(
            timeout(
                Duration::from_millis(200),
                t1.close_connection_async(&remote)
            )
            .await
            .is_ok(),
            "close waited on a writer that cannot finish"
        );

        t1.stop_async().await.unwrap();
    }

    // ========================================================================
    // Inbound pool keying
    // ========================================================================

    /// A reply addressed to an inbound peer goes back over the connection that
    /// peer opened, rather than dialing its ephemeral port.
    ///
    /// An inbound entry is keyed by the four-tuple, but a caller answering a
    /// received packet knows only the remote address it came from. The pool has
    /// to resolve that address to the entry; if it does not, the send falls
    /// through to connect-on-send against the peer's ephemeral port and fails.
    #[tokio::test]
    async fn a_reply_to_an_inbound_peer_uses_the_connection_it_arrived_on() {
        let (tx, mut rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();

        let mut peer = TcpStream::connect(listen).await.unwrap();
        peer.write_all(&build_msg1_frame()).await.unwrap();
        let packet = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for the inbound frame")
            .expect("packet channel closed");

        let mut reply = vec![0xBB; 69];
        reply[0] = 0x02;
        reply[1] = 0x00;
        reply[2..4].copy_from_slice(&65u16.to_le_bytes());
        transport
            .send_async(&packet.remote_addr, &reply)
            .await
            .expect("a reply to an inbound peer should use its connection");

        let mut received = vec![0u8; reply.len()];
        timeout(
            Duration::from_secs(2),
            tokio::io::AsyncReadExt::read_exact(&mut peer, &mut received),
        )
        .await
        .expect("timeout waiting for the reply")
        .expect("reply read failed");
        assert_eq!(received, reply);

        drop(peer);
        transport.stop_async().await.unwrap();
    }
}
