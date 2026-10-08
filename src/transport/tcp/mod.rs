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

use super::{
    ConnectionState, DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr,
    TransportError, TransportId, TransportState, TransportType,
};
use super::{resolve_socket_addrs, take_finished_connect};
use crate::config::TcpConfig;
use crate::proto::fmp::wire::{FMP_VERSION, PHASE_MSG2};
use crate::transport::framing::{StreamError, read_fmp_packet};
use crate::transport::stream::{
    ConnId, DrainingWriters, WRITER_DRAIN_TIMEOUT, next_conn_id, remove_own,
};
use pool::{
    ConnectingEntry, ConnectingPool, ConnectionPool, Direction, PoolKey, TcpConnection,
    key_for_remote,
};
use stats::TcpStats;

use futures::FutureExt;
use socket2::TcpKeepalive;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// Longest wait for each later complete inbound frame. Defaults to
    /// `INBOUND_IDLE_TIMEOUT`; the node sets it from its liveness timers.
    idle_timeout: Duration,
    /// Writers of deliberately closed connections still finishing their
    /// queues, which `stop_async` must also stop.
    draining: DrainingWriters,
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
            idle_timeout: INBOUND_IDLE_TIMEOUT,
            draining: DrainingWriters::default(),
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

    /// Set the inbound idle deadline: the longest an accepted connection may
    /// go, after its first frame, without delivering another complete frame.
    ///
    /// The node derives it from its own link-liveness timers, so it never
    /// drops a connection carrying a link the node would keep. Takes effect
    /// at the next `start_async()`.
    pub fn set_inbound_idle_timeout(&mut self, d: Duration) {
        self.idle_timeout = d;
    }

    /// The inbound idle deadline the accept loop will use.
    #[cfg(test)]
    pub(crate) fn inbound_idle_timeout(&self) -> Duration {
        self.idle_timeout
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
                source_cap: self.config.max_inbound_per_source(),
                nodelay: self.config.nodelay(),
                keepalive_secs: self.config.keepalive_secs(),
                recv_buf: self.config.recv_buf_size(),
                send_buf: self.config.send_buf_size(),
                deadline: InboundDeadline {
                    first_frame: self.first_frame_timeout,
                    idle: self.idle_timeout,
                },
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

        // Writers of connections closed before the stop are out of the pool,
        // so the loop above does not reach them.
        self.draining.stop().await;

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
        self.check_mtu(data)?;

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

        self.enqueue(addr, &send_tx, data)
    }

    /// Send a packet only over a connection that already exists.
    ///
    /// Uses the pooled connection for `addr`, or one a finished background
    /// connect has produced, which it moves into the pool. Never dials: with
    /// neither, it fails at once with [`TransportError::NotConnected`]. Like
    /// `send_async`, it only queues the frame for the connection's writer
    /// task and never awaits the wire.
    pub async fn send_existing(
        &self,
        addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }
        self.check_mtu(data)?;
        let send_tx = self
            .existing_sender(addr)
            .await
            .ok_or(TransportError::NotConnected)?;
        self.enqueue(addr, &send_tx, data)
    }

    /// Whether the pool holds a connection to `addr`: true exactly when
    /// [`send_existing`](Self::send_existing) finds one there without
    /// promoting a finished background connect.
    ///
    /// Reads only: a finished background connect is not moved into the pool,
    /// so for one that is waiting to be taken this reports false although
    /// `send_existing` would promote it and queue the frame. Awaits the pool
    /// lock, so it never reports a connection absent because the lock was
    /// busy. A pooled connection whose queue is full, or whose writer has
    /// exited but not yet removed its entry, is reported, as `send_existing`
    /// would find it and fail on the enqueue.
    pub async fn has_connection(&self, addr: &TransportAddr) -> bool {
        let pool = self.pool.lock().await;
        key_for_remote(&pool, addr).is_some()
    }

    /// The writer queue for an established connection to `addr`, promoting
    /// a background connect that has finished since it was started.
    ///
    /// Holds the pool lock across the promotion, so the connection cannot be
    /// inserted twice. A finished connect that failed is dropped, so the next
    /// `connect_async` starts a new attempt.
    async fn existing_sender(&self, addr: &TransportAddr) -> Option<mpsc::Sender<Vec<u8>>> {
        let mut pool = self.pool.lock().await;
        if let Some(conn) = key_for_remote(&pool, addr).and_then(|key| pool.get(&key)) {
            return Some(conn.send_tx.clone());
        }
        let finished = take_finished_connect(&mut *self.connecting.lock().await, addr)?;
        match finished {
            Ok((stream, mss_mtu)) => {
                let conn = self.outbound_connection(addr, stream, mss_mtu);
                let send_tx = conn.send_tx.clone();
                pool.insert(PoolKey::outbound(addr.clone()), conn);
                self.record_promoted(addr, mss_mtu);
                Some(send_tx)
            }
            Err(e) => {
                debug!(
                    transport_id = %self.transport_id,
                    remote_addr = %addr,
                    error = %e,
                    "Background TCP connect failed, nothing to send on"
                );
                None
            }
        }
    }

    /// Reject a packet larger than the transport MTU before queueing it.
    ///
    /// Without this, the receiver's FMP stream reader would see
    /// payload_len > max and close the connection, causing a disruptive
    /// reset-reconnect cycle.
    fn check_mtu(&self, data: &[u8]) -> Result<(), TransportError> {
        if data.len() > self.config.mtu() as usize {
            self.stats.record_mtu_exceeded();
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu: self.config.mtu(),
            });
        }
        Ok(())
    }

    /// Queue one packet for the writer task of the connection to `addr`.
    fn enqueue(
        &self,
        addr: &TransportAddr,
        send_tx: &mpsc::Sender<Vec<u8>>,
        data: &[u8],
    ) -> Result<usize, TransportError> {
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
        let socket_addrs: Vec<_> = resolve_socket_addrs(addr).await?.collect();
        let timeout_ms = self.config.connect_timeout_ms();

        let connected =
            connect_to_any_addr(self.transport_id, addr, &socket_addrs, timeout_ms).await;
        let stream = match connected {
            Ok(stream) => stream,
            Err(error @ TransportError::ConnectionRefused) => {
                self.stats.record_connect_refused();
                return Err(error);
            }
            Err(error @ TransportError::Timeout) => {
                self.stats.record_connect_timeout();
                return Err(error);
            }
            Err(error) => return Err(error),
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
        let msg2_sent = Arc::new(AtomicBool::new(false));
        let recv_msg2_sent = msg2_sent.clone();

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
                recv_msg2_sent,
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
            msg2_sent,
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
    /// discard what it had queued; stopping also ends a writer still draining
    /// from an earlier close.
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
            self.draining.drain(send_task, WRITER_DRAIN_TIMEOUT);
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
        addr.as_str()
            .ok_or_else(|| TransportError::InvalidAddress("not valid UTF-8".into()))?;
        let timeout_ms = self.config.connect_timeout_ms();
        let config = self.config.clone();
        let transport_id = self.transport_id;
        let remote_addr = addr.clone();
        let stats = self.stats.clone();

        debug!(
            transport_id = %transport_id,
            remote_addr = %remote_addr,
            timeout_ms,
            "Initiating background TCP connect"
        );

        let task = tokio::spawn(async move {
            // Resolve address (may involve DNS for hostnames)
            let socket_addrs: Vec<_> = resolve_socket_addrs(&remote_addr).await?.collect();

            // A refusal is logged with its OS error by connect_to_any_addr.
            // Failures are counted here, where they happen, as connect()
            // counts them; whoever later takes the result does not.
            let connected =
                connect_to_any_addr(transport_id, &remote_addr, &socket_addrs, timeout_ms).await;
            let stream = match connected {
                Ok(stream) => stream,
                Err(error @ TransportError::ConnectionRefused) => {
                    stats.record_connect_refused();
                    return Err(error);
                }
                Err(error @ TransportError::Timeout) => {
                    stats.record_connect_timeout();
                    debug!(
                        transport_id = %transport_id,
                        remote_addr = %remote_addr,
                        "Background TCP connect timed out"
                    );
                    return Err(error);
                }
                Err(error) => return Err(error),
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
        let conn = self.outbound_connection(addr, stream, mss_mtu);

        // Use try_lock since we're in a sync context and the pool
        // should be available (connection_state_sync already checked it)
        if let Ok(mut pool) = self.pool.try_lock() {
            pool.insert(PoolKey::outbound(addr.clone()), conn);
            self.record_promoted(addr, mss_mtu);
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

    /// Build the pool entry for a finished background connect: split the
    /// stream and spawn its receive loop and writer task.
    fn outbound_connection(
        &self,
        addr: &TransportAddr,
        stream: TcpStream,
        mss_mtu: u16,
    ) -> TcpConnection {
        let (read_half, write_half) = stream.into_split();

        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let pool = self.pool.clone();
        let recv_stats = self.stats.clone();
        let key = PoolKey::outbound(addr.clone());
        let recv_key = key.clone();
        let send_key = key;
        let id = next_conn_id();
        let msg2_sent = Arc::new(AtomicBool::new(false));
        let recv_msg2_sent = msg2_sent.clone();

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
                recv_msg2_sent,
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
            msg2_sent,
        ));

        TcpConnection {
            send_tx,
            send_task,
            recv_task,
            mtu: mss_mtu,
            established_at: Instant::now(),
            direction: Direction::Outbound,
            id,
        }
    }

    /// Count and log a background connection that has entered the pool.
    fn record_promoted(&self, addr: &TransportAddr, mss_mtu: u16) {
        self.stats.record_connection_established();
        self.stats.record_pool_outbound_added();
        debug!(
            transport_id = %self.transport_id,
            remote_addr = %addr,
            mtu = mss_mtu,
            "TCP connection established (background connect)"
        );
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

/// Default deadline for each complete inbound frame after the first.
///
/// Without it, a remote that sends one well-formed frame and then goes
/// silent holds its inbound slot for as long as it keeps the socket open:
/// a frame that names no session is dropped by the node without closing
/// the transport. The node replaces this with the bound derived from its
/// own liveness timers (`link_silence_ms`); 64 s is that bound at stock
/// settings, kept here so a transport built outside the node still has a
/// deadline.
pub(crate) const INBOUND_IDLE_TIMEOUT: Duration = Duration::from_secs(64);

/// Read deadlines for an inbound connection, which holds a capped pool
/// slot from accept.
///
/// Each deadline covers one complete frame, not a byte: a remote that
/// drips a frame slower than the deadline is dropped. The idle deadline
/// re-arms on every frame, so a connection carrying a live link, which
/// receives at least a heartbeat per interval, is never dropped by it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct InboundDeadline {
    /// Deadline from accept to the first complete frame.
    pub(crate) first_frame: Duration,
    /// Deadline for each later complete frame, from the end of the last.
    pub(crate) idle: Duration,
}

impl InboundDeadline {
    /// The deadline for the next read: `first` is true until a frame has
    /// been received.
    pub(crate) fn for_read(&self, first: bool) -> Duration {
        if first { self.first_frame } else { self.idle }
    }

    /// The log word for an expiry of the deadline `for_read(first)` gave.
    pub(crate) fn phase(first: bool) -> &'static str {
        if first { "first-frame" } else { "idle" }
    }
}

/// Socket configuration parameters passed to the accept loop.
struct AcceptConfig {
    mtu: u16,
    max_inbound: usize,
    /// Most inbound connections one source (IPv4 address or IPv6 /64) may
    /// hold at once.
    source_cap: usize,
    nodelay: bool,
    keepalive_secs: u64,
    recv_buf: usize,
    send_buf: usize,
    deadline: InboundDeadline,
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
        source_cap,
        nodelay,
        keepalive_secs,
        recv_buf,
        send_buf,
        deadline,
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

                // Per-source cap: one address (or IPv6 /64) may not take
                // every inbound slot. Counted from the pool rather than a
                // separate per-source counter so it cannot drift from it.
                // This loop is the only inserter of inbound entries, so
                // between here and the insert below the count can only fall.
                let from_source = inbound_from_source(&*pool.lock().await, peer_addr.ip());
                if from_source >= source_cap {
                    stats.record_connection_rejected();
                    stats.record_source_rejected();
                    debug!(
                        transport_id = %transport_id,
                        peer_addr = %peer_addr,
                        open_from_source = from_source,
                        max = source_cap,
                        "Rejecting inbound TCP connection (max_inbound_per_source reached)"
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
                let msg2_sent = Arc::new(AtomicBool::new(false));
                let recv_msg2_sent = msg2_sent.clone();

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
                        Some(deadline),
                        Some(ready_rx),
                        recv_msg2_sent,
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
                    msg2_sent,
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

                pool.lock().await.insert(key, conn);
                // The count taken at the gate plus this connection. It can
                // read one high if a connection from the same source closed
                // since the gate.
                let open_from_source = from_source + 1;

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
                    open_from_source,
                    open_total = stats.pool_inbound_count(),
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

/// The source an inbound connection is counted under: an IPv4 address as
/// itself, an IPv4-mapped IPv6 address as its IPv4 form, and any other IPv6
/// address as its /64, since one host commonly holds a whole /64.
fn source_of(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let prefix = u128::from(v6) & !((1u128 << 64) - 1);
            IpAddr::V6(prefix.into())
        }
        v4 => v4,
    }
}

/// How many pooled inbound connections come from the same source as `ip`.
fn inbound_from_source(pool: &pool::PoolMap, ip: IpAddr) -> usize {
    let source = source_of(ip);
    pool.iter()
        .filter(|(key, conn)| {
            conn.direction == Direction::Inbound
                && key
                    .remote
                    .as_str()
                    .and_then(|a| a.parse::<SocketAddr>().ok())
                    .is_some_and(|a| source_of(a.ip()) == source)
        })
        .count()
}

/// Whether `frame` is a msg2, by its version and phase nibbles.
fn is_msg2(frame: &[u8]) -> bool {
    frame
        .first()
        .is_some_and(|b| b >> 4 == FMP_VERSION && b & 0x0F == PHASE_MSG2)
}

/// The close reason for a receive that failed with `e`.
fn read_failure_reason(e: &StreamError) -> &'static str {
    match e {
        StreamError::Io(io) => match io.kind() {
            std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted => "remote-closed",
            _ => "read-error",
        },
        _ => "framing",
    }
}

/// The record of one connection's receive loop, logged as its close line
/// when the loop ends, however it ends.
///
/// It is logged from `Drop` because a loop can also end by being aborted:
/// closing the connection, a failed write and stopping the transport all
/// abort the receive task, which drops the loop at its await point and runs
/// nothing after it. The frame count lives in the loop, so no other site can
/// log it.
struct CloseNote {
    transport_id: TransportId,
    remote_addr: TransportAddr,
    direction: Direction,
    started: Instant,
    /// Complete frames received.
    frames: u64,
    /// Set by the writer once it has written a msg2 on the connection.
    msg2_sent: Arc<AtomicBool>,
    /// Why the loop ended. Left at `local` when it is aborted, which only
    /// this node does.
    reason: &'static str,
}

impl Drop for CloseNote {
    fn drop(&mut self) {
        debug!(
            transport_id = %self.transport_id,
            remote_addr = %self.remote_addr,
            direction = ?self.direction,
            lifetime_s = self.started.elapsed().as_secs(),
            frames = self.frames,
            msg2_sent = self.msg2_sent.load(Ordering::Relaxed),
            reason = %self.reason,
            "Closed TCP connection"
        );
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
///
/// `msg2_sent` is set once a msg2 has been written, for the receive loop's
/// close line.
#[allow(clippy::too_many_arguments)]
async fn tcp_send_loop(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut frames: mpsc::Receiver<Vec<u8>>,
    transport_id: TransportId,
    key: PoolKey,
    id: ConnId,
    pool: ConnectionPool,
    stats: Arc<TcpStats>,
    msg2_sent: Arc<AtomicBool>,
) {
    let remote_addr = &key.remote;
    while let Some(frame) = frames.recv().await {
        match writer.write_all(&frame).await {
            Ok(()) => {
                if is_msg2(&frame) {
                    msg2_sent.store(true, Ordering::Relaxed);
                }
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
/// `deadline` bounds the wait for every complete frame: the first-frame
/// deadline until one arrives, the idle deadline for each one after. It is
/// `Some` for inbound connections (which hold a capped pool slot from
/// accept) and `None` for outbound ones. `ready_rx`, when
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
///
/// Every loop logs one close line when it ends, through a [`CloseNote`]
/// created on entry; `msg2_sent` is shared with the connection's writer.
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
    deadline: Option<InboundDeadline>,
    ready_rx: Option<tokio::sync::oneshot::Receiver<()>>,
    msg2_sent: Arc<AtomicBool>,
) {
    let remote_addr = &key.remote;
    let mut note = CloseNote {
        transport_id,
        remote_addr: remote_addr.clone(),
        direction,
        started: Instant::now(),
        frames: 0,
        msg2_sent,
        reason: "local",
    };
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
            let read = match deadline {
                // Bound every read. A remote that goes silent, before or after
                // its first frame, otherwise holds its inbound slot for as
                // long as it keeps the socket open.
                Some(d) => {
                    let limit = d.for_read(first);
                    match tokio::time::timeout(limit, read_fmp_packet(&mut reader, mtu)).await {
                        Ok(result) => result,
                        Err(_) => {
                            // Not a recv error: `record_recv_error` means
                            // framing or I/O failure, and folding deadline
                            // expiries into it corrupts that counter.
                            debug!(
                                transport_id = %transport_id,
                                remote_addr = %remote_addr,
                                deadline = InboundDeadline::phase(first),
                                timeout_secs = limit.as_secs_f64(),
                                "No complete frame within the inbound deadline, dropping inbound connection"
                            );
                            note.reason = InboundDeadline::phase(first);
                            break;
                        }
                    }
                }
                None => read_fmp_packet(&mut reader, mtu).await,
            };
            first = false;

            match read {
                Ok(data) => {
                    note.frames += 1;
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
                        note.reason = "channel-closed";
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
                    note.reason = read_failure_reason(&e);
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

/// Connect to the first reachable of a peer's resolved addresses within one timeout.
async fn connect_to_any_addr(
    transport_id: TransportId,
    remote_addr: &TransportAddr,
    socket_addrs: &[SocketAddr],
    timeout_ms: u64,
) -> Result<TcpStream, TransportError> {
    if socket_addrs.is_empty() {
        return Err(TransportError::InvalidAddress(format!(
            "DNS resolution returned no addresses for {}",
            remote_addr
        )));
    }

    // Try candidates in resolver order within one overall connection timeout.
    match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(socket_addrs),
    )
    .await
    {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) => {
            // Tokio returns the last candidate's error; keep it in the log,
            // since the returned variant does not carry it.
            debug!(
                transport_id = %transport_id,
                remote_addr = %remote_addr,
                error = %error,
                "TCP connect failed"
            );
            Err(TransportError::ConnectionRefused)
        }
        Err(_) => Err(TransportError::Timeout),
    }
}

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
    use crate::testutil::{Blackhole, wait_until};
    use crate::transport::framing::{build_established_frame, build_msg1_frame};
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

    #[tokio::test]
    async fn test_connect_tries_later_candidates() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_addr = listener.local_addr().unwrap();

        // No listener can bind port zero: binding it allocates an ephemeral port.
        let bad_addr = "127.0.0.1:0".parse().unwrap();

        let remote = TransportAddr::from_string(&format!("localhost:{}", good_addr.port()));
        let stream =
            connect_to_any_addr(TransportId::new(1), &remote, &[bad_addr, good_addr], 1_000)
                .await
                .expect("second TCP candidate should connect");
        let (accepted, _) = timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), good_addr);
        assert_eq!(accepted.peer_addr().unwrap(), stream.local_addr().unwrap());
    }

    #[tokio::test]
    async fn test_connect_candidates_fail() {
        let id = TransportId::new(1);
        let remote = TransportAddr::from_string("localhost:0");
        assert!(matches!(
            connect_to_any_addr(id, &remote, &[], 1_000).await,
            Err(TransportError::InvalidAddress(ref message)) if message.ends_with("localhost:0")
        ));
        assert!(matches!(
            connect_to_any_addr(id, &remote, &["127.0.0.1:0".parse().unwrap()], 1_000).await,
            Err(TransportError::ConnectionRefused)
        ));
    }

    #[tokio::test]
    async fn test_connect_failure_logs_os_error_with_peer() {
        let remote = TransportAddr::from_string("localhost:0");
        let refused = ["127.0.0.1:0".parse().unwrap()];
        // Register the log callsite before installing the capture. Other
        // tests reach it in parallel, and one that registers it first while
        // this capture is the only subscriber caches its own thread's "never"
        // interest; installing the capture rebuilds already-registered
        // callsites, so registering first makes the capture see the event.
        let _ = connect_to_any_addr(TransportId::new(7), &remote, &refused, 1_000).await;
        let (logs, guard) = crate::testutil::capture_logs_scoped();
        let result = connect_to_any_addr(TransportId::new(7), &remote, &refused, 1_000).await;
        drop(guard);

        assert!(matches!(result, Err(TransportError::ConnectionRefused)));
        // The returned variant always reads "connection refused"; the log
        // line must carry the OS error and the peer instead.
        let lines = logs.lines();
        assert!(
            lines.iter().any(|line| line.starts_with("DEBUG")
                && line.contains("TCP connect failed")
                && line.contains("transport_id=transport:7")
                && line.contains("remote_addr=localhost:0")
                && line.contains("os error")),
            "expected a debug line with the OS error and peer, got {lines:?}",
        );
    }

    async fn send_to_hostname(background: bool) {
        // Prefer the last localhost address so dual-stack hosts also
        // exercise fallback through the full transport connection path.
        let mut addresses: Vec<_> = tokio::net::lookup_host("localhost:0")
            .await
            .unwrap()
            .collect();
        addresses.reverse();
        let listener = TcpListener::bind(addresses.as_slice()).await.unwrap();
        let (tx, _rx) = packet_channel(10);
        let config = make_outbound_config();
        // A refused localhost connection can take over two seconds on Windows.
        // Allow the configured connection timeout, plus DNS/scheduling margin.
        let connect_deadline =
            Duration::from_millis(config.connect_timeout_ms()) + Duration::from_secs(2);
        let mut sender = TcpTransport::new(TransportId::new(1), None, config, tx);
        sender.start_async().await.unwrap();
        let remote = TransportAddr::from_string(&format!(
            "localhost:{}",
            listener.local_addr().unwrap().port()
        ));

        if background {
            sender.connect_async(&remote).await.unwrap();
            assert!(
                wait_until(
                    || sender.connection_state_sync(&remote) == ConnectionState::Connected,
                    connect_deadline,
                )
                .await
            );
        }
        timeout(
            connect_deadline,
            sender.send_async(&remote, &build_msg1_frame()),
        )
        .await
        .expect("hostname send exceeded connection deadline")
        .unwrap();
        let (mut stream, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let packet = timeout(Duration::from_secs(2), read_fmp_packet(&mut stream, 1400))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(packet, build_msg1_frame());
        sender.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn test_connect_on_send_hostname() {
        send_to_hostname(false).await;
    }

    #[tokio::test]
    async fn test_connect_async_hostname() {
        send_to_hostname(true).await;
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

    /// The smallest frame the reader accepts as established: a 16-byte
    /// header, no payload, a 16-byte tag. The node drops one naming no
    /// session without closing the transport, so it is what a squatter
    /// sends to get past the first-frame deadline.
    fn squatter_frame() -> Vec<u8> {
        let frame = build_established_frame(0);
        assert_eq!(frame.len(), crate::proto::fmp::wire::ENCRYPTED_MIN_SIZE);
        frame
    }

    /// A remote that sends one well-formed frame and then goes silent must
    /// lose its inbound slot at the idle deadline, without disconnecting.
    ///
    /// The first-frame deadline is set far above the idle one, so the
    /// release can only be the idle deadline's doing. Break-check: scope the
    /// deadline back to the first read only and the count stays at 1.
    #[tokio::test]
    async fn inbound_connection_that_goes_silent_after_one_established_frame_releases_its_slot() {
        let (tx, mut rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);
        transport.set_first_frame_timeout(Duration::from_secs(5));
        transport.set_inbound_idle_timeout(Duration::from_millis(300));
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();

        let mut squatter = TcpStream::connect(listen).await.unwrap();
        squatter.write_all(&squatter_frame()).await.unwrap();
        let packet = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for the squatter's frame")
            .expect("packet channel closed");
        assert_eq!(packet.data, squatter_frame());
        assert_eq!(
            transport.stats().pool_inbound_count(),
            1,
            "the connection should hold its slot once its first frame is in"
        );

        assert!(
            wait_until(
                || transport.stats().pool_inbound_count() == 0,
                Duration::from_secs(2)
            )
            .await,
            "a connection silent after its first frame should lose its slot at the idle deadline"
        );
        assert!(
            transport.pool.lock().await.is_empty(),
            "the pool entry should go with the slot"
        );

        drop(squatter);
        transport.stop_async().await.unwrap();
    }

    /// With the cap filled by a one-frame squatter, a genuine peer is refused
    /// until the idle deadline frees the slot, and admitted afterwards.
    ///
    /// Break-check: without the idle deadline the squatter never releases,
    /// so the genuine peer's frame is never delivered.
    #[tokio::test]
    async fn inbound_cap_filled_by_one_frame_squatters_admits_a_genuine_peer_after_the_idle_deadline()
     {
        let (tx, mut rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, capped_config(1), tx);
        transport.set_first_frame_timeout(Duration::from_secs(5));
        transport.set_inbound_idle_timeout(Duration::from_secs(1));
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();

        let mut squatter = TcpStream::connect(listen).await.unwrap();
        squatter.write_all(&squatter_frame()).await.unwrap();
        timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for the squatter's frame")
            .expect("packet channel closed");
        assert_eq!(transport.stats().pool_inbound_count(), 1);

        // While the cap is full a genuine peer is rejected outright. The
        // 250 ms window ends well inside the squatter's 1 s idle deadline.
        let mut early = TcpStream::connect(listen).await.unwrap();
        let _ = early.write_all(&build_msg1_frame()).await;
        assert!(
            timeout(Duration::from_millis(250), rx.recv())
                .await
                .is_err(),
            "a peer arriving while the cap is full must not be admitted"
        );
        drop(early);

        assert!(
            wait_until(
                || transport.stats().pool_inbound_count() == 0,
                Duration::from_secs(3)
            )
            .await,
            "the idle deadline should free the slot the squatter took"
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

    /// The healthy path: a connection that delivers a frame more often than
    /// the idle deadline keeps its slot across many deadlines, and every
    /// frame is delivered. This is the shape of a link kept alive only by
    /// heartbeats.
    ///
    /// Break-check: a deadline that does not re-arm on each frame (a single
    /// deadline from accept) drops the connection after the first second.
    #[tokio::test]
    async fn inbound_connection_sending_a_frame_every_interval_below_the_idle_deadline_is_kept() {
        let (tx, mut rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);
        transport.set_first_frame_timeout(Duration::from_secs(1));
        transport.set_inbound_idle_timeout(Duration::from_secs(1));
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();

        let mut peer = TcpStream::connect(listen).await.unwrap();
        // Twelve frames 250 ms apart: 3 s, three idle deadlines, with 750 ms
        // of slack between each frame and the deadline it re-arms.
        for i in 0..12 {
            peer.write_all(&squatter_frame()).await.unwrap();
            let packet = timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap_or_else(|_| panic!("timeout waiting for frame {i}"))
                .expect("packet channel closed");
            assert_eq!(packet.data, squatter_frame());
            assert_eq!(
                transport.stats().pool_inbound_count(),
                1,
                "a connection delivering frames inside the idle deadline must keep its slot (frame {i})"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        assert_eq!(transport.stats().pool_inbound_count(), 1);
        assert!(!transport.pool.lock().await.is_empty());

        drop(peer);
        transport.stop_async().await.unwrap();
    }

    /// An established connection quiet for longer than the first-frame
    /// deadline, but not the idle deadline, keeps its slot: once a frame is
    /// in, the first-frame deadline no longer applies.
    ///
    /// Break-check: apply the first-frame deadline to every read and the
    /// connection is dropped after 200 ms of quiet.
    #[tokio::test]
    async fn established_connection_quiet_past_the_first_frame_deadline_is_kept() {
        let (tx, mut rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);
        transport.set_first_frame_timeout(Duration::from_millis(200));
        transport.set_inbound_idle_timeout(Duration::from_secs(5));
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();

        let mut peer = TcpStream::connect(listen).await.unwrap();
        peer.write_all(&build_msg1_frame()).await.unwrap();
        let packet = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout")
            .expect("packet channel closed");
        assert_eq!(packet.data, build_msg1_frame());

        // Four first-frame deadlines' worth of silence after the first frame.
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

    /// The idle deadline covers a complete frame, not its first bytes: a
    /// frame after the first whose prefix arrives inside the deadline and
    /// whose remainder arrives after it is not delivered, and the slot is
    /// released.
    ///
    /// Break-check: bound only the prefix read and the body read waits
    /// forever, so the late frame is delivered.
    #[tokio::test]
    async fn inbound_connection_dripping_a_frame_slower_than_the_idle_deadline_is_dropped() {
        let (tx, mut rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);
        transport.set_first_frame_timeout(Duration::from_secs(5));
        transport.set_inbound_idle_timeout(Duration::from_millis(300));
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();

        let mut peer = TcpStream::connect(listen).await.unwrap();
        peer.write_all(&squatter_frame()).await.unwrap();
        timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for the first frame")
            .expect("packet channel closed");

        let frame = squatter_frame();
        // Prefix inside the idle deadline, remainder well past it.
        peer.write_all(&frame[..4]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(600)).await;
        let _ = peer.write_all(&frame[4..]).await;

        assert!(
            timeout(Duration::from_millis(500), rx.recv())
                .await
                .is_err(),
            "a frame completing after the idle deadline must not be delivered"
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
            Some(InboundDeadline {
                first_frame: Duration::from_millis(50),
                idle: Duration::from_millis(50),
            }),
            Some(ready_rx),
            Arc::default(),
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
            Arc::default(),
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
            Arc::default(),
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

    /// Stopping the transport must stop a writer that is still draining after
    /// a deliberate close, rather than leave it to its drain timer.
    ///
    /// The writer holds a oneshot sender and never finishes, so the sender is
    /// dropped only once the task has been aborted. A stop that left it
    /// draining returns with the sender still held.
    #[tokio::test]
    async fn stopping_the_transport_ends_a_writer_still_draining_after_a_close() {
        let (tx1, _rx1) = packet_channel(100);
        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
        t1.start_async().await.unwrap();
        let remote = TransportAddr::from_string("127.0.0.1:9");
        let (guard_tx, mut guard_rx) = tokio::sync::oneshot::channel::<()>();
        t1.pool.lock().await.insert(
            PoolKey::outbound(remote.clone()),
            TcpConnection {
                send_tx: mpsc::channel(1).0,
                send_task: tokio::spawn(async move {
                    let _guard = guard_tx;
                    std::future::pending::<()>().await
                }),
                recv_task: tokio::spawn(std::future::pending::<()>()),
                mtu: 1400,
                established_at: Instant::now(),
                direction: Direction::Outbound,
                id: next_conn_id(),
            },
        );
        t1.stats.record_pool_outbound_added();

        t1.close_connection_async(&remote).await;
        timeout(Duration::from_secs(2), t1.stop_async())
            .await
            .expect("stop waited on a draining writer")
            .unwrap();

        assert!(
            matches!(
                guard_rx.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Closed)
            ),
            "a writer still draining after a close outlived the transport's stop"
        );
    }

    /// No frame a deliberate close left queued may reach the peer after the
    /// transport has stopped.
    ///
    /// The writer is parked on a peer that does not read, with a full queue,
    /// and the connection is closed and the transport stopped before the peer
    /// reads anything. A writer left draining delivers every frame it had
    /// queued once the peer reads; a stopped one delivers fewer, since the
    /// queue alone holds more frames than the kernel buffers leave unread.
    #[tokio::test]
    async fn no_queued_frame_reaches_the_peer_after_the_transport_stops() {
        let (tx1, _rx1) = packet_channel(100);
        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
        t1.start_async().await.unwrap();
        let listener = capped_deaf_listener();
        let remote = TransportAddr::from_string(&listener.local_addr().unwrap().to_string());
        let frame = vec![0xAB; 1400];

        let queued = park_tcp_writer(&t1, &remote, &frame).await;
        let (mut peer, _) = listener.accept().await.unwrap();

        t1.close_connection_async(&remote).await;
        t1.stop_async().await.unwrap();

        let read = read_to_eof(&mut peer, Duration::from_secs(10))
            .await
            .expect("the connection was never closed toward the peer");
        assert!(read > 0, "the kernel buffers held written frames");
        assert!(
            read < queued * frame.len(),
            "the writer kept writing after the transport stopped: \
             read={read} queued_bytes={}",
            queued * frame.len()
        );
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

    /// A minimal msg1-phase frame the receive loop accepts.
    fn msg1_frame() -> Vec<u8> {
        let mut frame = vec![0xAA; 114];
        frame[0] = 0x01;
        frame[1] = 0x00;
        frame[2..4].copy_from_slice(&110u16.to_le_bytes());
        frame
    }

    /// A minimal msg2-phase frame the receive loop accepts.
    fn msg2_frame() -> Vec<u8> {
        let mut frame = vec![0xBB; 69];
        frame[0] = 0x02;
        frame[1] = 0x00;
        frame[2..4].copy_from_slice(&65u16.to_le_bytes());
        frame
    }

    /// Wait until the background connect to `remote` has finished, leaving
    /// it unpromoted in the connecting map.
    async fn wait_connect_finished(t: &TcpTransport, remote: &TransportAddr) {
        let finished = wait_until(
            || {
                t.connecting
                    .try_lock()
                    .is_ok_and(|c| c.get(remote).is_some_and(|e| e.task.is_finished()))
            },
            Duration::from_secs(3),
        )
        .await;
        assert!(finished, "background connect to {remote} never finished");
    }

    /// With no pooled connection and no connect under way, `send_existing`
    /// fails with `NotConnected` and opens nothing.
    #[tokio::test]
    async fn send_existing_without_connection_fails_fast_and_dials_nothing() {
        let (tx1, _rx1) = packet_channel(100);
        let (tx2, _rx2) = packet_channel(100);
        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
        let mut t2 = TcpTransport::new(TransportId::new(2), None, make_config(), tx2);
        t1.start_async().await.unwrap();
        t2.start_async().await.unwrap();
        // Reachable, so a send that dialed would succeed.
        let remote = TransportAddr::from_string(&t2.local_addr().unwrap().to_string());

        let result = t1.send_existing(&remote, &msg1_frame()).await;

        assert!(
            matches!(result, Err(TransportError::NotConnected)),
            "expected NotConnected, got {result:?}"
        );
        assert!(
            t1.connecting.lock().await.is_empty(),
            "a connect was started"
        );
        assert_eq!(t1.connection_state_sync(&remote), ConnectionState::None);
        assert_eq!(t1.stats().snapshot().connections_established, 0);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            t2.stats().snapshot().connections_accepted,
            0,
            "the remote saw a connection"
        );

        t1.stop_async().await.unwrap();
        t2.stop_async().await.unwrap();
    }

    /// A background connect that has finished is moved into the pool and
    /// carries the send, with no second connection opened.
    #[tokio::test]
    async fn send_existing_promotes_a_finished_background_connect_and_sends_on_it() {
        let (tx1, _rx1) = packet_channel(100);
        let (tx2, mut rx2) = packet_channel(100);
        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
        let mut t2 = TcpTransport::new(TransportId::new(2), None, make_config(), tx2);
        t1.start_async().await.unwrap();
        t2.start_async().await.unwrap();
        let remote = TransportAddr::from_string(&t2.local_addr().unwrap().to_string());

        t1.connect_async(&remote).await.unwrap();
        wait_connect_finished(&t1, &remote).await;
        let frame = msg1_frame();
        let sent = t1.send_existing(&remote, &frame).await.unwrap();
        assert_eq!(sent, frame.len());

        let packet = timeout(Duration::from_secs(2), rx2.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(packet.data, frame);
        assert!(
            t1.connecting.lock().await.is_empty(),
            "the finished connect was left in the connecting map"
        );
        let stats = t1.stats().snapshot();
        assert_eq!(stats.connections_established, 1);
        assert_eq!(stats.pool_outbound, 1);
        assert_eq!(
            t2.stats().snapshot().connections_accepted,
            1,
            "the send used the background connection, not a new one"
        );

        t1.stop_async().await.unwrap();
        t2.stop_async().await.unwrap();
    }

    /// `has_connection` reports only what the pool holds. A finished
    /// background connect is not a pooled connection and is left where it
    /// is; once `send_existing` has promoted it, the connection is reported,
    /// and the accepting side reports the connection by its remote address.
    #[tokio::test]
    async fn has_connection_reports_the_pool_and_never_promotes_a_finished_connect() {
        let (tx1, _rx1) = packet_channel(100);
        let (tx2, mut rx2) = packet_channel(100);
        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
        let mut t2 = TcpTransport::new(TransportId::new(2), None, make_config(), tx2);
        t1.start_async().await.unwrap();
        t2.start_async().await.unwrap();
        let remote = TransportAddr::from_string(&t2.local_addr().unwrap().to_string());

        assert!(
            !t1.has_connection(&remote).await,
            "no connection before any connect"
        );

        t1.connect_async(&remote).await.unwrap();
        wait_connect_finished(&t1, &remote).await;
        assert!(
            !t1.has_connection(&remote).await,
            "a finished connect that is not pooled is not a connection"
        );
        assert!(
            t1.connecting.lock().await.contains_key(&remote),
            "the query moved the finished connect out of the connecting map"
        );
        assert!(
            t1.pool.lock().await.is_empty(),
            "the query put a connection in the pool"
        );
        assert_eq!(
            t1.stats().snapshot().connections_established,
            0,
            "the query promoted the finished connect"
        );

        t1.send_existing(&remote, &msg1_frame()).await.unwrap();
        assert!(
            t1.has_connection(&remote).await,
            "the promoted connection is pooled"
        );

        let packet = timeout(Duration::from_secs(2), rx2.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert!(
            t2.has_connection(&packet.remote_addr).await,
            "the accepting side holds the inbound connection by its remote address"
        );

        t1.stop_async().await.unwrap();
        t2.stop_async().await.unwrap();
    }

    /// A pooled connection that cannot take a frame is still reported, as
    /// `send_existing` finds it and fails on the enqueue rather than with
    /// `NotConnected`. Holds for a full queue and for a writer that has gone
    /// but not yet removed its entry. Reporting either as absent would let an
    /// off-link msg1 be answered as a rekey whose reply cannot be sent.
    #[tokio::test]
    async fn has_connection_reports_a_pooled_connection_whose_queue_is_full_or_closed() {
        let (tx, _rx) = packet_channel(100);
        let mut t = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx);
        t.start_async().await.unwrap();
        let remote = TransportAddr::from_string("127.0.0.1:9");

        let (send_tx, send_rx) = mpsc::channel(1);
        send_tx.try_send(vec![0]).unwrap();
        t.pool.lock().await.insert(
            PoolKey::outbound(remote.clone()),
            TcpConnection {
                send_tx,
                send_task: tokio::spawn(async {}),
                recv_task: tokio::spawn(async {}),
                mtu: 1234,
                established_at: Instant::now(),
                direction: Direction::Outbound,
                id: next_conn_id(),
            },
        );

        assert!(
            matches!(
                t.send_existing(&remote, &msg1_frame()).await,
                Err(TransportError::SendFailed(_))
            ),
            "a full queue fails the enqueue, not the lookup"
        );
        assert!(
            t.has_connection(&remote).await,
            "a pooled connection with a full queue is reported"
        );

        drop(send_rx);
        assert!(
            matches!(
                t.send_existing(&remote, &msg1_frame()).await,
                Err(TransportError::SendFailed(_))
            ),
            "a gone writer fails the enqueue, not the lookup"
        );
        assert!(
            t.has_connection(&remote).await,
            "a pooled connection whose writer has gone is reported"
        );

        t.stop_async().await.unwrap();
    }

    /// A background connect that failed is dropped from the connecting map,
    /// the send fails with `NotConnected`, and `connect_async` can start again.
    #[tokio::test]
    async fn send_existing_after_a_failed_background_connect_drops_it_so_a_new_one_can_start() {
        let (tx, _rx) = packet_channel(100);
        let mut t = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx);
        t.start_async().await.unwrap();
        // A port nothing listens on: the connect is refused.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let remote = TransportAddr::from_string(&closed.local_addr().unwrap().to_string());
        drop(closed);

        t.connect_async(&remote).await.unwrap();
        wait_connect_finished(&t, &remote).await;
        let result = t.send_existing(&remote, &msg1_frame()).await;

        assert!(
            matches!(result, Err(TransportError::NotConnected)),
            "expected NotConnected, got {result:?}"
        );
        assert!(
            t.connecting.lock().await.get(&remote).is_none(),
            "the failed connect was left in the connecting map"
        );
        t.connect_async(&remote).await.unwrap();
        assert!(
            t.connecting.lock().await.get(&remote).is_some(),
            "connect_async did not start a new attempt"
        );

        t.stop_async().await.unwrap();
    }

    /// A reply to a peer that connected in goes back on that inbound
    /// connection.
    #[tokio::test]
    async fn send_existing_replies_on_a_live_inbound_connection() {
        let (tx1, mut rx1) = packet_channel(100);
        let (tx2, mut rx2) = packet_channel(100);
        let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
        let mut t2 = TcpTransport::new(TransportId::new(2), None, make_config(), tx2);
        t1.start_async().await.unwrap();
        t2.start_async().await.unwrap();
        let remote = TransportAddr::from_string(&t2.local_addr().unwrap().to_string());

        t1.send_async(&remote, &msg1_frame()).await.unwrap();
        let inbound = timeout(Duration::from_secs(2), rx2.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        // The frame is only forwarded once the accept loop has pooled the
        // connection, so a reply to its address finds it.
        let reply = msg2_frame();
        t2.send_existing(&inbound.remote_addr, &reply)
            .await
            .unwrap();

        let packet = timeout(Duration::from_secs(2), rx1.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(packet.data, reply);
        assert_eq!(
            t2.stats().snapshot().connections_established,
            0,
            "the reply dialed"
        );

        t1.stop_async().await.unwrap();
        t2.stop_async().await.unwrap();
    }

    /// A background connect that times out is counted in `connect_timeouts`,
    /// as an inline one is.
    #[tokio::test]
    async fn background_connect_timeout_is_counted() {
        let bh = Blackhole::silent();
        let (tx, _rx) = packet_channel(100);
        let config = TcpConfig {
            connect_timeout_ms: Some(200),
            ..make_outbound_config()
        };
        let mut t = TcpTransport::new(TransportId::new(1), None, config, tx);
        t.start_async().await.unwrap();
        let remote = bh.transport_addr();

        t.connect_async(&remote).await.unwrap();
        wait_connect_finished(&t, &remote).await;

        let stats = t.stats().snapshot();
        assert_eq!(stats.connect_timeouts, 1, "the timeout was not counted");
        assert_eq!(stats.connect_refused, 0);
        assert_eq!(
            t.connection_state_sync(&remote),
            ConnectionState::Failed("transport timeout".into())
        );
        assert_eq!(
            t.stats().snapshot().connect_timeouts,
            1,
            "taking the result counted the timeout again"
        );

        t.stop_async().await.unwrap();
    }

    /// A background connect that is refused is counted in `connect_refused`,
    /// as an inline one is.
    #[tokio::test]
    async fn background_connect_refusal_is_counted() {
        let (tx, _rx) = packet_channel(100);
        let mut t = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx);
        t.start_async().await.unwrap();
        // A port nothing listens on: the connect is refused.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let remote = TransportAddr::from_string(&closed.local_addr().unwrap().to_string());
        drop(closed);

        t.connect_async(&remote).await.unwrap();
        wait_connect_finished(&t, &remote).await;

        let stats = t.stats().snapshot();
        assert_eq!(stats.connect_refused, 1, "the refusal was not counted");
        assert_eq!(stats.connect_timeouts, 0);
        let result = t.send_existing(&remote, &msg1_frame()).await;
        assert!(matches!(result, Err(TransportError::NotConnected)));
        assert_eq!(
            t.stats().snapshot().connect_refused,
            1,
            "taking the result counted the refusal again"
        );

        t.stop_async().await.unwrap();
    }

    // ========================================================================
    // Accept and close lines
    // ========================================================================

    /// Every captured line whose message is exactly `message`.
    fn lines_with(logs: &crate::testutil::LogCapture, message: &str) -> Vec<String> {
        let needle = format!(" message={message}");
        logs.lines()
            .into_iter()
            .filter(|line| {
                line.match_indices(&needle).any(|(at, _)| {
                    let rest = &line[at + needle.len()..];
                    rest.is_empty()
                        || rest
                            .strip_prefix(' ')
                            .and_then(|r| r.split(' ').next())
                            .is_some_and(|t| t.contains('='))
                })
            })
            .collect()
    }

    /// The value of `name` on `line`, or a panic naming the line.
    fn field(line: &str, name: &str) -> String {
        crate::testutil::log_field(line, name)
            .unwrap_or_else(|| panic!("no field {name} on {line}"))
            .to_string()
    }

    /// Wait for the close line of the connection whose remote address is
    /// `remote`, or panic listing what was captured.
    async fn close_line(logs: &crate::testutil::LogCapture, remote: &str) -> String {
        let find = || {
            lines_with(logs, "Closed TCP connection")
                .into_iter()
                .find(|l| crate::testutil::log_field(l, "remote_addr") == Some(remote))
        };
        wait_until(|| find().is_some(), Duration::from_secs(3)).await;
        find().unwrap_or_else(|| panic!("no close line for {remote} in {:#?}", logs.lines()))
    }

    /// The transport's accept lines are counted per source address, and the
    /// whole pool's inbound count is given beside it.
    #[tokio::test]
    async fn an_accepted_connection_logs_how_many_inbound_connections_its_source_holds() {
        let (tx, _rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();
        let (logs, guard) = crate::testutil::capture_logs_scoped();

        let first = TcpStream::connect(listen).await.unwrap();
        let second = TcpStream::connect(listen).await.unwrap();
        assert!(
            wait_until(
                || transport.stats().pool_inbound_count() == 2,
                Duration::from_secs(2)
            )
            .await
        );
        let lines = lines_with(&logs, "Accepted inbound TCP connection");
        assert_eq!(lines.len(), 2, "{lines:#?}");
        assert_eq!(field(&lines[0], "open_from_source"), "1", "{}", lines[0]);
        assert_eq!(field(&lines[1], "open_from_source"), "2", "{}", lines[1]);
        assert_eq!(field(&lines[1], "open_total"), "2", "{}", lines[1]);

        // A third connection from another address of the same host is a
        // different source.
        #[cfg(target_os = "linux")]
        let third = {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.bind("127.0.0.2:0".parse().unwrap()).unwrap();
            let stream = socket.connect(listen).await.unwrap();
            assert!(
                wait_until(
                    || transport.stats().pool_inbound_count() == 3,
                    Duration::from_secs(2)
                )
                .await
            );
            let lines = lines_with(&logs, "Accepted inbound TCP connection");
            assert_eq!(lines.len(), 3, "{lines:#?}");
            assert_eq!(field(&lines[2], "open_from_source"), "1", "{}", lines[2]);
            assert_eq!(field(&lines[2], "open_total"), "3", "{}", lines[2]);
            stream
        };
        drop(guard);

        drop((first, second));
        #[cfg(target_os = "linux")]
        drop(third);
        transport.stop_async().await.unwrap();
    }

    fn source_capped_config(source_cap: usize) -> TcpConfig {
        TcpConfig {
            max_inbound_per_source: Some(source_cap),
            ..capped_config(16)
        }
    }

    /// Open a connection to `listen` that sends one msg1 frame, and wait
    /// for the frame to be delivered.
    async fn admitted_peer(listen: SocketAddr, rx: &mut crate::transport::PacketRx) -> TcpStream {
        let mut peer = TcpStream::connect(listen).await.unwrap();
        peer.write_all(&build_msg1_frame()).await.unwrap();
        let packet = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for an admitted peer's frame")
            .expect("packet channel closed");
        assert_eq!(packet.data, build_msg1_frame());
        peer
    }

    /// With a per-source bound below the global cap, the connection past
    /// the bound from one address is closed and counted, while a connection
    /// from another address is still admitted.
    ///
    /// Break-check: without the per-source gate the fourth connection's
    /// frame is delivered and `source_rejected` stays 0.
    #[tokio::test]
    async fn inbound_connections_beyond_the_per_source_bound_are_refused_and_counted_while_another_source_is_admitted()
     {
        use tokio::io::AsyncReadExt;

        const N: usize = 3;
        let (tx, mut rx) = packet_channel(100);
        let mut transport =
            TcpTransport::new(TransportId::new(1), None, source_capped_config(N), tx);
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();

        let mut held = Vec::new();
        for _ in 0..N {
            held.push(admitted_peer(listen, &mut rx).await);
        }
        assert_eq!(transport.stats().pool_inbound_count(), N as u64);

        let mut over = TcpStream::connect(listen).await.unwrap();
        let _ = over.write_all(&build_msg1_frame()).await;
        assert!(
            timeout(Duration::from_millis(250), rx.recv())
                .await
                .is_err(),
            "a connection past the per-source bound must not be admitted"
        );
        let mut buf = [0u8; 16];
        match timeout(Duration::from_secs(2), over.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("the refused connection received {n} bytes"),
            Err(_) => panic!("the refused connection was left open"),
        }
        let stats = transport.stats().clone();
        assert!(
            wait_until(
                || stats.snapshot().source_rejected == 1,
                Duration::from_secs(2)
            )
            .await,
            "the refusal should be counted as per-source"
        );
        assert_eq!(stats.snapshot().connections_rejected, 1);
        assert_eq!(stats.pool_inbound_count(), N as u64);

        // Another address of the same host is a different source.
        #[cfg(target_os = "linux")]
        {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.bind("127.0.0.2:0".parse().unwrap()).unwrap();
            let mut other = socket.connect(listen).await.unwrap();
            other.write_all(&build_msg1_frame()).await.unwrap();
            let packet = timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("a connection from another source should be admitted")
                .expect("packet channel closed");
            assert_eq!(packet.data, build_msg1_frame());
            assert_eq!(stats.snapshot().source_rejected, 1);
            held.push(other);
        }

        drop(held);
        drop(over);
        transport.stop_async().await.unwrap();
    }

    /// The per-source count follows the pool, so a source at its bound is
    /// admitted again once one of its connections closes.
    ///
    /// Break-check: a per-source count that is never released on close
    /// refuses the new connection.
    #[tokio::test]
    async fn a_source_at_its_per_source_bound_is_admitted_again_after_one_of_its_connections_closes()
     {
        const N: usize = 3;
        let (tx, mut rx) = packet_channel(100);
        let mut transport =
            TcpTransport::new(TransportId::new(1), None, source_capped_config(N), tx);
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();

        let mut held = Vec::new();
        for _ in 0..N {
            held.push(admitted_peer(listen, &mut rx).await);
        }
        drop(held.pop());
        assert!(
            wait_until(
                || transport.stats().pool_inbound_count() == (N - 1) as u64,
                Duration::from_secs(2)
            )
            .await,
            "the closed connection should leave the pool"
        );

        held.push(admitted_peer(listen, &mut rx).await);
        assert_eq!(transport.stats().snapshot().source_rejected, 0);
        assert_eq!(transport.stats().pool_inbound_count(), N as u64);

        drop(held);
        transport.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn a_silent_inbound_connection_logs_its_close_at_the_first_frame_deadline() {
        let (tx, _rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);
        transport.set_first_frame_timeout(Duration::from_millis(100));
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();
        let (logs, guard) = crate::testutil::capture_logs_scoped();

        let client = TcpStream::connect(listen).await.unwrap();
        let remote = client.local_addr().unwrap().to_string();
        let line = close_line(&logs, &remote).await;
        drop(guard);
        assert!(line.starts_with("DEBUG"), "{line}");
        assert_eq!(field(&line, "reason"), "first-frame", "{line}");
        assert_eq!(field(&line, "frames"), "0", "{line}");
        assert_eq!(field(&line, "msg2_sent"), "false", "{line}");
        assert_eq!(field(&line, "direction"), "Inbound", "{line}");
        assert_eq!(field(&line, "transport_id"), "transport:1", "{line}");
        assert_eq!(field(&line, "lifetime_s"), "0", "{line}");

        drop(client);
        transport.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn a_connection_that_falls_silent_after_a_frame_logs_an_idle_close() {
        let (tx, _rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);
        transport.set_inbound_idle_timeout(Duration::from_millis(100));
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();
        let (logs, guard) = crate::testutil::capture_logs_scoped();

        let mut client = TcpStream::connect(listen).await.unwrap();
        client.write_all(&msg1_frame()).await.unwrap();
        let remote = client.local_addr().unwrap().to_string();
        let line = close_line(&logs, &remote).await;
        drop(guard);
        assert_eq!(field(&line, "reason"), "idle", "{line}");
        assert_eq!(field(&line, "frames"), "1", "{line}");

        drop(client);
        transport.stop_async().await.unwrap();
    }

    /// An inbound connection that this node answered with a msg2 says so when
    /// it closes, and one it never answered does not.
    #[tokio::test]
    async fn an_inbound_connection_answered_with_a_msg2_logs_msg2_sent_when_the_remote_closes() {
        let (tx, mut rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();
        let (logs, guard) = crate::testutil::capture_logs_scoped();

        let mut answered = TcpStream::connect(listen).await.unwrap();
        answered.write_all(&msg1_frame()).await.unwrap();
        let packet = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for the msg1")
            .expect("packet channel closed");
        transport
            .send_async(&packet.remote_addr, &msg2_frame())
            .await
            .unwrap();
        let mut reply = vec![0u8; msg2_frame().len()];
        timeout(
            Duration::from_secs(2),
            tokio::io::AsyncReadExt::read_exact(&mut answered, &mut reply),
        )
        .await
        .expect("timeout waiting for the msg2")
        .unwrap();
        let answered_addr = answered.local_addr().unwrap().to_string();
        drop(answered);

        let mut unanswered = TcpStream::connect(listen).await.unwrap();
        unanswered.write_all(&msg1_frame()).await.unwrap();
        timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for the second msg1")
            .expect("packet channel closed");
        let unanswered_addr = unanswered.local_addr().unwrap().to_string();
        drop(unanswered);

        let line = close_line(&logs, &answered_addr).await;
        assert_eq!(field(&line, "reason"), "remote-closed", "{line}");
        assert_eq!(field(&line, "frames"), "1", "{line}");
        assert_eq!(field(&line, "msg2_sent"), "true", "{line}");
        let line = close_line(&logs, &unanswered_addr).await;
        drop(guard);
        assert_eq!(field(&line, "reason"), "remote-closed", "{line}");
        assert_eq!(field(&line, "frames"), "1", "{line}");
        assert_eq!(field(&line, "msg2_sent"), "false", "{line}");

        transport.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn a_connection_closed_by_the_node_logs_a_local_close() {
        let (tx, mut rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();
        let (logs, guard) = crate::testutil::capture_logs_scoped();

        let mut client = TcpStream::connect(listen).await.unwrap();
        client.write_all(&msg1_frame()).await.unwrap();
        let packet = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for the frame")
            .expect("packet channel closed");
        transport.close_connection_async(&packet.remote_addr).await;
        let line = close_line(&logs, &packet.remote_addr.to_string()).await;
        drop(guard);
        assert_eq!(field(&line, "reason"), "local", "{line}");
        assert_eq!(field(&line, "frames"), "1", "{line}");

        drop(client);
        transport.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn a_connection_sending_a_non_fmp_stream_logs_a_framing_close() {
        let (tx, _rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();
        let (logs, guard) = crate::testutil::capture_logs_scoped();

        // The first bytes of a TLS ClientHello: version nibble 1.
        let mut client = TcpStream::connect(listen).await.unwrap();
        client
            .write_all(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01])
            .await
            .unwrap();
        let remote = client.local_addr().unwrap().to_string();
        let line = close_line(&logs, &remote).await;
        drop(guard);
        assert_eq!(field(&line, "reason"), "framing", "{line}");
        assert_eq!(field(&line, "frames"), "0", "{line}");

        drop(client);
        transport.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn a_connection_whose_node_stopped_receiving_logs_a_channel_closed_close() {
        let (tx, rx) = packet_channel(100);
        let mut transport = TcpTransport::new(TransportId::new(1), None, make_config(), tx);
        transport.start_async().await.unwrap();
        let listen = transport.local_addr().unwrap();
        drop(rx);
        let (logs, guard) = crate::testutil::capture_logs_scoped();

        let mut client = TcpStream::connect(listen).await.unwrap();
        client.write_all(&msg1_frame()).await.unwrap();
        let remote = client.local_addr().unwrap().to_string();
        let line = close_line(&logs, &remote).await;
        drop(guard);
        assert_eq!(field(&line, "reason"), "channel-closed", "{line}");
        assert_eq!(field(&line, "frames"), "1", "{line}");

        drop(client);
        transport.stop_async().await.unwrap();
    }

    /// Connections this node dialled log their close too, whether opened by a
    /// send or by a background connect.
    #[tokio::test]
    async fn outbound_connections_log_their_close_with_the_outbound_direction() {
        let (tx, _rx) = packet_channel(100);
        let mut t = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx);
        t.start_async().await.unwrap();
        let (logs, guard) = crate::testutil::capture_logs_scoped();

        // Opened by a send.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let on_send = TransportAddr::from_string(&listener.local_addr().unwrap().to_string());
        t.send_async(&on_send, &msg1_frame()).await.unwrap();
        let (accepted, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        drop(accepted);
        let line = close_line(&logs, &on_send.to_string()).await;
        assert_eq!(field(&line, "direction"), "Outbound", "{line}");
        assert_eq!(field(&line, "reason"), "remote-closed", "{line}");
        assert_eq!(field(&line, "frames"), "0", "{line}");

        // Opened by a background connect, then promoted by a send.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let background = TransportAddr::from_string(&listener.local_addr().unwrap().to_string());
        t.connect_async(&background).await.unwrap();
        wait_connect_finished(&t, &background).await;
        t.send_existing(&background, &msg1_frame()).await.unwrap();
        let (accepted, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        drop(accepted);
        let line = close_line(&logs, &background.to_string()).await;
        drop(guard);
        assert_eq!(field(&line, "direction"), "Outbound", "{line}");
        assert_eq!(field(&line, "reason"), "remote-closed", "{line}");

        t.stop_async().await.unwrap();
    }

    #[test]
    fn inbound_sources_are_ipv4_addresses_and_ipv6_slash_64s() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_ne!(source_of(ip("10.0.0.1")), source_of(ip("10.0.0.2")));
        assert_eq!(source_of(ip("::ffff:10.0.0.1")), ip("10.0.0.1"));
        assert_eq!(
            source_of(ip("2001:db8:1:2::1")),
            source_of(ip("2001:db8:1:2:ffff:ffff:ffff:ffff")),
            "one /64 is one source"
        );
        assert_ne!(
            source_of(ip("2001:db8:1:2::1")),
            source_of(ip("2001:db8:1:3::1")),
            "neighbouring /64s are different sources"
        );
        assert_eq!(source_of(ip("2001:db8:1:2::1")), ip("2001:db8:1:2::"));
    }

    /// The per-source count reads IPv6 pool keys back and groups them by
    /// /64, counting only inbound entries.
    #[tokio::test]
    async fn inbound_from_source_counts_inbound_ipv6_entries_by_slash_64() {
        let local: SocketAddr = "[2001:db8:ffff::1]:443".parse().unwrap();
        let entry = |direction| TcpConnection {
            send_tx: mpsc::channel(1).0,
            send_task: tokio::spawn(async {}),
            recv_task: tokio::spawn(async {}),
            mtu: 1400,
            established_at: Instant::now(),
            direction,
            id: next_conn_id(),
        };
        let remote = |s: &str| TransportAddr::from_string(s);
        let mut pool = PoolMap::new();
        for addr in ["[2001:db8:1:2::1]:5000", "[2001:db8:1:2::abcd]:5001"] {
            pool.insert(
                PoolKey::inbound(remote(addr), local),
                entry(Direction::Inbound),
            );
        }
        pool.insert(
            PoolKey::inbound(remote("[2001:db8:1:3::1]:5000"), local),
            entry(Direction::Inbound),
        );
        pool.insert(
            PoolKey::outbound(remote("[2001:db8:1:2::2]:8443")),
            entry(Direction::Outbound),
        );

        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(inbound_from_source(&pool, ip("2001:db8:1:2::ffff")), 2);
        assert_eq!(inbound_from_source(&pool, ip("2001:db8:1:3::9")), 1);
        assert_eq!(inbound_from_source(&pool, ip("2001:db8:1:4::1")), 0);
    }
}
