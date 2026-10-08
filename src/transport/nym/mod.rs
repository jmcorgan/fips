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
//! stream framing from `transport::framing` and follows the same connection
//! pool pattern. No inbound service is supported.

pub mod stats;

use super::{
    ConnectionState, DiscoveredPeer, PacketTx, Transport, TransportAddr, TransportError,
    TransportId, TransportState, TransportType,
};
use crate::config::NymConfig;
use crate::transport::socks5::{
    ConnectingEntry, ConnectingPool, DialError, ProxiedConnection, ProxiedPool, SEND_QUEUE_DEPTH,
    Socks5Auth, Socks5Dialer, SocksTarget, existing_sender, is_pooled, poll_connecting,
    proxied_receive_loop, proxied_send_loop,
};
use crate::transport::stream::{ConnId, DrainingWriters, WRITER_DRAIN_TIMEOUT, next_conn_id};
use stats::NymStats;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{debug, info, warn};

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
    pool: ProxiedPool<()>,
    /// Pending connection attempts: addr -> background connect task.
    connecting: ConnectingPool,
    /// Channel for delivering received packets to Node.
    packet_tx: PacketTx,
    /// Transport statistics.
    stats: Arc<NymStats>,
    /// Writers of deliberately closed connections still finishing their
    /// queues, which `stop_async` must also stop.
    draining: DrainingWriters,
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
            draining: DrainingWriters::default(),
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
            conn.send_task.abort();
            let _ = conn.recv_task.await;
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "Nym connection closed (transport stopping)"
            );
        }
        drop(pool);

        // Writers of connections closed before the stop are out of the pool,
        // so the loop above does not reach them.
        self.draining.stop().await;

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
        self.check_mtu(data)?;

        // Get or create the connection's send queue. Never the write half:
        // this function must not be able to await the wire (see
        // `proxied_send_loop`).
        let send_tx = {
            let pool = self.pool.lock().await;
            pool.get(addr).map(|c| c.send_tx.clone())
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
        let send_tx = existing_sender(&self.pool, &self.connecting, addr, |stream, mtu| {
            let conn = self.outbound_connection(addr, stream, mtu);
            self.record_promoted(addr);
            conn
        })
        .await
        .ok_or(TransportError::NotConnected)?;
        self.enqueue(addr, &send_tx, data)
    }

    /// Whether the pool holds a connection to `addr`: true exactly when
    /// [`send_existing`](Self::send_existing) finds one there without
    /// promoting a finished background connect.
    ///
    /// Reads only: a finished background connect is not moved into the pool,
    /// and the pool lock is awaited rather than tried.
    pub async fn has_connection(&self, addr: &TransportAddr) -> bool {
        is_pooled(&self.pool, addr).await
    }

    /// Reject a packet larger than the transport MTU before queueing it.
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
        send_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        // Queue the frame. `try_send`, not `send`: awaiting a full queue would
        // reinstate one level up exactly the block this removes. The byte
        // count is what was queued; bytes on the wire are recorded by the
        // writer task.
        match send_tx.try_send(data.to_vec()) {
            Ok(()) => Ok(data.len()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                self.stats.record_send_error();
                debug!(
                    transport_id = %self.transport_id,
                    remote_addr = %addr,
                    depth = SEND_QUEUE_DEPTH,
                    "Nym outbound queue full; peer is not draining"
                );
                Err(TransportError::SendFailed(
                    "outbound queue full: peer not draining".to_string(),
                ))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                self.stats.record_send_error();
                Err(TransportError::SendFailed(
                    "connection writer gone".to_string(),
                ))
            }
        }
    }

    /// Establish a new connection through the Nym SOCKS5 proxy.
    async fn connect(
        &self,
        addr: &TransportAddr,
    ) -> Result<tokio::sync::mpsc::Sender<Vec<u8>>, TransportError> {
        let target_addr = parse_target_addr(addr)?;
        let proxy_addr = self.config.socks5_addr();
        let timeout_ms = self.config.connect_timeout_ms();

        debug!(
            transport_id = %self.transport_id,
            remote_addr = %addr,
            proxy = %proxy_addr,
            timeout_secs = timeout_ms / 1000,
            "Connecting via Nym mixnet SOCKS5 proxy"
        );

        let dialer = Socks5Dialer {
            proxy_addr: proxy_addr.to_string(),
            connect_timeout: Duration::from_millis(timeout_ms),
            auth: Socks5Auth::None,
        };

        let connect_start = Instant::now();
        let stream = match dialer.dial(&target_addr).await {
            Ok(stream) => stream,
            Err(DialError::Socks(e)) => {
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
            Err(DialError::Timeout) => {
                self.stats.record_connect_timeout();
                warn!(
                    transport_id = %self.transport_id,
                    remote_addr = %addr,
                    timeout_secs = timeout_ms / 1000,
                    "Nym SOCKS5 connection timed out"
                );
                return Err(TransportError::Timeout);
            }
            Err(DialError::Setup(e)) => return Err(e),
        };

        // Split and spawn receive task
        let (read_half, write_half) = stream.into_split();

        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let pool = self.pool.clone();
        let recv_stats = self.stats.clone();
        let remote_addr = addr.clone();
        let mtu = self.config.mtu();
        let id = next_conn_id();

        let recv_task = tokio::spawn(async move {
            nym_receive_loop(
                read_half,
                transport_id,
                remote_addr.clone(),
                id,
                packet_tx,
                pool,
                mtu,
                recv_stats,
            )
            .await;
        });

        let (send_tx, send_rx) = tokio::sync::mpsc::channel(SEND_QUEUE_DEPTH);
        let send_task = tokio::spawn(proxied_send_loop(
            write_half,
            send_rx,
            transport_id,
            addr.clone(),
            id,
            self.pool.clone(),
            self.stats.clone(),
            "Nym",
            |_stats: &NymStats, _meta: &()| {},
        ));

        let conn = ProxiedConnection {
            send_tx: send_tx.clone(),
            send_task,
            recv_task,
            mtu,
            established_at: Instant::now(),
            meta: (),
            id,
        };

        let mut pool = self.pool.lock().await;
        pool.insert(addr.clone(), conn);

        self.stats.record_connection_established();

        debug!(
            transport_id = %self.transport_id,
            remote_addr = %addr,
            elapsed_secs = connect_start.elapsed().as_secs(),
            "Nym mixnet connection established via SOCKS5"
        );

        Ok(send_tx)
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
        let stats = self.stats.clone();

        debug!(
            transport_id = %transport_id,
            remote_addr = %remote_addr,
            timeout_ms,
            "Initiating background Nym SOCKS5 connect"
        );

        let task = tokio::spawn(async move {
            let connect_start = Instant::now();
            debug!(
                transport_id = %transport_id,
                remote_addr = %remote_addr,
                proxy = %proxy_addr,
                timeout_secs = timeout_ms / 1000,
                "Nym SOCKS5 CONNECT starting (this may take several minutes through mixnet)"
            );

            let dialer = Socks5Dialer {
                proxy_addr,
                connect_timeout: Duration::from_millis(timeout_ms),
                auth: Socks5Auth::None,
            };

            let stream = match dialer.dial(&target_addr).await {
                Ok(stream) => {
                    debug!(
                        transport_id = %transport_id,
                        remote_addr = %remote_addr,
                        elapsed_secs = connect_start.elapsed().as_secs(),
                        "Nym SOCKS5 CONNECT succeeded"
                    );
                    stream
                }
                // Counted as connect() counts them.
                Err(DialError::Socks(e)) => {
                    stats.record_socks5_error();
                    warn!(
                        transport_id = %transport_id,
                        remote_addr = %remote_addr,
                        error = %e,
                        elapsed_secs = connect_start.elapsed().as_secs(),
                        "Background Nym SOCKS5 connect failed"
                    );
                    return Err(TransportError::ConnectionRefused);
                }
                Err(DialError::Timeout) => {
                    stats.record_connect_timeout();
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
                Err(DialError::Setup(e)) => return Err(e),
            };

            let mtu = config.mtu();

            Ok((stream, mtu))
        });

        let mut connecting = self.connecting.lock().await;
        connecting.insert(addr.clone(), ConnectingEntry { task });

        Ok(())
    }

    /// Query the state of a connection to a remote address.
    pub fn connection_state_sync(&self, addr: &TransportAddr) -> ConnectionState {
        poll_connecting(&self.pool, &self.connecting, addr, |stream, mtu| {
            self.promote_connection(addr, stream, mtu)
        })
    }

    /// Promote a completed background connection to the established pool.
    fn promote_connection(&self, addr: &TransportAddr, stream: TcpStream, mtu: u16) {
        let conn = self.outbound_connection(addr, stream, mtu);

        if let Ok(mut pool) = self.pool.try_lock() {
            pool.insert(addr.clone(), conn);
            self.record_promoted(addr);
        } else {
            conn.recv_task.abort();
            conn.send_task.abort();
            warn!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "Failed to promote Nym connection (pool locked)"
            );
        }
    }

    /// Build the pool entry for a finished background connect: split the
    /// stream and spawn its receive loop and writer task.
    fn outbound_connection(
        &self,
        addr: &TransportAddr,
        stream: TcpStream,
        mtu: u16,
    ) -> ProxiedConnection<()> {
        let (read_half, write_half) = stream.into_split();

        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let pool = self.pool.clone();
        let recv_stats = self.stats.clone();
        let remote_addr = addr.clone();
        let id = next_conn_id();

        let recv_task = tokio::spawn(async move {
            nym_receive_loop(
                read_half,
                transport_id,
                remote_addr.clone(),
                id,
                packet_tx,
                pool,
                mtu,
                recv_stats,
            )
            .await;
        });

        let (send_tx, send_rx) = tokio::sync::mpsc::channel(SEND_QUEUE_DEPTH);
        let send_task = tokio::spawn(proxied_send_loop(
            write_half,
            send_rx,
            transport_id,
            addr.clone(),
            id,
            self.pool.clone(),
            self.stats.clone(),
            "Nym",
            |_stats: &NymStats, _meta: &()| {},
        ));

        ProxiedConnection {
            send_tx,
            send_task,
            recv_task,
            mtu,
            established_at: Instant::now(),
            meta: (),
            id,
        }
    }

    /// Count and log a background connection that has entered the pool.
    fn record_promoted(&self, addr: &TransportAddr) {
        self.stats.record_connection_established();
        debug!(
            transport_id = %self.transport_id,
            remote_addr = %addr,
            "Nym connection established (background connect)"
        );
    }

    /// Close a specific connection asynchronously.
    ///
    /// Aborts the receive task and lets the writer finish the frames already
    /// queued, within [`WRITER_DRAIN_TIMEOUT`], without waiting for it.
    /// Stopping the transport ends a writer still draining. This mirrors
    /// `TcpTransport::close_connection_async`.
    pub async fn close_connection_async(&self, addr: &TransportAddr) {
        let mut pool = self.pool.lock().await;
        if let Some(conn) = pool.remove(addr) {
            let ProxiedConnection {
                send_tx,
                send_task,
                recv_task,
                ..
            } = conn;
            drop(send_tx);
            recv_task.abort();
            self.draining.drain(send_task, WRITER_DRAIN_TIMEOUT);
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "Nym connection closed"
            );
        }
    }
}

impl Transport for NymTransport {
    fn role(&self) -> crate::config::TransportRole {
        self.config.role()
    }

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

/// Parse a TransportAddr string into a shared SOCKS5 target address.
fn parse_target_addr(addr: &TransportAddr) -> Result<SocksTarget, TransportError> {
    let s = addr.as_str().ok_or_else(|| {
        TransportError::InvalidAddress("Nym address must be a valid UTF-8 string".into())
    })?;

    if let Ok(socket_addr) = s.parse::<SocketAddr>() {
        Ok(SocksTarget::Ip(socket_addr))
    } else {
        let (host, port_str) = s.rsplit_once(':').ok_or_else(|| {
            TransportError::InvalidAddress(format!("invalid address (expected host:port): {}", s))
        })?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| TransportError::InvalidAddress(format!("invalid port: {}", s)))?;
        Ok(SocksTarget::Hostname(host.to_string(), port))
    }
}

// ============================================================================
// Receive Loop (per-connection)
// ============================================================================

/// Per-connection Nym receive loop.
///
/// Thin wrapper over the shared `proxied_receive_loop`: nym has no pool
/// counters, so its teardown hook is a no-op. Emits the terminal
/// "receive loop stopped" debug (without a `direction` field) that the
/// shared loop deliberately leaves to each transport.
///
/// The inbound deadline, both first-frame and idle, is `None` on every nym
/// connection. Nym is outbound-only (`accept_connections()` is `false` and
/// no listener is ever bound), so no nym connection is admitted before a
/// byte is read and none occupies a capped slot: the pool carries `()`
/// metadata and the teardown hook decrements nothing. There is no resource
/// for a silent remote to exhaust, and the mixnet's Sphinx routing makes a
/// frame legitimately slow, so a TCP-scale deadline here would drop good
/// connections to defend a cap that does not exist.
#[allow(clippy::too_many_arguments)]
async fn nym_receive_loop(
    reader: tokio::net::tcp::OwnedReadHalf,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    id: ConnId,
    packet_tx: PacketTx,
    pool: ProxiedPool<()>,
    mtu: u16,
    stats: Arc<NymStats>,
) {
    proxied_receive_loop(
        reader,
        transport_id,
        remote_addr.clone(),
        id,
        packet_tx,
        pool,
        mtu,
        stats,
        "Nym",
        None,
        // Nym binds no listener (`accept_connections()` is `false`), its pool
        // metadata is `()` and its teardown hook decrements nothing, so there
        // is no admission ordering for a readiness barrier to protect.
        None,
        |_stats, _meta| {},
    )
    .await;

    debug!(
        transport_id = %transport_id,
        remote_addr = %remote_addr,
        "Nym receive loop stopped"
    );
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::wait_until;
    use crate::transport::packet_channel;

    /// Test config: a syntactically valid loopback proxy address, with the
    /// startup readiness probe disabled (no real nym-socks5-client runs in
    /// unit tests) and a short connect timeout to bound any accidental dial.
    fn make_config() -> NymConfig {
        NymConfig {
            socks5_addr: Some("127.0.0.1:1080".to_string()),
            startup_timeout_secs: Some(0),
            connect_timeout_ms: Some(2000),
            ..Default::default()
        }
    }

    // ---- parse_target_addr ----

    #[test]
    fn test_parse_target_addr_ipv4() {
        let addr = TransportAddr::from_string("192.0.2.10:2121");
        match parse_target_addr(&addr).unwrap() {
            SocksTarget::Ip(socket_addr) => {
                assert_eq!(
                    socket_addr,
                    "192.0.2.10:2121".parse::<SocketAddr>().unwrap()
                );
            }
            other => panic!("expected Ip variant, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_target_addr_ipv6_bracketed() {
        // A bracketed IPv6 literal parses cleanly as a SocketAddr, so the
        // connect path treats it as an Ip target with the brackets handled
        // correctly (this is the path that actually dials peers).
        let addr = TransportAddr::from_string("[2001:db8::1]:443");
        match parse_target_addr(&addr).unwrap() {
            SocksTarget::Ip(socket_addr) => {
                assert_eq!(
                    socket_addr,
                    "[2001:db8::1]:443".parse::<SocketAddr>().unwrap()
                );
            }
            other => panic!("expected Ip variant, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_target_addr_hostname() {
        let addr = TransportAddr::from_string("peer.example.com:8443");
        match parse_target_addr(&addr).unwrap() {
            SocksTarget::Hostname(host, port) => {
                assert_eq!(host, "peer.example.com");
                assert_eq!(port, 8443);
            }
            other => panic!("expected Hostname variant, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_target_addr_missing_port() {
        // No colon at all — cannot be split into host:port.
        let addr = TransportAddr::from_string("peer.example.com");
        assert!(parse_target_addr(&addr).is_err());
    }

    #[test]
    fn test_parse_target_addr_non_numeric_port() {
        let addr = TransportAddr::from_string("peer.example.com:notaport");
        assert!(parse_target_addr(&addr).is_err());
    }

    // ---- validate_host_port ----

    #[test]
    fn test_validate_host_port_ok() {
        assert!(validate_host_port("127.0.0.1:1080", "socks5_addr").is_ok());
        assert!(validate_host_port("proxy.local:9050", "socks5_addr").is_ok());
    }

    #[test]
    fn test_validate_host_port_missing_port() {
        // No colon -> not host:port.
        assert!(validate_host_port("127.0.0.1", "socks5_addr").is_err());
    }

    #[test]
    fn test_validate_host_port_non_numeric_port() {
        assert!(validate_host_port("127.0.0.1:abc", "socks5_addr").is_err());
    }

    /// Documents a known limitation: `validate_host_port` splits on the last
    /// colon, so a bracketed IPv6 literal validates with port `1080` and a
    /// host of `[::1]` (stray brackets) rather than being rejected. It is
    /// harmless in practice because the SOCKS5 proxy defaults to an IPv4
    /// loopback address, and the Tor transport has the same gap. Pin the
    /// current behavior so any future change here is a deliberate one.
    #[test]
    fn test_validate_host_port_ipv6_bracket_is_accepted() {
        assert!(validate_host_port("[::1]:1080", "socks5_addr").is_ok());
    }

    // ---- config defaults ----

    #[test]
    fn test_config_defaults() {
        let config = NymConfig::default();
        assert_eq!(config.socks5_addr(), "127.0.0.1:1080");
        assert_eq!(config.connect_timeout_ms(), 300_000);
        assert_eq!(config.mtu(), 1400);
        assert_eq!(config.startup_timeout_secs(), 120);
    }

    // ---- Transport trait surface ----

    #[test]
    fn test_transport_type() {
        let (tx, _rx) = packet_channel(32);
        let transport = NymTransport::new(TransportId::new(1), None, make_config(), tx);
        let tt = transport.transport_type();
        assert_eq!(tt.name, "nym");
        assert!(tt.connection_oriented);
        assert!(tt.reliable);
    }

    #[test]
    fn test_accept_connections_false() {
        let (tx, _rx) = packet_channel(32);
        let transport = NymTransport::new(TransportId::new(1), None, make_config(), tx);
        assert!(!transport.accept_connections());
    }

    #[test]
    fn test_discover_returns_empty() {
        let (tx, _rx) = packet_channel(32);
        let transport = NymTransport::new(TransportId::new(1), None, make_config(), tx);
        assert!(transport.discover().unwrap().is_empty());
    }

    #[test]
    fn test_sync_methods_return_not_supported() {
        let (tx, _rx) = packet_channel(32);
        let mut transport = NymTransport::new(TransportId::new(1), None, make_config(), tx);
        assert!(transport.start().is_err());
        assert!(transport.stop().is_err());
        let addr = TransportAddr::from_string("127.0.0.1:2121");
        assert!(transport.send(&addr, &[0u8; 10]).is_err());
    }

    // ---- lifecycle ----

    #[tokio::test]
    async fn test_start_stop() {
        let (tx, _rx) = packet_channel(32);
        let mut transport = NymTransport::new(TransportId::new(1), None, make_config(), tx);
        transport.start_async().await.unwrap();
        assert_eq!(transport.state(), TransportState::Up);
        transport.stop_async().await.unwrap();
        assert_eq!(transport.state(), TransportState::Down);
    }

    #[tokio::test]
    async fn test_double_start_fails() {
        let (tx, _rx) = packet_channel(32);
        let mut transport = NymTransport::new(TransportId::new(1), None, make_config(), tx);
        transport.start_async().await.unwrap();
        assert!(transport.start_async().await.is_err());
    }

    #[tokio::test]
    async fn test_stop_not_started_fails() {
        let (tx, _rx) = packet_channel(32);
        let mut transport = NymTransport::new(TransportId::new(1), None, make_config(), tx);
        assert!(transport.stop_async().await.is_err());
    }

    #[tokio::test]
    async fn test_send_not_started() {
        let (tx, _rx) = packet_channel(32);
        let transport = NymTransport::new(TransportId::new(1), None, make_config(), tx);
        let addr = TransportAddr::from_string("127.0.0.1:2121");
        assert!(transport.send_async(&addr, &[0u8; 10]).await.is_err());
    }

    #[tokio::test]
    async fn test_invalid_socks5_addr_start_fails() {
        let (tx, _rx) = packet_channel(32);
        let config = NymConfig {
            socks5_addr: Some("not-a-host-port".to_string()),
            startup_timeout_secs: Some(0),
            ..Default::default()
        };
        let mut transport = NymTransport::new(TransportId::new(1), None, config, tx);
        assert!(transport.start_async().await.is_err());
    }

    #[tokio::test]
    async fn test_send_async_rejects_oversized_packet() {
        let (tx, _rx) = packet_channel(32);
        let mut transport = NymTransport::new(TransportId::new(1), None, make_config(), tx);
        transport.start_async().await.unwrap();

        let mtu = transport.mtu() as usize;
        let addr = TransportAddr::from_string("127.0.0.1:2121");

        // One byte over the MTU is rejected for size, before any dial.
        let oversized = vec![0u8; mtu + 1];
        let result = transport.send_async(&addr, &oversized).await;
        assert!(matches!(result, Err(TransportError::MtuExceeded { .. })));

        // A packet at exactly the MTU is not rejected for size. (It still
        // fails — no proxy is listening — but not with MtuExceeded.)
        let at_mtu = vec![0u8; mtu];
        let result = transport.send_async(&addr, &at_mtu).await;
        assert!(!matches!(result, Err(TransportError::MtuExceeded { .. })));

        transport.stop_async().await.unwrap();
    }

    // ========================================================================
    // Integration test using MockSocks5Server (connect path), mirroring the
    // Tor transport's `test_send_recv_via_socks5`.
    // ========================================================================

    use crate::config::TcpConfig;
    use crate::transport::socks5::mock::MockSocks5Server;
    use crate::transport::tcp::TcpTransport;

    /// msg1 wire size: 4 prefix + 4 sender_idx + 106 noise_msg1 = 114 bytes.
    const MSG1_WIRE_SIZE: usize = 114;
    /// msg1 payload_len: sender_idx(4) + noise_msg1(106) = 110.
    const MSG1_PAYLOAD_LEN: u16 = (MSG1_WIRE_SIZE - 4) as u16;

    /// Build a msg1 FMP frame (114 bytes) that `read_fmp_packet` accepts.
    fn build_msg1_frame() -> Vec<u8> {
        let mut frame = vec![0xAA; MSG1_WIRE_SIZE];
        frame[0] = 0x01; // ver=0, phase=1
        frame[1] = 0x00; // flags
        frame[2..4].copy_from_slice(&MSG1_PAYLOAD_LEN.to_le_bytes());
        frame
    }

    /// End-to-end connect path: a real TCP transport is the destination, a
    /// mock SOCKS5 proxy sits in front of it, and the Nym transport dials the
    /// destination through the proxy. A valid FMP frame sent via the Nym
    /// transport must arrive at the destination byte-for-byte.
    #[tokio::test]
    async fn test_send_recv_via_socks5() {
        // Destination TCP transport with a real listener.
        let (dest_tx, mut dest_rx) = packet_channel(32);
        let dest_config = TcpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        };
        let mut dest = TcpTransport::new(TransportId::new(100), None, dest_config, dest_tx);
        dest.start_async().await.unwrap();
        let dest_addr = dest.local_addr().unwrap();

        // Mock SOCKS5 proxy forwarding to the destination.
        let mock = MockSocks5Server::new(dest_addr).await.unwrap();
        let proxy_addr = mock.addr();
        let _proxy_handle = mock.spawn();

        // Nym transport pointing at the mock proxy.
        let (nym_tx, _nym_rx) = packet_channel(32);
        let nym_config = NymConfig {
            socks5_addr: Some(proxy_addr.to_string()),
            startup_timeout_secs: Some(5),
            connect_timeout_ms: Some(5000),
            ..Default::default()
        };
        let mut nym = NymTransport::new(TransportId::new(200), None, nym_config, nym_tx);
        nym.start_async().await.unwrap();

        // Send a valid FMP frame through the SOCKS5 (mixnet) path.
        let frame = build_msg1_frame();
        let target = TransportAddr::from_string(&dest_addr.to_string());
        nym.send_async(&target, &frame).await.unwrap();

        // It must arrive at the destination, byte-for-byte.
        let received = tokio::time::timeout(Duration::from_secs(5), dest_rx.recv())
            .await
            .expect("timeout waiting for packet")
            .expect("channel closed");
        assert_eq!(received.data, frame);

        nym.stop_async().await.unwrap();
        dest.stop_async().await.unwrap();
    }

    // ========================================================================
    // Connection identity and failure teardown
    // ========================================================================

    /// A destination TCP transport behind a mock SOCKS5 proxy, and a started
    /// Nym transport dialing through it.
    async fn nym_via_mock_proxy() -> (
        TcpTransport,
        crate::transport::PacketRx,
        NymTransport,
        TransportAddr,
    ) {
        let (dest_tx, dest_rx) = packet_channel(32);
        let dest_config = TcpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        };
        let mut dest = TcpTransport::new(TransportId::new(100), None, dest_config, dest_tx);
        dest.start_async().await.unwrap();
        let dest_addr = dest.local_addr().unwrap();

        let mock = MockSocks5Server::new(dest_addr).await.unwrap();
        let proxy_addr = mock.addr();
        let _proxy_handle = mock.spawn();

        let (nym_tx, _nym_rx) = packet_channel(32);
        let nym_config = NymConfig {
            socks5_addr: Some(proxy_addr.to_string()),
            startup_timeout_secs: Some(5),
            connect_timeout_ms: Some(5000),
            ..Default::default()
        };
        let mut nym = NymTransport::new(TransportId::new(200), None, nym_config, nym_tx);
        nym.start_async().await.unwrap();
        let target = TransportAddr::from_string(&dest_addr.to_string());
        (dest, dest_rx, nym, target)
    }

    /// A connection displaced from the pool by a newer one at the same address
    /// must not remove the newer one when its own receive loop ends.
    ///
    /// Both are built by `promote_connection`, and the MTU marks which entry
    /// is pooled. The last step checks the newer connection still removes its
    /// own entry.
    #[tokio::test]
    async fn nym_displaced_connection_cannot_remove_its_successor() {
        let (tx, _rx) = packet_channel(32);
        let nym = NymTransport::new(TransportId::new(1), None, make_config(), tx);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = listener.local_addr().unwrap();
        let remote = TransportAddr::from_string(&listen.to_string());

        let a = TcpStream::connect(listen).await.unwrap();
        let (sa, _) = listener.accept().await.unwrap();
        let b = TcpStream::connect(listen).await.unwrap();
        let (sb, _) = listener.accept().await.unwrap();

        nym.promote_connection(&remote, a, 1400);
        nym.promote_connection(&remote, b, 1300);
        {
            let pool = nym.pool.lock().await;
            assert_eq!(pool.len(), 1);
            assert_eq!(pool.get(&remote).map(|c| c.mtu), Some(1300));
        }

        drop(sa);
        assert!(
            wait_until(
                || nym.stats().snapshot().recv_errors == 1,
                Duration::from_secs(2)
            )
            .await,
            "the displaced connection's receive loop should have read EOF"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            nym.pool.lock().await.get(&remote).map(|c| c.mtu),
            Some(1300),
            "the displaced connection's teardown removed its successor"
        );

        drop(sb);
        assert!(
            wait_until(
                || nym.stats().snapshot().recv_errors == 2,
                Duration::from_secs(2)
            )
            .await,
            "the newer connection's receive loop should have read EOF"
        );
        assert!(
            wait_until(
                || nym.pool.try_lock().map(|p| p.is_empty()).unwrap_or(false),
                Duration::from_secs(2)
            )
            .await,
            "the newer connection's teardown should remove its own entry"
        );
    }

    /// A connection built by connect-on-send removes its own entry when the
    /// far side closes.
    #[tokio::test]
    async fn nym_connect_teardown_removes_its_own_entry() {
        let (mut dest, mut dest_rx, mut nym, target) = nym_via_mock_proxy().await;

        let frame = build_msg1_frame();
        nym.send_async(&target, &frame).await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(5), dest_rx.recv())
            .await
            .expect("timeout waiting for packet")
            .expect("channel closed");
        assert_eq!(received.data, frame);
        assert_eq!(nym.pool.lock().await.len(), 1);

        dest.stop_async().await.unwrap();
        assert!(
            wait_until(
                || nym.pool.try_lock().map(|p| p.is_empty()).unwrap_or(false),
                Duration::from_secs(5)
            )
            .await,
            "the receive loop should remove its own entry"
        );
        assert_eq!(
            nym.stats().snapshot().recv_errors,
            1,
            "the empty pool must be the receive loop's teardown"
        );

        nym.stop_async().await.unwrap();
    }

    // ========================================================================
    // Deliberate close finishes the frames already queued
    // ========================================================================

    /// A frame queued immediately before a deliberate close must still reach
    /// the peer through the proxy, and the close must still end the
    /// connection at the far side.
    #[tokio::test]
    async fn nym_frame_queued_just_before_close_still_reaches_the_peer() {
        let (mut dest, mut dest_rx, mut nym, target) = nym_via_mock_proxy().await;

        let frame = build_msg1_frame();
        nym.send_async(&target, &frame).await.unwrap();
        let first = tokio::time::timeout(Duration::from_secs(2), dest_rx.recv())
            .await
            .expect("timeout waiting for the first frame")
            .expect("channel closed");
        assert_eq!(first.data, frame);

        nym.send_async(&target, &frame).await.unwrap();
        nym.close_connection_async(&target).await;

        let second = tokio::time::timeout(Duration::from_secs(2), dest_rx.recv())
            .await
            .expect("a frame queued just before close was never written")
            .expect("channel closed");
        assert_eq!(second.data, frame);
        assert!(
            wait_until(
                || dest.stats().snapshot().pool_inbound == 0,
                Duration::from_secs(5)
            )
            .await,
            "the close must still end the connection once the queue is written"
        );

        nym.stop_async().await.unwrap();
        dest.stop_async().await.unwrap();
    }

    /// Stopping the transport must stop a writer that is still draining after
    /// a deliberate close, rather than leave it to its drain timer.
    ///
    /// The writer holds a oneshot sender and never finishes, so the sender is
    /// dropped only once the task has been aborted.
    #[tokio::test]
    async fn nym_stop_ends_a_writer_still_draining_after_a_close() {
        let (tx, _rx) = packet_channel(32);
        let mut nym = NymTransport::new(TransportId::new(1), None, make_config(), tx);
        nym.start_async().await.unwrap();
        let remote = TransportAddr::from_string("192.0.2.1:2121");
        let (guard_tx, mut guard_rx) = tokio::sync::oneshot::channel::<()>();
        nym.pool.lock().await.insert(
            remote.clone(),
            ProxiedConnection {
                send_tx: tokio::sync::mpsc::channel(1).0,
                send_task: tokio::spawn(async move {
                    let _guard = guard_tx;
                    std::future::pending::<()>().await
                }),
                recv_task: tokio::spawn(std::future::pending::<()>()),
                mtu: 1400,
                established_at: Instant::now(),
                meta: (),
                id: next_conn_id(),
            },
        );

        nym.close_connection_async(&remote).await;
        tokio::time::timeout(Duration::from_secs(2), nym.stop_async())
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

    /// With no pooled connection and no connect under way, `send_existing`
    /// fails with `NotConnected` and opens nothing.
    #[tokio::test]
    async fn send_existing_without_connection_fails_fast_and_dials_nothing() {
        let (mut dest, _dest_rx, mut t, target) = nym_via_mock_proxy().await;

        let result = t.send_existing(&target, &build_msg1_frame()).await;

        assert!(
            matches!(result, Err(TransportError::NotConnected)),
            "expected NotConnected, got {result:?}"
        );
        assert!(
            t.connecting.lock().await.is_empty(),
            "a connect was started"
        );
        assert_eq!(t.stats().snapshot().connections_established, 0);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            dest.stats().snapshot().connections_accepted,
            0,
            "the destination saw a connection"
        );

        t.stop_async().await.unwrap();
        dest.stop_async().await.unwrap();
    }

    /// `has_connection` reports only what the pool holds. A finished
    /// background connect is not a pooled connection and is left where it
    /// is; once `send_existing` has promoted it, the connection is reported.
    #[tokio::test]
    async fn has_connection_reports_the_pool_and_never_promotes_a_finished_connect() {
        let (mut dest, mut dest_rx, mut t, target) = nym_via_mock_proxy().await;

        assert!(
            !t.has_connection(&target).await,
            "no connection before any connect"
        );
        t.connect_async(&target).await.unwrap();
        let mut waited = 0;
        while !t
            .connecting
            .try_lock()
            .is_ok_and(|c| c.get(&target).is_some_and(|e| e.task.is_finished()))
        {
            assert!(waited < 150, "background connect never finished");
            tokio::time::sleep(Duration::from_millis(20)).await;
            waited += 1;
        }
        assert!(
            !t.has_connection(&target).await,
            "a finished connect that is not pooled is not a connection"
        );
        assert!(
            t.connecting.lock().await.contains_key(&target),
            "the query moved the finished connect out of the connecting map"
        );
        assert!(
            t.pool.lock().await.is_empty(),
            "the query put a connection in the pool"
        );
        assert_eq!(
            t.stats().snapshot().connections_established,
            0,
            "the query promoted the finished connect"
        );

        let frame = build_msg1_frame();
        t.send_existing(&target, &frame).await.unwrap();
        assert!(
            t.has_connection(&target).await,
            "the promoted connection is pooled"
        );
        tokio::time::timeout(Duration::from_secs(5), dest_rx.recv())
            .await
            .expect("timeout waiting for packet")
            .expect("channel closed");

        t.stop_async().await.unwrap();
        dest.stop_async().await.unwrap();
    }

    /// A background connect that has finished is moved into the pool and
    /// carries the send, with no second connection opened.
    #[tokio::test]
    async fn send_existing_promotes_a_finished_background_connect_and_sends_on_it() {
        let (mut dest, mut dest_rx, mut t, target) = nym_via_mock_proxy().await;

        t.connect_async(&target).await.unwrap();
        let mut waited = 0;
        while !t
            .connecting
            .try_lock()
            .is_ok_and(|c| c.get(&target).is_some_and(|e| e.task.is_finished()))
        {
            assert!(waited < 150, "background connect never finished");
            tokio::time::sleep(Duration::from_millis(20)).await;
            waited += 1;
        }
        let frame = build_msg1_frame();
        t.send_existing(&target, &frame).await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), dest_rx.recv())
            .await
            .expect("timeout waiting for packet")
            .expect("channel closed");
        assert_eq!(received.data, frame);
        assert!(
            t.connecting.lock().await.is_empty(),
            "the finished connect was left in the connecting map"
        );
        assert_eq!(t.stats().snapshot().connections_established, 1);
        assert_eq!(
            dest.stats().snapshot().connections_accepted,
            1,
            "the send used the background connection, not a new one"
        );

        t.stop_async().await.unwrap();
        dest.stop_async().await.unwrap();
    }

    /// Wait until the background connect to `target` has finished, leaving
    /// it in the connecting map.
    async fn wait_background_finished(t: &NymTransport, target: &TransportAddr) {
        let finished = wait_until(
            || {
                t.connecting
                    .try_lock()
                    .is_ok_and(|c| c.get(target).is_some_and(|e| e.task.is_finished()))
            },
            Duration::from_secs(3),
        )
        .await;
        assert!(finished, "background connect to {target} never finished");
    }

    /// A background connect through a proxy that accepts the TCP connection
    /// but never answers the SOCKS5 greeting times out, and is counted in
    /// `connect_timeouts` as an inline one is.
    #[tokio::test]
    async fn background_connect_timeout_is_counted() {
        // Bound and listening, never accepted: the kernel completes the TCP
        // handshake and nothing ever replies.
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (tx, _rx) = packet_channel(32);
        let config = NymConfig {
            socks5_addr: Some(silent.local_addr().unwrap().to_string()),
            startup_timeout_secs: Some(5),
            connect_timeout_ms: Some(200),
            ..Default::default()
        };
        let mut t = NymTransport::new(TransportId::new(200), None, config, tx);
        t.start_async().await.unwrap();
        let target = TransportAddr::from_string("127.0.0.1:9");

        t.connect_async(&target).await.unwrap();
        wait_background_finished(&t, &target).await;

        let stats = t.stats().snapshot();
        assert_eq!(stats.connect_timeouts, 1, "the timeout was not counted");
        assert_eq!(stats.socks5_errors, 0);
        let result = t.send_existing(&target, &build_msg1_frame()).await;
        assert!(matches!(result, Err(TransportError::NotConnected)));
        assert_eq!(
            t.stats().snapshot().connect_timeouts,
            1,
            "taking the result counted the timeout again"
        );

        t.stop_async().await.unwrap();
    }

    /// A background connect the proxy answers with a SOCKS5 failure is
    /// counted in `socks5_errors` as an inline one is.
    #[tokio::test]
    async fn background_connect_socks5_error_is_counted() {
        let dummy_target: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mock = MockSocks5Server::with_reply_code(dummy_target, 0x01)
            .await
            .unwrap();
        let proxy_addr = mock.addr();
        let _proxy_handle = mock.spawn();
        let (tx, _rx) = packet_channel(32);
        let config = NymConfig {
            socks5_addr: Some(proxy_addr.to_string()),
            startup_timeout_secs: Some(5),
            connect_timeout_ms: Some(2000),
            ..Default::default()
        };
        let mut t = NymTransport::new(TransportId::new(200), None, config, tx);
        t.start_async().await.unwrap();
        let target = TransportAddr::from_string("127.0.0.1:9");

        t.connect_async(&target).await.unwrap();
        wait_background_finished(&t, &target).await;

        let stats = t.stats().snapshot();
        assert_eq!(stats.socks5_errors, 1, "the SOCKS5 error was not counted");
        assert_eq!(stats.connect_timeouts, 0);

        t.stop_async().await.unwrap();
    }
}
