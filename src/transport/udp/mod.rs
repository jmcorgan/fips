//! UDP Transport Implementation
//!
//! Provides UDP-based transport for FIPS peer communication.

use super::{
    DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr, TransportError,
    TransportId, TransportState, TransportType,
};
mod socket;
mod stats;
use socket::{AsyncUdpSocket, UdpRawSocket};
use stats::UdpStats;
use super::resolve_socket_addr;
use crate::config::UdpConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

/// DNS cache TTL for hostname resolution (60 seconds).
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);

/// UDP transport for FIPS.
///
/// Provides connectionless, unreliable packet delivery over UDP/IP.
/// A single socket serves all peers; links are virtual tuples of
/// (transport_id, remote_addr).
pub struct UdpTransport {
    /// Unique transport identifier.
    transport_id: TransportId,
    /// Optional instance name (for named instances in config).
    name: Option<String>,
    /// Configuration.
    config: UdpConfig,
    /// Current state.
    state: TransportState,
    /// Bound socket (None until started).
    socket: Option<AsyncUdpSocket>,
    /// Channel for delivering received packets to Node.
    packet_tx: PacketTx,
    /// Receive loop task handle.
    recv_task: Option<JoinHandle<()>>,
    /// Local bound address (after start).
    local_addr: Option<SocketAddr>,
    /// Transport statistics.
    stats: Arc<UdpStats>,
    /// DNS resolution cache for hostname addresses.
    dns_cache: StdMutex<HashMap<TransportAddr, (SocketAddr, Instant)>>,
}

impl UdpTransport {
    /// Create a new UDP transport.
    pub fn new(
        transport_id: TransportId,
        name: Option<String>,
        config: UdpConfig,
        packet_tx: PacketTx,
    ) -> Self {
        Self {
            transport_id,
            name,
            config,
            state: TransportState::Configured,
            socket: None,
            packet_tx,
            recv_task: None,
            local_addr: None,
            stats: Arc::new(UdpStats::new()),
            dns_cache: StdMutex::new(HashMap::new()),
        }
    }

    /// Get the instance name (if configured as a named instance).
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the local bound address (only valid after start).
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Get the transport statistics.
    pub fn stats(&self) -> &Arc<UdpStats> {
        &self.stats
    }

    /// Resolve a transport address, using cached results for hostnames.
    ///
    /// Numeric IP addresses bypass the cache entirely. Hostnames are
    /// resolved via DNS and cached for `DNS_CACHE_TTL` to avoid
    /// per-packet resolution overhead.
    async fn resolve_cached(&self, addr: &TransportAddr) -> Result<SocketAddr, TransportError> {
        // Fast path: try numeric IP parse (no cache, no DNS)
        if let Some(s) = addr.as_str()
            && let Ok(sock_addr) = s.parse::<SocketAddr>()
        {
            return Ok(sock_addr);
        }

        // Check cache
        {
            let cache = self.dns_cache.lock().unwrap();
            if let Some((resolved, cached_at)) = cache.get(addr)
                && cached_at.elapsed() < DNS_CACHE_TTL
            {
                return Ok(*resolved);
            }
        }

        // Cache miss or expired — resolve via DNS
        let resolved = resolve_socket_addr(addr).await?;

        // Store in cache
        {
            let mut cache = self.dns_cache.lock().unwrap();
            cache.insert(addr.clone(), (resolved, Instant::now()));
        }

        Ok(resolved)
    }

    /// Query transport-local congestion indicators.
    pub fn congestion(&self) -> super::TransportCongestion {
        super::TransportCongestion {
            recv_drops: Some(self.stats.kernel_drops.load(std::sync::atomic::Ordering::Relaxed)),
        }
    }

    /// Start the transport asynchronously.
    ///
    /// Binds the UDP socket and spawns the receive loop.
    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }

        self.state = TransportState::Starting;

        // Parse bind address
        let bind_addr: SocketAddr = self
            .config
            .bind_addr()
            .parse()
            .map_err(|e| TransportError::StartFailed(format!("invalid bind address: {}", e)))?;

        // Create, bind, and configure UDP socket
        let raw_socket = UdpRawSocket::open(
            bind_addr,
            self.config.recv_buf_size(),
            self.config.send_buf_size(),
        )?;

        let actual_recv = raw_socket.recv_buffer_size()?;
        let actual_send = raw_socket.send_buffer_size()?;
        self.local_addr = Some(raw_socket.local_addr());

        // Wrap in AsyncFd for tokio integration
        let async_socket = raw_socket.into_async()?;
        self.socket = Some(async_socket.clone());

        // Spawn receive loop
        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let mtu = self.config.mtu();
        let stats = self.stats.clone();

        let recv_task = tokio::spawn(async move {
            udp_receive_loop(async_socket, transport_id, packet_tx, mtu, stats).await;
        });

        self.recv_task = Some(recv_task);
        self.state = TransportState::Up;

        if let Some(ref name) = self.name {
            info!(
                name = %name,
                local_addr = %self.local_addr.unwrap(),
                recv_buf = actual_recv,
                send_buf = actual_send,
                "UDP transport started"
            );
        } else {
            info!(
                local_addr = %self.local_addr.unwrap(),
                recv_buf = actual_recv,
                send_buf = actual_send,
                "UDP transport started"
            );
        }

        Ok(())
    }

    /// Stop the transport asynchronously.
    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        // Abort receive task
        if let Some(task) = self.recv_task.take() {
            task.abort();
            let _ = task.await; // Ignore JoinError from abort
        }

        // Drop socket
        self.socket.take();
        self.local_addr = None;

        self.state = TransportState::Down;

        info!(
            transport_id = %self.transport_id,
            "UDP transport stopped"
        );

        Ok(())
    }

    /// Send a packet asynchronously.
    pub async fn send_async(
        &self,
        addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        if data.len() > self.config.mtu() as usize {
            self.stats.record_mtu_exceeded();
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu: self.config.mtu(),
            });
        }

        let socket_addr = self.resolve_cached(addr).await?;
        let socket = self.socket.as_ref().ok_or(TransportError::NotStarted)?;

        match socket.send_to(data, &socket_addr).await {
            Ok(bytes_sent) => {
                self.stats.record_send(bytes_sent);
                trace!(
                    transport_id = %self.transport_id,
                    remote_addr = %socket_addr,
                    bytes = bytes_sent,
                    "UDP packet sent"
                );
                Ok(bytes_sent)
            }
            Err(e) => {
                self.stats.record_send_error();
                Err(e)
            }
        }
    }
}

impl Transport for UdpTransport {
    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::UDP
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn mtu(&self) -> u16 {
        self.config.mtu()
    }

    fn start(&mut self) -> Result<(), TransportError> {
        // Synchronous start not supported - use start_async()
        Err(TransportError::NotSupported(
            "use start_async() for UDP transport".into(),
        ))
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        // Synchronous stop not supported - use stop_async()
        Err(TransportError::NotSupported(
            "use stop_async() for UDP transport".into(),
        ))
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        // Synchronous send not supported - use send_async()
        Err(TransportError::NotSupported(
            "use send_async() for UDP transport".into(),
        ))
    }

    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        // UDP discovery not yet implemented (would use multicast/DNS-SD)
        // Peer configuration is handled at the node level, not transport level
        Ok(Vec::new())
    }
}

/// UDP receive loop - runs as a spawned task.
async fn udp_receive_loop(
    socket: AsyncUdpSocket,
    transport_id: TransportId,
    packet_tx: PacketTx,
    mtu: u16,
    stats: Arc<UdpStats>,
) {
    // Buffer with headroom for slightly oversized packets
    let mut buf = vec![0u8; mtu as usize + 100];

    debug!(transport_id = %transport_id, "UDP receive loop starting");

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, remote_addr, kernel_drops)) => {
                stats.record_recv(len);
                stats.set_kernel_drops(kernel_drops as u64);

                let data = buf[..len].to_vec();
                let addr = TransportAddr::from_string(&remote_addr.to_string());
                let packet = ReceivedPacket::new(transport_id, addr, data);

                trace!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    bytes = len,
                    "UDP packet received"
                );

                if packet_tx.send(packet).await.is_err() {
                    // Receiver dropped, exit loop
                    info!(
                        transport_id = %transport_id,
                        "Packet channel closed, stopping receive loop"
                    );
                    break;
                }
            }
            Err(e) => {
                stats.record_recv_error();
                // Log error but continue - transient errors are expected
                warn!(
                    transport_id = %transport_id,
                    error = %e,
                    "UDP receive error"
                );
            }
        }
    }

    debug!(transport_id = %transport_id, "UDP receive loop stopped");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::packet_channel;
    use tokio::time::{timeout, Duration};

    fn make_config(port: u16) -> UdpConfig {
        UdpConfig {
            bind_addr: Some(format!("127.0.0.1:{}", port)),
            mtu: Some(1280),
            recv_buf_size: None,
            send_buf_size: None,
        }
    }

    #[tokio::test]
    async fn test_start_stop() {
        let (tx, _rx) = packet_channel(100);
        let mut transport = UdpTransport::new(TransportId::new(1), None, make_config(0), tx);

        assert_eq!(transport.state(), TransportState::Configured);

        transport.start_async().await.unwrap();
        assert_eq!(transport.state(), TransportState::Up);
        assert!(transport.local_addr().is_some());

        transport.stop_async().await.unwrap();
        assert_eq!(transport.state(), TransportState::Down);
    }

    #[tokio::test]
    async fn test_double_start_fails() {
        let (tx, _rx) = packet_channel(100);
        let mut transport = UdpTransport::new(TransportId::new(1), None, make_config(0), tx);

        transport.start_async().await.unwrap();

        let result = transport.start_async().await;
        assert!(matches!(result, Err(TransportError::AlreadyStarted)));

        transport.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn test_stop_not_started_fails() {
        let (tx, _rx) = packet_channel(100);
        let mut transport = UdpTransport::new(TransportId::new(1), None, make_config(0), tx);

        let result = transport.stop_async().await;
        assert!(matches!(result, Err(TransportError::NotStarted)));
    }

    #[tokio::test]
    async fn test_send_recv() {
        let (tx1, _rx1) = packet_channel(100);
        let (tx2, mut rx2) = packet_channel(100);

        let mut t1 = UdpTransport::new(TransportId::new(1), None, make_config(0), tx1);
        let mut t2 = UdpTransport::new(TransportId::new(2), None, make_config(0), tx2);

        t1.start_async().await.unwrap();
        t2.start_async().await.unwrap();

        let addr1 = t1.local_addr().unwrap();
        let addr2 = t2.local_addr().unwrap();

        // Send from t1 to t2
        let data = b"hello world";
        let bytes_sent = t1
            .send_async(&TransportAddr::from_string(&addr2.to_string()), data)
            .await
            .unwrap();
        assert_eq!(bytes_sent, data.len());

        // Receive on t2
        let packet = timeout(Duration::from_secs(1), rx2.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        assert_eq!(packet.data, data);
        assert_eq!(packet.remote_addr.as_str(), Some(addr1.to_string().as_str()));

        t1.stop_async().await.unwrap();
        t2.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn test_bidirectional() {
        let (tx1, mut rx1) = packet_channel(100);
        let (tx2, mut rx2) = packet_channel(100);

        let mut t1 = UdpTransport::new(TransportId::new(1), None, make_config(0), tx1);
        let mut t2 = UdpTransport::new(TransportId::new(2), None, make_config(0), tx2);

        t1.start_async().await.unwrap();
        t2.start_async().await.unwrap();

        let addr1 = TransportAddr::from_string(&t1.local_addr().unwrap().to_string());
        let addr2 = TransportAddr::from_string(&t2.local_addr().unwrap().to_string());

        // Send from t1 to t2
        t1.send_async(&addr2, b"ping").await.unwrap();

        // Receive on t2
        let packet = timeout(Duration::from_secs(1), rx2.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(packet.data, b"ping");

        // Send from t2 to t1
        t2.send_async(&addr1, b"pong").await.unwrap();

        // Receive on t1
        let packet = timeout(Duration::from_secs(1), rx1.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(packet.data, b"pong");

        t1.stop_async().await.unwrap();
        t2.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn test_mtu_exceeded() {
        let (tx, _rx) = packet_channel(100);
        let mut transport = UdpTransport::new(
            TransportId::new(1),
            None,
            UdpConfig {
                mtu: Some(100),
                ..make_config(0)
            },
            tx,
        );

        transport.start_async().await.unwrap();

        let oversized = vec![0u8; 200];
        let result = transport
            .send_async(&TransportAddr::from_string("127.0.0.1:9999"), &oversized)
            .await;

        assert!(matches!(result, Err(TransportError::MtuExceeded { .. })));

        transport.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn test_send_not_started() {
        let (tx, _rx) = packet_channel(100);
        let transport = UdpTransport::new(TransportId::new(1), None, make_config(0), tx);

        let result = transport
            .send_async(&TransportAddr::from_string("127.0.0.1:9999"), b"test")
            .await;

        assert!(matches!(result, Err(TransportError::NotStarted)));
    }

    #[tokio::test]
    async fn test_discover_returns_empty() {
        let (tx, _rx) = packet_channel(100);
        let transport = UdpTransport::new(TransportId::new(1), None, make_config(0), tx);

        // Discovery returns empty until multicast/DNS-SD is implemented
        let peers = transport.discover().unwrap();
        assert!(peers.is_empty());
    }

    #[test]
    fn test_transport_type() {
        let (tx, _rx) = packet_channel(100);
        let transport = UdpTransport::new(TransportId::new(1), None, make_config(0), tx);

        assert_eq!(transport.transport_type().name, "udp");
        assert!(!transport.transport_type().connection_oriented);
        assert!(!transport.transport_type().reliable);
    }

    #[test]
    fn test_sync_methods_return_not_supported() {
        let (tx, _rx) = packet_channel(100);
        let mut transport = UdpTransport::new(TransportId::new(1), None, make_config(0), tx);

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

    #[tokio::test]
    async fn test_resolve_socket_addr_ip() {
        let addr = TransportAddr::from_string("192.168.1.1:2121");
        let result = resolve_socket_addr(&addr).await.unwrap();
        assert_eq!(result.to_string(), "192.168.1.1:2121");
    }

    #[tokio::test]
    async fn test_resolve_socket_addr_invalid() {
        let invalid = TransportAddr::from_string("nonexistent.invalid:2121");
        assert!(resolve_socket_addr(&invalid).await.is_err());

        let binary = TransportAddr::new(vec![0xff, 0x80]);
        assert!(resolve_socket_addr(&binary).await.is_err());
    }

    #[tokio::test]
    async fn test_resolve_socket_addr_hostname() {
        let addr = TransportAddr::from_string("localhost:2121");
        let result = resolve_socket_addr(&addr).await.unwrap();
        // localhost should resolve to 127.0.0.1 or [::1]
        assert!(result.ip().is_loopback());
        assert_eq!(result.port(), 2121);
    }

    #[tokio::test]
    async fn test_congestion_reports_kernel_drops() {
        let (tx, _rx) = packet_channel(100);
        let transport = UdpTransport::new(TransportId::new(1), None, make_config(0), tx);

        // Before start, congestion should still report (from stats)
        let cong = transport.congestion();
        assert_eq!(cong.recv_drops, Some(0));
    }

    #[tokio::test]
    async fn test_send_recv_ip_string() {
        let (tx1, _rx1) = packet_channel(100);
        let (tx2, mut rx2) = packet_channel(100);

        let mut t1 = UdpTransport::new(TransportId::new(1), None, make_config(0), tx1);
        let mut t2 = UdpTransport::new(TransportId::new(2), None, make_config(0), tx2);

        t1.start_async().await.unwrap();
        t2.start_async().await.unwrap();

        let port2 = t2.local_addr().unwrap().port();

        // Send using IP string address
        let data = b"hello via ip string";
        let bytes_sent = t1
            .send_async(&TransportAddr::from_string(&format!("127.0.0.1:{}", port2)), data)
            .await
            .unwrap();
        assert_eq!(bytes_sent, data.len());

        // Receive on t2
        let packet = timeout(Duration::from_secs(1), rx2.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        assert_eq!(packet.data, data);

        t1.stop_async().await.unwrap();
        t2.stop_async().await.unwrap();
    }
}
