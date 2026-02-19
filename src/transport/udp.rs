//! UDP Transport Implementation
//!
//! Provides UDP-based transport for FIPS peer communication.

use super::{
    DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr, TransportError,
    TransportId, TransportState, TransportType,
};
use crate::config::UdpConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

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
    socket: Option<Arc<UdpSocket>>,
    /// Channel for delivering received packets to Node.
    packet_tx: PacketTx,
    /// Receive loop task handle.
    recv_task: Option<JoinHandle<()>>,
    /// Local bound address (after start).
    local_addr: Option<SocketAddr>,
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

    /// Get a reference to the socket (only valid after start).
    pub fn socket(&self) -> Option<&Arc<UdpSocket>> {
        self.socket.as_ref()
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

        // Bind socket
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| TransportError::StartFailed(format!("bind failed: {}", e)))?;

        self.local_addr = Some(
            socket
                .local_addr()
                .map_err(|e| TransportError::StartFailed(format!("get local addr: {}", e)))?,
        );

        let socket = Arc::new(socket);
        self.socket = Some(socket.clone());

        // Spawn receive loop
        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let mtu = self.config.mtu();

        let recv_task = tokio::spawn(async move {
            udp_receive_loop(socket, transport_id, packet_tx, mtu).await;
        });

        self.recv_task = Some(recv_task);
        self.state = TransportState::Up;

        if let Some(ref name) = self.name {
            info!(
                name = %name,
                local_addr = %self.local_addr.unwrap(),
                "UDP transport started"
            );
        } else {
            info!(
                local_addr = %self.local_addr.unwrap(),
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
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu: self.config.mtu(),
            });
        }

        let socket_addr = parse_socket_addr(addr)?;
        let socket = self.socket.as_ref().ok_or(TransportError::NotStarted)?;

        let bytes_sent = socket
            .send_to(data, socket_addr)
            .await
            .map_err(|e| TransportError::SendFailed(format!("{}", e)))?;

        trace!(
            transport_id = %self.transport_id,
            remote_addr = %socket_addr,
            bytes = bytes_sent,
            "UDP packet sent"
        );

        Ok(bytes_sent)
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

/// Parse a TransportAddr as SocketAddr.
fn parse_socket_addr(addr: &TransportAddr) -> Result<SocketAddr, TransportError> {
    addr.as_str()
        .ok_or_else(|| TransportError::InvalidAddress("not valid UTF-8".into()))?
        .parse()
        .map_err(|e| TransportError::InvalidAddress(format!("{}", e)))
}

/// UDP receive loop - runs as a spawned task.
async fn udp_receive_loop(
    socket: Arc<UdpSocket>,
    transport_id: TransportId,
    packet_tx: PacketTx,
    mtu: u16,
) {
    // Buffer with headroom for slightly oversized packets
    let mut buf = vec![0u8; mtu as usize + 100];

    debug!(transport_id = %transport_id, "UDP receive loop starting");

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, remote_addr)) => {
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

    #[test]
    fn test_parse_socket_addr() {
        let addr = TransportAddr::from_string("192.168.1.1:4000");
        let result = parse_socket_addr(&addr).unwrap();
        assert_eq!(result.to_string(), "192.168.1.1:4000");

        let invalid = TransportAddr::from_string("not_an_address");
        assert!(parse_socket_addr(&invalid).is_err());

        let binary = TransportAddr::new(vec![0xff, 0x80]);
        assert!(parse_socket_addr(&binary).is_err());
    }
}
