//! BLE I/O abstraction layer.
//!
//! Defines the `BleIo` trait that separates transport logic from the
//! BlueZ/bluer stack. `BluerIo` (behind `cfg(feature = "ble")`) provides
//! the real implementation; `MockBleIo` provides an in-memory test double.

use crate::transport::TransportError;

use super::addr::BleAddr;

// ============================================================================
// BLE I/O Traits
// ============================================================================

/// A connected L2CAP stream for sending and receiving data.
pub trait BleStream: Send + Sync {
    /// Send data over the L2CAP connection.
    fn send(
        &self,
        data: &[u8],
    ) -> impl std::future::Future<Output = Result<(), TransportError>> + Send;

    /// Receive data from the L2CAP connection.
    ///
    /// Returns the number of bytes read into `buf`.
    fn recv(
        &self,
        buf: &mut [u8],
    ) -> impl std::future::Future<Output = Result<usize, TransportError>> + Send;

    /// Get the L2CAP send MTU for this connection.
    fn send_mtu(&self) -> u16;

    /// Get the L2CAP receive MTU for this connection.
    fn recv_mtu(&self) -> u16;

    /// Get the remote device address.
    fn remote_addr(&self) -> &BleAddr;
}

/// An acceptor that yields inbound L2CAP connections.
pub trait BleAcceptor: Send {
    /// The concrete stream type yielded by this acceptor.
    type Stream: BleStream + 'static;

    /// Accept the next inbound connection.
    fn accept(
        &mut self,
    ) -> impl std::future::Future<Output = Result<Self::Stream, TransportError>> + Send;
}

/// A scanner that yields discovered BLE devices advertising the FIPS UUID.
pub trait BleScanner: Send {
    /// Wait for the next discovered device.
    ///
    /// Returns `None` when scanning is stopped.
    fn next(
        &mut self,
    ) -> impl std::future::Future<Output = Option<BleAddr>> + Send;
}

/// Core BLE I/O operations.
///
/// This trait abstracts the BlueZ/bluer stack so that `BleTransport`
/// can be tested with `MockBleIo` (in-memory channels) in CI without
/// requiring Bluetooth hardware, D-Bus, or bluetoothd.
pub trait BleIo: Send + Sync + 'static {
    /// The concrete stream type returned by this I/O implementation.
    type Stream: BleStream + 'static;
    /// The concrete acceptor type.
    type Acceptor: BleAcceptor<Stream = Self::Stream> + 'static;
    /// The concrete scanner type.
    type Scanner: BleScanner + 'static;

    /// Start listening for inbound L2CAP connections on the given PSM.
    fn listen(
        &self,
        psm: u16,
    ) -> impl std::future::Future<Output = Result<Self::Acceptor, TransportError>> + Send;

    /// Connect to a remote BLE device on the given PSM.
    fn connect(
        &self,
        addr: &BleAddr,
        psm: u16,
    ) -> impl std::future::Future<Output = Result<Self::Stream, TransportError>> + Send;

    /// Start advertising the FIPS service UUID.
    fn start_advertising(
        &self,
    ) -> impl std::future::Future<Output = Result<(), TransportError>> + Send;

    /// Stop advertising.
    fn stop_advertising(
        &self,
    ) -> impl std::future::Future<Output = Result<(), TransportError>> + Send;

    /// Start passive scanning for FIPS service UUID advertisements.
    fn start_scanning(
        &self,
    ) -> impl std::future::Future<Output = Result<Self::Scanner, TransportError>> + Send;

    /// Get the adapter's BLE address.
    fn local_addr(&self) -> Result<BleAddr, TransportError>;

    /// Get the adapter name (e.g., "hci0").
    fn adapter_name(&self) -> &str;
}

// ============================================================================
// BluerIo — Production BLE I/O via BlueZ D-Bus
// ============================================================================

#[cfg(feature = "ble")]
mod bluer_impl {
    use super::*;
    use crate::transport::TransportError;

    use bluer::l2cap::{SeqPacket, SeqPacketListener, Socket, SocketAddr};
    use bluer::{adv::Advertisement, AdapterEvent, AddressType, DiscoveryFilter, DiscoveryTransport};
    use futures::StreamExt;
    use std::collections::{BTreeSet, HashSet};
    use std::pin::Pin;
    use tokio::sync::Mutex;
    use tracing::{debug, trace};

    /// FIPS BLE service UUID.
    ///
    /// Derived from SHA-256("FIPS: welcome to cryptoanarchy") with UUID v4
    /// version/variant bits applied.
    pub const FIPS_SERVICE_UUID: bluer::Uuid =
        bluer::Uuid::from_u128(0x9c90_b790_2cc5_42c0_9f87_c9cc_4064_8f4c);

    /// Map a bluer error to a TransportError.
    fn map_err(context: &str, e: bluer::Error) -> TransportError {
        TransportError::Io(std::io::Error::other(format!("{}: {}", context, e)))
    }

    /// Map a std::io::Error to a TransportError.
    fn map_io_err(context: &str, e: std::io::Error) -> TransportError {
        TransportError::Io(std::io::Error::new(
            e.kind(),
            format!("{}: {}", context, e),
        ))
    }

    // ----------------------------------------------------------------
    // BluerStream
    // ----------------------------------------------------------------

    /// BLE stream wrapping a bluer L2CAP SeqPacket connection.
    pub struct BluerStream {
        conn: SeqPacket,
        remote: BleAddr,
        send_mtu: u16,
        recv_mtu: u16,
    }

    impl BluerStream {
        /// Construct from a connected SeqPacket, querying MTU values.
        pub fn new(conn: SeqPacket, remote: BleAddr) -> Result<Self, TransportError> {
            let send_mtu = conn
                .send_mtu()
                .map_err(|e| map_io_err("send_mtu", e))? as u16;
            let recv_mtu = conn
                .recv_mtu()
                .map_err(|e| map_io_err("recv_mtu", e))? as u16;

            // Log negotiated PHY for diagnostics (2M vs 1M)
            match conn.as_ref().phy() {
                Ok(phy) => debug!(addr = %remote, phy, send_mtu, recv_mtu, "BLE connection established"),
                Err(_) => debug!(addr = %remote, send_mtu, recv_mtu, "BLE connection established (PHY query unsupported)"),
            }

            Ok(Self { conn, remote, send_mtu, recv_mtu })
        }
    }

    impl BleStream for BluerStream {
        async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
            self.conn
                .send(data)
                .await
                .map(|_| ())
                .map_err(|e| TransportError::SendFailed(format!("{}", e)))
        }

        async fn recv(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
            self.conn
                .recv(buf)
                .await
                .map_err(|e| TransportError::RecvFailed(format!("{}", e)))
        }

        fn send_mtu(&self) -> u16 {
            self.send_mtu
        }

        fn recv_mtu(&self) -> u16 {
            self.recv_mtu
        }

        fn remote_addr(&self) -> &BleAddr {
            &self.remote
        }
    }

    // ----------------------------------------------------------------
    // BluerAcceptor
    // ----------------------------------------------------------------

    /// Acceptor wrapping a bluer L2CAP SeqPacketListener.
    pub struct BluerAcceptor {
        listener: SeqPacketListener,
        adapter_name: String,
    }

    impl BleAcceptor for BluerAcceptor {
        type Stream = BluerStream;

        async fn accept(&mut self) -> Result<BluerStream, TransportError> {
            let (conn, peer_sa) = self
                .listener
                .accept()
                .await
                .map_err(|e| map_io_err("accept", e))?;

            let remote = BleAddr::from_bluer(peer_sa.addr, &self.adapter_name);
            BluerStream::new(conn, remote)
        }
    }

    // ----------------------------------------------------------------
    // BluerScanner
    // ----------------------------------------------------------------

    /// Scanner wrapping a bluer discovery event stream.
    pub struct BluerScanner {
        events: Pin<Box<dyn futures::Stream<Item = AdapterEvent> + Send>>,
        adapter: bluer::Adapter,
        adapter_name: String,
    }

    impl BleScanner for BluerScanner {
        async fn next(&mut self) -> Option<BleAddr> {
            loop {
                match self.events.next().await {
                    Some(AdapterEvent::DeviceAdded(addr)) => {
                        // Check if device advertises FIPS UUID
                        if let Ok(device) = self.adapter.device(addr) {
                            match device.uuids().await {
                                Ok(Some(uuids)) if uuids.contains(&FIPS_SERVICE_UUID) => {
                                    let ble_addr =
                                        BleAddr::from_bluer(addr, &self.adapter_name);
                                    debug!(addr = %ble_addr, "BLE scanner: FIPS peer found");
                                    return Some(ble_addr);
                                }
                                Ok(_) => {
                                    trace!(addr = %addr, "BLE scanner: device without FIPS UUID");
                                }
                                Err(e) => {
                                    trace!(addr = %addr, error = %e, "BLE scanner: failed to read UUIDs");
                                }
                            }
                        }
                    }
                    Some(_) => continue,
                    None => return None,
                }
            }
        }
    }

    // ----------------------------------------------------------------
    // BluerIo
    // ----------------------------------------------------------------

    /// Production BLE I/O implementation via BlueZ D-Bus (bluer crate).
    pub struct BluerIo {
        #[allow(dead_code)] // Session must be kept alive for the adapter.
        session: bluer::Session,
        adapter: bluer::Adapter,
        adapter_name: String,
        adv_handle: Mutex<Option<bluer::adv::AdvertisementHandle>>,
        mtu: u16,
    }

    impl BluerIo {
        /// Create a new BluerIo for the given adapter.
        ///
        /// Connects to BlueZ via D-Bus and powers on the adapter.
        pub async fn new(adapter_name: &str, mtu: u16) -> Result<Self, TransportError> {
            let session = bluer::Session::new()
                .await
                .map_err(|e| map_err("Session::new", e))?;

            let adapter = if adapter_name == "default" {
                session
                    .default_adapter()
                    .await
                    .map_err(|e| map_err("default_adapter", e))?
            } else {
                session
                    .adapter(adapter_name)
                    .map_err(|e| map_err("adapter", e))?
            };

            adapter
                .set_powered(true)
                .await
                .map_err(|e| map_err("set_powered", e))?;

            let name = adapter.name().to_string();
            debug!(adapter = %name, "BluerIo initialized");

            Ok(Self {
                session,
                adapter,
                adapter_name: name,
                adv_handle: Mutex::new(None),
                mtu,
            })
        }
    }

    impl BleIo for BluerIo {
        type Stream = BluerStream;
        type Acceptor = BluerAcceptor;
        type Scanner = BluerScanner;

        async fn listen(&self, psm: u16) -> Result<Self::Acceptor, TransportError> {
            let local_addr = self
                .adapter
                .address()
                .await
                .map_err(|e| map_err("address", e))?;

            let sa = SocketAddr::new(local_addr, AddressType::LePublic, psm);
            let listener = SeqPacketListener::bind(sa)
                .await
                .map_err(|e| map_io_err("bind", e))?;

            // Request high MTU for accepted connections
            listener
                .as_ref()
                .set_recv_mtu(self.mtu)
                .map_err(|e| map_io_err("set_recv_mtu", e))?;

            // Prevent sniff mode to reduce latency during data transfer
            if let Err(e) = listener.as_ref().set_power_forced_active(true) {
                debug!(error = %e, "BLE listener: set_power_forced_active not supported");
            }

            debug!(psm, mtu = self.mtu, "BLE listener bound");

            Ok(BluerAcceptor {
                listener,
                adapter_name: self.adapter_name.clone(),
            })
        }

        async fn connect(
            &self,
            addr: &BleAddr,
            psm: u16,
        ) -> Result<Self::Stream, TransportError> {
            let target_sa = addr.to_socket_addr(psm);

            let socket = Socket::<SeqPacket>::new_seq_packet()
                .map_err(|e| map_io_err("new_seq_packet", e))?;
            socket
                .bind(SocketAddr::any_le())
                .map_err(|e| map_io_err("bind", e))?;
            socket
                .set_recv_mtu(self.mtu)
                .map_err(|e| map_io_err("set_recv_mtu", e))?;

            // Prevent sniff mode to reduce latency during data transfer
            if let Err(e) = socket.set_power_forced_active(true) {
                debug!(error = %e, "BLE connect: set_power_forced_active not supported");
            }

            let conn = socket
                .connect(target_sa)
                .await
                .map_err(|e| map_io_err("connect", e))?;

            let remote = addr.clone();
            BluerStream::new(conn, remote)
        }

        async fn start_advertising(&self) -> Result<(), TransportError> {
            let adv = Advertisement {
                advertisement_type: bluer::adv::Type::Peripheral,
                service_uuids: {
                    let mut s = BTreeSet::new();
                    s.insert(FIPS_SERVICE_UUID);
                    s
                },
                local_name: Some("fips".to_string()),
                min_interval: Some(std::time::Duration::from_millis(400)),
                max_interval: Some(std::time::Duration::from_millis(600)),
                ..Default::default()
            };

            let handle = self
                .adapter
                .advertise(adv)
                .await
                .map_err(|e| map_err("advertise", e))?;

            *self.adv_handle.lock().await = Some(handle);
            debug!("BLE advertising started");
            Ok(())
        }

        async fn stop_advertising(&self) -> Result<(), TransportError> {
            let _ = self.adv_handle.lock().await.take();
            debug!("BLE advertising stopped");
            Ok(())
        }

        async fn start_scanning(&self) -> Result<Self::Scanner, TransportError> {
            // Set discovery filter for LE transport with FIPS UUID
            let filter = DiscoveryFilter {
                transport: DiscoveryTransport::Le,
                uuids: {
                    let mut s = HashSet::new();
                    s.insert(FIPS_SERVICE_UUID);
                    s
                },
                ..Default::default()
            };

            self.adapter
                .set_discovery_filter(filter)
                .await
                .map_err(|e| map_err("set_discovery_filter", e))?;

            let events = self
                .adapter
                .discover_devices()
                .await
                .map_err(|e| map_err("discover_devices", e))?;

            debug!("BLE scanning started");

            Ok(BluerScanner {
                events: Box::pin(events),
                adapter: self.adapter.clone(),
                adapter_name: self.adapter_name.clone(),
            })
        }

        fn local_addr(&self) -> Result<BleAddr, TransportError> {
            // Use futures::executor::block_on since this is a sync method
            // but needs an async call. The adapter address is cached so
            // the D-Bus call is fast.
            let addr = futures::executor::block_on(self.adapter.address())
                .map_err(|e| map_err("address", e))?;
            Ok(BleAddr::from_bluer(addr, &self.adapter_name))
        }

        fn adapter_name(&self) -> &str {
            &self.adapter_name
        }
    }

    // Compile-time assertion that BluerIo satisfies Send + Sync.
    #[allow(dead_code)]
    fn _assert_bluer_io_send_sync() {
        fn require<T: Send + Sync>() {}
        require::<BluerIo>();
    }
}

#[cfg(feature = "ble")]
pub use bluer_impl::{BluerAcceptor, BluerIo, BluerScanner, BluerStream, FIPS_SERVICE_UUID};

// ============================================================================
// Mock BLE I/O (for testing without hardware)
// ============================================================================

/// Mock BLE stream backed by tokio channels.
pub struct MockBleStream {
    addr: BleAddr,
    send_mtu: u16,
    recv_mtu: u16,
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
}

impl MockBleStream {
    /// Create a linked pair of mock streams simulating an L2CAP connection.
    pub fn pair(
        addr_a: BleAddr,
        addr_b: BleAddr,
        mtu: u16,
    ) -> (Self, Self) {
        let (tx_a, rx_a) = tokio::sync::mpsc::channel(64);
        let (tx_b, rx_b) = tokio::sync::mpsc::channel(64);
        let stream_a = Self {
            addr: addr_b.clone(),
            send_mtu: mtu,
            recv_mtu: mtu,
            tx: tx_a,
            rx: tokio::sync::Mutex::new(rx_b),
        };
        let stream_b = Self {
            addr: addr_a,
            send_mtu: mtu,
            recv_mtu: mtu,
            tx: tx_b,
            rx: tokio::sync::Mutex::new(rx_a),
        };
        (stream_a, stream_b)
    }
}

impl BleStream for MockBleStream {
    async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        self.tx
            .send(data.to_vec())
            .await
            .map_err(|_| TransportError::SendFailed("channel closed".into()))
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        let mut rx = self.rx.lock().await;
        match rx.recv().await {
            Some(data) => {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                Ok(len)
            }
            None => Ok(0), // channel closed = connection closed = zero-length read
        }
    }

    fn send_mtu(&self) -> u16 {
        self.send_mtu
    }

    fn recv_mtu(&self) -> u16 {
        self.recv_mtu
    }

    fn remote_addr(&self) -> &BleAddr {
        &self.addr
    }
}

/// Mock BLE acceptor backed by a channel of pre-connected streams.
pub struct MockBleAcceptor {
    rx: tokio::sync::mpsc::Receiver<MockBleStream>,
}

impl BleAcceptor for MockBleAcceptor {
    type Stream = MockBleStream;

    async fn accept(&mut self) -> Result<MockBleStream, TransportError> {
        self.rx
            .recv()
            .await
            .ok_or(TransportError::RecvFailed("acceptor channel closed".into()))
    }
}

/// Mock BLE scanner backed by a channel of discovered addresses.
pub struct MockBleScanner {
    rx: tokio::sync::mpsc::Receiver<BleAddr>,
}

impl BleScanner for MockBleScanner {
    async fn next(&mut self) -> Option<BleAddr> {
        self.rx.recv().await
    }
}

/// Handler type for outbound mock connections.
type ConnectHandler =
    Box<dyn Fn(&BleAddr, u16) -> Result<MockBleStream, TransportError> + Send + Sync>;

/// Mock BLE I/O for testing without hardware.
///
/// Create with `MockBleIo::new()`, then use `inject_*` methods to
/// feed connections and scan results into the transport under test.
pub struct MockBleIo {
    adapter: String,
    local_addr: BleAddr,
    accept_tx: tokio::sync::mpsc::Sender<MockBleStream>,
    accept_rx: std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<MockBleStream>>>,
    scan_tx: tokio::sync::mpsc::Sender<BleAddr>,
    scan_rx: std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<BleAddr>>>,
    connect_handler: std::sync::Mutex<Option<ConnectHandler>>,
}

impl MockBleIo {
    /// Create a new mock BLE I/O with the given adapter name and address.
    pub fn new(adapter: &str, local_addr: BleAddr) -> Self {
        let (accept_tx, accept_rx) = tokio::sync::mpsc::channel(16);
        let (scan_tx, scan_rx) = tokio::sync::mpsc::channel(64);
        Self {
            adapter: adapter.to_string(),
            local_addr,
            accept_tx,
            accept_rx: std::sync::Mutex::new(Some(accept_rx)),
            scan_tx,
            scan_rx: std::sync::Mutex::new(Some(scan_rx)),
            connect_handler: std::sync::Mutex::new(None),
        }
    }

    /// Inject an inbound connection (simulates a remote device connecting).
    pub async fn inject_inbound(&self, stream: MockBleStream) {
        let _ = self.accept_tx.send(stream).await;
    }

    /// Inject a scan result (simulates discovering a remote device).
    pub async fn inject_scan_result(&self, addr: BleAddr) {
        let _ = self.scan_tx.send(addr).await;
    }

    /// Set a handler for outbound connect calls.
    pub fn set_connect_handler<F>(&self, handler: F)
    where
        F: Fn(&BleAddr, u16) -> Result<MockBleStream, TransportError> + Send + Sync + 'static,
    {
        *self.connect_handler.lock().unwrap() = Some(Box::new(handler));
    }
}

impl BleIo for MockBleIo {
    type Stream = MockBleStream;
    type Acceptor = MockBleAcceptor;
    type Scanner = MockBleScanner;

    async fn listen(&self, _psm: u16) -> Result<Self::Acceptor, TransportError> {
        let rx = self
            .accept_rx
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| TransportError::NotSupported("acceptor already taken".into()))?;
        Ok(MockBleAcceptor { rx })
    }

    async fn connect(&self, addr: &BleAddr, psm: u16) -> Result<Self::Stream, TransportError> {
        let handler = self.connect_handler.lock().unwrap();
        match handler.as_ref() {
            Some(f) => f(addr, psm),
            None => Err(TransportError::ConnectionRefused),
        }
    }

    async fn start_advertising(&self) -> Result<(), TransportError> {
        Ok(())
    }

    async fn stop_advertising(&self) -> Result<(), TransportError> {
        Ok(())
    }

    async fn start_scanning(&self) -> Result<Self::Scanner, TransportError> {
        let rx = self
            .scan_rx
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| TransportError::NotSupported("scanner already taken".into()))?;
        Ok(MockBleScanner { rx })
    }

    fn local_addr(&self) -> Result<BleAddr, TransportError> {
        Ok(self.local_addr.clone())
    }

    fn adapter_name(&self) -> &str {
        &self.adapter
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addr(n: u8) -> BleAddr {
        BleAddr {
            adapter: "hci0".to_string(),
            device: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n],
        }
    }

    #[tokio::test]
    async fn test_mock_stream_pair_send_recv() {
        let (a, b) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);

        a.send(b"hello").await.unwrap();
        let mut buf = [0u8; 64];
        let n = b.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        b.send(b"world").await.unwrap();
        let n = a.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"world");
    }

    #[tokio::test]
    async fn test_mock_stream_mtu() {
        let (a, b) = MockBleStream::pair(test_addr(1), test_addr(2), 512);
        assert_eq!(a.send_mtu(), 512);
        assert_eq!(a.recv_mtu(), 512);
        assert_eq!(b.send_mtu(), 512);
        assert_eq!(b.recv_mtu(), 512);
    }

    #[tokio::test]
    async fn test_mock_stream_remote_addr() {
        let (a, b) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        assert_eq!(a.remote_addr(), &test_addr(2));
        assert_eq!(b.remote_addr(), &test_addr(1));
    }

    #[tokio::test]
    async fn test_mock_io_listen_accept() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let mut acceptor = io.listen(0x0085).await.unwrap();

        let (stream_a, _stream_b) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        io.inject_inbound(stream_a).await;

        let accepted = acceptor.accept().await.unwrap();
        // stream_a's remote_addr is addr_b (test_addr(2))
        assert_eq!(accepted.remote_addr(), &test_addr(2));
    }

    #[tokio::test]
    async fn test_mock_io_connect() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let local = test_addr(1);
        io.set_connect_handler(move |addr, _psm| {
            let (stream, _peer) = MockBleStream::pair(local.clone(), addr.clone(), 2048);
            Ok(stream)
        });

        let stream = io.connect(&test_addr(2), 0x0085).await.unwrap();
        assert_eq!(stream.remote_addr(), &test_addr(2));
    }

    #[tokio::test]
    async fn test_mock_io_connect_no_handler() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let result = io.connect(&test_addr(2), 0x0085).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mock_io_scan() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let mut scanner = io.start_scanning().await.unwrap();

        io.inject_scan_result(test_addr(2)).await;
        io.inject_scan_result(test_addr(3)).await;

        assert_eq!(scanner.next().await, Some(test_addr(2)));
        assert_eq!(scanner.next().await, Some(test_addr(3)));
    }

    #[tokio::test]
    async fn test_mock_io_local_addr() {
        let io = MockBleIo::new("hci0", test_addr(1));
        assert_eq!(io.local_addr().unwrap(), test_addr(1));
        assert_eq!(io.adapter_name(), "hci0");
    }

    #[tokio::test]
    async fn test_mock_io_advertising_noop() {
        let io = MockBleIo::new("hci0", test_addr(1));
        io.start_advertising().await.unwrap();
        io.stop_advertising().await.unwrap();
    }

    #[tokio::test]
    async fn test_mock_io_listen_twice_fails() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let _acceptor = io.listen(0x0085).await.unwrap();
        assert!(io.listen(0x0085).await.is_err());
    }
}
