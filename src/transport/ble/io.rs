//! BLE I/O abstraction layer.
//!
//! Defines the `BleIo` seam that separates transport logic from any one
//! radio stack, and the in-memory `MockBleIo` test double. Everything in
//! this file is platform-neutral; each concrete backend lives beside it in
//! its own `io_<platform>.rs` — [`super::io_linux`] for BlueZ.

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
    ///
    /// A single call must never return bytes drawn from more than one SDU.
    /// The receive loop emits what one call returns as one FMP frame. A
    /// concatenation is caught by the frame-length check in the node's
    /// dispatch only when the leading frame is an established one; where it
    /// is a handshake frame, that check passes and the buffer is dropped one
    /// step later by that frame kind's exact-size parse. Returning less than
    /// a whole SDU is allowed: a truncated frame fails the AEAD tag or the
    /// exact-size parse regardless.
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

/// One advertisement observed by a scanner.
///
/// Carries what the backend could read from the advert, not what it wishes
/// were there: a backend that cannot surface a field reports `None` for it,
/// the way `TransportHandle::local_addr` already does for transports that
/// have no address to give.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanAdvert {
    /// The advertiser's link address.
    pub addr: BleAddr,
    /// The L2CAP listener PSM the peer advertised, if it advertised one.
    ///
    /// `None` for a legacy UUID-only advertiser, and for a backend that
    /// cannot read advertised service data. The dialer then falls back to the
    /// configured PSM. See [`super::psm`] for the wire layout.
    pub psm: Option<u16>,
    /// Received signal strength in dBm, if the backend reports it.
    pub rssi: Option<i16>,
}

impl ScanAdvert {
    /// An advert carrying nothing but a link address — what a legacy
    /// UUID-only advertiser produces.
    pub fn new(addr: BleAddr) -> Self {
        Self {
            addr,
            psm: None,
            rssi: None,
        }
    }

    /// An advert carrying a listener PSM.
    pub fn with_psm(addr: BleAddr, psm: u16) -> Self {
        Self {
            addr,
            psm: Some(psm),
            rssi: None,
        }
    }
}

/// A scanner that yields discovered BLE devices advertising the FIPS UUID.
pub trait BleScanner: Send {
    /// Wait for the next observed advertisement.
    ///
    /// Returns `None` when scanning is stopped.
    fn next(&mut self) -> impl std::future::Future<Output = Option<ScanAdvert>> + Send;
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

    /// Start listening for inbound L2CAP connections, and report the PSM
    /// actually bound.
    ///
    /// `psm` is the PSM to request. Backends that let an application choose
    /// one (BlueZ) bind it and report it back unchanged. Backends whose
    /// platform assigns the PSM (Android, macOS) ignore the request and
    /// report what the OS gave them — which is why this returns a value
    /// rather than being assumed equal to the argument. The reported PSM is
    /// what gets advertised.
    fn listen(
        &self,
        psm: u16,
    ) -> impl std::future::Future<Output = Result<(Self::Acceptor, u16), TransportError>> + Send;

    /// Connect to a remote BLE device on the given PSM.
    fn connect(
        &self,
        addr: &BleAddr,
        psm: u16,
    ) -> impl std::future::Future<Output = Result<Self::Stream, TransportError>> + Send;

    /// Start advertising the FIPS service UUID, and the listener PSM.
    ///
    /// `psm` is the PSM this node's listener is bound to; see [`super::psm`]
    /// for the wire layout it should be advertised in. A backend that cannot
    /// put it in its advert ignores the argument, and peers dial it at their
    /// configured PSM as before.
    fn start_advertising(
        &self,
        psm: u16,
    ) -> impl std::future::Future<Output = Result<(), TransportError>> + Send;

    /// Stop advertising.
    fn stop_advertising(
        &self,
    ) -> impl std::future::Future<Output = Result<(), TransportError>> + Send;

    /// Start passive scanning for FIPS service UUID advertisements.
    fn start_scanning(
        &self,
    ) -> impl std::future::Future<Output = Result<Self::Scanner, TransportError>> + Send;

    /// Stop scanning.
    ///
    /// The counterpart to [`Self::stop_advertising`], and needed for the same
    /// reason: dropping the transport's scan task stops *us* reading adverts,
    /// but on a backend whose radio is owned elsewhere it does not stop the
    /// radio. A backend whose scan ends when its `Scanner` is dropped
    /// implements this as a no-op and says so.
    fn stop_scanning(&self)
    -> impl std::future::Future<Output = Result<(), TransportError>> + Send;

    /// Get the adapter's BLE address.
    fn local_addr(&self) -> Result<BleAddr, TransportError>;

    /// Get the adapter name (e.g., "hci0").
    fn adapter_name(&self) -> &str;
}

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
    pub fn pair(addr_a: BleAddr, addr_b: BleAddr, mtu: u16) -> (Self, Self) {
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

/// Mock BLE scanner backed by a channel of observed adverts.
pub struct MockBleScanner {
    rx: tokio::sync::mpsc::Receiver<ScanAdvert>,
}

impl BleScanner for MockBleScanner {
    async fn next(&mut self) -> Option<ScanAdvert> {
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
    scan_tx: tokio::sync::mpsc::Sender<ScanAdvert>,
    scan_rx: std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<ScanAdvert>>>,
    connect_handler: std::sync::Mutex<Option<ConnectHandler>>,
    /// PSM `listen` reports back, overriding the requested one.
    ///
    /// Simulates a platform that assigns the PSM itself.
    bound_psm: std::sync::Mutex<Option<u16>>,
    /// PSM most recently passed to `start_advertising`.
    advertised_psm: std::sync::Mutex<Option<u16>>,
    /// Number of times `stop_scanning` has been called.
    stop_scans: std::sync::atomic::AtomicUsize,
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
            bound_psm: std::sync::Mutex::new(None),
            advertised_psm: std::sync::Mutex::new(None),
            stop_scans: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// How many times the transport has asked this backend to stop scanning.
    pub fn stop_scan_calls(&self) -> usize {
        self.stop_scans.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Inject an inbound connection (simulates a remote device connecting).
    pub async fn inject_inbound(&self, stream: MockBleStream) {
        let _ = self.accept_tx.send(stream).await;
    }

    /// Inject a scan result (simulates discovering a legacy UUID-only
    /// advertiser, which carries no PSM).
    pub async fn inject_scan_result(&self, addr: BleAddr) {
        self.inject_scan_advert(ScanAdvert::new(addr)).await;
    }

    /// Inject an observed advertisement verbatim.
    pub async fn inject_scan_advert(&self, advert: ScanAdvert) {
        let _ = self.scan_tx.send(advert).await;
    }

    /// Make `listen` report a PSM other than the one requested, the way a
    /// platform that assigns PSMs itself would.
    pub fn set_bound_psm(&self, psm: u16) {
        *self.bound_psm.lock().unwrap_or_else(|e| e.into_inner()) = Some(psm);
    }

    /// The PSM most recently handed to `start_advertising`.
    pub fn advertised_psm(&self) -> Option<u16> {
        *self
            .advertised_psm
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Set a handler for outbound connect calls.
    pub fn set_connect_handler<F>(&self, handler: F)
    where
        F: Fn(&BleAddr, u16) -> Result<MockBleStream, TransportError> + Send + Sync + 'static,
    {
        *self
            .connect_handler
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Box::new(handler));
    }
}

impl BleIo for MockBleIo {
    type Stream = MockBleStream;
    type Acceptor = MockBleAcceptor;
    type Scanner = MockBleScanner;

    async fn listen(&self, psm: u16) -> Result<(Self::Acceptor, u16), TransportError> {
        let rx = self
            .accept_rx
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| TransportError::NotSupported("acceptor already taken".into()))?;
        let bound = self
            .bound_psm
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .unwrap_or(psm);
        Ok((MockBleAcceptor { rx }, bound))
    }

    async fn connect(&self, addr: &BleAddr, psm: u16) -> Result<Self::Stream, TransportError> {
        let handler = self
            .connect_handler
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match handler.as_ref() {
            Some(f) => f(addr, psm),
            None => Err(TransportError::ConnectionRefused),
        }
    }

    async fn start_advertising(&self, psm: u16) -> Result<(), TransportError> {
        *self
            .advertised_psm
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(psm);
        Ok(())
    }

    async fn stop_advertising(&self) -> Result<(), TransportError> {
        Ok(())
    }

    async fn stop_scanning(&self) -> Result<(), TransportError> {
        self.stop_scans
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
        let (mut acceptor, bound) = io.listen(0x0085).await.unwrap();
        assert_eq!(bound, 0x0085, "mock binds what it is asked for by default");

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

        assert_eq!(scanner.next().await, Some(ScanAdvert::new(test_addr(2))));
        assert_eq!(scanner.next().await, Some(ScanAdvert::new(test_addr(3))));
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
        io.start_advertising(0x0085).await.unwrap();
        assert_eq!(io.advertised_psm(), Some(0x0085));
        io.stop_advertising().await.unwrap();
    }

    /// A backend whose platform assigns the PSM reports back something other
    /// than what was requested — the case the return value exists for.
    #[tokio::test]
    async fn test_mock_io_listen_reports_an_os_assigned_psm() {
        let io = MockBleIo::new("hci0", test_addr(1));
        io.set_bound_psm(0x00C1);
        let (_acceptor, bound) = io.listen(0x0085).await.unwrap();
        assert_eq!(bound, 0x00C1);
    }

    #[tokio::test]
    async fn test_mock_io_scan_advert_carries_a_psm() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let mut scanner = io.start_scanning().await.unwrap();
        io.inject_scan_advert(ScanAdvert::with_psm(test_addr(2), 0x00C1))
            .await;
        let advert = scanner.next().await.unwrap();
        assert_eq!(advert.addr, test_addr(2));
        assert_eq!(advert.psm, Some(0x00C1));
        assert_eq!(advert.rssi, None);
    }

    #[tokio::test]
    async fn test_mock_io_listen_twice_fails() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let _acceptor = io.listen(0x0085).await.unwrap();
        assert!(io.listen(0x0085).await.is_err());
    }
}
