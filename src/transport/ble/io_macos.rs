//! macOS BLE I/O implementation via `bluest` (CoreBluetooth).
//!
//! Implements the `BleIo` trait for macOS using the `bluest` crate, which
//! wraps CoreBluetooth's L2CAP CoC support.
//!
//! Current scope: outbound connections only (macOS → Linux). The acceptor
//! and advertising are stubs — inbound connections and macOS ↔ macOS
//! support require GATT-based PSM exchange (see docs/macos-ble-design.md).

use super::*;
use crate::transport::TransportError;
use crate::transport::ble::addr::BleAddr;

use bluest::{Adapter, Device, DeviceId};
use futures::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, trace};

/// FIPS BLE service UUID (same value as Linux — derived from
/// SHA-256("FIPS: welcome to cryptoanarchy") with UUID v4 bits).
const FIPS_SERVICE_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0x9c90_b790_2cc5_42c0_9f87_c9cc_4064_8f4c);

/// Default adapter name used on macOS (CoreBluetooth doesn't expose adapter names).
const MACOS_ADAPTER_NAME: &str = "default";

// ============================================================================
// BluestStream — wraps a split L2capChannel
// ============================================================================

/// BLE stream wrapping a bluest L2CAP channel with length-prefix framing.
///
/// CoreBluetooth exposes L2CAP channels as byte streams (`NSInputStream`/
/// `NSOutputStream`), which may coalesce or fragment L2CAP SDUs. This
/// stream adds 2-byte big-endian length framing to reconstruct message
/// boundaries, matching the framing added by the Linux `BluerStream`.
pub struct BluestStream {
    reader: Mutex<bluest::L2capChannelReader>,
    writer: Mutex<bluest::L2capChannelWriter>,
    remote: BleAddr,
    mtu: u16,
    /// Byte buffer for reassembling length-prefixed frames from the
    /// underlying byte stream.
    recv_buf: Mutex<Vec<u8>>,
}

impl BleStream for BluestStream {
    async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        // Length-prefix framing: [len:2 BE][payload]
        let mut framed = Vec::with_capacity(2 + data.len());
        framed.extend_from_slice(&(data.len() as u16).to_be_bytes());
        framed.extend_from_slice(data);
        trace!(len = data.len(), framed_len = framed.len(), addr = %self.remote, "BLE macOS send");
        self.writer
            .lock()
            .await
            .write(&framed)
            .await
            .map_err(|e| TransportError::Io(std::io::Error::other(format!("BLE send: {e}"))))
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        loop {
            // Check if we have a complete frame in the buffer
            {
                let mut recv_buf = self.recv_buf.lock().await;
                if recv_buf.len() >= 2 {
                    let payload_len = u16::from_be_bytes([recv_buf[0], recv_buf[1]]) as usize;
                    if recv_buf.len() >= 2 + payload_len {
                        let copy_len = payload_len.min(buf.len());
                        buf[..copy_len].copy_from_slice(&recv_buf[2..2 + copy_len]);
                        recv_buf.drain(..2 + payload_len);
                        trace!(
                            len = copy_len,
                            buf_remaining = recv_buf.len(),
                            addr = %self.remote,
                            "BLE macOS recv frame"
                        );
                        return Ok(copy_len);
                    }
                }
            } // drop recv_buf lock

            // Read more bytes from the L2CAP channel
            let mut tmp = [0u8; 2048];
            let n =
                self.reader.lock().await.read(&mut tmp).await.map_err(|e| {
                    TransportError::Io(std::io::Error::other(format!("BLE recv: {e}")))
                })?;
            if n == 0 {
                return Ok(0);
            }
            trace!(raw_bytes = n, addr = %self.remote, "BLE macOS recv raw");

            // Append to buffer
            self.recv_buf.lock().await.extend_from_slice(&tmp[..n]);
        }
    }

    fn send_mtu(&self) -> u16 {
        self.mtu
    }

    fn recv_mtu(&self) -> u16 {
        self.mtu
    }

    fn remote_addr(&self) -> &BleAddr {
        &self.remote
    }
}

// ============================================================================
// BluestAcceptor — stub (macOS inbound not yet supported)
// ============================================================================

/// Stub acceptor that never accepts.
///
/// macOS inbound L2CAP connections require GATT-based PSM exchange,
/// which is not yet implemented. This acceptor blocks forever.
pub struct BluestAcceptor;

impl BleAcceptor for BluestAcceptor {
    type Stream = BluestStream;

    async fn accept(&mut self) -> Result<BluestStream, TransportError> {
        // Block forever — no inbound connections on macOS yet
        std::future::pending().await
    }
}

// ============================================================================
// BluestScanner — wraps bluest scan stream
// ============================================================================

/// Scanner that yields discovered BLE devices advertising the FIPS UUID.
pub struct BluestScanner {
    rx: tokio::sync::mpsc::Receiver<BleAddr>,
}

impl BleScanner for BluestScanner {
    async fn next(&mut self) -> Option<BleAddr> {
        self.rx.recv().await
    }
}

// ============================================================================
// BluestIo — macOS BLE I/O implementation
// ============================================================================

/// macOS BLE I/O using bluest (CoreBluetooth).
pub struct BluestIo {
    adapter: Adapter,
    /// Configured MTU (bluest doesn't expose per-connection MTU).
    mtu: u16,
    /// Cache of discovered devices, keyed by the 6-byte pseudo-address
    /// derived from CoreBluetooth's DeviceId.
    devices: Arc<Mutex<HashMap<[u8; 6], Device>>>,
}

impl BluestIo {
    /// Create a new macOS BLE I/O instance.
    ///
    /// Requires the main thread to be running CFRunLoopRun() — the `fips`
    /// binary handles this when built with the `ble-macos` feature by
    /// dedicating the main thread to the NSRunLoop and running tokio on
    /// a background thread.
    pub async fn new(_adapter_name: &str, mtu: u16) -> Result<Self, TransportError> {
        let adapter = Adapter::default()
            .await
            .ok_or_else(|| TransportError::StartFailed("CoreBluetooth adapter not found".into()))?;

        adapter
            .wait_available()
            .await
            .map_err(|e| TransportError::StartFailed(format!("Bluetooth not available: {e}")))?;

        debug!("CoreBluetooth adapter ready");

        Ok(Self {
            adapter,
            mtu,
            devices: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}

/// Derive a 6-byte pseudo-address from a CoreBluetooth DeviceId.
///
/// CoreBluetooth doesn't expose real Bluetooth MAC addresses. We use the
/// first 6 bytes of the DeviceId's UUID as a stable (within this host)
/// identifier for pool lookups and `BleAddr` compatibility.
fn device_id_to_bytes(id: &DeviceId) -> [u8; 6] {
    // DeviceId displays as a UUID string; parse it back
    let s = format!("{id}");
    if let Ok(uuid) = uuid::Uuid::parse_str(&s) {
        let b = uuid.as_bytes();
        [b[0], b[1], b[2], b[3], b[4], b[5]]
    } else {
        // Fallback: hash the display string
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        s.hash(&mut hasher);
        let h = hasher.finish().to_le_bytes();
        [h[0], h[1], h[2], h[3], h[4], h[5]]
    }
}

impl BleIo for BluestIo {
    type Stream = BluestStream;
    type Acceptor = BluestAcceptor;
    type Scanner = BluestScanner;

    async fn listen(&self, _psm: u16) -> Result<BluestAcceptor, TransportError> {
        // macOS inbound requires GATT-based PSM exchange — not yet implemented.
        // Return a stub acceptor that blocks forever (accept_loop will just idle).
        debug!("BLE listen: macOS inbound not supported, acceptor will idle");
        Ok(BluestAcceptor)
    }

    async fn connect(&self, addr: &BleAddr, psm: u16) -> Result<BluestStream, TransportError> {
        let device = {
            let devices = self.devices.lock().await;
            devices.get(&addr.device).cloned()
        };

        let device = device.ok_or_else(|| {
            TransportError::Io(std::io::Error::other(format!(
                "BLE device not found in cache: {addr}"
            )))
        })?;

        // Ensure the device is connected at GATT level (required by CoreBluetooth
        // before opening an L2CAP channel).
        self.adapter.connect_device(&device).await.map_err(|e| {
            TransportError::Io(std::io::Error::other(format!("BLE connect {addr}: {e}")))
        })?;

        debug!(addr = %addr, psm = psm, "Opening L2CAP channel");

        let channel = device.open_l2cap_channel(psm, false).await.map_err(|e| {
            TransportError::Io(std::io::Error::other(format!(
                "L2CAP open {addr} PSM {psm}: {e}"
            )))
        })?;

        let (reader, writer) = channel.split();

        debug!(addr = %addr, psm = psm, "L2CAP channel open");

        Ok(BluestStream {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
            remote: addr.clone(),
            mtu: self.mtu,
            recv_buf: Mutex::new(Vec::new()),
        })
    }

    async fn start_advertising(&self) -> Result<(), TransportError> {
        // macOS advertising requires GATT PSM service — not yet implemented.
        debug!("BLE advertising: macOS not yet supported (outbound only)");
        Ok(())
    }

    async fn stop_advertising(&self) -> Result<(), TransportError> {
        Ok(())
    }

    async fn start_scanning(&self) -> Result<BluestScanner, TransportError> {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let devices = self.devices.clone();
        let adapter = self.adapter.clone();

        // Spawn a task that owns the adapter clone and drives the scan stream.
        // We must call adapter.scan() inside the task because the returned stream
        // borrows the adapter (lifetime-tied), so it can't cross a spawn boundary.
        tokio::spawn(async move {
            let scan_stream = match adapter.scan(&[FIPS_SERVICE_UUID]).await {
                Ok(s) => s,
                Err(e) => {
                    debug!(error = %e, "BLE scan failed to start");
                    return;
                }
            };

            futures::pin_mut!(scan_stream);
            let mut seen = std::collections::HashSet::new();
            while let Some(discovered) = scan_stream.next().await {
                let device = discovered.device;
                let id = device.id();
                let bytes = device_id_to_bytes(&id);

                // Deduplicate within this scan session
                if !seen.insert(bytes) {
                    continue;
                }

                let name = discovered
                    .adv_data
                    .local_name
                    .as_deref()
                    .unwrap_or("unknown");
                debug!(
                    device_id = %id,
                    name = name,
                    addr = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]),
                    "Discovered FIPS BLE device"
                );

                // Cache the Device for later connect()
                devices.lock().await.insert(bytes, device);

                let addr = BleAddr {
                    adapter: MACOS_ADAPTER_NAME.to_string(),
                    device: bytes,
                };

                if tx.send(addr).await.is_err() {
                    break; // Scanner dropped
                }
            }
            trace!("BLE scan stream ended");
        });

        Ok(BluestScanner { rx })
    }

    fn local_addr(&self) -> Result<BleAddr, TransportError> {
        // CoreBluetooth doesn't expose the local adapter address.
        // Return a synthetic address for API compatibility.
        Ok(BleAddr {
            adapter: MACOS_ADAPTER_NAME.to_string(),
            device: [0, 0, 0, 0, 0, 0],
        })
    }

    fn adapter_name(&self) -> &str {
        MACOS_ADAPTER_NAME
    }
}
