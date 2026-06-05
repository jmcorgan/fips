//! In-process loopback transport (test harness only).
//!
//! Delivers packets directly between nodes running in the same process via
//! an unbounded in-process channel and a shared address-to-receiver
//! registry, instead of going over real localhost UDP sockets. This is used
//! by node-level multi-node tests to avoid the kernel UDP receive-buffer
//! overflow that drops handshake packets when many tests run in parallel
//! under CPU contention.
//!
//! An UNBOUNDED channel is used deliberately: the test harness drains
//! packets sequentially (it fires the whole handshake burst before draining,
//! with no background reader), so a bounded awaiting send would deadlock and
//! a bounded try_send would drop. `UnboundedSender::send` is synchronous,
//! never blocks, and never drops — it only errors if the receiver is gone —
//! making delivery provably lossless and deadlock-free.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc::UnboundedSender;

use super::{
    DiscoveredPeer, ReceivedPacket, Transport, TransportAddr, TransportError, TransportId,
    TransportState, TransportType,
};

/// Shared registry mapping each loopback address to the receiver-side
/// channel sender for the node listening on that address.
///
/// One registry instance is shared by all loopback transports in a given
/// test run so they can locate each other by address.
pub type LoopbackRegistry = Arc<Mutex<HashMap<TransportAddr, UnboundedSender<ReceivedPacket>>>>;

/// Create a fresh, empty loopback registry.
pub fn new_registry() -> LoopbackRegistry {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Default loopback MTU, mirroring the UDP test path.
const DEFAULT_LOOPBACK_MTU: u16 = 1280;

/// In-process loopback transport.
pub struct LoopbackTransport {
    transport_id: TransportId,
    /// This transport's synthetic unique address (e.g. "loopback:7").
    my_addr: TransportAddr,
    /// Transport MTU. Enforced on send to mirror UDP's MtuExceeded behavior,
    /// so PMTUD/heterogeneous-MTU tests still exercise the forward-path
    /// bottleneck detection.
    mtu: u16,
    /// Shared address-to-receiver registry.
    registry: LoopbackRegistry,
}

impl LoopbackTransport {
    /// Create a new loopback transport bound to `my_addr` with the default
    /// MTU, sharing `registry`.
    pub fn new(
        transport_id: TransportId,
        my_addr: TransportAddr,
        registry: LoopbackRegistry,
    ) -> Self {
        Self::with_mtu(transport_id, my_addr, DEFAULT_LOOPBACK_MTU, registry)
    }

    /// Create a new loopback transport with an explicit MTU.
    pub fn with_mtu(
        transport_id: TransportId,
        my_addr: TransportAddr,
        mtu: u16,
        registry: LoopbackRegistry,
    ) -> Self {
        Self {
            transport_id,
            my_addr,
            mtu,
            registry,
        }
    }

    /// This transport's synthetic loopback address.
    pub fn my_addr(&self) -> &TransportAddr {
        &self.my_addr
    }

    /// Send data to a destination loopback address.
    ///
    /// Looks up `dest_addr` in the shared registry and, if found, delivers a
    /// `ReceivedPacket` to its receiver. The packet's `remote_addr` is set to
    /// the sender's own address (`my_addr`), mirroring how UDP sets
    /// `remote_addr` from the datagram source, so the receiver's handlers
    /// learn the peer source.
    pub async fn send_async(
        &self,
        dest_addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        if data.len() > self.mtu as usize {
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu: self.mtu,
            });
        }

        let dest_tx = {
            let registry = self.registry.lock().map_err(|e| {
                TransportError::SendFailed(format!("registry lock poisoned: {}", e))
            })?;
            registry.get(dest_addr).cloned()
        };

        match dest_tx {
            Some(tx) => {
                let packet =
                    ReceivedPacket::new(self.transport_id, self.my_addr.clone(), data.to_vec());
                tx.send(packet).map_err(|_| {
                    TransportError::SendFailed(format!("loopback receiver gone for {}", dest_addr))
                })?;
                Ok(data.len())
            }
            None => Err(TransportError::SendFailed(format!(
                "no loopback route to {}",
                dest_addr
            ))),
        }
    }

    /// Asynchronous start (no-op; the transport is ready on construction).
    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        Ok(())
    }

    /// Asynchronous stop (no-op).
    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

impl Transport for LoopbackTransport {
    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::LOOPBACK
    }

    fn state(&self) -> TransportState {
        TransportState::Up
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn start(&mut self) -> Result<(), TransportError> {
        Ok(())
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        Ok(())
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        // Synchronous send not supported — use send_async().
        Err(TransportError::NotSupported(
            "use send_async() for loopback transport".into(),
        ))
    }

    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        Ok(Vec::new())
    }
}
