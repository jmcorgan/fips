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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc::UnboundedSender;

use super::{
    DiscoveredPeer, ReceivedPacket, Transport, TransportAddr, TransportError, TransportId,
    TransportState, TransportType,
};

/// Shared registry mapping each loopback address to the transport listening
/// on it: that transport's id and the channel sender of the node it belongs
/// to.
///
/// One registry instance is shared by all loopback transports in a given
/// test run so they can locate each other by address. A delivered packet
/// carries the receiving transport's id from here, as a packet a real
/// transport reads carries the id of the transport that read it.
pub type LoopbackRegistry =
    Arc<Mutex<HashMap<TransportAddr, (TransportId, UnboundedSender<ReceivedPacket>)>>>;

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
    /// The type the transport reports, `LOOPBACK` unless a test set
    /// another, to stand in for that transport's class, kind and
    /// connection orientation.
    ty: TransportType,
    /// Whether the transport accepts inbound handshakes, as a test set.
    accepts: AtomicBool,
    /// Every `close_connection` the node asked for, in order. Loopback is
    /// connectionless, so the close itself does nothing; the record lets a
    /// test say whether a connection a connection-oriented transport would
    /// hold was kept or closed.
    closed: Mutex<Vec<TransportAddr>>,
    /// Links a test has ended as though their far end went (a cable
    /// pulled), until the node takes them with `take_closed_links`.
    ended: Mutex<Vec<TransportAddr>>,
    /// Carrier a test has set, standing in for an interface-bound
    /// transport's `IFF_RUNNING`. `None`, the default: not bound to an
    /// interface, so no presence is reported.
    carrier: Mutex<Option<bool>>,
    /// While set, every send fails with [`TransportError::NotConnected`], as
    /// a connection-oriented transport's does once its connection is gone.
    unconnected: AtomicBool,
    /// While set, every send fails with [`TransportError::Unreachable`], as
    /// one over an interface that is down does.
    unreachable: AtomicBool,
    /// Beacons a test queued, handed out by the next `discover()`.
    discovered: Mutex<Vec<DiscoveredPeer>>,
    /// Whether the node dials the peers `discover()` hands out, as a test
    /// set; off by default, as on Ethernet and BLE.
    autoconnect: AtomicBool,
    /// The part the transport plays in a link's paths, standing in for a
    /// configured `role`; `normal` unless a test set another.
    role: crate::config::TransportRole,
    /// The instance name the transport reports, standing in for a
    /// configured instance's name; none unless a test set one.
    name: Option<String>,
    /// The medium the transport reports, standing in for the one an
    /// interface-bound transport reads from its interface; unknown unless
    /// a test set one.
    medium: fips_core::proto::path::Medium,
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
            ty: TransportType::LOOPBACK,
            accepts: AtomicBool::new(true),
            closed: Mutex::new(Vec::new()),
            ended: Mutex::new(Vec::new()),
            carrier: Mutex::new(None),
            unconnected: AtomicBool::new(false),
            unreachable: AtomicBool::new(false),
            discovered: Mutex::new(Vec::new()),
            autoconnect: AtomicBool::new(false),
            role: crate::config::TransportRole::Normal,
            name: None,
            medium: fips_core::proto::path::Medium::Unknown,
        }
    }

    /// Report `ty` as this transport's type from now on.
    pub fn typed(&mut self, ty: TransportType) {
        self.ty = ty;
    }

    /// Play `role` in a link's paths from now on, as a transport configured
    /// with that `role` does.
    pub fn set_role(&mut self, role: crate::config::TransportRole) {
        self.role = role;
    }

    /// Report `medium` from now on, as an interface-bound transport does
    /// once it has read its interface's medium.
    pub fn set_medium(&mut self, medium: fips_core::proto::path::Medium) {
        self.medium = medium;
    }

    /// The medium a test set, `Unknown` by default.
    pub fn medium(&self) -> fips_core::proto::path::Medium {
        self.medium
    }

    /// Report `name` as this transport's instance name from now on, as a
    /// transport configured under that name does.
    pub fn set_name(&mut self, name: &str) {
        self.name = Some(name.to_string());
    }

    /// The instance name a test gave this transport, if any.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The part this transport plays in a link's paths.
    pub fn role(&self) -> crate::config::TransportRole {
        self.role
    }

    /// Report this transport bound to an interface with carrier (`Some(true)`)
    /// or without it (`Some(false)`); `None` returns it to reporting no
    /// presence at all.
    pub fn set_carrier(&self, carrier: Option<bool>) {
        *self.carrier.lock().unwrap() = carrier;
    }

    /// The carrier a test set, if any.
    pub fn carrier(&self) -> Option<bool> {
        *self.carrier.lock().unwrap()
    }

    /// Make every send fail as one with no connection to its address does
    /// (`true`), or stop doing so.
    pub fn set_unconnected(&self, unconnected: bool) {
        self.unconnected.store(unconnected, Ordering::Relaxed);
    }

    /// Make every send fail as one to an unreachable address does (`true`),
    /// or stop doing so.
    pub fn set_unreachable(&self, unreachable: bool) {
        self.unreachable.store(unreachable, Ordering::Relaxed);
    }

    /// Accept inbound handshakes (`true`, the default) or refuse them.
    pub fn set_accepts(&self, accepts: bool) {
        self.accepts.store(accepts, Ordering::Relaxed);
    }

    /// Queue a beacon for the next `discover()` drain, as if this transport
    /// had heard `addr` announce `pubkey_hint`.
    pub fn inject_discovered(&self, addr: TransportAddr, pubkey_hint: secp256k1::XOnlyPublicKey) {
        let mut peer = DiscoveredPeer::new(self.transport_id, addr);
        peer.pubkey_hint = Some(pubkey_hint);
        self.discovered
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(peer);
    }

    /// Have the node dial the peers this transport discovers (`true`), as a
    /// transport configured with `auto_connect` does, or not (the default).
    pub fn set_autoconnect(&self, on: bool) {
        self.autoconnect.store(on, Ordering::Relaxed);
    }

    /// Record a `close_connection` call for `addr`.
    pub fn record_close(&self, addr: &TransportAddr) {
        self.closed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(addr.clone());
    }

    /// End the link to `addr` as though its far end went, as a USB
    /// transport reports a pulled cable: the node's next read of closed links
    /// takes it.
    pub fn end_link(&self, addr: &TransportAddr) {
        self.ended
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(addr.clone());
    }

    /// The links ended since the last call.
    pub fn take_closed_links(&self) -> Vec<TransportAddr> {
        std::mem::take(&mut *self.ended.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// The addresses the node has asked to close on this transport, in
    /// order.
    pub fn closed(&self) -> Vec<TransportAddr> {
        self.closed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
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
    /// learn the peer source. Its `transport_id` is the one registered for
    /// `dest_addr`, the receiving transport's, so a node with two transports
    /// sees which one a packet came in on.
    pub async fn send_async(
        &self,
        dest_addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        if self.unconnected.load(Ordering::Relaxed) {
            return Err(TransportError::NotConnected);
        }
        if self.unreachable.load(Ordering::Relaxed) {
            return Err(TransportError::Unreachable(
                "Network is unreachable (os error 101)".into(),
            ));
        }
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
            Some((receiver, tx)) => {
                let packet = ReceivedPacket::new(receiver, self.my_addr.clone(), data.to_vec());
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
        &self.ty
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
        Ok(std::mem::take(
            &mut *self.discovered.lock().unwrap_or_else(|e| e.into_inner()),
        ))
    }

    fn auto_connect(&self) -> bool {
        self.autoconnect.load(Ordering::Relaxed)
    }

    fn accept_connections(&self) -> bool {
        self.accepts.load(Ordering::Relaxed)
    }
}
