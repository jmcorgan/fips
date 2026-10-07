//! USB Transport Implementation
//!
//! Carries FIPS between two nodes joined by a USB cable, over an Android Open
//! Accessory (AOA) bulk pipe: one side is the USB host and switches the other
//! into accessory mode, and from then on the two exchange bytes over a pair of
//! bulk endpoints. Which side is which does not matter above the backend —
//! the transport sees a [`UsbLink`]: a reliable, ordered byte stream to
//! exactly one other node.
//!
//! ## Discovery is the cable
//!
//! A link has no address either end could dial. It exists because a cable was
//! plugged in, and it is handed to the transport by whatever noticed: the
//! embedder that opened the accessory, or a host backend that switched a
//! device into accessory mode. [`connect_async`](UsbTransport::connect_async)
//! therefore never dials; it reports a link that is already there.
//!
//! ## Identity
//!
//! The node's Noise IK handshake needs the responder's static key before it
//! can send msg1, and nothing on a cable advertises one. So both ends open a
//! link with a hello carrying their key — the same idea as BLE's pre-handshake
//! pubkey exchange, with a magic and a version so that a stale or foreign
//! byte stream is refused rather than misframed. A completed hello publishes
//! the peer as a [`DiscoveredPeer`] with its key as hint, and the node's
//! ordinary discovery path dials it over the link, or adds the link as a path
//! to a peer it already has a session with.
//!
//! ## Throughput
//!
//! A USB transfer costs a few hundred microseconds whatever its size, so one
//! FMP packet per transfer would cap a link at a few MB/s. Each link's writer
//! coalesces the packets queued behind the first into one transfer of up to
//! [`USB_TRANSFER_MAX`]; the reader recovers packet boundaries from the FMP
//! length prefix, so how the bytes were split on the wire does not matter.

pub mod link;
pub mod stats;

pub use link::{USB_TRANSFER_MAX, UsbAttach, UsbLink, UsbLinkQueue};

use super::framing::{StreamError, read_fmp_packet};
use super::stream::{ConnId, PooledConn, next_conn_id, remove_own};
use super::{
    ConnectionState, DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr,
    TransportError, TransportId, TransportState, TransportType,
};
use crate::config::UsbConfig;
use crate::identity::NodeAddr;
use link::LinkRead;
use stats::UsbStats;

use secp256k1::XOnlyPublicKey;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

/// Magic that opens every link's hello.
const HELLO_MAGIC: [u8; 4] = *b"FUSB";

/// Hello format version.
const HELLO_VERSION: u8 = 1;

/// Hello size: magic, version, x-only public key.
const HELLO_SIZE: usize = HELLO_MAGIC.len() + 1 + 32;

/// How long either half of the hello may take. A peer answers in well under
/// a millisecond; a link that says nothing for this long is not a FIPS node.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// Packets a link's writer may have queued before sends fail fast.
const SEND_QUEUE_DEPTH: usize = 64;

/// One established link in the pool.
struct UsbConnection {
    id: ConnId,
    node_addr: NodeAddr,
    send_tx: mpsc::Sender<Vec<u8>>,
    send_task: JoinHandle<()>,
    recv_task: JoinHandle<()>,
}

impl PooledConn for UsbConnection {
    fn conn_id(&self) -> ConnId {
        self.id
    }
}

impl Drop for UsbConnection {
    fn drop(&mut self) {
        self.send_task.abort();
        self.recv_task.abort();
    }
}

type Pool = Arc<Mutex<HashMap<TransportAddr, UsbConnection>>>;

/// USB transport for FIPS.
pub struct UsbTransport {
    transport_id: TransportId,
    name: Option<String>,
    config: UsbConfig,
    state: TransportState,
    /// Where attached links wait to be taken. Shared with whoever attaches
    /// them, and outlives a stop: links queued while the transport is down
    /// are taken when it starts.
    links: Arc<UsbLinkQueue>,
    pool: Pool,
    packet_tx: PacketTx,
    accept_task: Option<JoinHandle<()>>,
    /// Peers whose hello completed, drained by `discover()`.
    neighbors: Arc<std::sync::Mutex<Vec<DiscoveredPeer>>>,
    stats: Arc<UsbStats>,
    /// Our public key, sent in every hello. A transport without one cannot
    /// identify itself and refuses links.
    local_pubkey: Option<[u8; 32]>,
}

impl UsbTransport {
    /// Create a USB transport that takes its links from `links`.
    pub fn new(
        transport_id: TransportId,
        name: Option<String>,
        config: UsbConfig,
        links: Arc<UsbLinkQueue>,
        packet_tx: PacketTx,
    ) -> Self {
        Self {
            transport_id,
            name,
            config,
            state: TransportState::Configured,
            links,
            pool: Arc::new(Mutex::new(HashMap::new())),
            packet_tx,
            accept_task: None,
            neighbors: Arc::new(std::sync::Mutex::new(Vec::new())),
            stats: Arc::new(UsbStats::new()),
            local_pubkey: None,
        }
    }

    /// Get the instance name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the transport statistics.
    pub fn stats(&self) -> &Arc<UsbStats> {
        &self.stats
    }

    /// Set the key this node identifies itself with in each link's hello.
    /// Must be called before `start_async()`.
    pub fn set_local_pubkey(&mut self, pubkey: [u8; 32]) {
        self.local_pubkey = Some(pubkey);
    }

    /// Start taking links.
    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }
        let Some(local_pubkey) = self.local_pubkey else {
            self.state = TransportState::Failed;
            return Err(TransportError::StartFailed(
                "USB transport has no local key for the link hello".into(),
            ));
        };
        let local_node = XOnlyPublicKey::from_slice(&local_pubkey)
            .map(|key| NodeAddr::from_pubkey(&key))
            .map_err(|e| TransportError::StartFailed(format!("invalid local key: {e}")))?;

        self.accept_task = Some(tokio::spawn(accept_loop(
            LinkContext {
                transport_id: self.transport_id,
                local_pubkey,
                local_node,
                mtu: self.config.mtu(),
                pool: Arc::clone(&self.pool),
                packet_tx: self.packet_tx.clone(),
                neighbors: Arc::clone(&self.neighbors),
                stats: Arc::clone(&self.stats),
            },
            Arc::clone(&self.links),
        )));

        self.state = TransportState::Up;
        info!(name = ?self.name, mtu = self.config.mtu(), "USB transport started");
        Ok(())
    }

    /// Stop the transport and drop every link.
    ///
    /// A dropped link is gone for good: its cable has to be re-attached for
    /// the backend to hand it over again. Links queued and not yet taken
    /// stay queued for the next start.
    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        // Aborting the accept loop drops its in-flight hellos with it.
        if let Some(task) = self.accept_task.take() {
            task.abort();
        }
        self.pool.lock().await.clear();
        self.state = TransportState::Down;
        info!(name = ?self.name, "USB transport stopped");
        Ok(())
    }

    /// Whether a link at `addr` is pooled.
    pub async fn has_connection(&self, addr: &TransportAddr) -> bool {
        self.pool.lock().await.contains_key(addr)
    }

    /// Queue a packet on the link at `addr`. Never waits on the link: a full
    /// queue fails the send, as on BLE.
    pub async fn send_async(
        &self,
        addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        let send_tx = {
            let pool = self.pool.lock().await;
            match pool.get(addr) {
                Some(conn) => conn.send_tx.clone(),
                None => return Err(TransportError::NotConnected),
            }
        };

        let mtu = self.config.mtu();
        if data.len() > mtu as usize {
            self.stats.record_mtu_exceeded();
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu,
            });
        }

        match send_tx.try_send(data.to_vec()) {
            Ok(()) => Ok(data.len()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.stats.record_send_error();
                debug!(addr = %addr, depth = SEND_QUEUE_DEPTH, "USB outbound queue full");
                Err(TransportError::SendFailed(
                    "outbound queue full: peer not draining".into(),
                ))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.stats.record_send_error();
                Err(TransportError::SendFailed("link writer gone".into()))
            }
        }
    }

    /// "Connect" to `addr`: succeeds only if the link is already there.
    ///
    /// A USB link cannot be dialled; it appears when its cable is attached.
    pub async fn connect_async(&self, addr: &TransportAddr) -> Result<(), TransportError> {
        if self.pool.lock().await.contains_key(addr) {
            Ok(())
        } else {
            Err(TransportError::NotConnected)
        }
    }

    /// State of the link at `addr`: connected while pooled, otherwise none.
    pub fn connection_state_sync(&self, addr: &TransportAddr) -> ConnectionState {
        match self.pool.try_lock() {
            Ok(pool) if pool.contains_key(addr) => ConnectionState::Connected,
            _ => ConnectionState::None,
        }
    }

    /// Drop the link at `addr`.
    pub async fn close_connection_async(&self, addr: &TransportAddr) {
        if self.pool.lock().await.remove(addr).is_some() {
            debug!(addr = %addr, "USB link closed");
        }
    }
}

impl Transport for UsbTransport {
    fn role(&self) -> crate::config::TransportRole {
        self.config.role()
    }

    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::USB
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn mtu(&self) -> u16 {
        self.config.mtu()
    }

    fn start(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use start_async() for USB transport".into(),
        ))
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use stop_async() for USB transport".into(),
        ))
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use send_async() for USB transport".into(),
        ))
    }

    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        Ok(std::mem::take(
            &mut *self.neighbors.lock().unwrap_or_else(|e| e.into_inner()),
        ))
    }

    /// Always: a completed hello is the only way a USB peer is ever reached,
    /// so it must be dialled.
    fn auto_connect(&self) -> bool {
        true
    }

    fn accept_connections(&self) -> bool {
        true
    }
}

// ============================================================================
// Background tasks
// ============================================================================

/// What the accept loop and each link's tasks share.
#[derive(Clone)]
struct LinkContext {
    transport_id: TransportId,
    local_pubkey: [u8; 32],
    local_node: NodeAddr,
    mtu: u16,
    pool: Pool,
    packet_tx: PacketTx,
    neighbors: Arc<std::sync::Mutex<Vec<DiscoveredPeer>>>,
    stats: Arc<UsbStats>,
}

/// Take attached links as they arrive and admit each on its own task, so a
/// link whose far end never says hello delays nobody else.
///
/// The admissions live in a `JoinSet` owned by this task, so aborting the
/// loop on stop aborts them too and none can insert into a drained pool.
async fn accept_loop(ctx: LinkContext, links: Arc<UsbLinkQueue>) {
    let mut admitting = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            link = links.next() => {
                ctx.stats.record_link_attached();
                debug!(link = %link.label, "USB link attached");
                admitting.spawn(admit(ctx.clone(), link));
            }
            Some(_) = admitting.join_next(), if !admitting.is_empty() => {}
        }
    }
}

/// Run a link's hello and, if it completes, pool the link and publish the
/// peer for the node to dial.
async fn admit(ctx: LinkContext, link: UsbLink) {
    let UsbLink { label, rx, tx } = link;
    let ta = TransportAddr::from_string(&label);
    // One reader across the hello and the receive loop, so bytes the peer
    // sent right behind its hello are kept.
    let mut reader = LinkRead::new(rx);

    let peer_key = match hello(&tx, &mut reader, &ctx.local_pubkey).await {
        Ok(key) => key,
        Err(e) => {
            ctx.stats.record_hello_failure();
            debug!(link = %label, error = %e, "USB link hello failed, dropping link");
            return;
        }
    };
    let peer_node = NodeAddr::from_pubkey(&peer_key);
    if peer_node == ctx.local_node {
        ctx.stats.record_hello_failure();
        warn!(link = %label, "USB link answered with our own key, dropping link");
        return;
    }

    let id = next_conn_id();
    {
        let mut pool = ctx.pool.lock().await;
        // One link per peer. A second one to the same node is almost always
        // a replug whose old link has not noticed yet, so the newcomer wins;
        // a label in use is likewise a link that has been replaced.
        let stale: Vec<TransportAddr> = pool
            .iter()
            .filter(|(addr, conn)| conn.node_addr == peer_node || **addr == ta)
            .map(|(addr, _)| addr.clone())
            .collect();
        for addr in stale {
            pool.remove(&addr);
            ctx.stats.record_link_replaced();
            debug!(link = %label, replaced = %addr, "USB link replaces an older link to the same peer");
        }

        let (send_tx, send_rx) = mpsc::channel(SEND_QUEUE_DEPTH);
        let send_task = tokio::spawn(send_loop(
            tx,
            send_rx,
            ta.clone(),
            id,
            Arc::clone(&ctx.pool),
            Arc::clone(&ctx.stats),
        ));
        let recv_task = tokio::spawn(receive_loop(reader, ta.clone(), id, ctx.clone()));
        pool.insert(
            ta.clone(),
            UsbConnection {
                id,
                node_addr: peer_node,
                send_tx,
                send_task,
                recv_task,
            },
        );
    }

    ctx.stats.record_link_established();
    info!(link = %label, peer = %peer_node, "USB link established");
    let mut neighbors = ctx.neighbors.lock().unwrap_or_else(|e| e.into_inner());
    neighbors.retain(|p| p.addr != ta);
    neighbors.push(DiscoveredPeer::with_hint(ctx.transport_id, ta, peer_key));
}

/// Exchange hellos: send ours, read theirs, and return the key it carries.
async fn hello(
    tx: &mpsc::Sender<Vec<u8>>,
    reader: &mut LinkRead,
    local_pubkey: &[u8; 32],
) -> Result<XOnlyPublicKey, TransportError> {
    let mut ours = Vec::with_capacity(HELLO_SIZE);
    ours.extend_from_slice(&HELLO_MAGIC);
    ours.push(HELLO_VERSION);
    ours.extend_from_slice(local_pubkey);
    match tokio::time::timeout(HELLO_TIMEOUT, tx.send(ours)).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => return Err(TransportError::SendFailed("link closed".into())),
        Err(_) => return Err(TransportError::Timeout),
    }

    let mut theirs = [0u8; HELLO_SIZE];
    match tokio::time::timeout(HELLO_TIMEOUT, reader.read_exact(&mut theirs)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(TransportError::RecvFailed(format!("hello: {e}"))),
        Err(_) => return Err(TransportError::Timeout),
    }
    if theirs[..4] != HELLO_MAGIC {
        return Err(TransportError::RecvFailed("hello: bad magic".into()));
    }
    if theirs[4] != HELLO_VERSION {
        return Err(TransportError::RecvFailed(format!(
            "hello: unsupported version {}",
            theirs[4]
        )));
    }
    XOnlyPublicKey::from_slice(&theirs[5..])
        .map_err(|e| TransportError::RecvFailed(format!("hello: invalid key: {e}")))
}

/// A link's writer: the only place its bytes are put on the wire.
///
/// Takes the first queued packet and every packet queued behind it that still
/// fits, and writes them as one transfer of at most [`USB_TRANSFER_MAX`]. A
/// packet that would overflow the transfer starts the next one.
async fn send_loop(
    link_tx: mpsc::Sender<Vec<u8>>,
    mut frames: mpsc::Receiver<Vec<u8>>,
    addr: TransportAddr,
    id: ConnId,
    pool: Pool,
    stats: Arc<UsbStats>,
) {
    let mut carried: Option<Vec<u8>> = None;
    loop {
        let mut batch = match carried.take() {
            Some(frame) => frame,
            None => match frames.recv().await {
                Some(frame) => frame,
                None => return,
            },
        };
        let mut packets = 1;
        while let Ok(next) = frames.try_recv() {
            if batch.len() + next.len() > USB_TRANSFER_MAX {
                carried = Some(next);
                break;
            }
            batch.extend_from_slice(&next);
            packets += 1;
        }

        let bytes = batch.len();
        if link_tx.send(batch).await.is_err() {
            stats.record_send_error();
            debug!(addr = %addr, "USB link writer gone, removing link");
            remove_own(&mut *pool.lock().await, &addr, id);
            return;
        }
        stats.record_send(packets, bytes);
    }
}

/// A link's reader: pulls whole FMP packets out of the byte stream and hands
/// them to the node. Ends, and removes its own link, when the link closes or
/// carries something that is not FMP.
async fn receive_loop(mut reader: LinkRead, addr: TransportAddr, id: ConnId, ctx: LinkContext) {
    loop {
        match read_fmp_packet(&mut reader, ctx.mtu).await {
            Ok(data) => {
                ctx.stats.record_recv(data.len());
                let packet = ReceivedPacket::new(ctx.transport_id, addr.clone(), data);
                if ctx.packet_tx.send(packet).await.is_err() {
                    trace!("USB packet_tx closed, stopping receive loop");
                    break;
                }
            }
            Err(StreamError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                info!(addr = %addr, "USB link closed");
                break;
            }
            Err(e) => {
                ctx.stats.record_recv_error();
                debug!(addr = %addr, error = %e, "USB receive error, dropping link");
                break;
            }
        }
    }
    remove_own(&mut *ctx.pool.lock().await, &addr, id);
}

#[cfg(test)]
mod tests;
