//! Shared connection pool for the proxied (Tor / Nym) transports.
//!
//! Both transports keep the same two maps — an established-connection pool and
//! a pending-connection ("connecting") pool — and poll a completed background
//! connect the same way. The only per-transport difference is the metadata
//! carried on each pooled connection (`Direction` for tor's inbound/outbound
//! pool accounting, `()` for nym), captured by the generic `M` type parameter.

use std::collections::HashMap;
use std::sync::Arc;

use futures::FutureExt;
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, trace};

use crate::transport::framing::read_fmp_packet;
use crate::transport::{
    ConnectionState, PacketTx, ReceivedPacket, TransportAddr, TransportError, TransportId,
};

/// State for a single pooled connection to a peer.
///
/// `M` is per-transport metadata: `Direction` for tor (drives
/// inbound/outbound pool accounting), `()` for nym.
pub(crate) struct ProxiedConnection<M> {
    /// Write half of the split stream.
    pub writer: Arc<Mutex<OwnedWriteHalf>>,
    /// Receive task for this connection.
    pub recv_task: JoinHandle<()>,
    /// MTU for this connection.
    #[allow(dead_code)]
    pub mtu: u16,
    /// When the connection was established.
    #[allow(dead_code)]
    pub established_at: Instant,
    /// Per-transport metadata (tor: `Direction`; nym: `()`).
    pub meta: M,
}

/// Shared connection pool: addr -> per-connection state.
pub(crate) type ProxiedPool<M> = Arc<Mutex<HashMap<TransportAddr, ProxiedConnection<M>>>>;

/// A pending background connection attempt.
///
/// Holds the JoinHandle for a spawned SOCKS5 connect task. The task
/// produces a configured `TcpStream` and MTU on success.
pub(crate) struct ConnectingEntry {
    /// Background task performing SOCKS5 connect + socket configuration.
    pub task: JoinHandle<Result<(TcpStream, u16), TransportError>>,
}

/// Map of addresses with background connection attempts in progress.
pub(crate) type ConnectingPool = Arc<Mutex<HashMap<TransportAddr, ConnectingEntry>>>;

/// Poll the state of a connection to a remote address.
///
/// Checks both established and connecting pools. If a background connect task
/// has completed successfully, invokes `promote` (which spawns a receive loop
/// and inserts into the established pool) and reports `Connected`; on failure
/// reports it. Synchronous — uses `try_lock` internally and returns
/// `ConnectionState::Connecting` if a lock can't be acquired.
///
/// This is the byte-for-byte former `connection_state_sync` body, with the
/// per-transport `promote_connection` call abstracted behind `promote`.
pub(crate) fn poll_connecting<M>(
    pool: &ProxiedPool<M>,
    connecting: &ConnectingPool,
    addr: &TransportAddr,
    promote: impl FnOnce(TcpStream, u16),
) -> ConnectionState {
    // Check established pool first
    if let Ok(pool) = pool.try_lock() {
        if pool.contains_key(addr) {
            return ConnectionState::Connected;
        }
    } else {
        return ConnectionState::Connecting; // can't tell, assume still going
    }

    // Check connecting pool
    let mut connecting = match connecting.try_lock() {
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
    let addr_clone = addr.clone();
    let task = connecting.remove(&addr_clone).unwrap().task;

    // Since the task is finished, we can safely poll it with now_or_never.
    match task.now_or_never() {
        Some(Ok(Ok((stream, mtu)))) => {
            promote(stream, mtu);
            ConnectionState::Connected
        }
        Some(Ok(Err(e))) => ConnectionState::Failed(format!("{}", e)),
        Some(Err(e)) => ConnectionState::Failed(format!("task failed: {}", e)),
        None => ConnectionState::Connecting,
    }
}

/// Minimal stats surface the shared receive loop needs.
///
/// The per-transport stats structs implement this by delegating to their
/// shared counter base; the loop records received bytes and receive errors
/// without knowing the concrete transport.
pub(crate) trait ProxiedStats: Send + Sync + 'static {
    /// Record a successful receive of `bytes` bytes.
    fn record_recv(&self, bytes: usize);
    /// Record a receive error.
    fn record_recv_error(&self);
}

/// Shared per-connection receive loop for the proxied transports.
///
/// Reads complete FMP packets, delivers them to the node, and on error/EOF
/// removes the connection from the pool and runs `on_remove` for any
/// per-transport teardown accounting. The `label` is the in-loop log word
/// ("Nym" / "Tor").
///
/// Teardown/cleanup contract (reproduced exactly to stay behavior-neutral):
/// the pool entry is removed, and `on_remove` fires **only** when the removal
/// returned `Some`, taking the metadata from the removed entry, and after the
/// pool guard is dropped. Firing on `Some` only means a concurrent
/// `close`/`stop` teardown of the same address can never double-count.
///
/// The terminal "receive loop stopped" log is **not** emitted here — it is
/// hoisted into each per-transport wrapper (tor carries a `direction` field
/// nym lacks), so this loop is silent on exit.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn proxied_receive_loop<S: ProxiedStats, M>(
    mut reader: OwnedReadHalf,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    packet_tx: PacketTx,
    pool: ProxiedPool<M>,
    mtu: u16,
    stats: Arc<S>,
    label: &'static str,
    on_remove: impl Fn(&S, &M),
) {
    debug!(
        transport_id = %transport_id,
        remote_addr = %remote_addr,
        "{} receive loop starting",
        label
    );

    loop {
        match read_fmp_packet(&mut reader, mtu).await {
            Ok(data) => {
                stats.record_recv(data.len());

                trace!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    bytes = data.len(),
                    "{} packet received",
                    label
                );

                let packet = ReceivedPacket::new(transport_id, remote_addr.clone(), data);

                if packet_tx.send(packet).await.is_err() {
                    debug!(
                        transport_id = %transport_id,
                        "Packet channel closed, stopping {} receive loop",
                        label
                    );
                    break;
                }
            }
            Err(e) => {
                stats.record_recv_error();
                debug!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    error = %e,
                    "{} receive error, removing connection",
                    label
                );
                break;
            }
        }
    }

    // Clean up: remove ourselves from the pool, then run per-transport
    // teardown accounting. The teardown fires only when this loop actually
    // removed the entry, using the metadata from the removed entry, so a
    // concurrent close/stop teardown of the same address can never
    // double-count.
    let mut pool_guard = pool.lock().await;
    if let Some(removed) = pool_guard.remove(&remote_addr) {
        drop(pool_guard);
        on_remove(&*stats, &removed.meta);
    }
}
