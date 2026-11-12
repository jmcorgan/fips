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

use crate::transport::framing::{RECV_CEILING, read_fmp_packet};
use crate::transport::tcp::InboundDeadline;
use crate::transport::{
    ConnectionState, PacketTx, ReceivedPacket, TransportAddr, TransportError, TransportId,
    take_finished_connect,
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

impl AsMut<JoinHandle<Result<(TcpStream, u16), TransportError>>> for ConnectingEntry {
    /// The background connect task.
    fn as_mut(&mut self) -> &mut JoinHandle<Result<(TcpStream, u16), TransportError>> {
        &mut self.task
    }
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

/// The writer for an established connection to `addr`, promoting a
/// background connect that has finished since it was started.
///
/// `promote` builds the pool entry for a finished connect and does the
/// transport's own accounting; it runs with the pool lock held, so the
/// connection cannot be inserted twice. A finished connect that failed is
/// dropped, so the next `connect_async` starts a new attempt. Never dials.
pub(crate) async fn existing_writer<M>(
    pool: &ProxiedPool<M>,
    connecting: &ConnectingPool,
    addr: &TransportAddr,
    promote: impl FnOnce(TcpStream, u16) -> ProxiedConnection<M>,
) -> Option<Arc<Mutex<OwnedWriteHalf>>> {
    let mut pool = pool.lock().await;
    if let Some(conn) = pool.get(addr) {
        return Some(conn.writer.clone());
    }
    let finished = take_finished_connect(&mut *connecting.lock().await, addr)?;
    match finished {
        Ok((stream, mtu)) => {
            let conn = promote(stream, mtu);
            let writer = conn.writer.clone();
            pool.insert(addr.clone(), conn);
            Some(writer)
        }
        Err(e) => {
            debug!(
                remote_addr = %addr,
                error = %e,
                "Background SOCKS5 connect failed, nothing to send on"
            );
            None
        }
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
/// Every frame is read up to `RECV_CEILING`, whatever the local `mtu`, as
/// the TCP receive loop reads: nothing tells a sender its peer's `mtu`, so a
/// peer configured higher sends frames above it, and bounding receives by
/// the local value would drop the connection on the first of them.
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
///
/// `deadline` bounds the wait for every complete frame: the first-frame
/// deadline until one arrives, the idle deadline for each one after. It is
/// `Some` for a connection that takes a capped inbound slot from accept
/// — today only tor's onion listener — and `None` everywhere else, which
/// covers every outbound connection and the whole of the nym transport (nym
/// is outbound-only and keeps no counted slots). A deadline expiry is not a
/// receive error and is deliberately not recorded as one.
///
/// `ready_rx`, when present, is the accept loop's readiness barrier: the loop
/// must not run its cleanup before the accept loop has inserted the pool entry
/// and bumped its counter, or the removal finds nothing, `on_remove` never
/// fires, and the increment is stranded for the life of the process.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn proxied_receive_loop<S: ProxiedStats, M>(
    mut reader: OwnedReadHalf,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    packet_tx: PacketTx,
    pool: ProxiedPool<M>,
    stats: Arc<S>,
    label: &'static str,
    deadline: Option<InboundDeadline>,
    ready_rx: Option<tokio::sync::oneshot::Receiver<()>>,
    on_remove: impl Fn(&S, &M),
) {
    debug!(
        transport_id = %transport_id,
        remote_addr = %remote_addr,
        "{} receive loop starting",
        label
    );

    // An `Err` here means the accept loop went away between the insert and
    // the signal. Fall through to the cleanup below rather than returning,
    // so a pooled entry cannot be stranded with the counter incremented.
    let admitted = match ready_rx {
        Some(rx) => rx.await.is_ok(),
        None => true,
    };

    if admitted {
        let mut first = true;
        loop {
            let read = match deadline {
                // Bound every read. A remote that goes silent, before or after
                // its first frame, otherwise holds its inbound slot for as long
                // as it keeps the socket open.
                Some(d) => {
                    let limit = d.for_read(first);
                    match tokio::time::timeout(limit, read_fmp_packet(&mut reader, RECV_CEILING))
                        .await
                    {
                        Ok(result) => result,
                        Err(_) => {
                            // Not a recv error: `record_recv_error` means framing
                            // or I/O failure, and folding deadline expiries into
                            // it corrupts that counter.
                            debug!(
                                transport_id = %transport_id,
                                remote_addr = %remote_addr,
                                deadline = InboundDeadline::phase(first),
                                timeout_secs = limit.as_secs_f64(),
                                "No complete frame within the inbound deadline, dropping inbound {} connection",
                                label
                            );
                            break;
                        }
                    }
                }
                None => read_fmp_packet(&mut reader, RECV_CEILING).await,
            };
            first = false;

            match read {
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
