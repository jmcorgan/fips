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
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, trace};

use tokio::io::AsyncWriteExt;

use crate::transport::framing::{RECV_CEILING, read_fmp_packet};
use crate::transport::stream::{ConnId, PooledConn, remove_own};
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
    /// Frames queued for the writer task. Sending is an enqueue, never a
    /// write: the write half belongs to `send_task`, so no caller can block on
    /// the wire. A full queue is a peer that has stopped draining.
    pub send_tx: mpsc::Sender<Vec<u8>>,
    /// Writer task for this connection.
    pub send_task: JoinHandle<()>,
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
    /// Identity of this connection, shared with its writer and receive loop.
    /// Either loop removes the entry at its address only when the entry
    /// carries this id, so a loop that outlives its connection cannot remove
    /// a newer connection at the same address.
    pub id: ConnId,
}

impl<M> PooledConn for ProxiedConnection<M> {
    fn conn_id(&self) -> ConnId {
        self.id
    }
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

/// The writer queue for an established connection to `addr`, promoting a
/// background connect that has finished since it was started.
///
/// `promote` builds the pool entry for a finished connect and does the
/// transport's own accounting; it runs with the pool lock held, so the
/// connection cannot be inserted twice. A finished connect that failed is
/// dropped, so the next `connect_async` starts a new attempt. Never dials.
pub(crate) async fn existing_sender<M>(
    pool: &ProxiedPool<M>,
    connecting: &ConnectingPool,
    addr: &TransportAddr,
    promote: impl FnOnce(TcpStream, u16) -> ProxiedConnection<M>,
) -> Option<mpsc::Sender<Vec<u8>>> {
    let mut pool = pool.lock().await;
    if let Some(conn) = pool.get(addr) {
        return Some(conn.send_tx.clone());
    }
    let finished = take_finished_connect(&mut *connecting.lock().await, addr)?;
    match finished {
        Ok((stream, mtu)) => {
            let conn = promote(stream, mtu);
            let send_tx = conn.send_tx.clone();
            pool.insert(addr.clone(), conn);
            Some(send_tx)
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

/// Whether `pool` holds a connection to `addr`: the lookup
/// [`existing_sender`] makes before it would promote a finished background
/// connect. Reads only; the pool lock is awaited rather than tried.
pub(crate) async fn is_pooled<M>(pool: &ProxiedPool<M>, addr: &TransportAddr) -> bool {
    pool.lock().await.contains_key(addr)
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
    /// Record `bytes` actually written to the wire.
    fn record_send(&self, bytes: usize);
    /// Record a send error.
    fn record_send_error(&self);
}

/// How many frames may be queued for one connection before sends to it fail.
/// See `crate::transport::tcp::pool::SEND_QUEUE_DEPTH`, which this mirrors.
pub(crate) const SEND_QUEUE_DEPTH: usize = 64;

/// Per-connection writer task: the only place a write to a proxied stream is
/// ever awaited.
///
/// The reasoning is the TCP transport's, and the shape is deliberately the
/// same. `write_all` blocks once the local socket to the proxy stops draining,
/// and the callers are the rx loop's tick handlers, where that holds every
/// other arm of the select. The loop owns the write half, so nothing else can
/// block on it.
///
/// Teardown mirrors [`proxied_receive_loop`]: the pool entry is removed and
/// `on_remove` fires only when the removal returned `Some`, taking the
/// metadata from the removed entry, so a concurrent `close`/`stop` of the same
/// address cannot double-count. The entry is removed only when it carries
/// this connection's `id`. A writer can outlive its entry, and by the time its
/// write fails a newer connection may hold the address; that one is left
/// alone.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn proxied_send_loop<S: ProxiedStats, M>(
    mut writer: OwnedWriteHalf,
    mut frames: mpsc::Receiver<Vec<u8>>,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    id: ConnId,
    pool: ProxiedPool<M>,
    stats: Arc<S>,
    label: &'static str,
    on_remove: impl Fn(&S, &M) + Send + 'static,
) {
    while let Some(frame) = frames.recv().await {
        match writer.write_all(&frame).await {
            Ok(()) => {
                stats.record_send(frame.len());
                trace!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    bytes = frame.len(),
                    "{} packet sent",
                    label
                );
            }
            Err(e) => {
                stats.record_send_error();
                debug!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    error = %e,
                    "{} write failed; dropping connection",
                    label
                );
                let removed = {
                    let mut guard = pool.lock().await;
                    remove_own(&mut guard, &remote_addr, id)
                };
                if let Some(conn) = removed {
                    conn.recv_task.abort();
                    on_remove(&stats, &conn.meta);
                }
                return;
            }
        }
    }
    trace!(
        transport_id = %transport_id,
        remote_addr = %remote_addr,
        "{} writer task exiting",
        label
    );
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
///
/// `id` is the connection's identity. The cleanup removes the entry at
/// `remote_addr` only when it carries this id, so a loop whose entry has
/// already been replaced by a newer connection at the same address leaves
/// that connection alone. When it does remove its own entry it also stops the
/// entry's writer: the loop ended on EOF, a read error or a missed deadline,
/// and frames still queued for a connection in that state are not worth
/// writing.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn proxied_receive_loop<S: ProxiedStats, M>(
    mut reader: OwnedReadHalf,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    id: ConnId,
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
    if let Some(removed) = remove_own(&mut pool_guard, &remote_addr, id) {
        drop(pool_guard);
        removed.send_task.abort();
        on_remove(&*stats, &removed.meta);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::wait_until;
    use crate::transport::packet_channel;
    use crate::transport::stream::{next_conn_id, park_writer};
    use portable_atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    /// Counters the shared loops write, plus how often `on_remove` fired.
    #[derive(Default)]
    struct CountingStats {
        send_errors: AtomicU64,
        recv_errors: AtomicU64,
        removed: AtomicU64,
    }

    impl ProxiedStats for CountingStats {
        fn record_recv(&self, _bytes: usize) {}
        fn record_recv_error(&self) {
            self.recv_errors.fetch_add(1, Ordering::Relaxed);
        }
        fn record_send(&self, _bytes: usize) {}
        fn record_send_error(&self) {
            self.send_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The `on_remove` hook the tests pass to both loops.
    fn count_removal(stats: &CountingStats, _meta: &()) {
        stats.removed.fetch_add(1, Ordering::Relaxed);
    }

    /// A pool entry that stands for some other connection at the same
    /// address, marked by its MTU.
    fn successor() -> ProxiedConnection<()> {
        ProxiedConnection {
            send_tx: mpsc::channel(1).0,
            send_task: tokio::spawn(async {}),
            recv_task: tokio::spawn(async {}),
            mtu: 1234,
            established_at: Instant::now(),
            meta: (),
            id: next_conn_id(),
        }
    }

    /// A writer whose write fails must not remove a newer connection that has
    /// taken its address in the pool, nor run `on_remove` for it.
    #[tokio::test]
    async fn proxied_writer_error_leaves_a_newer_connection_at_the_same_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = listener.local_addr().unwrap();
        let client = TcpStream::connect(listen).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        socket2::SockRef::from(&server)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        drop(server);
        let (_read_half, write_half) = client.into_split();
        let remote = TransportAddr::from_string(&listen.to_string());

        let pool: ProxiedPool<()> = Arc::new(Mutex::new(HashMap::new()));
        let stats = Arc::new(CountingStats::default());
        pool.lock().await.insert(remote.clone(), successor());

        let (send_tx, send_rx) = mpsc::channel(SEND_QUEUE_DEPTH);
        let writer = tokio::spawn(proxied_send_loop(
            write_half,
            send_rx,
            TransportId::new(1),
            remote.clone(),
            next_conn_id(),
            pool.clone(),
            stats.clone(),
            "Test",
            count_removal,
        ));

        let frame = vec![0xAB; 114];
        let deadline = Instant::now() + Duration::from_secs(5);
        while !writer.is_finished() && Instant::now() < deadline {
            let _ = send_tx.try_send(frame.clone());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(writer.is_finished(), "the writer never hit a write error");
        assert_eq!(
            stats.send_errors.load(Ordering::Relaxed),
            1,
            "the writer's error path must have run"
        );

        assert_eq!(
            pool.lock().await.get(&remote).map(|c| c.mtu),
            Some(1234),
            "a failed writer removed the newer connection at its address"
        );
        assert_eq!(stats.removed.load(Ordering::Relaxed), 0);
    }

    /// A receive loop that ends on EOF must stop its writer rather than leave
    /// it writing to a peer that has gone.
    ///
    /// The writer is parked on a peer that does not read, with a full queue.
    /// The peer then half-closes, which ends the receive loop, and only
    /// afterwards reads. A writer left running delivers every frame it had
    /// queued; a stopped one delivers fewer.
    #[tokio::test]
    async fn proxied_receive_teardown_stops_the_writer() {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(64 * 1024).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = socket.listen(8).unwrap();
        let listen = listener.local_addr().unwrap();

        let client = TcpStream::connect(listen).await.unwrap();
        socket2::SockRef::from(&client)
            .set_send_buffer_size(64 * 1024)
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        let remote = TransportAddr::from_string(&listen.to_string());
        let (read_half, write_half) = client.into_split();

        let (packet_tx, _packet_rx) = packet_channel(10);
        let pool: ProxiedPool<()> = Arc::new(Mutex::new(HashMap::new()));
        let stats = Arc::new(CountingStats::default());
        let (send_tx, send_rx) = mpsc::channel(SEND_QUEUE_DEPTH);
        let id = next_conn_id();
        let send_task = tokio::spawn(proxied_send_loop(
            write_half,
            send_rx,
            TransportId::new(1),
            remote.clone(),
            id,
            pool.clone(),
            stats.clone(),
            "Test",
            count_removal,
        ));
        let recv_task = tokio::spawn({
            let pool = pool.clone();
            let stats = stats.clone();
            let remote = remote.clone();
            async move {
                proxied_receive_loop(
                    read_half,
                    TransportId::new(1),
                    remote,
                    id,
                    packet_tx,
                    pool,
                    stats,
                    "Test",
                    None,
                    None,
                    count_removal,
                )
                .await;
            }
        });
        pool.lock().await.insert(
            remote.clone(),
            ProxiedConnection {
                send_tx,
                send_task,
                recv_task,
                mtu: 1400,
                established_at: Instant::now(),
                meta: (),
                id,
            },
        );

        // Never keep a sender past the fill: the teardown below relies on the
        // pool entry holding the only one.
        let frame = vec![0xAB; 1400];
        let queued = park_writer(
            async || {
                pool.lock()
                    .await
                    .get(&remote)
                    .is_some_and(|c| c.send_tx.try_send(frame.clone()).is_ok())
            },
            async || pool.lock().await.get(&remote).map(|c| c.send_tx.capacity()),
        )
        .await;

        peer.shutdown().await.unwrap();
        assert!(
            wait_until(
                || stats.removed.load(Ordering::Relaxed) == 1,
                Duration::from_secs(5)
            )
            .await,
            "the receive loop should have torn the connection down on EOF"
        );

        let mut buf = vec![0u8; 64 * 1024];
        let read = timeout(Duration::from_secs(10), async {
            let mut total = 0usize;
            loop {
                match peer.read(&mut buf).await {
                    Ok(0) | Err(_) => return total,
                    Ok(n) => total += n,
                }
            }
        })
        .await
        .expect("the connection was never closed toward the peer");
        assert!(read > 0, "the kernel buffers held written frames");
        assert!(
            read < queued * frame.len(),
            "the writer kept writing after its receive loop tore the connection down: \
             read={read} queued_bytes={}",
            queued * frame.len()
        );
    }

    /// A receive loop's teardown must leave alone a newer entry at its address,
    /// and must not run `on_remove` for it.
    #[tokio::test]
    async fn proxied_receive_teardown_leaves_a_newer_connection_at_the_same_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = listener.local_addr().unwrap();
        let client = TcpStream::connect(listen).await.unwrap();
        let (server, peer_addr) = listener.accept().await.unwrap();
        let remote = TransportAddr::from_string(&peer_addr.to_string());
        let (read_half, _write_half) = server.into_split();

        let (packet_tx, _packet_rx) = packet_channel(10);
        let pool: ProxiedPool<()> = Arc::new(Mutex::new(HashMap::new()));
        let stats = Arc::new(CountingStats::default());
        pool.lock().await.insert(remote.clone(), successor());

        drop(client);
        proxied_receive_loop(
            read_half,
            TransportId::new(1),
            remote.clone(),
            next_conn_id(),
            packet_tx,
            pool.clone(),
            stats.clone(),
            "Test",
            None,
            None,
            count_removal,
        )
        .await;
        assert_eq!(
            stats.recv_errors.load(Ordering::Relaxed),
            1,
            "the loop should have ended on EOF"
        );

        assert_eq!(
            pool.lock().await.get(&remote).map(|c| c.mtu),
            Some(1234),
            "the teardown removed a newer connection at its address"
        );
        assert_eq!(
            stats.removed.load(Ordering::Relaxed),
            0,
            "the teardown ran on_remove for a connection it did not remove"
        );
    }
}
