//! TCP connection pool types.
//!
//! Holds the per-connection state and the pooled/connecting maps used by the
//! TCP transport.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::transport::stream::{ConnId, PooledConn};
use crate::transport::{TransportAddr, TransportError};

/// Direction of a pooled connection, used to drive separate
/// `pool_inbound` / `pool_outbound` accounting for the
/// `max_inbound_connections` admission cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Direction {
    /// Inbound — accepted by the listener.
    Inbound,
    /// Outbound — initiated by connect-on-send or background connect.
    Outbound,
}

/// How many frames may be queued for one connection before sends to it start
/// failing.
///
/// The queue exists so the caller never awaits the wire; the bound exists so a
/// peer that has stopped draining cannot turn that into unbounded memory. Deep
/// enough to absorb a burst — a heartbeat sweep plus the forwarding this node
/// does for one peer — and shallow enough that a stranded peer is recognised
/// within a tick or two rather than after megabytes have piled up behind it.
pub(crate) const SEND_QUEUE_DEPTH: usize = 64;

/// State for a single TCP connection to a peer.
pub(crate) struct TcpConnection {
    /// Frames queued for the writer task. Sending is an enqueue, never a
    /// write: the write half belongs to `send_task` and nothing else can
    /// block on it. A full queue is a peer that has stopped draining, and the
    /// send fails rather than waiting.
    pub(crate) send_tx: mpsc::Sender<Vec<u8>>,
    /// Writer task for this connection. Owns the write half of the split
    /// stream, so the only code that can ever await `write_all` is this task.
    pub(crate) send_task: JoinHandle<()>,
    /// Receive task for this connection.
    pub(crate) recv_task: JoinHandle<()>,
    /// The smaller of `TCP_MAXSEG` and the configured `mtu` at connection
    /// setup on Linux, the configured `mtu` elsewhere. Logged as a diagnostic
    /// only; it bounds nothing.
    #[allow(dead_code)]
    pub(crate) mtu: u16,
    /// When the connection was established. Read by `key_for_remote` to pick
    /// the newest of several inbound entries sharing a peer address.
    pub(crate) established_at: Instant,
    /// Direction of the connection — drives pool-inbound/outbound accounting.
    pub(crate) direction: Direction,
    /// Identity of this connection, shared with its writer and receive loop.
    /// Either loop removes the entry at its address only when the entry
    /// carries this id, so a loop that outlives its connection cannot remove
    /// a newer connection at the same address.
    pub(crate) id: ConnId,
}

impl PooledConn for TcpConnection {
    fn conn_id(&self) -> ConnId {
        self.id
    }
}

/// Key identifying one pooled connection.
///
/// The kernel names a TCP connection by its four-tuple, so a listener on a
/// wildcard address can accept two connections whose peer `ip:port` is the
/// same on two different local addresses. An inbound entry therefore carries
/// the accepted socket's local address as well, and two such connections get
/// two entries rather than displacing each other.
///
/// Outbound entries carry no local address. Nothing distinguishes two
/// outbound connections to one peer, since the transport keeps at most one,
/// and leaving the local address out keeps the connect-on-send lookup a
/// single hash probe.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PoolKey {
    /// Remote address, as the peer is named by callers and packets.
    pub(crate) remote: TransportAddr,
    /// Local address of an accepted socket; `None` for outbound.
    pub(crate) local: Option<SocketAddr>,
}

impl PoolKey {
    /// Key for a connection this node opened.
    pub(crate) fn outbound(remote: TransportAddr) -> Self {
        Self {
            remote,
            local: None,
        }
    }

    /// Key for a connection the listener accepted on `local`.
    pub(crate) fn inbound(remote: TransportAddr, local: SocketAddr) -> Self {
        Self {
            remote,
            local: Some(local),
        }
    }
}

/// The pooled connections, keyed by [`PoolKey`].
pub(crate) type PoolMap = HashMap<PoolKey, TcpConnection>;

/// Shared connection pool.
pub(crate) type ConnectionPool = Arc<Mutex<PoolMap>>;

/// Resolve a bare remote address to the key of the connection to use for it.
///
/// Callers that send, close or query by peer address know only the remote, so
/// the four-tuple has to be recovered. An outbound entry is tried first, so the
/// common case is one hash probe. Inbound entries also carry a local address,
/// so they are found by scanning for the remote and taking the most recently
/// established, which is the connection a peer that reconnected is using.
pub(crate) fn key_for_remote(pool: &PoolMap, remote: &TransportAddr) -> Option<PoolKey> {
    let outbound = PoolKey::outbound(remote.clone());
    if pool.contains_key(&outbound) {
        return Some(outbound);
    }
    pool.iter()
        .filter(|(key, _)| &key.remote == remote)
        .max_by_key(|(_, conn)| conn.established_at)
        .map(|(key, _)| key.clone())
}

/// A pending background connection attempt.
///
/// Holds the JoinHandle for a spawned TCP connect task. The task
/// produces a configured `TcpStream` and MSS-derived MTU on success.
pub(crate) struct ConnectingEntry {
    /// Background task performing TCP connect + socket configuration.
    pub(crate) task: JoinHandle<Result<(TcpStream, u16), TransportError>>,
}

impl AsMut<JoinHandle<Result<(TcpStream, u16), TransportError>>> for ConnectingEntry {
    /// The background connect task.
    fn as_mut(&mut self) -> &mut JoinHandle<Result<(TcpStream, u16), TransportError>> {
        &mut self.task
    }
}

/// Map of addresses with background connection attempts in progress.
pub(crate) type ConnectingPool = Arc<Mutex<HashMap<TransportAddr, ConnectingEntry>>>;
