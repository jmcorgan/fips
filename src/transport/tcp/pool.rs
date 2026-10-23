//! TCP connection pool types.
//!
//! Holds the per-connection state and the pooled/connecting maps used by the
//! TCP transport.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;

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

/// State for a single TCP connection to a peer.
pub(crate) struct TcpConnection {
    /// Write half of the split stream.
    pub(crate) writer: Arc<Mutex<OwnedWriteHalf>>,
    /// Receive task for this connection.
    pub(crate) recv_task: JoinHandle<()>,
    /// The smaller of `TCP_MAXSEG` and the configured `mtu` at connection
    /// setup on Linux, the configured `mtu` elsewhere. Logged as a diagnostic
    /// only; it bounds nothing.
    #[allow(dead_code)]
    pub(crate) mtu: u16,
    /// When the connection was established.
    pub(crate) established_at: Instant,
    /// Direction of the connection — drives pool-inbound/outbound accounting.
    pub(crate) direction: Direction,
}

/// Key identifying one pooled connection.
///
/// The kernel demultiplexes TCP by the connection four-tuple, so a remote
/// `ip:port` does not name a connection on its own: two accepted sockets
/// can carry the same peer address when they arrive on different local
/// addresses of a wildcard listener. Inbound entries therefore carry the
/// accepted socket's local address as well, and two such connections get
/// two entries instead of one overwriting the other.
///
/// Outbound entries carry no local address. Nothing distinguishes two
/// outbound connections to one peer — the transport makes at most one —
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
    /// Key for a connection this node initiated.
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

/// Resolve a remote address to the key of the connection that a caller
/// naming only that address should use.
///
/// An outbound connection is keyed by the remote address alone, so the
/// common case is one hash probe. Inbound entries also carry a local
/// address, and are searched; where several share a remote address the
/// most recently established one wins, which is the entry an
/// address-keyed pool held before inbound keys became four-tuples.
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
