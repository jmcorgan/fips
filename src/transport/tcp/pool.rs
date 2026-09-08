//! TCP connection pool types.
//!
//! Holds the per-connection state and the pooled/connecting maps used by the
//! TCP transport.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
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
    /// MSS-derived MTU for this connection (used for dynamic MTU re-reading).
    #[allow(dead_code)]
    pub(crate) mtu: u16,
    /// When the connection was established.
    #[allow(dead_code)]
    pub(crate) established_at: Instant,
    /// Direction of the connection — drives pool-inbound/outbound accounting.
    pub(crate) direction: Direction,
}

/// Shared connection pool.
pub(crate) type ConnectionPool = Arc<Mutex<HashMap<TransportAddr, TcpConnection>>>;

/// A pending background connection attempt.
///
/// Holds the JoinHandle for a spawned TCP connect task. The task
/// produces a configured `TcpStream` and MSS-derived MTU on success.
pub(crate) struct ConnectingEntry {
    /// Background task performing TCP connect + socket configuration.
    pub(crate) task: JoinHandle<Result<(TcpStream, u16), TransportError>>,
}

/// Map of addresses with background connection attempts in progress.
pub(crate) type ConnectingPool = Arc<Mutex<HashMap<TransportAddr, ConnectingEntry>>>;
