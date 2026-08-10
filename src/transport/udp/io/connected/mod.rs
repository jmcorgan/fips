//! Per-peer connected-UDP fast path.
//!
//! One of the levers boringtun uses to hit 2.5–3.2 Gbps on a real NIC:
//! after a peer is established, give them their **own UDP socket
//! `connect()`-ed to their address**. The kernel then routes inbound
//! packets from that peer directly to the connected socket
//! (most-specific-match wins over the wildcard listen socket under
//! `SO_REUSEPORT`), and lets us `send(2)` with `msg_name = NULL` —
//! skipping the per-packet sockaddr copy + route lookup + neighbor
//! resolve.
//!
//! The whole mechanism lives here, in three pieces that only make sense
//! together:
//!
//! - `fd` — the socket / sockopt / bind / connect syscall sequence that
//!   constructs the fd.
//! - `socket::ConnectedPeerSocket` — the owning handle that adopts it and
//!   closes it on drop.
//! - `drain::PeerRecvDrain` — the recv-side drain thread that must
//!   accompany every connected socket, since the kernel routes the peer's
//!   inbound packets to it and something has to read them.
//!
//! Gated to Linux and macOS: the rest of `io` compiles more broadly
//! (Windows uses `tokio::net::UdpSocket`), but this path is libc-syscall
//! and Darwin-sockopt specific.

mod drain;
mod fd;
mod socket;

pub(crate) use drain::PeerRecvDrain;
pub(crate) use fd::open_connected_fd;
pub(crate) use socket::ConnectedPeerSocket;
