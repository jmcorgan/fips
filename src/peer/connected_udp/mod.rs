//! Per-peer connected-UDP fast-path handles.
//!
//! The connected-socket rationale and the fd-construction syscall
//! sequence live in `crate::transport::udp::open_connected_fd`. This
//! module owns the runtime handle types that adopt the resulting fd:
//!
//! - [`socket::ConnectedPeerSocket`] — the owning fd wrapper.
//! - [`drain::PeerRecvDrain`] — the recv-side drain thread that must
//!   accompany every connected socket (the kernel routes the peer's
//!   inbound packets to it, so it has to be drained).

pub(crate) mod drain;
pub(crate) mod socket;

pub(crate) use drain::PeerRecvDrain;
pub(crate) use socket::ConnectedPeerSocket;
