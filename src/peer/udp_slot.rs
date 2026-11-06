//! The driver slot each of a peer's paths carries in this crate: the path's
//! connected UDP socket and its drain on Linux and macOS, and nothing on
//! other targets. The path set holds one per path and never touches it; the
//! peer and the node install, read and clear it.

/// The UDP driver state of one path.
#[derive(Debug, Default)]
pub(crate) struct UdpSlot {
    /// Unix UDP fast-path: per-path `connect()`-ed socket (paired with
    /// the listen socket via `SO_REUSEPORT`). The kernel demux prefers
    /// the connected 5-tuple, so inbound packets land here; the
    /// encrypt-worker send path sends with `msg_name = NULL`, skipping
    /// per-packet sockaddr handling + route lookup. Behind an `Arc` so
    /// in-flight worker jobs survive rekey/address-change rotations.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    connected_udp: Option<std::sync::Arc<crate::transport::udp::ConnectedPeerSocket>>,

    /// Recv drain thread for `connected_udp`. Always paired with it: the
    /// kernel routes inbound packets from this peer to the connected
    /// socket, so it *must* be drained or the kernel recv buffer fills.
    /// Drop signals shutdown via self-pipe.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    peer_recv_drain: Option<crate::transport::udp::PeerRecvDrain>,
}

impl UdpSlot {
    /// The connected UDP socket installed on this path, if any.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) fn connected_udp(
        &self,
    ) -> Option<std::sync::Arc<crate::transport::udp::ConnectedPeerSocket>> {
        self.connected_udp.clone()
    }

    /// Install a connected UDP socket and its drain, replacing any old pair.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) fn set_connected_udp(
        &mut self,
        socket: std::sync::Arc<crate::transport::udp::ConnectedPeerSocket>,
        drain: crate::transport::udp::PeerRecvDrain,
    ) {
        // Drop the old drain BEFORE the old socket so its last fd
        // reference is released cleanly.
        self.clear_connected_udp();
        self.connected_udp = Some(socket);
        self.peer_recv_drain = Some(drain);
    }

    /// Drop the connected socket and its drain. The drain goes first so
    /// its last fd reference is released cleanly; the kernel fd closes on
    /// the last `Arc` drop, so in-flight worker jobs holding the old `Arc`
    /// stay valid until they complete.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn clear_connected_udp(&mut self) {
        self.peer_recv_drain = None;
        self.connected_udp = None;
    }
}
