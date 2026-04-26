//! Bootstrap handoff types.
//!
//! These types model the boundary between an external rendezvous/bootstrap
//! runtime and the core FIPS transport/handshake stack. The rendezvous side
//! owns Nostr/STUN/UDP hole punching; once a direct UDP path is established,
//! it hands the live socket and selected remote endpoint to FIPS so the
//! existing Noise/FMP transport path can take over.

#[cfg(feature = "nostr-discovery")]
pub mod nostr;

use crate::config::UdpConfig;
use crate::{NodeAddr, TransportId};
use std::net::{SocketAddr, UdpSocket};

/// Result of handing an established traversal session into FIPS.
#[derive(Debug, Clone)]
pub struct BootstrapHandoffResult {
    /// Newly allocated transport ID used for the adopted UDP socket.
    pub transport_id: TransportId,
    /// Local socket address now owned by the FIPS UDP transport.
    pub local_addr: SocketAddr,
    /// Confirmed remote UDP endpoint selected by traversal.
    pub remote_addr: SocketAddr,
    /// Peer node address derived from the supplied peer identity.
    pub peer_node_addr: NodeAddr,
    /// Nostr session identifier used by the bootstrap runtime.
    pub session_id: String,
}

/// Established UDP traversal ready to be handed into FIPS.
///
/// The socket must already be bound and must be the same socket used for the
/// traversal runtime's STUN and punch traffic so the NAT mapping is preserved.
#[derive(Debug)]
pub struct EstablishedTraversal {
    /// Rendezvous session identifier for logging/correlation.
    pub session_id: String,
    /// Remote peer identity in `npub` form.
    pub peer_npub: String,
    /// The selected remote UDP endpoint to use for the FIPS handshake.
    pub remote_addr: SocketAddr,
    /// The live UDP socket carrying the established mapping.
    pub socket: UdpSocket,
    /// Optional name for the adopted UDP transport.
    pub transport_name: Option<String>,
    /// Optional UDP transport tuning overrides.
    pub transport_config: Option<UdpConfig>,
}

impl EstablishedTraversal {
    /// Construct an established traversal handoff.
    pub fn new(
        session_id: impl Into<String>,
        peer_npub: impl Into<String>,
        remote_addr: SocketAddr,
        socket: UdpSocket,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            peer_npub: peer_npub.into(),
            remote_addr,
            socket,
            transport_name: None,
            transport_config: None,
        }
    }

    /// Attach an explicit transport name to the adopted UDP transport.
    pub fn with_transport_name(mut self, name: impl Into<String>) -> Self {
        self.transport_name = Some(name.into());
        self
    }

    /// Override UDP transport tuning for the adopted socket.
    pub fn with_transport_config(mut self, config: UdpConfig) -> Self {
        self.transport_config = Some(config);
        self
    }
}
