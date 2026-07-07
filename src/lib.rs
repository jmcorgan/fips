//! FIPS: Free Internetworking Peering System
//!
//! A distributed, decentralized network routing protocol for mesh nodes
//! connecting over arbitrary transports.

// Name the `alloc` crate directly so the sans-IO protocol cores can spell their
// heap-type imports in `no_std`-forward form (`alloc::sync::Arc`,
// `alloc::collections::BTreeMap`). The crate remains `std`; this only reduces the
// distance to extracting the pure cores into a `no_std` crate later.
extern crate alloc;

pub mod cache;
pub mod config;
pub mod control;
pub mod discovery;
#[cfg(target_os = "linux")]
pub mod gateway;
pub mod identity;
pub mod mmp;
pub mod node;
pub mod noise;
pub mod peer;
pub mod perf_profile;
pub(crate) mod proto;
pub mod protocol;
#[cfg(test)]
pub(crate) mod testutil;
pub mod transport;
pub mod upper;
pub mod utils;
pub mod version;

// Re-export identity types
pub use identity::{
    AuthChallenge, AuthResponse, FipsAddress, Identity, IdentityError, NodeAddr, PeerIdentity,
    decode_npub, decode_nsec, decode_secret, encode_npub, encode_nsec,
};

// Re-export config types
pub use config::{Config, ConfigError, IdentityConfig, NymConfig, TorConfig, UdpConfig};
pub use upper::config::{DnsConfig, TunConfig};

// Re-export discovery types
pub use discovery::{BootstrapHandoffResult, EstablishedTraversal};

// Re-export tree types (relocated from tree:: to proto::stp)
pub use proto::stp::{CoordEntry, ParentDeclaration, TreeCoordinate, TreeError, TreeState};

// Re-export bloom filter types (relocated from bloom:: to proto::bloom)
pub use proto::bloom::{BloomError, BloomFilter, BloomState};

// Re-export transport types
pub use transport::udp::UdpTransport;
pub use transport::{
    DiscoveredPeer, Link, LinkDirection, LinkId, LinkState, LinkStats, PacketRx, PacketTx,
    ReceivedPacket, Transport, TransportAddr, TransportError, TransportHandle, TransportId,
    TransportState, TransportType, packet_channel,
};

// Re-export protocol types
pub use protocol::{
    LinkMessageType, ProtocolError, SessionAck, SessionDatagram, SessionFlags, SessionMessageType,
    SessionSetup,
};

// Re-export STP wire types (relocated from protocol:: to proto::stp)
pub use proto::stp::TreeAnnounce;

// Re-export bloom wire types (relocated from protocol:: to proto::bloom)
pub use proto::bloom::FilterAnnounce;

// Re-export discovery wire types (relocated from protocol:: to proto::discovery)
pub use proto::discovery::{LookupRequest, LookupResponse};

// Re-export routing wire types (relocated from protocol:: to proto::routing)
pub use proto::routing::{
    COORDS_REQUIRED_SIZE, CoordsRequired, MTU_EXCEEDED_SIZE, MtuExceeded, PathBroken,
};

// Re-export FMP link-framing wire type (relocated from protocol:: to proto::fmp)
pub use proto::fmp::HandshakeMessageType;

// Re-export FMP negotiation wire types (relocated from protocol:: to proto::fmp)
pub use proto::fmp::{NegotiationPayload, NodeProfile, TlvEntry};

// Re-export cache types
pub use cache::{CacheEntry, CacheError, CacheStats, CoordCache};

// Re-export FMP tie-break helper (relocated from peer:: to proto::fmp)
pub use proto::fmp::cross_connection_winner;

// Re-export peer types
pub use peer::{
    ActivePeer, ConnectivityState, HandshakeState, PeerConnection, PeerError, PeerSlot,
    PromotionResult,
};

// Re-export node types
pub use node::{Node, NodeError, NodeState, UpdatePeersOutcome};
