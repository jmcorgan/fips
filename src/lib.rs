//! FIPS: Federated Interoperable Peering System
//!
//! A distributed, decentralized network routing protocol for mesh nodes
//! connecting over arbitrary transports.

pub mod bloom;
pub mod cache;
pub mod config;
pub mod dns;
pub mod icmp;
pub mod identity;
pub mod index;
pub mod noise;
pub mod node;
pub mod peer;
pub mod protocol;
pub mod rate_limit;
pub mod transport;
pub mod tree;
pub mod tun;
pub mod wire;

// Re-export identity types
pub use identity::{
    decode_npub, decode_nsec, decode_secret, encode_npub, encode_nsec, AuthChallenge, AuthResponse,
    FipsAddress, Identity, IdentityError, NodeAddr, PeerIdentity,
};

// Re-export config types
pub use config::{Config, ConfigError, DnsConfig, IdentityConfig, TunConfig, UdpConfig};

// Re-export DNS types
pub use dns::{DnsIdentityRx, DnsIdentityTx, DnsResolvedIdentity};

// Re-export tree types
pub use tree::{CoordEntry, ParentDeclaration, TreeCoordinate, TreeError, TreeState};

// Re-export bloom filter types
pub use bloom::{BloomError, BloomFilter, BloomState};

// Re-export transport types
pub use transport::{
    packet_channel, DiscoveredPeer, Link, LinkDirection, LinkId, LinkState, LinkStats, PacketRx,
    PacketTx, ReceivedPacket, Transport, TransportAddr, TransportError, TransportHandle,
    TransportId, TransportState, TransportType,
};
pub use transport::udp::UdpTransport;

// Re-export protocol types
pub use protocol::{
    CoordsRequired, DataFlags, DataPacket, FilterAnnounce, HandshakeMessageType, LinkMessageType,
    LookupRequest, LookupResponse, PathBroken, ProtocolError, SessionAck, SessionDatagram,
    SessionFlags, SessionMessageType, SessionSetup, TreeAnnounce,
};

// Re-export cache types
pub use cache::{CacheEntry, CacheError, CacheStats, CachedCoords, CoordCache, RouteCache};

// Re-export peer types
pub use peer::{
    cross_connection_winner, ActivePeer, ConnectivityState, HandshakeState, PeerConnection,
    PeerError, PeerSlot, PromotionResult,
};

// Re-export node types
pub use node::{Node, NodeError, NodeState};

