//! FIPS: Free Internetworking Peering System
//!
//! A distributed, decentralized network routing protocol for mesh nodes
//! connecting over arbitrary transports.

pub mod bloom;
pub mod cache;
pub mod config;
pub mod control;
#[cfg(feature = "gateway")]
pub mod gateway;
pub mod identity;
pub mod mmp;
pub mod node;
pub mod noise;
pub mod peer;
pub mod protocol;
pub mod transport;
pub mod tree;
pub mod upper;
pub mod utils;
pub mod version;

// Re-export identity types
pub use identity::{
    AuthChallenge, AuthResponse, FipsAddress, Identity, IdentityError, NodeAddr, PeerIdentity,
    decode_npub, decode_nsec, decode_secret, encode_npub, encode_nsec,
};

// Re-export config types
pub use config::{Config, ConfigError, IdentityConfig, TorConfig, UdpConfig};
pub use upper::config::{DnsConfig, TunConfig};

// Re-export tree types
pub use tree::{CoordEntry, ParentDeclaration, TreeCoordinate, TreeError, TreeState};

// Re-export bloom filter types
pub use bloom::{BloomError, BloomFilter, BloomState};

// Re-export transport types
pub use transport::udp::UdpTransport;
pub use transport::{
    DiscoveredPeer, Link, LinkDirection, LinkId, LinkState, LinkStats, PacketRx, PacketTx,
    ReceivedPacket, Transport, TransportAddr, TransportError, TransportHandle, TransportId,
    TransportState, TransportType, packet_channel,
};

// Re-export protocol types
pub use protocol::{
    CoordsRequired, FilterAnnounce, HandshakeMessageType, LinkMessageType, LookupRequest,
    LookupResponse, PathBroken, ProtocolError, SessionAck, SessionDatagram, SessionFlags,
    SessionMessageType, SessionSetup, TreeAnnounce,
};

// Re-export cache types
pub use cache::{CacheEntry, CacheError, CacheStats, CoordCache};

// Re-export peer types
pub use peer::{
    ActivePeer, ConnectivityState, HandshakeState, PeerConnection, PeerError, PeerSlot,
    PromotionResult, cross_connection_winner,
};

// Re-export node types
pub use node::{Node, NodeError, NodeState};
