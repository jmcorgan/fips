//! FIPS: Federated Interoperable Peering System
//!
//! A distributed, decentralized network routing protocol for mesh nodes
//! connecting over arbitrary transports.

pub mod bloom;
pub mod cache;
pub mod config;
pub mod icmp;
pub mod identity;
pub mod node;
pub mod peer;
pub mod protocol;
pub mod transport;
pub mod tree;
pub mod tun;

// Re-export identity types
pub use identity::{
    decode_npub, decode_nsec, decode_secret, encode_npub, encode_nsec, AuthChallenge, AuthResponse,
    FipsAddress, Identity, IdentityError, NodeId, PeerIdentity,
};

// Re-export config types
pub use config::{Config, ConfigError, IdentityConfig, TunConfig};

// Re-export tree types
pub use tree::{ParentDeclaration, TreeCoordinate, TreeError, TreeState};

// Re-export bloom filter types
pub use bloom::{BloomError, BloomFilter, BloomState};

// Re-export transport types
pub use transport::{
    DiscoveredPeer, Link, LinkDirection, LinkId, LinkState, LinkStats, Transport, TransportAddr,
    TransportError, TransportId, TransportState, TransportType,
};

// Re-export protocol types
pub use protocol::{
    Auth, AuthAck, Challenge, CoordsRequired, DataFlags, DataPacket, FilterAnnounce, Hello,
    LookupRequest, LookupResponse, MessageType, PathBroken, ProtocolError, SessionAck,
    SessionFlags, SessionSetup, TreeAnnounce,
};

// Re-export cache types
pub use cache::{CacheEntry, CacheError, CacheStats, CachedCoords, CoordCache, RouteCache};

// Re-export peer types
pub use peer::{Peer, PeerError, PeerState, UpstreamPeer};

// Re-export node types
pub use node::{Node, NodeError, NodeState};

// Re-export TUN types
pub use tun::{log_ipv6_packet, shutdown_tun_interface, TunDevice, TunError, TunState, TunTx, TunWriter};

// Re-export ICMPv6 types
pub use icmp::{build_dest_unreachable, should_send_icmp_error, DestUnreachableCode, Icmpv6Type};
