//! FIPS: Federated Interoperable Peering System
//!
//! A distributed, decentralized network routing protocol for mesh nodes
//! connecting over arbitrary transports.

pub mod bloom;
pub mod cache;
pub mod config;
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
    FipsAddress, Identity, IdentityError, NodeId, PeerIdentity,
};

// Re-export config types
pub use config::{Config, ConfigError, IdentityConfig, TunConfig, UdpConfig};

// Re-export tree types
pub use tree::{ParentDeclaration, TreeCoordinate, TreeError, TreeState};

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

// Re-export TUN types
pub use tun::{log_ipv6_packet, shutdown_tun_interface, TunDevice, TunError, TunState, TunTx, TunWriter};

// Re-export ICMPv6 types
pub use icmp::{build_dest_unreachable, should_send_icmp_error, DestUnreachableCode, Icmpv6Type};

// Re-export Noise types (HandshakeState not re-exported to avoid conflict with peer::HandshakeState)
pub use noise::{CipherState, HandshakeRole, NoiseError, NoiseSession};

// Re-export index types
pub use index::{IndexAllocator, IndexError, SessionIndex};

// Re-export rate limiting types
pub use rate_limit::{HandshakeRateLimiter, TokenBucket};

// Re-export wire format types
pub use wire::{
    build_encrypted, build_msg1, build_msg2, EncryptedHeader, Msg1Header, Msg2Header,
    DISCRIMINATOR_ENCRYPTED, DISCRIMINATOR_MSG1, DISCRIMINATOR_MSG2, ENCRYPTED_MIN_SIZE,
    ENCRYPTED_OVERHEAD, MSG1_WIRE_SIZE, MSG2_WIRE_SIZE,
};
