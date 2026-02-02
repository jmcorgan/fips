//! FIPS Protocol Messages
//!
//! Wire format definitions for FIPS protocol communication across two layers:
//!
//! ## Link Layer (peer-to-peer, hop-by-hop)
//!
//! Messages exchanged between directly connected peers over Noise-encrypted
//! links. Includes spanning tree gossip, bloom filter propagation, discovery
//! protocol, and forwarding of session-layer datagrams.
//!
//! Link-layer peer authentication uses Noise IK (see `noise.rs`), which
//! establishes the encrypted channel before any of these messages are sent.
//!
//! ## Session Layer (end-to-end, between FIPS addresses)
//!
//! Messages exchanged between source and destination FIPS nodes, encrypted
//! with session keys that intermediate nodes cannot read. Includes session
//! establishment, IPv6 datagram encapsulation, and routing errors.
//!
//! Session-layer datagrams are carried as opaque payloads through the link
//! layer, encrypted end-to-end independently of per-hop link encryption.

use crate::bloom::BloomFilter;
use crate::tree::{ParentDeclaration, TreeCoordinate};
use crate::{FipsAddress, NodeId};
use secp256k1::schnorr::Signature;
use std::fmt;
use thiserror::Error;

/// Protocol version for message compatibility.
pub const PROTOCOL_VERSION: u8 = 1;

/// Data packet header size in bytes (excluding payload).
pub const DATA_HEADER_SIZE: usize = 36;

// ============================================================================
// Link Layer Message Types (peer-to-peer, hop-by-hop)
// ============================================================================

/// Handshake message type identifiers.
///
/// These messages are exchanged during Noise IK handshake before link
/// encryption is established. They use the same TLV framing as link
/// messages but payloads are not encrypted (except Noise-internal encryption).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeMessageType {
    /// Noise IK message 1: initiator sends ephemeral + encrypted static.
    /// Payload: 82 bytes (33 ephemeral + 33 static + 16 tag).
    NoiseIKMsg1 = 0x01,

    /// Noise IK message 2: responder sends ephemeral.
    /// Payload: 33 bytes (ephemeral pubkey only).
    NoiseIKMsg2 = 0x02,
}

impl HandshakeMessageType {
    /// Try to convert from a byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(HandshakeMessageType::NoiseIKMsg1),
            0x02 => Some(HandshakeMessageType::NoiseIKMsg2),
            _ => None,
        }
    }

    /// Convert to a byte.
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Check if a byte represents a handshake message type.
    pub fn is_handshake(b: u8) -> bool {
        matches!(b, 0x01 | 0x02)
    }
}

impl fmt::Display for HandshakeMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            HandshakeMessageType::NoiseIKMsg1 => "NoiseIKMsg1",
            HandshakeMessageType::NoiseIKMsg2 => "NoiseIKMsg2",
        };
        write!(f, "{}", name)
    }
}

// ============================================================================
// Link-Layer Message Types
// ============================================================================

/// Link-layer message type identifiers.
///
/// These messages are exchanged between directly connected peers over
/// Noise-encrypted links. All payloads are encrypted with session keys
/// established during the Noise IK handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkMessageType {
    // Tree protocol (0x10-0x1F)
    /// Spanning tree state announcement.
    TreeAnnounce = 0x10,

    // Bloom filter (0x20-0x2F)
    /// Bloom filter reachability update.
    FilterAnnounce = 0x20,

    // Discovery (0x30-0x3F)
    /// Request to discover a node's coordinates.
    LookupRequest = 0x30,
    /// Response with target's coordinates.
    LookupResponse = 0x31,

    // Forwarding (0x40-0x4F)
    /// Encapsulated session-layer datagram for forwarding.
    /// Payload is opaque to intermediate nodes (end-to-end encrypted).
    SessionDatagram = 0x40,
}

impl LinkMessageType {
    /// Try to convert from a byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x10 => Some(LinkMessageType::TreeAnnounce),
            0x20 => Some(LinkMessageType::FilterAnnounce),
            0x30 => Some(LinkMessageType::LookupRequest),
            0x31 => Some(LinkMessageType::LookupResponse),
            0x40 => Some(LinkMessageType::SessionDatagram),
            _ => None,
        }
    }

    /// Convert to a byte.
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for LinkMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            LinkMessageType::TreeAnnounce => "TreeAnnounce",
            LinkMessageType::FilterAnnounce => "FilterAnnounce",
            LinkMessageType::LookupRequest => "LookupRequest",
            LinkMessageType::LookupResponse => "LookupResponse",
            LinkMessageType::SessionDatagram => "SessionDatagram",
        };
        write!(f, "{}", name)
    }
}

// ============================================================================
// Session Layer Message Types (end-to-end, between FIPS addresses)
// ============================================================================

/// Session-layer message type identifiers.
///
/// These messages are exchanged end-to-end between FIPS nodes, encrypted
/// with session keys that intermediate nodes cannot read. They are carried
/// as payloads inside `LinkMessageType::SessionDatagram`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionMessageType {
    // Session establishment (0x00-0x0F)
    /// Session setup with coordinates (warms router caches).
    SessionSetup = 0x00,
    /// Session acknowledgement.
    SessionAck = 0x01,

    // Data (0x10-0x1F)
    /// Encrypted IPv6 datagram payload.
    DataPacket = 0x10,

    // Errors (0x20-0x2F)
    /// Router cache miss - needs coordinates.
    CoordsRequired = 0x20,
    /// Routing failure (local minimum or unreachable).
    PathBroken = 0x21,
}

impl SessionMessageType {
    /// Try to convert from a byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(SessionMessageType::SessionSetup),
            0x01 => Some(SessionMessageType::SessionAck),
            0x10 => Some(SessionMessageType::DataPacket),
            0x20 => Some(SessionMessageType::CoordsRequired),
            0x21 => Some(SessionMessageType::PathBroken),
            _ => None,
        }
    }

    /// Convert to a byte.
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for SessionMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            SessionMessageType::SessionSetup => "SessionSetup",
            SessionMessageType::SessionAck => "SessionAck",
            SessionMessageType::DataPacket => "DataPacket",
            SessionMessageType::CoordsRequired => "CoordsRequired",
            SessionMessageType::PathBroken => "PathBroken",
        };
        write!(f, "{}", name)
    }
}

// Legacy type alias for compatibility during transition
#[deprecated(note = "Use LinkMessageType or SessionMessageType instead")]
pub type MessageType = LinkMessageType;

/// Errors related to protocol message handling.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid message type: 0x{0:02x}")]
    InvalidMessageType(u8),

    #[error("message too short: expected at least {expected}, got {got}")]
    MessageTooShort { expected: usize, got: usize },

    #[error("message too long: max {max}, got {got}")]
    MessageTooLong { max: usize, got: usize },

    #[error("invalid signature")]
    InvalidSignature,

    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("malformed message: {0}")]
    Malformed(String),

    #[error("hop limit exceeded")]
    HopLimitExceeded,

    #[error("ttl expired")]
    TtlExpired,
}

// ============================================================================
// Link Layer Messages
// ============================================================================

// ============ Tree Protocol Messages ============

/// Spanning tree announcement carrying parent declaration and ancestry.
///
/// Sent to peers to propagate tree state. The declaration proves the
/// sender's parent selection; the ancestry provides path to root for
/// routing decisions.
#[derive(Clone, Debug)]
pub struct TreeAnnounce {
    /// The sender's parent declaration.
    pub declaration: ParentDeclaration,
    /// Full ancestry from sender to root.
    pub ancestry: TreeCoordinate,
}

impl TreeAnnounce {
    /// Create a new TreeAnnounce message.
    pub fn new(declaration: ParentDeclaration, ancestry: TreeCoordinate) -> Self {
        Self {
            declaration,
            ancestry,
        }
    }
}

// ============ Bloom Filter Messages ============

/// Bloom filter announcement for reachability propagation.
///
/// Sent to peers to advertise which destinations are reachable.
/// The TTL controls propagation depth (decremented at each hop).
///
/// ## Wire Format (v1)
///
/// | Offset | Field       | Size     | Notes                           |
/// |--------|-------------|----------|----------------------------------|
/// | 0      | msg_type    | 1 byte   | 0x20                            |
/// | 1      | sequence    | 8 bytes  | LE u64                          |
/// | 9      | ttl         | 1 byte   | Remaining hops                  |
/// | 10     | hash_count  | 1 byte   | Number of hash functions        |
/// | 11     | size_class  | 1 byte   | Filter size: 512 << size_class  |
/// | 12     | filter_bits | variable | 512 << size_class bytes         |
#[derive(Clone, Debug)]
pub struct FilterAnnounce {
    /// The bloom filter contents.
    pub filter: BloomFilter,
    /// Remaining propagation hops (decremented at each forward).
    pub ttl: u8,
    /// Sequence number for freshness/dedup.
    pub sequence: u64,
    /// Number of hash functions used by the filter.
    pub hash_count: u8,
    /// Size class: filter size in bytes = 512 << size_class.
    /// v1 protocol requires size_class=1 (1 KB filters).
    pub size_class: u8,
}

impl FilterAnnounce {
    /// Create a new FilterAnnounce message with v1 defaults.
    pub fn new(filter: BloomFilter, ttl: u8, sequence: u64) -> Self {
        Self {
            hash_count: filter.hash_count(),
            size_class: crate::bloom::V1_SIZE_CLASS,
            filter,
            ttl,
            sequence,
        }
    }

    /// Create with explicit size_class (for testing or future protocol versions).
    pub fn with_size_class(
        filter: BloomFilter,
        ttl: u8,
        sequence: u64,
        size_class: u8,
    ) -> Self {
        Self {
            hash_count: filter.hash_count(),
            size_class,
            filter,
            ttl,
            sequence,
        }
    }

    /// Check if this filter can be forwarded (TTL > 0).
    pub fn can_forward(&self) -> bool {
        self.ttl > 0
    }

    /// Create a forwarded version with decremented TTL.
    pub fn forwarded(&self) -> Option<Self> {
        if self.ttl == 0 {
            return None;
        }
        Some(Self {
            filter: self.filter.clone(),
            ttl: self.ttl - 1,
            sequence: self.sequence,
            hash_count: self.hash_count,
            size_class: self.size_class,
        })
    }

    /// Get the expected filter size in bytes for this size_class.
    pub fn filter_size_bytes(&self) -> usize {
        512 << self.size_class
    }

    /// Validate the filter matches the declared size_class.
    pub fn is_valid(&self) -> bool {
        self.filter.num_bytes() == self.filter_size_bytes()
            && self.filter.hash_count() == self.hash_count
    }

    /// Check if this is a v1-compliant filter (size_class=1).
    pub fn is_v1_compliant(&self) -> bool {
        self.size_class == crate::bloom::V1_SIZE_CLASS
    }
}

// ============ Discovery Messages ============

/// Request to discover a node's coordinates.
///
/// Flooded through the network with TTL limiting scope. The visited
/// filter prevents routing loops.
#[derive(Clone, Debug)]
pub struct LookupRequest {
    /// Unique request identifier.
    pub request_id: u64,
    /// Node we're looking for.
    pub target: NodeId,
    /// Who's asking (for response routing).
    pub origin: NodeId,
    /// Origin's coordinates (for return path).
    pub origin_coords: TreeCoordinate,
    /// Remaining propagation hops.
    pub ttl: u8,
    /// Visited nodes filter (loop prevention).
    pub visited: BloomFilter,
}

impl LookupRequest {
    /// Create a new lookup request.
    pub fn new(
        request_id: u64,
        target: NodeId,
        origin: NodeId,
        origin_coords: TreeCoordinate,
        ttl: u8,
    ) -> Self {
        // Small filter for visited tracking
        let visited = BloomFilter::with_params(256 * 8, 5).expect("valid params");
        Self {
            request_id,
            target,
            origin,
            origin_coords,
            ttl,
            visited,
        }
    }

    /// Generate a new request with a random ID.
    pub fn generate(
        target: NodeId,
        origin: NodeId,
        origin_coords: TreeCoordinate,
        ttl: u8,
    ) -> Self {
        use rand::Rng;
        let request_id = rand::thread_rng().r#gen();
        Self::new(request_id, target, origin, origin_coords, ttl)
    }

    /// Decrement TTL and add self to visited.
    ///
    /// Returns false if TTL was already 0.
    pub fn forward(&mut self, my_node_id: &NodeId) -> bool {
        if self.ttl == 0 {
            return false;
        }
        self.ttl -= 1;
        self.visited.insert(my_node_id);
        true
    }

    /// Check if this request can still be forwarded.
    pub fn can_forward(&self) -> bool {
        self.ttl > 0
    }

    /// Check if a node was already visited.
    pub fn was_visited(&self, node_id: &NodeId) -> bool {
        self.visited.contains(node_id)
    }
}

/// Response to a lookup request with target's coordinates.
///
/// Routed back to the origin using the origin_coords from the request.
#[derive(Clone, Debug)]
pub struct LookupResponse {
    /// Echoed request identifier.
    pub request_id: u64,
    /// The target node.
    pub target: NodeId,
    /// Target's coordinates in the tree.
    pub target_coords: TreeCoordinate,
    /// Proof that target authorized this response (signature over request).
    pub proof: Signature,
}

impl LookupResponse {
    /// Create a new lookup response.
    pub fn new(
        request_id: u64,
        target: NodeId,
        target_coords: TreeCoordinate,
        proof: Signature,
    ) -> Self {
        Self {
            request_id,
            target,
            target_coords,
            proof,
        }
    }

    /// Get the bytes that should be signed as proof.
    ///
    /// Format: request_id (8) || target (32)
    pub fn proof_bytes(request_id: u64, target: &NodeId) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(40);
        bytes.extend_from_slice(&request_id.to_le_bytes());
        bytes.extend_from_slice(target.as_bytes());
        bytes
    }
}

// ============ Session Datagram (Link-Layer Encapsulation) ============

/// Encapsulated session-layer datagram for forwarding.
///
/// This is a link-layer message that carries an opaque, end-to-end encrypted
/// session-layer payload. Intermediate nodes route based on the destination
/// address but cannot decrypt the payload.
#[derive(Clone, Debug)]
pub struct SessionDatagram {
    /// Destination FIPS address (for routing decisions).
    pub dest_addr: FipsAddress,
    /// Hop limit (decremented at each hop).
    pub hop_limit: u8,
    /// Encrypted session-layer payload (opaque to intermediate nodes).
    pub payload: Vec<u8>,
}

impl SessionDatagram {
    /// Create a new session datagram.
    pub fn new(dest_addr: FipsAddress, payload: Vec<u8>) -> Self {
        Self {
            dest_addr,
            hop_limit: 64,
            payload,
        }
    }

    /// Set the hop limit.
    pub fn with_hop_limit(mut self, hop_limit: u8) -> Self {
        self.hop_limit = hop_limit;
        self
    }

    /// Decrement hop limit, returning false if exhausted.
    pub fn decrement_hop_limit(&mut self) -> bool {
        if self.hop_limit > 0 {
            self.hop_limit -= 1;
            true
        } else {
            false
        }
    }

    /// Check if the datagram can be forwarded.
    pub fn can_forward(&self) -> bool {
        self.hop_limit > 0
    }
}

// ============================================================================
// Session Layer Messages (end-to-end, between FIPS addresses)
// ============================================================================

/// Session flags for setup options.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionFlags {
    /// Request acknowledgement from destination.
    pub request_ack: bool,
    /// Set up bidirectional session.
    pub bidirectional: bool,
}

impl SessionFlags {
    /// Create default flags.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set request_ack flag.
    pub fn with_ack(mut self) -> Self {
        self.request_ack = true;
        self
    }

    /// Set bidirectional flag.
    pub fn bidirectional(mut self) -> Self {
        self.bidirectional = true;
        self
    }

    /// Convert to a byte.
    pub fn to_byte(&self) -> u8 {
        let mut flags = 0u8;
        if self.request_ack {
            flags |= 0x01;
        }
        if self.bidirectional {
            flags |= 0x02;
        }
        flags
    }

    /// Convert from a byte.
    pub fn from_byte(byte: u8) -> Self {
        Self {
            request_ack: byte & 0x01 != 0,
            bidirectional: byte & 0x02 != 0,
        }
    }
}

/// Session setup to establish cached coordinate state.
///
/// Sent before data packets to warm router caches with coordinate
/// information. Routers along the path cache the mappings.
#[derive(Clone, Debug)]
pub struct SessionSetup {
    /// Source FIPS address.
    pub src_addr: FipsAddress,
    /// Destination FIPS address.
    pub dest_addr: FipsAddress,
    /// Source coordinates (for return path caching).
    pub src_coords: TreeCoordinate,
    /// Destination coordinates (for forward routing).
    pub dest_coords: TreeCoordinate,
    /// Session options.
    pub flags: SessionFlags,
}

impl SessionSetup {
    /// Create a new session setup message.
    pub fn new(
        src_addr: FipsAddress,
        dest_addr: FipsAddress,
        src_coords: TreeCoordinate,
        dest_coords: TreeCoordinate,
    ) -> Self {
        Self {
            src_addr,
            dest_addr,
            src_coords,
            dest_coords,
            flags: SessionFlags::new(),
        }
    }

    /// Set session flags.
    pub fn with_flags(mut self, flags: SessionFlags) -> Self {
        self.flags = flags;
        self
    }
}

/// Session acknowledgement.
///
/// Sent in response to SessionSetup when request_ack is set.
#[derive(Clone, Debug)]
pub struct SessionAck {
    /// Source address (the acknowledger).
    pub src_addr: FipsAddress,
    /// Destination address (original session initiator).
    pub dest_addr: FipsAddress,
    /// Acknowledger's coordinates.
    pub src_coords: TreeCoordinate,
}

impl SessionAck {
    /// Create a new session acknowledgement.
    pub fn new(src_addr: FipsAddress, dest_addr: FipsAddress, src_coords: TreeCoordinate) -> Self {
        Self {
            src_addr,
            dest_addr,
            src_coords,
        }
    }
}

// ============ Data Messages ============

/// Data packet flags.
///
/// ## Flag Bits
///
/// | Bit | Name           | Description                              |
/// |-----|----------------|------------------------------------------|
/// | 0   | COORDS_PRESENT | Coordinates follow the fixed header      |
/// | 1-7 | reserved       | Reserved for future use                  |
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DataFlags {
    /// When set, source and destination coordinates follow the header.
    /// Used to warm router caches after receiving CoordsRequired.
    pub coords_present: bool,
    /// Reserved bits (preserved for forward compatibility).
    reserved: u8,
}

/// Bit 0: coordinates follow the header.
pub const DATA_FLAG_COORDS_PRESENT: u8 = 0x01;

impl DataFlags {
    /// Create default flags (no coordinates).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create flags with COORDS_PRESENT set.
    pub fn with_coords() -> Self {
        Self {
            coords_present: true,
            reserved: 0,
        }
    }

    /// Set the coords_present flag.
    pub fn set_coords_present(&mut self, value: bool) {
        self.coords_present = value;
    }

    /// Convert to a byte.
    pub fn to_byte(&self) -> u8 {
        let mut flags = self.reserved & !DATA_FLAG_COORDS_PRESENT;
        if self.coords_present {
            flags |= DATA_FLAG_COORDS_PRESENT;
        }
        flags
    }

    /// Convert from a byte.
    pub fn from_byte(byte: u8) -> Self {
        Self {
            coords_present: byte & DATA_FLAG_COORDS_PRESENT != 0,
            reserved: byte & !DATA_FLAG_COORDS_PRESENT,
        }
    }
}

/// Minimal data packet with addresses only (no coordinates).
///
/// The 36-byte header contains:
/// - flags (1 byte)
/// - hop_limit (1 byte)
/// - payload_length (2 bytes)
/// - src_addr (16 bytes)
/// - dest_addr (16 bytes)
///
/// Routers use cached coordinates for routing decisions.
#[derive(Clone, Debug)]
pub struct DataPacket {
    /// Packet flags.
    pub flags: DataFlags,
    /// Hop limit (TTL).
    pub hop_limit: u8,
    /// Source FIPS address.
    pub src_addr: FipsAddress,
    /// Destination FIPS address.
    pub dest_addr: FipsAddress,
    /// Payload data.
    pub payload: Vec<u8>,
}

impl DataPacket {
    /// Create a new data packet.
    pub fn new(src_addr: FipsAddress, dest_addr: FipsAddress, payload: Vec<u8>) -> Self {
        Self {
            flags: DataFlags::new(),
            hop_limit: 64,
            src_addr,
            dest_addr,
            payload,
        }
    }

    /// Set the hop limit.
    pub fn with_hop_limit(mut self, hop_limit: u8) -> Self {
        self.hop_limit = hop_limit;
        self
    }

    /// Set the flags.
    pub fn with_flags(mut self, flags: DataFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Decrement hop limit, returning false if exhausted.
    pub fn decrement_hop_limit(&mut self) -> bool {
        if self.hop_limit > 0 {
            self.hop_limit -= 1;
            true
        } else {
            false
        }
    }

    /// Check if the packet can be forwarded.
    pub fn can_forward(&self) -> bool {
        self.hop_limit > 0
    }

    /// Get the payload length.
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// Total packet size (header + payload).
    pub fn total_size(&self) -> usize {
        DATA_HEADER_SIZE + self.payload.len()
    }

    /// Header size in bytes.
    pub fn header_size(&self) -> usize {
        DATA_HEADER_SIZE
    }
}

// ============ Error Messages ============

/// Error indicating router cache miss - needs coordinates.
///
/// Sent back to the source when a router doesn't have cached
/// coordinates for the destination.
#[derive(Clone, Debug)]
pub struct CoordsRequired {
    /// Destination that couldn't be routed.
    pub dest_addr: FipsAddress,
    /// Router reporting the miss.
    pub reporter: NodeId,
}

impl CoordsRequired {
    /// Create a new CoordsRequired error.
    pub fn new(dest_addr: FipsAddress, reporter: NodeId) -> Self {
        Self { dest_addr, reporter }
    }
}

/// Error indicating routing failure (local minimum or unreachable).
///
/// Sent back to the source when greedy routing fails.
#[derive(Clone, Debug)]
pub struct PathBroken {
    /// Original source of the failed packet.
    pub original_src: FipsAddress,
    /// Destination that couldn't be reached.
    pub dest_addr: FipsAddress,
    /// Node that detected the failure.
    pub reporter: NodeId,
    /// Optional: last known coordinates of destination.
    pub last_known_coords: Option<TreeCoordinate>,
}

impl PathBroken {
    /// Create a new PathBroken error.
    pub fn new(original_src: FipsAddress, dest_addr: FipsAddress, reporter: NodeId) -> Self {
        Self {
            original_src,
            dest_addr,
            reporter,
            last_known_coords: None,
        }
    }

    /// Add last known coordinates.
    pub fn with_last_coords(mut self, coords: TreeCoordinate) -> Self {
        self.last_known_coords = Some(coords);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node_id(val: u8) -> NodeId {
        let mut bytes = [0u8; 32];
        bytes[0] = val;
        NodeId::from_bytes(bytes)
    }

    fn make_address(val: u8) -> FipsAddress {
        let mut bytes = [0xfdu8; 16];
        bytes[1] = val;
        FipsAddress::from_bytes(bytes).unwrap()
    }

    fn make_coords(ids: &[u8]) -> TreeCoordinate {
        TreeCoordinate::new(ids.iter().map(|&v| make_node_id(v)).collect()).unwrap()
    }

    // ===== HandshakeMessageType Tests =====

    #[test]
    fn test_handshake_message_type_roundtrip() {
        let types = [
            HandshakeMessageType::NoiseIKMsg1,
            HandshakeMessageType::NoiseIKMsg2,
        ];

        for ty in types {
            let byte = ty.to_byte();
            let restored = HandshakeMessageType::from_byte(byte);
            assert_eq!(restored, Some(ty));
        }
    }

    #[test]
    fn test_handshake_message_type_invalid() {
        assert!(HandshakeMessageType::from_byte(0x00).is_none());
        assert!(HandshakeMessageType::from_byte(0x03).is_none());
        assert!(HandshakeMessageType::from_byte(0x10).is_none());
    }

    #[test]
    fn test_handshake_message_type_is_handshake() {
        assert!(HandshakeMessageType::is_handshake(0x01));
        assert!(HandshakeMessageType::is_handshake(0x02));
        assert!(!HandshakeMessageType::is_handshake(0x00));
        assert!(!HandshakeMessageType::is_handshake(0x10));
    }

    // ===== LinkMessageType Tests =====

    #[test]
    fn test_link_message_type_roundtrip() {
        let types = [
            LinkMessageType::TreeAnnounce,
            LinkMessageType::FilterAnnounce,
            LinkMessageType::LookupRequest,
            LinkMessageType::LookupResponse,
            LinkMessageType::SessionDatagram,
        ];

        for ty in types {
            let byte = ty.to_byte();
            let restored = LinkMessageType::from_byte(byte);
            assert_eq!(restored, Some(ty));
        }
    }

    #[test]
    fn test_link_message_type_invalid() {
        assert!(LinkMessageType::from_byte(0xFF).is_none());
        assert!(LinkMessageType::from_byte(0x00).is_none());
    }

    // ===== SessionMessageType Tests =====

    #[test]
    fn test_session_message_type_roundtrip() {
        let types = [
            SessionMessageType::SessionSetup,
            SessionMessageType::SessionAck,
            SessionMessageType::DataPacket,
            SessionMessageType::CoordsRequired,
            SessionMessageType::PathBroken,
        ];

        for ty in types {
            let byte = ty.to_byte();
            let restored = SessionMessageType::from_byte(byte);
            assert_eq!(restored, Some(ty));
        }
    }

    #[test]
    fn test_session_message_type_invalid() {
        assert!(SessionMessageType::from_byte(0xFF).is_none());
        assert!(SessionMessageType::from_byte(0x99).is_none());
    }

    // ===== SessionFlags Tests =====

    #[test]
    fn test_session_flags() {
        let flags = SessionFlags::new().with_ack().bidirectional();

        assert!(flags.request_ack);
        assert!(flags.bidirectional);

        let byte = flags.to_byte();
        let restored = SessionFlags::from_byte(byte);

        assert_eq!(flags, restored);
    }

    #[test]
    fn test_session_flags_default() {
        let flags = SessionFlags::new();
        assert!(!flags.request_ack);
        assert!(!flags.bidirectional);
        assert_eq!(flags.to_byte(), 0);
    }

    // ===== DataPacket Tests =====

    #[test]
    fn test_data_packet_size() {
        let packet = DataPacket::new(make_address(1), make_address(2), vec![0u8; 100]);

        // 36 byte header + 100 byte payload
        assert_eq!(packet.total_size(), 136);
        assert_eq!(packet.header_size(), 36);
        assert_eq!(packet.payload_len(), 100);
    }

    #[test]
    fn test_data_packet_hop_limit() {
        let mut packet = DataPacket::new(make_address(1), make_address(2), vec![]);

        packet.hop_limit = 2;
        assert!(packet.can_forward());

        assert!(packet.decrement_hop_limit());
        assert_eq!(packet.hop_limit, 1);

        assert!(packet.decrement_hop_limit());
        assert_eq!(packet.hop_limit, 0);
        assert!(!packet.can_forward());

        assert!(!packet.decrement_hop_limit());
        assert_eq!(packet.hop_limit, 0);
    }

    #[test]
    fn test_data_packet_builder() {
        let packet = DataPacket::new(make_address(1), make_address(2), vec![1, 2, 3])
            .with_hop_limit(32)
            .with_flags(DataFlags::from_byte(0x80));

        assert_eq!(packet.hop_limit, 32);
        assert_eq!(packet.flags.to_byte(), 0x80);
    }

    #[test]
    fn test_data_flags_coords_present() {
        // Default: no coords
        let flags = DataFlags::new();
        assert!(!flags.coords_present);
        assert_eq!(flags.to_byte(), 0x00);

        // With coords
        let flags = DataFlags::with_coords();
        assert!(flags.coords_present);
        assert_eq!(flags.to_byte(), 0x01);

        // Round-trip preserves flag
        let flags = DataFlags::from_byte(0x01);
        assert!(flags.coords_present);
        assert_eq!(flags.to_byte(), 0x01);

        // Reserved bits preserved
        let flags = DataFlags::from_byte(0x81); // coords + reserved bit 7
        assert!(flags.coords_present);
        assert_eq!(flags.to_byte(), 0x81);

        // Coords bit toggles independently
        let flags = DataFlags::from_byte(0x80); // only reserved bit 7
        assert!(!flags.coords_present);
        assert_eq!(flags.to_byte(), 0x80);
    }

    // ===== LookupRequest Tests =====

    #[test]
    fn test_lookup_request_forward() {
        let target = make_node_id(1);
        let origin = make_node_id(2);
        let coords = make_coords(&[2, 0]);
        let forwarder = make_node_id(3);

        let mut request = LookupRequest::new(123, target, origin, coords, 5);

        assert!(request.can_forward());
        assert!(!request.was_visited(&forwarder));

        assert!(request.forward(&forwarder));

        assert_eq!(request.ttl, 4);
        assert!(request.was_visited(&forwarder));
    }

    #[test]
    fn test_lookup_request_ttl_exhausted() {
        let target = make_node_id(1);
        let origin = make_node_id(2);
        let coords = make_coords(&[2, 0]);

        let mut request = LookupRequest::new(123, target, origin, coords, 1);

        assert!(request.forward(&make_node_id(3)));
        assert!(!request.can_forward());
        assert!(!request.forward(&make_node_id(4)));
    }

    #[test]
    fn test_lookup_request_generate() {
        let target = make_node_id(1);
        let origin = make_node_id(2);
        let coords = make_coords(&[2, 0]);

        let req1 = LookupRequest::generate(target, origin, coords.clone(), 5);
        let req2 = LookupRequest::generate(target, origin, coords, 5);

        // Random IDs should differ
        assert_ne!(req1.request_id, req2.request_id);
    }

    // ===== LookupResponse Tests =====

    #[test]
    fn test_lookup_response_proof_bytes() {
        let target = make_node_id(42);
        let bytes = LookupResponse::proof_bytes(12345, &target);

        assert_eq!(bytes.len(), 40); // 8 + 32
        assert_eq!(&bytes[0..8], &12345u64.to_le_bytes());
        assert_eq!(&bytes[8..40], target.as_bytes());
    }

    // ===== FilterAnnounce Tests =====

    #[test]
    fn test_filter_announce_forward() {
        let filter = BloomFilter::new();
        let announce = FilterAnnounce::new(filter, 2, 100);

        assert!(announce.can_forward());

        let forwarded = announce.forwarded().unwrap();
        assert_eq!(forwarded.ttl, 1);
        assert_eq!(forwarded.sequence, 100);

        let forwarded2 = forwarded.forwarded().unwrap();
        assert_eq!(forwarded2.ttl, 0);
        assert!(!forwarded2.can_forward());

        assert!(forwarded2.forwarded().is_none());
    }

    #[test]
    fn test_filter_announce_size_class() {
        let filter = BloomFilter::new();
        let announce = FilterAnnounce::new(filter.clone(), 2, 100);

        // v1 defaults
        assert_eq!(announce.size_class, 1);
        assert_eq!(announce.hash_count, 5);
        assert!(announce.is_v1_compliant());
        assert!(announce.is_valid());
        assert_eq!(announce.filter_size_bytes(), 1024);

        // Forwarded preserves size_class
        let forwarded = announce.forwarded().unwrap();
        assert_eq!(forwarded.size_class, 1);
        assert_eq!(forwarded.hash_count, 5);
    }

    #[test]
    fn test_filter_announce_with_size_class() {
        let filter = BloomFilter::with_params(2048 * 8, 7).unwrap();
        let announce = FilterAnnounce::with_size_class(filter, 2, 100, 2);

        assert_eq!(announce.size_class, 2);
        assert_eq!(announce.hash_count, 7);
        assert!(!announce.is_v1_compliant());
        assert!(announce.is_valid());
        assert_eq!(announce.filter_size_bytes(), 2048);
    }

    // ===== SessionSetup Tests =====

    #[test]
    fn test_session_setup() {
        let setup = SessionSetup::new(
            make_address(1),
            make_address(2),
            make_coords(&[1, 0]),
            make_coords(&[2, 0]),
        )
        .with_flags(SessionFlags::new().with_ack());

        assert!(setup.flags.request_ack);
        assert!(!setup.flags.bidirectional);
    }

    // ===== CoordsRequired Tests =====

    #[test]
    fn test_coords_required() {
        let err = CoordsRequired::new(make_address(1), make_node_id(2));

        assert_eq!(err.dest_addr, make_address(1));
        assert_eq!(err.reporter, make_node_id(2));
    }

    // ===== PathBroken Tests =====

    #[test]
    fn test_path_broken() {
        let err = PathBroken::new(make_address(1), make_address(2), make_node_id(3))
            .with_last_coords(make_coords(&[2, 0]));

        assert!(err.last_known_coords.is_some());
    }

    // ===== TreeAnnounce Tests =====

    #[test]
    fn test_tree_announce() {
        let node = make_node_id(1);
        let parent = make_node_id(2);
        let decl = ParentDeclaration::new(node, parent, 1, 1000);
        let ancestry = make_coords(&[1, 2, 0]);

        let announce = TreeAnnounce::new(decl, ancestry);

        assert_eq!(announce.declaration.node_id(), &node);
        assert_eq!(announce.ancestry.depth(), 2);
    }
}
