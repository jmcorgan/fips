//! Session-layer message types: setup, ack, data, and error messages.

use super::ProtocolError;
use crate::tree::TreeCoordinate;
use crate::NodeAddr;
use std::fmt;

// ============================================================================
// Session Layer Message Types
// ============================================================================

/// SessionDatagram payload message type identifiers.
///
/// These messages are carried as payloads inside `SessionDatagram` (link
/// message type 0x00). Session-layer messages (SessionSetup, SessionAck,
/// DataPacket) are end-to-end encrypted with session keys. Error signals
/// (CoordsRequired, PathBroken) are plaintext link-layer messages generated
/// by transit routers that cannot establish e2e sessions with the source.
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

    // Link-layer error signals (0x20-0x2F) — plaintext, from transit routers
    /// Router cache miss — needs coordinates (link-layer error signal).
    CoordsRequired = 0x20,
    /// Routing failure — local minimum or unreachable (link-layer error signal).
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

// ============================================================================
// Coordinate Wire Format Helpers
// ============================================================================

/// Encode a TreeCoordinate as address-only wire format: count(u16 LE) + addrs(16 × n).
///
/// Session-layer messages serialize coordinates as NodeAddr arrays (16 bytes each),
/// without the sequence/timestamp metadata used by the tree gossip protocol.
pub(crate) fn encode_coords(coords: &TreeCoordinate, buf: &mut Vec<u8>) {
    let addrs: Vec<&NodeAddr> = coords.node_addrs().collect();
    let count = addrs.len() as u16;
    buf.extend_from_slice(&count.to_le_bytes());
    for addr in addrs {
        buf.extend_from_slice(addr.as_bytes());
    }
}

/// Decode a TreeCoordinate from address-only wire format.
///
/// Returns the decoded coordinate and the number of bytes consumed.
pub(crate) fn decode_coords(data: &[u8]) -> Result<(TreeCoordinate, usize), ProtocolError> {
    if data.len() < 2 {
        return Err(ProtocolError::MessageTooShort {
            expected: 2,
            got: data.len(),
        });
    }
    let count = u16::from_le_bytes([data[0], data[1]]) as usize;
    let needed = 2 + count * 16;
    if data.len() < needed {
        return Err(ProtocolError::MessageTooShort {
            expected: needed,
            got: data.len(),
        });
    }
    if count == 0 {
        return Err(ProtocolError::Malformed(
            "coordinate with zero entries".into(),
        ));
    }
    let mut addrs = Vec::with_capacity(count);
    for i in 0..count {
        let offset = 2 + i * 16;
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&data[offset..offset + 16]);
        addrs.push(NodeAddr::from_bytes(bytes));
    }
    let coord = TreeCoordinate::from_addrs(addrs)
        .map_err(|e| ProtocolError::Malformed(e.to_string()))?;
    Ok((coord, needed))
}

/// Decode an optional coordinate field (count may be 0).
///
/// Returns None if count is 0, Some(coord) otherwise, plus bytes consumed.
fn decode_optional_coords(data: &[u8]) -> Result<(Option<TreeCoordinate>, usize), ProtocolError> {
    if data.len() < 2 {
        return Err(ProtocolError::MessageTooShort {
            expected: 2,
            got: data.len(),
        });
    }
    let count = u16::from_le_bytes([data[0], data[1]]) as usize;
    let needed = 2 + count * 16;
    if data.len() < needed {
        return Err(ProtocolError::MessageTooShort {
            expected: needed,
            got: data.len(),
        });
    }
    if count == 0 {
        return Ok((None, 2));
    }
    let mut addrs = Vec::with_capacity(count);
    for i in 0..count {
        let offset = 2 + i * 16;
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&data[offset..offset + 16]);
        addrs.push(NodeAddr::from_bytes(bytes));
    }
    let coord = TreeCoordinate::from_addrs(addrs)
        .map_err(|e| ProtocolError::Malformed(e.to_string()))?;
    Ok((Some(coord), needed))
}

/// Encode a count of zero (for empty/absent coordinate fields).
fn encode_empty_coords(buf: &mut Vec<u8>) {
    buf.extend_from_slice(&0u16.to_le_bytes());
}

// ============================================================================
// Session Flags
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

// ============================================================================
// Session Setup
// ============================================================================

/// Session setup to establish cached coordinate state.
///
/// Carried inside a SessionDatagram envelope which provides src_addr and
/// dest_addr. The SessionSetup payload contains coordinates, session flags,
/// and the Noise IK handshake message for session establishment.
///
/// ## Wire Format
///
/// | Offset | Field            | Size    | Description                         |
/// |--------|------------------|---------|-------------------------------------|
/// | 0      | msg_type         | 1 byte  | 0x00                                |
/// | 1      | flags            | 1 byte  | Bit 0: REQUEST_ACK, Bit 1: BIDIR   |
/// | 2      | src_coords_count | 2 bytes | u16 LE, number of src coord entries |
/// | 4      | src_coords       | 16 × n  | NodeAddr array (self → root)        |
/// | ...    | dest_coords_count| 2 bytes | u16 LE, number of dest coord entries|
/// | ...    | dest_coords      | 16 × m  | NodeAddr array (dest → root)        |
/// | ...    | handshake_len    | 2 bytes  | u16 LE, Noise payload length        |
/// | ...    | handshake_payload| variable| Noise IK msg1 (82 bytes typical)    |
#[derive(Clone, Debug)]
pub struct SessionSetup {
    /// Source coordinates (for return path caching).
    pub src_coords: TreeCoordinate,
    /// Destination coordinates (for forward routing).
    pub dest_coords: TreeCoordinate,
    /// Session options.
    pub flags: SessionFlags,
    /// Noise IK handshake message 1.
    pub handshake_payload: Vec<u8>,
}

impl SessionSetup {
    /// Create a new session setup message.
    pub fn new(src_coords: TreeCoordinate, dest_coords: TreeCoordinate) -> Self {
        Self {
            src_coords,
            dest_coords,
            flags: SessionFlags::new(),
            handshake_payload: Vec::new(),
        }
    }

    /// Set session flags.
    pub fn with_flags(mut self, flags: SessionFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Set the Noise handshake payload.
    pub fn with_handshake(mut self, payload: Vec<u8>) -> Self {
        self.handshake_payload = payload;
        self
    }

    /// Encode as wire format (msg_type + flags + coords + handshake).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(SessionMessageType::SessionSetup.to_byte());
        buf.push(self.flags.to_byte());
        encode_coords(&self.src_coords, &mut buf);
        encode_coords(&self.dest_coords, &mut buf);
        let hs_len = self.handshake_payload.len() as u16;
        buf.extend_from_slice(&hs_len.to_le_bytes());
        buf.extend_from_slice(&self.handshake_payload);
        buf
    }

    /// Decode from wire format (after msg_type byte has been consumed).
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.is_empty() {
            return Err(ProtocolError::MessageTooShort {
                expected: 1,
                got: 0,
            });
        }
        let flags = SessionFlags::from_byte(payload[0]);
        let mut offset = 1;

        let (src_coords, consumed) = decode_coords(&payload[offset..])?;
        offset += consumed;

        let (dest_coords, consumed) = decode_coords(&payload[offset..])?;
        offset += consumed;

        if payload.len() < offset + 2 {
            return Err(ProtocolError::MessageTooShort {
                expected: offset + 2,
                got: payload.len(),
            });
        }
        let hs_len = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;

        if payload.len() < offset + hs_len {
            return Err(ProtocolError::MessageTooShort {
                expected: offset + hs_len,
                got: payload.len(),
            });
        }
        let handshake_payload = payload[offset..offset + hs_len].to_vec();

        Ok(Self {
            src_coords,
            dest_coords,
            flags,
            handshake_payload,
        })
    }
}

// ============================================================================
// Session Ack
// ============================================================================

/// Session acknowledgement.
///
/// Carried inside a SessionDatagram envelope which provides src_addr and
/// dest_addr. The SessionAck payload contains the acknowledger's coordinates
/// for route cache warming and the Noise IK handshake response.
///
/// ## Wire Format
///
/// | Offset | Field            | Size    | Description                         |
/// |--------|------------------|---------|-------------------------------------|
/// | 0      | msg_type         | 1 byte  | 0x01                                |
/// | 1      | flags            | 1 byte  | Reserved                            |
/// | 2      | src_coords_count | 2 bytes | u16 LE                              |
/// | 4      | src_coords       | 16 × n  | Acknowledger's coords (for caching) |
/// | ...    | handshake_len    | 2 bytes  | u16 LE, Noise payload length        |
/// | ...    | handshake_payload| variable| Noise IK msg2 (33 bytes typical)    |
#[derive(Clone, Debug)]
pub struct SessionAck {
    /// Acknowledger's coordinates.
    pub src_coords: TreeCoordinate,
    /// Reserved flags byte (for forward compatibility).
    pub flags: u8,
    /// Noise IK handshake message 2.
    pub handshake_payload: Vec<u8>,
}

impl SessionAck {
    /// Create a new session acknowledgement.
    pub fn new(src_coords: TreeCoordinate) -> Self {
        Self {
            src_coords,
            flags: 0,
            handshake_payload: Vec::new(),
        }
    }

    /// Set the Noise handshake payload.
    pub fn with_handshake(mut self, payload: Vec<u8>) -> Self {
        self.handshake_payload = payload;
        self
    }

    /// Encode as wire format (msg_type + flags + coords + handshake).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(SessionMessageType::SessionAck.to_byte());
        buf.push(self.flags);
        encode_coords(&self.src_coords, &mut buf);
        let hs_len = self.handshake_payload.len() as u16;
        buf.extend_from_slice(&hs_len.to_le_bytes());
        buf.extend_from_slice(&self.handshake_payload);
        buf
    }

    /// Decode from wire format (after msg_type byte has been consumed).
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.is_empty() {
            return Err(ProtocolError::MessageTooShort {
                expected: 1,
                got: 0,
            });
        }
        let flags = payload[0];
        let mut offset = 1;

        let (src_coords, consumed) = decode_coords(&payload[offset..])?;
        offset += consumed;

        if payload.len() < offset + 2 {
            return Err(ProtocolError::MessageTooShort {
                expected: offset + 2,
                got: payload.len(),
            });
        }
        let hs_len = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;

        if payload.len() < offset + hs_len {
            return Err(ProtocolError::MessageTooShort {
                expected: offset + hs_len,
                got: payload.len(),
            });
        }
        let handshake_payload = payload[offset..offset + hs_len].to_vec();

        Ok(Self {
            src_coords,
            flags,
            handshake_payload,
        })
    }
}

// ============================================================================
// Data Messages
// ============================================================================

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

/// DataPacket header size in bytes (excluding payload).
/// msg_type(1) + flags(1) + counter(8) + payload_length(2) = 12
/// (Addressing and TTL are in the SessionDatagram envelope.)
pub const DATA_HEADER_SIZE: usize = 12;

/// Encrypted application data carried inside a SessionDatagram.
///
/// ## Wire Format (minimal, no coordinates)
///
/// | Offset | Field          | Size    | Description                   |
/// |--------|----------------|---------|-------------------------------|
/// | 0      | msg_type       | 1 byte  | 0x10                          |
/// | 1      | flags          | 1 byte  | Bit 0: COORDS_PRESENT         |
/// | 2      | counter        | 8 bytes | u64 LE, encryption nonce      |
/// | 10     | payload_length | 2 bytes | u16 LE                        |
/// | 12     | payload        | variable| Encrypted application data    |
///
/// ## Wire Format (with coordinates, when COORDS_PRESENT is set)
///
/// | Offset | Field            | Size    | Description                |
/// |--------|------------------|---------|----------------------------|
/// | 0      | msg_type         | 1 byte  | 0x10                       |
/// | 1      | flags            | 1 byte  | 0x01 (COORDS_PRESENT)      |
/// | 2      | counter          | 8 bytes | u64 LE, encryption nonce   |
/// | 10     | payload_length   | 2 bytes | u16 LE                     |
/// | 12     | src_coords_count | 2 bytes | u16 LE                     |
/// | 14     | src_coords       | 16 × n  | Source coordinates          |
/// | ...    | dest_coords_count| 2 bytes | u16 LE                     |
/// | ...    | dest_coords      | 16 × m  | Destination coordinates    |
/// | ...    | payload          | variable| Encrypted application data |
#[derive(Clone, Debug)]
pub struct DataPacket {
    /// Packet flags.
    pub flags: DataFlags,
    /// Encryption counter (used as nonce for ChaCha20Poly1305).
    /// Transmitted on the wire so the receiver can decrypt out-of-order packets.
    pub counter: u64,
    /// Payload data (end-to-end encrypted application data).
    pub payload: Vec<u8>,
    /// Source coordinates (present when COORDS_PRESENT flag is set).
    pub src_coords: Option<TreeCoordinate>,
    /// Destination coordinates (present when COORDS_PRESENT flag is set).
    pub dest_coords: Option<TreeCoordinate>,
}

impl DataPacket {
    /// Create a new data packet with the given counter and payload.
    pub fn new(counter: u64, payload: Vec<u8>) -> Self {
        Self {
            flags: DataFlags::new(),
            counter,
            payload,
            src_coords: None,
            dest_coords: None,
        }
    }

    /// Set the flags.
    pub fn with_flags(mut self, flags: DataFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Set coordinates for route cache warming.
    pub fn with_coords(mut self, src: TreeCoordinate, dest: TreeCoordinate) -> Self {
        self.src_coords = Some(src);
        self.dest_coords = Some(dest);
        self.flags.coords_present = true;
        self
    }

    /// Get the payload length.
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// Total packet size (header + optional coords + payload).
    pub fn total_size(&self) -> usize {
        DATA_HEADER_SIZE + self.coords_wire_size() + self.payload.len()
    }

    /// Header size in bytes.
    pub fn header_size(&self) -> usize {
        DATA_HEADER_SIZE
    }

    /// Wire size of the optional coordinate fields.
    fn coords_wire_size(&self) -> usize {
        if !self.flags.coords_present {
            return 0;
        }
        let src_count = self.src_coords.as_ref().map_or(0, |c| c.depth() + 1);
        let dest_count = self.dest_coords.as_ref().map_or(0, |c| c.depth() + 1);
        2 + src_count * 16 + 2 + dest_count * 16
    }

    /// Encode as wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(SessionMessageType::DataPacket.to_byte());
        buf.push(self.flags.to_byte());
        buf.extend_from_slice(&self.counter.to_le_bytes());
        let payload_len = self.payload.len() as u16;
        buf.extend_from_slice(&payload_len.to_le_bytes());
        if self.flags.coords_present {
            if let Some(ref src) = self.src_coords {
                encode_coords(src, &mut buf);
            } else {
                encode_empty_coords(&mut buf);
            }
            if let Some(ref dest) = self.dest_coords {
                encode_coords(dest, &mut buf);
            } else {
                encode_empty_coords(&mut buf);
            }
        }
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode from wire format (after msg_type byte has been consumed).
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        // flags(1) + counter(8) + payload_len(2) = 11
        if payload.len() < 11 {
            return Err(ProtocolError::MessageTooShort {
                expected: 11,
                got: payload.len(),
            });
        }
        let flags = DataFlags::from_byte(payload[0]);
        let counter = u64::from_le_bytes([
            payload[1], payload[2], payload[3], payload[4],
            payload[5], payload[6], payload[7], payload[8],
        ]);
        let payload_len = u16::from_le_bytes([payload[9], payload[10]]) as usize;
        let mut offset = 11;

        let (src_coords, dest_coords) = if flags.coords_present {
            let (src, consumed) = decode_optional_coords(&payload[offset..])?;
            offset += consumed;
            let (dest, consumed) = decode_optional_coords(&payload[offset..])?;
            offset += consumed;
            (src, dest)
        } else {
            (None, None)
        };

        if payload.len() < offset + payload_len {
            return Err(ProtocolError::MessageTooShort {
                expected: offset + payload_len,
                got: payload.len(),
            });
        }
        let data = payload[offset..offset + payload_len].to_vec();

        Ok(Self {
            flags,
            counter,
            payload: data,
            src_coords,
            dest_coords,
        })
    }
}

// ============================================================================
// Error Messages
// ============================================================================

/// Link-layer error signal indicating router cache miss.
///
/// Generated by a transit router when it cannot forward a SessionDatagram
/// due to missing cached coordinates for the destination. Carried inside
/// a new SessionDatagram addressed back to the original source
/// (src_addr=reporter, dest_addr=original_source). Plaintext — not
/// end-to-end encrypted, since the transit router has no session with
/// the source.
///
/// ## Wire Format
///
/// | Offset | Field    | Size     | Description                        |
/// |--------|----------|---------|------------------------------------|
/// | 0      | msg_type | 1 byte  | 0x20                               |
/// | 1      | flags    | 1 byte  | Reserved                           |
/// | 2      | dest_addr| 16 bytes| The node_addr we couldn't route to |
/// | 18     | reporter | 16 bytes| NodeAddr of reporting router       |
///
/// Payload: 34 bytes
#[derive(Clone, Debug)]
pub struct CoordsRequired {
    /// Destination that couldn't be routed.
    pub dest_addr: NodeAddr,
    /// Router reporting the miss.
    pub reporter: NodeAddr,
}

/// Wire size of CoordsRequired payload: msg_type(1) + flags(1) + dest_addr(16) + reporter(16).
pub const COORDS_REQUIRED_SIZE: usize = 34;

impl CoordsRequired {
    /// Create a new CoordsRequired error.
    pub fn new(dest_addr: NodeAddr, reporter: NodeAddr) -> Self {
        Self { dest_addr, reporter }
    }

    /// Encode as wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(COORDS_REQUIRED_SIZE);
        buf.push(SessionMessageType::CoordsRequired.to_byte());
        buf.push(0x00); // reserved flags
        buf.extend_from_slice(self.dest_addr.as_bytes());
        buf.extend_from_slice(self.reporter.as_bytes());
        buf
    }

    /// Decode from wire format (after msg_type byte has been consumed).
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        // flags(1) + dest_addr(16) + reporter(16) = 33
        if payload.len() < 33 {
            return Err(ProtocolError::MessageTooShort {
                expected: 33,
                got: payload.len(),
            });
        }
        // payload[0] is flags (reserved, ignored)
        let mut dest_bytes = [0u8; 16];
        dest_bytes.copy_from_slice(&payload[1..17]);
        let mut reporter_bytes = [0u8; 16];
        reporter_bytes.copy_from_slice(&payload[17..33]);

        Ok(Self {
            dest_addr: NodeAddr::from_bytes(dest_bytes),
            reporter: NodeAddr::from_bytes(reporter_bytes),
        })
    }
}

/// Error indicating routing failure (local minimum or unreachable).
///
/// Carried inside a SessionDatagram addressed back to the original source.
/// The reporting router creates a new SessionDatagram with src_addr=reporter
/// and dest_addr=original_source, so the `original_src` field from the old
/// design is no longer needed — it's the SessionDatagram's dest_addr.
///
/// ## Wire Format
///
/// | Offset | Field             | Size     | Description                   |
/// |--------|-------------------|----------|-------------------------------|
/// | 0      | msg_type          | 1 byte   | 0x21                          |
/// | 1      | flags             | 1 byte   | Reserved                      |
/// | 2      | dest_addr         | 16 bytes | The unreachable node_addr     |
/// | 18     | reporter          | 16 bytes | NodeAddr of reporting router   |
/// | 34     | last_coords_count | 2 bytes  | u16 LE                        |
/// | 36     | last_known_coords | 16 × n   | Stale coords that failed      |
#[derive(Clone, Debug)]
pub struct PathBroken {
    /// Destination that couldn't be reached.
    pub dest_addr: NodeAddr,
    /// Node that detected the failure.
    pub reporter: NodeAddr,
    /// Optional: last known coordinates of destination.
    pub last_known_coords: Option<TreeCoordinate>,
}

impl PathBroken {
    /// Create a new PathBroken error.
    pub fn new(dest_addr: NodeAddr, reporter: NodeAddr) -> Self {
        Self {
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

    /// Encode as wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(SessionMessageType::PathBroken.to_byte());
        buf.push(0x00); // reserved flags
        buf.extend_from_slice(self.dest_addr.as_bytes());
        buf.extend_from_slice(self.reporter.as_bytes());
        if let Some(ref coords) = self.last_known_coords {
            encode_coords(coords, &mut buf);
        } else {
            encode_empty_coords(&mut buf);
        }
        buf
    }

    /// Decode from wire format (after msg_type byte has been consumed).
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        // flags(1) + dest_addr(16) + reporter(16) + coords_count(2) = 35 minimum
        if payload.len() < 35 {
            return Err(ProtocolError::MessageTooShort {
                expected: 35,
                got: payload.len(),
            });
        }
        // payload[0] is flags (reserved, ignored)
        let mut dest_bytes = [0u8; 16];
        dest_bytes.copy_from_slice(&payload[1..17]);
        let mut reporter_bytes = [0u8; 16];
        reporter_bytes.copy_from_slice(&payload[17..33]);

        let (last_known_coords, _consumed) = decode_optional_coords(&payload[33..])?;

        Ok(Self {
            dest_addr: NodeAddr::from_bytes(dest_bytes),
            reporter: NodeAddr::from_bytes(reporter_bytes),
            last_known_coords,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node_addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    fn make_coords(ids: &[u8]) -> TreeCoordinate {
        TreeCoordinate::from_addrs(ids.iter().map(|&v| make_node_addr(v)).collect()).unwrap()
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
        let packet = DataPacket::new(0, vec![0u8; 100]);

        // 12 byte header + 100 byte payload
        assert_eq!(packet.total_size(), 112);
        assert_eq!(packet.header_size(), 12);
        assert_eq!(packet.payload_len(), 100);
    }

    #[test]
    fn test_data_packet_builder() {
        let packet = DataPacket::new(0, vec![1, 2, 3])
            .with_flags(DataFlags::from_byte(0x80));

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

    // ===== SessionSetup Tests =====

    #[test]
    fn test_session_setup() {
        let setup = SessionSetup::new(make_coords(&[1, 0]), make_coords(&[2, 0]))
            .with_flags(SessionFlags::new().with_ack());

        assert!(setup.flags.request_ack);
        assert!(!setup.flags.bidirectional);
    }

    // ===== CoordsRequired Tests =====

    #[test]
    fn test_coords_required() {
        let err = CoordsRequired::new(make_node_addr(1), make_node_addr(2));

        assert_eq!(err.dest_addr, make_node_addr(1));
        assert_eq!(err.reporter, make_node_addr(2));
    }

    // ===== PathBroken Tests =====

    #[test]
    fn test_path_broken() {
        let err = PathBroken::new(make_node_addr(2), make_node_addr(3))
            .with_last_coords(make_coords(&[2, 0]));

        assert_eq!(err.dest_addr, make_node_addr(2));
        assert_eq!(err.reporter, make_node_addr(3));
        assert!(err.last_known_coords.is_some());
    }

    // ===== Encode/Decode Roundtrip Tests =====

    #[test]
    fn test_session_setup_encode_decode() {
        let handshake = vec![0xAA; 82]; // typical Noise IK msg1
        let setup = SessionSetup::new(make_coords(&[1, 2, 0]), make_coords(&[3, 4, 0]))
            .with_flags(SessionFlags::new().with_ack().bidirectional())
            .with_handshake(handshake.clone());

        let encoded = setup.encode();

        // Verify msg_type byte
        assert_eq!(encoded[0], 0x00);

        // Decode (skip msg_type byte)
        let decoded = SessionSetup::decode(&encoded[1..]).unwrap();

        assert_eq!(decoded.flags, setup.flags);
        assert_eq!(decoded.src_coords, setup.src_coords);
        assert_eq!(decoded.dest_coords, setup.dest_coords);
        assert_eq!(decoded.handshake_payload, handshake);
    }

    #[test]
    fn test_session_setup_no_handshake() {
        let setup = SessionSetup::new(make_coords(&[5, 0]), make_coords(&[6, 0]));

        let encoded = setup.encode();
        let decoded = SessionSetup::decode(&encoded[1..]).unwrap();

        assert!(decoded.handshake_payload.is_empty());
        assert_eq!(decoded.src_coords, setup.src_coords);
        assert_eq!(decoded.dest_coords, setup.dest_coords);
    }

    #[test]
    fn test_session_ack_encode_decode() {
        let handshake = vec![0xBB; 33]; // typical Noise IK msg2
        let ack = SessionAck::new(make_coords(&[7, 8, 0]))
            .with_handshake(handshake.clone());

        let encoded = ack.encode();
        assert_eq!(encoded[0], 0x01);

        let decoded = SessionAck::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.src_coords, ack.src_coords);
        assert_eq!(decoded.handshake_payload, handshake);
    }

    #[test]
    fn test_data_packet_encode_decode_minimal() {
        let data = vec![1, 2, 3, 4, 5];
        let packet = DataPacket::new(42, data.clone());

        let encoded = packet.encode();
        assert_eq!(encoded[0], 0x10); // msg_type
        assert_eq!(encoded[1], 0x00); // flags (no coords)

        let decoded = DataPacket::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.payload, data);
        assert_eq!(decoded.counter, 42);
        assert!(!decoded.flags.coords_present);
        assert!(decoded.src_coords.is_none());
        assert!(decoded.dest_coords.is_none());
    }

    #[test]
    fn test_data_packet_encode_decode_with_coords() {
        let data = vec![0xFF; 100];
        let src = make_coords(&[1, 2, 0]);
        let dest = make_coords(&[3, 4, 0]);
        let packet = DataPacket::new(1000, data.clone())
            .with_coords(src.clone(), dest.clone());

        let encoded = packet.encode();
        assert_eq!(encoded[0], 0x10);
        assert_eq!(encoded[1], 0x01); // COORDS_PRESENT

        let decoded = DataPacket::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.payload, data);
        assert_eq!(decoded.counter, 1000);
        assert!(decoded.flags.coords_present);
        assert_eq!(decoded.src_coords.unwrap(), src);
        assert_eq!(decoded.dest_coords.unwrap(), dest);
    }

    #[test]
    fn test_coords_required_encode_decode() {
        let err = CoordsRequired::new(make_node_addr(0xAA), make_node_addr(0xBB));

        let encoded = err.encode();
        assert_eq!(encoded.len(), COORDS_REQUIRED_SIZE);
        assert_eq!(encoded[0], 0x20);

        let decoded = CoordsRequired::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.dest_addr, err.dest_addr);
        assert_eq!(decoded.reporter, err.reporter);
    }

    #[test]
    fn test_path_broken_encode_decode_no_coords() {
        let err = PathBroken::new(make_node_addr(0xCC), make_node_addr(0xDD));

        let encoded = err.encode();
        assert_eq!(encoded[0], 0x21);

        let decoded = PathBroken::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.dest_addr, err.dest_addr);
        assert_eq!(decoded.reporter, err.reporter);
        assert!(decoded.last_known_coords.is_none());
    }

    #[test]
    fn test_path_broken_encode_decode_with_coords() {
        let coords = make_coords(&[0xCC, 0xDD, 0xEE]);
        let err = PathBroken::new(make_node_addr(0x11), make_node_addr(0x22))
            .with_last_coords(coords.clone());

        let encoded = err.encode();
        let decoded = PathBroken::decode(&encoded[1..]).unwrap();

        assert_eq!(decoded.dest_addr, err.dest_addr);
        assert_eq!(decoded.reporter, err.reporter);
        assert_eq!(decoded.last_known_coords.unwrap(), coords);
    }

    #[test]
    fn test_session_setup_decode_too_short() {
        assert!(SessionSetup::decode(&[]).is_err());
    }

    #[test]
    fn test_session_ack_decode_too_short() {
        assert!(SessionAck::decode(&[]).is_err());
    }

    #[test]
    fn test_data_packet_decode_too_short() {
        assert!(DataPacket::decode(&[]).is_err());
        assert!(DataPacket::decode(&[0x00]).is_err());
    }

    #[test]
    fn test_coords_required_decode_too_short() {
        assert!(CoordsRequired::decode(&[]).is_err());
        assert!(CoordsRequired::decode(&[0x00; 10]).is_err());
    }

    #[test]
    fn test_path_broken_decode_too_short() {
        assert!(PathBroken::decode(&[]).is_err());
        assert!(PathBroken::decode(&[0x00; 20]).is_err());
    }

    #[test]
    fn test_data_packet_large_payload() {
        let data = vec![0x42; 65000];
        let packet = DataPacket::new(0, data.clone());

        let encoded = packet.encode();
        let decoded = DataPacket::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.payload.len(), 65000);
        assert_eq!(decoded.payload, data);
    }

    #[test]
    fn test_session_setup_deep_coords() {
        // Depth-10 coordinate (11 entries: self + 10 ancestors)
        let addrs: Vec<u8> = (0..11).collect();
        let src = make_coords(&addrs);
        let dest = make_coords(&[20, 21, 22, 23, 24]);
        let setup = SessionSetup::new(src.clone(), dest.clone())
            .with_handshake(vec![0x55; 82]);

        let encoded = setup.encode();
        let decoded = SessionSetup::decode(&encoded[1..]).unwrap();

        assert_eq!(decoded.src_coords, src);
        assert_eq!(decoded.dest_coords, dest);
    }
}
