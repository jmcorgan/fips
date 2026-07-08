//! FSP Wire Format Parsing and Serialization
//!
//! Defines the FIPS session-layer wire format (FSP) for packet dispatch.
//! All FSP messages begin with a 4-byte common prefix followed by phase-specific
//! fields. Encrypted messages use a 12-byte cleartext header as AAD for AEAD,
//! and a 6-byte encrypted inner header containing timestamps and message type.
//!
//! ## Common Prefix (4 bytes)
//!
//! ```text
//! [ver+phase:1][flags:1][payload_len:2 LE]
//! ```
//!
//! ## DataPacket Port Multiplexing
//!
//! DataPacket (msg_type 0x10) payloads inside the AEAD envelope carry a 4-byte
//! port header for service dispatch:
//!
//! ```text
//! [src_port:2 LE][dst_port:2 LE][service payload...]
//! ```
//!
//! Port 256 (0x100) = IPv6 shim with header compression.
//!
//! ## Message Classes
//!
//! | Phase | U Flag | Type             | Description                       |
//! |-------|--------|------------------|-----------------------------------|
//! | 0x0   | 0      | Encrypted        | Post-handshake encrypted data     |
//! | 0x0   | 1      | Plaintext error  | CoordsRequired, PathBroken        |
//! | 0x1   | -      | Handshake msg1   | SessionSetup (Noise XK msg1)      |
//! | 0x2   | -      | Handshake msg2   | SessionAck (Noise XK msg2)        |
//! | 0x3   | -      | Handshake msg3   | SessionMsg3 (Noise XK msg3)       |

use crate::proto::Error;
use crate::proto::stp::{TreeCoordinate, decode_coords, decode_optional_coords, encode_coords};
use std::fmt;

// ============================================================================
// Constants
// ============================================================================

/// FSP protocol version (4 high bits of byte 0).
pub const FSP_VERSION: u8 = 0;

/// Phase value for established (encrypted or plaintext error) messages.
pub const FSP_PHASE_ESTABLISHED: u8 = 0x0;

/// Phase value for SessionSetup (Noise IK message 1).
pub const FSP_PHASE_MSG1: u8 = 0x1;

/// Phase value for SessionAck (Noise handshake message 2).
pub const FSP_PHASE_MSG2: u8 = 0x2;

/// Phase value for XK message 3 (initiator's encrypted static).
pub const FSP_PHASE_MSG3: u8 = 0x3;

/// Size of the common packet prefix (all FSP message types).
pub const FSP_COMMON_PREFIX_SIZE: usize = 4;

/// Size of the full encrypted message header (prefix + counter).
pub const FSP_HEADER_SIZE: usize = 12;

/// Size of the encrypted inner header (timestamp + msg_type + inner_flags).
pub const FSP_INNER_HEADER_SIZE: usize = 6;

/// AEAD authentication tag size (ChaCha20-Poly1305).
pub(crate) const TAG_SIZE: usize = 16;

/// Minimum size for an encrypted FSP message: header + tag (no plaintext).
pub const FSP_ENCRYPTED_MIN_SIZE: usize = FSP_HEADER_SIZE + TAG_SIZE; // 28 bytes

// FSP DataPacket port header constants.

/// Size of the FSP DataPacket port header (src_port + dst_port).
pub const FSP_PORT_HEADER_SIZE: usize = 4;

/// FSP port: IPv6 shim service.
pub const FSP_PORT_IPV6_SHIM: u16 = 256;

// Cleartext flag bit constants (byte 1 of common prefix, phase 0x0 only).

/// Coords Present — source and destination coordinates follow the header.
pub const FSP_FLAG_CP: u8 = 0x01;

/// Key Epoch — selects active key during rekeying.
#[allow(dead_code)]
pub const FSP_FLAG_K: u8 = 0x02;

/// Unencrypted — payload is plaintext (error signals).
pub const FSP_FLAG_U: u8 = 0x04;

// ============================================================================
// Common Prefix
// ============================================================================

/// Parsed FSP common packet prefix (first 4 bytes of every FSP message).
///
/// Wire format:
/// ```text
/// [ver(4bits)+phase(4bits)][flags:1][payload_len:2 LE]
/// ```
#[derive(Clone, Debug)]
pub struct FspCommonPrefix {
    /// Protocol version (high nibble of byte 0).
    #[cfg_attr(not(test), allow(dead_code))]
    pub version: u8,
    /// Session lifecycle phase (low nibble of byte 0).
    pub phase: u8,
    /// Per-message signal flags.
    pub flags: u8,
    /// Length of payload following the phase-specific header.
    #[cfg_attr(not(test), allow(dead_code))]
    pub payload_len: u16,
}

impl FspCommonPrefix {
    /// Parse a common prefix from the first 4 bytes of FSP message data.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < FSP_COMMON_PREFIX_SIZE {
            return None;
        }

        let version = data[0] >> 4;
        let phase = data[0] & 0x0F;
        let flags = data[1];
        let payload_len = u16::from_le_bytes([data[2], data[3]]);

        Some(Self {
            version,
            phase,
            flags,
            payload_len,
        })
    }

    /// Check if the Unencrypted flag is set.
    pub fn is_unencrypted(&self) -> bool {
        self.flags & FSP_FLAG_U != 0
    }

    /// Check if the Coords Present flag is set.
    pub fn has_coords(&self) -> bool {
        self.flags & FSP_FLAG_CP != 0
    }

    /// Encode the ver+phase byte.
    fn ver_phase_byte(version: u8, phase: u8) -> u8 {
        (version << 4) | (phase & 0x0F)
    }
}

// ============================================================================
// Encrypted Message Header
// ============================================================================

/// Parsed FSP encrypted message header (phase 0x0, U flag clear).
///
/// Wire format (12 bytes):
/// ```text
/// [ver+phase:1][flags:1][payload_len:2 LE][counter:8 LE]
/// ```
///
/// The full 12-byte header is used as AAD for the AEAD construction.
/// No receiver_idx — unlike FMP, FSP is end-to-end (dispatched by src_addr
/// from the SessionDatagram envelope, not by index).
#[derive(Clone, Debug)]
pub struct FspEncryptedHeader {
    /// Per-message flags (CP, K).
    pub flags: u8,
    /// Length of encrypted payload (excluding AEAD tag).
    #[cfg_attr(not(test), allow(dead_code))]
    pub payload_len: u16,
    /// Monotonic counter used as AEAD nonce.
    pub counter: u64,
    /// Raw 12-byte header for use as AEAD AAD.
    pub header_bytes: [u8; FSP_HEADER_SIZE],
}

impl FspEncryptedHeader {
    /// Parse an encrypted message header from FSP message data.
    ///
    /// Returns None if the data is too short or has wrong version/phase,
    /// or if the U flag is set (plaintext messages use a different path).
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < FSP_ENCRYPTED_MIN_SIZE {
            return None;
        }

        let version = data[0] >> 4;
        let phase = data[0] & 0x0F;

        if version != FSP_VERSION || phase != FSP_PHASE_ESTABLISHED {
            return None;
        }

        let flags = data[1];

        // U flag means plaintext — not an encrypted message
        if flags & FSP_FLAG_U != 0 {
            return None;
        }

        let payload_len = u16::from_le_bytes([data[2], data[3]]);
        let counter = u64::from_le_bytes([
            data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
        ]);

        let mut header_bytes = [0u8; FSP_HEADER_SIZE];
        header_bytes.copy_from_slice(&data[..FSP_HEADER_SIZE]);

        Some(Self {
            flags,
            payload_len,
            counter,
            header_bytes,
        })
    }

    /// Check if the Coords Present flag is set.
    pub fn has_coords(&self) -> bool {
        self.flags & FSP_FLAG_CP != 0
    }

    /// Offset where ciphertext (or coords if CP) begins in the original data.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn data_offset(&self) -> usize {
        FSP_HEADER_SIZE
    }
}

// ============================================================================
// Serialization Helpers
// ============================================================================

/// Build the 12-byte cleartext header for an encrypted FSP message.
///
/// Returns the header bytes for use as AEAD AAD.
pub fn build_fsp_header(counter: u64, flags: u8, payload_len: u16) -> [u8; FSP_HEADER_SIZE] {
    let mut header = [0u8; FSP_HEADER_SIZE];
    header[0] = FspCommonPrefix::ver_phase_byte(FSP_VERSION, FSP_PHASE_ESTABLISHED);
    header[1] = flags;
    header[2..4].copy_from_slice(&payload_len.to_le_bytes());
    header[4..12].copy_from_slice(&counter.to_le_bytes());
    header
}

/// Assemble a wire-format encrypted FSP message.
///
/// Format: `[header:12][ciphertext+tag]`
#[cfg_attr(not(test), allow(dead_code))]
pub fn build_fsp_encrypted(header: &[u8; FSP_HEADER_SIZE], ciphertext: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(FSP_HEADER_SIZE + ciphertext.len());
    packet.extend_from_slice(header);
    packet.extend_from_slice(ciphertext);
    packet
}

/// Build a 4-byte common prefix for a handshake message.
///
/// `phase` should be `FSP_PHASE_MSG1`, `FSP_PHASE_MSG2`, or `FSP_PHASE_MSG3`.
/// Flags are zero during handshake.
#[cfg_attr(not(test), allow(dead_code))]
pub fn build_fsp_handshake_prefix(phase: u8, payload_len: u16) -> [u8; FSP_COMMON_PREFIX_SIZE] {
    let mut prefix = [0u8; FSP_COMMON_PREFIX_SIZE];
    prefix[0] = FspCommonPrefix::ver_phase_byte(FSP_VERSION, phase);
    prefix[1] = 0x00; // flags must be zero during handshake
    prefix[2..4].copy_from_slice(&payload_len.to_le_bytes());
    prefix
}

/// Build a 4-byte common prefix for a plaintext error signal.
///
/// Sets phase 0x0 and U flag.
#[cfg_attr(not(test), allow(dead_code))]
pub fn build_fsp_error_prefix(payload_len: u16) -> [u8; FSP_COMMON_PREFIX_SIZE] {
    let mut prefix = [0u8; FSP_COMMON_PREFIX_SIZE];
    prefix[0] = FspCommonPrefix::ver_phase_byte(FSP_VERSION, FSP_PHASE_ESTABLISHED);
    prefix[1] = FSP_FLAG_U;
    prefix[2..4].copy_from_slice(&payload_len.to_le_bytes());
    prefix
}

// ============================================================================
// Inner Header Helpers
// ============================================================================

/// Prepend the 6-byte FSP inner header to a message payload.
///
/// Inner header: `[timestamp:4 LE][msg_type:1][inner_flags:1]`
///
/// The caller provides the message-type-specific payload (e.g., application
/// data for msg_type 0x10, report fields for SenderReport). This function
/// prepends the inner header.
pub fn fsp_prepend_inner_header(
    timestamp_ms: u32,
    msg_type: u8,
    inner_flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FSP_INNER_HEADER_SIZE + payload.len());
    buf.extend_from_slice(&timestamp_ms.to_le_bytes());
    buf.push(msg_type);
    buf.push(inner_flags);
    buf.extend_from_slice(payload);
    buf
}

/// Strip the 6-byte FSP inner header from a decrypted payload.
///
/// Returns `(timestamp, msg_type, inner_flags, &rest)` or None if too short.
pub fn fsp_strip_inner_header(plaintext: &[u8]) -> Option<(u32, u8, u8, &[u8])> {
    if plaintext.len() < FSP_INNER_HEADER_SIZE {
        return None;
    }
    let timestamp = u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
    let msg_type = plaintext[4];
    let inner_flags = plaintext[5];
    Some((
        timestamp,
        msg_type,
        inner_flags,
        &plaintext[FSP_INNER_HEADER_SIZE..],
    ))
}

// ============================================================================
// Coordinate Parsing (for transit nodes and receive path)
// ============================================================================

/// Parse source and destination coordinates from the cleartext section
/// of an encrypted FSP message when the CP flag is set.
///
/// Coordinates appear between the 12-byte header and the ciphertext:
/// `[src_coords_count:2 LE][src_coords:16×n][dest_coords_count:2 LE][dest_coords:16×m]`
///
/// Returns `(src_coords, dest_coords, bytes_consumed)`.
pub fn parse_encrypted_coords(
    data: &[u8],
) -> Result<(Option<TreeCoordinate>, Option<TreeCoordinate>, usize), Error> {
    let (src_coords, src_consumed) = decode_optional_coords(data)?;
    let (dest_coords, dest_consumed) = decode_optional_coords(&data[src_consumed..])?;
    Ok((src_coords, dest_coords, src_consumed + dest_consumed))
}

// ============================================================================
// Session Layer Message Types
// ============================================================================

/// FSP encrypted-inner message type identifiers (`0x10`–`0x1F`).
///
/// These messages are carried end-to-end encrypted inside the FSP AEAD
/// envelope; the type is the `msg_type` byte of the encrypted inner header.
/// The plaintext link-layer error signals (`0x20`–`0x2F`) are a separate
/// registry — [`RoutingSignalType`](crate::proto::routing::RoutingSignalType)
/// — since they are dispatched on the cleartext (U-flag) path with no session.
///
/// Handshake messages (SessionSetup, SessionAck, SessionMsg3) are **not**
/// identified by a message-type byte; they are dispatched by the FSP phase
/// nibble in the common prefix (0x1, 0x2, 0x3 respectively). The 0x00-0x0F
/// range is therefore unallocated in this enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionMessageType {
    // Session establishment (0x00-0x0F)
    /// Session setup with coordinates (warms router caches).
    SessionSetup = 0x00,
    /// Session acknowledgement.
    SessionAck = 0x01,

    // Data and metrics (0x10-0x1F) — encrypted, inner header msg_type
    /// Port-multiplexed service payload: `[src_port:2 LE][dst_port:2 LE][service data...]`.
    /// Port 256 = IPv6 shim (compressed header). Receiver dispatches by dst_port.
    DataPacket = 0x10,
    /// MMP sender report (metrics from sender to receiver).
    SenderReport = 0x11,
    /// MMP receiver report (metrics from receiver to sender).
    ReceiverReport = 0x12,
    /// Path MTU notification (discovered path MTU).
    PathMtuNotification = 0x13,
    /// Standalone coordinate cache warming (empty body, coords in CP flag).
    CoordsWarmup = 0x14,
}

impl SessionMessageType {
    /// Try to convert from a byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(SessionMessageType::SessionSetup),
            0x01 => Some(SessionMessageType::SessionAck),
            0x10 => Some(SessionMessageType::DataPacket),
            0x11 => Some(SessionMessageType::SenderReport),
            0x12 => Some(SessionMessageType::ReceiverReport),
            0x13 => Some(SessionMessageType::PathMtuNotification),
            0x14 => Some(SessionMessageType::CoordsWarmup),
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
            SessionMessageType::SenderReport => "SenderReport",
            SessionMessageType::ReceiverReport => "ReceiverReport",
            SessionMessageType::PathMtuNotification => "PathMtuNotification",
            SessionMessageType::CoordsWarmup => "CoordsWarmup",
        };
        write!(f, "{}", name)
    }
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
// FSP Packet Flags
// ============================================================================

/// FSP common prefix flags (cleartext, in outer header).
///
/// | Bit | Name | Description                                    |
/// |-----|------|------------------------------------------------|
/// | 0   | CP   | Coords present between header and ciphertext   |
/// | 1   | K    | Key epoch (for rekeying)                       |
/// | 2   | U    | Unencrypted payload (error signals)            |
/// | 3-7 |      | Reserved                                       |
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FspFlags {
    /// Coordinates present between header and ciphertext.
    pub coords_present: bool,
    /// Key epoch bit for rekeying.
    pub key_epoch: bool,
    /// Unencrypted payload (plaintext error signals from transit routers).
    pub unencrypted: bool,
}

#[cfg_attr(not(test), allow(dead_code))]
#[allow(clippy::wrong_self_convention)]
impl FspFlags {
    /// Create default flags (all clear).
    pub fn new() -> Self {
        Self::default()
    }

    /// Convert to a byte.
    pub fn to_byte(&self) -> u8 {
        let mut flags = 0u8;
        if self.coords_present {
            flags |= 0x01;
        }
        if self.key_epoch {
            flags |= 0x02;
        }
        if self.unencrypted {
            flags |= 0x04;
        }
        flags
    }

    /// Convert from a byte.
    pub fn from_byte(byte: u8) -> Self {
        Self {
            coords_present: byte & 0x01 != 0,
            key_epoch: byte & 0x02 != 0,
            unencrypted: byte & 0x04 != 0,
        }
    }
}

/// FSP inner header flags (encrypted, inside AEAD envelope).
///
/// | Bit | Name | Description                     |
/// |-----|------|---------------------------------|
/// | 0-7 |      | Reserved (all zero)             |
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FspInnerFlags;

#[allow(clippy::wrong_self_convention)]
impl FspInnerFlags {
    /// Create default inner flags (all clear).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new() -> Self {
        Self
    }

    /// Convert to a byte.
    pub fn to_byte(&self) -> u8 {
        0x00
    }

    /// Convert from a byte.
    pub fn from_byte(_byte: u8) -> Self {
        Self
    }
}

// ============================================================================
// Session Setup
// ============================================================================

/// Session setup to establish cached coordinate state.
///
/// Carried inside a SessionDatagram envelope which provides src_addr and
/// dest_addr. The SessionSetup payload contains coordinates, session flags,
/// and the Noise XX handshake message for session establishment.
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
/// | ...    | handshake_payload| variable| Noise XX msg1 (33 bytes — ephemeral key)    |
#[derive(Clone, Debug)]
pub struct SessionSetup {
    /// Source coordinates (for return path caching).
    pub src_coords: TreeCoordinate,
    /// Destination coordinates (for forward routing).
    pub dest_coords: TreeCoordinate,
    /// Session options.
    pub flags: SessionFlags,
    /// Noise XX handshake message 1.
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

    /// Encode as wire format (4-byte FSP prefix + flags + coords + handshake).
    ///
    /// The 4-byte prefix: `[ver_phase:1][flags:1][payload_len:2 LE]`
    /// where ver_phase = 0x01 (version 0, phase MSG1).
    pub fn encode(&self) -> Vec<u8> {
        // Build body first to compute payload_len
        let mut body = Vec::new();
        body.push(self.flags.to_byte());
        encode_coords(&self.src_coords, &mut body);
        encode_coords(&self.dest_coords, &mut body);
        let hs_len = self.handshake_payload.len() as u16;
        body.extend_from_slice(&hs_len.to_le_bytes());
        body.extend_from_slice(&self.handshake_payload);

        // Prepend 4-byte FSP common prefix
        let payload_len = body.len() as u16;
        let mut buf = Vec::with_capacity(4 + body.len());
        buf.push(0x01); // version 0, phase 0x1 (MSG1)
        buf.push(0x00); // flags (must be zero for handshake)
        buf.extend_from_slice(&payload_len.to_le_bytes());
        buf.extend_from_slice(&body);
        buf
    }

    /// Decode from wire format (after 4-byte FSP prefix has been consumed).
    pub fn decode(payload: &[u8]) -> Result<Self, Error> {
        if payload.is_empty() {
            return Err(Error::MessageTooShort {
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
            return Err(Error::MessageTooShort {
                expected: offset + 2,
                got: payload.len(),
            });
        }
        let hs_len = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;

        if payload.len() < offset + hs_len {
            return Err(Error::MessageTooShort {
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
/// dest_addr. The SessionAck payload contains both the acknowledger's and
/// initiator's coordinates for route cache warming (ensuring return-path
/// transit nodes can route independently of the forward path) and the Noise
/// XX handshake response.
///
/// ## Wire Format
///
/// | Offset | Field            | Size    | Description                         |
/// |--------|------------------|---------|-------------------------------------|
/// | 0      | msg_type         | 1 byte  | 0x01                                |
/// | 1      | flags            | 1 byte  | Reserved                            |
/// | 2      | src_coords_count | 2 bytes | u16 LE                              |
/// | 4      | src_coords       | 16 × n  | Acknowledger's coords (for caching) |
/// | ...    | dest_coords_count| 2 bytes | u16 LE                              |
/// | ...    | dest_coords      | 16 × m  | Initiator's coords (for return path)|
/// | ...    | handshake_len    | 2 bytes  | u16 LE, Noise payload length        |
/// | ...    | handshake_payload| variable| Noise XX msg2 (106+ bytes — ephemeral + static + epoch + negotiation)    |
#[derive(Clone, Debug)]
pub struct SessionAck {
    /// Acknowledger's coordinates.
    pub src_coords: TreeCoordinate,
    /// Initiator's coordinates (for return-path cache warming).
    pub dest_coords: TreeCoordinate,
    /// Reserved flags byte (for forward compatibility).
    pub flags: u8,
    /// Noise XX handshake message 2.
    pub handshake_payload: Vec<u8>,
}

impl SessionAck {
    /// Create a new session acknowledgement.
    pub fn new(src_coords: TreeCoordinate, dest_coords: TreeCoordinate) -> Self {
        Self {
            src_coords,
            dest_coords,
            flags: 0,
            handshake_payload: Vec::new(),
        }
    }

    /// Set the Noise handshake payload.
    pub fn with_handshake(mut self, payload: Vec<u8>) -> Self {
        self.handshake_payload = payload;
        self
    }

    /// Encode as wire format (4-byte FSP prefix + flags + coords + handshake).
    ///
    /// The 4-byte prefix: `[ver_phase:1][flags:1][payload_len:2 LE]`
    /// where ver_phase = 0x02 (version 0, phase MSG2).
    pub fn encode(&self) -> Vec<u8> {
        // Build body first to compute payload_len
        let mut body = Vec::new();
        body.push(self.flags);
        encode_coords(&self.src_coords, &mut body);
        encode_coords(&self.dest_coords, &mut body);
        let hs_len = self.handshake_payload.len() as u16;
        body.extend_from_slice(&hs_len.to_le_bytes());
        body.extend_from_slice(&self.handshake_payload);

        // Prepend 4-byte FSP common prefix
        let payload_len = body.len() as u16;
        let mut buf = Vec::with_capacity(4 + body.len());
        buf.push(0x02); // version 0, phase 0x2 (MSG2)
        buf.push(0x00); // flags (must be zero for handshake)
        buf.extend_from_slice(&payload_len.to_le_bytes());
        buf.extend_from_slice(&body);
        buf
    }

    /// Decode from wire format (after 4-byte FSP prefix has been consumed).
    pub fn decode(payload: &[u8]) -> Result<Self, Error> {
        if payload.is_empty() {
            return Err(Error::MessageTooShort {
                expected: 1,
                got: 0,
            });
        }
        let flags = payload[0];
        let mut offset = 1;

        let (src_coords, consumed) = decode_coords(&payload[offset..])?;
        offset += consumed;

        let (dest_coords, consumed) = decode_coords(&payload[offset..])?;
        offset += consumed;

        if payload.len() < offset + 2 {
            return Err(Error::MessageTooShort {
                expected: offset + 2,
                got: payload.len(),
            });
        }
        let hs_len = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;

        if payload.len() < offset + hs_len {
            return Err(Error::MessageTooShort {
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
// Session Msg3 (XX Handshake Message 3)
// ============================================================================

/// XX handshake message 3 (initiator -> responder).
///
/// Carries the initiator's encrypted static key and epoch. Sent by the
/// initiator after receiving msg2. The responder learns the initiator's
/// identity from this message.
///
/// ## Wire Format
///
/// | Offset | Field            | Size    | Description                         |
/// |--------|------------------|---------|-------------------------------------|
/// | 0      | flags            | 1 byte  | Reserved                            |
/// | 1      | handshake_len    | 2 bytes | u16 LE, Noise payload length        |
/// | 3      | handshake_payload| variable| Noise XX msg3 (73 bytes typical)    |
#[derive(Clone, Debug)]
pub struct SessionMsg3 {
    /// Reserved flags byte.
    pub flags: u8,
    /// Noise XX handshake message 3.
    pub handshake_payload: Vec<u8>,
}

impl SessionMsg3 {
    /// Create a new SessionMsg3 with the given handshake payload.
    pub fn new(handshake_payload: Vec<u8>) -> Self {
        Self {
            flags: 0,
            handshake_payload,
        }
    }

    /// Encode as wire format (4-byte FSP prefix + flags + handshake).
    ///
    /// The 4-byte prefix: `[ver_phase:1][flags:1][payload_len:2 LE]`
    /// where ver_phase = 0x03 (version 0, phase MSG3).
    pub fn encode(&self) -> Vec<u8> {
        // Build body first to compute payload_len
        let mut body = Vec::new();
        body.push(self.flags);
        let hs_len = self.handshake_payload.len() as u16;
        body.extend_from_slice(&hs_len.to_le_bytes());
        body.extend_from_slice(&self.handshake_payload);

        // Prepend 4-byte FSP common prefix
        let payload_len = body.len() as u16;
        let mut buf = Vec::with_capacity(4 + body.len());
        buf.push(0x03); // version 0, phase 0x3 (MSG3)
        buf.push(0x00); // flags (must be zero for handshake)
        buf.extend_from_slice(&payload_len.to_le_bytes());
        buf.extend_from_slice(&body);
        buf
    }

    /// Decode from wire format (after 4-byte FSP prefix has been consumed).
    pub fn decode(payload: &[u8]) -> Result<Self, Error> {
        if payload.is_empty() {
            return Err(Error::MessageTooShort {
                expected: 1,
                got: 0,
            });
        }
        let flags = payload[0];
        let mut offset = 1;

        if payload.len() < offset + 2 {
            return Err(Error::MessageTooShort {
                expected: offset + 2,
                got: payload.len(),
            });
        }
        let hs_len = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;

        if payload.len() < offset + hs_len {
            return Err(Error::MessageTooShort {
                expected: offset + hs_len,
                got: payload.len(),
            });
        }
        let handshake_payload = payload[offset..offset + hs_len].to_vec();

        Ok(Self {
            flags,
            handshake_payload,
        })
    }
}
