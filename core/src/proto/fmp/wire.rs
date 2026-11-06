//! FMP link-framing messages and link-layer wire codec.
//!
//! The Noise IK handshake message-type discriminants and the orderly
//! disconnect codec, per the wire-migrates-with-subsystem policy.
//! `Disconnect::encode` reads the shared `LinkMessageType::Disconnect` catalog
//! variant (a downward `proto -> proto` dependency); the catalog itself lives
//! in `crate::proto::link`.
//!
//! This module also carries the FMP mesh-layer packet-dispatch wire format
//! (the common prefix, encrypted/msg1/msg2 headers, and the `build_*`/
//! inner-header codec functions), relocated from `node/wire.rs` so all FMP
//! wire lives with its subsystem. See the "FMP link wire framing" section
//! banner below for the packet-type layout.

use crate::noise::{HANDSHAKE_MSG1_SIZE, HANDSHAKE_MSG2_SIZE, TAG_SIZE};
use crate::proto::Error;
use crate::proto::codec::Reader;
use crate::proto::link::LinkMessageType;
use crate::utils::index::SessionIndex;
use ::core::fmt;
use alloc::vec::Vec;

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

/// Reason for an orderly disconnect notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DisconnectReason {
    /// Normal shutdown (operator requested).
    Shutdown = 0x00,
    /// Restarting (may reconnect soon).
    Restart = 0x01,
    /// Protocol error encountered.
    ProtocolError = 0x02,
    /// Transport failure.
    TransportFailure = 0x03,
    /// Resource exhaustion (memory, connections).
    ResourceExhaustion = 0x04,
    /// Authentication or security policy violation.
    SecurityViolation = 0x05,
    /// Configuration change (peer removed from config).
    ConfigurationChange = 0x06,
    /// Timeout or keepalive failure.
    Timeout = 0x07,
    /// Unspecified reason.
    Other = 0xFF,
}

impl DisconnectReason {
    /// Try to convert from a byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(DisconnectReason::Shutdown),
            0x01 => Some(DisconnectReason::Restart),
            0x02 => Some(DisconnectReason::ProtocolError),
            0x03 => Some(DisconnectReason::TransportFailure),
            0x04 => Some(DisconnectReason::ResourceExhaustion),
            0x05 => Some(DisconnectReason::SecurityViolation),
            0x06 => Some(DisconnectReason::ConfigurationChange),
            0x07 => Some(DisconnectReason::Timeout),
            0xFF => Some(DisconnectReason::Other),
            _ => None,
        }
    }

    /// Convert to a byte.
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for DisconnectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            DisconnectReason::Shutdown => "Shutdown",
            DisconnectReason::Restart => "Restart",
            DisconnectReason::ProtocolError => "ProtocolError",
            DisconnectReason::TransportFailure => "TransportFailure",
            DisconnectReason::ResourceExhaustion => "ResourceExhaustion",
            DisconnectReason::SecurityViolation => "SecurityViolation",
            DisconnectReason::ConfigurationChange => "ConfigurationChange",
            DisconnectReason::Timeout => "Timeout",
            DisconnectReason::Other => "Other",
        };
        write!(f, "{}", name)
    }
}

/// Orderly disconnect notification sent before closing a peer link.
///
/// Sent as a link-layer message (type 0x50) inside an encrypted frame.
/// Allows the receiving peer to immediately clean up state rather than
/// waiting for timeout-based detection.
///
/// ## Wire Format
///
/// | Offset | Field    | Size   | Notes                  |
/// |--------|----------|--------|------------------------|
/// | 0      | msg_type | 1 byte | 0x50                   |
/// | 1      | reason   | 1 byte | DisconnectReason value |
#[derive(Clone, Debug)]
pub struct Disconnect {
    /// Reason for disconnection.
    pub reason: DisconnectReason,
}

impl Disconnect {
    /// Create a new Disconnect message.
    pub fn new(reason: DisconnectReason) -> Self {
        Self { reason }
    }

    /// Encode as link-layer plaintext (msg_type + reason).
    pub fn encode(&self) -> [u8; 2] {
        [LinkMessageType::Disconnect.to_byte(), self.reason.to_byte()]
    }

    /// Decode from link-layer payload (after msg_type byte has been consumed).
    pub fn decode(payload: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(payload);
        let reason =
            DisconnectReason::from_byte(reader.read_u8()?).unwrap_or(DisconnectReason::Other);
        Ok(Self { reason })
    }
}

// ============================================================================
// FMP link wire framing (relocated from node/wire.rs)
// ============================================================================
//
// The FIPS mesh-layer wire format (FMP) for packet dispatch. All packets begin
// with a 4-byte common prefix followed by phase-specific fields.
//
// Common Prefix (4 bytes):
//
//     [ver+phase:1][flags:1][payload_len:2 LE]
//
// Packet Types:
//
//   | Phase | Type            | Size       | Description                    |
//   |-------|-----------------|------------|--------------------------------|
//   | 0x0   | Encrypted frame | 32+ bytes  | Post-handshake encrypted data  |
//   | 0x1   | Noise IK msg1   | 114 bytes  | Handshake initiation           |
//   | 0x2   | Noise IK msg2   | 69 bytes   | Handshake response             |

// ============================================================================
// Constants
// ============================================================================

/// FMP protocol version (4 high bits of byte 0).
pub const FMP_VERSION: u8 = 0;

/// Phase value for established (encrypted) frames.
pub const PHASE_ESTABLISHED: u8 = 0x0;

/// Phase value for Noise IK message 1 (handshake initiation).
pub const PHASE_MSG1: u8 = 0x1;

/// Phase value for Noise IK message 2 (handshake response).
pub const PHASE_MSG2: u8 = 0x2;

/// Size of the common packet prefix (all packet types).
pub const COMMON_PREFIX_SIZE: usize = 4;

/// Size of the full established frame header (prefix + receiver_idx + counter).
pub const ESTABLISHED_HEADER_SIZE: usize = 16;

/// Size of Noise IK message 1 wire packet: prefix + sender_idx + noise_msg1.
pub const MSG1_WIRE_SIZE: usize = COMMON_PREFIX_SIZE + 4 + HANDSHAKE_MSG1_SIZE; // 114 bytes

/// Size of Noise IK message 2 wire packet: prefix + sender_idx + receiver_idx + noise_msg2.
pub const MSG2_WIRE_SIZE: usize = COMMON_PREFIX_SIZE + 4 + 4 + HANDSHAKE_MSG2_SIZE; // 69 bytes

/// Minimum size for encrypted frame: header + tag (no plaintext).
pub const ENCRYPTED_MIN_SIZE: usize = ESTABLISHED_HEADER_SIZE + TAG_SIZE; // 32 bytes

/// Size of the encrypted inner header (timestamp + message type).
pub const INNER_HEADER_SIZE: usize = 5;

/// Bytes an established frame adds around a link message counted from its
/// type byte: the established header, the 4-byte inner timestamp (the inner
/// header less its type byte, which is the link message's own first byte)
/// and the AEAD tag, 36 bytes. A transport link MTU less this is the largest
/// link message the transport carries in one frame.
pub const FRAME_OVERHEAD: usize = ESTABLISHED_HEADER_SIZE + (INNER_HEADER_SIZE - 1) + TAG_SIZE;

// Flag bit constants (byte 1 of common prefix, meaningful only for phase 0x0).
// Reserved for upcoming rekeying, congestion signaling, and RTT measurement.
#[allow(dead_code)]
/// Key epoch flag — selects active key during rekeying.
pub const FLAG_KEY_EPOCH: u8 = 0x01;
#[allow(dead_code)]
/// Congestion Experienced echo flag.
pub const FLAG_CE: u8 = 0x02;
#[allow(dead_code)]
/// Spin bit for RTT measurement.
pub const FLAG_SP: u8 = 0x04;

// ============================================================================
// Wire Length Validation
// ============================================================================

/// Expected `payload_len` for a packet of `phase` and total wire length
/// `total`, or `None` if the phase carries no fixed relationship.
///
/// Each frame kind states its own relationship; there is no single shared
/// convention. The handshake frames count everything after the 4-byte common
/// prefix. The established frame counts only the inner plaintext, excluding
/// both the 16-byte header and the AEAD tag, which is what
/// [`CommonPrefix::payload_len`] documents.
///
/// The handshake arms are built from the same constants the encoders use; the
/// established arm is not, since no encoder reads `ENCRYPTED_MIN_SIZE`. Neither
/// shape stops a one-sided edit from making the two disagree, which is what the
/// tests below exist to catch.
///
/// A `None` from the established arm means "no fixed relationship", so a caller
/// skips such a frame rather than rejecting it. That is the safe direction: a
/// truncating cast here would produce a false rejection instead.
pub fn expected_payload_len(phase: u8, total: usize) -> Option<u16> {
    match phase {
        PHASE_MSG1 => Some((MSG1_WIRE_SIZE - COMMON_PREFIX_SIZE) as u16),
        PHASE_MSG2 => Some((MSG2_WIRE_SIZE - COMMON_PREFIX_SIZE) as u16),
        PHASE_ESTABLISHED => total
            .checked_sub(ENCRYPTED_MIN_SIZE)
            .and_then(|n| u16::try_from(n).ok()),
        _ => None,
    }
}

// ============================================================================
// Common Prefix
// ============================================================================

/// Parsed common packet prefix (first 4 bytes of every FMP packet).
///
/// Wire format:
/// ```text
/// [ver(4bits)+phase(4bits)][flags:1][payload_len:2 LE]
/// ```
#[derive(Clone, Debug)]
pub struct CommonPrefix {
    /// Protocol version (high nibble of byte 0).
    pub version: u8,
    /// Session lifecycle phase (low nibble of byte 0).
    pub phase: u8,
    /// Per-packet signal flags (meaningful only for phase 0x0).
    #[allow(dead_code)]
    pub flags: u8,
    /// Length of payload following the phase-specific header (excludes AEAD tag).
    #[allow(dead_code)]
    pub payload_len: u16,
}

impl CommonPrefix {
    /// Parse a common prefix from the first 4 bytes of packet data.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < COMMON_PREFIX_SIZE {
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

    /// Encode the ver+phase byte.
    fn ver_phase_byte(version: u8, phase: u8) -> u8 {
        (version << 4) | (phase & 0x0F)
    }
}

// ============================================================================
// Encrypted Frame Header
// ============================================================================

/// Parsed established frame header (phase 0x0).
///
/// Wire format (16 bytes):
/// ```text
/// [ver+phase:1][flags:1][payload_len:2 LE][receiver_idx:4 LE][counter:8 LE]
/// ```
///
/// The full 16-byte header is used as AAD for the AEAD construction.
#[derive(Clone, Debug)]
pub struct EncryptedHeader {
    /// Per-packet flags (K, CE, SP).
    #[allow(dead_code)]
    pub flags: u8,
    /// Length of encrypted payload (excluding AEAD tag).
    #[allow(dead_code)]
    pub payload_len: u16,
    /// Session index chosen by the receiver (for O(1) lookup).
    pub receiver_idx: SessionIndex,
    /// Monotonic counter used as AEAD nonce.
    pub counter: u64,
    /// Raw 16-byte header for use as AEAD AAD.
    pub header_bytes: [u8; ESTABLISHED_HEADER_SIZE],
}

impl EncryptedHeader {
    /// Parse an established frame header from packet data.
    ///
    /// Returns None if the packet is too short or has wrong version/phase.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < ENCRYPTED_MIN_SIZE {
            return None;
        }

        let version = data[0] >> 4;
        let phase = data[0] & 0x0F;

        if version != FMP_VERSION || phase != PHASE_ESTABLISHED {
            return None;
        }

        let flags = data[1];
        let payload_len = u16::from_le_bytes([data[2], data[3]]);
        let receiver_idx = SessionIndex::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let counter = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);

        let mut header_bytes = [0u8; ESTABLISHED_HEADER_SIZE];
        header_bytes.copy_from_slice(&data[..ESTABLISHED_HEADER_SIZE]);

        Some(Self {
            flags,
            payload_len,
            receiver_idx,
            counter,
            header_bytes,
        })
    }

    /// Offset where ciphertext begins in the original packet.
    pub fn ciphertext_offset(&self) -> usize {
        ESTABLISHED_HEADER_SIZE
    }

    /// Get the ciphertext slice from the original packet.
    #[cfg(test)]
    pub fn ciphertext<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[ESTABLISHED_HEADER_SIZE..]
    }
}

// ============================================================================
// Msg1 Header
// ============================================================================

/// Parsed Noise IK message 1 header (phase 0x1).
///
/// Wire format (114 bytes):
/// ```text
/// [0x01][0x00][payload_len:2 LE][sender_idx:4 LE][noise_msg1:106]
/// ```
#[derive(Clone, Debug)]
pub struct Msg1Header {
    /// Session index chosen by the sender (becomes receiver_idx for responses).
    pub sender_idx: SessionIndex,
    /// Offset where Noise msg1 payload begins.
    pub noise_msg1_offset: usize,
}

impl Msg1Header {
    /// Parse a msg1 header from packet data.
    ///
    /// Returns None if the packet has wrong size or version/phase.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != MSG1_WIRE_SIZE {
            return None;
        }

        let version = data[0] >> 4;
        let phase = data[0] & 0x0F;

        if version != FMP_VERSION || phase != PHASE_MSG1 {
            return None;
        }

        // flags must be zero during handshake
        if data[1] != 0 {
            return None;
        }

        let sender_idx = SessionIndex::from_le_bytes([data[4], data[5], data[6], data[7]]);

        Some(Self {
            sender_idx,
            noise_msg1_offset: COMMON_PREFIX_SIZE + 4, // 8
        })
    }

    /// Get the Noise msg1 payload from the original packet.
    #[cfg(test)]
    pub fn noise_msg1<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.noise_msg1_offset..]
    }
}

// ============================================================================
// Msg2 Header
// ============================================================================

/// Parsed Noise IK message 2 header (phase 0x2).
///
/// Wire format (69 bytes):
/// ```text
/// [0x02][0x00][payload_len:2 LE][sender_idx:4 LE][receiver_idx:4 LE][noise_msg2:57]
/// ```
#[derive(Clone, Debug)]
pub struct Msg2Header {
    /// Session index chosen by the responder.
    pub sender_idx: SessionIndex,
    /// Echo of the initiator's sender_idx from msg1.
    pub receiver_idx: SessionIndex,
    /// Offset where Noise msg2 payload begins.
    pub noise_msg2_offset: usize,
}

impl Msg2Header {
    /// Parse a msg2 header from packet data.
    ///
    /// Returns None if the packet has wrong size or version/phase.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != MSG2_WIRE_SIZE {
            return None;
        }

        let version = data[0] >> 4;
        let phase = data[0] & 0x0F;

        if version != FMP_VERSION || phase != PHASE_MSG2 {
            return None;
        }

        // flags must be zero during handshake
        if data[1] != 0 {
            return None;
        }

        let sender_idx = SessionIndex::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let receiver_idx = SessionIndex::from_le_bytes([data[8], data[9], data[10], data[11]]);

        Some(Self {
            sender_idx,
            receiver_idx,
            noise_msg2_offset: COMMON_PREFIX_SIZE + 4 + 4, // 12
        })
    }

    /// Get the Noise msg2 payload from the original packet.
    #[cfg(test)]
    pub fn noise_msg2<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.noise_msg2_offset..]
    }
}

// ============================================================================
// Serialization Helpers
// ============================================================================

/// Build a wire-format msg1 packet.
///
/// Format: `[0x01][0x00][payload_len:2 LE][sender_idx:4 LE][noise_msg1:106]`
pub fn build_msg1(sender_idx: SessionIndex, noise_msg1: &[u8]) -> Vec<u8> {
    debug_assert_eq!(noise_msg1.len(), HANDSHAKE_MSG1_SIZE);

    let payload_len = (4 + noise_msg1.len()) as u16; // sender_idx + noise_msg1

    let mut packet = Vec::with_capacity(MSG1_WIRE_SIZE);
    packet.push(CommonPrefix::ver_phase_byte(FMP_VERSION, PHASE_MSG1));
    packet.push(0x00); // flags must be zero
    packet.extend_from_slice(&payload_len.to_le_bytes());
    packet.extend_from_slice(&sender_idx.to_le_bytes());
    packet.extend_from_slice(noise_msg1);
    packet
}

/// Build a wire-format msg2 packet.
///
/// Format: `[0x02][0x00][payload_len:2 LE][sender_idx:4 LE][receiver_idx:4 LE][noise_msg2:57]`
pub fn build_msg2(
    sender_idx: SessionIndex,
    receiver_idx: SessionIndex,
    noise_msg2: &[u8],
) -> Vec<u8> {
    debug_assert_eq!(noise_msg2.len(), HANDSHAKE_MSG2_SIZE);

    let payload_len = (4 + 4 + noise_msg2.len()) as u16; // sender + receiver + noise

    let mut packet = Vec::with_capacity(MSG2_WIRE_SIZE);
    packet.push(CommonPrefix::ver_phase_byte(FMP_VERSION, PHASE_MSG2));
    packet.push(0x00); // flags must be zero
    packet.extend_from_slice(&payload_len.to_le_bytes());
    packet.extend_from_slice(&sender_idx.to_le_bytes());
    packet.extend_from_slice(&receiver_idx.to_le_bytes());
    packet.extend_from_slice(noise_msg2);
    packet
}

/// Build the 16-byte outer header for an established frame.
///
/// Returns the header bytes (for use as AAD) separately from the construction.
pub fn build_established_header(
    receiver_idx: SessionIndex,
    counter: u64,
    flags: u8,
    payload_len: u16,
) -> [u8; ESTABLISHED_HEADER_SIZE] {
    let mut header = [0u8; ESTABLISHED_HEADER_SIZE];
    header[0] = CommonPrefix::ver_phase_byte(FMP_VERSION, PHASE_ESTABLISHED);
    header[1] = flags;
    header[2..4].copy_from_slice(&payload_len.to_le_bytes());
    header[4..8].copy_from_slice(&receiver_idx.to_le_bytes());
    header[8..16].copy_from_slice(&counter.to_le_bytes());
    header
}

/// Build a wire-format encrypted frame.
///
/// Format: `[header:16][ciphertext+tag]`
///
/// The header is constructed from the parameters and used as AAD during
/// encryption. The caller should use `build_established_header` to construct
/// the header, encrypt with it as AAD, then call this to assemble the packet.
pub fn build_encrypted(header: &[u8; ESTABLISHED_HEADER_SIZE], ciphertext: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + ciphertext.len());
    packet.extend_from_slice(header);
    packet.extend_from_slice(ciphertext);
    packet
}

// ============================================================================
// Inner Header Helpers
// ============================================================================

/// Prepend the 5-byte inner header (timestamp + msg_type) to a link message.
///
/// The caller provides the original plaintext starting with `[msg_type][payload...]`.
/// This prepends `[timestamp:4 LE]` before the msg_type byte.
pub fn prepend_inner_header(timestamp_ms: u32, plaintext: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + plaintext.len());
    buf.extend_from_slice(&timestamp_ms.to_le_bytes());
    buf.extend_from_slice(plaintext);
    buf
}

/// Strip the 4-byte timestamp from a decrypted inner payload.
///
/// Returns `(timestamp, &payload_starting_at_msg_type)` or None if too short.
pub fn strip_inner_header(plaintext: &[u8]) -> Option<(u32, &[u8])> {
    if plaintext.len() < INNER_HEADER_SIZE {
        return None;
    }
    let timestamp = u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
    Some((timestamp, &plaintext[4..]))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "tests/wire_private.rs"]
mod tests;
