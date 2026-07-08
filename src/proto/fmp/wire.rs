//! FMP wire codec: XX handshake framing, orderly disconnect, and the
//! protocol-negotiation payload.
//!
//! The Noise XX handshake message-type discriminants and the orderly
//! disconnect codec, relocated from `protocol::link`, plus the
//! negotiation-payload codec relocated from `protocol::negotiation`, per the
//! wire-migrates-with-subsystem policy. `Disconnect::encode` reads the shared
//! `LinkMessageType::Disconnect` catalog variant (a downward `proto ->
//! protocol` dependency); the catalog itself stays in `protocol::link`. The
//! negotiation *decision* logic (version agreement, profile validation, FMP
//! feature helpers) lives in `core.rs`; only the payload codec is here.

use crate::proto::Error;
use crate::proto::codec::Reader;
use crate::proto::link::LinkMessageType;
use ::core::fmt;

/// Handshake message type identifiers.
///
/// These messages are exchanged during Noise XX handshake before link
/// encryption is established. They use the same TLV framing as link
/// messages but payloads are not encrypted (except Noise-internal encryption).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeMessageType {
    /// Noise XX message 1: initiator sends ephemeral key.
    /// Payload: 33 bytes (ephemeral pubkey).
    Msg1 = 0x01,

    /// Noise XX message 2: responder sends ephemeral + encrypted static + epoch.
    /// Payload: 106+ bytes (33 ephemeral + 49 encrypted static + 24 encrypted epoch + negotiation).
    Msg2 = 0x02,

    /// Noise XX message 3: initiator sends encrypted static + epoch.
    /// Payload: 73+ bytes (49 encrypted static + 24 encrypted epoch + negotiation).
    Msg3 = 0x03,
}

impl HandshakeMessageType {
    /// Try to convert from a byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(HandshakeMessageType::Msg1),
            0x02 => Some(HandshakeMessageType::Msg2),
            0x03 => Some(HandshakeMessageType::Msg3),
            _ => None,
        }
    }

    /// Convert to a byte.
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Check if a byte represents a handshake message type.
    pub fn is_handshake(b: u8) -> bool {
        matches!(b, 0x01..=0x03)
    }
}

impl fmt::Display for HandshakeMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            HandshakeMessageType::Msg1 => "Msg1",
            HandshakeMessageType::Msg2 => "Msg2",
            HandshakeMessageType::Msg3 => "Msg3",
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
// Protocol Negotiation Payload
// ============================================================================
//
// Encodes/decodes the negotiation payload embedded in XX handshake
// messages (msg2/msg3). Each layer (FMP, FSP) uses the same wire format with
// layer-specific version ranges and feature catalogs.
//
// Wire Format:
//   Byte 0:     format (must be 0)
//   Byte 1:     [version_min:4 high][version_max:4 low]
//   Bytes 2-9:  feature bitfield (64 bits, LE)
//   Bytes 10+:  TLV entries, each: [field_num:2 LE][length:2 LE][value:N]

/// Size of the fixed negotiation header (format + version + features).
pub const NEGOTIATION_HEADER_SIZE: usize = 10;

/// Format byte value for the initial negotiation format.
pub(crate) const NEGOTIATION_FORMAT_V0: u8 = 0;

// --- FMP feature bitfield constants ---

/// Mask for the 3-bit node profile enum (bits 0-2).
pub const FMP_FEAT_PROFILE_MASK: u64 = 0x07;

/// Bit 3: Can provide MMP sender reports.
pub const FMP_FEAT_PROVIDES_SR: u64 = 1 << 3;

/// Bit 4: Can provide MMP receiver reports.
pub const FMP_FEAT_PROVIDES_RR: u64 = 1 << 4;

/// Bit 5: Want MMP sender reports from peer.
pub const FMP_FEAT_WANTS_SR: u64 = 1 << 5;

/// Bit 6: Want MMP receiver reports from peer.
pub const FMP_FEAT_WANTS_RR: u64 = 1 << 6;

/// Node profile advertised during FMP negotiation.
///
/// Encoded in bits 0-2 of the FMP feature bitfield. Self-declared (not
/// AND-intersected). At least one side of a link must be `Full` or the
/// link is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NodeProfile {
    /// Full routing node. Combines bloom filters, forwards transit.
    Full = 0,
    /// Non-routing node. Tree participation, one-way bloom receipt,
    /// no transit forwarding.
    NonRouting = 1,
    /// Leaf node. Single upstream peer, no tree/bloom/transit.
    Leaf = 2,
}

impl fmt::Display for NodeProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "full"),
            Self::NonRouting => write!(f, "non-routing"),
            Self::Leaf => write!(f, "leaf"),
        }
    }
}

impl TryFrom<u8> for NodeProfile {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Full),
            1 => Ok(Self::NonRouting),
            2 => Ok(Self::Leaf),
            _ => Err(Error::Malformed("unknown node profile")),
        }
    }
}

/// A TLV entry in the negotiation payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlvEntry {
    /// Field number identifying this TLV.
    pub field_num: u16,
    /// Raw value bytes.
    pub value: Vec<u8>,
}

/// Protocol negotiation payload.
///
/// Carried in XX msg2/msg3 encrypted payloads. Shared codec for both
/// FMP and FSP layers, with layer-specific version ranges and feature
/// bit assignments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationPayload {
    /// Format byte (must be 0).
    pub format: u8,
    /// Minimum protocol version supported (4-bit, 0-15).
    pub version_min: u8,
    /// Maximum protocol version supported (4-bit, 0-15).
    pub version_max: u8,
    /// Feature bitfield (64 bits, LE).
    pub features: u64,
    /// Optional TLV extension entries.
    pub tlv_entries: Vec<TlvEntry>,
}

impl NegotiationPayload {
    /// Create a new negotiation payload.
    pub fn new(version_min: u8, version_max: u8, features: u64) -> Self {
        Self {
            format: NEGOTIATION_FORMAT_V0,
            version_min,
            version_max,
            features,
            tlv_entries: Vec::new(),
        }
    }

    /// Add a TLV entry.
    pub fn with_tlv(mut self, field_num: u16, value: Vec<u8>) -> Self {
        self.tlv_entries.push(TlvEntry { field_num, value });
        self
    }

    /// Encode to wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(NEGOTIATION_HEADER_SIZE);

        buf.push(self.format);
        buf.push((self.version_min << 4) | (self.version_max & 0x0F));
        buf.extend_from_slice(&self.features.to_le_bytes());

        for entry in &self.tlv_entries {
            buf.extend_from_slice(&entry.field_num.to_le_bytes());
            let len = entry.value.len() as u16;
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(&entry.value);
        }

        buf
    }

    /// Decode from wire format.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.len() < NEGOTIATION_HEADER_SIZE {
            return Err(Error::MessageTooShort {
                expected: NEGOTIATION_HEADER_SIZE,
                got: data.len(),
            });
        }

        let format = data[0];
        if format != NEGOTIATION_FORMAT_V0 {
            return Err(Error::Malformed("unknown negotiation format"));
        }

        let version_min = data[1] >> 4;
        let version_max = data[1] & 0x0F;
        if version_min > version_max {
            return Err(Error::Malformed("version_min > version_max"));
        }

        let features = u64::from_le_bytes(data[2..10].try_into().unwrap());

        let mut tlv_entries = Vec::new();
        let mut offset = NEGOTIATION_HEADER_SIZE;
        while offset < data.len() {
            // Need at least 4 bytes for field_num + length
            if offset + 4 > data.len() {
                return Err(Error::Malformed("truncated TLV header"));
            }

            let field_num = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap());
            let length =
                u16::from_le_bytes(data[offset + 2..offset + 4].try_into().unwrap()) as usize;
            offset += 4;

            if offset + length > data.len() {
                return Err(Error::Malformed(
                    "TLV field declared length exceeds remaining data",
                ));
            }

            let value = data[offset..offset + length].to_vec();
            offset += length;

            tlv_entries.push(TlvEntry { field_num, value });
        }

        Ok(Self {
            format,
            version_min,
            version_max,
            features,
            tlv_entries,
        })
    }
}
