//! Protocol negotiation payload codec.
//!
//! Encodes/decodes the negotiation payload embedded in XX handshake
//! messages (msg2/msg3). Each layer (FMP, FSP) uses the same wire
//! format with layer-specific version ranges and feature catalogs.
//!
//! ## Wire Format
//!
//! ```text
//! Byte 0:     format (must be 0)
//! Byte 1:     [version_min:4 high][version_max:4 low]
//! Bytes 2-9:  feature bitfield (64 bits, LE)
//! Bytes 10+:  TLV entries, each:
//!               [field_num:2 LE][length:2 LE][value:N]
//! ```

use super::ProtocolError;

/// Size of the fixed negotiation header (format + version + features).
pub const NEGOTIATION_HEADER_SIZE: usize = 10;

/// Format byte value for the initial negotiation format.
const NEGOTIATION_FORMAT_V0: u8 = 0;

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
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < NEGOTIATION_HEADER_SIZE {
            return Err(ProtocolError::MessageTooShort {
                expected: NEGOTIATION_HEADER_SIZE,
                got: data.len(),
            });
        }

        let format = data[0];
        if format != NEGOTIATION_FORMAT_V0 {
            return Err(ProtocolError::Malformed(format!(
                "unknown negotiation format: {format}"
            )));
        }

        let version_min = data[1] >> 4;
        let version_max = data[1] & 0x0F;
        if version_min > version_max {
            return Err(ProtocolError::Malformed(format!(
                "version_min ({version_min}) > version_max ({version_max})"
            )));
        }

        let features = u64::from_le_bytes(data[2..10].try_into().unwrap());

        let mut tlv_entries = Vec::new();
        let mut offset = NEGOTIATION_HEADER_SIZE;
        while offset < data.len() {
            // Need at least 4 bytes for field_num + length
            if offset + 4 > data.len() {
                return Err(ProtocolError::Malformed(
                    "truncated TLV header".to_string(),
                ));
            }

            let field_num = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap());
            let length =
                u16::from_le_bytes(data[offset + 2..offset + 4].try_into().unwrap()) as usize;
            offset += 4;

            if offset + length > data.len() {
                return Err(ProtocolError::Malformed(format!(
                    "TLV field {field_num}: declared length {length} exceeds remaining data {}",
                    data.len() - offset
                )));
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

    /// Agree on a protocol version with a peer's negotiation payload.
    ///
    /// Returns `min(our_max, their_max)`, rejecting if the agreed version
    /// is below either side's minimum.
    pub fn agree_version(&self, other: &Self) -> Result<u8, ProtocolError> {
        let agreed = self.version_max.min(other.version_max);
        if agreed < self.version_min || agreed < other.version_min {
            return Err(ProtocolError::Malformed(format!(
                "version mismatch: ours [{},{}] theirs [{},{}]",
                self.version_min, self.version_max, other.version_min, other.version_max
            )));
        }
        Ok(agreed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let payload = NegotiationPayload::new(1, 3, 0x00000000_0000002A);
        let encoded = payload.encode();
        assert_eq!(encoded.len(), NEGOTIATION_HEADER_SIZE);

        let decoded = NegotiationPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_encode_decode_with_tlv() {
        let payload = NegotiationPayload::new(0, 1, 0)
            .with_tlv(1, vec![0xAA, 0xBB])
            .with_tlv(256, vec![0x01, 0x02, 0x03, 0x04]);

        let encoded = payload.encode();
        // 10 header + (2+2+2) + (2+2+4) = 10 + 6 + 8 = 24
        assert_eq!(encoded.len(), 24);

        let decoded = NegotiationPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(decoded.tlv_entries.len(), 2);
        assert_eq!(decoded.tlv_entries[0].field_num, 1);
        assert_eq!(decoded.tlv_entries[0].value, vec![0xAA, 0xBB]);
        assert_eq!(decoded.tlv_entries[1].field_num, 256);
        assert_eq!(decoded.tlv_entries[1].value, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_version_agreement_basic() {
        let ours = NegotiationPayload::new(1, 3, 0);
        let theirs = NegotiationPayload::new(1, 2, 0);
        assert_eq!(ours.agree_version(&theirs).unwrap(), 2);
    }

    #[test]
    fn test_version_agreement_mismatch() {
        let ours = NegotiationPayload::new(3, 5, 0);
        let theirs = NegotiationPayload::new(1, 2, 0);
        assert!(ours.agree_version(&theirs).is_err());
    }

    #[test]
    fn test_version_agreement_asymmetric() {
        // Ours: [2,5], theirs: [1,4] → agreed = min(5,4) = 4, 4 >= 2 and 4 >= 1 → ok
        let ours = NegotiationPayload::new(2, 5, 0);
        let theirs = NegotiationPayload::new(1, 4, 0);
        assert_eq!(ours.agree_version(&theirs).unwrap(), 4);

        // Ours: [1,4], theirs: [2,5] → agreed = min(4,5) = 4, 4 >= 1 and 4 >= 2 → ok
        assert_eq!(theirs.agree_version(&ours).unwrap(), 4);
    }

    #[test]
    fn test_unknown_format_rejected() {
        let mut data = NegotiationPayload::new(0, 0, 0).encode();
        data[0] = 1; // Set format to 1
        assert!(NegotiationPayload::decode(&data).is_err());
    }

    #[test]
    fn test_invalid_version_range() {
        let mut data = NegotiationPayload::new(0, 0, 0).encode();
        // Set version_min=5, version_max=3 (invalid: min > max)
        data[1] = (5 << 4) | 3;
        assert!(NegotiationPayload::decode(&data).is_err());
    }

    #[test]
    fn test_unknown_tlv_forward_compat() {
        // Unknown field_nums should be preserved through encode/decode
        let payload = NegotiationPayload::new(0, 1, 0)
            .with_tlv(9999, vec![0xFF, 0xFE, 0xFD]);

        let encoded = payload.encode();
        let decoded = NegotiationPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.tlv_entries.len(), 1);
        assert_eq!(decoded.tlv_entries[0].field_num, 9999);
        assert_eq!(decoded.tlv_entries[0].value, vec![0xFF, 0xFE, 0xFD]);
    }

    #[test]
    fn test_empty_payload() {
        let payload = NegotiationPayload::new(0, 0, 0);
        let encoded = payload.encode();
        assert_eq!(encoded.len(), NEGOTIATION_HEADER_SIZE);

        let decoded = NegotiationPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.version_min, 0);
        assert_eq!(decoded.version_max, 0);
        assert_eq!(decoded.features, 0);
        assert!(decoded.tlv_entries.is_empty());
    }

    #[test]
    fn test_truncated_payload() {
        // Less than header size
        assert!(NegotiationPayload::decode(&[0u8; 5]).is_err());
        assert!(NegotiationPayload::decode(&[]).is_err());
    }

    #[test]
    fn test_truncated_tlv() {
        let payload = NegotiationPayload::new(0, 1, 0)
            .with_tlv(1, vec![0xAA, 0xBB, 0xCC]);
        let mut encoded = payload.encode();

        // Truncate the TLV value (remove last byte)
        encoded.pop();
        assert!(NegotiationPayload::decode(&encoded).is_err());

        // Truncate to just partial TLV header (only 2 of 4 header bytes)
        let mut partial = NegotiationPayload::new(0, 1, 0).encode();
        partial.extend_from_slice(&[0x01, 0x00]); // Only field_num, no length
        assert!(NegotiationPayload::decode(&partial).is_err());
    }
}
