//! FilterAnnounce message: bloom filter reachability propagation.

use super::error::ProtocolError;
use super::link::LinkMessageType;
use crate::bloom::BloomFilter;

/// Bloom filter announcement for reachability propagation.
///
/// Sent to peers to advertise which destinations are reachable.
///
/// ## Wire Format (v1)
///
/// | Offset | Field       | Size     | Notes                           |
/// |--------|-------------|----------|----------------------------------|
/// | 0      | msg_type    | 1 byte   | 0x20                            |
/// | 1      | sequence    | 8 bytes  | LE u64                          |
/// | 9      | hash_count  | 1 byte   | Number of hash functions        |
/// | 10     | size_class  | 1 byte   | Filter size: 512 << size_class  |
/// | 11     | filter_bits | variable | 512 << size_class bytes         |
#[derive(Clone, Debug)]
pub struct FilterAnnounce {
    /// The bloom filter contents.
    pub filter: BloomFilter,
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
    pub fn new(filter: BloomFilter, sequence: u64) -> Self {
        Self {
            hash_count: filter.hash_count(),
            size_class: crate::bloom::V1_SIZE_CLASS,
            filter,
            sequence,
        }
    }

    /// Create with explicit size_class (for testing or future protocol versions).
    pub fn with_size_class(filter: BloomFilter, sequence: u64, size_class: u8) -> Self {
        Self {
            hash_count: filter.hash_count(),
            size_class,
            filter,
            sequence,
        }
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

    /// Minimum payload size after msg_type is stripped:
    /// sequence(8) + hash_count(1) + size_class(1) = 10
    const MIN_PAYLOAD_SIZE: usize = 10;

    /// Maximum allowed size_class value.
    const MAX_SIZE_CLASS: u8 = 3;

    /// Encode as link-layer plaintext (includes msg_type byte).
    ///
    /// ```text
    /// [0x20][sequence:8 LE][hash_count:1][size_class:1][filter_bits:variable]
    /// ```
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        if !self.is_valid() {
            return Err(ProtocolError::Malformed(
                "filter size does not match size_class".into(),
            ));
        }

        let filter_bytes = self.filter.as_bytes();
        let size = 1 + Self::MIN_PAYLOAD_SIZE + filter_bytes.len();
        let mut buf = Vec::with_capacity(size);

        // msg_type
        buf.push(LinkMessageType::FilterAnnounce.to_byte());
        // sequence (8 LE)
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        // hash_count
        buf.push(self.hash_count);
        // size_class
        buf.push(self.size_class);
        // filter_bits
        buf.extend_from_slice(filter_bytes);

        Ok(buf)
    }

    /// Decode from link-layer payload (after msg_type byte stripped by dispatcher).
    ///
    /// The payload starts with the sequence field.
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < Self::MIN_PAYLOAD_SIZE {
            return Err(ProtocolError::MessageTooShort {
                expected: Self::MIN_PAYLOAD_SIZE,
                got: payload.len(),
            });
        }

        let mut pos = 0;

        // sequence (8 LE)
        let sequence = u64::from_le_bytes(
            payload[pos..pos + 8]
                .try_into()
                .map_err(|_| ProtocolError::Malformed("bad sequence".into()))?,
        );
        pos += 8;

        // hash_count
        let hash_count = payload[pos];
        pos += 1;

        // size_class
        let size_class = payload[pos];
        pos += 1;

        // Validate size_class range
        if size_class > Self::MAX_SIZE_CLASS {
            return Err(ProtocolError::Malformed(format!(
                "invalid size_class: {size_class} (max {})",
                Self::MAX_SIZE_CLASS
            )));
        }

        // v1 compliance check
        if size_class != crate::bloom::V1_SIZE_CLASS {
            return Err(ProtocolError::Malformed(format!(
                "unsupported size_class: {size_class} (v1 requires {})",
                crate::bloom::V1_SIZE_CLASS
            )));
        }

        // Expected filter size from size_class
        let expected_filter_bytes = 512usize << size_class;
        let remaining = payload.len() - pos;
        if remaining != expected_filter_bytes {
            return Err(ProtocolError::MessageTooShort {
                expected: Self::MIN_PAYLOAD_SIZE + expected_filter_bytes,
                got: payload.len(),
            });
        }

        // Construct BloomFilter from bytes
        let filter = crate::bloom::BloomFilter::from_slice(&payload[pos..], hash_count)
            .map_err(|e| ProtocolError::Malformed(format!("invalid bloom filter: {e}")))?;

        let announce = Self {
            filter,
            sequence,
            hash_count,
            size_class,
        };

        Ok(announce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeAddr;

    fn make_node_addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    #[test]
    fn test_filter_announce_size_class() {
        let filter = BloomFilter::new();
        let announce = FilterAnnounce::new(filter.clone(), 100);

        // v1 defaults
        assert_eq!(announce.size_class, 1);
        assert_eq!(announce.hash_count, 5);
        assert!(announce.is_v1_compliant());
        assert!(announce.is_valid());
        assert_eq!(announce.filter_size_bytes(), 1024);
    }

    #[test]
    fn test_filter_announce_with_size_class() {
        let filter = BloomFilter::with_params(2048 * 8, 7).unwrap();
        let announce = FilterAnnounce::with_size_class(filter, 100, 2);

        assert_eq!(announce.size_class, 2);
        assert_eq!(announce.hash_count, 7);
        assert!(!announce.is_v1_compliant());
        assert!(announce.is_valid());
        assert_eq!(announce.filter_size_bytes(), 2048);
    }

    #[test]
    fn test_filter_announce_encode_decode_roundtrip() {
        let mut filter = BloomFilter::new();
        filter.insert(&make_node_addr(42));
        filter.insert(&make_node_addr(99));
        let announce = FilterAnnounce::new(filter, 500);

        let encoded = announce.encode().unwrap();
        // msg_type(1) + sequence(8) + hash_count(1) + size_class(1) + filter(1024)
        assert_eq!(encoded.len(), 1035);
        assert_eq!(encoded[0], LinkMessageType::FilterAnnounce.to_byte());

        // Decode strips msg_type (as dispatcher does)
        let decoded = FilterAnnounce::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.sequence, 500);
        assert_eq!(decoded.hash_count, 5);
        assert_eq!(decoded.size_class, 1);
        assert!(decoded.is_valid());
        assert!(decoded.is_v1_compliant());

        // Filter contents preserved
        assert!(decoded.filter.contains(&make_node_addr(42)));
        assert!(decoded.filter.contains(&make_node_addr(99)));
        assert!(!decoded.filter.contains(&make_node_addr(1)));
    }

    #[test]
    fn test_filter_announce_decode_rejects_bad_size_class() {
        let filter = BloomFilter::new();
        let announce = FilterAnnounce::new(filter, 100);
        let mut encoded = announce.encode().unwrap();

        // Corrupt size_class byte (offset: 1 msg_type + 8 seq + 1 hash = 10)
        encoded[10] = 5; // invalid size_class > MAX_SIZE_CLASS

        let result = FilterAnnounce::decode(&encoded[1..]);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid size_class")
        );
    }

    #[test]
    fn test_filter_announce_decode_rejects_non_v1_size_class() {
        // Build a size_class=0 payload manually (valid range but not v1)
        let filter = BloomFilter::with_params(512 * 8, 5).unwrap();
        let announce = FilterAnnounce::with_size_class(filter, 100, 0);
        let encoded = announce.encode().unwrap();

        let result = FilterAnnounce::decode(&encoded[1..]);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unsupported size_class")
        );
    }

    #[test]
    fn test_filter_announce_decode_rejects_truncated() {
        let result = FilterAnnounce::decode(&[0u8; 5]);
        assert!(result.is_err());
    }
}
