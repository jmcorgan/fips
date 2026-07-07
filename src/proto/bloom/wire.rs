//! FilterAnnounce message: bloom filter reachability propagation.

use super::BloomFilter;
use crate::protocol::LinkMessageType;
use crate::protocol::ProtocolError;

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
            size_class: super::V1_SIZE_CLASS,
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
        self.size_class == super::V1_SIZE_CLASS
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
        if size_class != super::V1_SIZE_CLASS {
            return Err(ProtocolError::Malformed(format!(
                "unsupported size_class: {size_class} (v1 requires {})",
                super::V1_SIZE_CLASS
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
        let filter = BloomFilter::from_slice(&payload[pos..], hash_count)
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
