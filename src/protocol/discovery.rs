//! Discovery messages: LookupRequest and LookupResponse.

use crate::NodeAddr;
use crate::protocol::error::ProtocolError;
use crate::protocol::negotiation::TlvEntry;
use crate::protocol::session::{decode_coords, encode_coords};
use crate::tree::TreeCoordinate;
use secp256k1::schnorr::Signature;

/// Request to discover a node's coordinates.
///
/// Routed through the spanning tree via bloom-filter-guided forwarding.
/// Each transit node forwards only to tree peers whose bloom filter
/// contains the target. TTL limits propagation depth.
#[derive(Clone, Debug)]
pub struct LookupRequest {
    /// Unique request identifier.
    pub request_id: u64,
    /// Node we're looking for.
    pub target: NodeAddr,
    /// Who's asking (for response routing).
    pub origin: NodeAddr,
    /// Remaining propagation hops.
    pub ttl: u8,
    /// Minimum transport MTU the origin requires for a viable route.
    /// 0 means no requirement.
    pub min_mtu: u16,
    /// Optional TLV extension entries.
    pub tlv_entries: Vec<TlvEntry>,
}

impl LookupRequest {
    /// Create a new lookup request.
    pub fn new(request_id: u64, target: NodeAddr, origin: NodeAddr, ttl: u8, min_mtu: u16) -> Self {
        Self {
            request_id,
            target,
            origin,
            ttl,
            min_mtu,
            tlv_entries: Vec::new(),
        }
    }

    /// Generate a new request with a random ID.
    pub fn generate(target: NodeAddr, origin: NodeAddr, ttl: u8, min_mtu: u16) -> Self {
        use rand::RngExt;
        let request_id = rand::rng().random();
        Self::new(request_id, target, origin, ttl, min_mtu)
    }

    /// Add a TLV entry.
    pub fn with_tlv(mut self, field_num: u16, value: Vec<u8>) -> Self {
        self.tlv_entries.push(TlvEntry { field_num, value });
        self
    }

    /// Decrement TTL for forwarding.
    ///
    /// Returns false if TTL was already 0.
    pub fn forward(&mut self) -> bool {
        if self.ttl == 0 {
            return false;
        }
        self.ttl -= 1;
        true
    }

    /// Check if this request can still be forwarded.
    pub fn can_forward(&self) -> bool {
        self.ttl > 0
    }

    /// Encode as wire format (includes msg_type byte).
    ///
    /// Format: `[0x30][request_id:8][target:16][origin:16][ttl:1][min_mtu:2][tlv entries...]`
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(44);

        buf.push(0x30); // msg_type
        buf.extend_from_slice(&self.request_id.to_le_bytes());
        buf.extend_from_slice(self.target.as_bytes());
        buf.extend_from_slice(self.origin.as_bytes());
        buf.push(self.ttl);
        buf.extend_from_slice(&self.min_mtu.to_le_bytes());

        for entry in &self.tlv_entries {
            buf.extend_from_slice(&entry.field_num.to_le_bytes());
            let len = entry.value.len() as u16;
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(&entry.value);
        }

        buf
    }

    /// Decode from wire format (after msg_type byte has been consumed).
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        // Minimum: request_id(8) + target(16) + origin(16) + ttl(1) + min_mtu(2) = 43 bytes
        if payload.len() < 43 {
            return Err(ProtocolError::MessageTooShort {
                expected: 43,
                got: payload.len(),
            });
        }

        let mut pos = 0;

        let request_id = u64::from_le_bytes(
            payload[pos..pos + 8]
                .try_into()
                .map_err(|_| ProtocolError::Malformed("bad request_id".into()))?,
        );
        pos += 8;

        let mut target_bytes = [0u8; 16];
        target_bytes.copy_from_slice(&payload[pos..pos + 16]);
        let target = NodeAddr::from_bytes(target_bytes);
        pos += 16;

        let mut origin_bytes = [0u8; 16];
        origin_bytes.copy_from_slice(&payload[pos..pos + 16]);
        let origin = NodeAddr::from_bytes(origin_bytes);
        pos += 16;

        let ttl = payload[pos];
        pos += 1;

        let min_mtu = u16::from_le_bytes(
            payload[pos..pos + 2]
                .try_into()
                .map_err(|_| ProtocolError::Malformed("bad min_mtu".into()))?,
        );
        pos += 2;

        // Parse TLV entries from remaining bytes
        let mut tlv_entries = Vec::new();
        while pos < payload.len() {
            if pos + 4 > payload.len() {
                return Err(ProtocolError::Malformed(
                    "truncated TLV header in LookupRequest".to_string(),
                ));
            }
            let field_num = u16::from_le_bytes(payload[pos..pos + 2].try_into().unwrap());
            let length = u16::from_le_bytes(payload[pos + 2..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + length > payload.len() {
                return Err(ProtocolError::Malformed(format!(
                    "TLV field {field_num}: declared length {length} exceeds remaining data {}",
                    payload.len() - pos
                )));
            }
            let value = payload[pos..pos + length].to_vec();
            pos += length;
            tlv_entries.push(TlvEntry { field_num, value });
        }

        Ok(Self {
            request_id,
            target,
            origin,
            ttl,
            min_mtu,
            tlv_entries,
        })
    }
}

/// Response to a lookup request with target's coordinates.
///
/// Routed back to the origin using reverse-path routing or tree
/// routing toward the origin's NodeAddr.
#[derive(Clone, Debug)]
pub struct LookupResponse {
    /// Echoed request identifier.
    pub request_id: u64,
    /// The target node.
    pub target: NodeAddr,
    /// Minimum transport MTU along the response path.
    ///
    /// Initialized to `u16::MAX` by the target. Each transit node applies
    /// `path_mtu = path_mtu.min(outgoing_link_mtu)` when forwarding.
    /// NOT included in the proof signature (transit annotation).
    pub path_mtu: u16,
    /// Target's coordinates in the tree.
    pub target_coords: TreeCoordinate,
    /// Proof that target authorized this response (signature over request).
    pub proof: Signature,
    /// Optional TLV extension entries.
    pub tlv_entries: Vec<TlvEntry>,
}

impl LookupResponse {
    /// Create a new lookup response.
    ///
    /// `path_mtu` is initialized to `u16::MAX` by the target; transit
    /// nodes reduce it as they forward.
    pub fn new(
        request_id: u64,
        target: NodeAddr,
        target_coords: TreeCoordinate,
        proof: Signature,
    ) -> Self {
        Self {
            request_id,
            target,
            path_mtu: u16::MAX,
            target_coords,
            proof,
            tlv_entries: Vec::new(),
        }
    }

    /// Add a TLV entry.
    pub fn with_tlv(mut self, field_num: u16, value: Vec<u8>) -> Self {
        self.tlv_entries.push(TlvEntry { field_num, value });
        self
    }

    /// Get the bytes that should be signed as proof.
    ///
    /// Format: request_id (8) || target (16) || coords_encoding (2 + 16×n)
    pub fn proof_bytes(
        request_id: u64,
        target: &NodeAddr,
        target_coords: &TreeCoordinate,
    ) -> Vec<u8> {
        let coord_size = 2 + target_coords.entries().len() * 16;
        let mut bytes = Vec::with_capacity(24 + coord_size);
        bytes.extend_from_slice(&request_id.to_le_bytes());
        bytes.extend_from_slice(target.as_bytes());
        encode_coords(target_coords, &mut bytes);
        bytes
    }

    /// Encode as wire format (includes msg_type byte).
    ///
    /// Format: `[0x31][request_id:8][target:16][path_mtu:2][coords_cnt:2][coords:16×n][proof:64][tlv entries...]`
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(93 + self.target_coords.depth() * 16);

        buf.push(0x31); // msg_type
        buf.extend_from_slice(&self.request_id.to_le_bytes());
        buf.extend_from_slice(self.target.as_bytes());
        buf.extend_from_slice(&self.path_mtu.to_le_bytes());
        encode_coords(&self.target_coords, &mut buf);
        buf.extend_from_slice(self.proof.as_ref());

        for entry in &self.tlv_entries {
            buf.extend_from_slice(&entry.field_num.to_le_bytes());
            let len = entry.value.len() as u16;
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(&entry.value);
        }

        buf
    }

    /// Decode from wire format (after msg_type byte has been consumed).
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        // Minimum: request_id(8) + target(16) + path_mtu(2) + coords_count(2) + proof(64) = 92
        if payload.len() < 92 {
            return Err(ProtocolError::MessageTooShort {
                expected: 92,
                got: payload.len(),
            });
        }

        let mut pos = 0;

        let request_id = u64::from_le_bytes(
            payload[pos..pos + 8]
                .try_into()
                .map_err(|_| ProtocolError::Malformed("bad request_id".into()))?,
        );
        pos += 8;

        let mut target_bytes = [0u8; 16];
        target_bytes.copy_from_slice(&payload[pos..pos + 16]);
        let target = NodeAddr::from_bytes(target_bytes);
        pos += 16;

        let path_mtu = u16::from_le_bytes(
            payload[pos..pos + 2]
                .try_into()
                .map_err(|_| ProtocolError::Malformed("bad path_mtu".into()))?,
        );
        pos += 2;

        let (target_coords, consumed) = decode_coords(&payload[pos..])?;
        pos += consumed;

        if payload.len() < pos + 64 {
            return Err(ProtocolError::MessageTooShort {
                expected: pos + 64,
                got: payload.len(),
            });
        }
        let proof = Signature::from_slice(&payload[pos..pos + 64])
            .map_err(|_| ProtocolError::Malformed("bad proof signature".into()))?;
        pos += 64;

        // Parse TLV entries from remaining bytes after proof
        let mut tlv_entries = Vec::new();
        while pos < payload.len() {
            if pos + 4 > payload.len() {
                return Err(ProtocolError::Malformed(
                    "truncated TLV header in LookupResponse".to_string(),
                ));
            }
            let field_num = u16::from_le_bytes(payload[pos..pos + 2].try_into().unwrap());
            let length = u16::from_le_bytes(payload[pos + 2..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + length > payload.len() {
                return Err(ProtocolError::Malformed(format!(
                    "TLV field {field_num}: declared length {length} exceeds remaining data {}",
                    payload.len() - pos
                )));
            }
            let value = payload[pos..pos + length].to_vec();
            pos += length;
            tlv_entries.push(TlvEntry { field_num, value });
        }

        Ok(Self {
            request_id,
            target,
            path_mtu,
            target_coords,
            proof,
            tlv_entries,
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

    fn make_test_sig() -> Signature {
        use secp256k1::Secp256k1;
        let secp = Secp256k1::new();
        let mut secret_bytes = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut secret_bytes);
        let secret_key = secp256k1::SecretKey::from_slice(&secret_bytes)
            .expect("32 random bytes is a valid secret key");
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret_key);
        let target = make_node_addr(42);
        let coords = make_coords(&[42, 1, 0]);
        let proof_data = LookupResponse::proof_bytes(999, &target, &coords);
        use sha2::Digest;
        let digest: [u8; 32] = sha2::Sha256::digest(&proof_data).into();
        secp.sign_schnorr(&digest, &keypair)
    }

    #[test]
    fn test_lookup_request_forward() {
        let target = make_node_addr(1);
        let origin = make_node_addr(2);

        let mut request = LookupRequest::new(123, target, origin, 5, 0);

        assert!(request.can_forward());
        assert!(request.forward());
        assert_eq!(request.ttl, 4);
    }

    #[test]
    fn test_lookup_request_ttl_exhausted() {
        let target = make_node_addr(1);
        let origin = make_node_addr(2);

        let mut request = LookupRequest::new(123, target, origin, 1, 0);

        assert!(request.forward());
        assert!(!request.can_forward());
        assert!(!request.forward());
    }

    #[test]
    fn test_lookup_request_generate() {
        let target = make_node_addr(1);
        let origin = make_node_addr(2);

        let req1 = LookupRequest::generate(target, origin, 5, 0);
        let req2 = LookupRequest::generate(target, origin, 5, 0);

        // Random IDs should differ
        assert_ne!(req1.request_id, req2.request_id);
    }

    #[test]
    fn test_lookup_response_proof_bytes() {
        let target = make_node_addr(42);
        let coords = make_coords(&[42, 1, 0]);
        let bytes = LookupResponse::proof_bytes(12345, &target, &coords);

        // 8 (request_id) + 16 (target) + 2 (count) + 3*16 (coords) = 74
        assert_eq!(bytes.len(), 74);
        assert_eq!(&bytes[0..8], &12345u64.to_le_bytes());
        assert_eq!(&bytes[8..24], target.as_bytes());

        // Verify coordinate encoding is present
        let count = u16::from_le_bytes([bytes[24], bytes[25]]);
        assert_eq!(count, 3); // 3 entries in coords
    }

    #[test]
    fn test_lookup_request_encode_decode_roundtrip() {
        let target = make_node_addr(10);
        let origin = make_node_addr(20);

        let mut request = LookupRequest::new(12345, target, origin, 8, 1386);
        request.forward();

        let encoded = request.encode();
        assert_eq!(encoded[0], 0x30);

        let decoded = LookupRequest::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.request_id, 12345);
        assert_eq!(decoded.target, target);
        assert_eq!(decoded.origin, origin);
        assert_eq!(decoded.ttl, 7); // decremented by forward()
        assert_eq!(decoded.min_mtu, 1386);
        assert!(decoded.tlv_entries.is_empty());
    }

    #[test]
    fn test_lookup_request_decode_too_short() {
        assert!(LookupRequest::decode(&[]).is_err());
        assert!(LookupRequest::decode(&[0u8; 42]).is_err());
    }

    #[test]
    fn test_lookup_request_min_mtu_boundary_values() {
        let target = make_node_addr(10);
        let origin = make_node_addr(20);

        for mtu_val in [0u16, 1386, u16::MAX] {
            let request = LookupRequest::new(100, target, origin, 5, mtu_val);
            let encoded = request.encode();
            let decoded = LookupRequest::decode(&encoded[1..]).unwrap();
            assert_eq!(decoded.min_mtu, mtu_val);
        }
    }

    #[test]
    fn test_lookup_request_with_tlv_roundtrip() {
        let target = make_node_addr(10);
        let origin = make_node_addr(20);

        let request = LookupRequest::new(555, target, origin, 5, 1280)
            .with_tlv(1, vec![0xAA, 0xBB])
            .with_tlv(256, vec![0x01, 0x02, 0x03, 0x04]);

        let encoded = request.encode();
        let decoded = LookupRequest::decode(&encoded[1..]).unwrap();

        assert_eq!(decoded.request_id, 555);
        assert_eq!(decoded.min_mtu, 1280);
        assert_eq!(decoded.tlv_entries.len(), 2);
        assert_eq!(decoded.tlv_entries[0].field_num, 1);
        assert_eq!(decoded.tlv_entries[0].value, vec![0xAA, 0xBB]);
        assert_eq!(decoded.tlv_entries[1].field_num, 256);
        assert_eq!(decoded.tlv_entries[1].value, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_lookup_request_tlv_forward_compat() {
        // Unknown field_nums should be preserved through decode→encode
        let target = make_node_addr(10);
        let origin = make_node_addr(20);

        let request =
            LookupRequest::new(777, target, origin, 5, 0).with_tlv(9999, vec![0xFF, 0xFE, 0xFD]);

        let encoded = request.encode();
        let mut decoded = LookupRequest::decode(&encoded[1..]).unwrap();

        // Simulate transit: forward then re-encode
        decoded.forward();
        let re_encoded = decoded.encode();
        let final_decoded = LookupRequest::decode(&re_encoded[1..]).unwrap();

        assert_eq!(final_decoded.ttl, 4);
        assert_eq!(final_decoded.tlv_entries.len(), 1);
        assert_eq!(final_decoded.tlv_entries[0].field_num, 9999);
        assert_eq!(final_decoded.tlv_entries[0].value, vec![0xFF, 0xFE, 0xFD]);
    }

    #[test]
    fn test_lookup_response_encode_decode_roundtrip() {
        let target = make_node_addr(42);
        let coords = make_coords(&[42, 1, 0]);
        let sig = make_test_sig();

        let response = LookupResponse::new(999, target, coords, sig);

        // Default path_mtu should be u16::MAX
        assert_eq!(response.path_mtu, u16::MAX);

        let encoded = response.encode();
        assert_eq!(encoded[0], 0x31);

        let decoded = LookupResponse::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.request_id, 999);
        assert_eq!(decoded.target, target);
        assert_eq!(decoded.path_mtu, u16::MAX);
        assert_eq!(decoded.proof, sig);
        assert!(decoded.tlv_entries.is_empty());
    }

    #[test]
    fn test_lookup_response_path_mtu_roundtrip() {
        let target = make_node_addr(42);
        let coords = make_coords(&[42, 1, 0]);
        let sig = make_test_sig();

        for mtu_val in [0u16, 1280, 1386, 9000, u16::MAX] {
            let mut response = LookupResponse::new(999, target, coords.clone(), sig);
            response.path_mtu = mtu_val;

            let encoded = response.encode();
            let decoded = LookupResponse::decode(&encoded[1..]).unwrap();
            assert_eq!(decoded.path_mtu, mtu_val);
        }
    }

    #[test]
    fn test_lookup_response_path_mtu_not_in_proof_bytes() {
        // Verify that proof_bytes does NOT include path_mtu
        let target = make_node_addr(42);
        let coords = make_coords(&[42, 1, 0]);

        let bytes = LookupResponse::proof_bytes(12345, &target, &coords);

        // proof_bytes format: request_id(8) + target(16) + coords_encoding(2 + 3*16) = 74
        // No path_mtu(2) in here
        assert_eq!(bytes.len(), 74);
    }

    #[test]
    fn test_lookup_response_decode_too_short() {
        assert!(LookupResponse::decode(&[]).is_err());
        assert!(LookupResponse::decode(&[0u8; 50]).is_err());
    }

    #[test]
    fn test_lookup_response_with_tlv_roundtrip() {
        let target = make_node_addr(42);
        let coords = make_coords(&[42, 1, 0]);
        let sig = make_test_sig();

        let response = LookupResponse::new(999, target, coords, sig)
            .with_tlv(1, vec![0xAA, 0xBB])
            .with_tlv(500, vec![0x01, 0x02, 0x03]);

        let encoded = response.encode();
        let decoded = LookupResponse::decode(&encoded[1..]).unwrap();

        assert_eq!(decoded.request_id, 999);
        assert_eq!(decoded.proof, sig);
        assert_eq!(decoded.tlv_entries.len(), 2);
        assert_eq!(decoded.tlv_entries[0].field_num, 1);
        assert_eq!(decoded.tlv_entries[0].value, vec![0xAA, 0xBB]);
        assert_eq!(decoded.tlv_entries[1].field_num, 500);
        assert_eq!(decoded.tlv_entries[1].value, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_lookup_response_tlv_forward_compat() {
        // Unknown field_nums preserved through decode→modify path_mtu→encode
        let target = make_node_addr(42);
        let coords = make_coords(&[42, 1, 0]);
        let sig = make_test_sig();

        let response =
            LookupResponse::new(999, target, coords, sig).with_tlv(9999, vec![0xFF, 0xFE, 0xFD]);

        let encoded = response.encode();
        let mut decoded = LookupResponse::decode(&encoded[1..]).unwrap();

        // Simulate transit: modify path_mtu then re-encode
        decoded.path_mtu = 1280;
        let re_encoded = decoded.encode();
        let final_decoded = LookupResponse::decode(&re_encoded[1..]).unwrap();

        assert_eq!(final_decoded.path_mtu, 1280);
        assert_eq!(final_decoded.tlv_entries.len(), 1);
        assert_eq!(final_decoded.tlv_entries[0].field_num, 9999);
        assert_eq!(final_decoded.tlv_entries[0].value, vec![0xFF, 0xFE, 0xFD]);
    }
}
