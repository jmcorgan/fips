//! Discovery messages: LookupRequest and LookupResponse.

use crate::NodeAddr;
use crate::protocol::error::ProtocolError;
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
    /// Origin's coordinates (for return path).
    pub origin_coords: TreeCoordinate,
    /// Remaining propagation hops.
    pub ttl: u8,
    /// Minimum transport MTU the origin requires for a viable route.
    /// 0 means no requirement.
    pub min_mtu: u16,
}

impl LookupRequest {
    /// Create a new lookup request.
    pub fn new(
        request_id: u64,
        target: NodeAddr,
        origin: NodeAddr,
        origin_coords: TreeCoordinate,
        ttl: u8,
        min_mtu: u16,
    ) -> Self {
        Self {
            request_id,
            target,
            origin,
            origin_coords,
            ttl,
            min_mtu,
        }
    }

    /// Generate a new request with a random ID.
    pub fn generate(
        target: NodeAddr,
        origin: NodeAddr,
        origin_coords: TreeCoordinate,
        ttl: u8,
        min_mtu: u16,
    ) -> Self {
        use rand::RngExt;
        let request_id = rand::rng().random();
        Self::new(request_id, target, origin, origin_coords, ttl, min_mtu)
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
    /// Format: `[0x30][request_id:8][target:16][origin:16][ttl:1][min_mtu:2]`
    ///         `[origin_coords_cnt:2][origin_coords:16×n]`
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(46 + self.origin_coords.depth() * 16);

        buf.push(0x30); // msg_type
        buf.extend_from_slice(&self.request_id.to_le_bytes());
        buf.extend_from_slice(self.target.as_bytes());
        buf.extend_from_slice(self.origin.as_bytes());
        buf.push(self.ttl);
        buf.extend_from_slice(&self.min_mtu.to_le_bytes());
        encode_coords(&self.origin_coords, &mut buf);

        buf
    }

    /// Decode from wire format (after msg_type byte has been consumed).
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        // Minimum: request_id(8) + target(16) + origin(16) + ttl(1) + min_mtu(2)
        //          + coords_count(2) = 45 bytes
        if payload.len() < 45 {
            return Err(ProtocolError::MessageTooShort {
                expected: 45,
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

        let (origin_coords, _consumed) = decode_coords(&payload[pos..])?;

        Ok(Self {
            request_id,
            target,
            origin,
            origin_coords,
            ttl,
            min_mtu,
        })
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
        }
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
    /// Format: `[0x31][request_id:8][target:16][path_mtu:2][target_coords_cnt:2][target_coords:16×n][proof:64]`
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(93 + self.target_coords.depth() * 16);

        buf.push(0x31); // msg_type
        buf.extend_from_slice(&self.request_id.to_le_bytes());
        buf.extend_from_slice(self.target.as_bytes());
        buf.extend_from_slice(&self.path_mtu.to_le_bytes());
        encode_coords(&self.target_coords, &mut buf);
        buf.extend_from_slice(self.proof.as_ref());

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

        Ok(Self {
            request_id,
            target,
            path_mtu,
            target_coords,
            proof,
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

    #[test]
    fn test_lookup_request_forward() {
        let target = make_node_addr(1);
        let origin = make_node_addr(2);
        let coords = make_coords(&[2, 0]);

        let mut request = LookupRequest::new(123, target, origin, coords, 5, 0);

        assert!(request.can_forward());
        assert!(request.forward());
        assert_eq!(request.ttl, 4);
    }

    #[test]
    fn test_lookup_request_ttl_exhausted() {
        let target = make_node_addr(1);
        let origin = make_node_addr(2);
        let coords = make_coords(&[2, 0]);

        let mut request = LookupRequest::new(123, target, origin, coords, 1, 0);

        assert!(request.forward());
        assert!(!request.can_forward());
        assert!(!request.forward());
    }

    #[test]
    fn test_lookup_request_generate() {
        let target = make_node_addr(1);
        let origin = make_node_addr(2);
        let coords = make_coords(&[2, 0]);

        let req1 = LookupRequest::generate(target, origin, coords.clone(), 5, 0);
        let req2 = LookupRequest::generate(target, origin, coords, 5, 0);

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
        let coords = make_coords(&[20, 0]);

        let mut request = LookupRequest::new(12345, target, origin, coords, 8, 1386);
        request.forward();

        let encoded = request.encode();
        assert_eq!(encoded[0], 0x30);

        let decoded = LookupRequest::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.request_id, 12345);
        assert_eq!(decoded.target, target);
        assert_eq!(decoded.origin, origin);
        assert_eq!(decoded.ttl, 7); // decremented by forward()
        assert_eq!(decoded.min_mtu, 1386);
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
        let coords = make_coords(&[20, 0]);

        for mtu_val in [0u16, 1386, u16::MAX] {
            let request = LookupRequest::new(100, target, origin, coords.clone(), 5, mtu_val);
            let encoded = request.encode();
            let decoded = LookupRequest::decode(&encoded[1..]).unwrap();
            assert_eq!(decoded.min_mtu, mtu_val);
        }
    }

    #[test]
    fn test_lookup_response_encode_decode_roundtrip() {
        use secp256k1::Secp256k1;

        let target = make_node_addr(42);
        let coords = make_coords(&[42, 1, 0]);

        // Create a dummy signature for testing
        let secp = Secp256k1::new();
        let mut secret_bytes = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut secret_bytes);
        let secret_key = secp256k1::SecretKey::from_slice(&secret_bytes)
            .expect("32 random bytes is a valid secret key");
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret_key);
        let proof_data = LookupResponse::proof_bytes(999, &target, &coords);
        use sha2::Digest;
        let digest: [u8; 32] = sha2::Sha256::digest(&proof_data).into();
        let sig = secp.sign_schnorr(&digest, &keypair);

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
    }

    #[test]
    fn test_lookup_response_path_mtu_roundtrip() {
        use secp256k1::Secp256k1;

        let target = make_node_addr(42);
        let coords = make_coords(&[42, 1, 0]);

        let secp = Secp256k1::new();
        let mut secret_bytes = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut secret_bytes);
        let secret_key = secp256k1::SecretKey::from_slice(&secret_bytes)
            .expect("32 random bytes is a valid secret key");
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret_key);
        let proof_data = LookupResponse::proof_bytes(999, &target, &coords);
        use sha2::Digest;
        let digest: [u8; 32] = sha2::Sha256::digest(&proof_data).into();
        let sig = secp.sign_schnorr(&digest, &keypair);

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
}
