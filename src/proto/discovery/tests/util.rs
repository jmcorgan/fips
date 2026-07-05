//! Shared test helpers for the discovery subsystem unit tests.

use sha2::Digest;

use crate::proto::discovery::{
    Discovery, DiscoveryAction, DiscoveryBackoff, DiscoveryForwardRateLimiter, LookupRequest,
    LookupResponse, RoutingView,
};
use crate::testutil::make_node_addr;
use crate::{NodeAddr, TreeCoordinate};

/// Mock routing view: each entry is `(addr, is_tree, may_reach)`.
pub(super) struct MockRoutingView {
    pub(super) peers: Vec<(NodeAddr, bool, bool)>,
}

impl RoutingView for MockRoutingView {
    fn is_tree_peer(&self, addr: &NodeAddr) -> bool {
        self.peers
            .iter()
            .find(|(a, _, _)| a == addr)
            .map(|(_, is_tree, _)| *is_tree)
            .unwrap_or(false)
    }
    fn peers_reaching(&self, _target: &NodeAddr) -> Vec<NodeAddr> {
        self.peers
            .iter()
            .filter(|(_, _, may_reach)| *may_reach)
            .map(|(a, _, _)| *a)
            .collect()
    }
}

pub(super) fn make_request(ttl: u8) -> LookupRequest {
    let target = make_node_addr(0xAA);
    let origin = make_node_addr(0xBB);
    let origin_coords = TreeCoordinate::root(origin);
    LookupRequest::new(1, target, origin, origin_coords, ttl, 0)
}

/// Build a request with an explicit request_id and target.
pub(super) fn make_request_id(request_id: u64, target: NodeAddr, ttl: u8) -> LookupRequest {
    let origin = make_node_addr(0xBB);
    let origin_coords = TreeCoordinate::root(origin);
    LookupRequest::new(request_id, target, origin, origin_coords, ttl, 0)
}

pub(super) fn make_coords(ids: &[u8]) -> TreeCoordinate {
    TreeCoordinate::from_addrs(ids.iter().map(|&v| make_node_addr(v)).collect()).unwrap()
}

pub(super) fn action_peers(actions: &[DiscoveryAction]) -> Vec<NodeAddr> {
    actions
        .iter()
        .map(|action| match action {
            DiscoveryAction::SendLink { peer, .. } => *peer,
            _ => panic!("expected SendLink, got a different action variant"),
        })
        .collect()
}

pub(super) fn empty_discovery() -> Discovery {
    Discovery::new(
        DiscoveryBackoff::default(),
        DiscoveryForwardRateLimiter::default(),
    )
}

/// A Discovery whose backoff is armed (non-zero base/cap) so that a single
/// recorded failure suppresses the target — the default backoff is inert.
pub(super) fn suppressing_discovery() -> Discovery {
    Discovery::new(
        DiscoveryBackoff::with_params(30, 300),
        DiscoveryForwardRateLimiter::default(),
    )
}

/// Build a `LookupResponse` carrying a valid schnorr proof over its own
/// `proof_bytes`, factoring out the secp/sha256/sign_schnorr setup shared by
/// the wire response roundtrip tests. `path_mtu` is the default `u16::MAX`.
pub(super) fn signed_response(
    request_id: u64,
    target: &NodeAddr,
    coords: &TreeCoordinate,
) -> LookupResponse {
    use secp256k1::Secp256k1;

    let secp = Secp256k1::new();
    let mut secret_bytes = [0u8; 32];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut secret_bytes);
    let secret_key = secp256k1::SecretKey::from_slice(&secret_bytes)
        .expect("32 random bytes is a valid secret key");
    let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret_key);
    let proof_data = LookupResponse::proof_bytes(request_id, target, coords);
    let digest: [u8; 32] = sha2::Sha256::digest(&proof_data).into();
    let sig = secp.sign_schnorr(&digest, &keypair);
    LookupResponse::new(request_id, *target, coords.clone(), sig)
}
