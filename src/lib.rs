//! FIPS: Federated Interoperable Peering System
//!
//! A distributed, decentralized network routing protocol for mesh nodes
//! connecting over arbitrary transports.

pub mod identity;

pub use identity::{
    decode_npub, encode_npub, AuthChallenge, AuthResponse, FipsAddress, Identity, IdentityError,
    NodeId, PeerIdentity,
};
