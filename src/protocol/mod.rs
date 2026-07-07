//! FIPS Protocol Messages
//!
//! Wire format definitions for FIPS protocol communication across two layers:
//!
//! ## Link Layer (peer-to-peer, hop-by-hop)
//!
//! Messages exchanged between directly connected peers over Noise-encrypted
//! links. Includes spanning tree gossip, bloom filter propagation, discovery
//! protocol, and forwarding of session-layer datagrams.
//!
//! Link-layer peer authentication uses Noise IK (see `noise.rs`), which
//! establishes the encrypted channel before any of these messages are sent.
//!
//! ## Session Layer (end-to-end, between FIPS addresses)
//!
//! Messages exchanged between source and destination FIPS nodes, encrypted
//! with session keys that intermediate nodes cannot read. Includes session
//! establishment, IPv6 datagram encapsulation, and routing errors.
//!
//! Session-layer datagrams are carried as opaque payloads through the link
//! layer, encrypted end-to-end independently of per-hop link encryption.

mod error;
mod filter;
mod link;
pub(crate) mod session;
mod tree;

// Re-export all public types at protocol:: level
pub use error::ProtocolError;
pub use filter::FilterAnnounce;
pub use link::{
    LinkMessageType, SESSION_DATAGRAM_HEADER_SIZE, SessionDatagram, SessionDatagramRef,
};
pub use session::{
    FspFlags, FspInnerFlags, SessionAck, SessionFlags, SessionMessageType, SessionMsg3,
    SessionSetup,
};
pub(crate) use session::{coords_wire_size, decode_optional_coords, encode_coords};
pub use tree::TreeAnnounce;

/// Protocol version for message compatibility.
pub const PROTOCOL_VERSION: u8 = 1;

// Legacy type alias re-export
#[allow(deprecated)]
pub use link::MessageType;
