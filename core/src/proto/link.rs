//! Link-layer message types: the shared frame catalog and session datagram.

use crate::identity::NodeAddr;
use crate::proto::Error;
use alloc::vec::Vec;
use core::fmt;

// ============================================================================
// Link-Layer Message Types
// ============================================================================

/// Link-layer message type identifiers.
///
/// These messages are exchanged between directly connected peers over
/// Noise-encrypted links. All payloads are encrypted with session keys
/// established during the Noise IK handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkMessageType {
    // Forwarding (0x00-0x0F)
    /// Encapsulated session-layer datagram for forwarding.
    /// Payload is opaque to intermediate nodes (end-to-end encrypted).
    SessionDatagram = 0x00,

    // MMP reports (0x01-0x02) — payload is an encoded SenderReport or ReceiverReport
    /// Sender-side MMP report.
    SenderReport = 0x01,
    /// Receiver-side MMP report.
    ReceiverReport = 0x02,

    // Tree protocol (0x10-0x1F)
    /// Spanning tree state announcement.
    TreeAnnounce = 0x10,

    // Bloom filter (0x20-0x2F)
    /// Bloom filter reachability update.
    FilterAnnounce = 0x20,

    // Discovery (0x30-0x3F)
    /// Request to discover a node's coordinates.
    LookupRequest = 0x30,
    /// Response with target's coordinates.
    LookupResponse = 0x31,

    // Link Control (0x50-0x5F)
    /// Orderly disconnect notification before link closure.
    Disconnect = 0x50,
    /// Periodic heartbeat for link liveness detection.
    /// No payload — the msg_type byte alone is sufficient.
    Heartbeat = 0x51,
    /// Probe a candidate path to a peer under the existing session.
    /// Payload is a [`PathMessage`].
    PathProbe = 0x52,
    /// Answer to a [`LinkMessageType::PathProbe`], sent back on the path
    /// the probe arrived on. Payload is a [`PathMessage`].
    PathAck = 0x53,
    /// "I am closing this path": sent on any other path when the sender
    /// knows a path is going (interface gone, carrier lost). Payload is a
    /// [`PathClose`].
    PathClose = 0x54,
}

impl LinkMessageType {
    /// Try to convert from a byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(LinkMessageType::SessionDatagram),
            0x01 => Some(LinkMessageType::SenderReport),
            0x02 => Some(LinkMessageType::ReceiverReport),
            0x10 => Some(LinkMessageType::TreeAnnounce),
            0x20 => Some(LinkMessageType::FilterAnnounce),
            0x30 => Some(LinkMessageType::LookupRequest),
            0x31 => Some(LinkMessageType::LookupResponse),
            0x50 => Some(LinkMessageType::Disconnect),
            0x51 => Some(LinkMessageType::Heartbeat),
            0x52 => Some(LinkMessageType::PathProbe),
            0x53 => Some(LinkMessageType::PathAck),
            0x54 => Some(LinkMessageType::PathClose),
            _ => None,
        }
    }

    /// Convert to a byte.
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for LinkMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            LinkMessageType::SessionDatagram => "SessionDatagram",
            LinkMessageType::SenderReport => "SenderReport",
            LinkMessageType::ReceiverReport => "ReceiverReport",
            LinkMessageType::TreeAnnounce => "TreeAnnounce",
            LinkMessageType::FilterAnnounce => "FilterAnnounce",
            LinkMessageType::LookupRequest => "LookupRequest",
            LinkMessageType::LookupResponse => "LookupResponse",
            LinkMessageType::Disconnect => "Disconnect",
            LinkMessageType::Heartbeat => "Heartbeat",
            LinkMessageType::PathProbe => "PathProbe",
            LinkMessageType::PathAck => "PathAck",
            LinkMessageType::PathClose => "PathClose",
        };
        write!(f, "{}", name)
    }
}

// ============================================================================
// Path Probe / Path Ack
// ============================================================================

/// Payload shared by `PathProbe` (0x52) and `PathAck` (0x53).
///
/// A probe is an ordinary encrypted frame under the current session, sent on
/// a candidate transport. The receiver, having decrypted it against the
/// session found by index, has proof the peer is reachable there: it adds
/// the path and answers with an ack **on that same path**. The prober's
/// receipt of the ack proves the reverse direction. One round trip, no
/// handshake, no new key material, no index allocation.
///
/// ## Wire Format
///
/// | Offset | Field         | Size    | Notes                                   |
/// |--------|---------------|---------|-----------------------------------------|
/// | 0      | msg_type      | 1 byte  | 0x52 or 0x53                            |
/// | 1      | probe_id      | 4 bytes | LE; the ack echoes the probe's          |
/// | 5      | flags         | 1 byte  | bit 0: `remote_active`                  |
/// | 6      | path_id       | 4 bytes | LE; the sender's id for its path        |
/// | 10     | padding       | any     | ignored; a full-size probe pads to MTU  |
///
/// Trailing bytes are ignored on decode, so a probe may be padded to the
/// link MTU: a path that forwards small frames and drops large ones then
/// never proves itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathMessage {
    /// Per-path sequence chosen by the prober; the ack carries it back.
    pub probe_id: u32,
    /// "This path is where I currently send." Costs one bit and is a free
    /// detection signal: a peer that stops sending here may have stopped
    /// hearing us here too.
    pub remote_active: bool,
    /// The sender's own identifier for the path this travels on. Transport
    /// ids are local to each node; each side learns the other's id from its
    /// probes and acks, and a later [`PathClose`] names the path by the
    /// *receiver's* id, so the receiver needs no lookup table.
    pub path_id: u32,
}

impl PathMessage {
    /// Encoded size including the msg_type byte.
    pub const WIRE_SIZE: usize = 10;

    const FLAG_REMOTE_ACTIVE: u8 = 0x01;

    /// Encode as a `PathProbe` link message (msg_type included).
    pub fn encode_probe(&self) -> [u8; Self::WIRE_SIZE] {
        self.encode(LinkMessageType::PathProbe)
    }

    /// Encode as a `PathAck` link message (msg_type included).
    pub fn encode_ack(&self) -> [u8; Self::WIRE_SIZE] {
        self.encode(LinkMessageType::PathAck)
    }

    fn encode(&self, kind: LinkMessageType) -> [u8; Self::WIRE_SIZE] {
        let mut out = [0u8; Self::WIRE_SIZE];
        out[0] = kind.to_byte();
        out[1..5].copy_from_slice(&self.probe_id.to_le_bytes());
        if self.remote_active {
            out[5] |= Self::FLAG_REMOTE_ACTIVE;
        }
        out[6..10].copy_from_slice(&self.path_id.to_le_bytes());
        out
    }

    /// Decode from the link-layer payload (after the msg_type byte).
    pub fn decode(payload: &[u8]) -> Result<Self, Error> {
        let mut reader = crate::proto::codec::Reader::new(payload);
        let probe_id = reader.read_u32_le()?;
        let flags = reader.read_u8()?;
        let path_id = reader.read_u32_le()?;
        Ok(Self {
            probe_id,
            remote_active: flags & Self::FLAG_REMOTE_ACTIVE != 0,
            path_id,
        })
    }
}

/// Why a path is being closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PathCloseReason {
    /// No particular reason given.
    Unspecified = 0,
    /// The interface under the path went away.
    InterfaceGone = 1,
    /// The interface lost carrier.
    CarrierLost = 2,
    /// An operator asked for it.
    Operator = 3,
}

impl PathCloseReason {
    fn from_byte(b: u8) -> Self {
        match b {
            1 => Self::InterfaceGone,
            2 => Self::CarrierLost,
            3 => Self::Operator,
            _ => Self::Unspecified,
        }
    }
}

/// `PathClose` (0x54): the sender is closing the path it identifies.
///
/// Sent on any path that still works, so the peer learns at once rather
/// than after an echo timeout. The peer withdraws its side of that path
/// (keeping its history) and moves its traffic if it was on it. Advisory:
/// a later probe on the path revives it.
///
/// ## Wire Format
///
/// | Offset | Field    | Size    | Notes                                     |
/// |--------|----------|---------|-------------------------------------------|
/// | 0      | msg_type | 1 byte  | 0x54                                      |
/// | 1      | path_id  | 4 bytes | LE; the *receiver's* id for the path      |
/// | 5      | reason   | 1 byte  | [`PathCloseReason`]                       |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathClose {
    /// The receiver's identifier for the path, as it carried in its own
    /// probes and acks on it.
    pub path_id: u32,
    pub reason: PathCloseReason,
}

impl PathClose {
    /// Encoded size including the msg_type byte.
    pub const WIRE_SIZE: usize = 6;

    /// Encode as a link message (msg_type included).
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut out = [0u8; Self::WIRE_SIZE];
        out[0] = LinkMessageType::PathClose.to_byte();
        out[1..5].copy_from_slice(&self.path_id.to_le_bytes());
        out[5] = self.reason as u8;
        out
    }

    /// Decode from the link-layer payload (after the msg_type byte).
    pub fn decode(payload: &[u8]) -> Result<Self, Error> {
        let mut reader = crate::proto::codec::Reader::new(payload);
        let path_id = reader.read_u32_le()?;
        let reason = PathCloseReason::from_byte(reader.read_u8()?);
        Ok(Self { path_id, reason })
    }
}

// ============================================================================
// Session Datagram (Link-Layer Encapsulation)
// ============================================================================

/// Encapsulated session-layer datagram for multi-hop forwarding.
///
/// This is a link-layer message (type 0x00) that carries session-layer
/// payloads through the mesh. The envelope provides source and destination
/// addressing that transit routers use for forwarding decisions and error
/// routing.
///
/// ## Wire Format (36-byte fixed header)
///
/// | Offset | Field     | Size     | Description                         |
/// |--------|-----------|----------|-------------------------------------|
/// | 0      | msg_type  | 1 byte   | 0x00                                |
/// | 1      | ttl       | 1 byte   | Decremented each hop                |
/// | 2      | path_mtu  | 2 bytes  | Path MTU (LE), min'd at each hop    |
/// | 4      | src_addr  | 16 bytes | Source node_addr                    |
/// | 20     | dest_addr | 16 bytes | Destination node_addr               |
/// | 36     | payload   | variable | Session-layer message               |
///
/// The payload is either end-to-end encrypted (handshake messages, data,
/// reports) or plaintext error signals (CoordsRequired, PathBroken)
/// generated by transit routers.
#[derive(Clone, Debug)]
pub struct SessionDatagram {
    /// Source node address (originator of this datagram).
    /// For data traffic: the source endpoint.
    /// For error signals: the transit router that generated the error.
    pub src_addr: NodeAddr,
    /// Destination node address (for routing decisions).
    pub dest_addr: NodeAddr,
    /// Time-to-live (decremented at each hop, dropped at zero).
    pub ttl: u8,
    /// Path MTU: minimum link MTU along the path so far.
    /// Each forwarding hop applies min(path_mtu, outgoing_link_mtu).
    pub path_mtu: u16,
    /// Session-layer payload (e2e encrypted or plaintext error signal).
    pub payload: Vec<u8>,
}

/// Borrowed view of a session datagram payload.
///
/// This avoids allocating and copying the inner payload when the caller only
/// needs to inspect or locally deliver it.
#[derive(Clone, Copy, Debug)]
pub struct SessionDatagramRef<'a> {
    pub src_addr: NodeAddr,
    pub dest_addr: NodeAddr,
    pub ttl: u8,
    pub path_mtu: u16,
    pub payload: &'a [u8],
}

/// The TTL a transit datagram leaves this node with, or `None` when it may not
/// be transmitted because it would leave with zero.
///
/// Follows IP semantics: the decrement comes first, and `saturating_sub` folds
/// an already-exhausted arrival (TTL 0) into the same outcome as a last-hop
/// arrival (TTL 1). This is the one rule behind the routing core's hop-limit
/// drop and both `can_forward`s.
pub fn ttl_after_hop(ttl: u8) -> Option<u8> {
    match ttl.saturating_sub(1) {
        0 => None,
        left => Some(left),
    }
}

/// SessionDatagram fixed header size: msg_type(1) + ttl(1) + path_mtu(2) + src_addr(16) + dest_addr(16).
pub const SESSION_DATAGRAM_HEADER_SIZE: usize = 36;

impl SessionDatagram {
    /// Create a new session datagram.
    pub fn new(src_addr: NodeAddr, dest_addr: NodeAddr, payload: Vec<u8>) -> Self {
        Self {
            src_addr,
            dest_addr,
            ttl: 64,
            path_mtu: u16::MAX,
            payload,
        }
    }

    /// Set the TTL.
    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    /// Set the path MTU.
    pub fn with_path_mtu(mut self, path_mtu: u16) -> Self {
        self.path_mtu = path_mtu;
        self
    }

    /// Decrement the TTL for a transit hop, returning whether the result may
    /// still be transmitted.
    ///
    /// Follows IP semantics: the decrement happens first, and a datagram that
    /// would leave with a TTL of zero is not transmitted. `saturating_sub`
    /// folds an already-exhausted arrival (TTL 0) into the same outcome as a
    /// last-hop arrival (TTL 1); both leave `ttl` at 0 and return false.
    ///
    /// This governs forwarding only. Delivery to the addressed node is not
    /// TTL-gated and must not consult this method.
    pub fn decrement_ttl(&mut self) -> bool {
        self.ttl = self.ttl.saturating_sub(1);
        self.ttl > 0
    }

    /// Check whether this datagram would survive a transit hop.
    ///
    /// True only at TTL 2 or more: at TTL 1 the decrement leaves zero, so the
    /// datagram is dropped rather than forwarded.
    pub fn can_forward(&self) -> bool {
        ttl_after_hop(self.ttl).is_some()
    }

    /// Encode as link-layer message (msg_type + ttl + path_mtu + src_addr + dest_addr + payload).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SESSION_DATAGRAM_HEADER_SIZE + self.payload.len());
        buf.push(LinkMessageType::SessionDatagram.to_byte());
        buf.push(self.ttl);
        buf.extend_from_slice(&self.path_mtu.to_le_bytes());
        buf.extend_from_slice(self.src_addr.as_bytes());
        buf.extend_from_slice(self.dest_addr.as_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode from link-layer payload (after msg_type byte has been consumed).
    pub fn decode(payload: &[u8]) -> Result<Self, Error> {
        let view = SessionDatagramRef::decode(payload)?;
        Ok(view.into_owned())
    }
}

impl<'a> SessionDatagramRef<'a> {
    /// Decode a borrowed view from link-layer payload after the msg_type byte.
    pub fn decode(payload: &'a [u8]) -> Result<Self, Error> {
        // ttl(1) + path_mtu(2) + src_addr(16) + dest_addr(16) = 35
        if payload.len() < 35 {
            return Err(Error::MessageTooShort {
                expected: 35,
                got: payload.len(),
            });
        }
        let ttl = payload[0];
        let path_mtu = u16::from_le_bytes([payload[1], payload[2]]);
        let mut src_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&payload[3..19]);
        let mut dest_bytes = [0u8; 16];
        dest_bytes.copy_from_slice(&payload[19..35]);

        Ok(Self {
            src_addr: NodeAddr::from_bytes(src_bytes),
            dest_addr: NodeAddr::from_bytes(dest_bytes),
            ttl,
            path_mtu,
            payload: &payload[35..],
        })
    }

    /// Check whether this datagram would survive a transit hop, by the same
    /// rule the routing core drops on (`ttl_after_hop`).
    pub fn can_forward(&self) -> bool {
        ttl_after_hop(self.ttl).is_some()
    }

    /// Materialize an owned datagram for forwarding/re-encoding paths.
    pub fn into_owned(self) -> SessionDatagram {
        SessionDatagram {
            src_addr: self.src_addr,
            dest_addr: self.dest_addr,
            ttl: self.ttl,
            path_mtu: self.path_mtu,
            payload: self.payload.to_vec(),
        }
    }
}

#[cfg(test)]
#[path = "tests/link.rs"]
mod tests;
