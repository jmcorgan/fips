//! The punch packet: its two reserved prefixes, its codec, and the check a
//! receive path makes on a datagram before FMP sees it.

use alloc::string::ToString;

use super::error::Error;
use super::types::{PunchPacket, PunchPacketKind};

pub mod plan;
pub mod refusal;

/// Punch-probe magic ("NPTC", network byte order). First byte `0x4E`
/// collides with FMP's prefix-version high-nibble check, so the UDP
/// transport silently filters packets carrying this magic to keep
/// post-adoption handshake logs clean. Defined in the nostr rendezvous
/// home so the UDP filter and the nostr submodule's punch sender share
/// the same constant.
pub const PUNCH_MAGIC: u32 = 0x4E505443;

/// Punch-probe-ack magic ("NPTA", network byte order). Same filter as
/// [`PUNCH_MAGIC`].
pub const PUNCH_ACK_MAGIC: u32 = 0x4E505441;

/// Returns `true` if the first four bytes of `data` match a punch-probe or
/// punch-ack magic. Used by the UDP transport's receive loop to silently
/// drop stray probes that arrive on an adopted socket after the remote
/// peer's punch attempt has already timed out.
pub fn is_punch_packet(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    magic == PUNCH_MAGIC || magic == PUNCH_ACK_MAGIC
}

pub fn session_hash(session_id: &str) -> [u8; 16] {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(session_id.as_bytes());
    let mut output = [0u8; 16];
    output.copy_from_slice(&digest[..16]);
    output
}

pub fn build_punch_packet(kind: PunchPacketKind, sequence: u32, session_id: &str) -> [u8; 24] {
    let magic = match kind {
        PunchPacketKind::Probe => PUNCH_MAGIC,
        PunchPacketKind::Ack => PUNCH_ACK_MAGIC,
    };
    let mut packet = [0u8; 24];
    packet[..4].copy_from_slice(&magic.to_be_bytes());
    packet[4..8].copy_from_slice(&sequence.to_be_bytes());
    packet[8..24].copy_from_slice(&session_hash(session_id));
    packet
}

pub fn parse_punch_packet(bytes: &[u8]) -> Result<PunchPacket, Error> {
    if bytes.len() < 24 {
        return Err(Error::Protocol("invalid-punch-packet-length".to_string()));
    }
    let magic = u32::from_be_bytes(
        bytes[..4]
            .try_into()
            .map_err(|_| Error::Protocol("invalid-punch-magic".to_string()))?,
    );
    let kind = match magic {
        PUNCH_MAGIC => PunchPacketKind::Probe,
        PUNCH_ACK_MAGIC => PunchPacketKind::Ack,
        _ => {
            return Err(Error::Protocol("invalid-punch-magic".to_string()));
        }
    };
    let sequence = u32::from_be_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| Error::Protocol("invalid-punch-seq".to_string()))?,
    );
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&bytes[8..24]);
    Ok(PunchPacket {
        kind,
        sequence,
        session_hash: hash,
    })
}

/// Classification of a received UDP datagram on the punch socket. Returned
/// by [`classify_punch_packet`]; the timing loop performs the actual ack
/// send / break described by the variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchAction {
    /// Not a valid punch packet for this session — keep listening.
    Ignore,
    /// A matching probe: the driver builds and sends an ack for `sequence`,
    /// then treats the peer as reached.
    Ack { sequence: u32 },
    /// A matching non-probe (ack) packet: the peer is reached, no ack to send.
    Matched,
}

/// Pure classification of a received datagram against the expected session
/// hash. No I/O: the caller sends any ack and decides control flow.
pub fn classify_punch_packet(bytes: &[u8], expected_hash: [u8; 16]) -> PunchAction {
    let Ok(packet) = parse_punch_packet(bytes) else {
        return PunchAction::Ignore;
    };
    if packet.session_hash != expected_hash {
        return PunchAction::Ignore;
    }
    if packet.kind == PunchPacketKind::Probe {
        PunchAction::Ack {
            sequence: packet.sequence,
        }
    } else {
        PunchAction::Matched
    }
}

#[cfg(test)]
mod tests;
