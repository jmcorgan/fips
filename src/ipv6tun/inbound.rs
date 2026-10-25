//! Host-side half of delivering what a peer sent to the IPv6 port.
//!
//! The node hands the adapter each such datagram as a [`Deliver`]: the
//! sender's key, the packet with its header compressed, and whether it
//! arrived marked Congestion Experienced. The adapter rebuilds the packet
//! with the sender's address as its source and ours as its destination,
//! marks it CE when the datagram was, so the host's transport sees the
//! congestion the mesh signalled, and queues it for the host.
//!
//! [`unpack`] and [`mark_ce`] are the synchronous decisions; they read only
//! what they are given.

use std::sync::mpsc::SendError;

use super::ipv6_shim::decompress_ipv6;
use super::link::Deliver;

/// What became of a datagram handed to the adapter, for the node to log.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Delivery {
    /// Queued for the host, or dropped and counted on a full queue.
    Delivered,
    /// The payload is not a compressed IPv6 packet.
    Malformed,
    /// No TUN is up to hand it to.
    NoDevice,
    /// The TUN writer or the embedder has gone.
    Closed(SendError<Vec<u8>>),
}

/// The IPv6 packet `deliver` carries, from `source` to `dest`, marked CE
/// when the datagram arrived marked, or `None` if its payload is not a
/// compressed IPv6 packet.
pub(crate) fn unpack(deliver: &Deliver, source: [u8; 16], dest: [u8; 16]) -> Option<Vec<u8>> {
    let mut packet = decompress_ipv6(&deliver.payload, source, dest)?;
    if deliver.ce {
        mark_ce(&mut packet);
    }
    Some(packet)
}

/// Mark ECN-CE in an IPv6 packet's Traffic Class field.
///
/// IPv6 Traffic Class occupies bits across bytes 0 and 1:
///   byte\[0\] bits\[3:0\] = TC\[7:4\]
///   byte\[1\] bits\[7:4\] = TC\[3:0\]
/// ECN is TC\[1:0\]. Only marks CE (0b11) if the packet is ECN-capable (ECT(0) or
/// ECT(1)). Packets with ECN=0b00 (Not-ECT) are never marked per RFC 3168.
///
/// No checksum update needed: IPv6 has no header checksum, and the Traffic Class
/// field is not part of the TCP/UDP pseudo-header.
pub(crate) fn mark_ce(packet: &mut [u8]) {
    if packet.len() < 2 {
        return;
    }
    // Extract 8-bit Traffic Class from IPv6 header bytes 0-1
    let tc = ((packet[0] & 0x0F) << 4) | (packet[1] >> 4);
    let ecn = tc & 0x03;
    // Only mark CE on ECN-capable packets (ECT(0)=0b10 or ECT(1)=0b01)
    if ecn == 0 {
        return;
    }
    // Set both ECN bits to 1 (CE = 0b11)
    let new_tc = tc | 0x03;
    packet[0] = (packet[0] & 0xF0) | (new_tc >> 4);
    packet[1] = (new_tc << 4) | (packet[1] & 0x0F);
}

#[cfg(test)]
#[path = "tests/inbound.rs"]
mod tests;
