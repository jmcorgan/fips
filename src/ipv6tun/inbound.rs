//! Host-side half of delivering what a peer sent to the IPv6 port.
//!
//! A datagram that arrived marked Congestion Experienced is delivered with
//! its IPv6 packet marked CE, so the host's transport sees the congestion
//! the mesh signalled. [`mark_ce`] is that marking; it reads only the packet
//! it is given.

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
