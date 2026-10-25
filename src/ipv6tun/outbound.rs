//! Host-side half of forwarding an IPv6 packet read from the TUN.
//!
//! This side checks the packet against the node-wide IPv6 MTU, answers the
//! host with ICMPv6 when the mesh cannot take it or the destination names
//! no key the adapter holds, and hands the rest to the node as a
//! [`Datagram`]: the destination's key and the packet with its header
//! compressed. What happens to it inside the mesh (session lookup, queueing
//! while a session is set up, discovery) is the node's business; a
//! datagram the node refuses comes back as a [`Refusal`], which [`answer`]
//! turns into the ICMPv6 the host is owed.
//!
//! The decisions are the synchronous functions [`admit`], [`outbound`] and
//! [`answer`]; they read only the adapter's own state.

use super::core::{MeshState, ipv6_mtu};
use super::icmp::IcmpContext;
use super::ipv6_shim::{compress_ipv6, decompress_ipv6};
use super::link::{Datagram, PeerKey, Refusal};
use fips_core::identity::NodePrefix;

/// The verdict on a packet read from the TUN, before the mesh is asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Admit {
    /// Not an IPv6 packet, or shorter than its fixed header.
    Drop,
    /// Larger than the mesh carries; answer Packet Too Big with this MTU.
    TooBig(u32),
    /// Forward to the destination with this address prefix.
    Forward(NodePrefix),
}

/// The node prefix a packet's destination address names, its bytes 1 to 15.
/// The caller has checked the packet holds a whole IPv6 header; byte 0 of the
/// address is not read, so a destination outside `fd00::/8` names one too.
fn destination(packet: &[u8]) -> NodePrefix {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&packet[24..40]);
    NodePrefix::from_octets(&octets)
}

/// Check a packet from the TUN against the node-wide IPv6 MTU and extract
/// its destination prefix.
pub(crate) fn admit(packet: &[u8], ipv6_mtu: u16) -> Admit {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return Admit::Drop;
    }

    // Check if packet will fit after FIPS encapsulation
    let effective_mtu = ipv6_mtu as usize;
    if packet.len() > effective_mtu {
        return Admit::TooBig(effective_mtu as u32);
    }

    // IPv6 header: bytes 24-39 are the destination address.
    Admit::Forward(destination(packet))
}

/// Forward one IPv6 packet from the host: check it, answer it or drop it
/// here, or return the datagram for the node.
///
/// A packet that is not IPv6 is dropped. A packet to a destination whose
/// prefix names a key goes to the node whatever its size: the node judges it
/// against the limit it carries now, which the adapter's copy can trail. A
/// packet to any other destination is answered here, with Packet Too Big
/// when it is over the node-wide IPv6 MTU last published, as the size check
/// comes first, and with Destination Unreachable otherwise.
pub(crate) fn outbound(
    packet: &[u8],
    state: &MeshState,
    icmp: &mut IcmpContext<'_>,
) -> Option<Datagram> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return None;
    }
    if let Some(peer) = state.key(&destination(packet)) {
        // What compression refuses, anything shorter than an IPv6 header or
        // of another version, has been dropped above.
        let payload = compress_ipv6(packet)?;
        return Some(Datagram { peer, payload });
    }
    match admit(packet, state.ipv6_mtu()) {
        Admit::TooBig(mtu) => icmp.too_big(packet, mtu),
        _ => icmp.dest_unreachable(packet),
    }
    None
}

/// Answer the host for a datagram the node refused, rebuilding each packet
/// from its payload with our address as its source.
///
/// The rebuilt packet is the one the host sent whenever the host sent it
/// from our own address, the normal case; compression keeps every other
/// header field it had.
pub(crate) fn answer(refusal: Refusal, icmp: &mut IcmpContext<'_>) {
    match refusal {
        Refusal::TooBig {
            peer,
            payload_limit,
            payload,
        } => {
            if let Some(packet) = rebuild(&payload, &peer, icmp) {
                icmp.too_big(&packet, u32::from(ipv6_mtu(payload_limit)));
            }
        }
        Refusal::TableFull { peer, payload } => {
            if let Some(packet) = rebuild(&payload, &peer, icmp) {
                icmp.dest_unreachable(&packet);
            }
        }
        Refusal::NoRoute { peer, payloads } => {
            for payload in payloads {
                if let Some(packet) = rebuild(&payload, &peer, icmp) {
                    icmp.dest_unreachable(&packet);
                }
            }
        }
    }
}

/// The IPv6 packet `payload` was compressed from, sent from our address to
/// `peer`'s.
fn rebuild(payload: &[u8], peer: &PeerKey, icmp: &IcmpContext<'_>) -> Option<Vec<u8>> {
    decompress_ipv6(
        payload,
        icmp.our_addr().octets(),
        *peer.address().as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The destination tests address.
    fn dest() -> std::net::Ipv6Addr {
        "fd12:3456:789a::2".parse().unwrap()
    }

    /// An IPv6 UDP packet of `len` bytes from a host address to `dst`.
    fn packet(dst: std::net::Ipv6Addr, len: usize) -> Vec<u8> {
        let mut p = vec![0u8; len];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
        p[6] = 17;
        p[7] = 64;
        let src: std::net::Ipv6Addr = "fd00::5".parse().unwrap();
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p
    }

    #[test]
    fn admit_drops_short_and_non_ipv6_packets() {
        assert_eq!(admit(&[0x60; 39], 1280), Admit::Drop);
        let mut p = packet(dest(), 60);
        p[0] = 0x45;
        assert_eq!(admit(&p, 1280), Admit::Drop);
    }

    #[test]
    fn admit_reports_the_node_mtu_for_an_oversized_packet() {
        assert_eq!(admit(&packet(dest(), 1281), 1280), Admit::TooBig(1280));
        assert!(matches!(
            admit(&packet(dest(), 1280), 1280),
            Admit::Forward(_)
        ));
    }

    #[test]
    fn admit_extracts_destination_bytes_one_to_fifteen() {
        let expected = NodePrefix::from_bytes(dest().octets()[1..16].try_into().unwrap());
        assert_eq!(admit(&packet(dest(), 60), 1280), Admit::Forward(expected));
    }
}

#[cfg(test)]
#[path = "tests/outbound.rs"]
mod host_tests;
