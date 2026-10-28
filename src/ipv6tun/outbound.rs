//! Host-side half of forwarding an IPv6 packet read from the TUN.
//!
//! This side checks the packet against the node-wide IPv6 MTU, decides the
//! ICMPv6 the host is owed when the mesh cannot take it or the destination
//! names no key the adapter holds, and otherwise makes it a [`Datagram`] for
//! the node: the destination's key and the packet with its header
//! compressed. What happens to it inside the mesh (session lookup, queueing
//! while a session is set up, discovery) is the node's business; a datagram
//! the node refuses comes back as a [`Refusal`], which [`answer`] turns into
//! the ICMPv6 the host is owed.
//!
//! The decisions are synchronous functions that return what to send rather
//! than sending it, and read no clock: [`from_tun`] for a packet the system
//! TUN reader read (the `fd00::/8` filter, the hairpin and the MSS clamp,
//! then the shared step), [`outbound`] for the shared step, which is all a
//! packet an embedder that owns the TUN sends gets, and [`answer`] for a
//! refusal. The TUN reader and the adapter's handles carry the result out,
//! and only they consult the ICMPv6 limiters: the Packet Too Big limiter
//! when told to, and the Destination Unreachable bucket for every
//! Destination Unreachable.

use super::core::{MeshState, PathMtuReplica};
use super::icmp::{source_refused, unreachable};
use super::ipv6_shim::{compress_ipv6, decompress_ipv6};
use super::link::{Datagram, PeerKey, Refusal};
use super::mss::{Remote, clamp};
use super::mtu::ipv6_mtu;
use super::tcp_mss::recalculate_l4_checksum;
use crate::identity::IPV6_ADDRESS_PREFIX;
use fips_core::identity::NodePrefix;
use std::net::Ipv6Addr;
use tracing::debug;

/// What the host half does with one packet from the host, on either path.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Host {
    /// Nothing is sent: the packet is dropped, or the answer it is owed
    /// cannot be built.
    Nothing,
    /// Hand the node this datagram.
    Mesh(Datagram),
    /// Send the host this Destination Unreachable, if the Destination
    /// Unreachable bucket has a token. A closed queue toward the host is
    /// ignored.
    Unreachable(Vec<u8>),
    /// Send the host Packet Too Big for the packet, reporting this MTU, if
    /// the limiter lets the packet's source have one. A closed queue toward
    /// the host is ignored.
    TooBig(u32),
}

/// What the system TUN reader does with one packet it read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FromTun {
    /// Nothing is sent: the packet is not IPv6, or the Destination
    /// Unreachable a destination outside the mesh is owed cannot be built.
    Nothing,
    /// The packet is addressed to us: write it back toward the host, its
    /// checksum now complete. A closed queue toward the host ends the reader.
    Hairpin,
    /// The destination is outside `fd00::/8`: send the host this Destination
    /// Unreachable, if the Destination Unreachable bucket has a token. A
    /// closed queue toward the host ends the reader.
    OffMesh(Vec<u8>),
    /// A mesh destination: the shared step's verdict, on the packet as
    /// clamped. `clamped` is the MSS a SYN was clamped to, if it was.
    Host {
        /// The MSS ceiling the clamp applied, if it clamped.
        clamped: Option<u16>,
        /// The shared step's verdict.
        host: Host,
    },
}

/// An answer the host is owed for a datagram the node refused.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Owed {
    /// Send the host this Destination Unreachable, if the Destination
    /// Unreachable bucket has a token.
    Unreachable(Vec<u8>),
    /// Send the host Packet Too Big for this rebuilt packet, reporting this
    /// MTU, if the limiter lets its source have one.
    TooBig(Vec<u8>, u32),
}

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

/// Decide what the system TUN reader does with one packet it read.
///
/// A packet that is not IPv6 is dropped. A destination outside `fd00::/8`
/// is answered Destination Unreachable from `our_addr`. A packet to
/// `our_addr` itself is hairpinned, after its checksum is completed. Any
/// other packet has a SYN's MSS clamped to the smaller of `ceiling` and the
/// stored path to its destination, in place, and then takes the shared
/// step, so a datagram carries the clamped segment and an answer quotes it.
pub(crate) fn from_tun(
    packet: &mut [u8],
    ceiling: u16,
    paths: &PathMtuReplica,
    state: &MeshState,
    our_addr: Ipv6Addr,
) -> FromTun {
    // Must be a valid IPv6 packet
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return FromTun::Nothing;
    }
    // Non-FIPS destination (outside fd00::/8): ICMPv6 Destination Unreachable
    if packet[24] != IPV6_ADDRESS_PREFIX {
        return unreachable(packet, our_addr).map_or(FromTun::Nothing, FromTun::OffMesh);
    }
    // Loopback: a packet to our own mesh address must be delivered
    // locally, not pushed into the mesh (we have no session/route to
    // ourselves, so it would just be dropped). The reader hairpins it back
    // to the TUN writer for inbound delivery.
    //
    // Platform note: in practice this branch is reached only on macOS.
    // macOS point-to-point `utun` interfaces egress self-addressed traffic
    // down the tunnel into the TUN reader, so the daemon has to loop it back
    // itself. On Linux the kernel routes traffic to our own bound
    // addresses via `lo` before it ever reaches the TUN, so this branch
    // never fires there. The check is kept unconditional anyway, both as a
    // platform-independent self-delivery invariant and so the path stays
    // exercised by the Linux-only CI unit tests.
    if packet[24..40] == our_addr.octets() {
        // Finish the checksum macOS leaves offloaded on self-traffic, else the
        // local stack drops every non-SYN segment. See recalculate_l4_checksum.
        recalculate_l4_checksum(packet);
        return FromTun::Hairpin;
    }
    // Per-destination clamp: if discovery has learned a smaller path MTU
    // for this destination, tighten the ceiling for this flow.
    let clamped = clamp(packet, ceiling, paths, Remote::Destination);
    FromTun::Host {
        clamped,
        host: outbound(packet, state, our_addr),
    }
}

/// Decide what to do with one IPv6 packet from the host: the shared step
/// both paths take, and all a packet an embedder that owns the TUN sends
/// gets.
///
/// A packet that is not IPv6 is dropped. A packet whose source is not
/// `our_addr` never reaches the mesh, whose receiver would rebuild it with
/// our address as its source, so that its checksum fails there: it is
/// answered with Destination Unreachable code 5 (source address failed
/// ingress/egress policy) from `our_addr`. A packet to a destination whose
/// prefix names a key goes to the node whatever its size: the node judges it
/// against the limit it carries now, which the adapter's copy can trail. A
/// packet to any other destination is answered here: one to `fd00::/8` with
/// Packet Too Big when it is over the node-wide IPv6 MTU last published, as
/// the size check comes first, and every other with Destination Unreachable
/// from `our_addr`, or nothing when it is owed no ICMPv6 error. A
/// destination outside `fd00::/8`, which only an embedder that owns the TUN
/// can send, is never too big: the mesh could not carry it at any size.
pub(crate) fn outbound(packet: &[u8], state: &MeshState, our_addr: Ipv6Addr) -> Host {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return Host::Nothing;
    }
    if packet[8..24] != our_addr.octets() {
        debug!(
            src = %Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap()),
            "Refusing a packet from the host whose source is not our address"
        );
        return source_refused(packet, our_addr).map_or(Host::Nothing, Host::Unreachable);
    }
    if let Some(peer) = state.key(&destination(packet)) {
        // What compression refuses, anything shorter than an IPv6 header or
        // of another version, has been dropped above.
        return compress_ipv6(packet).map_or(Host::Nothing, |payload| {
            Host::Mesh(Datagram { peer, payload })
        });
    }
    match admit(packet, state.ipv6_mtu()) {
        Admit::TooBig(mtu) if packet[24] == IPV6_ADDRESS_PREFIX => Host::TooBig(mtu),
        _ => unreachable(packet, our_addr).map_or(Host::Nothing, Host::Unreachable),
    }
}

/// The answers the host is owed for a datagram the node refused, in the
/// order the refused payloads came, each packet rebuilt from its payload
/// with `our_addr` as its source.
///
/// The rebuilt packet is the one the host sent whenever the host sent it
/// from our own address, the normal case; compression keeps every other
/// header field it had.
pub(crate) fn answer(refusal: Refusal, our_addr: Ipv6Addr) -> Vec<Owed> {
    match refusal {
        Refusal::TooBig {
            peer,
            payload_limit,
            payload,
        } => rebuild(&payload, &peer, our_addr)
            .map(|packet| Owed::TooBig(packet, u32::from(ipv6_mtu(payload_limit))))
            .into_iter()
            .collect(),
        Refusal::TableFull { peer, payload } => rebuild(&payload, &peer, our_addr)
            .and_then(|packet| unreachable(&packet, our_addr))
            .map(Owed::Unreachable)
            .into_iter()
            .collect(),
        Refusal::NoRoute { peer, payloads } => payloads
            .iter()
            .filter_map(|payload| rebuild(payload, &peer, our_addr))
            .filter_map(|packet| unreachable(&packet, our_addr))
            .map(Owed::Unreachable)
            .collect(),
    }
}

/// The IPv6 packet `payload` was compressed from, sent from `our_addr` to
/// `peer`'s address.
fn rebuild(payload: &[u8], peer: &PeerKey, our_addr: Ipv6Addr) -> Option<Vec<u8>> {
    decompress_ipv6(payload, our_addr.octets(), *peer.address().as_bytes())
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
