//! IPv6 fragmentation at the node that carries a host's packet onto the mesh.
//!
//! IPv6 promises every path 1280 bytes (RFC 8200 Section 5), and a host
//! ignores a Packet Too Big that reports less (RFC 8201 Section 4; Linux drops
//! it). When a FIPS path cannot carry 1280 bytes after encapsulation, a packet
//! between the path's IPv6 MTU and 1280 bytes therefore has no remedy at the
//! host. The node that read it from its TUN splits it into ordinary IPv6
//! fragments instead, and the destination host reassembles them. RFC 8200
//! reserves fragmentation to the source and asks a link that cannot carry 1280
//! bytes to fragment below IPv6; the ingress node does this on the link's
//! behalf. The fragments are IPv6 packets like any other, so the FIPS wire
//! format and every other node are unchanged.
//!
//! Only packets the host could not have sized down are split. Anything else
//! (a packet that fits, one over 1280 bytes, one this module cannot split
//! correctly) is left to the caller's Packet Too Big, as before.

use crate::upper::icmp::{FIPS_IPV6_OVERHEAD, MIN_ACTIONABLE_PATH_MTU};
use crate::upper::tun::IPV6_MIN_MTU;

/// Fixed IPv6 header length.
const HDR: usize = 40;
/// IPv6 Fragment extension header length.
const FRAG_HDR: usize = 8;
/// The IPv6 minimum MTU, the largest packet this module splits.
const MIN_MTU: usize = IPV6_MIN_MTU as usize;
/// Largest end, in bytes, of a fragment's data within the original payload:
/// the 13-bit offset field counts 8-byte units, and a reassembled payload
/// cannot exceed the 16-bit payload length.
const MAX_DATA_END: usize = 65535;
/// Most extension headers walked before the upper-layer header.
const MAX_EXT_HEADERS: usize = 8;

/// Smallest data chunk a fragment may carry: the chunk at the smallest path
/// MTU a node acts on (an IPv6 MTU of 179, a chunk of 128 bytes). A
/// 1280-byte packet is therefore never split into more than ten fragments,
/// whatever MTU a link or a forged signal reports.
const MIN_FRAG_DATA: usize =
    ((MIN_ACTIONABLE_PATH_MTU - FIPS_IPV6_OVERHEAD) as usize - HDR - FRAG_HDR) & !7;

// Next-header values.
const NH_HOP_BY_HOP: u8 = 0;
const NH_TCP: u8 = 6;
const NH_UDP: u8 = 17;
const NH_ROUTING: u8 = 43;
const NH_FRAGMENT: u8 = 44;
const NH_ESP: u8 = 50;
const NH_AH: u8 = 51;
const NH_ICMPV6: u8 = 58;
const NH_NONE: u8 = 59;
const NH_DEST_OPTS: u8 = 60;

/// How a packet is to be split: what goes in each Fragment header, the data
/// to split, and the data each fragment carries.
struct Split<'a> {
    /// Next header of the fragmentable part, written into each Fragment header.
    inner_nh: u8,
    /// Offset of `data` within the original payload (non-zero only when the
    /// packet is already a host-made fragment).
    base: usize,
    /// M flag of the last piece (set only when splitting a host-made
    /// fragment that is not the last of its datagram).
    last_more: bool,
    /// Identification of a host-made fragment, kept for its pieces.
    ident: Option<u32>,
    /// The fragmentable part to split.
    data: &'a [u8],
    /// Data bytes per fragment, a multiple of 8.
    chunk: usize,
}

/// Decide whether `packet` is this node's to fragment for a path whose IPv6
/// MTU is `mtu`, and how.
fn plan(packet: &[u8], mtu: usize) -> Option<Split<'_>> {
    // Over the MTU but no larger than the IPv6 minimum, which implies an MTU
    // under 1280: the case the host has no remedy for.
    if packet.len() <= mtu || packet.len() > MIN_MTU {
        return None;
    }
    if packet.len() < HDR || packet[0] >> 4 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if HDR + payload_len != packet.len() {
        return None;
    }
    let payload = &packet[HDR..];
    let (inner_nh, base, last_more, ident, data) = if packet[6] == NH_FRAGMENT {
        let f = payload.get(..FRAG_HDR)?;
        let offset_m = u16::from_be_bytes([f[2], f[3]]);
        let ident = u32::from_be_bytes([f[4], f[5], f[6], f[7]]);
        let base = (offset_m & 0xfff8) as usize;
        (
            f[0],
            base,
            offset_m & 1 == 1,
            Some(ident),
            &payload[FRAG_HDR..],
        )
    } else {
        (packet[6], 0, false, None, payload)
    };
    if base + data.len() > MAX_DATA_END {
        return None;
    }
    let chunk = mtu.checked_sub(HDR + FRAG_HDR)? & !7;
    if chunk < MIN_FRAG_DATA {
        return None;
    }
    if base == 0 {
        // The first fragment must carry every header through the
        // upper-layer one (RFC 8200 Section 4.5).
        if headers_len(inner_nh, data)? > chunk {
            return None;
        }
    } else if matches!(inner_nh, NH_HOP_BY_HOP | NH_ROUTING | NH_FRAGMENT) {
        return None;
    }
    Some(Split {
        inner_nh,
        base,
        last_more,
        ident,
        data,
        chunk,
    })
}

/// Length of the fragmentable part's headers, from its first header `nh`
/// through the upper-layer header, or `None` when that chain cannot go into
/// fragments: a Hop-by-Hop, Routing or Fragment header (which belong before a
/// Fragment header, or would nest one), an upper-layer protocol this module
/// does not recognise, more than `MAX_EXT_HEADERS` headers, or a chain that
/// runs past the data.
fn headers_len(mut nh: u8, data: &[u8]) -> Option<usize> {
    let mut off = 0;
    for _ in 0..MAX_EXT_HEADERS {
        match nh {
            NH_DEST_OPTS | NH_AH => {
                let h = data.get(off..off + 2)?;
                let len = if nh == NH_AH {
                    (h[1] as usize + 2) * 4
                } else {
                    (h[1] as usize + 1) * 8
                };
                nh = h[0];
                off += len;
            }
            NH_TCP => {
                let data_offset = *data.get(off + 12)? >> 4;
                let len = data_offset as usize * 4;
                if len < 20 {
                    return None;
                }
                return (off + len <= data.len()).then_some(off + len);
            }
            NH_UDP | NH_ICMPV6 | NH_ESP => {
                return (off + 8 <= data.len()).then_some(off + 8);
            }
            NH_NONE => return (off <= data.len()).then_some(off),
            _ => return None,
        }
    }
    None
}

/// Whether [`fragment_for_path`] would split `packet` for a path whose IPv6
/// MTU is `mtu`. Runs the same checks without building the fragments.
pub fn can_fragment(packet: &[u8], mtu: usize) -> bool {
    plan(packet, mtu).is_some()
}

/// Split `packet` into IPv6 fragments that each fit `mtu`, or return `None`
/// when fragmenting is not this node's to do.
///
/// `Some` only when the packet is over `mtu` and at most 1280 bytes, is a
/// well-formed IPv6 packet whose payload length matches its size, has no
/// Hop-by-Hop or Routing header, carries a recognised upper-layer header that
/// fits whole in the first fragment, and `mtu` leaves each fragment at least
/// [`MIN_FRAG_DATA`] bytes of data. A packet that is already a fragment is
/// split further under its own identification, offset and final M flag, so
/// the receiver reassembles it with its siblings; any other packet gets
/// `ident`.
pub fn fragment_for_path(packet: &[u8], mtu: usize, ident: u32) -> Option<Vec<Vec<u8>>> {
    let split = plan(packet, mtu)?;
    let ident = split.ident.unwrap_or(ident);
    let data = split.data;
    let mut out = Vec::with_capacity(data.len().div_ceil(split.chunk));
    let mut pos = 0;
    while pos < data.len() {
        let end = (pos + split.chunk).min(data.len());
        let more = end < data.len() || split.last_more;
        let offset = (split.base + pos) as u16;
        let mut frag = Vec::with_capacity(HDR + FRAG_HDR + end - pos);
        frag.extend_from_slice(&packet[..HDR]);
        frag[4..6].copy_from_slice(&((FRAG_HDR + end - pos) as u16).to_be_bytes());
        frag[6] = NH_FRAGMENT;
        frag.extend_from_slice(&[split.inner_nh, 0]);
        frag.extend_from_slice(&(offset | more as u16).to_be_bytes());
        frag.extend_from_slice(&ident.to_be_bytes());
        frag.extend_from_slice(&data[pos..end]);
        out.push(frag);
        pos = end;
    }
    Some(out)
}

/// The MTU a Packet Too Big should report for a `packet_len`-byte packet
/// that does not fit `mtu` and is not fragmented.
///
/// A packet over 1280 bytes on a path under 1280 is answered with 1280: the
/// host accepts that value (it ignores anything lower), and its next packets,
/// of at most 1280 bytes, are fragmented. Otherwise the path's own value.
pub fn packet_too_big_mtu(packet_len: usize, mtu: usize) -> u32 {
    if packet_len > MIN_MTU && mtu < MIN_MTU {
        MIN_MTU as u32
    } else {
        mtu as u32
    }
}

#[cfg(test)]
#[path = "tests/ipv6_frag.rs"]
mod tests;
