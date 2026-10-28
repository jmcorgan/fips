//! The IPv6 extension header chain (RFC 8200 Section 4): where a packet's
//! upper-layer header starts, past any extension headers between it and the
//! fixed header.
//!
//! The ICMPv6 error checks use it to find an ICMPv6 message that is not
//! straight after the fixed header, and the TCP MSS clamp to find a TCP
//! header that is not.

/// Hop-by-Hop Options.
const HOP_OPTS: u8 = 0;
/// Routing.
const ROUTING: u8 = 43;
/// Fragment.
const FRAGMENT: u8 = 44;
/// Authentication Header (RFC 4302).
const AUTH: u8 = 51;
/// Destination Options.
const DEST_OPTS: u8 = 60;

/// What the walk from the fixed header found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Chain {
    /// The upper-layer header: its protocol number, its offset in the
    /// packet, and whether an Authentication or Fragment header comes
    /// before it. A protocol the walk does not step over ends it, so ESP
    /// (50), No Next Header (59) and any unknown value are reported here
    /// with the offset of that header.
    Upper {
        /// The upper-layer protocol number.
        proto: u8,
        /// Where its header starts.
        at: usize,
        /// Whether an Authentication or Fragment header precedes it, so
        /// that rewriting the upper layer would break the packet.
        sealed: bool,
    },
    /// A fragment other than the first: it names the upper-layer protocol
    /// in its Fragment header but carries none of that protocol's header.
    LaterFragment {
        /// The upper-layer protocol number the Fragment header names.
        proto: u8,
    },
    /// The packet is not IPv6, is shorter than its fixed header, or an
    /// extension header runs past its end.
    Truncated,
}

/// Walk `packet`'s extension headers from its fixed header's Next Header
/// field to its upper-layer header, stepping over Hop-by-Hop, Routing and
/// Destination Options headers (each `(length + 1) * 8` bytes), an
/// Authentication Header (`(length + 2) * 4` bytes) and a first Fragment
/// header (8 bytes). Every step is bounds-checked and moves forward by at
/// least 8 bytes, so the walk ends.
pub(crate) fn upper(packet: &[u8]) -> Chain {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return Chain::Truncated;
    }
    let (mut next, mut at, mut sealed) = (packet[6], 40, false);
    loop {
        let len = match next {
            HOP_OPTS | ROUTING | DEST_OPTS | AUTH | FRAGMENT if packet.len() < at + 8 => {
                return Chain::Truncated;
            }
            HOP_OPTS | ROUTING | DEST_OPTS => (usize::from(packet[at + 1]) + 1) * 8,
            AUTH => (usize::from(packet[at + 1]) + 2) * 4,
            FRAGMENT => {
                let offset = u16::from_be_bytes([packet[at + 2], packet[at + 3]]) >> 3;
                if offset != 0 {
                    return Chain::LaterFragment { proto: packet[at] };
                }
                8
            }
            proto => return Chain::Upper { proto, at, sealed },
        };
        sealed |= matches!(next, AUTH | FRAGMENT);
        next = packet[at];
        at += len;
        if at > packet.len() {
            return Chain::Truncated;
        }
    }
}

#[cfg(test)]
#[path = "tests/exthdr.rs"]
mod tests;
