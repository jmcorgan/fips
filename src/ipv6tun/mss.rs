//! The IPv6 adapter's TCP MSS clamp: the node-wide ceiling the TUN threads
//! share, and the per-destination ceiling read from the adapter's copy of
//! the path MTU map.

use super::core::PathMtuReplica;
use super::tcp_mss::clamp_tcp_mss;
use crate::Ipv6Address;
use std::sync::Arc;
use tracing::trace;

/// The IPv6 minimum link MTU (RFC 8200): every compliant path accepts a packet
/// this large, so an MSS derived from it fits anywhere.
///
/// Three uses, and they must not disagree: the cold-flow fallback in
/// [`flow_ceiling`], and the two seeds of the node-wide limit before any
/// transport has bound, the adapter's (`MeshState::new`) and the node's record
/// of what it has published (`NodeMtuFeed::new`). It is also the value
/// `Node::transport_mtu()` falls back to when nothing is bound.
pub const IPV6_MIN_MTU: u16 = 1280;

/// The TCP MSS ceiling the IPv6 adapter derives from the node-wide payload
/// limit, shared live with the TUN reader and writer threads.
///
/// Shared rather than copied because the limit moves at runtime. The node
/// publishes it from `Node::transport_mtu()`, the minimum across *bound*
/// transports, and a transport can bind minutes after start or unbind
/// mid-operation: a narrow interface appearing must tighten the clamp, and
/// its departure must release it. The adapter stores the ceiling of each
/// limit the node pushes over the link here (`MeshState` in `core.rs`), so
/// the threads clamp by the limit last published rather than one captured
/// at spawn.
///
/// A relaxed load per packet, beside the `PathMtuReplica` read that already
/// happens on the same packet — strictly the cheaper of the two. Ordering is
/// irrelevant: this is a clamp, and a packet that reads the previous value
/// during the store is clamped by the ceiling that was correct a microsecond
/// earlier. The per-flow ceiling has always had that property.
pub type MssCeiling = Arc<std::sync::atomic::AtomicU16>;

/// Compute the effective TCP MSS ceiling for a packet given its peer
/// address bytes (a 16-byte IPv6 destination on outbound, source on
/// inbound). Returns `min(global_max_mss, learned_path_max_mss)` when
/// the per-destination path MTU is known via discovery; otherwise
/// returns `min(global_max_mss, ipv6_minimum_safe_max_mss)`, the
/// conservative IPv6-minimum-derived ceiling.
///
/// The conservative empty-lookup fallback exists because there is a
/// race window between TCP-SYN-out and discovery-completes-with-path-
/// MTU on cold flows. Without the floor, the first SYN exits at the
/// kernel-natural MSS (TUN MTU minus IPv6/TCP headers), which can
/// exceed what some downstream forwarder hop is willing to carry.
/// The drop is silent (no PTB feedback through the userspace TUN to
/// the kernel TCP stack), so TCP retransmits at the same too-large
/// MSS and the application's first connection wedges before discovery
/// completes for a corrected second SYN to fire.
///
/// RFC 8200 mandates every IPv6 path accepts at least 1280-byte
/// packets, so a SYN clamped to the IPv6-minimum-derived MSS fits
/// any compliant path. Subsequent flows pick up the actual learned
/// per-destination value, which can be larger (when path supports
/// it) or smaller (when path is observed-tighter than the IPv6 min).
///
/// The node reports each learned path as a payload limit; the shim turns it
/// into an IPv6 MTU, and the 40-byte IPv6 and 20-byte TCP headers come off
/// that (see [`tcp_mss`](super::mtu::tcp_mss)). The ceiling itself is
/// [`flow_ceiling`]'s, which the node's re-clamp of a held SYN shares.
pub(crate) fn per_flow_max_mss(
    lookup: &PathMtuReplica,
    addr_bytes: &[u8],
    global_max_mss: u16,
) -> u16 {
    use super::mtu::tcp_mss;

    let empty_lookup_ceiling = flow_ceiling(None, global_max_mss);

    if addr_bytes.len() != 16 {
        trace!(
            len = addr_bytes.len(),
            global_max_mss,
            empty_lookup_ceiling,
            "per_flow_max_mss: addr_bytes wrong length, fall back to conservative ceiling"
        );
        return empty_lookup_ceiling;
    }
    let Ok(fips_addr) = Ipv6Address::from_slice(addr_bytes) else {
        trace!(
            global_max_mss,
            empty_lookup_ceiling,
            "per_flow_max_mss: Ipv6Address::from_slice rejected (non-fd::/8 prefix), fall back to conservative ceiling"
        );
        return empty_lookup_ceiling;
    };
    let Ok(map) = lookup.read() else {
        trace!(
            fips_addr = %fips_addr,
            global_max_mss,
            empty_lookup_ceiling,
            "per_flow_max_mss: lookup read lock poisoned, fall back to conservative ceiling"
        );
        return empty_lookup_ceiling;
    };
    let Some(payload_limit) = map.get(&fips_addr).copied() else {
        trace!(
            fips_addr = %fips_addr,
            global_max_mss,
            empty_lookup_ceiling,
            map_len = map.len(),
            "per_flow_max_mss: no path_mtu_lookup entry for destination, fall back to conservative ceiling"
        );
        return empty_lookup_ceiling;
    };
    let path_max_mss = tcp_mss(payload_limit);
    let result = flow_ceiling(Some(payload_limit), global_max_mss);
    // `trace!`, not `warn!`, because this runs on every packet rather than
    // only on SYNs: one degenerate stored value would otherwise emit a WARN
    // per packet indefinitely and bury every other warning on the node. The
    // link promotion path warns once instead.
    if path_max_mss == 0 {
        trace!(
            fips_addr = %fips_addr,
            payload_limit,
            empty_lookup_ceiling,
            "per_flow_max_mss: stored path_mtu leaves no room for a TCP payload byte, using conservative ceiling"
        );
        return result;
    }
    trace!(
        fips_addr = %fips_addr,
        payload_limit,
        path_max_mss,
        global_max_mss,
        result,
        "per_flow_max_mss: per-destination clamp applied"
    );
    result
}

/// The TCP MSS ceiling for a flow under the node-wide ceiling `global`, given
/// the payload limit of the stored path to its far end, or `None` when
/// nothing is stored: `min(global, tcp_mss(payload_limit))`, or the
/// conservative `min(global, mss_ceiling(1280))` when nothing is stored or
/// the stored limit leaves no room for one TCP payload byte.
///
/// The system TUN reader's clamp ([`per_flow_max_mss`]) and the node's
/// re-clamp of a held SYN at release both take their ceiling from here, so
/// the two cannot disagree.
pub(crate) fn flow_ceiling(payload_limit: Option<u16>, global: u16) -> u16 {
    use super::mtu::{mss_ceiling, tcp_mss};

    // RFC 8200 IPv6-minimum MTU (1280) → effective FIPS-encapsulated
    // payload (1203) → TCP segment after IPv6+TCP headers (1143).
    // Used as the conservative ceiling for empty-lookup destinations.
    let empty_lookup_ceiling = std::cmp::min(global, mss_ceiling(IPV6_MIN_MTU));
    let Some(payload_limit) = payload_limit else {
        return empty_lookup_ceiling;
    };
    let path_max_mss = tcp_mss(payload_limit);
    // The actionable floor deliberately does not apply here. Every value a
    // remote party supplies is refused before it can reach this map, at the
    // path MTU state machine, the reactive `MtuExceeded` write and the
    // discovery response, so a small stored value is one the node derived
    // from its own outgoing link: a configured transport MTU, or the MTU a
    // BLE connection negotiated, which on that transport is routinely well
    // under the floor. Such a value is exact rather than suspect, and the
    // tight clamp it yields is the reason it is stored: discarding it would
    // advertise the conservative ceiling on a link that cannot carry it, and
    // a direct link has no forwarder to answer with `MtuExceeded`, so the
    // flow would stall with no feedback.
    //
    // What no provenance rescues is the arithmetic degenerating. At a stored
    // MTU of 137 or less (a payload limit of 27 or less) not one payload byte fits alongside the IPv6 and TCP
    // headers, and `clamp_tcp_mss` refuses a ceiling of zero, which would
    // leave the SYN carrying the kernel-natural MSS instead. Fall back to the
    // conservative ceiling there; any positive result is by construction the
    // largest segment the stored MTU admits.
    if path_max_mss == 0 {
        return empty_lookup_ceiling;
    }
    std::cmp::min(global, path_max_mss)
}

/// Which address of a packet names the far end of its flow: the source of a
/// packet toward the host, the destination of one from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Remote {
    /// The source address, bytes 8 to 24 of the IPv6 header.
    Source,
    /// The destination address, bytes 24 to 40 of the IPv6 header.
    Destination,
}

/// Clamp the MSS option of a SYN-flagged TCP segment in `packet` to the
/// smaller of `ceiling` and the path ceiling for the flow's far end, read
/// from `paths` at the address `remote` names. A packet too short to hold
/// that address is clamped to `ceiling` alone. Returns the ceiling applied
/// when the segment was clamped.
pub(crate) fn clamp(
    packet: &mut [u8],
    ceiling: u16,
    paths: &PathMtuReplica,
    remote: Remote,
) -> Option<u16> {
    let at = match remote {
        Remote::Source => 8,
        Remote::Destination => 24,
    };
    let limit = if packet.len() >= at + 16 {
        per_flow_max_mss(paths, &packet[at..at + 16], ceiling)
    } else {
        ceiling
    };
    clamp_tcp_mss(packet, limit).then_some(limit)
}

#[cfg(test)]
#[path = "tests/mss.rs"]
mod tests;
