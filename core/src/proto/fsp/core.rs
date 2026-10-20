//! Sans-IO FSP session decision core.
//!
//! Pure, runtime-agnostic decisions for the FSP end-to-end session lifecycle:
//! the coordinate and path-MTU reactions, and the transforms applied to
//! session data. The async session handlers in `node::handlers::session`
//! pass in the facts these decisions read, call them, and drive the returned
//! effects: the cache writes, lookups, metrics and logging. No I/O, no
//! clock, no crypto, no metrics, no logging here.
//!
//! A session's handshakes, keys and epochs are held by its rekey machine
//! (`proto::rekey` on the profile in `fsp::rekey`), which `SessionEntry` owns
//! shell-side and which runs the first handshake and decides every rekey,
//! cutover and drain; this core carries no `proto -> noise` and no
//! `proto -> node` dependency.

use super::quorum::QuorumVerdict;
use crate::identity::{Ipv6Address, NodeAddr};
use alloc::vec;
use alloc::vec::Vec;

/// FSP session-lifecycle subsystem anchor owned by `Node`.
///
/// Like [`Fmp`](crate::proto::fmp::Fmp), the FSP core owns **no** mutable state:
/// every `SessionEntry`/coord-cache/path-MTU mutation stays shell-side, driven
/// by the [`FspAction`]s (and outcome enums) the pure decisions emit. `Fsp` is a
/// stateless namespace anchor so the decisions can hang off a `Node` field
/// (`self.fsp`) in the same shape the other migrated subsystems use.
pub struct Fsp;

/// The same as `Fsp::new`.
impl Default for Fsp {
    fn default() -> Self {
        Self::new()
    }
}

impl Fsp {
    /// Create the (stateless) FSP lifecycle anchor.
    pub fn new() -> Self {
        Self
    }
}

/// A coordinate-cache, path-MTU or discovery effect the async shell performs
/// on the core's behalf.
///
/// A variant exists only while a decision here emits it, since an
/// unconstructed variant would trip `clippy::dead_code`. Rekey, cutover and
/// drain effects are the session rekey machine's outputs, not variants here.
#[derive(Debug, PartialEq, Eq)]
pub enum FspAction {
    /// Invalidate the shared cached coordinates for `addr`
    /// (`coord_cache.remove`).
    InvalidateCoords { addr: NodeAddr },
    /// Mark the shared cached coordinates for `addr` as an unverified hint,
    /// keeping the value (`coord_cache.demote`). The entry goes on routing,
    /// but no longer refuses a hint that replaces it.
    DemoteCoords { addr: NodeAddr },
    /// Write `mtu` into the shared `Ipv6Address`-keyed path-MTU lookup, keeping
    /// the tighter of existing-or-new (the shell applies the write under the
    /// `path_mtu_lookup` guard).
    TightenPathMtuLookup { fips_addr: Ipv6Address, mtu: u16 },
    /// Trigger discovery toward `dest` (`maybe_initiate_lookup`). The
    /// `CoordsRequired` decision emits it only when the target's identity is
    /// cached; the `PathBroken` decision emits it always.
    InitiateLookup { dest: NodeAddr },
}

impl Fsp {
    /// Decide the discovery reaction to a `CoordsRequired` signal: trigger a
    /// lookup toward `dest` only when the target's identity is cached (else the
    /// `LookupResponse` proof cannot be verified). The rate-limited warmup send
    /// and warmup-counter reset stay shell-side.
    pub fn plan_coords_required_lookup(
        &self,
        dest: NodeAddr,
        has_cached_identity: bool,
    ) -> Vec<FspAction> {
        if has_cached_identity {
            vec![FspAction::InitiateLookup { dest }]
        } else {
            Vec::new()
        }
    }

    /// Decide the reaction to an admitted `PathBroken` signal for `dest`.
    ///
    /// The signal is unauthenticated, so it may not discard coordinates a
    /// lookup verified on its own say-so. `verified` is whether the cached
    /// entry for `dest` is verified and still within its verification window;
    /// `quorum` is what this report did to the destination's link quorum
    /// (ignored when the entry is not verified).
    ///
    /// - Not verified: remove the entry, as a hint can be replaced by any warm
    ///   anyway, then look it up.
    /// - Verified, quorum reached: demote the entry to a hint, keeping the
    ///   value, then look it up.
    /// - Verified, below quorum: leave the entry alone and look it up. A
    ///   successful lookup replaces the value whatever it was.
    ///
    /// The lookup is emitted in every case. The warmup send, path-MTU release
    /// and warmup-counter reset stay shell-side.
    pub fn plan_path_broken(
        &self,
        dest: NodeAddr,
        verified: bool,
        quorum: QuorumVerdict,
    ) -> Vec<FspAction> {
        let lookup = FspAction::InitiateLookup { dest };
        match (verified, quorum) {
            (false, _) => vec![FspAction::InvalidateCoords { addr: dest }, lookup],
            (true, QuorumVerdict::Reached) => vec![FspAction::DemoteCoords { addr: dest }, lookup],
            (true, QuorumVerdict::Below { .. }) => vec![lookup],
        }
    }

    /// Decide whether a path-MTU update should tighten the shared lookup: emit
    /// `TightenPathMtuLookup` only when there is no `existing` value or
    /// `candidate` is strictly tighter than it (keep-tighter, never loosen).
    /// The `existing` read and the applied write are performed shell-side
    /// under one `path_mtu_lookup` write guard, so the decision stays atomic.
    pub fn plan_path_mtu_tighten(
        &self,
        fips_addr: Ipv6Address,
        existing: Option<u16>,
        candidate: u16,
    ) -> Vec<FspAction> {
        if should_apply_path_mtu(existing, candidate) {
            vec![FspAction::TightenPathMtuLookup {
                fips_addr,
                mtu: candidate,
            }]
        } else {
            Vec::new()
        }
    }
}

/// Decide whether a path-MTU update should be applied to the shared
/// `Ipv6Address`-keyed lookup: keep the tighter of existing-or-candidate, never
/// loosen. Returns `true` when `candidate` should be written (there is no
/// existing value, or the candidate is strictly tighter). An equal candidate is
/// not written, so the stored entry, and any learn time it carries, is kept.
pub fn should_apply_path_mtu(existing: Option<u16>, candidate: u16) -> bool {
    !matches!(existing, Some(existing) if existing <= candidate)
}

/// Push `packet` onto a bounded per-destination pending queue, dropping the
/// oldest entry first when the queue is at `per_dest` capacity. Pure transform
/// over a passed-in queue (the max-destinations cap is a shell-side map-level
/// check).
pub fn push_bounded_pending<T>(
    queue: &mut alloc::collections::VecDeque<T>,
    packet: T,
    per_dest: usize,
) {
    if queue.len() >= per_dest {
        queue.pop_front(); // Drop oldest
    }
    queue.push_back(packet);
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
pub fn mark_ipv6_ecn_ce(packet: &mut [u8]) {
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
