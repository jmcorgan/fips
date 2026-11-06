//! Path selection (multipath v1 draft, Section 5.7 and its note, and the
//! note of Section 5.5): the score of a path and the order in which a
//! link's Live paths are ranked for the active path.
//!
//! A path's score is the quality index the spanning tree costs a link by,
//! its expected transmission count times one plus its least round trip
//! over 100 ms, lower being better. The least round trip is taken over the
//! samples its window holds: at most the last 32, none older than the
//! round-trip window when the latest was taken. Selection reads a score
//! only once the path has `min_samples` round-trip samples; a path with
//! fewer ranks behind every scored one, by its latest round trip.
//!
//! A path ranks first by the tier of its transport's role: a backup
//! transport's paths below a normal or preferred one's, and a path held
//! on a transport since set never to carry paths below them all. Within
//! the highest tier present, a path whose link MTU carries a
//! `FilterAnnounce` ([`FILTER_FRAME`], draft Section 5.11) is taken over
//! one whose link MTU does not, whatever their scores, while any such path
//! is a rival; among those, a path on a preferred transport is taken over
//! a better-scoring one while its score is within the switch margin of
//! the best.
//!
//! An operator's [`Pin`] comes before tiers, the `FilterAnnounce` and
//! scores: while a Live, acked path it names is held, only the paths it
//! names are ranked.
//!
//! A change of active path holds the link's cost ([`Hold`]), a choice of
//! this implementation, since the draft leaves the link cost of a bundle
//! to the node (Section 5.12, its note): the cost the spanning tree sees
//! stays at its value from before the change until the switch dwell has
//! passed and two receiver reports have arrived since.
//!
//! Nothing here reads a clock or allocates: the rivals of a choice are a
//! fixed array, one slot per path the link may hold, and a hold is timed
//! on the host's instants.

use super::live::Liveness;
use super::set::PATH_MAX_PER_PEER;
use super::{PathRef, Role};
use crate::proto::bloom::V1_SIZE_CLASS;
use crate::proto::fmp::wire::FRAME_OVERHEAD;
use crate::proto::mmp::quality_index;
use crate::time::{Duration, Instant, deadline};
use crate::transport::{TransportAddr, TransportId};

/// The bytes of the established frame that carries a node's
/// `FilterAnnounce` to its peer, 1,071: the frame's overhead around a link
/// message, and the message itself, whose type byte, 8-byte sequence,
/// hash count and size class come to 11 bytes ahead of a filter of
/// `512 << V1_SIZE_CLASS` bytes, sized by the shift as the bloom encoder
/// sizes it. A path whose link MTU is smaller cannot carry the filter
/// (draft Section 5.11).
pub(super) const FILTER_FRAME: usize = FRAME_OVERHEAD + 11 + (512 << V1_SIZE_CLASS);

/// The score of the path whose liveness is `live`: the quality index of
/// its ETX and its least round trip in milliseconds, lower being better.
/// `None` until a round trip has been measured.
pub(super) fn score<I: Instant>(live: &Liveness<I>) -> Option<f64> {
    live.min_rtt()
        .map(|rtt| quality_index(live.etx(), rtt.as_secs_f64() * 1000.0))
}

/// One Live, acked path a choice may take.
#[derive(Clone, Copy, Debug)]
pub(super) struct Rival {
    /// The path's index in the link's set.
    pub(super) index: usize,
    /// Its score, only once it has enough round-trip samples.
    pub(super) score: Option<f64>,
    /// Its latest round trip.
    pub(super) rtt: Option<Duration>,
    /// The tier of its transport's role ([`tier`]).
    pub(super) tier: u8,
    /// Whether its transport's role is `Preferred`.
    pub(super) preferred: bool,
    /// Whether the operator's pin names it.
    pub(super) pinned: bool,
    /// Whether its link MTU carries a frame of [`FILTER_FRAME`] bytes.
    pub(super) fits: bool,
}

/// An operator's pin of a link: to one of its paths, by the pair, or to
/// whichever of its paths on a transport the usual rules rank first. While
/// a Live, acked path the pin names is held, the link moves to it at once
/// and stays there, whatever the scores, roles and link MTUs of the
/// others; while none is, the pin is suspended and the link's paths are
/// chosen as with no pin. It lasts until it is lifted or its transport is
/// removed, its interface leaving included, or until the bundle ends; the
/// host lifts it when the peer is replaced and the link kept, and a
/// crossed handshake won on the tie-break keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    /// The local transport.
    pub transport: TransportId,
    /// The peer's address on it, or `None` for any path on it.
    pub addr: Option<TransportAddr>,
}

impl Pin {
    /// Whether the pin names the path `to`.
    pub fn names(&self, to: &PathRef) -> bool {
        to.transport == self.transport && self.addr.as_ref().is_none_or(|a| *a == to.addr)
    }
}

/// The tier of a transport whose role is `role`, higher ranking first: a
/// normal or preferred transport above a backup one, and a transport set
/// never to carry paths below both, so a path held on it from before
/// carries the link only while no other path is Live.
pub(super) fn tier(role: Role) -> u8 {
    match role {
        Role::Never => 0,
        Role::Backup => 1,
        Role::Normal | Role::Preferred => 2,
    }
}

/// The rivals of one choice, each in its path's slot.
pub(super) type Field = [Option<Rival>; PATH_MAX_PER_PEER];

/// The rival a choice takes, among the pinned rivals while any rival is
/// pinned, among those the rivals of the highest tier present, and among
/// those the rivals that carry a `FilterAnnounce` while any does: the
/// least score among the scored rivals, unless a scored preferred rival
/// scores at most `margin` times that least, in which case the
/// least-scoring such rival; with none scored, the least latest round
/// trip, a rival with none measured last. Every tie goes to the lower
/// index. `None` for an empty field.
pub(super) fn choose(field: &Field, margin: f64) -> Option<usize> {
    let rivals = ranked(field);
    let least = |r: &Rival| r.score.map(|s| (s, r.index));
    let order = |a: &(f64, usize), b: &(f64, usize)| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1));
    if let Some((best, index)) = rivals.clone().filter_map(least).min_by(order) {
        let preferred = rivals
            .clone()
            .filter(|r| r.preferred)
            .filter_map(least)
            .filter(|&(s, _)| s <= best * margin)
            .min_by(order);
        return Some(preferred.map_or(index, |(_, i)| i));
    }
    rivals
        .min_by_key(|r| (r.rtt.is_none(), r.rtt, r.index))
        .map(|r| r.index)
}

/// The least score among the scored rivals [`choose`] ranks, the score a
/// preferred rival must stay within the margin of to keep its
/// precedence. `None` with none scored.
pub(super) fn best(field: &Field) -> Option<f64> {
    ranked(field).filter_map(|r| r.score).min_by(f64::total_cmp)
}

/// The rivals [`choose`] ranks: the pinned rivals while any rival is
/// pinned, among those the rivals of the highest tier present, and among
/// those the rivals that carry a `FilterAnnounce` while any does.
fn ranked(field: &Field) -> impl Iterator<Item = &Rival> + Clone {
    let all = field.iter().flatten();
    let pinned = all.clone().any(|r| r.pinned);
    let named = all.filter(move |r| r.pinned || !pinned);
    let top = named.clone().map(|r| r.tier).max();
    let fit = named.clone().any(|r| Some(r.tier) == top && r.fits);
    named.filter(move |r| Some(r.tier) == top && (r.fits || !fit))
}

/// The receiver reports a hold waits for after a change of active path:
/// the first spans the change and counts the frames lost in flight on the
/// path left, and the second replaces it.
const REPORTS: u8 = 2;

/// The hold on a link's cost after a change of active path: the cost from
/// just before the change, held until both the switch dwell has passed
/// since the change and [`REPORTS`] receiver reports have arrived since.
/// Without it, one report that spans the change could move the spanning
/// tree's parent.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct Hold<I> {
    /// The cost held.
    cost: f64,
    /// The instant of the change.
    at: I,
    /// The receiver reports still to come.
    owed: u8,
}

impl<I: Instant> Hold<I> {
    /// A hold of `cost` from a change of active path at `at`, owing every
    /// report.
    pub(super) fn new(cost: f64, at: I) -> Self {
        Self {
            cost,
            at,
            owed: REPORTS,
        }
    }

    /// Count one receiver report toward the hold.
    pub(super) fn report(&mut self) {
        self.owed = self.owed.saturating_sub(1);
    }

    /// The cost held at `now`, while the hold is in force under a switch
    /// dwell of `dwell`: before the dwell has passed since the change, or
    /// while a report is still owed. `None` once both have passed.
    pub(super) fn held(&self, now: I, dwell: Duration) -> Option<f64> {
        (now < deadline(self.at, dwell) || self.owed > 0).then_some(self.cost)
    }
}

#[cfg(test)]
#[path = "tests/select.rs"]
mod tests;
