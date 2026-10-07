//! Shared field vocabulary for diagnostic log lines.
//!
//! Lines about one link at both of its ends use the same field names and the
//! same renderings, so two nodes' logs can be joined on them: the transport
//! and address a message arrived on, a 4-byte prefix of a msg1's digest, and
//! a 4-byte prefix of a session's handshake hash, which both ends of a
//! session hold. Every value here displays without spaces, and an absent one as
//! `none`.
//!
//! Lines about a frame that failed to decrypt also say which of the peer's
//! sessions its index names and what key state the peer held, and a
//! per-packet line with no peer to suppress on shares one node-wide budget.
//!
//! A handshake outcome that repeats on a peer's handshakes is logged the first
//! three times in a session, then once as a notice, then only counted. The
//! count is logged with the first such line after a session change, or when
//! the peer is removed.
//!
//! Lines about filters carry an 8-byte digest of the filter bits, which the
//! sender and the receiver of one announce compute alike, and a peer's place
//! in the spanning tree as `tree_role`.

use super::rate_limit::TokenBucket;
use crate::noise::NoiseSession;
use crate::peer::ActivePeer;
use crate::proto::bloom::BloomFilter;
use crate::proto::fmp::Msg1Digest;
use crate::utils::index::SessionIndex;
use std::fmt;
use std::time::Instant;

/// Bytes displayed as lowercase hex, two digits per byte, no separators.
pub(crate) struct Hex<'a>(pub(crate) &'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// An `N`-byte prefix of a digest or hash, displayed as hex.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tag<const N: usize>([u8; N]);

impl<const N: usize> fmt::Display for Tag<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Hex(&self.0).fmt(f)
    }
}

/// A 4-byte prefix, displayed as 8 hex digits.
pub(crate) type Tag4 = Tag<4>;

/// The session's tag: the first four bytes of its handshake hash. Both ends
/// of a session derive the same hash, so both ends' lines carry the same tag.
pub(crate) fn epoch_tag(session: &NoiseSession) -> Tag4 {
    let h = session.handshake_hash();
    Tag([h[0], h[1], h[2], h[3]])
}

/// The msg1's tag: the first four bytes of its digest.
pub(crate) fn msg1_tag(digest: &Msg1Digest) -> Tag4 {
    Tag(digest.prefix())
}

/// How many leading bytes of a dropped frame a line shows.
const HEAD_BYTES: usize = 8;

/// The first bytes of a frame, up to eight, for a line about a frame that
/// was dropped before it could be parsed.
pub(crate) fn head(data: &[u8]) -> Hex<'_> {
    Hex(&data[..data.len().min(HEAD_BYTES)])
}

/// The filter's digest: the first eight bytes of a SHA-256 over its bits.
/// The sender and the receiver of one announce hash the same bits, so both
/// ends' lines carry the same digest.
pub(crate) fn filter_tag(filter: &BloomFilter) -> Tag<8> {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(filter.as_bytes());
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&h[..8]);
    Tag(tag)
}

/// A peer's place in this node's spanning tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TreeRole {
    /// The peer is this node's parent.
    Parent,
    /// The peer has declared this node its parent.
    Child,
    /// Neither: a link the tree does not use.
    None,
}

impl fmt::Display for TreeRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Parent => "parent",
            Self::Child => "child",
            Self::None => "none",
        })
    }
}

/// A ratio, displayed with three decimals.
pub(crate) struct Ratio(pub(crate) f64);

impl fmt::Display for Ratio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.3}", self.0)
    }
}

/// Names displayed joined by `,`, with no spaces.
pub(crate) struct Names(pub(crate) Vec<String>);

impl fmt::Display for Names {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.join(","))
    }
}

/// Displays the value, or `none` when there is none.
pub(crate) struct OrNone<T>(pub(crate) Option<T>);

impl<T: fmt::Display> fmt::Display for OrNone<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(v) => v.fmt(f),
            None => f.write_str("none"),
        }
    }
}

/// Which of a peer's sessions a receiver index names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Slot {
    /// The session the peer sends and receives on.
    Current,
    /// The session a cutover retired, still draining.
    Previous,
    /// A pending session from a completed rekey, not yet cut over. Which
    /// side initiated the rekey is not recorded on the peer.
    Pending,
    /// No session the peer holds, such as one whose drain has completed.
    Unknown,
}

impl Slot {
    /// The slot `idx` names among `peer`'s sessions.
    pub(crate) fn of(peer: &ActivePeer, idx: SessionIndex) -> Self {
        if peer.our_index() == Some(idx) {
            Self::Current
        } else if peer.previous_our_index() == Some(idx) {
            Self::Previous
        } else if peer.pending_our_index() == Some(idx) {
            Self::Pending
        } else {
            Self::Unknown
        }
    }
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Current => "current",
            Self::Previous => "previous",
            Self::Pending => "pending",
            Self::Unknown => "none",
        })
    }
}

/// The key state a decryption line logs, read from the peer as owned values
/// so the caller can release its borrow of the peer before logging.
pub(crate) struct KeyView {
    /// The slot the frame's index names.
    pub(crate) slot: Slot,
    /// This node's current K-bit.
    pub(crate) kbit_ours: OrNone<bool>,
    /// The current session's tag.
    pub(crate) epoch: OrNone<Tag4>,
    /// The draining previous session's tag.
    pub(crate) prev_epoch: OrNone<Tag4>,
    /// The pending session's tag.
    pub(crate) pending_epoch: OrNone<Tag4>,
}

impl KeyView {
    /// The key state of `peer` for a frame naming `idx`. Every field is
    /// `none` without a peer, and the slot is `none` without an index.
    pub(crate) fn of(peer: Option<&ActivePeer>, idx: Option<SessionIndex>) -> Self {
        let Some(p) = peer else {
            return Self {
                slot: Slot::Unknown,
                kbit_ours: OrNone(None),
                epoch: OrNone(None),
                prev_epoch: OrNone(None),
                pending_epoch: OrNone(None),
            };
        };
        Self {
            slot: idx.map_or(Slot::Unknown, |i| Slot::of(p, i)),
            kbit_ours: OrNone(Some(p.current_k_bit())),
            epoch: OrNone(p.noise_session().map(epoch_tag)),
            prev_epoch: OrNone(p.previous_session().map(epoch_tag)),
            pending_epoch: OrNone(p.pending_new_session().map(epoch_tag)),
        }
    }
}

/// Whether a failing frame was tried against the peer's pending session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Trial {
    /// The peer held no pending session.
    NotRunNoPending,
    /// A pending session was held, but the frame's K-bit matched ours and
    /// it did not name the pending index, so the gate did not try it.
    NotRunKbitEqual,
    /// The gate tried the pending session on a flipped K-bit and it did not
    /// authenticate the frame.
    Failed,
    /// The gate tried the pending session only because the frame named the
    /// pending index, its K-bit equal to ours, and it did not authenticate
    /// the frame.
    RunIndex,
}

impl Trial {
    /// The trial outcome for a frame that went on to fail: `pending` is
    /// whether a pending session was held, `tried` is the gate's own
    /// decision, and `kbit_differs` is whether the frame's K-bit differed
    /// from ours. A differing K-bit takes precedence, so `failed` keeps the
    /// meaning it had before an index match could select the trial. A trial
    /// that succeeded never reaches a failure line.
    pub(crate) fn of(pending: bool, tried: bool, kbit_differs: bool) -> Self {
        match (pending, tried, kbit_differs) {
            (false, _, _) => Self::NotRunNoPending,
            (true, false, _) => Self::NotRunKbitEqual,
            (true, true, true) => Self::Failed,
            (true, true, false) => Self::RunIndex,
        }
    }
}

impl fmt::Display for Trial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotRunNoPending => "not-run-no-pending",
            Self::NotRunKbitEqual => "not-run-kbit-equal",
            Self::Failed => "failed",
            Self::RunIndex => "run-index",
        })
    }
}

/// Lines a [`LogBudget`] admits at once.
const BUDGET_BURST: u32 = 10;
/// Lines per second a [`LogBudget`] admits after its burst.
const BUDGET_RATE: f64 = 1.0;

/// One node-wide budget for a per-packet line that has no authenticated peer
/// to suppress on. It holds no per-source state, so its size does not grow
/// with the number of sources sending, which an unauthenticated sender
/// chooses.
pub(crate) struct LogBudget {
    bucket: TokenBucket,
    withheld: u64,
}

impl LogBudget {
    /// A full budget as of `now`.
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            bucket: TokenBucket::with_params_at(BUDGET_BURST, BUDGET_RATE, now),
            withheld: 0,
        }
    }

    /// Whether to emit one more line at `now`. When admitted, returns how
    /// many lines were withheld since the last admitted one and resets that
    /// count; otherwise counts this line as withheld.
    pub(crate) fn admit(&mut self, now: Instant) -> Option<u64> {
        if self.bucket.try_acquire_at(now) {
            Some(std::mem::take(&mut self.withheld))
        } else {
            self.withheld = self.withheld.saturating_add(1);
            None
        }
    }
}

/// Lines of one kind a peer logs before the rest are suppressed.
pub(crate) const REPEAT_SHOWN: u32 = 3;

/// A handshake outcome whose line repeats for as long as a peer sends handshakes
/// faster than its state changes. Each kind is counted apart, so repeats of
/// one outcome never hide the first line of a different one, and a failed
/// answer is a different outcome from a sent one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HsLine {
    /// The stored msg2 was resent for a duplicate handshake.
    Resend,
    /// That resend failed.
    ResendFailed,
    /// A new-epoch msg3 was dropped by the restart gate.
    Restart,
    /// A msg3 was refused by the silent-session back-off. Counted on the
    /// identity's silent-session record, never on a peer entry.
    Refused,
}

impl HsLine {
    /// Number of kinds.
    const COUNT: usize = 4;
}

impl fmt::Display for HsLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Resend => "resend",
            Self::ResendFailed => "resend_failed",
            Self::Restart => "restart",
            Self::Refused => "refused",
        })
    }
}

/// What to log for the `count`th line of one kind: the line itself up to
/// [`REPEAT_SHOWN`], one notice in place of the next, then nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Shown {
    Line,
    Notice,
    Nothing,
}

impl Shown {
    /// The verdict for the `count`th occurrence, counting from 1.
    pub(crate) fn of(count: u32) -> Self {
        if count <= REPEAT_SHOWN {
            Self::Line
        } else if count == REPEAT_SHOWN + 1 {
            Self::Notice
        } else {
            Self::Nothing
        }
    }
}

/// Lines not logged out of `count` occurrences of one kind.
pub(crate) fn withheld(count: u32) -> u32 {
    count.saturating_sub(REPEAT_SHOWN)
}

/// Suppressed line counts by kind, for a summary line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Withheld([u32; HsLine::COUNT]);

impl Withheld {
    /// Lines of `kind` not logged.
    pub(crate) fn of(&self, kind: HsLine) -> u32 {
        self.0[kind as usize]
    }

    /// `self`, or `None` when no line of any kind was withheld.
    fn nonzero(self) -> Option<Self> {
        self.0.iter().any(|&n| n > 0).then_some(self)
    }
}

/// One peer's repeated handshake line counts. The current session's counts
/// restart at each session change; what they withheld moves into a carried
/// total that the next counted line, or the peer's removal, reports.
#[derive(Debug, Default)]
pub(crate) struct HsLineCounts {
    current: [u32; HsLine::COUNT],
    carried: Withheld,
}

impl HsLineCounts {
    /// Count one more line of `kind` this session, returning the new count.
    pub(crate) fn count(&mut self, kind: HsLine) -> u32 {
        let n = &mut self.current[kind as usize];
        *n = n.saturating_add(1);
        *n
    }

    /// The session changed: carry what this session withheld and start its
    /// counts again.
    pub(crate) fn roll(&mut self) {
        for (carried, current) in self.carried.0.iter_mut().zip(&mut self.current) {
            *carried = carried.saturating_add(withheld(std::mem::take(current)));
        }
    }

    /// Take what earlier sessions withheld, if anything.
    pub(crate) fn take_carried(&mut self) -> Option<Withheld> {
        std::mem::take(&mut self.carried).nonzero()
    }

    /// Everything withheld and not yet reported: earlier sessions' carried
    /// total plus this session's, if anything.
    pub(crate) fn unreported(&self) -> Option<Withheld> {
        let mut total = self.carried;
        for (t, &current) in total.0.iter_mut().zip(&self.current) {
            *t = t.saturating_add(withheld(current));
        }
        total.nonzero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tag_renders_exactly_the_first_four_bytes_of_a_msg1_digest() {
        let wire = b"a msg1";
        let digest = Msg1Digest::of(wire);
        let full: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(wire).into()
        };
        let want: String = full[..4].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(msg1_tag(&digest).to_string(), want);
        assert_eq!(Tag([0x00, 0x0a, 0xb0, 0xff]).to_string(), "000ab0ff");
    }

    #[test]
    fn an_absent_value_renders_as_none() {
        assert_eq!(OrNone::<u32>(None).to_string(), "none");
        assert_eq!(OrNone(Some(7u32)).to_string(), "7");
    }

    #[test]
    fn the_trial_reads_whether_a_pending_was_held_whether_the_gate_tried_it_and_on_which_signal() {
        for kbit_differs in [false, true] {
            assert_eq!(
                Trial::of(false, false, kbit_differs).to_string(),
                "not-run-no-pending"
            );
            assert_eq!(
                Trial::of(false, true, kbit_differs).to_string(),
                "not-run-no-pending"
            );
            assert_eq!(
                Trial::of(true, false, kbit_differs).to_string(),
                "not-run-kbit-equal"
            );
        }
        assert_eq!(Trial::of(true, true, true).to_string(), "failed");
        assert_eq!(Trial::of(true, true, false).to_string(), "run-index");
    }

    #[test]
    fn the_log_budget_admits_its_burst_then_one_line_a_second_with_the_withheld_count() {
        let t0 = Instant::now();
        let mut budget = LogBudget::new(t0);
        for _ in 0..BUDGET_BURST {
            assert_eq!(budget.admit(t0), Some(0));
        }
        assert_eq!(budget.admit(t0), None);
        assert_eq!(budget.admit(t0), None);

        let t1 = t0 + std::time::Duration::from_secs(1);
        assert_eq!(budget.admit(t1), Some(2), "the withheld count is reported");
        assert_eq!(budget.admit(t1), None, "and only one line is admitted");
        let t2 = t1 + std::time::Duration::from_secs(1);
        assert_eq!(budget.admit(t2), Some(1), "the count was reset");
    }

    #[test]
    fn a_repeated_line_is_logged_three_times_then_replaced_by_one_notice_then_dropped() {
        let shown: Vec<Shown> = (1..=6).map(Shown::of).collect();
        assert_eq!(
            shown,
            [
                Shown::Line,
                Shown::Line,
                Shown::Line,
                Shown::Notice,
                Shown::Nothing,
                Shown::Nothing
            ]
        );
        assert_eq!(withheld(3), 0);
        assert_eq!(withheld(4), 1);
        assert_eq!(withheld(u32::MAX), u32::MAX - REPEAT_SHOWN);
    }

    #[test]
    fn line_counts_are_kept_per_kind_and_carry_only_the_withheld_part_across_sessions() {
        let mut counts = HsLineCounts::default();
        for _ in 0..5 {
            counts.count(HsLine::Resend);
        }
        assert_eq!(
            counts.count(HsLine::Restart),
            1,
            "another kind counts apart"
        );
        assert_eq!(counts.unreported().map(|w| w.of(HsLine::Resend)), Some(2));

        // Two sessions of four lines each withheld one apiece.
        let mut counts = HsLineCounts::default();
        for _ in 0..2 {
            for _ in 0..4 {
                counts.count(HsLine::Restart);
            }
            counts.roll();
        }
        assert_eq!(counts.unreported().map(|w| w.of(HsLine::Restart)), Some(2));
        let carried = counts.take_carried().expect("lines were withheld");
        assert_eq!(carried.of(HsLine::Restart), 2);
        assert_eq!(carried.of(HsLine::Resend), 0);
        assert_eq!(counts.take_carried(), None, "taken once");
        assert_eq!(counts.count(HsLine::Restart), 1, "the count restarted");
    }

    #[test]
    fn a_count_saturates_instead_of_wrapping() {
        let mut counts = HsLineCounts::default();
        counts.current[HsLine::Restart as usize] = u32::MAX;
        assert_eq!(counts.count(HsLine::Restart), u32::MAX);
        counts.roll();
        counts.current[HsLine::Restart as usize] = u32::MAX;
        counts.roll();
        assert_eq!(
            counts.unreported().map(|w| w.of(HsLine::Restart)),
            Some(u32::MAX)
        );
    }

    #[test]
    fn a_key_view_without_a_peer_renders_none_for_every_field() {
        let v = KeyView::of(None, None);
        for value in [
            v.slot.to_string(),
            v.kbit_ours.to_string(),
            v.epoch.to_string(),
            v.prev_epoch.to_string(),
            v.pending_epoch.to_string(),
        ] {
            assert_eq!(value, "none");
        }
    }

    #[test]
    fn hex_and_an_eight_byte_tag_render_exactly_their_bytes() {
        assert_eq!(Hex(&[0x00, 0x0a, 0xb0, 0xff]).to_string(), "000ab0ff");
        assert_eq!(Hex(&[]).to_string(), "");
        let tag = Tag([0x00, 0x0a, 0xb0, 0xff, 0x01, 0x10, 0x7f, 0x80]);
        assert_eq!(tag.to_string(), "000ab0ff01107f80");
    }

    #[test]
    fn the_head_of_a_frame_is_at_most_its_first_eight_bytes() {
        let frame: Vec<u8> = (0x10..0x24).collect();
        assert_eq!(head(&frame[..4]).to_string(), "10111213");
        assert_eq!(head(&frame).to_string(), "1011121314151617");
    }

    #[test]
    fn a_filter_tag_is_the_first_eight_bytes_of_the_hash_of_its_bits() {
        use sha2::{Digest, Sha256};
        let mut filter = BloomFilter::new();
        filter.insert(&crate::testutil::make_node_addr(0x31));
        let full: [u8; 32] = Sha256::digest(filter.as_bytes()).into();
        let want: String = full[..8].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(filter_tag(&filter).to_string(), want);
        assert_ne!(
            filter_tag(&filter),
            filter_tag(&BloomFilter::new()),
            "different bits give different tags"
        );
    }

    #[test]
    fn tree_roles_ratios_and_names_render_without_spaces() {
        assert_eq!(TreeRole::Parent.to_string(), "parent");
        assert_eq!(TreeRole::Child.to_string(), "child");
        assert_eq!(TreeRole::None.to_string(), "none");
        assert_eq!(Ratio(1.0).to_string(), "1.000");
        assert_eq!(Ratio(2.0 / 3.0).to_string(), "0.667");
        assert_eq!(Names(vec!["a".into(), "b".into()]).to_string(), "a,b");
        assert_eq!(Names(vec![]).to_string(), "");
    }
}
