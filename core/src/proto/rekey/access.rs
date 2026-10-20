//! What a link shell reads from its machine, and the link setup's record
//! it hands it after promotion.
//!
//! The link machines decide every rekey through `step`, and take every
//! input there, a decrypt worker's acceptance of an epoch included. One
//! move still reaches a machine another way: the shell hands it the record
//! of the link setup's msg1 and its answer once the link is promoted, since
//! the promotion path does not carry those bytes to the machine's build.
//! The rest are reads. None carries a rule or is reachable from a row.

use super::Wire;
use super::cycle::Cycle;
use super::epoch::Slot;
use super::lease::EpochTag;
use super::machine::Rekey;
use super::profile::{Profile, SessionKeys};
use super::record::{Digest, Record};
use crate::time::Clock;

impl<P: Profile, C: Clock> Rekey<P, C> {
    /// Take `setup`, the record of the link-setup msg1 the link was
    /// promoted from and the msg2 this node answered it with, as the
    /// record's setup, keeping every ephemeral the record already holds
    /// (those of an earlier link with the same peer epoch) behind it: a
    /// resend of the setup msg1 draws the msg2 again while the link is too
    /// young to rekey, and a copy of it counts as answered.
    #[doc(hidden)]
    pub fn note_setup(&mut self, mut setup: Record) {
        setup.absorb(core::mem::take(&mut self.record));
        self.record = setup;
    }

    /// The digest of the msg1 that armed the responder pending held, and
    /// the msg2 that answered it.
    #[doc(hidden)]
    pub fn rekey_answer(&self) -> Option<(Digest, &Wire)> {
        match &self.cycle {
            Cycle::PendR(p) => p.answer.as_ref().map(|a| (a.msg1, &a.msg2)),
            Cycle::Idle | Cycle::Init(_) | Cycle::PendI(_) => None,
        }
    }

    /// The keys of the epoch in `slot`, read-only.
    #[doc(hidden)]
    pub fn keys(&self, slot: Slot) -> Option<&P::Session> {
        self.epoch(slot).map(|ep| ep.session.as_ref())
    }

    /// The tag of the epoch in `slot`.
    #[doc(hidden)]
    pub fn tag(&self, slot: Slot) -> Option<EpochTag> {
        self.epoch(slot).map(|ep| ep.tag)
    }

    /// This node's index of the epoch in `slot`.
    #[doc(hidden)]
    pub fn ours(&self, slot: Slot) -> Option<u32> {
        self.epoch(slot).and_then(|ep| ep.ids.ours())
    }

    /// The peer's index of the epoch in `slot`.
    #[doc(hidden)]
    pub fn theirs(&self, slot: Slot) -> Option<u32> {
        self.epoch(slot).and_then(|ep| ep.ids.theirs)
    }

    /// When the epoch in `slot` was made current, or, for the pending
    /// epoch, when its handshake completed.
    #[doc(hidden)]
    pub fn started(&self, slot: Slot) -> Option<C::Instant> {
        self.epoch(slot).map(|ep| ep.started)
    }

    /// The current epoch's inner-header timestamp base.
    #[doc(hidden)]
    pub fn base(&self) -> Option<C::Instant> {
        self.cur.as_ref().and_then(|cur| cur.base)
    }

    /// The key-epoch bit this node seals under: the current epoch's, or 0
    /// while opening.
    #[doc(hidden)]
    pub fn k(&self) -> bool {
        self.cur.as_ref().is_some_and(|cur| cur.k)
    }

    /// Frames sealed under the current epoch so far; zero while opening.
    #[doc(hidden)]
    pub fn sent(&self) -> u64 {
        self.cur.as_ref().map_or(0, |cur| cur.session.sent())
    }

    /// The rekey jitter drawn at the last install or cutover, in whole
    /// seconds.
    #[doc(hidden)]
    pub fn jitter_secs(&self) -> i32 {
        self.mem.jitter
    }

    /// When the drain ends, while an epoch is drained.
    #[doc(hidden)]
    pub fn drain_deadline(&self) -> Option<C::Instant> {
        self.drain.as_ref().map(|d| d.deadline)
    }

    /// When the last cutover happened, in either role. Kept after the drain
    /// completes.
    #[doc(hidden)]
    pub fn last_cutover(&self) -> Option<C::Instant> {
        self.mem.last_cutover
    }
}
