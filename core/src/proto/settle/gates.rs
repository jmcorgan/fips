//! The restart and replacement gates (FRC-1201 Section 5.5), as one
//! function every restart source calls, and the memory per peer identity
//! they read.
//!
//! A restart or replacement tears a working peering down, and a captured
//! msg1 stays authentic after capture, so [`Gates::gate`] bounds when one
//! may. The sources are a msg1 from an identity not held (rule 1), a msg1
//! at a new epoch (rule 2), a same-epoch msg1 that would replace the
//! peering (rule 3.3), a new epoch in the msg2 of this node's own dial, and
//! a new epoch revealed in a rekey msg2. They are judged as the current
//! node judges them:
//!
//! - **The silent-session refusal.** A peer whose last sessions at one
//!   epoch, [`Params::silent`] or more in a row, ended without one
//!   authenticated frame has its msg1s at that epoch refused for a back-off
//!   that starts at [`Params::silentbase`] and doubles with each further
//!   silent session up to [`Params::silentcap`]. It is asked only where the
//!   msg1 would promote a new session without a restart: rules 1 and 3.3.
//! - **The replay memory.** A msg1 that would tear down an unheard peering
//!   is refused when its ephemeral already promoted an unheard peering of
//!   that peer within [`Params::interval`], or when the peer has spent
//!   [`Params::replays`] ephemerals within it.
//! - **The floors.** An unheard peering younger than [`Params::unheard`],
//!   or a heard one whose last frame (or, with none, its installation) is
//!   within [`Params::interval`], is not torn down.
//! - **The dampener.** Within [`Params::interval`] of an accepted restart
//!   or replacement that tore down a heard peering, none is accepted. Only
//!   an acceptance stamps it, so a sustained replay cannot keep a genuine
//!   restart out.
//!
//! A redial (a fresh same-epoch msg1 off the established link of a held
//! peering that has been heard from, operator decision 2026-11-17) is
//! judged by the silent-session refusal, its own memory of the ephemerals
//! that armed a redial of the peer within [`Params::interval`] (at most
//! [`Params::replays`] of them) and the dampener, and not by the heard
//! floor or the replay memory of unheard promotions: it tears nothing down
//! when it is answered, and the peering it would replace is one the peer
//! was heard on. A peering not yet heard from is never redialed, so the
//! unheard floor does not arise. Its
//! acceptance stamps nothing; the swap its first frame proves does
//! ([`Gates::swapped`]), so a replayer, which sends no frame, cannot.
//!
//! A new epoch in a msg2 is the reply to this node's own handshake, so
//! neither msg2 source is refused or stamps the dampener. A frame that
//! authenticates forgets the peer's replay memory and silent sessions.
//!
//! The memory holds only identities with something live, as the node's
//! replay memory, dampener and silent-session record each do: a question
//! about an identity with no memory inserts none, and every call that
//! takes an instant first drops each identity whose stamp, replays and
//! silence have all lapsed. A lapsed entry decides nothing, so dropping it
//! changes no answer; it bounds the memory by the identities whose state
//! still counts, where a sender minting identities would otherwise grow it
//! by one entry per msg1.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::params::{Params, backoff, deadline};
use crate::identity::NodeAddr;
use crate::proto::fmp::EphemeralDigest;
use crate::time::{Duration, Instant};

/// A peer's startup epoch, as a msg1 or msg2 carries it.
pub type Epoch = [u8; 8];

/// What asks the gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// A msg1 from an identity not held (rule 1).
    NotHeld,
    /// A msg1 at an epoch other than the one on record (rule 2).
    Restart,
    /// A same-epoch msg1 that would replace the peering (rule 3.3).
    Replacement,
    /// A fresh same-epoch msg1 off the held peer's established link, to be
    /// answered into a redial that replaces the peering only at the peer's
    /// first frame under it (operator decision, 2026-11-17).
    Redial,
    /// A new epoch in the msg2 of this node's own dial.
    OwnMsg2,
    /// A new epoch revealed in the msg2 of a rekey.
    RekeyMsg2,
}

impl Source {
    /// Whether the source is a msg1.
    fn msg1(self) -> bool {
        match self {
            Self::NotHeld | Self::Restart | Self::Replacement | Self::Redial => true,
            Self::OwnMsg2 | Self::RekeyMsg2 => false,
        }
    }
}

/// Why the gate refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The peering is unheard and younger than [`Params::unheard`].
    Unheard,
    /// The peering is heard and its last frame, or its installation, is
    /// within [`Params::interval`].
    Heard,
    /// A restart or replacement of the identity was accepted within
    /// [`Params::interval`].
    Dampened,
    /// The msg1's ephemeral already promoted an unheard peering of the
    /// identity within [`Params::interval`].
    Replayed,
    /// The identity has spent [`Params::replays`] ephemerals within
    /// [`Params::interval`].
    ReplayFull,
    /// The identity's silent-session back-off is running at this epoch.
    Silent,
    /// The redial's ephemeral already armed a redial of the identity within
    /// [`Params::interval`], or [`Params::replays`] of them did.
    Redialed,
}

/// What the gate knows of the peering a source would tear down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Liveness<I> {
    /// The peering is heard from: a frame authenticated on it, or this
    /// node set it up by its own dial.
    pub heard: bool,
    /// When it was installed.
    pub installed: I,
    /// When its last frame authenticated.
    pub last: Option<I>,
}

/// One question to the gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ask<I> {
    /// What asks.
    pub source: Source,
    /// The peering it would tear down, if one is held.
    pub held: Option<Liveness<I>>,
    /// The msg1's ephemeral, for a msg1 source.
    pub ephemeral: Option<EphemeralDigest>,
    /// The epoch the msg1 or msg2 carries.
    pub epoch: Option<Epoch>,
}

/// A silent-session record.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Silence<I> {
    /// The epoch of the sessions counted, if any carried one.
    epoch: Option<Epoch>,
    /// Sessions counted in a row at that epoch.
    count: u32,
    /// When the last one ended.
    last: I,
    /// When the refusal in force ends.
    until: Option<I>,
    /// The setup ephemerals already counted.
    counted: Vec<EphemeralDigest>,
}

/// What the gates remember of one identity. It outlives the peering, since
/// a restart or replacement destroys that.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Memory<I> {
    /// When a restart or replacement of a heard peering was last accepted.
    stamp: Option<I>,
    /// The ephemerals that promoted an unheard peering, and when.
    replays: Vec<(EphemeralDigest, I)>,
    /// The silent-session record.
    silence: Option<Silence<I>>,
    /// The ephemerals that armed a redial, and when. Kept apart from
    /// `replays`, which a frame forgets: the held peering a redial meets
    /// keeps sending frames.
    redials: Vec<(EphemeralDigest, I)>,
}

impl<I> Default for Memory<I> {
    fn default() -> Self {
        Self {
            stamp: None,
            replays: Vec::new(),
            silence: None,
            redials: Vec::new(),
        }
    }
}

/// Whether two epochs name different runs: both present and unequal.
fn differ(a: Option<Epoch>, b: Option<Epoch>) -> bool {
    matches!((a, b), (Some(x), Some(y)) if x != y)
}

/// The restart gates and the memory per identity they read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gates<I> {
    peers: BTreeMap<NodeAddr, Memory<I>>,
}

impl<I> Default for Gates<I> {
    fn default() -> Self {
        Self {
            peers: BTreeMap::new(),
        }
    }
}

impl<I: Instant> Gates<I> {
    /// No memory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Judge `ask` for `peer` at `now`. An acceptance that tears down a
    /// heard peering stamps the dampener.
    pub fn gate(
        &mut self,
        peer: NodeAddr,
        ask: Ask<I>,
        now: I,
        params: &Params,
    ) -> Option<Refusal> {
        self.lapse(now, params);
        if kept() {
            self.peers.entry(peer).or_default();
        }
        let none = Memory::default();
        let mem = self.peers.get(&peer).unwrap_or(&none);
        let silenced = match ask.source {
            Source::NotHeld | Source::Replacement | Source::Redial => mem.silencing(ask.epoch, now),
            Source::Restart | Source::OwnMsg2 | Source::RekeyMsg2 => false,
        };
        if silenced {
            return Some(Refusal::Silent);
        }
        let held = match (ask.source, ask.held) {
            (Source::NotHeld, _) | (_, None) => return None,
            (_, Some(held)) => held,
        };
        if ask.source == Source::Redial {
            return mem.redial(&ask, held, now, params);
        }
        let gated = match ask.source {
            Source::Restart | Source::Replacement | Source::Redial => true,
            Source::OwnMsg2 => fault!(OutboundGated),
            Source::NotHeld | Source::RekeyMsg2 => false,
        };
        if !gated {
            if fault!(DampenerAtMsg2) {
                self.peers.entry(peer).or_default().stamp = Some(now);
            }
            return None;
        }
        let refusal = mem.judge(&ask, held, now, params);
        if (refusal.is_none() && held.heard) || (refusal.is_some() && fault!(DampenerFromRefusal)) {
            self.peers.entry(peer).or_default().stamp = Some(now);
        }
        refusal
    }

    /// Drop every identity whose stamp, replays, silence and redial memory
    /// have all lapsed at `now`, and the lapsed replays of the rest.
    fn lapse(&mut self, now: I, params: &Params) {
        if kept() {
            return;
        }
        self.peers.retain(|_, mem| {
            mem.prune(now, params);
            mem.live(now, params)
        });
    }

    /// An unheard peering of `peer` was promoted from a msg1 with
    /// `ephemeral` at `now`.
    pub fn promoted(
        &mut self,
        peer: NodeAddr,
        ephemeral: EphemeralDigest,
        now: I,
        params: &Params,
    ) {
        self.lapse(now, params);
        let mem = self.peers.entry(peer).or_default();
        mem.prune(now, params);
        if !mem.replays.iter().any(|(e, _)| *e == ephemeral) {
            mem.replays.push((ephemeral, now));
        }
        if mem.replays.len() > params.replays && !fault!(ReplayUnbounded) {
            mem.replays.remove(0);
        }
    }

    /// A frame from `peer` authenticated: forget its replay memory and its
    /// silent sessions.
    pub fn heard(&mut self, peer: &NodeAddr) {
        if fault!(HeardKeepsMemory) {
            return;
        }
        if let Some(mem) = self.peers.get_mut(peer) {
            mem.replays.clear();
            mem.silence = None;
            if mem.stamp.is_none()
                && (mem.redials.is_empty() || fault!(RedialMemoryLapses))
                && !kept()
            {
                self.peers.remove(peer);
            }
        }
    }

    /// A session of `peer` at `epoch`, promoted from a msg1 with `setup`
    /// (none for a session this node dialed), ended at `now` without one
    /// authenticated frame. Returns the length of the refusal this starts,
    /// if it starts one.
    pub fn ended(
        &mut self,
        peer: NodeAddr,
        epoch: Option<Epoch>,
        setup: Option<EphemeralDigest>,
        now: I,
        params: &Params,
    ) -> Option<Duration> {
        self.lapse(now, params);
        let mem = self.peers.entry(peer).or_default();
        let fresh = || Silence {
            epoch,
            count: 0,
            last: now,
            until: None,
            counted: Vec::new(),
        };
        let rec = match mem.silence.take() {
            Some(r) if !r.expired(now, params) && !differ(r.epoch, epoch) => r,
            Some(_) | None => fresh(),
        };
        let rec = mem.silence.insert(rec);
        if rec.epoch.is_none() {
            rec.epoch = epoch;
        }
        if let Some(setup) = setup {
            if rec.counted.contains(&setup) {
                return None;
            }
            if rec.counted.len() == params.counted {
                rec.counted.remove(0);
            }
            rec.counted.push(setup);
        }
        rec.count = rec.count.saturating_add(1);
        rec.last = now;
        let limit = if fault!(SilentEarly) {
            params.silent.saturating_sub(1)
        } else {
            params.silent
        };
        if rec.count < limit {
            return None;
        }
        let exponent = if fault!(SilentFlat) {
            0
        } else {
            rec.count - limit
        };
        let length = backoff(exponent, params.silentbase, params.silentcap);
        rec.until = Some(deadline(now, length));
        Some(length)
    }

    /// Whether `peer`'s silent-session back-off refuses a msg1 at `epoch`
    /// at `now`: the gate's first question, asked alone.
    pub fn silenced(&self, peer: &NodeAddr, epoch: Option<Epoch>, now: I) -> bool {
        self.peers
            .get(peer)
            .is_some_and(|m| m.silencing(epoch, now))
    }

    /// A redial of `peer` was armed by a msg1 with `ephemeral` at `now`.
    pub fn redialed(
        &mut self,
        peer: NodeAddr,
        ephemeral: EphemeralDigest,
        now: I,
        params: &Params,
    ) {
        if fault!(RedialUngated) {
            return;
        }
        let mem = self.peers.entry(peer).or_default();
        mem.redials.retain(|(_, at)| recent(*at, now, params));
        if !mem.redials.iter().any(|(e, _)| *e == ephemeral) {
            mem.redials.push((ephemeral, now));
        }
        if mem.redials.len() > params.replays {
            mem.redials.remove(0);
        }
    }

    /// A redial of `peer` replaced its peering at `now`, proven by the
    /// peer's frame: the dampener is stamped if the peering it replaced was
    /// `heard`, and the redial memory is forgotten.
    pub fn swapped(&mut self, peer: NodeAddr, heard: bool, now: I) {
        if heard {
            self.peers.entry(peer).or_default().stamp = Some(now);
        }
        if let Some(mem) = self.peers.get_mut(&peer) {
            mem.redials.clear();
        }
    }

    /// When a restart or replacement of `peer` last stamped the dampener.
    pub fn stamp(&self, peer: &NodeAddr) -> Option<I> {
        self.peers.get(peer).and_then(|m| m.stamp)
    }
}

impl<I: Instant> Memory<I> {
    /// The replay memory, floors and dampener, in the current node's order.
    fn judge(&self, ask: &Ask<I>, held: Liveness<I>, now: I, params: &Params) -> Option<Refusal> {
        if ask.source.msg1()
            && !held.heard
            && let Some(e) = ask.ephemeral
        {
            let live = self
                .replays
                .iter()
                .filter(|(_, at)| recent(*at, now, params));
            let mut n = 0;
            for (seen, _) in live {
                if *seen == e && !fault!(ReplaySeenIgnored) {
                    return Some(Refusal::Replayed);
                }
                n += 1;
            }
            if n >= params.replays && !fault!(ReplayUnbounded) {
                return Some(Refusal::ReplayFull);
            }
        }
        let young = if held.heard {
            let from = match held.last {
                Some(_) if fault!(HeardFromInstall) => Some(held.installed),
                Some(last) => Some(last),
                None if fault!(HeardNeedsFrame) => None,
                None => Some(held.installed),
            };
            from.is_some_and(|from| now.saturating_duration_since(from) < params.interval)
        } else {
            let age = now.saturating_duration_since(held.installed);
            if fault!(UnheardInclusive) {
                age <= params.unheard
            } else {
                age < params.unheard
            }
        };
        if young {
            return Some(if held.heard {
                Refusal::Heard
            } else {
                Refusal::Unheard
            });
        }
        if self.stamp.is_some_and(|t| recent(t, now, params)) {
            return Some(Refusal::Dampened);
        }
        None
    }

    /// A redial's memory and dampener, in the current node's order. It
    /// stamps nothing.
    fn redial(&self, ask: &Ask<I>, held: Liveness<I>, now: I, params: &Params) -> Option<Refusal> {
        if fault!(RedialUngated) {
            return None;
        }
        if let Some(e) = ask.ephemeral {
            let live: Vec<&EphemeralDigest> = self
                .redials
                .iter()
                .filter(|(_, at)| recent(*at, now, params))
                .map(|(e, _)| e)
                .collect();
            if live.contains(&&e) || live.len() >= params.replays {
                return Some(Refusal::Redialed);
            }
        }
        if fault!(RedialHeardFloored)
            && held.heard
            && recent(held.last.unwrap_or(held.installed), now, params)
        {
            return Some(Refusal::Heard);
        }
        if self.stamp.is_some_and(|t| recent(t, now, params)) {
            return Some(Refusal::Dampened);
        }
        None
    }

    /// Whether the silent-session back-off refuses a msg1 at `epoch` now.
    fn silencing(&self, epoch: Option<Epoch>, now: I) -> bool {
        self.silence
            .as_ref()
            .is_some_and(|r| r.until.is_some_and(|u| u > now) && !differ(r.epoch, epoch))
    }

    /// Drop the replay entries older than the interval.
    fn prune(&mut self, now: I, params: &Params) {
        self.replays.retain(|(_, at)| recent(*at, now, params));
    }

    /// Whether anything here still counts at `now`: a stamp within the
    /// interval, a replay or a redial ephemeral within it, or a
    /// silent-session record within its horizon.
    fn live(&self, now: I, params: &Params) -> bool {
        self.stamp.is_some_and(|t| recent(t, now, params))
            || self.replays.iter().any(|(_, at)| recent(*at, now, params))
            || (!fault!(RedialMemoryLapses)
                && self.redials.iter().any(|(_, at)| recent(*at, now, params)))
            || self
                .silence
                .as_ref()
                .is_some_and(|r| !r.expired(now, params))
    }
}

impl<I: Instant> Silence<I> {
    /// Whether the record has outlived its horizon at `now`.
    fn expired(&self, now: I, params: &Params) -> bool {
        let from = self.until.unwrap_or(self.last);
        now >= deadline(from, params.horizon)
    }
}

/// Whether the memory keeps every identity that was ever asked about, as
/// it did before it dropped what had lapsed.
fn kept() -> bool {
    fault!(MemoryNeverDropped) || node_fault!(MemoryNeverDropped)
}

/// Whether `at` is within the interval before `now`.
fn recent<I: Instant>(at: I, now: I, params: &Params) -> bool {
    now.saturating_duration_since(at) < params.interval
}

#[cfg(test)]
#[path = "tests/gates.rs"]
mod tests;
