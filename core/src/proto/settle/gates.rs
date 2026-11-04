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
//! A new epoch in a msg2 is the reply to this node's own handshake, so
//! neither msg2 source is refused or stamps the dampener. A frame that
//! authenticates forgets the peer's replay memory and silent sessions.

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
    /// A new epoch in the msg2 of this node's own dial.
    OwnMsg2,
    /// A new epoch revealed in the msg2 of a rekey.
    RekeyMsg2,
}

impl Source {
    /// Whether the source is a msg1.
    fn msg1(self) -> bool {
        match self {
            Self::NotHeld | Self::Restart | Self::Replacement => true,
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
}

impl<I> Default for Memory<I> {
    fn default() -> Self {
        Self {
            stamp: None,
            replays: Vec::new(),
            silence: None,
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
        let mem = self.peers.entry(peer).or_default();
        let silenced = match ask.source {
            Source::NotHeld | Source::Replacement => mem.silencing(ask.epoch, now),
            Source::Restart | Source::OwnMsg2 | Source::RekeyMsg2 => false,
        };
        if silenced {
            return Some(Refusal::Silent);
        }
        let held = match (ask.source, ask.held) {
            (Source::NotHeld, _) | (_, None) => return None,
            (_, Some(held)) => held,
        };
        let gated = match ask.source {
            Source::Restart | Source::Replacement => true,
            Source::OwnMsg2 => fault!(OutboundGated),
            Source::NotHeld | Source::RekeyMsg2 => false,
        };
        if !gated {
            if fault!(DampenerAtMsg2) {
                mem.stamp = Some(now);
            }
            return None;
        }
        let refusal = mem.judge(&ask, held, now, params);
        if (refusal.is_none() && held.heard) || (refusal.is_some() && fault!(DampenerFromRefusal)) {
            mem.stamp = Some(now);
        }
        refusal
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
}

impl<I: Instant> Silence<I> {
    /// Whether the record has outlived its horizon at `now`.
    fn expired(&self, now: I, params: &Params) -> bool {
        let from = self.until.unwrap_or(self.last);
        now >= deadline(from, params.horizon)
    }
}

/// Whether `at` is within the interval before `now`.
fn recent<I: Instant>(at: I, now: I, params: &Params) -> bool {
    now.saturating_duration_since(at) < params.interval
}

#[cfg(test)]
#[path = "tests/gates.rs"]
mod tests;
