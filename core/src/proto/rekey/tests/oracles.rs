//! The rekey simulator's oracles over one machine or one delivery, as
//! predicates, so any test shell that drives a real machine holds the same
//! rules with the same messages.
//!
//! Each returns what `sim.rs` reports, its label first: O1 convergence, O3
//! conservation, O4 deadlines, O5 unauthenticated input with its list of what
//! a record owes, O6 bounded memory, O8 key retention and O10 residual
//! containment. `sim.rs` gives the meaning of each. O2, O7, O9 and O11 read
//! the simulator's own traffic, worker and first handshakes, and stay there.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Debug;

pub(crate) use super::super::machine::Peek;
use super::stub::{Ev, Stub, kid};
use crate::proto::rekey::{CycleView, Digest, Profile, RECORD_BOUND, Reason, Rekey, leaked};
use crate::testutil::{TestClock, TestInstant};

/// O3: the indices shell `x` holds are the ones it can account for.
pub(crate) fn balanced(x: usize, held: usize, bound: usize) -> Result<(), String> {
    if held == bound {
        return Ok(());
    }
    Err(format!(
        "O3: n{x} holds {held} indices, its machine and legs {bound}"
    ))
}

/// O3: no lease leaked since the count stood at `base`.
pub(crate) fn unleaked(base: usize) -> Result<(), String> {
    if leaked() == base {
        return Ok(());
    }
    Err(format!("O3: {} leases leaked", leaked() - base))
}

/// O4: after a poll at `now`, a live machine's next wake is in the future.
pub(crate) fn ahead(x: usize, wake: Option<u64>, now: u64) -> Result<(), String> {
    match wake {
        Some(w) if w <= now => Err(format!(
            "O4: n{x}'s next wake {w} is not after the poll at {now}"
        )),
        Some(_) | None => Ok(()),
    }
}

/// O4: no own attempt, started at `start`, outlives its `budget` at `now`.
pub(crate) fn attempt<P: Profile>(
    x: usize,
    m: &Rekey<P, TestClock>,
    start: Option<u64>,
    now: u64,
    budget: u64,
) -> Result<(), String> {
    match start {
        Some(s) if m.view().cycle == CycleView::Init && now >= s + budget => Err(format!(
            "O4: n{x}'s attempt started at {s} outlived its deadline at {} in the poll at {now}",
            s + budget
        )),
        Some(_) | None => Ok(()),
    }
}

/// O6: the record stays within its bound.
pub(crate) fn memory<P: Profile>(x: usize, p: &Peek<'_, P, TestInstant>) -> Result<(), String> {
    if p.record > RECORD_BOUND + 1 {
        return Err(format!("O6: n{x}'s record holds {}", p.record));
    }
    Ok(())
}

/// O8: no previous epoch outlives `retention` (ms) from the current epoch's
/// start, or, once `polled`, its own drain.
pub(crate) fn retained<P: Profile>(
    x: usize,
    p: &Peek<'_, P, TestInstant>,
    retention: u64,
    now: u64,
    polled: bool,
) -> Result<(), String> {
    if let (Some(end), Some(cur)) = (p.drain_end, &p.current) {
        let ceiling = cur.started.0 + retention;
        if end.0 > ceiling || (polled && now >= end.0) {
            return Err(format!(
                "O8: n{x} keeps a previous epoch to {} past its ceiling {ceiling}",
                end.0
            ));
        }
    }
    Ok(())
}

/// O1: both ends hold the same current epoch and nothing else is in
/// progress.
pub(crate) fn converged<P: Stub>(
    a: Option<&Rekey<P, TestClock>>,
    b: Option<&Rekey<P, TestClock>>,
    now: u64,
) -> Result<(), String> {
    let (Some(a), Some(b)) = (a, b) else {
        return Err(String::from("O1: a node has no session"));
    };
    let (pa, pb) = (a.peek(), b.peek());
    let (Some(ca), Some(cb)) = (&pa.current, &pb.current) else {
        return Err(String::from("O1: a node is not established"));
    };
    if kid(ca.session) != kid(cb.session) {
        return Err(String::from("O1: the ends hold different current epochs"));
    }
    if a.view().cycle != CycleView::Idle || b.view().cycle != CycleView::Idle {
        return Err(format!(
            "O1: cycles {:?} and {:?}",
            a.view().cycle,
            b.view().cycle
        ));
    }
    if pa
        .candidates
        .iter()
        .chain(&pb.candidates)
        .any(|d| d.0 <= now)
    {
        return Err(String::from("O1: an expired candidate is held"));
    }
    if P::INDEXED && (ca.theirs != cb.ours || cb.theirs != ca.ours) {
        return Err(String::from("O1: the index pairs disagree"));
    }
    Ok(())
}

/// A machine before one delivery, as O5 and O10 compare it. A forged input
/// must leave the record alone too; a copy may add to it.
pub(crate) struct Before {
    digest: String,
    last: Option<TestInstant>,
    cycle: String,
    forged: bool,
}

/// What one delivery did to a machine.
pub(crate) struct Change {
    /// It armed a responder pending.
    pub(crate) armed: bool,
    /// It refreshed liveness.
    pub(crate) refreshed: bool,
    /// It changed the state O5 watches.
    pub(crate) changed: bool,
}

impl Before {
    /// Read `m` before a delivery.
    pub(crate) fn of<P: Profile>(m: &Rekey<P, TestClock>, forged: bool) -> Self {
        Self {
            digest: m.digest_core(forged),
            last: m.view().last_rx,
            cycle: format!("{:?}", m.view().cycle),
            forged,
        }
    }

    /// The cycle the machine was in.
    pub(crate) fn cycle(&self) -> &str {
        &self.cycle
    }

    /// What the delivery did, reading `m` after it.
    pub(crate) fn change<P: Profile>(&self, m: &Rekey<P, TestClock>) -> Change {
        Change {
            armed: m.view().cycle == CycleView::PendR && self.cycle != "PendR",
            refreshed: m.view().last_rx != self.last,
            changed: m.digest_core(self.forged) != self.digest,
        }
    }
}

/// Which delivery an O5 failure names: its origin in the shell's own terms,
/// the datagram it is or copies, and the receiver.
pub(crate) struct Seen<O> {
    pub(crate) origin: O,
    pub(crate) root: u64,
    pub(crate) x: usize,
}

/// Oldest first: the ephemerals of the IK msg1s a machine has answered,
/// refused or handed to a replacement, which its replay record must still
/// hold. Kept from the machine's outputs, never from its record, so a lost
/// replay defence fails O5 instead of passing as the residual, and cleared
/// when the shell drops the machine and the record with it.
#[derive(Clone, Debug, Default)]
pub(crate) struct Owed(Vec<Digest>);

impl Owed {
    /// Add the ephemeral `e` of a msg1 the machine just took, when the take
    /// armed a pending (whose exit records it) or drew a refusal or
    /// replacement that records it. A refusal for a copy already on the list
    /// records nothing new.
    pub(crate) fn add<T>(&mut self, e: Digest, armed: bool, evs: &[Ev<T>]) {
        let recorded = armed
            || evs.iter().any(|ev| {
                matches!(
                    ev,
                    Ev::Replace
                        | Ev::Reject(Reason::OffLink | Reason::PendingHeld | Reason::DualInitWon)
                )
            });
        if recorded && !self.0.contains(&e) {
            self.0.push(e);
            if self.0.len() > RECORD_BOUND {
                self.0.remove(0);
            }
        }
    }

    /// Forget the list, with the machine.
    pub(crate) fn clear(&mut self) {
        self.0.clear();
    }

    /// Whether the list holds the ephemeral `e`: a msg1 carrying it was
    /// taken before, so a copy of it is a repeat.
    pub(crate) fn owes(&self, e: &Digest) -> bool {
        self.0.contains(e)
    }
}

/// O5: a msg1 whose ephemeral `e` the record owes arms no pending.
pub(crate) fn rearmed<O: Debug, T: Debug>(
    seen: &Seen<O>,
    owed: &Owed,
    e: &Digest,
    change: &Change,
    evs: &[Ev<T>],
) -> Result<(), String> {
    if change.armed && owed.0.contains(e) {
        return Err(format!(
            "O5: {:?} of #{} at n{} armed a pending from a msg1 its record holds: {evs:?}",
            seen.origin, seen.root, seen.x
        ));
    }
    Ok(())
}

/// O5: a `repeat`, a forgery or a copy of what the machine already took,
/// changes nothing.
pub(crate) fn unchanged<O: Debug, T: Debug>(
    seen: &Seen<O>,
    repeat: bool,
    change: &Change,
    evs: &[Ev<T>],
) -> Result<(), String> {
    if repeat && change.changed {
        return Err(format!(
            "O5: {:?} of #{} at n{} changed the state: {evs:?}",
            seen.origin, seen.root, seen.x
        ));
    }
    Ok(())
}

/// O10: a residual replay at node `x` adopts, confirms and refreshes
/// nothing. Every breach, in the order `sim.rs` reports them.
pub(crate) fn contained<T: Debug>(x: usize, change: &Change, evs: &[Ev<T>]) -> Vec<String> {
    let mut out = Vec::new();
    let bad = evs.iter().find(|e| {
        matches!(
            e,
            Ev::Installed(..) | Ev::Rekeyed(..) | Ev::Reverted(..) | Ev::Retired(..)
        )
    });
    if let Some(e) = bad {
        out.push(format!("O10: a residual replay at n{x} emitted {e:?}"));
    }
    if change.refreshed {
        out.push(format!("O10: a residual replay at n{x} refreshed liveness"));
    }
    out
}
