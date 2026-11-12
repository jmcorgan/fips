//! The one function that joins a peer's two machines to the settlement
//! core.
//!
//! A held peer has a rekey machine and a path bundle. [`join`] is the one
//! place both are built for a new link, carried across a cross-connection
//! move and closed at a removal, and the one rule for what each machine's
//! outputs tell the core: a restart report, a teardown and a replacement
//! request from the rekey machine, and every path change the bundle
//! reports, its one-path roams and binds besides. It holds no state and
//! performs no I/O. It takes the machines' slots where the shell keeps
//! them, makes the machine calls in their order, and returns [`Joined`],
//! which says front to back what the shell is to carry out: a core input
//! ([`Step::Core`]), a replacement for the core's gates ([`Step::Replace`])
//! or one of the machines' own outputs ([`Step::Rekey`], [`Step::Path`]).
//!
//! Every call is generic over the rekey profile, the clock, the entropy
//! source and the driver slot, so a node and a test shell call the same
//! code. A rekey machine's step is converted as it is taken, moving the
//! outputs the machine already returned, so a frame through it costs no
//! allocation here.

use alloc::vec::{IntoIter, Vec};

use crate::entropy::EntropySource;
use crate::identity::{NodeAddr, PeerKey};
use crate::proto::path::{self, Bundle, PathRef, PathState};
use crate::proto::rekey::{
    self, Authentic, Bond, Carry, Close, Completed, Identity, Ids, IndexLease, Params, Profile,
    Record, Rekey, Replayable, SetupFacts,
};
use crate::time::Clock;
use crate::transport::{TransportAddr, TransportId};

use super::input::Input as In;
use super::links::{LinkNo, Pair, Proven};

/// A completed handshake a peer's rekey machine is built on.
#[derive(Debug)]
pub struct Setup<P: Profile> {
    /// The completion.
    pub done: Completed<P>,
    /// This node's index for the session.
    pub lease: IndexLease,
    /// The peer's index for it.
    pub theirs: u32,
    /// The transport the index is bound on.
    pub transport: P::Transport,
}

/// What building a rekey machine reads from the shell.
pub struct Caps<'a, 'e, P: Profile, I> {
    /// The machine's settings.
    pub params: Params,
    /// This node's address.
    pub me: NodeAddr,
    /// Now.
    pub now: I,
    /// The capabilities a call borrows.
    pub env: &'a mut rekey::Env<'e, P>,
}

/// What [`join`] is asked to do. Built and consumed in one call, so the
/// size of its largest variant costs one stack frame, and boxing a setup
/// would cost an allocation at every promotion.
#[allow(clippy::large_enum_variant)]
pub enum Event<'a, 'c, 'e, P: Profile, C: Clock, E: EntropySource, D: Default> {
    /// A new link: build the rekey machine on `setup`, bonded to `key`,
    /// then the bundle whose original path is `to`, into the two slots.
    /// A setup that authenticated another key builds neither.
    Start {
        /// The rekey machine's slot.
        rekey: &'a mut Option<Rekey<P, C>>,
        /// The bundle's slot.
        bundle: &'a mut Option<Bundle<C, E, D>>,
        /// The key the machine is bonded to.
        key: PeerKey,
        /// The completed handshake.
        setup: Setup<P>,
        /// What link setup knows.
        facts: SetupFacts<C::Instant>,
        /// The rekey machine's capabilities.
        caps: &'a mut Caps<'c, 'e, P, C::Instant>,
        /// The original path.
        to: (TransportId, TransportAddr),
        /// The bundle's settings.
        params: path::Params,
        /// The bundle's facts.
        env: &'a path::Env<'a>,
        /// The link the core holds the peer on, if the shell feeds one.
        link: Option<LinkNo>,
    },
    /// A cross-connection move: close the rekey machine, build the next
    /// from what it carried on `setup`, then renew the bundle at `to`. A
    /// machine that does not hold the setup's key stays as it was, and the
    /// lease comes back as a release.
    Shift {
        /// The rekey machine's slot.
        rekey: &'a mut Option<Rekey<P, C>>,
        /// The bundle, or `None` where the caller withholds the renewal.
        bundle: Option<&'a mut Bundle<C, E, D>>,
        /// The completed handshake.
        setup: Setup<P>,
        /// The rekey machine's capabilities.
        caps: &'a mut Caps<'c, 'e, P, C::Instant>,
        /// The pair moved to.
        to: (TransportId, TransportAddr),
        /// The bundle's facts.
        env: &'a path::Env<'a>,
    },
    /// A removal: the bundle, then the rekey machine, out of their slots
    /// and closed.
    Stop {
        /// The rekey machine's slot, emptied.
        rekey: &'a mut Option<Rekey<P, C>>,
        /// The bundle's slot, emptied.
        bundle: &'a mut Option<Bundle<C, E, D>>,
        /// Why the rekey machine is closed.
        why: Close,
    },
    /// What a step of the rekey machine returned.
    Rekey {
        /// The outputs.
        out: rekey::Outputs<P>,
    },
    /// What a step of the bundle returned.
    Paths {
        /// The outputs.
        out: path::Outputs<D>,
        /// What the bundle holds of a path after the step.
        read: &'a dyn Fn(&PathRef) -> Proven,
        /// The link the peer holds, `None` at its removal, when the
        /// link's record goes with it.
        link: Option<LinkNo>,
        /// The link a released path belongs to, where it is not `link`.
        released: Option<LinkNo>,
    },
    /// A one-path roam, or a bind of a bundle holding no path, which the
    /// bundle reports in no output.
    Roam {
        /// The link.
        link: LinkNo,
        /// The pair the path left; `None` for a bind.
        from: Option<Pair>,
        /// The pair it holds now.
        to: Pair,
    },
}

/// One thing for the shell to carry out, in order.
#[derive(Debug)]
pub enum Step<P: Profile, D> {
    /// The core's input, in the step that emitted it.
    Core(In),
    /// A msg1 the rekey machine asks the core's gates to take as a
    /// replacement.
    Replace(Authentic<P::Msg1, Replayable>),
    /// A rekey machine output that is the shell's own.
    Rekey(rekey::Output<P>),
    /// A bundle output, its driver slot with it.
    Path(path::Output<D>),
}

/// What [`join`] returns: the steps, front to back. The rekey machine's
/// outputs are converted as they are taken.
#[derive(Debug)]
pub struct Joined<P: Profile, D, I> {
    peer: NodeAddr,
    /// Steps before the rekey machine's.
    head: IntoIter<Step<P, D>>,
    /// The rekey machine's outputs, not yet converted.
    rekey: IntoIter<rekey::Output<P>>,
    /// Steps after the rekey machine's.
    tail: IntoIter<Step<P, D>>,
    /// The machine was built: always at a start that returned, and at a
    /// move only when the rekey machine held the setup's key.
    pub built: bool,
    /// What a closed rekey machine carried, for the node's record store:
    /// a removal's.
    pub carry: Option<Carry<I>>,
}

impl<P: Profile, D, I> Joined<P, D, I> {
    /// Steps for `peer`: `head`, then `rekey` converted, then `tail`.
    fn new(
        peer: NodeAddr,
        head: Vec<Step<P, D>>,
        rekey: rekey::Outputs<P>,
        tail: Vec<Step<P, D>>,
    ) -> Self {
        Self {
            peer,
            head: head.into_iter(),
            rekey: rekey.into_iter(),
            tail: tail.into_iter(),
            built: false,
            carry: None,
        }
    }
}

impl<P: Profile, D, I> Iterator for Joined<P, D, I> {
    type Item = Step<P, D>;

    fn next(&mut self) -> Option<Step<P, D>> {
        if let Some(s) = self.head.next() {
            return Some(s);
        }
        if let Some(o) = self.rekey.next() {
            return Some(told(o, self.peer));
        }
        self.tail.next()
    }
}

/// The one function that joins a peer's rekey machine and bundle to the
/// settlement core: it makes every machine call `event` needs for `peer`,
/// and says, front to back, what the shell is to carry out. Only a
/// [`Event::Start`] whose setup authenticated another key than the one
/// given is refused, with its lease back and both slots left empty.
pub fn join<P, C, E, D>(
    peer: NodeAddr,
    event: Event<'_, '_, '_, P, C, E, D>,
) -> Result<Joined<P, D, C::Instant>, IndexLease>
where
    P: Profile,
    C: Clock,
    E: EntropySource,
    D: Default,
{
    Ok(match event {
        Event::Start {
            rekey,
            bundle,
            key,
            setup,
            facts,
            caps,
            to,
            params,
            env,
            link,
        } => {
            let at = Pair {
                transport: to.0,
                addr: to.1.clone(),
            };
            let (machine, out) = built::<P, C>(key, setup, facts, caps)?;
            *rekey = Some(machine);
            *bundle = Some(Bundle::new(caps.now, to.0, to.1, params, env));
            let live = link.map(|link| {
                Step::Core(In::State {
                    link,
                    pair: at,
                    proven: Proven::Live,
                })
            });
            let mut j = Joined::new(peer, Vec::new(), out, live.into_iter().collect());
            j.built = true;
            j
        }
        Event::Shift {
            rekey,
            bundle,
            setup,
            caps,
            to,
            env,
        } => {
            let (out, paths, built) = shift(rekey, bundle, setup, caps, to, env);
            let mut j = Joined::new(
                peer,
                Vec::new(),
                out,
                paths.into_iter().map(Step::Path).collect(),
            );
            j.built = built;
            j
        }
        Event::Stop { rekey, bundle, why } => {
            let paths = bundle.take().map(Bundle::close).unwrap_or_default();
            let (out, carry) = match rekey.take() {
                Some(r) => r.close(why),
                None => (rekey::Outputs::new(), None),
            };
            let mut j = Joined::new(
                peer,
                paths.into_iter().map(Step::Path).collect(),
                out,
                Vec::new(),
            );
            j.carry = carry;
            j
        }
        Event::Rekey { out } => Joined::new(peer, Vec::new(), out, Vec::new()),
        Event::Paths {
            out,
            read,
            link,
            released,
        } => {
            let mut head = Vec::new();
            for o in out {
                let input = mirrored(&o, read, peer, link, released);
                head.push(Step::Path(o));
                head.extend(input.map(Step::Core));
            }
            Joined::new(peer, head, Vec::new(), Vec::new())
        }
        Event::Roam { link, from, to } => {
            let input = match from {
                Some(from) => In::Moved { link, from, to },
                None => In::State {
                    link,
                    pair: to,
                    proven: Proven::Live,
                },
            };
            Joined::new(peer, alloc::vec![Step::Core(input)], Vec::new(), Vec::new())
        }
    })
}

/// A rekey machine bonded to `key`, built on `setup` with `facts`; the
/// lease back when the setup authenticated another key.
fn built<P: Profile, C: Clock>(
    key: PeerKey,
    setup: Setup<P>,
    facts: SetupFacts<C::Instant>,
    caps: &mut Caps<'_, '_, P, C::Instant>,
) -> Result<(Rekey<P, C>, rekey::Outputs<P>), IndexLease> {
    let bond = Bond::Key(key);
    let Ok(first) = bond.check(setup.done) else {
        return Err(setup.lease);
    };
    let ids = Ids::new(setup.lease, setup.theirs, setup.transport);
    Ok(Rekey::established(
        caps.params,
        bond,
        caps.me,
        first,
        ids,
        facts,
        caps.now,
        caps.env,
    ))
}

/// Move a held peer onto `setup`: close the rekey machine in `slot`, build
/// the next from what it carried, then, only if it was built, renew
/// `bundle` at `to`. Returns the rekey machine's outputs (the close's
/// first), the renewal's, and whether the machine was built. A machine that
/// does not hold the setup's key goes back in its slot, and the lease comes
/// back in a release.
fn shift<P, C, E, D>(
    slot: &mut Option<Rekey<P, C>>,
    bundle: Option<&mut Bundle<C, E, D>>,
    setup: Setup<P>,
    caps: &mut Caps<'_, '_, P, C::Instant>,
    to: (TransportId, TransportAddr),
    env: &path::Env<'_>,
) -> (rekey::Outputs<P>, path::Outputs<D>, bool)
where
    P: Profile,
    C: Clock,
    E: EntropySource,
    D: Default,
{
    let refused = |mut out: rekey::Outputs<P>, lease| {
        out.push(rekey::Output::Release(lease));
        (out, Vec::new(), false)
    };
    let Some(old) = slot.take() else {
        return refused(rekey::Outputs::new(), setup.lease);
    };
    let remote = setup.done.remote;
    let held = match old.view().identity {
        Identity::Proven(key) if key == remote => Some(key),
        Identity::Proven(_) | Identity::Claimed(_) => None,
    };
    let Some(key) = held else {
        *slot = Some(old);
        return refused(rekey::Outputs::new(), setup.lease);
    };
    let (mut out, carry): (_, Option<Carry<C::Instant>>) = old.close(Close::CrossConnectionMove);
    let Some(carry) = carry else {
        return refused(out, setup.lease);
    };
    let facts = if fault!(MoveBuildsFresh) {
        // The defect's shape: the moved session built as a new link's.
        SetupFacts {
            peer_epoch: Some(setup.done.epoch),
            k: false,
            link_since: caps.now,
            started: caps.now,
            peer_k: None,
            last_rx: None,
            record: Record::new(),
        }
    } else {
        carry.into()
    };
    match built::<P, C>(key, setup, facts, caps) {
        Ok((machine, more)) => {
            out.extend(more);
            *slot = Some(machine);
            let paths = bundle.map_or_else(Vec::new, |b| b.renew(caps.now, env, to));
            (out, paths, true)
        }
        Err(lease) => refused(out, lease),
    }
}

/// The step the rekey output `o` of `peer`'s machine asks for: a restart
/// report and a teardown are the core's, a replacement request goes to its
/// gates, and everything else is the shell's.
fn told<P: Profile, D>(o: rekey::Output<P>, peer: NodeAddr) -> Step<P, D> {
    match o {
        rekey::Output::PeerRestarted { epoch, .. } => Step::Core(In::Restarted { peer, epoch }),
        rekey::Output::Teardown(_) => Step::Core(In::Ended { peer }),
        rekey::Output::ReplaceRequested { tok } => Step::Replace(tok),
        other @ (rekey::Output::Send { .. }
        | rekey::Output::Prompt { .. }
        | rekey::Output::Deliver { .. }
        | rekey::Output::Bind { .. }
        | rekey::Output::Unbind { .. }
        | rekey::Output::Delegate { .. }
        | rekey::Output::Revoke { .. }
        | rekey::Output::Release(_)
        | rekey::Output::Installed { .. }
        | rekey::Output::Retired { .. }
        | rekey::Output::Reverted { .. }
        | rekey::Output::Rekeyed { .. }
        | rekey::Output::Reject(_)
        | rekey::Output::Abandoned(_)) => Step::Rekey(other),
    }
}

/// The core's pair for path `p`.
pub fn pair(p: &PathRef) -> Pair {
    Pair {
        transport: p.transport,
        addr: p.addr.clone(),
    }
}

/// What the core is told of the path to `p`, read from bundle `b`: `Live`
/// for a Live path, `Acked` for another acknowledged one, and `Probing`
/// for any other and for one the bundle does not hold.
pub fn proven<C: Clock, E: EntropySource, D: Default>(b: &Bundle<C, E, D>, p: &PathRef) -> Proven {
    let paths = b.paths();
    let Some(path) = paths.find(p.transport, &p.addr).and_then(|i| paths.get(i)) else {
        return Proven::Probing;
    };
    if path.state() == PathState::Live {
        Proven::Live
    } else if path.acked() {
        Proven::Acked
    } else {
        Proven::Probing
    }
}

/// The core input the bundle output `o` of `peer`'s link stands for, if
/// any, with each path's proven state as `read` gives it. `link` is the
/// link the peer holds, `None` at its removal; `released` the link a
/// released path belongs to where it is not `link`.
fn mirrored<D>(
    o: &path::Output<D>,
    read: &dyn Fn(&PathRef) -> Proven,
    peer: NodeAddr,
    link: Option<LinkNo>,
    released: Option<LinkNo>,
) -> Option<In> {
    match o {
        path::Output::State { next: None, .. } => None,
        path::Output::State { to, .. } => Some(In::State {
            link: link?,
            pair: pair(to),
            proven: read(to),
        }),
        path::Output::Moved { from, to, .. } => Some(In::Moved {
            link: link?,
            from: pair(from),
            to: pair(to),
        }),
        path::Output::Switched { to, .. } => Some(In::Switched {
            link: link?,
            to: pair(to),
        }),
        path::Output::Released { to, keep, .. } => Some(In::Released {
            link: released.or(link)?,
            pair: pair(to),
            keep: *keep,
        }),
        path::Output::Orphaned => link.map(|_| In::Orphaned { peer }),
        path::Output::Capable
        | path::Output::NotCapable
        | path::Output::Refused { .. }
        | path::Output::Send { .. }
        | path::Output::Connect { .. }
        | path::Output::Proven { .. } => None,
    }
}

#[cfg(test)]
#[path = "tests/join.rs"]
mod tests;
