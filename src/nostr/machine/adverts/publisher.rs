//! The local advert and the decision to publish it: which body, if any,
//! goes out, when (the republish schedule, one publish at a time), and the
//! node's transports with the public addresses learned for them, from which
//! the body is assembled. No NIP-09 deletion is ever sent for
//! an advert: a stopped advert is left to NIP-40 expiration.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::SocketAddr;
use core::time::Duration;

use fips_core::time::{Instant, deadline};

use super::super::error::Error;
use super::super::params::PUBLIC_ADDR_FAILURE_TTL;
use super::super::types::{ADVERT_IDENTIFIER, ADVERT_VERSION, OverlayAdvert};
use super::assemble::{self, AdvertTransportSnapshot};
use super::{NatGap, apply_nat_rule, endpoint_advert_is_publicly_usable};

/// What a publish request comes to. Returned by
/// [`Publisher::plan_publish`]: the pure decision of which advert body goes
/// out, or nothing. The rendezvous machine clamps, signs and sends it.
#[derive(Debug, Clone)]
pub enum PublishPlan {
    /// Nothing to publish (advertising disabled, no local advert yet, or
    /// the advert has no publicly usable endpoints).
    Nothing,
    /// Publish this fully-prepared advert body. The rendezvous machine
    /// builds the tags and expiration, signs it, and sends it.
    Publish(OverlayAdvert),
}

/// The advert this node wants to publish, and whether it advertises at all.
#[derive(Debug)]
pub struct Publisher {
    /// Whether this node advertises at all (`config.advertise`).
    advertise: bool,
    /// The advert body we currently want to publish, if any.
    local_advert: Option<OverlayAdvert>,
}

impl Publisher {
    /// A publisher with no local advert yet.
    pub fn new(advertise: bool) -> Self {
        Self {
            advertise,
            local_advert: None,
        }
    }

    /// Set the local advert we want to publish. Returns `true` when the
    /// value changed (so the machine should request a republish).
    pub fn set_local_advert(&mut self, advert: Option<OverlayAdvert>) -> bool {
        if self.local_advert == advert {
            false
        } else {
            self.local_advert = advert;
            true
        }
    }

    /// Build the publish decision: which advert body to publish, or nothing.
    /// Pure logic: the rendezvous machine signs the event and the shell
    /// sends it.
    pub fn plan_publish(&self) -> Result<PublishPlan, Error> {
        if !self.advertise {
            return Ok(PublishPlan::Nothing);
        }

        let mut advert = match self.local_advert.clone() {
            Some(advert) => advert,
            // Transient absence (e.g., an assembly during startup that
            // finds no endpoint yet). Don't proactively
            // emit a NIP-09 delete: the next publish supersedes the old
            // event via parameterized-replaceable semantics, and the NIP-40
            // expiration tag bounds the worst case if we never re-publish.
            None => return Ok(PublishPlan::Nothing),
        };

        advert.identifier = ADVERT_IDENTIFIER.to_string();
        advert.version = ADVERT_VERSION;
        advert.endpoints.retain(endpoint_advert_is_publicly_usable);
        // Defensive: the assembly gives no advert when it has no
        // endpoints, so this is only reachable from non-lifecycle callers.
        if advert.endpoints.is_empty() {
            return Ok(PublishPlan::Nothing);
        }

        match apply_nat_rule(&mut advert) {
            Ok(()) => Ok(PublishPlan::Publish(advert)),
            Err(NatGap::SignalRelays) => Err(Error::InvalidAdvert(
                "udp:nat endpoint requires non-empty signalRelays".to_string(),
            )),
            Err(NatGap::StunServers) => Err(Error::InvalidAdvert(
                "udp:nat endpoint requires non-empty stunServers".to_string(),
            )),
        }
    }
}

/// When the advert is published: on request and on a republish deadline,
/// one publish at a time, with requests made during a publish coalesced
/// into one more after it.
#[derive(Debug)]
pub struct PublishSchedule<I> {
    /// The republish interval.
    period: Duration,
    /// The next republish, once started.
    republish_at: Option<I>,
    /// A publish is running.
    in_flight: bool,
    /// A request arrived while one was running.
    pending: bool,
}

impl<I: Instant> PublishSchedule<I> {
    /// A schedule republishing every `period`, not yet started.
    pub fn new(period: Duration) -> Self {
        Self {
            period,
            republish_at: None,
            in_flight: false,
            pending: false,
        }
    }

    /// Start the republish schedule: the first republish is one period
    /// after `now`, not at `now`, since start-up publishes on its own.
    pub fn start(&mut self, now: I) {
        self.republish_at = Some(deadline(now, self.period));
    }

    /// The next republish.
    pub fn deadline(&self) -> Option<I> {
        self.republish_at
    }

    /// Whether a republish is due at `now`. Periods missed while a step ran
    /// late count as one.
    pub fn due(&mut self, now: I) -> bool {
        let Some(mut at) = self.republish_at.filter(|at| *at <= now) else {
            return false;
        };
        while at <= now {
            at = deadline(at, self.period);
        }
        self.republish_at = Some(at);
        true
    }

    /// Ask for a publish. Returns whether to start one now; otherwise one
    /// is running and another will follow it.
    pub fn request(&mut self) -> bool {
        if self.in_flight {
            self.pending = true;
            false
        } else {
            self.in_flight = true;
            true
        }
    }

    /// The publish ended, or found nothing to send. Returns whether to
    /// start the one requested meanwhile.
    pub fn finished(&mut self) -> bool {
        self.in_flight = false;
        if self.pending {
            self.pending = false;
            self.in_flight = true;
            true
        } else {
            false
        }
    }
}

/// A public address learned for one transport, and when.
#[derive(Debug, Clone, Copy)]
struct Learned<I> {
    addr: Option<SocketAddr>,
    at: I,
}

/// The node's advertisable transports, the public addresses learned for
/// them, and the requests waiting for the advert assembled from them.
///
/// The addresses [`assemble::learned_wanted`] names are observed one at a
/// time, in snapshot order, each kept for its time to live: a success for
/// `max(advert_refresh_secs, 60)` seconds, a failure for
/// [`PUBLIC_ADDR_FAILURE_TTL`], counted from when its result arrived. The
/// advert is assembled only once no wanted address is missing or being
/// observed, so the publish waits for the address.
#[derive(Debug)]
pub struct LocalTransports<I, R, Q> {
    snapshot: Vec<AdvertTransportSnapshot>,
    /// A snapshot has arrived that has not been assembled yet.
    stale: bool,
    /// The requests waiting for the next assembly.
    waiting: Vec<R>,
    learned: BTreeMap<u32, Learned<I>>,
    /// The observation in flight: its request and transport key.
    observing: Option<(Q, u32)>,
    success_ttl: Duration,
}

impl<I: Instant, R, Q: PartialEq> LocalTransports<I, R, Q> {
    /// No transports yet, keeping a learned address for `success_ttl`.
    pub fn new(success_ttl: Duration) -> Self {
        Self {
            snapshot: Vec::new(),
            stale: false,
            waiting: Vec::new(),
            learned: BTreeMap::new(),
            observing: None,
            success_ttl,
        }
    }

    /// Take a new snapshot, and the request waiting on its assembly, if
    /// any. Requests still waiting on an earlier snapshot wait on this one.
    pub fn set(&mut self, snapshot: Vec<AdvertTransportSnapshot>, reply: Option<R>) {
        self.snapshot = snapshot;
        self.stale = true;
        self.waiting.extend(reply);
    }

    /// How long `learned` is kept.
    fn ttl(&self, learned: &Learned<I>) -> Duration {
        if learned.addr.is_some() {
            self.success_ttl
        } else {
            PUBLIC_ADDR_FAILURE_TTL
        }
    }

    /// Whether an address of `learned` is current at `now`.
    fn current(&self, learned: &Learned<I>, now: I) -> bool {
        now.saturating_duration_since(learned.at) < self.ttl(learned)
    }

    /// The next address to observe at `now`: the first wanted transport,
    /// in snapshot order, with no current learned address. `None` while an
    /// observation is in flight.
    pub fn next_observation(&self, now: I) -> Option<(u32, u16)> {
        if self.observing.is_some() {
            return None;
        }
        assemble::learned_wanted(&self.snapshot)
            .into_iter()
            .find(|(key, _)| {
                self.learned
                    .get(key)
                    .is_none_or(|learned| !self.current(learned, now))
            })
    }

    /// Record that `key`'s address is unknown at `now`, without observing
    /// it.
    pub fn unlearned(&mut self, key: u32, now: I) {
        self.learned.insert(
            key,
            Learned {
                addr: None,
                at: now,
            },
        );
    }

    /// Record that `request` is observing `key`'s address.
    pub fn observe(&mut self, request: Q, key: u32) {
        self.observing = Some((request, key));
    }

    /// Record the result of the observation `request`: `addr` learned at
    /// `now`. Returns whether that observation was the one in flight.
    pub fn observed(&mut self, request: &Q, addr: Option<SocketAddr>, now: I) -> bool {
        match self.observing.take() {
            Some((req, key)) if req == *request => {
                self.learned.insert(key, Learned { addr, at: now });
                true
            }
            other => {
                self.observing = other;
                false
            }
        }
    }

    /// When the first learned address the snapshot wants ages out, while no
    /// observation is in flight.
    pub fn expiry(&self) -> Option<I> {
        if self.observing.is_some() {
            return None;
        }
        assemble::learned_wanted(&self.snapshot)
            .iter()
            .filter_map(|(key, _)| self.learned.get(key))
            .map(|learned| deadline(learned.at, self.ttl(learned)))
            .min()
    }

    /// Whether a learned address the snapshot wants has aged out at `now`;
    /// if so the snapshot is to be assembled again once it is observed.
    pub fn refresh_due(&mut self, now: I) -> bool {
        if self.observing.is_none() && self.next_observation(now).is_some() {
            self.stale = true;
            true
        } else {
            false
        }
    }

    /// Whether a snapshot is ready to assemble at `now`: one has arrived
    /// since the last assembly, and no address it wants is missing or being
    /// observed.
    pub fn ready(&self, now: I) -> bool {
        self.stale && self.observing.is_none() && self.next_observation(now).is_none()
    }

    /// Assemble the advert from the snapshot and the learned addresses, and
    /// hand back the requests that were waiting on it.
    pub fn assemble(
        &mut self,
        dm_relays: &[String],
        stun_servers: &[String],
    ) -> (assemble::Assembly, Vec<R>) {
        let learned = self
            .learned
            .iter()
            .map(|(key, learned)| (*key, learned.addr))
            .collect();
        self.stale = false;
        (
            assemble::assemble(&self.snapshot, &learned, dm_relays, stun_servers),
            core::mem::take(&mut self.waiting),
        )
    }
}

#[cfg(test)]
#[path = "tests/publisher.rs"]
mod tests;
