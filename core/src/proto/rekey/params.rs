//! Rekey parameters, their validation and the values derived from them.
//!
//! [`Params::new`] is the only way to make a [`Params`], and it refuses any
//! configuration under which a timer would fire on every poll or never, or
//! a rekey interval below the jitter plus the link-age floor. Every derived
//! value (the resend schedules, the confirmation window, the probe grace cap
//! and so on) is worked out there once, and a configured resend count whose
//! rungs fall at or after their deadline is reported, never sent.

use thiserror::Error;

use super::ladder::{Schedule, millis};
use crate::time::Duration;

/// The first interval of every fixed resend ladder.
const RUNG: Duration = Duration::from_secs(1);

/// Probe rungs after a revert: at the revert, then 1, 3 and 7 s.
const REVERT_PROBES: u8 = 3;

/// Prompt repeats after a cutover: at the cutover, then 1 and 3 s.
const ELICIT_REPEATS: u8 = 2;

/// Rekey msg3 resends of a next-only delayed cutover: 1, 3, 7 and 15 s.
const DELAY_RESENDS: u8 = 4;

/// The offset of the last first-message resend of a doubling ladder with
/// `resends` rungs from one second, whether or not it falls inside the
/// attempt budget: 31 s at the default five. The budget of an IK msg1
/// attempt is the smaller of this span plus one check and the handshake
/// timeout, so a link shell that defers its link-dead reap while an attempt
/// is in flight bounds the silence it tolerates during a rekey by this span
/// plus two checks.
pub fn msg1_span(resends: u8) -> Duration {
    Schedule::doubling(RUNG, resends, None)
        .0
        .last_send()
        .map_or(Duration::ZERO, Duration::from_millis)
}

/// The session age, measured from its last cutover, below which a 0.5.0
/// to 0.5.2 peer takes a same-epoch msg1 for a fresh dial rather than a
/// rekey. A link's own rekeys wait one check past it.
pub const DEPLOYED_SESSION_FLOOR: Duration = Duration::from_secs(30);

/// The largest time trigger accepted, in seconds. A larger value is the
/// configuration idiom for switching the time trigger off, which rekey no
/// longer has.
pub const MAX_AFTER: u64 = u32::MAX as u64;

/// The settings a profile's machines run with.
///
/// The shell builds one from its configuration, or starts from
/// [`Config::fmp`] or [`Config::fsp`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// The time trigger: rekey this long after the last cutover.
    pub after: Duration,
    /// The jitter, in whole seconds, added to `after` from
    /// `[-jitter, +jitter]` at every cutover.
    pub jitter: u16,
    /// The message trigger: rekey once this many frames were sealed.
    pub messages: u64,
    /// How long a handshake may take.
    pub handshake: Duration,
    /// The shell's tick: one check interval.
    pub check: Duration,
    /// How long the previous epoch is kept after evidence the peer moved.
    pub drain: Duration,
    /// The ceiling on how long the previous epoch is kept.
    pub retention: Duration,
    /// How long a responder pending waits for the frame that adopts it.
    pub hold: Duration,
    /// How long a reverted epoch waits for evidence.
    pub revert: Duration,
    /// How long after answering (IK) or completing (XK) a peer's rekey no
    /// own rekey starts.
    pub dampening: Duration,
    /// How long a candidate lives from its setup.
    pub ttl: Duration,
    /// The age below which a first-handshake attempt is young.
    pub young: Duration,
    /// The link age at which an IK msg1 is eligible as a rekey.
    pub link_age: Duration,
    /// The session age at which an IK msg1 is eligible as a rekey.
    pub session_age: Duration,
    /// The link age before which no own rekey starts.
    pub floor_link: Duration,
    /// The session age before which no own rekey starts.
    pub floor_session: Duration,
    /// The time since the last cutover before which no own rekey starts.
    pub floor_cutover: Duration,
    /// The first interval of the silence trigger.
    pub silence: Duration,
    /// Configured resends of a retained handshake message.
    pub resends: u8,
    /// The send counter at which a rekey is forced past dampening and
    /// backoff.
    pub soft: u64,
    /// The send counter at which the session is torn down.
    pub hard: u64,
    /// The initiator's cutover delay of a next-only delayed-cutover
    /// profile.
    pub delay: Duration,
    /// Send a responder's msg2 on the msg1's arrival path (multipath).
    pub arrival: bool,
}

impl Config {
    /// The defaults for a link (FMP).
    pub const fn fmp() -> Self {
        let check = Duration::from_secs(1);
        let link_age = Duration::from_secs(30);
        Self {
            after: Duration::from_secs(120),
            jitter: 15,
            messages: 1 << 16,
            handshake: Duration::from_secs(30),
            check,
            drain: Duration::from_secs(10),
            retention: Duration::from_secs(120),
            hold: Duration::from_secs(120),
            revert: Duration::from_secs(10),
            dampening: Duration::from_secs(30),
            ttl: Duration::from_secs(40),
            young: Duration::from_secs(5),
            link_age,
            session_age: Duration::from_secs(10),
            floor_link: link_age.saturating_add(check),
            floor_session: DEPLOYED_SESSION_FLOOR.saturating_add(check),
            floor_cutover: Duration::ZERO,
            silence: Duration::from_secs(30),
            resends: 5,
            soft: 1 << 62,
            hard: u64::MAX - (1 << 20) + 1,
            delay: Duration::from_secs(2),
            arrival: false,
        }
    }

    /// The defaults for an end-to-end session (FSP).
    pub const fn fsp() -> Self {
        Self {
            floor_link: Duration::ZERO,
            floor_session: Duration::ZERO,
            floor_cutover: Duration::from_secs(10),
            ..Self::fmp()
        }
    }

    /// This configuration with the pending hold a link responder needs:
    /// the longest of the drain ceiling, the time a peer that lost the
    /// answer to its rekey takes to try again (its msg1 resend span, the
    /// handshake timeout and the dampening window), and `silence`, the
    /// longest the link shell lets a kept link go unheard. A hold shorter
    /// than any of them can retire a session the initiator still adopts:
    /// 120 s at the defaults (FRC-1201 §7.6).
    pub fn with_hold(self, silence: Duration) -> Self {
        let retry = msg1_span(self.resends)
            .saturating_add(self.handshake)
            .saturating_add(self.dampening);
        Self {
            hold: self.retention.max(retry).max(silence),
            ..self
        }
    }
}

/// A configuration [`Params::new`] refuses.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ParamsError {
    /// The message trigger would fire on every poll.
    #[error("the message trigger must be at least 1")]
    ZeroMessages,
    /// The message trigger lies past the soft counter limit, so it would
    /// never fire before the limit forces a rekey.
    #[error("the message trigger must not exceed the soft counter limit")]
    MessagesPastSoft,
    /// The time trigger is not above the jitter, so jittered intervals
    /// saturate to zero and fire on sight.
    #[error("the time trigger must be greater than the jitter")]
    AfterNotAboveJitter,
    /// The time trigger is below the jitter plus the link-age floor, so a
    /// rekey could fall due before the peer would answer it.
    #[error("the time trigger must be at least the jitter plus the link-age floor")]
    AfterBelowLinkFloor,
    /// The time trigger is so long it never fires.
    #[error("the time trigger must not exceed {MAX_AFTER} seconds")]
    AfterTooLong,
    /// A duration that must be positive is zero.
    #[error("{0} must be greater than zero")]
    Zero(&'static str),
    /// The handshake timeout leaves no room for two setup resends.
    #[error("the handshake timeout must exceed one check by at least 3 seconds")]
    HandshakeTooShort,
    /// The drain window leaves no room for a keepalive with one lost.
    #[error("the drain window must exceed 2 seconds")]
    DrainTooShort,
    /// The drain ceiling is below the drain window.
    #[error("the drain ceiling must not be below the drain window")]
    RetentionBelowDrain,
    /// The pending hold does not outlast the peer's latest cutover.
    #[error("the pending hold must exceed the handshake timeout plus one check")]
    HoldTooShort,
    /// The soft counter limit is not below the hard one.
    #[error("the soft counter limit must be below the hard one")]
    SoftNotBelowHard,
}

/// Configured resend rungs that fall at or after their deadline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Inert {
    /// Of the IK msg1 and the first-handshake setup.
    pub first: u8,
    /// Of the rekey msg3, against the confirmation deadline, plus any probe
    /// or keepalive rung the schedule had no room for.
    pub probes: u8,
}

/// Validated settings and every value derived from them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub(crate) cfg: Config,
    /// The confirmation window: the handshake timeout plus one check.
    pub(crate) confirm: Duration,
    /// The confirmation window plus one drain window.
    pub(crate) span: Duration,
    /// The cap on the probe grace.
    pub(crate) grace: Duration,
    /// The cap on the first rung of a rekey setup.
    pub(crate) rung: Duration,
    /// The longest gap between frames under the current epoch while a
    /// completed rekey awaits evidence.
    pub(crate) gap: Duration,
    /// The deadline of an IK msg1 attempt or a first-handshake setup.
    pub(crate) budget: Duration,
    /// IK msg1 and first-handshake setup resends.
    pub(crate) first: Schedule,
    /// Resends of a retained final message in the current epoch.
    pub(crate) fin: Schedule,
    /// Rekey msg3 probe rungs and keepalive-only rungs.
    pub(crate) probes: Schedule,
    /// Probe rungs after a revert.
    pub(crate) revert: Schedule,
    /// Prompt repeats after a cutover.
    pub(crate) elicit: Schedule,
    /// Rekey msg3 resends of a delayed cutover.
    pub(crate) delayed: Schedule,
    inert: Inert,
}

impl Params {
    /// Validate `cfg` and derive every value the machine uses.
    pub fn new(cfg: Config) -> Result<Self, ParamsError> {
        Self::check(&cfg)?;
        let confirm = if fault!(ConfirmWithoutCheck) {
            cfg.handshake
        } else {
            cfg.handshake.saturating_add(cfg.check)
        };
        let span = confirm.saturating_add(cfg.drain);
        let rung_secs = cfg.handshake.saturating_sub(cfg.check).as_secs() / 3;
        let rung = Duration::from_secs(rung_secs);
        let gap = cfg.drain.saturating_sub(Duration::from_secs(2)) / 2;

        let exhausted = msg1_span(cfg.resends).saturating_add(cfg.check);
        let budget = exhausted.min(cfg.handshake);
        let (first, first_inert) = Schedule::doubling(RUNG, cfg.resends, Some(budget));
        let (fin, _) = Schedule::doubling(RUNG, cfg.resends, None);
        let (probes, probe_inert) = Schedule::probes(RUNG, cfg.resends, confirm, gap);
        let (revert, _) = Schedule::probes(RUNG, REVERT_PROBES, cfg.revert, gap);
        let (elicit, _) = Schedule::doubling(RUNG, ELICIT_REPEATS, None);
        let (delayed, _) = Schedule::doubling(RUNG, DELAY_RESENDS, None);
        let last_probe = probes.last_send().unwrap_or(0);
        let grace = Duration::from_millis(millis(confirm).saturating_sub(last_probe) / 2);

        Ok(Self {
            cfg,
            confirm,
            span,
            grace,
            rung,
            gap,
            budget,
            first,
            fin,
            probes,
            revert,
            elicit,
            delayed,
            inert: Inert {
                first: first_inert,
                probes: probe_inert,
            },
        })
    }

    /// The defaults for a link (FMP).
    pub fn fmp() -> Self {
        Self::new(Config::fmp()).expect("the FMP defaults are valid")
    }

    /// The defaults for an end-to-end session (FSP).
    pub fn fsp() -> Self {
        Self::new(Config::fsp()).expect("the FSP defaults are valid")
    }

    /// Refuse a configuration that would make a timer fire on every poll
    /// or never.
    fn check(cfg: &Config) -> Result<(), ParamsError> {
        if cfg.messages == 0 && !fault!(NoZeroMessagesCheck) {
            return Err(ParamsError::ZeroMessages);
        }
        if cfg.messages > cfg.soft {
            return Err(ParamsError::MessagesPastSoft);
        }
        let jitter = Duration::from_secs(u64::from(cfg.jitter));
        if cfg.after <= jitter {
            return Err(ParamsError::AfterNotAboveJitter);
        }
        if cfg.after < jitter.saturating_add(cfg.link_age) && !fault!(NoLinkFloorCheck) {
            return Err(ParamsError::AfterBelowLinkFloor);
        }
        if cfg.after > Duration::from_secs(MAX_AFTER) {
            return Err(ParamsError::AfterTooLong);
        }
        let positive = [
            (cfg.check, "the check interval"),
            (cfg.hold, "the pending hold"),
            (cfg.revert, "the revert window"),
            (cfg.ttl, "the candidate lifetime"),
            (cfg.silence, "the silence interval"),
        ];
        for (value, name) in positive {
            if value.is_zero() {
                return Err(ParamsError::Zero(name));
            }
        }
        if cfg.handshake < cfg.check.saturating_add(Duration::from_secs(3)) {
            return Err(ParamsError::HandshakeTooShort);
        }
        if cfg.drain <= Duration::from_secs(2) {
            return Err(ParamsError::DrainTooShort);
        }
        if cfg.retention < cfg.drain {
            return Err(ParamsError::RetentionBelowDrain);
        }
        if cfg.hold <= cfg.handshake.saturating_add(cfg.check) {
            return Err(ParamsError::HoldTooShort);
        }
        if cfg.soft >= cfg.hard {
            return Err(ParamsError::SoftNotBelowHard);
        }
        Ok(())
    }

    /// The settings these parameters were made from.
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// The configured resend rungs that fall at or after their deadline and
    /// are therefore never sent.
    pub fn inert(&self) -> Inert {
        self.inert
    }

    /// The abandon backoff after `n` abandoned attempts, before its random
    /// term: one check doubled per abandon, capped at the pending hold.
    pub(crate) fn backoff(&self, n: u8) -> Duration {
        let shift = u32::from(n.saturating_sub(1));
        let factor = 1u32.checked_shl(shift).unwrap_or(u32::MAX);
        self.cfg.check.saturating_mul(factor).min(self.cfg.hold)
    }
}

#[cfg(test)]
#[path = "tests/params.rs"]
mod tests;
