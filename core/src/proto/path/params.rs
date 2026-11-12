//! The path machine's settings, their validation and the values derived
//! from them.
//!
//! [`Params::new`] is the only way to make a [`Params`]: it refuses a zero
//! for every interval and count, a switch margin that is not a finite
//! number of at least 1.0, and a probe ring larger than a path holds, and
//! it derives the round-trip window once. [`Config::draft`] gives the
//! values of the multipath v1 draft, Appendix A. The draft's bounds on a
//! path that has stopped answering, [`PATH_SILENCE_MAX`],
//! [`PATH_DEAD_PROBE_INTERVAL_MIN`] and [`PATH_DEAD_PROBE_INTERVAL_MAX`],
//! are constants, not settings: no node chooses a bound.

use thiserror::Error;

use crate::time::Duration;

/// The most probes a path keeps outstanding at once.
pub const RING: usize = 8;

/// The longest a path that is not Probing goes from the earliest probe no
/// matching answer has followed before it has stopped answering (draft
/// Section 5.6; `PATH_SILENCE_MAX`, Appendix A).
pub const PATH_SILENCE_MAX: Duration = Duration::from_secs(60);

/// The least wait before each of the first two probes on its own cadence
/// of a path that has stopped answering, the first counted from the stop
/// (draft Section 5.6; `PATH_DEAD_PROBE_INTERVAL_MIN`, Appendix A).
pub const PATH_DEAD_PROBE_INTERVAL_MIN: Duration = Duration::from_secs(1);

/// The cap on the doubling least gap between the later probes on its own
/// cadence of a path that has stopped answering (draft Section 5.6;
/// `PATH_DEAD_PROBE_INTERVAL_MAX`, Appendix A).
pub const PATH_DEAD_PROBE_INTERVAL_MAX: Duration = Duration::from_secs(30);

/// The shortest round-trip window.
const WINDOW: Duration = Duration::from_secs(30);

/// The settings a link's path machine runs with.
///
/// The shell builds one from its configuration, or starts from
/// [`Config::draft`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Config {
    /// Whether this node sends and answers path messages (draft Section
    /// 8.2).
    pub enabled: bool,
    /// The score ratio a discretionary change of active path needs
    /// (`SWITCH_MARGIN`).
    pub switch_margin: f64,
    /// How long the margin must hold before the change (`SWITCH_DWELL`).
    pub switch_dwell: Duration,
    /// Round-trip samples a path needs before selection may choose it.
    pub min_samples: u8,
    /// Probe interval on a path either end sends data on
    /// (`PATH_PROBE_INTERVAL_ACTIVE`), and the first interval of the
    /// discovery backoff.
    pub active_interval: Duration,
    /// Probe interval on a Live or Suspect standby path
    /// (`PATH_PROBE_INTERVAL_STANDBY`), and the first interval of the Dead
    /// cadence.
    pub standby_interval: Duration,
    /// Whether paths of another kind than the original path's are admitted
    /// (draft Section 5.5 recommends the same kind by default).
    pub mix_kinds: bool,
    /// The floor of the probe timeout (`PATH_PROBE_TIMEOUT_MIN`).
    pub timeout: Duration,
    /// The verdict cap, a local choice the draft gives no value: the
    /// longest a probe's verdict waits after the probe is sent while the
    /// peer's session datagrams arrive on its path, and the cap on the
    /// probe timeout's term from the largest round trip in the path's
    /// window (draft Section 5.6 leaves the timeout to the node).
    pub verdict_cap: Duration,
    /// The horizon, a local choice the draft gives no value: the least
    /// span a path's least round trip is also kept over, beside the
    /// round-trip window. A discretionary change away from the active path
    /// on score must also beat the active path's score from that least
    /// round trip, unless the path taken is the faster of the two at its
    /// best over the horizon, so load on the active path alone does not
    /// move the link to a path slower at its best for a horizon.
    pub horizon: Duration,
    /// Consecutive unanswered probes before a Live path becomes Suspect
    /// (`PATH_TIMEOUT_K`).
    pub suspect: u8,
    /// Consecutive unanswered probes before a Suspect path becomes Dead
    /// (`PATH_SUSPECT_RETIRE`).
    pub retire: u8,
    /// Unanswered probes before a Probing path becomes Dead
    /// (`MAX_DISCOVERY_PROBES`).
    pub discovery: u8,
    /// The cap of the discovery backoff: the FMP heartbeat interval.
    pub heartbeat: Duration,
    /// The longest interval between probes of an acked Dead path on this
    /// node's own Dead cadence, which the node sets. The floor on a path
    /// that has stopped answering is capped by the bound
    /// [`PATH_DEAD_PROBE_INTERVAL_MAX`] instead, which no node sets; at
    /// the draft's values the two agree.
    pub dead_interval: Duration,
    /// How long a Dead path is held before it is discarded
    /// (`PATH_DEAD_GRACE`).
    pub grace: Duration,
    /// Consecutive authentication failures on a counted path before it
    /// becomes Dead (`AUTH_FAIL_LIMIT`).
    pub auth_limit: u8,
    /// Probes a Live or Suspect path keeps outstanding at once, at most
    /// [`RING`].
    pub ring: u8,
    /// Capability probes in the first round to a peer not known to be
    /// capable (`CAPABILITY_PROBE_BUDGET`).
    pub budget: u8,
    /// The time the first round of capability probes is spread over, and
    /// the first interval of the backoff after it
    /// (`CAPABILITY_PROBE_SPAN`).
    pub span: Duration,
    /// The longest interval between capability probes after the first
    /// round (`CAPABILITY_PROBE_INTERVAL_MAX`).
    pub cap: Duration,
}

impl Config {
    /// The values of the multipath v1 draft (Appendix A), and for the
    /// verdict cap and the horizon, which the draft leaves to the node, 3 s
    /// and 60 s.
    pub const fn draft() -> Self {
        Self {
            enabled: true,
            switch_margin: 1.3,
            switch_dwell: Duration::from_secs(2),
            min_samples: 2,
            active_interval: Duration::from_millis(200),
            standby_interval: Duration::from_secs(1),
            mix_kinds: false,
            timeout: Duration::from_millis(400),
            verdict_cap: Duration::from_secs(3),
            horizon: Duration::from_secs(60),
            suspect: 3,
            retire: 10,
            discovery: 8,
            heartbeat: Duration::from_secs(10),
            dead_interval: Duration::from_secs(30),
            grace: Duration::from_secs(600),
            auth_limit: 20,
            ring: RING as u8,
            budget: 3,
            span: Duration::from_secs(30),
            cap: Duration::from_secs(600),
        }
    }
}

/// A configuration [`Params::new`] refuses.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ParamsError {
    /// An interval or count that must be positive is zero.
    #[error("{0} must be greater than zero")]
    Zero(&'static str),
    /// The switch margin is not a finite number of at least 1.0, so two
    /// equal paths would swap after every dwell.
    #[error("the switch margin must be a finite number of at least 1.0")]
    Margin,
    /// The ring holds more probes than a path keeps.
    #[error("the probe ring must hold at most {RING} probes")]
    Ring,
}

/// Validated settings and the values derived from them.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Params {
    pub(super) cfg: Config,
    /// The span of round-trip samples a path's minimum is taken over: two
    /// standby intervals per required sample, and at least 30 seconds.
    pub(super) window: Duration,
}

impl Params {
    /// Validate `cfg` and derive the round-trip window.
    pub fn new(cfg: Config) -> Result<Self, ParamsError> {
        Self::check(&cfg)?;
        let window = cfg
            .standby_interval
            .saturating_mul(u32::from(cfg.min_samples))
            .saturating_mul(2)
            .max(WINDOW);
        Ok(Self { cfg, window })
    }

    /// The draft's values.
    pub fn draft() -> Self {
        Self::new(Config::draft()).expect("the draft's values are valid")
    }

    /// The settings these parameters were made from.
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Refuse a zero interval or count, a margin under which equal paths
    /// would swap, and a ring larger than a path holds.
    fn check(cfg: &Config) -> Result<(), ParamsError> {
        let spans = [
            (cfg.switch_dwell, "the switch dwell"),
            (cfg.active_interval, "the active probe interval"),
            (cfg.standby_interval, "the standby probe interval"),
            (cfg.timeout, "the probe timeout floor"),
            (cfg.verdict_cap, "the verdict cap"),
            (cfg.horizon, "the horizon"),
            (cfg.heartbeat, "the heartbeat interval"),
            (cfg.dead_interval, "the Dead probe interval cap"),
            (cfg.grace, "the Dead grace"),
            (cfg.span, "the capability probe span"),
            (cfg.cap, "the capability probe interval cap"),
        ];
        for (value, name) in spans {
            if value.is_zero() {
                return Err(ParamsError::Zero(name));
            }
        }
        let counts = [
            (cfg.min_samples, "the minimum samples"),
            (cfg.suspect, "the Suspect count"),
            (cfg.retire, "the retire count"),
            (cfg.discovery, "the discovery probe count"),
            (cfg.auth_limit, "the authentication failure limit"),
            (cfg.ring, "the probe ring"),
            (cfg.budget, "the capability probe budget"),
        ];
        for (value, name) in counts {
            if value == 0 {
                return Err(ParamsError::Zero(name));
            }
        }
        if !cfg.switch_margin.is_finite() || cfg.switch_margin < 1.0 {
            return Err(ParamsError::Margin);
        }
        if usize::from(cfg.ring) > RING {
            return Err(ParamsError::Ring);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/params.rs"]
mod tests;
