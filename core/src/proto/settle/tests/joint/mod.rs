//! The joint world: nodes that run the settlement core, a real rekey
//! machine and a real path bundle per held peer, on the stub IK profile.
//! See this directory's README.
//!
//! Every joint node states its multipath setting as a [`Mode`]: nothing
//! here reads a default, since the node's default changes with a release
//! and both settings ship.

pub mod explore;
pub mod facts;
pub mod feeds;
pub mod machines;
pub mod names;
pub mod oracle;
pub mod party;
pub mod pins;
pub mod route;
pub mod runs;
pub mod starts;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::proto::path;
use crate::proto::rekey;
use crate::time::Duration;

use super::super::model::history::Node;
use super::party::Configured;
use super::starts::{BLE, TCP, UDP};
use super::world::{Kind, Party};

/// A joint node with multipath off.
pub fn off(ix: usize, me: Node, configured: Vec<Configured>) -> Box<dyn Party> {
    Box::new(party::JointParty::new(ix, me, configured, Mode::Off))
}

/// A joint node with multipath on.
pub fn on(ix: usize, me: Node, configured: Vec<Configured>) -> Box<dyn Party> {
    Box::new(party::JointParty::new(ix, me, configured, Mode::On))
}

/// A joint node with multipath on at node index 0 and off at every other.
pub fn on_off(ix: usize, me: Node, configured: Vec<Configured>) -> Box<dyn Party> {
    let mode = if ix == 0 { Mode::On } else { Mode::Off };
    Box::new(party::JointParty::new(ix, me, configured, mode))
}

/// A joint node with multipath off at node index 0 and on at every other.
pub fn off_on(ix: usize, me: Node, configured: Vec<Configured>) -> Box<dyn Party> {
    let mode = if ix == 0 { Mode::Off } else { Mode::On };
    Box::new(party::JointParty::new(ix, me, configured, mode))
}

/// The world's transports, as every start builds them.
pub fn kinds() -> BTreeMap<u8, Kind> {
    [(UDP, Kind::Datagram), (TCP, Kind::Stream), (BLE, Kind::Ble)]
        .into_iter()
        .collect()
}

/// A joint node's multipath setting, `node.path.enabled`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mode {
    /// Multipath disabled: the bundle holds one path and discards every
    /// candidate, path message and connection report.
    Off,
    /// Multipath enabled.
    On,
}

impl Mode {
    /// Whether multipath is enabled.
    pub fn enabled(self) -> bool {
        self == Self::On
    }

    /// The setting's name in a run's name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
        }
    }

    /// The path machine's settings the node derives at the default
    /// configuration with this setting (`path_params`,
    /// `src/node/handlers/path.rs:162-176`): the draft's values, enabled
    /// by the setting, with the 10 s heartbeat.
    pub fn path(self) -> path::Params {
        path::Params::new(self.config())
            .expect("the draft's values with a 10 s heartbeat are valid")
    }

    /// The path settings [`Self::path`] is made from, which the path
    /// shell's checks read.
    pub fn config(self) -> path::Config {
        path::Config {
            enabled: self.enabled(),
            heartbeat: Duration::from_secs(10),
            ..path::Config::draft()
        }
    }

    /// The link rekey settings the node derives at the default
    /// configuration with this setting (`link_params`,
    /// `src/node/handlers/rekey.rs:103-158`): the FMP defaults, with the
    /// 1 s check, five resends and the 30 s handshake timeout, the pending
    /// hold the link's longest silence needs, and the answer on a msg1's
    /// arrival path when multipath is enabled. At the defaults the time
    /// trigger (120 s, above the 15 s jitter plus the 30 s link age), the
    /// message trigger and both start floors (31 s) are the FMP defaults'.
    pub fn rekey(self) -> rekey::Params {
        let base = rekey::Config {
            // The defect's shape: the answer on the established link
            // whatever the setting.
            arrival: self.enabled() && !fault!(ArrivalIgnored),
            check: Duration::from_secs(1),
            resends: 5,
            handshake: Duration::from_secs(30),
            ..rekey::Config::fmp()
        };
        rekey::Params::new(base.with_hold(silence())).expect("the link defaults are valid")
    }
}

/// The longest silence the node tolerates on a link it keeps, at the
/// default configuration (`link_silence_ms`, `src/node/handlers/rekey.rs:50-58`):
/// the msg1 resend ladder of five resends, three 1 s ticks, and the longer
/// of the 10 s heartbeat and the 30 s link-dead timeout.
fn silence() -> Duration {
    rekey::msg1_span(5)
        .saturating_add(Duration::from_secs(3))
        .saturating_add(Duration::from_secs(30))
}
