//! Test-only switches, each of which puts back one break of the mutation
//! lane.
//!
//! A switch is the shape a real defect took, or the smallest change that
//! fixes a known defect, written in the code behind one condition rather
//! than kept as a patch. `testing/mutations/run.sh` runs each test its
//! manifest names in its own process with the switch's name set, and
//! classifies the run; a switch whose tests stay green is a guard that
//! guards nothing.
//!
//! One list holds every switch, whichever crate its site is in. A site is
//! `node_fault!(Name)`, defined once in each crate's root: in test builds it
//! asks [`on`], and in any other build it is the literal `false`, so a
//! normal or release build compiles the branch away. This crate's sites see
//! the module through `cfg(test)` and the root crate's through the
//! `test-hooks` feature, which the root enables from its
//! `[dev-dependencies]` only.
//!
//! The set is read once per process from the `FIPS_NODE_FAULTS`
//! environment variable, a comma-separated list of variant names, and an
//! unknown name panics. A test in a shared binary cannot set it, so the
//! reading is split: [`parse`] is pure, and the process's set goes through
//! [`load`], which a test can call with any text.
//!
//! The switches of the rekey machine (`proto/rekey/faults.rs`) and of the
//! settlement core stay with their own meta-tests.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use std::sync::OnceLock;

/// The environment variable that names the switches a test process runs
/// with.
pub const VAR: &str = "FIPS_NODE_FAULTS";

/// Declares [`Fault`] and its list from one list of variants, so the list
/// cannot drift from the enum. `run.sh` reads the variant names from this
/// macro's invocation below: one name per line, followed by a comma.
macro_rules! faults {
    ($($(#[$doc:meta])* $name:ident,)*) => {
        /// One break of the mutation lane, switched on.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Fault {
            $($(#[$doc])* $name,)*
        }

        impl Fault {
            /// Every switch, in declaration order.
            pub const ALL: &'static [Fault] = &[$(Fault::$name,)*];

            /// The variant's name, as `FIPS_NODE_FAULTS` spells it.
            pub fn name(self) -> &'static str {
                match self {
                    $(Fault::$name => stringify!($name),)*
                }
            }
        }
    };
}

faults! {
    /// The lane's self-check: its one site is in a planted test, which it
    /// turns red at that test's `defect:` assertion. It has no manifest
    /// line.
    PlantedRed,
    /// The lane's self-check: it has no site, so a test run with it on
    /// passes. It has no manifest line.
    PlantedGreen,
    /// A crossed dial's move builds the new link machine on the link's old
    /// transport and leaves the path bundle as it was, instead of taking
    /// the winning msg2's transport and address.
    MoveKeepsOldPair,
    /// The FMP decision for an outbound handshake completing beside an
    /// existing peer ignores that the dial was this node's own, so only
    /// the tie-break decides between swapping and keeping.
    IgnoreOwnDial,
    /// A link's MMP state keeps its spin bit through a rekey cutover,
    /// whose counters start again at zero.
    LinkSpinKept,
    /// A session's MMP state keeps its spin bit through a rekey cutover,
    /// whose counters start again at zero.
    SessionSpinKept,
    /// A rekey machine that yields to a peer's completed attempt keeps its
    /// own attempt instead of abandoning it.
    YieldKeepsOwnAttempt,
    /// The restart gate measures a heard peering's idle time on the wall
    /// clock instead of the peer clock.
    GateOnWall,
    /// The restart gate measures an unheard peering's age from the msg1's
    /// wall-clock stamp instead of on the peer clock from its promotion.
    UnheardAgeOnWall,
    /// The replay memory of msg1s that promoted an unheard peering is kept
    /// and read on the wall clock.
    MemoryOnWall,
    /// The replay memory is read at the packet's wall-clock stamp.
    MemoryVerdictOnPacketStamp,
    /// The replay memory never ages an entry out.
    MemoryNeverExpires,
    /// The node's interval clock reads the wall clock.
    IntervalOnWall,
    /// An authenticated frame marks the peer heard without moving the
    /// instant it was last heard.
    TouchKeepsHeardInstant,
    /// A peer never sent a tree announce counts as sent one at instant 0.
    TreeNoneAsZero,
    /// The tree announce rate limit reads the wall clock.
    TreeOnWall,
    /// Closing an end-to-end session, by a probe's teardown or by the
    /// session closer, keeps the path MTU clamp entry the session
    /// tightened.
    ClampEntryKept,
    /// Removing a peer at a restart keeps the path MTU clamp entry its
    /// promotion seeded.
    RestartKeepsClamp,
    /// An initiator's promotion does not tell the transport which link the
    /// new peer uses, so on BLE the link stays unverified until the
    /// responder's first frame.
    DropInitiatorMark,
    /// A msg2 that does not authenticate ends the pending dial instead of
    /// keeping the attempt for the genuine msg2.
    ForgetDialOnRefusedMsg2,
    /// A newly promoted peer starts as if a tree announce had just been
    /// sent to it, so the rate limit holds back its first one.
    NewPeerStartsRateLimited,
    /// A peer replaced by a restart keeps the old peer's record of when it
    /// was last sent a tree announce.
    TreeCarryAcrossRestart,
    /// A rekey this node answered as responder does not mark its filter to
    /// be sent again.
    ResponderCutoverSkipsFilterMark,
    /// A stream transport's close aborts the connection's writer at once
    /// instead of letting it write what was queued.
    DrainAbortsAtOnce,
    /// Stopping a stream transport leaves the writers of closed
    /// connections still draining.
    DrainStopLeavesWriters,
    /// An accepted stream connection is closed at half its first-frame
    /// deadline.
    FirstFrameAtHalf,
    /// An accepted stream connection that sends nothing is held for a
    /// year instead of its first-frame deadline.
    FirstFrameDeadlineIgnored,
    /// The TCP receive loop bounds frames by the connection's own `mtu`
    /// instead of the receive ceiling.
    TcpRecvBoundedByMtu,
    /// The Tor and Nym receive loop bounds frames by the connection's own
    /// `mtu` instead of the receive ceiling.
    ProxiedRecvBoundedByMtu,
    /// A BLE writer whose write fails removes whatever connection is
    /// pooled at its address, not only its own.
    BleWriterRemovesByAddress,
    /// A deliberate BLE close aborts the connection's writer instead of
    /// letting it write what was queued.
    BleCloseAbortsWriter,
    /// Stopping the BLE transport leaves the writers of closed connections
    /// still draining.
    BleStopLeavesDrains,
    /// The BLE transport never closes a channel on which no handshake has
    /// completed.
    BleUnprovenNeverClosed,
    /// The BLE transport closes an unproven channel at half the handshake
    /// timeout.
    BleUnprovenAtHalfTimeout,
    /// The BLE transport closes an unproven channel two seconds before the
    /// handshake timeout.
    BleUnprovenTwoSecondsEarly,
    /// The BLE transport closes an unverified channel even when a
    /// handshake completed on it.
    BleUnprovenIgnoresHandshake,
    /// The BLE transport does not restart the timeout of a channel the
    /// node holds.
    BleUnprovenIgnoresHeld,
}

impl Fault {
    /// The switch whose variant name is `name`.
    pub fn named(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|f| f.name() == name)
    }
}

/// The switches a comma-separated list names, in its order. Empty entries
/// are skipped; an unknown name is an error naming it.
pub fn parse(names: &str) -> Result<Vec<Fault>, String> {
    names
        .split(',')
        .filter(|n| !n.is_empty())
        .map(|n| Fault::named(n).ok_or_else(|| format!("{VAR} names no switch {n:?}")))
        .collect()
}

/// The switches a list names, panicking on an unknown name, as the
/// process's set does.
pub fn load(names: &str) -> Vec<Fault> {
    parse(names).unwrap_or_else(|e| panic!("{e}"))
}

/// The switches this process runs with.
fn set() -> &'static [Fault] {
    static SET: OnceLock<Vec<Fault>> = OnceLock::new();
    SET.get_or_init(|| load(&std::env::var(VAR).unwrap_or_default()))
}

/// Whether `fault` is on in this process.
pub fn on(fault: Fault) -> bool {
    set().contains(&fault)
}

#[cfg(test)]
#[path = "tests/faults.rs"]
mod tests;
