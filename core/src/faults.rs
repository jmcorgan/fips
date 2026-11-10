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
    /// A crossed dial's move sends the peer a tree announce on the session
    /// it is about to leave, before the move, as well as after it.
    MoveAnnouncesFirst,
    /// The smaller node of a crossed dial keeps the peer on its inbound
    /// session and closes its own dial, as the larger node does, where the
    /// tie-break moves it onto its dial.
    CrossedRunsKeep,
    /// A peer's record keeps its link's MMP counters through a rekey
    /// cutover, whose frame counter starts again at zero.
    CutoverSkipsMmpReset,
    /// A peer's record keeps its link's MMP counters through a move onto
    /// a new session, whose frame counter starts again at zero.
    MoveSkipsMmpReset,
    /// A rekey machine that yields to a peer's completed attempt keeps its
    /// own attempt instead of abandoning it.
    YieldKeepsOwnAttempt,
    /// The restart gate measures a heard peering's idle time on the wall
    /// clock instead of the peer clock.
    GateOnWall,
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
    /// A promotion runs the link machine's outputs before the peer is in
    /// the table, so its session finds no peer's total to hand the decrypt
    /// workers and is not delegated.
    OutputsBeforeInstall,
    /// A crossed dial's move builds the new link machine without offering
    /// its session to the decrypt workers, though a pool runs.
    MoveSkipsWorkerOffer,
    /// A newly promoted peer starts as if a tree announce had just been
    /// sent to it, so the rate limit holds back its first one.
    NewPeerStartsRateLimited,
    /// A peer replaced by a restart keeps the old peer's record of when it
    /// was last sent a tree announce.
    TreeCarryAcrossRestart,
    /// A peer restart found at a rekey leaves the peer in the spanning
    /// tree's state, so the declaration its previous run sent stays held.
    RestartSkipsTreeReset,
    /// A peer restart the link rekey machine reports is not acted on at
    /// the node, so what is held about the peer's previous run stays.
    RestartNotRouted,
    /// A link rekey machine's teardown is not acted on at the node, so the
    /// peer whose link it ended stays held.
    TeardownNotRouted,
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
    /// A BLE writer whose write fails removes every channel pooled at its
    /// address, not only its own.
    BleWriterRemovesByAddress,
    /// Following a moved path keeps the link's index entry at the pair the
    /// path left, beside the one at the pair it moved to.
    MovedLeavesEntry,
    /// A switch of the active path leaves the link's index without an entry
    /// at the newly active pair.
    SwitchSkipsClaim,
    /// A path released while the link lives leaves its connection open,
    /// though the peer has no further use for it and no other link uses it.
    ReleaseKeepsPairOpen,
    /// A crossed dial's renewal of the path machine logs none of its paths'
    /// changes of state.
    RenewedStateDropped,
    /// Removing an active peer leaves its link in the link table, with
    /// every index entry naming it.
    RemoveKeepsLink,
    /// An index the link machine unbinds stays in the session-index map,
    /// naming the peer that held it.
    UnbindKept,
    /// The operator's disconnect leaves the transport connection at the
    /// peer's pair open once the peer is removed.
    AdminKeepsConnection,
    /// A peer that sent a Disconnect is removed with the transport's mark
    /// at its pair left in place.
    DisconnectKeepsVerified,
    /// A link its rekey machine ended schedules a reconnect to the peer.
    EndedSchedulesRetry,
    /// The core's record of a link is never told a path's state, so a new
    /// bundle's original path and every later change of a path's state are
    /// missing from it.
    LinksNotFed,
    /// The live audit lets off any acknowledged path the core records Live,
    /// not only the active path a switch made Live.
    MirrorLetsAckedOff,
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
