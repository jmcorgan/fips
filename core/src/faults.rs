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
    /// The FMP decision for an outbound handshake completing beside an
    /// existing peer ignores that the dial was this node's own, so only
    /// the tie-break decides between swapping and keeping.
    IgnoreOwnDial,
    /// The smaller node of a crossed dial keeps the peer on its inbound
    /// session and closes its own dial, as the larger node does, where the
    /// tie-break moves it onto its dial.
    CrossedRunsKeep,
    /// A link's MMP state keeps its spin bit through a rekey cutover,
    /// whose counters start again at zero.
    LinkSpinKept,
    /// A session's MMP state keeps its spin bit through a rekey cutover,
    /// whose counters start again at zero.
    SessionSpinKept,
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
    /// Removing an unheard peering keeps its end-to-end session but leaves
    /// it in place while the path MTU state is released, so the release
    /// resets the estimate the session made of its own path.
    KeptSessionNotSetAside,
    /// An initiator's promotion does not tell the transport which link the
    /// new peer uses, so on BLE the link stays unverified until the
    /// responder's first frame.
    DropInitiatorMark,
    /// Telling the transports a peer moved links clears the old link before
    /// marking the new one, so for a moment the peer has no verified link.
    RelinkClearsFirst,
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
    /// A rekey this node answered as responder does not mark its filter to
    /// be sent again.
    ResponderCutoverSkipsFilterMark,
    /// A peer restart found at a rekey leaves the peer in the spanning
    /// tree's state, so the declaration its previous run sent stays held.
    RestartSkipsTreeReset,
    /// A peer restart the link rekey machine reports is not acted on at
    /// the node, so what is held about the peer's previous run stays.
    RestartNotRouted,
    /// A link rekey machine's teardown is not acted on at the node, so the
    /// peer whose link it ended stays held.
    TeardownNotRouted,
    /// A link rekey machine's request for the restart gates is not acted
    /// on at the node, so the msg1 it was given replaces nothing.
    ReplaceNotRouted,
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
    /// A moved path's old pair stays in the link's record, so the index
    /// derived from it keeps an entry there, beside the one at the pair it
    /// moved to.
    MovedLeavesEntry,
    /// A path released while the link lives leaves its connection open,
    /// though the peer has no further use for it and no other link uses it.
    ReleaseKeepsPairOpen,
    /// A queued close is drained without asking the close rule again, so it
    /// closes a connection a link took up after the close was queued.
    DrainReadsNothing,
    /// A crossed dial's renewal of the path machine logs none of its paths'
    /// changes of state.
    RenewedStateDropped,
    /// A connection that opens for a pair the link's bundle no longer
    /// holds is stepped into the bundle and left open, though no link
    /// uses it.
    ConnectLeftOpen,
    /// A connection that opens for a pair is closed when no other link
    /// uses it, even when the link's own bundle still holds the pair.
    ConnectClosesHeld,
    /// Removing an active peer leaves its link in the link table, with
    /// every index entry naming it.
    RemoveKeepsLink,
    /// An index the link machine unbinds stays in the session-index map,
    /// naming the peer that held it.
    UnbindKept,
    /// The operator's disconnect leaves the transport connection at the
    /// peer's pair open once the peer is removed.
    AdminKeepsConnection,
    /// The node's close rule counts only the proven paths of peers on
    /// other links, so a handshake leg in flight keeps no connection open.
    CloseByPeerAddress,
    /// The node's close rule answers a link a peer holds by the pair it was
    /// set up at, whatever paths its bundle has proven.
    CloseBySetupAddress,
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
    /// A link's setup address stays in the index derived from the link
    /// records after its bundle released the path there.
    ReleasedSetupIndexed,
    /// Closing a link takes the index's entry at each pair it was named at
    /// from any other link that uses the pair, as the written index did.
    ShadowLosesEntry,
    /// Abandoning a dial takes the index's entry at the dial's pair from
    /// whichever link it named, as the written index did.
    ForgetTakesKey,
    /// A pair several links use names the link opened first, not the one
    /// opened last.
    IndexOldestWins,
    /// Applying a bundle's report to a link's record leaves the index as it
    /// was, so a path the record gains or loses is not reflected in it.
    IndexNotRebuilt,
    /// A one-path roam or a bind, which the bundle reports in no output, is
    /// not told to the core, so the link's record keeps the old pair.
    RoamNotFed,
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
