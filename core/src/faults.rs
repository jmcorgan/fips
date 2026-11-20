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
    /// the winning msg2's transport and address, and leaves the peer on the
    /// link it was held on, the old pair's.
    MoveKeepsOldPair,
    /// A crossed dial's move sends the peer a tree announce on the session
    /// it is about to leave, before the move, as well as after it.
    MoveAnnouncesFirst,
    /// A crossed dial's move leaves the peer on the link it was held on and
    /// tears down the dial's link, instead of holding the link it dialed
    /// and tearing down the one it left.
    MoveKeepsInboundLink,
    /// A move onto the dial's link leaves the peer's control machine and
    /// its timers under the link the peer left.
    MachineLeftBehind,
    /// A move onto the dial's link leaves the peer's carrier readings under
    /// the link the peer left.
    CarrierLeftBehind,
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
    /// A move that makes a peering heard keeps the replay memory of the
    /// msg1s that promoted it unheard.
    MoveKeepsReplayMemory,
    /// The node's interval clock reads the wall clock.
    IntervalOnWall,
    /// An authenticated frame marks the peer heard without moving the
    /// instant it was last heard.
    TouchKeepsHeardInstant,
    /// A move onto this node's own dial leaves the peering unheard until
    /// the peer's first frame.
    MoveLeavesUnheard,
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
    /// The BLE transport starts a link's receive loop before offering the
    /// link to the pool, so a link the pool refuses still delivers frames
    /// under the address another link holds.
    BleReceiveBeforeAdmission,
    /// The BLE scan loop's retry tick never prunes its memory of what link
    /// addresses resolved to.
    BleRetryTickSkipsPrune,
    /// The BLE scan loop's retry tick prunes that memory as though no
    /// address were pooled or in the retry book.
    BleRetryTickPrunesLive,
    /// A queueing transport puts path messages in the connection's data
    /// queue, behind the data and refused when it is full, instead of in
    /// their own queue, which its writer drains first.
    PathLaneShared,
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
    /// The settlement core removes a peer whose bundle was orphaned with no
    /// reconnect, though the node notes that loss for one as it does a dead
    /// link.
    OrphanedNoRetry,
    /// The settlement core removes a peer for a restart, a replacement or
    /// an own-dial restart with no reconnect, though the peer's control
    /// machine reports each loss for one before the new session is
    /// promoted.
    RestartNoRetry,
    /// The settlement core's removal of an orphaned or disconnected peer
    /// closes every pair of its link no other link uses, a setup pair the
    /// bundle released to keep included, and leaves the pair a
    /// disconnected peer was held at open while another link uses it.
    RemovalClosesEveryPair,
    /// The core's record of a link is never told a path's state, so a new
    /// bundle's original path and every later change of a path's state are
    /// missing from it.
    LinksNotFed,
    /// A link's setup address stays in the index derived from the link
    /// records after its bundle released the path there.
    ReleasedSetupIndexed,
    /// The peer's bundle turning capable never reaches the core's record of
    /// its link, so the record holds the link not capable for life.
    CapableUnmirrored,
    /// The settlement core counts a msg1 from a held link's setup pair as on
    /// the link whether or not the peer is capable, where the node counts a
    /// capable peer's pair that its bundle holds no path at as off it.
    CapableIgnored,
    /// The settlement core counts a msg1 from the pair its record of the
    /// peer is at as on the link, and a msg1 from the setup pair whatever
    /// the state of the path there, where the node counts only the proven
    /// paths, and the index at a pair the bundle holds no path at.
    AttributeByCurrent,
    /// The settlement core counts a msg1 as on a held peer's link only from
    /// the link's setup pair, as a post-move msg1 classified by the old
    /// setup address would be.
    AttributeBySetupOnly,
    /// The settlement core leaves its record of where a peer is at the
    /// path its bundle switched away from.
    SwitchLeavesPeer,
    /// The settlement core moves its record of where a peer is to the
    /// source of each frame, wherever the frame came from, and not when the
    /// bundle moves the path the peer is at.
    HeardMovesPeer,
    /// The settlement core resets a peer's data as a roam when the bundle
    /// moves the path the peer is at at a path message, which the node runs
    /// as a move of that path and no roam.
    FollowResets,
    /// A switch records the path switched to Live in the link's record,
    /// the settlement core's and the node's, whatever state the bundle holds
    /// it in.
    SwitchWritesLive,
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
    /// A probe's verdict does not wait while the peer's session datagrams
    /// arrive on its path: a probe queued behind the data is counted
    /// unanswered at its timeout.
    VerdictIgnoresData,
    /// A probe's timeout is the larger of the floor and three times the
    /// latest round trip only, as before, so the probes sent as a queue
    /// builds time out before their answers can arrive.
    TimeoutFromLatest,
    /// The verdict cap bounds neither the wait nor the timeout's term from
    /// the largest round trip: a probe is judged only once the peer has
    /// sent nothing on its path for the cap, so a failure of this node's
    /// own direction is not found while the peer's traffic arrives.
    VerdictUncapped,
    /// Every frame but a path message holds a probe's verdict, heartbeats
    /// and other link control too, so on an idle link the peer's heartbeats
    /// delay finding a failure of this node's own direction.
    VerdictCountsControl,
    /// A Probing or Dead path whose padded probe went unanswered alternates
    /// the padded and the smallest size, as before the size ladder, so a
    /// path across a hop narrower than its link MTU proves no size.
    DiscoveryAlternates,
    /// The upward size search runs on a connection-oriented transport too,
    /// where an oversized probe closes the connection.
    SeekOnStreams,
    /// A size search probe goes in the path's ring as an ordinary probe,
    /// after the probe at its cadence, so its loss is a miss and an ETX loss
    /// sample.
    SeekCountsLoss,
    /// A discretionary change away from the active path on score reads the
    /// active path's score over the round-trip window only, as before, so
    /// load on the active path alone hands the link to an idle path slower
    /// at its best within seconds.
    MoveOnWindowScore,
    /// A discretionary change on score to a path faster at its best than
    /// the active path is held like any other, so after a mandatory move to
    /// a slower path that the load followed, the return waits until that
    /// path's idle round trips have left its horizon.
    MoveToFasterHeld,
    /// The return to a path a mandatory change left, Live again, needs the
    /// switch margin like any discretionary change on score, so after a
    /// real outage of a fast path under load the link stays on the slower
    /// path it fled to until that path's own loaded round trips fill its
    /// window.
    ReturnNeedsMargin,
    /// Nothing reads the size a path is proven to carry: the node seeds a
    /// peer's path MTU, folds the next hop's MTU and tightens sessions from
    /// the link MTU alone, so a path across a hop narrower than its link
    /// MTU is used at the link MTU and its large frames are lost, and the
    /// path machine counts such a path as carrying a `FilterAnnounce` by
    /// its link MTU.
    ProvenMtuUnused,
    /// A change of the active path's proven size reseeds the peer's path
    /// MTU under the never-loosen rule, so it only ever lowers it, and a
    /// path whose hop widens keeps the narrow size it proved first.
    ProvenMtuOnlyLowers,
    /// The size a path on a connection-oriented transport proves bounds the
    /// frames it carries, as on a connectionless one, though no search
    /// raises it there: a padded probe lost while the path is probed leaves
    /// the peer's path MTU entry, and whether the path carries a
    /// `FilterAnnounce`, at a smaller rung of the ladder for as long as the
    /// path is Live.
    ProvenMtuOnStreams,
    /// A path that carried the link and went silent is re-checked on the
    /// doubling cadence like any other, so after a silent outage it waits
    /// for the doubling's next slot, up to 30 s later, before it is found
    /// again.
    DeadRecheckDoubles,
    /// Heartbeat pacing reads `std::time::Instant` instead of the node's
    /// monotonic clock, which the link-dead check reads.
    HeartbeatsOnStdClock,
    /// The explorer's world reads its nodes' decrypt-worker results without
    /// waiting for the jobs dispatched before, so a round counts quiet with
    /// a frame still on a worker thread.
    WorldSkipsWorkerWait,
    /// The node tests' drain steps the test clock without waiting for the
    /// jobs dispatched to the nodes' decrypt workers, so it returns with a
    /// frame still on a worker thread.
    DrainSkipsWorkerWait,
    /// Choosing the active path ignores the medium a path runs over, as
    /// before the medium ranked paths, so a cable within the switch margin
    /// of a better-scoring Wi-Fi path never takes the link from it.
    MediumIgnored,
    /// A discretionary change on score to a path faster at its best than
    /// the active path is never held, even from a cable within the switch
    /// margin of it at their best, so load that follows the link hands it
    /// from the cable to a Wi-Fi path and the cable's medium takes it back
    /// one dwell later, over and over.
    LoadLeavesCable,
    /// A discretionary change for a faster known medium is never held, so
    /// load that follows the link onto a Wi-Fi path faster at its best than
    /// a cable outside the switch margin of it hands the link to the cable
    /// as soon as the Wi-Fi path's window score passes the cable's, and the
    /// Wi-Fi path takes it back once the load has followed, over and over.
    MediumMoveUnheld,
    /// A pending inbound link's stored msg2, once sent, answers any msg1
    /// from the link's address, not only the msg1 it was written for.
    StoredAnswersAny,
    /// A fresh same-epoch msg1 off the established link of a heard peering
    /// is refused as off the link while that link is reachable, and asks
    /// for a replacement on a link too young to rekey, as before redials
    /// were answered.
    OffLinkFreshRefused,
    /// The link machine records a redial msg1's ephemeral when it judges
    /// the msg1, so a redial the node then refuses has its resends refused
    /// as copies for as long as the link lives.
    RedialRecordsAtJudge,
    /// A redial is answered by tearing the held peering down at the msg1,
    /// and promoting the msg1 at once, as a replacement is.
    RedialTearsDownAtMsg1,
    /// A pending redial replaces the held peering as soon as its msg2 is
    /// sent, with no frame from the peer.
    RedialSwapsUnproven,
    /// A pending redial is never reaped at the handshake timeout.
    RedialNeverExpires,
    /// A second redial for an identity replaces its pending one however
    /// young that one is.
    RedialSlotIgnored,
    /// A redial's ephemeral is not remembered, so a capture is answered
    /// each time it is sent.
    RedialMemoryIgnored,
    /// A redial of a peering this node replaced within 15 s is answered
    /// anyway: the restart dampener is not consulted.
    RedialSkipsDampener,
    /// A fresh msg1 off the established link of a peering not yet heard
    /// from is answered into a redial, as one of a heard peering is, where
    /// it should be replaced at the msg1 (rule 3.3) or refused as off the
    /// link (rule 4.1) as before.
    RedialCoversUnheard,
    /// A frame that names a pending redial's index and fails to open is
    /// charged to the held peer as a decryption failure.
    RedialChargesHeld,
    /// A pending redial's entry survives the promotion of its link by a
    /// msg2 resend.
    RedialEntryKeptAtPromote,
    /// The swap removes the redialed peer as a replacement does, dropping
    /// its tree declaration, its filter and this node's filter state for it.
    RedialDropsIdentity,
    /// The swap does not open the end-to-end session again after closing a
    /// heard one.
    RedialNoSessionReopen,
    /// A redial is answered whatever the ACL says of its identity.
    RedialSkipsAcl,
    /// An operator disconnect of a held peer leaves its pending redial, so
    /// the redial's first frame promotes the peer again.
    RedialKeptAtDisconnect,
    /// A link rekey reads every msg2 under its attempt's index, however
    /// many it has refused, as before the cap: a party that saw the rekey's
    /// msg1 makes it read as many forged msg2s as it sends. The node half
    /// of the rekey machine's switch of the same name.
    CapIgnored,
    /// Past its budget of refused reads a link rekey drops a msg2 from the
    /// established link unread too, so a forger who spends the budget
    /// keeps the peer's genuine msg2 from completing the rekey. The node
    /// half of the rekey machine's switch of the same name.
    CapDropsOnLink,
    /// The settlement core's restart gates keep a memory entry for every
    /// identity they were ever asked about and never drop one, however
    /// long its stamp, replays and silence have lapsed.
    MemoryNeverDropped,
    /// A settlement core dial resend whose send failed stays due at the
    /// instant it was missed, so the core's next wake stays in the past and
    /// every poll until the dial's deadline asks for it again.
    UnsentStaysDue,
    /// A settlement core dial resend whose send failed is due only at the
    /// wake it reports, one tick on, not at the next poll, so a poll that
    /// falls before that instant does not try it again.
    UnsentDueAtWake,
    /// A settlement core dial whose last resend was sent takes a failed
    /// send reported after it as one more resend to try again.
    UnsentPastCap,
    /// The settlement core's msg1 resend waits double from the first
    /// interval, whatever multiplier the node is configured with, so a node
    /// configured with another multiplier would resend on another schedule
    /// than the one it runs today.
    BackoffDoubles,
    /// The settlement core ignores a dial's own resend cap, so a dial an
    /// mDNS advert directs at a node not configured to dial resends the
    /// configured count, where the node stops it at its discovery cap.
    OriginIgnored,
    /// The settlement core opens no link record for a dial on a connection
    /// still to be opened until its msg1, so the connection being opened is
    /// in no index and in use by nothing, where the node's link and index
    /// entry exist from the dial.
    ConnectingUnlinked,
    /// The settlement core says a move onto this node's own dial ends an
    /// operator's pin of the peer's path only when the link it left was
    /// this node's dial, where the node also ends it when the dial was made
    /// while the peer was held on that link (`own_dial || later_dial`).
    UnpinOwnOnly,
    /// The settlement core asks for a msg1's answer before it classifies
    /// the msg1, so a refused or rekey msg1 would cost a msg2 write and an
    /// index draw, as the answer built before the decision did.
    AnswerBeforeAdmit,
    /// The settlement core's max-peers cap counts no peer, so at the cap a
    /// msg1 from a new identity is answered and a dial to one installed,
    /// where the node drops the msg1 and refuses the promotion.
    CapNotCounted,
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
