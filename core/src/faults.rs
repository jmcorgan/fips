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
//! `node_fault!(Name)`, defined once in each crate's root: in test builds
//! and under the `test-hooks` feature it asks [`on`], and in any other build
//! it is the literal `false`, so a normal or release build compiles the
//! branch away. This crate's sites see the module in its own test builds
//! and under its `test-hooks` feature, and the root crate's sites through
//! that feature alone. The root enables it from its `[dev-dependencies]`,
//! so this crate's sites are live in the root's tests and in the integration
//! image, and from its own `test-hooks` feature, which also turns the root's
//! `node_fault!` sites on, for the chaos break image: a chaos run can then
//! start its nodes with a switch set and see the chaos assertions red. No
//! package build enables either.
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
    /// The settlement core's decision for a msg2 completing beside a held
    /// peer ignores that the link the peer is held on was this node's own
    /// dial, so only the tie-break decides between moving and keeping.
    IgnoreOwnDial,
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
    /// The BLE scan loop's retry tick never prunes its memory of the PSMs
    /// link addresses advertised.
    BleRetryTickSkipsPrune,
    /// The BLE scan loop's retry tick prunes that memory as though no
    /// address were pooled or in the retry book.
    BleRetryTickPrunesLive,
    /// A queueing transport puts path messages in the connection's data
    /// queue, behind the data and refused when it is full, instead of in
    /// their own queue, which its writer drains first.
    PathLaneShared,
    /// The settlement core takes a restarted peer's epoch only at the
    /// cutover that reports the restart, not at the rekey msg2 that revealed
    /// it, where the peer's rekey takes it: a msg1 at the new epoch in
    /// between is a restart to the core and a rekey to the peer's machine.
    EpochAtCutover,
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
    /// an own-dial restart with no reconnect, though the node notes each
    /// loss for one before the new session is promoted.
    RestartNoRetry,
    /// The settlement core removes a peer a redial's swap replaces with no
    /// reconnect, though the node notes the loss for one before the
    /// redial's leg is promoted.
    RedialNoRetry,
    /// The settlement core installs the peer a redial's swap promotes
    /// heard at the swap, forgetting its replay memory and silent sessions
    /// there, where the node promotes the redial's leg unheard, noting its
    /// ephemeral, and hears it at the proving frame's own entry, a later
    /// one under decrypt workers.
    RedialSwapHeard,
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
    /// The settlement core's move retires the link it leaves before the
    /// moved-onto link's record holds the msg2's pair, so it closes the
    /// connection the peering moved onto.
    MoveClosesNewPair,
    /// A move onto this node's dial at a pair other than the dial's own
    /// leaves the connection the dial was set up at open, though no path and
    /// no handshake uses it, in the settlement core and in the node.
    MoveLeavesDialOpen,
    /// The settlement core leaves the record of a link this node dialed as
    /// its dial when the peer adopts a rekey answer that went out on the
    /// connection its msg1 arrived on, the link's own connection having
    /// gone, so the node keeps the link `Outbound` while the peer, which
    /// opened that connection, holds it as one it dialed.
    AdoptedKeepsDir,
    /// Closing a link takes the index's entry at each pair it was named at
    /// from any other link that uses the pair, as the written index did.
    ShadowLosesEntry,
    /// Abandoning a dial takes the index's entry at the dial's pair from
    /// whichever link it named, as the written index did.
    ForgetTakesKey,
    /// The node's test-only resync of its link records writes nothing, so a
    /// link, an index entry or a peer a test planted past the writers has no
    /// record the msg1 predicates can read.
    ResyncSkipped,
    /// A pair several links use names the link opened first, not the one
    /// opened last.
    IndexOldestWins,
    /// Applying a bundle's report to a link's record leaves the index as it
    /// was, so a path the record gains or loses is not reflected in it.
    IndexNotRebuilt,
    /// A one-path roam or a bind, which the bundle reports in no output, is
    /// not told to the core, so the link's record keeps the old pair.
    RoamNotFed,
    /// A frame that roams a link's one path while it is not the active
    /// path tells the settlement core's record nothing of the pair it left,
    /// so the record gains the new pair and keeps the old.
    StandbyRoamUnfed,
    /// An anonymous beacon at any pair the link index names is not dialled,
    /// whatever holds the link there, so a beacon at a proven path of a
    /// held peer silent past its liveness is skipped too.
    BeaconSkipsAnyIndexed,
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
    /// The heartbeat check never finds a peer's link dead, however long the
    /// peer has been silent, so a silent peer stays held: nothing ends a
    /// pair split across two sessions, and the redial that follows
    /// link-dead never comes.
    LinkDeadNever,
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
    /// A pending redial's entry survives the promotion of its link by a
    /// msg2 resend.
    RedialEntryKeptAtPromote,
    /// An operator disconnect of a held peer leaves its pending redial, so
    /// the redial's first frame promotes the peer again. Read by the node
    /// and by the settlement core, whose disconnect abandons the pending
    /// redial as the node drops it.
    RedialKeptAtDisconnect,
    /// A redial proven by a frame from another transport than the
    /// redial's, at a pair of the held link, replaces the peering on the
    /// redial's link, as any proof does, rather than moving the held link
    /// onto the redial's session: the node then sends on the connection a
    /// peer that kept its address has left. Read by the settlement core.
    RedialProofLeavesHeldLink,
    /// A redial the ACL passed and no session index could be drawn for
    /// leaves no mark in the redial memory, so its resends and the
    /// ephemerals after it are judged as if it never arrived. Read by the
    /// settlement core at the shell's abandon of the redial's ask.
    AuthorizedRedialUnnoted,
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
    /// The settlement core sends a dial's first msg1 resend one configured
    /// resend interval after the msg1, where the node sends it a second
    /// after, whatever the interval, so a node configured with another
    /// interval would send its first resend at another instant.
    FirstResendAtInterval,
    /// The settlement core ignores a dial's own resend cap, so a dial an
    /// mDNS advert directs at a node not configured to dial resends the
    /// configured count, where the node stops it at its discovery cap.
    OriginIgnored,
    /// The settlement core opens no link record for a dial on a connection
    /// still to be opened until its msg1, so the connection being opened is
    /// in no index and in use by nothing, where the node's link and index
    /// entry exist from the dial.
    ConnectingUnlinked,
    /// The settlement core closes the pair a dial still connecting dialed
    /// when the dial is given up, where the node closes nothing for a dial
    /// it gives up before its msg1.
    ConnectingCloses,
    /// The settlement core closes the msg1's pair when it gives up an
    /// answer whose msg2 could not be sent at all, where the node forgets
    /// the link and closes nothing.
    UnsendableCloses,
    /// The settlement core gives up a redial's answer whose msg2 could not
    /// be sent and keeps the identity's pending redial on its retired link,
    /// where the node forgets the redial with the leg's machine.
    UnsendableKeepsRedial,
    /// The settlement core closes a torn-down link's paths by its records
    /// alone, not by its bundle's keep, where the node closes, on a capable
    /// link, each path other than the one the peer sends on, and on any
    /// other none.
    TeardownIgnoresKeep,
    /// The settlement core says a move onto this node's own dial ends an
    /// operator's pin of the peer's path only when the link it left was
    /// this node's dial, where the node also ends it when the dial was made
    /// while the peer was held on that link (`own_dial || later_dial`).
    UnpinOwnOnly,
    /// The settlement core's frame on a peering heard already, by this
    /// node's own dial or a move, forgets the replay memory an earlier
    /// unheard peering left, where the node forgets it only at the frame or
    /// move that makes the peering heard.
    FrameForgetsReplays,
    /// The settlement core counts a removed session toward the identity's
    /// silent-session back-off only when the peering was unheard, so a
    /// session of this node's own dial that ends before the peer's first
    /// frame is not counted, where the node counts every session that
    /// carried no frame.
    SilentReadsHeard,
    /// The settlement core resets a peer, as at a roam, when its link's one
    /// path roams while it is not the active path, where the node moves the
    /// path and resets nothing.
    StandbyRoamResets,
    /// The settlement core asks for a msg1's answer before it classifies
    /// the msg1, so a refused or rekey msg1 would cost a msg2 write and an
    /// index draw, as the answer built before the decision did.
    AnswerBeforeAdmit,
    /// The settlement core's max-peers cap counts no peer, so at the cap a
    /// msg1 from a new identity is answered and a dial to one installed,
    /// where the node drops the msg1 and refuses the promotion.
    CapNotCounted,
    /// The settlement core's restart gates judge a new epoch in the msg2 of
    /// this node's own dial as they judge a msg1 restart, by the floors and
    /// the dampener, where the node accepts it as the reply to its own
    /// msg1. The node half of the gates' switch of the same name.
    OutboundGated,
    /// The settlement core's restart interval is 10 s, so the dampener
    /// accepts a second restart 12 s after the first, which the node
    /// refuses. The node half of the core parameters' switch of the same
    /// name.
    IntervalTen,
    /// The XX flow (`proto/fmp/flow`): an anonymous answer's leg names the
    /// peer held on the link at the msg1's source, so the table's send rule
    /// takes it for that peer's answer.
    AnonLegNamed,
    /// The XX flow: the admission cap stops counting an anonymous answer
    /// once its msg2 is sent, though the answer waits for its msg3.
    PendingFreesSentAnswers,
    /// The XX flow: a msg2 completes under the identity its dial named, so
    /// an anonymous dial never completes.
    AnonDialNamed,
    /// The XX flow: a msg2 beside this node's own dial goes to address order
    /// and sends its msg3.
    BesideOwnSendsFinal,
    /// The XX flow: a msg2's decision runs before the outcome of its msg3
    /// send.
    FinalBeforeSendOutcome,
    /// The XX flow: the smaller node's move at msg2 closes the dial's own
    /// connection when the msg2 came from another pair.
    MoveClosesDial,
    /// The XX flow: a dial past its deadline is reaped with no retry.
    TimeoutNoRetry,
    /// The XX flow: an identified dial whose connection could not be opened
    /// asks for no retry.
    ConnectFailNoRetry,
    /// The XX flow: a leaf's refusal of a second peer leaves the leg for its
    /// reap.
    LeafKeepsLink,
    /// The XX flow: the max-peers cap's refusal at msg3 leaves the answer's
    /// leg for its reap.
    CapKeepsAnswer,
    /// The XX flow: a msg3 at a new epoch restarts the held peer with no
    /// gate.
    Msg3RestartUngated,
    /// The XX flow: a msg3 that claims a session not held replaces the held
    /// peer, where next repeats the stored msg2.
    MismatchClaimTearsDown,
    /// The XX flow: a msg3 that claims the session held is read as a
    /// crossing.
    MatchesReadAsCross,
    /// The XX flow: the silent-session refusal at msg3 refuses an identity
    /// at any epoch.
    SilentRefusalAnyEpoch,
    /// The XX flow and the node: a session this node dialed that ends before
    /// the peer's first frame counts toward the peer's silent-session
    /// back-off.
    OwnDialCountsSilent,
    /// The node: the ACL's refusal at an answer's msg3 leaves open the
    /// inbound connection the handshake ran on, though no other link uses
    /// it.
    AclRefusalKeepsConnection,
    /// The node: a msg1 refused for want of a session index leaves open the
    /// inbound connection it came over, though no other link uses it.
    IndexRefusalKeepsConnection,
    /// The node: a dial refused at the peer cap at its msg2 leaves its
    /// connection open until the leg is reaped, though no other link uses
    /// it.
    CapRefusalKeepsConnection,
    /// The node: an answer refused at the peer cap at its msg3 leaves open
    /// the inbound connection the handshake ran on, though no other link
    /// uses it.
    CapMsg3KeepsConnection,
    /// The node: a leaf's refusal of a second peer at an answer's msg3
    /// leaves open the inbound connection the handshake ran on, though no
    /// other link uses it.
    LeafMsg3KeepsConnection,
    /// The node: a leaf's refusal of a second peer at its own dial's msg2
    /// leaves the dial's connection open, though no other link uses it.
    LeafMsg2KeepsConnection,
    /// The XX flow and the node: the larger node of a crossing settled at
    /// the peer's msg3 takes the inbound leg's session on the link it
    /// dialed and stays held there, and the leg's link is the one retired.
    Msg3MoveKeepsHeldLink,
    /// The node: the smaller node of a crossing settled at the peer's msg3
    /// keeps its own dial and leaves the inbound leg's connection open,
    /// though no other link uses it.
    Msg3KeepLeavesLegOpen,
    /// The XX flow and the node: a msg3 with no claim from a peer held on a
    /// link the peer dialed is settled by address order, so the smaller
    /// node keeps the old link while the peer has left it.
    SameSideByOrder,
    /// The XX flow and the node: the larger node holding the peer on a link
    /// it dialed sends the msg3 of a later dial that address order keeps,
    /// so the peer moves onto a link the larger node drops.
    SameSideFinalSent,
    /// The XX flow and the node: a move keeps the frame heard under the
    /// session it leaves, so a dial in flight at the move is no longer
    /// beside the node's own unheard dial and sends its msg3.
    MoveKeepsFramed,
    /// The node: a later dial ended at its msg2 with no msg3, before the
    /// peer was heard under the session held, does not resend the msg3 of
    /// the dial that installed it, so a lost one leaves the peer holding
    /// nothing until the link-dead timeout.
    WithheldMsg3NotResent,
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
