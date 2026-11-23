//! Test-only switches of the XX flow, each of which turns one guard off.
//!
//! Every guard of the flow sits behind one condition, read as
//! `xx_fault!(Name) || node_fault!(Name)`, and each has a switch here that
//! removes it in a shape a real defect would take. A test that a switch
//! names (`tests/faults.rs`) must fail with the switch on and pass with
//! none. Each switch is also a variant of the node's list
//! (`crate::faults`), so the mutation lane breaks it by `FIPS_NODE_FAULTS`.
//!
//! The set is read once per process from the `FIPS_SETTLE_XX_FAULTS`
//! environment variable, a comma-separated list of variant names, as the
//! settlement core's switches are read from theirs. Outside test builds the
//! `xx_fault!` macro is the literal `false` and this module is not
//! compiled.

use std::sync::OnceLock;
use std::vec::Vec;

/// The environment variable that names the switches a test process runs
/// with.
pub(crate) const VAR: &str = "FIPS_SETTLE_XX_FAULTS";

/// One guard of the XX flow switched off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    /// An anonymous answer's leg names the peer held on the link at the
    /// msg1's source, as an IK answer names the msg1's identity, so the
    /// table's send rule takes it for that peer's answer.
    AnonLegNamed,
    /// The admission cap stops counting an anonymous answer once its msg2
    /// is sent, though the answer waits for its msg3.
    PendingFreesSentAnswers,
    /// A msg2 completes under the identity its dial named, as an IK dial's
    /// does, so an anonymous dial never completes.
    AnonDialNamed,
    /// A msg2 beside this node's own dial goes to address order and sends
    /// its msg3.
    BesideOwnSendsFinal,
    /// A msg2's decision runs before the outcome of its msg3 send.
    FinalBeforeSendOutcome,
    /// The smaller node's move onto its dial at msg2 closes the dial's own
    /// connection when the msg2 came from another pair, as the table's move
    /// does, where next leaves it open.
    MoveClosesDial,
    /// A dial past its deadline is reaped with no retry, where next's
    /// handshake timeout retries the identity it expects.
    TimeoutNoRetry,
    /// An identified dial whose connection could not be opened asks for no
    /// retry, where next retries the identity it named.
    ConnectFailNoRetry,
    /// A leaf's refusal of a second peer leaves the dial's or answer's leg
    /// for its reap, as the max-peers cap does.
    LeafKeepsLink,
    /// The max-peers cap's refusal at msg3 leaves the answer's leg for its
    /// reap, as the cap at msg2 leaves a dial's, where next's inbound
    /// promote failure removes the answer's link at once.
    CapKeepsAnswer,
    /// A msg3 at a new epoch restarts the held peer with no gate, while the
    /// peering is still heard or the dampener holds.
    Msg3RestartUngated,
    /// A msg3 that claims a session not held replaces the held peer, where
    /// next repeats the stored msg2.
    MismatchClaimTearsDown,
    /// A msg3 that claims the session held is read as a crossing, before
    /// the claim.
    MatchesReadAsCross,
    /// The silent-session refusal at msg3 refuses an identity at any epoch,
    /// not only the epoch its silent sessions counted.
    SilentRefusalAnyEpoch,
    /// A session this node dialed that ends before the peer's first frame
    /// counts toward the peer's silent-session back-off, as one the peer
    /// dialed does.
    OwnDialCountsSilent,
    /// A msg2 the address order settles keeps the peer where it is at the
    /// smaller node, as at the larger, where next moves the smaller node
    /// onto its dial.
    CrossedRunsKeep,
    /// The larger node of a crossing settled at the peer's msg3 takes the
    /// answer's session on the link it dialed and stays held there, and the
    /// answer's link is the one retired.
    Msg3MoveKeepsHeldLink,
    /// A msg3 with no claim from a peer held on a link the peer dialed is
    /// settled by address order, as a crossing is, so the smaller node
    /// keeps the old link, where the same-side rule moves it onto the new
    /// session.
    SameSideByOrder,
    /// The larger node holding the peer on a link it dialed, whose later
    /// dial address order keeps, still sends that dial's msg3, where the
    /// same-side rule withholds it and ends the dial.
    SameSideFinalSent,
    /// A move keeps the frame heard under the session it leaves, where
    /// next's `heard_on_session` starts afresh, so a dial in flight at the
    /// move is no longer beside this node's own unheard dial and sends its
    /// msg3.
    MoveKeepsFramed,
}

impl Fault {
    /// Every switch, for the name lookup and the meta-test.
    pub(crate) const ALL: &'static [Fault] = &[
        Self::AnonLegNamed,
        Self::PendingFreesSentAnswers,
        Self::AnonDialNamed,
        Self::BesideOwnSendsFinal,
        Self::FinalBeforeSendOutcome,
        Self::MoveClosesDial,
        Self::TimeoutNoRetry,
        Self::ConnectFailNoRetry,
        Self::LeafKeepsLink,
        Self::CapKeepsAnswer,
        Self::Msg3RestartUngated,
        Self::MismatchClaimTearsDown,
        Self::MatchesReadAsCross,
        Self::SilentRefusalAnyEpoch,
        Self::OwnDialCountsSilent,
        Self::CrossedRunsKeep,
        Self::Msg3MoveKeepsHeldLink,
        Self::SameSideByOrder,
        Self::SameSideFinalSent,
        Self::MoveKeepsFramed,
    ];

    /// The switch whose variant name is `name`.
    pub(crate) fn named(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|f| std::format!("{f:?}") == name)
    }
}

/// The switches this process runs with.
fn set() -> &'static [Fault] {
    static SET: OnceLock<Vec<Fault>> = OnceLock::new();
    SET.get_or_init(|| {
        let names = std::env::var(VAR).unwrap_or_default();
        names
            .split(',')
            .filter(|n| !n.is_empty())
            .map(|n| Fault::named(n).unwrap_or_else(|| panic!("{VAR} names no switch {n:?}")))
            .collect()
    })
}

/// Whether `fault` is on in this process.
pub(crate) fn on(fault: Fault) -> bool {
    set().contains(&fault)
}
