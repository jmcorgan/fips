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
    /// The admission cap counts an anonymous answer whose msg2 was sent, as
    /// the IK flow counts every answer leg.
    PendingCountsSentAnswers,
    /// A msg2 completes under the identity its dial named, as an IK dial's
    /// does, so an anonymous dial never completes.
    AnonDialNamed,
    /// A msg2 beside this node's own dial goes to address order and sends
    /// its msg3.
    BesideOwnSendsFinal,
    /// A msg2's decision runs before the outcome of its msg3 send.
    FinalBeforeSendOutcome,
    /// A leaf's refusal of a second peer leaves the dial's or answer's leg
    /// for its reap, as the max-peers cap does.
    LeafKeepsLink,
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
}

impl Fault {
    /// Every switch, for the name lookup and the meta-test.
    pub(crate) const ALL: &'static [Fault] = &[
        Self::AnonLegNamed,
        Self::PendingCountsSentAnswers,
        Self::AnonDialNamed,
        Self::BesideOwnSendsFinal,
        Self::FinalBeforeSendOutcome,
        Self::LeafKeepsLink,
        Self::Msg3RestartUngated,
        Self::MismatchClaimTearsDown,
        Self::MatchesReadAsCross,
        Self::SilentRefusalAnyEpoch,
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
