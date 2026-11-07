//! Multipath paths: the paths a node holds to each peer, the rules for
//! holding them, and the machine that proves them.
//!
//! - `capable.rs`: [`Capability`], the capability probes of a link whose
//!   peer is not yet known to implement multipath, and their schedule.
//! - `candidate.rs`: [`Candidates`], the pairs the host's sources report
//!   for a link's peer, which of them are held back, and the order a full
//!   table replaces them in.
//! - `live.rs`: [`Liveness`], one path's outstanding probes, what their
//!   answers measured, and the frames received on it.
//! - `machine.rs`: [`Bundle`], the machine of one link's paths, driven by
//!   [`Input`]s and answering with [`Output`]s; [`Account`], what it did
//!   with one authentic frame; and [`Charge`], what it did with one frame
//!   that failed to authenticate.
//! - `params.rs`: [`Config`] and [`Params`], the settings of a link's path
//!   machine, validated, with the draft's values.
//! - `rules.rs`: path policy (draft Section 5.5), the checks on the
//!   transports a link's paths may run over, and a link's [`Scope`].
//! - `select.rs`: path selection (draft Section 5.7): a path's score, the
//!   tier of a transport's role, an operator's [`Pin`], the ranking of a
//!   link's Live paths for its active path, and the hold on the link's
//!   cost across a change of active path, this implementation's choice,
//!   since the draft leaves the link cost of a bundle to the node
//!   (Section 5.12, its note).
//! - `set.rs`: [`PathSet`], the paths to one peer, keyed by (transport,
//!   address), with the multipath v1 draft's limits, eviction order and
//!   address rules.
//! - `wire.rs`: the codec of the path messages, `PathProbe`, `PathAck` and
//!   `PathClose`.

#![deny(clippy::wildcard_enum_match_arm)]

use alloc::vec::Vec;

use crate::transport::{TransportAddr, TransportId};
use wire::{PathAck, PathClose, PathProbe};

mod candidate;
mod capable;
mod live;
mod machine;
mod params;
mod rules;
mod select;
mod set;
#[cfg(test)]
mod tests;
pub mod wire;

pub use candidate::{Candidates, Entry, Sources};
pub use capable::Capability;
pub use live::{Answer, Liveness, Sent};
pub use machine::{Account, Bundle, Charge, PathView, PinView, View};
pub use params::{
    Config, PATH_DEAD_PROBE_INTERVAL_MAX, PATH_DEAD_PROBE_INTERVAL_MIN, PATH_SILENCE_MAX, Params,
    ParamsError, RING,
};
pub use rules::{Rule, Scope};
pub use select::Pin;
pub use set::{
    Admission, Match, Medium, PATH_MAX_PER_PEER, PATH_MAX_PER_TRANSPORT, PathRefused, PathSet,
    PathState, PeerPath, Rebind, Roam,
};

/// One path, by its pair: a local transport and the peer's address on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathRef {
    /// The local transport.
    pub transport: TransportId,
    /// The peer's address on it.
    pub addr: TransportAddr,
}

/// The anonymity class of a transport (multipath v1 draft, Section 3): all
/// paths of a link run over transports of one class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// A transport that carries the node's addresses in the clear.
    Clear,
    /// Tor.
    Tor,
    /// Nym.
    Nym,
}

/// Whether a path runs over a local medium or faces the Internet (multipath
/// v1 draft, Section 5.5): by default a link's paths are all of its
/// original path's kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A local medium: a cable, a radio, or a local address.
    Local,
    /// An Internet-facing transport or address.
    Internet,
}

/// The operator's setting of a transport's part in a link's paths (draft
/// Section 5.5, the note on local policy). In choosing the active path a
/// `Normal` or `Preferred` transport's paths rank above a `Backup` one's,
/// and those above a path held on a `Never` transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Refused for new paths; a path held on it from before ranks last.
    Never,
    /// Used only while no `Normal` or `Preferred` path is Live, or while
    /// the operator's pin names it.
    Backup,
    /// The default.
    Normal,
    /// Preferred over others: its path carries the link whenever it is
    /// Live and scores within the switch margin of the best.
    Preferred,
}

/// Where a candidate came from (multipath v1 draft, Section 5.4, the
/// note). A source reports a pair again on every tick it still lists it,
/// and says when it no longer does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The node's configuration.
    Config,
    /// A Nostr advert of the peer's addresses.
    Nostr,
    /// Local discovery: a beacon heard on a transport.
    Discovery,
    /// An address the peer was heard from on no path.
    Heard,
    /// An operator's request naming the address: every report is fresh.
    Request,
}

/// What the machine needs to know about the host's transports. Every
/// answer is a fact the host already holds, from its configuration or the
/// transport's type; none needs I/O. The host answers for the peer whose
/// bundle it is stepping, and the machine reads the facts again at each
/// decision that needs them, so a change takes effect at the next one.
pub trait Facts {
    /// The link MTU of `transport` toward `addr`, in frame bytes.
    fn mtu(&self, transport: TransportId, addr: &TransportAddr) -> usize;
    /// The kind of `transport`, for the path limits.
    fn medium(&self, transport: TransportId) -> Medium;
    /// Whether `transport` is connection-oriented, as TCP, Tor, Nym and BLE
    /// are: a path to a candidate on it needs a connection opened before
    /// its first probe can go.
    fn oriented(&self, transport: TransportId) -> bool;
    /// The anonymity class of `transport` (draft Section 3).
    fn class(&self, transport: TransportId) -> Class;
    /// The kind of `transport`, when its medium or its setting fixes one;
    /// `None` when a path on it takes the kind of the peer's address.
    fn kind(&self, transport: TransportId) -> Option<Kind>;
    /// The operator's role for `transport`.
    fn role(&self, transport: TransportId) -> Role;
    /// Whether this node would accept the peer's handshake initiation on
    /// `transport`.
    fn accepts(&self, transport: TransportId) -> bool;
    /// Whether this node would initiate a handshake to the peer on
    /// `transport`. For a peer the node already holds a link with, a
    /// setting that only stops it dialling newly discovered nodes does not
    /// make this false.
    fn dials(&self, transport: TransportId) -> bool;
}

/// What a call needs from the shell.
pub struct Env<'e> {
    /// The facts about the host's transports.
    pub facts: &'e dyn Facts,
    /// The link's cost as the host measures it now, with no hold applied:
    /// what [`Bundle::cost`] returns while no hold is in force, and what a
    /// change of active path holds when none is.
    pub cost: f64,
}

/// One input to [`Bundle::step`].
///
/// A path message arrives here only after the frame carrying it has
/// authenticated under the link's keys and passed the replay check (draft
/// Section 7.1), and only once it has decoded; a message that fails to
/// decode is dropped by the shell unanswered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    /// Nothing arrived: run the timers, and offer again for admission
    /// each held candidate a rule refused at its last attempt, so a change
    /// in the facts takes effect; a refusal is reported only when the
    /// refusing rule differs from the one last reported for it. A poll
    /// before [`Bundle::next_wake`], with the facts unchanged, does
    /// nothing.
    Poll,
    /// `source` reports that the peer may be reachable at (`transport`,
    /// `addr`). The bundle holds the pair as a candidate whatever the
    /// peer's capability and path policy. A report from a source that
    /// already lists the pair is a repeat and changes nothing but its
    /// recency, so a source may report every pair it lists on every tick.
    Candidate {
        /// The local transport.
        transport: TransportId,
        /// The peer's address on it.
        addr: TransportAddr,
        /// The source reporting it.
        source: Source,
    },
    /// `source` no longer lists (`transport`, `addr`): its next report of
    /// the pair is fresh. A pair no source lists is forgotten, unless it
    /// is held back.
    Unlisted {
        /// The local transport.
        transport: TransportId,
        /// The peer's address on it.
        addr: TransportAddr,
        /// The source that listed it.
        source: Source,
    },
    /// A `PathProbe` arrived on `transport` from `addr`.
    ///
    /// The ack's `rx_frames` and `rx_bytes` count the probe's own frame
    /// (draft Section 7.3), so the shell passes the frame carrying it to
    /// [`Bundle::account`] first, with the whole FMP frame's length, and
    /// steps the decoded probe after.
    Probe {
        /// The arrival transport.
        transport: TransportId,
        /// The source address.
        addr: TransportAddr,
        /// The decoded probe, with its length as received.
        msg: PathProbe,
    },
    /// A `PathAck` arrived on `transport` from `addr`.
    Ack {
        /// The arrival transport.
        transport: TransportId,
        /// The source address.
        addr: TransportAddr,
        /// The decoded ack, with its length as received.
        msg: PathAck,
    },
    /// A `PathClose` arrived on `transport` from `addr`.
    Close {
        /// The arrival transport.
        transport: TransportId,
        /// The source address.
        addr: TransportAddr,
        /// The decoded close.
        msg: PathClose,
    },
    /// The local transport `transport` lost carrier (`up` false) or
    /// regained it (`up` true).
    Carrier {
        /// The local transport.
        transport: TransportId,
        /// Whether it has carrier now.
        up: bool,
    },
    /// A send on (`transport`, `addr`) failed because the address is
    /// unreachable.
    SendFailed {
        /// The local transport.
        transport: TransportId,
        /// The peer's address on it.
        addr: TransportAddr,
    },
    /// The interface the local transport `transport` is bound to left
    /// (`present` false) or came back (`present` true). Leaving discards
    /// the transport's paths and lifts a pin of it as its removal does,
    /// but holds back its candidates, the discarded pairs among them;
    /// coming back is its carrier's return.
    Present {
        /// The local transport.
        transport: TransportId,
        /// Whether its interface is present now.
        present: bool,
    },
    /// The local transport `transport` was removed: every path on it is
    /// discarded, every candidate on it forgotten, and a pin of it lifted.
    Removed {
        /// The local transport.
        transport: TransportId,
    },
    /// The connection [`Output::Connect`] asked for to (`transport`,
    /// `addr`) settled: opened (`ok` true) or failed (`ok` false).
    Connected {
        /// The local transport.
        transport: TransportId,
        /// The peer's address on it.
        addr: TransportAddr,
        /// Whether the connection opened.
        ok: bool,
    },
    /// The operator pins the link to `transport`: to its path at `addr`,
    /// or with `addr` `None` to whichever of its paths the usual rules
    /// rank first. The pin replaces any before it, and is kept even while
    /// nothing it names is held, until `Input::Unpin`, its transport's
    /// removal or a new bundle ([`Pin`]).
    Pin {
        /// The local transport.
        transport: TransportId,
        /// The peer's address on it, or `None` for any path on it.
        addr: Option<TransportAddr>,
    },
    /// The operator lifts the pin, if any: the usual rules choose the
    /// active path from the next selection on, a change by the margin
    /// after the switch dwell. The host steps it too where the peer is
    /// replaced and the link kept: at a restart this node learns of during
    /// its own rekey.
    Unpin,
    /// A `ReceiverReport` arrived on the link. While a hold on the link's
    /// cost is in force ([`Bundle::cost`]), it counts toward the reports
    /// the hold waits for; otherwise it changes nothing. A report stepped
    /// in the step that changes the active path came with the change, so
    /// it counts toward the hold before it, if any, and not the new one.
    Report,
    /// An unauthenticated beacon was heard from (`transport`, `addr`).
    /// A path held there that is Probing and was never acked has its next
    /// probe, or the connection it needs first, brought forward to now:
    /// once each time it enters Probing, only while none of its probes is
    /// outstanding and the next is not already due, and with the probe
    /// counted toward `MAX_DISCOVERY_PROBES` and held to the floor of a
    /// path that has stopped answering, as one on its own cadence is.
    /// Nothing else changes: no state, no candidate, no capability.
    Beacon {
        /// The local transport.
        transport: TransportId,
        /// The beacon's source address on it.
        addr: TransportAddr,
    },
}

/// Why a path changed state, for the shell's log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// A candidate of the peer was admitted.
    Candidate,
    /// The peer's probe created the path or brought it back from Dead.
    Probed,
    /// One of our probes on the path was answered.
    Answered,
    /// The peer closed the path.
    Closed,
    /// `PATH_TIMEOUT_K` probes in a row went unanswered on a Live path.
    Timeout,
    /// `PATH_SUSPECT_RETIRE` probes in a row went unanswered on a Suspect
    /// path.
    Retired,
    /// `MAX_DISCOVERY_PROBES` probes in a row went unanswered on a Probing
    /// path.
    Exhausted,
    /// The path's transport lost carrier.
    Carrier,
    /// A send on the path failed because the address is unreachable.
    Unreachable,
    /// The path's transport regained carrier.
    Returned,
    /// The path's pair was reported afresh as a candidate, or local
    /// discovery found the peer again on its transport.
    Found,
    /// The path had been Dead for `PATH_DEAD_GRACE`, and was never acked
    /// or a path of the link is Live.
    Grace,
    /// The path was discarded to make room for a new one.
    Evicted,
    /// The path's local transport was removed, or its interface left.
    Removed,
    /// `AUTH_FAIL_LIMIT` frames in a row failed to authenticate on the
    /// path while another path was Live or acked Suspect.
    AuthLimit,
    /// `MAX_DISCOVERY_PROBES` connections in a row to a Probing path's
    /// address failed to open, each counted as an unanswered probe.
    Connect,
    /// The link started again at the pair FMP v1 moved it to: every path
    /// of the old link ends, and the new link's original path begins.
    Renewed,
}

/// Why the machine changed the active path, for the shell's log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Switch {
    /// The active path became Suspect or Dead and another path is better
    /// placed to carry the link (draft Section 5.7).
    Mandatory,
    /// The active path was discarded and another took its place.
    Handover,
    /// The active path is Live, and another Live path is on a transport
    /// of a higher tier, which moves the link at once, or, throughout the
    /// switch dwell, could carry a `FilterAnnounce` where the active path
    /// cannot, was preferred where it is not, or scored better by the
    /// switch margin (draft Section 5.7 and its note, and Section 5.11).
    Discretionary,
    /// The operator's pin names a Live path, and not the active one, which
    /// moves the link at once (draft Section 5.7).
    Pinned,
}

/// Why the machine took no action on an input, for the shell's log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A probe shorter than the smallest a node answers.
    Short,
    /// The path limits are full and no Dead path may be discarded.
    Full,
    /// An ack that answers no outstanding probe of ours.
    Unmatched,
    /// A close naming a path we do not hold.
    Unknown,
    /// Path policy refuses a probe to the pair, a path created at it or a
    /// path moved to it (draft Section 5.5), by the rule given.
    Rule(Rule),
    /// The candidate table is full and no entry may be replaced: the
    /// report is dropped.
    Table,
}

/// One thing the shell must do or record. `D` is the driver slot.
#[derive(Debug)]
pub enum Output<D> {
    /// Send the encoded path message `bytes`, padded, on the path `to`.
    Send {
        /// The path.
        to: PathRef,
        /// The link message, from its type byte.
        bytes: Vec<u8>,
    },
    /// A path's address moved from `from` to `to`. `driver` is the slot it
    /// held, which may still aim at the old address; the path now holds a
    /// fresh one.
    Moved {
        /// The pair the path left.
        from: PathRef,
        /// The pair it holds now.
        to: PathRef,
        /// Its old slot.
        driver: D,
    },
    /// The path `to` is gone: dispose of its driver slot, unless `keep`
    /// says the peer still sends on it (draft Section 5.8).
    Released {
        /// The path.
        to: PathRef,
        /// Its slot.
        driver: D,
        /// Whether a connection the slot holds stays open: the path is the
        /// peer's active path, so the peer still sends on it, or the peer
        /// has not shown it implements multipath, so FMP v1 governs the
        /// link and keeps every connection (draft Sections 5.8 and 9.2).
        keep: bool,
    },
    /// A path changed state. `None` stands for no path: `from: None` for a
    /// path just created, `next: None` for one discarded.
    State {
        /// The path.
        to: PathRef,
        /// Our identifier for it.
        path_id: u32,
        /// Its state before.
        from: Option<PathState>,
        /// Its state now.
        next: Option<PathState>,
        /// Why.
        why: Why,
    },
    /// The peer has shown it implements multipath; from now on the machine
    /// may send it path messages.
    Capable,
    /// The first round of capability probes went unanswered: the link is
    /// held not capable (draft Section 5.2). Capability probes go on at the
    /// backoff while a candidate allows them, and an answer or any path
    /// message still makes the peer capable.
    NotCapable,
    /// An input changed nothing, for the reason given.
    Refused {
        /// The pair the input concerned.
        to: PathRef,
        /// Why.
        why: Refusal,
    },
    /// Our frames now go out on the path `to`: send every link message
    /// other than path messages there. `from` is the path they went out on
    /// before, or `None` when it was discarded.
    Switched {
        /// The path active before, if it is still held.
        from: Option<PathRef>,
        /// The path active now.
        to: PathRef,
        /// Why.
        why: Switch,
    },
    /// No original or acked path is left: remove the peer, as a link of one
    /// path is removed when its transport goes, and close the bundle. The
    /// bundle answers nothing after this.
    Orphaned,
    /// Open a connection to the path `to` on its connection-oriented
    /// transport, with no handshake on it, and step [`Input::Connected`]
    /// when it settles. The path is probed only once it has opened.
    Connect {
        /// The path.
        to: PathRef,
    },
}

/// The outputs of one call, executed by the shell front to back.
pub type Outputs<D> = Vec<Output<D>>;
