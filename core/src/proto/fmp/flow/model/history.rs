//! The abstract history the XX judge reads: what one node saw of one peer
//! identity, in order.
//!
//! Nothing here is a wire value. A handshake is named by its msg1's
//! ephemeral ([`Hs`]), which both ends know. An XX msg1 carries no
//! identity (FRC-2201 Section 5.2), so the node cannot tell whose it is
//! until the msg3 authenticates the initiator; the history is written by
//! whoever knows, and puts a msg1 in the history of the identity whose
//! handshake it opened. The judge reads a msg1 only as a node can: by its
//! source address and its handshake.

/// Milliseconds on the node's monotonic clock.
pub type Ms = u64;

/// A node's address, compared as FRC-2201 Section 5.7 orders node
/// addresses. Only the order matters to the judge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Node(pub u8);

/// A transport address on one transport: the `(transport, address)` pair a
/// link is set up at and a connection is held at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Addr {
    /// The transport.
    pub transport: u8,
    /// The address on that transport.
    pub at: u16,
}

/// A handshake attempt, named by the ephemeral of its msg1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hs(pub u32);

/// A peer's startup epoch (FRC-2201 Section 5.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Epoch(pub u32);

/// A link as this node numbers it. Every handshake that is not a rekey
/// sets up a link of its own (FRC-2201 Section 5.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkId(pub u32);

/// Whether a link's transport holds a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    /// No connection.
    Connectionless,
    /// A connection per link, closed when no remaining link uses it.
    Connected,
}

/// The identity a dial names (FRC-2201 Section 5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Named {
    /// The dial names the identity this history is of.
    Peer,
    /// The dial names another identity, so this peer's msg2 fails the
    /// identity check of Section 5.3.
    Other,
    /// The dial names no identity, as one to a node found by local peer
    /// discovery: whoever answers is accepted.
    Anyone,
}

/// The rekey declaration a msg3 carries (FRC-2201 Section 7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Claim {
    /// No declaration: not a rekey.
    None,
    /// A declaration naming the session index this node holds for the
    /// peer.
    Held,
    /// A declaration naming another session index.
    Other,
}

/// One input to the node, in history order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// The clock moves forward by this much.
    Advance(Ms),
    /// This node starts its own initial handshake `hs` on a new link
    /// `link` to `to`, naming `named`.
    Dial {
        /// The handshake the dial starts.
        hs: Hs,
        /// The new link this node opens for it.
        link: LinkId,
        /// The address dialed.
        to: Addr,
        /// The link's binding.
        binding: Binding,
        /// The identity the dial names.
        named: Named,
    },
    /// This node reads a msg1 of handshake `hs` from `from`, admitted. A
    /// msg1 that opens a handshake gets the new link `link`; a duplicate
    /// gets none, and its `link` is not read.
    Msg1 {
        /// The handshake.
        hs: Hs,
        /// The link it would set up.
        link: LinkId,
        /// Its source address.
        from: Addr,
        /// The link's binding.
        binding: Binding,
    },
    /// The msg2 of this node's own initial handshake `hs` arrives and
    /// authenticates the peer's static, carrying `epoch`. A handshake
    /// message never moves the peer's address (Section 6.5), so its source
    /// is not read.
    /// `refused` says whether this node's peering decision or its
    /// negotiation verdict refuses it (Sections 5.2 and 5.8.4).
    Msg2 {
        /// The handshake it completes.
        hs: Hs,
        /// The epoch it carries.
        epoch: Epoch,
        /// The peering decision or the negotiation verdict refuses it.
        refused: bool,
    },
    /// The msg3 of the peer's handshake `hs`, which this node answered,
    /// arrives and authenticates, carrying `epoch` and `claim`. `refused` says whether the attribution check, the peering
    /// decision or the negotiation verdict refuses it (Section 5.7, "The
    /// order of checks").
    Msg3 {
        /// The handshake it completes.
        hs: Hs,
        /// The epoch it carries.
        epoch: Epoch,
        /// Its rekey declaration.
        claim: Claim,
        /// A check before classification refuses it.
        refused: bool,
    },
    /// A frame from the peer authenticates under the session of handshake
    /// `hs`, from `from`.
    Frame {
        /// The handshake whose session the frame authenticated under.
        hs: Hs,
        /// Its source address.
        from: Addr,
    },
    /// This node's own attempt `hs` ends without completing (its resends
    /// are exhausted or its deadline passed), or its pending inbound
    /// handshake `hs` is reclaimed by the handshake timeout.
    Timeout {
        /// The attempt or handshake.
        hs: Hs,
    },
    /// This node starts its own rekey of the peer, handshake `hs`.
    RekeyStart {
        /// The rekey handshake.
        hs: Hs,
    },
    /// The msg2 of this node's own rekey `hs` arrives and passes the
    /// identity check of Section 7.2, carrying `epoch`.
    RekeyMsg2 {
        /// The rekey handshake.
        hs: Hs,
        /// The epoch it carries.
        epoch: Epoch,
    },
    /// This node, the initiator of a completed rekey, cuts over to its
    /// pending session (Section 7.4). Not named `Cutover`: a scan of the
    /// core bans that identifier.
    RekeyCutover,
    /// The peer is lost: its link is declared dead or it sent a
    /// `Disconnect`.
    Lost,
    /// This node's own process restarts and forgets everything.
    Restart,
}
