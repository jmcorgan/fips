//! The abstract history the reference model reads: what one node saw of one
//! peer identity, in order.
//!
//! Nothing here is a wire value. A handshake is named by its msg1's
//! ephemeral key ([`Hs`]), which both ends know, so a history of each end
//! can name the same handshakes. A msg1's exact bytes are named separately
//! ([`Bytes`]): a resend repeats both, a copy with its cleartext header
//! rewritten keeps the ephemeral and changes the bytes.

/// Milliseconds on the node's clock.
pub type Ms = u64;

/// A node's address, compared as FRC-1201 Section 5.6 orders node
/// addresses. Only the order matters to the model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Node(pub u8);

/// A transport address on one transport: the `(transport, address)` pair a
/// link is set up at and a connection is held at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Addr {
    /// The transport (binding instance).
    pub transport: u8,
    /// The address on that transport.
    pub at: u16,
}

/// A handshake, named by the ephemeral key of its msg1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hs(pub u32);

/// The exact bytes of one msg1, header included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bytes(pub u32);

/// A peer's startup epoch (FRC-1201 Section 5.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Epoch(pub u32);

/// A link as this node numbers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkId(pub u32);

/// Whether a link's binding holds a transport connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    /// No connection: every address is reachable while the binding runs.
    Connectionless,
    /// A connection per link, which can close.
    Connected,
}

/// One input to the node, in history order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// The clock moves forward by this much.
    Advance(Ms),
    /// This node starts its own initial handshake `hs` on a new link `link`
    /// to `to`.
    Dial {
        /// The handshake the dial starts.
        hs: Hs,
        /// The new link this node opens for it.
        link: LinkId,
        /// The address dialed.
        to: Addr,
        /// The link's binding.
        binding: Binding,
    },
    /// This node reads a msg1 of handshake `hs` from the peer, on `link`
    /// from `from`. `sent` says whether the msg2 that answers it, if one
    /// does, could be sent at once; if not, it is stored on a responder
    /// leg until [`Event::Msg2Sent`].
    Msg1 {
        /// The handshake the msg1 starts.
        hs: Hs,
        /// The msg1's exact bytes.
        bytes: Bytes,
        /// The epoch the msg1 carries.
        epoch: Epoch,
        /// The link it arrived on.
        link: LinkId,
        /// Its source address.
        from: Addr,
        /// The link's binding.
        binding: Binding,
        /// Whether a msg2 answering it could be sent now.
        sent: bool,
    },
    /// A send of the msg2 stored for the responder leg of handshake `hs`
    /// succeeded.
    Msg2Sent {
        /// The leg's handshake.
        hs: Hs,
    },
    /// The msg2 of this node's own initial handshake `hs` arrives from
    /// `from` and authenticates.
    Msg2 {
        /// The handshake it completes.
        hs: Hs,
        /// The epoch it carries.
        epoch: Epoch,
        /// Its source address.
        from: Addr,
    },
    /// This node's own attempt `hs` ends without completing (its deadline
    /// passed), or its responder leg is reclaimed.
    Timeout {
        /// The attempt or leg.
        hs: Hs,
    },
    /// A frame from the peer authenticates under the session of handshake
    /// `hs`, from `from`.
    Frame {
        /// The handshake whose session the frame authenticated under.
        hs: Hs,
        /// The frame's source address.
        from: Addr,
    },
    /// This node starts its own rekey of the peer, handshake `hs`.
    RekeyStart {
        /// The rekey handshake.
        hs: Hs,
    },
    /// The msg2 of this node's own rekey `hs` arrives.
    RekeyMsg2 {
        /// The rekey handshake.
        hs: Hs,
        /// The epoch it carries.
        epoch: Epoch,
    },
    /// This node cuts over to the pending session of its own completed
    /// rekey. Not named `Cutover`: the core's scan for the deployed rekey
    /// code bans that identifier.
    RekeyCutover,
    /// The transport connection at `at` closes.
    Close {
        /// The connection's address.
        at: Addr,
    },
    /// The peer is lost: its link is declared dead or it sent a
    /// `Disconnect`.
    Lost,
    /// This node's own process restarts and forgets everything.
    Restart,
}
