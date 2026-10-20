//! The link rekey profile over Noise XX, and the node-level msg3 read of an
//! inbound leg.
//!
//! [`FmpXx`] binds the shared rekey machine to the link layer as this line
//! speaks it: a three-message Noise XX handshake whose messages travel in
//! the 41-, 118- and 85-byte link framing (msg2 and msg3 followed by an
//! encrypted negotiation payload) with a fresh session index per attempt,
//! established frames selected by their receiver index and authenticated
//! over their 16-byte header, and a Heartbeat as the prompt. Every byte it
//! writes is built by the link codec in `proto::fmp::wire` and the Noise
//! code in `crate::noise`.
//!
//! The machine starts its own rekeys and reads the peer's msg2, but never
//! sees a peer's msg1 or msg3. A peer's rekey arrives as a new link
//! handshake, answered by the node's inbound leg; at msg3 the node reads
//! the leg's handshake with [`read_final`], which learns the initiator's
//! identity, startup epoch and the rekey it declares, and decides from
//! those whether the completion is a link setup or a rekey of a peer's
//! session. A rekey is handed to that peer's machine as
//! `Input::PeerDone`, carrying the leg's index lease.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::Cell;
use core::convert::Infallible;
use core::fmt;
use core::marker::PhantomData;

use super::super::core::decide_fmp_negotiation;
use super::super::wire::{
    ESTABLISHED_HEADER_SIZE, INNER_HEADER_SIZE, Msg2Header, Msg3Header, NegotiationPayload,
    NodeProfile, build_msg1, build_msg3,
};
use crate::entropy::EntropySource;
use crate::noise::{HandshakeState, NoiseSession};
use crate::proto::Error;
use crate::proto::link::LinkMessageType;
use crate::proto::rekey::keys::peer_key;
use crate::proto::rekey::{
    Authentic, Commit, Completed, DampenAt, DoneRead, Fresh, HsError, IndexLease, InitiatorCutover,
    Layer, Leg, NodeKeys, NoiseKeys, PeerKey, Profile, Read, ResponderCutover, Select, Wire,
};
use crate::time::Duration;
use crate::transport::TransportId;
use crate::utils::index::{IndexAllocator, SessionIndex};

/// The link layer's rekey profile: Noise XX, three messages, frames found
/// by receiver index. `E` is the host's entropy source, for ephemeral keys
/// and session indices.
pub struct FmpXx<E>(PhantomData<fn() -> E>);

impl<E> fmt::Debug for FmpXx<E> {
    /// The profile's name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FmpXx")
    }
}

/// The epoch keys of a link: a Noise session authenticating the 16-byte
/// established-frame header.
pub type LinkKeys = NoiseKeys<ESTABLISHED_HEADER_SIZE>;

/// What one call into a link's machine needs to know about this node: its
/// static key and startup epoch, its node profile, and the peer's index of
/// the session a rekey replaces.
///
/// A rekey's msg3 carries a negotiation payload with this node's profile
/// and a declaration naming the session it replaces by the index the peer
/// receives it on; without the declaration the peer reads the handshake as
/// a fresh dial. The shell builds this for each call, declaring the index
/// the peer's machine holds as theirs for its current epoch.
///
/// It also records the key a msg2 this call read authenticated
/// ([`LinkLocal::replied`]). The machine refuses a msg2 that reads but
/// authenticates another key than the link's bond for the same reason it
/// refuses one that does not read, and the shell counts the two apart.
pub struct LinkLocal {
    keys: NodeKeys,
    profile: NodeProfile,
    declared: Option<u32>,
    replied: Cell<Option<PeerKey>>,
}

impl LinkLocal {
    /// The local keys for a call, declaring `declared` as the peer's index
    /// of the session a rekey replaces.
    pub fn new(keys: NodeKeys, profile: NodeProfile, declared: Option<u32>) -> Self {
        Self {
            keys,
            profile,
            declared,
            replied: Cell::new(None),
        }
    }

    /// The local keys for one call, copied from the node's `keys`, as
    /// [`LinkLocal::new`] builds them.
    pub fn for_call(keys: &NodeKeys, profile: NodeProfile, declared: Option<u32>) -> Self {
        Self::new(
            NodeKeys::new(keys.keypair(), keys.epoch()),
            profile,
            declared,
        )
    }

    /// The static key and startup epoch.
    pub fn keys(&self) -> &NodeKeys {
        &self.keys
    }

    /// This node's profile.
    pub fn profile(&self) -> NodeProfile {
        self.profile
    }

    /// The peer's index of the session a rekey replaces.
    pub fn declared(&self) -> Option<u32> {
        self.declared
    }

    /// The static key a msg2 read during this call authenticated, whether
    /// or not the machine then accepted it. `None` when no msg2 read.
    pub fn replied(&self) -> Option<PeerKey> {
        self.replied.get()
    }
}

impl fmt::Debug for LinkLocal {
    /// The keys' public half, the profile and the declared index.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkLocal")
            .field("keys", &self.keys)
            .field("profile", &self.profile)
            .field("declared", &self.declared)
            .field("replied", &self.replied.get())
            .finish()
    }
}

/// A peer's rekey that the node's leg completed, with the leg's index
/// lease, as `Input::PeerDone` carries it.
pub struct XxDone<E: EntropySource + 'static> {
    done: Completed<FmpXx<E>>,
    lease: Option<IndexLease>,
}

impl<E: EntropySource + 'static> fmt::Debug for XxDone<E> {
    /// The completion and the lease; never key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XxDone")
            .field("done", &self.done)
            .field("lease", &self.lease)
            .finish()
    }
}

impl<E: EntropySource + 'static> DoneRead<FmpXx<E>> for XxDone<E> {
    fn epoch(&self) -> [u8; 8] {
        self.done.epoch
    }

    fn take(self) -> Leg<FmpXx<E>> {
        Leg {
            done: self.done,
            lease: self.lease,
        }
    }
}

/// A peer's msg3, read by this node's inbound leg: the session it
/// completed, what it authenticated, the negotiation payload it carried,
/// and the leg's index lease.
///
/// Every exit hands the lease on: [`into_rekey`](Self::into_rekey) to the
/// peer's machine, [`into_setup`](Self::into_setup) to link setup, and
/// [`into_lease`](Self::into_lease) back to the caller to release. Dropping
/// it with the lease still held counts a leaked index.
pub struct XxFinal<E> {
    session: NoiseSession,
    remote: secp256k1::PublicKey,
    epoch: [u8; 8],
    theirs: u32,
    payload: Option<Vec<u8>>,
    lease: Option<IndexLease>,
    entropy: PhantomData<fn() -> E>,
}

impl<E> fmt::Debug for XxFinal<E> {
    /// What the msg3 proved and the lease; never key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XxFinal")
            .field("remote", &self.remote)
            .field("epoch", &self.epoch)
            .field("theirs", &self.theirs)
            .field("payload", &self.payload)
            .field("lease", &self.lease)
            .finish()
    }
}

impl<E> XxFinal<E> {
    /// The initiator's static key, as the handshake authenticated it.
    pub fn remote(&self) -> &secp256k1::PublicKey {
        &self.remote
    }

    /// The initiator's startup epoch.
    pub fn epoch(&self) -> [u8; 8] {
        self.epoch
    }

    /// The initiator's index, from the msg3 header.
    pub fn theirs(&self) -> SessionIndex {
        SessionIndex::new(self.theirs)
    }

    /// The decrypted negotiation payload, when the msg3 carried one.
    pub fn payload(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }

    /// The index of the session the initiator declares this handshake
    /// replaces, `None` when it declares none. A payload that does not
    /// decode, or a declaration that is not 4 bytes, is an error, never an
    /// absence: reading it as "not a rekey" would put a rekey on the
    /// cross-connection path.
    pub fn declared(&self) -> Result<Option<SessionIndex>, Error> {
        match &self.payload {
            None => Ok(None),
            Some(bytes) => NegotiationPayload::decode(bytes)?.rekey_of(),
        }
    }

    /// The initiator's node profile, validated against `ours`, or `None`
    /// when the msg3 carried no payload.
    pub fn negotiate(&self, ours: NodeProfile) -> Result<Option<NodeProfile>, Error> {
        self.payload
            .as_deref()
            .map(|bytes| decide_fmp_negotiation(ours, bytes))
            .transpose()
    }

    /// The completion as a link setup: the session and the leg's lease,
    /// which becomes the index of the link's first epoch.
    pub fn into_setup(self) -> (NoiseSession, Option<IndexLease>) {
        (self.session, self.lease)
    }

    /// Give up the completion and hand back the leg's lease, for a
    /// completion the node refuses.
    pub fn into_lease(self) -> Option<IndexLease> {
        self.lease
    }
}

impl<E: EntropySource + 'static> XxFinal<E> {
    /// The completion as a rekey of the initiator's session, for its
    /// machine, which takes over the leg's lease.
    pub fn into_rekey(self) -> Authentic<XxDone<E>, Fresh> {
        let remote = PeerKey::from_xonly(&self.remote.x_only_public_key().0);
        Authentic::new(XxDone {
            done: Completed {
                session: Box::new(LinkKeys::new(self.session)),
                remote,
                epoch: self.epoch,
                theirs: Some(self.theirs),
            },
            lease: self.lease,
        })
    }
}

/// A msg3 that did not read. The leg's handshake is unchanged, so the
/// genuine msg3 can still complete it, and the lease comes back to the leg.
#[derive(Debug)]
pub struct Unread(pub Option<IndexLease>);

/// Read a framed msg3 and the negotiation payload after it on a fork of the
/// leg's responder handshake `hs`, and take the leg's `lease` with it.
///
/// Nothing authenticates a msg3 before this read except the receiver index
/// it names, which travelled in cleartext in msg2's header, so the message
/// may be a forgery: a failed read leaves `hs` untouched and returns the
/// lease.
pub fn read_final<E: EntropySource>(
    hs: &HandshakeState<E>,
    msg3: &[u8],
    lease: Option<IndexLease>,
) -> Result<XxFinal<E>, Unread> {
    let Some(read) = read(hs, msg3) else {
        return Err(Unread(lease));
    };
    let (session, remote, epoch, theirs, payload) = read;
    Ok(XxFinal {
        session,
        remote,
        epoch,
        theirs,
        payload,
        lease,
        entropy: PhantomData,
    })
}

/// What a msg3 read yields: the session, the initiator's static key and
/// epoch, its index and the payload.
type Msg3Read = (
    NoiseSession,
    secp256k1::PublicKey,
    [u8; 8],
    u32,
    Option<Vec<u8>>,
);

/// Read the framed `msg3` on a fork of `hs`.
fn read<E: EntropySource>(hs: &HandshakeState<E>, msg3: &[u8]) -> Option<Msg3Read> {
    let header = Msg3Header::parse(msg3)?;
    let (fork, payload) = hs.fork_msg3(msg3.get(header.noise_msg3_offset..)?).ok()?;
    let remote = *fork.remote_static()?;
    let epoch = fork.remote_epoch()?;
    let session = fork.into_session().ok()?;
    Some((session, remote, epoch, header.sender_idx.as_u32(), payload))
}

impl<E: EntropySource + 'static> Profile for FmpXx<E> {
    type Hs = HandshakeState<E>;
    type Session = LinkKeys;
    type Indices = IndexAllocator<E>;
    type Transport = TransportId;
    type Carrier = ();
    type Route = ();
    type Ext = ();
    type LocalKeys = LinkLocal;
    type Fsp = Infallible;
    type Fmp = ();
    type Msg1 = Infallible;
    type Done = XxDone<E>;

    const LAYER: Layer = Layer::Fmp;
    const MESSAGES: u8 = 3;
    const COMMIT: Commit = Commit::AtFinal;
    const INITIATOR_CUTOVER: InitiatorCutover = InitiatorCutover::AfterDelay;
    const RESPONDER_CUTOVER: ResponderCutover = ResponderCutover::OnFrame;
    const CANDIDATES: usize = 0;
    const PER_CARRIER: usize = 0;
    const DAMPEN_AT: DampenAt = DampenAt::Completion;
    const SELECT: Select = Select::ByIndex;
    const SILENCE: bool = false;
    const SETUP_RTT: bool = false;
    const INDEXED: bool = true;
    const FLOOR: usize = INNER_HEADER_SIZE;

    /// An XX initiator names no responder key: the machine's bond checks
    /// the key msg2 authenticates instead.
    fn initiate(
        local: &LinkLocal,
        _: &PeerKey,
        ours: Option<u32>,
    ) -> Result<(Self::Hs, Wire), HsError> {
        let ours = ours.ok_or(HsError)?;
        let mut hs = HandshakeState::new_initiator(local.keys.keypair());
        hs.set_local_epoch(local.keys.epoch());
        let noise = hs.write_message_1().map_err(|_| HsError)?;
        Ok((hs, build_msg1(SessionIndex::new(ours), &noise)))
    }

    fn valid(_: &[u8]) -> bool {
        false
    }

    /// A peer's msg1 is answered by the node's leg, never by a machine.
    fn answer(_: &LinkLocal, _: &[u8]) -> Result<(Self::Hs, Wire), HsError> {
        Err(HsError)
    }

    fn index(reply: &[u8]) -> Option<u32> {
        Msg2Header::parse(reply).map(|h| h.receiver_idx.as_u32())
    }

    /// Read msg2 and the responder's payload on a fork, then write msg3 on
    /// the same fork with this node's payload declaring the session it
    /// replaces, framed with the attempt's index and the responder's.
    ///
    /// The responder's payload is decrypted and dropped: a rekey takes no
    /// negotiation result, but the decrypt advances the cipher msg3 is
    /// written under. Without an index to declare the read fails, since a
    /// msg3 without the declaration reads at the peer as a fresh dial.
    fn reply(hs: &Self::Hs, local: &LinkLocal, bytes: &[u8]) -> Result<Read<Self>, HsError> {
        let header = Msg2Header::parse(bytes).ok_or(HsError)?;
        let declared = local.declared.ok_or(HsError)?;
        let noise = bytes.get(header.noise_msg2_offset..).ok_or(HsError)?;
        let (mut fork, _) = hs.fork_msg2(noise).map_err(|_| HsError)?;
        let remote = peer_key(&fork)?;
        local.replied.set(Some(remote));
        let epoch = fork.remote_epoch().ok_or(HsError)?;
        let mut msg3 = fork.write_message_3().map_err(|_| HsError)?;
        let payload = NegotiationPayload::fmp(1, 1, local.profile)
            .with_rekey_of(SessionIndex::new(declared))
            .encode();
        msg3.extend(fork.encrypt_payload(&payload).map_err(|_| HsError)?);
        let session = fork.into_session().map_err(|_| HsError)?;
        let done = Completed {
            session: Box::new(LinkKeys::new(session)),
            remote,
            epoch,
            theirs: Some(header.sender_idx.as_u32()),
        };
        let fin = build_msg3(header.receiver_idx, header.sender_idx, &msg3);
        Ok(Read {
            done,
            fin: Some(fin),
        })
    }

    /// A peer's msg3 is read by the node's leg ([`read_final`]), never by a
    /// machine.
    fn complete(_: &Self::Hs, _: &[u8]) -> Result<Completed<Self>, HsError> {
        Err(HsError)
    }

    /// `[timestamp:4 LE][0x51]`: a Heartbeat link message under its inner
    /// header, the timestamp truncated to 32 bits as a sender truncates it.
    fn prompt(elapsed: Duration, out: &mut Vec<u8>) {
        out.extend_from_slice(&(elapsed.as_millis() as u32).to_le_bytes());
        out.push(LinkMessageType::Heartbeat.to_byte());
    }

    fn is_probe(_: &[u8]) -> bool {
        false
    }
}

#[cfg(test)]
#[path = "tests/xx.rs"]
mod tests;
