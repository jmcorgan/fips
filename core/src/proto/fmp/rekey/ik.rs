//! The link rekey profile over Noise IK, and the node-level msg1 read.
//!
//! [`FmpIk`] binds the shared rekey machine to the link layer as deployed:
//! a two-message Noise IK handshake whose msg1 and msg2 travel in the
//! existing 114- and 69-byte link framing with a fresh session index per
//! attempt, established frames selected by their receiver index and
//! authenticated over their 16-byte header, and a Heartbeat as the prompt.
//! Every byte it writes is built by the link codec in `proto::fmp::wire`
//! and the Noise code in `crate::noise`, so the wire is the deployed one.
//!
//! A peer's msg1 is not read by its machine. The node reads it first with
//! [`read_msg1`], which runs the responder's half of the handshake under
//! this node's static key, learns the initiator's identity and startup
//! epoch, and mints the replayable proof the machine takes as
//! `Input::PeerMsg1`. The shell decides from the identity which machine, if
//! any, the msg1 goes to.

use alloc::boxed::Box;
use core::convert::Infallible;
use core::fmt;
use core::marker::PhantomData;

use sha2::{Digest as _, Sha256};

use super::super::wire::{
    ESTABLISHED_HEADER_SIZE, INNER_HEADER_SIZE, Msg1Header, Msg2Header, build_msg1, build_msg2,
};
use crate::entropy::EntropySource;
use crate::noise::{HandshakeState, PUBKEY_SIZE};
use crate::proto::link::LinkMessageType;
use crate::proto::rekey::keys::{peer_key, pinned};
use crate::proto::rekey::{
    Authentic, Commit, Completed, DampenAt, Digest, HsError, InitiatorCutover, Layer, Msg1Read,
    NodeKeys, NoiseKeys, PeerKey, Profile, Read, Record, Replayable, ResponderCutover, Select,
    Wire,
};
use crate::time::Duration;
use crate::transport::TransportId;
use crate::utils::index::{IndexAllocator, SessionIndex};

/// The link layer's rekey profile: Noise IK, two messages, frames found by
/// receiver index. `E` is the host's entropy source, for ephemeral keys and
/// session indices.
pub struct FmpIk<E>(PhantomData<fn() -> E>);

impl<E> fmt::Debug for FmpIk<E> {
    /// The profile's name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FmpIk")
    }
}

/// The epoch keys of a link: a Noise session authenticating the 16-byte
/// established-frame header.
pub type LinkKeys = NoiseKeys<ESTABLISHED_HEADER_SIZE>;

/// The digest of the ephemeral at the start of a Noise IK msg1, which the
/// msg1's AEAD binds, so a copy with a rewritten header still matches it.
/// The same digest `proto::fmp::EphemeralDigest` takes.
fn ephemeral(noise_msg1: &[u8]) -> Option<Digest> {
    let e = noise_msg1.get(..PUBKEY_SIZE)?;
    Some(Digest(Sha256::digest(e).into()))
}

/// The replay record of a link set up from the framed `msg1`, answered with
/// the framed `msg2` when this node was the link setup's responder.
pub fn setup_record(msg1: &[u8], msg2: Option<&[u8]>) -> Option<Record> {
    let header = Msg1Header::parse(msg1)?;
    let noise = msg1.get(header.noise_msg1_offset..)?;
    Some(Record::setup(
        Digest(Sha256::digest(msg1).into()),
        ephemeral(noise)?,
        msg2.map(<[u8]>::to_vec),
    ))
}

/// A peer's msg1, read by this node as its IK responder: the handshake
/// advanced past msg1, the identity and epoch it authenticated, and the
/// digests the replay record compares.
pub struct IkMsg1<E> {
    hs: HandshakeState<E>,
    theirs: u32,
    whole: Digest,
    ephemeral: Digest,
    remote: PeerKey,
    epoch: [u8; 8],
}

impl<E> fmt::Debug for IkMsg1<E> {
    /// What the msg1 proved; never key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IkMsg1")
            .field("remote", &self.remote)
            .field("epoch", &self.epoch)
            .field("theirs", &self.theirs)
            .finish()
    }
}

/// Read a framed IK msg1 as its responder under `local`, or `None` when it
/// is not a well-formed msg1 that authenticates under this node's static
/// key. The proof is replayable: a msg1 carries nothing fresh, so a captured
/// copy reads as the peer again.
pub fn read_msg1<E: EntropySource>(
    local: &NodeKeys,
    bytes: &[u8],
) -> Option<Authentic<IkMsg1<E>, Replayable>> {
    let header = Msg1Header::parse(bytes)?;
    let noise = bytes.get(header.noise_msg1_offset..)?;
    let mut hs = HandshakeState::<E>::new_responder(local.keypair());
    hs.set_local_epoch(local.epoch());
    hs.read_message_1(noise).ok()?;
    let remote = peer_key(&hs).ok()?;
    let epoch = hs.remote_epoch()?;
    Some(Authentic::new(IkMsg1 {
        theirs: header.sender_idx.as_u32(),
        whole: Digest(Sha256::digest(bytes).into()),
        ephemeral: ephemeral(noise)?,
        remote,
        epoch,
        hs,
    }))
}

impl<E: EntropySource + 'static> Msg1Read<FmpIk<E>> for IkMsg1<E> {
    fn epoch(&self) -> [u8; 8] {
        self.epoch
    }

    fn digest(&self) -> Digest {
        self.whole
    }

    fn ephemeral(&self) -> Digest {
        self.ephemeral
    }

    fn remote(&self) -> PeerKey {
        self.remote
    }

    /// Write msg2 on a fork of the read handshake, so the proof can answer
    /// again, and frame it with index `ours` and the msg1's sender index.
    fn answer(
        &self,
        _: &NodeKeys,
        ours: Option<u32>,
    ) -> Result<(Completed<FmpIk<E>>, Wire), HsError> {
        use crate::noise::Fork;
        let ours = ours.ok_or(HsError)?;
        let mut hs = self.hs.fork();
        let noise = hs.write_message_2().map_err(|_| HsError)?;
        let session = hs.into_session().map_err(|_| HsError)?;
        let msg2 = build_msg2(
            SessionIndex::new(ours),
            SessionIndex::new(self.theirs),
            &noise,
        );
        let done = Completed {
            session: Box::new(LinkKeys::new(session)),
            remote: self.remote,
            epoch: self.epoch,
            theirs: Some(self.theirs),
        };
        Ok((done, msg2))
    }
}

impl<E: EntropySource + 'static> Profile for FmpIk<E> {
    type Hs = HandshakeState<E>;
    type Session = LinkKeys;
    type Indices = IndexAllocator<E>;
    type Transport = TransportId;
    type Carrier = ();
    type Route = ();
    type Ext = ();
    type LocalKeys = NodeKeys;
    type Fsp = Infallible;
    type Fmp = ();
    type Msg1 = IkMsg1<E>;
    type Done = Infallible;

    const LAYER: Layer = Layer::Fmp;
    const MESSAGES: u8 = 2;
    const COMMIT: Commit = Commit::AtAnswer;
    const INITIATOR_CUTOVER: InitiatorCutover = InitiatorCutover::OnProof;
    const RESPONDER_CUTOVER: ResponderCutover = ResponderCutover::OnFrame;
    const CANDIDATES: usize = 0;
    const PER_CARRIER: usize = 0;
    const DAMPEN_AT: DampenAt = DampenAt::Answer;
    const SELECT: Select = Select::ByIndex;
    const SILENCE: bool = false;
    const SETUP_RTT: bool = false;
    const INDEXED: bool = true;
    const FLOOR: usize = INNER_HEADER_SIZE;

    fn initiate(
        local: &NodeKeys,
        peer: &PeerKey,
        ours: Option<u32>,
    ) -> Result<(Self::Hs, Wire), HsError> {
        let ours = ours.ok_or(HsError)?;
        let mut hs = HandshakeState::new_initiator(local.keypair(), pinned(peer)?);
        hs.set_local_epoch(local.epoch());
        let noise = hs.write_message_1().map_err(|_| HsError)?;
        Ok((hs, build_msg1(SessionIndex::new(ours), &noise)))
    }

    fn valid(_: &[u8]) -> bool {
        false
    }

    fn answer(_: &NodeKeys, _: &[u8]) -> Result<(Self::Hs, Wire), HsError> {
        Err(HsError)
    }

    fn index(reply: &[u8]) -> Option<u32> {
        Msg2Header::parse(reply).map(|h| h.receiver_idx.as_u32())
    }

    fn reply(hs: &Self::Hs, _: &NodeKeys, bytes: &[u8]) -> Result<Read<Self>, HsError> {
        let header = Msg2Header::parse(bytes).ok_or(HsError)?;
        let noise = bytes.get(header.noise_msg2_offset..).ok_or(HsError)?;
        let fork = hs.fork_msg2(noise).map_err(|_| HsError)?;
        let remote = peer_key(&fork)?;
        let epoch = fork.remote_epoch().ok_or(HsError)?;
        let session = fork.into_session().map_err(|_| HsError)?;
        let done = Completed {
            session: Box::new(LinkKeys::new(session)),
            remote,
            epoch,
            theirs: Some(header.sender_idx.as_u32()),
        };
        Ok(Read { done, fin: None })
    }

    fn complete(_: &Self::Hs, _: &[u8]) -> Result<Completed<Self>, HsError> {
        Err(HsError)
    }

    /// `[timestamp:4 LE][0x51]`: a Heartbeat link message under its inner
    /// header, the timestamp truncated to 32 bits as the deployed sender
    /// truncates it.
    fn prompt(elapsed: Duration, out: &mut alloc::vec::Vec<u8>) {
        out.extend_from_slice(&(elapsed.as_millis() as u32).to_le_bytes());
        out.push(LinkMessageType::Heartbeat.to_byte());
    }

    fn is_probe(_: &[u8]) -> bool {
        false
    }
}

#[cfg(test)]
#[path = "tests/ik.rs"]
mod tests;
