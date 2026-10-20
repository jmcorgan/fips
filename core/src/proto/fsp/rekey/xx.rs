//! The session rekey profile over Noise XX.
//!
//! [`FspXx`] binds the shared rekey machine to the end-to-end session layer
//! as this line speaks it: a three-message Noise XX handshake (33, 106 and
//! 73 bytes, the last two followed by an encrypted negotiation payload on a
//! session's first handshake) that the shell carries in the existing
//! `SessionSetup`, `SessionAck` and `SessionMsg3` bodies, established frames
//! tried under every held key and authenticated over their 12-byte header,
//! and a `CoordsWarmup` as the prompt, which a receiver promotes on and
//! treats as a no-op. The machine's `Wire` values for this profile are the
//! bare Noise messages with their payload; the shell wraps each in its
//! session message with the coordinates it has at the time of the send.
//!
//! The profile is transitional: the session layer's v2 handshake is XK,
//! and this profile keeps the session rules master's XK profile has, over
//! the XX messages this line already sends.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::Cell;
use core::convert::Infallible;
use core::fmt;
use core::marker::PhantomData;

use super::super::wire::{
    FSP_HEADER_SIZE, FSP_INNER_HEADER_SIZE, SessionMessageType, fsp_prepend_inner_header,
    fsp_strip_inner_header,
};
use crate::entropy::EntropySource;
use crate::identity::NodeAddr;
use crate::noise::{HANDSHAKE_MSG1_SIZE, HandshakeState};
use crate::proto::fmp::wire::NegotiationPayload;
use crate::proto::rekey::keys::peer_key;
use crate::proto::rekey::{
    Commit, Completed, DampenAt, HsError, InitiatorCutover, Layer, NodeKeys, NoiseKeys, PeerKey,
    Profile, Read, ResponderCutover, Select, Wire,
};
use crate::proto::stp::TreeCoordinate;
use crate::time::Duration;

/// The session layer's rekey profile: Noise XX, three messages, frames
/// found by trial. `E` is the host's entropy source, for ephemeral keys.
pub struct FspXx<E>(PhantomData<fn() -> E>);

impl<E> fmt::Debug for FspXx<E> {
    /// The profile's name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FspXx")
    }
}

/// The epoch keys of a session: a Noise session authenticating the 12-byte
/// encrypted-message header. Coordinates a frame carries between that
/// header and the ciphertext are outside the AEAD.
pub type SessionKeys = NoiseKeys<FSP_HEADER_SIZE>;

/// What one call into the machine needs to know about this node: its
/// static key and startup epoch, and whether the session has no epoch yet,
/// so that the handshake is its first.
///
/// The first handshake's ack and msg3 carry the negotiation payload; a
/// rekey's carry none, because a node of this line reads a rekey's ack as
/// exactly the base msg2 and would refuse one with a payload. The shell
/// builds this for each call, marking `opening` while the machine's view
/// shows no current epoch.
///
/// It also records the key an ack this call read authenticated
/// ([`SessionLocal::replied`]). The machine refuses an ack that reads but
/// authenticates another key than the session's bond for the same reason
/// it refuses one that does not read, and the shell counts the two apart.
pub struct SessionLocal {
    keys: NodeKeys,
    opening: bool,
    replied: Cell<Option<PeerKey>>,
}

impl SessionLocal {
    /// The local keys for a call, `opening` when the session has no epoch.
    pub fn new(keys: NodeKeys, opening: bool) -> Self {
        Self {
            keys,
            opening,
            replied: Cell::new(None),
        }
    }

    /// The local keys for one call, copied from the node's `keys`, as
    /// [`SessionLocal::new`] builds them.
    pub fn for_call(keys: &NodeKeys, opening: bool) -> Self {
        Self::new(NodeKeys::new(keys.keypair(), keys.epoch()), opening)
    }

    /// The static key and startup epoch.
    pub fn keys(&self) -> &NodeKeys {
        &self.keys
    }

    /// Whether this handshake is the session's first.
    pub fn opening(&self) -> bool {
        self.opening
    }

    /// The static key an ack read during this call authenticated, whether
    /// or not the machine then accepted it. `None` when no ack read.
    pub fn replied(&self) -> Option<PeerKey> {
        self.replied.get()
    }
}

impl fmt::Debug for SessionLocal {
    /// The keys' public half and whether the session is opening.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionLocal")
            .field("keys", &self.keys)
            .field("opening", &self.opening)
            .field("replied", &self.replied.get())
            .finish()
    }
}

/// The negotiation payload a session's first handshake carries in its ack
/// and msg3: format 0, versions 0 to 0, no features.
fn negotiation() -> Vec<u8> {
    NegotiationPayload::new(0, 0, 0).encode()
}

/// Append the encrypted negotiation payload to `msg` when `local` says the
/// handshake is the session's first.
fn seal_payload<E: EntropySource>(
    hs: &mut HandshakeState<E>,
    local: &SessionLocal,
    msg: &mut Vec<u8>,
) -> Result<(), HsError> {
    if local.opening {
        let payload = hs.encrypt_payload(&negotiation()).map_err(|_| HsError)?;
        msg.extend_from_slice(&payload);
    }
    Ok(())
}

/// The completion of an XX handshake that `hs` has finished, its remote
/// static key taken from the handshake.
fn completed<E: EntropySource + 'static>(
    hs: HandshakeState<E>,
) -> Result<Completed<FspXx<E>>, HsError> {
    let remote = peer_key(&hs)?;
    let epoch = hs.remote_epoch().ok_or(HsError)?;
    let session = hs.into_session().map_err(|_| HsError)?;
    Ok(Completed {
        session: Box::new(SessionKeys::new(session)),
        remote,
        epoch,
        theirs: None,
    })
}

impl<E: EntropySource + 'static> Profile for FspXx<E> {
    type Hs = HandshakeState<E>;
    type Session = SessionKeys;
    type Indices = ();
    type Transport = ();
    type Carrier = NodeAddr;
    type Route = TreeCoordinate;
    type Ext = ();
    type LocalKeys = SessionLocal;
    type Fsp = ();
    type Fmp = Infallible;
    type Msg1 = Infallible;
    type Done = Infallible;

    const LAYER: Layer = Layer::Fsp;
    const MESSAGES: u8 = 3;
    const COMMIT: Commit = Commit::AtFinal;
    const INITIATOR_CUTOVER: InitiatorCutover = InitiatorCutover::OnEvidence;
    const RESPONDER_CUTOVER: ResponderCutover = ResponderCutover::AtProof;
    const CANDIDATES: usize = 4;
    const PER_CARRIER: usize = 2;
    const DAMPEN_AT: DampenAt = DampenAt::Completion;
    const SELECT: Select = Select::Trial;
    const SILENCE: bool = true;
    const SETUP_RTT: bool = true;
    const INDEXED: bool = false;
    const FLOOR: usize = FSP_INNER_HEADER_SIZE;

    /// An XX initiator names no responder key: the machine's bond checks
    /// the key the ack authenticates instead.
    fn initiate(
        local: &SessionLocal,
        _: &PeerKey,
        _: Option<u32>,
    ) -> Result<(Self::Hs, Wire), HsError> {
        let mut hs = HandshakeState::new_initiator(local.keys.keypair());
        hs.set_local_epoch(local.keys.epoch());
        let msg1 = hs.write_message_1().map_err(|_| HsError)?;
        Ok((hs, msg1))
    }

    /// A receiver's checks: an XX msg1 of the right length whose ephemeral
    /// is a point on the curve.
    fn valid(msg1: &[u8]) -> bool {
        msg1.len() == HANDSHAKE_MSG1_SIZE && secp256k1::PublicKey::from_slice(msg1).is_ok()
    }

    fn answer(local: &SessionLocal, msg1: &[u8]) -> Result<(Self::Hs, Wire), HsError> {
        let mut hs = HandshakeState::new_responder(local.keys.keypair());
        hs.set_local_epoch(local.keys.epoch());
        hs.read_message_1(msg1).map_err(|_| HsError)?;
        let mut ack = hs.write_message_2().map_err(|_| HsError)?;
        seal_payload(&mut hs, local, &mut ack)?;
        Ok((hs, ack))
    }

    fn index(_: &[u8]) -> Option<u32> {
        None
    }

    /// Read the ack and any payload after it on a fork, and write msg3 on
    /// the same fork. The payload is read whether or not this handshake is
    /// the first: its decrypt advances the cipher msg3 is written under.
    fn reply(hs: &Self::Hs, local: &SessionLocal, bytes: &[u8]) -> Result<Read<Self>, HsError> {
        let (mut fork, _) = hs.fork_msg2(bytes).map_err(|_| HsError)?;
        let mut fin = fork.write_message_3().map_err(|_| HsError)?;
        seal_payload(&mut fork, local, &mut fin)?;
        let done = completed(fork)?;
        local.replied.set(Some(done.remote));
        Ok(Read {
            done,
            fin: Some(fin),
        })
    }

    /// Read msg3 and any payload after it on a fork, so a msg3 with a
    /// payload completes a rekey as well as a first handshake: a peer that
    /// restarted opens with one.
    fn complete(hs: &Self::Hs, bytes: &[u8]) -> Result<Completed<Self>, HsError> {
        let (fork, _) = hs.fork_msg3(bytes).map_err(|_| HsError)?;
        completed(fork)
    }

    /// `[timestamp:4 LE][0x14][0x00]`: a `CoordsWarmup` inner header with an
    /// empty body.
    fn prompt(elapsed: Duration, out: &mut Vec<u8>) {
        out.extend_from_slice(&fsp_prepend_inner_header(
            elapsed.as_millis() as u32,
            SessionMessageType::CoordsWarmup.to_byte(),
            0,
            &[],
        ));
    }

    fn is_probe(plaintext: &[u8]) -> bool {
        fsp_strip_inner_header(plaintext).is_some_and(|(_, msg_type, _, _)| {
            msg_type == SessionMessageType::CoordsWarmup.to_byte()
        })
    }
}

#[cfg(test)]
#[path = "tests/xx.rs"]
mod tests;
