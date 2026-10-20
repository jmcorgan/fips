//! The session rekey profile over Noise XK.
//!
//! [`FspXk`] binds the shared rekey machine to the end-to-end session layer
//! as deployed: a three-message Noise XK handshake (33, 57 and 73 bytes)
//! that the shell carries in the existing `SessionSetup`, `SessionAck` and
//! `SessionMsg3` bodies, established frames tried under every held key and
//! authenticated over their 12-byte header, and a `CoordsWarmup` as the
//! prompt, which a deployed receiver promotes on and treats as a no-op.
//! The machine's `Wire` values for this profile are the bare Noise
//! messages; the shell wraps each in its session message with the
//! coordinates it has at the time of the send, so a resent setup carries
//! current coordinates around identical Noise bytes.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::convert::Infallible;
use core::fmt;
use core::marker::PhantomData;

use super::super::wire::{
    FSP_HEADER_SIZE, FSP_INNER_HEADER_SIZE, SessionMessageType, fsp_prepend_inner_header,
    fsp_strip_inner_header,
};
use crate::entropy::EntropySource;
use crate::identity::NodeAddr;
use crate::noise::{HandshakeState, XK_HANDSHAKE_MSG1_SIZE};
use crate::proto::rekey::keys::{peer_key, pinned};
use crate::proto::rekey::{
    Commit, Completed, DampenAt, HsError, InitiatorCutover, Layer, NodeKeys, NoiseKeys, PeerKey,
    Profile, Read, ResponderCutover, Select, Wire,
};
use crate::proto::stp::TreeCoordinate;
use crate::time::Duration;

/// The session layer's rekey profile: Noise XK, three messages, frames
/// found by trial. `E` is the host's entropy source, for ephemeral keys.
pub struct FspXk<E>(PhantomData<fn() -> E>);

impl<E> fmt::Debug for FspXk<E> {
    /// The profile's name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FspXk")
    }
}

/// The epoch keys of a session: a Noise session authenticating the 12-byte
/// encrypted-message header. Coordinates a frame carries between that
/// header and the ciphertext are outside the AEAD, as deployed.
pub type SessionKeys = NoiseKeys<FSP_HEADER_SIZE>;

/// The completion of an XK handshake that `hs` has finished, its remote
/// static key taken from the handshake.
fn completed<E: EntropySource + 'static>(
    hs: HandshakeState<E>,
) -> Result<Completed<FspXk<E>>, HsError> {
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

impl<E: EntropySource + 'static> Profile for FspXk<E> {
    type Hs = HandshakeState<E>;
    type Session = SessionKeys;
    type Indices = ();
    type Transport = ();
    type Carrier = NodeAddr;
    type Route = TreeCoordinate;
    type Ext = ();
    type LocalKeys = NodeKeys;
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

    fn initiate(
        local: &NodeKeys,
        peer: &PeerKey,
        _: Option<u32>,
    ) -> Result<(Self::Hs, Wire), HsError> {
        let mut hs = HandshakeState::new_xk_initiator(local.keypair(), pinned(peer)?);
        hs.set_local_epoch(local.epoch());
        let msg1 = hs.write_xk_message_1().map_err(|_| HsError)?;
        Ok((hs, msg1))
    }

    /// The deployed receiver's checks: an XK msg1 of the right length whose
    /// ephemeral is a point on the curve.
    fn valid(msg1: &[u8]) -> bool {
        msg1.len() == XK_HANDSHAKE_MSG1_SIZE && secp256k1::PublicKey::from_slice(msg1).is_ok()
    }

    fn answer(local: &NodeKeys, msg1: &[u8]) -> Result<(Self::Hs, Wire), HsError> {
        let mut hs = HandshakeState::new_xk_responder(local.keypair());
        hs.set_local_epoch(local.epoch());
        hs.read_xk_message_1(msg1).map_err(|_| HsError)?;
        let ack = hs.write_xk_message_2().map_err(|_| HsError)?;
        Ok((hs, ack))
    }

    fn index(_: &[u8]) -> Option<u32> {
        None
    }

    /// Read the ack on a fork and write msg3 on the same fork.
    fn reply(hs: &Self::Hs, _: &NodeKeys, bytes: &[u8]) -> Result<Read<Self>, HsError> {
        let mut fork = hs.fork_xk2(bytes).map_err(|_| HsError)?;
        let fin = fork.write_xk_message_3().map_err(|_| HsError)?;
        Ok(Read {
            done: completed(fork)?,
            fin: Some(fin),
        })
    }

    fn complete(hs: &Self::Hs, bytes: &[u8]) -> Result<Completed<Self>, HsError> {
        completed(hs.fork_xk3(bytes).map_err(|_| HsError)?)
    }

    /// `[timestamp:4 LE][0x14][0x00]`: a `CoordsWarmup` inner header with an
    /// empty body. The inner flags carry no spin bit: the core keeps no MMP
    /// state, and a warmup is infrastructure traffic a receiver's spin
    /// tracking does not need.
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
#[path = "tests/xk.rs"]
mod tests;
