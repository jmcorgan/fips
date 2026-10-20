//! Reading a handshake message on a fork.
//!
//! A Noise read mixes the sender's ephemeral and the DH results into the
//! symmetric state, and advances its nonce, before the AEAD that
//! authenticates the message has run. A read that fails partway therefore
//! leaves a handshake that can no longer read the genuine message. Nothing
//! authenticates a handshake message before its read, so any message that
//! names a handshake may be a forgery, and the handshake has to survive it.
//!
//! The rule here is that a read never runs on the state it might spoil. It
//! runs on a fork, and the caller commits by replacing the handshake it
//! forked with the fork the read returned. A failed read drops the fork and
//! leaves the original exactly as it was, because the read methods borrow
//! the original immutably.

use super::handshake::HandshakeState;
use super::{HANDSHAKE_MSG2_SIZE, HANDSHAKE_MSG3_SIZE, NoiseError};
use crate::entropy::EntropySource;
use alloc::vec::Vec;
use core::marker::PhantomData;

/// A handshake state that can be copied for a read that may fail.
///
/// `HandshakeState` is not `Clone`: a clone would be a second live copy of
/// the node's long-term private key that any caller could make in passing.
/// A fork is the same copy made for one purpose, a read whose result
/// replaces the original or is dropped.
pub trait Fork: Sized {
    /// An independent copy of this state.
    fn fork(&self) -> Self;

    /// Run `read` on a fork and return the fork it advanced.
    ///
    /// `self` is borrowed immutably, so a failed read changes nothing; the
    /// fork it ran on is dropped with the error.
    fn forked<T>(&self, read: impl FnOnce(&mut Self) -> Result<(), T>) -> Result<Self, T> {
        let mut fork = self.fork();
        read(&mut fork)?;
        Ok(fork)
    }
}

impl<E> Fork for HandshakeState<E> {
    /// Copy every field.
    ///
    /// The struct literal names every field, so a field added to
    /// `HandshakeState` fails to compile here until the fork copies it; no
    /// list of fields is maintained by hand. Both copies clear their secrets
    /// when dropped: `Drop for HandshakeState` erases the two private keys
    /// in each, and the symmetric state's chaining key and hash clear
    /// themselves.
    fn fork(&self) -> Self {
        Self {
            pattern: self.pattern,
            role: self.role,
            progress: self.progress,
            symmetric: self.symmetric.clone(),
            static_keypair: self.static_keypair,
            ephemeral_keypair: self.ephemeral_keypair,
            remote_static: self.remote_static,
            remote_ephemeral: self.remote_ephemeral,
            entropy: PhantomData,
            local_epoch: self.local_epoch,
            remote_epoch: self.remote_epoch,
        }
    }
}

/// A message read on a fork: the fork it advanced, and the negotiation
/// payload that followed the base message, decrypted, if there was one.
pub type ForkRead<E> = (HandshakeState<E>, Option<Vec<u8>>);

impl<E: EntropySource> HandshakeState<E> {
    /// Read XX message 2 (initiator only) and the negotiation payload after
    /// it, if any, on one fork, and return the fork, ready to write msg3.
    ///
    /// `message` is the base msg2 of [`HANDSHAKE_MSG2_SIZE`] bytes, followed
    /// by the encrypted payload when the responder sent one. The payload is
    /// decrypted on the same fork because its decrypt advances the
    /// handshake cipher's nonce and the hash: a fork that skipped it would
    /// write a msg3 the responder cannot read. The caller commits by
    /// replacing this handshake with the result. On an error this handshake
    /// is unchanged and can still read the genuine msg2.
    pub fn fork_msg2(&self, message: &[u8]) -> Result<ForkRead<E>, NoiseError> {
        self.fork_read(message, HANDSHAKE_MSG2_SIZE, Self::read_message_2)
    }

    /// Read XX message 3 (responder only) and the negotiation payload after
    /// it, if any, on one fork, and return the completed fork, which knows
    /// the initiator's static key.
    ///
    /// `message` is the base msg3 of [`HANDSHAKE_MSG3_SIZE`] bytes, followed
    /// by the encrypted payload when the initiator sent one. The caller
    /// commits by replacing this handshake with the result. On an error
    /// this handshake is unchanged and can still read the genuine msg3.
    pub fn fork_msg3(&self, message: &[u8]) -> Result<ForkRead<E>, NoiseError> {
        self.fork_read(message, HANDSHAKE_MSG3_SIZE, Self::read_message_3)
    }

    /// Split `message` after its first `base` bytes, read the base with
    /// `read` and decrypt any rest as the payload, all on one fork.
    fn fork_read(
        &self,
        message: &[u8],
        base: usize,
        read: fn(&mut Self, &[u8]) -> Result<(), NoiseError>,
    ) -> Result<ForkRead<E>, NoiseError> {
        let (head, rest) = message.split_at(base.min(message.len()));
        let mut payload = None;
        let fork = self.forked(|fork| -> Result<(), NoiseError> {
            read(fork, head)?;
            if !rest.is_empty() {
                payload = Some(fork.decrypt_payload(rest)?);
            }
            Ok(())
        })?;
        Ok((fork, payload))
    }
}

#[cfg(test)]
#[path = "tests/fork.rs"]
mod tests;
