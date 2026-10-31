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

use super::NoiseError;
use super::handshake::HandshakeState;
use crate::entropy::EntropySource;
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
    /// and msg1's `es` output in each, and the symmetric state's chaining
    /// key and hash clear themselves.
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
            es: self.es,
        }
    }
}

impl<E: EntropySource> HandshakeState<E> {
    /// Read IK message 2 (initiator only) on a fork, and return the
    /// completed fork.
    ///
    /// The caller commits by replacing this handshake with the result. On an
    /// error this handshake is unchanged and can still read the genuine
    /// msg2.
    pub fn fork_msg2(&self, message: &[u8]) -> Result<Self, NoiseError> {
        self.forked(|fork| fork.read_message_2(message))
    }

    /// Read XK message 2 (initiator only) on a fork, and return the fork,
    /// ready to write msg3.
    ///
    /// The caller commits by replacing this handshake with the result. On an
    /// error this handshake is unchanged and can still read the genuine
    /// msg2.
    pub fn fork_xk2(&self, message: &[u8]) -> Result<Self, NoiseError> {
        self.forked(|fork| fork.read_xk_message_2(message))
    }

    /// Read XK message 3 (responder only) on a fork, and return the
    /// completed fork, which knows the initiator's static key.
    ///
    /// The caller commits by replacing this handshake with the result. On an
    /// error this handshake is unchanged and can still read the genuine
    /// msg3.
    pub fn fork_xk3(&self, message: &[u8]) -> Result<Self, NoiseError> {
        self.forked(|fork| fork.read_xk_message_3(message))
    }
}

#[cfg(test)]
#[path = "tests/fork.rs"]
mod tests;
