//! The IK replay record and the answer held for a responder pending.
//!
//! An IK msg1 authenticates the initiator's static key and startup epoch and
//! carries nothing fresh, so a copy taken off the wire still reads as the
//! peer after the cycle it started has ended. The record is how a copy is
//! told from a fresh msg1: it holds the ephemeral of every msg1 this machine
//! answered or refused after authentication, and the ephemeral of the msg1
//! the link was set up from. The ephemeral is bound by the msg1's own AEAD,
//! so a copy with a rewritten header still matches it.
//!
//! The record outlives a machine: `close` hands it back in the `Carry`, the
//! shell files it under the peer's identity and epoch, and a later machine
//! for the same peer epoch receives it again in its `SetupFacts`.

use alloc::collections::VecDeque;

use super::Wire;

/// How many msg1 ephemerals the record keeps, besides the setup msg1's.
pub const RECORD_BOUND: usize = 256;

/// A SHA-256 digest of a message or of the ephemeral it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Digest(pub [u8; 32]);

/// What an IK machine remembers of the msg1s it has seen.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Record {
    /// The whole link-setup msg1, for its byte-identical resends.
    setup: Option<Digest>,
    /// The link-setup msg1's ephemeral, kept outside the bound.
    origin: Option<Digest>,
    /// The msg2 the link was set up with, answered again for a resend of
    /// the setup msg1 while the link is young.
    answer: Option<Wire>,
    /// Ephemerals of the msg1s answered or refused since, oldest first.
    seen: VecDeque<Digest>,
}

impl Record {
    /// An empty record.
    pub fn new() -> Self {
        Self::default()
    }

    /// The record of a link set up from the msg1 with digest `msg1` and
    /// ephemeral digest `ephemeral`, answered with `msg2` when this node
    /// was its responder.
    pub fn setup(msg1: Digest, ephemeral: Digest, msg2: Option<Wire>) -> Self {
        Self {
            setup: Some(msg1),
            origin: Some(ephemeral),
            answer: msg2,
            seen: VecDeque::new(),
        }
    }

    /// Add the ephemerals of an older record of the same peer epoch, kept
    /// by the node across a re-peering, ahead of this record's own.
    pub fn absorb(&mut self, older: Record) {
        let mut seen = older.seen;
        if let Some(origin) = older.origin {
            seen.push_back(origin);
        }
        seen.extend(self.seen.drain(..));
        while seen.len() > RECORD_BOUND {
            seen.pop_front();
        }
        self.seen = seen;
    }

    /// Remember the ephemeral of a msg1 answered or refused, dropping the
    /// oldest at the bound.
    pub(crate) fn push(&mut self, ephemeral: Digest) {
        if self.seen.len() == RECORD_BOUND && !fault!(RecordUnbounded) {
            self.seen.pop_front();
        }
        self.seen.push_back(ephemeral);
    }

    /// Whether a msg1 with this ephemeral was seen before.
    pub(crate) fn holds(&self, ephemeral: &Digest) -> bool {
        self.origin.as_ref() == Some(ephemeral) || self.seen.contains(ephemeral)
    }

    /// Whether `msg1` is byte for byte the link-setup msg1.
    pub(crate) fn is_setup(&self, msg1: &Digest) -> bool {
        self.setup.as_ref() == Some(msg1)
    }

    /// The setup msg2 to answer a resend of the setup msg1 with.
    pub(crate) fn setup_answer(&self) -> Option<&Wire> {
        self.answer.as_ref()
    }

    /// The number of ephemerals held, the setup msg1's included.
    pub fn len(&self) -> usize {
        self.seen.len() + usize::from(self.origin.is_some())
    }

    /// Whether the record holds nothing.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The answer a responder pending holds: the msg1 that armed it, whole and
/// by ephemeral, and the msg2 sent back, which a byte-identical resend of
/// that msg1 draws again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HeldAnswer {
    pub(crate) msg1: Digest,
    pub(crate) ephemeral: Digest,
    pub(crate) msg2: Wire,
}

#[cfg(test)]
#[path = "tests/record.rs"]
mod tests;
