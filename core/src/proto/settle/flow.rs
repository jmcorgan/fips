//! The handshake flow a settlement table runs.
//!
//! The table's shared rules (the link records, the legs, the gates' memory,
//! the held peers, removal, the path inputs and the close rule) hold for
//! every handshake. What a flow decides is how a handshake's messages are
//! classified: what a msg1 opens, what a completed dial does to a held
//! peer, and, for a flow of three messages, what the msg3 does. A flow adds
//! its own inputs, outputs and refusals to the shared ones, each carried by
//! one extension variant ([`Input::Flow`](super::input::Input::Flow),
//! [`Output::Flow`](super::output::Output::Flow),
//! [`Denial::Flow`](super::output::Denial::Flow)), and keeps its own state
//! in the table, as the value of its type. It reaches the table only
//! through [`Ops`], which only the table builds, and the shared rules call
//! its hooks where a flow may differ.
//!
//! [`Ik`] is the flow of FMP's two-message IK handshake: every rule the
//! table's own inputs carry. It adds no input, output or refusal, keeps no
//! state, and each hook's body is the table's own rule.

use alloc::vec::Vec;
use core::fmt::Debug;

use super::links::{LinkNo, Pair};
use super::output::Output;
use super::table::{Ops, Table};
use crate::identity::NodeAddr;
use crate::time::Instant;

/// The outputs of a table running flow `F` at instants `I`.
pub type Outs<I, F> = Output<<F as Flow<I>>::Out, <F as Flow<I>>::Deny>;

/// A handshake flow: its own inputs, outputs and refusals, and the hooks the
/// shared rules call.
pub trait Flow<I: Instant>: Sized {
    /// The inputs the flow adds.
    type In: Debug + PartialEq + Eq;
    /// The outputs the flow adds.
    type Out: Debug + PartialEq + Eq;
    /// The refusals the flow adds.
    type Deny: Clone + Copy + Debug + PartialEq + Eq;

    /// Take one of the flow's own inputs at `now`.
    fn step(ops: &mut Ops<'_, I, Self>, input: Self::In, now: I, out: &mut Vec<Outs<I, Self>>);

    /// The stored answer to `bytes` from `from`, if a responder leg there
    /// holds one: the link and the msg2.
    fn stored(table: &Table<I, Self>, from: &Pair, bytes: &[u8]) -> Option<(LinkNo, Vec<u8>)>;

    /// How many answers in flight the admission cap counts.
    fn pending(table: &Table<I, Self>) -> usize;

    /// The msg2 of the responder leg on `link`, which names no peer, went
    /// out.
    fn answer_sent(ops: &mut Ops<'_, I, Self>, link: LinkNo);

    /// `peer` was installed.
    fn installed(ops: &mut Ops<'_, I, Self>, peer: NodeAddr);

    /// The held `peer` moved onto this node's own completed dial, after
    /// where it is was set and before the move's outputs.
    fn moved(ops: &mut Ops<'_, I, Self>, peer: NodeAddr);

    /// A frame of the held `peer` authenticated.
    fn heard(ops: &mut Ops<'_, I, Self>, peer: NodeAddr);

    /// The held `peer` was removed.
    fn removed(ops: &mut Ops<'_, I, Self>, peer: NodeAddr);
}

/// The flow of FMP's two-message IK handshake (see the module's comment).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ik;
