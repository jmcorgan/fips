//! A schedule as data, and the runner that applies it to a world.
//!
//! A step names nodes and transports by their index in the world: node 0 is
//! the node with the smallest node address, and transport 0 is each node's
//! first transport. So a schedule says which end does what by address order,
//! and runs the same on any of the world's transports.

use super::world::World;

/// The class of a held packet a step names. A msg1 or a msg2, a first dial's
/// or a rekey's, is held until a step names it; an established frame flows
/// on its own (`world.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    /// A handshake's first message: a dial's, or a rekey's.
    Msg1,
    /// The answer to a msg1.
    Msg2,
}

/// One step of a schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
    /// Node `from` dials node `to` at `to`'s address on transport
    /// `transport`, from its own transport of that index, through
    /// `initiate_connection`.
    Dial {
        from: usize,
        to: usize,
        transport: usize,
    },
    /// Node `node`'s pending transport connects resolve: it polls them until
    /// none is left, sending each dial's msg1 as its connect completes. A
    /// connectionless dial has none, and this does nothing.
    Connected { node: usize },
    /// The `nth` packet of class `kind` held at node `to`, counted from 0 in
    /// the order the held packets arrived, is handed to it.
    Handshake { to: usize, kind: Kind, nth: usize },
    /// That packet is dropped.
    Drop { to: usize, kind: Kind, nth: usize },
    /// A copy of that packet is handed to it, and the packet stays held.
    Duplicate { to: usize, kind: Kind, nth: usize },
    /// That packet and the next held packet of its class at `to` change
    /// places.
    Swap { to: usize, kind: Kind, nth: usize },
    /// Everything sent is handed to the node it was sent to, and what that
    /// sends in turn, with every node's pending connects polled, until the
    /// nodes are quiet.
    Heal,
    /// The monotonic clock moves this many milliseconds on, and every node
    /// runs its timers once.
    Advance(u64),
    /// Node `node` restarts: a new run of the same identity, with no peers,
    /// at the same addresses on the same transports.
    Restart { node: usize },
    /// Node `node` starts a rekey of every link it holds, as if each
    /// session had reached its rekey age.
    Rekey { node: usize },
}

/// Apply `steps` to `world` in order. After each step but a `Heal` the
/// world lets established frames flow, so a step's state is the one its
/// named packets and their frames leave. Returns whether every `Heal` left
/// the nodes quiet; one that did not is a world still sending when its
/// rounds ran out.
pub(super) async fn run(world: &mut World, steps: &[Step]) -> bool {
    let mut quiet = true;
    for step in steps {
        match *step {
            Step::Dial {
                from,
                to,
                transport,
            } => world.dial(from, to, transport).await,
            Step::Connected { node } => world.connected(node).await,
            Step::Handshake { to, kind, nth } => world.deliver(to, kind, nth).await,
            Step::Drop { to, kind, nth } => world.lose(to, kind, nth).await,
            Step::Duplicate { to, kind, nth } => world.duplicate(to, kind, nth).await,
            Step::Swap { to, kind, nth } => world.swap(to, kind, nth).await,
            Step::Heal => quiet &= world.heal().await,
            Step::Advance(ms) => world.advance(ms).await,
            Step::Restart { node } => world.restart(node).await,
            Step::Rekey { node } => world.rekey(node).await,
        }
    }
    quiet
}
