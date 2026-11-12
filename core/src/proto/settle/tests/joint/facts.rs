//! What a joint node's bundles read about the world: the facts of its
//! transports, the world's addresses as the path machine's pairs, and a
//! stream of path identifiers per node.
//!
//! A bundle draws a path identifier from its entropy source by a static
//! call, so the source cannot be a field of the node. [`Draw`] reads a
//! thread-local that [`Stream::lend`] sets around each bundle call to the
//! calling node's own stream and takes back after it, so one node's draws
//! never move another's, and an identifier is a function of the node and
//! how many it drew before.

use alloc::collections::BTreeMap;
use core::cell::Cell;

use crate::entropy::EntropySource;
use crate::proto::path::{Class, Facts, Kind as PathKind, Medium, PathRef, Role};
use crate::testutil::SplitMix64;
use crate::transport::{TransportAddr, TransportId};

use super::super::super::links::Pair;
use super::super::super::model::history::{Addr, Node};
use super::super::drive;
use super::super::world::Kind;

/// The link MTU every world transport has, in frame bytes.
const MTU: usize = 1280;

/// The world's transports as a bundle's facts: each transport's model
/// decides whether it is connection-oriented and whether it is a BLE
/// binding; every transport is clear, has the role Normal, and accepts and
/// dials the peer, as the node's facts are at the default configuration
/// with no ACL. UDP and TCP paths take the kind of the peer's address, as
/// the node's do; BLE is local.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Transports {
    kinds: BTreeMap<u8, Kind>,
}

impl Transports {
    /// The facts of the world transports `kinds`.
    pub fn new(kinds: &BTreeMap<u8, Kind>) -> Self {
        Self {
            kinds: kinds.clone(),
        }
    }

    /// The model of `transport`, if the world has it.
    fn kind(&self, transport: TransportId) -> Option<Kind> {
        let t = u8::try_from(transport.as_u32()).ok()?;
        self.kinds.get(&t).copied()
    }
}

impl Facts for Transports {
    fn mtu(&self, transport: TransportId, _addr: &TransportAddr) -> usize {
        self.kind(transport).map_or(0, |_| MTU)
    }

    fn medium(&self, transport: TransportId, _addr: &TransportAddr) -> Medium {
        match self.kind(transport) {
            Some(Kind::Ble) => Medium::Ble,
            Some(Kind::Datagram | Kind::Stream) | None => Medium::Unknown,
        }
    }

    fn oriented(&self, transport: TransportId) -> bool {
        matches!(self.kind(transport), Some(Kind::Stream | Kind::Ble))
    }

    fn class(&self, _transport: TransportId) -> Class {
        Class::Clear
    }

    fn kind(&self, transport: TransportId) -> Option<PathKind> {
        match self.kind(transport) {
            Some(Kind::Ble) => Some(PathKind::Local),
            Some(Kind::Datagram | Kind::Stream) | None => None,
        }
    }

    fn role(&self, _transport: TransportId) -> Role {
        Role::Normal
    }

    fn accepts(&self, transport: TransportId) -> bool {
        self.kind(transport).is_some()
    }

    fn dials(&self, transport: TransportId) -> bool {
        self.kind(transport).is_some()
    }
}

/// The path machine's pair of world address `a`, as the core's.
pub fn pair(a: Addr) -> PathRef {
    let Pair { transport, addr } = drive::pair(a);
    PathRef { transport, addr }
}

/// The world address of the pair (`transport`, `addr`), the inverse of
/// [`pair`].
pub fn addr(transport: TransportId, addr: &TransportAddr) -> Addr {
    drive::addr(&Pair {
        transport,
        addr: addr.clone(),
    })
}

/// The world address of path `p`.
pub fn at(p: &PathRef) -> Addr {
    addr(p.transport, &p.addr)
}

std::thread_local! {
    /// The stream lent to the bundle call under way on this thread.
    static LENT: Cell<Option<Stream>> = const { Cell::new(None) };
}

/// One node's stream of path identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stream {
    seed: u64,
    drawn: u64,
}

impl Stream {
    /// Node `me`'s stream, from its start.
    pub fn new(me: Node) -> Self {
        Self {
            seed: u64::from(me.0),
            drawn: 0,
        }
    }

    /// Run `f`, a bundle call, drawing from this stream.
    pub fn lend<R>(&mut self, f: impl FnOnce() -> R) -> R {
        let outer = LENT.with(|l| l.replace(Some(*self)));
        assert!(outer.is_none(), "one bundle call at a time draws");
        let r = f();
        *self = LENT
            .with(Cell::take)
            .expect("the stream comes back from the call it was lent to");
        r
    }
}

/// The entropy source of a joint node's bundles: the stream lent to the
/// call under way.
pub struct Draw;

impl EntropySource for Draw {
    fn fill(dest: &mut [u8]) {
        LENT.with(|l| {
            let mut s = l.get().expect("a bundle draws only inside `Stream::lend`");
            for chunk in dest.chunks_mut(8) {
                let v = SplitMix64::mix(s.seed, &[s.drawn]).to_le_bytes();
                s.drawn += 1;
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
            l.set(Some(s));
        });
    }
}
