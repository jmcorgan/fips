//! The paths a peer is reachable over, and the rules for holding them.
//!
//! A path is identified by the pair (local transport, peer's address on it):
//! one transport can carry several paths to one peer, and a node never holds
//! two paths with the same pair. The set enforces the multipath v1 draft's
//! limits (Section 5.1, Appendix A) and its eviction order, and owns the rule
//! for when an authentic frame may move a path's address. A BLE binding holds
//! at most one path to a peer, as FRC-1301 Section 6.5.4 keeps one verified
//! BLE channel to a node per binding; two BLE bindings still give two paths.
//!
//! The rules are sans-IO: the set never reads a clock or performs I/O. Times
//! are passed in as instants of the host's clock, the type parameter `I`,
//! and identifier draws are passed in, so every rule is testable directly.
//! Each path carries a driver slot, the type parameter `D`, for the state the
//! host's transport driver keeps per path, such as a connected socket. The
//! set makes a path's slot with `D::default()` when it admits the path, and
//! never reads, changes or drops one: a rule that discards a path hands it
//! back, and one that leaves a path's slot aimed at an old address says so,
//! so the caller disposes of both.
//! State transitions (probing, acking, going Suspect or Dead) are driven by
//! the path probe exchange in the machine, [`super::Bundle`]; this module
//! only records them, and only the path module may record a state.

use super::live::Liveness;
use crate::time::Instant;
use crate::transport::{TransportAddr, TransportId};
use alloc::vec::Vec;

/// Most paths a node holds to one peer (multipath v1 draft, Appendix A).
pub const PATH_MAX_PER_PEER: usize = 8;

/// Most paths a node holds to one peer on one local transport (Appendix A).
pub const PATH_MAX_PER_TRANSPORT: usize = 4;

/// The medium a path's local transport runs over, as the host knows it:
/// the set's limits depend on whether it is a BLE binding, and the choice
/// of the active path on how fast a known medium is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Medium {
    /// A BLE binding: it holds at most one path to a peer (FRC-1301 Section
    /// 6.5.4 keeps one verified BLE channel to a node per binding).
    Ble,
    /// A cable: up to `PATH_MAX_PER_TRANSPORT` paths to a peer.
    Wired,
    /// A wireless network other than BLE, such as Wi-Fi: up to
    /// `PATH_MAX_PER_TRANSPORT` paths to a peer.
    Wireless,
    /// A medium the host does not know: up to `PATH_MAX_PER_TRANSPORT`
    /// paths to a peer.
    Unknown,
}

impl Medium {
    /// Most paths a transport of this kind holds to one peer.
    fn limit(self) -> usize {
        match self {
            Medium::Ble => 1,
            Medium::Wired | Medium::Wireless | Medium::Unknown => PATH_MAX_PER_TRANSPORT,
        }
    }
}

/// Where a path stands (multipath v1 draft, Section 5.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathState {
    /// Created, not yet proven in our direction by an answered probe.
    Probing,
    /// Proven and in use.
    Live,
    /// Was Live; its recent probes have gone unanswered.
    Suspect,
    /// Given up on. Still held, and still counted toward the limits, until
    /// it is evicted to make room.
    Dead,
}

/// One path to a peer: a local transport and the peer's address on it.
///
/// Everything that is per session (the epochs, their keys, indices and
/// key-epoch bits) stays in the peer's link rekey machine; a path carries
/// only what is bound to the medium it runs over, plus its multipath
/// identity and state. `I` is the host clock's instant type and `D` the
/// driver slot.
#[derive(Debug)]
pub struct PeerPath<I, D> {
    /// The transport instance this path runs over.
    transport_id: TransportId,
    /// The peer's current address on that transport.
    addr: TransportAddr,
    /// Our identifier for this path: random, never 0, unique in the set,
    /// stable for the path's life.
    path_id: u32,
    /// The peer's identifier for this path, once learned.
    peer_id: Option<u32>,
    /// Where the path stands.
    state: PathState,
    /// Whether one of our probes on this path has been answered in this
    /// link. The original path counts as acked from the handshake.
    acked: bool,
    /// When the path last became Dead; `None` while it is not Dead.
    dead_since: Option<I>,
    /// The path's probes and what their answers measured.
    live: Liveness<I>,
    /// The host driver's state for this path. The set never reads it.
    driver: D,
}

impl<I: Instant, D: Default> PeerPath<I, D> {
    fn new(transport_id: TransportId, addr: TransportAddr, path_id: u32) -> Self {
        Self {
            transport_id,
            addr,
            path_id,
            peer_id: None,
            state: PathState::Probing,
            acked: false,
            dead_since: None,
            live: Liveness::new(),
            driver: D::default(),
        }
    }

    /// The path's probes and what their answers measured.
    pub fn live(&self) -> &Liveness<I> {
        &self.live
    }

    /// The path's liveness, for the machine to change.
    pub(super) fn live_mut(&mut self) -> &mut Liveness<I> {
        &mut self.live
    }

    /// The path's driver slot, as the path is handed back.
    pub(super) fn into_driver(self) -> D {
        self.driver
    }

    /// The path's driver slot, replaced by a fresh one, as the path's
    /// address moves and the old slot may still aim at the old address.
    pub(super) fn take_driver(&mut self) -> D {
        core::mem::take(&mut self.driver)
    }

    /// The transport instance this path runs over.
    pub fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    /// The peer's current address on this path.
    pub fn addr(&self) -> &TransportAddr {
        &self.addr
    }

    /// Our identifier for this path.
    pub fn path_id(&self) -> u32 {
        self.path_id
    }

    /// The peer's identifier for this path, if it has been learned.
    pub fn peer_id(&self) -> Option<u32> {
        self.peer_id
    }

    /// Where the path stands.
    pub fn state(&self) -> PathState {
        self.state
    }

    /// Whether the path has been acked in this link.
    pub fn acked(&self) -> bool {
        self.acked
    }

    /// When the path last became Dead, if it is Dead.
    pub fn dead_since(&self) -> Option<I> {
        self.dead_since
    }

    fn is(&self, transport_id: TransportId, addr: &TransportAddr) -> bool {
        self.transport_id == transport_id && &self.addr == addr
    }

    /// The host driver's state for this path.
    pub fn driver(&self) -> &D {
        &self.driver
    }

    /// The host driver's state for this path, to change.
    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }

    /// This path as the original path of a new link on the same pair:
    /// identified by `path_id`, Live and acked, its peer's identifier
    /// unknown, its liveness started again but for its count of failed
    /// frames, and its driver slot kept.
    pub(super) fn reborn(self, path_id: u32) -> Self {
        let mut live = Liveness::new();
        live.inherit(self.live.fails());
        Self {
            path_id,
            peer_id: None,
            state: PathState::Live,
            acked: true,
            dead_since: None,
            live,
            ..self
        }
    }

    /// The original path of a new link at (`transport_id`, `addr`), a pair
    /// the old link's active path was not on: identified by `path_id`, Live
    /// and acked, with no failed frame counted and a driver slot of its own.
    pub(super) fn original(transport_id: TransportId, addr: TransportAddr, path_id: u32) -> Self {
        Self::new(transport_id, addr, path_id).reborn(path_id)
    }
}

/// How [`PathSet::admit`] placed a path.
#[derive(Debug)]
pub enum Admission<I, D> {
    /// The pair was already held; this is its index.
    Known(usize),
    /// A new path was added at `index`. `evicted` is the Dead path that
    /// was discarded to make room for it, if one was.
    Added {
        index: usize,
        evicted: Option<PeerPath<I, D>>,
    },
}

impl<I, D> Admission<I, D> {
    /// The index of the admitted path, new or known.
    pub fn index(&self) -> usize {
        match self {
            Admission::Known(index) | Admission::Added { index, .. } => *index,
        }
    }
}

/// Why [`PathSet::admit`] refused a path: the limit that is full, with no
/// Dead path counting toward it that may be discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathRefused {
    /// The new path's transport holds as many paths as its kind allows:
    /// `PATH_MAX_PER_TRANSPORT`, or one on a BLE binding.
    TransportFull,
    /// `PATH_MAX_PER_PEER` paths are held to the peer.
    PeerFull,
}

/// What [`PathSet::rebind`] did with the pair it was asked to send on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rebind {
    /// The pair is already the active path's; nothing changed.
    Unchanged,
    /// The pair's path is now the active one: a path already held and
    /// acked, or the set's first path, bound as the link's original.
    Switched,
    /// The active path is unchanged and the pair's path is not active. A
    /// pair held but not yet acked stays as it is until one of our probes on
    /// it is answered; a pair not held is admitted as a new path in the
    /// Probing state, to be probed and acked before it can carry the link;
    /// or a limit refused it, and it is not held at all.
    Refused,
}

/// What a (transport, address) pair is to the set, for a caller asking
/// whether a frame from that pair came over one of the peer's paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Match {
    /// A held path that is Live or that one of our probes on it has had
    /// answered in this link (the original path is both), in whatever state
    /// it is now. `active` says whether it is the path our frames go out on,
    /// which is always a proven one.
    Proven { active: bool, state: PathState },
    /// A held path that is neither Live nor acked: still Probing, or Suspect
    /// or Dead without one of our probes on it ever answered.
    Unproven,
    /// The set holds no path with this pair.
    None,
}

/// What [`PathSet::roam`] did on an authentic frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Roam {
    /// No address moved and no path was bound.
    Unmoved,
    /// The set held no path; the frame's pair is now the link's original
    /// path, Live, acked and active.
    Bound,
    /// The active path's address moved inside its transport. `from` is the
    /// pair the peer left.
    Roamed { from: (TransportId, TransportAddr) },
    /// The path at `index`, which is not active, moved its address. Its
    /// driver slot may still aim at the old address.
    Standby { index: usize },
}

impl Roam {
    /// Whether the address our frames go to changed: the set's first path
    /// was bound, or the active path roamed.
    pub fn changed(&self) -> bool {
        matches!(self, Roam::Bound | Roam::Roamed { .. })
    }

    /// The pair the peer left: the active path's old pair after a roam, and
    /// `None` for every other result, a first bind included.
    pub fn left(self) -> Option<(TransportId, TransportAddr)> {
        match self {
            Roam::Roamed { from } => Some(from),
            Roam::Unmoved | Roam::Bound | Roam::Standby { .. } => None,
        }
    }
}

/// The paths to one peer, and which of them our frames go out on. `I` is
/// the host clock's instant type and `D` each path's driver slot.
#[derive(Debug)]
pub struct PathSet<I, D> {
    paths: Vec<PeerPath<I, D>>,
    /// Index into `paths` of the path our frames go out on.
    active: Option<usize>,
}

// Not derived: a derive would ask for `I: Default`, which no instant needs.
impl<I, D> Default for PathSet<I, D> {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            active: None,
        }
    }
}

impl<I: Instant, D: Default> PathSet<I, D> {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// A set of the one path `path`, active: the original path of a link
    /// started again on it.
    pub(super) fn holding(path: PeerPath<I, D>) -> Self {
        Self {
            paths: alloc::vec![path],
            active: Some(0),
        }
    }

    /// Every path held, in admission order.
    pub fn paths(&self) -> &[PeerPath<I, D>] {
        &self.paths
    }

    /// Number of paths held, Dead ones included.
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Whether no path is held.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// The path at `index`.
    pub fn get(&self, index: usize) -> Option<&PeerPath<I, D>> {
        self.paths.get(index)
    }

    /// Index of the path our frames go out on.
    pub fn active_index(&self) -> Option<usize> {
        self.active
    }

    /// The path our frames go out on.
    pub fn active(&self) -> Option<&PeerPath<I, D>> {
        self.active.and_then(|i| self.paths.get(i))
    }

    /// The path our frames go out on, to reach its driver slot, the one
    /// per-path state only the host changes.
    pub fn active_mut(&mut self) -> Option<&mut PeerPath<I, D>> {
        self.active.and_then(|i| self.paths.get_mut(i))
    }

    /// The path at `index`, to reach the driver slot of a path that is not
    /// active.
    pub fn path_mut(&mut self, index: usize) -> Option<&mut PeerPath<I, D>> {
        self.paths.get_mut(index)
    }

    /// Index of the path with this (transport, address) pair.
    pub fn find(&self, transport_id: TransportId, addr: &TransportAddr) -> Option<usize> {
        self.paths.iter().position(|p| p.is(transport_id, addr))
    }

    /// What (`transport_id`, `addr`) is to the set: see [`Match`]. The active
    /// path always answers `Proven { active: true, .. }`, since a path is
    /// acked when it is bound and only an acked path becomes active.
    pub fn classify(&self, transport_id: TransportId, addr: &TransportAddr) -> Match {
        let Some(index) = self.find(transport_id, addr) else {
            return Match::None;
        };
        let path = &self.paths[index];
        if path.acked || path.state == PathState::Live {
            Match::Proven {
                active: self.active == Some(index),
                state: path.state,
            }
        } else {
            Match::Unproven
        }
    }

    /// Index of the path on `transport_id` that the peer calls `peer_id`.
    pub fn find_by_peer(&self, transport_id: TransportId, peer_id: u32) -> Option<usize> {
        self.paths
            .iter()
            .position(|p| p.transport_id == transport_id && p.peer_id == Some(peer_id))
    }

    /// Record the peer's identifier for the path at `index`. An identifier
    /// of 0 is never learned (multipath v1 draft, Section 5.1). Returns
    /// whether it was recorded.
    pub fn learn_peer(&mut self, index: usize, peer_id: u32) -> bool {
        if peer_id == 0 {
            return false;
        }
        match self.paths.get_mut(index) {
            Some(path) => {
                path.peer_id = Some(peer_id);
                true
            }
            None => false,
        }
    }

    /// The machine's transition entry: record that the path at `index` is
    /// now in `state`. Entering Dead stamps `now`, an instant of the host
    /// clock, as its Dead time; leaving Dead clears it.
    pub(super) fn transition(&mut self, index: usize, state: PathState, now: I) {
        if let Some(path) = self.paths.get_mut(index) {
            if state == PathState::Dead {
                if path.state != PathState::Dead {
                    path.dead_since = Some(now);
                }
            } else {
                path.dead_since = None;
            }
            path.state = state;
        }
    }

    /// Mark the path at `index` Dead at `now`, for the root crate's tests
    /// that need a held path given up on.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn mark_dead(&mut self, index: usize, now: I) {
        self.transition(index, PathState::Dead, now);
    }

    /// Move the path at `index` to the peer's address `addr` on its
    /// transport, as an authenticated path message from that address allows
    /// (multipath v1 draft, Section 5.3). Returns the address it left, or
    /// `None` when another path holds the pair, since two paths never share
    /// one, or when there is no such path or it is already there.
    pub(super) fn readdress(&mut self, index: usize, addr: TransportAddr) -> Option<TransportAddr> {
        let transport_id = self.paths.get(index)?.transport_id;
        if self.find(transport_id, &addr).is_some() {
            return None;
        }
        let path = self.paths.get_mut(index)?;
        Some(core::mem::replace(&mut path.addr, addr))
    }

    /// Remove the path at `index` and hand it back, keeping the active
    /// index on the path it named; removing the active path leaves the set
    /// with none.
    pub(super) fn discard(&mut self, index: usize) -> Option<PeerPath<I, D>> {
        (index < self.paths.len()).then(|| self.remove(index))
    }

    /// Make the path at `index` the one our frames go out on. Only an
    /// acked path carries the link, so any other is refused. Returns
    /// whether the path at `index` is active now.
    pub(super) fn activate(&mut self, index: usize) -> bool {
        if !self.paths.get(index).is_some_and(|p| p.acked) {
            return false;
        }
        self.active = Some(index);
        true
    }

    /// Every path, in set order, as the set is closed.
    pub(super) fn into_paths(self) -> Vec<PeerPath<I, D>> {
        self.paths
    }

    /// Record that one of our probes on the path at `index` was answered.
    pub fn mark_acked(&mut self, index: usize) {
        if let Some(path) = self.paths.get_mut(index) {
            path.acked = true;
        }
    }

    /// Admit the path (`transport_id`, `addr`), in the Probing state.
    ///
    /// A pair already held is returned as it is. Otherwise both limits of
    /// the multipath v1 draft (Section 5.1) apply, Dead paths counted, with
    /// the per-transport limit one when `medium` is a BLE binding. When
    /// a limit is full, room is made by discarding a Dead path that counts
    /// toward every full limit: one on the new path's transport when the
    /// per-transport limit is full, any one when only the per-peer limit
    /// is. A never-acked Dead path goes first, then the acked one Dead
    /// longest; the last acked Dead path is kept while no path is Live, and
    /// the active path is never discarded. With nothing to discard, the
    /// path is refused.
    ///
    /// `ids` draws candidate path identifiers; draws of 0 or of an
    /// identifier already in the set are skipped. Production passes
    /// `rand::random`.
    pub fn admit(
        &mut self,
        transport_id: TransportId,
        addr: TransportAddr,
        medium: Medium,
        mut ids: impl FnMut() -> u32,
    ) -> Result<Admission<I, D>, PathRefused> {
        if let Some(index) = self.find(transport_id, &addr) {
            return Ok(Admission::Known(index));
        }
        let evicted = self.make_room(transport_id, medium)?;
        let path_id = self.fresh_id(&mut ids);
        self.paths.push(PeerPath::new(transport_id, addr, path_id));
        Ok(Admission::Added {
            index: self.paths.len() - 1,
            evicted,
        })
    }

    /// Discard a Dead path if a limit is full; refuse if none may go.
    fn make_room(
        &mut self,
        transport_id: TransportId,
        medium: Medium,
    ) -> Result<Option<PeerPath<I, D>>, PathRefused> {
        let on_transport = self
            .paths
            .iter()
            .filter(|p| p.transport_id == transport_id)
            .count();
        let transport_full = on_transport >= medium.limit();
        let peer_full = self.paths.len() >= PATH_MAX_PER_PEER;
        if !transport_full && !peer_full {
            return Ok(None);
        }
        let refused = if transport_full {
            PathRefused::TransportFull
        } else {
            PathRefused::PeerFull
        };
        let victim = self.eviction_candidate(transport_full.then_some(transport_id));
        let index = victim.ok_or(refused)?;
        Ok(Some(self.remove(index)))
    }

    /// The Dead path to discard, restricted to `only_on` when the
    /// per-transport limit is the one that must be relieved.
    fn eviction_candidate(&self, only_on: Option<TransportId>) -> Option<usize> {
        let any_live = self.paths.iter().any(|p| p.state == PathState::Live);
        let acked_dead = self
            .paths
            .iter()
            .filter(|p| p.state == PathState::Dead && p.acked)
            .count();
        self.paths
            .iter()
            .enumerate()
            .filter(|(i, p)| {
                p.state == PathState::Dead
                    && Some(*i) != self.active
                    && only_on.is_none_or(|t| p.transport_id == t)
                    && !(p.acked && !any_live && acked_dead == 1)
            })
            // Never-acked before acked; then the one Dead longest.
            .min_by_key(|(_, p)| (p.acked, p.dead_since))
            .map(|(i, _)| i)
    }

    /// Remove the path at `index`, keeping `active` pointing at the same
    /// path, or at none when it is the one removed.
    fn remove(&mut self, index: usize) -> PeerPath<I, D> {
        let path = self.paths.remove(index);
        self.active = match self.active {
            Some(a) if a > index => Some(a - 1),
            Some(a) if a == index => None,
            other => other,
        };
        path
    }

    /// A path identifier that is not 0 and not used in the set.
    fn fresh_id(&self, ids: &mut impl FnMut() -> u32) -> u32 {
        loop {
            let id = ids();
            if id != 0 && !self.paths.iter().any(|p| p.path_id == id) {
                return id;
            }
        }
    }

    /// Move the peer's address on receipt of an authentic frame from
    /// (`transport_id`, `addr`).
    ///
    /// A set with no path binds the pair as the link's original path, as
    /// [`bind_original`](Self::bind_original) does, drawing its identifier
    /// from `ids`. With one path, the frame roams that path's address inside
    /// its transport, as FMP v1 does; a frame on another transport moves
    /// nothing. With more than one path, no frame moves an address: only an
    /// authenticated path probe or matching ack may (multipath v1 draft,
    /// Section 5.3). The result says which of these happened, with the pair
    /// the peer left when the active path roamed, and the index of a path
    /// that is not active when it is that path that roamed, so the caller
    /// can release that path's stale driver slot.
    pub fn roam(
        &mut self,
        transport_id: TransportId,
        addr: TransportAddr,
        ids: impl FnMut() -> u32,
    ) -> Roam {
        if self.paths.is_empty() {
            return match self.bind(transport_id, addr, Medium::Unknown, ids) {
                Ok(evicted) => {
                    debug_assert!(evicted.is_none(), "an empty set has nothing to evict");
                    Roam::Bound
                }
                Err(_) => Roam::Unmoved,
            };
        }
        if self.paths.len() != 1 {
            return Roam::Unmoved;
        }
        let path = &mut self.paths[0];
        if path.transport_id != transport_id || path.addr == addr {
            return Roam::Unmoved;
        }
        let from = core::mem::replace(&mut path.addr, addr);
        if self.active == Some(0) {
            Roam::Roamed {
                from: (transport_id, from),
            }
        } else {
            Roam::Standby { index: 0 }
        }
    }

    /// Ask for our frames to go out on (`transport_id`, `addr`).
    ///
    /// A path is identified by its pair (multipath v1 draft, Section 5.1),
    /// so no path is ever re-pointed onto a new address. If the pair is held
    /// and acked, its path becomes active; a held pair not yet acked is
    /// refused, since a path carries the link only once one of our probes on
    /// it has been answered (Section 5.6). With no active path, the pair is
    /// bound as the link's original path. Otherwise the pair is admitted as
    /// a new Probing path, under the limits and eviction order of
    /// [`admit`](Self::admit), and the active path stays as it is until the
    /// new one has been probed and acked. The result tells a switch from a
    /// no-op and from a refusal; beside it is the Dead path discarded to make
    /// room for the pair, if one was, for the caller to dispose of. `medium`
    /// is the kind of `transport_id`.
    pub fn rebind(
        &mut self,
        transport_id: TransportId,
        addr: TransportAddr,
        medium: Medium,
        ids: impl FnMut() -> u32,
    ) -> (Rebind, Option<PeerPath<I, D>>) {
        if self.active().is_some_and(|p| p.is(transport_id, &addr)) {
            return (Rebind::Unchanged, None);
        }
        if let Some(index) = self.find(transport_id, &addr) {
            if !self.paths[index].acked {
                return (Rebind::Refused, None);
            }
            self.active = Some(index);
            return (Rebind::Switched, None);
        }
        if self.active.is_none() {
            return match self.bind(transport_id, addr, medium, ids) {
                Ok(evicted) => (Rebind::Switched, evicted),
                Err(_) => (Rebind::Refused, None),
            };
        }
        // Admitted or refused by a limit, the pair does not become active.
        let evicted = match self.admit(transport_id, addr, medium, ids) {
            Ok(Admission::Added { evicted, .. }) => evicted,
            Ok(Admission::Known(_)) | Err(_) => None,
        };
        (Rebind::Refused, evicted)
    }

    /// Admit the link's original path: Live and acked from the handshake
    /// (multipath v1 draft, Section 5.6), and active. Returns the Dead path
    /// discarded to make room, if one was, or the limit that refused it.
    ///
    /// The transport's kind is not asked for: production binds the original
    /// path only into an empty set (at promotion through this method, and
    /// for a peer's first authentic frame through [`roam`](Self::roam)),
    /// where no limit can bind.
    pub fn bind_original(
        &mut self,
        transport_id: TransportId,
        addr: TransportAddr,
        ids: impl FnMut() -> u32,
    ) -> Result<Option<PeerPath<I, D>>, PathRefused> {
        self.bind(transport_id, addr, Medium::Unknown, ids)
    }

    /// Admit (`transport_id`, `addr`) on a transport of kind `medium` as the
    /// link's original path: Live, acked and active. Returns the Dead path
    /// discarded to make room, if one was.
    fn bind(
        &mut self,
        transport_id: TransportId,
        addr: TransportAddr,
        medium: Medium,
        ids: impl FnMut() -> u32,
    ) -> Result<Option<PeerPath<I, D>>, PathRefused> {
        let admission = self.admit(transport_id, addr, medium, ids)?;
        let index = admission.index();
        let path = &mut self.paths[index];
        path.state = PathState::Live;
        path.dead_since = None;
        path.acked = true;
        self.active = Some(index);
        Ok(match admission {
            Admission::Added { evicted, .. } => evicted,
            Admission::Known(_) => None,
        })
    }
}

#[cfg(test)]
#[path = "tests/set.rs"]
mod tests;
