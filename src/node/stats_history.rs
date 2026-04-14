//! Time-series history of node-level and per-peer statistics.
//!
//! Maintains a fast ring (1s × 3600 = 1h) and a slow ring (1m × 1440 = 24h)
//! per metric, in daemon memory. Used by the control socket
//! `show_stats_history` family and rendered as sparklines / braille plots
//! by `fipsctl` and `fipstop`. Lost on restart.
//!
//! Storage is split between node-level metrics (one ring per metric) and
//! per-peer metrics (one map `NodeAddr -> PeerStatsRings`, each holding
//! one ring per per-peer metric). Per-peer rings are back-filled with
//! NaN on first sight so every peer shares the same time axis with the
//! node-level rings. When a peer is absent from a tick, NaN is appended
//! to keep alignment. Peers are evicted once they have been absent from
//! every tick in the full 24h slow-ring window.
//!
//! Gap representation: `f64::NAN` for any sample where data is not
//! available (new peer back-fill, disconnected peer, MMP not yet
//! established, counter reset on link reconnect). NaN is serialized as
//! JSON `null` via a custom serializer.

use crate::identity::NodeAddr;
use serde::{Serialize, Serializer};
use std::collections::{HashMap, HashSet, VecDeque};
use std::str::FromStr;
use std::time::{Duration, Instant};

/// Fast-ring capacity: 3600 seconds = 1 hour at 1s resolution.
pub const FAST_RING_CAPACITY: usize = 3600;

/// Slow-ring capacity: 1440 minutes = 24 hours at 1m resolution.
pub const SLOW_RING_CAPACITY: usize = 1440;

/// Downsample window: how many fast samples fold into one slow sample.
pub const DOWNSAMPLE_FACTOR: usize = 60;

/// Evict peers that have been silent for at least this long.
pub const PEER_EVICTION_SECS: u64 = 24 * 3600;

/// Node-level metrics tracked in the history. Keep this list in sync
/// with `ALL_METRICS` and with the snapshot construction in
/// [`StatsHistory::tick`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Metric {
    MeshSize,
    TreeDepth,
    PeerCount,
    ParentSwitches,
    BytesIn,
    BytesOut,
    PacketsIn,
    PacketsOut,
    LossRate,
    ActiveSessions,
}

/// Every node-level metric tracked, in a stable order (for enumeration
/// via `stats list` and for Graphs-tab cycling).
pub const ALL_METRICS: &[Metric] = &[
    Metric::MeshSize,
    Metric::TreeDepth,
    Metric::PeerCount,
    Metric::ParentSwitches,
    Metric::BytesIn,
    Metric::BytesOut,
    Metric::PacketsIn,
    Metric::PacketsOut,
    Metric::LossRate,
    Metric::ActiveSessions,
];

/// Per-peer metrics tracked in the history (one ring per metric, per peer).
/// Names collide with some `Metric` variants because the two live in
/// separate namespaces on the wire — a query is per-peer iff `peer` is
/// specified in the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerMetric {
    SrttMs,
    LossRate,
    BytesIn,
    BytesOut,
    PacketsIn,
    PacketsOut,
    EcnCe,
}

pub const ALL_PEER_METRICS: &[PeerMetric] = &[
    PeerMetric::SrttMs,
    PeerMetric::LossRate,
    PeerMetric::BytesIn,
    PeerMetric::BytesOut,
    PeerMetric::PacketsIn,
    PeerMetric::PacketsOut,
    PeerMetric::EcnCe,
];

/// How a metric reduces a window of fast samples into one slow sample.
/// NaN samples are excluded from all reductions; a window of entirely
/// NaN samples produces NaN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Aggregation {
    /// Keep the last non-NaN value.
    Last,
    /// Sum non-NaN values.
    Sum,
    /// Mean of non-NaN values.
    Mean,
}

impl Metric {
    pub fn name(self) -> &'static str {
        match self {
            Metric::MeshSize => "mesh_size",
            Metric::TreeDepth => "tree_depth",
            Metric::PeerCount => "peer_count",
            Metric::ParentSwitches => "parent_switches",
            Metric::BytesIn => "bytes_in",
            Metric::BytesOut => "bytes_out",
            Metric::PacketsIn => "packets_in",
            Metric::PacketsOut => "packets_out",
            Metric::LossRate => "loss_rate",
            Metric::ActiveSessions => "active_sessions",
        }
    }

    pub fn unit(self) -> &'static str {
        match self {
            Metric::MeshSize => "nodes",
            Metric::TreeDepth => "hops",
            Metric::PeerCount => "peers",
            Metric::ParentSwitches => "events/s",
            Metric::BytesIn | Metric::BytesOut => "bytes/s",
            Metric::PacketsIn | Metric::PacketsOut => "packets/s",
            Metric::LossRate => "fraction",
            Metric::ActiveSessions => "sessions",
        }
    }

    pub fn aggregation(self) -> Aggregation {
        match self {
            Metric::MeshSize | Metric::TreeDepth | Metric::PeerCount | Metric::ActiveSessions => {
                Aggregation::Last
            }
            Metric::ParentSwitches => Aggregation::Sum,
            Metric::BytesIn
            | Metric::BytesOut
            | Metric::PacketsIn
            | Metric::PacketsOut
            | Metric::LossRate => Aggregation::Mean,
        }
    }
}

impl FromStr for Metric {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for m in ALL_METRICS {
            if m.name() == s {
                return Ok(*m);
            }
        }
        Err(format!("unknown metric: {s}"))
    }
}

impl PeerMetric {
    pub fn name(self) -> &'static str {
        match self {
            PeerMetric::SrttMs => "srtt_ms",
            PeerMetric::LossRate => "loss_rate",
            PeerMetric::BytesIn => "bytes_in",
            PeerMetric::BytesOut => "bytes_out",
            PeerMetric::PacketsIn => "packets_in",
            PeerMetric::PacketsOut => "packets_out",
            PeerMetric::EcnCe => "ecn_ce",
        }
    }

    pub fn unit(self) -> &'static str {
        match self {
            PeerMetric::SrttMs => "ms",
            PeerMetric::LossRate => "fraction",
            PeerMetric::BytesIn | PeerMetric::BytesOut => "bytes/s",
            PeerMetric::PacketsIn | PeerMetric::PacketsOut => "packets/s",
            PeerMetric::EcnCe => "events/s",
        }
    }

    pub fn aggregation(self) -> Aggregation {
        match self {
            PeerMetric::SrttMs => Aggregation::Mean,
            PeerMetric::LossRate => Aggregation::Mean,
            PeerMetric::BytesIn
            | PeerMetric::BytesOut
            | PeerMetric::PacketsIn
            | PeerMetric::PacketsOut => Aggregation::Mean,
            PeerMetric::EcnCe => Aggregation::Sum,
        }
    }

    /// Whether this metric is derived from a monotonic counter (sample =
    /// delta per tick, reset to NaN if the counter decreases).
    pub fn is_counter(self) -> bool {
        matches!(
            self,
            PeerMetric::BytesIn
                | PeerMetric::BytesOut
                | PeerMetric::PacketsIn
                | PeerMetric::PacketsOut
                | PeerMetric::EcnCe
        )
    }
}

impl FromStr for PeerMetric {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for m in ALL_PEER_METRICS {
            if m.name() == s {
                return Ok(*m);
            }
        }
        Err(format!("unknown peer metric: {s}"))
    }
}

/// Snapshot of raw node-level counter state used to derive per-tick
/// samples. Produced by `Node` and passed into [`StatsHistory::tick`].
#[derive(Clone, Copy, Debug)]
pub struct Snapshot {
    pub mesh_size: Option<u64>,
    pub tree_depth: u32,
    pub peer_count: u64,
    pub parent_switches_total: u64,
    pub bytes_in_total: u64,
    pub bytes_out_total: u64,
    pub packets_in_total: u64,
    pub packets_out_total: u64,
    pub loss_rate: f64,
    pub active_sessions: u64,
}

/// Snapshot of one peer's state at the current tick. An entry missing
/// from the `peers` slice of [`StatsHistory::tick`] is treated as "peer
/// absent this tick" and backs NaN into each of its rings.
#[derive(Clone, Debug)]
pub struct PeerSnapshot {
    pub node_addr: NodeAddr,
    pub last_seen: Instant,
    /// MMP SRTT; `None` when no MMP measurement exists yet.
    pub srtt_ms: Option<f64>,
    /// MMP loss rate; `None` when the peer has no MMP session yet.
    pub loss_rate: Option<f64>,
    /// Monotonic counters. May decrease when the peer reconnects on a
    /// new link (fresh LinkStats); that's detected per-ring and emits
    /// NaN for the affected tick.
    pub bytes_in_total: u64,
    pub bytes_out_total: u64,
    pub packets_in_total: u64,
    pub packets_out_total: u64,
    pub ecn_ce_total: u64,
}

/// Which ring a query reads from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Granularity {
    /// 1-second samples from the fast ring.
    Fast,
    /// 1-minute samples from the slow ring.
    Slow,
}

impl Granularity {
    pub fn seconds(self) -> u64 {
        match self {
            Granularity::Fast => 1,
            Granularity::Slow => 60,
        }
    }
}

impl FromStr for Granularity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "1s" => Ok(Granularity::Fast),
            "1m" => Ok(Granularity::Slow),
            other => Err(format!("unknown granularity: {other} (expected 1s or 1m)")),
        }
    }
}

/// One metric's dual-tier ring.
struct Ring {
    fast: VecDeque<f64>,
    slow: VecDeque<f64>,
    /// Accumulator used for downsampling fast → slow on minute boundaries.
    accum: DownsampleAccum,
    aggregation: Aggregation,
    /// Value from the previous tick, used to derive deltas for counter
    /// metrics. `None` means "first sample upcoming" and produces NaN.
    prev_total: Option<u64>,
}

/// Running accumulator over up to `DOWNSAMPLE_FACTOR` fast samples.
/// NaN samples are skipped from all statistics; `total` still tracks
/// them so we know whether ANY sample arrived this window.
struct DownsampleAccum {
    sum: f64,
    /// Count of non-NaN samples.
    count: u32,
    /// Most recent non-NaN sample, or NaN if none.
    last: f64,
    /// Total samples observed (including NaN).
    total: u32,
}

impl DownsampleAccum {
    fn new() -> Self {
        Self {
            sum: 0.0,
            count: 0,
            last: f64::NAN,
            total: 0,
        }
    }

    fn push(&mut self, v: f64) {
        self.total += 1;
        if !v.is_nan() {
            self.sum += v;
            self.count += 1;
            self.last = v;
        }
    }

    fn reduce(&self, agg: Aggregation) -> Option<f64> {
        if self.total == 0 {
            return None;
        }
        if self.count == 0 {
            return Some(f64::NAN);
        }
        Some(match agg {
            Aggregation::Last => self.last,
            Aggregation::Sum => self.sum,
            Aggregation::Mean => self.sum / self.count as f64,
        })
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Ring {
    fn new(aggregation: Aggregation) -> Self {
        Self {
            fast: VecDeque::with_capacity(FAST_RING_CAPACITY),
            slow: VecDeque::with_capacity(SLOW_RING_CAPACITY),
            accum: DownsampleAccum::new(),
            aggregation,
            prev_total: None,
        }
    }

    fn push_fast(&mut self, value: f64) {
        if self.fast.len() == FAST_RING_CAPACITY {
            self.fast.pop_front();
        }
        self.fast.push_back(value);
        self.accum.push(value);
    }

    fn flush_slow(&mut self) {
        if let Some(v) = self.accum.reduce(self.aggregation) {
            if self.slow.len() == SLOW_RING_CAPACITY {
                self.slow.pop_front();
            }
            self.slow.push_back(v);
        }
        self.accum.reset();
    }
}

/// Helper: convert a monotonic counter into a per-tick delta. Returns
/// NaN when no previous sample exists (first observation) or when the
/// counter decreased (new link). Updates `prev_total` on every call so
/// the next tick's baseline is the current value.
fn delta_or_nan(ring: &mut Ring, total: u64) -> f64 {
    let prev = ring.prev_total;
    ring.prev_total = Some(total);
    match prev {
        None => f64::NAN,
        Some(p) if total < p => f64::NAN,
        Some(p) => (total - p) as f64,
    }
}

/// Custom serializer: NaN / infinity → JSON `null`; finite values pass
/// through as numbers.
fn serialize_nan_as_null<S: Serializer>(values: &[f64], s: S) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let mut seq = s.serialize_seq(Some(values.len()))?;
    for &v in values {
        if v.is_finite() {
            seq.serialize_element(&v)?;
        } else {
            seq.serialize_element(&Option::<f64>::None)?;
        }
    }
    seq.end()
}

/// Query result — a contiguous series of samples newest-last.
/// Gap samples are NaN in memory and `null` in JSON.
#[derive(Clone, Debug, Serialize)]
pub struct Series {
    pub metric: &'static str,
    pub unit: &'static str,
    pub granularity_seconds: u64,
    #[serde(serialize_with = "serialize_nan_as_null")]
    pub values: Vec<f64>,
}

/// One peer's per-metric rings plus lifecycle metadata.
pub struct PeerStatsRings {
    rings: Vec<Ring>,
    first_seen: Instant,
    last_contact: Instant,
}

impl PeerStatsRings {
    fn new(now: Instant, fast_pushes_so_far: u64) -> Self {
        let mut rings: Vec<Ring> = ALL_PEER_METRICS
            .iter()
            .map(|m| Ring::new(m.aggregation()))
            .collect();

        // Back-fill NaN so this peer's rings share a time axis with the
        // node-level rings that have been collecting since start. We
        // fill up to (but not including) the slot this tick will take.
        let n_fast = (fast_pushes_so_far as usize).min(FAST_RING_CAPACITY);
        let n_slow = ((fast_pushes_so_far as usize) / DOWNSAMPLE_FACTOR).min(SLOW_RING_CAPACITY);
        for ring in &mut rings {
            for _ in 0..n_fast {
                ring.fast.push_back(f64::NAN);
            }
            for _ in 0..n_slow {
                ring.slow.push_back(f64::NAN);
            }
        }

        Self {
            rings,
            first_seen: now,
            last_contact: now,
        }
    }

    fn ring(&self, metric: PeerMetric) -> &Ring {
        let idx = ALL_PEER_METRICS.iter().position(|m| *m == metric).unwrap();
        &self.rings[idx]
    }

    fn ring_mut(&mut self, metric: PeerMetric) -> &mut Ring {
        let idx = ALL_PEER_METRICS.iter().position(|m| *m == metric).unwrap();
        &mut self.rings[idx]
    }

    fn push_sample(&mut self, snap: &PeerSnapshot, now: Instant) {
        self.last_contact = now;
        for &metric in ALL_PEER_METRICS {
            let value = match metric {
                PeerMetric::SrttMs => snap.srtt_ms.unwrap_or(f64::NAN),
                PeerMetric::LossRate => snap.loss_rate.unwrap_or(f64::NAN),
                PeerMetric::BytesIn => delta_or_nan(self.ring_mut(metric), snap.bytes_in_total),
                PeerMetric::BytesOut => delta_or_nan(self.ring_mut(metric), snap.bytes_out_total),
                PeerMetric::PacketsIn => delta_or_nan(self.ring_mut(metric), snap.packets_in_total),
                PeerMetric::PacketsOut => {
                    delta_or_nan(self.ring_mut(metric), snap.packets_out_total)
                }
                PeerMetric::EcnCe => delta_or_nan(self.ring_mut(metric), snap.ecn_ce_total),
            };
            self.ring_mut(metric).push_fast(value);
        }
    }

    /// Push NaN for every ring (peer was absent this tick). Also clears
    /// the counter baseline so the next real sample produces NaN rather
    /// than an inflated delta accumulated over the silence.
    fn push_nan(&mut self) {
        for (i, ring) in self.rings.iter_mut().enumerate() {
            ring.push_fast(f64::NAN);
            if ALL_PEER_METRICS[i].is_counter() {
                ring.prev_total = None;
            }
        }
    }

    fn flush_slow(&mut self) {
        for ring in &mut self.rings {
            ring.flush_slow();
        }
    }

    pub fn first_seen(&self) -> Instant {
        self.first_seen
    }

    pub fn last_contact(&self) -> Instant {
        self.last_contact
    }
}

/// Per-metric ring storage for node-level metrics plus a map of
/// per-peer rings keyed by `NodeAddr`.
pub struct StatsHistory {
    rings: Vec<Ring>,
    peers: HashMap<NodeAddr, PeerStatsRings>,
    /// Wall-clock anchor for 1-minute downsample boundaries. Set on the
    /// first tick; downsample fires when elapsed since the anchor crosses
    /// a multiple of 60s (coarsely — we just count fast pushes).
    fast_pushes: u64,
    /// Monotonic timestamp of the most recent tick, used by readers that
    /// want to label the series in wall-clock terms.
    last_tick: Option<Instant>,
}

impl StatsHistory {
    pub fn new() -> Self {
        let rings = ALL_METRICS
            .iter()
            .map(|m| Ring::new(m.aggregation()))
            .collect();
        Self {
            rings,
            peers: HashMap::new(),
            fast_pushes: 0,
            last_tick: None,
        }
    }

    fn ring_mut(&mut self, metric: Metric) -> &mut Ring {
        let idx = ALL_METRICS.iter().position(|m| *m == metric).unwrap();
        &mut self.rings[idx]
    }

    fn ring(&self, metric: Metric) -> &Ring {
        let idx = ALL_METRICS.iter().position(|m| *m == metric).unwrap();
        &self.rings[idx]
    }

    /// Record one tick. Should be invoked once per second from the node
    /// event loop, passing the latest snapshot and the set of peers
    /// observed this tick.
    ///
    /// Derives per-second rates from delta on counter totals; gauges
    /// are sampled directly. Every 60 pushes, the accumulator is
    /// flushed to the slow ring. Peers that have been absent for the
    /// full eviction window are dropped from the map.
    pub fn tick(&mut self, now: Instant, snapshot: &Snapshot, peers: &[PeerSnapshot]) {
        // Node-level metrics.
        for &metric in ALL_METRICS {
            let value = match metric {
                Metric::MeshSize => snapshot.mesh_size.unwrap_or(0) as f64,
                Metric::TreeDepth => snapshot.tree_depth as f64,
                Metric::PeerCount => snapshot.peer_count as f64,
                Metric::ParentSwitches => {
                    Self::node_delta(self.ring_mut(metric), snapshot.parent_switches_total)
                }
                Metric::BytesIn => Self::node_delta(self.ring_mut(metric), snapshot.bytes_in_total),
                Metric::BytesOut => {
                    Self::node_delta(self.ring_mut(metric), snapshot.bytes_out_total)
                }
                Metric::PacketsIn => {
                    Self::node_delta(self.ring_mut(metric), snapshot.packets_in_total)
                }
                Metric::PacketsOut => {
                    Self::node_delta(self.ring_mut(metric), snapshot.packets_out_total)
                }
                Metric::LossRate => snapshot.loss_rate,
                Metric::ActiveSessions => snapshot.active_sessions as f64,
            };
            self.ring_mut(metric).push_fast(value);
        }

        // Per-peer metrics.
        let mut seen: HashSet<NodeAddr> = HashSet::with_capacity(peers.len());
        for ps in peers {
            seen.insert(ps.node_addr);
            let entry = self
                .peers
                .entry(ps.node_addr)
                .or_insert_with(|| PeerStatsRings::new(now, self.fast_pushes));
            entry.push_sample(ps, now);
        }
        for (addr, rings) in self.peers.iter_mut() {
            if !seen.contains(addr) {
                rings.push_nan();
            }
        }

        self.fast_pushes += 1;
        if self.fast_pushes.is_multiple_of(DOWNSAMPLE_FACTOR as u64) {
            for ring in &mut self.rings {
                ring.flush_slow();
            }
            for rings in self.peers.values_mut() {
                rings.flush_slow();
            }
        }

        // Evict peers silent for at least PEER_EVICTION_SECS.
        let threshold = Duration::from_secs(PEER_EVICTION_SECS);
        self.peers
            .retain(|_, rings| now.duration_since(rings.last_contact) < threshold);

        self.last_tick = Some(now);
    }

    /// Helper: node-level monotonic counter → per-tick delta. Uses
    /// `saturating_sub` because node totals never reset; the defensive
    /// saturation matches the pre-per-peer behavior.
    fn node_delta(ring: &mut Ring, total: u64) -> f64 {
        let prev = ring.prev_total;
        ring.prev_total = Some(total);
        match prev {
            None => 0.0,
            Some(p) => total.saturating_sub(p) as f64,
        }
    }

    /// Answer a query for a single node-level metric across a given
    /// window and granularity. The returned series always has the full
    /// window width (clipped only to ring capacity); any samples older
    /// than the ring has seen are front-padded with NaN so each window
    /// renders at its chosen density.
    pub fn query(&self, metric: Metric, window: Duration, granularity: Granularity) -> Series {
        let ring = self.ring(metric);
        Self::build_series(ring, metric.name(), metric.unit(), window, granularity)
    }

    /// Answer a query for one peer's metric. Returns `None` if the peer
    /// is not tracked.
    pub fn peer_query(
        &self,
        addr: &NodeAddr,
        metric: PeerMetric,
        window: Duration,
        granularity: Granularity,
    ) -> Option<Series> {
        let rings = self.peers.get(addr)?;
        Some(Self::build_series(
            rings.ring(metric),
            metric.name(),
            metric.unit(),
            window,
            granularity,
        ))
    }

    fn build_series(
        ring: &Ring,
        name: &'static str,
        unit: &'static str,
        window: Duration,
        granularity: Granularity,
    ) -> Series {
        let (source, capacity): (&VecDeque<f64>, usize) = match granularity {
            Granularity::Fast => (&ring.fast, FAST_RING_CAPACITY),
            Granularity::Slow => (&ring.slow, SLOW_RING_CAPACITY),
        };

        let want = (window.as_secs() / granularity.seconds()) as usize;
        let want = want.min(capacity);
        let take = source.len().min(want);
        let tail: Vec<f64> = source.iter().rev().take(take).rev().copied().collect();
        let values = if tail.len() < want {
            let pad = want - tail.len();
            let mut out = Vec::with_capacity(want);
            out.resize(pad, f64::NAN);
            out.extend(tail);
            out
        } else {
            tail
        };

        Series {
            metric: name,
            unit,
            granularity_seconds: granularity.seconds(),
            values,
        }
    }

    /// Most recent node-level value for a metric, reading from the fast
    /// ring.
    pub fn latest(&self, metric: Metric) -> Option<f64> {
        self.ring(metric).fast.back().copied()
    }

    /// Return the last `n` node-level samples from the fast ring,
    /// oldest-first.
    pub fn recent(&self, metric: Metric, n: usize) -> Vec<f64> {
        let ring = self.ring(metric);
        let n = n.min(ring.fast.len());
        ring.fast.iter().rev().take(n).rev().copied().collect()
    }

    /// Iterate tracked peer addresses.
    pub fn peer_addrs(&self) -> impl Iterator<Item = &NodeAddr> {
        self.peers.keys()
    }

    /// Iterate tracked peers with their ring metadata.
    pub fn peers(&self) -> impl Iterator<Item = (&NodeAddr, &PeerStatsRings)> {
        self.peers.iter()
    }

    /// Number of tracked peers (includes recently-disconnected within
    /// the 24h retention window).
    pub fn tracked_peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Whether this peer is currently in the tracking map (has been
    /// seen at some point and not yet evicted).
    pub fn has_peer(&self, addr: &NodeAddr) -> bool {
        self.peers.contains_key(addr)
    }

    /// Whether tick() has ever been called.
    pub fn has_data(&self) -> bool {
        self.last_tick.is_some()
    }
}

impl Default for StatsHistory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_snap(t: u64) -> Snapshot {
        Snapshot {
            mesh_size: Some(10 + t),
            tree_depth: 2,
            peer_count: 3,
            parent_switches_total: t,
            bytes_in_total: 100 * t,
            bytes_out_total: 200 * t,
            packets_in_total: t,
            packets_out_total: 2 * t,
            loss_rate: 0.01 * t as f64,
            active_sessions: t,
        }
    }

    fn make_addr(tag: u8) -> NodeAddr {
        NodeAddr::from_bytes([tag; 16])
    }

    fn make_peer_snap(tag: u8, now: Instant, t: u64) -> PeerSnapshot {
        PeerSnapshot {
            node_addr: make_addr(tag),
            last_seen: now,
            srtt_ms: Some(10.0 + t as f64),
            loss_rate: Some(0.01 * t as f64),
            bytes_in_total: 50 * t,
            bytes_out_total: 75 * t,
            packets_in_total: t,
            packets_out_total: 2 * t,
            ecn_ce_total: 0,
        }
    }

    #[test]
    fn push_and_query_fast_ring() {
        let mut h = StatsHistory::new();
        let t0 = Instant::now();
        for i in 0..10 {
            h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
        }
        let s = h.query(Metric::MeshSize, Duration::from_secs(5), Granularity::Fast);
        assert_eq!(s.values.len(), 5);
        assert_eq!(s.values, vec![15.0, 16.0, 17.0, 18.0, 19.0]);
        assert_eq!(s.granularity_seconds, 1);
    }

    #[test]
    fn fast_ring_wraps_at_capacity() {
        let mut h = StatsHistory::new();
        let t0 = Instant::now();
        for i in 0..3610u64 {
            h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
        }
        let s = h.query(
            Metric::MeshSize,
            Duration::from_secs(FAST_RING_CAPACITY as u64 * 2),
            Granularity::Fast,
        );
        assert_eq!(s.values.len(), FAST_RING_CAPACITY);
        assert_eq!(s.values[0], 20.0);
        assert_eq!(*s.values.last().unwrap(), 3619.0);
    }

    #[test]
    fn delta_for_counter_metric() {
        let mut h = StatsHistory::new();
        let t0 = Instant::now();
        let totals = [0, 0, 2, 5];
        for (i, &v) in totals.iter().enumerate() {
            let mut s = make_snap(i as u64);
            s.parent_switches_total = v;
            h.tick(t0 + Duration::from_secs(i as u64), &s, &[]);
        }
        let s = h.query(
            Metric::ParentSwitches,
            Duration::from_secs(10),
            Granularity::Fast,
        );
        assert_eq!(s.values.len(), 10);
        assert!(s.values[..6].iter().all(|v| v.is_nan()));
        assert_eq!(s.values[6..], [0.0, 0.0, 2.0, 3.0]);
    }

    #[test]
    fn downsample_last_aggregation() {
        let mut h = StatsHistory::new();
        let t0 = Instant::now();
        for i in 0..60u64 {
            h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
        }
        let s = h.query(
            Metric::MeshSize,
            Duration::from_secs(60 * 5),
            Granularity::Slow,
        );
        assert_eq!(s.values.len(), 5);
        assert!(s.values[..4].iter().all(|v| v.is_nan()));
        assert_eq!(s.values[4], 69.0);
        assert_eq!(s.granularity_seconds, 60);
    }

    #[test]
    fn downsample_mean_aggregation() {
        let mut h = StatsHistory::new();
        let t0 = Instant::now();
        for i in 0..60u64 {
            h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
        }
        let s = h.query(Metric::LossRate, Duration::from_secs(60), Granularity::Slow);
        assert_eq!(s.values.len(), 1);
        assert!((s.values[0] - 0.295).abs() < 1e-9);
    }

    #[test]
    fn downsample_sum_aggregation() {
        let mut h = StatsHistory::new();
        let t0 = Instant::now();
        for i in 0..60u64 {
            let mut s = make_snap(0);
            s.parent_switches_total = i;
            h.tick(t0 + Duration::from_secs(i), &s, &[]);
        }
        let s = h.query(
            Metric::ParentSwitches,
            Duration::from_secs(60),
            Granularity::Slow,
        );
        assert_eq!(s.values.len(), 1);
        assert_eq!(s.values[0], 59.0);
    }

    #[test]
    fn query_pads_front_with_nan_when_ring_is_short() {
        let mut h = StatsHistory::new();
        let t0 = Instant::now();
        for i in 0..3u64 {
            h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
        }
        let s = h.query(Metric::MeshSize, Duration::from_secs(10), Granularity::Fast);
        assert_eq!(s.values.len(), 10);
        assert!(s.values[..7].iter().all(|v| v.is_nan()));
        assert_eq!(s.values[7..], [10.0, 11.0, 12.0]);
    }

    #[test]
    fn fast_query_young_ring_returns_full_hour_with_leading_nan() {
        let mut h = StatsHistory::new();
        let t0 = Instant::now();
        // 5 minutes of data.
        for i in 0..300u64 {
            h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
        }
        let s = h.query(
            Metric::MeshSize,
            Duration::from_secs(3600),
            Granularity::Fast,
        );
        assert_eq!(s.values.len(), 3600);
        assert!(s.values[..3300].iter().all(|v| v.is_nan()));
        assert_eq!(s.values[3300], 10.0);
        assert_eq!(*s.values.last().unwrap(), 309.0);
    }

    #[test]
    fn slow_query_young_ring_returns_full_day_with_leading_nan() {
        let mut h = StatsHistory::new();
        let t0 = Instant::now();
        // 30 minutes of data → 30 slow samples flushed.
        for i in 0u64..1800 {
            h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
        }
        let s = h.query(
            Metric::MeshSize,
            Duration::from_secs(24 * 3600),
            Granularity::Slow,
        );
        assert_eq!(s.values.len(), 1440);
        assert!(s.values[..1410].iter().all(|v| v.is_nan()));
        assert!(s.values[1410..].iter().all(|v| !v.is_nan()));
    }

    #[test]
    fn metric_parse_roundtrip() {
        for m in ALL_METRICS {
            assert_eq!(Metric::from_str(m.name()).unwrap(), *m);
        }
        assert!(Metric::from_str("bogus").is_err());
    }

    #[test]
    fn peer_metric_parse_roundtrip() {
        for m in ALL_PEER_METRICS {
            assert_eq!(PeerMetric::from_str(m.name()).unwrap(), *m);
        }
        assert!(PeerMetric::from_str("bogus").is_err());
    }

    #[test]
    fn granularity_parse() {
        assert_eq!(Granularity::from_str("1s").unwrap(), Granularity::Fast);
        assert_eq!(Granularity::from_str("1m").unwrap(), Granularity::Slow);
        assert!(Granularity::from_str("1h").is_err());
    }

    #[test]
    fn latest_and_recent() {
        let mut h = StatsHistory::new();
        let t0 = Instant::now();
        for i in 0..5u64 {
            h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
        }
        assert_eq!(h.latest(Metric::MeshSize), Some(14.0));
        let r = h.recent(Metric::MeshSize, 3);
        assert_eq!(r, vec![12.0, 13.0, 14.0]);
        let r2 = h.recent(Metric::MeshSize, 100);
        assert_eq!(r2.len(), 5);
    }

    #[test]
    fn active_sessions_is_sampled_as_gauge() {
        let mut h = StatsHistory::new();
        let t0 = Instant::now();
        for i in 0..3u64 {
            let mut s = make_snap(i);
            s.active_sessions = 10 + i;
            h.tick(t0 + Duration::from_secs(i), &s, &[]);
        }
        let s = h.query(
            Metric::ActiveSessions,
            Duration::from_secs(5),
            Granularity::Fast,
        );
        assert_eq!(s.values.len(), 5);
        assert!(s.values[..2].iter().all(|v| v.is_nan()));
        assert_eq!(s.values[2..], [10.0, 11.0, 12.0]);
    }

    #[test]
    fn new_peer_backfills_nan_to_align_with_node_rings() {
        let mut h = StatsHistory::new();
        let t0 = Instant::now();
        // Tick 5 times with no peers (node rings fill up).
        for i in 0..5u64 {
            h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
        }
        // Peer A joins on tick 6.
        let a = make_addr(1);
        h.tick(
            t0 + Duration::from_secs(5),
            &make_snap(5),
            &[make_peer_snap(1, t0 + Duration::from_secs(5), 5)],
        );
        // A's srtt ring has 5 NaN backfill + 1 real = 6 samples. A 60s
        // window front-pads with 54 more NaN so the real value lands at
        // the tail.
        let s = h
            .peer_query(
                &a,
                PeerMetric::SrttMs,
                Duration::from_secs(60),
                Granularity::Fast,
            )
            .unwrap();
        assert_eq!(s.values.len(), 60);
        assert!(s.values[..59].iter().all(|v| v.is_nan()));
        assert_eq!(s.values[59], 15.0);
    }

    #[test]
    fn absent_peer_gets_nan_sample() {
        let mut h = StatsHistory::new();
        let t0 = Instant::now();
        let a = make_addr(1);
        // Tick 3 times with A present.
        for i in 0..3u64 {
            h.tick(
                t0 + Duration::from_secs(i),
                &make_snap(i),
                &[make_peer_snap(1, t0 + Duration::from_secs(i), i)],
            );
        }
        // A disappears for 2 ticks.
        for i in 3..5u64 {
            h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
        }
        let s = h
            .peer_query(
                &a,
                PeerMetric::SrttMs,
                Duration::from_secs(60),
                Granularity::Fast,
            )
            .unwrap();
        assert_eq!(s.values.len(), 60);
        // 55 NaN front-pad, then 3 real, then 2 NaN (A gone).
        assert!(s.values[..55].iter().all(|v| v.is_nan()));
        assert_eq!(s.values[55], 10.0);
        assert_eq!(s.values[57], 12.0);
        assert!(s.values[58].is_nan());
        assert!(s.values[59].is_nan());
    }

    #[test]
    fn counter_decrease_emits_nan_and_rebaselines() {
        let mut h = StatsHistory::new();
        let t0 = Instant::now();
        let a = make_addr(1);
        // Three ticks with bytes_in increasing.
        for (i, total) in [(0u64, 100u64), (1, 200), (2, 300)].iter().copied() {
            let mut ps = make_peer_snap(1, t0 + Duration::from_secs(i), i);
            ps.bytes_in_total = total;
            h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[ps]);
        }
        // Fourth tick: bytes_in drops to 50 (link reconnected).
        let mut ps = make_peer_snap(1, t0 + Duration::from_secs(3), 3);
        ps.bytes_in_total = 50;
        h.tick(t0 + Duration::from_secs(3), &make_snap(3), &[ps]);
        // Fifth tick: bytes_in grows to 80.
        let mut ps = make_peer_snap(1, t0 + Duration::from_secs(4), 4);
        ps.bytes_in_total = 80;
        h.tick(t0 + Duration::from_secs(4), &make_snap(4), &[ps]);

        let s = h
            .peer_query(
                &a,
                PeerMetric::BytesIn,
                Duration::from_secs(60),
                Granularity::Fast,
            )
            .unwrap();
        assert_eq!(s.values.len(), 60);
        // 55 NaN front-pad, then the 5 per-tick samples at the tail.
        assert!(s.values[..55].iter().all(|v| v.is_nan()));
        // First real tick has no prev → NaN.
        assert!(s.values[55].is_nan());
        assert_eq!(s.values[56], 100.0);
        assert_eq!(s.values[57], 100.0);
        // Decrease → NaN, rebaseline to 50.
        assert!(s.values[58].is_nan());
        // Next delta from new baseline.
        assert_eq!(s.values[59], 30.0);
    }

    #[test]
    fn peer_eviction_fires_after_24h_of_silence() {
        let mut h = StatsHistory::new();
        let t0 = Instant::now();
        let a = make_addr(1);
        // One real sample for A at t=0.
        h.tick(t0, &make_snap(0), &[make_peer_snap(1, t0, 0)]);
        assert!(h.has_peer(&a));
        // Keep ticking every minute without A for 24 hours + 1 minute.
        // (we tick at 60s intervals to avoid building a 24h fast ring)
        let eviction = Duration::from_secs(PEER_EVICTION_SECS);
        let mut i = 1u64;
        loop {
            let t = t0 + Duration::from_secs(i * 60);
            h.tick(t, &make_snap(i), &[]);
            if t.duration_since(t0) >= eviction {
                break;
            }
            i += 1;
        }
        assert!(!h.has_peer(&a));
    }

    #[test]
    fn nan_mean_downsample_skips_nan_samples() {
        let mut h = StatsHistory::new();
        let t0 = Instant::now();
        let a = make_addr(1);
        // 60 ticks alternating present / absent — 30 real SRTT samples
        // at values 10, 12, 14, ..., 68, mean = 39.
        for i in 0..60u64 {
            if i.is_multiple_of(2) {
                h.tick(
                    t0 + Duration::from_secs(i),
                    &make_snap(i),
                    &[make_peer_snap(1, t0 + Duration::from_secs(i), i)],
                );
            } else {
                h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
            }
        }
        let s = h
            .peer_query(
                &a,
                PeerMetric::SrttMs,
                Duration::from_secs(60),
                Granularity::Slow,
            )
            .unwrap();
        assert_eq!(s.values.len(), 1);
        let expected: f64 = (0..60u64)
            .filter(|i| i.is_multiple_of(2))
            .map(|i| 10.0 + i as f64)
            .sum::<f64>()
            / 30.0;
        assert!((s.values[0] - expected).abs() < 1e-9);
    }

    #[test]
    fn all_nan_window_downsamples_to_nan() {
        let mut h = StatsHistory::new();
        let t0 = Instant::now();
        let a = make_addr(1);
        // Introduce A, then silence it for 60+ ticks so one full slow
        // sample accumulates entirely of NaN.
        h.tick(t0, &make_snap(0), &[make_peer_snap(1, t0, 0)]);
        for i in 1..=60u64 {
            h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
        }
        let s = h
            .peer_query(
                &a,
                PeerMetric::SrttMs,
                Duration::from_secs(60 * 5),
                Granularity::Slow,
            )
            .unwrap();
        // We got one slow sample after 60 fast ticks. First 60 samples
        // in the fast ring were 1 real + 59 NaN → Last = 10.0. But the
        // boundary lands at fast_pushes == 60, AFTER pushing tick 59
        // (index 59). So the slow window covers fast indices 0..59, i.e.
        // tick 0 (real) + ticks 1..59 (NaN) → Last = 10.0. Not all-NaN.
        //
        // Window is 300s / 60s = 5 slots; ring has 1 slow sample, so 4
        // leading NaN from the front-pad and the real value at the tail.
        //
        // Let's instead assert that the NEXT slow flush (after another
        // 60 all-NaN ticks) is NaN.
        assert_eq!(s.values.len(), 5);
        assert!(s.values[..4].iter().all(|v| v.is_nan()));
        assert_eq!(s.values[4], 10.0);

        for i in 61..=120u64 {
            h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
        }
        let s = h
            .peer_query(
                &a,
                PeerMetric::SrttMs,
                Duration::from_secs(60 * 5),
                Granularity::Slow,
            )
            .unwrap();
        // 3 leading NaN from front-pad, then 2 real slow samples: the
        // first Last=10.0, the second a fully-NaN slow window → NaN.
        assert_eq!(s.values.len(), 5);
        assert!(s.values[..3].iter().all(|v| v.is_nan()));
        assert_eq!(s.values[3], 10.0);
        assert!(s.values[4].is_nan());
    }

    #[test]
    fn nan_serializes_to_json_null() {
        let series = Series {
            metric: "srtt_ms",
            unit: "ms",
            granularity_seconds: 1,
            values: vec![1.0, f64::NAN, 3.0],
        };
        let json = serde_json::to_value(&series).unwrap();
        let values = json.get("values").unwrap().as_array().unwrap();
        assert!(values[0].is_f64());
        assert!(values[1].is_null());
        assert!(values[2].is_f64());
    }
}
