//! Micro-benchmark quantifying the per-forwarded-packet heap-allocation cost
//! of the routing next-hop candidate-assembly path.
//!
//! `find_next_hop` runs once per forwarded data packet. Its sans-IO core
//! assembles a `Vec<Candidate>` by enumerating every peer through the
//! `RoutingView` seam: `peer_addrs()` materializes a `Vec<NodeAddr>` of all
//! peers, the survivors are snapshotted (each cloning its `TreeCoordinate`),
//! and the result is collected into a second `Vec`. This bench measures that
//! per-call allocation against a fused zero-alloc reference that iterates the
//! peer map directly and borrows coordinates instead of cloning.
//!
//! Visibility caveat: the production `routing_candidates` / `select_best_candidate`
//! / `RoutingView` / `Candidate` are `pub(crate)` (src/proto/routing/core.rs)
//! and are not re-exported at the crate root, so an external bench crate cannot
//! name them. Rather than change production visibility, this file reproduces
//! that path verbatim over the real public `NodeAddr` / `TreeCoordinate` /
//! `CoordEntry` / `BloomFilter` types with the same iterator chain and the same
//! `HashMap`-backed view the shell uses (src/node/mod.rs NodeRoutingView). The
//! allocation behavior is therefore identical to production by construction;
//! only the symbol identity differs.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fips::{BloomFilter, NodeAddr, TreeCoordinate};

// ---------------------------------------------------------------------------
// Counting global allocator: bumps a process-global counter on every heap
// allocation operation (alloc / alloc_zeroed / realloc). Sampled tightly and
// single-threaded in `report_allocs` so no unrelated allocations are captured.
// ---------------------------------------------------------------------------
struct CountingAlloc;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

const PEER_COUNTS: [usize; 4] = [8, 32, 128, 256];
/// Fraction of peers whose bloom filter reports the destination reachable.
const REACH_NUMERATOR: usize = 1;
const REACH_DENOMINATOR: usize = 2;
/// Tree depth for synthetic coordinates (self..root), a realistic mesh depth.
const COORD_DEPTH: usize = 8;

// ---------------------------------------------------------------------------
// Reproduction of the pub(crate) routing seam (src/proto/routing/core.rs).
// ---------------------------------------------------------------------------
trait RoutingView {
    fn peer_addrs(&self) -> Vec<NodeAddr>;
    fn peer_may_reach(&self, peer: &NodeAddr, dest: &NodeAddr) -> bool;
    fn peer_can_send(&self, peer: &NodeAddr) -> bool;
    fn peer_link_cost(&self, peer: &NodeAddr) -> f64;
    fn peer_coords(&self, peer: &NodeAddr) -> Option<TreeCoordinate>;
}

struct Candidate {
    addr: NodeAddr,
    can_send: bool,
    link_cost: f64,
    coords: Option<TreeCoordinate>,
}

/// Verbatim from `routing::routing_candidates` (core.rs). Allocates the
/// `peer_addrs` Vec, clones each survivor's coords, and collects into a Vec.
fn routing_candidates(rv: &impl RoutingView, dest: &NodeAddr) -> Vec<Candidate> {
    rv.peer_addrs()
        .into_iter()
        .filter(|peer| rv.peer_may_reach(peer, dest))
        .map(|peer| Candidate {
            can_send: rv.peer_can_send(&peer),
            link_cost: rv.peer_link_cost(&peer),
            coords: rv.peer_coords(&peer),
            addr: peer,
        })
        .collect()
}

/// Verbatim from `routing::select_best_candidate` (core.rs). Pure, no alloc.
fn select_best_candidate(
    candidates: &[Candidate],
    dest_coords: &TreeCoordinate,
    my_coords: &TreeCoordinate,
) -> Option<NodeAddr> {
    let my_distance = my_coords.distance_to(dest_coords);
    let mut best: Option<(&Candidate, f64, usize)> = None;
    for candidate in candidates {
        if !candidate.can_send {
            continue;
        }
        let cost = candidate.link_cost;
        let dist = candidate
            .coords
            .as_ref()
            .map(|pc| pc.distance_to(dest_coords))
            .unwrap_or(usize::MAX);
        if dist >= my_distance {
            continue;
        }
        let dominated = match &best {
            None => true,
            Some((_, best_cost, best_dist)) => {
                cost < *best_cost
                    || (cost == *best_cost && dist < *best_dist)
                    || (cost == *best_cost
                        && dist == *best_dist
                        && candidate.addr < best.as_ref().unwrap().0.addr)
            }
        };
        if dominated {
            best = Some((candidate, cost, dist));
        }
    }
    best.map(|(candidate, _, _)| candidate.addr)
}

// ---------------------------------------------------------------------------
// Bench-local view, HashMap-backed exactly like src/node/mod.rs NodeRoutingView.
// ---------------------------------------------------------------------------
struct BenchPeer {
    bloom: BloomFilter,
    can_send: bool,
    link_cost: f64,
}

struct BenchView {
    peers: HashMap<NodeAddr, BenchPeer>,
    coords: HashMap<NodeAddr, TreeCoordinate>,
}

impl RoutingView for BenchView {
    fn peer_addrs(&self) -> Vec<NodeAddr> {
        self.peers.keys().copied().collect()
    }
    fn peer_may_reach(&self, peer: &NodeAddr, dest: &NodeAddr) -> bool {
        self.peers.get(peer).is_some_and(|p| p.bloom.contains(dest))
    }
    fn peer_can_send(&self, peer: &NodeAddr) -> bool {
        self.peers.get(peer).is_some_and(|p| p.can_send)
    }
    fn peer_link_cost(&self, peer: &NodeAddr) -> f64 {
        self.peers.get(peer).map_or(f64::INFINITY, |p| p.link_cost)
    }
    fn peer_coords(&self, peer: &NodeAddr) -> Option<TreeCoordinate> {
        self.coords.get(peer).cloned()
    }
}

/// Zero-alloc reference: what an iterator/visitor seam would do. Iterates the
/// peer map directly, fuses the may_reach + can_send filters, borrows coords
/// instead of cloning, and tracks the best hop inline. No Vec, no coord clone.
fn resolve_next_hop_zeroalloc(
    view: &BenchView,
    dest: &NodeAddr,
    dest_coords: &TreeCoordinate,
    my_coords: &TreeCoordinate,
) -> Option<NodeAddr> {
    let my_distance = my_coords.distance_to(dest_coords);
    let mut best: Option<(NodeAddr, f64, usize)> = None;
    for (addr, peer) in &view.peers {
        if !peer.bloom.contains(dest) {
            continue;
        }
        if !peer.can_send {
            continue;
        }
        let cost = peer.link_cost;
        let dist = view
            .coords
            .get(addr)
            .map(|pc| pc.distance_to(dest_coords))
            .unwrap_or(usize::MAX);
        if dist >= my_distance {
            continue;
        }
        let dominated = match &best {
            None => true,
            Some((best_addr, best_cost, best_dist)) => {
                cost < *best_cost
                    || (cost == *best_cost && dist < *best_dist)
                    || (cost == *best_cost && dist == *best_dist && *addr < *best_addr)
            }
        };
        if dominated {
            best = Some((*addr, cost, dist));
        }
    }
    best.map(|(addr, _, _)| addr)
}

// ---------------------------------------------------------------------------
// Scenario construction.
// ---------------------------------------------------------------------------
fn addr(tag: u8, i: u16) -> NodeAddr {
    let mut b = [0u8; 16];
    b[0] = tag;
    b[1..3].copy_from_slice(&i.to_le_bytes());
    NodeAddr::from_bytes(b)
}

/// A depth-`COORD_DEPTH` coordinate whose leaf is `leaf`, sharing a fixed
/// interior path and root with `shared_tag`. Peers built with the dest's
/// shared_tag sit close to the destination (distance 2); a distinct shared_tag
/// sits far (near the root), modeling our own position.
fn coord(leaf: NodeAddr, shared_tag: u8) -> TreeCoordinate {
    let mut path = Vec::with_capacity(COORD_DEPTH);
    path.push(leaf);
    for level in 1..(COORD_DEPTH - 1) {
        path.push(addr(shared_tag, level as u16));
    }
    path.push(addr(9, 0)); // common root
    TreeCoordinate::from_addrs(path).expect("valid coord path")
}

struct Scenario {
    view: BenchView,
    dest: NodeAddr,
    dest_coords: TreeCoordinate,
    my_coords: TreeCoordinate,
}

impl Scenario {
    fn new(n: usize) -> Self {
        let dest = addr(2, 0);
        // Destination path uses interior tag 4; peers reuse tag 4 so survivors
        // are close to the destination. Our own coords use tag 5 (far).
        let dest_coords = coord(dest, 4);
        let my_coords = coord(addr(6, 0), 5);

        let mut peers = HashMap::new();
        let mut coords = HashMap::new();
        for i in 0..n {
            let paddr = addr(1, i as u16);
            let mut bloom = BloomFilter::new();
            // Realistic fill: a handful of unrelated reachable addrs.
            for f in 0..4u16 {
                bloom.insert(&addr(7, i as u16 * 4 + f));
            }
            // A controlled fraction advertise the destination as reachable.
            if (i % REACH_DENOMINATOR) < REACH_NUMERATOR {
                bloom.insert(&dest);
            }
            peers.insert(
                paddr,
                BenchPeer {
                    bloom,
                    can_send: true,
                    link_cost: 1.0 + (i as f64) * 0.01,
                },
            );
            // Peers share the destination's interior path (tag 4) → close.
            coords.insert(paddr, coord(paddr, 4));
        }

        Self {
            view: BenchView { peers, coords },
            dest,
            dest_coords,
            my_coords,
        }
    }

    fn survivors(&self) -> usize {
        self.view
            .peers
            .values()
            .filter(|p| p.bloom.contains(&self.dest))
            .count()
    }
}

// ---------------------------------------------------------------------------
// Allocation-per-call report (printed once, before criterion timing).
// ---------------------------------------------------------------------------
fn count_allocs<T>(iters: usize, mut f: impl FnMut() -> T) -> f64 {
    for _ in 0..8 {
        black_box(f());
    }
    let start = ALLOCS.load(Ordering::Relaxed);
    for _ in 0..iters {
        black_box(f());
    }
    let end = ALLOCS.load(Ordering::Relaxed);
    (end - start) as f64 / iters as f64
}

fn report_allocs() {
    const ITERS: usize = 2000;
    println!("\n=== allocations per call (heap alloc ops: alloc+alloc_zeroed+realloc) ===");
    println!(
        "{:>6} {:>10} {:>16} {:>16}",
        "peers", "survivors", "current/call", "zero-alloc/call"
    );
    for &n in &PEER_COUNTS {
        let s = Scenario::new(n);
        let survivors = s.survivors();
        let current = count_allocs(ITERS, || {
            let cands = routing_candidates(&s.view, &s.dest);
            select_best_candidate(&cands, &s.dest_coords, &s.my_coords)
        });
        let zero = count_allocs(ITERS, || {
            resolve_next_hop_zeroalloc(&s.view, &s.dest, &s.dest_coords, &s.my_coords)
        });
        println!("{n:>6} {survivors:>10} {current:>16.2} {zero:>16.2}");
    }
    println!();
}

fn bench_next_hop(c: &mut Criterion) {
    report_allocs();

    let mut group = c.benchmark_group("find_next_hop");
    for &n in &PEER_COUNTS {
        let scenario = Scenario::new(n);
        group.bench_with_input(BenchmarkId::new("current_alloc", n), &n, |b, _| {
            b.iter(|| {
                let cands = routing_candidates(&scenario.view, &scenario.dest);
                black_box(select_best_candidate(
                    &cands,
                    &scenario.dest_coords,
                    &scenario.my_coords,
                ))
            });
        });
        group.bench_with_input(BenchmarkId::new("zero_alloc_ref", n), &n, |b, _| {
            b.iter(|| {
                black_box(resolve_next_hop_zeroalloc(
                    &scenario.view,
                    &scenario.dest,
                    &scenario.dest_coords,
                    &scenario.my_coords,
                ))
            });
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = bench_next_hop
}
criterion_main!(benches);
