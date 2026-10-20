//! Session-index leases and epoch tags.
//!
//! An FMP epoch is found by the session index its peer puts in every frame.
//! The machine takes an index from the node's allocator when it needs one
//! (starting an attempt, answering a peer's msg1) and gives it back only by
//! emitting `Output::Release` with the lease, which the shell returns to the
//! allocator. Link setup mints the index of a link's first epoch with the
//! same [`allocate`], so no other code can make a lease.

#[cfg(not(test))]
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::entropy::EntropySource;
use crate::utils::index::IndexAllocator;

/// Leases dropped without being released, process-wide.
///
/// A dropped lease is a leaked index: the allocator still counts it in use.
/// Dropping one must not panic (an `Outputs` list dropped on an error path,
/// a machine dropped without `close`), so the drop is counted instead, and
/// tests assert the count stays zero.
#[cfg(not(test))]
static LEAKED: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
std::thread_local! {
    /// In test builds the count is per thread, so a test that leaks on
    /// purpose (or runs a guard switched off) cannot move the count another
    /// test thread reads.
    static LEAKED: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// A source of session indices: the node's allocator, lent as a capability.
pub trait IndexSource {
    /// Take an index no live session uses, or `None` when none is free.
    fn draw(&mut self) -> Option<u32>;
}

/// The index source of a profile that has no indices (FSP).
impl IndexSource for () {
    fn draw(&mut self) -> Option<u32> {
        None
    }
}

impl<E: EntropySource> IndexSource for IndexAllocator<E> {
    fn draw(&mut self) -> Option<u32> {
        self.allocate().ok().map(|index| index.as_u32())
    }
}

/// One session index, held by exactly one owner until it is released.
///
/// Linear by construction: no `Clone`, minted only by [`allocate`], and
/// consumed by [`IndexLease::release`], which the shell calls when it
/// executes `Output::Release`. A `u32` read from a wire header has no
/// conversion into a lease, so the machine can never free an index a peer
/// named:
///
/// ```compile_fail
/// use fips_core::proto::rekey::IndexLease;
/// let lease: IndexLease = 7u32.into();
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct IndexLease {
    index: u32,
    live: bool,
}

impl IndexLease {
    /// The index this lease holds.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Give the lease up and return the index, for the shell to free in the
    /// allocator it was drawn from.
    pub fn release(mut self) -> u32 {
        self.live = false;
        self.index
    }
}

impl Drop for IndexLease {
    /// Count a lease that was dropped while still held.
    fn drop(&mut self) {
        if self.live {
            #[cfg(not(test))]
            LEAKED.fetch_add(1, Ordering::Relaxed);
            #[cfg(test)]
            LEAKED.with(|n| n.set(n.get() + 1));
        }
    }
}

/// Take a lease on a fresh index from `source`, or `None` when the source
/// has none to give.
pub fn allocate<I: IndexSource + ?Sized>(source: &mut I) -> Option<IndexLease> {
    source.draw().map(|index| IndexLease { index, live: true })
}

/// How many leases have been dropped without being released in this
/// process (in this thread, in test builds).
pub fn leaked() -> usize {
    #[cfg(not(test))]
    return LEAKED.load(Ordering::Relaxed);
    #[cfg(test)]
    return LEAKED.with(core::cell::Cell::get);
}

/// The name of one epoch, unique within a process.
///
/// Drawn from the node-wide [`TagSource`], so a decrypt worker's report for
/// an epoch that has since been retired can never match a later epoch of
/// any machine. It keys the shell's per-epoch state (worker registrations,
/// MMP receivers) and never reaches the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EpochTag(u64);

impl EpochTag {
    /// The tag's number.
    pub fn get(self) -> u64 {
        self.0
    }
}

/// The node-wide counter epoch tags are drawn from.
#[derive(Debug, Default)]
pub struct TagSource {
    next: u64,
}

impl TagSource {
    /// A counter that starts at tag 0.
    pub const fn new() -> Self {
        Self { next: 0 }
    }

    /// The next tag. The counter saturates rather than wrapping, which a
    /// 64-bit count of epochs never reaches.
    pub fn draw(&mut self) -> EpochTag {
        let tag = EpochTag(self.next);
        self.next = self.next.saturating_add(1);
        tag
    }
}

#[cfg(test)]
#[path = "tests/lease.rs"]
mod tests;
