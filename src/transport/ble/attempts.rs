//! Per-peer BLE connect-attempt log.
//!
//! The tiebreaker, connect and pool sites in this transport already emit debug
//! traces when an attempt resolves. Those traces answer "what happened" only
//! while a debugger is attached and only for the attempt currently scrolling
//! past. This module turns the same events into structured, queryable state: for
//! each peer address, which role this node chose, how long discovery took, how
//! the attempt resolved, and how many sends to that peer failed.
//!
//! That matters most for the cross-probe tiebreaker. The convention is
//! deterministic in source and unit-tested, but nothing records whether *both*
//! sides actually agreed at runtime — a disagreement between two nodes is
//! exactly the kind of race that leaves no evidence behind. Recording both the
//! inbound drop (peripheral role losing) and the outbound yield (central role
//! losing) makes such a disagreement visible as data rather than inferred from
//! reading the source.
//!
//! The log is a bounded in-memory ring: at most [`MAX_ATTEMPTS_PER_PEER`]
//! entries per address, oldest dropped first, pruned on write with no background
//! job. Retention beyond process lifetime is deliberately *not* handled here —
//! an embedder that wants attempts to survive a restart persists snapshots
//! itself.
//!
//! Every method takes a short critical section and holds no lock across an
//! `.await`, so recording an attempt never perturbs the timing of the operation
//! it is measuring.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Maximum attempts retained per peer address. The oldest falls off as a new one
/// lands, so a fast-churning peer costs a bounded amount of memory and a
/// full ring is itself a signal worth reading.
pub const MAX_ATTEMPTS_PER_PEER: usize = 20;

/// Which side of the L2CAP connection this node took for an attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BleRole {
    /// This node dialled the peer (outbound probe).
    Central,
    /// This node accepted the peer's connection (inbound).
    Peripheral,
}

impl BleRole {
    /// Stable lowercase wire label.
    pub fn as_str(&self) -> &'static str {
        match self {
            BleRole::Central => "central",
            BleRole::Peripheral => "peripheral",
        }
    }
}

/// How one discovery-to-resolution cycle ended. Exactly one value is recorded
/// per attempt, so one cycle is one log entry rather than several fragments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BleAttemptOutcome {
    /// The connection was promoted into the pool and is carrying traffic.
    Connected,
    /// The L2CAP connect exceeded the configured connect timeout.
    ConnectTimeout,
    /// The L2CAP connect returned an error.
    ConnectError,
    /// The connection opened but the pubkey exchange did not complete.
    PubkeyExchangeFailed,
    /// The cross-probe tiebreaker resolved in the peer's favour, so this side
    /// dropped its connection and deferred to the peer's.
    LostTiebreaker,
    /// The connection was usable but the pool had no room for it.
    PoolRejected,
}

impl BleAttemptOutcome {
    /// Stable kebab-case wire label.
    pub fn as_str(&self) -> &'static str {
        match self {
            BleAttemptOutcome::Connected => "connected",
            BleAttemptOutcome::ConnectTimeout => "connect-timeout",
            BleAttemptOutcome::ConnectError => "connect-error",
            BleAttemptOutcome::PubkeyExchangeFailed => "pubkey-exchange-failed",
            BleAttemptOutcome::LostTiebreaker => "lost-tiebreaker",
            BleAttemptOutcome::PoolRejected => "pool-rejected",
        }
    }
}

/// One resolved connect attempt against one peer.
#[derive(Clone, Debug)]
pub struct BleAttempt {
    /// Wall-clock milliseconds since the Unix epoch at which the attempt
    /// resolved. Wall clock rather than monotonic because an embedder persists
    /// these and must be able to compare them across process lifetimes.
    pub at_ms: u64,
    /// The peer's BLE address as this transport names it.
    pub ble_addr: String,
    /// The peer's node address in hex, when the attempt got far enough to learn
    /// one; empty otherwise. Never guessed.
    pub node_addr_hex: String,
    /// Which role this node took for the attempt.
    pub role: BleRole,
    /// Milliseconds between the address being discovered and this resolution;
    /// `0` when no discovery stamp was recorded for the address.
    pub discovery_ms: u64,
    /// How the attempt ended.
    pub outcome: BleAttemptOutcome,
}

/// Everything recorded about one peer address, as returned by
/// [`BleAttemptLog::snapshot`].
#[derive(Clone, Debug)]
pub struct BlePeerAttempts {
    /// The peer's BLE address.
    pub ble_addr: String,
    /// The node address hex learned for this peer, or empty if no attempt has
    /// carried one yet.
    pub node_addr_hex: String,
    /// Count of sends to this peer that failed at the link.
    pub send_failures: u64,
    /// Attempts oldest-first, capped at [`MAX_ATTEMPTS_PER_PEER`].
    pub attempts: Vec<BleAttempt>,
}

/// The mutable interior, behind one lock so a snapshot is always self-consistent.
#[derive(Default)]
struct Inner {
    /// Per-address attempt rings.
    attempts: HashMap<String, VecDeque<BleAttempt>>,
    /// Discovery stamps for addresses whose attempt has not yet resolved.
    in_flight: HashMap<String, Instant>,
    /// Per-address link send-failure counters.
    send_failures: HashMap<String, u64>,
    /// Address-to-node-address pairs learned from attempts that carried one.
    node_addrs: HashMap<String, String>,
}

/// Bounded, process-global record of BLE connect attempts per peer.
pub struct BleAttemptLog {
    inner: Mutex<Inner>,
}

impl BleAttemptLog {
    /// Create an empty log.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Stamp the moment `ble_addr` was discovered, starting the clock that
    /// [`Self::discovery_elapsed_ms`] later reads. Re-stamping an address whose
    /// previous attempt never resolved simply restarts its clock — the newer
    /// discovery is the one the pending attempt belongs to.
    pub fn note_discovered(&self, ble_addr: &str) {
        let mut inner = self.lock();
        inner.in_flight.insert(ble_addr.to_string(), Instant::now());
    }

    /// Milliseconds since `ble_addr` was discovered, or `0` if it was never
    /// stamped. Returning zero rather than an `Option` keeps the recording sites
    /// free of branches, and zero already means "no discovery measured".
    pub fn discovery_elapsed_ms(&self, ble_addr: &str) -> u64 {
        let inner = self.lock();
        inner
            .in_flight
            .get(ble_addr)
            .map(|t| t.elapsed().as_millis() as u64)
            .unwrap_or(0)
    }

    /// Record a resolved attempt: push it onto that address's ring, drop the
    /// oldest entry if the ring is full, clear the address's in-flight discovery
    /// stamp, and learn the address-to-node-address pair when the attempt
    /// carries one.
    pub fn record(&self, attempt: BleAttempt) {
        let mut inner = self.lock();
        let addr = attempt.ble_addr.clone();
        if !attempt.node_addr_hex.is_empty() {
            inner
                .node_addrs
                .insert(addr.clone(), attempt.node_addr_hex.clone());
        }
        inner.in_flight.remove(&addr);
        let ring = inner.attempts.entry(addr).or_default();
        ring.push_back(attempt);
        while ring.len() > MAX_ATTEMPTS_PER_PEER {
            ring.pop_front();
        }
    }

    /// Count one failed send to `ble_addr`. Only link-level send failures belong
    /// here — a packet rejected for exceeding the MTU is a caller bug, not a
    /// property of the peer's link, and conflating the two would make this
    /// counter useless as evidence.
    pub fn record_send_failure(&self, ble_addr: &str) {
        let mut inner = self.lock();
        *inner.send_failures.entry(ble_addr.to_string()).or_insert(0) += 1;
    }

    /// Point-in-time copy of every address's history, ordered by address so the
    /// output is stable across calls.
    pub fn snapshot(&self) -> Vec<BlePeerAttempts> {
        let inner = self.lock();
        let mut addrs: Vec<&String> = inner
            .attempts
            .keys()
            .chain(inner.send_failures.keys())
            .collect();
        addrs.sort_unstable();
        addrs.dedup();
        addrs
            .into_iter()
            .map(|addr| BlePeerAttempts {
                ble_addr: addr.clone(),
                node_addr_hex: inner.node_addrs.get(addr).cloned().unwrap_or_default(),
                send_failures: inner.send_failures.get(addr).copied().unwrap_or(0),
                attempts: inner
                    .attempts
                    .get(addr)
                    .map(|r| r.iter().cloned().collect())
                    .unwrap_or_default(),
            })
            .collect()
    }

    /// Take the lock, recovering from a poisoned mutex rather than panicking: a
    /// diagnostic log must never be the thing that takes the transport down.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Default for BleAttemptLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Wall-clock milliseconds since the Unix epoch, saturating to `0` if the system
/// clock is set before the epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

static ATTEMPT_LOG: OnceLock<Arc<BleAttemptLog>> = OnceLock::new();

/// The process-global attempt log, created on first use.
///
/// A module-local singleton rather than a value threaded through
/// `accept_loop` / `scan_probe_loop`: both already carry a
/// too-many-arguments allowance, and widening their signatures would be a
/// larger and harder-to-extract diff than a free accessor.
pub fn ble_attempt_log() -> &'static Arc<BleAttemptLog> {
    ATTEMPT_LOG.get_or_init(|| Arc::new(BleAttemptLog::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt(addr: &str, outcome: BleAttemptOutcome) -> BleAttempt {
        BleAttempt {
            at_ms: 1,
            ble_addr: addr.to_string(),
            node_addr_hex: String::new(),
            role: BleRole::Central,
            discovery_ms: 0,
            outcome,
        }
    }

    #[test]
    fn outcome_labels_are_stable_kebab_case() {
        assert_eq!(BleAttemptOutcome::Connected.as_str(), "connected");
        assert_eq!(
            BleAttemptOutcome::ConnectTimeout.as_str(),
            "connect-timeout"
        );
        assert_eq!(BleAttemptOutcome::ConnectError.as_str(), "connect-error");
        assert_eq!(
            BleAttemptOutcome::PubkeyExchangeFailed.as_str(),
            "pubkey-exchange-failed"
        );
        assert_eq!(
            BleAttemptOutcome::LostTiebreaker.as_str(),
            "lost-tiebreaker"
        );
        assert_eq!(BleAttemptOutcome::PoolRejected.as_str(), "pool-rejected");
        assert_eq!(BleRole::Central.as_str(), "central");
        assert_eq!(BleRole::Peripheral.as_str(), "peripheral");
    }

    #[test]
    fn ring_caps_at_max_dropping_oldest_first() {
        let log = BleAttemptLog::new();
        for i in 0..(MAX_ATTEMPTS_PER_PEER + 5) {
            let mut a = attempt("ble0/AA", BleAttemptOutcome::ConnectError);
            a.at_ms = i as u64;
            log.record(a);
        }
        let snap = log.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].attempts.len(), MAX_ATTEMPTS_PER_PEER);
        // The five oldest fell off the front, so the ring starts at 5.
        assert_eq!(snap[0].attempts[0].at_ms, 5);
        assert_eq!(
            snap[0].attempts[MAX_ATTEMPTS_PER_PEER - 1].at_ms,
            (MAX_ATTEMPTS_PER_PEER + 4) as u64
        );
    }

    #[test]
    fn discovery_elapsed_is_zero_for_an_unstamped_address() {
        let log = BleAttemptLog::new();
        assert_eq!(log.discovery_elapsed_ms("ble0/NEVER"), 0);
    }

    #[test]
    fn recording_clears_the_in_flight_stamp() {
        let log = BleAttemptLog::new();
        log.note_discovered("ble0/BB");
        log.record(attempt("ble0/BB", BleAttemptOutcome::Connected));
        // Stamp cleared, so a later read reports "no discovery measured".
        assert_eq!(log.discovery_elapsed_ms("ble0/BB"), 0);
    }

    #[test]
    fn node_addr_is_learned_only_from_an_attempt_that_carries_one() {
        let log = BleAttemptLog::new();
        log.record(attempt("ble0/CC", BleAttemptOutcome::ConnectError));
        assert_eq!(log.snapshot()[0].node_addr_hex, "");

        let mut with_addr = attempt("ble0/CC", BleAttemptOutcome::LostTiebreaker);
        with_addr.node_addr_hex = "dead".to_string();
        log.record(with_addr);
        assert_eq!(log.snapshot()[0].node_addr_hex, "dead");

        // A later attempt without one must not erase what was learned.
        log.record(attempt("ble0/CC", BleAttemptOutcome::ConnectTimeout));
        assert_eq!(log.snapshot()[0].node_addr_hex, "dead");
    }

    #[test]
    fn snapshot_returns_one_entry_per_address_with_send_failures() {
        let log = BleAttemptLog::new();
        log.record(attempt("ble0/BB", BleAttemptOutcome::Connected));
        log.record(attempt("ble0/AA", BleAttemptOutcome::ConnectError));
        log.record_send_failure("ble0/AA");
        log.record_send_failure("ble0/AA");
        // An address with only send failures still gets a row.
        log.record_send_failure("ble0/CC");

        let snap = log.snapshot();
        assert_eq!(snap.len(), 3);
        // Ordered by address, not insertion order.
        assert_eq!(snap[0].ble_addr, "ble0/AA");
        assert_eq!(snap[0].send_failures, 2);
        assert_eq!(snap[0].attempts.len(), 1);
        assert_eq!(snap[1].ble_addr, "ble0/BB");
        assert_eq!(snap[1].send_failures, 0);
        assert_eq!(snap[2].ble_addr, "ble0/CC");
        assert_eq!(snap[2].attempts.len(), 0);
    }

    #[test]
    fn discovery_elapsed_is_measured_from_the_stamp() {
        let log = BleAttemptLog::new();
        log.note_discovered("ble0/DD");
        std::thread::sleep(std::time::Duration::from_millis(12));
        assert!(log.discovery_elapsed_ms("ble0/DD") >= 10);
    }
}
