//! Tick-body instrumentation.
//!
//! A purpose-built, feature-gated profiler for the rx-loop tick arm. It exists
//! to answer one question with field data: which subsystem step dominates the
//! tick body, and how long does the tick arm wait behind the other `select!`
//! arms before it runs at all.
//!
//! # Shape
//!
//! - Everything that costs anything at runtime is behind the `profiling` Cargo
//!   feature, which is **off by default**. The default build's neutrality is a
//!   property of the generated code, not of a runtime check.
//! - The instrumentation macro is defined twice, once per feature state. The
//!   feature-off definition is a pure pass-through: it expands to the measured
//!   expression and nothing else, so no timing code exists in a default build.
//! - The always-present surface — [`gate`], [`tick_entry`], [`tick_gauges`],
//!   [`shutdown`] — exists in both feature states because the call sites in
//!   `rx_loop.rs` and the lifecycle teardown must compile either way. Their
//!   feature-off forms are empty (and [`gate`] is a `const fn` returning
//!   `false`), so they cost nothing.
//! - The module is named `instr` rather than `profiling` so that it sorts
//!   before `node` in `lib.rs`'s alphabetical module list: a `#[macro_use]`
//!   module must be declared before the modules that use its macros.
//!
//! # Data model
//!
//! Domain above step: [`Domain`] carries exactly one variant today
//! (`Domain::Tick`). The primitive, the recorder, the writer and the `fipsctl`
//! surface all take a domain, so adding a data-path domain later is additive.
//! No second domain is declared until something records into it.
//!
//! Per (domain, step) the recorder keeps an exact count, max and total in fixed
//! static `AtomicU64` arrays — no histogram, no accumulation, a fixed footprint
//! regardless of run length. Gauges (ticks per interval, peer count, and the
//! arm-starvation figures) live in a parallel array and are emitted with an
//! explicit row kind so a gauge value never lands under a duration column.

#[cfg(feature = "profiling")]
pub(crate) mod capture;
#[cfg(feature = "profiling")]
mod recorder;
#[cfg(feature = "profiling")]
mod writer;

#[cfg(feature = "profiling")]
pub(crate) use recorder::{Domain, Step, now, record};

// ---------------------------------------------------------------------------
// The macro pair.
//
// Every path in the body is `$crate::`-qualified. `macro_rules!` bodies are not
// path-hygienic: an unqualified `Instant::now()` or `record(..)` would resolve
// at the *call site* (`rx_loop.rs`), where neither name is in scope. Importing
// them there is worse still, because the imports would be unused in the
// feature-off build and red it under `-D warnings`.
//
// `$e` is evaluated exactly once in both forms, which is what makes nesting the
// whole-tick span around the per-step spans safe.
// ---------------------------------------------------------------------------

/// Time `$e` as one step of `$domain`, when `$on` is true.
///
/// `$on` is the per-tick gate hoist: the enable flag is read once at the top of
/// the tick arm into a local, and that local is passed explicitly to every
/// invocation, because macro hygiene makes a call-site local invisible inside
/// the macro body.
#[cfg(feature = "profiling")]
macro_rules! instr_step {
    ($on:expr, $domain:expr, $step:expr, $e:expr) => {{
        let t0 = if $on {
            Some($crate::instr::now())
        } else {
            None
        };
        let r = $e;
        if let Some(t) = t0 {
            $crate::instr::record($domain, $step, t.elapsed());
        }
        r
    }};
}

/// Feature-off form: a pure pass-through. The expansion contains no clock read,
/// no counter update and no reference to the recorder — only the measured
/// expression, plus a discard of the gate local so it is not unused.
#[cfg(not(feature = "profiling"))]
macro_rules! instr_step {
    ($on:expr, $domain:expr, $step:expr, $e:expr) => {{
        let _ = &$on;
        $e
    }};
}

// ---------------------------------------------------------------------------
// Always-present surface.
// ---------------------------------------------------------------------------

/// Whether a capture is armed. Read **once per tick** into a local that is then
/// passed to each `instr_step!` invocation, so the feature-on-but-idle cost of
/// the whole tick arm is a single relaxed load.
#[cfg(feature = "profiling")]
#[inline]
pub(crate) fn gate() -> bool {
    capture::gate()
}

/// Feature-off gate: a `const fn` returning `false`, so the whole tick arm
/// folds to the uninstrumented sequence at compile time.
#[cfg(not(feature = "profiling"))]
#[inline]
pub(crate) const fn gate() -> bool {
    false
}

/// Record how late this tick-arm entry is against its scheduled deadline.
///
/// The arm is polled **last** under `biased;`, so its lateness is the time it
/// spent waiting behind the packet, TUN and control arms. `tokio::time::
/// interval::tick` returns the deadline it was scheduled for, so this is a
/// direct subtraction rather than a model. Two earlier designs derived it from
/// the inter-entry gap instead and both under-reported: one by the previous
/// body, the other by reporting only the first difference of the delay, so a
/// sustained stall read as zero. The inter-entry gap is still recorded as its
/// own gauge, but it carries no starvation signal on its own.
#[cfg(feature = "profiling")]
#[inline]
pub(crate) fn tick_entry(on: bool, deadline: std::time::Instant, now: std::time::Instant) {
    recorder::tick_entry(on, deadline, now);
}

#[cfg(not(feature = "profiling"))]
#[inline]
pub(crate) fn tick_entry(_on: bool, _deadline: std::time::Instant, _now: std::time::Instant) {}

/// Sample the per-tick gauges taken from node state.
#[cfg(feature = "profiling")]
#[inline]
pub(crate) fn tick_gauges(on: bool, peers: u64) {
    recorder::tick_gauges(on, peers);
}

#[cfg(not(feature = "profiling"))]
#[inline]
pub(crate) fn tick_gauges(_on: bool, _peers: u64) {}

/// Stop and reap any running capture at daemon teardown. Idempotent.
#[cfg(feature = "profiling")]
pub(crate) fn shutdown() {
    capture::shutdown();
}

#[cfg(not(feature = "profiling"))]
pub(crate) fn shutdown() {}

/// One serialization lock for every test in this module tree.
///
/// The recorder counters and the capture state machine are the *same* process
/// statics: `capture::start` calls `recorder::reset`, and `capture::stop`
/// drains every slot. Two suites with their own locks therefore do not
/// serialize against each other, and the feature-on stage runs tests as
/// threads in one process, so a capture round-trip can zero the counters a
/// recorder test is mid-way through asserting on. One lock for both.
#[cfg(all(test, feature = "profiling"))]
pub(crate) static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take the shared test lock, recovering from a poisoned mutex so one failing
/// test does not cascade into every other one.
#[cfg(all(test, feature = "profiling"))]
pub(crate) fn test_serial() -> std::sync::MutexGuard<'static, ()> {
    TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}
