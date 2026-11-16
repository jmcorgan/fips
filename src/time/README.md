# src/time

The daemon's clocks: where the host reads time and hands it to the
sans-IO cores. The core's side of the seam, the `Clock` and `Instant`
traits, is `fips_core::time` (`core/src/time/`).

## Files

- `mod.rs`:
  - `HostClock` and `HostInstant`: the process's monotonic clock as the
    core's `Clock`, over `std::time::Instant`. `HostInstant` converts to
    and from `std::time::Instant` for code that still holds those.
  - `mono_ms()`: the same monotonic clock as `u64` milliseconds from the
    process's first read, for the cores that still take milliseconds.
    `mono_ms_at(instant)` reads a `HostInstant` on that scale, so a time
    held as an instant compares exactly with one held as milliseconds.
  - `mono_now()`: now on `HostClock`, as a `std::time::Instant`, for
    code that stores std instants and measures intervals from them (the
    routing hold, the restart dampener, the per-peer budgets). Outside
    tests it is `std::time::Instant::now()`.
  - `wall_ms()`: Unix time in milliseconds. `Node::now_ms` delegates to
    it, and so does the receive stamp on every `ReceivedPacket`.
  - `WallStamp`: Unix milliseconds of an instant, for the control API
    and logs. For a `HostInstant` it is the wall clock now less the
    instant's monotonic age.
  - `deadline(now, d)`: `fips_core::time::deadline`, re-exported for
    the shell's timers: `now + d`, with `d` capped at `CEILING` (100
    years) so it never overflows or panics. Its tests here run through
    the re-export, on the host clock and on a test instant whose whole
    range they can reach.
  - Test only: `step_wall` and `advance`, per-thread offsets on the
    wall and monotonic clocks; `freeze`, which starts the process's
    monotonic epoch if nothing has yet, so the frozen instant is never
    before it, then stops the thread's monotonic clock so that only
    `advance` moves it; and `TestEpoch`
    with `at::<C>(ms)`, an instant `ms` milliseconds after a clock's
    fixed test epoch.
- `tests.rs`: the unit tests for `mod.rs`.

## Rules

- **Read clocks here, at the edge.** Code that decides takes the
  instant as an argument; only the shell calls `HostClock.now()`,
  `mono_ms()`, `mono_now()` or `wall_ms()`.
- **Read the node's clocks through here, not through `std::time`.** The
  test hooks move these functions only, so a stamp taken from
  `SystemTime::now()` or `Instant::now()` and compared with one taken here
  drifts apart from it in a test that steps or advances a clock. A site
  that reads `std::time` directly says at the site why the difference
  cannot change an outcome.
- **Monotonic for intervals, wall for stamps.** Timeouts, rate limits
  and schedules measure on `HostClock` or `mono_ms`; wall time is for
  what goes on the wire or is reported as a date.
- **The test hooks stay `#[cfg(test)]`.** They exist only in test
  builds, so no other build can step a clock. They are thread-local:
  each test thread sees its own offsets, and a multi-thread runtime's
  workers do not see them.
- **Tests name instants through `at`**, not through a clock's concrete
  instant type, so a test does not change when the code it tests
  changes clocks.
