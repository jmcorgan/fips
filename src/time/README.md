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
  - `wall_ms()`: Unix time in milliseconds. `Node::now_ms` delegates to
    it.
  - `WallStamp`: Unix milliseconds of an instant, for the control API
    and logs. For a `HostInstant` it is the wall clock now less the
    instant's monotonic age.
  - `deadline(now, d)`: `now + d`, with `d` capped at `CEILING` (100
    years) so it never overflows or panics.
  - Test only: `step_wall` and `advance`, per-thread offsets on the
    wall and monotonic clocks, and `TestEpoch` with `at::<C>(ms)`, an
    instant `ms` milliseconds after a clock's fixed test epoch.
- `tests.rs`: the unit tests for `mod.rs`.

## Rules

- **Read clocks here, at the edge.** Code that decides takes the
  instant as an argument; only the shell calls `HostClock.now()`,
  `mono_ms()` or `wall_ms()`.
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
