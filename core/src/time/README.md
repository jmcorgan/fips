# core/src/time

How the core takes time from its host. The core never reads a clock: a
type that measures time takes the host's clock as a type parameter and
takes the clock's instants as method arguments, and the host reads its
clock and passes them in. This is the time counterpart of
`entropy.rs`, one level up.

## Files

- `mod.rs`: `Duration` (re-exported from `core::time`), the `Instant`
  trait and the `Clock` trait. `Instant` is a point on a monotonic
  clock, `Copy + Ord`, with three arithmetic methods:
  `saturating_duration_since`, `checked_add` and `checked_sub`. `Clock`
  names its instant type and reads it with `now`. Two helpers build on
  them: `deadline(now, d)`, `now + d` with `d` capped at `CEILING` (100
  years) and halved until it fits, so it never overflows or panics; and
  `backoff(exponent, base, cap)`, `base` doubled `exponent` times,
  saturating, and capped at `cap`.
- `tests.rs`: the unit tests. They check the arithmetic contract on the
  millisecond test instant (`testutil::TestInstant`) and on a 32 768 Hz
  tick-count instant defined in the test, the shape of an embedded
  timer's clock, and the two helpers, at the cap and at the end of an
  instant's range.

## How a type uses it

A type that measures time is generic over `C: Clock`, holds
`PhantomData<fn() -> C>` if it stores no instant, and its methods take
`now: C::Instant`. It uses only the trait's methods on instants. The
root crate fixes `C` with an alias over its `HostClock`; the core's
tests use `testutil::TestClock`.

A type that only holds the instants it is handed, never the clock, is
generic over `I: Instant` and takes the instants as arguments in the
same way, as rekey's `Ladder<I>`, `SetupFacts<I>` and `Carry<I>` and
`proto::path::PathSet<I, D>` are. The root crate fixes `I` with an alias
over its `HostClock`'s instant; the core's tests use
`testutil::TestInstant`.

## Invariants

- **The core never calls `Clock::now`.** Only a host does. The trait
  carries `now` so a host has one name for its clock and its instant
  type together.
- **No `std`, no allocation.** An instant is a small `Copy` value; the
  traits must stay implementable by a bare-metal timer such as
  embassy-time's tick count, converting durations at its own edge.
- **Monotonic.** A `Clock`'s successive reads never go backwards. A
  host that adapts a clock that can step (a wall clock) breaks the
  contract and must say so at the type.
- **Arithmetic saturates or reports.** A difference saturates at zero;
  an add or subtract past either end of the representation is `None`,
  never a panic or a wrap.
- **Two end-of-range rules, each deliberate.** `deadline` stops at or
  before the end of an instant's range and never reaches past
  `CEILING`. The rekey machine's own `ladder::later` adds a step in full
  and falls due at once past the end of the range, the safe side for a
  rekey expiry. Neither replaces the other.
