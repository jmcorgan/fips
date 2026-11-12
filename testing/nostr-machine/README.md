# testing/nostr-machine

Fixture tests for `testing/check-nostr-machine.py`, the guard that keeps
`src/nostr/machine/` inside its fence.

The machine module is written to build without `std`, and to name nothing in
the root crate but itself, but nothing compiles it that way. The guard reads
its committed files as text and fails on a path rooted at a host crate (`std`,
`tokio`, `tracing`, `nostr_sdk`, `rand`, `libc`, `if_addrs`, `socket2`,
`arc_swap`), on a `crate::` path outside `crate::nostr::machine`, on a `super`
chain that climbs out of the module, on the macros and attributes that reach
outside with no path written, and on a test module not gated by
`#[cfg(test)]`. Its docstring lists every rule, its known
gaps, and its exit codes (0 pass, 1 finding, 2 cannot check).

## Files

- `test.sh`: the fixture runner. It runs from local CI's guards
  (`run_nostr_machine` in `testing/ci-local.sh`) and from the same job in
  `.github/workflows/ci.yml` that runs the portable-atomics guard; the two are
  kept in step by hand. It also checks that an empty tree exits 2.
- `base.fixture`: a small tree laid out as `src/nostr/machine/` that must pass.
  It is one file holding several: after its header, each `=== <path>` line
  starts a file at that path. It holds each in-module path shape the guard must
  let through, and each way text only looks like a banned path (comments,
  strings, raw strings, a `'"'` char literal, a test file).
- `*.case`: one case each, in the same format. The runner writes a case's files
  over a copy of the base tree. The header's `#` line says what the case
  breaks; `expect exit N` is the status the guard must return, and each
  `expect <text>` or `expect-absent <text>` is a string its output must or must
  not contain, so a case that fails for the wrong reason fails the runner.

## Rules for changing it

- Each rule the guard applies is shown to fire by a case. A change that removes
  a rule, or makes one pass on input it cannot read, should turn a case red; if
  no case turns red, add one.
- A new banned crate or macro gets its case in the same change.
- The fixture trees are never compiled. They need only the text the guard
  reads, written as real code would be.
