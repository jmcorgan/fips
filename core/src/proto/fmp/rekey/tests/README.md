# core/src/proto/fmp/rekey/tests

The link rekey profile's tests, attached from `ik.rs` with `#[path]` so
they can name its private items.

- `ik.rs`: a conformance test. It checks that the profile's msg1 and
  msg2 parse with the deployed link parsers and read with a deployed
  Noise IK handshake, that each carries its sender's startup epoch and
  the indices the framing names, that `read_msg1` refuses an altered copy
  or a msg1 for another static key, that a failed msg2 read leaves the
  attempt readable, that the epoch keys open each other's frames over the
  16-byte header with counters from 0 and refuse a repeated counter and
  `2^64 - 1`, and that the prompt is a Heartbeat under the inner header.
- `ik.rs` also holds the replay-record test. A responder's machine built
  from a link setup's `setup_record` takes msg1s read by `read_msg1`: the
  setup msg1 again draws the setup msg2 while the link is young, a copy
  with its sender index rewritten is refused as answered before, a fresh
  msg1 goes to the shell and is remembered, and once the link is old
  enough both setup copies are refused, a fresh msg1 arms a pending, that
  msg1 again draws the same msg2 and a rewritten copy of it is refused.
  It holds the two digests the production profile computes (of the whole
  framed msg1 and of the Noise ephemeral behind the header) to the ones
  the record compares.

Whole rekeys on this profile run in `proto/rekey/tests/legacy/`.
