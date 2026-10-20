# core/src/proto/fsp/rekey/tests

The session rekey profile's tests, attached from `xk.rs` with `#[path]`
so they can name its private items.

- `xk.rs`: one conformance test. It checks that a setup is a 33-byte XK
  msg1 a deployed responder reads and that malformed ones fail `valid`,
  that the ack and msg3 carry their senders' startup epochs and msg3 the
  initiator's static key, that a failed read leaves the handshake
  readable, that the epoch keys open each other's frames over the 12-byte
  header with coordinates between the header and the ciphertext, and
  that the prompt is a `CoordsWarmup` inner header that `is_probe` takes
  and nothing else is.

Whole rekeys and first handshakes on this profile run in
`proto/rekey/tests/legacy/`.
