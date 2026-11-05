# core/src/proto/routing/tests

Unit tests for routing, declared from `routing/mod.rs` as
`#[cfg(test)] mod tests;`.

- `mod.rs`: declares the test files.
- `util.rs`: shared fixtures (a routing view, coordinates).
- `core.rs`: next-hop selection and the transit decision.
- `limits.rs`: the error-signal rate limiter and its bound.
- `wire.rs`: the error-signal codecs, including the refusal of a
  reserved flag bit and of bytes after a body.
