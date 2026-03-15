# AGENTS.md

This file is for coding agents working in `fips`.

## Scope

- Repository: `fips`
- Language: Rust (`edition = 2024`)
- Primary targets: `fips` daemon, `fipsctl` CLI, `fipstop` TUI
- Platform assumptions: Linux first; some code is gated with `#[cfg(target_os = "linux")]`
- Architecture: protocol-heavy mesh networking stack with transport, link, session, routing, TUN, DNS, and control layers

## Read This First

- Read `docs/README.md` and `docs/design/README.md` for the document map.
- Start protocol work from `docs/design/fips-intro.md`.
- For behavior changes, consult the specific design doc first:
  - transport: `docs/design/fips-transport-layer.md`
  - link/mesh: `docs/design/fips-mesh-layer.md`
  - routing/tree/bloom: `docs/design/fips-mesh-operation.md`, `docs/design/fips-spanning-tree.md`, `docs/design/fips-bloom-filters.md`
  - session layer: `docs/design/fips-session-layer.md`
  - wire formats: `docs/design/fips-wire-formats.md`
  - config: `docs/design/fips-configuration.md`
  - IPv6/TUN/DNS: `docs/design/fips-ipv6-adapter.md`
  - connection details: `docs/connection-lifecycle.md`

## External Agent Rules

- No `.cursor/rules/` directory was present when this file was generated.
- No `.cursorrules` file was present.
- No `.github/copilot-instructions.md` file was present.
- Do not assume any hidden editor-specific rules beyond this file and the repo docs.

## Build Commands

- Debug build: `cargo build`
- Release build: `cargo build --release`
- Build all default targets exactly like CI build stage: `cargo build --release`
- Build without relying on workspace features: `cargo build --manifest-path Cargo.toml`

## Lint And Format

- Format: `cargo fmt`
- Check formatting only: `cargo fmt -- --check`
- Lint exactly as local CI does: `cargo clippy --all -- -D warnings`
- There is no repo-local `rustfmt.toml` or `clippy.toml`; use standard tool defaults unless the code already establishes a local pattern.

## Unit Test Commands

- Run all tests with Cargo: `cargo test --all`
- Run all tests with nextest (preferred when installed): `cargo nextest run --all`
- CI profile for nextest: `cargo nextest run --all --profile ci`
- Run library tests only: `cargo test --lib`
- Run one exact test by full path: `cargo test --lib node::tests::unit::test_node_creation -- --exact`
- Run one exact non-node test: `cargo test --lib noise::tests::test_full_handshake -- --exact`
- Run a module or prefix match: `cargo test --lib node::tests::disconnect`
- If `cargo-nextest` is not available, fall back to `cargo test --all`.

## Integration And System Test Commands

- Local CI pipeline: `./testing/ci-local.sh`
- Build + clippy only: `./testing/ci-local.sh --build-only`
- Unit tests only: `./testing/ci-local.sh --test-only`
- Skip integration suites: `./testing/ci-local.sh --skip-integration`
- Run a single integration suite: `./testing/ci-local.sh --only static-mesh`
- Run one chaos suite through local CI: `./testing/ci-local.sh --only chaos-smoke-10`
- Run sidecar suite through local CI: `./testing/ci-local.sh --only sidecar`

## Static Docker Harness

- Build binary, generate configs, and build images: `./testing/static/scripts/build.sh`
- Build a specific topology: `./testing/static/scripts/build.sh mesh`
- Generate configs only: `./testing/static/scripts/generate-configs.sh mesh`
- Start static topology manually: `docker compose -f testing/static/docker-compose.yml --profile mesh up -d`
- Ping test: `./testing/static/scripts/ping-test.sh mesh`
- Throughput test: `./testing/static/scripts/iperf-test.sh mesh`
- Stop topology: `docker compose -f testing/static/docker-compose.yml --profile mesh down --volumes --remove-orphans`
- Rekey integration flow: `./testing/static/scripts/generate-configs.sh rekey` then `./testing/static/scripts/rekey-test.sh`

## Chaos Harness

- Build chaos artifacts: `./testing/chaos/scripts/build.sh`
- Run default smoke scenario: `./testing/chaos/scripts/chaos.sh smoke-10`
- List scenarios: `./testing/chaos/scripts/chaos.sh --list`
- Run a scenario with overrides: `./testing/chaos/scripts/chaos.sh chaos-10 --seed 123 --duration 60`

## Sidecar Harness

- Build sidecar images: `./testing/sidecar/scripts/build.sh`
- Run sidecar test directly: `./testing/sidecar/scripts/test-sidecar.sh`

## Before Making Changes

- Check whether the change is protocol, wire format, config, or operational behavior.
- For protocol-affecting changes, verify the implementation still matches the design docs, or update docs in the same change.
- Prefer small, targeted changes; this codebase has many interacting subsystems.
- Preserve Linux-only guards where they already exist.

## Code Organization Hints

- `src/node/`: orchestration, handshake handling, forwarding, retry, lifecycle
- `src/protocol/`: wire-level encode/decode and protocol types
- `src/transport/`: UDP, TCP, Ethernet transports and abstractions
- `src/noise/`: Noise handshake/session/replay logic
- `src/tree/`, `src/bloom/`, `src/cache/`: routing data structures
- `src/upper/`: TUN, DNS, IPv6 shim, ICMP helpers
- `src/config/`: YAML config loading and defaults
- `src/node/tests/`: heavy integration-style unit tests for node behavior

## Style Guidelines

- Use `cargo fmt`; do not hand-format against rustfmt unless preserving a deliberate local style in touched code.
- Follow existing Rust naming: `snake_case` for functions/modules/fields, `CamelCase` for types, `UPPER_SNAKE_CASE` for constants.
- Keep domain-specific suffixes meaningful: `*_ms`, `*_secs`, `*_count`, `*_at`, `*_addr`, `*_id`, `*_idx`.
- Prefer domain types over primitive aliases when available: `NodeAddr`, `TransportId`, `LinkId`, `SessionIndex`, `TransportAddr`.
- Reuse existing config and protocol structs instead of introducing ad hoc maps or tuples when a typed model already exists.
- Keep methods small and state-machine-oriented; early returns are common and fit the existing style.

## Imports

- Match the surrounding file's import style instead of mass-reordering imports.
- Use grouped brace imports where the file already does so, for example `use tracing::{debug, info, warn};`.
- Keep `#[cfg(...)]` imports adjacent to the related import they gate.
- Avoid broad `use super::*;` outside tests unless the file already follows that pattern.

## Error Handling

- Use typed error enums with `thiserror::Error`; this is the repo norm across modules.
- Return `Result<_, ModuleError>` or `Result<_, NodeError>` rather than `anyhow`/`eyre`.
- Convert lower-level failures into domain errors with context at subsystem boundaries.
- Do not introduce panics in production paths for recoverable failures.
- `unwrap()` and `expect()` are acceptable in tests; avoid them in runtime code unless the invariant is truly internal and well-established.
- Many invalid network inputs are intentionally dropped silently or with `debug!` logging; preserve that policy where protocol behavior expects it.

## Logging And Observability

- Use `tracing`, not `println!`.
- Follow existing level conventions:
  - `trace!`/`debug!` for packet flow and noisy state transitions
  - `info!` for operator-visible lifecycle and important protocol events
  - `warn!` for degraded but recoverable conditions
  - `error!` in binaries for fatal startup/shutdown failures
- Keep log fields structured (`peer = %...`, `transport_id = %...`) rather than embedding everything in free text.

## Types, Ownership, And Concurrency

- This repo prefers explicit state and ownership over hidden shared mutability.
- Keep `Node` state single-threaded unless there is a strong reason otherwise; the daemon runs on Tokio current-thread.
- Do not introduce `Arc<Mutex<_>>` into core node logic unless there is already an async/task boundary requiring it.
- Use channels and task boundaries the way transports and TUN code already do.
- Be careful with `NoiseSession` and similar stateful crypto objects; avoid cloning or duplicating nonce-bearing state.

## Testing Expectations For Changes

- Add or update unit tests for new protocol logic, parser changes, routing behavior, and config defaults.
- Prefer nearby tests for local logic (`src/<module>/tests.rs`) and `src/node/tests/` for end-to-end node behavior.
- If you touch transport/TUN/Docker behavior, run the narrowest relevant integration harness you can.
- If you change config defaults or YAML shape, add/adjust serde tests and update `docs/design/fips-configuration.md`.
- If you change a wire format, update tests and `docs/design/fips-wire-formats.md` in the same change.

## Documentation Update Rules

- Update docs whenever behavior, config semantics, wire layout, or operational workflows change.
- Prefer keeping design docs authoritative rather than adding conflicting comments in code.
- Use code comments sparingly; the repo already favors module docs and design docs over dense inline commentary.

## Good Defaults For Agents

- For small code changes: run `cargo test --lib <relevant-path-fragment>` or one exact test.
- For medium changes: run `cargo test --all`.
- Before handing off substantial Rust changes: run `cargo clippy --all -- -D warnings`.
- For protocol or integration-sensitive changes: run the smallest relevant harness from `testing/` in addition to unit tests.
