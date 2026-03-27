# Contributing to FIPS

## Getting Started

Clone the repo:

```
git clone https://github.com/jmcorgan/fips.git
cd fips
```

Before changing code, read the protocol docs in this order:

- [docs/design/README.md](docs/design/README.md)
- [docs/design/fips-intro.md](docs/design/fips-intro.md)
- the specific design doc for the behavior you are touching

## Prerequisites

- Rust 1.94.0 and Linux with TUN support
- Use the pinned toolchain from [rust-toolchain.toml](rust-toolchain.toml) for deterministic builds
- For the default BLE-enabled build on Debian/Ubuntu:
  `sudo apt install bluez libdbus-1-dev pkg-config`
- Docker is required for the integration harnesses under [testing/](testing/)

If you do not want BLE locally, build and test without default features:

```bash
cargo build --no-default-features --features tui
cargo test --no-default-features --features tui
```

## Local Verification

Choose the narrowest check that matches your change:

- Docs-only changes:

```bash
git diff --check
```

- Normal code changes:

```bash
cargo build
cargo test
cargo clippy --all -- -D warnings
```

- Local CI-style unit test run:

```bash
./testing/ci-local.sh --test-only
```

- Narrow integration run for transport, routing, Docker, or packaging-sensitive changes:

```bash
./testing/ci-local.sh --only static-mesh
```

See [testing/README.md](testing/README.md) for the available integration and chaos harnesses.

## Filing Issues

- Search existing issues before opening a new one.
- Include FIPS version, Rust version, and OS.
- For bugs: steps to reproduce, expected vs actual behavior.

## Pull Requests

- All PRs must pass `cargo build`, `cargo test`, and `cargo clippy --all -- -D warnings`.
- Keep commits focused — one logical change per commit.
- Add tests for new functionality.
- Reference relevant design docs if the change touches protocol behavior.
- Update docs in the same change when you modify:
  - protocol or routing behavior
  - wire formats
  - configuration shape or defaults
  - operational workflows or testing instructions

In practice this usually means updating one or more of:

- [docs/design/fips-mesh-operation.md](docs/design/fips-mesh-operation.md)
- [docs/design/fips-wire-formats.md](docs/design/fips-wire-formats.md)
- [docs/design/fips-configuration.md](docs/design/fips-configuration.md)
- [README.md](README.md)
- [testing/README.md](testing/README.md)

## Questions

Open a GitHub issue for design or implementation questions.
