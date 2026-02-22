# Contributing to FIPS

## Getting Started

Clone the repo and verify your setup:

```
git clone https://github.com/jmcorgan/fips.git
cd fips
cargo build
cargo test
```

Read [docs/design/](docs/design/) for protocol understanding, starting with
[fips-intro.md](docs/design/fips-intro.md).

## Filing Issues

- Search existing issues before opening a new one.
- Include FIPS version, Rust version, and OS.
- For bugs: steps to reproduce, expected vs actual behavior.

## Pull Requests

- All PRs must pass `cargo build`, `cargo test`, and `cargo clippy` with no
  warnings.
- Keep commits focused — one logical change per commit.
- Add tests for new functionality.
- Reference relevant design docs if the change touches protocol behavior.

## Questions

Open a GitHub issue for design or implementation questions.
