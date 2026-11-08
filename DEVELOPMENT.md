<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Development

## Toolchain

- Rust 1.89 or newer (stable is what CI uses for everything but the MSRV
  build).
- The gate's tools: `cargo-deny`, `cargo-vet` 0.10, `reuse`, `jq` and
  `rust-code-analysis-cli` 0.0.25.

```bash
cargo install cargo-deny --locked
cargo install cargo-vet --version 0.10.2 --locked
cargo install rust-code-analysis-cli --version 0.0.25 --locked
pipx install reuse
```

## The gate

```bash
cargo xtask ci
```

Runs, in order and stopping at the first failure: `cargo fmt --check`,
`cargo clippy` with warnings denied, `cargo test`, `cargo doc` with
warnings denied, `cargo deny check`, `cargo vet`, `reuse lint` and
`scripts/complexity.sh`. CI runs this command and nothing else on Linux,
so passing it locally means the Linux job passes.

## Nightly-only checks

```bash
rustup toolchain install nightly --component miri
cargo install cargo-fuzz --locked
cargo xtask miri        # tunnelward-proto's tests under Miri
cargo xtask fuzz 60     # replay seeds, then 60 s per fuzz target
```

A fuzz crash leaves its input in `fuzz/artifacts/`. Fix the bug, then
commit that input to `fuzz/seeds/<target>/` so every run replays it.

## Test certificates

`crates/tw-testpki/pki/` holds TEST-ONLY certificates and keys,
written by `scripts/gen-test-pki.sh` (needs the `openssl` CLI). They are
valid for 100 years; regenerate them only if a test needs a new one.

## Supply chain

`cargo vet` must pass, and `scripts/vet.sh` fails if the number of
exempted crates changes without `supply-chain/exemptions-baseline.txt`
changing with it. How a dependency gets vetted, and the maintainer's
trust decisions, are in [supply-chain/README.md](supply-chain/README.md).

## Testing the MSRV on macOS

Older toolchains cannot link against a newer macOS SDK (`tapi error:
malformed file`). Point them at an older SDK:

```bash
SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk \
  cargo +1.89 test --workspace --locked
```

## Layout

| Path | What it holds |
| :--- | :--- |
| `crates/tw-*` | One crate per concern; see the README's ecosystem table |
| `crates/tw-cli` | The `tunnelward` binary |
| `crates/xtask` | Developer tasks, including the gate |
| `scripts/` | Shell helpers the gate calls |
| `supply-chain/` | cargo-vet state |
| `docs/` | Policies; the manual and ADRs land here |

## Demo

`make demo` re-renders `.github/demo.gif` from `.github/demo.tape` with
[VHS](https://github.com/charmbracelet/vhs). Re-render it in any change
that alters what it shows.

## Releasing

Each version is one pull request from `feat/vX.Y.Z` into `main`, merged
with a merge commit. Then, on an up-to-date `main`:

1. `scripts/release-preflight.sh X.Y.Z` must pass: no open alert or
   issue, a clean tree equal to `origin/main`, the version and CHANGELOG
   at the release commit, `docs/releases/vX.Y.Z.md`, and a dry-run
   `cargo publish --workspace`.
2. `git tag -s -a vX.Y.Z -m "tunnelward vX.Y.Z"`, then the preflight
   again, which now also checks the tag's signature, message and target.
3. `git push origin vX.Y.Z`. `.github/workflows/release.yml` builds the
   binaries, SBOM, provenance, signed checksums, Homebrew formula and
   container image, and publishes the GitHub Release titled
   `tunnelward X.Y.Z`.

crates.io: the five crates with code are published from 0.0.8. The
first publish is by hand (`cargo publish --workspace` with a crates.io
token), because trusted publishing can only be set up for a crate that
exists. Then each crate names `release.yml` as its trusted publisher on
crates.io, and the repository variable `CRATES_IO_TRUSTED_PUBLISHING` is
set to `true`; from there the workflow's `crates` job publishes every
release without a stored token. docs.rs builds each published version.
