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
cargo xtask miri        # tw-proto's tests under Miri
cargo xtask fuzz 60     # replay seeds, then 60 s per fuzz target
```

A fuzz crash leaves its input in `fuzz/artifacts/`. Fix the bug, then
commit that input to `fuzz/seeds/<target>/` so every run replays it.

## Test certificates

`crates/tw-crypto/tests/pki/` holds TEST-ONLY certificates and keys,
written by `scripts/gen-test-pki.sh` (needs the `openssl` CLI). They are
valid for 100 years; regenerate them only if a test needs a new one.

## Supply chain

`cargo vet` must pass, and `scripts/vet.sh` fails if the number of
exempted crates changes without `supply-chain/exemptions-baseline.txt`
changing with it. A new dependency comes with an audit
(`cargo vet certify`) or a trust entry, never a new exemption.

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
