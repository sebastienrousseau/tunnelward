<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Development

## Toolchain

- Rust 1.85 or newer (stable is what CI uses for everything but the MSRV
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
