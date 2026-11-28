<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Policies

## Minimum supported Rust version

The floor is **Rust 1.89**, set by `rust-version` in the workspace
`Cargo.toml` and checked by the `msrv` CI job, which builds every crate
with exactly that toolchain.

- 1.89 matches kyberlib, the sibling crate Tunnelward will use for
  ML-KEM, so the two build on the same toolchain. Edition 2024 needs
  only 1.85.
- The floor may rise in any 0.0.N release, only when a dependency or a
  language feature needs it. The release's CHANGELOG entry names the new
  floor and the reason.
- No Linux distribution's packaged toolchain is promised to build
  Tunnelward. That claim will be made only with a table that maps distro
  toolchains to the floor.

## Versioning

Every release moves the patch number by one (0.0.1, 0.0.2, ...), prepared
on a `feat/v0.0.N` branch and merged through one pull request. Until 0.1.0
any release may change any API; the CHANGELOG says what changed.

## Dependencies

No new third-party dependency without the maintainer's approval of that
named dependency (`~/Code/AGENTS.md` section 11): a capability is built
in this repository, so the code is written, tested and vetted here.
Cryptography (`aws-lc-rs`, `rustls`) and the HTTP/2 stack (`h2`, `hyper`)
stay dependencies. `.dependency-baseline` lists every third-party crate
in `Cargo.lock` and may only shrink; `scripts/deps-baseline.sh` enforces
it in `cargo xtask ci`.

Approved by name:

| Package | Scope | Approved | Why |
| :-- | :-- | :-- | :-- |
| `kyberlib` 0.0.18 | test only (`tunnelward-crypto`) | 0.0.22 | expands X-Wing's draft seeds for its known-answer test (ADR 0016), and checks aws-lc-rs's ML-KEM-768 in `tests/ml_kem_differential.rs` (0.0.23); a second ML-KEM implementation, not ours to write |
| `rand_core` 0.6 | test only: `kyberlib`'s own dependency, and from 0.0.23 a direct dev-dependency of `tunnelward-crypto` for `kyberlib`'s RNG trait | 0.0.22 | no package added: the same locked version |
| `signal-hook-registry` 1.4 | runtime (`tunnelward`, through tokio's `signal` feature) | 0.0.23 | graceful shutdown on SIGTERM and SIGINT; a signal handler needs `unsafe` code, which this workspace forbids |
| `errno` 0.3 | runtime, through `signal-hook-registry` 1.4.8 | 0.0.23 | restores `errno` when a signal handler returns (signal-hook-registry 1.4.8) |

## Complexity

Every function stays within cyclomatic complexity 10, cognitive complexity
15, Halstead difficulty 30 and 60 source lines, and every file within 500
source lines. Clippy (`clippy.toml`) and `scripts/complexity.sh` enforce
these in `cargo xtask ci`. `.complexity-baseline` lists accepted
offenders and may only shrink; it is empty.
