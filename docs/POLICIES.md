<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Policies

## Minimum supported Rust version

The floor is **Rust 1.85**, set by `rust-version` in the workspace
`Cargo.toml` and checked by the `msrv` CI job, which builds every crate
with exactly that toolchain.

- 1.85 is the first release with edition 2024, which the workspace uses.
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

## Complexity

Every function stays within cyclomatic complexity 10, cognitive complexity
15, Halstead difficulty 30 and 60 source lines, and every file within 500
source lines. Clippy (`clippy.toml`) and `scripts/complexity.sh` enforce
these in `cargo xtask ci`. `.complexity-baseline` lists accepted
offenders and may only shrink; it is empty.
