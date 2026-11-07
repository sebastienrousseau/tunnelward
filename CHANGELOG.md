<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow the 0.0.N release train described in `AGENTS.md`.

## [0.0.1]

### Added

- Cargo workspace (edition 2024, resolver 3, MSRV 1.85) with one crate
  per concern: `tw-proto`, `tw-crypto`, `tw-identity`, `tw-attest`,
  `tw-policy`, `tw-mcp`, `tw-audit`, `tw-gateway`, `tw-connector`.
  They are placeholders; the code arrives from v0.0.2.
- `tunnelward` binary (`tw-cli`) that prints its version and usage.
- `cargo xtask ci`, the single gate: format, clippy, tests, docs,
  cargo-deny, cargo-vet, REUSE and the complexity ceilings.
- CI workflow running the gate on Linux, tests on macOS and Windows, and
  an MSRV build.
- Licence GPL-3.0-only, REUSE metadata, security policy, contribution
  guide, code of conduct and agent instructions.

[0.0.1]: https://github.com/sebastienrousseau/tunnelward/releases/tag/v0.0.1
