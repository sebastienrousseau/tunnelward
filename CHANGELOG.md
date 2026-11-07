<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow the 0.0.N release train described in `AGENTS.md`.

## [0.0.2]

### Added

- `tw-proto`: the `Register`, `Accept` and `Reject` frames, stable
  `RejectCode` numbers, the hard-limits table as `Limits`, validation of
  SPIFFE IDs and route claims, and a length-prefixed CBOR codec that
  checks the length before reading the body.
- Property tests (round trip; arbitrary bytes never panic or overrun),
  a `decode` fuzz target with a seed corpus, and Miri on `tw-proto`.
- `cargo xtask miri` and `cargo xtask fuzz [seconds]`, with CI jobs;
  a weekly 30-minute fuzz run.
- ADRs 0001 (reverse HTTP/2), 0002 (hybrid PQ by default) and 0003
  (cbor4ii for the register frames).
- Release tooling: a signed tag `vX.Y.Z` builds `tunnelward` for five
  platforms and publishes a GitHub Release with SHA-256 checksums, a
  CycloneDX SBOM, SLSA provenance and a rendered Homebrew formula, plus a
  cosign-signed container image on GHCR (`.github/workflows/release.yml`).
  `scripts/release-preflight.sh` blocks a tag while any alert or issue
  is open. Notes Highlights live in `docs/releases/`.
- CodeQL code scanning for Rust and the workflows.
- cargo-vet imports from seven peer organisations, publisher trust
  matching kyberlib's, and a ratchet that stops exemptions growing.

### Changed

- MSRV is 1.89.
- cargo-deny now fails on duplicate crate versions instead of warning.

## [0.0.1]

### Added

- Cargo workspace (edition 2024, resolver 3, MSRV 1.89) with one crate
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

[0.0.2]: https://github.com/sebastienrousseau/tunnelward/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/sebastienrousseau/tunnelward/releases/tag/v0.0.1
