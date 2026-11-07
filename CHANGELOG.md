<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow the 0.0.N release train described in `AGENTS.md`.

## [0.0.3]

### Added

- `tw-crypto`: rustls server and client configurations on the AWS-LC
  provider, TLS 1.3 only (TLS 1.2 is not compiled in), offering the
  hybrid group `X25519MLKEM768` first. `KeyExchange::HybridOnly` drops
  the classical fallback. Servers either require a client certificate
  from given roots (connector listener) or ask for none (agent ingress).
  `negotiated_group` reports the group a handshake used. `Identity`
  never prints its key.
- Handshake tests that assert the negotiated group, the X25519 fallback,
  the hybrid-only refusal, and mutual-TLS acceptance and rejection,
  against TEST-ONLY certificates from `scripts/gen-test-pki.sh`.

### Notes

- Checked against rustls 0.23.46: with the `aws_lc_rs` and
  `prefer-post-quantum` features its default group list starts with
  `X25519MLKEM768`. Tunnelward sets the list itself, so a change of
  upstream default does not change what it offers.
- cargo-vet: the rustls project's publishers (ctz, cpu, djc) are newly
  trusted; the others match kyberlib's existing trust. The r-efi
  exemption now covers safe-to-deploy, because aws-lc-sys's build
  reaches it on UEFI hosts, so the exemption baseline is 3 for the
  same three crates.

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

[0.0.3]: https://github.com/sebastienrousseau/tunnelward/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/sebastienrousseau/tunnelward/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/sebastienrousseau/tunnelward/releases/tag/v0.0.1
