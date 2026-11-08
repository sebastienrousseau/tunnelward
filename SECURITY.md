<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Security Policy

Tunnelward is a gateway and connector that carry AI-agent traffic into
private networks, so a flaw in it can expose the services behind it. At
v0.0.1 the repository holds a workspace skeleton and no network code; this
policy applies from the first release onwards.

## Reporting a Vulnerability

Report security issues through GitHub's private vulnerability reporting on
the repository (Security, then "Report a vulnerability"). Do not open a
public issue.

You will receive an acknowledgement within **72 hours**. A confirmed
vulnerability is fixed and released within **90 days** of the report, or
sooner when a fix is straightforward; if the window cannot be met you will
be told why and given a revised date.

## Supported Versions

Only the latest release is supported. A security fix ships as the next
release (the patch number moves by one), never as a backport.

## Security Measures

Each item names what enforces it. Nothing is listed that is not checked
mechanically.

- **No `unsafe` code in Tunnelward crates.** `unsafe_code = "forbid"`
  in `[workspace.lints.rust]` (`Cargo.toml`), applied to every crate.
- **TLS 1.3 only, hybrid post-quantum key exchange first.** `tunnelward-crypto`
  builds every TLS configuration; TLS 1.2 is not compiled in. The
  handshake tests assert `X25519MLKEM768` is negotiated, that
  `HybridOnly` refuses a classical-only peer, and that mutual TLS rejects
  a missing or foreign client certificate
  (`crates/tw-crypto/tests/handshake.rs`).
- **A connector is admitted only through a bounded handshake.** The
  gateway closes a connection that does not negotiate ALPN `tw/1`,
  refuses a frame whose length prefix is over the limit before reading
  its body, answers an invalid frame with `Reject`, and drops a
  connection that sends nothing within the registration timeout
  (`crates/tw-gateway/tests/tunnel.rs`).
- **A client cannot choose its own address.** The ingress believes
  `Forwarded`, `X-Forwarded-For` and PROXY headers only from configured
  trusted proxies, removes whatever forwarding headers a client sent,
  and states the resolved client once (`crates/tw-gateway/tests/ingress.rs`,
  `src/client_addr.rs`, `src/forwarding.rs`). The PROXY protocol parser is
  fuzzed (`fuzz/fuzz_targets/proxy.rs`).
- **No panicking shortcuts outside tests.** `unwrap_used`, `expect_used`
  and `panic` are denied in `[workspace.lints.clippy]`.
- **Dependencies are checked for advisories, licences and sources** by
  `cargo deny` (`deny.toml`) and for provenance by `cargo vet`
  (`supply-chain/`), both run by `cargo xtask ci` on every pull request.
- **GitHub Actions are pinned to commit SHAs** (`.github/workflows/`),
  and Dependabot watches Cargo and Actions (`.github/dependabot.yml`).
- **Every file's licence is machine-readable**, checked by `reuse lint`.
- **Commits are signed and carry a DCO sign-off.**

The threat model and the controls planned against it are in the
specification; they become entries here only as each one is built and
tested.
