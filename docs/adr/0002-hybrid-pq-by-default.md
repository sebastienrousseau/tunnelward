<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# ADR 0002: Hybrid post-quantum key exchange by default

- Status: Accepted
- Date: 2026-11-07

## Context

Agent traffic carries tool arguments and results that may need to stay
confidential for years, so traffic recorded today and decrypted later by
a quantum computer is a present risk. ML-KEM (FIPS 203) is standardised,
and the hybrid TLS group `X25519MLKEM768` is deployed by major browsers
and TLS libraries. Post-quantum signatures (FIPS 204, 205) are
standardised too, but certificate support around them is still settling.

## Decision

- Every TLS hop is TLS 1.3 only and offers `X25519MLKEM768` first. A
  classical-only fallback exists for old peers and can be switched off.
- Every post-quantum mechanism is hybrid with a classical one, so a flaw
  in either alone does not break confidentiality or authenticity.
- Post-quantum signatures are used first where Tunnelward controls both
  ends (enrolment tokens, leases, audit checkpoints), as composite
  ML-DSA-65 + Ed25519 signatures that both must verify. Certificates move
  when IETF composite certificates and SPIRE support them.
- Algorithms are named in configuration and on the wire, never assumed.

## Consequences

- `tw-crypto` (v0.0.3) carries a test that asserts the negotiated group.
- Handshakes are larger (about 1.1 KiB more each way for ML-KEM-768). On
  long-lived connector connections this is paid once.
- Which rustls provider enables `X25519MLKEM768` by default, and in which
  order, is checked against the pinned versions in v0.0.3, not assumed.
