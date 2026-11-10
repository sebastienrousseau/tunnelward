<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# ADR 0007: Composite ML-DSA-65 and Ed25519 signatures

- Status: Accepted, implemented in 0.0.12
- Date: 2026-11-09

## Context

The plan puts post-quantum signatures first where Tunnelward controls
both ends, each hybrid with a classical algorithm so a flaw in either
alone breaks nothing (ADR 0002 made the same choice for key exchange).
It listed enrolment tokens and registration leases as the first
artefacts to sign.

By 0.0.12, enrolment tokens are random 256-bit secrets checked against
a stored hash, not signed statements, and leases are granted inside the
connector's mutual TLS session and read by nothing outside it. Neither
would gain from a signature. Provider snapshots would: they decide which
requests are tagged as an AI provider's, and gateways trust them only by
signature.

The IETF LAMPS composite-signature draft defines an encoding, OIDs and a
message construction, but is still a draft that has changed between
revisions, and no peer of Tunnelward needs to read these signatures.

## Decision

- `tunnelward_crypto::composite` signs with ML-DSA-65 (FIPS 204) and
  Ed25519, both from aws-lc-rs, over the same message behind a fixed
  domain label, and verifies only when both halves do.
- The format is Tunnelward's own: a public key is the Ed25519 key then
  the ML-DSA-65 key (1,984 bytes); a signature is the Ed25519 signature
  then the ML-DSA-65 one (3,373 bytes). It does not claim to be the
  LAMPS encoding.
- Provider snapshots use it. A composite public key accepts only a
  composite signature, so the post-quantum half cannot be stripped off.
  Ed25519 keys made before 0.0.12 still work.
- ML-DSA-65 is checked against NIST ACVP vectors kept in the
  repository under NIST's notice.

## When to revisit

Move to the LAMPS encoding when it is published as an RFC and a peer
(SPIRE, a certificate authority, another gateway implementation) needs
to read Tunnelward's signatures, and use it for SVIDs when composite
certificates are supported end to end.

## Consequences

- Snapshot signatures and keys are large (3,373 and 1,984 bytes); the
  public key goes in a file (`<key>.pub`, `[providers] key_files`).
- Anything Tunnelward signs from now on should use this module rather
  than Ed25519 alone.
