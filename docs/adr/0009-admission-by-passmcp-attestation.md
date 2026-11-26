<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# ADR 0009: Admission by passmcp attestation, signed by keys the operator names

- Status: Accepted, implemented in 0.0.15
- Date: 2026-11-26

## Context

FR-5 lets a route require that the MCP server behind a connector holds
a valid passmcp attestation: signed by a trusted key, about the server
the connector fronts, not expired and not revoked. A revoked one must
drain the connector within one lease.

passmcp writes an in-toto Statement v1 with predicate type
`https://satellion.com/attestation/mcp-evaluation/v1`. Its subject
digest is the SHA-256 of `transport + "\n" + endpoint`, a descriptor of
the target rather than a hash of an artifact. passmcp signs nothing: it
leaves that to cosign (`cosign attest-blob --statement`), which writes a
Sigstore bundle holding a DSSE envelope. With `--key`, the signature is
ECDSA P-256 over SHA-256, DER-encoded, over the DSSE pre-authentication
encoding. A statement carries no expiry.

The gateway never sees the MCP server. Only the connector does, and the
connector is the party the check is about.

## Decision

- **The gateway reads a DSSE envelope, bare or inside a Sigstore
  bundle** (`dsseEnvelope`), with payload type
  `application/vnd.in-toto+json`. Everything else in a bundle,
  including its verification material, is ignored.
- **Trust is a list of public keys in the gateway's configuration**
  (PEM `PUBLIC KEY`, as `cosign generate-key-pair` writes): ECDSA P-256
  with SHA-256, or Ed25519. A statement is signed when any of its
  signatures (at most 8) verifies under any configured key. Keyless
  Sigstore (a Fulcio certificate, a Rekor inclusion proof, a TUF trust
  root) is not supported: it needs an X.509 chain builder, SCT and
  Merkle proof checks and an online trust root, about a dozen crates
  no imported audit covers, for a check an operator can make with a
  key they already hold. The transparency log is not consulted.
- **The statement is checked as passmcp checks it**: statement and
  predicate types, one subject named for the target's endpoint, every
  SHA-256 and SHA-512 subject digest recomputed from the descriptor,
  the subject kind, a known transport, an identified instrument, a run
  time, at least one verdict, a check-inventory version, a rubric
  beside any score, and counts that agree with the verdicts.
- **Each route that requires one has a rule.** It names the targets
  the route may be served by (`transport` and `endpoint`, at least
  one), and the subject digest must be one of theirs. A statement is
  fresh for `max_age` after its `ranAt` (default 30 days) and refused
  if it ran more than 5 minutes in the future. At most `max_fail`
  checks may have failed (default 0), every check in `require` must
  have passed, and the score must reach `min_score` when one is set.
  When the connector sends an `McpDescriptor` and the statement names
  the server, their name and version must be equal.
- **Revocation is a file of statement digests**: the SHA-256 of the
  DSSE payload, hex, one per line, `#` for comments.
  `tunnelward attest verify` prints the digest. When the gateway's
  configuration is reloaded, every connection admitted with a now
  revoked statement drains at once, with `drain_grace`.
- **A connection is admitted once per lease.** A statement that ages
  past `max_age`, or a rule that tightens, takes effect when the lease
  ends and the connector registers again (ADR 0005).
- **Refusals use the codes reserved for them**: no attestation where a
  route needs one is `AttestationRequired` (TW-R006); anything else
  wrong with it is `AttestationInvalid` (TW-R007), with the reason.

## Amendment: the limits are configurable (2026-11-26, in 0.0.16)

The 8 signatures, 5 minutes of skew and a revocation list's size were
first fixed constants, against the rule that every limit is
configurable with a documented default. 0.0.15 shipped them that way. From 0.0.16 they are `Limits`
(`max_signatures`, `future_skew`, `max_revoked`, defaults 8, 5 minutes
and 100,000), set in `[attestation]`. The signatures are counted
before any is decoded, and the envelope is read without buffering the
document; the register frame limit (64 KiB by default) bounds the bytes
read before that.

## Why the signature is classical

ADR 0002 makes key exchange hybrid post-quantum by default. This
signature is checked when a connector registers, by a gateway that
trusts the key now; forging one later gains nothing, because by then
the lease it would buy has to be bought again. The signer is cosign,
which signs with no post-quantum algorithm. When it does, the same
configuration takes the new key type.

## What it does not prove

The connector reports what it fronts, and a compromised connector can
present a valid statement about a server it is not forwarding to. The
attestation shows that the operator's chosen target passed passmcp's
checks under a trusted key, recently; the connector's identity (mutual
TLS, FR-3) is what ties that to a process. Continuous re-attestation
(M5) narrows the gap.

## When to revisit

Keyless Sigstore when a design partner signs that way. Composite or
ML-DSA keys when cosign supports them. Recording each admission in the
audit log when registrations are audited (FR-10).

## Consequences

- An operator distributes a public key to every gateway and lists the
  targets per route; a target that moves needs a new statement and a
  configuration change, which is the point.
- A connector carries its statement in the register frame, so a bundle
  must fit in 64 KiB with the rest of the frame. Key-signed bundles are
  about 2 KiB.
