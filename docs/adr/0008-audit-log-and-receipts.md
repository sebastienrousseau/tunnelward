<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# ADR 0008: A hash-chained audit log, pseudonymous by default, and signed receipts

- Status: Accepted, implemented in 0.0.14
- Date: 2026-11-10

## Context

FR-15 asks for evidence: every call recorded with its provenance,
argument and result digests and decision, in a log that shows tampering,
and a signed receipt the caller can check offline. FR-18 and decision D7
ask that personal data (client addresses, certificate fingerprints) be
kept raw for at most 30 days and as keyed-hash pseudonyms after that.
D7 also asks for the retention window to be confirmed with a design
partner's data protection officer, which has not happened.

The plan anchored checkpoints to an RFC 3161 timestamp authority.
Verifying a timestamp token means parsing DER and checking a CMS
signature: about ten crates that no imported audit covers, or a DER
parser of our own. Neither is needed for the rest of FR-15.

A hash chain over a log that is later redacted breaks: removing a raw
address from an entry changes its hash and every hash after it.

## Decision

- **The log is JSON Lines, one entry per line.** Every line has `seq`
  (from 0, no gaps) and `prev`, the SHA-256 of the previous line's exact
  bytes (64 zeros for the first). The hash is over the bytes as written,
  so verifying needs no canonical JSON, and a verifier ignores fields it
  does not know.
- **Checkpoints are lines in the same chain**, written every 1,000
  entries or 60 seconds (configurable) and when the gateway stops. A
  checkpoint signs its `seq`, `prev` and `time` with the composite
  ML-DSA-65 + Ed25519 key of ADR 0007, behind its own label, so it
  vouches for every line before it. Entries after the last checkpoint
  are reported as unsigned: they could be cut off without trace.
- **Entries never hold a raw address or fingerprint.** The client
  address and the SHA-256 of a client certificate are written as
  HMAC-SHA-256 pseudonyms under a key the operator keeps, with a label
  per field. This is stricter than D7's default, at the maintainer's
  choice while the window is unconfirmed.
- **Raw values are an opt-in, kept beside the chain, not in it.** With
  `raw_days` set (1 to 30), the raw address and fingerprint go to a
  sidecar file keyed by `seq`, which the writer prunes to the window at
  start and every day. Pruning never touches the chained file, so the
  chain still verifies.
- **Arguments and results are digests.** Each MCP call's `arguments`
  are hashed as serde_json writes them back (keys sorted), the request
  body and the response body as sent. The query string is not logged;
  the path is.
- **Receipts are opt-in.** With `receipts = true`, every answer carries
  `tw-receipt`: base64url JSON, a dot, and a composite signature over it
  behind a receipt label. It names the request, the caller as the
  gateway knew it, the calls and their argument digests, the decision
  and the status, and the key that signed it. It cannot carry the
  result digest, which is known only after the headers are sent; the
  log entry has it. Signing one took 90 to 100 µs in a release build
  on the development laptop (Apple A18 Pro, five runs of 1,000,
  `cargo xtask bench`), about a fifth of NFR-1's 500 µs budget at p50,
  and the header is about 5 KB: too much to impose on every call.
- **Writing never blocks a request.** Entries go through a bounded
  queue to a writer thread. When the queue is full the entry is dropped
  and counted, and the writer records a `gap` line with the count, so
  a loss is visible in the log rather than silent.
- **RFC 3161 anchoring moves to a later version**, where the choice
  between new dependencies and our own DER parser can be made on its
  own. Checkpoints can be anchored later without changing the format.
- **OCSF export is a view, not the format.** `tunnelward audit export
  --ocsf` writes each entry as an OCSF 1.3 API Activity event (class
  6003); the chained file stays the record.

## When to revisit

Anchor checkpoints to a timestamp authority once its dependency choice
is made. Revisit the pseudonym default when the retention window is
confirmed. Add file rotation (a new file whose first `prev` is the old
file's last hash) when a deployment needs it.

## Consequences

- An operator keeps two secrets beside the signing key's public half:
  the signing key and the pseudonym key. Rotating the pseudonym key
  ends linkability across the rotation.
- A partial last line (a crash mid-write) stops the gateway at start
  with an error naming the file, rather than appending after it.
- Entries for the same client can be linked to each other, but not to
  an address without the pseudonym key.
