<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# ADR 0016: Gateway-blind mode, HPKE with X-Wing between agent and connector

- Status: Accepted, implemented in 0.0.22 (experimental)
- Date: 2026-11-27

## Context

Every hop is TLS, but the gateway terminates the agent's TLS and the
connector's: whoever operates it can read a tool call's arguments and
answer. For the most sensitive tools (a payment, a medical record) a
customer wants the gateway to route and police the call without being
able to read it (spec G4, "gateway-blind payload mode"). The payload must
also resist harvest-now-decrypt-later, so the key exchange is hybrid
post-quantum. No dependency may be added (D9); aws-lc-rs has ML-KEM-768,
X25519, SHA3-256, HMAC, HKDF and AES-GCM, but no HPKE, no SHAKE256 and
no seeded ML-KEM key generation.

## Decision

**Data.** Each connector in blind mode holds an X-Wing key pair
(draft-connolly-cfrg-xwing-kem-11: ML-KEM-768 and X25519, combined with
SHA3-256; public key 1216 bytes). The agent is configured with that
public key by the connector's operator: it is never fetched through the
gateway, which could otherwise substitute its own.

A `tools/call` keeps its method, tool name and id in the clear and seals
its arguments:

```text
params.arguments = {"tw_blind": {"v": 1, "enc": b64url(X-Wing ct), "ct": b64url(AEAD ct || tag)}}
HPKE base mode, KEM X-Wing (0x647a), KDF HKDF-SHA256, AEAD AES-256-GCM
info = "tunnelward blind v1"; aad = "tools/call" || 0x00 || tool name
```

The connector opens it, forwards the plain call to its server, and seals
the answer's `result` or `error` under a key exported from the same HPKE
context (`Export("tunnelward blind response", 32)`, AES-256-GCM, a zero
nonce since the key serves one message, the label as AAD):
`{"jsonrpc":"2.0","id":..,"result":{"tw_blind":{"v":1,"ct":..}}}`.

**What the gateway still does.** It routes on the path, its policy
decides on agent, tool and evidence, its rate limits and risk score run,
and its audit log records the call with a digest of the sealed
arguments. It cannot read or change the arguments: the tool name is in
the AAD, so renaming the tool makes the call fail to open.

**Code.** HPKE (RFC 9180, base mode) and X-Wing are written here over
aws-lc-rs (`tunnelward-crypto`: `hpke`, `xwing`, `blind`); the JSON
layer is `tunnelward-mcp::blind`; the connector opens and seals
(`[blind]`, `tunnelward blind keygen`). The private key is stored
expanded (ML-KEM's 2400 bytes, X25519's 32), not as the draft's seed,
since aws-lc-rs cannot expand a seed; public keys, ciphertexts and
shared secrets are the draft's.

**Evidence.** HPKE is checked against RFC 9180 A.1.1 (DHKEM X25519,
AES-128-GCM: schedule, encryptions at sequence 0 to 256, exports).
X-Wing is checked against the draft's three known answers, with the
seeds expanded by kyberlib (a test dependency only, approved for this
second implementation): aws-lc-rs must then give the draft's public
keys and decapsulate its ciphertexts to its shared secrets. The
TypeScript (Node, `node:crypto` and WebCrypto) and Java (JDK 25) agent
helpers are checked against the Rust connector side in both directions
(`scripts/sdk-interop.sh`).

**Experimental.** The connector refuses `[blind]` without
`experimental = true`. A connector may also `require` sealing, so an
unsealed `tools/call` never reaches its server.

## Consequences

- Content-based policy and DLP cannot apply to a sealed call's
  arguments; policy on who may call which tool still does.
- One JSON answer per call: an answer streamed as server-sent events is
  refused in this alpha.
- No key discovery: distributing the connector's public key is the
  operator's job. A key in a signed attestation (ADR 0009) is the
  natural next step.
- The browser helper runs on kyberlib-wasm for ML-KEM and SHA3-256; it
  is not yet tested in a browser.

## Alternatives

- **TLS end to end through the gateway (a CONNECT tunnel)** hides the
  tool name too, so the gateway could not route or police the call.
- **An HPKE crate (`hpke`, `hpke-rs`)**: more dependencies, and neither
  had X-Wing on aws-lc-rs.
- **OpenID CIBA or COSE**: not a confidentiality mechanism for JSON-RPC.
