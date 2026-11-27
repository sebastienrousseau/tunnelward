<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# ADR 0012: A control plane that signs policy bundles for gateways to pull

- Status: Accepted, implemented in 0.0.19
- Date: 2026-11-27

## Context

The plan gives 0.0.19 a control plane: one place to change the tool
policy of a fleet of gateways, with operators signing in through their
company's OpenID Connect provider and allowed what their role allows.
Today each gateway reads its own policy file, so a change means editing
every gateway's file. The repository adds no dependency (D9,
`~/Code/AGENTS.md` section 11): the gateway already verifies JWTs
against issuers' JWK Sets, signs with composite ML-DSA-65 + Ed25519
keys, serves HTTPS with hyper and fetches over HTTPS.

## Decision

**Data.** A bundle is the unit a gateway applies:

```text
Bundle   { version: u64, issued_ms: u64, publisher: String, policy: String }
Envelope { payload: base64(Bundle as JSON), key: key id, sig: base64 }
```

`policy` is the policy file's TOML, exactly as an operator sent it.
`version` only goes up: a rollback publishes the old policy as a new
version. The signature covers the payload bytes as sent, so nothing is
canonicalised. The control keeps each envelope as
`<store>/bundles/<version>.json` and serves the highest.

**Pull, not push.** Gateways dial out to the control, as connectors
dial out to gateways, so a gateway needs no inbound port for it. A
gateway with `[control]` asks every `every_secs` for the bundle after
the version it has. It applies a bundle only if its signature verifies
under the control's public key, which the gateway file names, its
version is higher than the one running, and its policy passes the same
checks as a policy file. Anything else leaves the running policy in
place and is logged. A compromised control can push a policy, but not
a key, a certificate or code, and every bundle names its publisher.

**Two listeners, two trust models.**

- The *fleet* listener requires mutual TLS. A gateway's certificate
  must chain to the configured roots and carry a SPIFFE ID matching
  `gateways` (a trailing `*` matches a prefix). The control records
  which version each gateway last fetched.
- The *API* listener serves operators over TLS with OIDC access tokens
  (`Authorization: Bearer`). Tokens are checked by the gateway's own
  verifier (issuer, signature, audience, expiry). A role comes from a
  claim (`groups` by default): `viewer` reads bundles and the fleet,
  `operator` also publishes a policy, `admin` also rolls back. Each
  role includes the ones below it.

**Audit.** Each publish and rollback is an admin entry in the control's
hash-chained audit log, naming the token's subject.

## Consequences

- One signed artefact per change, checked by every gateway before use.
- The alpha distributes the tool policy only. Certificates, routes and
  limits stay in each gateway's file.
- Fleet state is in memory: after a restart the control learns it again
  from the next fetches.
- No user interface: operators call the API with a token their
  provider issues (for example with its CLI or device flow).
- DPoP and certificate-bound operator tokens are not required yet.

## Alternatives

- `openidconnect` and `jsonwebtoken`: new crates (D9), and the gateway
  already verifies the same tokens.
- Pushing to gateways: needs an inbound port on every gateway, which is
  what Tunnelward exists to avoid.
- Signing with TLS alone: a bundle copied off the control's disk, or
  served by a compromised proxy, would carry no proof of origin.
