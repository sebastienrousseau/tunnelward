<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!--
README template. Global rules: see ~/Code/AGENTS.md and ~/Code/REPO-STANDARD.md.
Releases adhere strictly to https://github.com/sebastienrousseau/passmcp/releases/tag/v0.0.5
-->

<p align="center">
  <img src=".github/logo.svg" alt="Tunnelward logo: an arch-shaped tunnel entrance" width="128" />
</p>

<h1 align="center">Tunnelward</h1>

<p align="center">
  Serve AI agents from behind a firewall: services dial out to a gateway, prove what they are, and need no inbound port.
</p>

<p align="center">
  <a href="https://github.com/sebastienrousseau/tunnelward/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/sebastienrousseau/tunnelward/ci.yml?branch=main&style=for-the-badge&logo=github&label=Build" alt="Build" height="28" /></a>
  <a href="https://crates.io/crates/tunnelward"><img src="https://img.shields.io/crates/v/tunnelward.svg?style=for-the-badge&color=fc8d62&logo=rust" alt="Registry" height="28" /></a>
  <a href="https://docs.rs/tunnelward"><img src="https://img.shields.io/badge/docs.rs-tunnelward-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" alt="Docs" height="28" /></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/sebastienrousseau/tunnelward"><img src="https://img.shields.io/ossf-scorecard/github.com/sebastienrousseau/tunnelward?style=for-the-badge&label=OpenSSF%20Scorecard&logo=openssf" alt="OpenSSF Scorecard" height="28" /></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-GPL--3.0--only%20%7C%20MIT%20OR%20Apache--2.0-blue.svg?style=for-the-badge" alt="License: GPL-3.0-only for the gateway and binaries, MIT OR Apache-2.0 for the SDK crates" height="28" /></a>
  <a href="https://github.com/sebastienrousseau/tunnelward/blob/main/docs/POLICIES.md"><img src="https://img.shields.io/badge/MSRV-1.89-93450a.svg?style=for-the-badge&logo=rust" alt="Minimum supported Rust version 1.89" height="28" /></a>
</p>

<p align="center">
  <img src=".github/demo.gif" alt="A terminal prints the tunnelward version, then runs tunnelward dev in front of a local web server; curl through the tunnel prints hello from a private service, and the admin API shows one connector with two connections. Then a tool policy permits one agent to read and transfer, marks transfer high impact, and tunnelward policy test passes three cases: a read allowed, a transfer denied without cryptographic evidence, another agent denied" width="100%" />
</p>

---

## Contents

**Getting started**

- [Install](#install) — from source with cargo
- [Requirements](#requirements) — toolchain floor, platforms
- [Quick Start](#quick-start) — build the workspace and run the gate

**The Tunnelward ecosystem**

- [The Tunnelward ecosystem](#the-tunnelward-ecosystem) — tunnelward-proto, tunnelward-crypto, tunnelward-identity, tunnelward-attest, tunnelward-policy, tunnelward-mcp, tunnelward-audit, tunnelward-gateway, tunnelward-connector, tunnelward

**Library reference**

- [Capabilities at a glance](#capabilities-at-a-glance) — the current surface by theme
- [Ecosystem comparison](#ecosystem-comparison) — short matrix; full table at [`docs/COMPARISON.md`](docs/COMPARISON.md)
- [Benchmarks](#benchmarks) — headline numbers; full table at [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md)
- [Features](#features) — module-level capability list
- [Configuration](#configuration) — core options
- [Examples](#examples) — runnable example index

**Operational**

- [When not to use Tunnelward](#when-not-to-use-tunnelward) — limitations
- [Development](#development) — make targets, fuzzing, CI
- [Security](#security) — guarantees and compliance
- [Documentation](#documentation) — all reference docs
- [Stability guarantees](#stability-guarantees) — SemVer axis, output stability, minimum toolchain discipline
- [License](#license)

---

## Install

### The `tunnelward` binary

```bash
cargo install --locked tunnelward
```

Pre-built binaries for Linux (static musl), macOS and Windows, with
checksums, an SBOM and build provenance, are on each
[GitHub Release](https://github.com/sebastienrousseau/tunnelward/releases).
A container image is at `ghcr.io/sebastienrousseau/tunnelward`.

### As a Rust library

```toml
[dependencies]
tunnelward-connector = "0.0.13"   # embed a connector in your service
tunnelward-gateway = "0.0.13"     # embed a gateway in your server
```

`tunnelward-proto` and `tunnelward-crypto` are the wire protocol and
the TLS configuration underneath; `tunnelward-identity` reads a
connector's SPIFFE ID from its X.509-SVID, fetches SVIDs from the
SPIFFE Workload API, and holds the CA a gateway enrols connectors with;
`tunnelward-mcp` parses MCP
envelopes. API documentation is on
[docs.rs](https://docs.rs/tunnelward-connector).

---

## Requirements

- Rust 1.89 or newer ([policy](docs/POLICIES.md)).
- CI tests Linux (x86_64 and aarch64), macOS and Windows on stable, and
  Linux on 1.89.

---

## Quick Start

Put a tunnel in front of a service running on your machine:

```bash
python3 -m http.server 8080 &              # any local HTTP service
tunnelward dev --to http://127.0.0.1:8080  # gateway and connector, one process
curl http://127.0.0.1:8000/                # an agent's request, through the tunnel
```

`tunnelward dev` runs a gateway and a connector together. The connector
dials the gateway over the same mutual TLS, with post-quantum key
exchange, that a real deployment uses, using throwaway certificates made
at startup, and every listener stays on loopback. Add
`--admin 127.0.0.1:9000` to see `/inventory` and `/metrics`.

---

## The Tunnelward ecosystem

One crate per concern, so the protocol core can be fuzzed and audited on
its own. `tunnelward-proto`, `tunnelward-crypto`, `tunnelward-identity`,
`tunnelward-mcp`, `tunnelward-policy`, `tunnelward-gateway`,
`tunnelward-connector` and `tunnelward` have code; `tunnelward-attest` and
`tunnelward-audit` are placeholders until the release the plan gives them.

| Component | Purpose | Use case |
| :--- | :--- | :--- |
| `tunnelward-proto` | Register frames, limits, error codes | Parsing what a connector sends before its identity is known |
| `tunnelward-crypto` | rustls configuration with hybrid post-quantum key exchange | X25519MLKEM768 on every TLS hop |
| `tunnelward-identity` | The SPIFFE ID in an X.509-SVID; the Workload API client; the enrolment CA and signing requests | Proving which workload a connector is |
| `tunnelward-attest` | passmcp attestation verification | Admitting only MCP servers that passed passmcp |
| `tunnelward-policy` | Per-tool policy and evidence levels (Cedar later, behind the same trait) | Allowing or denying each `tools/call` |
| `tunnelward-mcp` | MCP envelope parsing, Streamable HTTP, SSE | Reading the method and tool name without parsing the body |
| `tunnelward-audit` | Hash-chained log, offline verifier | Proving what was allowed, after the fact |
| `tunnelward-gateway` | Ingress, routing, admission, admin API | The public side agents connect to |
| `tunnelward-connector` | Outbound registration, stdio bridge | The private side next to the MCP server |
| `tunnelward` | The `tunnelward` binary | Operating all of the above |

---

## Capabilities at a glance

| Area | Capability | Status |
| :--- | :--- | :--- |
| CLI | `tunnelward --version`, `--help` | Shipped in 0.0.1 |
| Protocol | Register, Accept, Reject frames; length-prefixed CBOR codec | Shipped in 0.0.2 |
| Transport | Reverse HTTP/2 over the connector's outbound TLS connection | Shipped in 0.0.4 |
| Routing | Domain (exact or `*.` wildcard), longest route, catch-all `*`; pluggable resolver | Shipped in 0.0.4, resolver in 0.0.5 |
| Load | Pools, least-loaded of two random picks, capacity per connector, bounded wait queue with `Retry-After`, routes kept after connectors leave | Shipped in 0.0.5 |
| Forwarding | Connector forwards to a local HTTP/1.1 server over TCP, TLS with a pinned CA, or a Unix socket; request hook | Shipped in 0.0.5, hook in 0.0.6 |
| Resilience | Several connections to several gateways, DNS discovery, jittered reconnects, lease renewal with no lost request, keep-alive pings | Shipped in 0.0.6 |
| Operations | Drain by connector, route or address with a deadline; graceful connector shutdown; connector source allowlist | Shipped in 0.0.6 |
| Ingress | HTTP/1.1 and HTTP/2 (TLS, ALPN) for agents; streaming responses with backpressure; client address from trusted proxies only, PROXY v1/v2; URL, body, timeout and rate limits; observer hooks | Shipped in 0.0.7 |
| Crypto | TLS 1.3 only; hybrid PQ key exchange (X25519MLKEM768) first, optional hybrid-only; mutual TLS | Shipped in 0.0.3 |
| Operating | Admin API on its own listener (health, readiness, inventory with redaction, metrics, drain); `tunnelward dev`, `gateway`, `config check` and `doctor`; stable error ids | Shipped in 0.0.8 |
| MCP and provenance | MCP envelope parsing (method, tool, declared client); a request id on every request; declared User-Agent and `traceparent` recorded | Shipped in 0.0.9 |
| Live changes | Dark mode per connector, route or address; certificates reloaded from disk without a restart; `tunnelward connector`; CORS per path | Shipped in 0.0.9 |
| Connector identity | The registered SPIFFE ID must be the one in the connector's X.509-SVID; routes owned by identities; registrations per source, domains per gateway and routes per identity enforced | Shipped in 0.0.10 |
| Agent authorisation | OAuth 2.1 resource server per the MCP authorisation spec: bearer JWTs (ES256, RS256, PS256, EdDSA) checked against each issuer's JWK Set, audience, expiry and scopes; protected-resource metadata (RFC 9728); tokens never passed to connectors | Shipped in 0.0.11 |
| SVID rotation | Connector SVIDs from the SPIFFE Workload API or from files, rotated without a restart; an SVID for another identity is refused | Shipped in 0.0.11 |
| Enrolment | A connector with no SVID redeems a one-time token bound to a SPIFFE ID for a short-lived SVID from the gateway's CA, then renews with a new key before it expires; `tunnelward enrol ca`, `token` and `revoke` | Shipped in 0.0.11 |
| Provider identification | Requests from Anthropic's and OpenAI's published egress ranges tagged with the provider, from a signed, versioned snapshot (`tunnelward providers`); Web Bot Auth signatures (RFC 9421) from listed agents raise the tag to signature level, with a nonce replay check | Shipped in 0.0.11 |
| Shared state | Replay caches and rate limits shared by several gateways through a Redis-compatible store (`[state]`), so a replay is caught whichever gateway it reaches; replay checks fail closed and rate limits fail open when the store is down | Shipped in 0.0.12 |
| Token replay defences | DPoP-bound tokens (RFC 9449) work only with a proof by their key; certificate-bound tokens (RFC 8705) only from their certificate; paths can demand bound or single-use tokens (`[[agents.paths]]`); replays refused across gateways | Shipped in 0.0.12 |
| Tool policy | Permit or forbid each MCP call by agent, provider, path, method, tool and evidence level, with the D6 baseline; a denied call gets a JSON-RPC error and never reaches the connector; hot reload and `tunnelward policy test`; idempotency keys on high-impact tools | Shipped in 0.0.12 |
| Post-quantum signatures | Provider snapshots signed with a composite ML-DSA-65 + Ed25519 key; both halves must verify; ML-DSA-65 checked against NIST ACVP vectors | Shipped in 0.0.12 |
| Claim mismatches | A `User-Agent` or MCP `clientInfo` naming a provider the gateway did not see is recorded as a mismatch, and policy can forbid such calls | Shipped in 0.0.13 |
| stdio bridge | A connector serves a local stdio MCP server as Streamable HTTP through the tunnel: one process per session, an event stream with `Last-Event-ID` resumption (`[target] stdio`); checked in CI against the MCP reference server, server-everything 2.0.1 | Shipped in 0.0.13 |
| Benchmarks | Added latency, memory per connection and scaling measured against NFR-1 to NFR-3, with method and caveats (`docs/BENCHMARKS.md`, `cargo xtask bench`) | Shipped in 0.0.13 |

---

## Ecosystem comparison

Tunnelward's own column, with the test that shows each. A comparison
with other tunnels and MCP gateways needs a sourced claim for each of
them, and is not written yet.

| Project | Inbound port needed | Connector identity checked | Admission by attestation | Self-hosted |
| :--- | :---: | :---: | :---: | :---: |
| **Tunnelward** | No: connectors dial out (`tests/tunnel.rs`) | Yes: SPIFFE ID from the SVID (`tests/ownership.rs`) | Not yet (FR-5, planned) | Yes |

See [`docs/COMPARISON.md`](docs/COMPARISON.md) for the evidence and complete matrix.

---

## Benchmarks

Measured with `cargo xtask bench`. A number appears here only after a benchmark anyone can rerun has measured it; the p99 latency (NFR-1) and scaling across cores (NFR-3) are not measured yet, because the laptop used is too noisy for them.

| Scenario | Result | Environment |
| :--- | ---: | :--- |
| Latency added to a 1 KiB MCP call, p50 (NFR-1, budget 500 µs) | 125 to 160 µs over 5 runs | Apple A18 Pro, macOS 27.2, loopback |
| Gateway heap per idle connector connection (NFR-2, budget 64 KiB) | 58.9 KiB | Apple A18 Pro, macOS 27.2, 500 connectors |
| Gateway heap per request in flight (NFR-2, budget 16 KiB + 256 KiB window) | 25.8 KiB | Apple A18 Pro, macOS 27.2, 500 requests |

See [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) for methodology and full results.

---

## Features

The workspace has no Cargo features yet.

---

## Configuration

`tunnelward gateway --config tunnelward.toml` runs a gateway from a TOML
file: its listeners, its TLS certificates (picked up again when renewed),
the agent ingress with CORS rules, the connector allowlist and route
owners, the admin token, and the OAuth issuers agents' tokens must come
from (`[agents]`, documented in [`agents.rs`](crates/tw-cli/src/agents.rs)),
and the signed provider snapshot requests are tagged with (`[providers]`,
documented in [`providers.rs`](crates/tw-cli/src/providers.rs)). `tunnelward connector --config connector.toml` runs a connector
in front of a local service. Each format, with every key, is documented
at the top of [`config.rs`](crates/tw-cli/src/config.rs) and
[`connector.rs`](crates/tw-cli/src/connector.rs).
Check a file before deploying it:

```bash
tunnelward config check tunnelward.toml   # every problem, or "ok"
tunnelward doctor --config tunnelward.toml
```

Errors carry stable ids (`TW-S001` and so on), explained in
[docs/errors.md](docs/errors.md).

---

## Examples

The [Quick Start](#quick-start) is the first example: a gateway and a
connector on one machine with `tunnelward dev`. For embedding, the
gateway's tests show each feature end to end
(`crates/tw-gateway/tests/`).

---

## When not to use Tunnelward

- In production, yet: per-tool policy, attestation, the audit log and agent-side authorisation are still to come (see the plan).
- For LLM routing, prompt guardrails or token accounting: use an MCP or LLM gateway such as agentgateway in front of it.
- As a general-purpose VPN or mesh.
- If you want a vendor edge to run the data plane for you: Tunnelward is self-hosted.

---

## Development

```bash
cargo xtask ci   # the single gate CI runs
make demo        # re-render .github/demo.gif
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for the toolchain and what the gate runs.

---

## Security

- TLS 1.3 only, with `X25519MLKEM768` offered first on every hop; a test asserts the negotiated group (`crates/tw-crypto/tests/handshake.rs`).
- No `unsafe` code in any published Tunnelward crate (`unsafe_code = "forbid"`). The one exception is the counting allocator in the unpublished benchmark crate, and CI fails if unsafe code appears anywhere else (`scripts/unsafe-boundary.sh`).
- No `unwrap`, `expect` or `panic!` outside tests (clippy, denied).
- Dependencies checked by `cargo deny` and `cargo vet` on every pull request; Actions pinned by commit SHA.
- A connector registers as the SPIFFE ID in its X.509-SVID and no other, and a route belongs to one identity: another identity's claim is refused (`docs/errors.md`, TW-R003 and TW-R004).
- The register-frame decoder, the only parser that sees bytes before a connector's identity is known, is fuzzed (`fuzz/fuzz_targets/decode.rs`, 60 s per pull request, 30 min weekly), property-tested, and run under Miri. The SVID reader is fuzzed the same way (`fuzz/fuzz_targets/svid.rs`).

Report vulnerabilities according to [`SECURITY.md`](SECURITY.md).

---

## Documentation

- User manual: not written yet.
- API reference: `cargo doc --workspace --open`; docs.rs once published.
- Developer docs: [DEVELOPMENT.md](DEVELOPMENT.md), [docs/POLICIES.md](docs/POLICIES.md), [design decisions](docs/adr/README.md).
- Ecosystem: [the table above](#the-tunnelward-ecosystem); passmcp is the sibling that writes the attestations Tunnelward checks.

---

## Stability guarantees

Pre-0.1.0, any release may change any API, wire format or CLI output; the CHANGELOG says what changed. Each release moves the patch number by one. The minimum Rust version may rise in any release, and the CHANGELOG names the reason ([policy](docs/POLICIES.md)).

---

## License

Two licences, split by what you embed (decision D8):

| Crates | Licence | Why |
| :--- | :--- | :--- |
| `tunnelward-proto`, `tunnelward-crypto`, `tunnelward-identity`, `tunnelward-mcp`, `tunnelward-connector`, `tunnelward-testpki` | [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE), at your option | They ship inside your services, as the connector library and the SDKs' base |
| `tunnelward-gateway`, `tunnelward-policy`, `tunnelward-audit`, `tunnelward-attest`, `tunnelward` (the `tunnelward` binary), `xtask` | [GPL-3.0-only](LICENSE-GPL) | The gateway and tools you run, not embed |

The gate fails if a permissive crate depends on a GPL one
(`scripts/licence-boundary.sh`). Every file names its licence in an SPDX
header; `REUSE.toml` covers the rest, including the logo, which is a Noun
Project icon used under the maintainer's licence and not under either of
the above.

Contributions are accepted under the [Contributor License Agreement](docs/cla/README.md).
