<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow the 0.0.N release train described in `AGENTS.md`.

## [0.0.9]

### Added

- `tunnelward-mcp` parses MCP envelopes (FR-2, FR-4 groundwork): from a
  JSON POST body of at most 1 MiB, each JSON-RPC 2.0 message's kind, id
  and method, the tool a `tools/call` names, the declared `clientInfo`
  of `initialize`, and `params._meta.traceparent`. Arguments are never
  kept. A `tools/call` that does not name its tool as a string is
  refused, so no call can hide its tool from per-tool policy. A fuzz
  target, `envelope`, joins the CI replay. The crate is published.
- Provenance, first part (FR-14): every ingress request gets a ULID
  request id, sent to the connector and back to the client in
  `tw-request-id` (a client cannot choose it), refusals included.
  `RequestInfo` records the declared `User-Agent`, a well-formed W3C
  `traceparent` and the `Mcp-Session-Id`; observers get each JSON POST's
  envelope through `ProxyObserver::on_envelope`.
- Dark mode (G14): `Gateway::set_dark` by connector, route or address,
  and `POST /dark` and `GET /dark` on the admin API. A dark connection
  stays connected and finishes its requests but takes no new one;
  requests for a route with only dark connections wait, then get 503
  with `Retry-After`, and are served at once if it comes back in time.
  Connections that arrive later and match are dark too. The internal
  inventory shows which connections are dark. Writing it to the audit
  log waits for the audit log (0.0.14).
- Certificate reload without a restart (G16): `Gateway::set_tls` and
  `Gateway::set_ingress_tls` apply to the next handshake; established
  connections keep theirs. `tunnelward gateway` watches its file and the
  certificates and keys it names (`[tls] reload_secs`, default 10) and
  swaps them in after the whole file passes its checks again; a file
  that fails keeps the running certificates and says why.
- MCP pass-through tests: `initialize` with its session header and a
  `tools/call` answered by an SSE stream reach the client byte for byte.

## [0.0.8]

### Added

- The admin API (FR-9) on its own listener, `Gateway::serve_admin`
  (`Gateway::admin` for embedders): `/healthz`, `/readyz`, `/inventory`
  (counts only by default; `?redaction=internal` adds each connection's
  connector, address, routes and load), `/metrics` in Prometheus text
  (G15), and `POST /drain` by connector, route or address. With
  `AdminConfig::token` set every request needs that bearer token;
  without one only loopback clients are served.
- The `tunnelward` command gets its first commands. `tunnelward dev
  --to http://host:port` runs a gateway and a connector in one process
  in front of a local service, over the same mutual TLS as a real
  deployment, with throwaway self-signed certificates made at startup
  (no keys on disk or in the package), on loopback only.
  `tunnelward gateway --config <file>` runs a gateway from a TOML file
  (listeners, TLS, ingress, connector allowlist, admin token from an
  environment variable). `tunnelward config check <file>` lists every
  problem in a file, and `tunnelward doctor` checks the clock, the
  post-quantum group, the file and whether its listeners are free.
- Stable error ids (`TW-R`, `TW-A`, `TW-S`, `TW-I`, `TW-C` and three
  digits) on every error type, with `id()` and `docs_url()`, explained in
  `docs/errors.md`. Ingress refusals carry the id in a `tw-error` header
  and in the body with its link. A test keeps the catalogue and the code
  in step.
- FR-1's acceptance test: a gateway killed under load fails only its
  own in-flight requests, and new requests succeed on the other gateway
  within one backoff window.

### Changed

- The crates are renamed `tunnelward-*` (the binary crate is
  `tunnelward`), and the five with code are published on crates.io from
  this release. Directories keep their `crates/tw-*` names.
- The release workflow builds `-p tunnelward`, and a `crates` job
  publishes to crates.io through trusted publishing once the repository
  variable `CRATES_IO_TRUSTED_PUBLISHING` is `true`; it skips a version
  crates.io already has. `DEVELOPMENT.md` describes the release steps.
- `serde_json` joins the gateway's dependencies for the admin API, and
  `toml` the CLI's for its configuration file. Their publishers (dtolnay,
  BurntSushi, epage) meet rule 2 of the cargo-vet policy; the exemption
  count is unchanged.

### Deferred

- Dark mode (G14) and certificate reload without a restart (G16), which
  the plan put in this release, move to 0.0.9, as does a `tunnelward
  connector` command.
- M1's exit test, the five Cranker defect reproducers rewritten as
  Tunnelward tests, is not written yet; FR-1's test, the other half, is.

### Notes

- The CLI stops at once on Ctrl-C rather than draining first: graceful
  shutdown on a signal needs tokio's `signal` feature, whose
  `signal-hook-registry` dependency is not yet vetted.

## [0.0.7]

### Added

- The agent-facing ingress (FR-2): `Gateway::serve_ingress` serves
  HTTP/1.1, or over TLS HTTP/2 and HTTP/1.1 chosen by ALPN;
  `Gateway::ingress` is the same per-connection service for embedders
  (G10). Responses stream, and a client that stops reading stalls the
  connector's stream through flow control instead of filling memory.
- Client address (FR-11, G12): the socket's peer is authoritative;
  `Forwarded` and `X-Forwarded-For` are believed only from
  `trusted_proxies`, and a PROXY v1 or v2 header is read only from them
  (`proxy_protocol`). The connector sees one authoritative `Forwarded`
  (and legacy `X-Forwarded-*`, unless off) and the gateway's `Via` hop;
  whatever the client sent is removed.
- Ingress limits (G13): URL 8 KiB (414), body 16 MiB (413), request
  timeout (504), per-address token-bucket rate limit (429 with
  `Retry-After`), idle timeout. Routing errors map to 404, 503 with
  `Retry-After` and 502.
- `ProxyObserver` hooks (G11): request, response headers, body complete
  with byte count, and failures.
- A `proxy` fuzz target for the PROXY protocol parser.

### Deferred

- WebSocket passthrough needs HTTP/2 extended CONNECT (RFC 8441)
  through the tunnel and splicing at the connector; MCP's Streamable
  HTTP does not use it. It gets its own release.
- JA4 and HTTP/2 SETTINGS fingerprints need checking against FoxIO's
  reference outputs before a provenance record can rely on them. They
  get their own release.

## [0.0.6]

### Added

- `tw_connector::Connector`: keeps `connections_per_gateway` (default 2)
  connections to every gateway (FR-1), from a fixed list or a DNS name
  looked up again on an interval (G6); TLS verifies the configured name,
  never the IP. Failed connections are retried with decorrelated-jitter
  backoff (250 ms to 30 s). Leases are renewed make-before-break at 70%
  to 90% of their length (ADR 0005). `Connector::events` streams
  `ConnectorEvent`s (G8); `Connector::shutdown(deadline)` sends GOAWAY,
  lets requests finish and reports whether they did (G7).
- `Forward::with_request_hook`: change requests before they reach the
  target (G8).
- `Gateway::drain` by connector, route or peer address (FR-7): no new
  requests, in-flight ones finish until the deadline, the rest are
  reset. A lease that ends drains its connection (`lease_secs`, default
  1 h; `drain_grace`, default 30 s).
- The gateway retries a request once on another connection when the
  first refused it unprocessed (GOAWAY or `REFUSED_STREAM`), so lease
  renewal loses no request.
- HTTP/2 keep-alive pings (`keep_alive`, default 20 s) drop a connector
  that stops answering without closing its socket.
- `Config::connector_allow`: CIDR allowlist for connector sources,
  checked before TLS (G9).
- ADR 0004 (state shared across gateways, design) and ADR 0005 (leases
  renew by reconnecting).

### Changed

- Each connection is its own registry session; `Gateway::admit_from`
  records the connector's address.

## [0.0.5]

### Added

- Pools. Every connector whose claim ranks highest for a request forms
  its pool; of two picked at random, the one with fewer requests in
  flight takes it. A connector never holds more requests than the
  smaller of its capacity and the gateway's stream grant, and a response
  body keeps its slot until it ends or is dropped.
- A bounded wait queue (FR-8): with no free slot, a request waits up to
  `max_wait` (default 2 s) in a queue of at most
  `limits.max_waiting_per_route`, then gets `SendError::Unavailable` with
  a `Retry-After`.
- Routes are kept after their last connector leaves
  (`routes_keep_time`, default 2 h): requests for them wait and get
  `Unavailable`, not `NoRoute`, and a connector that comes back serves
  the waiting ones (gap G4).
- A pluggable `RouteResolver`, with `LongestFirst` as the default (G3).
- `tw_connector::Forward`: sends each request on to a local HTTP/1.1
  server over TCP, TLS with a pinned CA, or a Unix socket; 502 when the
  target fails, 504 when it is late (G5).
- `Config::new` with defaults; `Gateway::in_flight` and
  `Gateway::waiting`.
- The README logo.

### Changed

- Licences (decision D8): `tw-proto`, `tw-crypto`, `tw-identity`,
  `tw-mcp`, `tw-connector` and `tw-testpki` are now MIT OR Apache-2.0, so
  services can embed them; the gateway, binaries and the other crates stay
  GPL-3.0-only. `LICENSE` is now `LICENSE-GPL`, beside `LICENSE-MIT` and
  `LICENSE-APACHE`. The gate fails if a permissive crate depends on a GPL
  one (`scripts/licence-boundary.sh`).
- Contributions need the Contributor License Agreement (`docs/cla/`, a
  draft pending legal review) as well as the DCO sign-off.

## [0.0.4]

### Added

- A working tunnel. `tw-connector` dials the gateway over TLS with ALPN
  `tw/1`, sends `Register`, and on `Accept` serves HTTP/2 on the same
  connection with the roles reversed (ADR 0001). `tw-gateway` admits
  connectors (`Gateway::admit` on any stream, or `serve_connectors` on a
  TCP listener) and sends requests through them (`Gateway::send`).
- Routing by domain, then the longest route on a `/` boundary, then the
  catch-all `*`. A connector leaves the routing table when its
  connection ends.
- `Register` can claim `domains` (exact or `*.` wildcard, up to 16) and the
  catch-all route `*` (gaps G1 and G2).
- The gateway closes a connection that does not negotiate `tw/1`,
  answers a bad register frame with `Reject` and its code, refuses an
  oversized length prefix before reading the body, and drops a
  connection that sends no frame within the registration timeout.
- `tw-proto` feature `io`: `read_frame` and `write_frame` on tokio
  streams; a read stops exactly at the frame's end.
- `tw-testpki`: the TEST-ONLY certificates, shared by every crate's tests.
- `supply-chain/README.md`: how a dependency gets vetted, and the
  maintainer's trust decisions.

### Notes

- Reversed-role HTTP/2 works on hyper 1.12 and h2 0.4.20 with no
  workaround; ADR 0001's fallback (RFC 8441) is not needed.
- A commit on this branch (1f876b6) went in while the gate was red; the
  next commit (3cba209) fixed it.

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

### Fixed

- Release packaging: the build step failed on the `LICENSES/` directory,
  so the first v0.0.1 release run published nothing. Archives now carry
  `LICENSES/` alongside `LICENSE`.
- Release notes: What's Changed titles are set in backticks, and the
  Checksums block lists every attached asset, `SHA256SUMS` included,
  as the release standard asks.

### Changed

- Releases attach `SHA256SUMS.sigstore.json`, a keyless cosign
  signature of `SHA256SUMS` tied to the release workflow run.

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

[0.0.7]: https://github.com/sebastienrousseau/tunnelward/compare/v0.0.6...v0.0.7
[0.0.6]: https://github.com/sebastienrousseau/tunnelward/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/sebastienrousseau/tunnelward/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/sebastienrousseau/tunnelward/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/sebastienrousseau/tunnelward/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/sebastienrousseau/tunnelward/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/sebastienrousseau/tunnelward/releases/tag/v0.0.1
