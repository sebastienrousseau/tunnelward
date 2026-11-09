<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow the 0.0.N release train described in `AGENTS.md`.

## [0.0.13]

### Added

- The stdio bridge (FR-6): a connector can serve a local MCP server that
  speaks JSON-RPC over stdio, as MCP Streamable HTTP through the tunnel.
  `[target] stdio = ["command", "args"]` (with optional `env`,
  `max_sessions`, `idle_secs`), or `StdioBridge` in the library. Each
  session gets its own process, started by `initialize` and named by
  `Mcp-Session-Id`. A POST's requests are answered with their responses;
  notifications get 202. A GET with `Accept: text/event-stream` streams
  what the server sends on its own, as numbered events, and a client
  that reconnects with `Last-Event-ID` gets what it missed. DELETE, the
  process exiting, or 10 idle minutes end a session, whose id then gets
  404. Sessions, message size and the replay buffer are bounded. The
  `stdio-echo` example is a small stdio server to try it with, and the
  tests run it end to end through a gateway.
- The first benchmark numbers against NFR-1 to NFR-3, in
  `docs/benchmarks.md`, from `cargo xtask bench` (a new, unpublished
  `tunnelward-bench` crate using only the workspace's own dependencies).
  The gateway and tunnel add 125 to 160 µs at p50 to a 1 KiB MCP call
  (budget 500 µs). The p99, memory per in-flight request and core
  scaling could not be measured on the laptop used, and an idle connector
  connection costs about 120 KiB of resident memory against a 64 KiB
  target; the document says why for each.

- Mismatches between claims and evidence (FR-14): a `User-Agent` or MCP
  `clientInfo` that names an AI provider (Claude or Anthropic, ChatGPT or
  OpenAI, by their published agent names) is checked against the
  provider the gateway saw, from published ranges or a verified
  signature. When it is another provider or none, the request carries a
  `Mismatch` (`RequestInfo::mismatches`), its evidence stays at the level
  the gateway established, and policy rules can match on it (`mismatch =
  true` in the policy file, `Rule::mismatch`), for example to forbid a
  script dressed as Claude. The plan's risk score is not built: no input
  for it exists yet.
- Kani proofs for the frame parser (`cargo xtask kani`, and a CI job on
  Kani 0.68.0): for every buffer up to 12 bytes and every limit, framing
  never panics, a frame's body lies within the buffer and the limit, and
  a request for more bytes never reaches past the limit, so reading a
  frame never allocates more than the limit plus the prefix; the length
  check refuses exactly the empty and the over-long frame. The framing
  step is split out of `decode` for this; the CBOR decoding after it
  stays covered by fuzzing and Miri.

### Fixed

- A request that arrived just after a connector registered could get
  404 `TW-S001` ("no connector serves this route"): the connector reads
  `Accept` before the gateway's side of the connection is ready and its
  routes are in the registry. A route whose connector is being admitted
  now makes the request wait, as for a busy or kept route, up to
  `max_wait`; an admission that fails wakes those requests at once.
  Seen once in CI on macOS (`a_gateway_and_a_connector_from_their_files_serve_a_request`).

### Documentation

- ADR 0006 records why the tool policy is an in-house engine before
  Cedar (126 unaudited crates) and when Cedar comes in; ADR 0007 records
  the composite ML-DSA-65 + Ed25519 signature format, why it is not the
  IETF LAMPS draft's encoding yet, and why leases and enrolment tokens
  are not signed.

## [0.0.12]

### Added

- State shared across gateways (ADR 0004): `Config::state` takes a
  `SharedState`, the one interface for replay caches, idempotency keys
  and rate counters. `InMemory` (the default) serves one gateway. Web
  Bot Auth nonces are recorded there, so a signature replayed to another
  gateway sharing the store is refused, and a store that cannot answer
  refuses the signature (fail closed). With a shared store the ingress
  rate limit is counted there, in windows of `burst / per_second`; if
  the store fails each gateway falls back to its share of the limit,
  `RateLimit::gateways` (fail open). Entries live for a time-to-live on
  the store's clock, so gateways need not agree on the time.
- `RedisState`, a shared store for any server that speaks RESP (Redis,
  Valkey and compatible services), over `redis://` or `rediss://` (TLS
  1.3), with a password kept out of the URL. Each operation is one
  command or one atomic script; a command has 2 s, and a dropped
  connection is reopened. The gateway file's `[state]` section sets it
  up (`url`, `password_env`, `ca`, `gateways`). A new CI job runs its
  tests against Valkey 9.1.
- Token replay defences (FR-13). A token bound to a DPoP key (RFC 9449,
  `cnf.jkt`) works only with the `DPoP` scheme and a proof signed by that
  key for this method, URL and token, issued within `dpop_window` (60 s);
  a copied token fails from another client. A token bound to a client
  certificate (RFC 8705, `cnf.x5t#S256`) is refused unless the connection
  presents it: `ClientAuth::AnyHolder` (`[ingress] client_certificates =
  true`) asks agents for a certificate, accepts any or none, and checks
  only that the client signed the TLS 1.3 handshake with its key, which is
  what the binding needs; the metadata then says
  `tls_client_certificate_bound_access_tokens`. `AgentAuth::token_rules` (`[[agents.paths]]`) can demand
  bound tokens on a path, and single use of each token's `jti`. Proof and
  token `jti`s are recorded in the shared state, so a replay to another
  gateway is refused too; when the store cannot answer the request gets
  503 `TW-I012`. The `DPoP` header is never passed to a connector, and
  the metadata lists `dpop_signing_alg_values_supported`. Verified
  against RFC 7638's example thumbprint.

- Tool policy (FR-4) in the new `tunnelward-policy` crate: rules that
  permit or forbid calls by agent (`client_id`), provider, path, JSON-RPC
  method, tool and least evidence; forbid wins, then permit, then the
  default (deny unless set). Before the rules, the D6 baseline: every
  call needs a valid token or a provider-range match, and a tool marked
  `high_impact` needs cryptographic evidence. Each request now carries
  its evidence level (`RequestInfo::evidence`, FR-14): cryptographic for
  a bound token or a verified Web Bot Auth signature, network for a
  provider-range match, declared otherwise. A denied JSON-RPC call gets a
  JSON-RPC error from the gateway (code -32001, `TW-P001`) and never
  reaches the connector; a batch with one denied call is held back
  whole; a JSON body the policy cannot read as JSON-RPC is refused, so a
  body the server reads differently cannot carry a call past it. The
  engine sits behind `PolicyEngine`, so Cedar can stand in once its
  dependencies are audited (126 crates today). The gateway file names a
  policy file in `[policy]`, read again when it changes
  (`Gateway::set_policy`), and `tunnelward policy test` runs a file of
  example calls against a policy.
- Idempotency keys on high-impact tools (FR-13): such a call needs an
  `Idempotency-Key`; the key is claimed in the shared state, a repeat
  gets the first answer (`tw-idempotent-replay: true`) without the tool
  running again, at this gateway or another, a repeat while it runs gets
  409 (`TW-P003`), and the key on another request 422 (`TW-P004`). When
  the first call's outcome is unknown, repeats get 502 (`TW-P005`) so the
  tool never runs twice to find out.

- Composite post-quantum signatures: `tunnelward_crypto::composite`
  signs with ML-DSA-65 (FIPS 204) and Ed25519 over the same
  domain-labelled message, and verifies only when both halves do, so a
  flaw in either algorithm alone does not let a signature be forged.
  Provider snapshots use it: `tunnelward providers keygen` makes a
  composite key and writes its public half to `<key>.pub`, which
  `[providers] key_files` names; a composite key accepts only a composite
  signature, so its post-quantum half cannot be stripped. Ed25519 keys
  made before 0.0.12 still sign and verify. ML-DSA-65 is checked against
  NIST ACVP vectors, kept with NIST's notice. The format is Tunnelward's
  own, not the IETF LAMPS composite draft's.

### Changed

- `BotAuth::verify` is async and takes the request parts as a tuple and
  the `SharedState` to record nonces in. `ClientAuth` has an `AnyHolder`
  variant; `AgentAuth` has `token_rules`, `dpop_window` and
  `certificate_bound`; `Ingress::with_client_certificate` is new.
- `tunnelward providers keygen` makes composite keys and prints the
  paths of the key and its public half instead of a hex Ed25519 key. `RateLimit` has a `gateways`
  field (default 1).

### Fixed

- The release workflow's crates.io job passed cargo a bare `--exclude`
  when no crate of the version was published yet, and failed before
  publishing anything; v0.0.11 was published by hand.

## [0.0.11]

### Added

- Agent-side authorisation, per the MCP authorisation specification: with
  `IngressConfig::agent_auth` (`[agents]` in the gateway file) the
  gateway is an OAuth 2.1 resource server. Every request needs a bearer
  JWT access token from a listed issuer, signed with one of its keys
  (ES256, RS256, PS256 or EdDSA; never `none` or a shared secret), whose
  `aud` is the gateway's resource (RFC 8707), in date, with the scopes
  asked for. Otherwise 401 `TW-I008` or 403 `TW-I009`, with a
  `WWW-Authenticate` challenge naming the metadata. The gateway serves
  its protected-resource metadata (RFC 9728), strips the token before a
  connector sees it, and records the token's `client_id` for observers.
  Issuer keys come from a JWK Set file or are fetched from `jwks_uri`
  over HTTPS, refreshed every 10 minutes and sooner for an unknown key
  id; a failed fetch keeps the old keys. Token checks are in-house on
  aws-lc-rs: no JWT or base64 crate joins cargo-vet.
- Connector SVIDs that rotate without a restart. `tunnelward connector`
  takes its X.509-SVID from the SPIFFE Workload API
  (`[identity] workload_api = "unix:///..."`), following the agent's
  stream as it rotates and reconnecting if the agent restarts, or from
  `cert` and `key` files read again when they change. Each SVID must be
  for the configured SPIFFE ID, proven by its certificate rather than by
  the agent's label; one that is not is refused and the current kept.
  New handshakes present the new SVID; established connections move to
  it at their next lease renewal. Library parts:
  `tunnelward_identity::workload` (gRPC over a Unix socket on hyper, an
  in-house protobuf reader; Unix only) and
  `tunnelward_crypto::{RotatingIdentity, client_config_rotating}`.
- Enrolment tokens: a connector with no SVID gets one from the gateway.
  `tunnelward enrol ca` makes an ECDSA P-256 CA; with `[enrolment]` the
  gateway issues SVIDs from it and its connector listener trusts it.
  `tunnelward enrol token --spiffe-id <id>` prints a one-time token
  bound to that ID; only its SHA-256 is stored, in a directory the CLI
  and gateways share, and redeeming it is an atomic rename, so it works
  once. A connector with `[identity.enrol]` POSTs the token and a
  signing request to `/.well-known/tunnelward/enrol` on the ingress and
  gets an SVID (default lifetime 1 h), keeps it and its key in
  `state_dir`, and two thirds into its life renews at
  `/.well-known/tunnelward/renew` with a new key, proving it holds the
  current SVID's key. `tunnelward enrol revoke` stops an identity's
  renewals. Refusals are `TW-I011`. Certificates, signing requests and
  key identifiers are written in-house on aws-lc-rs; OpenSSL verifies the
  CA and an issued SVID in strict mode.
- Provider identification at the network level (FR-12). A gateway with
  `[providers]` loads a snapshot of AI providers' published egress
  ranges, signed with Ed25519 by a key it trusts, and tags each request
  whose client address is in one (`RequestInfo::provider`: provider,
  agent, `level = "network"`, snapshot version). A snapshot is accepted
  whole or not at all and never replaces a newer one; the gateway looks
  for a newer one every 5 minutes. `tunnelward providers build` fetches
  each provider's own list (Anthropic's outbound ranges from its IP
  addresses page; OpenAI's chatgpt-user, chatgpt-actions, searchbot and
  gptbot files), `keygen` and `sign` make and sign it. An address match
  says where a request came from, not who sent it.
- Web Bot Auth (FR-12, signature level): a request signed per
  draft-ietf-webbotauth-httpsig-protocol (RFC 9421 HTTP message
  signatures, `tag="web-bot-auth"`, Ed25519, a `keyid` that is the
  key's RFC 7638 thumbprint, covering `@authority` and
  `signature-agent`) by an agent listed in `[[providers.signers]]` is
  tagged at `level = "signature"`. Its key directory is fetched from the
  configured URL only, never one a request names. `created` must be
  within five minutes and a nonce is accepted once. A failing signature
  is refused (401 `TW-I010`) or served unsigned, per `on_invalid`. Both
  Ed25519 test vectors of the draft (Appendix E.2) verify.

## [0.0.10]

### Added

- Connector identity (FR-3 groundwork): `tunnelward-identity` reads the
  SPIFFE ID in an X.509-SVID (exactly one URI SAN, a SPIFFE ID), with an
  in-house DER reader and a fuzz target, `svid`. The crate is published.
- Route ownership (FR-3). `Config::route_owners` (`[[connectors.owners]]`
  in the gateway file) names the identities allowed to claim a route; a
  route not listed belongs to the identity holding it, live or kept. Any
  other identity's claim is refused with `TW-R004`.
- `Limits::max_routes_per_identity` (64) is enforced across all of an
  identity's connections, refused with `TW-R005`.

### Changed

- The gate (`cargo xtask ci`) runs `cargo semver-checks` on every
  published crate (`scripts/semver.sh`; a crate not yet on crates.io is
  named and skipped), and CI tests on Linux aarch64 as well.
- **Breaking:** a connector's client certificate must be an X.509-SVID
  for the SPIFFE ID it registers; otherwise the gateway refuses it with
  `TW-R003`. Until now the claimed ID was never checked against the
  certificate, so any trusted certificate could claim any identity.
  `tunnelward dev` now issues its connector an SVID, and
  `tunnelward config check` reports a connector file whose `spiffe_id`
  is not its certificate's.

### Fixed

- Two limits in `Limits` were declared but not enforced. A gateway now
  refuses a registration from a source address past
  `registrations_per_minute` (default 60, counted on arrival, so failed
  attempts count) with `TW-R009`, and one whose new domains would take
  it past `max_domains` (default 1,024 distinct domains, kept routes
  included) with `TW-R010`. Domains are reserved while a registration is
  admitted, so concurrent registrations cannot overshoot the cap.
- CI: the CLA workflow grants nothing at the top level; its one
  job asks for the four scopes it needs.
- The release workflow's `crates` job resumes instead of failing on a
  rerun: a crate crates.io already has at the version is skipped. A crate
  crates.io has never seen stops the job before anything is published,
  since trusted publishing cannot create one.
- A Windows-only flaky test (`a_slow_client_holds_back_an_endless_stream`)
  now waits for production to stall instead of sleeping a fixed second.

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
- `tunnelward connector --config <file>`: a connector in front of a local
  service (HTTP or a Unix socket), from a TOML file naming the gateway
  (a fixed address, or a name looked up again every minute), its CA and
  server name, the connector's certificate and SPIFFE ID, and its routes
  and domains. `tunnelward config check` checks a connector's file too.
- CORS per path (G17) for browser-based MCP clients:
  `IngressConfig::cors` rules, and `[[ingress.cors]]` in the gateway's
  file. An allowed origin's preflight is answered by the gateway (204,
  the MCP request headers allowed); its real responses can be read, with
  `Mcp-Session-Id`, `tw-request-id` and `tw-error` exposed. A preflight
  from any other origin gets 403 (`TW-I007`). Credentials are never
  allowed: MCP clients use bearer tokens.
- MCP pass-through tests: `initialize` with its session header and a
  `tools/call` answered by an SSE stream reach the client byte for byte.

### Notes

- MCP pass-through is tested against a minimal MCP server written for
  the test (JSON answers, a session header, an SSE stream); the official
  MCP conformance suite has not been run through the gateway yet.
- `tunnelward-mcp` is new on crates.io, and trusted publishing cannot
  create a crate, so 0.0.9's first publish is by hand like 0.0.8's.

### Fixed

- README build badge: it now reads `ci.yml` on `main` only, labelled
  `Build`, like the other repositories' badges, instead of the latest
  run on any branch.
- The OpenSSF Scorecard badge had no results to show: a Scorecard
  workflow now scores the repository on every push to `main` and
  weekly, publishes to scorecard.dev and uploads its findings to code
  scanning.

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
