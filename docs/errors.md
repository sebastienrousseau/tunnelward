<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Error catalogue

Every error Tunnelward reports has a stable id. An id never changes
meaning; a new error takes a new id. The gateway's ingress puts the id in
a `tw-error` response header and in the body, with a link here. In code,
each error type has `id()` and `docs_url()`.

| Prefix | Raised by |
| :--- | :--- |
| `TW-R` | The gateway, refusing a registration. Sent to the connector in a `Reject` frame with the same number. |
| `TW-A` | The gateway, admitting a connector connection. |
| `TW-S` | The gateway, sending a request through a connector. |
| `TW-I` | The gateway's agent ingress, refusing a request. |
| `TW-C` | The connector. |

## Registration rejected (`TW-R`)

### TW-R001

**Malformed.** The register frame could not be parsed. The connector and
gateway disagree on the wire format: check that both run the same
protocol version.

### TW-R002

**Unsupported version.** The connector speaks a protocol version the
gateway does not. Upgrade the older side.

### TW-R003

**Identity mismatch.** The SPIFFE ID in the frame is not the one in the
connector's client certificate, or the certificate is not an X.509-SVID
(no URI, more than one URI, or a URI that is not a SPIFFE ID). The
reason names which. Fix the connector's `[identity] spiffe_id` or issue
it an SVID; `tunnelward config check` catches a mismatch before
connecting.

### TW-R004

**Route owned.** A claimed route belongs to another identity: one named
for it in `[[connectors.owners]]`, or, for a route not listed there, the
identity that holds it now or held it within `routes_keep_time`. Claim a
different route, or move ownership in the gateway's configuration.

### TW-R005

**Invalid.** A claimed route, domain or other field breaks the rules in
`tunnelward-proto` (`is_route`, `is_domain`), or the registration would
take its identity past `Limits::max_routes_per_identity` (64) distinct
routes across its connections. The reason names which.

### TW-R006

**Attestation required.** The route requires a passmcp attestation and
the connector sent none.

### TW-R007

**Attestation invalid.** The attestation is expired, revoked, unsigned or
for another server. Re-run passmcp against the server the connector
fronts.

### TW-R008

**Policy denied.** Policy does not allow this identity to register.

### TW-R009

**Rate limited.** Too many registration attempts from this source
address: more than `Limits::registrations_per_minute` (60 by default),
counting attempts that failed. The connector backs off and retries on
its own. Many connectors behind one NAT address share the limit; raise
it for that deployment.

### TW-R010

**Overloaded.** The gateway is at capacity: the registration's new
domains would take it past `Limits::max_domains` (1,024 by default),
counting routes kept after their connectors left. A domain the gateway
already serves never counts twice. The connector retries; add gateway
capacity if it persists.

### TW-R011

**Internal.** The gateway failed while registering. Retry, and check the
gateway's logs.

## Admission (`TW-A`)

A rejected registration reports its `TW-R` id instead.

### TW-A001

**TLS handshake failed.** Usually a client certificate the gateway's
roots do not trust, an expired certificate, or a client that is not a
connector at all.

### TW-A002

**No `tw/1`.** The client did not negotiate ALPN `tw/1`; the gateway
closed the connection. Point only connectors at the connector listener.

### TW-A003

**Registration timeout.** No register frame arrived in time. The client
is slow, stuck or not a connector.

### TW-A004

**Read failed.** The stream failed or ended before a whole frame
arrived, or the frame's length prefix was over the limit.

### TW-A005

**Write failed.** The gateway's answer could not be written; the
connector went away.

### TW-A006

**HTTP/2 failed.** The HTTP/2 handshake failed after the registration was
accepted.

## Sending a request (`TW-S`)

### TW-S001

**No route.** No connector serves the request's host and path, and no
route is kept for it. The ingress answers 404. Check the connector's
claimed routes and domains (`/inventory?redaction=internal` on the admin
API).

### TW-S002

**Unavailable.** The route exists, but no connector had a free slot
within `max_wait`, or its wait queue was full. The ingress answers 503
with `Retry-After`.

### TW-S003

**Bad request.** The request's URI could not be made absolute. The
ingress answers 400.

### TW-S004

**Connector failed.** The request failed on the connector's connection:
it reset the stream, or the connection ended. The ingress answers 502.

## Ingress refusals (`TW-I`)

Routing failures at the ingress report their `TW-S` id.

### TW-I001

**URL too long.** The URL is over `max_url_len` (8 KiB by default). 414.

### TW-I002

**Declared body too large.** `Content-Length` is over `max_body` (16 MiB
by default). 413, before any of the body is read.

### TW-I003

**Body too large.** The body grew past `max_body` while it was read. 413.

### TW-I004

**Rate limited.** The client's address is over its token-bucket rate.
429 with `Retry-After`.

### TW-I005

**Body read failed.** The client's request body failed before it ended.
400.

### TW-I006

**Request timeout.** No response arrived within `request_timeout`. 504.

### TW-I007

**Origin not allowed.** A browser's CORS preflight came from an origin no
`cors` rule allows for that path. 403; the connector never sees it. Add
the origin to the path's rule if the page should reach the service.

### TW-I008

**Unauthorized.** Agent authorisation (`[agents]`) is on and the request
has no bearer token, or its token fails a check: an issuer not listed, a
signature no key of that issuer verifies, an `aud` that is not the
gateway's `resource`, or an `exp` or `nbf` outside the 60 s leeway. Also
for the replay defences (FR-13): a token bound to a DPoP key (`cnf.jkt`)
without a valid proof by that key (the challenge is then `DPoP
error="invalid_dpop_proof"`), a bound token sent as `Bearer`, a token
bound to a client certificate the connection did not present, a path in
`[[agents.paths]]` that needs a bound or single-use token, and a token or
proof used before. 401
with `WWW-Authenticate`, whose `error_description` names the check and
whose `resource_metadata` points at the gateway's protected-resource
metadata, where an MCP client finds the authorisation server. Get a token
for the resource from one of the listed issuers.

### TW-I009

**Insufficient scope.** The token is valid but does not grant every scope
in `[agents] scopes`. 403 with `WWW-Authenticate: Bearer
error="insufficient_scope"` naming the scopes. Ask the authorisation
server for a token with them.

### TW-I010

**Web Bot Auth signature fails.** The request carries a
`tag="web-bot-auth"` signature that does not pass: its `Signature-Agent`
is not in `[[providers.signers]]`, its `keyid` is not in that agent's key
directory, it does not verify, `created` is more than five minutes old
(or more than one minute ahead), it has expired, or its nonce was used
before. 401, only with `[providers] on_invalid = "reject"`; with
`"downgrade"` the request is served without a signature-level tag. The
reason names the check.

### TW-I011

**Enrolment refused.** A POST to `/.well-known/tunnelward/enrol` or
`/renew` did not get an SVID. 403 when the token is unknown, already used
or expired (issue a new one with `tunnelward enrol token`), or, for a
renewal, when the SVID is not a current one from this gateway's CA, its
identity was revoked (`tunnelward enrol revoke`), or the proof does not
verify with the SVID's key (an expired SVID cannot renew: enrol again
with a new token). 400 for a body or signing request that does not parse,
405 for a method other than POST, 413 for a body over 64 KiB, 500 when the token store cannot be
read or written. The reason names which.

### TW-I012

**Shared state unavailable.** A check that must record a first use (a
DPoP proof's or a single-use token's `jti`) could not reach the shared
store (`[state]`), or the in-process store is full. 503: these checks
fail closed, so a store outage refuses the request rather than risk a
replay (ADR 0004). Check the store and its credentials.

## Connector (`TW-C`)

A rejected registration reports its `TW-R` id instead.

### TW-C001

**Cannot reach the gateway.** The TCP connection or TLS handshake failed.
Check the address, the gateway's certificate and name, and the
connector's own certificate. The supervised connector retries with
backoff.

### TW-C002

**No `tw/1`.** The gateway did not agree to ALPN `tw/1`: the address is
not a Tunnelward connector listener.

### TW-C003

**Registration timeout.** The registration took longer than the
configured handshake timeout.

### TW-C004

**Write failed.** The register frame could not be sent.

### TW-C005

**Read failed.** The gateway's answer could not be read.

### TW-C006

**Unexpected frame.** The gateway answered with something other than
Accept or Reject.

### TW-C007

**HTTP/2 failed.** The HTTP/2 connection failed after registration.
