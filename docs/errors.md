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

**Identity mismatch.** The SPIFFE ID in the frame does not match the
connector's client certificate. Fix the connector's configured identity
or its certificate.

### TW-R004

**Route owned.** A claimed route belongs to another identity. Claim a
different route, or move ownership in the gateway's configuration.

### TW-R005

**Invalid.** A claimed route, domain or other field breaks the rules in
`tunnelward-proto` (`is_route`, `is_domain`). The reason names the field.

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

**Rate limited.** Too many registration attempts from this source. The
connector backs off and retries on its own.

### TW-R010

**Overloaded.** The gateway is at capacity. The connector retries; add
gateway capacity if it persists.

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
