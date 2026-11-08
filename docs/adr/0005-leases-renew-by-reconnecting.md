<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# ADR 0005: Leases renew by reconnecting

- Status: Accepted
- Date: 2026-11-07

## Context

`Accept` grants a lease. The specification said renewals ride as HTTP/2
PINGs plus "a periodic `POST /tw/v1/lease` on the connection". After the
roles reverse (ADR 0001) the connector is the HTTP/2 *server*: it cannot
send requests to the gateway, so that POST cannot exist. A lease still has
to end, so that a revoked identity or attestation stops being served
within one lease (FR-5).

## Decision

- A lease is the longest a connection may live. When it ends, the gateway
  drains the connection (`drain_grace`, default 30 s) and cuts it.
- The connector renews by reconnecting, make before break: at a random
  point between 70% and 90% of the lease it dials a successor and
  registers, then sends GOAWAY on the old connection and lets its requests
  finish. Registration re-checks identity and attestation every time.
- A request the gateway started on the old connection as the GOAWAY
  arrived is refused unprocessed, and the gateway retries it once on
  another connection. Nothing that may have reached the connector is
  ever retried.
- Liveness is HTTP/2 PING, which needs no new frame type.

## Consequences

- No lease protocol to design, parse or fuzz: renewal reuses registration.
- Each renewal costs a TLS handshake (hybrid key exchange included). With
  the default 1 h lease that is one handshake per connection per hour.
- The renewal test sends requests back to back for 3.5 s with a 1 s lease
  and requires every one to succeed; it fails if the retry is removed.
