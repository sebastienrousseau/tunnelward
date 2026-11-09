<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# ADR 0004: State shared across gateways

- Status: Accepted. Implemented in v0.0.12: the `SharedState` trait, the
  in-process store and a Redis-compatible (RESP) store. The embedded Raft
  store is not built.
- Date: 2026-11-07

## Context

A connector keeps connections to several gateways (FR-1), and an agent's
calls can land on any of them. Some checks only work if every gateway sees
the same state: a replayed token is only caught if the gateway it is
replayed against knows the first use. A shared store can also fail, and
each check must say in advance what it does then.

## Decision

State sits behind one `SharedState` trait (v0.0.12), with three
implementations: in-process for a single gateway, an embedded Raft store,
and an external Redis-compatible store for high availability.

| State | Shared | If the store is unreachable |
| :--- | :--- | :--- |
| `jti` replay cache (FR-13) | Yes | Fail closed: refuse tokens the route requires to be single-use |
| DPoP and RFC 9421 nonce caches (FR-12, FR-13) | Yes | Fail closed |
| Idempotency keys on `high_impact` tools (FR-13) | Yes | Fail closed: refuse the call rather than risk running it twice |
| Rate limits per identity and IP (G13) | Yes, approximate | Fail open to a local bucket of the limit divided by the gateway count |
| Risk baselines (FR-16) | Yes, eventually consistent | Fail open; the score is marked degraded in the provenance record |
| Receipt and audit sequence (FR-15) | No | Each gateway signs its own sequence, named by gateway id |
| Pools, wait queues, kept routes | No | Each gateway knows its own connectors |

## Consequences

- One gateway needs no store at all; HA deployments choose one.
- Failing closed on replay and idempotency means a store outage refuses
  some calls. That is the safe failure for the checks that exist to stop
  a call running twice; operators see it as an alert, not as silent fraud.
- Tests replay a Web Bot Auth nonce across two gateways sharing a store
  and expect the second to refuse it, against an in-process store and a
  real Valkey in CI.
