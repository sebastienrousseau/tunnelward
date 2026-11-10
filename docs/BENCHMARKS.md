<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Benchmarks

The first numbers against the plan's performance requirements, NFR-1 to
NFR-3. Each section says what was measured, how, and what could not be
measured yet. A number that the machine's noise could have produced is
not published.

Reproduce with `cargo xtask bench`, which builds `tunnelward-bench` in
release mode and prints these figures. The harness uses only the
workspace's own crates. Its memory figures come from a counting global
allocator (`crates/tw-bench/src/alloc.rs`), the one file in the
workspace with unsafe code: the benchmark crate is never published,
every published crate forbids unsafe code, and
`scripts/unsafe-boundary.sh` fails CI if unsafe code appears anywhere
else.

## Machine

- Apple A18 Pro: 6 cores, 2 performance and 4 efficiency; 8 GiB.
- macOS 27.2; Rust 1.97.1; release builds. The gateway's code is the
  same at every commit measured (`780b77f` for latency, the v0.0.13
  release for memory).
- Everything on loopback: client, gateway, connector and service.

## NFR-1: added latency

**Requirement:** the gateway adds under 0.5 ms at p50 and under 2 ms at
p99 to a 1 KiB MCP call on a warm connection.

**Method:** one keep-alive HTTP/1.1 connection sends a 1 KiB
`tools/call` to a service that answers with 1 KiB, once directly and
once through the gateway and a connector. Open loop: calls are due at
1,000 a second and each is timed from when it was due, so a slow call's
delay to the next counts (no coordinated omission). The timer wakes 2 ms
early and spins the rest, since it is good only to a millisecond. 2,000
calls warm each path; 5,000 are measured; five runs.

| Run | Direct p50 | Gateway p50 | Added p50 |
| ---: | ---: | ---: | ---: |
| 1 | 101 µs | 254 µs | 153 µs |
| 2 | 99 µs | 224 µs | 125 µs |
| 3 | 115 µs | 261 µs | 145 µs |
| 4 | 101 µs | 259 µs | 157 µs |
| 5 | 103 µs | 263 µs | 160 µs |

**Verdict:**

- **p50: met.** The gateway and tunnel add 125 to 160 µs across the five
  runs, against a 500 µs budget.
- **p99: not yet measured.** On this laptop the direct path's own p99,
  with no gateway involved, swings by tens of milliseconds between runs,
  so the gateway's share cannot be separated from the machine's
  scheduling. It needs a quiet Linux machine with isolated cores.

## NFR-2: memory per connection

**Requirement:** under 64 KiB per idle connector connection; under
16 KiB plus the stream window per in-flight stream. The stream window
is 256 KiB (`Limits::default`), so the second budget is 272 KiB.

**Method:** the gateway runs alone in one process. Another process
registers 500 connectors; then opens 500 HTTP/1.1 client connections to
the gateway's ingress; then sends a 1 KiB call on each, which the
connectors hold unanswered. It moves to each phase only when the
gateway's process says so, and the bytes live on the gateway's heap,
counted by the allocator, are read after each phase settles and the
growth divided by 500. These are exact heap bytes: no allocator slack,
no pages. Three runs gave the same figures to within 0.2 KiB.

| Measured | Live heap |
| :--- | ---: |
| Per idle connector connection (TLS session, HTTP/2 connection, registry entry) | 58.9 KiB |
| Per idle HTTP/1.1 client connection at the ingress | 22.0 KiB |
| Per request in flight, beyond its client connection | 25.8 KiB |

**Verdict:**

- **Idle connector connection: met.** 58.9 KiB against 64 KiB.
- **In-flight request: met.** 25.8 KiB against 272 KiB. Of the 25.8 KiB,
  about 2 KiB is the request and its body; the rest is the gateway's
  per-request state on both sides of the tunnel. Read strictly, that
  fixed part is above the 16 KiB the requirement allows before the
  window, by about 8 KiB.

An earlier measurement for this page, from resident memory, gave about
120 KiB per idle connection. It was wrong in two ways: resident memory
counts the allocator's slack, and the harness let the requests start
before the idle reading, so that reading included them. Both are fixed.

## NFR-3: scaling

**Requirement:** throughput scales near-linearly from 1 to 8 cores.

**Verdict: not yet measured.** `tunnelward-bench scaling` runs the
gateway in its own process with 1, 2 and 4 worker threads and loads it
from another. On this six-core laptop the load and the gateway share
the same cores, and throughput varied by about a third between runs, so
the result says more about the machine than about the gateway. It needs
at least 8 cores for the gateway and a second machine, or more cores,
for the load.

## Call receipts (FR-15)

**What:** issuing and checking one signed `tw-receipt` (ADR 0008), for
a `tools/call` with one argument digest. Issuing is on the request path
when `receipts = true`, so it counts against NFR-1's budget; checking is
what a client or auditor does offline. Measured at v0.0.14 with
`tunnelward-bench receipts`: five runs of 1,000 each, on the machine
above with Rust 1.99.0.

| Run | Issue | Verify | Header |
| ---: | ---: | ---: | ---: |
| 1 | 100 µs | 69 µs | 5045 B |
| 2 | 93 µs | 68 µs | 5045 B |
| 3 | 90 µs | 71 µs | 5045 B |
| 4 | 95 µs | 70 µs | 5045 B |
| 5 | 90 µs | 66 µs | 5045 B |

**Reading:** issuing a receipt takes 90 to 100 µs, about a fifth of
NFR-1's 500 µs at p50, and adds a 5 KB header; that is why receipts are
off by default. The latency figures above were measured without them.
Writing the audit log itself happens off the request path, on the
writer's own thread; its cost to a request (hashing the body, queueing
an entry) is not measured separately yet.
