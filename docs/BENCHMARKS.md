<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Benchmarks

The first numbers against the plan's performance requirements, NFR-1 to
NFR-3, measured on 2026-11-09. What each number means, and what could
not be measured on this machine, is stated with it.

Reproduce with `cargo xtask bench`, which builds `tunnelward-bench` in
release mode and prints these tables. The harness uses only the
workspace's own crates: Criterion and dhat, which the plan named, would
add crates to audit, and dhat needs a custom allocator, which this
workspace forbids (`unsafe_code = "forbid"`).

## Machine

- Apple A18 Pro: 6 cores, 2 performance and 4 efficiency; 8 GiB.
- macOS 27.2; Rust 1.97.1; release build of commit `780b77f`.
- Everything on loopback: client, gateway, connector and service.

A laptop with cores of two kinds is a noisy place to measure tails:
see each section.

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

| Run | Direct p50 | Direct p99 | Gateway p50 | Gateway p99 | Added p50 | Added p99 |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 101 µs | 182 µs | 254 µs | 1686 µs | 153 µs | 1503 µs |
| 2 | 99 µs | 210 µs | 224 µs | 27545 µs | 125 µs | 27335 µs |
| 3 | 115 µs | 6439 µs | 261 µs | 4273 µs | 145 µs | -2166 µs |
| 4 | 101 µs | 204 µs | 259 µs | 4179 µs | 157 µs | 3975 µs |
| 5 | 103 µs | 32153 µs | 263 µs | 1254 µs | 160 µs | -30900 µs |

**Verdict:**

- **p50: met.** The gateway and tunnel add 125 to 160 µs across the five
  runs, against a 500 µs budget.
- **p99: not determined here.** The direct path's own p99 reaches 6 ms and
  32 ms in some runs, with no gateway involved: the machine's scheduling,
  not the gateway, sets the tail. The negative values in the last column
  are that noise. A quiet Linux machine with isolated cores is needed to
  measure the p99 the requirement names.

## NFR-2: memory per connection

**Requirement:** under 64 KiB per idle connector connection; under
16 KiB plus the stream window per in-flight stream.

**Method:** the gateway runs alone in one process; 500 connectors, then
500 clients whose calls the connectors hold open, run in another. The
gateway's growth in resident memory is divided by the count. Resident
memory includes the allocator's slack and is rounded to pages, so this
is an upper bound, coarser than an allocator profile.

| Measured | Run 1 | Run 2 |
| :--- | ---: | ---: |
| Per idle connector connection | 117.5 KiB | 122.2 KiB |
| Per request in flight | not resolved | not resolved |

**Verdict:**

- **Idle connection: not met, as measured.** About 120 KiB, against 64 KiB.
  It holds a TLS session, an HTTP/2 connection and the gateway's
  registry entry; some of the 120 KiB is allocator slack that an
  allocator-level measurement would separate out. Reducing it (rustls
  and HTTP/2 buffer sizes) is follow-up work once that measurement
  exists.
- **In-flight request: not measured.** Resident memory did not grow
  measurably while 500 requests were held, most likely because the
  process reused memory freed earlier; this method cannot see it.

## NFR-3: scaling

**Requirement:** throughput scales near-linearly from 1 to 8 cores.

**Method:** the gateway runs in its own process with a runtime of 1, 2
or 4 worker threads; four connectors and 64 clients calling back to back
run in another, for 5 s each. The gateway's CPU use is read from `ps`
(average over its life, so a little low).

Two runs:

| Workers | Run 1 calls/s | Run 1 gateway CPU | Run 2 calls/s | Run 2 gateway CPU |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 11727 | 75% | 16383 | 88% |
| 2 | 15051 (1.28x) | 81% | 20630 (1.26x) | 169% |
| 4 | 14387 (1.23x) | 58% | 20910 (1.28x) | 214% |

**Verdict: not measurable here.** Throughput stops rising after two
workers in both runs, while the gateway's CPU use differs between them:
in run 2 it used more than two cores with four workers and still did not
go faster, so something outside the gateway, the clients and connectors
sharing the same six cores, set the limit. Throughput also varies by
about a third between runs on this machine. Measuring 1 to 8 cores needs
at least 8 cores for the gateway and more for the load, or a second
machine for the load.
