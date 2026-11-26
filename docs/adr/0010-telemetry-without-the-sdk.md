<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# ADR 0010: Telemetry as OTLP/HTTP JSON, written in-house

- Status: Accepted, implemented in 0.0.16
- Date: 2026-11-26

## Context

The plan gives 0.0.16 OpenTelemetry: a span per call with its route,
tool, identities and negotiated key exchange; RED metrics (rate,
errors, duration) with exemplars; a Grafana dashboard in the
repository. The official Rust SDK with its OTLP exporter (opentelemetry
0.33, HTTP transport) adds 35 crates the lockfile does not have, and
46 with gRPC. No imported cargo-vet audit covers most of them, and the
exemption count may only shrink. ADR 0006 made the same call for Cedar.

OTLP has a JSON encoding over HTTP (`POST /v1/traces`), which every
OpenTelemetry Collector and most backends accept. The gateway already
has a hyper client and the `ProxyObserver` hooks (G11).

## Decision

- **Spans are written by an observer, `OtlpExporter`, as OTLP/HTTP
  JSON.** One span per ingress request, kind server, named
  `<METHOD> <path>`. Its trace continues the client's `traceparent`
  when there is one. Attributes follow the HTTP semantic conventions
  (`http.request.method`, `url.path`, `http.response.status_code`) and
  name the rest under `tunnelward.*`: request id, client id, provider,
  evidence level, mismatches, MCP methods and tools, the negotiated TLS
  key exchange group, the risk score and signals. A risk alert is a span
  event. Error status is set for 5xx and refusals.
- **Export never blocks a request.** Spans go to a bounded queue (2,048
  by default) and are sent in batches (512, or every 5 seconds). A full
  queue drops the span and counts it in `/metrics`, as the audit log
  does with entries.
- **The collector is `https://`, or `http://` on loopback only**, for a
  collector beside the gateway. Spans name agents and tools; they do not
  cross a network in clear.
- **RED metrics live on the existing `/metrics`**: requests by route and
  status class, a duration histogram by route, and the dropped-span
  count. Asked with `Accept: application/openmetrics-text`, histogram
  buckets carry the trace id of a recent request as an exemplar.
- **A Grafana dashboard** (`deploy/grafana/tunnelward.json`) reads
  those metrics.
- **Routes in metrics are the claimed route that served the request**,
  so labels stay bounded by the number of routes, never by paths.

## Consequences

- No new crate. The exporter is about 300 lines with its tests.
- Semantic-convention changes are ours to follow. The exporter sits
  behind `ProxyObserver`, so the SDK can replace it when its crates are
  vetted.
- Metrics are pull only (Prometheus text or OpenMetrics), not OTLP.
