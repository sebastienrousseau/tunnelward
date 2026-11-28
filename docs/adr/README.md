<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Architecture decision records

One file per decision that someone will later question. A record is
never rewritten once accepted; a new record supersedes it.

| ADR | Title | Status |
| :--- | :--- | :--- |
| [0001](0001-reverse-http2.md) | Reverse HTTP/2 instead of a custom multiplexer | Accepted |
| [0002](0002-hybrid-pq-by-default.md) | Hybrid post-quantum key exchange by default | Accepted |
| [0003](0003-cbor4ii-for-register-frames.md) | cbor4ii for the register frames | Accepted |
| [0004](0004-state-shared-across-gateways.md) | State shared across gateways | Accepted, implemented in 0.0.12 |
| [0005](0005-leases-renew-by-reconnecting.md) | Leases renew by reconnecting | Accepted |
| [0006](0006-in-house-policy-before-cedar.md) | An in-house policy engine before Cedar | Accepted, implemented in 0.0.12 |
| [0007](0007-composite-signatures.md) | Composite ML-DSA-65 and Ed25519 signatures | Accepted, implemented in 0.0.12 |
| [0008](0008-audit-log-and-receipts.md) | A hash-chained audit log, pseudonymous by default, and signed receipts | Accepted, implemented in 0.0.14 |
| [0009](0009-admission-by-passmcp-attestation.md) | Admission by passmcp attestation, signed by keys the operator names | Accepted, implemented in 0.0.15 |
| [0010](0010-telemetry-without-the-sdk.md) | Telemetry as OTLP/HTTP JSON, written in-house | Accepted, implemented in 0.0.16 |
| [0011](0011-risk-signals.md) | Risk signals that need no IP data | Accepted, implemented in 0.0.16 |
| [0012](0012-control-plane-alpha.md) | A control plane that signs policy bundles for gateways to pull | Accepted, implemented in 0.0.19 |
| [0013](0013-audit-export-to-siem.md) | Audit export to a SIEM over syslog and OTLP logs | Accepted, implemented in 0.0.20 |
| [0014](0014-out-of-band-approval.md) | Out-of-band approval for high-impact tools, by MCP URL elicitation | Accepted, implemented in 0.0.20 |
| [0015](0015-kubernetes-operator-alpha.md) | A Kubernetes operator written against the API server's REST API | Accepted, implemented in 0.0.21 |
| [0016](0016-gateway-blind-mode.md) | Gateway-blind mode, HPKE with X-Wing between agent and connector | Accepted, implemented in 0.0.22 (experimental) |
| [0017](0017-server-descriptor-and-tool-guard.md) | The connector reports its MCP server and guards its tool list | Accepted, implemented in 0.0.23 |
