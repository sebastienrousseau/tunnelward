<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# ADR 0013: Audit export to a SIEM over syslog and OTLP logs

- Status: Accepted, implemented in 0.0.20
- Date: 2026-11-27

## Context

A security team reads events in its SIEM, not in a file on each
gateway. Since 0.0.14 the audit log is a hash-chained file (ADR 0008),
and `tunnelward audit export` turns it into OCSF 1.3.0 events after the
fact. The plan gives 0.0.20 a live export. Every SIEM takes syslog, and
most take OpenTelemetry logs. No dependency may be added (D9): the
gateway already writes OTLP/HTTP JSON for spans (ADR 0010) and has
rustls for TLS.

## Decision

**The file stays the record.** The audit writer hands each line to a
`Forward` hook after it has written it. Export is a copy: a SIEM that
missed an event is filled from `audit export`, and verification still
runs against the file.

**Data.** One bounded queue of lines (4,096 by default) feeds one task.
The task turns each entry into its OCSF event; checkpoints and gaps are
not events and are skipped. It sends batches of up to 256 events, at
least every second. A full queue drops the line and counts it, so a
slow SIEM never holds up the log or a request. A send that fails is
counted, and the batch is not retried beyond one fresh connection.

**Syslog.** Each event is an RFC 5424 message, its MSG the OCSF event as
JSON and its MSGID `ocsf-<class_uid>`, framed by octet counting (RFC
6587) on one TCP connection. TLS (RFC 5425) is the default, trusting the
`ca` given or the system roots. Plain TCP is allowed only to a loopback
address, for a local relay. Severity is warning (4) for an OCSF failure
and informational (6) otherwise; the facility defaults to 13, log audit.

**OTLP logs.** One log record per event, its body the OCSF event as JSON,
posted to `<endpoint>/v1/logs` under the span exporter's endpoint rules:
`https://`, or `http://` to loopback.

**Configuration.** `[audit.export]` holds the limits, with
`[audit.export.syslog]` and `[audit.export.otlp]` as destinations. The
gateway and the control both read it, as part of `[audit]`.

## Consequences

- An event reaches the SIEM about a second after it is written. Events
  still queued when the process stops are not sent; the file has them.
- Delivery is at most once per destination, except that a message a
  broken connection half wrote may arrive twice on the new one.
- Counters for dropped and failed sends exist on the forwarder but are
  not yet on `/metrics`.

## Alternatives

- **Syslog over UDP** (RFC 5426) loses messages without saying so, and a
  JSON event can exceed a datagram. Not offered.
- **The OpenTelemetry SDK or a syslog crate** would add dependencies for
  a few hundred lines we own (D9).
- **A Splunk HEC or Sentinel connector** is planned with the
  integrations in 0.0.28; both also ingest syslog and OTLP today.
