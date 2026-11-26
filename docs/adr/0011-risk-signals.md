<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# ADR 0011: Risk signals that need no IP data

- Status: Accepted, implemented in 0.0.16
- Date: 2026-11-26

## Context

FR-16 asks for a risk score from velocity per subject, tool and IP
prefix; impossible travel; first-seen ASN; tool-sequence drift; canary
tools and canary records. The score is policy context, and alerts go
out over telemetry. Its acceptance test: a scripted search-then-bulk-
export run crosses the threshold, and a canary call ends the session and
raises an alert.

Impossible travel and first-seen ASN need IP geolocation and ASN data.
IP enrichment was dropped in v0.0.12 until a licensed data source is
chosen.

## Decision

- **Four signals now**, in a new crate, `tunnelward-risk`:
  - velocity: calls per subject, per tool and per IP prefix (/24, /48)
    in a window, each against its own limit;
  - drift: after a warm-up, a step from one tool to another that the
    subject has never taken; it stays on the subject for the velocity
    window, because the calls after a switch are as suspect as the
    switch;
  - canary tools: a call to a tool no legitimate agent uses;
  - canary records: a request body containing a planted value.
- **The subject is the OAuth client id**, else the client address.
  Keys in the shared store are SHA-256 digests, never raw addresses.
- **Velocity counts go through `SharedState`**, so they hold across
  gateways (ADR 0004). If the store fails, that signal is skipped: risk
  fails open, because the policy, not the score, is what refuses.
- **Drift baselines stay in process**, at most 10,000 subjects; the
  oldest is forgotten first. A restarted gateway learns them again.
- **The score is 0 to 100**: each signal adds its weight, capped at 100.
  A canary sets it to 100. By default a velocity limit is worth 35 and a
  drift 25, and the alert is at 70: one limit crossed, with or without
  a drift (35 or 60), does not alert; two limits do (70, or 95 with a
  drift).
- **Policy reads it**: a rule with `risk = N` matches calls whose score
  is N or more, so `forbid` with `risk = 70` refuses them.
- **A canary ends the session.** Its subject and MCP session are refused
  (`TW-I008`) for `block_secs` (one hour by default) on this gateway,
  and the alert goes to every observer, the audit entry and the span.
- **The score and its signals are in the audit entry and on the span.**

## When to revisit

Impossible travel and first-seen ASN when an IP data source is chosen.
Sharing the canary block across gateways when `SharedState` can be read
without writing.

## Consequences

- Every limit and weight is configurable in `[risk]`, with defaults.
- A subject without a token is its address, so agents behind one NAT
  share a velocity count; give them tokens.
