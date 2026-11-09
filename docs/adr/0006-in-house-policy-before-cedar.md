<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# ADR 0006: An in-house policy engine before Cedar

- Status: Accepted, implemented in 0.0.12
- Date: 2026-11-09

## Context

The plan named Cedar for per-tool policy (FR-4): a policy language with
formally verified semantics that many operators already know. Adding
`cedar-policy` 4.14 to `tunnelward-policy` brings 126 crates that no
audit imported by `cargo vet` covers, among them a parser generator, a
regex engine and their build-time dependencies. The gate refuses new
exemptions, and taking 126 at once would make the supply-chain check
mean little for the crate that decides what agents may do.

What 0.0.12 needs from a policy is small: permit or forbid a call by
agent, provider, path, method, tool and least evidence (FR-14), with
the D6 baseline in front.

## Decision

- `tunnelward-policy` holds an in-house rules engine with no
  dependencies. A forbid that matches wins, then a permit, then the
  default (deny unless set). Patterns are exact or a prefix (`read_*`);
  paths match on a `/` boundary.
- The gateway depends only on the `PolicyEngine` trait. A Cedar engine
  can implement it, behind a cargo feature, without the gateway or the
  configuration around it changing.
- The rule file is TOML in the gateway's own style, not a Cedar subset.
  A language that looks like Cedar but differs in corner cases would
  mislead operators about what a policy means.

## When to revisit

Cedar comes in, as a feature, when its crates are covered by audits
`cargo vet` imports, or by audits written here, and when a customer
needs what the rules cannot say: conditions over arbitrary context
attributes, entity hierarchies (`principal in Group::"payments"`), or
policies shared with other systems that already use Cedar.

## Consequences

- No new supply-chain exposure in the crate that gates every call.
- Operators learn a small rule format; `tunnelward policy test` runs
  their example calls against it before a policy ships.
- Moving to Cedar later means translating rule files; the rules map to
  Cedar `permit` and `forbid` statements one for one.
