<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# ADR 0017: The connector reports its MCP server and guards its tool list

- Status: Accepted, implemented in 0.0.23
- Date: 2026-11-28

## Context

Since 0.0.15 a route can require a passmcp attestation (ADR 0009), and
the rule can match the attested server's name and version against what
the connector reports in `Register.mcp` (`McpDescriptor`: name, version,
`tools_digest`). The tunnelward connector never filled that field in, so
the version match never ran (spec G3, "partial").

A second gap is the tool list itself. An MCP server can change a tool's
description or input schema at any time: a tool reviewed as "moves
money" can come back telling the agent to read a key file first (a "rug
pull", or tool poisoning). Agents read `tools/list` answers as
instructions. Nothing between the reviewed server and the agent noticed
such a change.

In gateway-blind mode (ADR 0016) the gateway cannot read answers, so a
check there cannot cover every route. The connector reads every answer
in the clear, in both modes.

## Decision

**Data.** At start, the connector asks its server who it is and what
tools it has: `initialize`, `notifications/initialized`, then every page
of `tools/list` (at most 64), then the session ends. Over HTTP this is
Streamable HTTP, JSON or an event stream; the stdio bridge runs it on a
process of its own. What it keeps, `Described`, is the server's name and
version and one SHA-256 digest per tool, by name:

```text
tool digest   = SHA-256(the tool's JSON, keys sorted, no whitespace, as serde_json writes it)
tools_digest  = SHA-256(for each tool in name order: u32_be(len(name)) || name || tool digest)
```

`tools_digest` goes in every register frame, with the name and version.
The gateway's attestation rule checks the name and version as before,
and its registration audit entry now records all three (`server`,
`server_version`, `tools_digest`), so a change of tools between two
registrations shows in the log.

**The guard.** With a server pinned, the connector reads the answer to
every `initialize` and `tools/list` request before it goes back. An
answer that names another server or version, or lists a tool that is
new or whose digest changed, is replaced with a JSON-RPC error (code
-32001, "the server's tools changed since registration"); the changed
text never reaches the agent. A tool that disappears is not stopped:
removing a tool cannot instruct an agent. Two policies:

- `block` (the default): the change stays refused until the connector
  restarts, which re-describes the server. An operator reviews the
  change first.
- `reregister`: the connector takes the change and every connection
  registers again with the new descriptor, so the gateway's admission
  (and the route's attestation rule) decides afresh, and the log shows
  the new digest.

On the HTTP path the guard buffers POST bodies, within the 1 MiB MCP
body limit, to find the guarded requests; answers to those are read in
full within the same limit, and every other answer streams as before.

**Configuration.** `[register.describe]` in the connector's file, with
`path` (the HTTP target's MCP endpoint, default `/mcp`) and `on_change`.
`Pinned::check_exchange` gives the same guard to an embedder with a
service of its own.

## Consequences

- G3 holds end to end: when the route's attestation names a server, a
  connector fronting another server or version is refused at
  registration. A statement that names no server still matches any.
- A rewritten or added tool is refused at the connector in both normal
  and gateway-blind mode, with no new dependency (SHA-256 from
  aws-lc-rs, already used).
- With describe on, a POST over 1 MiB is refused (413) on the HTTP path;
  MCP messages are well under it.
- The digest is ours: it is not RFC 8785 (JCS). Only the connector
  computes it, and a test pins it to a value recomputed independently
  (Python, `json.dumps(sort_keys=True, separators=(",", ":"))`) for an
  ASCII tool list; non-ASCII text and floating-point numbers are written
  as serde_json writes them.
- The passmcp statement names the server, not its tools, so an
  attestation cannot pin the tool set yet. Under `reregister` a changed
  tool set is admitted whenever the name and version still match; the
  audit log is the record. `block` is the default for that reason.
- A server that changes its tools without being asked (a
  `notifications/tools/list_changed` on its event stream) is not
  re-described until the agent asks again; the guard checks what the
  agent is shown, which is the answer to its next `tools/list`.

## Alternatives

- **Check at the gateway.** It sees `tools/list` answers only outside
  blind mode, and must parse event streams it otherwise passes through.
  The connector sees every answer, so the check lives there.
- **One digest for the whole list.** A paginated answer shows one page,
  whose digest says nothing about the list; per-tool digests check each
  page on its own.
- **Poll the server.** Polling finds a change between polls, but an
  agent can be shown it before the next poll. Reading the answers checks
  exactly what agents are shown.
- **RFC 8785 canonical JSON.** It needs number formatting that
  serde_json does not do, so it would mean writing a serializer, for a
  digest no one else computes.
