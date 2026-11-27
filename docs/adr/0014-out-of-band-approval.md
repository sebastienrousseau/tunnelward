<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# ADR 0014: Out-of-band approval for high-impact tools, by MCP URL elicitation

- Status: Accepted, implemented in 0.0.20
- Date: 2026-11-27

## Context

FR-17 asks that a call to a `high_impact` tool (one that moves money,
deletes data, sends mail) runs only once a person has approved it, and
that the approval covers exactly that call: "an approval for one
argument set cannot authorise a changed one". Since 0.0.12 such a call
needs cryptographic evidence (D6) and, since 0.0.13, an idempotency key
(FR-13), but an injected agent with a valid token can still make one.

MCP 2025-11-25 defines URL-mode elicitation for this: a server that
needs the user to do something outside the client answers with the
error `URLElicitationRequiredError` (code -32042), naming a URL; the
client shows it, the user acts there, and the client retries. OpenID
CIBA was the alternative: it needs an identity provider that supports
it, and pushes to a device the gateway cannot see. No dependency may be
added (D9).

## Decision

**Turned on by `[approval]`**, which needs `[agents]`: an approval is
bound to the agent's token, so the gateway must have checked one. Every
call to a tool the policy marks `high_impact` then needs an approval.

**Data.** An approval binds one call:

```text
digest   = SHA-256(token sub, client_id, path, tool, SHA-256(arguments))
Request  { id, digest, tool, arguments, sub, client_id, path, at_ms }
```

`arguments` are digested as JSON with sorted keys, as the audit log
does, so key order and spacing do not matter and any changed value
does. `id` is 128 random bits. Records live in the shared state (ADR
0004) for `ttl_secs` (600 by default), so any gateway behind a load
balancer can serve the page and honour the approval:

| Key | Holds |
| :-- | :-- |
| `approval:<id>` | the Request, as JSON |
| `approval-login:<state>` | the login under way: id, PKCE verifier, nonce |
| `approval-form:<token>` | a signed-in approver's form: id, approver |
| `approved:<digest>` | the id of the approval granted |
| `approval-spent:<id>` | set once, when the retried call uses it |

**The call.** A `tools/call` to a high-impact tool is looked up by its
digest. With an unspent approval it is marked spent, atomically, and
forwarded; that call alone uses it. Otherwise the gateway stores a new
Request and answers the JSON-RPC error -32042 with one URL elicitation:
`<public_url>/.well-known/tunnelward/approvals/<id>`. A batch with a
high-impact call in it is refused: approve one call at a time.

**The page.** Opening the URL starts an OpenID Connect sign-in at the
approvers' provider: authorization code with PKCE (S256), `state` and
`nonce` single-use and bound to the Request. The callback exchanges the
code at the token endpoint and checks the ID token with the gateway's
own JWT verifier: signature under the provider's keys, issuer, `aud`
equal to `client_id`, dates and `nonce`. The approver may decide if
their `sub` is the agent token's `sub` (people approve their own
agents' calls) or a group in `approver_groups` is in their token's
`groups` claim (or the claim named). The page shows the tool, the
arguments and the agent, with Approve and Deny buttons; the form
carries a single-use token. The page runs no script and sets a
Content-Security-Policy of `default-src 'none'; form-action 'self'`.

**Audit.** Each approval and denial is an admin entry in the audit log
(`approve` or `deny`, `approval=<id> tool=<tool> digest=<digest>`) with
the approver as actor. The call that needed one is a refused request
(`TW-P006`).

## Consequences

- An agent that does not support URL elicitation shows the error's
  message; the user can still open the URL from it.
- The sign-in needs the provider's authorization and token endpoints and
  keys in the file; discovery from the issuer is not read.
- One approval, one run: a client that retries with changed arguments
  gets a new elicitation.

## Alternatives

- **OpenID CIBA**: needs provider support and a device binding; it can
  sit behind the same digest later.
- **Approving with a bearer token on an API**: a browser has no token,
  and URL elicitation sends a person to a browser.
- **Signing approvals into the call**: needs client support MCP does not
  have.
