<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Data protection impact assessment: template

A starting point for the data protection impact assessment (GDPR
Article 35) an organisation runs before it puts Tunnelward in front of
tools that AI agents call. The facts about what Tunnelward records come
from the code and its ADRs; everything marked **[controller]** is yours
to decide and fill in. This is a template, not legal advice: your data
protection officer owns the assessment.

## 1. The processing

| | |
| :-- | :-- |
| Controller | **[controller]** |
| Data protection officer | **[controller]** |
| Purpose | Admit AI agents to internal tools, decide each call against a policy, and keep evidence of every call and decision (FR-4, FR-15). |
| Lawful basis | **[controller]**: usually legitimate interests (security of the systems behind the gateway), or a legal obligation where a regulator requires the evidence. |
| Data subjects | People whose addresses or certificates reach the gateway; users on whose behalf agents act; operators and approvers who sign in. |
| Systems | The gateway, its connectors, the audit log file, the shared state store (in process, or a Redis-compatible store), and any SIEM the log exports to. |

## 2. What is recorded, and where

**The audit log** (`[audit]`, ADR 0008), one line per request, admin
action or connector registration:

| Data | As written | Personal data? |
| :-- | :-- | :-- |
| Caller's IP address | HMAC-SHA-256 pseudonym under the operator's key | Pseudonymised |
| Caller's certificate | Pseudonym of its SHA-256 | Pseudonymised |
| OAuth client (`client_id`) | As the token names it | Rarely; it names software |
| Approver or operator (`actor`) | The ID token's `sub` | Yes, an identifier |
| Host, path, method, `User-Agent`, MCP session id | As sent; no query string | Possibly, if a path or agent string names a person |
| Tool arguments, request and response bodies | SHA-256 digests only | No content is kept |
| Status, timings, risk score and signals, decision | As computed | No |

**Raw addresses** are kept only with `raw_days` set (1 to 30), in a
sidecar file pruned daily; by default none are kept (D7).

**The SIEM export** (`[audit.export]`, ADR 0013) sends each entry as an
OCSF event: the same fields, pseudonyms included, to the syslog
receiver or OpenTelemetry collector you name. Retention there is the
SIEM's. **[controller]**: name each destination and its retention.

**Approvals** (`[approval]`, ADR 0014) keep, in the shared state for
`ttl_secs` (600 s by default), the call waiting for approval: its tool,
its **arguments in full**, so the approver can read them, the agent
token's `sub` and client, and the path. After the window they expire.
Arguments to a high-impact tool often hold personal data (a payee, an
account): **[controller]** decide whether that window and the store's
location fit.

**The control plane** (`tunnelward control`, ADR 0012) records each
policy publish and rollback with the operator's `sub`.

## 3. Necessity and proportionality

- **Minimisation**: addresses and certificates are pseudonyms; contents
  are digests; the query string is not logged; raw values are off.
- **Retention**: the audit log is kept as long as **[controller]**
  decides; it has no built-in expiry, so rotate files by policy. Raw
  addresses at most 30 days. Approval records `ttl_secs`.
- **Access**: the log file is created owner-only; the pseudonym key and
  the signing key are separate files. **[controller]**: who holds them.
- **Re-identification**: only with the pseudonym key, and only for a
  value you already know: pseudonyms are keyed hashes, not encryption.
- **Transfers**: none by Tunnelward itself; the SIEM and the identity
  providers you configure may be elsewhere. **[controller]**

## 4. Risks and measures

| Risk | Likelihood, severity | Measure in Tunnelward | Left to you |
| :-- | :-- | :-- | :-- |
| An audit file leaks | **[controller]** | Pseudonyms, digests, no contents | Disk encryption, access control |
| The pseudonym key leaks with the log | **[controller]** | Separate file, owner-only | Key storage, rotation |
| A SIEM keeps events longer than needed | **[controller]** | Export is a copy of pseudonymised events | SIEM retention policy |
| Approval arguments seen by the wrong person | **[controller]** | Only the agent's own user or an approver group, after an OIDC sign-in; single-use links and forms | Group membership, the store's access |
| The shared store is read by others | **[controller]** | Keys expire with `ttl_secs` | Store authentication and network isolation |
| A log is altered to hide an action | **[controller]** | Hash chain with signed checkpoints, `audit verify` | Keep the public key apart from the log |

## 5. Outcome

| | |
| :-- | :-- |
| Residual risk | **[controller]** |
| DPO advice | **[controller]** |
| Decision and date | **[controller]** |
| Next review | **[controller]** |
