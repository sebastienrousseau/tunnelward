<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# AGENTS.md: Tunnelward

Tunnelward lets an MCP server or internal tool behind a firewall dial out
to a gateway, prove what it is, and serve AI agents through that gateway
with no inbound port, hybrid post-quantum TLS on every hop, and an audit
trail anyone can verify offline. It is the connectivity and admission
layer of the Satellion suite, next to passmcp. Its core value is trust:
a defect that weakens identity, admission, confidentiality or audit
outranks any feature.

The workspace-wide rules in `~/Code/AGENTS.md` apply; this file adds what
is specific here and wins where it is stricter.

## Rules

1. **Do not invent a multiplexing protocol.** Connector traffic is HTTP/2
   with reversed roles over the connector's outbound TLS stream, then
   QUIC. Bounds come from `h2`/`quinn`, not from hand-written framing.
2. **Every limit is enforced before allocation**, and every limit is
   configurable with a documented default.
3. **No `unsafe`, no panics outside tests.** Enforced by workspace lints.
4. **Security is never paywalled.** PQ TLS, mTLS, route ownership, policy
   and the audit log stay in the open crates.
5. **No performance number without a benchmark anyone can rerun.**
6. **Keep the licence boundary.** `tunnelward-proto`, `tunnelward-crypto`, `tunnelward-identity`,
   `tunnelward-mcp`, `tunnelward-connector` and `tunnelward-testpki` are MIT OR Apache-2.0 and must
   never depend on a GPL crate (`scripts/licence-boundary.sh`). A new crate
   an SDK needs is permissive from its first commit.
7. **Crypto changes need an ADR** in `docs/adr/` and test vectors.
8. **Releases**: `v0.0.N`, one `feat/v0.0.N` branch and one pull request
   per release; signed annotated tag `tunnelward v0.0.N`; GitHub release
   title `tunnelward 0.0.N`.

## The gate

```bash
cargo xtask ci
```

It is the source of truth; see [DEVELOPMENT.md](DEVELOPMENT.md).

## Leave alone

- `LICENSE-GPL`, `LICENSE-MIT`, `LICENSE-APACHE`, `LICENSES/`: legal texts.
- `docs/cla/`: drafts pending legal review; change only on the maintainer's word.
- `supply-chain/` and `Cargo.lock`: change them only through `cargo vet`
  and `cargo`, never by hand.
- `.complexity-baseline`: it may only shrink.
