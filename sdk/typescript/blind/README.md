<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Gateway-blind mode: TypeScript agent helper (experimental)

Seals a `tools/call`'s arguments to a connector's X-Wing public key, so a
Tunnelward gateway routes and polices the call without reading it, and
opens the sealed answer ([ADR 0016](../../../docs/adr/0016-gateway-blind-mode.md)).
Standard libraries only: WebCrypto for X25519, HMAC and AES-GCM, plus a
provider for ML-KEM-768 and SHA3-256.

| Runtime | Provider | Needs |
| :-- | :-- | :-- |
| Node | `nodeProvider` (`node.ts`) | Node 24.7 or later (`node:crypto` ML-KEM) |
| Browser | `browserProvider(kyberlib)` (`browser.ts`) | kyberlib-wasm 0.0.17 or later, loaded by the page |

```ts
import { sealCall, openAnswer, fromBase64url } from "./blind.ts";
import { nodeProvider } from "./node.ts";

// From the connector's operator (blind.key.pub), never through the gateway.
const connectorKey = fromBase64url(process.env.CONNECTOR_BLIND_KEY!);
const call = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call",
  params: { name: "transfer", arguments: { to: "alice", amount: 5 } } });
const { body, responseKey } = await sealCall(call, connectorKey, nodeProvider);
const answer = await fetch(gatewayUrl, { method: "POST", body, headers }).then((r) => r.text());
console.log(await openAnswer(answer, responseKey));
```

Node runs the `.ts` files as they are (type stripping); a browser build
compiles them. Checked against the Rust connector side by
`scripts/sdk-interop.sh`. The browser provider is not yet tested in a
browser.
