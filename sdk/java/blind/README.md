<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Gateway-blind mode: Java agent helper (experimental)

`TunnelwardBlind` seals a `tools/call`'s arguments to a connector's X-Wing
public key, so a Tunnelward gateway routes and polices the call without
reading it, and opens the sealed answer
([ADR 0016](../../../docs/adr/0016-gateway-blind-mode.md)). JDK 25 or
later, nothing else: `javax.crypto.KEM` (ML-KEM-768), X25519, SHA3-256,
HMAC-SHA256 and AES-GCM are all in the JDK.

The JDK has no JSON parser, so the helper works on the parts of the
message; build and read the JSON-RPC envelope with your MCP client's own
JSON library:

```java
byte[] connectorKey = Base64.getUrlDecoder().decode(publicKeyText); // blind.key.pub
TunnelwardBlind.Sealed sealed = TunnelwardBlind.seal(connectorKey, "transfer", argumentsJson);
// send params.arguments = sealed.arguments() (a JSON object), then from the answer:
String inner = TunnelwardBlind.open(sealed.responseKey(), result.get("tw_blind").get("ct"));
// inner is {"result": ...} or {"error": ...}, as the server wrote it
```

Get the connector's public key from its operator, never through the
gateway. Checked against the Rust connector side by
`scripts/sdk-interop.sh`; not yet published to Maven Central.
