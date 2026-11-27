// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

// The gateway-blind provider for Node 24.7 or later: ML-KEM-768 and
// SHA3-256 from node:crypto (OpenSSL 3.5), nothing else.

import { createHash, createPublicKey, encapsulate } from "node:crypto";
import type { Provider } from "./blind.ts";

/**
 * SubjectPublicKeyInfo header of an ML-KEM-768 key (OID
 * 2.16.840.1.101.3.4.4.2, FIPS 203): node:crypto imports keys as SPKI.
 */
const SPKI_HEADER = Uint8Array.from([
  0x30, 0x82, 0x04, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02, 0x03, 0x82,
  0x04, 0xa1, 0x00,
]);

export const nodeProvider: Provider = {
  async encapsulate(publicKey: Uint8Array) {
    const spki = new Uint8Array(SPKI_HEADER.length + publicKey.length);
    spki.set(SPKI_HEADER);
    spki.set(publicKey, SPKI_HEADER.length);
    const key = createPublicKey({ key: Buffer.from(spki), format: "der", type: "spki" });
    const { sharedKey, ciphertext } = encapsulate(key);
    return { ciphertext: new Uint8Array(ciphertext), sharedSecret: new Uint8Array(sharedKey) };
  },
  async sha3_256(data: Uint8Array) {
    return new Uint8Array(createHash("sha3-256").update(data).digest());
  },
};
