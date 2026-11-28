// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

// The gateway-blind provider for browsers: WebCrypto has neither
// ML-KEM nor SHA-3, so both come from kyberlib-wasm (0.0.17 or later),
// which the page loads and initialises; pass its module here.

import type { Provider } from "./blind.ts";

/** What this provider uses of kyberlib-wasm's exports. */
export interface KyberlibWasm {
  encapsulate(publicKey: Uint8Array): { ciphertext: Uint8Array; sharedSecret: Uint8Array; free(): void };
  sha3_256(data: Uint8Array): Uint8Array;
}

export function browserProvider(kyberlib: KyberlibWasm): Provider {
  return {
    async encapsulate(publicKey: Uint8Array) {
      const kex = kyberlib.encapsulate(publicKey);
      try {
        return { ciphertext: kex.ciphertext.slice(), sharedSecret: kex.sharedSecret.slice() };
      } finally {
        kex.free();
      }
    },
    async sha3_256(data: Uint8Array) {
      return kyberlib.sha3_256(data);
    },
  };
}
