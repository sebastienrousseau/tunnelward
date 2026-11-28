// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

// Tunnelward gateway-blind mode, agent side (ADR 0016, experimental).
//
// sealCall() seals a JSON-RPC tools/call's arguments to a connector's
// X-Wing public key with HPKE (RFC 9180: X-Wing, HKDF-SHA256,
// AES-256-GCM); openAnswer() opens the sealed answer. The gateway sees
// the method, the tool name and the id, never the arguments or the
// answer.
//
// Standard libraries only: WebCrypto (in Node and in browsers) for
// X25519, HMAC and AES-GCM, and a provider for the two primitives
// WebCrypto lacks, ML-KEM-768 and SHA3-256: node.ts on Node 24.7 or
// later, browser.ts on kyberlib-wasm. Get the connector's public key
// from its operator, never through the gateway.

/** ML-KEM-768 encapsulation and SHA3-256, which WebCrypto lacks. */
export interface Provider {
  encapsulate(publicKey: Uint8Array): Promise<{ ciphertext: Uint8Array; sharedSecret: Uint8Array }>;
  sha3_256(data: Uint8Array): Promise<Uint8Array>;
}

/** Opens one call's answer. */
export interface ResponseKey {
  readonly key: Uint8Array;
}

const subtle = globalThis.crypto.subtle;
const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);
const INFO = utf8("tunnelward blind v1");
const RESPONSE = utf8("tunnelward blind response");
const LABEL = utf8("\\.//^\\");
const KEM_ID = 0x647a;
const ML_KEM_PUBLIC = 1184;
/** HPKE suite: X-Wing, HKDF-SHA256, AES-256-GCM. */
const SUITE = concat(utf8("HPKE"), u16(KEM_ID), u16(0x0001), u16(0x0002));

function u16(n: number): Uint8Array {
  return new Uint8Array([n >> 8, n & 0xff]);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  // WebCrypto refuses an empty HMAC key; HMAC pads any key shorter than
  // its block with zeros, so 32 zero bytes is the same key.
  const raw = key.length === 0 ? new Uint8Array(32) : key;
  const k = await subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", k, data));
}

function labeledExtract(salt: Uint8Array, label: string, ikm: Uint8Array): Promise<Uint8Array> {
  return hmac(salt, concat(utf8("HPKE-v1"), SUITE, utf8(label), ikm));
}

/** HKDF-Expand (RFC 5869) with HPKE's label. */
async function labeledExpand(prk: Uint8Array, label: string, info: Uint8Array, length: number): Promise<Uint8Array> {
  const labeled = concat(u16(length), utf8("HPKE-v1"), SUITE, utf8(label), info);
  let block = new Uint8Array(0);
  const out: Uint8Array[] = [];
  for (let i = 1; out.reduce((n, b) => n + b.length, 0) < length; i++) {
    block = await hmac(prk, concat(block, labeled, new Uint8Array([i])));
    out.push(block);
  }
  return concat(...out).slice(0, length);
}

/** FIPS 203's encapsulation key check: every coefficient below q. */
function mlKemPublicOk(publicKey: Uint8Array): boolean {
  for (let i = 0; i + 2 < ML_KEM_PUBLIC - 32; i += 3) {
    const first = publicKey[i] | ((publicKey[i + 1] & 0x0f) << 8);
    const second = (publicKey[i + 1] >> 4) | (publicKey[i + 2] << 4);
    if (first >= 3329 || second >= 3329) return false;
  }
  return true;
}

/** X-Wing Encapsulate (draft-connolly-cfrg-xwing-kem-11). */
async function xwingEncapsulate(provider: Provider, publicKey: Uint8Array): Promise<{ enc: Uint8Array; shared: Uint8Array }> {
  if (publicKey.length !== ML_KEM_PUBLIC + 32 || !mlKemPublicOk(publicKey)) {
    throw new Error("not an X-Wing public key");
  }
  const pkM = publicKey.slice(0, ML_KEM_PUBLIC);
  const pkX = publicKey.slice(ML_KEM_PUBLIC);
  const { ciphertext: ctM, sharedSecret: ssM } = await provider.encapsulate(pkM);
  const ephemeral = (await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  const ctX = new Uint8Array(await subtle.exportKey("raw", ephemeral.publicKey));
  const peer = await subtle.importKey("raw", pkX, { name: "X25519" }, false, []);
  const ssX = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: peer }, ephemeral.privateKey, 256));
  const shared = await provider.sha3_256(concat(ssM, ssX, ctX, pkX, LABEL));
  return { enc: concat(ctM, ctX), shared };
}

/** HPKE base-mode KeySchedule: key, base nonce, exporter secret. */
async function keySchedule(shared: Uint8Array): Promise<{ key: Uint8Array; nonce: Uint8Array; exporter: Uint8Array }> {
  const pskIdHash = await labeledExtract(new Uint8Array(0), "psk_id_hash", new Uint8Array(0));
  const infoHash = await labeledExtract(new Uint8Array(0), "info_hash", INFO);
  const context = concat(new Uint8Array([0]), pskIdHash, infoHash);
  const secret = await labeledExtract(shared, "secret", new Uint8Array(0));
  return {
    key: await labeledExpand(secret, "key", context, 32),
    nonce: await labeledExpand(secret, "base_nonce", context, 12),
    exporter: await labeledExpand(secret, "exp", context, 32),
  };
}

async function aesGcm(mode: "encrypt" | "decrypt", key: Uint8Array, iv: Uint8Array, aad: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await subtle.importKey("raw", key, { name: "AES-GCM" }, false, [mode]);
  const params = { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 };
  return new Uint8Array(mode === "encrypt" ? await subtle.encrypt(params, k, data) : await subtle.decrypt(params, k, data));
}

export function base64url(bytes: Uint8Array): string {
  let text = "";
  for (const b of bytes) text += String.fromCharCode(b);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64url(text: string): Uint8Array {
  const standard = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = standard + "=".repeat((4 - (standard.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

/**
 * Seals a JSON-RPC tools/call's arguments to the connector's X-Wing
 * `publicKey`. Returns the body to send and the key for its answer.
 */
export async function sealCall(body: string, publicKey: Uint8Array, provider: Provider): Promise<{ body: string; responseKey: ResponseKey }> {
  const call = JSON.parse(body);
  if (Array.isArray(call) || call?.method !== "tools/call" || typeof call?.params?.name !== "string") {
    throw new Error("gateway-blind mode seals one tools/call at a time");
  }
  const { enc, shared } = await xwingEncapsulate(provider, publicKey);
  const schedule = await keySchedule(shared);
  const aad = concat(utf8("tools/call\0"), utf8(call.params.name));
  const plaintext = utf8(JSON.stringify(call.params.arguments ?? {}));
  const ct = await aesGcm("encrypt", schedule.key, schedule.nonce, aad, plaintext);
  call.params.arguments = { tw_blind: { v: 1, enc: base64url(enc), ct: base64url(ct) } };
  const key = await labeledExpand(schedule.exporter, "sec", RESPONSE, 32);
  return { body: JSON.stringify(call), responseKey: { key } };
}

/** Opens the sealed answer to a call `sealCall` sealed. */
export async function openAnswer(body: string, responseKey: ResponseKey): Promise<string> {
  const answer = JSON.parse(body);
  const sealed = answer?.result?.tw_blind;
  if (sealed?.v !== 1 || typeof sealed.ct !== "string") {
    throw new Error("not a sealed answer");
  }
  const plaintext = await aesGcm("decrypt", responseKey.key, new Uint8Array(12), RESPONSE, fromBase64url(sealed.ct));
  const inner = JSON.parse(new TextDecoder().decode(plaintext));
  return JSON.stringify({ jsonrpc: "2.0", id: answer.id, ...inner });
}
