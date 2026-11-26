#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# Regenerates the TEST-ONLY attestation vectors in
# crates/tw-attest/tests/vectors/ (ADR 0009). Each run makes new keys,
# so every vector changes together. Needs cosign 3, openssl 3 and jq.
#
#   statement.json        passmcp's own fixture (passmcp-reporting,
#                         attestation/testdata, Apache-2.0), unchanged
#   cosign-p256.pub       the ECDSA P-256 key cosign signed with
#   cosign-bundle.json    cosign attest-blob --statement: a Sigstore
#                         bundle v0.3, no transparency log, checked here
#                         with cosign verify-blob-attestation
#   ed25519.pub           an Ed25519 key
#   ed25519-dsse.json     a bare DSSE envelope signed by it with openssl
#   tampered-bundle.json  cosign-bundle.json with one payload byte changed
#
# Only public keys are kept; the private keys are thrown away.
set -euo pipefail
cd "$(dirname "$0")/.."

src="${PASSMCP_REPORTING:-$HOME/Code/Public/Go/passmcp-reporting}/attestation/testdata/statement.json"
out="crates/tw-attest/tests/vectors"
type="https://satellion.com/attestation/mcp-evaluation/v1"
payload_type="application/vnd.in-toto+json"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$out"
cp "$src" "$out/statement.json"

# cosign: ECDSA P-256, signature over the DSSE pre-authentication encoding.
(
  cd "$tmp"
  COSIGN_PASSWORD='' cosign generate-key-pair --output-key-prefix p256 >/dev/null
)
cosign signing-config create --no-default-fulcio --no-default-rekor \
  --no-default-tsa --no-default-oidc --out "$tmp/offline.json" >/dev/null
COSIGN_PASSWORD='' cosign attest-blob --statement "$out/statement.json" \
  --key "$tmp/p256.key" --signing-config "$tmp/offline.json" \
  --bundle "$out/cosign-bundle.json" --yes >/dev/null 2>&1
cp "$tmp/p256.pub" "$out/cosign-p256.pub"
cosign verify-blob-attestation --key "$out/cosign-p256.pub" \
  --bundle "$out/cosign-bundle.json" --type "$type" \
  --insecure-ignore-tlog --check-claims=false >/dev/null 2>&1

# Ed25519 over PAE(type, body) = "DSSEv1 <len> <type> <len> <body>".
openssl genpkey -algorithm ed25519 -out "$tmp/ed.pem"
openssl pkey -in "$tmp/ed.pem" -pubout -out "$out/ed25519.pub"
body="$tmp/body.json"
cp "$out/statement.json" "$body"
{
  printf 'DSSEv1 %d %s %d ' "${#payload_type}" "$payload_type" "$(wc -c <"$body" | tr -d ' ')"
  cat "$body"
} >"$tmp/pae"
openssl pkeyutl -sign -rawin -inkey "$tmp/ed.pem" -in "$tmp/pae" -out "$tmp/sig"
openssl pkeyutl -verify -rawin -pubin -inkey "$out/ed25519.pub" -in "$tmp/pae" -sigfile "$tmp/sig" >/dev/null
jq -n --arg t "$payload_type" --arg p "$(base64 <"$body" | tr -d '\n')" \
  --arg s "$(base64 <"$tmp/sig" | tr -d '\n')" \
  '{payloadType: $t, payload: $p, signatures: [{keyid: "", sig: $s}]}' >"$out/ed25519-dsse.json"

# The cosign bundle with its endpoint moved by one character.
jq -r '.dsseEnvelope.payload' "$out/cosign-bundle.json" | base64 -d \
  | sed 's#https://mcp.example.com/mcp#https://mcp.example.com/mcq#' >"$tmp/edited"
jq --arg p "$(base64 <"$tmp/edited" | tr -d '\n')" '.dsseEnvelope.payload = $p' \
  "$out/cosign-bundle.json" >"$out/tampered-bundle.json"
echo "vectors written to $out"
