#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# Regenerates the TEST-ONLY certificates and keys in
# crates/tw-testpki/pki/. They exist so the handshake tests need no
# certificate-generation crate (rcgen would add 36 crates to cargo-vet).
# The keys protect nothing and must never be used outside tests.
#
# Two CAs ("ours" and "other"), each P-256, valid for 100 years:
#   ca.der             our CA certificate
#   gateway.{der,key}  server leaf, SAN DNS:gateway.test, serverAuth
#   connector.{der,key} client leaf, an X.509-SVID: SAN
#                      URI:spiffe://example.org/connector and DNS:connector.test
#   rival.{der,key}    client leaf, SVID for spiffe://example.org/rival
#   plain.{der,key}    client leaf with a DNS name and no SPIFFE ID
#   two-ids.{der,key}  client leaf with two SPIFFE IDs (not a valid SVID)
#   other-ca.der       a CA nobody trusts
#   intruder.{der,key} client leaf issued by the other CA
# Keys are PKCS#8 DER.
set -euo pipefail
cd "$(dirname "$0")/../crates/tw-testpki/pki"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
days=36500

key() { # name
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp/$1.pem"
  openssl pkcs8 -topk8 -nocrypt -in "$tmp/$1.pem" -outform DER -out "$1.key"
}

ca() { # name subject
  key "$1"
  openssl req -x509 -new -key "$tmp/$1.pem" -subj "/CN=$2" -days "$days" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -outform PEM -out "$tmp/$1.crt"
  openssl x509 -in "$tmp/$1.crt" -outform DER -out "$1.der"
  rm -f "$1.key"
}

leaf() { # name cn usage ca san
  key "$1"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\nsubjectAltName=%s\n' \
    "$3" "$5" > "$tmp/$1.ext"
  openssl req -new -key "$tmp/$1.pem" -subj "/CN=$2" -out "$tmp/$1.csr"
  openssl x509 -req -in "$tmp/$1.csr" -CA "$tmp/$4.crt" -CAkey "$tmp/$4.pem" \
    -CAcreateserial -days "$days" -extfile "$tmp/$1.ext" -outform DER -out "$1.der"
}

ca ca "Tunnelward Test CA"
ca other-ca "Untrusted Test CA"
leaf gateway gateway.test serverAuth ca DNS:gateway.test
leaf connector connector.test clientAuth ca \
  URI:spiffe://example.org/connector,DNS:connector.test
leaf rival rival.test clientAuth ca URI:spiffe://example.org/rival
leaf plain plain.test clientAuth ca DNS:plain.test
leaf two-ids two-ids.test clientAuth ca \
  URI:spiffe://example.org/one,URI:spiffe://example.org/two
leaf intruder intruder.test clientAuth other-ca DNS:intruder.test
ls -1
