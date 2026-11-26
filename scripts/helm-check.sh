#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# Checks the Helm chart in deploy/helm/tunnelward: it lints, refuses to
# render without the values it requires, and the gateway file it renders
# runs a real gateway that passes the conformance kit. Needs helm and
# openssl; builds the tunnelward binary unless $TUNNELWARD names one.
set -euo pipefail
cd "$(dirname "$0")/.."

chart=deploy/helm/tunnelward
tw="${TUNNELWARD:-target/debug/tunnelward}"
[[ -n "${TUNNELWARD:-}" ]] || cargo build -q --locked -p tunnelward

work="$(mktemp -d)"
pid=""
cleanup() {
  [[ -n "$pid" ]] && kill "$pid" 2>/dev/null
  rm -rf "$work"
}
trap cleanup EXIT

fail() {
  echo "helm check: $*" >&2
  exit 1
}

# --- Lint, and refuse what is missing ---------------------------------
required=(--set tls.connectorsSecret=tls --set admin.tokenSecret.name=admin)
helm lint --strict "$chart" "${required[@]}" >/dev/null
if helm template t "$chart" >/dev/null 2>&1; then
  fail "rendered without tls.connectorsSecret"
fi
if helm template t "$chart" --set tls.connectorsSecret=tls >/dev/null 2>&1; then
  fail "rendered the admin API without a token"
fi
if helm template t "$chart" "${required[@]}" --set admin.enabled=false \
  --set serviceMonitor.enabled=true >/dev/null 2>&1; then
  fail "rendered a ServiceMonitor without the admin API"
fi

# --- A test PKI, laid out as the chart mounts it -----------------------
mkdir -p "$work/tls" "$work/ingress" "$work/config" "$work/pki"
pki="$work/pki"
openssl ecparam -name prime256v1 -genkey -noout -out "$pki/ca.key" 2>/dev/null
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' >"$pki/ca.ext"
openssl req -new -key "$pki/ca.key" -subj /CN=helm-check-ca -out "$pki/ca.csr" 2>/dev/null
openssl x509 -req -in "$pki/ca.csr" -signkey "$pki/ca.key" -days 1 \
  -extfile "$pki/ca.ext" -out "$work/tls/ca.crt" 2>/dev/null

# leaf <name> <subjectAltName> <extendedKeyUsage>
leaf() {
  openssl ecparam -name prime256v1 -genkey -noout -out "$pki/$1.ec" 2>/dev/null
  openssl pkcs8 -topk8 -nocrypt -in "$pki/$1.ec" -out "$pki/$1.key"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\nsubjectAltName=%s\n' \
    "$3" "$2" >"$pki/$1.ext"
  openssl req -new -key "$pki/$1.key" -subj "/CN=$1" -out "$pki/$1.csr" 2>/dev/null
  openssl x509 -req -in "$pki/$1.csr" -CA "$work/tls/ca.crt" -CAkey "$pki/ca.key" \
    -CAcreateserial -days 1 -extfile "$pki/$1.ext" -out "$pki/$1.crt" 2>/dev/null
}
leaf gateway DNS:gateway.test serverAuth
leaf connector URI:spiffe://example.org/connector clientAuth
cp "$pki/gateway.crt" "$work/tls/tls.crt"
cp "$pki/gateway.key" "$work/tls/tls.key"
cp "$pki/gateway.crt" "$work/ingress/tls.crt"
cp "$pki/gateway.key" "$work/ingress/tls.key"

# --- Render the gateway file and run it --------------------------------
connectors=17443
agents=18443
admin=19090
helm template t "$chart" "${required[@]}" \
  --set tls.ingressSecret=ingress \
  --set mountRoot="$work" \
  --set containerPorts.connectors=$connectors \
  --set containerPorts.agents=$agents \
  --set admin.port=$admin \
  --set-string config=$'[connectors]\nlease_secs = 600' \
  --show-only templates/configmap.yaml >"$work/configmap.yaml"
awk '/tunnelward.toml: \|/ { on = 1; next } on { sub(/^    /, ""); print }' \
  "$work/configmap.yaml" >"$work/config/tunnelward.toml"
TUNNELWARD_ADMIN_TOKEN=helm-check "$tw" config check "$work/config/tunnelward.toml" >/dev/null ||
  fail "the rendered gateway file does not pass config check"

TUNNELWARD_ADMIN_TOKEN=helm-check "$tw" gateway --config "$work/config/tunnelward.toml" \
  >"$work/gateway.out" 2>&1 &
pid=$!
started=""
for _ in $(seq 50); do
  started="$(cat "$work/gateway.out")"
  [[ "$started" == *"agents on"* ]] && break
  sleep 0.2
done
[[ "$started" == *"agents on"* ]] || fail "the gateway did not start: $started"

"$tw" conformance --gateway "127.0.0.1:$connectors" --server-name gateway.test \
  --ca "$work/tls/ca.crt" --cert "$pki/connector.crt" --key "$pki/connector.key" \
  --timeout-secs 2 || fail "the chart's gateway failed the conformance kit"
echo "helm check: chart lints; its gateway file runs and passes the conformance kit"
