#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
# SPDX-License-Identifier: GPL-3.0-only
#
# The operator end to end (ADR 0015), against a real cluster. In a fresh
# namespace it installs the CRDs and the operator's role, runs the operator
# from this tree against the API server, and checks that:
#   1. a TunnelwardGateway with a ConnectorBinding and a RoutePolicy gets
#      its ConfigMap, Deployment and Services, and its pods become Ready;
#   2. a changed policy reaches the ConfigMap and rolls the pods;
#   3. a policy that does not check is refused and changes nothing;
#   4. a binding with a bad identity is refused and changes nothing;
#   5. deleting the gateway deletes what the operator made.
#
# Needs: a cluster, openssl, jq.
#   TW_SERVER   the API server as this machine reaches it (required)
#   KUBECTL     how to run kubectl (default: kubectl), word-split, such as
#               "colima ssh -- sudo k3s kubectl"
#   TW_IMAGE    the gateway image the pods run
#               (default: ghcr.io/sebastienrousseau/tunnelward:0.0.20)
set -euo pipefail
cd "$(dirname "$0")/.."

server="${TW_SERVER:?set TW_SERVER to the API server, such as https://127.0.0.1:6443}"
read -r -a kubectl <<<"${KUBECTL:-kubectl}"
image="${TW_IMAGE:-ghcr.io/sebastienrousseau/tunnelward:0.0.20}"
ns="tw-e2e-$$"
work="$(mktemp -d)"
operator=""

k() { "${kubectl[@]}" "$@"; }
kn() { k -n "$ns" "$@"; }

cleanup() {
  [[ -n "$operator" ]] && kill "$operator" 2>/dev/null
  k delete namespace "$ns" --wait=false >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

fail() {
  echo "operator e2e: FAIL: $*" >&2
  [[ -f "$work/operator.log" ]] && sed 's/^/  operator: /' "$work/operator.log" >&2
  exit 1
}
ok() { echo "  ok    $*"; }

# until <seconds> <what> <command...>: retries the command until it succeeds.
until_ok() {
  local deadline=$((SECONDS + $1)) what=$2
  shift 2
  until "$@" >/dev/null 2>&1; do
    ((SECONDS < deadline)) || fail "$what (after waiting)"
    sleep 2
  done
}

condition() { # condition <kind> <name> <type>
  kn get "$1" "$2" -o "jsonpath={.status.conditions[?(@.type==\"$3\")].status}"
}
is() { [[ "$("${@:2}")" == "$1" ]]; }

echo "== setup: namespace $ns"
cargo build -q --locked -p tunnelward
k create namespace "$ns" >/dev/null
k apply -f - <deploy/operator/crds.yaml >/dev/null
sed "s/namespace: tunnelward$/namespace: $ns/" deploy/operator/operator.yaml |
  awk '/^kind: Deployment/{exit} {print}' | sed '$d' | kn apply -f - >/dev/null
k wait --for=condition=Established crd/tunnelwardgateways.tunnelward.satellion.com >/dev/null
kn create token tunnelward-operator --duration 1h >"$work/token"
k config view --raw -o 'jsonpath={.clusters[0].cluster.certificate-authority-data}' |
  base64 -d >"$work/ca.crt"

# The gateway's connector listener certificate and CA, as a Secret.
pki="$work/pki"
mkdir -p "$pki"
openssl ecparam -name prime256v1 -genkey -noout -out "$pki/ca.key" 2>/dev/null
openssl req -new -x509 -key "$pki/ca.key" -subj /CN=e2e-ca -days 1 -out "$pki/ca.crt" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$pki/gw.ec" 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in "$pki/gw.ec" -out "$pki/gw.key"
printf 'subjectAltName=DNS:gateway.test\nextendedKeyUsage=serverAuth\n' >"$pki/gw.ext"
openssl req -new -key "$pki/gw.key" -subj /CN=gateway.test -out "$pki/gw.csr" 2>/dev/null
openssl x509 -req -in "$pki/gw.csr" -CA "$pki/ca.crt" -CAkey "$pki/ca.key" -CAcreateserial \
  -days 1 -extfile "$pki/gw.ext" -out "$pki/gw.crt" 2>/dev/null
b64() { base64 <"$1" | tr -d '\n'; }
kn apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Secret
metadata: {name: edge-tls}
data: {tls.crt: $(b64 "$pki/gw.crt"), tls.key: $(b64 "$pki/gw.key"), ca.crt: $(b64 "$pki/ca.crt")}
EOF

target/debug/tunnelward operator --namespace "$ns" --server "$server" \
  --token-file "$work/token" --ca "$work/ca.crt" --every-secs 2 >"$work/operator.log" 2>&1 &
operator=$!

echo "== 1. a gateway, a binding and a policy"
kn apply -f - >/dev/null <<EOF
apiVersion: tunnelward.satellion.com/v1alpha1
kind: TunnelwardGateway
metadata: {name: edge}
spec: {image: "$image", replicas: 1, tlsSecret: edge-tls}
---
apiVersion: tunnelward.satellion.com/v1alpha1
kind: ConnectorBinding
metadata: {name: payments}
spec: {gateway: edge, identity: "spiffe://example.org/payments", routes: [mcp/payments]}
---
apiVersion: tunnelward.satellion.com/v1alpha1
kind: RoutePolicy
metadata: {name: edge-policy}
spec:
  gateway: edge
  policy: |
    default = "deny"
    [[rules]]
    effect = "permit"
    tools = ["read_*"]
EOF
until_ok 180 "gateway edge Ready" is True condition tunnelwardgateway edge Ready
ok "gateway edge is Ready"
is True condition connectorbinding payments Bound || fail "binding not Bound"
is True condition routepolicy edge-policy Accepted || fail "policy not Accepted"
config="$(kn get configmap edge-config -o json)"
jq -e '.data["tunnelward.toml"] | contains("route = \"mcp/payments\"") and contains("spiffe://example.org/payments")' \
  <<<"$config" >/dev/null || fail "owners missing from the gateway file"
jq -e '.data["policy.toml"] | contains("read_*")' <<<"$config" >/dev/null || fail "policy missing"
for svc in edge-connectors edge-agents; do kn get service "$svc" >/dev/null || fail "no service $svc"; done
ok "ConfigMap holds the owners and the policy; Services exist"

echo "== 2. a changed policy rolls the pods"
digest() { kn get deployment edge -o 'jsonpath={.spec.template.metadata.annotations.tunnelward\.satellion\.com/config-digest}'; }
before="$(digest)"
kn patch routepolicy edge-policy --type merge \
  -p '{"spec":{"policy":"default = \"deny\"\n[[rules]]\neffect = \"permit\"\ntools = [\"list_*\"]\n"}}' >/dev/null
changed() { [[ "$(digest)" != "$before" ]]; }
until_ok 60 "the digest to change" changed
until_ok 180 "gateway edge Ready again" is True condition tunnelwardgateway edge Ready
kn get configmap edge-config -o json | jq -e '.data["policy.toml"] | contains("list_*")' >/dev/null ||
  fail "new policy not in the ConfigMap"
ok "new policy applied, pods rolled and Ready"

echo "== 3. a bad policy is refused"
before="$(digest)"
kn patch routepolicy edge-policy --type merge -p '{"spec":{"policy":"default = \"maybe\"\n"}}' >/dev/null
until_ok 60 "policy Accepted=False" is False condition routepolicy edge-policy Accepted
until_ok 30 "gateway Accepted=False" is False condition tunnelwardgateway edge Accepted
[[ "$(digest)" == "$before" ]] || fail "a bad policy reached the Deployment"
kn get configmap edge-config -o json | jq -e '.data["policy.toml"] | contains("list_*")' >/dev/null ||
  fail "a bad policy reached the ConfigMap"
ok "refused, the running gateway untouched"
kn patch routepolicy edge-policy --type merge -p '{"spec":{"policy":"default = \"deny\"\n"}}' >/dev/null
until_ok 60 "policy Accepted again" is True condition routepolicy edge-policy Accepted

echo "== 4. a binding with a bad identity is refused"
before="$(digest)"
kn apply -f - >/dev/null <<EOF
apiVersion: tunnelward.satellion.com/v1alpha1
kind: ConnectorBinding
metadata: {name: rogue}
spec: {gateway: edge, identity: "not-a-spiffe-id", routes: [mcp/rogue]}
EOF
until_ok 60 "binding rogue Bound=False" is False condition connectorbinding rogue Bound
[[ "$(digest)" == "$before" ]] || fail "a bad binding reached the Deployment"
ok "refused, the running gateway untouched"
kn delete connectorbinding rogue >/dev/null

echo "== 5. deleting the gateway deletes what the operator made"
kn delete tunnelwardgateway edge >/dev/null
gone() { ! kn get deployment edge >/dev/null 2>&1 && ! kn get configmap edge-config >/dev/null 2>&1; }
until_ok 90 "the Deployment and ConfigMap to go" gone
ok "Deployment and ConfigMap garbage-collected"

echo "operator e2e: passed"
