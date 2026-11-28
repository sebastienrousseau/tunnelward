#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# The MCP project's conformance suite through the gateway (M2): runs
# @modelcontextprotocol/conformance's server scenarios against the MCP
# reference server (@modelcontextprotocol/server-everything, over
# Streamable HTTP) twice, directly and through `tunnelward dev`, and
# fails unless every scenario has the same result both ways. Both are
# pinned with their npm lockfiles (scripts/mcp-conformance/,
# scripts/stdio-reference/) and run in containers.
#
# The suite's scenarios target its own test server, which is not
# published on npm, so against the reference server some fail either
# way; what this checks is that the gateway changes no result.
#
# Needs docker; run before each release (DEVELOPMENT.md).
set -euo pipefail
cd "$(dirname "$0")/.."

suite="tunnelward-mcp-conformance:local"
server="tunnelward-mcp-reference:local"
name="tunnelward-mcp-conformance-server"
work="$(mktemp -d)"
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  [ -n "${dev_pid:-}" ] && kill "$dev_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

docker build --quiet --tag "$suite" scripts/mcp-conformance >/dev/null
docker build --quiet --tag "$server" scripts/stdio-reference >/dev/null
cargo build --locked -q -p tunnelward

# The server on the host's loopback only.
docker rm -f "$name" >/dev/null 2>&1 || true
docker run --detach --rm --name "$name" --publish 127.0.0.1:3001:3001 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --entrypoint /srv/node_modules/.bin/mcp-server-everything "$server" streamableHttp >/dev/null
for _ in $(seq 50); do
  docker logs "$name" 2>&1 | grep -q 'listening on port 3001' && break
  sleep 0.2
done

# The scenario results of one run against `url`, one "<scenario> <passed> <failed>" per line.
run() {
  docker run --rm --add-host host.docker.internal:host-gateway \
    --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
    "$suite" server --url "$1" >"$work/$2.log" 2>&1 || true
  sed -n 's/^[✓✗] \([a-z0-9-]*\): \([0-9]*\) passed, \([0-9]*\) failed$/\1 \2 \3/p' "$work/$2.log" | sort
}

echo "== 1. The reference server directly =="
run "http://host.docker.internal:3001/mcp" direct >"$work/direct"
[ -s "$work/direct" ] || { cat "$work/direct.log" >&2; echo "no results from the direct run" >&2; exit 1; }

echo "== 2. Through tunnelward dev =="
./target/debug/tunnelward dev --to http://127.0.0.1:3001 --listen 127.0.0.1:8017 >"$work/dev.log" 2>&1 &
dev_pid=$!
for _ in $(seq 50); do
  grep -q "tunnelward dev: ready" "$work/dev.log" && break
  sleep 0.2
done
grep -q "tunnelward dev: ready" "$work/dev.log" || { cat "$work/dev.log" >&2; echo "tunnelward dev did not register" >&2; exit 1; }
run "http://host.docker.internal:8017/mcp" tunnelled >"$work/tunnelled"

echo "== 3. Compare =="
scenarios="$(wc -l <"$work/direct" | tr -d ' ')"
passed="$(awk '$3 == 0' "$work/direct" | wc -l | tr -d ' ')"
if ! diff -u "$work/direct" "$work/tunnelled"; then
  echo "the gateway changed a result (above: - direct, + tunnelled)" >&2
  exit 1
fi
echo "mcp-conformance: $scenarios scenarios, the same result through the gateway ($passed pass either way)"
