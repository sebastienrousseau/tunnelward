#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# passmcp, the Satellion suite's MCP validator, on every MCP server this
# repository ships or serves:
#
#   1. the stdio-echo example on its own: no check may fail
#   2. stdio-echo through the whole tunnel (gateway ingress, connector,
#      stdio bridge): no check may fail
#   3. the MCP reference server (@modelcontextprotocol/server-everything,
#      pinned in scripts/stdio-reference/) directly and through
#      `tunnelward dev`: the same counts both ways. That server is not
#      ours, so its own findings stay; the gateway must add none.
#
# Needs passmcp (the latest release) and docker. Run before each release
# (DEVELOPMENT.md).
set -euo pipefail
cd "$(dirname "$0")/.."

command -v passmcp >/dev/null || { echo "passmcp-check: passmcp not found (mise use -g github:sebastienrousseau/passmcp@latest)" >&2; exit 1; }
echo "passmcp-check: $(passmcp version)"
work="$(mktemp -d)"
name="tunnelward-passmcp-reference"
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  [ -n "${dev_pid:-}" ] && kill "$dev_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

cargo build --locked -q -p tunnelward -p tunnelward-connector --example stdio-echo
echo_bin="$PWD/target/debug/examples/stdio-echo"

# "<pass> <warn> <fail>" from a passmcp JSON report.
counts() { jq -r '.counts | "\(.pass) \(.warn) \(.fail)"' "$1"; }

echo "== 1. stdio-echo on its own =="
passmcp check --stdio --output json -- "$echo_bin" >"$work/echo.json" \
  || { jq '.score' "$work/echo.json" >&2; echo "passmcp failed stdio-echo" >&2; exit 1; }
echo "pass warn fail: $(counts "$work/echo.json")"

echo "== 2. stdio-echo through the tunnel =="
cargo test --locked -q -p tunnelward-gateway --test passmcp -- --ignored --nocapture 2>&1 | grep -E 'passmcp through|test result'

echo "== 3. The reference server, directly and through tunnelward dev =="
docker build --quiet --tag tunnelward-mcp-reference:local scripts/stdio-reference >/dev/null
docker rm -f "$name" >/dev/null 2>&1 || true
docker run --detach --rm --name "$name" --publish 127.0.0.1:3002:3001 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --entrypoint /srv/node_modules/.bin/mcp-server-everything tunnelward-mcp-reference:local streamableHttp >/dev/null
for _ in $(seq 50); do
  docker logs "$name" 2>&1 | grep -q 'listening on port' && break
  sleep 0.2
done
./target/debug/tunnelward dev --to http://127.0.0.1:3002 --listen 127.0.0.1:8018 >"$work/dev.log" 2>&1 &
dev_pid=$!
for _ in $(seq 50); do
  grep -q "tunnelward dev: ready" "$work/dev.log" && break
  sleep 0.2
done
grep -q "tunnelward dev: ready" "$work/dev.log" || { cat "$work/dev.log" >&2; exit 1; }
passmcp check http://127.0.0.1:3002/mcp --output json >"$work/direct.json" || true
passmcp check http://127.0.0.1:8018/mcp --output json >"$work/tunnelled.json" || true
direct="$(counts "$work/direct.json")"
tunnelled="$(counts "$work/tunnelled.json")"
echo "pass warn fail, direct: $direct; through the gateway: $tunnelled"
[ "$direct" = "$tunnelled" ] || { echo "the gateway changed passmcp's findings" >&2; exit 1; }
echo "passmcp-check: every MCP server here passes, and the gateway adds no finding"
