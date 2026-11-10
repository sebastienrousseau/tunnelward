#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# FR-6 against a server that is not ours: runs the stdio bridge's
# end-to-end test with the MCP project's reference server,
# @modelcontextprotocol/server-everything, at the version pinned in
# scripts/stdio-reference.Dockerfile. The image is built once, with
# network; each session the bridge starts runs it with no network, a
# read-only filesystem, no capabilities and no new privileges. Needs
# docker.
set -euo pipefail
cd "$(dirname "$0")/.."

image="tunnelward-mcp-reference:local"
docker build --quiet --tag "$image" --file scripts/stdio-reference.Dockerfile scripts >/dev/null

export TW_STDIO_REFERENCE="docker run --interactive --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges $image"
cargo build --locked -p tunnelward-connector --example stdio-echo
cargo test --locked -p tunnelward-connector --test stdio -- \
  --ignored --exact a_reference_server_works_end_to_end --nocapture
