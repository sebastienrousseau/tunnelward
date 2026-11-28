#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
# SPDX-License-Identifier: GPL-3.0-only
#
# The gateway-blind SDK helpers against the Rust connector side (ADR 0016):
# the TypeScript helper on Node and the Java helper on the JDK each seal a
# call the Rust side opens and open the answer it seals
# (crates/tw-mcp/tests/sdk_interop.rs). Needs Node 24.7 or later
# (node:crypto's ML-KEM) and JDK 25 or later; NODE and JAVA name other
# binaries. Fails, rather than skips, when one is missing.
set -euo pipefail
cd "$(dirname "$0")/.."

node="${NODE:-node}"
java="${JAVA:-java}"
fail() {
  echo "sdk interop: $*" >&2
  exit 1
}

version="$("$node" --version 2>/dev/null)" || fail "no Node ($node): install 24.7 or later, or set NODE"
IFS=. read -r major minor _ <<<"${version#v}"
((major > 24 || (major == 24 && minor >= 7))) || fail "Node $version has no ML-KEM; need 24.7 or later"

jversion="$("$java" -version 2>&1 | head -1)" || fail "no Java ($java): install JDK 25 or later, or set JAVA"
jmajor="$(sed -E 's/.*version "([0-9]+).*/\1/' <<<"$jversion")"
((jmajor >= 25)) || fail "$jversion: need JDK 25 or later"

echo "sdk interop: Node $version, Java $jmajor"
NODE="$node" JAVA="$java" cargo test -q --locked -p tunnelward-mcp --test sdk_interop -- --ignored
