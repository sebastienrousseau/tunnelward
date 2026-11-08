#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# Renders the Homebrew formula for VERSION from the release archives in
# DIST, printing it. The tap copies the rendered tunnelward.rb attached to
# each release (Formula/tunnelward.rb in sebastienrousseau/homebrew-tap).
#
# Usage: scripts/render-formula.sh VERSION DIST
set -euo pipefail
version="$1"
dist="$2"
template="$(dirname "$0")/../pkg/brew/tunnelward.rb.in"

sha() { # target
  local file="$dist/tunnelward-$version-$1.tar.gz"
  [[ -f "$file" ]] || { echo "render-formula: missing $file" >&2; exit 1; }
  if command -v sha256sum >/dev/null; then sha256sum "$file" | cut -d' ' -f1; else shasum -a 256 "$file" | cut -d' ' -f1; fi
}

# Each checksum is its own assignment: set -e ignores a failure inside a
# command substitution that is only an argument to another command.
mac_arm="$(sha aarch64-apple-darwin)"
mac_x86="$(sha x86_64-apple-darwin)"
linux_arm="$(sha aarch64-unknown-linux-musl)"
linux_x86="$(sha x86_64-unknown-linux-musl)"
formula="$(sed \
  -e "s/@VERSION@/$version/g" \
  -e "s/@SHA_AARCH64_APPLE_DARWIN@/$mac_arm/" \
  -e "s/@SHA_X86_64_APPLE_DARWIN@/$mac_x86/" \
  -e "s/@SHA_AARCH64_UNKNOWN_LINUX_MUSL@/$linux_arm/" \
  -e "s/@SHA_X86_64_UNKNOWN_LINUX_MUSL@/$linux_x86/" \
  "$template")"
if grep -q '@[A-Z0-9_]*@' <<<"$formula"; then
  echo "render-formula: a placeholder is left" >&2
  exit 1
fi
printf '%s\n' "$formula"
