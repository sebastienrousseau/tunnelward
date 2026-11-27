#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# Dependency gate (~/Code/AGENTS.md section 11). .dependency-baseline
# lists every third-party package in Cargo.lock, one name per locked
# version, and may only shrink: a package the lockfile gains fails (a new
# dependency, or an update that pulls in a new transitive one), and so
# does a listed one that is gone, so the baseline is edited in the change
# that removes it. Updating a package to a new version keeps its name and
# passes.
set -euo pipefail
cd "$(dirname "$0")/.."

locked="$(mktemp)"
listed="$(mktemp)"
trap 'rm -f "$locked" "$listed"' EXIT

# A package with a `source` line comes from a registry or git: third party.
awk '
  /^\[\[package\]\]/ { name = "" }
  /^name = / { gsub(/"/, "", $3); name = $3 }
  /^source = / && name != "" { print name }
' Cargo.lock | LC_ALL=C sort >"$locked"
grep -v '^#' .dependency-baseline | sed '/^$/d' | LC_ALL=C sort >"$listed"

added="$(LC_ALL=C comm -23 "$locked" "$listed")"
gone="$(LC_ALL=C comm -13 "$locked" "$listed")"
status=0
if [ -n "$added" ]; then
  echo "deps: Cargo.lock gained third-party packages (AGENTS.md section 11):" >&2
  echo "$added" | sed 's/^/  + /' >&2
  echo "  a new dependency needs the maintainer's approval by name; build it in-house" >&2
  status=1
fi
if [ -n "$gone" ]; then
  echo "deps: no longer locked; remove from .dependency-baseline:" >&2
  echo "$gone" | sed 's/^/  - /' >&2
  status=1
fi
[ "$status" = 0 ] && echo "deps: $(wc -l <"$locked" | tr -d ' ') third-party packages, none new"
exit "$status"
