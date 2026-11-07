#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# The blocking release preflight (~/Code/AGENTS.md section 3). Run it on
# main before tagging, and again after creating the tag and before
# pushing it. It fails on anything that would make the release wrong.
#
# Usage: scripts/release-preflight.sh VERSION      (e.g. 0.0.2)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
version="$1"
tag="v$version"
repo="sebastienrousseau/tunnelward"
failed=0

ok() { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; failed=1; }
check() { # description, command...
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$what"; else bad "$what"; fi
}
count() { # api path -> number of open alerts, or "off" when the scanner is not enabled
  gh api "$1" --jq length 2>/dev/null || echo off
}

echo "== hygiene (section 0)"
for kind in dependabot code-scanning secret-scanning; do
  n="$(count "repos/$repo/$kind/alerts?state=open&per_page=100")"
  case "$n" in
    0) ok "$kind: no open alerts" ;;
    off) bad "$kind: scanner not enabled (a disabled scanner is a finding)" ;;
    *) bad "$kind: $n open alerts" ;;
  esac
done
issues="$(gh issue list --repo "$repo" --state open --json number --jq length)"
[[ "$issues" == 0 ]] && ok "no open issues" || bad "$issues open issues"

echo "== tree"
check "on main" test "$(git branch --show-current)" = main
check "working tree clean" git diff --quiet HEAD
git fetch -q origin main
check "main matches origin/main" test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"

echo "== version $version"
check "workspace version is $version" grep -qx "version = \"$version\"" Cargo.toml
check "CHANGELOG has a $version section" grep -q "^## \[$version\]" CHANGELOG.md
check "docs/releases/$tag.md has Highlights" grep -q '^## Highlights' "docs/releases/$tag.md"
check "Highlights have no em dash" bash -c "! grep -q '—' docs/releases/$tag.md"

if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  echo "== tag $tag"
  check "annotated" test "$(git cat-file -t "refs/tags/$tag")" = tag
  check "signature verifies" git tag -v "$tag"
  check "message is 'tunnelward $tag'" test "$(git for-each-ref --format='%(contents:subject)' "refs/tags/$tag")" = "tunnelward $tag"
  check "points at main's head" test "$(git rev-parse "$tag^{commit}")" = "$(git rev-parse HEAD)"
  check "not on origin yet" bash -c "! git ls-remote --exit-code --tags origin refs/tags/$tag"
fi

publishable="$(cargo metadata --format-version 1 --no-deps --locked | jq '[.packages[] | select(.publish != [])] | length')"
if [[ "$publishable" != 0 ]]; then
  echo "== crates.io dry run ($publishable crates)"
  check "cargo publish --workspace --dry-run" cargo publish --workspace --dry-run --locked
fi

if [[ "$failed" != 0 ]]; then
  echo "preflight FAILED: do not push $tag"
  exit 1
fi
echo "preflight passed for $tag"
