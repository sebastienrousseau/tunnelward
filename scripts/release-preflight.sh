#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# The blocking release preflight (~/Code/AGENTS.md section 3). Run it on
# main before tagging, and again after creating the tag and before
# pushing it. It fails on anything that would make the release wrong.
#
# Usage: scripts/release-preflight.sh VERSION [COMMIT]
#   VERSION  e.g. 0.0.2
#   COMMIT   the release commit, when it is not main's head (the first
#            release, tagged after the release tooling reached main).
#            Versions and the changelog are read from COMMIT; the
#            Highlights always come from main.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
version="$1"
tag="v$version"
target="$(git rev-parse "${2:-HEAD}^{commit}")"
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
if [[ "$issues" == 0 ]]; then ok "no open issues"; else bad "$issues open issues"; fi

echo "== tree"
check "on main" test "$(git branch --show-current)" = main
check "working tree clean" git diff --quiet HEAD
git fetch -q origin main
check "main matches origin/main" test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"

echo "== version $version at ${target:0:7}"
check "release commit is on main" git merge-base --is-ancestor "$target" HEAD
check "workspace version is $version" bash -c "git show $target:Cargo.toml | grep -qx 'version = \"$version\"'"
check "CHANGELOG has a $version section" bash -c "git show $target:CHANGELOG.md | grep -q '^## \[$version\]'"
check "docs/releases/$tag.md has Highlights" grep -q '^## Highlights' "docs/releases/$tag.md"
check "Highlights have no em dash" bash -c "! grep -q '—' docs/releases/$tag.md"

if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  echo "== tag $tag"
  check "annotated" test "$(git cat-file -t "refs/tags/$tag")" = tag
  check "signature verifies" git tag -v "$tag"
  check "message is 'tunnelward $tag'" test "$(git for-each-ref --format='%(contents:subject)' "refs/tags/$tag")" = "tunnelward $tag"
  check "points at the release commit" test "$(git rev-parse "$tag^{commit}")" = "$target"
  check "not on origin yet" bash -c "! git ls-remote --exit-code --tags origin refs/tags/$tag"
fi

echo "== README and demo"
check "README in step with $version (scripts/readme-check.sh)" bash scripts/readme-check.sh
# The demo shows `tunnelward --version`, so it is rendered again after
# every version bump: its last commit must descend from the bump.
bump="$(git log --format=%H --reverse -S"version = \"$version\"" -- Cargo.toml | head -1)"
demo="$(git log -1 --format=%H -- .github/demo.gif)"
check "demo re-rendered after the $version bump (make demo)" \
  bash -c "[ -n '$bump' ] && [ -n '$demo' ] && git merge-base --is-ancestor '$bump' '$demo'"
# Each badge must render a value, not an error.
while IFS= read -r url; do
  title="$(curl -s -A 'tunnelward-release' "$url" | grep -o '<title>[^<]*</title>' | head -1)"
  label="$(sed -E 's/.*(img.shields.io\/[a-z-]+\/[a-z-]*).*/\1/' <<< "$url")"
  check "badge $label renders (${title:-no title})" \
    bash -c "[ -n '$title' ] && ! grep -qiE 'inaccessible|invalid|not found|unknown|no releases|error' <<< '$title'"
done < <(grep -o 'src="https://img.shields.io[^"]*"' README.md | sed 's/^src="//; s/"$//; s/&amp;/\&/g')

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
