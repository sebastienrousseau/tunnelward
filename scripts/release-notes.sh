#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# Prints the release notes for TAG in the house format: the hand-written
# Highlights from HIGHLIGHTS_DIR/TAG.md, What's Changed from the pull
# requests merged since the previous tag (or its commits when there were
# none), the SHA-256 of every asset in ASSET_DIR (every file the release
# attaches, SHA256SUMS and its signature included), and the Full Changelog
# link. The shape follows ~/Code/AGENTS.md section 3: titles in backticks,
# then the author and the pull request or commit URL.
#
# Usage: scripts/release-notes.sh TAG ASSET_DIR HIGHLIGHTS_DIR
# Needs: git history with tags, gh authenticated.
set -euo pipefail
tag="$1"
assets="$2"
dir="$3"
repo="${GITHUB_REPOSITORY:-sebastienrousseau/tunnelward}"

sha256() { # sha256sum where it exists (Linux), shasum elsewhere (macOS)
  if command -v sha256sum > /dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

highlights="$dir/$tag.md"
[[ -f "$highlights" ]] || { echo "release-notes: no $highlights" >&2; exit 1; }
prev="$(git tag --list 'v*' --sort=-v:refname --merged "$tag" | grep -vx "$tag" | head -1 || true)"
range="${prev:+$prev..}$tag"

# The Highlights file starts with its own "## Highlights" heading.
sed '/^<!--/,/-->$/d' "$highlights" | sed '/./,$!d'
echo
echo "## What's Changed"
echo
prs="$(git log --merges --reverse --format=%s "$range" | sed -n 's/^Merge pull request #\([0-9][0-9]*\) .*/\1/p')"
if [[ -n "$prs" ]]; then
  for n in $prs; do
    gh pr view "$n" --repo "$repo" --json title,author,url --jq '"* \u0060\(.title)\u0060 by @\(.author.login) in \(.url)"'
  done
else
  git log --no-merges --reverse --format='%H %s' "$range" | while read -r sha subject; do
    # gh prints the error body on stdout when the call fails: keep the
    # output only when it succeeded.
    login=""
    if found="$(gh api "repos/$repo/commits/$sha" --jq '.author.login // empty' 2>/dev/null)"; then
      login="$found"
    fi
    echo "* \`$subject\` by @${login:-sebastienrousseau} in https://github.com/$repo/commit/$sha"
  done
fi
echo
echo "## Checksums"
echo
echo "SHA-256 of every asset attached to this release:"
echo
echo '```text'
(cd "$assets" && export LC_ALL=C && sha256 -- *)
echo '```'
echo
if [[ -n "$prev" ]]; then
  echo "**Full Changelog**: https://github.com/$repo/compare/$prev...$tag"
else
  echo "**Full Changelog**: https://github.com/$repo/commits/$tag"
fi
