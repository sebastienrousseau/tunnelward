#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# Keeps the README in step with the release it describes:
#   1. every `tunnelward... = "X"` dependency example names the workspace
#      version;
#   2. a version whose CHANGELOG section has "### Added" has a row in
#      the capabilities table ("Shipped in X").
# The demo and the live badges are checked by release-preflight.sh,
# which has the git history and the network.
set -euo pipefail
cd "$(dirname "$0")/.."

version="$(cargo metadata --format-version 1 --no-deps --locked |
  jq -r '[.packages[] | select(.name == "tunnelward")][0].version')"
failed=0

while IFS= read -r line; do
  crate="${line%% *}"
  named="$(sed -E 's/^[^"]*"([^"]*)".*/\1/' <<< "$line")"
  echo "readme: the $crate example names $named, not $version" >&2
  failed=1
done < <(grep -E '^tunnelward[a-z-]* = "[^"]+"' README.md | grep -v "= \"$version\"" || true)

added="$(awk -v v="## [$version]" '
  index($0, v) == 1 { inside = 1; next }
  inside && /^## \[/ { exit }
  inside && /^### Added/ { print "yes"; exit }' CHANGELOG.md)"
if [[ $added == yes ]] && ! grep -q "Shipped in $version" README.md; then
  echo "readme: CHANGELOG $version adds features, but no capability row says \"Shipped in $version\"" >&2
  failed=1
fi

[[ $failed == 0 ]] && echo "readme: in step with $version"
exit "$failed"
