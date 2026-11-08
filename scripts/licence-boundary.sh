#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# Licence boundary (D8): a workspace crate licensed MIT OR Apache-2.0 must
# not depend, through normal or build dependencies, on a workspace crate
# under the GPL. Otherwise an SDK user would take on the GPL after all.
# Third-party licences are cargo-deny's job; this checks our own crates.
set -euo pipefail
cd "$(dirname "$0")/.."

violations="$(cargo metadata --format-version 1 --locked | jq -r '
  .workspace_members as $ws
  | (.packages | map(select(.id as $i | $ws | index($i))) ) as $own
  | ($own | map({key: .id, value: .license}) | from_entries) as $lic
  | ($own | map({key: .id, value: .name}) | from_entries) as $name
  | (.resolve.nodes
     | map({key: .id, value: [.deps[]
         | select(any(.dep_kinds[]; .kind == null or .kind == "build"))
         | .pkg]})
     | from_entries) as $deps
  | $ws[] as $root
  | select($lic[$root] | test("GPL") | not)
  | [$root | recurse($deps[.][]? | select($lic[.] != null))][1:][]
  | select($lic[.] | test("GPL"))
  | "\($name[$root]) (\($lic[$root])) depends on \($name[.]) (\($lic[.]))"
' | sort -u)"

if [[ -n "$violations" ]]; then
  echo "licence boundary: a permissive crate depends on a GPL crate:" >&2
  echo "$violations" >&2
  exit 1
fi
count="$(cargo metadata --format-version 1 --locked --no-deps | jq '[.packages[] | select(.license | test("GPL") | not)] | length')"
echo "licence boundary: $count permissive crates, none depends on a GPL crate"
