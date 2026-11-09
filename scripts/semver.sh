#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# API-breakage check (C6.L3): cargo semver-checks on every publishable
# crate against its newest version on crates.io. A crate with no version
# there yet has no baseline: it is named and skipped, and checked from
# its first release on. Under 0.0.x every release may break the API, so
# this mostly guards the 0.1.0 line; it runs now so it is in place then.
set -euo pipefail
cd "$(dirname "$0")/.."

# The sparse-index path of a crate name, as crates.io lays it out.
index_path() { # name
  local n=$1
  case ${#n} in
    1) echo "1/$n" ;;
    2) echo "2/$n" ;;
    3) echo "3/${n:0:1}/$n" ;;
    *) echo "${n:0:2}/${n:2:2}/$n" ;;
  esac
}

excluded=()
while IFS= read -r name; do
  code="$(curl -s --retry 3 --retry-all-errors -o /dev/null -w '%{http_code}' "https://index.crates.io/$(index_path "$name")")"
  case $code in
    200) ;;
    404) echo "semver: $name has no release on crates.io yet; skipped"; excluded+=(--exclude "$name") ;;
    *) echo "semver: crates.io index answered $code for $name" >&2; exit 1 ;;
  esac
done < <(cargo metadata --format-version 1 --no-deps --locked |
  jq -r '.packages[] | select(.publish != []) | .name')

# The +-expansion keeps bash 3.2 (macOS) happy with an empty array under -u.
cargo semver-checks --workspace ${excluded[@]+"${excluded[@]}"}
