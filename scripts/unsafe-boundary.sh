#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# Unsafe boundary: the workspace forbids unsafe code, with one exception,
# the counting allocator in the unpublished benchmark crate
# (crates/tw-bench/src/alloc.rs, for NFR-2). This fails if
#   - any other Rust file has an unsafe block, function, impl or trait;
#   - any crate but tw-bench stops taking the workspace's lints;
#   - tw-bench's lints differ from the workspace's in anything but
#     `unsafe_code`.
set -euo pipefail
cd "$(dirname "$0")/.."

allowed="crates/tw-bench/src/alloc.rs"
fail=0

found="$(grep -rlE --include='*.rs' '\bunsafe[[:space:]]*(\{|fn\b|impl\b|trait\b|extern\b)' crates fuzz \
  | grep -vxF "$allowed" || true)"
if [[ -n "$found" ]]; then
  echo "unsafe boundary: unsafe code outside $allowed:" >&2
  echo "$found" >&2
  fail=1
fi

for manifest in crates/*/Cargo.toml; do
  [[ "$manifest" == crates/tw-bench/Cargo.toml ]] && continue
  if ! grep -A1 -x '\[lints\]' "$manifest" | grep -qx 'workspace = true'; then
    echo "unsafe boundary: $manifest does not take the workspace's lints" >&2
    fail=1
  fi
done

# The lint lines of a table, without comments, blank lines or unsafe_code.
lints() {
  awk -v rust="$2" -v clippy="$3" '
    /^\[/ { on = ($0 == rust || $0 == clippy) ; next }
    on && !/^#/ && NF && !/^unsafe_code/ { print }
  ' "$1"
}
if ! diff <(lints Cargo.toml '[workspace.lints.rust]' '[workspace.lints.clippy]') \
          <(lints crates/tw-bench/Cargo.toml '[lints.rust]' '[lints.clippy]') >&2; then
  echo "unsafe boundary: tw-bench's lints differ from the workspace's (above)" >&2
  fail=1
fi

exit "$fail"
