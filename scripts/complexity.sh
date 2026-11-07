#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# Complexity gate (~/Code/AGENTS.md section 0). Every function stays within
# cyclomatic 10, cognitive 15, Halstead difficulty 30 and 60 source lines;
# every file within 500 source lines. Clippy enforces cognitive complexity
# and function length as well; this script adds the two it cannot measure.
#
# .complexity-baseline lists known offenders, one per line, and may only
# shrink: a new offender fails, and so does a listed one that has been
# fixed, so the baseline is edited in the same change that fixes it.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v rust-code-analysis-cli >/dev/null || {
  echo "complexity: rust-code-analysis-cli not found" >&2
  echo "  install: cargo install rust-code-analysis-cli --version 0.0.25 --locked" >&2
  exit 1
}

found="$(mktemp)"
trap 'rm -f "$found"' EXIT

while IFS= read -r file; do
  rust-code-analysis-cli -m -O json -p "$file" | jq -r --arg f "$file" '
    ( select(.metrics.loc.sloc > 500)
      | "\($f) file sloc=\(.metrics.loc.sloc)" ),
    ( .. | objects | select(.kind? == "function") | . as $s
      | [ (if $s.metrics.cyclomatic.sum > 10 then "cyclomatic=\($s.metrics.cyclomatic.sum)" else empty end),
          (if $s.metrics.cognitive.sum > 15 then "cognitive=\($s.metrics.cognitive.sum)" else empty end),
          (if $s.metrics.halstead.difficulty > 30 then "halstead=\($s.metrics.halstead.difficulty|floor)" else empty end),
          (if $s.metrics.loc.sloc > 60 then "sloc=\($s.metrics.loc.sloc)" else empty end) ]
      | select(length > 0)
      | "\($f) fn \($s.name) \(join(" "))" )'
done < <(git ls-files --cached --others --exclude-standard -- '*.rs') | LC_ALL=C sort > "$found"

baseline=.complexity-baseline
new="$(LC_ALL=C comm -23 "$found" <(grep -v '^#' "$baseline" | LC_ALL=C sort))"
fixed="$(LC_ALL=C comm -13 "$found" <(grep -v '^#' "$baseline" | LC_ALL=C sort))"

status=0
if [[ -n "$new" ]]; then
  echo "complexity: over a ceiling (not in $baseline):" >&2
  echo "$new" >&2
  status=1
fi
if [[ -n "$fixed" ]]; then
  echo "complexity: fixed, remove from $baseline:" >&2
  echo "$fixed" >&2
  status=1
fi
[[ $status -eq 0 ]] && echo "complexity: $(wc -l < "$found" | tr -d ' ') offenders, matching $baseline"
exit $status
