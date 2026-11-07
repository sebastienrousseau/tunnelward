#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# cargo vet, plus a ratchet: the number of exempted crates may shrink,
# never grow. A new dependency arrives with an audit or a trust entry,
# not with another exemption. Lower supply-chain/exemptions-baseline.txt
# in the change that removes one.
set -euo pipefail
cd "$(dirname "$0")/.."

out="$(cargo vet --locked 2>&1)" || { echo "$out" >&2; exit 1; }
echo "$out"
baseline="$(tr -d '[:space:]' < supply-chain/exemptions-baseline.txt)"
current="$(grep -oE '[0-9]+ exempted' <<<"$out" | grep -oE '[0-9]+' || true)"
current="${current:-0}"
if (( current > baseline )); then
  echo "vet: exemptions grew from $baseline to $current" >&2
  exit 1
fi
if (( current < baseline )); then
  echo "vet: exemptions fell to $current; lower the baseline from $baseline" >&2
  exit 1
fi
echo "vet: $current exempted, matching the baseline"
