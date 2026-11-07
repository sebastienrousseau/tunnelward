<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# ADR 0003: cbor4ii for the register frames

- Status: Accepted
- Date: 2026-11-07

## Context

The specification named CBOR for the register frames, and `ciborium` as
the codec. Adding ciborium brought `half`, `crunchy`, `zerocopy` and
`zerocopy-derive` (over 40,000 changed lines since the last peer audit),
and a second copy of `syn`, all to parse one small frame. None of those
crates had an audit or trusted publisher covering their current versions.

## Decision

Use `cbor4ii` 1.2.4 (MIT) with only its `serde1` and `use_std`
features. Its one required dependency is serde, whose publisher is
already trusted. It caps nesting at 256 levels and caps preallocation for
declared lengths, so a hostile length inside a frame cannot allocate more
than the frame's own size. `tw-proto` decodes with `from_reader` on the
frame body and rejects bytes left after the CBOR value.

## Consequences

- `tw-proto`'s runtime dependencies are cbor4ii and the serde family.
- cbor4ii is a cargo-vet exemption until it is audited; the audit is due
  before v0.1.0, and the exemption count is ratcheted (`scripts/vet.sh`).
- Unknown fields and unknown reject codes fail to parse
  (`deny_unknown_fields`). A new field therefore needs a new protocol
  version, which the `version` field and `UnsupportedVersion` code cover.
