<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Architecture decision records

One file per decision that someone will later question. A record is
never rewritten once accepted; a new record supersedes it.

| ADR | Title | Status |
| :--- | :--- | :--- |
| [0001](0001-reverse-http2.md) | Reverse HTTP/2 instead of a custom multiplexer | Accepted |
| [0002](0002-hybrid-pq-by-default.md) | Hybrid post-quantum key exchange by default | Accepted |
| [0003](0003-cbor4ii-for-register-frames.md) | cbor4ii for the register frames | Accepted |
| [0004](0004-state-shared-across-gateways.md) | State shared across gateways | Accepted, implemented in 0.0.12 |
| [0005](0005-leases-renew-by-reconnecting.md) | Leases renew by reconnecting | Accepted |
