<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Supply chain

`cargo vet` must pass, and `scripts/vet.sh` stops the number of
exemptions growing. The files here are written by `cargo vet`; edit them
only through it (`cargo vet trust`, `cargo vet certify`, `cargo vet fmt`).

## How a dependency gets vetted

1. **An import covers it.** Audits are imported from Mozilla, Google,
   Bytecode Alliance, ISRG, Embark Studios, Fermyon and Zcash.
2. **Its publisher is trusted.** Trust is recorded for a publisher when
   kyberlib already trusts that publisher, or when at least two of
   Mozilla, Bytecode Alliance and ISRG do.
3. **The maintainer decided.** Trust outside rule 2 is recorded only on
   the maintainer's decision, listed below.
4. **Otherwise it is exempt**, with a note saying why, and counted against
   `exemptions-baseline.txt`.

## Maintainer decisions

| Date | Crate | Publisher | Decision |
| :--- | :--- | :--- | :--- |
| 2026-11-07 | rustls, rustls-webpki, ring | cpu, ctz | Trusted: the rustls maintainers, for the TLS stack |
| 2026-11-07 | rustls-pki-types | djc | Trusted: rustls maintainer |
| 2026-11-07 | pin-project-lite | github:taiki-e/pin-project-lite | Trusted (tokio and hyper depend on it) |
| 2026-11-07 | tracing | hds | Trusted (tokio maintainer; h2 depends on it) |
| 2026-11-07 | smallvec | alejandro-vaz | Trusted: a listed crates.io owner beside the Servo team (hyper depends on it) |

## Exemptions

| Crate | Why | Until |
| :--- | :--- | :--- |
| cbor4ii | The register-frame codec (ADR 0003) | Audited before v0.1.0 |
| bitflags | proptest dependency, tests only | Its publisher meets rule 2, or proptest drops it |
| r-efi | getrandom on UEFI targets only, reached by aws-lc-sys's build | Never built for Tunnelward's targets; revisit if a UEFI build is added |
