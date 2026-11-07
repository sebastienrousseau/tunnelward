<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Contributing

Tunnelward is a Rust gateway and connector that let a service behind a
firewall serve AI agents without an inbound port. Contributions are
welcome; please read this first.

## Workflow

1. Fork and clone the repository; set up the tools in
   [DEVELOPMENT.md](DEVELOPMENT.md).
2. Branch from `main` and open the pull request against `main`. Release
   work is prepared on `feat/v0.0.N`.
3. Run `cargo xtask ci` before pushing. CI runs the same command.
4. A bug fix starts with a test that fails without the fix. A behaviour
   change comes with a test and a CHANGELOG entry.

## Commits

- [Conventional Commits](https://www.conventionalcommits.org/) headers,
  50 characters at most: `feat`, `fix`, `docs`, `refactor`, `perf`,
  `test`, `build`, `ci`, `chore`.
- Cryptographically signed (SSH or GPG): `git config commit.gpgsign true`.
- A [DCO](https://developercertificate.org) sign-off on every commit:
  `git commit -s`. The trailer certifies you have the right to contribute
  the change under GPL-3.0-only.
- Work assisted by an AI tool says so in an `Assisted-by:` trailer.

## Code rules

- No `unsafe`; no `unwrap`, `expect` or `panic!` outside tests.
- Functions within the complexity ceilings in
  [docs/POLICIES.md](docs/POLICIES.md).
- Every public item documented.
- New dependencies pass `cargo deny` and `cargo vet`; say in the pull
  request why the dependency is worth its weight.

## Conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). Security
issues go through [SECURITY.md](SECURITY.md), never a public issue.
