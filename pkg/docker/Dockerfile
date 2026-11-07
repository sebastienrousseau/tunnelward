# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# Built by .github/workflows/release.yml from the release's static musl
# binaries: the context holds linux/amd64/tunnelward and
# linux/arm64/tunnelward. Nothing is compiled here.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/tunnelward /usr/local/bin/tunnelward
USER nonroot
ENTRYPOINT ["/usr/local/bin/tunnelward"]
