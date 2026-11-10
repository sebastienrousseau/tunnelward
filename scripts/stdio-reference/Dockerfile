# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# The MCP project's reference stdio server, for the stdio bridge's
# end-to-end check (scripts/stdio-reference.sh). Exact versions only: the
# base image by digest, and the package and every dependency by the
# integrity hashes in package-lock.json, installed with `npm ci` and
# without install scripts. Move them up deliberately, never to a release
# under two weeks old: change the version in package.json and regenerate
# the lockfile in this same image.
FROM node:22-alpine@sha256:0e1754758c2df4cfa3e68d59e2e1b7374bb7fd9ea6328eaaacf15cc934af8202
WORKDIR /srv
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --omit=dev --no-audit --no-fund \
 && npm cache clean --force
USER node
ENTRYPOINT ["/srv/node_modules/.bin/mcp-server-everything", "stdio"]
