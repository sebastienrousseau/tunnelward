# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# The MCP project's reference stdio server, for the stdio bridge's
# end-to-end check (scripts/stdio-reference.sh). Exact versions only: the
# base image by digest, the package by version, installed without its
# install scripts. Move both up deliberately, never to a release under
# two weeks old.
FROM node:22-alpine@sha256:0e1754758c2df4cfa3e68d59e2e1b7374bb7fd9ea6328eaaacf15cc934af8202
RUN npm install --global --ignore-scripts @modelcontextprotocol/server-everything@2.0.1 \
 && npm cache clean --force
USER node
ENTRYPOINT ["mcp-server-everything", "stdio"]
