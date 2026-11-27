# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only

.PHONY: ci test build demo helm clean

ci: ## Run the single gate CI runs
	cargo xtask ci

test:
	cargo test --workspace --locked

build:
	cargo build --workspace --locked --release

demo: build ## Re-render .github/demo.gif from .github/demo.tape
	PATH="$(CURDIR)/target/release:$$PATH" vhs .github/demo.tape

helm: ## Check the Helm chart (needs helm and openssl)
	bash scripts/helm-check.sh

clean:
	cargo clean
