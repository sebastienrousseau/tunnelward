# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only

.PHONY: ci test build demo clean

ci: ## Run the single gate CI runs
	cargo xtask ci

test:
	cargo test --workspace --locked

build:
	cargo build --workspace --locked --release

demo: build ## Re-render .github/demo.gif from .github/demo.tape
	PATH="$(CURDIR)/target/release:$$PATH" vhs .github/demo.tape

clean:
	cargo clean
