// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The gateway's `[state]` section: a store shared by several gateways
//! (ADR 0004), so a replay is caught whichever gateway it reaches and a
//! client's rate is counted once across them.
//!
//! ```toml
//! [state]                                  # optional; one gateway needs none
//! url = "rediss://valkey.internal:6380"    # redis:// or rediss:// (TLS 1.3)
//! password_env = "TUNNELWARD_STATE_PASSWORD"  # optional
//! ca = "valkey-ca.crt"                     # optional: roots for rediss://
//! gateways = 3                             # how many gateways share it
//! ```
//!
//! If the store fails, replay and idempotency checks refuse, and each
//! gateway rate-limits on its own at the limit divided by `gateways`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use tunnelward_gateway::{RedisState, SharedState};

use crate::config::{Problems, resolve};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Section {
    url: String,
    password_env: Option<String>,
    ca: Option<PathBuf>,
    gateways: Option<u32>,
}

/// A checked section: the store, and how many gateways share it.
pub(crate) struct Checked {
    pub(crate) state: Arc<dyn SharedState>,
    pub(crate) gateways: u32,
}

fn password(section: &Section) -> Result<Option<String>, String> {
    let Some(var) = &section.password_env else {
        return Ok(None);
    };
    match std::env::var(var) {
        Ok(value) if !value.is_empty() => Ok(Some(value)),
        _ => Err(format!("[state] password_env: {var} is not set")),
    }
}

/// Checks `section`; every problem goes to `problems`.
pub(crate) fn check(base: &Path, section: &Section, problems: &mut Problems) -> Option<Checked> {
    let gateways = section.gateways.unwrap_or(1);
    if gateways == 0 {
        problems.push("[state] gateways: give at least 1".into());
    }
    let password = password(section).map_err(|e| problems.push(e)).ok()?;
    let tls = section.url.starts_with("rediss://");
    let roots = if tls {
        crate::agents::system_roots(section.ca.as_ref().map(|ca| resolve(base, ca)))
            .map_err(|e| problems.push(format!("[state] ca: {e}")))
            .ok()?
    } else {
        Arc::new(tunnelward_crypto::rustls::RootCertStore::empty())
    };
    let store = RedisState::new(&section.url, password, roots)
        .map_err(|e| problems.push(format!("[state] url: {e}")))
        .ok()?;
    Some(Checked {
        state: Arc::new(store),
        gateways: gateways.max(1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(url: &str) -> Section {
        Section {
            url: url.into(),
            password_env: None,
            ca: None,
            gateways: Some(3),
        }
    }

    #[test]
    fn a_store_url_checks_and_keeps_the_gateway_count() {
        let mut problems = Problems::new();
        let checked = check(
            Path::new("."),
            &section("redis://127.0.0.1:6379"),
            &mut problems,
        );
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(checked.map(|c| c.gateways), Some(3));
    }

    #[test]
    fn a_bad_url_a_missing_password_and_no_gateways_are_problems() {
        let mut problems = Problems::new();
        let mut bad = section("redis://user:pw@h:1");
        let _none = check(Path::new("."), &bad, &mut problems);
        assert!(
            problems.iter().any(|p| p.contains("[state] url")),
            "{problems:?}"
        );
        bad = section("redis://h:1");
        bad.password_env = Some("TUNNELWARD_TEST_UNSET_PASSWORD".into());
        bad.gateways = Some(0);
        let mut problems = Problems::new();
        let _none = check(Path::new("."), &bad, &mut problems);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("gateways: give at least 1"))
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("TUNNELWARD_TEST_UNSET_PASSWORD is not set"))
        );
    }
}
