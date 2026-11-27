// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The gateway file's `[approval]` (FR-17, ADR 0014): every call to a
//! tool the policy marks `high_impact` runs only once a person approves
//! exactly that call. It needs `[agents]`, since an approval is bound to
//! the agent's token.
//!
//! ```toml
//! [approval]
//! public_url = "https://mcp.example.org"      # where approvers reach this gateway
//! issuer = "https://login.example.org"        # the approvers' provider
//! authorization_endpoint = "https://login.example.org/authorize"
//! token_endpoint = "https://login.example.org/token"
//! jwks_uri = "https://login.example.org/keys" # or jwks = "keys.json"
//! client_id = "tunnelward-approvals"          # registered with redirect URI
//!                       # <public_url>/.well-known/tunnelward/approvals/callback
//! client_secret_env = "TW_APPROVAL_SECRET"    # optional: a confidential client
//! ca = "idp-ca.crt"                           # optional: else the system roots
//! approver_groups = ["tw-approvers"]          # optional: may approve any call;
//!                                             # anyone may approve their own agent's
//! approver_claim = "groups"                   # the ID token claim listing groups
//! ttl_secs = 600                              # wait for approval, and for the retry
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tunnelward_gateway::{AgentAuth, Approvals, Issuer, KeySet};

use crate::config::{Problems, resolve};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Section {
    public_url: String,
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: Option<String>,
    jwks: Option<PathBuf>,
    client_id: String,
    client_secret_env: Option<String>,
    ca: Option<PathBuf>,
    #[serde(default)]
    approver_groups: Vec<String>,
    approver_claim: Option<String>,
    ttl_secs: Option<u64>,
}

/// A checked `[approval]`, and the approvers' key set when it is fetched.
pub(crate) struct Checked {
    pub(crate) approvals: Arc<Approvals>,
    pub(crate) fetched: Option<Arc<KeySet>>,
}

/// Checks `section`, read from a file in `base`; `with_agents` when the
/// file has `[agents]`.
pub(crate) fn check(
    base: &Path,
    section: &Section,
    with_agents: bool,
    problems: &mut Problems,
) -> Option<Checked> {
    let before = problems.len();
    if !with_agents {
        problems
            .push("[approval] needs [agents]: an approval is bound to the agent's token".into());
    }
    urls(section, problems);
    let secret = secret(section, problems);
    let roots = crate::agents::system_roots(section.ca.as_ref().map(|c| resolve(base, c)))
        .map_err(|e| problems.push(format!("[approval] ca: {e}")))
        .ok()?;
    let jwks = (section.jwks_uri.as_deref(), section.jwks.as_ref());
    let (keys, fetched) = crate::agents::issuer_keys(base, jwks, roots.clone())
        .map_err(|e| problems.push(format!("[approval] {e}")))
        .ok()?;
    if problems.len() > before {
        return None;
    }
    let issuer = Issuer {
        issuer: section.issuer.clone(),
        keys: keys.clone(),
    };
    let verifier = AgentAuth::new(section.client_id.clone(), vec![issuer]);
    let endpoints = (
        section.authorization_endpoint.clone(),
        section.token_endpoint.clone(),
    );
    let mut approvals = Approvals::new(
        &section.public_url,
        endpoints,
        section.client_id.clone(),
        verifier,
        roots,
    );
    approvals.client_secret = secret;
    approvals
        .approver_groups
        .clone_from(&section.approver_groups);
    if let Some(claim) = &section.approver_claim {
        approvals.approver_claim.clone_from(claim);
    }
    approvals.ttl = Duration::from_secs(section.ttl_secs.unwrap_or(600).clamp(60, 86_400));
    Some(Checked {
        approvals: Arc::new(approvals),
        fetched: fetched.then_some(keys),
    })
}

/// The client secret from the variable `client_secret_env` names, if any.
fn secret(section: &Section, problems: &mut Problems) -> Option<String> {
    let name = section.client_secret_env.as_ref()?;
    std::env::var(name)
        .map_err(|_| problems.push(format!("[approval] client_secret_env: {name} is not set")))
        .ok()
}

/// Every URL the sign-in uses must be `https://`.
fn urls(section: &Section, problems: &mut Problems) {
    for (key, url) in [
        ("public_url", &section.public_url),
        ("authorization_endpoint", &section.authorization_endpoint),
        ("token_endpoint", &section.token_endpoint),
    ] {
        if !url.starts_with("https://") {
            problems.push(format!("[approval] {key} {url:?}: give an https:// URL"));
        }
    }
}
