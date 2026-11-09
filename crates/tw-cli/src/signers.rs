// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `[[providers.signers]]`: the agents whose Web Bot Auth signatures a
//! gateway verifies (FR-12).
//!
//! ```toml
//! [providers]
//! on_invalid = "downgrade"       # or "reject": 401 TW-I010
//! ca = "/etc/ssl/cert.pem"       # optional roots for the directories
//!
//! [[providers.signers]]
//! signature_agent = "https://chatgpt.com"   # exactly as in Signature-Agent
//! provider = "openai"
//! agent = "chatgpt-agent"
//! # directory = "https://chatgpt.com/.well-known/http-message-signatures-directory"
//! ```
//!
//! Only listed agents are verified, and each directory is fetched from
//! the URL configured here, never one a request names.

use std::path::PathBuf;
use std::sync::Arc;

use serde::Deserialize;
use tunnelward_gateway::{BotAuth, KeySet, OnInvalid, Signer};

/// Where a key directory lives, under the agent's origin.
const DIRECTORY: &str = "/.well-known/http-message-signatures-directory";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignerPart {
    signature_agent: String,
    provider: String,
    agent: String,
    directory: Option<String>,
}

/// The verifier for `parts`, and the key sets to keep fresh.
pub(crate) fn check(
    parts: &[SignerPart],
    on_invalid: Option<&str>,
    ca: Option<PathBuf>,
    problems: &mut Vec<String>,
) -> Option<(Arc<BotAuth>, Vec<Arc<KeySet>>)> {
    let on_invalid = policy(on_invalid, problems);
    let roots = crate::agents::system_roots(ca)
        .map_err(|e| problems.push(format!("[providers] ca: {e}")))
        .ok();
    // Each signer is checked even without roots (Windows has no CA
    // bundle file), so every problem is listed at once.
    let checking = roots
        .clone()
        .unwrap_or_else(|| Arc::new(tunnelward_crypto::rustls::RootCertStore::empty()));
    let signers: Vec<Signer> = parts
        .iter()
        .filter_map(|p| signer(p, &checking).map_err(|e| problems.push(e)).ok())
        .collect();
    roots?;
    let keys = signers.iter().map(|s| s.keys.clone()).collect();
    Some((Arc::new(BotAuth::new(signers, on_invalid?)), keys))
}

/// `[providers] on_invalid`, `reject` when absent.
fn policy(on_invalid: Option<&str>, problems: &mut Vec<String>) -> Option<OnInvalid> {
    match on_invalid.unwrap_or("reject") {
        "reject" => Some(OnInvalid::Reject),
        "downgrade" => Some(OnInvalid::Downgrade),
        other => {
            problems.push(format!(
                "[providers] on_invalid {other:?}: give reject or downgrade"
            ));
            None
        }
    }
}

fn signer(
    part: &SignerPart,
    roots: &Arc<tunnelward_crypto::rustls::RootCertStore>,
) -> Result<Signer, String> {
    let at = format!(
        "[[providers.signers]] signature_agent {:?}",
        part.signature_agent
    );
    if !part.signature_agent.starts_with("https://") {
        return Err(format!("{at}: give the agent's https:// URL"));
    }
    let directory = part
        .directory
        .clone()
        .unwrap_or_else(|| format!("{}{DIRECTORY}", part.signature_agent.trim_end_matches('/')));
    let keys = KeySet::from_url(&directory, roots.clone()).map_err(|e| format!("{at}: {e}"))?;
    Ok(Signer {
        signature_agent: part.signature_agent.clone(),
        provider: part.provider.clone(),
        agent: part.agent.clone(),
        keys: Arc::new(keys),
    })
}
