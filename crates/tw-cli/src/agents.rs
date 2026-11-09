// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The gateway file's `[agents]` section: the bearer tokens agents must
//! present (MCP authorisation).
//!
//! ```toml
//! [agents]
//! resource = "https://mcp.example.org"  # the URL agents use; tokens' aud
//! scopes = ["mcp"]                      # optional: required on every token
//! ca = "/etc/ssl/cert.pem"              # optional roots for jwks_uri; default
//!                                       # SSL_CERT_FILE, then the system bundle
//! refresh_secs = 600                    # how often to fetch jwks_uri again
//!
//! [[agents.issuers]]
//! issuer = "https://auth.example.org"   # exactly as in the tokens' iss
//! jwks_uri = "https://auth.example.org/.well-known/jwks.json"   # or jwks = "keys.json"
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tunnelward_crypto::rustls::RootCertStore;
use tunnelward_gateway::{AgentAuth, Issuer, KeySet};

use crate::config::{Problems, resolve, roots};

/// Where the system's CA bundle usually is, in the order tried.
const SYSTEM_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/ssl/cert.pem",
    "/etc/pki/tls/certs/ca-bundle.crt",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Agents {
    resource: String,
    #[serde(default)]
    scopes: Vec<String>,
    ca: Option<PathBuf>,
    refresh_secs: Option<u64>,
    #[serde(default)]
    issuers: Vec<IssuerPart>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuerPart {
    issuer: String,
    jwks_uri: Option<String>,
    jwks: Option<PathBuf>,
}

/// The checked section: the gateway's setting and the key sets that
/// need fetching, with how often.
pub(crate) struct Checked {
    pub(crate) auth: AgentAuth,
    pub(crate) fetched: Vec<Arc<KeySet>>,
    pub(crate) refresh: Duration,
}

/// Checks `agents`, read from a file in `base`, adding to `problems`.
pub(crate) fn check(base: &Path, agents: &Agents, problems: &mut Problems) -> Option<Checked> {
    let before = problems.len();
    if !agents.resource.starts_with("https://") && !agents.resource.starts_with("http://") {
        problems.push(format!(
            "[agents] resource {:?}: give the https:// URL agents use",
            agents.resource
        ));
    }
    if agents.issuers.is_empty() {
        problems.push("[agents]: name at least one [[agents.issuers]]".into());
    }
    let mut fetched = Vec::new();
    let issuers: Vec<Issuer> = agents
        .issuers
        .iter()
        .filter_map(|part| issuer(base, agents, part, &mut fetched, problems))
        .collect();
    (problems.len() == before).then(|| {
        let mut auth = AgentAuth::new(agents.resource.clone(), issuers);
        auth.scopes.clone_from(&agents.scopes);
        Checked {
            auth,
            fetched,
            refresh: Duration::from_secs(agents.refresh_secs.unwrap_or(600).max(60)),
        }
    })
}

fn issuer(
    base: &Path,
    agents: &Agents,
    part: &IssuerPart,
    fetched: &mut Vec<Arc<KeySet>>,
    problems: &mut Problems,
) -> Option<Issuer> {
    let at = format!("[[agents.issuers]] issuer {:?}", part.issuer);
    let keys = match (&part.jwks_uri, &part.jwks) {
        (Some(_), Some(_)) => Err("give jwks_uri or jwks, not both".to_owned()),
        (None, None) => Err("give jwks_uri or jwks".to_owned()),
        (None, Some(file)) => fixed(&resolve(base, file)),
        (Some(url), None) => fetched_from(base, agents, url).inspect(|k| fetched.push(k.clone())),
    };
    match keys {
        Ok(keys) => Some(Issuer {
            issuer: part.issuer.clone(),
            keys,
        }),
        Err(why) => {
            problems.push(format!("{at}: {why}"));
            None
        }
    }
}

/// The key set fetched from `url`. The URL is checked first: without a
/// CA bundle (Windows has none) the bundle's problem would hide the
/// URL's.
fn fetched_from(base: &Path, agents: &Agents, url: &str) -> Result<Arc<KeySet>, String> {
    KeySet::from_url(url, Arc::new(RootCertStore::empty())).map_err(|e| e.to_string())?;
    let roots = ca_roots(base, agents)?;
    KeySet::from_url(url, roots)
        .map(Arc::new)
        .map_err(|e| e.to_string())
}

fn fixed(path: &Path) -> Result<Arc<KeySet>, String> {
    let json = std::fs::read(path).map_err(|e| format!("jwks {}: {e}", path.display()))?;
    KeySet::from_jwks(&json)
        .map(Arc::new)
        .map_err(|e| format!("jwks {}: {e}", path.display()))
}

/// The roots `jwks_uri` fetches trust: `ca`, else the system's.
fn ca_roots(
    base: &Path,
    agents: &Agents,
) -> Result<Arc<tunnelward_crypto::rustls::RootCertStore>, String> {
    system_roots(agents.ca.as_ref().map(|ca| resolve(base, ca)))
}

/// `explicit`, else `SSL_CERT_FILE`, else the first system CA bundle
/// found, as a root store for HTTPS fetches.
pub(crate) fn system_roots(
    explicit: Option<PathBuf>,
) -> Result<Arc<tunnelward_crypto::rustls::RootCertStore>, String> {
    let path = match (explicit, std::env::var_os("SSL_CERT_FILE")) {
        (Some(path), _) => path,
        (None, Some(env)) => PathBuf::from(env),
        (None, None) => SYSTEM_BUNDLES
            .iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
            .ok_or("no CA bundle found; set [agents] ca or SSL_CERT_FILE")?,
    };
    roots(&path)
}
