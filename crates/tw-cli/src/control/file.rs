// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The control file (ADR 0012).
//!
//! ```toml
//! [listen]
//! api = "0.0.0.0:9443"              # operators: TLS, OIDC bearer tokens
//! fleet = "0.0.0.0:9444"            # gateways: mutual TLS
//!
//! [tls]
//! cert = "control.crt"              # the control's certificate, both listeners
//! key = "control.key"
//! gateway_ca = "ca.crt"             # roots gateway certificates chain to
//! gateways = ["spiffe://example.org/gateway/*"]   # SPIFFE IDs allowed to
//!                                   # fetch; a trailing * matches a prefix
//!
//! [operators]                       # the keys of a gateway's [agents]
//! resource = "https://control.example.org"        # tokens' aud
//! [[operators.issuers]]
//! issuer = "https://login.example.org"
//! jwks_uri = "https://login.example.org/keys"     # or jwks = "keys.json"
//!
//! [roles]                           # see roles.rs
//! operator = ["tw-operators"]
//!
//! [store]
//! dir = "control-data"              # bundles/<version>.json
//! key = "bundle.key"                # tunnelward control keygen --out bundle.key
//!
//! [audit]                           # optional, as a gateway's
//! path = "control-audit.jsonl"
//! key = "audit.key"
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use tunnelward_crypto::composite::SigningKey;
use tunnelward_crypto::rustls::ServerConfig;
use tunnelward_crypto::{ClientAuth, KeyExchange, server_config};

use super::roles::Roles;
use crate::config::{Problems, identity, resolve, roots};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    listen: Listen,
    tls: Tls,
    operators: crate::agents::Agents,
    roles: Roles,
    store: Store,
    audit: Option<crate::audit::Section>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Listen {
    api: SocketAddr,
    fleet: SocketAddr,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tls {
    cert: PathBuf,
    key: PathBuf,
    gateway_ca: PathBuf,
    gateways: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Store {
    dir: PathBuf,
    key: PathBuf,
}

/// A control file with every check passed.
pub(crate) struct Checked {
    pub(crate) api: SocketAddr,
    pub(crate) fleet: SocketAddr,
    pub(crate) api_tls: Arc<ServerConfig>,
    pub(crate) fleet_tls: Arc<ServerConfig>,
    pub(crate) gateways: Vec<String>,
    pub(crate) operators: crate::agents::Checked,
    pub(crate) roles: Roles,
    pub(crate) store_dir: PathBuf,
    pub(crate) key: SigningKey,
    pub(crate) audit: Option<crate::audit::Checked>,
}

/// The control file at `path`, checked, or every problem with it.
pub(crate) fn check(path: &Path) -> Result<Checked, Problems> {
    let text =
        std::fs::read_to_string(path).map_err(|e| vec![format!("{}: {e}", path.display())])?;
    let file: File = toml::from_str(&text).map_err(|e| vec![format!("{}: {e}", path.display())])?;
    let base = path.parent().unwrap_or(Path::new("."));
    let mut problems = Problems::new();
    let tls = tls(base, &file.tls, &mut problems);
    let operators = crate::agents::check_named(base, &file.operators, "operators", &mut problems);
    problems.extend(file.roles.problem());
    let key = crate::audit::signing_key(&resolve(base, &file.store.key))
        .map_err(|e| problems.push(format!("[store] key: {e}")))
        .ok();
    let audit = (file.audit.as_ref()).and_then(|a| crate::audit::check(base, a, &mut problems));
    match (tls, operators, key) {
        (Some((api_tls, fleet_tls)), Some(operators), Some(key)) if problems.is_empty() => {
            Ok(Checked {
                api: file.listen.api,
                fleet: file.listen.fleet,
                api_tls,
                fleet_tls,
                gateways: file.tls.gateways,
                operators,
                roles: file.roles,
                store_dir: resolve(base, &file.store.dir),
                key,
                audit,
            })
        }
        _ => Err(problems),
    }
}

/// The API's and the fleet's server configurations.
fn tls(
    base: &Path,
    tls: &Tls,
    problems: &mut Problems,
) -> Option<(Arc<ServerConfig>, Arc<ServerConfig>)> {
    for id in tls
        .gateways
        .iter()
        .filter(|id| !id.starts_with("spiffe://"))
    {
        problems.push(format!(
            "[tls] gateways {id:?}: give a spiffe:// ID or prefix"
        ));
    }
    if tls.gateways.is_empty() {
        problems.push("[tls] gateways: name the SPIFFE IDs allowed to fetch".into());
    }
    server_configs(base, tls)
        .map_err(|e| problems.push(format!("[tls]: {e}")))
        .ok()
}

/// The API's configuration, with no client certificate, and the
/// fleet's, which requires one chaining to `gateway_ca`.
fn server_configs(
    base: &Path,
    tls: &Tls,
) -> Result<(Arc<ServerConfig>, Arc<ServerConfig>), String> {
    // Read twice: an identity holds its private key and is not Clone.
    let id = || identity(&resolve(base, &tls.cert), &resolve(base, &tls.key));
    let ca = roots(&resolve(base, &tls.gateway_ca))?;
    let alpn: &[&[u8]] = &[b"http/1.1"];
    let api = server_config(id()?, ClientAuth::None, KeyExchange::default(), alpn);
    let fleet = server_config(
        id()?,
        ClientAuth::Required(ca),
        KeyExchange::default(),
        alpn,
    );
    let api = api.map_err(|e| e.to_string())?;
    let fleet = fleet.map_err(|e| e.to_string())?;
    Ok((Arc::new(api), Arc::new(fleet)))
}

/// Whether `id` is one of `allowed`: equal, or under a prefix ending `*`.
pub(crate) fn allowed(allowed: &[String], id: &str) -> bool {
    allowed.iter().any(|a| match a.strip_suffix('*') {
        Some(prefix) => id.starts_with(prefix),
        None => a == id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_ids_match_exactly_or_by_prefix() {
        let list = vec![
            "spiffe://example.org/gateway/*".to_owned(),
            "spiffe://other.org/gw".to_owned(),
        ];
        assert!(allowed(&list, "spiffe://example.org/gateway/eu-1"));
        assert!(allowed(&list, "spiffe://other.org/gw"));
        assert!(!allowed(&list, "spiffe://other.org/gw/2"));
        assert!(!allowed(&list, "spiffe://example.org/connector"));
    }
}
