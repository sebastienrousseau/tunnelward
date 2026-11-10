// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The gateway's configuration file (TOML), its checks, and the
//! [`tunnelward_gateway::Config`] it builds.
//!
//! ```toml
//! [listen]
//! connectors = "0.0.0.0:7443"   # connectors dial in here (mutual TLS)
//! ingress = "0.0.0.0:8443"      # agents connect here
//! admin = "127.0.0.1:9090"      # optional admin API
//!
//! [tls]                         # the connector listener
//! cert = "gateway.crt"          # PEM chain, leaf first
//! key = "gateway.key"           # PEM private key
//! client_ca = "connectors.crt"  # PEM roots connector certificates chain to
//! reload_secs = 10              # how often to look for renewed files
//!
//! [ingress]                     # optional; plain HTTP without cert and key
//! cert = "ingress.crt"
//! key = "ingress.key"
//! client_certificates = false   # ask agents for one, for tokens bound
//!                               # to it (RFC 8705); any is accepted"
//! trusted_proxies = ["10.0.0.0/8"]
//! proxy_protocol = false
//!
//! [[ingress.cors]]              # optional, per path (G17)
//! path = "/mcp"
//! origins = ["https://app.example.org"]
//!
//! [connectors]
//! allow = ["10.1.0.0/16"]       # empty: any source
//! lease_secs = 3600
//!
//! [[connectors.owners]]         # optional (FR-3); unlisted routes belong
//! route = "mcp/payments"        # to whichever identity holds them
//! identities = ["spiffe://example.org/ns/prod/sa/payments"]
//!
//! [admin]
//! token_env = "TUNNELWARD_ADMIN_TOKEN"   # required unless admin is loopback
//!
//! [agents]                      # optional: bearer tokens (see agents.rs)
//!
//! [providers]                   # optional: tag requests by provider
//!                               # (see providers.rs)
//!
//! [enrolment]                   # optional: connectors enrol with a token
//!                               # (see enrol.rs)
//!
//! [state]                       # optional: a store several gateways
//!                               # share (see state.rs)
//!
//! [policy]                      # optional: tool policy (see policy.rs)
//! file = "policy.toml"          # read again when it changes
//!
//! [audit]                       # optional: the audit log (see audit.rs)
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use tunnelward_crypto::rustls::RootCertStore;
use tunnelward_crypto::rustls::pki_types::pem::PemObject;
use tunnelward_crypto::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tunnelward_crypto::{ClientAuth, Identity, KeyExchange, server_config};
use tunnelward_gateway::{AdminConfig, Cidr, Config, CorsRule, RouteOwner};
use tunnelward_proto::{ALPN, is_route, is_spiffe_id};

mod assemble;

use assemble::{state_and_policy, watched, with_agents, with_ingress, with_providers, with_state};

/// The whole file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct File {
    pub(crate) listen: Listen,
    tls: Tls,
    #[serde(default)]
    ingress: Ingress,
    #[serde(default)]
    connectors: Connectors,
    #[serde(default)]
    admin: Admin,
    agents: Option<crate::agents::Agents>,
    providers: Option<crate::providers::Section>,
    enrolment: Option<crate::enrol::Section>,
    state: Option<crate::state::Section>,
    policy: Option<crate::policy::Section>,
    audit: Option<crate::audit::Section>,
}

impl File {
    /// The `[enrolment]` token store, if the file has one.
    pub(crate) fn enrolment(&self, base: &Path) -> Option<tunnelward_gateway::Tokens> {
        self.enrolment.as_ref().map(|e| e.tokens(base))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Listen {
    pub(crate) connectors: SocketAddr,
    pub(crate) ingress: SocketAddr,
    pub(crate) admin: Option<SocketAddr>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tls {
    cert: PathBuf,
    key: PathBuf,
    client_ca: PathBuf,
    reload_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ingress {
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    #[serde(default)]
    trusted_proxies: Vec<String>,
    #[serde(default)]
    proxy_protocol: bool,
    #[serde(default)]
    client_certificates: bool,
    #[serde(default)]
    cors: Vec<CorsPart>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorsPart {
    path: String,
    origins: Vec<String>,
}

/// An origin as browsers send it: `*`, or a scheme and host with no path.
fn is_origin(origin: &str) -> bool {
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"));
    origin == "*" || rest.is_some_and(|host| !host.is_empty() && !host.contains('/'))
}

fn cors(parts: &[CorsPart], problems: &mut Problems) -> Vec<CorsRule> {
    for part in parts {
        if !part.path.starts_with('/') {
            problems.push(format!(
                "[[ingress.cors]] path {:?}: start it with /",
                part.path
            ));
        }
        let bad = part.origins.iter().filter(|o| !is_origin(o));
        problems.extend(
            bad.map(|o| format!("[[ingress.cors]] origin {o:?}: give scheme://host[:port] or *")),
        );
    }
    parts
        .iter()
        .map(|p| CorsRule::new(p.path.clone(), p.origins.clone()))
        .collect()
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Connectors {
    #[serde(default)]
    allow: Vec<String>,
    lease_secs: Option<u32>,
    #[serde(default)]
    owners: Vec<OwnerPart>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerPart {
    route: String,
    identities: Vec<String>,
}

/// The `[[connectors.owners]]` entries, each route named once, valid
/// routes and SPIFFE IDs only.
fn owners(parts: &[OwnerPart], problems: &mut Problems) -> Vec<RouteOwner> {
    let mut seen = std::collections::HashSet::new();
    for part in parts {
        let route = &part.route;
        let at = format!("[[connectors.owners]] route {route:?}");
        if !is_route(route) {
            problems.push(format!("{at} is not a route"));
        }
        if !seen.insert(route) {
            problems.push(format!("{at}: {route:?} is listed twice"));
        }
        if part.identities.is_empty() {
            problems.push(format!("{at}: name at least one identity"));
        }
        let bad = part.identities.iter().filter(|id| !is_spiffe_id(id));
        problems.extend(bad.map(|id| format!("{at}: {id:?} is not a SPIFFE ID")));
    }
    parts
        .iter()
        .map(|p| RouteOwner {
            route: p.route.clone(),
            identities: p.identities.clone(),
        })
        .collect()
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Admin {
    token_env: Option<String>,
}

/// Everything wrong with a file, each as one line for the operator.
pub(crate) type Problems = Vec<String>;

/// A file that passed every check, ready to run.
pub(crate) struct Checked {
    pub(crate) listen: Listen,
    pub(crate) gateway: Config,
    pub(crate) admin: AdminConfig,
    /// The file and every certificate and key it names, to watch for
    /// renewal (G16).
    pub(crate) watched: Vec<PathBuf>,
    /// How often to look at them.
    pub(crate) reload_every: std::time::Duration,
    /// Agent-auth key sets fetched from a `jwks_uri`, and how often.
    pub(crate) key_sets: Vec<std::sync::Arc<tunnelward_gateway::KeySet>>,
    pub(crate) key_refresh: std::time::Duration,
    /// The provider snapshot, to reload when it changes (FR-12).
    pub(crate) providers: Option<crate::providers::Loaded>,
    /// The audit log to open when the gateway starts.
    pub(crate) audit: Option<tunnelward_audit::Settings>,
}

/// Reads and parses `path`. A parse error names the line and column.
pub(crate) fn load(path: &Path) -> Result<File, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Paths in the file are relative to the file's directory.
pub(crate) fn resolve(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    }
}

pub(crate) fn chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = CertificateDer::pem_file_iter(path)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("{}: no PEM certificate", path.display()));
    }
    Ok(certs)
}

pub(crate) fn identity(cert: &Path, key: &Path) -> Result<Identity, String> {
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{}: {e}", key.display()))?;
    Ok(Identity {
        chain: chain(cert)?,
        key,
    })
}

pub(crate) fn roots(path: &Path) -> Result<Arc<RootCertStore>, String> {
    let mut store = RootCertStore::empty();
    for cert in chain(path)? {
        store
            .add(cert)
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(Arc::new(store))
}

fn cidrs(field: &str, values: &[String], problems: &mut Problems) -> Vec<Cidr> {
    values
        .iter()
        .filter_map(|v| {
            v.parse()
                .map_err(|e| problems.push(format!("{field}: {v:?}: {e}")))
                .ok()
        })
        .collect()
}

/// The connector listener's TLS: mutual, `tw/1` only, trusting
/// `client_ca` and the enrolment CA when there is one.
fn connector_tls(
    base: &Path,
    tls: &Tls,
    enrolment_ca: Option<CertificateDer<'static>>,
) -> Result<tunnelward_crypto::rustls::ServerConfig, String> {
    let id = identity(&resolve(base, &tls.cert), &resolve(base, &tls.key))?;
    let mut trusted = Arc::unwrap_or_clone(roots(&resolve(base, &tls.client_ca))?);
    if let Some(ca) = enrolment_ca {
        trusted
            .add(ca)
            .map_err(|e| format!("[enrolment] ca_cert: {e}"))?;
    }
    let auth = ClientAuth::Required(Arc::new(trusted));
    server_config(id, auth, KeyExchange::default(), &[ALPN]).map_err(|e| format!("[tls]: {e}"))
}

/// The ingress TLS, when both a certificate and a key are given.
fn ingress_tls(
    base: &Path,
    ingress: &Ingress,
) -> Result<Option<tunnelward_crypto::rustls::ServerConfig>, String> {
    match (&ingress.cert, &ingress.key) {
        (None, None) if ingress.client_certificates => {
            Err("[ingress] client_certificates: needs the ingress cert and key".into())
        }
        (None, None) => Ok(None),
        (Some(cert), Some(key)) => {
            let id = identity(&resolve(base, cert), &resolve(base, key))?;
            let alpn: [&[u8]; 2] = [b"h2", b"http/1.1"];
            let auth = if ingress.client_certificates {
                ClientAuth::AnyHolder
            } else {
                ClientAuth::None
            };
            server_config(id, auth, KeyExchange::default(), &alpn)
                .map(Some)
                .map_err(|e| format!("[ingress]: {e}"))
        }
        _ => Err("[ingress]: give both cert and key, or neither".into()),
    }
}

/// The admin API's token, read from the environment variable the file names.
fn admin(listen: &Listen, admin: &Admin, problems: &mut Problems) -> AdminConfig {
    let Some(var) = &admin.token_env else {
        if listen.admin.is_some_and(|a| !a.ip().is_loopback()) {
            problems.push("[admin]: a non-loopback admin listener needs token_env".into());
        }
        return AdminConfig::default();
    };
    match std::env::var(var) {
        Ok(token) if !token.is_empty() => AdminConfig::with_token(token),
        _ => {
            problems.push(format!("[admin]: environment variable {var} is not set"));
            AdminConfig::default()
        }
    }
}

/// Both listeners' TLS, the connector listener trusting `enrolment_ca`
/// too; each failure goes to `problems`.
fn listener_tls(
    base: &Path,
    file: &File,
    enrolment_ca: Option<CertificateDer<'static>>,
    problems: &mut Problems,
) -> Option<(
    tunnelward_crypto::rustls::ServerConfig,
    Option<tunnelward_crypto::rustls::ServerConfig>,
)> {
    let tls = connector_tls(base, &file.tls, enrolment_ca)
        .map_err(|e| problems.push(e))
        .ok();
    let ingress = ingress_tls(base, &file.ingress)
        .map_err(|e| problems.push(e))
        .ok();
    Some((tls?, ingress?))
}

/// Runs every check on `file` (read from `path`) and builds the gateway
/// configuration, or lists every problem found.
pub(crate) fn check(path: &Path, file: File) -> Result<Checked, Problems> {
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let mut problems = Problems::new();
    let enrolment = file
        .enrolment
        .as_ref()
        .and_then(|e| crate::enrol::check(base, e, &mut problems));
    let enrolment_ca = enrolment.as_ref().map(|e| e.ca.clone());
    let tls = listener_tls(base, &file, enrolment_ca, &mut problems);
    let trusted = cidrs(
        "[ingress] trusted_proxies",
        &file.ingress.trusted_proxies,
        &mut problems,
    );
    let allow = cidrs("[connectors] allow", &file.connectors.allow, &mut problems);
    let admin = admin(&file.listen, &file.admin, &mut problems);
    let cors = cors(&file.ingress.cors, &mut problems);
    let owners = owners(&file.connectors.owners, &mut problems);
    let agents = file
        .agents
        .as_ref()
        .and_then(|a| crate::agents::check(base, a, &mut problems));
    let providers = file
        .providers
        .as_ref()
        .and_then(|p| crate::providers::check(base, p, &mut problems));
    let (shared, policy) = state_and_policy(base, &file, &mut problems);
    let audit = (file.audit.as_ref()).and_then(|a| crate::audit::check(base, a, &mut problems));
    let (Some((tls, ingress_tls)), true) = (tls, problems.is_empty()) else {
        return Err(problems);
    };
    let mut gateway = Config::new(Arc::new(tls));
    gateway.connector_allow = allow;
    gateway.route_owners = owners;
    let (key_sets, key_refresh) =
        with_agents(&mut gateway, agents, file.ingress.client_certificates);
    let (providers, signer_keys) = with_providers(&mut gateway, providers);
    gateway.ingress.enrolment = enrolment.map(|e| e.enrolment);
    with_state(&mut gateway, shared, policy);
    let key_sets = [key_sets, signer_keys].concat();
    with_ingress(&mut gateway.ingress, ingress_tls, trusted, cors, &file);
    if let Some(secs) = file.connectors.lease_secs {
        gateway.lease_secs = secs;
    }
    let watched = watched(path, base, &file);
    let reload_every = std::time::Duration::from_secs(file.tls.reload_secs.unwrap_or(10).max(1));
    Ok(Checked {
        listen: file.listen,
        gateway,
        admin,
        watched,
        reload_every,
        key_sets,
        key_refresh,
        providers,
        audit,
    })
}
