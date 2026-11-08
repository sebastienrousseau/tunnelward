// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `tunnelward connector --config <file>`: a connector in front of a local
//! service, from its TOML file.
//!
//! ```toml
//! [gateway]
//! address = "gateway.example.org:7443"  # host:port; a name is looked up again every minute
//! server_name = "gateway.example.org"   # the name in the gateway's certificate
//! ca = "gateway-ca.crt"                 # PEM roots the gateway's certificate chains to
//!
//! [identity]
//! cert = "connector.crt"                # PEM chain, leaf first
//! key = "connector.key"                 # PEM private key
//! spiffe_id = "spiffe://example.org/ns/prod/sa/payments"
//!
//! [register]
//! routes = ["mcp/payments"]
//! domains = []                          # optional
//! capacity = 64                         # optional
//!
//! [target]
//! url = "http://127.0.0.1:8080"         # or unix:/path/to/socket
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use tunnelward_connector::{
    Config as Session, Connector, ConnectorConfig, Forward, Gateways, Target,
};
use tunnelward_crypto::rustls::pki_types::ServerName;
use tunnelward_crypto::{Identity, KeyExchange, client_config};
use tunnelward_proto::{
    ALPN, ConnectorId, Limits, PROTOCOL_VERSION, Register, is_domain, is_route, is_spiffe_id,
};

use crate::config::{Problems, identity, resolve, roots};

/// How often a gateway name is looked up again.
const DNS_REFRESH: Duration = Duration::from_secs(60);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct File {
    gateway: GatewayPart,
    identity: IdentityPart,
    register: RegisterPart,
    target: TargetPart,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayPart {
    address: String,
    server_name: String,
    ca: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityPart {
    cert: PathBuf,
    key: PathBuf,
    spiffe_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterPart {
    routes: Vec<String>,
    #[serde(default)]
    domains: Vec<String>,
    capacity: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetPart {
    url: String,
}

/// Whether a TOML text is a connector's file: it has a `[target]`.
pub(crate) fn is_connector_file(text: &str) -> bool {
    text.parse::<toml::Table>()
        .is_ok_and(|t| t.contains_key("target"))
}

pub(crate) fn load(path: &Path) -> Result<File, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// `host:port` as fixed addresses, or as a name to look up.
fn gateways(address: &str) -> Result<Gateways, String> {
    if let Ok(addr) = address.parse::<SocketAddr>() {
        return Ok(Gateways::Static(vec![addr]));
    }
    let (name, port) = address
        .rsplit_once(':')
        .ok_or_else(|| format!("[gateway] address {address:?}: give host:port"))?;
    let port = port
        .parse()
        .map_err(|_| format!("[gateway] address {address:?}: bad port"))?;
    Ok(Gateways::Dns {
        name: name.to_owned(),
        port,
        refresh: DNS_REFRESH,
    })
}

/// `http://host:port` or `unix:/path`.
fn target(url: &str) -> Result<Target, String> {
    if let Some(addr) = url.strip_prefix("http://") {
        let addr = addr.trim_end_matches('/');
        if addr.contains(':') && !addr.contains('/') {
            return Ok(Target::Http {
                addr: addr.to_owned(),
            });
        }
    }
    #[cfg(unix)]
    if let Some(path) = url.strip_prefix("unix:") {
        return Ok(Target::Unix {
            path: PathBuf::from(path),
        });
    }
    Err(format!(
        "[target] url {url:?}: give http://host:port or unix:/path"
    ))
}

/// The routes, domains, identity and capacity, each checked.
fn register(file: &File, problems: &mut Problems) -> Register {
    let r = &file.register;
    let bad_routes = r.routes.iter().filter(|x| !is_route(x));
    problems.extend(bad_routes.map(|x| format!("[register] routes: {x:?} is not a route")));
    let bad_domains = r.domains.iter().filter(|x| !is_domain(x));
    problems.extend(bad_domains.map(|x| format!("[register] domains: {x:?} is not a domain")));
    if r.routes.is_empty() {
        problems.push("[register] routes: claim at least one route".into());
    }
    if !is_spiffe_id(&file.identity.spiffe_id) {
        problems.push(format!(
            "[identity] spiffe_id {:?} is not a SPIFFE ID",
            file.identity.spiffe_id
        ));
    }
    Register {
        version: PROTOCOL_VERSION,
        connector_id: ConnectorId([0; 16]),
        spiffe_id: file.identity.spiffe_id.clone(),
        routes: r.routes.clone(),
        domains: r.domains.clone(),
        mcp: None,
        attestation: None,
        capacity: r.capacity.unwrap_or(64),
    }
}

fn session(base: &Path, file: &File, register: Register) -> Result<Session, String> {
    let g = &file.gateway;
    let id = identity(
        &resolve(base, &file.identity.cert),
        &resolve(base, &file.identity.key),
    )?;
    claims_its_certificate(&id, &register.spiffe_id)?;
    let tls = client_config(
        roots(&resolve(base, &g.ca))?,
        Some(id),
        KeyExchange::default(),
        &[ALPN],
    )
    .map_err(|e| format!("[identity]: {e}"))?;
    let server_name = ServerName::try_from(g.server_name.clone())
        .map_err(|e| format!("[gateway] server_name {:?}: {e}", g.server_name))?;
    Ok(Session {
        gateway: g.address.clone(),
        server_name,
        tls: Arc::new(tls),
        register,
        limits: Limits::default(),
        handshake_timeout: Duration::from_secs(10),
    })
}

/// Fails unless `claimed` is the SPIFFE ID in `id`'s leaf certificate,
/// which the gateway checks too (TW-R003).
fn claims_its_certificate(id: &Identity, claimed: &str) -> Result<(), String> {
    let leaf = id.chain.first().ok_or("[identity] cert: no certificate")?;
    match tunnelward_identity::spiffe_id(leaf.as_ref()) {
        Ok(proven) if proven == claimed => Ok(()),
        Ok(proven) => Err(format!(
            "[identity] spiffe_id {claimed:?} is not the certificate's, {proven:?}"
        )),
        Err(e) => Err(format!("[identity] cert: {e}")),
    }
}

/// A file that passed every check.
pub(crate) struct Checked {
    pub(crate) config: ConnectorConfig,
    pub(crate) target: Target,
}

/// Every check on `file`, read from `path`.
pub(crate) fn check(path: &Path, file: &File) -> Result<Checked, Problems> {
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let mut problems = Problems::new();
    let register = register(file, &mut problems);
    let gateways = gateways(&file.gateway.address)
        .map_err(|e| problems.push(e))
        .ok();
    let target = target(&file.target.url).map_err(|e| problems.push(e)).ok();
    let session = session(base, file, register)
        .map_err(|e| problems.push(e))
        .ok();
    match (gateways, target, session) {
        (Some(gateways), Some(target), Some(session)) if problems.is_empty() => Ok(Checked {
            config: ConnectorConfig::new(gateways, session),
            target,
        }),
        _ => Err(problems),
    }
}

/// Runs the connector until the process stops.
pub(crate) async fn run(path: &Path) -> Result<(), String> {
    let file = load(path)?;
    let mut checked = check(path, &file).map_err(|p| p.join("\n"))?;
    let mut id = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut id)
        .map_err(|_| "no randomness for the connector id".to_owned())?;
    checked.config.session.register.connector_id = ConnectorId(id);
    let forward = Forward::new(checked.target.clone(), Duration::from_secs(30));
    let connector = Connector::start(checked.config, forward);
    let mut events = connector.events();
    println!("tunnelward connector: forwarding to {}", file.target.url);
    loop {
        match events.recv().await {
            Ok(event) => println!("tunnelward connector: {event:?}"),
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}
