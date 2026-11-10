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
//! [identity]                            # an X.509-SVID for spiffe_id, from
//! spiffe_id = "spiffe://example.org/ns/prod/sa/payments"
//! cert = "connector.crt"                # PEM files, read again when they
//! key = "connector.key"                 # change (every reload_secs, 10)
//! # workload_api = "unix:///run/spire/sockets/agent.sock"   # or the SPIFFE
//! #                                     # Workload API, rotating as it sends
//! # [identity.enrol]                    # or enrol with the gateway (a
//! # url = "https://gateway.example.org:8443"  # one-time token, then
//! # token_file = "enrol.token"          # renewal; TUNNELWARD_ENROL_TOKEN
//! # state_dir = "state"                 # if no file); SVID and key kept here
//! # ca = "ingress-ca.crt"               # optional: roots for the ingress
//!
//! [register]
//! routes = ["mcp/payments"]
//! domains = []                          # optional
//! capacity = 64                         # optional
//!
//! [target]                              # see backend.rs: or a stdio command
//! url = "http://127.0.0.1:8080"         # or unix:/path/to/socket
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use tunnelward_connector::{
    Config as Session, Connector, ConnectorConfig, Forward, Gateways, StdioBridge,
};
use tunnelward_crypto::rustls::RootCertStore;
use tunnelward_crypto::rustls::pki_types::ServerName;
use tunnelward_crypto::{KeyExchange, RotatingIdentity, client_config_rotating};
use tunnelward_proto::{
    ALPN, ConnectorId, Limits, PROTOCOL_VERSION, Register, is_domain, is_route, is_spiffe_id,
};

use crate::config::{Problems, identity, resolve, roots};
use crate::svid::{self, Source, claims_its_certificate};

/// How often a gateway name is looked up again.
const DNS_REFRESH: Duration = Duration::from_secs(60);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct File {
    gateway: GatewayPart,
    identity: IdentityPart,
    register: RegisterPart,
    target: crate::backend::TargetPart,
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
    spiffe_id: String,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    workload_api: Option<String>,
    reload_secs: Option<u64>,
    enrol: Option<EnrolPart>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrolPart {
    url: String,
    token_file: Option<PathBuf>,
    state_dir: PathBuf,
    ca: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterPart {
    routes: Vec<String>,
    #[serde(default)]
    domains: Vec<String>,
    capacity: Option<u32>,
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

/// Where the SVID comes from: the files (loaded once now, so a file
/// for another identity fails the check), the Workload API endpoint, or
/// enrolment with the gateway.
fn source(base: &Path, id: &IdentityPart) -> Result<Source, String> {
    match (&id.cert, &id.key, &id.workload_api, &id.enrol) {
        (Some(cert), Some(key), None, None) => {
            let (cert, key) = (resolve(base, cert), resolve(base, key));
            claims_its_certificate(&identity(&cert, &key)?, &id.spiffe_id)?;
            let every = Duration::from_secs(id.reload_secs.unwrap_or(10).max(1));
            Ok(Source::Files { cert, key, every })
        }
        #[cfg(unix)]
        (None, None, Some(endpoint), None) => tunnelward_identity::workload::socket_path(endpoint)
            .map(Source::Workload)
            .map_err(|e| format!("[identity] workload_api: {e}")),
        (None, None, None, Some(enrol)) => enrolment(base, enrol).map(Source::Enrol),
        _ => Err(
            "[identity]: give cert and key, workload_api (Unix only), or [identity.enrol]".into(),
        ),
    }
}

fn enrolment(base: &Path, part: &EnrolPart) -> Result<crate::enrolled::Enrol, String> {
    if !part.url.starts_with("https://") {
        return Err(format!(
            "[identity.enrol] url {:?}: give an https:// URL",
            part.url
        ));
    }
    let roots = crate::agents::system_roots(part.ca.as_ref().map(|ca| resolve(base, ca)))
        .map_err(|e| format!("[identity.enrol] ca: {e}"))?;
    Ok(crate::enrolled::Enrol {
        url: part.url.clone(),
        token_file: part.token_file.as_ref().map(|t| resolve(base, t)),
        state_dir: resolve(base, &part.state_dir),
        roots,
    })
}

/// A file that passed every check: everything but the SVID itself.
pub(crate) struct Checked {
    gateways: Gateways,
    target: crate::backend::Backend,
    register: Register,
    roots: Arc<RootCertStore>,
    server_name: ServerName<'static>,
    address: String,
    source: Source,
}

/// `result`'s value, or its error added to `problems`.
fn note<T>(problems: &mut Problems, result: Result<T, String>) -> Option<T> {
    result.map_err(|e| problems.push(e)).ok()
}

/// Every check on `file`, read from `path`.
pub(crate) fn check(path: &Path, file: &File) -> Result<Checked, Problems> {
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let mut problems = Problems::new();
    let gateways = note(&mut problems, gateways(&file.gateway.address));
    let target = note(&mut problems, crate::backend::backend(&file.target));
    let source = note(&mut problems, source(base, &file.identity));
    let roots = note(&mut problems, roots(&resolve(base, &file.gateway.ca)));
    let name = &file.gateway.server_name;
    let server_name = note(
        &mut problems,
        ServerName::try_from(name.clone())
            .map_err(|e| format!("[gateway] server_name {name:?}: {e}")),
    );
    let register = register(file, &mut problems);
    match (gateways, target, source, roots, server_name) {
        (Some(gateways), Some(target), Some(source), Some(roots), Some(server_name))
            if problems.is_empty() =>
        {
            Ok(Checked {
                gateways,
                target,
                register,
                roots,
                server_name,
                address: file.gateway.address.clone(),
                source,
            })
        }
        _ => Err(problems),
    }
}

/// The connector's configuration, presenting `identity` at each
/// handshake.
fn config(checked: Checked, identity: Arc<RotatingIdentity>) -> Result<ConnectorConfig, String> {
    let tls = client_config_rotating(checked.roots, identity, KeyExchange::default(), &[ALPN])
        .map_err(|e| format!("[identity]: {e}"))?;
    let session = Session {
        gateway: checked.address,
        server_name: checked.server_name,
        tls: Arc::new(tls),
        register: checked.register,
        limits: Limits::default(),
        handshake_timeout: Duration::from_secs(10),
    };
    Ok(ConnectorConfig::new(checked.gateways, session))
}

/// Runs the connector until the process stops.
pub(crate) async fn run(path: &Path) -> Result<(), String> {
    let file = load(path)?;
    let mut checked = check(path, &file).map_err(|p| p.join("\n"))?;
    checked.register.connector_id = fresh_id()?;
    let (identity, keeper) =
        svid::start(checked.source.clone(), checked.register.spiffe_id.clone()).await?;
    let backend = checked.target.clone();
    let config = config(checked, identity)?;
    println!("tunnelward connector: {}", backend.describe());
    let connector = match backend {
        crate::backend::Backend::Http(target) => {
            Connector::start(config, Forward::new(target, Duration::from_secs(30)))
        }
        crate::backend::Backend::Stdio(stdio) => Connector::start(config, StdioBridge::new(stdio)),
    };
    report(&connector).await;
    keeper.abort();
    Ok(())
}

/// A random connector id.
fn fresh_id() -> Result<ConnectorId, String> {
    let mut id = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut id)
        .map_err(|_| "no randomness for the connector id".to_owned())?;
    Ok(ConnectorId(id))
}

/// Prints the connector's events until it stops.
async fn report(connector: &Connector) {
    let mut events = connector.events();
    loop {
        match events.recv().await {
            Ok(event) => println!("tunnelward connector: {event:?}"),
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
        }
    }
}
